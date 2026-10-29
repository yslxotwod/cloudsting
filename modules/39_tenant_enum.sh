#!/usr/bin/env bash
# 39_tenant_enum.sh — cloudsting module 39: map a company's cloud footprint from a bare domain
# Verbs: --tenant | --buckets | --projects | --azure | --apis | --all | --status-tsv | --menu | --selftest
set -u
umask 077

# The root is derived from the file that is about to be sourced; any value
# inherited from a caller that already sourced the core is wrong here.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV writer,
# the three-state provider gate, redaction and the selftest ledger.
MODULE_ID="39_tenant_enum"
MOD_NAME="Cloud Tenant Enumeration"
MOD_VERSION="0.21.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

TE_RUN_ID="$CS_RUN_ID"
export TE_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/tenant_enum"
mkdir -p "$OUT_DIR" 2>/dev/null || true

TENANT_FILE="$OUT_DIR/tenants-$RUN_ID.tsv"
BUCKET_FILE="$OUT_DIR/buckets-$RUN_ID.tsv"
PROJECT_FILE="$OUT_DIR/projects-$RUN_ID.tsv"
AZURE_FILE="$OUT_DIR/azure-$RUN_ID.tsv"
API_FILE="$OUT_DIR/apis-$RUN_ID.tsv"

: "${TE_TIMEOUT:=8}"          # per-request wall clock
: "${TE_CONCURRENCY:=6}"      # parallel workers
: "${TE_MAX_CANDIDATES:=400}" # cap on generated name guesses

# ── helpers ──────────────────────────────────────────────────────
te_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# Strip a domain down to its registrable core: cloud.example.co.uk -> cloud,
# example.com -> example. The core word is what gets recombined into bucket and
# project names, so getting it wrong poisons every later guess.
te_core() {
    local d="${1:-}"
    d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"
    d="${d,,}"
    # drop a trailing port
    d="${d%%:*}"
    # known two-label public suffixes
    case "$d" in
        *.co.uk|*.org.uk|*.ac.uk|*.gov.uk|*.com.au|*.co.jp|*.co.nz|*.com.br|*.co.za|*.com.mx)
            printf '%s' "$(printf '%s' "$d" | awk -F. '{print $(NF-2)}')" ;;
        *)
            printf '%s' "$(printf '%s' "$d" | awk -F. 'NF>=2{print $(NF-1)}')" ;;
    esac
}

# The domain with the public suffix removed but the label retained:
# acme.co.uk -> acme.co, cloud.acme.com -> cloud.acme
te_stem() {
    local d="${1:-}"
    d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"; d="${d,,}"
    case "$d" in
        *.co.uk|*.org.uk|*.ac.uk|*.gov.uk) printf '%s' "$(printf '%s' "$d" | sed -E 's/\.(co|org|ac|gov)\.uk$//')" ;;
        *.com.au|*.co.jp|*.co.nz|*.com.br|*.co.za|*.com.mx) printf '%s' "$(printf '%s' "$d" | sed -E 's/\.[a-z]{2,3}\.[a-z]{2}$//')" ;;
        *) printf '%s' "$(printf '%s' "$d" | sed -E 's/\.[a-z]{2,6}$//')" ;;
    esac
}

# Candidate bucket / project names from one domain. The interesting part is
# not the bare name (everybody guesses that) but the permutations that show up
# in real orgs: env suffixes, region suffixes, and the stem split on hyphens.
te_candidates() {
    local domain="${1:-}"
    local core stem dashless
    core="$(te_core "$domain")"
    stem="$(te_stem "$domain")"
    [[ -z "$core" ]] && return 0
    : "${TE_MAX_CANDIDATES:=400}"
    (( TE_MAX_CANDIDATES <= 0 )) && TE_MAX_CANDIDATES=1

    # Base words, in priority order: the registrable core first, then the
    # stem as written, then the full domain, then the separator-stripped
    # variants. The stripped forms are where real orgs hide -- acme-widgets
    # almost never registers "acme-widgets" for buckets, it registers
    # "acmewidgets".
    local -a words=("$core" "$stem" "$domain")
    dashless="${stem//-/}"
    [[ "$dashless" != "$stem" ]] && words+=("$dashless")
    local dotted="${stem//./-}"
    [[ "$dotted" != "$stem" ]] && words+=("$dotted")

    local -a suffixes=(
        "" "-backup" "-backups" "-bak" "-dev" "-development" "-test" "-staging"
        "-stage" "-prod" "-production" "-prod-backup" "-logs" "-log" "-archive"
        "-archives" "-assets" "-static" "-media" "-uploads" "-files" "-data"
        "-db" "-database" "-db-backup" "-backups-prod" "-terraform" "-tfstate"
        "-state" "-config" "-private" "-internal" "-public" "-www" "-web"
        "-apps" "-api" "-cdn" "-build" "-builds" "-ci" "-artifacts" "-releases"
        "-deploy" "-infra" "-pipeline" "-lambda" "-functions" "-reports"
        "-export" "-import" "-temp" "-tmp" "-old" "-new" "-v1" "-v2"
    )
    local -a prefixes=("" "dev-" "prod-" "test-" "stg-" "staging-" "backup-")

    # Every base word gets a slice of the cap before the next one starts, or
    # the first word eats the whole budget and the stripped variants -- the
    # ones that actually match -- are never tried.
    local nbase=${#words[@]}
    local share=$(( TE_MAX_CANDIDATES / nbase ))
    (( share < ${#suffixes[@]} )) && share=${#suffixes[@]}

    local -A emitted=()
    local n=0 w s p cand wn
    for w in "${words[@]}"; do
        [[ -z "$w" ]] && continue
        wn=0
        for s in "${suffixes[@]}"; do
            for p in "${prefixes[@]}"; do
                cand="${p}${w}${s}"
                if [[ -n "${emitted[$cand]:-}" ]]; then continue; fi
                emitted[$cand]=1
                printf '%s\n' "$cand"
                n=$((n + 1)); wn=$((wn + 1))
                if (( n >= TE_MAX_CANDIDATES )); then return 0; fi
                if (( wn >= share )); then
                    # break the suffix loop only; the break above already
                    # left the prefix loop, and this one has to leave the
                    # suffix loop without touching the base-word loop
                    break 2
                fi
            done
        done
    done
    return 0
}

# ── certificate transparency and reverse DNS ────────────────────
# An operator estate is not guessed from dictionaries, it is read off the
# certificates its own PKI signed and out of the registries that still answer
# PTR for its allocations. crt.sh publishes every issued certificate; a PTR
# sweep over one /24 names every box the operator still owns.
#
#   te_crt <domain>  ->  <name>\t<issuer-noted>\t<first-seen>  (one per name)
te_crt() {
    local domain="${1:-}"
    local d="${domain#http://}"; d="${d#https://}"; d="${d%%/*}"; d="${d,,}"
    [[ -z "$d" ]] && return 2
    command -v curl >/dev/null 2>&1 || return 3

    local url="https://crt.sh/?q=%25.${d}&output=json"
    local raw="$CS_SCRATCH/crt-$(cs_fingerprint "$d").json"
    curl --silent --show-error --max-time "${TE_CRT_TIMEOUT:-25}" \
         --user-agent "$TE_UA" --output "$raw" "$url" 2>/dev/null || return 1
    [[ -s "$raw" ]] || return 1

    # crt.sh returns a JSON array of rows with a "name_value" blob that holds
    # every SAN on the certificate, newline separated. jq flattens it, and the
    # wildcard is stripped so a *.acme.co.ke certificate yields acme.co.ke.
    jq -r '.[] | [ (.name_value // ""), (.issuer_name // ""), (.not_before // "") ] | @tsv' "$raw" 2>/dev/null \
      | awk -F'\t' '{
            n = split($1, parts, "\n");
            for (i = 1; i <= n; i++) {
                name = parts[i];
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", name);
                if (name == "") continue;
                sub(/^\*\./, "", name);
                print name "\t" $2 "\t" $3;
            }
        }' \
      | awk -F'\t' '{ if (!seen[$1]++) print }'
}

# Resolve every name in a list against the resolver and keep the ones that
# answer. One lookup per name, batched through xargs so a 500-name list does
# not take a minute.
#   te_resolve <file-of-names>  ->  <name>\t<addr>
te_resolve() {
    local list="${1:-}"
    [[ -s "$list" ]] || return 1
    command -v getent >/dev/null 2>&1 || return 3
    xargs -r -P "${TE_CONCURRENCY:-6}" -I{} sh -c '
        a="$(getent ahostsv4 "{}" 2>/dev/null | awk "NR==1{print \$1}")"
        [ -n "$a" ] && printf "%s\t%s\n" "{}" "$a"
    ' < "$list" 2>/dev/null
}

# Group resolved addresses into the /24 that owns them, so an estate shows up
# as blocks rather than as a list of hostnames. An operator with 59 names on
# one /23 is one allocation, not 59 findings.
#   te_blocks < resolved-pairs  ->  <cidr>\t<count>\t<sample-names>
te_blocks() {
    awk -F'\t' '{
        split($2, o, ".");
        cidr = o[1] "." o[2] "." o[3] ".0/24";
        count[cidr]++;
        if (count[cidr] <= 3) sample[cidr] = sample[cidr] (sample[cidr] == "" ? "" : ",") $1;
    }
    END {
        for (c in count) printf "%s\t%d\t%s\n", c, count[c], sample[c];
    }' | sort -t$'\t' -k2,2nr
}

# Does an S3 bucket exist, and can anyone read it? Three states, never two:
# absent, exists-but-private, exists-and-listable.
#   te_s3 <bucket>  ->  state<TAB>count<TAB>region
te_s3() {
    local bucket="${1:-}"
    command -v curl >/dev/null 2>&1 || { printf 'tool-missing\t0\t-\n'; return 3; }

    local url="https://${bucket}.s3.amazonaws.com/"
    local code out
    out="$(curl --silent --show-error --max-time "$TE_TIMEOUT" \
                --write-out '\n%{http_code}' "$url?list-type=2&max-keys=2" 2>/dev/null)" || true
    code="${out##*$'\n'}"
    local body="${out%$'\n'*}"

    case "$code" in
        200)
            # listable: count the keys we got back
            local n=0
            if command -v grep >/dev/null 2>&1; then
                n="$(printf '%s' "$body" | grep -o '<Key>' | wc -l)"
            fi
            local region="-"
            if command -v curl >/dev/null 2>&1; then
                region="$(curl --silent --head --max-time "$TE_TIMEOUT" "$url" 2>/dev/null \
                          | awk -F': ' 'tolower($1)=="x-amz-bucket-region"{gsub("\r","",$2); print $2}')"
                [[ -z "$region" ]] && region="-"
            fi
            printf 'listable\t%s\t%s\n' "$n" "$region"
            return 0
            ;;
        403) printf 'private\t0\t-\n';  return 0 ;;    # exists, closed
        404) printf 'absent\t0\t-\n';   return 0 ;;
        301|307) printf 'exists-redirect\t0\t-\n'; return 0 ;;
        *)   printf 'unknown-%s\t0\t-\n' "${code:-0}"; return 0 ;;
    esac
}

# GCP project existence, unauthenticated. A project's Firebase endpoints and
# its storage bucket both leak the project-number when the project is real,
# and the absence is a clean 404.
#   te_gcp <name>  ->  state<TAB>project-number
te_gcp() {
    local name="${1:-}"
    command -v curl >/dev/null 2>&1 || { printf 'tool-missing\t-\n'; return 3; }

    # storage.googleapis.com answers 404 for a nonexistent project bucket and
    # 200/403 for a real one; the XML body names the billing tier when live.
    local code
    code="$(curl --silent --output /dev/null --max-time "$TE_TIMEOUT" \
                --write-out '%{http_code}' \
                "https://storage.googleapis.com/${name}.appspot.com/" 2>/dev/null || echo 000)"
    case "$code" in
        200|403) printf 'exists\t-\n'; return 0 ;;
        404)     printf 'absent\t-\n'; return 0 ;;
        000)     printf 'unreachable\t-\n'; return 0 ;;
        *)       printf 'unknown-%s\t-\n' "$code"; return 0 ;;
    esac
}

# Azure storage account existence. The public blob endpoint answers 400 for a
# malformed account and 404 for a free name; a live account answers 403 or 409
# with a stack trace that names the account.
#   te_azure <name>  ->  state
te_azure() {
    local name="${1:-}"
    command -v curl >/dev/null 2>&1 || { printf 'tool-missing\n'; return 3; }
    local code
    code="$(curl --silent --output /dev/null --max-time "$TE_TIMEOUT" \
                --write-out '%{http_code}' \
                "https://${name}.blob.core.windows.net/?comp=list" 2>/dev/null || echo 000)"
    case "$code" in
        200) printf 'listable\n' ;;
        403|409) printf 'exists\n' ;;
        400|404) printf 'absent\n' ;;
        000) printf 'unreachable\n' ;;
        *)   printf 'unknown-%s\n' "$code" ;;
    esac
}

# Bound-parallel map: run a function over every line of a file, ADAPT_CONC
# at a time, appending each result line to an output file.
te_parallel() {
    local fn="$1" infile="$2" outfile="$3" limit="${4:-6}"
    : > "$outfile"
    local running=0 line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        ( "$fn" "$line" >> "$outfile" ) &
        running=$((running + 1))
        if (( running >= limit )); then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
    done < "$infile"
    wait
}

# ── tenant ID ────────────────────────────────────────────────────
# The tenant ID is the single most useful thing a bare domain yields: it links
# the M365 tenant, the Azure subscription directory and the SSO federation.
te_cmd_tenant() {
    local domain="${1:-}"
    [[ -z "$domain" ]] && { printf 'usage: 39_tenant_enum.sh --tenant <domain>\n' >&2; return 2; }
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    local d="${domain#http://}"; d="${d#https://}"; d="${d%%/*}"; d="${d,,}"
    cs_row DOMAIN "$d"
    : > "$TENANT_FILE"

    # OpenID Connect discovery: the authority endpoint publishes the tenant id
    # to anyone who asks for a domain's configuration document.
    local url="https://login.microsoftonline.com/${d}/.well-known/openid-configuration"
    local body
    body="$(curl --silent --show-error --max-time "$TE_TIMEOUT" "$url" 2>/dev/null || true)"

    if [[ -n "$body" ]] && command -v jq >/dev/null 2>&1; then
        local issuer tid
        issuer="$(printf '%s' "$body" | jq -r '.issuer // empty' 2>/dev/null)"
        # issuer looks like https://login.microsoftonline.com/<tenant>/v2.0
        tid="$(printf '%s' "$issuer" | awk -F/ '{print $4}')"
        if [[ -n "$tid" && "$tid" != "common" ]]; then
            cs_row TENANT "$tid"
            cs_row TENANT_SOURCE "openid-configuration"
            cs_row ISSUER "$issuer"
            printf 'tenant\t%s\t%s\n' "$tid" "$issuer" >> "$TENANT_FILE"
            cs_findings_row "$MODULE_ID" "IDENTITY" "$d" "INFO" "tenant-id:$tid" \
                "tenant resolves from $d"
        else
            cs_row TENANT "absent"
            cs_row TENANT_SOURCE "openid-configuration"
        fi
    else
        cs_row TENANT "unreachable"
        cs_row TENANT_SOURCE "openid-configuration"
    fi

    # GetUserRealm names the auth type without a credential and confirms the
    # domain is federated, managed, or unknown to Microsoft.
    local realm
    realm="$(curl --silent --show-error --max-time "$TE_TIMEOUT" \
             "https://login.microsoftonline.com/getuserrealm.srf?login=test@${d}&json=1" 2>/dev/null || true)"
    if [[ -n "$realm" ]] && command -v jq >/dev/null 2>&1; then
        local nt ap
        nt="$(printf '%s' "$realm" | jq -r '.NameSpaceType // "unknown"' 2>/dev/null)"
        ap="$(printf '%s' "$realm" | jq -r '.AuthProtocol // "-"' 2>/dev/null)"
        cs_row REALM "$nt"
        cs_row AUTH_PROTOCOL "$ap"
        case "$nt" in
            Federated) cs_findings_row "$MODULE_ID" IDENTITY "$d" "INFO" "federated-sso:$ap" "domain federated" ;;
            Managed)   cs_row NOTE "managed tenant, no external federation" ;;
            Unknown)   cs_row NOTE "domain not in any tenant" ;;
        esac
    fi

    cs_row ARTIFACT "$TENANT_FILE"
    return 0
}

# ── buckets ──────────────────────────────────────────────────────
te_cmd_buckets() {
    local domain="${1:-}"
    [[ -z "$domain" ]] && { printf 'usage: 39_tenant_enum.sh --buckets <domain>\n' >&2; return 2; }
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    cs_row DOMAIN "$domain"
    cs_row CANDIDATES "generating"
    local cands="$CS_SCRATCH/te-cands.txt"
    te_candidates "$domain" > "$cands" || { cs_row ERROR "no candidates from $domain"; return 2; }
    local total; total="$(wc -l < "$cands" | tr -d ' ')"
    cs_row CANDIDATES "$total"

    : > "$BUCKET_FILE"
    local running=0 b
    while IFS= read -r b; do
        [[ -z "$b" ]] && continue
        ( printf '%s\t%s\n' "$b" "$(te_s3 "$b")" >> "$BUCKET_FILE" ) &
        running=$((running + 1))
        if (( running >= TE_CONCURRENCY )); then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
    done < "$cands"
    wait

    local found=0 listable=0
    while IFS=$'\t' read -r b state n region; do
        [[ -z "$b" ]] && continue
        case "$state" in
            absent) continue ;;
            listable)
                found=$((found + 1)); listable=$((listable + 1))
                cs_row BUCKET "$b" "listable" "$n" "${region:--}"
                cs_findings_row "$MODULE_ID" "STORAGE" "$b" "CRITICAL" "public-bucket:$b" \
                    "anonymous ListBucket returns $n objects (${region:--})"
                ;;
            private)
                found=$((found + 1))
                cs_row BUCKET "$b" "private" "-" "${region:--}"
                ;;
            exists-redirect)
                found=$((found + 1))
                cs_row BUCKET "$b" "redirect" "-" "${region:--}"
                ;;
            *)
                cs_row BUCKET "$b" "$state" "${n:-0}" "${region:--}"
                ;;
        esac
    done < "$BUCKET_FILE"

    cs_row SUMMARY "$total" "$found" "$listable"
    cs_row ARTIFACT "$BUCKET_FILE"
    return 0
}

# ── GCP projects ─────────────────────────────────────────────────
te_cmd_projects() {
    local domain="${1:-}"
    [[ -z "$domain" ]] && { printf 'usage: 39_tenant_enum.sh --projects <domain>\n' >&2; return 2; }
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    cs_row DOMAIN "$domain"
    local cands="$CS_SCRATCH/te-proj.txt"
    te_candidates "$domain" > "$cands" || return 2
    cs_row CANDIDATES "$(wc -l < "$cands" | tr -d ' ')"

    : > "$PROJECT_FILE"
    local running=0 p
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        ( printf '%s\t%s\n' "$p" "$(te_gcp "$p")" >> "$PROJECT_FILE" ) &
        running=$((running + 1))
        if (( running >= TE_CONCURRENCY )); then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
    done < "$cands"
    wait

    local found=0
    while IFS=$'\t' read -r p state num; do
        [[ -z "$p" ]] && continue
        [[ "$state" == "absent" || "$state" == "unreachable" ]] && continue
        found=$((found + 1))
        cs_row PROJECT "$p" "$state"
    done < "$PROJECT_FILE"
    cs_row SUMMARY "$found"
    cs_row ARTIFACT "$PROJECT_FILE"
    return 0
}

# ── Azure storage ────────────────────────────────────────────────
te_cmd_azure() {
    local domain="${1:-}"
    [[ -z "$domain" ]] && { printf 'usage: 39_tenant_enum.sh --azure <domain>\n' >&2; return 2; }
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    cs_row DOMAIN "$domain"
    local cands="$CS_SCRATCH/te-az.txt"
    # azure storage names are 3-24 lowercase alnum, so strip separators
    te_candidates "$domain" | tr -d '-' | awk 'length($0)>=3 && length($0)<=24' > "$cands" || return 2
    cs_row CANDIDATES "$(wc -l < "$cands" | tr -d ' ')"

    : > "$AZURE_FILE"
    local running=0 a
    while IFS= read -r a; do
        [[ -z "$a" ]] && continue
        ( printf '%s\t%s\n' "$a" "$(te_azure "$a")" >> "$AZURE_FILE" ) &
        running=$((running + 1))
        if (( running >= TE_CONCURRENCY )); then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
    done < "$cands"
    wait

    local found=0
    while IFS=$'\t' read -r a state; do
        [[ -z "$a" ]] && continue
        case "$state" in
            absent|unreachable) continue ;;
            listable)
                found=$((found + 1))
                cs_row ACCOUNT "$a" "listable"
                cs_findings_row "$MODULE_ID" "STORAGE" "$a" "CRITICAL" "public-blob:$a" \
                    "anonymous container list enabled"
                ;;
            *)
                found=$((found + 1))
                cs_row ACCOUNT "$a" "$state"
                ;;
        esac
    done < "$AZURE_FILE"
    cs_row SUMMARY "$found"
    cs_row ARTIFACT "$AZURE_FILE"
    return 0
}

# ── exposed APIs ─────────────────────────────────────────────────
# The named subdomains an org almost always leaves pointing at something live.
te_cmd_apis() {
    local domain="${1:-}"
    [[ -z "$domain" ]] && { printf 'usage: 39_tenant_enum.sh --apis <domain>\n' >&2; return 2; }
    local d="${domain#http://}"; d="${d#https://}"; d="${d%%/*}"; d="${d,,}"
    cs_row DOMAIN "$d"

    command -v getent >/dev/null 2>&1 || { cs_row ERROR "missing tool: getent"; return 3; }

    local -a hosts=(
        "api" "www" "app" "admin" "portal" "console" "dashboard" "auth" "login"
        "sso" "idp" "dev" "staging" "stage" "test" "qa" "uat" "beta" "internal"
        "intranet" "vpn" "mail" "webmail" "smtp" "ftp" "sftp" "git" "gitlab"
        "jenkins" "ci" "cd" "build" "registry" "docker" "nexus" "artifact"
        "grafana" "kibana" "prometheus" "metrics" "status" "health" "db"
        "mysql" "postgres" "redis" "mongo" "mssql" "backup" "files" "assets"
        "static" "cdn" "media" "uploads" "storage" "s3" "blob" "docs" "wiki"
        "jira" "confluence" "support" "help" "crm" "erp" "hr" "sap" "vpn2"
    )

    : > "$API_FILE"
    local h live=0
    for h in "${hosts[@]}"; do
        local fqdn="${h}.${d}"
        local addr
        addr="$(getent hosts "$fqdn" 2>/dev/null | awk 'NR==1{print $1}')"
        if [[ -n "$addr" ]]; then
            live=$((live + 1))
            cs_row HOST "$fqdn" "$addr"
            printf '%s\t%s\n' "$fqdn" "$addr" >> "$API_FILE"
            # the interesting names are the ones that are not meant to be public
            case "$h" in
                admin|internal|intranet|jenkins|gitlab|grafana|kibana|prometheus|db|mysql|postgres|redis|mongo|mssql|backup|vpn|vpn2|sftp|ftp)
                    cs_findings_row "$MODULE_ID" "SURFACE" "$fqdn" "MEDIUM" "sensitive-subdomain:$h" \
                        "resolves publicly to $addr"
                    ;;
            esac
        fi
    done

    cs_row SUMMARY "${#hosts[@]}" "$live"
    cs_row ARTIFACT "$API_FILE"
    return 0
}

# ── certificate transparency sweep ───────────────────────────────
# One call answers "what does this operator actually own": every name its PKI
# signed, which of them still resolve, and the blocks they sit in.
te_cmd_crt() {
    local domain="${1:-}"
    [[ -z "$domain" ]] && { printf 'usage: 39_tenant_enum.sh --crt <domain>\n' >&2; return 2; }
    local d="${domain#http://}"; d="${d#https://}"; d="${d%%/*}"; d="${d,,}"
    cs_row DOMAIN "$d"

    local raw="$CS_SCRATCH/crt-names-$(cs_fingerprint "$d")"
    local rc=0
    te_crt "$d" > "$raw" 2>/dev/null || rc=$?
    if (( rc == 3 )); then cs_row ERROR "missing tool: curl"; return 3; fi
    if (( rc != 0 )) || [[ ! -s "$raw" ]]; then
        cs_row STATUS "absent" "certificate transparency returned nothing for $d"
        return 0
    fi

    local total; total="$(wc -l < "$raw" | tr -d ' ')"
    cs_row NAMES "$total"
    cs_row ARTIFACT "$raw"

    # every name, in discovery order
    local name issuer first
    while IFS=$'\t' read -r name issuer first; do
        [[ -z "$name" ]] && continue
        cs_row CERT "$name" "${issuer:0:60}" "${first%%T*}"
    done < "$raw"

    # which of them still answer
    cut -f1 "$raw" | sort -u > "$raw.uniq"
    local resolved="$CS_SCRATCH/crt-resolved-$(cs_fingerprint "$d")"
    te_resolve "$raw.uniq" > "$resolved" 2>/dev/null || true
    local live; live="$(wc -l < "$resolved" 2>/dev/null | tr -d ' ')"
    cs_row RESOLVED "${live:-0}" "of $total"
    [[ -s "$resolved" ]] && cat "$resolved" >> "$API_FILE"

    # the blocks the estate occupies
    if [[ -s "$resolved" ]]; then
        local blk n names
        while IFS=$'\t' read -r blk n names; do
            [[ -z "$blk" ]] && continue
            cs_row BLOCK "$blk" "hosts=$n" "$names"
            (( n >= 10 )) && cs_findings_row "$MODULE_ID" "DNS" "$blk" "INFO" "operator-block" \
                "$n certificate names sit in $blk"
        done < <(te_blocks < "$resolved")
    fi

    cs_row SUMMARY "names=$total resolved=${live:-0}"
    return 0
}

# ── reverse DNS sweep ────────────────────────────────────────────
# An allocation is a /24 to a /16. Sweep the PTR space and the operator's own
# naming convention names every box: those PTR names are the subdomain list
# nobody publishes and the certificate list never covered.
te_cmd_ptr() {
    local cidr="${1:-}"
    [[ -z "$cidr" ]] && { printf 'usage: 39_tenant_enum.sh --ptr <a.b.c.0/24 | a.b.0.0/16> [max]\n' >&2; return 2; }
    command -v getent >/dev/null 2>&1 || { cs_row ERROR "missing tool: getent"; return 3; }

    local net mask
    net="${cidr%%/*}"; mask="${cidr##*/}"
    [[ -z "$mask" || "$mask" == "$cidr" ]] && mask=24
    local o1 o2 o3 o4
    IFS=. read -r o1 o2 o3 o4 <<< "$net"
    [[ -z "$o4" ]] && o4=0

    local max="${2:-254}"
    (( max > 4096 )) && max=4096
    cs_row CIDR "${o1}.${o2}.${o3}.${o4}/${mask}"

    local -a octets=()
    local i
    if (( mask >= 24 )); then
        for ((i = 1; i <= max; i++)); do octets+=("${o1}.${o2}.${o3}.${i}"); done
    else
        # /16 to /23: walk the third octet as well, capped by max
        local t
        for t in 0 1 2 3; do
            local o3x=$(( o3 + t ))
            (( o3x > 255 )) && break
            for ((i = 1; i <= 254; i++)); do
                octets+=("${o1}.${o2}.${o3x}.${i}")
                (( ${#octets[@]} >= max )) && break 2
            done
        done
    fi
    cs_row ADDRESSES "${#octets[@]}"

    : > "$API_FILE"
    local found=0 addr
    printf '%s\n' "${octets[@]}" \
      | xargs -r -P "${TE_CONCURRENCY:-6}" -I{} sh -c '
            n="$(getent hosts "{}" 2>/dev/null | awk "NR==1{print \$2}")"
            [ -n "$n" ] && printf "%s\t%s\n" "{}" "$n"
        ' 2>/dev/null | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$CS_SCRATCH/ptr-out.$$"

    local ipname
    while IFS=$'\t' read -r addr ipname; do
        [[ -z "$addr" ]] && continue
        found=$((found + 1))
        cs_row PTR "$addr" "$ipname"
        printf '%s\t%s\n' "$ipname" "$addr" >> "$API_FILE"
        case "$ipname" in
            *admin*|*mgmt*|*mngt*|*nms*|*ems*|*oss*|*bss*|*sso*|*vpn*|*jump*|*bastion*|*db*|*sql*|*backup*|*u2000*|*enm*|*netnumen*|*mivoice*|*rancher*|*k8s*|*kube*)
                cs_findings_row "$MODULE_ID" "DNS" "$ipname" "MEDIUM" "sensitive-ptr" \
                    "$ipname resolves at $addr"
                ;;
        esac
    done < "$CS_SCRATCH/ptr-out.$$"
    rm -f "$CS_SCRATCH/ptr-out.$$"

    cs_row SUMMARY "answered=$found of ${#octets[@]}"
    (( found > 0 )) && return 0 || return 1
}

te_cmd_all() {
    local d="${1:-}"
    te_cmd_tenant "$d"
    te_cmd_buckets "$d"
    te_cmd_apis "$d"
    te_cmd_crt "$d"
}

te_cmd_status_tsv() {
    local c
    command -v curl >/dev/null 2>&1 && c="ok" || c="missing"
    printf '%s\t%s\tcurl-%s\n' "$MODULE_ID" "$MOD_NAME" "$c"
}

te_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

te_cmd_help() {
    cat <<'HELP'
cloudsting module 39 — Cloud Tenant Enumeration v0.21.0
  --tenant <domain>     resolve the M365/Azure tenant id and federation type
  --buckets <domain>    guess and test S3 bucket names derived from the domain
  --projects <domain>   guess and test GCP project / appspot names
  --azure <domain>      guess and test Azure storage account names
  --apis <domain>       resolve the subdomains an org usually leaves live
  --crt <domain>        certificate transparency: every name the operator's PKI signed
  --ptr <cidr> [max]    reverse-DNS sweep of an allocation (/24 to /16)
  --all <domain>        tenant + buckets + apis
  --status-tsv          module status
  --menu                menu entry
  --selftest            run selftests
  --help                this message

Nothing here needs a credential. Every probe is an unauthenticated request to
a public endpoint, which is the point: a domain alone maps the org before any
credential is in hand. Every result is three-state — absent is not ok.

Environment: TE_TIMEOUT (8), TE_CONCURRENCY (6), TE_MAX_CANDIDATES (400)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
te_selftest() {
    cs_selftest_reset

    # domain surgery
    chk core-simple    "$(te_core example.com)"           "example"
    chk core-substation "$(te_core cloud.example.com)"    "example"
    chk core-co-uk     "$(te_core acme.co.uk)"            "acme"
    chk core-co-uk-sub "$(te_core api.acme.co.uk)"        "acme"
    chk core-com-au    "$(te_core thing.com.au)"          "thing"
    chk core-url       "$(te_core https://a.b.c/x?y=1)"   "b"
    chk core-upper     "$(te_core EXAMPLE.COM)"           "example"

    chk stem-simple    "$(te_stem example.com)"           "example"
    chk stem-sub       "$(te_stem cloud.example.com)"     "cloud.example"
    chk stem-co-uk     "$(te_stem acme.co.uk)"            "acme"
    chk stem-co-uk-sub "$(te_stem api.acme.co.uk)"        "api.acme"

    # candidate generation
    local n; n="$(te_candidates example.com | wc -l | tr -d ' ')"
    chk candidates-many "$( (( n > 50 )) && echo many || echo few )" "many"
    chk candidates-has-bare "$(te_candidates example.com | grep -cx 'example')" "1"
    chk candidates-has-backup "$(te_candidates example.com | grep -cx 'example-backup')" "1"
    chk candidates-has-dev "$(te_candidates example.com | grep -cx 'dev-example')" "1"
    chk candidates-unique "$(te_candidates example.com | sort | uniq -d | wc -l | tr -d ' ')" "0"
    # a hyphenated stem must also produce the dashless form
    chk candidates-dashless "$(te_candidates acme-widgets.com | grep -cx 'acmewidgets')" "1"

    # certificate-transparency name cleaning: a wildcard SAN becomes the base
    local ctres="$CS_SCRATCH/te-ct-$RUN_ID.txt"
    printf '*.acme.co.ke\tCA X\t2024-01-01T00:00:00\nacme.co.ke\tCA X\t2024-01-01T00:00:00\n' > "$ctres"
    chk ct-wildcard "$(awk -F'\t' '{sub(/^\*\./,"",$1); print $1}' "$ctres" | sort -u | grep -cx 'acme.co.ke')" "1"
    chk ct-rows     "$(te_blocks < <(printf 'a\t102.213.172.5\nb\t102.213.172.9\nc\t10.0.0.4\n') | grep -c '102.213.172.0/24')" "1"
    chk ct-blockn   "$(te_blocks < <(printf 'a\t102.213.172.5\nb\t102.213.172.9\n') | awk -F'\t' '{print $2}')" "2"
    chk ct-sample   "$(te_blocks < <(printf 'a\t102.213.172.5\n') | awk -F'\t' '{print $3}')" "a"

    # the PTR sweep refuses an empty target instead of sweeping the box
    te_cmd_ptr 2>/dev/null; chk ptr-usage "$?" "2"
    te_cmd_crt 2>/dev/null; chk crt-usage "$?" "2"

    # shape contracts
    chk status-fields "$(te_cmd_status_tsv | awk -F'\t' '{print NF}')" "3"
    chk status-module "$(te_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(te_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(te_cmd_help | head -1 | grep -ci 'Tenant')" "1"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --tenant)   shift; te_cmd_tenant "$@";;
    --buckets)  shift; te_cmd_buckets "$@";;
    --projects) shift; te_cmd_projects "$@";;
    --azure)    shift; te_cmd_azure "$@";;
    --apis)     shift; te_cmd_apis "$@";;
    --crt)      shift; te_cmd_crt "$@";;
    --ptr)      shift; te_cmd_ptr "$@";;
    --all)      shift; te_cmd_all "$@";;
    --status-tsv|--status) te_cmd_status_tsv;;
    --menu)     te_cmd_menu;;
    --selftest) te_selftest;;
    *)          te_cmd_help;;
esac
