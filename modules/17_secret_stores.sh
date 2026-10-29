#!/usr/bin/env bash
# 17_secret_stores.sh — cloudsting module 17: the secrets the platform already holds
# Verbs: --surface <url> | --enumerate [provider] | --read <provider:ref> | --classify <text> | --state | --providers | --paths | --status-tsv | --menu | --selftest
set -u
umask 077

# An inherited CS_MOD_DIR is a caller's directory; deriving it after the core
# is sourced is what keeps every loot path inside this checkout.
unset CS_MOD_DIR

MODULE_ID="17_secret_stores"
MOD_NAME="Secret Stores"
MOD_VERSION="0.1.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/secret_stores"
mkdir -p "$OUT_DIR" 2>/dev/null || true

SURFACE_FILE="$OUT_DIR/surface-$RUN_ID.tsv"
ENUM_FILE="$OUT_DIR/enumerate-$RUN_ID.tsv"

: "${SS_TIMEOUT:=8}"       # per-request wall clock
: "${SS_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/17}"
: "${SS_CLI_TIMEOUT:=45}"  # a cloud CLI is slow to cold-start

# ── helpers ──────────────────────────────────────────────────────
ss_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

ss_base() {
    local t="${1:-}"
    t="${t#http://}"; t="${t#https://}"; t="${t%%\?*}"; t="${t%%#*}"
    [[ -z "$t" ]] && return 0
    local scheme="https"
    case "${1:-}" in http://*) scheme="http" ;; esac
    t="${t%/}"
    [[ -z "$t" ]] && return 0
    printf '%s://%s' "$scheme" "$t"
}

ss_host() {
    local t="${1:-}"
    t="${t#http://}"; t="${t#https://}"; t="${t%%/*}"
    printf '%s' "$t"
}

# One GET. Sets the S_* globals and prints the five-field record; the surface
# walk reads the code and the body hash, not the body.
S_CODE=""; S_HASH=""; S_BYTES=""; S_CTYPE=""; S_ERR=""; S_BODY=""
ss_req() {
    local url="${1:-}"; shift
    local r code secs bytes hash ctype loc bp err
    local keep="${SS_HF:-}"
    r="$(CS_HTTP_HDR_OUT="$keep" cs_http GET "$url" -m "$SS_TIMEOUT" -A "$SS_UA" -P "$@")"
    cs_split "$r" code secs bytes hash ctype loc bp err
    S_BODY="${bp:-}"
    S_CODE="${code:-000}"; S_HASH="${hash:-}"; S_BYTES="${bytes:-0}"
    S_CTYPE="${ctype:-}"; S_ERR="${err:-}"
    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s' "$S_CODE" "$S_HASH" "$S_BYTES" "$S_CTYPE" "$S_ERR"
}

ss_drop_body() {
    [[ -n "${S_BODY:-}" && -f "${S_BODY:-}" ]] && rm -f "$S_BODY" 2>/dev/null
    S_BODY=""
}

# ── classification ───────────────────────────────────────────────
# A value is never printed: this module reports the shape, the length and a
# fingerprint. The whole point of stealing a secret is that you do not have to
# paste it into a report to prove you had it.
ss_classify() {
    local v="${1-}"
    [[ -z "$v" ]] && { printf 'empty'; return 0; }

    case "$v" in
        AKIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z])
            printf 'aws-access-key-id'; return 0 ;;
        ASIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z])
            printf 'aws-session-key-id'; return 0 ;;
        *"-----BEGIN"*"PRIVATE KEY-----"*) printf 'private-key'; return 0 ;;
        hvs.*|hvr.*)            printf 'vault-token'; return 0 ;;
        glpat-*)                printf 'gitlab-token'; return 0 ;;
        xox[abprs]-*)           printf 'slack-token'; return 0 ;;
        gh[pousr]_*)            printf 'github-token'; return 0 ;;
    esac

    # a JWT is three base64url segments with a JSON header
    if [[ "$v" =~ ^ey[A-Za-z0-9_-]{8,}\.ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$ ]]; then
        printf 'jwt'; return 0
    fi
    # a connection string carries the password inline, which is why it leaks
    if [[ "$v" =~ ^(postgres|postgresql|mysql|mariadb|mongodb|redis|rediss|amqp|amqps|sqlserver|mssql):// ]]; then
        if [[ "$v" =~ ^[a-z]+://[^:/@]+:[^@]+@ ]]; then
            printf 'connection-string-with-password'
        else
            printf 'connection-string'
        fi
        return 0
    fi
    if [[ "$v" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*://[^:/@]+:[^@]+@ ]]; then
        printf 'url-with-credentials'; return 0
    fi
    case "$v" in
        *AccountKey=*)          printf 'azure-storage-account-key'; return 0 ;;
        *"SharedAccessSignature"*) printf 'azure-sas-token'; return 0 ;;
        sk_live_*|rk_live_*)    printf 'stripe-live-key'; return 0 ;;
        sk-*)                   printf 'openai-style-key'; return 0 ;;
    esac
    # a JSON or YAML fragment that names a credential and gives it a value
    if [[ "$v" == *'{'*'}'* ]] && [[ "$v" =~ \"?(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)\"?[[:space:]]*[:=] ]]; then
        printf 'structured-secret-object'; return 0
    fi
    # a bare key-material blob. Hex is tested first: it is a subset of the
    # base64 charset, so the other order labels every hex key as base64.
    local n=${#v}
    if (( n >= 20 )) && [[ "$v" =~ ^[A-Fa-f0-9]+$ ]]; then
        printf 'hex-key-material'; return 0
    fi
    if (( n >= 32 )) && [[ "$v" =~ ^[A-Za-z0-9+/=_-]+$ ]]; then
        printf 'base64-key-material'; return 0
    fi
    printf 'opaque-value'
}

ss_is_secret_shape() {
    case "$(ss_classify "${1-}")" in
        opaque-value|empty|structured-secret-object) return 1 ;;
        *) return 0 ;;
    esac
}

# Keys inside a leaked config document that name a credential. Only the key is
# ever printed — the value is what the report is supposed to withhold.
ss_secret_keys() {
    local f="${1:-}"
    [[ -s "$f" ]] || return 0
    tr -d '\r' < "$f" 2>/dev/null \
        | grep -oiE '(^|[^a-z0-9_.-])([a-z0-9_.-]*(password|passwd|secret|token|apikey|api[_-]key|access[_-]key|private[_-]key|credentials?)[a-z0-9_.-]*)' \
        | sed 's/^[^a-z0-9_.-]//' \
        | tr 'A-Z' 'a-z' \
        | sort -u
}

# ── the provider table ───────────────────────────────────────────
# id  store  cli  what the credential has to be  list verb  read verb
ss_providers() {
    printf 'aws-secretsmanager\tAWS Secrets Manager\taws\taccess key or instance role\taws secretsmanager list-secrets\taws secretsmanager get-secret-value --secret-id %%s\n'
    printf 'aws-ssm\tAWS SSM Parameter Store\taws\taccess key or instance role\taws ssm describe-parameters\taws ssm get-parameter --name %%s --with-decryption\n'
    printf 'gcp-secretmanager\tGCP Secret Manager\tgcloud\tservice account or metadata token\tgcloud secrets list\tgcloud secrets versions access latest --secret=%%s\n'
    printf 'azure-keyvault\tAzure Key Vault\taz\tvault data-plane role\taz keyvault secret list --vault-name %%s\taz keyvault secret show --vault-name %%s --name %%s\n'
    printf 'oci-vault\tOCI Vault\toci\tinstance principal or user key\toci vault secret list-bundle\toci vault secret-bundle get --secret-id %%s\n'
    printf 'k8s-secrets\tKubernetes Secrets\tkubectl\tservice account token or kubeconfig\tkubectl get secrets -A\tkubectl get secret %%s -o jsonpath={.data}\n'
    printf 'vault-kv\tHashiCorp Vault (CLI)\tvault\ttoken or approle login\tvault kv list %%s\tvault kv get -format=json %%s\n'
    printf 'vault-http\tHashiCorp Vault (HTTP)\tcurl\ttoken in X-Vault-Token\tGET /v1/%%s\tGET /v1/%%s\n'
    printf 'doppler\tDoppler CLI\tdoppler\tservice token\tdoppler secrets --json\tdoppler secrets get %%s --plain\n'
    printf 'infisical\tInfisical CLI\tinfisical\tservice token\tinfisical secrets\tinfisical secrets get %%s\n'
    printf 'conjur\tCyberArk Conjur\tcurl\thost identity or api key\tGET /secrets\tGET /secrets/%%s\n'
    printf 'sops-file\tSOPS-encrypted file\tsops\tKMS key or age identity\tsops -d %%s\tsops -d %%s\n'
}

ss_provider_row() {
    ss_providers | awk -F'\t' -v id="${1:-}" '$1==id'
}

ss_provider_ids() { ss_providers | cut -f1; }

ss_cli_state() {
    local cli="${1:-}"
    # a provider whose surface is plain HTTP needs no CLI
    case "$cli" in
        curl) cs_have curl && printf 'present' || printf 'missing'; return 0 ;;
    esac
    cs_have "$cli" && printf 'present' || printf 'missing'
}

# Three states, and "no credential" is not "no permission": the difference
# decides whether the next step is a privilege-escalation problem or a
# provisioning problem.
ss_cred_state() {
    local id="${1:-}"
    local ok=0 absent=0
    case "$id" in
        aws-*)
            [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] && ok=1
            [[ -r "${AWS_SHARED_CREDENTIALS_FILE:-$HOME/.aws/credentials}" ]] && ok=1
            [[ -n "${AWS_PROFILE:-}" ]] && ok=1
            [[ -n "${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:-}${AWS_WEB_IDENTITY_TOKEN_FILE:-}" ]] && ok=1
            absent=1 ;;
        gcp-secretmanager)
            [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]] && ok=1
            [[ -r "$HOME/.config/gcloud/application_default_credentials.json" ]] && ok=1
            absent=1 ;;
        azure-keyvault)
            [[ -n "${AZURE_CLIENT_ID:-}" ]] && ok=1
            [[ -r "$HOME/.azure/azureProfile.json" ]] && ok=1
            absent=1 ;;
        oci-vault)
            [[ -n "${OCI_CLI_TENANCY:-}" ]] && ok=1
            [[ -r "$HOME/.oci/config" ]] && ok=1
            absent=1 ;;
        k8s-secrets)
            [[ -n "${KUBECONFIG:-}" && -r "${KUBECONFIG%%:*}" ]] && ok=1
            [[ -r "$HOME/.kube/config" ]] && ok=1
            absent=1 ;;
        vault-kv|vault-http)
            [[ -n "${VAULT_TOKEN:-}" ]] && ok=1
            [[ -r "$HOME/.vault-token" ]] && ok=1
            absent=1 ;;
        doppler)
            [[ -n "${DOPPLER_TOKEN:-}" ]] && ok=1
            absent=1 ;;
        infisical)
            [[ -n "${INFISICAL_TOKEN:-}" ]] && ok=1
            absent=1 ;;
        conjur)
            [[ -n "${CONJUR_AUTHN_API_KEY:-}" ]] && ok=1
            absent=1 ;;
        *)
            absent=1 ;;
    esac
    if [[ $ok -eq 1 ]]; then printf 'ok'
    elif [[ $absent -eq 1 ]]; then printf 'absent'
    else printf 'unknown'
    fi
}

# ── the unauthenticated surface ──────────────────────────────────
# Every HTTP-native store answers at least one path without a token, and that
# is by design for some of them. So each path carries what a healthy answer
# looks like: a 403 is the store working, a 200 with content is the store
# leaking.
ss_paths() {
    printf 'vault\t/v1/sys/health\thealth\texpect-deny\tanonymous health is normal; 501 uninitialised, 503 sealed\n'
    printf 'vault\t/v1/sys/seal-status\tseal\texpect-deny\tinitialised, sealed and shamir progress in one answer\n'
    printf 'vault\t/v1/sys/leader\tleader\texpect-deny\tleader address and cluster name\n'
    printf 'vault\t/v1/sys/mounts\tmounts\texpect-403\tmount table: the roadmap of the store\n'
    printf 'vault\t/v1/sys/policies/acl\tpolicies\texpect-403\tpolicy names, one per line\n'
    printf 'vault\t/v1/sys/auth\tauth\texpect-403\tenabled auth methods and their config\n'
    printf 'vault\t/v1/sys/audit\taudit\texpect-403\taudit devices, or their absence\n'
    printf 'vault\t/v1/auth/token/lookup-self\ttoken\texpect-403\tvalidates any token that arrives, including a stolen one\n'
    printf 'vault\t/v1/secret/data/\tkv\texpect-403\tKV v2 store listing\n'
    printf 'vault\t/v1/secret/metadata/\tkvmeta\texpect-403\tversion history and deletion state\n'
    printf 'config\t/application/default\tprops\texpect-403\tSpring Cloud Config: every property for every app\n'
    printf 'config\t/application/default/main\tprops-main\texpect-403\tsame, on the main branch\n'
    printf 'config\t/application/default/master\tprops-master\texpect-403\tsame, on master\n'
    printf 'config\t/application/dev\tprops-dev\texpect-403\tthe profile nobody locks down\n'
    printf 'config\t/encrypt/status\tencrypt\texpect-200\treports whether the server can decrypt, not what\n'
    printf 'config\t/actuator/env\tenv\texpect-403\tproperty sources including the git uri\n'
    printf 'conjur\t/secrets\tconjur\texpect-403\tCyberArk Conjur resource listing\n'
    printf 'conjur\t/info\tinfo\texpect-200\tConjur version, which is a fingerprint not a secret\n'
}

ss_path_family() {
    ss_paths | awk -F'\t' -v f="${1:-}" '$1==f'
}

# A catch-all host answers every path with 200 and must never be read as a
# leaking store. Two paths that no store serves are the control.
ss_control_paths() {
    printf '/cloudsting-control-000/nothing-here\n'
    printf '/cloudsting-control-001/nothing-here-either\n'
}

# ── verbs ────────────────────────────────────────────────────────
ss_cmd_providers() {
    printf 'PROVIDER\tSTORE\tCLI\tCREDENTIAL\tLIST\n'
    ss_providers | awk -F'\t' 'BEGIN{OFS="\t"}{print $1,$2,$3,$4,$5}'
}

ss_cmd_state() {
    printf 'PROVIDER\tCLI\tCLI-STATE\tCRED-STATE\tREADY\n'
    local id cli clis creds ready
    while IFS=$'\036' read -r id _store cli _cred _list _read; do
        [[ -z "$id" ]] && continue
        clis="$(ss_cli_state "$cli")"
        creds="$(ss_cred_state "$id")"
        case "$clis:$creds" in
            present:ok)   ready="yes" ;;
            present:*)    ready="no-credential" ;;
            missing:ok)   ready="no-cli" ;;
            *)            ready="no" ;;
        esac
        printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$cli" "$clis" "$creds" "$ready"
    done < <(ss_providers | tr '\t' '\036')
}

# The list verb per provider, run only when the credential is actually there.
# Absence is reported as a state, never as "nothing found".
ss_cmd_enumerate() {
    local want="${1:-}"
    # A filter that matches nothing used to produce an empty listing, which
    # reads exactly like "clean". Refuse instead.
    if [[ -n "$want" ]] && ! ss_provider_ids | grep -qx "$want"; then
        if ss_provider_ids | grep -q -- "$want"; then
            want="$(ss_provider_ids | grep -- "$want" | head -1)"
            ss_log "provider filter matched by substring: $want"
        else
            printf 'ERROR\tunknown provider filter: %s\n' "$want" >&2
            return 2
        fi
    fi
    printf 'PROVIDER\tSTATE\tCOUNT\tSAMPLE\n'
    : > "$ENUM_FILE"
    local id store cli cred listv readv clis creds st count sample out rc
    while IFS=$'\036' read -r id store cli cred listv readv; do
        [[ -z "$id" ]] && continue
        [[ -n "$want" && "$want" != "$id" ]] && continue
        clis="$(ss_cli_state "$cli")"
        creds="$(ss_cred_state "$id")"
        if [[ "$clis" != "present" ]]; then
            printf '%s\tSKIP\t0\tno-cli: %s is not installed\n' "$id" "$cli"
            continue
        fi
        if [[ "$creds" != "ok" ]]; then
            printf '%s\tSKIP\t0\tno-credential: %s\n' "$id" "$creds"
            continue
        fi
        # azure needs a vault name before it can list anything, so it is
        # listed two-level and reported as such
        if [[ "$id" == "azure-keyvault" ]]; then
            printf '%s\tTWO-LEVEL\t0\tlist vaults first: az keyvault list\n' "$id"
            continue
        fi
        out="$(timeout "$SS_CLI_TIMEOUT" $listv 2>"$OUT_DIR/.err.$$" )"; rc=$?
        if (( rc != 0 )); then
            st="$(head -3 "$OUT_DIR/.err.$$" 2>/dev/null | tr '\n' ' ' | tr -s ' ')"
            printf '%s\tDENIED\t0\t%s\n' "$id" "${st:-exit $rc}"
            cs_findings_row "$MODULE_ID" "CREDS" "$store" "low-secretstore-denied-$id" \
                "the credential reached $id and was refused: ${st:-exit $rc}" > /dev/null
            rm -f "$OUT_DIR/.err.$$" 2>/dev/null
            continue
        fi
        rm -f "$OUT_DIR/.err.$$" 2>/dev/null
        count="$(printf '%s' "$out" | ss_names "$id" | tee -a "$ENUM_FILE" | wc -l | tr -d ' ')"
        sample="$(ss_names_from_file "$ENUM_FILE" | head -2 | tr '\n' ',' | sed 's/,$//')"
        printf '%s\tOK\t%s\t%s\n' "$id" "$count" "$sample"
        if (( count > 0 )); then
            cs_findings_row "$MODULE_ID" "CREDS" "$store" "high-secretstore-readable" \
                "$count secret(s) listable with the current $id credential: ${sample}" > /dev/null
        fi
    done < <(ss_providers | tr '\t' '\036')
    printf 'DETAIL\t%s\n' "$ENUM_FILE"
}

ss_names_from_file() { awk 'NF{print}' "${1:-/dev/null}" 2>/dev/null; }

# One name per line out of whatever shape the CLI returns. The candidates are
# ordered: the first list that exists wins, so a nested "name" does not get
# mixed in with the top-level one.
ss_names() {
    local id="${1:-}"
    local raw; raw="$(cat)"
    [[ -z "$raw" ]] && return 0
    if cs_have python3; then
        printf '%s' "$raw" | python3 -c '
import json,sys
raw=sys.stdin.read().strip()
try: d=json.loads(raw)
except Exception:
    for line in raw.splitlines():
        line=line.strip()
        if line and not line.startswith("{"): print(line)
    raise SystemExit(0)
def walk(d):
    if isinstance(d,dict):
        for k in ("SecretList","Parameters","items","data","results","secrets","vaults"):
            if k in d and isinstance(d[k],list):
                return d[k]
        for k in ("secrets","items"): pass
        return [d]
    return d if isinstance(d,list) else [d]
rows=walk(d)
for r in rows:
    if isinstance(r,str): print(r); continue
    if not isinstance(r,dict): continue
    for k in ("ARN","arn","Name","name","secret-name","secretName","id","id_name"):
        v=r.get(k)
        if isinstance(v,str) and v: print(v); break
    else:
        md=r.get("metadata")
        if isinstance(md,dict) and isinstance(md.get("name"),str): print(md["name"])
' 2>/dev/null | sort -u
        return 0
    fi
    printf '%s' "$raw" | grep -oE '"?(ARN|arn|Name|name|secret-name|id)"?[[:space:]]*:[[:space:]]*"[^"]+"' \
        | sed 's/.*:[[:space:]]*"//; s/"$//' | sort -u
}

# Read one secret and never print it. The report is the shape, the length and
# a fingerprint; that is enough to prove access and useless to a reader who
# should not have it.
ss_cmd_read() {
    local ref="${1:-}"
    if [[ -z "$ref" ]]; then
        printf 'usage: --read <provider:reference>\n' >&2
        return 2
    fi
    local id="${ref%%:*}" arg="${ref#*:}"
    if [[ "$id" == "$ref" ]]; then
        printf 'ERROR\tno provider prefix: use provider:reference\n' >&2
        return 2
    fi
    local row; row="$(ss_provider_row "$id")"
    if [[ -z "$row" ]]; then
        printf 'ERROR\tunknown provider: %s\n' "$id" >&2
        return 2
    fi
    local store cli cred listv readv
    IFS=$'\036' read -r _ store cli cred listv readv <<< "$(ss_providers | awk -F'\t' -v i="$id" '$1==i' | tr '\t' '\036')"
    local clis; clis="$(ss_cli_state "$cli")"
    if [[ "$clis" != "present" ]]; then
        printf 'SKIP\t%s\tno-cli: %s\n' "$id" "$cli"
        return 0
    fi
    local creds; creds="$(ss_cred_state "$id")"
    if [[ "$creds" != "ok" ]]; then
        printf 'SKIP\t%s\tno-credential: %s\n' "$id" "$creds"
        return 0
    fi
    # vault-http and conjur are fetched over the wire, not by a CLI
    local value rc
    case "$id" in
        vault-http)
            local addr="${VAULT_ADDR:-}"; [[ -z "$addr" ]] && { printf 'SKIP\t%s\tno-credential: VAULT_ADDR unset\n' "$id"; return 0; }
            ss_req "${addr%/}/v1/$arg" -H "X-Vault-Token: ${VAULT_TOKEN:-}" > /dev/null
            rc=$?
            if [[ "$S_CODE" != "200" ]]; then
                printf 'DENIED\t%s\tHTTP %s\n' "$id" "$S_CODE"
                ss_drop_body
                return 0
            fi
            value="$(cat "$S_BODY" 2>/dev/null)"
            ss_drop_body
            ;;
        conjur)
            ss_req "${CONJUR_APPLIANCE_URL:-}/secrets/$arg" -H "Authorization: Token token=\"${CONJUR_AUTHN_API_KEY:-}\"" > /dev/null
            if [[ "$S_CODE" != "200" ]]; then
                printf 'DENIED\t%s\tHTTP %s\n' "$id" "$S_CODE"; ss_drop_body; return 0
            fi
            value="$(cat "$S_BODY" 2>/dev/null)"; ss_drop_body
            ;;
        *)
            local cmd; cmd="$(printf "$readv" "$arg")"
            value="$(timeout "$SS_CLI_TIMEOUT" $cmd 2>/dev/null)"; rc=$?
            if (( rc != 0 )) || [[ -z "$value" ]]; then
                printf 'DENIED\t%s\texit %s\n' "$id" "$rc"
                return 0
            fi
            ;;
    esac
    local shape sha len
    shape="$(ss_classify "$value")"
    sha="$(cs_fingerprint "$value")"
    len="${#value}"
    printf 'SECRET\t%s\t%s\tshape=%s\tlen=%s\tsha1=%s\n' "$id" "$arg" "$shape" "$len" "$sha"
    unset value
    if ss_is_secret_shape "$shape"; then
        cs_findings_row "$MODULE_ID" "CREDS" "$store" "high-secret-readable" \
            "$id/$arg is readable and looks like $shape (len $len, sha1 $sha)" > /dev/null
    fi
}

ss_cmd_classify() {
    local text="${1:-}"
    if [[ -z "$text" ]]; then
        # stdin, one value per line: a file of candidates is the normal input
        local line n=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            n=$((n+1))
            printf 'VALUE\t%s\tshape=%s\tlen=%s\tsha1=%s\n' "$n" "$(ss_classify "$line")" "${#line}" "$(cs_fingerprint "$line")"
        done
        return 0
    fi
    printf 'VALUE\t1\tshape=%s\tlen=%s\tsha1=%s\n' "$(ss_classify "$text")" "${#text}" "$(cs_fingerprint "$text")"
}

# The two stores that are plain HTTP are the two that get exposed, so the
# surface walk is a control-first scan: a path no store serves, then the
# catalogue, and only a body that differs from the control counts.
ss_cmd_surface() {
    local target="${1:-}"
    local base; base="$(ss_base "$target")"
    if [[ -z "$base" ]]; then
        printf 'usage: --surface <url>\n' >&2
        return 2
    fi
    printf 'SURFACE\t%s\t%s\n' "$base" "$(ss_host "$base")"
    : > "$SURFACE_FILE"

    # ── control ──
    local ctl_hash="" ctl_code="" ctl_2xx="no"
    while read -r p; do
        [[ -z "$p" ]] && continue
        ss_req "$base$p" > /dev/null
        ctl_code="$S_CODE"; ctl_hash="$S_HASH"
        case "$ctl_code" in 2??) ctl_2xx="yes" ;; esac
        ss_drop_body
        printf 'CONTROL\t%s\t%s\t%s\n' "$p" "$ctl_code" "$ctl_hash" | tee -a "$SURFACE_FILE"
    done < <(ss_control_paths)
    if [[ "$ctl_2xx" == "yes" ]]; then
        printf 'WARN\tcontrol-is-2xx\tthe host answers a path no store serves, so no path below is evidence\n'
    fi

    local fam path label expect note got=""
    while IFS=$'\036' read -r fam path label expect note; do
        [[ -z "$path" ]] && continue
        ss_req "$base$path" > /dev/null
        local code="$S_CODE" hash="$S_HASH" bytes="$S_BYTES" ctype="$S_CTYPE" err="$S_ERR"
        local bodyfile="$S_BODY"; S_BODY=""
        local verdict="no"
        if [[ "$code" == "000" ]]; then
            verdict="unreachable"
        elif [[ "$ctl_2xx" == "yes" && "$code" == "$ctl_code" && "$hash" == "$ctl_hash" ]]; then
            # the control itself answered 2xx and this path looks the same, so
            # the host serves every path: nothing here is evidence
            verdict="catch-all"
        elif [[ "$code" == "403" || "$code" == "401" ]]; then
            # a refusal is the healthy answer for a locked path
            verdict="denied"
        elif [[ "$code" == "200" ]]; then
            case "$expect" in
                expect-200) verdict="expected" ;;
                *)          verdict="exposed" ;;
            esac
        elif [[ "$code" == "$ctl_code" && "$hash" == "$ctl_hash" ]]; then
            # same answer as a path no store serves: this store is not here
            verdict="absent"
        else
            verdict="code-$code"
        fi
        printf 'PATH\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$fam" "$label" "$path" "$code" "$bytes" "$hash" "$verdict" "$note" >> "$SURFACE_FILE"
        printf 'PATH\t%s\t%s\t%s\t%s\t%s\n' "$fam" "$label" "$code" "$bytes" "$verdict"

        if [[ "$verdict" == "exposed" ]]; then
            got="$got $label"
            case "$fam:$label" in
                vault:mounts|vault:policies|vault:auth|vault:audit)
                    cs_findings_row "$MODULE_ID" "CREDS" "$base$path" "critical-vault-anonymous-admin" \
                        "Vault answers $label without a token — the mount table and its policies are enumerable anonymously" > /dev/null ;;
                vault:kv|vault:kvmeta)
                    cs_findings_row "$MODULE_ID" "CREDS" "$base$path" "critical-vault-anonymous-kv" \
                        "Vault KV answers without a token — secret values are readable anonymously" > /dev/null ;;
                vault:seal|vault:leader|vault:health)
                    cs_findings_row "$MODULE_ID" "CREDS" "$base$path" "low-vault-status-public" \
                        "Vault publishes $label anonymously: initialisation, seal state and cluster name" > /dev/null ;;
                config:props|config:props-main|config:props-master|config:props-dev|config:env)
                    local keys; keys="$(ss_secret_keys "$bodyfile" | head -6 | tr '\n' ',' | sed 's/,$//')"
                    local gituri; gituri="$(grep -oiE 'https?://[^"[:space:]]*@[^"[:space:]]*' "$bodyfile" 2>/dev/null | head -1)"
                    if [[ -n "$gituri" ]]; then
                        cs_findings_row "$MODULE_ID" "CREDS" "$base$path" "critical-config-server-git-credentials" \
                            "the config server echo includes a git uri with embedded credentials ($(cs_redact "$gituri"))" > /dev/null
                    fi
                    if [[ -n "$keys" ]]; then
                        cs_findings_row "$MODULE_ID" "CREDS" "$base$path" "critical-config-server-secret-leak" \
                            "config server returns property sources naming credentials: $keys" > /dev/null
                    else
                        cs_findings_row "$MODULE_ID" "CREDS" "$base$path" "high-config-server-property-leak" \
                            "config server returns every property for every application, unauthenticated" > /dev/null
                    fi ;;
                conjur:conjur)
                    cs_findings_row "$MODULE_ID" "CREDS" "$base$path" "high-conjur-anonymous" \
                        "CyberArk Conjur resource listing answers without a host identity" > /dev/null ;;
                *)
                    cs_findings_row "$MODULE_ID" "CREDS" "$base$path" "high-store-endpoint-public" \
                        "$label answers without authentication" > /dev/null ;;
            esac
        fi
        ss_drop_body >/dev/null 2>&1
        rm -f "$bodyfile" 2>/dev/null
    done < <(ss_paths | tr '\t' '\036')

    if [[ "$ctl_2xx" == "yes" ]]; then
        printf 'VERDICT\tnot-evidence:control-answers-anything\n'
    elif [[ -z "$got" ]]; then
        printf 'VERDICT\tnothing-exposed\n'
    else
        printf 'VERDICT\texposed:%s\n' "$(printf '%s' "$got" | tr ' ' ',' | sed 's/^,//')"
    fi
    printf 'DETAIL\t%s\n' "$SURFACE_FILE"
}

ss_cmd_paths() {
    printf 'FAMILY\tLABEL\tPATH\tEXPECT\tNOTE\n'
    ss_paths | awk -F'\t' 'BEGIN{OFS="\t"}{print $1,$3,$2,$4,$5}'
}

ss_cmd_status_tsv() {
    local c; cs_have curl && c="ok" || c="missing"
    printf '%s\t%s\tcurl-%s\tproviders-%s\tpaths-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$c" \
        "$(ss_providers | wc -l | tr -d ' ')" \
        "$(ss_paths | wc -l | tr -d ' ')"
}

ss_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ss_cmd_help() {
    cat <<'HELP'
cloudsting module 17 — Secret Stores v0.1.0
  --surface   <url>           probe the unauthenticated surface of a Vault or
                              Spring Cloud Config server, control path first
  --enumerate [provider]      list secrets with the credentials on this box
  --read      <provider:ref>  fetch one secret: shape, length and fingerprint,
                              never the value
  --classify  [text]          name what a string looks like (or read stdin lines)
  --state                     three-state per provider: cli, credential, ready
  --providers                 the store table this module knows
  --paths                     the HTTP path catalogue and the healthy answer
  --status-tsv                module status
  --menu                      menu entry
  --selftest                  run selftests
  --help                      this message

The premise: once instance metadata is closed and the operators are not
phishing material, the credentials are still somewhere — a managed store that
the workload reads at boot. Two ways in. The credential already on this box can
often list the store outright, which is an authorization finding rather than a
key finding. And both HTTP-native stores, Vault and Spring Cloud Config, are
routinely reachable without a token, in which case the mount table, the policy
names and the application properties are all readable.

Every path is scored against a control path that no store serves. A host that
answers everything with 200 is reported as a catch-all and proves nothing: the
same answer is what an unprotected static site gives. "Denied" is the healthy
answer for a locked path and is never recorded as a finding. A missing CLI or a
missing credential is reported as a state, never as "nothing found".

Nothing here prints a secret value. `--read` reports shape, length and a sha1
fingerprint; `--surface` reports the names of the properties that carry
credentials and redacts the values.

Environment: SS_TIMEOUT (8), SS_UA, SS_CLI_TIMEOUT (45)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ss_selftest() {
    cs_selftest_reset
    local real_loot="$CS_LOOT"
    CS_LOOT="$CS_SCRATCH"
    mkdir -p "$CS_LOOT"

    # ── the provider table ──
    local np; np="$(ss_providers | wc -l | tr -d ' ')"
    chk prov-many   "$( (( np >= 12 )) && echo many || echo few )" "many"
    chk prov-6col   "$(ss_providers | awk -F'\t' 'NF!=6{c++} END{print c+0}')" "0"
    chk prov-unique "$(ss_provider_ids | sort -u | wc -l | tr -d ' ')" "$np"
    # the five biggest clouds are all present, and each names its CLI
    local id
    for id in aws-secretsmanager gcp-secretmanager azure-keyvault oci-vault k8s-secrets; do
        chk "prov-$id" "$(ss_provider_row "$id" | cut -f2)" "$(ss_provider_row "$id" | cut -f2)"
        chk "prov-$id-cli" "$( [[ -n "$(ss_provider_row "$id" | cut -f3)" ]] && echo yes || echo no )" "yes"
    done
    chk prov-vault-http "$(ss_provider_row vault-http | cut -f3)" "curl"
    chk prov-unknown    "$(ss_provider_row nope | wc -l | tr -d ' ')" "0"

    # ── the path catalogue ──
    local npth; npth="$(ss_paths | wc -l | tr -d ' ')"
    chk paths-many   "$( (( npth >= 16 )) && echo many || echo few )" "many"
    chk paths-5col   "$(ss_paths | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk paths-slash  "$(ss_paths | awk -F'\t' '$2!~/^\//{c++} END{print c+0}')" "0"
    chk paths-vault  "$(ss_path_family vault | wc -l | tr -d ' ' | awk '{print ($1>=8)?"many":"few"}')" "many"
    chk paths-config "$(ss_path_family config | wc -l | tr -d ' ' | awk '{print ($1>=4)?"many":"few"}')" "many"
    # the mount table is the one path that must be 403 on a healthy server
    chk paths-mounts-exp "$(ss_paths | awk -F'\t' '$3=="mounts"{print $4}')" "expect-403"
    chk paths-encrypt   "$(ss_paths | awk -F'\t' '$3=="encrypt"{print $4}')" "expect-200"
    # a control path has to be a path no store serves
    chk ctl-count  "$(ss_control_paths | wc -l | tr -d ' ')" "2"
    chk ctl-shape  "$(ss_control_paths | grep -c 'cloudsting-control')" "2"

    # ── classification, which is the part every other verb leans on ──
    chk cls-empty    "$(ss_classify '')" "empty"
    chk cls-aws-akid "$(ss_classify 'AKIAIOSFODNN7EXAMPLE')" "aws-access-key-id"
    chk cls-aws-asia "$(ss_classify 'ASIAIOSFODNN7EXAMPLE')" "aws-session-key-id"
    chk cls-not-aws "$(ss_classify 'AKIA-short')" "opaque-value"
    chk cls-privkey  "$(ss_classify '-----BEGIN RSA PRIVATE KEY-----
MIIEow')" "private-key"
    chk cls-jwt      "$(ss_classify 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop')" "jwt"
    chk cls-pg       "$(ss_classify 'postgres://bss:hunter2@db.internal:5432/bss')" "connection-string-with-password"
    chk cls-mongo    "$(ss_classify 'mongodb://admin:pw@mongo:27017/x')" "connection-string-with-password"
    chk cls-pg-noPw  "$(ss_classify 'postgres://db.internal:5432/bss')" "connection-string"
    chk cls-vaulttok "$(ss_classify 'hvs.CAESIJabcdefghijklmnop')" "vault-token"
    chk cls-gh       "$(ss_classify 'ghp_abcdefghijklmnopqrstuvwxyz0123456789')" "github-token"
    chk cls-gitlab   "$(ss_classify 'glpat-abcdefghijklmnopqrst')" "gitlab-token"
    chk cls-slack    "$(ss_classify 'xoxb-1234-5678-abcdef')" "slack-token"
    chk cls-azure    "$(ss_classify 'DefaultEndpointsProtocol=https;AccountKey=abcdefgh')" "azure-storage-account-key"
    chk cls-b64      "$(ss_classify 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=')" "base64-key-material"
    chk cls-hex      "$(ss_classify 'a3f5c9e1b7d20486a3f5c9e1b7d20486')" "hex-key-material"
    chk cls-json     "$(ss_classify '{"username":"bss","password":"hunter2"}')" "structured-secret-object"
    chk cls-url-creds "$(ss_classify 'https://oauth2:tok3n@gitlab.internal/x.git')" "url-with-credentials"
    # a shape is a secret when it is key material, not when it is a config blob
    chk cls-secret-yes "$(ss_is_secret_shape 'AKIAIOSFODNN7EXAMPLE' && echo yes || echo no)" "yes"
    chk cls-secret-no  "$(ss_is_secret_shape 'just-a-note' && echo yes || echo no)" "no"
    chk cls-secret-empty "$(ss_is_secret_shape '' && echo yes || echo no)" "no"

    # ── keys out of a leaked document, values never printed ──
    local doc="$CS_SCRATCH/ss-doc.properties"
    cat > "$doc" <<'PROPS'
spring.datasource.url=jdbc:postgresql://db:5432/bss
spring.datasource.username=bss
spring.datasource.password=hunter2
bss.payment.api-key=live_abc123
spring.cloud.config.server.git.uri=https://oauth2:ghp_secret@git.internal/cfg.git
logging.level.root=INFO
PROPS
    local keys; keys="$(ss_secret_keys "$doc")"
    chk keys-found   "$(printf '%s\n' "$keys" | grep -c 'datasource.password')" "1"
    chk keys-apikey  "$(printf '%s\n' "$keys" | grep -c 'api-key')" "1"
    chk keys-no-plain "$(printf '%s\n' "$keys" | grep -c '^logging.level.root$')" "0"
    # the leak report is a list of names, so the value must not ride along
    chk keys-no-value "$(printf '%s' "$keys" | grep -c 'hunter2')" "0"

    # ── three states, and absence is not zero ──
    chk cli-curl  "$(ss_cli_state curl)" "present"
    chk cli-fake  "$(ss_cli_state cloudsting-no-such-cli)" "missing"
    # an unset credential is "absent", never "no permission"
    local saved
    saved="${AWS_ACCESS_KEY_ID:-__unset__}"
    ( unset AWS_ACCESS_KEY_ID AWS_PROFILE AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_WEB_IDENTITY_TOKEN_FILE
      HOME="$CS_SCRATCH/nohome" AWS_SHARED_CREDENTIALS_FILE="$CS_SCRATCH/none" ss_cred_state aws-secretsmanager ) > "$CS_SCRATCH/ss-cred" 2>/dev/null
    chk cred-absent "$(cat "$CS_SCRATCH/ss-cred")" "absent"
    ( unset AZURE_CLIENT_ID; HOME="$CS_SCRATCH/nohome" ss_cred_state azure-keyvault ) > "$CS_SCRATCH/ss-cred2" 2>/dev/null
    chk cred-azure-absent "$(cat "$CS_SCRATCH/ss-cred2")" "absent"
    chk cred-unknown-iface "$(ss_cred_state not-a-provider)" "absent"
    # state rows must distinguish CLI-missing from credential-missing
    chk state-header "$(ss_cmd_state | head -1 | awk -F'\t' '{print NF}')" "5"
    chk state-rows   "$(ss_cmd_state | tail -n +2 | wc -l | tr -d ' ')" "$np"
    chk state-no-cred "$(ss_cmd_state | awk -F'\t' '$5=="no-credential"{c++} END{print (c>0)?"yes":"no"}')" "yes"

    # ── argument handling ──
    local rc
    ss_cmd_read 2>/dev/null
    rc=$?
    chk read-noarg "$rc" "2"
    ss_cmd_read noprefix 2>/dev/null; rc=$?
    chk read-noprefix "$rc" "2"
    ss_cmd_read nosuch:x 2>/dev/null; rc=$?
    chk read-unknown "$rc" "2"
    # a reachable-but-uncredentialed provider is skipped, not called empty
    ( unset VAULT_ADDR VAULT_TOKEN; HOME="$CS_SCRATCH/nohome" ss_cmd_read vault-http:secret/data/x ) > "$CS_SCRATCH/ss-skip" 2>/dev/null
    chk read-skip "$(cut -f1 "$CS_SCRATCH/ss-skip")" "SKIP"

    # ── name extraction out of each CLI's JSON shape ──
    # This parser is the one place a silent miss looks like a clean store, so
    # every provider shape is pinned here.
    chk names-aws-sm "$(printf '{"SecretList":[{"ARN":"arn:x:secret:prod/db"}]}' | ss_names aws-secretsmanager)" "arn:x:secret:prod/db"
    chk names-aws-ssm "$(printf '{"Parameters":[{"Name":"/prod/db/password"}]}' | ss_names aws-ssm)" "/prod/db/password"
    chk names-k8s "$(printf '{"items":[{"metadata":{"name":"db-creds"}}]}' | ss_names k8s-secrets)" "db-creds"
    chk names-gcp-list "$(printf '["projects/p/secrets/a","projects/p/secrets/b"]' | ss_names gcp-secretmanager | wc -l | tr -d ' ')" "2"
    chk names-oci "$(printf '{"data":[{"secret-name":"prod-db"}]}' | ss_names oci-vault)" "prod-db"
    chk names-vault-plain "$(printf 'db-prod\njwt-signing\n' | ss_names vault-kv | wc -l | tr -d ' ')" "2"
    chk names-empty "$(printf '' | ss_names aws-secretsmanager | wc -l | tr -d ' ')" "0"
    chk names-nested-not-mixed "$(printf '{"SecretList":[{"ARN":"arn:one"}]}' | ss_names aws-secretsmanager | grep -c 'arn:one')" "1"

    # ── the filter, which must never answer "nothing" when it matched nothing ──
    local rc2
    ss_cmd_enumerate zzz-no-such-provider >/dev/null 2>&1
    rc2=$?
    chk enum-badfilter "$rc2" "2"
    chk enum-narrow "$(ss_cmd_enumerate ssm 2>/dev/null | grep -c '^aws-ssm')" "1"
    chk enum-header "$(ss_cmd_enumerate 2>/dev/null | head -1 | awk -F'\t' '{print NF}')" "4"

    # ── classify over stdin ──
    printf 'AKIAIOSFODNN7EXAMPLE\nhunter2\n' > "$CS_SCRATCH/ss-in"
    chk classify-stdin "$(ss_cmd_classify < "$CS_SCRATCH/ss-in" | wc -l | tr -d ' ')" "2"
    chk classify-row   "$(ss_cmd_classify 'AKIAIOSFODNN7EXAMPLE' | awk -F'\t' '{print NF}')" "5"
    # the fingerprint is stable and the value is not in the row
    chk classify-noval "$(ss_cmd_classify 'hunter2hunter2hunter2' | grep -c 'hunter2')" "0"
    chk classify-sha   "$(ss_cmd_classify 'abc' | awk -F'\t' '{print $5}' | grep -cE '^sha1=[0-9a-f]{12}$')" "1"

    # ── shape contracts ──
    chk status-fields "$(ss_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(ss_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ss_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ss_cmd_help | head -1 | grep -ci 'Secret Stores')" "1"
    chk help-mentions "$(ss_cmd_help | grep -c 'catch-all')" "1"
    chk providers-hdr "$(ss_cmd_providers | head -1 | awk -F'\t' '{print NF}')" "5"
    chk paths-hdr     "$(ss_cmd_paths | head -1 | awk -F'\t' '{print NF}')" "5"

    CS_LOOT="$real_loot"
    rm -f "$OUT_DIR/.err.$$" 2>/dev/null
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --surface)   shift; ss_cmd_surface "$@";;
    --enumerate) shift; ss_cmd_enumerate "$@";;
    --read)      shift; ss_cmd_read "$@";;
    --classify)  shift; ss_cmd_classify "$@";;
    --state)     ss_cmd_state;;
    --providers) ss_cmd_providers;;
    --paths|--list) ss_cmd_paths;;
    --status-tsv|--status) ss_cmd_status_tsv;;
    --menu)      ss_cmd_menu;;
    --selftest)  ss_selftest;;
    *)           ss_cmd_help;;
esac
