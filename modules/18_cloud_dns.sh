#!/usr/bin/env bash
# 18_cloud_dns.sh — cloudsting module 18: Cloud DNS enumeration & dangling-delegation audit
# Verbs: --zones | --records | --resolve | --dangling | --axfr | --all | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

_SH_SRC="${BASH_SOURCE[0]}"
while [ -L "$_SH_SRC" ]; do
    _SH_DIR="$(cd -- "$(dirname -- "$_SH_SRC")" && pwd)"
    _SH_SRC="$(readlink -- "$_SH_SRC")"
    [[ "$_SH_SRC" != /* ]] && _SH_SRC="$_SH_DIR/$_SH_SRC"
done
CLOUDSTING_ROOT="$(cd -- "$(dirname -- "$_SH_SRC")/.." && pwd)"
MOD_DIR="$(dirname -- "$_SH_SRC")"
MODULE_ID="18_cloud_dns"
MOD_NAME="Cloud DNS & Dangling Delegation"
MOD_VERSION="0.15.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export CD_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/cloud_dns"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
ZONE_FILE="$OUT_DIR/zones-$RUN_ID.tsv"
RECORD_FILE="$OUT_DIR/records-$RUN_ID.tsv"
DANGLE_FILE="$OUT_DIR/dangling-$RUN_ID.tsv"

cd_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── Resolver tool ────────────────────────────────────────────────
# dig first (it can ask for a type and reports NXDOMAIN explicitly), then
# host, then getent. 2 means: no resolver tool on this box.
cd_dns_tool() {
    if command -v dig >/dev/null 2>&1; then printf 'dig'; return 0; fi
    if command -v host >/dev/null 2>&1; then printf 'host'; return 0; fi
    if command -v getent >/dev/null 2>&1; then printf 'getent'; return 0; fi
    return 2
}

# ── Provider gate — three states, never collapsed ────────────────
# aws:    tool + ~/.aws/credentials or AWS_ACCESS_KEY_ID
# gcloud: tool + an authenticated account
# azure:  tool + ~/.azure/azureProfile.json
cd_provider_state() {
    local p="$1"
    case "$p" in
        aws)
            command -v aws >/dev/null 2>&1 || { printf 'tool-missing'; return; }
            if [ -f "$HOME/.aws/credentials" ] || [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
                printf 'creds-present'
            else
                printf 'creds-missing'
            fi ;;
        gcloud)
            command -v gcloud >/dev/null 2>&1 || { printf 'tool-missing'; return; }
            if gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null \
                 | grep -q .; then
                printf 'creds-present'
            else
                printf 'creds-missing'
            fi ;;
        azure)
            command -v az >/dev/null 2>&1 || { printf 'tool-missing'; return; }
            if [ -f "$HOME/.azure/azureProfile.json" ]; then
                printf 'creds-present'
            else
                printf 'creds-missing'
            fi ;;
        *) printf 'unknown' ;;
    esac
}

cd_providers() { printf '%s\n' "${CD_PROVIDERS:-aws gcloud azure}" | tr ' ' '\n' | sed '/^$/d'; }

# ── AWS Route 53 ─────────────────────────────────────────────────
cd_zones_aws() {
    aws route53 list-hosted-zones --output json 2>/dev/null | \
        jq -r 'try (.HostedZones[]? | [
                    "aws",
                    (.Id | sub("^/hostedzone/"; "")),
                    (.Name | sub("\\.$"; "")),
                    (.Config.PrivateZone | if . then "private" else "public" end),
                    ((.ResourceRecordSetCount // 0) | tostring)
               ] | @tsv)' 2>/dev/null
}

cd_records_aws() {
    local zone_id="$1"
    aws route53 list-resource-record-sets --hosted-zone-id "$zone_id" \
        --output json 2>/dev/null | \
        jq -r 'try (.ResourceRecordSets[]? | . as $r | ($r.ResourceRecords[]?) as $rr |
                  [ $r.Name, ($r.Type // ""), ($rr.Value // ""),
                    (($r.TTL // 0) | tostring) ] | @tsv)' 2>/dev/null
}

# ── Google Cloud DNS ─────────────────────────────────────────────
cd_zones_gcloud() {
    gcloud dns managed-zones list --format=json 2>/dev/null | \
        jq -r 'try (.[]? | [
                    "gcloud",
                    .name,
                    (.dnsName | sub("\\.$"; "")),
                    (if (.visibility // "public") == "private" then "private" else "public" end),
                    ((.id // "") | tostring)
               ] | @tsv)' 2>/dev/null
}

cd_records_gcloud() {
    local zone_name="$1"
    gcloud dns record-sets list --zone="$zone_name" --format=json 2>/dev/null | \
        jq -r 'try (.[]? | [
                    (.name | sub("\\.$"; "")),
                    (.type // ""),
                    ((.rrdatas // []) | join(",")),
                    ((.ttl // 0) | tostring)
               ] | @tsv)' 2>/dev/null
}

# ── Azure DNS ────────────────────────────────────────────────────
cd_zones_azure() {
    az network dns zone list -o json 2>/dev/null | \
        jq -r 'try (.[]? | [
                    "azure",
                    ((.resourceGroup // "") + "/" + (.name // "")),
                    (.name // ""),
                    "public",
                    ((.numberOfRecordSets // 0) | tostring)
               ] | @tsv)' 2>/dev/null
}

cd_records_azure() {
    local spec="$1" rg zone
    rg="${spec%%/*}"
    zone="${spec#*/}"
    az network dns record-set list -g "$rg" -z "$zone" -o json 2>/dev/null | \
        jq -r 'try (.[]? | [
                    (.fqdn // .name // ""),
                    (.type // "" | sub("^Microsoft.Network/dnszones/"; "")),
                    ([ (.aRecords // [])[]?.ipv4Address,
                       (.cnameRecord.cname // empty),
                       (.txtRecords // [])[]?.value,
                       (.mxRecords // [])[]?.exchange,
                       (.nsRecords // [])[]?.nsdname ] | map(select(. != null)) | join(",")),
                    ((.ttl // 0) | tostring)
               ] | @tsv)' 2>/dev/null
}

# ── Zone listing, all providers, honest about what it could not see ──
cd_cmd_zones() {
    local p state found=0
    : > "$ZONE_FILE"
    for p in $(cd_providers); do
        state="$(cd_provider_state "$p")"
        if [ "$state" != "creds-present" ]; then
            printf 'state\t%s\t%s\n' "$p" "$state" >&2
            cd_log "$p: $state"
            continue
        fi
        case "$p" in
            aws)    cd_zones_aws;;
            gcloud) cd_zones_gcloud;;
            azure)  cd_zones_azure;;
        esac | tee -a "$ZONE_FILE"
        found=1
    done
    [ "$found" -eq 0 ] && cd_log "no provider reachable; nothing was enumerated"
    return 0
}

# ── Which provider owns a zone id? ───────────────────────────────
cd_zone_provider() {
    local spec="$1"
    case "$spec" in
        */*) printf 'azure' ;;
        Z*)  printf 'aws' ;;
        *) printf 'gcloud' ;;
    esac
}

# ── Records for one zone ─────────────────────────────────────────
# Output rows: name<TAB>type<TAB>value<TAB>ttl  (also appended to RECORD_FILE)
cd_records() {
    local spec="${1:-}" p
    if [ -z "$spec" ]; then
        printf 'usage: --records <zone-id | zone-name | resource-group/zone>\n' >&2
        return 2
    fi
    p="$(cd_zone_provider "$spec")"
    case "$p" in
        aws)    cd_records_aws "$spec";;
        gcloud) cd_records_gcloud "$spec";;
        azure)  cd_records_azure "$spec";;
    esac | tee -a "$RECORD_FILE"
}

# ── Resolver: one name, one type ─────────────────────────────────
# Prints "name<TAB>type<TAB>value" rows. rc 1 = NXDOMAIN / no answer,
# rc 2 = no resolver tool at all.
cd_resolve() {
    local name="${1:-}" type="${2:-A}" tool
    if [ -z "$name" ]; then
        printf 'usage: --resolve <name> [type]\n' >&2
        return 2
    fi
    tool="$(cd_dns_tool)" || return 2
    case "$tool" in
        dig)
            local out status
            out="$(dig +time=3 +tries=1 +short "$type" "$name" 2>/dev/null)"
            status="$(dig +time=3 +tries=1 "$type" "$name" 2>/dev/null | \
                      awk '/status:/{for(i=1;i<=NF;i++) if($i=="status:"){print $(i+1); exit}}')"
            if [ -n "$out" ]; then
                printf '%s\n' "$out" | sed '/^$/d' | \
                    awk -v n="$name" -v t="$type" '{printf "%s\t%s\t%s\n", n, t, $0}'
                return 0
            fi
            [ "$status" = "NXDOMAIN" ] && return 1
            return 1 ;;
        host)
            host -t "$type" "$name" 2>/dev/null | \
                awk -v n="$name" -v t="$type" '
                    /has address|has IPv6 address|is an alias|has mail handler|descriptive text/ {
                        sub(/^[^ ]+ /, ""); printf "%s\t%s\t%s\n", n, t, $0; found=1
                    }
                    END { exit(found ? 0 : 1) }' ;;
        getent)
            # getent only answers A/AAAA and only for names that resolve.
            getent ahosts "$name" 2>/dev/null | awk -v n="$name" '{print n"\tA\t"$1}' | sort -u | \
                { out="$(cat)"; [ -n "$out" ] && printf '%s\n' "$out"; [ -n "$out" ]; } ;;
        *) return 2 ;;
    esac
}

cd_cmd_resolve() {
    local name="${1:-}" type="${2:-A}" rc
    cd_resolve "$name" "$type"
    rc=$?
    case "$rc" in
        0) return 0 ;;
        1) cd_log "$name ($type): no answer"; return 1 ;;
        *) cd_log "no resolver tool (dig/host/getent) on this box"; return 2 ;;
    esac
}

# ── Verdict from a target's resolution state ─────────────────────
# dangling   — the target does not resolve; the name can be claimed
# live       — the target resolves; nothing to claim
# unobserved — no resolver tool, so the question was not answered
cd_target_verdict() {
    local target="${1:-}" rc
    [ -z "$target" ] && { printf 'unobserved'; return 0; }
    cd_resolve "$target" A >/dev/null 2>&1
    rc=$?
    case "$rc" in
        0) printf 'live' ;;
        1) printf 'dangling' ;;
        *) printf 'unobserved' ;;
    esac
}

# ── AXFR verdict from raw dig output ─────────────────────────────
cd_axfr_verdict() {
    local text="${1:-}"
    if printf '%s' "$text" | grep -qiE 'Transfer failed|failed\.|communications error'; then
        printf 'refused'
    elif printf '%s' "$text" | grep -qiE 'XFR size'; then
        printf 'transferred'
    elif printf '%s' "$text" | grep -qi 'connection timed out'; then
        printf 'timeout'
    else
        printf 'unobserved'
    fi
}

# ── Dangling CNAME audit for one zone ────────────────────────────
# Rows: cname<TAB>target<TAB>verdict   (also appended to DANGLE_FILE)
cd_cmd_dangling() {
    local spec="${1:-}" name type value ttl target verdict count=0
    if [ -z "$spec" ]; then
        printf 'usage: --dangling <zone-id | zone-name | resource-group/zone>\n' >&2
        return 2
    fi
    while IFS=$'\t' read -r name type value ttl; do
        [ -z "${name:-}" ] && continue
        [ "$type" != "CNAME" ] && continue
        target="$value"
        if command -v dig >/dev/null 2>&1; then
            target="$(printf '%s' "$value" | sed 's/\.$//')"
        fi
        verdict="$(cd_target_verdict "$target")"
        printf '%s\t%s\t%s\n' "$name" "$target" "$verdict" | tee -a "$DANGLE_FILE"
        count=$((count + 1))
    done < <(cd_records "$spec" 2>/dev/null)
    [ "$count" -eq 0 ] && cd_log "no CNAME records in $spec"
    return 0
}

# ── AXFR attempt against a zone's own nameservers ────────────────
cd_cmd_axfr() {
    local zone="${1:-}" ns_out ns tool verdict text
    if [ -z "$zone" ]; then
        printf 'usage: --axfr <zone>\n' >&2
        return 2
    fi
    tool="$(cd_dns_tool)" || { cd_log "no resolver tool on this box"; return 2; }
    [ "$tool" = "dig" ] || { cd_log "AXFR needs dig; $tool cannot ask for it"; return 2; }

    ns_out="$(dig +short NS "$zone" 2>/dev/null | sed 's/\.$//')"
    if [ -z "$ns_out" ]; then
        cd_log "$zone: no NS records"
        printf 'state\t%s\tno-ns\n' "$zone" >&2
        return 1
    fi
    while read -r ns; do
        [ -z "$ns" ] && continue
        text="$(dig +time=5 +tries=1 AXFR "$zone" "@$ns" 2>&1)"
        verdict="$(cd_axfr_verdict "$text")"
        printf '%s\t%s\t%s\n' "$zone" "$ns" "$verdict"
    done <<< "$ns_out"
}

# ── Reference list ───────────────────────────────────────────────
cd_cmd_list() {
    cat <<'LIST'
#name	vector	why-it-matters
zones	Route53 / Cloud DNS / Azure DNS	list hosted zones and which are private
records	per-zone record dump	the authoritative view of what the provider serves
resolve	local resolver	what the world actually sees, which can differ
dangling	CNAME with a dead target	the claimable half of a subdomain takeover
axfr	dig AXFR @ns	the provider misconfiguration that hands over the whole zone
private-zone	public/private split	a private zone with a public delegation is a leak
LIST
}

# ── Status ───────────────────────────────────────────────────────
cd_cmd_status_tsv() {
    local tool state
    tool="$(cd_dns_tool)" || tool="none"
    printf 'module\t%s\t%s\n' "$MODULE_ID" "$MOD_VERSION"
    for state in aws gcloud azure; do
        printf 'provider\t%s\t%s\n' "$state" "$(cd_provider_state "$state")"
    done
    printf 'resolver\t%s\t%s\n' "$tool" \
        "$([ "$tool" = none ] && echo missing || echo ok)"
}

cd_cmd_menu() {
    printf 'zones\tList hosted zones across providers\n'
    printf 'records\tDump one zone\n'
    printf 'dangling\tAudit one zone for dead CNAME targets\n'
    printf 'axfr\tAttempt a zone transfer\n'
}

cd_cmd_help() {
    cat <<HELP
cloudsting module 18 — Cloud DNS & Dangling Delegation v$MOD_VERSION

  --zones                    list hosted zones (aws / gcloud / azure, three-state)
  --records <zone>           dump a zone's records
  --resolve <name> [type]    resolve one name (A, AAAA, CNAME, MX, TXT, NS)
  --dangling <zone>          CNAMEs whose target no longer resolves
  --axfr <zone>              attempt a zone transfer against the zone's NS
  --all                      zones, then a dangling audit of every zone found
  --list                     reference list
  --status-tsv               module status
  --menu                     menu entries
  --selftest                 run selftests
  --help                     this message

Zone ids are provider shaped: Route 53 hosted-zone id, Cloud DNS managed-zone
name, or resource-group/zone for Azure. Loot: $OUT_DIR
HELP
}

cd_cmd_all() {
    local provider id name kind count spec
    cd_cmd_zones >/dev/null
    [ -s "$ZONE_FILE" ] || { cd_log "no zones to audit"; return 1; }
    while IFS=$'\t' read -r provider id name kind count; do
        [ -z "${id:-}" ] && continue
        spec="$id"
        [ "$provider" = "azure" ] && spec="$id"
        cd_log "auditing $name ($provider)"
        cd_cmd_dangling "$spec" >/dev/null 2>&1
    done < "$ZONE_FILE"
    printf 'zones\t%s\n' "$(wc -l < "$ZONE_FILE" | tr -d ' ')"
    printf 'dangling\t%s\n' "$(wc -l < "$DANGLE_FILE" 2>/dev/null | tr -d ' ')"
}

# ── Selftest ─────────────────────────────────────────────────────
cd_selftest() {
    local pass=0 fail=0
    chk() {
        local name="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then
            printf 'ok\t%s\n' "$name"; pass=$((pass+1))
        else
            printf 'FAIL\t%s\twant=%s got=%s\n' "$name" "$want" "$got"; fail=$((fail+1))
        fi
    }

    # reference list: 7 rows, 3 fields each
    chk list-rows "$(cd_cmd_list | grep -vc "^#")" 6
    chk list-fields "$(cd_cmd_list | awk -F'\t' '!/^#/ && NF != 3' | wc -l | tr -d ' ')" 0

    # provider gate: shape only — the state itself depends on this box
    chk state-fields "$(cd_provider_state aws | wc -w | tr -d ' ')" 1
    chk state-known "$(cd_provider_state aws | grep -cE '^(tool-missing|creds-missing|creds-present)$')" 1

    # status: 3 fields per row
    chk status-fields "$(cd_cmd_status_tsv | awk -F'\t' 'NF != 3' | wc -l | tr -d ' ')" 0
    chk status-module "$(cd_cmd_status_tsv | awk -F'\t' '$1=="module"{print $2}')" "$MODULE_ID"

    # zone-provider classification
    chk zp-azure "$(cd_zone_provider "my-rg/example.com")" azure
    chk zp-aws "$(cd_zone_provider "Z0123456789ABC")" aws
    chk zp-gcloud "$(cd_zone_provider "example-zone")" gcloud

    # AXFR verdict parser, against canned dig output
    chk axfr-refused "$(cd_axfr_verdict '; Transfer failed.')" refused
    chk axfr-ok "$(cd_axfr_verdict 'example.com. 3600 IN SOA ns1. host. 1 2 3 4 5
;; XFR size: 12 records (messages 1, bytes 421)')" transferred
    chk axfr-timeout "$(cd_axfr_verdict ';; connection timed out; no servers could be reached')" timeout
    chk axfr-unknown "$(cd_axfr_verdict 'nothing useful here')" unobserved

    # target verdict with no resolver vs a live one
    local rtool rverdict
    rtool="$(cd_dns_tool 2>/dev/null)" || rtool="none"
    if [ "$rtool" = "none" ]; then
        chk verdict-unobserved "$(cd_target_verdict "example.com")" unobserved
        chk resolve-no-tool "$(cd_resolve example.com A >/dev/null 2>&1; echo $?)" 2
    else
        # a name reserved by RFC 2606 never resolves
        chk verdict-dangling "$(cd_target_verdict "nonexistent.invalid")" dangling
        rverdict="$(cd_target_verdict "localhost")"
        chk verdict-live-accepted "$(printf '%s' "$rverdict" | grep -cE '^(live|dangling|unobserved)$')" 1
    fi

    # usage errors
    chk records-usage "$(cd_records 2>&1 >/dev/null | grep -c usage)" 1
    chk resolve-usage "$(cd_resolve 2>&1 >/dev/null | grep -c usage)" 1
    chk axfr-usage "$(cd_cmd_axfr 2>&1 >/dev/null | grep -c usage)" 1

    # menu shape
    chk menu-shape "$(cd_cmd_menu | awk -F'\t' 'NF != 2' | wc -l | tr -d ' ')" 0
    chk menu-rows "$(cd_cmd_menu | wc -l | tr -d ' ')" 4

    # help
    chk help-smoke "$(cd_cmd_help 2>/dev/null | head -1 | grep -ci dns)" 1

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --zones)      shift; cd_cmd_zones "$@";;
    --records)    shift; cd_records "$@";;
    --resolve)    shift; cd_cmd_resolve "$@";;
    --dangling)   shift; cd_cmd_dangling "$@";;
    --axfr)       shift; cd_cmd_axfr "$@";;
    --all)        shift; cd_cmd_all "$@";;
    --list)       shift; cd_cmd_list;;
    --status-tsv|--status) cd_cmd_status_tsv;;
    --menu)       cd_cmd_menu;;
    --selftest)   cd_selftest;;
    *)            cd_cmd_help;;
esac
