#!/usr/bin/env bash
# 09_ssrf_imds.sh — cloudsting module 09: SSRF → IMDS endpoint probe & exploitation scanner
# Verbs: --probe | --tunnel | --check | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="09_ssrf_imds"
MOD_NAME="SSRF → IMDS Probe & Exploitation Scanner"
MOD_VERSION="0.4.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export SI_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/ssrf_imds"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
FINDINGS_FILE="$OUT_DIR/findings-$RUN_ID.tsv"

si_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# IMDS probe endpoints — AWS, GCP, Azure, DO, Alibaba, OCI
si_imds_endpoints() {
cat <<'IMDS'
aws-imdsv1	http://169.254.169.254/latest/meta-data/	AWS IMDSv1 root
aws-imdsv2	http://169.254.169.254/latest/meta-data/ami-id	AWS IMDSv2 (needs token)
gcp-metadata	http://metadata.google.internal/computeMetadata/v1/	GCP metadata
gcp-via-dns	http://metadata.google.internal./computeMetadata/v1/	GCP metadata (alt)
azure-imds	http://169.254.169.254/metadata/instance?api-version=2021-02-01	Azure IMDS
do-metadata	http://169.254.169.254/metadata/v1.json	DO metadata
aliyun-ecs	http://100.100.100.200/latest/meta-data/	Alibaba ECS meta
oci-metadata	http://169.254.169.254/opc/v1/instance/	OCI instance metadata
IMDS
}

# si_imds_token_v2 — AWS IMDSv2 session token
si_imds_token_v2() {
    printf '%s' "$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)"
}

# si_probe <endpoint-url> <header? >
# returns 0 if reachable, prints found<TAB>url<TAB>status
si_probe() {
    local url="$1" header="${2:-}" status body
    if [ -n "$header" ]; then
        status="$(curl -s -o /dev/null -w '%{http_code}' --max-time "${SI_TIMEOUT:-5}" -H "$header" "$url" 2>/dev/null)"
    else
        status="$(curl -s -o /dev/null -w '%{http_code}' --max-time "${SI_TIMEOUT:-5}" "$url" 2>/dev/null)"
    fi
    if [ -n "$status" ] && [ "$status" != "000" ]; then
        printf 'found\t%s\t%s\n' "$url" "$status"
    fi
}

# --probe <target-url>: test a specific URL for IMDS/SSRF access
si_cmd_probe() {
    local target="${1:?usage: --probe <url>}"
    command -v curl >/dev/null 2>&1 || { si_log 'curl required'; return 2; }
    si_probe "$target" "Metadata: true"
}

# --tunnel: probe all known cloud metadata endpoints (must be inside cloud)
si_cmd_tunnel() {
    command -v curl >/dev/null 2>&1 || { si_log 'curl required'; return 2; }
    local name url header
    while IFS=$'\t' read -r name url header; do
        [ -z "$name" ] && continue
        local hdrs=""
        case "$name" in
            gcp*) hdrs="Metadata-Flavor: Google" ;;
            aws-imdsv2) hdrs="X-aws-ec2-metadata-token: $(si_imds_token_v2)" ;;
            *) hdrs="" ;;
        esac
        local result
        result="$(si_probe "$url" "$hdrs")"
        if [ -n "$result" ]; then
            printf '%s\t%s\n' "$name" "$result" | tee -a "$FINDINGS_FILE"
        fi
    done <<EIMDS
$(si_imds_endpoints)
EIMDS
    si_log "findings -> $FINDINGS_FILE"
}

# --check <url>: lightweight reachability test for SSRF vectors
si_cmd_check() {
    local target="${1:?usage: --check <url>}"
    command -v curl >/dev/null 2>&1 || { si_log 'curl required'; return 2; }
    local code time
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time "${SI_TIMEOUT:-5}" "$target" 2>/dev/null)"
    time="$(curl -s -o /dev/null -w '%{time_total}' --max-time "${SI_TIMEOUT:-5}" "$target" 2>/dev/null)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
        printf 'reachable\t%s\t%s\t%s\n' "$target" "$code" "$time"
    else
        printf 'unreachable\t%s\n' "$target"
    fi
}

# --list: show endpoints KB
si_cmd_list() { si_imds_endpoints; }

# --status-tsv
si_cmd_status_tsv() {
    command -v curl >/dev/null 2>&1 && printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "curl-present" \
        || printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "curl-missing"
}

# --menu
si_cmd_menu() { printf 'menu\t%s\t[%s]\n' "$MODULE_ID" "$MOD_NAME"; }

# --help
si_cmd_help() {
cat <<HELP
$MODULE_ID v$MOD_VERSION — $MOD_NAME
VERBS
  --probe <url>        test one URL with Metadata header (IMDS trick)
  --tunnel             probe all known cloud metadata endpoints
  --check <url>        lightweight reachability (code + time)
  --list               IMDS endpoint knowledge base
  --status-tsv         curl availability
  --menu | --selftest | --help
ENV
  SI_TIMEOUT (default 5) — curl max-time seconds per probe
LOOT
  loot/ssrf_imds/findings-$SI_RUN_ID.tsv rows: provider<TAB>found<TAB>url<TAB>status
HELP
}

# selftest
si_selftest() {
    local pass=0 fail=0
    chk() { local n="$1" got="$2" want="$3"
            if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$n"
            else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$n" "$want" "$got"; fi; }

    chk endpoints-count "$(si_imds_endpoints | grep -c .)" 8
    chk endpoints-fields "$(si_imds_endpoints | awk -F'\t' 'NF!=3' | wc -l)" 0
    chk has-aws-v2 "$(si_imds_endpoints | awk -F'\t' '$1=="aws-imdsv2"' | wc -l)" 1
    chk has-gcp "$(si_imds_endpoints | awk -F'\t' '$1=="gcp-metadata"' | wc -l)" 1
    chk has-azure "$(si_imds_endpoints | awk -F'\t' '$1=="azure-imds"' | wc -l)" 1
    chk has-do "$(si_imds_endpoints | awk -F'\t' '$1=="do-metadata"' | wc -l)" 1
    chk has-aliyun "$(si_imds_endpoints | awk -F'\t' '$1=="aliyun-ecs"' | wc -l)" 1
    chk has-oci "$(si_imds_endpoints | awk -F'\t' '$1=="oci-metadata"' | wc -l)" 1

    # check-status-tsv verifies offline output shape (no HTTP needed)
    chk status-shape "$(si_cmd_status_tsv | awk -F'\t' '{print NF}')" 3
    chk status-module "$(si_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"

    # --help smoke: no network, just print and exit
    chk help-shape "$(si_cmd_help 2>/dev/null | head -1 | grep -c "$MODULE_ID")" 1

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# dispatcher
si_dispatch() {
    local verb="${1:---help}"
    shift || true
    case "$verb" in
        --probe)      si_cmd_probe "$@" ;;
        --tunnel)     si_cmd_tunnel ;;
        --check)      si_cmd_check "$@" ;;
        --list)       si_cmd_list ;;
        --status-tsv) si_cmd_status_tsv ;;
        --menu)       si_cmd_menu ;;
        --selftest)   si_selftest ;;
        --help|-h)    si_cmd_help ;;
        *)            si_log "unknown verb: $verb"; si_cmd_help; return 2 ;;
    esac
}

if [ "${CLOUDSTING_SOURCE_ONLY:-0}" != "0" ]; then
    return 0 2>/dev/null || true
fi
[ "${BASH_SOURCE[0]}" = "$0" ] && si_dispatch "$@"
