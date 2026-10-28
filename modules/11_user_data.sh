#!/usr/bin/env bash
# 11_user_data.sh — cloudsting module 11: EC2 User-Data & Instance Metadata Extraction
# Verbs: --dump | --extract | --keys | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="11_user_data"
MOD_NAME="User-Data & Instance Metadata"
MOD_VERSION="0.6.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export UD_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/user_data"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true

# IMDS endpoints
UD_IMDS_IP="169.254.169.254"
UD_META_ROOT="http://$UD_IMDS_IP/latest/meta-data"
UD_USERDATA_URL="http://$UD_IMDS_IP/latest/user-data"
UD_DYNAMIC_URL="http://$UD_IMDS_IP/latest/dynamic"

: "${UD_TIMEOUT:=5}"
: "${UD_TOKEN_TTL:=21600}"

ud_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── IMDSv2 token ─────────────────────────────────────────────────
ud_get_token() {
    curl -s -X PUT "http://$UD_IMDS_IP/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: $UD_TOKEN_TTL" \
        --max-time "$UD_TIMEOUT" 2>/dev/null
}

# ── ud_fetch(path, [token]) ──────────────────────────────────────
ud_fetch() {
    local path="$1" token="${2:-}" url="http://$UD_IMDS_IP$path"
    if [ -n "$token" ]; then
        curl -s -H "X-aws-ec2-metadata-token: $token" --max-time "$UD_TIMEOUT" "$url" 2>/dev/null
    else
        curl -s --max-time "$UD_TIMEOUT" "$url" 2>/dev/null
    fi
}

# ── Key metadata paths ───────────────────────────────────────────
UD_KNOWN_KEYS="ami-id
ami-launch-index
ami-manifest-path
block-device-mapping
hostname
iam/info
instance-action
instance-id
instance-type
kernel-id
local-hostname
local-ipv4
mac
metrics
network
placement
profile
public-hostname
public-ipv4
public-keys
reservation-id
security-groups
services"

# ── ud_dump [token] — dump all known meta-data keys ──────────────
ud_dump() {
    local token="${1:-}" key val
    printf '%s\t%s\n' "#" "user-data"
    val="$(ud_fetch "/latest/user-data" "$token")"
    printf 'user-data\t%s\n' "$(printf '%s' "$val" | head -c 1024 | tr '\n' ' ')"
    printf '%s\t%s\n' "#" "meta-data"
    for key in $UD_KNOWN_KEYS; do
        val="$(ud_fetch "/latest/meta-data/$key" "$token" 2>/dev/null)"
        [ -n "$val" ] && printf '%s\t%s\n' "$key" "$(printf '%s' "$val" | head -c 256 | tr '\n' ' ')"
    done
    printf '%s\t%s\n' "#" "dynamic"
    val="$(ud_fetch "/latest/dynamic/instance-identity/document" "$token" 2>/dev/null)"
    [ -n "$val" ] && printf 'instance-identity\t%s\n' "$(printf '%s' "$val" | head -c 512 | tr '\n' ' ')"
}

# ── ud_extract [token] — extract secrets from user-data ──────────
ud_extract() {
    local token="${1:-}" raw outfile
    raw="$(ud_fetch "/latest/user-data" "$token")"
    [ -z "$raw" ] && { ud_log "no user-data (or IMDS unreachable)"; return 1; }
    outfile="$OUT_DIR/userdata-$RUN_ID.txt"
    printf '%s' "$raw" > "$outfile"
    ud_log "user-data saved to $outfile ($(printf '%s' "$raw" | wc -c) bytes)"
    # Extract common sensitive patterns
    local hits=0
    printf '%s' "$raw" | grep -nioE -- '(AKIA[0-9A-Z]{16}|ghp_[-A-Za-z0-9_]{20,}|sk_live_[-A-Za-z0-9]{20,}|-----BEGIN (RSA |EC |)?PRIVATE KEY)' 2>/dev/null || true | while IFS=: read -r ln pat; do
        ud_log "  secret at line $ln: $(printf '%s' "$pat" | head -c 40)..."
        hits=$((hits+1))
    done
    [ "$hits" -eq 0 ] && ud_log "  no common secrets found in user-data"
}

# ── ud_keys — list known metadata keys ───────────────────────────
ud_keys() {
    printf '%s\n' $UD_KNOWN_KEYS | while IFS= read -r k; do
        printf '%s\t/latest/meta-data/%s\n' "$k" "$k"
    done
    printf '%s\t%s\n' "user-data" "/latest/user-data"
    printf '%s\t%s\n' "instance-identity" "/latest/dynamic/instance-identity/document"
}

# ── Verb dispatchers ─────────────────────────────────────────────
ud_cmd_dump() { local t="${1:-$(ud_get_token)}"; ud_dump "$t" | awk -F'\n' '{print}'; }
ud_cmd_extract() { local t="${1:-$(ud_get_token)}"; ud_extract "$t"; }
ud_cmd_keys() { ud_keys; }
ud_cmd_list() { ud_keys; }
ud_cmd_status_tsv() {
    local curl_state
    if command -v curl >/dev/null 2>&1; then curl_state="ok"; else curl_state="missing"; fi
    printf '%s\t%s\tcurl-%s\n' "$MODULE_ID" "$MOD_NAME" "$curl_state"
}
ud_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }
ud_cmd_help() {
    cat <<'HELP'
cloudsting module 11 — User-Data & Instance Metadata Extraction v0.6.0
  --dump [token]          dump all known meta-data keys + user-data + identity doc
  --extract [token]       save user-data to loot and scan for secrets
  --keys                  list known meta-data keys
  --list                  alias for --keys
  --status-tsv            module status
  --menu                  menu entry
  --selftest              run selftests
  --help                  this message
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ud_selftest() {
    local pass=0 fail=0
    chk() { local n="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$n"
        else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$n" "$want" "$got"; fi; }

    # Keys integrity
    local kc
    kc="$(ud_keys | awk -F'\t' 'NF==2' | wc -l)"
    chk keys-count "$kc" "$(($(printf '%s\n' $UD_KNOWN_KEYS | wc -l) + 2))"

    kc="$(ud_keys | awk -F'\t' '$1=="ami-id"' | wc -l)"
    chk has-ami-id "$kc" 1

    kc="$(ud_keys | awk -F'\t' '$1=="instance-identity"' | wc -l)"
    chk has-identity "$kc" 1

    # --list smoke
    chk list-output "$(ud_cmd_list | wc -l)" "$(($(printf '%s\n' $UD_KNOWN_KEYS | wc -l) + 2))"

    # --status-tsv shape
    chk status-shape "$(ud_cmd_status_tsv | awk -F'\t' '{print NF}')" 3
    chk status-module "$(ud_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"

    # --help smoke
    chk help-smoke "$(ud_cmd_help 2>/dev/null | head -1 | grep -ci user-data)" 1

    # --dump against localhost (should fail gracefully)
    local result
    chk dump-fails "$(ud_cmd_dump "$(echo)" 2>/dev/null | wc -l)" 4

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --dump)    shift; ud_cmd_dump "$@";;
    --extract) shift; ud_cmd_extract "$@";;
    --keys)    shift; ud_cmd_keys "$@";;
    --list)    shift; ud_cmd_list;;
    --status-tsv|--status) ud_cmd_status_tsv;;
    --menu)    ud_cmd_menu;;
    --selftest) ud_selftest;;
    *)         ud_cmd_help;;
esac
