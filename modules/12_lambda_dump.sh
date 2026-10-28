#!/usr/bin/env bash
# 12_lambda_dump.sh — cloudsting module 12: AWS Lambda Function Enumeration & Code Extraction
# Verbs: --list | --dump <func> | --download <func> | --env <func> | --urls | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="12_lambda_dump"
MOD_NAME="Lambda Function Enumeration & Code Dump"
MOD_VERSION="0.7.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export LD_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/lambda_dump"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true

: "${LD_TIMEOUT:=10}"

ld_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── AWS credential gate ──────────────────────────────────────────
ld_has_aws() {
    command -v aws >/dev/null 2>&1 || return 1
    aws sts get-caller-identity >/dev/null 2>&1 || return 1
    return 0
}

# ── ld_list_functions — list all Lambda functions ────────────────
# output: func-name<TAB>runtime<TAB>handler<TAB>last-modified<TAB>arn
ld_list_functions() {
    ld_has_aws || { ld_log "AWS credentials not available"; return 1; }
    aws lambda list-functions --output json 2>/dev/null | \
        jq -r '.Functions[] | [.FunctionName, .Runtime // "-", .Handler // "-", .LastModified // "-", .FunctionArn] | @tsv' 2>/dev/null
}

# ── ld_get_function <func> — get function config ─────────────────
ld_get_function() {
    local func="$1"
    ld_has_aws || return 1
    aws lambda get-function --function-name "$func" --output json 2>/dev/null | \
        jq '{Configuration: {FunctionName, Runtime, Handler, Role, Description, Timeout, MemorySize, Environment, VpcConfig, PackageType, FunctionUrl}}' 2>/dev/null
}

# ── ld_get_code <func> — download Lambda code zip ────────────────
ld_get_code() {
    local func="$1" dl_url outfile
    ld_has_aws || return 1
    dl_url="$(aws lambda get-function --function-name "$func" --output json 2>/dev/null | jq -r '.Code.Location // empty')"
    [ -z "$dl_url" ] && { ld_log "no code URL for $func"; return 1; }
    outfile="$OUT_DIR/${func}-$RUN_ID.zip"
    curl -s -L --max-time "$LD_TIMEOUT" -o "$outfile" "$dl_url" 2>/dev/null || { ld_log "download failed"; return 1; }
    ld_log "downloaded $func -> $outfile ($(stat --printf='%s' "$outfile" 2>/dev/null || stat -f%z "$outfile" 2>/dev/null) bytes)"
    printf '%s\n' "$outfile"
}

# ── ld_get_env <func> — print environment variables ──────────────
ld_get_env() {
    local func="$1"
    ld_get_function "$func" | jq -r '.Configuration.Environment.Variables | to_entries[] | [.key, .value] | @tsv' 2>/dev/null
}

# ── ld_list_urls — list all Lambda function URLs ─────────────────
ld_list_urls() {
    ld_has_aws || return 1
    aws lambda list-functions --output json 2>/dev/null | \
        jq -r '.Functions[] | select(.FunctionUrl != null) | [.FunctionName, .FunctionUrl] | @tsv' 2>/dev/null
}

# ── Verb dispatchers ─────────────────────────────────────────────
ld_cmd_list() { ld_list_functions; }
ld_cmd_dump() {
    local func="${1:-}"
    [ -z "$func" ] && { ld_log "usage: --dump <function-name>"; return 1; }
    ld_get_function "$func"
}
ld_cmd_download() {
    local func="${1:-}"
    [ -z "$func" ] && { ld_log "usage: --download <function-name>"; return 1; }
    ld_get_code "$func"
}
ld_cmd_env() {
    local func="${1:-}"
    [ -z "$func" ] && { ld_log "usage: --env <function-name>"; return 1; }
    ld_get_env "$func"
}
ld_cmd_urls() { ld_list_urls; }
ld_cmd_status_tsv() {
    if ! command -v aws >/dev/null 2>&1; then
        printf '%s\t%s\taws-cli-missing\n' "$MODULE_ID" "$MOD_NAME"
        return
    fi
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        printf '%s\t%s\tcreds-missing\n' "$MODULE_ID" "$MOD_NAME"
        return
    fi
    printf '%s\t%s\tcreds-present\n' "$MODULE_ID" "$MOD_NAME"
}
ld_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }
ld_cmd_help() {
    cat <<'HELP'
cloudsting module 12 — Lambda Enumeration & Code Dump v0.7.0
  --list                    list all Lambda functions (name, runtime, handler)
  --dump <func>             get function configuration (env, role, vpc, etc.)
  --download <func>         download function code zip to loot/
  --env <func>              print environment variables (key=value TSV)
  --urls                    list all Lambda function URLs
  --status-tsv              module status (aws-cli-missing / creds-missing / creds-present)
  --menu                    menu entry for launcher
  --selftest                run selftests
  --help                    this message
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ld_selftest() {
    local pass=0 fail=0
    chk() { local n="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$n"
        else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$n" "$want" "$got"; fi; }

    # --status-tsv honest 3-state
    local state_line
    state_line="$(ld_cmd_status_tsv 2>/dev/null)"
    chk status-fields "$(printf '%s' "$state_line" | awk -F'\t' '{print NF}')" 3
    chk status-module "$(printf '%s' "$state_line" | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk status-honest "$(printf '%s' "$state_line" | awk -F'\t' '{print $3}' | grep -cE '^(aws-cli-missing|creds-missing|creds-present)$')" 1

    # --help smoke
    chk help-smoke "$(ld_cmd_help 2>/dev/null | head -1 | grep -ci lambda)" 1

    # --list with no creds = honest failure
    local list_out
    list_out="$(ld_cmd_list 2>&1)" || true
    chk list-honest "$(printf '%s' "$list_out" | head -1 | grep -ciE '(aws|cred|error|usage)')" 1

    # --menu shape
    chk menu-shape "$(ld_cmd_menu | awk -F'\t' '{print NF}')" 3

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --list|--ls) shift; ld_cmd_list "$@";;
    --dump)      shift; ld_cmd_dump "$@";;
    --download)  shift; ld_cmd_download "$@";;
    --env)       shift; ld_cmd_env "$@";;
    --urls)      shift; ld_cmd_urls;;
    --status-tsv|--status) ld_cmd_status_tsv;;
    --menu)      ld_cmd_menu;;
    --selftest)  ld_selftest;;
    *)           ld_cmd_help;;
esac
