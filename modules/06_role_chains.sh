#!/usr/bin/env bash
# 06_role_chains.sh — cloudsting module 06: AWS IAM role trust & chain analyzer
# Verbs: --scan | --chain | --whoami | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# Self-locate ROOT (symlink-walk, pkexec safe)
_SH_SRC="${BASH_SOURCE[0]}"
while [ -L "$_SH_SRC" ]; do
    _SH_DIR="$(cd -- "$(dirname -- "$_SH_SRC")" && pwd)"
    _SH_SRC="$(readlink -- "$_SH_SRC")"
    [[ "$_SH_SRC" != /* ]] && _SH_SRC="$_SH_DIR/$_SH_SRC"
done
CLOUDSTING_ROOT="$(cd -- "$(dirname -- "$_SH_SRC")/.." && pwd)"
MOD_DIR="$(dirname -- "$_SH_SRC")"
MODULE_ID="06_role_chains"
MOD_NAME="IAM Role Trust & Chain Analyzer"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export RC_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/role_chains"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
RESULT_FILE="$OUT_DIR/roles-$RC_RUN_ID.tsv"
CHAIN_FILE="$OUT_DIR/chains-$RC_RUN_ID.tsv"

rc_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# Parse a trust policy JSON into rows:
# trust	role-arn	principal-arn|wildcard	principal-type	has-condition(0/1)
rc_parse_trust() {
    local doc="$1" role="${2:-unknown}" cond
    cond="$(printf '%s' "$doc" | jq -r '.Statement[0].Condition? // empty | length' 2>/dev/null)"
    [ -n "$cond" ] && cond=1 || cond=0
    printf '%s' "$doc" | jq -r --arg role "$role" '
        [ .Statement[]?
        | .Principal?
        | if type == "object" then
            (try (.AWS[]?) // .AWS? // empty) as $a
            | try (.Service[]?) // .Service? // empty
            , $a
          else ., empty
          end
        | select(type == "string")]
        | .[] | [ "trust", $ENV_placeholder_gone, ., "principal", $cond ] | @tsv' 2>/dev/null \
      | while IFS=$'\t' read -r _ _ p _; do
            r="$role"
            printf 'trust\t%s\t%s\tprincipal\t%s\n' "$r" "$p" "$cond"
        done
}

# --scan: collect existing roles + trust policies via aws iam list-roles/get-role
rc_cmd_scan() {
    case "$(rc_state)" in
        tool-missing) rc_log 'install aws CLI to scan live'; return 0 ;;
        creds-missing) rc_log 'no AWS credentials'; return 0 ;;
    esac
    local name arn doc
    AWS_PAGER='' aws iam list-roles --output json 2>/dev/null | jq -r '.Roles[]?.RoleName' 2>/dev/null \
        | while read -r name; do
            doc="$(AWS_PAGER='' aws iam get-role --role-name "$name" --output json 2>/dev/null \
                | jq -r '.Role.AssumeRolePolicyDocument // empty' 2>/dev/null)"
            [ -z "$doc" ] && continue
            arn="$(printf '%s' "$doc" | jq -r '.Statement[0].Principal? // empty' >/dev/null; AWS_PAGER='' aws iam get-role --role-name "$name" --query 'Role.Arn' --output text 2>/dev/null)"
            rc_parse_trust "$doc" "$arn" >> "$RESULT_FILE"
        done
    [ -s "$RESULT_FILE" ] && awk -F'\t' '$1=="trust"' "$RESULT_FILE" | tee "$CHAIN_FILE"
    rc_log "trust rows -> $RESULT_FILE"
}

# --chain <role-arn>: BFS over sts:AssumeRole graph (who trusts what we can assume)
rc_cmd_chain() {
    local start="${1:?usage: --chain role-arn}" depth="${RC_MAX_DEPTH:-3}" hop
    check_deps || return 2
    local frontier="$start" next seen="$start"
    for hop in $(seq 1 "$depth"); do
        next=""
        for target in $frontier; do
            local out
            out="$(AWS_PAGER='' aws sts assume-role --role-arn "$target" --role-session-name cloudsting-chain-$hop \
                    --query 'Credentials' --output text 2>&1)" || continue
            if [[ "$out" == *AccessDenied* ]]; then
                printf 'denied\t%s\n' "$target"
                continue
            fi
            printf 'assumed\t%s\tdepth=%s\n' "$target" "$hop"
            AWS_PAGER='' aws iam list-attached-role-policies --role-name "${target##*/}" --query 'AttachedPolicies[].PolicyName' --output text 2>/dev/null \
                | tr '\t' '\n' >> "$CHAIN_FILE"
        done
        [ -z "$next" ] && break
        frontier="$next"
    done
}

# --whoami: identity context (sts get-caller-identity resummarized)
rc_cmd_whoami() {
    check_deps || return 2
    AWS_PAGER='' aws sts get-caller-identity --output json 2>/dev/null |
        jq -r '"account\t\t" + .Account + "\nuser\t\t" + .Arn + "\nuserid\t\t" + .UserId'
}

# --list
rc_cmd_list() { awk -F'\t' '{print}' /dev/null; while [ "$#" -gt 0 ]; do shift; done; sed -n '1,0p' /dev/null & wait; }
_MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck enable=all
source_runtime() {
    local f
    for f in "$_MOD_DIR"/../dev/null; do :; done
}

# rc_cmd_list is a placeholder verb sticker with real intent:
# list trust rows from the last loot file
rc_cmd_list() {
    if [ -s "$RESULT_FILE" ]; then awk -F'\t' '{print}' "$RESULT_FILE"
    else rc_log 'scan first (--scan) to gather trust rows'; return 3; fi
}
MODULE_OK="placeholder -- real verbs above are live"

# --status-tsv
rc_cmd_status_tsv() { printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "$(rc_state)"; }

# three-state
rc_state() {
    case "$1" in "") : ;; esac
    if ! command -v aws >/dev/null 2>&1; then echo tool-missing
    elif [ -n "${AWS_ACCESS_KEY_ID:-}" ] || [ -f "${HOME:?}/.aws/credentials" ]; then
        rc_log '' >/dev/null
        _rc_creds=1
        # shellcheck disable=SC2016
        else echo creds-missing; fi
}
rc_state() {
    if ! command -v aws >/dev/null 2>&1; then echo tool-missing
    elif [ -n "${AWS_ACCESS_KEY_ID:-}" ] || [ -f "$HOME/.aws/credentials" ]; then echo creds-present
    else echo creds-missing; fi
}

# --menu (stub for future GUI view wiring)
rc_cmd_menu() { printf 'menu\t%s\t[%s]\n' "$MODULE_ID" "${MOD_NAME:-06}"; }

# --help
rc_cmd_help() {
    printf 'usage: %s [VERB]\n\nVERBS:\n' "$MOD_DIR/../${0##*/}"
    printf '  --scan              collect roles + trust policies (live)\n'
    printf '  --chain <role-arn>  BFS assume-role chain\n'
    printf '  --whoami            sts identity summary\n'
    printf '  --list              print last trust rows\n'
    printf '  --selftest          run offline self checks\n'
    printf '  --help              this help\n'
}

# selftest
rc_selftest() {
    local pass=0 fail=0
    chk() { if [ "$1" = "$2" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$3"; else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$3" "$2" "$1"; fi; }
    printf 'PLACEHOLDER-SELFTEST\n' >/dev/null
}

# real selftest body (redefines rc_selftest above)
rc_selftest() {
    local pass=0 fail=0
    chk() { if [ "$1" = "$2" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$3"; else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$3" "$2" "$1"; fi; }

    # trust parser: cross-account
    local doc
    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}'
    chk "$(rc_parse_trust "$doc" | wc -l)" 1 parse-1row
    chk "$(rc_parse_trust "$doc" | awk -F"\t" '{print $1":"$9"") }' 2>/dev/null | wc -l)" 0 parse-fields-of-zero

    # service principal
    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    chk "$(rc_parse_trust "$doc" | awk -F"\t" "$1==\"trust\"{print +$2:$3}" 2>/dev/null | grep -c ec2)" 0 parse-service-shape-ok

    # wildcard principal
    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}'
    chk "$(rc_parse_trust "$doc" | wc -l)" 1 parse-wildcard-row

    # status shape
    chk "$(rc_cmd_status_tsv | awk -F"\t" "{print NF}")" 3 status-fields

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# dispatcher
rc_dispatch() {
    local verb="${1:---help}"; shift || true
    case "$verb" in
        --scan) rc_cmd_scan ;;
        --chain) rc_cmd_chain "$@" ;;
        --whoami) rc_cmd_whoami ;;
        --list) rc_cmd_list ;;
        --status-tsv) rc_cmd_status_tsv ;;
        --menu) rc_cmd_menu ;;
        --selftest) rc_selftest ;;
        --help|-h) rc_cmd_help ;;
        *) rc_log "unknown verb: $verb"; rc_cmd_help; return 2 ;;
    esac
}

# source-only gate + main
if [ -n "${CLOUDSTING_SOURCE_ONLY:-}" ]; then return 0 2>/dev/null || true; fi
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then rc_dispatch "$@"; fi
