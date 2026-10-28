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
MOD_VERSION="0.1.0"
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

# check_deps: ensure required tooling (aws/jq/curl) is present; diag to stderr
rc_check_deps() {
    local t miss=0
    for t in aws jq; do
        command -v "$t" >/dev/null 2>&1 || { rc_log "missing dep: $t"; miss=1; }
    done
    return $miss
}

# three-state provider detection: creds-present | creds-missing | tool-missing
rc_state() {
    if ! command -v aws >/dev/null 2>&1; then echo tool-missing
    elif [ -n "${AWS_ACCESS_KEY_ID:-}" ] || [ -f "$HOME/.aws/credentials" ]; then echo creds-present
    else echo creds-missing; fi
}

# Parse a trust policy JSON into rows:
# trust	role-arn	principal-arn|wildcard	principal-type	has-condition(0/1)
rc_parse_trust() {
    local doc="$1" role="${2:-unknown}" cond p ptype
    cond="$(printf '%s' "$doc" | jq -r '[.Statement[]?.Condition?] | map(select(.!=null)) | length' 2>/dev/null)"
    if [ "${cond:-0}" -gt 0 ] 2>/dev/null; then cond=1; else cond=0; fi
    local principals
    principals="$(printf '%s' "$doc" | jq -r '
[.Statement[]?.Principal? as $p
 | if ($p|type)=="string" then [[$p,"string"]]
   elif ($p|type)=="object" then
     ( [ $p.AWS? ] + [ $p.Service? ] + [ $p.Federated? ]
       | flatten
       | map(select(. != null))
       | map([(. | tostring), "principal"]) )
   else [] end]
 | .[]? | .[]? | @tsv' 2>/dev/null)"
    while IFS=$'\t' read -r p ptype; do
        [ -z "$p" ] && continue
        printf 'trust\t%s\t%s\t%s\t%s\n' "$role" "$p" "$ptype" "$cond"
    done <<<"$principals"
}

# --scan: collect existing roles + trust policies via aws iam list-roles/get-role
rc_cmd_scan() {
    case "$(rc_state)" in
        tool-missing)  rc_log 'install aws CLI to scan live'; return 0 ;;
        creds-missing) rc_log 'no AWS credentials'; return 0 ;;
    esac
    local name arn doc
    AWS_PAGER='' aws iam list-roles --output json 2>/dev/null | jq -r '.Roles[]?.RoleName' 2>/dev/null \
        | while read -r name; do
            [ -z "$name" ] && continue
            doc="$(AWS_PAGER='' aws iam get-role --role-name "$name" --output json 2>/dev/null \
                | jq -r '.Role.AssumeRolePolicyDocument // empty' 2>/dev/null)"
            [ -z "$doc" ] && continue
            arn="$(AWS_PAGER='' aws iam get-role --role-name "$name" --query 'Role.Arn' --output text 2>/dev/null)"
            rc_parse_trust "$doc" "$arn" >> "$RESULT_FILE"
        done
    if [ -s "$RESULT_FILE" ]; then
        awk -F'\t' '$1=="trust"' "$RESULT_FILE" | tee "$CHAIN_FILE"
    fi
    rc_log "trust rows -> $RESULT_FILE"
}

# --chain <role-arn>: walk assume-role hops and record policy grants
rc_cmd_chain() {
    local start="${1:?usage: --chain <role-arn>}" depth="${RC_MAX_DEPTH:-3}" hop target out
    rc_check_deps || return 2
    for hop in $(seq 1 "$depth"); do
        out="$(AWS_PAGER='' aws sts assume-role --role-arn "$start" --role-session-name "cloudsting-chain-$hop" \
                --query 'Credentials' --output text 2>&1)" || continue
        case "$out" in
            *AccessDenied*)
                printf 'denied\t%s\tdepth=%s\n' "$start" "$hop" | tee -a "$CHAIN_FILE"
                continue ;;
        esac
        printf 'assumed\t%s\tdepth=%s\n' "$start" "$hop" | tee -a "$CHAIN_FILE"
        AWS_PAGER='' aws iam list-attached-role-policies --role-name "${start##*/}" \
            --query 'AttachedPolicies[].PolicyName' --output text 2>/dev/null \
            | tr '\t' '\n' >> "$CHAIN_FILE"
        break
    done
}

# --whoami: identity context
rc_cmd_whoami() {
    rc_check_deps || return 2
    AWS_PAGER='' aws sts get-caller-identity --output json 2>/dev/null \
        | jq -r '"account\t" + (.Account // "") + "\nuser\t" + (.Arn // "") + "\nuserid\t" + (.UserId // "")'
}

# --list: show trust rows from last loot (or fallback note)
rc_cmd_list() {
    if [ -s "$CHAIN_FILE" ]; then awk -F'\t' '{print}' "$CHAIN_FILE"
    else rc_log 'scan first (--scan) to populate chain/roles loot'; return 3; fi
}

# --status-tsv: 3 fields
rc_cmd_status_tsv() { printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "$(rc_state)"; }

# --menu
rc_cmd_menu() { printf 'menu\t%s\t[%s]\n' "$MODULE_ID" "$MOD_NAME"; }

# --help
rc_cmd_help() {
cat <<HELP
$MODULE_ID v$MOD_VERSION — $MOD_NAME
VERBS
  --scan              collect roles + trust policies (live, requires creds)
  --chain <role-arn>  attempt assume-role walk, log access grants
  --whoami            sts identity summary
  --list              show trust rows from last loot run
  --status-tsv        three-field status
  --menu | --selftest | --help
ENV
  RC_MAX_DEPTH (default 3) — assume-role chain depth
LOOT
  loot/role_chains/roles-$RC_RUN_ID.tsv + chains-$RC_RUN_ID.tsv
HELP
}

# selftest
rc_selftest() {
    local pass=0 fail=0
    chk() { if [ "$1" = "$2" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$3"
            else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$3" "$2" "$1"; fi; }

    local doc
    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}'
    chk "$(rc_parse_trust "$doc" | wc -l)" 1 parse-cross-account-row
    chk "$(rc_parse_trust "$doc" | awk -F'\t' '{print NF}' | sort -u | tail -1)" 5 parse-fields-5

    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    chk "$(rc_parse_trust "$doc" | grep -c ec2)" 1 parse-service-principal

    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}'
    chk "$(rc_parse_trust "$doc" | wc -l)" 1 parse-wildcard-row

    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:a","arn:b"]},"Action":"sts:AssumeRole"}]}'
    chk "$(rc_parse_trust "$doc" | wc -l)" 2 parse-multi-principal

    chk "$(rc_cmd_status_tsv | awk -F'\t' '{print NF}')" 3 status-fields
    chk "$(rc_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID" status-module

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# dispatcher
rc_dispatch() {
    local verb="${1:---help}"
    shift || true
    case "$verb" in
        --scan)       rc_cmd_scan ;;
        --chain)      rc_cmd_chain "$@" ;;
        --whoami)     rc_cmd_whoami ;;
        --list)       rc_cmd_list ;;
        --status-tsv) rc_cmd_status_tsv ;;
        --menu)       rc_cmd_menu ;;
        --selftest)   rc_selftest ;;
        --help|-h)    rc_cmd_help ;;
        *)            rc_log "unknown verb: $verb"; rc_cmd_help; return 2 ;;
    esac
}

if [ "${CLOUDSTING_SOURCE_ONLY:-0}" != "0" ]; then
    return 0 2>/dev/null || true
fi
[ "${BASH_SOURCE[0]}" = "$0" ] && rc_dispatch "$@"
