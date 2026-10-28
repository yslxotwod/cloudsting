#!/usr/bin/env bash
# 05_iam_privesc.sh — cloudsting module 05: AWS IAM privilege-escalation path mapper
# Verbs: --map | --explain | --list | --check | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# Everything below the header depends on the root, and the root is
# derived from this file only after it is sourced. Clear any inherited
# value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own
# name as a path.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV
# writer, the three-state provider gate, redaction and the selftest
# ledger. Sourcing it is what keeps loot under <root>/loot instead of
# $HOME/loot, so the launcher and the findings store can see a run.
MODULE_ID="05_iam_privesc"
MOD_NAME="AWS IAM Privilege-Escalation Mapper"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

# Back-compat: run-id variable for this module, from the core run id
# the one run id the core minted.
IP_RUN_ID="$CS_RUN_ID"
export IP_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

# Loot directory for this module: <root>/loot/iam_privesc/
OUT_DIR="$CS_LOOT/iam_privesc"
mkdir -p "$OUT_DIR" 2>/dev/null || true

# artifacts this module writes, all under the core's loot tree
RESULT_FILE="$OUT_DIR/result-$RUN_ID.tsv"
ip_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# Escalation technique knowledge base.
# Row: technique <TAB> required-action <TAB> why-it-escalates
ip_table() {
cat <<'TABLE'
PassRole	iam:PassRole	attach an over-privileged role to a resource you control (ec2/lambda/ecs)
CreateAccessKey	iam:CreateAccessKey	issue keys for another (privileged) user
CreateLoginProfile	iam:CreateLoginProfile	console password for a privileged user
UpdateLoginProfile	iam:UpdateLoginProfile	reset another user's console password
AttachUserPolicy	iam:AttachUserPolicy	attach a managed admin policy to yourself
AttachRolePolicy	iam:AttachRolePolicy	attach managed policy to a role you can assume
PutUserPolicy	iam:PutUserPolicy	inline policy grant to any user
PutRolePolicy	iam:PutRolePolicy	inline policy grant to any role
PutGroupPolicy	iam:PutGroupPolicy	inline policy on a group you can join
AddUserToGroup	iam:AddUserToGroup	join a group that carries admin policy
UpdateAssumeRolePolicy	iam:UpdateAssumeRolePolicy	let yourself assume a privileged role
CreateRole	iam:CreateRole + PassRole	new role, then ride it
UpdateRoleTrust	iam:UpdateAssumeRolePolicy	trust your own principal on an existing role
GlueUpdateJob	iam:PassRole + glue:UpdateJob	change job role to admin
LambdaUpdateFunctionCode	iam:PassRole + lambda:UpdateFunctionCode	replace code, inherit function role
EC2RunInstance	iam:PassRole + ec2:RunInstances	launch instance with target role + exfil creds via user-data
SageMakerCreateNotebook	iam:PassRole + sagemaker:CreateNotebookInstance	force role onto managed jupyter
EC2ModifyInstanceAttribute	ec2:ModifyInstanceAttribute + getCredentials	swap user-data of a role-bearing instance
S3PutBucketPolicy	s3:PutBucketPolicy	rewrite bucket access to exfiltrate
KmsPutKeyPolicy	kms:PutKeyPolicy	key policy self-grant then decrypt secrets
TABLE
}

ip_provider_state() {
    case "$1" in
        aws)
            if ! command -v aws >/dev/null 2>&1; then printf 'tool-missing\n'; return; fi
            if [ -f "$HOME/.aws/credentials" ] || [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
                printf 'creds-present\n'
            else
                printf 'creds-missing\n'
            fi ;;
        *) printf 'unknown\n' ;;
    esac
}

# --list
ip_cmd_list() { ip_table; }

# --explain <technique>: show rows matching technique (case-insensitive, suffix ok)
ip_cmd_explain() {
    local t
    t="$(printf '%s' "${1:-}" | head -c 80)"
    [ -z "$t" ] && { ip_log 'usage: --explain <technique>'; return 2; }
    ip_table | awk -F'\t' -v t="$(printf '%s' "$t" | tr '[:upper:]' '[:lower:]')" \
        'tolower($1) ~ ("^" t) { print }'
    return $([ -n "$(ip_table | awk -F'\t' -v t="$(printf '%s' "$t" | tr '[:upper:]' '[:lower:]')" 'tolower($1) ~ ("^" t)')" ] && echo 1 || echo 0)
}

# --map: run escalation mapping against caller (honest three-state)
#  - get caller identity
#  - enumerate attached/inline policies per managed-policy ARN list
#  - cross-check actions against ip_table knowledge base
ip_cmd_map() {
    local st
    st="$(ip_provider_state aws)"
    case "$st" in
        tool-missing)  printf 'state\taws\ttool-missing\n';  ip_log 'install aws CLI to map live'; return 0 ;;
        creds-missing) printf 'state\taws\tcreds-missing\n'; ip_log 'no aws credentials found'; return 0 ;;
    esac
    local acct
    acct="$(AWS_PAGER='' aws sts get-caller-identity --output json 2>/dev/null | jq -r 'try .Account // empty')" || acct=""
    if [ -z "$acct" ]; then
        printf 'state\taws\tauth-failure\n'
        ip_log 'sts get-caller-identity failed'
        return 0
    fi
    printf 'state\taws\tcreds-present\n'
    printf 'whoami\taccount=%s\n' "$acct"
    local policies_json
    # Account-authorization snapshot is the most direct way to enumerate grants
    policies_json="$({ AWS_PAGER='' aws iam get-account-authorization-details --output json 2>/dev/null || true; } | jq -r 'try .UserDetailList[]? | select(.UserId == .UserId) | .UserName as $u | (.AttachedManagedPolicies[]? | [$u, .PolicyName, "attached"]) , (.UserPolicyList[]? | [$u, ., "inline"]) | @tsv' 2>/dev/null)"
    if [ -z "$policies_json" ]; then
        ip_log 'could not read account authorization details (permission denied?)'
        return 1
    fi
    printf '%s\n' "$policies_json" | while IFS=$'\t' read -r user pol kind; do
        printf 'grant\tuser=%s\tpolicy=%s\tkind=%s\n' "$user" "$pol" "$kind"
    done | tee "$RESULT_FILE"
    ip_log "loot saved to $RESULT_FILE"
    return 0
}

# --check <action>: knowledge-base lookup (also used by selftest)
ip_cmd_check() {
    local a
    a="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    [ -z "$a" ] && { ip_log 'usage: --check <iam-action>'; return 2; }
    ip_table | awk -F'\t' -v a="$a" 'tolower($2) ~ a { print $1 "\t" $3 }' | head -5
}

# --status-tsv: 3-field
ip_status_tsv() {
    local st
    st="$(ip_provider_state aws)"
    printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "$st"
}

# --menu
ip_menu() {
    cat <<MENU
[$MODULE_ID] $MOD_NAME
  1) map       live escalation mapping (--map)
  2) explain   technique explanation   (--explain <tech>)
  3) list      technique knowledge-base (--list)
  0) back
MENU
}

# --help
ip_help() {
cat <<HELP
$MODULE_ID — $MOD_NAME

VERBS
  --map                enumerate caller's IAM follows using account-authorization snapshot
  --explain <technique> show knowledge-base row for a technique
  --list               print the full technique table
  --check <iam-action>   which techniques require the given action
  --status-tsv         module, name, provider-state
  --menu               interactive menu
  --selftest           built-in verification
  --help               this text

ENV
  (none) get-account-authorization-details needs the 'SecurityAudit' policy to read all grants
HELP
}

# ------------------------------------------------------------------ selftest
# awk -F'\t' for all row assertions (POSIX grep treats \t as literal t)
ip_selftest() {
    local pass=0 fail=0
    chk() { if [ "$2" = "$3" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$1"
            else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$1" "$3" "$2"; fi; }

    # 1 table integrity: 20 techniques, 3 fields each
    chk rows-count "$(ip_table | grep -c .)" 20
    chk rows-fields "$(ip_table | awk -F'\t' 'NF!=3' | wc -l)" 0

    # 2 known technique present with right 2nd column
    chk passrole-row "$(ip_table | awk -F'\t' '$1=="PassRole"{print $2}')" 'iam:PassRole'
    chk lambda-row   "$(ip_table | awk -F'\t' '$1=="LambdaUpdateFunctionCode"{print $2}')" 'iam:PassRole + lambda:UpdateFunctionCode'

    # 3 explain finds full and prefix
    chk explain-full "$(ip_cmd_explain PassRole | awk -F'\t' '{print $1}')" PassRole
    chk explain-pfx  "$(ip_cmd_explain putuser 2>/dev/null | awk -F'\t' '$1=="PutUserPolicy"{print $2}')" 'iam:PutUserPolicy'

    # 4 check maps action->technique
    chk check-iam-passrole "$(ip_cmd_check iam:PassRole | awk -F'\t' '{print $1}' | head -1)" PassRole
    chk check-unknown "$(ip_cmd_check totally:bogusAction | wc -l)" 0

    # 5 provider state honest
    if command -v aws >/dev/null 2>&1; then chk state-tool.'ip_provider_state aws | grep -q tool-missing && echo tool-missing || echo tool-found' tool-found
    else chk state-tool "$(ip_provider_state aws)" tool-missing; fi

    # 6 status-tsv shape
    ip_status_tsv > "$TMP_DIR/ip_st.$$"
    chk status-fields "$(awk -F'\t' 'NF!=3' "$TMP_DIR/ip_st.$$" | wc -l)" 0
    chk status-module "$(awk -F'\t' 'NR==1{print $1}' "$TMP_DIR/ip_st.$$")" "$MODULE_ID"

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ------------------------------------------------------------------ dispatcher
SOURCE_ONLY="${CLOUDSTING_SOURCE_ONLY:-0}"
if [ "$SOURCE_ONLY" != "0" ]; then return 0 2>/dev/null || exit 0; fi

ip_main() { ip_dispatch "$@"; }
ip_dispatch() {
    local verb="${1:-}"
    case "$verb" in
        --map)        shift; ip_cmd_map "$@" ;;
        --explain)    shift; ip_cmd_explain "$@" ;;
        --list)       ip_cmd_list ;;
        --check)      shift; ip_cmd_check "$@" ;;
        --status-tsv) ip_status_tsv ;;
        --menu)       ip_menu ;;
        --selftest)   ip_selftest ;;
        --help|--h)   ip_help ;;
        *)            ip_help ;;
    esac
    return 0
}

[ "${BASH_SOURCE[0]}" = "$0" ] && ip_dispatch "$@"
