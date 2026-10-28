#!/usr/bin/env bash
# 07_policy_audit.sh — cloudsting module 07: AWS IAM policy auditor (wildcards, privilege holes)
# Verbs: --audit | --explain | --check | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="07_policy_audit"
MOD_NAME="IAM Policy Auditor"
MOD_VERSION="0.2.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export PA_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/policy_audit"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
FINDINGS_FILE="$OUT_DIR/findings-$RUN_ID.tsv"

pa_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# three-state provider detection: creds-present | creds-missing | tool-missing
pa_state() {
    if ! command -v aws >/dev/null 2>&1; then echo tool-missing
    elif [ -n "${AWS_ACCESS_KEY_ID:-}" ] || [ -f "$HOME/.aws/credentials" ]; then echo creds-present
    else echo creds-missing; fi
}

# Risk rule knowledge base.
# Row: rule-id  severity  description  pattern(jq)
# Rows: rule-id<TAB>severity<TAB>description<TAB>jit (jq filter)
pa_rules() {
cat <<'RULES'
wildcard-action	high	Action with '*' grants everything	any(.Statement[]?; (.Action == "*" or ((.Action|type)=="array" and any(.Action[]?; .=="*"))))
wildcard-resource	high	Resource '*' on non-idempotent action	any(.Statement[]?; (.Resource == "*" or ((.Resource|type)=="array" and any(.Resource[]?; .=="*"))))
wildcard-both	critical	Both Action and Resource are '*' (root-level admin)	any(.Statement[]?; ((.Action|type)=="string" and .Action=="*") or ((.Action|type)=="array" and any(.Action[]?; .=="*")) and ((.Resource|type)=="string" and .Resource=="*" or ((.Resource|type)=="array" and any(.Resource[]?; .=="*"))))
iam-write-passrole	critical	sts:PassRole or iam:*Write on trusts	any(.Statement[]?.Action[]?; test("PassRole|iam:\\*"))
notaction	medium	NotAction — deny-shaped but often permissive	any(.Statement[]?; .NotAction?)
notresource	medium	NotResource — applies to everything NOT listed	any(.Statement[]?; .NotResource?)
unrestricted-principal	high	Principal '*' in trust policy	any(.Statement[]?.Principal?; . == "*" or ((type=="object") and any((.AWS | if type=="array" then . elif type=="string" then [.] else [] end)[]?; .=="*")))
no-effect-deny	medium	Statement Effect not 'Allow' or 'Deny'	any(.Statement[]?; ((.Effect // "") != "Allow") and ((.Effect // "") != "Deny"))
RULES
}

# --list: show rules table
pa_cmd_list() { pa_rules; }

# pa_audit_doc <policy-json> <policy-name>
# Emits: finding<TAB>policy<TAB>rule-id<TAB>severity<TAB>description
pa_audit_doc() {
    local doc="$1" name="${2:-unnamed}" rule_id severity desc filter_text out
    while IFS=$'\t' read -r rule_id severity desc filter_text; do
        [ -z "$rule_id" ] && continue
        if printf '%s' "$doc" | jq -e "$filter_text" >/dev/null 2>&1; then
            printf 'finding\t%s\t%s\t%s\t%s\n' "$name" "$rule_id" "$severity" "$desc"
        fi
    done <<EORULES
$(pa_rules)
EORULES
}

# --audit <file|-> : audit a local policy file (or stdin), or live account policies
pa_cmd_audit() {
    local src="${1:--}"
    local rc=0
    if [ "$src" = "-" ] || [ -f "$src" ]; then
        local doc=""
        if [ "$src" = "-" ]; then doc="$(cat)"
        else doc="$(cat "$src")"; fi
        [ -z "$doc" ] && { pa_log 'empty policy input'; return 2; }
        pa_audit_doc "$doc" "$(basename "$src")" | tee -a "$FINDINGS_FILE"
        rc=$?
        pa_log "findings -> $FINDINGS_FILE"
        return $rc
    fi
    case "$(pa_state)" in
        tool-missing)  pa_log 'install aws CLI for live audit'; return 0 ;;
        creds-missing) pa_log 'no AWS credentials'; return 0 ;;
    esac
    local policies
    policies="$(AWS_PAGER='' aws iam list-policies --scope Local --query 'Policies[].{Name:PolicyName,Arn:Arn}' --output json 2>/dev/null)"
    if [ -z "$policies" ]; then
        pa_log 'could not list policies (permission denied?)'
        return 1
    fi
    printf '%s' "$policies" | jq -r '.[]? | .Arn + "\t" + .Name' 2>/dev/null \
        | while IFS=$'\t' read -r arn name; do
            [ -z "$arn" ] && continue
            local vdoc
            vdoc="$(AWS_PAGER='' aws iam get-policy-version --policy-arn "$arn" \
                    --query 'PolicyVersion.Document' --output json 2>/dev/null)"
            [ -z "$vdoc" ] || [ "$vdoc" = "null" ] && continue
            pa_audit_doc "$vdoc" "$name" >> "$FINDINGS_FILE"
        done
    [ -s "$FINDINGS_FILE" ] && awk -F'\t' '$1=="finding"' "$FINDINGS_FILE"
    pa_log "findings -> $FINDINGS_FILE"
    return 0
}

# --check <pattern>: grep policy JSON for a specific keyword (e.g. PassRole)
pa_cmd_check() {
    local kw="${1:?usage: --check <keyword>}"
    local doc=""; doc="$(cat)"
    [ -z "$doc" ] && { pa_log 'feed a policy on stdin'; return 2; }
    printf '%s' "$doc" | jq -r --arg k "$kw" '
        def acts($a): if ($a|type)=="string" then [$a] elif ($a|type)=="array" then ($a | map(tostring)) else [] end;
        [.Statement[]? | (acts(.NotAction? // [])) as $na
          | (acts(.Action? // [])) as $aa
          | ($aa + $na)[]? | select(test($k; "i")) | "action\t" + .] | .[]' 2>/dev/null
}

# --explain <rule-id>: show rule row detail
pa_cmd_explain() {
    local r="${1:?usage: --explain <rule-id>}"
    pa_rules | awk -F'\t' -v r="$r" 'tolower($1) ~ tolower(r) { print $1 "\t" $2 "\t" $3; print "  filter: " $4 }'
}

# --status-tsv: 3 fields
pa_cmd_status_tsv() { printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "$(pa_state)"; }

# --menu
pa_cmd_menu() { printf 'menu\t%s\t[%s]\n' "$MODULE_ID" "$MOD_NAME"; }

# --help
pa_cmd_help() {
cat <<HELP
$MODULE_ID v$MOD_VERSION — $MOD_NAME
VERBS
  --audit <file|->    audit local policy JSON (or '-') for risky patterns
  --audit             (with creds) enumerate & audit account-local policies
  --check <kw>        grep stdin policy for keyword (e.g. PassRole)
  --explain <rule>    describe an audit rule from the knowledge base
  --list              print all audit rules (id, severity, jq filter)
  --status-tsv        3-field status
  --menu | --selftest | --help
LOOT
  loot/policy_audit/findings-$PA_RUN_ID.tsv rows: finding<TAB>policy<TAB>rule<TAB>severity<TAB>desc
HELP
}

# selftest
pa_selftest() {
    local pass=0 fail=0
    chk() { local name="$1" got="$2" want="$3"
            if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$name"
            else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$name" "$want" "$got"; fi; }

    chk rules-count "$(pa_rules | grep -c .)" 8
    chk rules-fields "$(pa_rules | awk -F'\t' 'NF!=4' | wc -l)" 0

    local doc
    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    chk wc-both "$(pa_audit_doc "$doc" test | grep -c wildcard-both)" 1 wildcard-both-caught
    chk wa-act  "$(pa_audit_doc "$doc" test | grep -c wildcard-action)" 1 wildcard-action-caught
    chk wa-res  "$(pa_audit_doc "$doc" test | grep -c wildcard-resource)" 1 wildcard-resource-caught
    chk clean-print "$(pa_audit_doc "$doc" test | wc -l)" 3 wildcard-doc-yields-3

    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}'
    chk clean-0 "$(pa_audit_doc "$doc" clean | wc -l)" 0 clean-policy-yields-0

    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}'
    chk trust-star "$(pa_audit_doc "$doc" t | grep -c unrestricted-principal)" 1 unrestricted-principal-caught

    doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}'
    chk notaction "$(pa_audit_doc "$doc" n | grep -c "^finding.*notaction")" 1 notaction-caught

    chk fields-5 "$(pa_audit_doc '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' x | awk -F'\t' '{print NF}' | sort -u | tail -1)" 5 findings-fields-5
    chk status-shape "$(pa_cmd_status_tsv | awk -F'\t' '{print NF}')" 3 status-fields
    chk status-module "$(pa_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID" status-module

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# dispatcher
pa_dispatch() {
    local verb="${1:---help}"
    shift || true
    case "$verb" in
        --audit)      pa_cmd_audit "$@" ;;
        --check)      pa_cmd_check "$@" ;;
        --explain)    pa_cmd_explain "$@" ;;
        --list)       pa_cmd_list ;;
        --status-tsv) pa_cmd_status_tsv ;;
        --menu)       pa_cmd_menu ;;
        --selftest)   pa_selftest ;;
        --help|-h)    pa_cmd_help ;;
        *)            pa_log "unknown verb: $verb"; pa_cmd_help; return 2 ;;
    esac
}

if [ "${CLOUDSTING_SOURCE_ONLY:-0}" != "0" ]; then
    return 0 2>/dev/null || true
fi
[ "${BASH_SOURCE[0]}" = "$0" ] && pa_dispatch "$@"
