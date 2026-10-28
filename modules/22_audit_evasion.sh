#!/usr/bin/env bash
# 22_audit_evasion.sh — cloudsting module 22: audit trail coverage and blind spots
# Verbs: --posture | --blind | --explain | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="22_audit_evasion"
MOD_NAME="Audit Trail Coverage"
MOD_VERSION="0.19.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export AE_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/audit_evasion"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
POSTURE_FILE="$OUT_DIR/posture-$RUN_ID.tsv"

ae_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── Provider gate ────────────────────────────────────────────────
ae_provider_state() {
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

ae_providers() { printf '%s\n' "${AE_PROVIDERS:-aws gcloud azure}" | tr ' ' '\n' | sed '/^$/d'; }

# ── What each provider must have switched on ────────────────────
# check<TAB>provider<TAB>what-it-covers<TAB>severity-if-off<TAB>why
ae_checks() {
cat <<'CHECKS'
kms-key	aws	server-side encryption of the trail itself	high	without a KMS key the trail can be deleted by whoever holds the bucket
log-validation	aws	log file integrity validation	medium	without digests, a tampered or truncated trail cannot be proven tampered
multi-region	aws	trail covers every region	high	a single-region trail misses activity in regions nobody watches
data-events	aws	S3 object-level and Lambda-level events	high	calls that touch objects and functions are invisible by default
org-trail	aws	trail applies to the whole organisation	medium	per-account trails leave newly created accounts blind
trail-active	aws	logging is actually on	critical	a stopped trail records nothing at all
audit-log-active	gcloud	Data Access audit logs enabled	high	Data Access logs are off unless explicitly enabled per service
log-bucket-retention	gcloud	log bucket retention lock	medium	without a lock the trail can be deleted, and deletion is the attack
log-sink	gcloud	project logs routed to a sink	high	unsunk logs die with the project
activity-log-export	azure	activity log exported off-platform	high	an in-platform log dies with the subscription
diagnostics	azure	resource diagnostic settings	high	per-resource logs are opt-in and silent by default
retention-azure	azure	exported log retention	medium	90 days is the default and usually shorter than dwell time
CHECKS
}

ae_cmd_list() {
    printf '#check\tprovider\tcovers\tseverity-if-off\twhy\n'
    ae_checks
}

ae_cmd_explain() {
    local want="${1:-}"
    if [ -z "$want" ]; then
        printf 'usage: --explain <check>\n' >&2
        return 2
    fi
    local hit
    hit="$(ae_checks | awk -F'\t' -v w="$want" '$1==w || index($1, w)==1')"
    if [ -z "$hit" ]; then
        printf 'unknown check: %s\n' "$want" >&2
        return 1
    fi
    printf '%s\n' "$hit" | while IFS=$'\t' read -r n p covers sev why; do
        printf '%-22s %s\n' "check" "$n"
        printf '%-22s %s\n' "provider" "$p"
        printf '%-22s %s\n' "severity if off" "$sev"
        printf '%-22s %s\n' "covers" "$covers"
        printf '%-22s %s\n' "why it matters" "$why"
    done
}

# ── Live posture collection ────────────────────────────────────
# Emits: provider<TAB>check<TAB>state<TAB>detail   state in on|off|unknown
ae_posture_aws() {
    command -v aws >/dev/null 2>&1 || return 1
    local trails names name out
    if ! trails="$(aws cloudtrail describe-trails --output json 2>/dev/null)"; then
        printf 'aws\t%s\tunknown\tdescribe-trails failed\n' "trail-active"
        return 0
    fi
    names="$(printf '%s' "$trails" | jq -r 'try (.trailList[]?.Name) // empty' 2>/dev/null)"
    if [ -z "$names" ]; then
        printf 'aws\t%s\t%s\tno trail exists\n' "trail-active" "off"
        return 0
    fi
    printf '%s\n' "$names" | while read -r name; do
        [ -z "$name" ] && continue
        out="$(aws cloudtrail get-trail-status --name "$name" --output json 2>/dev/null)"
        if [ -n "$out" ]; then
            printf '%s' "$out" | jq -r --arg n "$name" 'try
              (if (.IsLogging // false) then "on" else "off" end) as $st |
              ["aws", "trail-active", $st,
               ($n + ": " + (if $st == "on" then "logging" else "NOT logging" end))]
              | @tsv' 2>/dev/null
        fi
    done
    # attributes that decide whether the trail is worth anything
    local kms mrv global
    kms="$(printf '%s' "$trails" | jq -r 'try (.trailList[]?.KmsKeyId) // empty' 2>/dev/null | grep -c . )"
    mrv="$(printf '%s' "$trails" | jq -r 'try ([.trailList[]? | select(.IsMultiRegionTrail==true)] | length) // 0' 2>/dev/null)"
    global="$(printf '%s' "$trails" | jq -r 'try ([.trailList[]? | select(.IncludeGlobalServiceEvents==true)] | length) // 0' 2>/dev/null)"
    printf 'aws\tkms-key\t%s\t%s trail(s) with a KMS key\n' \
        "$( [ "${kms:-0}" -gt 0 ] && printf on || printf off )" "${kms:-0}"
    printf 'aws\tmulti-region\t%s\t%s multi-region trail(s)\n' \
        "$( [ "${mrv:-0}" -gt 0 ] && printf on || printf off )" "${mrv:-0}"
    printf 'aws\tlog-validation\t%s\tglobal service events included by %s trail(s)\n' \
        "$( [ "${global:-0}" -gt 0 ] && printf on || printf off )" "${global:-0}"
}

ae_posture_gcloud() {
    command -v gcloud >/dev/null 2>&1 || return 1
    local cfg
    if ! cfg="$(gcloud logging sinks list --format=json 2>/dev/null)"; then
        printf 'gcloud\tlog-sink\tunknown\tsinks list failed\n'
        return 0
    fi
    local n
    n="$(printf '%s' "$cfg" | jq -r 'try (length) // 0' 2>/dev/null)"
    printf 'gcloud\tlog-sink\t%s\t%s sink(s) configured\n' \
        "$( [ "${n:-0}" -gt 0 ] && printf on || printf off )" "${n:-0}"
}

ae_posture_azure() {
    command -v az >/dev/null 2>&1 || return 1
    local settings
    if ! settings="$(az monitor diagnostic-settings subscription list -o json 2>/dev/null)"; then
        printf 'azure\tdiagnostics\tunknown\tsubscription diagnostics unreadable\n'
        return 0
    fi
    local n
    n="$(printf '%s' "$settings" | jq -r 'try (.value | length) // 0' 2>/dev/null)"
    printf 'azure\tdiagnostics\t%s\t%s subscription diagnostic setting(s)\n' \
        "$( [ "${n:-0}" -gt 0 ] && printf on || printf off )" "${n:-0}"
}

ae_collect() {
    local p state any=0
    : > "$POSTURE_FILE"
    for p in $(ae_providers); do
        state="$(ae_provider_state "$p")"
        if [ "$state" != "creds-present" ]; then
            printf 'state\t%s\t%s\n' "$p" "$state"
            continue
        fi
        any=1
        case "$p" in
            aws)    ae_posture_aws;;
            gcloud) ae_posture_gcloud;;
            azure)  ae_posture_azure;;
        esac 2>/dev/null | tee -a "$POSTURE_FILE"
    done
    [ "$any" -eq 0 ] && ae_log "no provider reachable; posture unknown for every provider"
    return 0
}

ae_cmd_posture() { ae_collect; }

# A blind spot is a control the catalogue requires but the account does not
# have on, plus every control the collection could not observe at all.
ae_blind_from_posture() {
    local file="${1:-$POSTURE_FILE}" provider check state detail
    local -A seen=()
    if [ -s "$file" ]; then
        while IFS=$'\t' read -r provider check state detail; do
            [ -z "${provider:-}" ] && continue
            [ "$provider" = "state" ] && continue
            seen["$provider/$check"]=1
            case "$state" in
                off)     printf 'high\t%s\t%s\t%s\n' "$provider" "$check" "${detail:-disabled}" ;;
                unknown) printf 'low\t%s\t%s\t%s\n' "$provider" "$check" "${detail:-not observable}" ;;
            esac
        done < "$file"
    fi
    local n p covers sev why
    while IFS=$'\t' read -r n p covers sev why; do
        [ -z "${n:-}" ] && continue
        [ -n "${seen["$p/$n"]:-}" ] && continue
        # controls the live collection never looked at are the honest blind spots
        printf '%s\t%s\t%s\tnot evaluated (no reachable %s account)\n' "$sev" "$p" "$n" "$p"
    done < <(ae_checks)
}

ae_cmd_blind() {
    ae_collect >/dev/null 2>&1 || true
    local out
    out="$(ae_blind_from_posture "$POSTURE_FILE")"
    if [ -z "$out" ]; then
        printf 'every catalogued control was observed and is on\n'
        return 0
    fi
    printf '%s\n' "$out"
    printf 'SUMMARY\t%s\n' "$(printf '%s\n' "$out" | awk -F'\t' '{c[$1]++} END {for (k in c) printf "%s=%d ", k, c[k]}')"
}

ae_cmd_status_tsv() {
    local p
    printf 'module\t%s\t%s\n' "$MODULE_ID" "$MOD_VERSION"
    for p in $(ae_providers); do
        printf 'provider\t%s\t%s\n' "$p" "$(ae_provider_state "$p")"
    done
    printf 'checks\tcatalogue\t%s\n' "$(ae_checks | wc -l | tr -d ' ')"
}

ae_cmd_menu() {
    printf 'posture\tObserve the audit configuration now\n'
    printf 'blind\tControls that are off or unobserved\n'
    printf 'list\tEvery control this module looks for\n'
}

ae_cmd_help() {
    cat <<HELP
cloudsting module 22 — Audit Trail Coverage v$MOD_VERSION

  --posture          observe the live audit configuration
  --blind            controls that are off, or were never observable
  --explain <check>  what one control covers and why it matters
  --list             the full control catalogue
  --status-tsv       module status
  --menu             menu entries
  --selftest         run selftests
  --help             this message

This module does not disable anything. It reports which audit controls are
missing, which is the same list an operator needs to fix. Loot: $OUT_DIR
HELP
}

# ── Selftest ────────────────────────────────────────────────────
ae_selftest() {
    local pass=0 fail=0 shim out
    chk() {
        local name="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then
            printf 'ok\t%s\n' "$name"; pass=$((pass+1))
        else
            printf 'FAIL\t%s\twant=%s got=%s\n' "$name" "$want" "$got"; fail=$((fail+1))
        fi
    }

    chk checks-count "$(ae_checks | wc -l | tr -d ' ')" 12
    chk checks-fields "$(ae_checks | awk -F'\t' 'NF != 5' | wc -l | tr -d ' ')" 0
    chk checks-aws "$(ae_checks | awk -F'\t' '$2=="aws"' | wc -l | tr -d ' ')" 6
    chk checks-gcloud "$(ae_checks | awk -F'\t' '$2=="gcloud"' | wc -l | tr -d ' ')" 3
    chk checks-azure "$(ae_checks | awk -F'\t' '$2=="azure"' | wc -l | tr -d ' ')" 3
    chk list-header "$(ae_cmd_list | head -1 | grep -c '^#check')" 1
    chk explain-hit "$(ae_cmd_explain kms-key | grep -c 'KMS')" 1
    chk explain-prefix "$(ae_cmd_explain retention | grep -c retention-azure)" 1
    chk explain-miss "$(ae_cmd_explain nonsense >/dev/null 2>&1; echo $?)" 1
    chk status-fields "$(ae_cmd_status_tsv | awk -F'\t' 'NF != 3' | wc -l | tr -d ' ')" 0
    chk state-known "$(ae_provider_state aws | grep -cE '^(tool-missing|creds-missing|creds-present)$')" 1
    chk menu-rows "$(ae_cmd_menu | wc -l | tr -d ' ')" 3

    # blind-spot logic: an explicit "off" is high, "unknown" is low, and a
    # control nobody observed is reported as unevaluated rather than as fine.
    shim="$(mktemp -d)"
    printf 'aws\ttrail-active\toff\tmain: NOT logging\n' > "$shim/posture"
    printf 'aws\tkms-key\tunknown\tdescribe-trails failed\n' >> "$shim/posture"
    out="$(ae_blind_from_posture "$shim/posture")"
    chk blind-off-high "$(printf '%s' "$out" | awk -F'\t' '$2=="aws" && $3=="trail-active"{print $1}')" high
    chk blind-unknown-low "$(printf '%s' "$out" | awk -F'\t' '$2=="aws" && $3=="kms-key"{print $1}')" low
    chk blind-unevaluated "$(printf '%s' "$out" | awk -F'\t' '$2=="gcloud" && $3=="log-sink"{print $1}')" high
    chk blind-unevaluated-count "$(printf '%s\n' "$out" | grep -c 'not evaluated')" 10
    chk blind-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF != 4' | wc -l | tr -d ' ')" 0
    chk blind-clean "$(printf 'state\taws\tcreds-present\naws\ttrail-active\ton\tmain\n' > "$shim/p2";
                        printf '' >/dev/null; ae_blind_from_posture "$shim/p2" | grep -c .)" 11

    # Trail status parsing through a shim that answers like CloudTrail.
    cat > "$shim/aws" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  "cloudtrail describe-trails")
    cat <<'JSON'
{"trailList":[{"Name":"main","KmsKeyId":"arn:aws:kms:us-east-1:111:key/abc",
              "IsMultiRegionTrail":true,"IncludeGlobalServiceEvents":true}]}
JSON
    ;;
  "cloudtrail get-trail-status")
    printf '{"IsLogging":%s}\n' "$([ "$4" = "main" ] && echo true || echo false)" ;;
  *) exit 1 ;;
esac
SH
    chmod +x "$shim/aws"
    out="$(PATH="$shim:$PATH" bash -c 'source "'"$MOD_DIR"'/22_audit_evasion.sh"; ae_posture_aws')"
    chk aws-trail-on "$(printf '%s\n' "$out" | awk -F'\t' '$2=="trail-active"{print $3}')" on
    chk aws-kms-on "$(printf '%s\n' "$out" | awk -F'\t' '$2=="kms-key"{print $3}')" on
    chk aws-mrv-on "$(printf '%s\n' "$out" | awk -F'\t' '$2=="multi-region"{print $3}')" on
    chk aws-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF != 4' | wc -l | tr -d ' ')" 0

    # A trail that exists but is not logging must read as off, not as fine.
    cat > "$shim/aws" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  "cloudtrail describe-trails") printf '{"trailList":[{"Name":"main"}]}\n' ;;
  "cloudtrail get-trail-status") printf '{"IsLogging":false}\n' ;;
  *) exit 1 ;;
esac
SH
    chmod +x "$shim/aws"
    out="$(PATH="$shim:$PATH" bash -c 'source "'"$MOD_DIR"'/22_audit_evasion.sh"; ae_posture_aws')"
    chk aws-trail-stopped "$(printf '%s\n' "$out" | awk -F'\t' '$2=="trail-active"{print $3}')" off
    chk aws-no-kms "$(printf '%s\n' "$out" | awk -F'\t' '$2=="kms-key"{print $3}')" off

    # No trail at all.
    cat > "$shim/aws" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  "cloudtrail describe-trails") printf '{"trailList":[]}\n' ;;
  *) exit 1 ;;
esac
SH
    chmod +x "$shim/aws"
    out="$(PATH="$shim:$PATH" bash -c 'source "'"$MOD_DIR"'/22_audit_evasion.sh"; ae_posture_aws')"
    chk aws-no-trail "$(printf '%s\n' "$out" | awk -F'\t' '$2=="trail-active"{print $3}')" off
    chk aws-no-trail-detail "$(printf '%s' "$out" | grep -c 'no trail exists')" 1

    rm -rf "$shim"
    chk help-smoke "$(ae_cmd_help 2>/dev/null | head -1 | grep -ci audit)" 1

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --posture)    shift; ae_cmd_posture "$@";;
    --blind)      shift; ae_cmd_blind "$@";;
    --explain)    shift; ae_cmd_explain "$@";;
    --list)       shift; ae_cmd_list;;
    --status-tsv|--status) ae_cmd_status_tsv;;
    --menu)       ae_cmd_menu;;
    --selftest)   ae_selftest;;
    *)            ae_cmd_help;;
esac
