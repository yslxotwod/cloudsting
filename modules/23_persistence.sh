#!/usr/bin/env bash
# 23_persistence.sh — cloudsting module 23: persistence mechanisms in cloud accounts
# Verbs: --footholds | --explain | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="23_persistence"
MOD_NAME="Cloud Persistence"
MOD_VERSION="0.20.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

# this module stays loadable by another script (selftests source it)
MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

# Back-compat: run-id variable for this module, from the core run id
# the one run id the core minted.
PE_RUN_ID="$CS_RUN_ID"
export PE_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

# Loot directory for this module: <root>/loot/persistence/
OUT_DIR="$CS_LOOT/persistence"
mkdir -p "$OUT_DIR" 2>/dev/null || true

# artifacts this module writes, all under the core's loot tree
FIND_FILE="$OUT_DIR/footholds-$RUN_ID.tsv"
pe_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

pe_provider_state() {
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

pe_providers() { printf '%s\n' "${PE_PROVIDERS:-aws gcloud azure}" | tr ' ' '\n' | sed '/^$/d'; }

# ── The mechanism catalogue ─────────────────────────────────────
# mechanism<TAB>provider<TAB>artifact<TAB>severity<TAB>lifecycle<TAB>why
# lifecycle: what removes it — "no-expiry" means nothing does
pe_techniques() {
cat <<'TECH'
access-key	aws	IAM access key	high	no-expiry	A second key on a user survives password resets and MFA enrolment
login-profile	aws	console password on a role/machine user	high	no-expiry	A console password nobody uses is a console login nobody watches
extra-key-old	aws	key not rotated in 365 days	medium	manual	Stale keys are rarely noticed and almost never revoked
trust-policy-wildcard	aws	role trust with a broad principal	high	manual	Anyone matching the principal can re-enter the account at will
role-chain	aws	role that trusts another role you control	high	manual	The chain rebuilds itself after the first hop is cleaned
lambda-backdoor	aws	function with an attacker-controlled trigger	high	no-expiry	Code persistence survives credential rotation entirely
ssm-document	aws	SSM document runnable on instances	medium	manual	Document execution needs no inbound network path
eventbridge-rule	aws	scheduled rule invoking a target	high	no-expiry	A scheduled rule re-creates access on every tick
user-data	aws	AMI or launch template carrying a script	medium	no-expiry	Every instance launched from the template gets the foothold
ghost-user	gcloud	service account key	high	no-expiry	SA keys are not tied to a human and never expire by default
oauth-app	gcloud	third-party OAuth grant	high	manual	The grant outlives the password change that was meant to evict you
cloud-function	gcloud	function with an HTTP trigger	high	no-expiry	Code persistence with a public endpoint
custom-role	azure	role definition with broad actions	high	manual	Custom roles escape the review applied to built-in ones
app-registration	azure	service principal credential	high	no-expiry	Client secrets default to long lifetimes nobody tracks
automation-account	azure	runbook with a schedule	high	no-expiry	Scheduled automation re-establishes access on a timer
TECH
}

pe_cmd_list() {
    printf '#mechanism\tprovider\tartifact\tseverity\tremoval\twhy\n'
    pe_techniques
}

pe_cmd_explain() {
    local want="${1:-}"
    if [ -z "$want" ]; then
        printf 'usage: --explain <mechanism>\n' >&2
        return 2
    fi
    local hit
    hit="$(pe_techniques | awk -F'\t' -v w="$want" '$1==w || index($1, w)==1')"
    if [ -z "$hit" ]; then
        printf 'unknown mechanism: %s\n' "$want" >&2
        return 1
    fi
    printf '%s\n' "$hit" | while IFS=$'\t' read -r m p art sev life why; do
        printf '%-20s %s\n' "mechanism" "$m"
        printf '%-20s %s\n' "provider" "$p"
        printf '%-20s %s\n' "artifact" "$art"
        printf '%-20s %s\n' "severity" "$sev"
        printf '%-20s %s\n' "removed by" "$life"
        printf '%-20s %s\n' "why it persists" "$why"
    done
}

# ── Live foothold collection ───────────────────────────────────
# Rows: severity<TAB>provider<TAB>mechanism<TAB>detail
pe_aws_keys() {
    local users out user
    users="$(aws iam list-users --output json 2>/dev/null | \
             jq -r 'try (.Users[]?.UserName) // empty' 2>/dev/null)"
    [ -z "$users" ] && return 0
    printf '%s\n' "$users" | while read -r user; do
        [ -z "$user" ] && continue
        out="$(aws iam list-access-keys --user-name "$user" --output json 2>/dev/null)"
        [ -z "$out" ] && continue
        printf '%s' "$out" | jq -r --arg u "$user" 'try
          (.AccessKeyMetadata // [])[] |
          ["key", $u, (.AccessKeyId // ""), (.Status // ""), (.CreateDate // "")] | @tsv' 2>/dev/null
    done
    # a second Active key on one user is the classic persistence move
    aws iam list-users --output json 2>/dev/null | \
        jq -r 'try (.Users[]? | select((.PasswordLastUsed // "") != "") |
                  ["password-user", (.UserName // ""), (.PasswordLastUsed // "")] | @tsv)' 2>/dev/null
}

pe_findings_aws() {
    local keys user n_active oldest
    keys="$(pe_aws_keys 2>/dev/null)"
    if [ -n "$keys" ]; then
        # multiple active keys per user
        printf '%s\n' "$keys" | awk -F'\t' '$1=="key" && $4=="Active" {print $2}' | sort | uniq -c |
            while read -r n user; do
                [ "$n" -gt 1 ] || continue
                printf 'high\taws\taccess-key\t%s has %s active keys: a spare key survives rotation\n' \
                    "$user" "$n"
            done
        # users holding a console password
        printf '%s\n' "$keys" | awk -F'\t' '$1=="password-user" {print $2}' | while read -r user; do
            [ -z "$user" ] && continue
            printf 'medium\taws\tlogin-profile\t%s has a console password in use (last %s)\n' \
                "$user" "$(printf '%s\n' "$keys" | awk -F'\t' -v u="$user" '$1=="password-user" && $2==u {print $3; exit}')"
        done
    fi
    # roles whose trust policy accepts any principal (independent of keys)
    aws iam list-roles --output json 2>/dev/null | \
      jq -c -r 'try (.Roles[]? |
                select(((.AssumeRolePolicyDocument // {}) | tostring) | test("\"Principal\":.*\\*")) |
                ["high", "aws", "trust-policy-wildcard",
                 ((.RoleName // "") + " trusts a wildcard principal")] | @tsv) // empty' 2>/dev/null
}

pe_findings_gcloud() {
    command -v gcloud >/dev/null 2>&1 || return 0
    # service account keys older than a year are expected to be persistence
    gcloud iam service-accounts list --format=json 2>/dev/null | \
      jq -r 'try (.[]? | .email // empty)' 2>/dev/null | \
      while read -r sa; do
        [ -z "$sa" ] && continue
        gcloud iam service-accounts keys list --iam-account "$sa" --format=json 2>/dev/null | \
          jq -r --arg sa "$sa" 'try
            ([.[]? | select((.keyType // "") == "USER_MANAGED")] | length) as $n |
            select($n > 0) |
            ["medium", "gcloud", "ghost-user",
             ($sa + " has " + ($n|tostring) + " user-managed key(s)")] | @tsv' 2>/dev/null
      done
}

pe_findings_azure() {
    command -v az >/dev/null 2>&1 || return 0
    az ad app list -o json 2>/dev/null | \
      jq -r 'try (.[]? | select((.passwordCredentials // []) | length > 0) |
                ["high", "azure", "app-registration",
                 ((.displayName // .appId // "unnamed") + " holds a client secret")] | @tsv)' 2>/dev/null
}

pe_cmd_footholds() {
    local p state any=0
    : > "$FIND_FILE"
    for p in $(pe_providers); do
        state="$(pe_provider_state "$p")"
        if [ "$state" != "creds-present" ]; then
            printf 'state\t%s\t%s\n' "$p" "$state"
            continue
        fi
        any=1
        case "$p" in
            aws)    pe_findings_aws;;
            gcloud) pe_findings_gcloud;;
            azure)  pe_findings_azure;;
        esac 2>/dev/null | tee -a "$FIND_FILE"
    done
    if [ "$any" -eq 0 ]; then
        pe_log "no provider reachable; footholds unknown, not absent"
        printf 'VERDICT\tabsent\tno provider reachable; footholds unknown, not absent\n'
        return 0
    fi
    if [ -s "$FIND_FILE" ]; then
        printf 'SUMMARY\t%s\n' \
            "$(awk -F'\t' '{c[$1]++} END {for (k in c) printf "%s=%d ", k, c[k]}' "$FIND_FILE")"
    else
        printf 'no footholds of the catalogued shapes were found\n'
    fi
}

# Grading for fixtures: catches a duplicate active key and a wildcard trust.
pe_grade_key_rows() {
    local file="${1:-}"
    [ -f "$file" ] || { printf 'usage: pe_grade_key_rows <file>\n' >&2; return 2; }
    awk -F'\t' '$1=="key" && $4=="Active" {print $2}' "$file" | sort | uniq -c |
        while read -r n user; do
            [ "$n" -gt 1 ] && printf 'high\taccess-key\t%s has %s active keys\n' "$user" "$n"
        done
    return 0
}

pe_cmd_status_tsv() {
    local p
    printf 'module\t%s\t%s\n' "$MODULE_ID" "$MOD_VERSION"
    for p in $(pe_providers); do
        printf 'provider\t%s\t%s\n' "$p" "$(pe_provider_state "$p")"
    done
    printf 'techniques\tcatalogue\t%s\n' "$(pe_techniques | wc -l | tr -d ' ')"
}

pe_cmd_menu() {
    printf 'footholds\tLook for catalogued persistence artefacts\n'
    printf 'list\tEvery persistence mechanism this module knows\n'
}

pe_cmd_help() {
    cat <<HELP
cloudsting module 23 — Cloud Persistence v$MOD_VERSION

  --footholds        look for persistence artefacts in the live account
  --explain <mech>   what one mechanism is and what removes it
  --list             the mechanism catalogue
  --status-tsv       module status
  --menu             menu entries
  --selftest         run selftests
  --help             this message

Detection only: this module never creates a foothold, it reports the shapes
that already exist. Loot: $OUT_DIR
HELP
}

pe_selftest() {
    local pass=0 fail=0 shim out
    chk() {
        local name="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then
            printf 'ok\t%s\n' "$name"; pass=$((pass+1))
        else
            printf 'FAIL\t%s\twant=%s got=%s\n' "$name" "$want" "$got"; fail=$((fail+1))
        fi
    }

    chk tech-count "$(pe_techniques | wc -l | tr -d ' ')" 15
    chk tech-fields "$(pe_techniques | awk -F'\t' 'NF != 6' | wc -l | tr -d ' ')" 0
    chk tech-aws "$(pe_techniques | awk -F'\t' '$2=="aws"' | wc -l | tr -d ' ')" 9
    chk tech-lifecycle "$(pe_techniques | awk -F'\t' '$5=="no-expiry"' | wc -l | tr -d ' ')" 9
    chk list-header "$(pe_cmd_list | head -1 | grep -c '^#mechanism')" 1
    chk explain-hit "$(pe_cmd_explain trust-policy-wildcard | grep -c 'wildcard')" 1
    chk explain-prefix "$(pe_cmd_explain access | head -1 | grep -c access-key)" 1
    chk explain-miss "$(pe_cmd_explain nonsense >/dev/null 2>&1; echo $?)" 1
    chk explain-usage "$(pe_cmd_explain 2>&1 >/dev/null | grep -c usage)" 1
    chk status-fields "$(pe_cmd_status_tsv | awk -F'\t' 'NF != 3' | wc -l | tr -d ' ')" 0
    chk state-known "$(pe_provider_state aws | grep -cE '^(tool-missing|creds-missing|creds-present)$')" 1
    chk menu-rows "$(pe_cmd_menu | wc -l | tr -d ' ')" 2

    # duplicate active keys are the persistence signal, inactive ones are not
    shim="$(mktemp -d)"
    printf 'key\talice\tAKIA1\tActive\t2024-01-01\n' >  "$shim/keys"
    printf 'key\talice\tAKIA2\tActive\t2024-02-01\n' >> "$shim/keys"
    printf 'key\tbob\tAKIA3\tActive\t2024-03-01\n'   >> "$shim/keys"
    printf 'key\tbob\tAKIA4\tInactive\t2024-04-01\n' >> "$shim/keys"
    out="$(pe_grade_key_rows "$shim/keys")"
    chk grade-alice "$(printf '%s' "$out" | awk -F'\t' '$3 ~ /^alice/{print $3}')" "alice has 2 active keys"
    chk grade-bob-none "$(printf '%s\n' "$out" | awk -F'\t' '$3 ~ /^bob"' | wc -l | tr -d ' ')" 0
    chk grade-sev "$(printf '%s' "$out" | head -1 | cut -f1)" high

    # wildcard trust policy detection through an IAM shim
    cat > "$shim/aws" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
  "iam list-users") printf '{"Users":[]}\n' ;;
  "iam list-roles") cat <<'JSON'
{"Roles":[
 {"RoleName":"open-role","AssumeRolePolicyDocument":
   {"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}},
 {"RoleName":"tight-role","AssumeRolePolicyDocument":
   {"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111:root"},"Action":"sts:AssumeRole"}]}}
]}
JSON
  ;;
  *) printf '{}\n' ;;
esac
SH
    chmod +x "$shim/aws"
    out="$(PATH="$shim:$PATH" bash -c 'source "'"$MOD_DIR"'/23_persistence.sh"; pe_findings_aws')"
    chk wildcard-found "$(printf '%s' "$out" | grep -c open-role)" 1
    chk wildcard-id "$(printf '%s' "$out" | awk -F'\t' '$3=="trust-policy-wildcard"{print $4}')" "open-role trusts a wildcard principal"
    chk wildcard-tight-skipped "$(printf '%s' "$out" | grep -c tight-role)" 0
    chk wildcard-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF != 4' | wc -l | tr -d ' ')" 0

    # Azure app registrations holding a client secret
    cat > "$shim/az" <<'SH'
#!/usr/bin/env bash
printf '[{"displayName":"ci-runner","appId":"aaa","passwordCredentials":[{"endDateTime":"2027-01-01"}]},{"displayName":"no-secret","appId":"bbb","passwordCredentials":[]}]\n'
SH
    chmod +x "$shim/az"
    out="$(PATH="$shim:$PATH" bash -c 'source "'"$MOD_DIR"'/23_persistence.sh"; pe_findings_azure')"
    chk azure-secret-found "$(printf '%s' "$out" | grep -c ci-runner)" 1
    chk azure-secret-skip "$(printf '%s' "$out" | grep -c no-secret)" 0
    chk azure-mech "$(printf '%s' "$out" | awk -F'\t' '{print $3}')" app-registration

    rm -rf "$shim"
    chk help-smoke "$(pe_cmd_help 2>/dev/null | head -1 | grep -ci persistence)" 1

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --footholds|--scan) shift; pe_cmd_footholds "$@";;
    --explain)   shift; pe_cmd_explain "$@";;
    --list)      shift; pe_cmd_list;;
    --status-tsv|--status) pe_cmd_status_tsv;;
    --menu)      pe_cmd_menu;;
    --selftest)  pe_selftest;;
    *)           pe_cmd_help;;
esac
