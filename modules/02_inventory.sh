#!/usr/bin/env bash
# 02_inventory.sh — cloud asset inventory (module 02)
#
# Given working provider credentials, enumerates every reachable resource
# across the installed provider CLIs and lands the whole estate in one
# TSV: provider | service | region | id | name | state.
# Degrades honestly per provider: no CLI → says so, no creds → says so.
#
# ── self-locate CLOUDSTING_ROOT ──
if [[ -z "${CLOUDSTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do
        _sl_dir="$(cd -P "$(dirname "$_sl_src")" && pwd)"
        _sl_tgt="$(readlink "$_sl_src")"
        [[ "$_sl_tgt" != /* ]] && _sl_tgt="$_sl_dir/$_sl_tgt"
        _sl_src="$_sl_tgt"
    done
    CLOUDSTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export CLOUDSTING_ROOT
    unset _sl_src _sl_dir _sl_tgt
fi

if [[ -n "${CLOUDSTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$CLOUDSTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi

: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$CLOUDSTING_ROOT/loot}"
: "${STATE_DIR:=$CLOUDSTING_ROOT/state}"
: "${INV_RUN_ID:=$$-$(date +%s)}"
INVOOT="$LOOT_DIR/inventory"
INVENTORY_CSV="$INVOOT/inventory-${INV_RUN_ID}.tsv"
STATE_FILE="$STATE_DIR/inventory.json"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$STATE_DIR" "$INVOOT" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F err   >/dev/null 2>&1 || err()  { printf '[err] %s\n'  "$*" >&2; }

# ═══════════════════════════════════════════════════════════════════
#  provider availability — three states, never a silent skip
# ═══════════════════════════════════════════════════════════════════

# The regions a provider scope reaches. Discoverable per provider, but
# we seed conservative defaults so --inventory works before any
# discover has run.
CLOUDSTING_REGIONS_AWS="${CLOUDSTING_REGIONS_AWS:-us-east-1}"
CLOUDSTING_REGIONS_GCP="${CLOUDSTING_REGIONS_GCP:-us-central1}"
CLOUDSTING_REGIONS_AZ="${CLOUDSTING_REGIONS_AZ:-eastus}"
CLOUDSTING_REGIONS_DO="${CLOUDSTING_REGIONS_DO:-nyc1}"

inv_provider_state() {
    local p="$1"
    if ! command -v "$p" >/dev/null 2>&1; then
        printf '%s\ttool-missing\n' "$p"; return 0
    fi
    case "$p" in
        aws)
            if [[ -r "${AWS_SHARED_CREDENTIALS_FILE:-$HOME/.aws/credentials}" ]] \
               || [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
                printf '%s\tcreds-present\n' "$p"
            else
                printf '%s\tcreds-missing\n' "$p"
            fi ;;
        gcloud)
            if gcloud auth	list 2>/dev/null | grep -q '@'; then
                printf '%s\tcreds-present\n' "$p"
            else
                printf '%s\tcreds-missing\n' "$p"
            fi ;;
        az)
            if [[ -r "$HOME/.azure/azureProfile.json" ]]; then
                printf '%s\tcreds-present\n' "$p"
            else
                printf '%s\tcreds-missing\n' "$p"
            fi ;;
        doctl)
            if doctl auth list 2>/dev/null | grep -qE '^\*\s|\s\(active\)'; then
                printf '%s\tcreds-present\n' "$p"
            else
                printf '%s\tcreds-missing\n' "$p"
            fi ;;
    esac
}

inv_regions() {
    case "$1" in
        aws)   printf '%s\n' $CLOUDSTING_REGIONS_AWS ;;
        gcp)   printf '%s\n' $CLOUDSTING_REGIONS_GCP ;;
        az)    printf '%s\n' $CLOUDSTING_REGIONS_AZ ;;
        doctl) printf '%s\n' $CLOUDSTING_REGIONS_DO ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
#  per-provider collectors — every row is one resource
#  columns: provider | service | region | id | name | state
# ═══════════════════════════════════════════════════════════════════

inv_aws_region() {
    local region="$1"
    AWS_PAGER='' aws --output json --region "$region" ec2 describe-instances 2>/dev/null \
        | jq -r --arg r "$region" \
        '.Reservations[]?.Instances[]? | [ "aws","ec2", $r, .InstanceId, ((.Tags // [])[]? | select(.Key=="Name") | .Value) // "-", .State.Name ] | @tsv'
    AWS_PAGER='' aws --output json --region "$region" lambda list-functions 2>/dev/null \
        | jq -r --arg r "$region" \
        '.Functions[]? | [ "aws","lambda", $r, .FunctionArn, .FunctionName, .State // "Active" ] | @tsv'
    AWS_PAGER='' aws --output json --region "$region" s3api list-buckets 2>/dev/null \
      | jq -r 'try (.Buckets[]?.Name // empty) | [ "aws", "s3", "global", ., ., "-" ] | @tsv' 2>/dev/null
}

inv_aws_global() {
    local qs
    qs="$(AWS_PAGER='' aws s3 ls 2>/dev/null | awk '{print $3}')" \
        && printf '%s\n' "$qs" | while read -r b; do
            [[ -n "$b" ]] && printf 'aws\ts3\tglobal\t%s\t%s\t-\n' "$b" "$b"
        done
    AWS_PAGER='' aws iam list-roles 2>/dev/null \
        | jq -r '.Roles[]? | [ "aws","iam","global", .Arn, .RoleName, "-" ] | @tsv'
    AWS_PAGER='' aws sts get-caller-identity 2>/dev/null \
        | jq -r 'try [.Account] | @tsv' \
        | while read -r acct; do
            printf 'aws\taccount\tglobal\t%s\t%s\t-\n' "$acct" "$acct"
        done
}

inv_gcp_project() {
    local proj="$1"
    gcloud compute instances list --project "$proj" --format='value(name,zone,status,id)' 2>/dev/null \
      | while IFS=$'\t' read -r name zone status id; do
            printf 'gcp\tcompute\t%s\t%s\t%s\t%s\n' "${zone%-*}" "$id" "$name" "$status"
        done
    gcloud run services list --project "$proj" --format='value(metadata.name,metadata.namespace,servingStatus)' 2>/dev/null \
      | while IFS=$'\t' read -r name ns status; do
            printf 'gcp\trun\t%s\t%s\t%s\t%s\n' "$ns" "$name" "$name" "$status"
        done
    gcloud storage buckets list --project "$proj" --format='value(name,location,status)' 2>/dev/null \
      | while IFS=$'\t' read -r name loc status; do
            printf 'gcp\tstorage\t%s\t%s\t%s\t%s\n' "$loc" "$name" "$name" "$status"
        done
    gcloud projects describe "$proj" --format='value(projectNumber,name)' 2>/dev/null \
      | while IFS=$'\t' read -r num name; do
            printf 'gcp\tproject\tglobal\t%s\t%s\t-\n' "$num" "${name:-$proj}"
        done
}

inv_az() {
    local rg
    az group list --query '[].{n:name, l:location}' -o tsv 2>/dev/null \
      | while IFS=$'\t' read -r rg loc; do
            az vm list -g "$rg" --query '[].{i:id, n:name, s:"exists"}' -o tsv 2>/dev/null \
                | while IFS=$'\t' read -r id name _; do
                    printf 'az\tvm\t%s\t%s\t%s\texists\n' "$loc" "${id##*/}" "$name"
                done
        done
    az account show --query '{i:id, n:name}' -o tsv 2>/dev/null \
      | while IFS=$'\t' read -r id name; do
            printf 'az\tsubscription\tglobal\t%s\t%s\t-\n' "$id" "$name"
        done
    az webapp list --query '[].{i:id, n:name, s:state}' -o tsv 2>/dev/null \
        | while IFS=$'\t' read -r id name state; do
            printf 'az\twebapp\tglobal\t%s\t%s\t%s\n' "${id##*/}" "$name" "${state:--}"
        done
    az storage account list --query '[].{i:id, n:name}' -o tsv 2>/dev/null \
        | while IFS=$'\t' read -r id name; do
            printf 'az\tstorage\tglobal\t%s\t%s\t-\n' "${id##*/}" "$name"
        done
}

inv_do() {
    doctl compute droplet list --format 'ID,Name,Status,Region' --no-header 2>/dev/null \
      | while IFS=',' read -r id name state region; do
            printf 'do\tdroplet\t%s\t%s\t%s\t%s\n' "${region// /}" "$id" "$name" "$state"
        done
    doctl compute project list --format 'ID,Name' --no-header 2>/dev/null \
      | while IFS=',' read -r id name; do
            printf 'do\tproject\tdefault\t%s\t%s\t-\n' "$id" "$name"
        done
    doctl storage bucket list --format 'Name,Region' --no-header 2>/dev/null \
      | while IFS=',' read -r name region; do
            printf 'do\tspace\t%s\t%s\t%s\t-\n' "${region// /}" "$name" "$name"
        done
}

# ═══════════════════════════════════════════════════════════════════
#  main inventory pass — always writes the three-state table first
# ═══════════════════════════════════════════════════════════════════

# INTERNAL: emit a row (concentration point for the selftest shim)
inv_emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6"; }

inv_run_provider() {
    local p="$1"
    local state
    state="$(inv_provider_state "$p" | cut -f2)"
    case "$state" in
        tool-missing)
            printf '%s\t%s\t-\t-\t-\ttool %s not installed\n' "skip" "$p" "$p"
            return 0 ;;
        creds-missing)
            printf '%s\t%s\t-\t-\t-\tno credentials configured\n' "skip" "$p"
            return 0 ;;
    esac
    case "$p" in
        aws)
            inv_aws_global                    | tee -a "$INVENTORY_CSV"
            local r
            for r in $(inv_regions aws); do inv_aws_region "$r" | tee -a "$INVENTORY_CSV"; done ;;
        gcp)
            local proj="${GCP_PROJECT:-}"
            [[ -z "$proj" ]] && gcloud config get-value project 2>/dev/null >/tmp/cs-proj.$$ && proj="$(cat /tmp/cs-proj.$$)" && rm -f /tmp/cs-proj.$$
            inv_gcp_project "${proj:-default}" | tee -a "$INVENTORY_CSV" ;;
        az)
            inv_az | tee -a "$INVENTORY_CSV" ;;
        doctl)
            inv_do | tee -a "$INVENTORY_CSV" ;;
    esac
}

inv_run() {
    local assume="yes"
    local providers=(aws gcloud az doctl)
    [[ -n "$1" ]] && providers=("$1")
    : > "$INVENTORY_CSV"   # truncate a fresh run; loot/ dir keeps stale runs
    {
        printf 'provider\tservice\tregion\tid\tname\tstate\n'
    } > "$INVENTORY_CSV"
    local skip_table
    local p
    for p in "${providers[@]}"; do
        case "$(inv_provider_state "$p" | cut -f2)" in
            tool-missing)   printf '%s\tskipped\ttool %s not installed\n' "$p" "tool-missing" ;;
            creds-missing)  printf '%s\tskipped\tno credentials configured\n' "$p" ;;
        esac
    done | grep -v '^$' > "$TMP_DIR/inv_skips.$$" || true

    for p in "${providers[@]}"; do
        inv_run_provider "$p"
    done

    # state file for GUI/CLI share
    {
        printf '{\n'
        printf ' "run": "%s", "ts": "%s",\n' "$INV_RUN_ID" "$(date -Iseconds)"
        printf ' "rows": %s\n' "$(($(wc -l < "$INVENTORY_CSV") - 1))"
        printf '}\n'
    } > "$STATE_FILE" 2>/dev/null
    printf 'inventory\t%s\n' "$INVENTORY_CSV"
    printf 'rows\t%s\n' "$(( $(wc -l < "$INVENTORY_CSV") - 1 ))"
    if [[ -s "$TMP_DIR/inv_skips.$$" ]]; then
        cat "$TMP_DIR/inv_skips.$$"
    fi
    rm -f "$TMP_DIR/inv_skips.$$"
}

# ═══════════════════════════════════════════════════════════════════
#  status TSV
# ═══════════════════════════════════════════════════════════════════

inv_status_tsv() {
    printf 'module\t02_inventory\n'
    printf 'state\tok\n'
    printf 'tsv_last\t%s\n' "$(latest_inventory)" | sed 's/\t$//'
    local i
    for i in aws gcloud az doctl; do
        printf 'provider-%s\t%s\n' "$i" "$(inv_provider_state "$i" | cut -f2)"
    done
}

latest_inventory() {
    ls -t "$INVOOT"/inventory-*.tsv 2>/dev/null | head -1 || printf '%s' "none"
}

# ═══════════════════════════════════════════════════════════════════
#  menu
# ═══════════════════════════════════════════════════════════════════

inv_menu() {
    while true; do
        printf '\n=== 02 — Cloud Asset Inventory ===\n'
        printf '  1) full inventory (all installed providers)\n'
        printf '  2) inventory one provider (aws|gcloud|az|doctl)\n'
        printf '  3) provider status\n'
        printf '  4) latest inventory TSV\n'
        printf '  0) back\n'
        read -rp '  choice> ' c
        case "$c" in
            1) inv_run ;;
            2) read -rp '  provider> ' p; inv_run "$p" ;;
            3) for i in aws gcloud az doctl; do inv_provider_state "$i"; done ;;
            4) latest_inventory ;;
            0|q) return 0 ;;
            *) printf '  unknown choice\n' ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════════════
#  selftest — offline. Fake provider CLIs on PATH emit canned output
#  and the parsers must turn them into exact rows.
# ═══════════════════════════════════════════════════════════════════

inv_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local shim="$TMP_DIR/inv_shim.$$"
    mkdir -p "$shim"

    # fake aws: describe-instances + list-roles + sts + s3 ls
    cat > "$shim/aws" <<'SHIM'
#!/usr/bin/env bash
case "$*" in
    *describe-instances*)
        exec jq -n --arg r "$CLOUDSTING_REGIONS_AWS" '{
            Reservations: [ { Instances: [ { InstanceId: "i-deadbeef1", State: { Name: "running" }, Tags: [ { Key: "Name", Value: "api-gateway-host" } ] } ] } ]
        }' ;;
    *lambda*) jq -n '{
        Functions: [ { FunctionName: "ingest-webhook", FunctionArn: "arn:aws:lambda:us-east-1:12345:function:ingest-webhook", State: "Active" } ]
    }' ;;
    *list-roles*) jq -n '{
        Roles: [ { RoleName: "admin-hopeful", Arn: "arn:aws:iam::12345:role/admin-hopeful" } ]
    }' ;;
    *get-caller-identity*) jq -n '{ Account: "12345", Arn: "arn:aws:iam::12345:user/selftest", UserId: "AIDADUMMY" }' ;;
    *) printf 'nothing-DUMMY\n' ;;
esac
SHIM

    # fake doctl: droplets only
    cat > "$shim/doctl" <<'SHIM'
#!/usr/bin/env bash
case "$*" in
    *droplet*) printf '101,edge-loadbal,active,nyc1\n' ;;
    *project*) printf 'p-1,default-project\n' ;;
    *bucket*)  printf 'edge-cdn-assets,nyc1\n' ;;
    *) printf 'nothing-DUMMY\n' ;;
esac
SHIM
    chmod +x "$shim/aws" "$shim/doctl"

    # gcloud and az deliberately left MISSING in the shim PATH on purpose:
    # the three-state table must still say tool-missing for them, not skip
    # the rest of the run.
    local old_path="$PATH"
    PATH="$shim:$PATH" CLOUDSTING_REGIONS_AWS=us-east-1 CLOUDSTING_SOURCE_ONLY=1 bash -c "
        source '$(realpath "${BASH_SOURCE[0]}")'
        for i in aws gcloud az doctl; do inv_provider_state \"\$i\"; done
    " > "$TMP_DIR/st_states.$$" 2>&1
    chk states-aws-present  "$(awk -F'\t' '$1=="aws"{print $2}' "$TMP_DIR/st_states.$$")" 'creds-missing'
    chk states-gcloud-miss  "$(awk -F'\t' '$1=="gcloud"{print $2}' "$TMP_DIR/st_states.$$")" 'tool-missing'
    chk states-az-miss      "$(awk -F'\t' '$1=="az"{print $2}' "$TMP_DIR/st_states.$$")" 'tool-missing'

    PATH="$shim:$PATH" CLOUDSTING_REGIONS_AWS=us-east-1 CLOUDSTING_SOURCE_ONLY=1 bash -c "
        source '$(realpath "${BASH_SOURCE[0]}")'
        inv_aws_region us-east-1
        inv_aws_global
    " | grep -v '^nothing-DUMMY$' > "$TMP_DIR/st_aws.$$" 2>&1
    chk aws-ec2-row-count "$(awk -F'\t' '$1=="aws" && ($2=="ec2" || $2=="lambda")' "$TMP_DIR/st_aws.$$" | wc -l)" 2

    # doctl shim — strip columns delimited by comma, not tab
    PATH="$shim:$PATH" CLOUDSTING_SOURCE_ONLY=1 bash -c "
        source '$(realpath "${BASH_SOURCE[0]}")'
        inv_do
    " > "$TMP_DIR/st_do.$$" 2>&1
    chk do-row-extract "$(awk -F'\t' '$1=="do" && $2=="droplet" && $3=="nyc1" && $4=="101"' "$TMP_DIR/st_do.$$" | wc -l)" 1
    chk do-project-row "$(awk -F'\t' '$1=="do" && $2=="project" && $3=="default"' "$TMP_DIR/st_do.$$" | wc -l)" 1
    chk do-bucket-row  "$(awk -F'\t' '$1=="do" && $2=="space" && $3=="nyc1" && $4=="edge-cdn-assets"' "$TMP_DIR/st_do.$$" | wc -l)" 1

    # region source: three seeded regions
    chk regions-seeded "$(inv_regions doctl | grep -c 'nyc1')" 1
    chk regions-aws "$(inv_regions aws | grep -c 'us-east-1')" 1

    # status shape
    inv_status_tsv > "$TMP_DIR/st_status.$$" 2>&1
    chk status-fields "$(printf '%s\n' "$(cat "$TMP_DIR/st_status.$$")" | awk -F'\t' 'NF!=2{c++} END{print c+0}')" 0
    chk status-module "$(printf '%s\n' "$(cat "$TMP_DIR/st_status.$$")" | awk -F'\t' '$1=="module"{print $2}')" '02_inventory'

    rm -rf "$shim" "$TMP_DIR"/st_states.* "$TMP_DIR"/st_aws.* "$TMP_DIR"/st_do.* "$TMP_DIR"/st_status.*
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

inv_usage() {
    cat <<EOF
Usage: $(basename "$0") VERB [ARGS]
  --run [provider]            inventory aws|gcloud|az|doctl (default: all)
  --regions [provider]        regions currently being enumerated
  --status-tsv                module status (with per-provider states)
  --menu                      interactive menu
  --selftest                  offline test suite
  --help
EOF
}

inv_main() {
    case "${1:-}" in
        --run|run)      shift; inv_run "${1:-}" ;;
        --regions)      shift; inv_regions "${1:-aws}" ;;
        --status-tsv)   inv_status_tsv ;;
        --provider-state) shift; inv_provider_state "${1:-aws}" ;;
        --menu)         inv_menu ;;
        --selftest)     inv_selftest ;;
        --help|-h)      inv_usage ;;
        *)              inv_usage >&2; exit 2 ;;
    esac
}

# Selftest helper: expose the module's functions when sourced with
# CLOUDSTING_SOURCE_ONLY=1 set (used by the selftest itself).
if [[ -n "${CLOUDSTING_SOURCE_ONLY:-}" ]]; then
    return 0 2>/dev/null || true
fi

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    inv_main "$@"
fi
