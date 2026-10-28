#!/usr/bin/env bash
# 13_serverless_recon.sh — cloudsting module 13: Multi-Cloud Serverless Recon & Exploitation
# Verbs: --list | --env | --urls | --invoke | --all | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="13_serverless_recon"
MOD_NAME="Multi-Cloud Serverless Recon & Exploitation"
MOD_VERSION="0.8.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export SR_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/serverless_recon"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true

sr_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── Provider gates ───────────────────────────────────────────────
sr_prov_state() {
    local n=0
    command -v aws >/dev/null 2>&1 && n=$((n+1)) && { aws sts get-caller-identity >/dev/null 2>&1 && n=$((n+2)); }
    printf 'aws\t%d\n' "$n"
    n=0
    command -v gcloud >/dev/null 2>&1 && n=$((n+1)) && { gcloud auth list --format=json 2>/dev/null | jq -e '.[] | select(.status=="ACTIVE")' >/dev/null 2>&1 && n=$((n+2)); }
    printf 'gcp\t%d\n' "$n"
    n=0
    command -v az >/dev/null 2>&1 && n=$((n+1)) && { az account show 2>/dev/null >/dev/null 2>&1 && n=$((n+2)); }
    printf 'az\t%d\n' "$n"
}

sr_has_aws() { command -v aws >/dev/null 2>&1 || return 1; aws sts get-caller-identity >/dev/null 2>&1 || return 1; return 0; }
sr_has_gcp() { command -v gcloud >/dev/null 2>&1 || return 1; gcloud auth list --format=json 2>/dev/null | jq -e '.[] | select(.status=="ACTIVE")' >/dev/null 2>&1; }
sr_has_az()  { command -v az >/dev/null 2>&1 || return 1; az account show 2>/dev/null >/dev/null 2>&1; }

# ── Collector: AWS Lambda ────────────────────────────────────────
sr_list_aws() {
    sr_has_aws || return 1
    aws lambda list-functions --output json 2>/dev/null | \
        jq -r '.Functions[] | ["aws", .FunctionName, .Runtime // "-", .Handler // "-", .FunctionArn] | @tsv' 2>/dev/null
}

sr_env_aws() {
    sr_has_aws || return 1
    local func="$1"
    aws lambda get-function --function-name "$func" --output json 2>/dev/null | \
        jq -r '.Configuration.Environment.Variables // {} | to_entries[] | ["aws", func, .key, .value] | @tsv' --arg func "$func" 2>/dev/null
}

sr_urls_aws() {
    sr_has_aws || return 1
    aws lambda list-functions --output json 2>/dev/null | \
        jq -r '.Functions[] | select(.FunctionUrl != null) | ["aws", .FunctionName, .FunctionUrl] | @tsv' 2>/dev/null
}

# ── Collector: GCP Cloud Functions ────────────────────────────────
sr_list_gcp() {
    sr_has_gcp || return 1
    local project
    project="$(gcloud config get-value project 2>/dev/null)"
    [ -z "$project" ] && return 1
    local regions
    regions="$(gcloud functions regions list --format='value(locationId)' 2>/dev/null | head -5)"
    [ -z "$regions" ] && regions="us-central1"
    while IFS= read -r region; do
        [ -z "$region" ] && continue
        gcloud functions list --project "$project" --region "$region" --format='csv[no-heading](NAME,RUNTIME,ENTRY_POINT,STATUS)' 2>/dev/null | \
            while IFS=, read -r name runtime entry status; do
                [ -z "$name" ] && continue
                printf 'gcp\t%s\t%s\t%s\t%s\n' "$name" "$runtime" "$entry" "status=$status"
            done
    done <<< "$regions"
}

sr_env_gcp() {
    sr_has_gcp || return 1
    local func="$1" project region
    project="$(gcloud config get-value project 2>/dev/null)"
    [ -z "$project" ] && return 1
    # Try common regions
    for region in us-central1 us-east1 europe-west1; do
        gcloud functions describe "$func" --project "$project" --region "$region" --format='json' 2>/dev/null | \
            jq -r '.environmentVariables // {} | to_entries[] | ["gcp", func, .key, .value] | @tsv' --arg func "$func" 2>/dev/null && return
    done
    return 1
}

sr_urls_gcp() {
    sr_has_gcp || return 1
    local project
    project="$(gcloud config get-value project 2>/dev/null)"
    [ -z "$project" ] && return 1
    gcloud functions list --project "$project" --format='csv[no-heading](NAME,STATUS,URL)' 2>/dev/null | \
        while IFS=, read -r name status url; do
            [ -n "$name" ] && [ -n "$url" ] && printf 'gcp\t%s\t%s\n' "$name" "$url"
        done
}

# ── Collector: Azure Functions ───────────────────────────────────
sr_list_az() {
    sr_has_az || return 1
    az functionapp list --output json 2>/dev/null | \
        jq -r '.[] | ["az", .name, .kind // "-", .state // "-", .id] | @tsv' 2>/dev/null
}

sr_env_az() {
    sr_has_az || return 1
    local func="$1"
    az functionapp config appsettings list --name "$func" --resource-group "$(az functionapp list --query "[?name=='$func'].resourceGroup" -o tsv 2>/dev/null)" --output json 2>/dev/null | \
        jq -r '.[] | ["az", func, .name, .value] | @tsv' --arg func "$func" 2>/dev/null
}

sr_urls_az() {
    sr_has_az || return 1
    az functionapp list --output json 2>/dev/null | \
        jq -r '.[] | ["az", .name, .defaultHostName] | @tsv' 2>/dev/null | awk -F'\t' '{print $1"\t"$2"\thttps://"$3}'
}

# ── Generic HTTP invoke ──────────────────────────────────────────
sr_invoke() {
    local provider="$1" func="$2" url="${3:-}"
    if [ -z "$url" ]; then
        case "$provider" in
            aws) url="$(aws lambda get-function-url-config --function-name "$func" --query 'FunctionUrl' -o text 2>/dev/null)" ;;
            gcp) url="$(gcloud functions describe "$func" --format='value(serviceConfig.uri)' 2>/dev/null)" ;;
            az)  url="https://$(az functionapp show --name "$func" --query 'defaultHostName' -o tsv 2>/dev/null)" ;;
        esac
    fi
    [ -z "$url" ] && { sr_log "no URL for $provider/$func"; return 1; }
    curl -s --max-time 10 "$url" 2>/dev/null | head -c 1024
}

# ── Verb dispatchers ─────────────────────────────────────────────
sr_cmd_list() {
    local out
    out="$(sr_list_aws 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(sr_list_gcp 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(sr_list_az 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
}
sr_cmd_env() {
    local func="${1:-}"
    [ -z "$func" ] && { sr_log "usage: --env <function-name>"; return 1; }
    local out
    out="$(sr_env_aws "$func" 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(sr_env_gcp "$func" 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(sr_env_az "$func" 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
}
sr_cmd_urls() {
    local out
    out="$(sr_urls_aws 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(sr_urls_gcp 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(sr_urls_az 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
}
sr_cmd_invoke() {
    local prov="${1:-}" func="${2:-}" url="${3:-}"
    [ -z "$prov" ] || [ -z "$func" ] && { sr_log "usage: --invoke <provider> <func> [url]"; return 1; }
    sr_invoke "$prov" "$func" "$url"
}
sr_cmd_all() {
    sr_log "=== Serverless Recon ==="
    sr_log "--- listing functions ---"
    sr_cmd_list
    sr_log "--- function URLs ---"
    sr_cmd_urls
}
sr_cmd_status_tsv() {
    local curl_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    printf '%s\t%s\tcurl-%s\n' "$MODULE_ID" "$MOD_NAME" "$curl_state"
}
sr_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }
sr_cmd_help() {
    cat <<'HELP'
cloudsting module 13 — Multi-Cloud Serverless Recon & Exploitation v0.8.0
  --list                    list functions across AWS Lambda, GCP CF, Azure Functions
  --env <func>              extract environment variables from all providers
  --urls                    list function URLs across all providers
  --invoke <prov> <func>    HTTP-invoke a function (read response body)
  --all                     full recon: list + URLs
  --status-tsv              module status
  --menu                    menu entry
  --selftest                run selftests
  --help                    this message
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
sr_selftest() {
    local pass=0 fail=0
    chk() { local n="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$n"
        else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$n" "$want" "$got"; fi; }

    # Provider state
    chk prov-state-fields "$(sr_prov_state | awk -F'\t' '{print NF}' | sort -u | paste -sd,)" "2"
    chk prov-state-lines "$(sr_prov_state | wc -l)" 3

    # --list with no creds = empty but no crash
    local list_out
    list_out="$(sr_cmd_list 2>/dev/null)"
    chk list-no-crash "${list_out:-ok}" "ok"

    # --env with no args = error message
    local env_out env_rc
    env_out="$(sr_cmd_env 2>&1 1>/dev/null)" || env_rc=$?
    chk env-usage "$(printf '%s' "$env_out" | head -1 | grep -ci usage)" 1

    # --status-tsv shape
    chk status-fields "$(sr_cmd_status_tsv | awk -F'\t' '{print NF}')" 3
    chk status-module "$(sr_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"

    # --help smoke
    chk help-smoke "$(sr_cmd_help 2>/dev/null | head -1 | grep -ci serverless)" 1

    # --menu shape
    chk menu-shape "$(sr_cmd_menu | awk -F'\t' '{print NF}')" 3

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --list)      shift; sr_cmd_list "$@";;
    --env)       shift; sr_cmd_env "$@";;
    --urls)      shift; sr_cmd_urls;;
    --invoke)    shift; sr_cmd_invoke "$@";;
    --all)       shift; sr_cmd_all;;
    --status-tsv|--status) sr_cmd_status_tsv;;
    --menu)      sr_cmd_menu;;
    --selftest)  sr_selftest;;
    *)           sr_cmd_help;;
esac
