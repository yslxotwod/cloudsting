#!/usr/bin/env bash
# 12_serverless.sh — cloudsting module 12: serverless functions, all clouds, through to code
# Verbs: --list | --env | --urls | --dump | --download | --invoke | --all | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file after the core is sourced. An inherited
# CS_MOD_DIR is a caller's directory, not this module's.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV writer,
# the three-state provider gate, redaction and the selftest ledger.
MODULE_ID="12_serverless"
MOD_NAME="Serverless Functions (list → env → urls → code)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

: "${SL_TIMEOUT:=10}"      # per HTTP/CLI call
: "${SL_MAX_BODY:=1024}"   # bytes of an invoked response worth showing
: "${SL_MAX_ZIPS:=16}"     # cap on how many code packages one --download-all pulls

SL_RUN_ID="$CS_RUN_ID"
export SL_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/serverless"
mkdir -p "$OUT_DIR" 2>/dev/null || true

FUNC_FILE="$OUT_DIR/functions-$RUN_ID.tsv"
ENV_FILE="$OUT_DIR/env-$RUN_ID.tsv"
URL_FILE="$OUT_DIR/urls-$RUN_ID.tsv"

sl_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── provider gates ───────────────────────────────────────────────
# One gate per provider, all three answering the same way, because every
# collector below is the same question asked three times.
sl_has_aws() {
    command -v aws >/dev/null 2>&1 || return 1
    aws sts get-caller-identity >/dev/null 2>&1 || return 1
}
sl_has_gcp() {
    command -v gcloud >/dev/null 2>&1 || return 1
    gcloud config get-value project >/dev/null 2>&1 || return 1
}
sl_has_az() {
    command -v az >/dev/null 2>&1 || return 1
    az account show >/dev/null 2>&1 || return 1
}

# Which providers are usable right now: <provider>\t<state>
sl_provider_states() {
    if sl_has_aws; then printf 'aws\tcreds-present\n'; else
        command -v aws >/dev/null 2>&1 && printf 'aws\tcreds-missing\n' || printf 'aws\ttool-missing\n'
    fi
    if sl_has_gcp; then printf 'gcp\tcreds-present\n'; else
        command -v gcloud >/dev/null 2>&1 && printf 'gcp\tcreds-missing\n' || printf 'gcp\ttool-missing\n'
    fi
    if sl_has_az; then printf 'az\tcreds-present\n'; else
        command -v az >/dev/null 2>&1 && printf 'az\tcreds-missing\n' || printf 'az\ttool-missing\n'
    fi
}

sl_any_provider() {
    sl_has_aws || sl_has_gcp || sl_has_az
}

# ── list ─────────────────────────────────────────────────────────
# Normalised shape for every cloud: provider\tname\truntime\thandler\tref
# The ref is what --env / --dump / --download take back, so it has to be the
# identifier the provider itself wants, not a display name.
sl_list_aws() {
    sl_has_aws || { printf 'aws\tabsent\taws credentials unavailable\n'; return 0; }
    aws lambda list-functions --output json 2>/dev/null | \
        jq -r '.Functions[]? | ["aws", .FunctionName, (.Runtime // "-"), (.Handler // "-"), .FunctionName, (.LastModified // "-"), (.FunctionArn // "-")] | @tsv' 2>/dev/null
}

sl_list_gcp() {
    sl_has_gcp || { printf 'gcp\tabsent\tgcloud not authenticated\n'; return 0; }
    local project; project="$(gcloud config get-value project 2>/dev/null)"
    [[ -z "$project" || "$project" == "(unset)" ]] && { printf 'gcp\tabsent\tno project set\n'; return 0; }
    local region
    for region in $(gcloud functions regions list --format='value(locationId)' 2>/dev/null | head -n 5); do
        [[ -z "$region" ]] && continue
        gcloud functions list --project "$project" --region "$region" \
            --format='csv[no-heading](NAME,RUNTIME,ENTRY_POINT,STATUS,URL)' 2>/dev/null | \
            while IFS=, read -r name runtime entry status url; do
                [[ -z "$name" ]] && continue
                printf 'gcp\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "${runtime:--}" "${entry:--}" "$region" "$status" "${url:--}"
            done
    done
}

sl_list_az() {
    sl_has_az || { printf 'az\tabsent\taz not authenticated\n'; return 0; }
    az functionapp list --output json 2>/dev/null | \
        jq -r '.[]? | ["az", .name, (.kind // "-"), (.state // "-"), .name, .resourceGroup, (.defaultHostName // "-")] | @tsv' 2>/dev/null
}

# One row per function, whichever cloud it lives on.
sl_cmd_list() {
    local filter="${1:-}" out
    : > "$FUNC_FILE"
    for prov in aws gcp az; do
        [[ -n "$filter" && "$prov" != "$filter" ]] && continue
        out="$(
            case "$prov" in
                aws) sl_list_aws ;;
                gcp) sl_list_gcp ;;
                az)  sl_list_az ;;
            esac
        )"
        [[ -z "$out" ]] && continue
        # provider/name rows come from the absent sentinel; normalise those.
        local line
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if [[ "$(printf '%s' "$line" | awk -F'\t' '{print $2}')" == "absent" ]]; then
                cs_row PROVIDER "$prov" "absent" "$(printf '%s' "$line" | awk -F'\t' '{print $3}')"
                continue
            fi
            cs_row FUNCTION "$line"
            printf '%s\n' "$line" >> "$FUNC_FILE"
        done <<< "$out"
    done

    local n; n="$(wc -l < "$FUNC_FILE" 2>/dev/null | tr -d ' ')"
    cs_row SUMMARY "${n:-0}"
    [[ "${n:-0}" -gt 0 ]] && cs_row ARTIFACT "$FUNC_FILE"

    # Functions that answer the internet are not the same as functions that
    # exist. Any function whose ref column names a URL is a finding on its own.
    local prov name runtime handler ref
    while IFS=$'\t' read -r prov name runtime handler ref; do
        [[ -z "$prov" ]] && continue
        case "$ref" in
            https://*|http://*)
                cs_row EXPOSED "$prov" "$name" "$ref"
                cs_findings_row "$MODULE_ID" "SURFACE" "$ref" "MEDIUM" "function-url-exposed" \
                    "$prov function $name answers over HTTP"
                ;;
        esac
    done < "$FUNC_FILE"
    return 0
}

# ── env ──────────────────────────────────────────────────────────
# Environment variables are where the credentials live in a serverless
# estate, so this verb doubles as a secret harvest.
sl_env_aws() {
    local func="$1"
    sl_has_aws && aws lambda get-function --function-name "$func" --output json 2>/dev/null | \
        jq -r '.Configuration.Environment.Variables // {} | to_entries[]? | ["aws", .key, .value] | @tsv' 2>/dev/null
}
sl_env_gcp() {
    local func="$1" project region
    sl_has_gcp || return 0
    project="$(gcloud config get-value project 2>/dev/null)"
    for region in us-central1 us-east1 europe-west1 europe-west2 asia-east1; do
        local out
        out="$(gcloud functions describe "$func" --project "$project" --region "$region" --format='json' 2>/dev/null)"
        if [[ -n "$out" ]]; then
            printf '%s' "$out" | jq -r '.environmentVariables // {} | to_entries[]? | ["gcp", .key, .value] | @tsv' 2>/dev/null
            return 0
        fi
    done
    return 0
}
sl_env_az() {
    local func="$1" rg
    sl_has_az || return 0
    rg="$(az functionapp list --query "[?name=='$func'].resourceGroup" -o tsv 2>/dev/null | head -1)"
    [[ -z "$rg" ]] && return 0
    az functionapp config appsettings list --name "$func" --resource-group "$rg" \
        --output json 2>/dev/null | \
        jq -r '.[]? | ["az", .name, .value] | @tsv' 2>/dev/null
}

sl_cmd_env() {
    local func="${1:-}" prov="${2:-}"
    if [[ -z "$func" ]]; then
        sl_log "usage: --env <function-name> [provider]"
        return 2
    fi
    : > "$ENV_FILE"
    local out=""
    for candidate in ${prov:-aws gcp az}; do
        out="$(
            case "$candidate" in
                aws) sl_env_aws "$func" ;;
                gcp) sl_env_gcp "$func" ;;
                az)  sl_env_az "$func" ;;
            esac
        )"
        [[ -z "$out" ]] && continue

        local p k v
        while IFS=$'\t' read -r p k v; do
            [[ -z "$k" ]] && continue
            printf '%s\t%s\t%s\t%s\n' "$func" "$p" "$k" "$v" >> "$ENV_FILE"
            # A key-shaped value is a finding no matter which key it hides in.
            if printf '%s' "$v" | grep -qE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|sk_live_|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-'; then
                cs_row SECRET "$p" "$k" "$(cs_redact "$v")"
                cs_findings_row "$MODULE_ID" "CREDS" "$func" "CRITICAL" "function-env-secret" \
                    "$p function $func exposes a credential in environment variable $k"
            else
                cs_row ENV "$p" "$k" "$(cs_redact "$v")"
            fi
        done <<< "$out"
        break
    done
    [[ -s "$ENV_FILE" ]] && cs_row ARTIFACT "$ENV_FILE"
    return 0
}

# ── urls ─────────────────────────────────────────────────────────
sl_cmd_urls() {
    sl_has_aws || sl_has_gcp || sl_has_az || { cs_row PROVIDER all absent "no cloud credentials"; return 0; }
    : > "$URL_FILE"
    local n=0

    if sl_has_aws; then
        while IFS=$'\t' read -r name url; do
            [[ -z "$name" ]] && continue
            n=$((n + 1))
            cs_row URL aws "$name" "$url"
            printf 'aws\t%s\t%s\n' "$name" "$url" >> "$URL_FILE"
            cs_findings_row "$MODULE_ID" "SURFACE" "$url" "MEDIUM" "lambda-url-public" \
                "Lambda function $name has a function URL"
        done < <(aws lambda list-functions --output json 2>/dev/null | \
                 jq -r '.Functions[]? | select(.FunctionUrlConfig.FunctionUrl != null) | [.FunctionName, .FunctionUrlConfig.FunctionUrl] | @tsv' 2>/dev/null)
    fi

    if sl_has_gcp; then
        while IFS=$'\t' read -r name url; do
            [[ -z "$name" || -z "$url" ]] && continue
            n=$((n + 1))
            cs_row URL gcp "$name" "$url"
            printf 'gcp\t%s\t%s\n' "$name" "$url" >> "$URL_FILE"
            cs_findings_row "$MODULE_ID" "SURFACE" "$url" "MEDIUM" "cloudrun-url-public" \
                "GCP function $name answers over HTTP"
        done < <(gcloud functions list --format='csv[no-heading](NAME,URL)' 2>/dev/null | \
                 while IFS=, read -r name url; do [[ -n "$url" ]] && printf '%s\t%s\n' "$name" "$url"; done)
    fi

    if sl_has_az; then
        while IFS=$'\t' read -r name host; do
            [[ -z "$name" || -z "$host" ]] && continue
            n=$((n + 1))
            cs_row URL az "$name" "https://$host"
            printf 'az\t%s\thttps://%s\n' "$name" "$host" >> "$URL_FILE"
        done < <(az functionapp list --output json 2>/dev/null | \
                 jq -r '.[]? | [.name, (.defaultHostName // empty)] | @tsv' 2>/dev/null)
    fi

    cs_row SUMMARY "$n"
    [[ "$n" -gt 0 ]] && cs_row ARTIFACT "$URL_FILE"
    return 0
}

# ── dump / download / invoke ─────────────────────────────────────
# The configuration of one function, normalised across clouds, so a reader
# does not have to remember three JSON shapes.
sl_cmd_dump() {
    local func="${1:-}" prov="${2:-}"
    [[ -z "$func" ]] && { sl_log "usage: --dump <function-name> [provider]"; return 2; }

    if [[ -z "$prov" || "$prov" == "aws" ]] && sl_has_aws; then
        local cfg
        cfg="$(aws lambda get-function --function-name "$func" --output json 2>/dev/null)"
        if [[ -n "$cfg" ]]; then
            cs_row PROVIDER aws
            cs_row NAME     "$func"
            cs_row RUNTIME  "$(printf '%s' "$cfg" | jq -r '.Configuration.Runtime // "-"')"
            cs_row HANDLER  "$(printf '%s' "$cfg" | jq -r '.Configuration.Handler // "-"')"
            cs_row ROLE     "$(printf '%s' "$cfg" | jq -r '.Configuration.Role // "-"')"
            cs_row MEMORY   "$(printf '%s' "$cfg" | jq -r '.Configuration.MemorySize // "-"')"
            cs_row TIMEOUT  "$(printf '%s' "$cfg" | jq -r '.Configuration.Timeout // "-"')"
            cs_row CODE_URL "$(printf '%s' "$cfg" | jq -r '.Code.Location // "-"')"
            cs_row ENV_COUNT "$(printf '%s' "$cfg" | jq -r '.Configuration.Environment.Variables // {} | length')"
            local role; role="$(printf '%s' "$cfg" | jq -r '.Configuration.Role // empty')"
            case "$role" in
                *":role/"*)
                    cs_findings_row "$MODULE_ID" "IDENTITY" "$func" "INFO" "function-role" \
                        "runs as ${role##*:role/}"
                    ;;
            esac
            return 0
        fi
    fi

    if [[ -z "$prov" || "$prov" == "gcp" ]] && sl_has_gcp; then
        local project out
        project="$(gcloud config get-value project 2>/dev/null)"
        local region
        for region in us-central1 us-east1 europe-west1 europe-west2 asia-east1; do
            out="$(gcloud functions describe "$func" --project "$project" --region "$region" --format='json' 2>/dev/null)"
            [[ -z "$out" ]] && continue
            cs_row PROVIDER gcp
            cs_row NAME     "$func"
            cs_row REGION   "$region"
            cs_row RUNTIME  "$(printf '%s' "$out" | jq -r '.runtime // "-"')"
            cs_row ENTRY    "$(printf '%s' "$out" | jq -r '.entryPoint // "-"')"
            cs_row URL      "$(printf '%s' "$out" | jq -r '.serviceConfig.uri // "-"')"
            cs_row SA       "$(printf '%s' "$out" | jq -r '.serviceAccountEmail // "-"')"
            cs_row ENV_COUNT "$(printf '%s' "$out" | jq -r '.environmentVariables // {} | length')"
            return 0
        done
    fi

    if [[ -z "$prov" || "$prov" == "az" ]] && sl_has_az; then
        local out
        out="$(az functionapp show --name "$func" --output json 2>/dev/null)"
        if [[ -n "$out" ]]; then
            cs_row PROVIDER az
            cs_row NAME     "$func"
            cs_row STATE    "$(printf '%s' "$out" | jq -r '.state // "-"')"
            cs_row RG       "$(printf '%s' "$out" | jq -r '.resourceGroup // "-"')"
            cs_row HOST     "https://$(printf '%s' "$out" | jq -r '.defaultHostName // "-"')"
            return 0
        fi
    fi

    cs_row VERDICT "not-found"
    return 0
}

# Code, not just configuration. Only AWS hands out a package URL directly.
sl_cmd_download() {
    local func="${1:-}"
    [[ -z "$func" ]] && { sl_log "usage: --download <function-name>"; return 2; }
    sl_has_aws || { cs_row PROVIDER aws absent "aws credentials unavailable"; return 0; }

    local url; url="$(aws lambda get-function --function-name "$func" --output json 2>/dev/null | jq -r '.Code.Location // empty')"
    [[ -z "$url" ]] && { cs_row VERDICT "no-code-url"; return 0; }

    local out="$OUT_DIR/$func-$RUN_ID.zip"
    if curl --silent --show-error -L --max-time "$SL_TIMEOUT" -o "$out" "$url" 2>/dev/null; then
        local sz; sz="$(wc -c < "$out" 2>/dev/null | tr -d ' ')"
        cs_row DOWNLOADED "$func" "$out" "${sz:-0}"
        cs_row ARTIFACT "$out"
        cs_findings_row "$MODULE_ID" "SURFACE" "$func" "INFO" "function-code-retrieved" \
            "function package for $func downloaded (${sz:-0} bytes)"
    else
        cs_row VERDICT "download-failed"
    fi
    return 0
}

# Pull every function package, up to the cap. --download one at a time is
# unusable on an estate of forty functions.
sl_cmd_download_all() {
    sl_cmd_list aws > /dev/null 2>&1
    local n=0 prov name rest
    while IFS=$'\t' read -r prov name rest; do
        [[ "$prov" != "aws" ]] && continue
        [[ "$n" -ge "$SL_MAX_ZIPS" ]] && { cs_row CAPPED "$SL_MAX_ZIPS"; break; }
        sl_cmd_download "$name" > /dev/null 2>&1
        n=$((n + 1))
    done < "$FUNC_FILE"
    cs_row DOWNLOADED_TOTAL "$n"
    return 0
}

# Call it. A serverless function is an attack surface, so a read of its
# response is the first thing worth doing.
sl_cmd_invoke() {
    local prov="${1:-}" func="${2:-}" url="${3:-}"
    if [[ -z "$func" ]]; then
        sl_log "usage: --invoke <provider> <function-name> [url]"
        return 2
    fi

    if [[ -z "$url" ]]; then
        case "$prov" in
            aws) url="$(aws lambda get-function-url-config --function-name "$func" --query 'FunctionUrl' -o text 2>/dev/null)" ;;
            gcp) url="$(gcloud functions describe "$func" --format='value(serviceConfig.uri)' 2>/dev/null)" ;;
            az)  url="https://$(az functionapp show --name "$func" --query 'defaultHostName' -o tsv 2>/dev/null)" ;;
        esac
    fi
    [[ -z "$url" || "$url" == "None" || "$url" == "https://" ]] && { cs_row VERDICT "no-url" "$prov" "$func"; return 0; }

    local body; body="$(mktemp "$CS_SCRATCH/sl.XXXXXX")" || return 1
    local code
    code="$(curl --silent --show-error --max-time "$SL_TIMEOUT" --output "$body" \
                 --write-out '%{http_code}' "$url" 2>/dev/null)" || code="000"
    cs_row INVOKE "$prov" "$func" "$url"
    cs_row RESPONSE "$code"
    cs_row BYTES "$(wc -c < "$body" 2>/dev/null | tr -d ' ')"

    if [[ "$code" == "200" ]]; then
        cs_row BODY "$(head -c "$SL_MAX_BODY" "$body" | tr '\n\t' '  ')"
        # An unauthenticated 200 from a function is the whole finding.
        cs_findings_row "$MODULE_ID" "SURFACE" "$url" "HIGH" "function-unauthenticated" \
            "$prov function $func answered $code without credentials"
    else
        cs_row VERDICT "denied-or-error"
    fi
    rm -f "$body"
    return 0
}

sl_cmd_all() {
    sl_cmd_list "$@"
    if sl_any_provider; then
        sl_cmd_urls
    fi
    return 0
}

sl_cmd_status_tsv() {
    local states; states="$(sl_provider_states | awk -F'\t' '{printf "%s-%s ", $1, $2}')"
    printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "${states% }"
}

sl_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

sl_cmd_help() {
    cat <<'HELP'
cloudsting module 12 — Serverless Functions v1.0.0
  --list [provider]              every function, all clouds, one shape
  --env <func> [provider]        environment variables, secrets graded
  --urls                         every function that answers the internet
  --dump <func> [provider]       one function's configuration
  --download <func>              pull the function package (AWS)
  --download-all                 pull every package, capped
  --invoke <prov> <func> [url]   call it and read the answer
  --all [provider]               list + urls
  --status-tsv                   module status, per provider
  --menu                         menu entry
  --selftest                     run selftests
  --help                         this message

AWS Lambda, GCP Cloud Functions and Azure Function Apps are one attack: find
the estate, read the configuration, read the environment, pull the code, call
the endpoint. --list normalises all three to
  provider<TAB>name<TAB>runtime<TAB>handler<TAB>ref<TAB>extra<TAB>arn
--env grades anything key-shaped as CRITICAL, because in a serverless estate
the environment is where the credentials live.

Environment: SL_TIMEOUT (10), SL_MAX_BODY (1024), SL_MAX_ZIPS (16)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
sl_selftest() {
    cs_selftest_reset

    # provider gate answers for all three, always three states
    chk gate-lines "$(sl_provider_states | wc -l | tr -d ' ')" "3"
    chk gate-2col  "$(sl_provider_states | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk gate-state "$(sl_provider_states | awk -F'\t' '{print $2}' | grep -cE '^(tool-missing|creds-missing|creds-present)$')" "3"

    # any-provider is a boolean, not a crash
    sl_any_provider && chk any-provider have any || chk any-provider none none

    # --list with no credentials still reports per provider, and never dies.
    # Every line is TSV with a key and at least one field; nothing scalar
    # leaks into the stream, and exactly one SUMMARY closes it.
    local out; out="$(sl_cmd_list 2>/dev/null)"
    chk list-runs    "$(printf '%s' "$out" | awk -F'\t' 'NF<2{c++} END{print c+0}')" "0"
    chk list-keys    "$(printf '%s' "$out" | grep -cE '^(PROVIDER|FUNCTION|SUMMARY|EXPOSED)')" "$(printf '%s' "$out" | grep -c .)"
    chk list-summary "$(printf '%s' "$out" | grep -c '^SUMMARY')" "1"

    # usage errors are usage errors
    local rc
    sl_cmd_env 2>/dev/null; rc=$?
    chk env-usage "$rc" "2"
    sl_cmd_dump 2>/dev/null; rc=$?
    chk dump-usage "$rc" "2"
    sl_cmd_invoke 2>/dev/null; rc=$?
    chk invoke-usage "$rc" "2"

    # invoke refuses to invent a URL
    chk invoke-no-url "$(sl_cmd_invoke aws nosuchfn 2>/dev/null | grep -c VERDICT)" "1"

    # dump of a function that does not exist is a verdict, not an error
    chk dump-notfound "$(sl_cmd_dump nosuchfn 2>/dev/null | grep -c 'VERDICT')" "1"

    # shape contracts
    chk status-fields "$(sl_cmd_status_tsv | awk -F'\t' '{print NF}')" "3"
    chk status-module "$(sl_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(sl_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(sl_cmd_help | head -1 | grep -ci 'Serverless')" "1"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --list|--ls)   shift; sl_cmd_list "$@";;
    --env)         shift; sl_cmd_env "$@";;
    --urls)        shift; sl_cmd_urls;;
    --dump)        shift; sl_cmd_dump "$@";;
    --download)    shift; sl_cmd_download "$@";;
    --download-all) sl_cmd_download_all;;
    --invoke)      shift; sl_cmd_invoke "$@";;
    --all)         shift; sl_cmd_all "$@";;
    --status-tsv|--status) sl_cmd_status_tsv;;
    --menu)        sl_cmd_menu;;
    --selftest)    sl_selftest;;
    *)             sl_cmd_help;;
esac
