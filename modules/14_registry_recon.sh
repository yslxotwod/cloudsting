#!/usr/bin/env bash
# 14_registry_recon.sh — cloudsting module 14: Container Registry Recon (ECR, GAR, ACR, Docker Hub)
# Verbs: --list | --images | --tags <repo> | --pull <repo:tag> | --scan | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="14_registry_recon"
MOD_NAME="Container Registry Reconnaissance"
MOD_VERSION="0.9.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

# tunables this module reads with a default (kept from its own header)
: "${RR_TIMEOUT:=10}"

# Back-compat: run-id variable for this module, from the core run id
# the one run id the core minted.
RR_RUN_ID="$CS_RUN_ID"
export RR_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

# Loot directory for this module: <root>/loot/registry_recon/
OUT_DIR="$CS_LOOT/registry_recon"
mkdir -p "$OUT_DIR" 2>/dev/null || true
rr_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── Provider gates ───────────────────────────────────────────────
rr_has_aws() { command -v aws >/dev/null 2>&1 && aws sts get-caller-identity >/dev/null 2>&1; }
rr_has_gcp() { command -v gcloud >/dev/null 2>&1 && gcloud auth list --format=json 2>/dev/null | jq -e '.[] | select(.status=="ACTIVE")' >/dev/null 2>&1; }
rr_has_az()  { command -v az >/dev/null 2>&1 && az account show 2>/dev/null >/dev/null 2>&1; }

# ── AWS ECR ──────────────────────────────────────────────────────
rr_list_aws() {
    rr_has_aws || return 1
    aws ecr describe-repositories --output json 2>/dev/null | \
        jq -r '.repositories[] | ["aws", .repositoryName, .registryId, .repositoryUri, .createdAt] | @tsv' 2>/dev/null
}
rr_images_aws() {
    local repo="$1"
    rr_has_aws || return 1
    aws ecr list-images --repository-name "$repo" --output json 2>/dev/null | \
        jq -r '.imageIds[] | ["aws", repo, .imageTag // "untagged", .imageDigest[0:20]] | @tsv' --arg repo "$repo" 2>/dev/null
}
rr_tags_aws() { rr_images_aws "$1"; }

# ── GCP Artifact Registry / Container Registry ───────────────────
rr_list_gcp() {
    rr_has_gcp || return 1
    local project
    project="$(gcloud config get-value project 2>/dev/null)"
    [ -z "$project" ] && return 1
    # Try GAR first
    local gar_out
    gar_out="$(gcloud artifacts repositories list --project "$project" --format='csv[no-heading](name,location,repository_uri,format)' 2>/dev/null)"
    if [ -n "$gar_out" ]; then
        printf '%s\n' "$gar_out" | while IFS=, read -r name loc uri fmt; do
            [ -n "$name" ] && [ -n "$loc" ] && printf 'gcp-gar\t%s\t%s\t%s\n' "$fmt" "$name" "$loc"
        done
    else
        # Fallback to legacy GCR
        gcloud container images list --project "$project" --format='csv[no-heading](NAME)' 2>/dev/null | \
            while IFS=, read -r name; do printf 'gcp-gcr\t%s\t%s\n' "$name" ""; done
    fi
}
rr_images_gcp() {
    local repo="$1"
    rr_has_gcp || return 1
    local project
    project="$(gcloud config get-value project 2>/dev/null)"
    [ -z "$project" ] && return 1
    # Try both formats
    gcloud container images list-tags "$repo" --project "$project" --format='csv[no-heading](TAGS,DIGEST)' 2>/dev/null | \
        while IFS=, read -r tags digest; do
            [ -n "$tags" ] && [ -n "$digest" ] && printf 'gcp\t%s\t%s\t%s\n' "$digest[0:20]" "$repo" "$tags"
        done
}
rr_tags_gcp() { rr_images_gcp "$1"; }

# ── Azure Container Registry ─────────────────────────────────────
rr_list_az() {
    rr_has_az || return 1
    az acr list --output json 2>/dev/null | \
        jq -r '.[] | ["az", .name, .resourceGroup, .loginServer, .sku.name] | @tsv' 2>/dev/null
}
rr_images_az() {
    local repo="$1"
    rr_has_az || return 1
    local registry
    registry="$(az acr list --query "[?name=='$repo'].loginServer" -o tsv 2>/dev/null)"
    [ -z "$registry" ] && registry="$repo"
    az acr repository show-tags --name "$registry" --output json 2>/dev/null | \
        jq -r '.[] | ["az", repo, ., ""] | @tsv' --arg repo "$repo" 2>/dev/null
}
rr_tags_az() { rr_images_az "$1"; }

# ── Docker Hub OSINT (unauthenticated) ──────────────────────────
rr_list_dockerhub() {
    local namespace="${1:-library}"
    curl -s --max-time "$RR_TIMEOUT" "https://hub.docker.com/v2/repositories/$namespace/?page_size=25" 2>/dev/null | \
        jq -r '.results[] | ["dockerhub", .name, .namespace, .description[0:80], .pull_count|tostring] | @tsv' 2>/dev/null
}
rr_tags_dockerhub() {
    local repo="$1" namespace="${2:-library}"
    curl -s --max-time "$RR_TIMEOUT" "https://hub.docker.com/v2/repositories/$namespace/$repo/tags/?page_size=50" 2>/dev/null | \
        jq -r '.results[] | ["dockerhub", .name, .tag_status, .last_updated] | @tsv' 2>/dev/null
}

# ── Pull & local scan ────────────────────────────────────────────
rr_pull() {
    local ref="$1"
    command -v docker >/dev/null 2>&1 || { rr_log "docker not installed"; return 1; }
    docker pull "$ref" 2>&1 | tail -3
    local ref_clean
    ref_clean="$(printf '%s' "$ref" | tr '/:' '_')"
    docker inspect "$ref" > "$OUT_DIR/inspect-${ref_clean}-$RUN_ID.json" 2>/dev/null && \
        rr_log "inspect saved to $OUT_DIR/inspect-${ref_clean}-$RUN_ID.json"
}

rr_cmd_images() {
    local repo="${1:-}"
    [ -z "$repo" ] && { rr_log "usage: --images <repo>"; return 1; }
    local out
    out="$(rr_images_aws "$repo" 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(rr_images_gcp "$repo" 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(rr_images_az "$repo" 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(rr_tags_dockerhub "$repo" 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
}
rr_cmd_tags() { rr_cmd_images "$@"; }

# ── Verb dispatchers ─────────────────────────────────────────────
rr_cmd_list() {
    local out n=0
    out="$(rr_list_aws 2>/dev/null)"
    if [ -n "$out" ]; then printf '%s\n' "$out"; n=$((n + 1)); fi
    out="$(rr_list_gcp 2>/dev/null)"
    if [ -n "$out" ]; then printf '%s\n' "$out"; n=$((n + 1)); fi
    out="$(rr_list_az 2>/dev/null)"
    if [ -n "$out" ]; then printf '%s\n' "$out"; n=$((n + 1)); fi
    printf 'SUMMARY\tproviders-with-repos=%s\n' "$n"
    return 0
}
rr_cmd_scan() {
    rr_log "indexing repositories..."
    rr_cmd_list
}
rr_cmd_status_tsv() {
    local curl_state docker_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    command -v docker >/dev/null 2>&1 && docker_state="docker-ok" || docker_state="docker-missing"
    printf '%s\t%s\tcurl-%s-%s\n' "$MODULE_ID" "$MOD_NAME" "$curl_state" "$docker_state"
}
rr_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }
rr_cmd_help() {
    cat <<'HELP'
cloudsting module 14 — Container Registry Reconnaissance v0.9.0
  --list                      list registries/repos (AWS ECR, GCP GAR, Azure ACR)
  --images <repo>             list images/tags in a repository
  --tags <repo>               alias for --images
  --pull <repo:tag>           pull image locally + docker inspect to loot/
  --dhl <namespace>           Docker Hub OSINT (default: library)
  --scan                      full registry index (list all repos)
  --status-tsv                module status
  --menu                      menu entry
  --selftest                  run selftests
  --help                      this message
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
rr_selftest() {
    local pass=0 fail=0
    chk() { local n="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$n"
        else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$n" "$want" "$got"; fi; }

    # --list with no creds = a clean zero, not a crash
    local list_out list_rc
    list_out="$(rr_cmd_list 2>/dev/null)"; list_rc=$?
    chk list-no-crash "$list_rc" "0"
    chk list-summary  "$(printf '%s' "$list_out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | grep -c .)" "1"

    # --images with no args = error
    local img_out
    img_out="$(rr_cmd_images 2>&1 1>/dev/null)" || true
    chk images-usage "$(printf '%s' "$img_out" | head -1 | grep -ci usage)" 1

    # Docker Hub OSINT — unauthenticated works
    local dh_out
    dh_out="$(rr_list_dockerhub library 2>/dev/null | head -5 | awk -F'\t' '$1=="dockerhub"' | wc -l)"
    chk dockerhub-list "$(( dh_out > 0 ? 1 : 0 ))" 1

    dh_out="$(rr_tags_dockerhub ubuntu 2>/dev/null | awk -F'\t' '$1=="dockerhub"' | wc -l)"
    chk dockerhub-tags "$(( dh_out > 0 ? 1 : 0 ))" 1

    # --status-tsv shape
    chk status-fields "$(rr_cmd_status_tsv | awk -F'\t' '{print NF}')" 3
    chk status-module "$(rr_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"

    # --help smoke
    chk help-smoke "$(rr_cmd_help 2>/dev/null | head -1 | grep -ci registry)" 1

    # --menu shape
    chk menu-shape "$(rr_cmd_menu | awk -F'\t' '{print NF}')" 3

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --list)      shift; rr_cmd_list "$@";;
    --images|--tags) shift; rr_cmd_images "$@";;
    --pull)      shift; rr_pull "$@";;
    --dhl)       shift; rr_list_dockerhub "${1:-library}";;
    --scan)      shift; rr_cmd_scan "$@";;
    --status-tsv|--status) rr_cmd_status_tsv;;
    --menu)      rr_cmd_menu;;
    --selftest)  rr_selftest;;
    *)           rr_cmd_help;;
esac
