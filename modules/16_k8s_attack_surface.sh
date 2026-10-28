#!/usr/bin/env bash
# 16_k8s_attack_surface.sh — cloudsting module 16: Kubernetes Attack Surface Reconnaissance
# Verbs: --clusters | --nodes | --pods | --rbac | --secrets | --all | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="16_k8s_attack_surface"
MOD_NAME="Kubernetes Attack Surface Recon"
MOD_VERSION="0.11.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export KS_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/k8s_attack_surface"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true

ks_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── Provider gates ───────────────────────────────────────────────
ks_has_kubectl() { command -v kubectl >/dev/null 2>&1; }
ks_has_aws() { command -v aws >/dev/null 2>&1 && aws sts get-caller-identity >/dev/null 2>&1; }
ks_has_gcp() { command -v gcloud >/dev/null 2>&1 && gcloud auth list --format=json 2>/dev/null | jq -e '.[] | select(.status=="ACTIVE")' >/dev/null 2>&1; }
ks_has_az()  { command -v az >/dev/null 2>&1 && az account show >/dev/null 2>&1; }

# ── Cluster enumeration: EKS, GKE, AKS ──────────────────────────
ks_clusters_aws() {
    ks_has_aws || return 1
    aws eks list-clusters --output json 2>/dev/null | jq -r '.clusters[]' | while IFS= read -r name; do
        local info
        info="$(aws eks describe-cluster --name "$name" --output json 2>/dev/null)"
        local version status endpoint
        version="$(printf '%s' "$info" | jq -r '.cluster.version // "-"')"
        status="$(printf '%s' "$info" | jq -r '.cluster.status // "-"')"
        endpoint="$(printf '%s' "$info" | jq -r '.cluster.endpoint // "-"')"
        printf 'aws-eks\t%s\t%s\t%s\t%s\n' "$name" "$version" "$status" "$endpoint"
    done
}

ks_clusters_gcp() {
    ks_has_gcp || return 1
    local project
    project="$(gcloud config get-value project 2>/dev/null)"
    [ -z "$project" ] && return 1
    gcloud container clusters list --project "$project" --format='csv[no-heading](NAME,LOCATION,STATUS,MASTER_VERSION,ENDPOINT)' 2>/dev/null | \
        while IFS=, read -r name loc status ver endpoint; do
            [ -n "$name" ] && printf 'gcp-gke\t%s\t%s\t%s\t%s\t%s\n' "$name" "$ver" "$loc" "$status" "$endpoint"
        done
}

ks_clusters_az() {
    ks_has_az || return 1
    az aks list --output json 2>/dev/null | \
        jq -r '.[] | ["az-aks", .name, .kubernetesVersion, .powerState.code, .fqdn] | @tsv' 2>/dev/null
}

# ── kubectl-based probes (needs active kubeconfig) ───────────────
ks_kubectl_nodes() {
    ks_has_kubectl || return 1
    kubectl get nodes -o json 2>/dev/null | \
        jq -r '.items[] | [.metadata.name, .status.nodeInfo.architecture, .status.nodeInfo.kubeletVersion, .status.nodeInfo.osImage, .status.nodeInfo.containerRuntimeVersion] | @tsv' 2>/dev/null
}

ks_kubectl_pods() {
    ks_has_kubectl || return 1
    kubectl get pods --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | [.metadata.namespace, .metadata.name, .spec.nodeName // "-", (.status.containerStatuses[0].image // "-"), .status.phase] | @tsv' 2>/dev/null
}

ks_kubectl_rbac() {
    ks_has_kubectl || return 1
    # ClusterRoles + bindings
    printf '# ClusterRoles\n'
    kubectl get clusterroles -o json 2>/dev/null | \
        jq -r '.items[] | select(.rules != null) | select(.rules[].resources != null) | [.metadata.name, (.rules[].resources | join(","))] | @tsv' 2>/dev/null
    printf '# ClusterRoleBindings\n'
    kubectl get clusterrolebindings -o json 2>/dev/null | \
        jq -r '.items[] | [.metadata.name, .roleRef.name, (.subjects[].name // "-")] | @tsv' 2>/dev/null
    # Check if current user can do dangerous things
    printf '# Can-I self-audit\n'
    for action in "create pods" "create deployments" "create roles" "create clusterroles" "list secrets"; do
        local verb="${action% *}" resource="${action#* }"
        local result
        result="$(kubectl auth can-i "$verb" "$resource" 2>/dev/null || echo "no")"
        printf '%s\t%s\t%s\n' "$verb" "$resource" "$result"
    done
}

ks_kubectl_secrets() {
    ks_has_kubectl || return 1
    kubectl get secrets --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | [.metadata.namespace, .metadata.name, (.type // "Opaque"), (.data | keys | join(","))] | @tsv' 2>/dev/null
}

# ── Verb dispatchers ─────────────────────────────────────────────
ks_cmd_clusters() {
    local out
    out="$(ks_clusters_aws 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(ks_clusters_gcp 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(ks_clusters_az 2>/dev/null)"
    [ -n "$out" ] && printf '%s\n' "$out"
}
ks_cmd_nodes() { ks_kubectl_nodes; }
ks_cmd_pods() { ks_kubectl_pods; }
ks_cmd_rbac() { ks_kubectl_rbac; }
ks_cmd_secrets() { ks_kubectl_secrets; }
ks_cmd_all() {
    ks_log "=== K8s Attack Surface ==="
    ks_log "--- clusters ---"
    ks_cmd_clusters
    if ks_has_kubectl; then
        ks_log "--- nodes ---"
        ks_cmd_nodes
        ks_log "--- pods ---"
        ks_cmd_pods
        ks_log "--- RBAC ---"
        ks_cmd_rbac
        ks_log "--- secrets ---"
        ks_cmd_secrets
    else
        ks_log "kubectl not available — skipping in-cluster probes"
    fi
}
ks_cmd_list() {
    cat <<'LIST'
cloud-provider-cluster	provider	EKS/GKE/AKS cluster metadata
kubeconfig-access	config	read ~/.kube/config for active contexts
kubectl-nodes	node	kubectl get nodes enumeration
kubectl-pods	pod	kubectl get pods --all-namespaces
kubectl-rbac	rbac	ClusterRole/RoleBinding audit + can-i self-audit
kubectl-secrets	secret	list all secrets across namespaces
LIST
}

ks_cmd_status_tsv() {
    local state
    if ks_has_kubectl; then
        if kubectl auth can-i list pods >/dev/null 2>&1; then
            state="kubectl-active"
        else
            state="kubectl-no-access"
        fi
    else
        state="kubectl-missing"
    fi
    printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "$state"
}
ks_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }
ks_cmd_help() {
    cat <<'HELP'
cloudsting module 16 — Kubernetes Attack Surface Recon v0.11.0
  --clusters                enumerate managed clusters (EKS, GKE, AKS)
  --nodes                   list nodes (kubectl)
  --pods                    list pods (kubectl, all namespaces)
  --rbac                    RBAC audit: clusterroles + can-i self-check
  --secrets                 list secrets across all namespaces
  --all                     full attack surface scan
  --list                    list surface categories
  --status-tsv              module status (kubectl-active / no-access / missing)
  --menu                    menu entry
  --selftest                run selftests
  --help                    this message
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ks_selftest() {
    local pass=0 fail=0
    chk() { local n="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$n"
        else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$n" "$want" "$got"; fi; }

    # --list smoke
    chk list-count "$(ks_cmd_list | wc -l)" 6

    # --clusters with no creds = empty but no crash
    local out
    out="$(ks_cmd_clusters 2>/dev/null)"
    chk clusters-no-crash "${out:-ok}" "ok"

    # --status-tsv shape
    chk status-fields "$(ks_cmd_status_tsv | awk -F'\t' '{print NF}')" 3
    chk status-module "$(ks_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"

    # --help smoke
    chk help-smoke "$(ks_cmd_help 2>/dev/null | head -1 | grep -ci kubernetes)" 1

    # --menu shape
    chk menu-shape "$(ks_cmd_menu | awk -F'\t' '{print NF}')" 3

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --clusters)  shift; ks_cmd_clusters "$@";;
    --nodes)     shift; ks_cmd_nodes "$@";;
    --pods)      shift; ks_cmd_pods "$@";;
    --rbac)      shift; ks_cmd_rbac "$@";;
    --secrets)   shift; ks_cmd_secrets "$@";;
    --all)       shift; ks_cmd_all;;
    --list)      shift; ks_cmd_list;;
    --status-tsv|--status) ks_cmd_status_tsv;;
    --menu)      ks_cmd_menu;;
    --selftest)  ks_selftest;;
    *)           ks_cmd_help;;
esac
