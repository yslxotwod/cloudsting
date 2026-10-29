#!/usr/bin/env bash
# data/lib/core.sh — the shared core every cloudsting module sources.
#
# Why this exists: each of the first twenty-three modules carried its own copy
# of the same hundred and fifty lines — provider gate, loot paths, run id, TSV
# writer, a chk() helper, colour, redaction. That duplication is where the
# recurring bugs came from: tab-in-IFS collapsing empty fields, grep '\t'
# matching a literal 't', unset variables under `set -u`.
#
# Source it after the module has decided its own name:
#
#     MODULE_ID="24_snapshot_theft"
#     # shellcheck source=../data/lib/core.sh
#     source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"
#
# It sets, and exports: CLOUDSTING_ROOT, CS_MOD_DIR, CS_LOOT, CS_OUT_DIR,
# CS_TMP_DIR, CS_STATE_DIR, CS_RUN_ID, and it creates them mode 700.
#
# It is safe to source twice. It does not call `set -e`; the module decides.
# It never touches $HOME: loot lives under the project root, so a run under
# pkexec writes to the same tree as a run by the operator.

# ── guard ───────────────────────────────────────────────────────────
[[ -n "${CS_CORE_LOADED:-}" ]] && return 0
CS_CORE_LOADED=1
CS_CORE_VERSION=1

# ── self-location ───────────────────────────────────────────────────
# CLOUDSTING_ROOT resolves from *this file's* path, not the caller's cwd, so
# it is correct through symlinks, through pkexec and from any directory.
cs_core_root() {
    local src="${BASH_SOURCE[1]:-}" dir
    if [[ -z "$src" ]]; then
        # sourced from stdin or eval: fall back to the module dir we were
        # handed, then to the caller's cwd
        if [[ -n "${CS_MOD_DIR:-}" && -d "$CS_MOD_DIR/.." ]]; then
            (cd -P "$CS_MOD_DIR/.." && pwd); return
        fi
        pwd; return
    fi
    while [[ -L "$src" ]]; do
        dir="$(cd -P "$(dirname "$src")" && pwd)"
        src="$(readlink "$src")"
        [[ "$src" != /* ]] && src="$dir/$src"
    done
    [[ "$src" == /* ]] || src="$PWD/$src"
    # <root>/data/lib/core.sh -> <root>
    (cd -P "$(dirname "$src")/../.." && pwd)
}

if [[ -z "${CLOUDSTING_ROOT:-}" || ! -d "${CLOUDSTING_ROOT:-/nonexistent}/modules" ]]; then
    CLOUDSTING_ROOT="$(cs_core_root)"
fi
export CLOUDSTING_ROOT

: "${CS_MOD_DIR:=$(cd -P "$(dirname "${BASH_SOURCE[1]:-$PWD/x}")" 2>/dev/null && pwd || pwd)}"
export CS_MOD_DIR

# ── paths ───────────────────────────────────────────────────────────
: "${CLOUDSTING_LOOT:=$CLOUDSTING_ROOT/loot}"
: "${CLOUDSTING_STATE:=$CLOUDSTING_ROOT/state}"
: "${CLOUDSTING_TMP:=$CLOUDSTING_ROOT/tmp}"
: "${CLOUDSTING_LOGS:=$CLOUDSTING_ROOT/logs}"
export CLOUDSTING_LOOT CLOUDSTING_STATE CLOUDSTING_TMP CLOUDSTING_LOGS

CS_LOOT="$CLOUDSTING_LOOT"
CS_STATE_DIR="$CLOUDSTING_STATE"
CS_TMP_DIR="$CLOUDSTING_TMP"
CS_LOGS_DIR="$CLOUDSTING_LOGS"

# per-module loot directory: the slug with its numeric prefix stripped, so
# loot/bucket_enum/ rather than loot/03_bucket_enum/
cs_loot_dir_for() { local s="${1:-${MODULE_ID:-module}}"; printf '%s' "${s#*_}"; }

: "${CS_OUT_DIR:=$CS_LOOT/$(cs_loot_dir_for "${MODULE_ID:-module}")}"
: "${CS_RUN_ID:=$(date -u '+%Y%m%dT%H%M%SZ')-$$}"
export CS_OUT_DIR CS_RUN_ID

# run-scoped scratch, removed on exit by cs_core_install_trap unless the
# caller opts out. Never in $TMPDIR: a run under pkexec must not scatter.
: "${CS_SCRATCH:=$CS_TMP_DIR/run-$CS_RUN_ID}"

mkdir -p "$CS_LOOT" "$CS_STATE_DIR" "$CS_TMP_DIR" "$CS_LOGS_DIR" "$CS_OUT_DIR" 2>/dev/null || true
chmod 700 "$CS_LOOT" "$CS_OUT_DIR" "$CS_TMP_DIR" 2>/dev/null || true

# Back-compat: modules written before the core reference $LOOT_DIR/$TMP_DIR.
: "${LOOT_DIR:=$CS_LOOT}"
: "${TMP_DIR:=$CS_TMP_DIR}"
: "${STATE_DIR:=$CS_STATE_DIR}"
: "${LOGS_DIR:=$CS_LOGS_DIR}"
export LOOT_DIR TMP_DIR STATE_DIR LOGS_DIR

: "${RUN_ID:=$CS_RUN_ID}"
export RUN_ID

# ── output ──────────────────────────────────────────────────────────
if [[ -t 1 && -z "${NO_COLOR:-}" && -z "${CS_NO_COLOR:-}" ]]; then
    CS_RED=$'\033[31m'; CS_GRN=$'\033[32m'; CS_YEL=$'\033[33m'
    CS_CYN=$'\033[36m'; CS_DIM=$'\033[2m'; CS_BLD=$'\033[1m'; CS_RST=$'\033[0m'
else
    CS_RED=''; CS_GRN=''; CS_YEL=''; CS_CYN=''; CS_DIM=''; CS_BLD=''; CS_RST=''
fi
export CS_RED CS_GRN CS_YEL CS_CYN CS_DIM CS_BLD CS_RST

# Diagnostics go to stderr so a TSV pipeline stays clean.
cs_log()  { printf '[%s] %s\n' "${MODULE_ID:-cloudsting}" "$*" >&2; }
cs_warn() { printf 'warn\t%s\n' "$*" >&2; }
cs_err()  { printf 'error\t%s\n' "$*" >&2; }

# ── TSV ─────────────────────────────────────────────────────────────
# One place where a row is written, so a value can never smuggle a tab, a
# newline or a CR into the wire format and shift every later column.
cs_esc() {
    local s="${1-}"
    s="${s//$'\t'/ }"
    s="${s//$'\r'/ }"
    s="${s//$'\n'/ }"
    printf '%s' "$s"
}

# cs_row KEY VALUE...  — first field is the key, the rest are columns
cs_row() {
    local k="${1-}"; shift || true
    printf '%s' "$(cs_esc "$k")"
    local v
    for v in "$@"; do printf '\t%s' "$(cs_esc "$v")"; done
    printf '\n'
}

# cs_rowc KEY | COL2 | COL3   — explicit separator for callers that build a
# row from an already-joined string
cs_rowc() { printf '%s\n' "$(cs_esc "${1-}")"; }

# Read a TSV file without letting IFS swallow empty fields.
#   cs_read_line <linevar> <field1var> <field2var> ...
# Tab is IFS *whitespace*, so `IFS=$'\t' read -r a b c` collapses runs of
# empty fields and every row with a hole in it shifts left. Splitting on a
# sentinel that cannot appear in the data keeps the columns aligned.
cs_split() {
    local line="${1-}"; shift
    # Fill a scalar (one name) or an array (one array name) from a row of
    # fields. Tab is IFS whitespace and collapses empty fields, so the split
    # is done on a non-whitespace sentinel and an empty middle column survives
    # — which is the whole reason this helper exists.
    local sep=$'\x1f'
    local -a _cs_f
    local IFS="$sep"
    read -r -a _cs_f <<<"${line//$'\t'/$sep}"
    (( $# == 0 )) && { printf '%s\n' "${line//$'\t'/$sep}"; return 0; }
    local i _cs_n
    for (( i = 1; i <= $#; i++ )); do
        _cs_n="${!i}"
        if [[ "$(declare -p "$_cs_n" 2>/dev/null)" == "declare -a"* ]]; then
            eval "${_cs_n}=()"
            local -a _cs_tmp=("${_cs_f[@]}")
            eval "${_cs_n}=(\"\${_cs_tmp[@]}\")"
        else
            printf -v "$_cs_n" '%s' "${_cs_f[$(( i - 1 ))]-}"
        fi
    done
    return 0
}
# §	— three-state enumeration. Never collapse these into two.
cs_state_tool_missing()  { printf 'tool-missing'; }
cs_state_creds_missing() { printf 'creds-missing'; }
cs_state_creds_present() { printf 'creds-present'; }

# cs_provider_state <aws|gcloud|azure|doctl|oci>
# One implementation of the gate the modules were each re-deriving.
cs_provider_state() {
    local p="${1:-}"
    case "$p" in
        aws)
            command -v aws >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if [[ -f "${AWS_SHARED_CREDENTIALS_FILE:-$HOME/.aws/credentials}" ]] \
               || [[ -n "${AWS_ACCESS_KEY_ID:-}" || -n "${AWS_PROFILE:-}" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        gcloud|gcp)
            command -v gcloud >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | grep -q .; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        azure|az)
            command -v az >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if [[ -f "$HOME/.azure/azureProfile.json" ]] \
               || az account show >/dev/null 2>&1; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        digitalocean|do|doctl)
            command -v doctl >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if doctl auth list 2>/dev/null | grep -q .; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        oci)
            command -v oci >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if [[ -f "${OCI_CLI_CONFIG_FILE:-$HOME/.oci/config}" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        kubectl|k8s)
            command -v kubectl >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if kubectl cluster-info >/dev/null 2>&1; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        ibm|ibmcloud|ics)
            command -v ibmcloud >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if ibmcloud target 2>/dev/null | grep -q 'Account:'; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        alibaba|aliyun|alicloud)
            command -v aliyun >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if [[ -n "${ALIBABACLOUD_ACCESS_KEY_ID:-}" || -f "$HOME/.aliyun/config.json" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        tencent|tcloud|tccli)
            command -v tccli >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if [[ -n "${TENCENTCLOUD_SECRET_ID:-}" || -f "$HOME/.tccli/default.credential" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        scaleway|scw)
            command -v scw >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if [[ -f "${SCW_CONFIG_PATH:-$HOME/.config/scw/config.yaml}" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        linode|akamai)
            command -v linode-cli >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if [[ -f "$HOME/.config/linode-cli" || -n "${LINODE_CLI_TOKEN:-}" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        hetzner|hcloud)
            command -v hcloud >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if [[ -f "${HCLOUD_CONFIG:-$HOME/.config/hcloud/cli.toml}" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        vultr)
            command -v vultr-cli >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if [[ -f "$HOME/.config/vultr-cli.yaml" || -n "${VULTR_API_KEY:-}" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        cloudflare|cf)
            # no CLI needed: the token is the whole story
            if [[ -n "${CLOUDFLARE_API_TOKEN:-}" || -n "${CF_API_TOKEN:-}" || -f "$HOME/.cloudflare/config.yaml" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        openstack|os)
            if [[ -n "${OS_AUTH_URL:-}" && -n "${OS_USERNAME:-}" ]]; then
                cs_state_creds_present
            elif [[ -f "$HOME/.config/openstack/clouds.yaml" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        vmware|vsphere)
            command -v govc >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if [[ -n "${GOVC_URL:-}" || -f "$HOME/.govc/env" ]]; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        kubernetes|k8s|kubectl)
            command -v kubectl >/dev/null 2>&1 || { cs_state_tool_missing; return; }
            if kubectl cluster-info >/dev/null 2>&1; then
                cs_state_creds_present
            else
                cs_state_creds_missing
            fi ;;
        *) printf 'unknown' ;;
    esac
}

# The provider order every module walks. One list, so a new provider lands
# in every module that enumerates the estate instead of in whichever ones
# somebody remembered to patch.
CS_PROVIDERS="aws gcp azure digitalocean alibaba tencent oci ibm linode hetzner vultr scaleway cloudflare openstack kubernetes"

# cs_provider_table <label> — one row per provider: <label>\t<provider>\t<state>
cs_provider_table() {
    local label="${1:-PROVIDER}" p st
    for p in $CS_PROVIDERS; do
        st="$(cs_provider_state "$p")"
        cs_row "$label" "$p" "$st"
    done
}

# cs_provider_any — 0 when at least one provider reports creds-present
cs_provider_any() {
    local p
    for p in $CS_PROVIDERS; do
        [[ "$(cs_provider_state "$p")" == "creds-present" ]] && return 0
    done
    return 1
}

# cs_have <tool>  — 0 when the tool is on PATH
cs_have() { command -v "${1:?tool required}" >/dev/null 2>&1; }

# cs_need <tool> [module hint] — emit ERROR row and return 3 when missing
cs_need() {
    local tool="${1:?tool required}" hint="${2:-}"
    cs_have "$tool" && return 0
    cs_row ERROR "missing tool: $tool${hint:+ ($hint)}"
    return 3
}

# ── redaction ───────────────────────────────────────────────────────
# Loot is not redacted by default, but a row that is going into a log or a
# findings store gets the value a credential may be wearing.
cs_redact() {
    local s="${1-}"
    local n=${#s}
    if (( n <= 8 )); then
        printf '***'
        return
    fi
    printf '%s…%s (%d chars)' "${s:0:4}" "${s: -2}" "$n"
}

# Fingerprint a secret without keeping it: the modules record this instead of
# the value. sha1 is fast and non-reversible enough for a loot index.
# cs_ipforge <mode> <seed>
# An address for a rate-limit bypass. Every proxy that trusts a forwarding
# header trusts one shape of it, so the modes are the shapes, not the ranges:
#   xff      X-Forwarded-For with one address
#   real     X-Real-IP
#   cf       CF-Connecting-IP (Cloudflare)
#   true     True-Client-IP (Akamai/Cloudflare enterprise)
#   fwd      Forwarded: for= (RFC 7239)
#   chain    X-Forwarded-For with a client hop and an edge hop
#   all      every header at once, same address
# Deterministic for a seed so a sweep is reproducible in a report.
cs_ipforge() {
    local mode="${1:-xff}" seed="${2:-0}"
    local a b c d
    # Documentation ranges are avoided on purpose: a proxy that recognizes
    # 10/8 or 192.0.2/24 as private may refuse to forward the request at all.
    a=$(( 11 + (seed % 200) % 200 ))
    b=$(( (seed * 37) % 254 + 1 ))
    c=$(( (seed * 91) % 254 + 1 ))
    d=$(( (seed * 13) % 254 + 1 ))
    local ip="${a}.${b}.${c}.${d}"
    case "$mode" in
        xff)   printf 'X-Forwarded-For: %s' "$ip" ;;
        real)  printf 'X-Real-IP: %s' "$ip" ;;
        cf)    printf 'CF-Connecting-IP: %s' "$ip" ;;
        true)  printf 'True-Client-IP: %s' "$ip" ;;
        fwd)   printf 'Forwarded: for=%s' "$ip" ;;
        chain) printf 'X-Forwarded-For: %s, %s' "$ip" "$(cs_ipforge __edge "$seed")" ;;
        all)   printf 'X-Forwarded-For: %s\nX-Real-IP: %s\nCF-Connecting-IP: %s\nTrue-Client-IP: %s\nX-Client-IP: %s\nX-Originating-IP: %s' \
                      "$ip" "$ip" "$ip" "$ip" "$ip" "$ip" ;;
        __edge) printf '172.%s.%s.%s' "$(( (seed * 7) % 30 + 16 ))" "$b" "$c" ;;
        *)     return 2 ;;
    esac
}

cs_ipforge_modes() { printf '%s\n' xff real cf true fwd chain all; }

cs_fingerprint() {
    if cs_have sha1sum; then printf '%s' "${1-}" | sha1sum | cut -c1-12
    elif cs_have openssl; then printf '%s' "${1-}" | openssl dgst -sha1 | awk '{print substr($NF,1,12)}'
    else printf '%s' "${1-}" | cksum | awk '{printf "%08x", $1}'
    fi
}

# ── http ────────────────────────────────────────────────────────────
# One request wrapper, because 33 modules had grown their own and the same
# two bugs kept appearing in them:
#
#   * curl does NOT expand \t or \036 inside --write-out. A format string
#     with a tab emits a literal backslash-t, so `IFS=$'\t' read` never
#     splits and the whole meta string lands in the status code. Two modules
#     were comparing garbage for weeks while looking healthy.
#   * Content-Type carries a space ("application/json; charset=utf-8"), so it
#     cannot ride along a space-separated format either.
#
# So: the body goes to a file, the headers go to a file, and --write-out
# emits exactly three always-numeric, space-separated fields. Content-Type
# and Location are read back out of the header dump — from what the server
# actually sent, not from a format string.
CS_HTTP_TIMEOUT="${CS_HTTP_TIMEOUT:-10}"
CS_HTTP_ERROR=""

# cs_http_header <header-dump> <name> — the LAST value wins, so a redirect
# chain reports the final response rather than the 302 that started it.
cs_http_header() {
    local f="${1:-}" want="${2:-}"
    [[ -r "$f" ]] || return 0
    awk -v w="${want,,}" '
        {
            line = $0; sub(/\r$/, "", line)
            i = index(line, ":")
            if (i > 1) {
                k = substr(line, 1, i - 1); gsub(/^[ \t]+|[ \t]+$/, "", k)
                if (tolower(k) == w) {
                    v = substr(line, i + 1); gsub(/^[ \t]+|[ \t]+$/, "", v)
                    out = v
                }
            }
        }
        END { print out }' "$f" 2>/dev/null
}

# cs_http <method> <url> [flags]
#   -H 'Header: value'   extra request header (repeatable)
#   -d <body>            request body as a string
#   -f <file>            request body from a file (bytes preserved exactly)
#   -c <ctype>           Content-Type for -d/-f
#   -m <seconds>         total timeout          (default $CS_HTTP_TIMEOUT)
#   -L                   follow redirects
#   -k                   skip TLS verification
#   -A <ua>              User-Agent
#   -b <cookie>          Cookie header
#   -t <token>           Authorization: Bearer <token>
#   -o <path>            keep the response body here (default: a temp file)
#
# Prints one U+001F separated record — split it with cs_split, never `read`:
#   code  secs  bytes  sha1-12  content-type  location  body-path  error
# code is 000 and bytes 0 when nothing answered; the last field then carries
# curl's own complaint. It is a FIELD rather than a global because the normal
# way to call this is `$(cs_http ...)`, and a command substitution runs in a
# subshell — a global set in there never reaches the caller.
cs_http() {
    local method="${1:-GET}" url="${2:-}"
    if [[ $# -ge 2 ]]; then shift 2; else shift $#; fi

    local -a hdrs=() cargs=()
    local body="" bfile="" ctype="" to="$CS_HTTP_TIMEOUT" follow=0 insecure=0
    local ua="" out="" cookie="" token="" own_body=1 pathas=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -H) hdrs+=("${2-}"); shift 2 ;;
            -d) body="${2-}";     shift 2 ;;
            -f) bfile="${2-}";    shift 2 ;;
            -c) ctype="${2-}";    shift 2 ;;
            -m) to="${2-}";       shift 2 ;;
            -A) ua="${2-}";       shift 2 ;;
            -b) cookie="${2-}";   shift 2 ;;
            -t) token="${2-}";    shift 2 ;;
            -o) out="${2-}";      shift 2 ;;
            -L) follow=1;         shift ;;
            -k) insecure=1;       shift ;;
            -P) pathas=1;         shift ;;
            *)  shift ;;
        esac
    done

    if [[ -z "$url" ]]; then
        CS_HTTP_ERROR="no-url"
        printf '000\x1f0\x1f0\x1f\x1f\x1f\x1f\x1f%s\n' "no-url"
        return 2
    fi
    if ! cs_have curl; then
        CS_HTTP_ERROR="tool-missing: curl"
        printf '000\x1f0\x1f0\x1f\x1f\x1f\x1f\x1f%s\n' "tool-missing: curl"
        return 3
    fi

    local dir="${CS_SCRATCH:-${TMPDIR:-/tmp}}"
    mkdir -p "$dir" 2>/dev/null || true
    local bf hf errf meta rc code bytes secs
    if [[ -n "$out" ]]; then
        bf="$out"; own_body=0
        mkdir -p "$(dirname "$out")" 2>/dev/null || true
    else
        bf="$(mktemp "$dir/http-body.XXXXXX" 2>/dev/null)"
    fi
    hf="$(mktemp "$dir/http-hdr.XXXXXX" 2>/dev/null)"
    errf="$(mktemp "$dir/http-err.XXXXXX" 2>/dev/null)"

    cargs=(-sS --max-time "$to" -D "$hf" -o "$bf"
           -w '%{http_code} %{size_download} %{time_total}')
    if [[ "${method^^}" == "HEAD" ]]; then
        cargs+=(--head)          # -X HEAD makes curl wait for a body that never comes
    else
        cargs+=(-X "$method")
    fi
    (( follow ))   && cargs+=(-L)
    (( insecure )) && cargs+=(-k)
    # Without this curl collapses "/./admin" to "/admin" before it leaves the
    # box, so a WAF-bypass test would measure curl's normaliser instead of the
    # target's — and report a bypass that never happened.
    (( pathas ))   && cargs+=(--path-as-is)
    [[ -n "$ua" ]]     && cargs+=(-A "$ua")
    [[ -n "$cookie" ]] && cargs+=(-b "$cookie")
    [[ -n "$token" ]]  && cargs+=(-H "Authorization: Bearer $token")
    [[ -n "$ctype" ]]  && cargs+=(-H "Content-Type: $ctype")
    [[ -n "$body" ]]   && cargs+=(--data-binary "$body")
    [[ -n "$bfile" ]]  && cargs+=(--data-binary "@$bfile")
    local h; for h in "${hdrs[@]}"; do [[ -n "$h" ]] && cargs+=(-H "$h"); done
    cargs+=(--url "$url")

    meta="$(curl "${cargs[@]}" 2>"$errf")"; rc=$?
    CS_HTTP_ERROR="$(tr -d '\r' < "$errf" 2>/dev/null | head -3 | tr '\n' ' ')"
    [[ "$rc" -eq 0 ]] || CS_HTTP_ERROR="${CS_HTTP_ERROR:-curl exit $rc}"

    # Three numeric fields, always on one line, so a tab never has to survive.
    read -r code bytes secs <<<"${meta:-000 0 0}"
    code="${code:-000}"
    [[ "$code" =~ ^[0-9]{3}$ ]] || code="000"
    bytes="${bytes:-0}"
    [[ "$bytes" =~ ^[0-9]+$ ]] || bytes=0
    secs="${secs:-0}"

    local ctype_out loc hash
    ctype_out="$(cs_http_header "$hf" 'content-type')"
    loc="$(cs_http_header "$hf" 'location')"
    hash="$(sha1sum "$bf" 2>/dev/null | cut -c1-12)"

    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' \
        "$code" "$secs" "$bytes" "$hash" "$ctype_out" "$loc" "$bf" \
        "$(printf '%s' "$CS_HTTP_ERROR" | tr -d '\037\n\r')"


    # A vendor fingerprint reads headers this record does not carry. Asking
    # for the dump by path keeps the eight-field record stable and hands back
    # the bytes the server actually sent, not a reconstruction.
    if [[ -n "${CS_HTTP_HDR_OUT:-}" && -s "$hf" ]]; then
        mkdir -p "$(dirname "$CS_HTTP_HDR_OUT")" 2>/dev/null || true
        cat "$hf" > "$CS_HTTP_HDR_OUT" 2>/dev/null || true
    fi
    rm -f "$hf" "$errf" 2>/dev/null || true
    (( own_body )) && [[ "$code" == "000" ]] && rm -f "$bf" 2>/dev/null
    return 0
}


# ── selftest ────────────────────────────────────────────────────────
# chk <name> <got> <want> — the helper every module was rewriting. Sets
# CS_PASS/CS_FAIL; cs_selftest_done prints the RESULT line and returns 0/1.
CS_PASS=0
CS_FAIL=0

chk() {
    local name="${1-}" got="${2-}" want="${3-}"
    if [[ "$got" == "$want" ]]; then
        printf 'ok\t%s\n' "$name"; CS_PASS=$((CS_PASS + 1))
    else
        printf 'FAIL\t%s\twant=%s got=%s\n' "$name" "$want" "$got"
        CS_FAIL=$((CS_FAIL + 1))
    fi
}

chk_eq()   { chk "$1" "$2" "$3"; }
chk_ne()   { local n="$1" got="$2" want="$3"; if [[ "$got" != "$want" ]]; then printf 'ok\t%s\n' "$n"; CS_PASS=$((CS_PASS+1)); else printf 'FAIL\t%s\tmust-differ\n' "$n"; CS_FAIL=$((CS_FAIL+1)); fi; }
chk_has()  { local n="$1" hay="$2" needle="$3"; if [[ "$hay" == *"$needle"* ]]; then printf 'ok\t%s\n' "$n"; CS_PASS=$((CS_PASS+1)); else printf 'FAIL\t%s\tmissing=%s\n' "$n" "$needle"; CS_FAIL=$((CS_FAIL+1)); fi; }
chk_num()  { local n="$1" got="$2" want="$3"; if [[ "$got" =~ ^-?[0-9]+$ ]] && (( got == want )); then printf 'ok\t%s\n' "$n"; CS_PASS=$((CS_PASS+1)); else printf 'FAIL\t%s\twant=%s got=%s\n' "$n" "$want" "$got"; CS_FAIL=$((CS_FAIL+1)); fi; }

cs_selftest_reset() { CS_PASS=0; CS_FAIL=0; }

cs_selftest_done() {
    if (( CS_FAIL == 0 )); then
        printf 'RESULT\tPASS(%d)\n' "$CS_PASS"
        return 0
    fi
    printf 'RESULT\tFAIL(%d)\n' "$CS_FAIL"
    return 1
}

# ── cleanup ─────────────────────────────────────────────────────────
cs_core_cleanup() {
    [[ -n "${CS_SCRATCH:-}" && -d "${CS_SCRATCH:-}" ]] && rm -rf "$CS_SCRATCH"
    return 0
}

cs_core_install_trap() {
    # preserve whatever trap the module already set
    local existing
    existing="$(trap -p EXIT 2>/dev/null | sed -E "s/^trap -- '(.*)' EXIT$/\1/")"
    if [[ -n "$existing" ]]; then
        # shellcheck disable=SC2064
        trap "$existing; cs_core_cleanup" EXIT
    else
        trap cs_core_cleanup EXIT
    fi
}

cs_findings_file() { printf '%s/findings.tsv' "$CS_LOOT"; }
cs_findings_map()  { printf "%s/data/findings.map" "${CLOUDSTING_ROOT:-${CS_ROOT:-}}"; }

# The schema this launcher writes. A reader checks the header before parsing.
# `run` is the last column so every earlier index keeps its meaning.
CS_FINDINGS_HEADER=$'ts\tmodule\tcategory\tseverity\ttarget\tcheck\tdetail\tevidence\trun'

# The one category vocabulary. A finding's category is what an analyst filters
# on, so a module spelling it differently is not a cosmetic problem — it splits
# one engagement across two buckets in `findings stats`.
CS_FINDINGS_CATEGORIES="SETUP CREDS IDENTITY ATTRITION DNS STORAGE COMPUTE NETWORK SURFACE WEBAPI TOOLING"

# cs_findings_category <module> <as-passed>
# Known words pass through, retired aliases are translated, and anything else
# is answered by asking the registry what category this module is registered
# under — so a module cannot invent a bucket by passing a new word.
cs_findings_category() {
    local mod="${1:-}" raw="${2:-}"
    local c
    c="$(printf '%s' "$raw" | tr -d '\t\n\r' | tr '[:lower:]' '[:upper:]')"
    case "$c" in
        SETUP|CREDS|IDENTITY|ATTRITION|DNS|STORAGE|COMPUTE|NETWORK|SURFACE|WEBAPI|TOOLING)
            printf '%s' "$c"; return 0 ;;
        # retired spellings this tree actually contains
        CREDENTIALS|CREDENTIAL|SECRETS|SECRET|KEYS|AUTH|PASSWORDS)
            printf 'CREDS'; return 0 ;;
        RECON|DISCOVERY|ENUM|ENUMERATION|PASSIVE|ASSETS)
            printf 'SURFACE'; return 0 ;;
        API|WEB|HTTP|REST|GRAPHQL|SOAP|ENDPOINT|ENDPOINTS)
            printf 'WEBAPI'; return 0 ;;
        AUDIT|LOGGING|DETECTION|EVASION|FORENSICS)
            printf 'ATTRITION'; return 0 ;;
        DATA|OBJECT|DATABASE|DB|FILES|BUCKETS)
            printf 'STORAGE'; return 0 ;;
        NET|VPC|FIREWALL|ROUTE|ROUTES|SUBNET)
            printf 'NETWORK'; return 0 ;;
        CONTAINER|K8S|KUBERNETES|HOST|VM|SERVERLESS|FUNCTIONS)
            printf 'COMPUTE'; return 0 ;;
        IAM|ROLE|POLICY|TRUST|PRIVILEGE)
            printf 'IDENTITY'; return 0 ;;
    esac
    # Not a word we know. The module's registered category is the honest
    # answer, and it keeps the fallback from guessing.
    local reg="${CLOUDSTING_ROOT:-${CS_ROOT:-}}/data/registry.tsv"
    if [[ -n "$mod" && -r "$reg" ]]; then
        local got
        got="$(awk -F'\t' -v m="$mod" '$2==m { print $4; exit }' "$reg" 2>/dev/null)"
        if [[ -n "$got" ]]; then printf '%s' "$got"; return 0; fi
    fi
    printf '%s' "${c:-SURFACE}"
}

cs_findings_ensure() {
    local f; f="$(cs_findings_file)"
    mkdir -p "$(dirname "$f")" 2>/dev/null || true
    if [[ ! -s "$f" ]]; then
        printf '%s\n' "$CS_FINDINGS_HEADER" > "$f"
    else
        # A ledger written before the `run` column has eight fields. Upgrade it
        # in place so every reader can index the same field either way.
        local head; head="$(head -1 "$f")"
        if [[ "$head" != "$CS_FINDINGS_HEADER" ]]; then
            local tmp
            tmp="$(mktemp "${CS_TMP_DIR:-${TMPDIR:-/tmp}}/findings.XXXXXX" 2>/dev/null)" || {
                printf '%s' "$f"; return 0; }
            {
                printf '%s\n' "$CS_FINDINGS_HEADER"
                awk 'NR>1 && $1!="ts" { n=gsub(/\t/,"\t"); while (n < 8) { $0 = $0 "\t"; n++ } print }' "$f"
            } > "$tmp" 2>/dev/null && mv "$tmp" "$f"
            rm -f "$tmp" 2>/dev/null || true
        fi
    fi
    printf '%s' "$f"
}

# severity lookup: cs_findings_severity <module-slug> <key> <value> <category>
# Rules are ordered; the first pattern that matches wins. A rule file line is:
#   <glob-on-module>\t<glob-on-key>\t<glob-on-value>\t<severity>
cs_findings_severity() {
    local mod="$1" key="$2" val="$3" fallback="$4"
    local map; map="$(cs_findings_map)"
    local sev=""
    if [[ -r "$map" ]]; then
        sev="$(awk -F'\t' -v m="$mod" -v k="$key" -v v="$val" '
            $1 !~ /^#/ && NF>=4 {
                if (m ~ glob2re($1) && k ~ glob2re($2) && v ~ glob2re($3)) { print $4; exit }
            }
            function glob2re(g,   s) {
                s = g
                gsub(/[][(){}.*+?^$|\\]/, "\\\\&", s)
                gsub(/\\\*/, ".*", s)
                return "^" s "$"
            }' "$map" 2>/dev/null)" || sev=""
    fi
    printf '%s' "${sev:-$fallback}"
}

# Map a module row into the unified shape.
#   cs_findings_row <slug> <category> <target> <key> <value...>
cs_findings_row() {
    local mod="$1" cat="$2" tgt="$3" key="$4"; shift 4
    local val="$*"

    # Modules grade a row two ways: the first field may itself be the grade
    # (`high<TAB>aws<TAB>wildcard ...`) or the grade may open the key
    # (`WARN<TAB>seccomp<TAB>...`). Read the whole row, first field first.
    local sev="info" check="$key" detail="$val"
    local lead="${key,,}"
    case "$lead" in
        crit*|critical*)            sev="critical" ;;
        high*)                       sev="high" ;;
        med*|medium*)                sev="medium" ;;
        warn*|warning*)              sev="medium" ;;
        low*)                        sev="low" ;;
        info*|ok|state|summary|plan|probe|clean) sev="info" ;;
    esac
    # `high<TAB>aws<TAB>wildcard<TAB>detail`: the grade is the first field and
    # the check name is the second, so the row keeps its own vocabulary.
    if [[ "$sev" != "info" && "$val" == *$'\t'* ]]; then
        local second="${val%%$'\t'*}"
        check="$key:$second"
    fi
    # a row whose value says it passed is clean, not informational
    case "${val,,}" in
        *"no "*"detected"*|*none*|*"not found"*|*"not public"*|*"not enabled"*|*absent*|*clean*|*"tool-missing"*)
            [[ "$sev" == "info" ]] && sev="clean" ;;
    esac
    sev="$(cs_findings_severity "$mod" "$key" "$val" "$sev")"
    cat="$(cs_findings_category "$mod" "$cat")"

    local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local chk det
    chk="$(printf '%s' "$check" | tr -d '\t\n\r')"
    det="$(printf '%s' "$detail" | tr -d '\t\n\r')"
    local row
    row="$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
        "$ts" "$mod" "$cat" "$sev" "$tgt" "$chk" "$det" \
        "${CS_EVIDENCE:-}" "${CS_RUN_ID:-}")"

    # A finding is a row in the ledger, not a line on the terminal. This used
    # to PRINT the row and leave the append to every call site, and 41 modules
    # never did it — so everything they found was shown once and thrown away,
    # and the cross-module correlation the store exists for never worked.
    # Append here, where it cannot be forgotten.
    local f; f="$(cs_findings_ensure)"

    # The same observation recorded twice is noise, not a second finding: two
    # scans of one target used to leave two identical rows and made the ledger
    # unreadable. Skip an exact repeat; CS_FINDINGS_NO_DEDUP=1 forces it in.
    if [[ -z "${CS_FINDINGS_NO_DEDUP:-}" ]]; then
        if awk -F'\t' -v m="$mod" -v c="$cat" -v s="$sev" -v t="$tgt" -v k="$chk" -v d="$det" '
                NR>1 && $2==m && $3==c && $4==s && $5==t && $6==k && $7==d { found=1; exit }
                END { exit !found }' "$f" 2>/dev/null; then
            printf '%s\n' "$row"
            return 0
        fi
    fi

    printf '%s\n' "$row" >> "$f"

    # keep printing it, because callers legitimately capture or display it
    printf '%s\n' "$row"
}

mkdir -p "$CS_SCRATCH" 2>/dev/null || true
cs_core_install_trap
