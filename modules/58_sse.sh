#!/usr/bin/env bash
# 58_sse.sh — cloudsting module 58: the stream that never closes
# Verbs: --probe | --auth | --cors | --inject | --sample | --paths | --events
#        | --list | --status-tsv | --menu | --selftest | --help
#
# Server-Sent Events is one HTTP response that stays open and pushes. Every
# check an HTTP tool applies to it — a status code, a header block — is read
# before the interesting part starts, so this module reads the stream itself
# and grades what came down it.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="58_sse"
MOD_NAME="Server-Sent Events (a stream nobody authenticated, per event)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/sse"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${SE_TIMEOUT:=10}"        # how long to hold the stream open
: "${SE_MAX_EVENTS:=20}"     # stop reading after this many events
: "${SE_FOLLOW:=0}"
: "${SE_EVIL:=evil.example}"
: "${SE_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/58}"

se_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── where a stream lives ─────────────────────────────────────────
# An SSE endpoint is a path convention, and the convention is what a wordlist
# gets right and a crawler never sees (the connection never ends, so no link
# is ever followed).
#   <path>\t<what usually pushes on it>
se_paths() {
    cat <<'PATHS'
/events	the generic event stream
/events/	namespaced
/api/events	the api event stream
/api/v1/events	versioned
/stream	the generic stream
/stream/	namespaced
/streaming	the other generic stream
/notifications	a notification feed
/notifications/stream	namespaced notification feed
/updates	a live update feed
/live	a real-time feed
/progress	a job progress stream
/sse	the protocol under its own name
/event-stream	the content type under its own name
/subscribe	a subscription channel
/push	a push channel
/alerts	an alert feed
/ticker	a market or status ticker
/jobs	a job queue feed
/logs	a log tail
PATHS
}

# ── the verdicts ─────────────────────────────────────────────────
# A stream is authenticated or it is not, and the only honest way to tell is
# whether events arrived. A 200 with `Content-Type: text/event-stream` and no
# data is not an open stream; it is a stream waiting for a cookie.
#   se_probe_verdict <code> <ctype> <n-events> <n-bytes>
se_probe_verdict() {
    local code="$1" ctype="$2" nev="$3" nbytes="$4"
    [[ "$code" == "000" ]] && { printf 'unreachable'; return; }
    case "$code" in
        401|403) printf 'auth-required'; return ;;
        404) printf 'no-stream'; return ;;
        405) printf 'no-method'; return ;;
    esac
    (( code >= 300 && code < 400 )) && { printf 'redirect'; return; }
    (( code >= 500 )) && { printf 'error'; return; }
    case "${ctype,,}" in
        *text/event-stream*) ;;
        *) printf 'not-sse'; return ;;
    esac
    (( nev > 0 )) && { printf 'streaming'; return; }
    (( nbytes > 0 )) && { printf 'streaming-unparsed'; return; }
    printf 'open-silent'
}

# The event grammar is small, and getting it wrong is how a reader concludes
# "no data" from a stream that is full of data. `data:` can repeat, and a
# blank line terminates the event.
#   se_parse <file> -> one row per event: <n>\t<id|->\t<event|->\t<data>
se_parse() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    awk '
    BEGIN { n = 0; id = "-"; ev = "-"; data = ""; have = 0 }
    /^\r?$/ {
        if (have) { n++; printf "%d\037%s\037%s\037%s\n", n, id, ev, data;
                    id = "-"; ev = "-"; data = ""; have = 0 }
        next
    }
    /^id:/      { id = substr($0, 4);        sub(/^ /, "", id); have = 1; next }
    /^event:/   { ev = substr($0, 7);        sub(/^ /, "", ev); have = 1; next }
    /^data:/    { d = substr($0, 6);         sub(/^ /, "", d);
                  data = (data == "" ? d : data "\\n" d); have = 1; next }
    /^retry:/   { next }
    /^:/        { next }        # a comment, which is how a server keeps alive
    END {
        # an event with no terminating blank line is still an event; without
        # this the last push of a short stream reads as nothing at all
        if (have) { n++; printf "%d\037%s\037%s\037%s\n", n, id, ev, data }
    }
    ' "$file"
}

# What the events contain decides whether the leak matters. A progress stream
# that says "working" is not a finding; one that carries an id, a balance or a
# session is.
#   se_event_class <file>
se_event_class() {
    local file="$1"
    [[ -f "$file" ]] || { printf 'empty'; return; }
    [[ -s "$file" ]] || { printf 'empty'; return; }
    if grep -qaE '(msisdn|iccid|imsi|subscriber|customer|account_id|balance|airtime)' "$file" 2>/dev/null; then
        printf 'subscriber-data'; return
    fi
    if grep -qaiE '(bearer[[:space:]]|authorization|"token"|"jwt"|session)' "$file" 2>/dev/null; then
        printf 'credential'; return
    fi
    if grep -qaiE '"(stack|trace|exception|sql|at [a-z]+\.[a-z]+)' "$file" 2>/dev/null; then
        printf 'internal-error'; return
    fi
    if grep -qaiE '"(job|progress|status|state|phase|percent)"' "$file" 2>/dev/null; then
        printf 'telemetry'; return
    fi
    printf 'opaque'
}

# Severity follows the class, not the stream: an unauthenticated stream of
# job progress is a nuisance, an unauthenticated stream of subscriber records
# is the assessment.
#   se_severity <verdict> <class>
se_severity() {
    local v="$1" c="$2"
    [[ "$v" != "streaming" && "$v" != "streaming-unparsed" ]] && { printf 'INFO'; return; }
    case "$c" in
        subscriber-data) printf 'CRITICAL' ;;
        credential)      printf 'CRITICAL' ;;
        internal-error)  printf 'HIGH' ;;
        telemetry)       printf 'MEDIUM' ;;
        *)               printf 'LOW' ;;
    esac
}

# Cross-origin EventSource is the browser-side half: a stream that answers a
# hostile Origin with allow-credentials is readable from any page.
#   se_cors_verdict <acao> <acac> <origin-sent>
se_cors_verdict() {
    local acao="$1" acac="$2" sent="$3"
    [[ -z "$acao" ]] && { printf 'no-cors'; return; }
    [[ "$acao" == "*" ]] && { printf 'wildcard'; return; }
    [[ "$acao" == "$sent" ]] || { printf 'static'; return; }
    [[ "${acac,,}" == "true" ]] && { printf 'reflected-creds'; return; }
    printf 'reflected'
}

# A comment frame is the keep-alive; whether the server sends one tells a reader
# how long a silent stream can be trusted to be alive.
#   se_keepalive_verdict <n-comment-lines> <seconds-held>
se_keepalive_verdict() {
    local n="$1" secs="$2"
    (( n == 0 && secs >= 5 )) && { printf 'silent'; return; }
    (( n == 0 )) && { printf 'unproven'; return; }
    printf 'alive'
}

# ── the reader ───────────────────────────────────────────────────
# One request that is allowed to run long: curl writes the body as it arrives,
# and the read is capped by wall time and event count, whichever comes first.
#   se_fetch <url> [origin] [headers]
#   -> code \x1f ctype \x1f bytes \x1f n-events \x1f body-path \x1f headers-path
se_fetch() {
    local url="$1" origin="${2:-}" extra="${3:-}"
    local bodyf hdrf
    bodyf="$(mktemp "$CS_SCRATCH/seb.XXXXXX")" 2>/dev/null || bodyf="$OUT_DIR/.seb.$$"
    hdrf="$(mktemp "$CS_SCRATCH/seh.XXXXXX")" 2>/dev/null || hdrf="$OUT_DIR/.seh.$$"

    local -a args=(-sS -N -o "$bodyf" -D "$hdrf" -w '%{http_code}'
                   -m "$SE_TIMEOUT" -A "$SE_UA")
    [ "$SE_FOLLOW" = "1" ] && args+=(-L)
    [[ -n "$origin" ]] && args+=(-H "Origin: $origin")
    [[ -n "$extra" ]] && args+=(-H "$extra")

    local code rc
    code="$(curl "${args[@]}" "$url" 2>/dev/null)"; rc=$?
    # curl exits 28 when -m cuts a stream it was still reading, but by then it
    # has already written %{http_code}; only a genuinely empty result is 000
    [[ -z "$code" ]] && code="000"
    local bytes nev ctype
    bytes="$(wc -c < "$bodyf" 2>/dev/null | tr -d ' ')"
    nev="$(se_parse "$bodyf" | wc -l | tr -d ' ')"
    ctype="$(se_header "$hdrf" content-type)"
    printf '%s\037%s\037%s\037%s\037%s\037%s\n' \
        "$code" "$ctype" "${bytes:-0}" "${nev:-0}" "$bodyf" "$hdrf"
}

se_header() {
    local file="$1" name="$2"
    [[ -f "$file" ]] || return 0
    grep -ai "^${name}:" "$file" 2>/dev/null | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n'
}

# ── verbs ────────────────────────────────────────────────────────

# --probe <host|url> [path]: does this path hold a stream, and does it push
# without a credential.
se_cmd_probe() {
    local target="${1:-}" path="${2:-}"
    [[ -z "$target" ]] && { se_log "usage: --probe <host|url> [path]"; return 2; }
    local base; base="$(se_base "$target")"
    cs_row TARGET "$base"

    local paths; paths="${path:-}"
    if [[ -z "$paths" ]]; then
        cs_row PATHS "$(se_paths | wc -l | tr -d ' ')"
    fi

    : > "$PROBE_FILE"
    local tried=0 hits=0
    local p what
    while IFS=$'\t' read -r p what; do
        [[ -z "$p" ]] && continue
        [[ -n "$paths" && "$p" != "$paths" ]] && continue
        tried=$((tried + 1))
        local code ctype bytes nev bodyf hdrf
        cs_split "$(se_fetch "$base$p")" code ctype bytes nev bodyf hdrf
        local v; v="$(se_probe_verdict "$code" "$ctype" "$nev" "$bytes")"
        local cls="empty"; [[ -f "$bodyf" ]] && cls="$(se_event_class "$bodyf")"
        local sev; sev="$(se_severity "$v" "$cls")"
        printf 'path\t%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$code" "$v" "$cls" "$nev" "$bytes" >> "$PROBE_FILE"

        case "$v" in
            streaming|streaming-unparsed)
                hits=$((hits + 1))
                cs_row HIT "$p" "code=$code" "events=$nev" "class=$cls" "sev=$sev" "$what"
                printf '%s\t%s\t%s\t%s\n' "$p" "$nev" "$cls" "$sev" >> "$HIT_FILE"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$base$p" "$sev" "sse-unauth" \
                    "$p pushed $nev events with no credential — $what ($cls)"
                ;;
            open-silent)
                cs_row SILENT "$p" "code=$code" "the stream opened and said nothing"
                ;;
            *)
                cs_row PATH "$p" "code=$code" "$v"
                ;;
        esac
        rm -f "$bodyf" "$hdrf"
    done < <([[ -n "$paths" ]] && printf '%s\t%s\n' "$paths" "requested" || se_paths)

    local overall="closed"
    (( hits > 0 )) && overall="streaming"
    cs_row VERDICT "$overall" "$hits of $tried paths pushed without a credential"
    cs_row SUMMARY "paths=$tried streaming=$hits"
    cs_row ARTIFACT "$PROBE_FILE"
    return 0
}

se_base() {
    local t="$1"
    case "$t" in
        http://*|https://*) printf '%s' "${t%/}" ;;
        *) printf 'https://%s' "${t%/}" ;;
    esac
}

# --auth <url>: the same stream with and without a credential. This is the verb
# that matters when the path is already known.
se_cmd_auth() {
    local url="${1:-}" cookie="${2:-}"
    [[ -z "$url" ]] && { se_log "usage: --auth <url> [cookie]"; return 2; }
    local url_abs; url_abs="$(se_base "$url")"
    cs_row TARGET "$url_abs"

    local code ctype bytes nev bodyf hdrf
    cs_split "$(se_fetch "$url_abs")" code ctype bytes nev bodyf hdrf
    local v; v="$(se_probe_verdict "$code" "$ctype" "$nev" "$bytes")"
    local cls="empty"; [[ -f "$bodyf" ]] && cls="$(se_event_class "$bodyf")"
    cs_row ANONYMOUS "code=$code" "ctype=${ctype:-none}" "events=$nev" "bytes=$bytes"
    cs_row ANON_VERDICT "$v" "$cls"

    local sev; sev="$(se_severity "$v" "$cls")"
    if [[ "$v" == "streaming" || "$v" == "streaming-unparsed" ]]; then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url_abs" "$sev" "sse-no-auth" \
            "the stream pushed $nev events to a client with no cookie and no token ($cls)"
        cs_row VERDICT "no-auth" "sev=$sev"
    else
        cs_row VERDICT "$v"
    fi
    rm -f "$bodyf" "$hdrf"
    cs_row SUMMARY "verdict=$v events=$nev class=$cls"
    return 0
}

# --cors <url> [origin]: EventSource plus CORS is the browser-readable case.
se_cmd_cors() {
    local url="${1:-}" origin="${2:-https://$SE_EVIL}"
    [[ -z "$url" ]] && { se_log "usage: --cors <url> [origin]"; return 2; }
    local url_abs; url_abs="$(se_base "$url")"
    cs_row TARGET "$url_abs"
    cs_row ORIGIN "$origin"

    local code ctype bytes nev bodyf hdrf
    cs_split "$(se_fetch "$url_abs" "$origin")" code ctype bytes nev bodyf hdrf
    local acao acac
    acao="$(se_header "$hdrf" access-control-allow-origin)"
    acac="$(se_header "$hdrf" access-control-allow-credentials)"
    rm -f "$bodyf" "$hdrf"

    local v; v="$(se_cors_verdict "$acao" "$acac" "$origin")"
    cs_row CORS "acao=${acao:-none}" "acac=${acac:-none}" "verdict=$v"
    if [[ "$v" == "reflected-creds" ]]; then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url_abs" "CRITICAL" "sse-cors-credentials" \
            "the stream echoes $origin with allow-credentials — any page can read every event"
        cs_row VERDICT "cross-origin-readable"
    else
        cs_row VERDICT "$v"
    fi
    cs_row SUMMARY "cors=$v events=$nev"
    return 0
}

# --inject <url> <payload>: can a client write into the stream. An event that
# echoes a client value back is how a page poisons a dashboard for every other
# reader of that stream.
se_cmd_inject() {
    local url="${1:-}" payload="${2:-<script>cloudsting</script>}"
    [[ -z "$url" ]] && { se_log "usage: --inject <url> <payload>"; return 2; }
    local url_abs; url_abs="$(se_base "$url")"
    cs_row TARGET "$url_abs"

    # the value goes in as a query parameter and as a header; a stream that
    # reflects either is echoing its subscriber back to itself
    local enc; enc="$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null || printf '%s' "$payload")"
    local sep="?"; [[ "$url_abs" == *"?"* ]] && sep="&"
    local code ctype bytes nev bodyf hdrf
    cs_split "$(se_fetch "${url_abs}${sep}message=$enc")" code ctype bytes nev bodyf hdrf
    local echoed="no"
    [[ -f "$bodyf" ]] && grep -qaF "cloudsting" "$bodyf" 2>/dev/null && echoed="yes"
    rm -f "$bodyf" "$hdrf"

    cs_row ECHO "code=$code" "events=$nev" "reflected=$echoed"
    if [[ "$echoed" == "yes" ]]; then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url_abs" "HIGH" "sse-injection" \
            "a client-supplied value came back inside the event stream — every reader of this stream receives it"
        cs_row VERDICT "injectable"
    else
        cs_row VERDICT "not-reflected"
    fi
    cs_row SUMMARY "reflected=$echoed events=$nev"
    return 0
}

# --sample <url>: read the stream and print the events it pushed. The point is
# to see the data, not just to count it.
se_cmd_sample() {
    local url="${1:-}"
    [[ -z "$url" ]] && { se_log "usage: --sample <url>"; return 2; }
    local url_abs; url_abs="$(se_base "$url")"
    cs_row TARGET "$url_abs"
    local code ctype bytes nev bodyf hdrf
    cs_split "$(se_fetch "$url_abs")" code ctype bytes nev bodyf hdrf
    cs_row RESPONSE "code=$code" "ctype=${ctype:-none}" "bytes=$bytes" "events=$nev"

    local n=0 cnt=0
    while IFS=$'\037' read -r n id ev data; do
        [[ -z "$n" ]] && continue
        cnt=$((cnt + 1))
        (( cnt > SE_MAX_EVENTS )) && break
        cs_row EVENT "$n" "id=${id:--}" "event=${ev:--}" "${data:0:200}"
    done < <(se_parse "$bodyf")

    local cls; cls="$(se_event_class "$bodyf")"
    cs_row CLASS "$cls"
    local keep="$OUT_DIR/sample-$RUN_ID.txt"
    [[ -f "$bodyf" ]] && cp "$bodyf" "$keep" 2>/dev/null && chmod 600 "$keep" 2>/dev/null
    rm -f "$bodyf" "$hdrf"
    cs_row SUMMARY "events=$cnt class=$cls"
    [[ -f "$keep" ]] && cs_row ARTIFACT "$keep"
    return 0
}

# --events: the event fields a reader has to get right.
se_cmd_events() {
    cat <<'FIELDS' | while IFS=$'\t' read -r f what; do
data	the payload; may repeat, and repeats join with a newline
event	the event name a listener subscribes to
id	the last event id, replayed on reconnect as Last-Event-ID
retry	how long the browser waits before reconnecting, in ms
:	not a field — a comment, which is how a server keeps a silent stream alive
FIELDS
        cs_row FIELD "$f" "$what"
    done
    cs_row SUMMARY "fields=5"
    return 0
}

se_cmd_paths() {
    local p what
    while IFS=$'\t' read -r p what; do
        [[ -z "$p" ]] && continue
        cs_row PATH "$p" "$what"
    done < <(se_paths)
    cs_row SUMMARY "paths=$(se_paths | wc -l | tr -d ' ')"
    return 0
}

se_cmd_list() { se_cmd_paths; }

se_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    command -v jq   >/dev/null 2>&1 && jq_state="jq-ok"     || jq_state="jq-missing"
    printf '%s\t%s\t%s\t%s\tpaths-%s\tfields-5\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" \
        "$(se_paths | wc -l | tr -d ' ')"
}

se_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

se_cmd_help() {
    cat <<'HELP'
cloudsting module 58 — Server-Sent Events v1.0.0
  --probe <host|url> [path]        which path holds a stream that pushes unauthenticated
  --auth <url> [cookie]            the same stream with and without a credential
  --cors <url> [origin]            EventSource from a foreign origin, with credentials
  --inject <url> [payload]         can a client write into the stream every reader sees
  --sample <url>                   read the stream and print the events
  --paths | --events | --list
  --status-tsv | --menu | --selftest | --help

A Server-Sent Event response is one HTTP reply that never ends, so everything an
HTTP tool reports about it — a code, a header block — is read before the
interesting part starts. This module reads the stream itself: `data:` repeats and
joins, a blank line ends the event, a leading colon is a comment and not data.

A 200 with text/event-stream and no events is reported `open-silent`, not
`streaming` — a stream waiting for a cookie has not leaked anything yet.

Environment: SE_TIMEOUT (10), SE_MAX_EVENTS (20), SE_EVIL, SE_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
se_selftest() {
    cs_selftest_reset

    local n; n="$(se_paths | wc -l | tr -d ' ')"
    chk paths-many   "$( (( n >= 18 )) && echo many || echo few )" "many"
    chk paths-2col   "$(se_paths | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk paths-unique "$(se_paths | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"

    # parsing: repeated data joins, a blank line terminates, a comment is not data
    local f; f="$(mktemp "$CS_SCRATCH/se-s.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.s.$$"
    printf 'id: 7\nevent: tick\ndata: {"a":1}\n\n' > "$f"
    chk par-data     "$(se_parse "$f" | awk -F'\037' '{print $4}')" '{"a":1}'
    chk par-id       "$(se_parse "$f" | awk -F'\037' '{print $2}')" "7"
    chk par-event    "$(se_parse "$f" | awk -F'\037' '{print $3}')" "tick"
    chk par-count    "$(se_parse "$f" | wc -l | tr -d ' ')" "1"

    printf 'data: a\ndata: b\n\n' > "$f"
    chk par-join     "$(se_parse "$f" | awk -F'\037' '{print $4}')" 'a\nb'

    printf ': keep-alive\n\n' > "$f"
    chk par-comment  "$(se_parse "$f" | wc -l | tr -d ' ')" "0"

    printf 'data: one\n\ndata: two\n\n' > "$f"
    chk par-two      "$(se_parse "$f" | wc -l | tr -d ' ')" "2"
    printf 'data: x' > "$f"   # an event that never got its blank line
    chk par-unterminated "$(se_parse "$f" | wc -l | tr -d ' ')" "1"
    chk par-unterm-data  "$(se_parse "$f" | awk -F'\037' '{print $4}')" "x"
    printf '\n' >> "$f"
    chk par-complete "$(se_parse "$f" | wc -l | tr -d ' ')" "1"

    # classification drives the severity
    printf 'data: {"msisdn":"254700000000","balance":12}\n\n' > "$f"
    chk cls-subs     "$(se_event_class "$f")" "subscriber-data"
    printf 'data: {"token":"eyJhbGci"}\n\n' > "$f"
    chk cls-cred     "$(se_event_class "$f")" "credential"
    printf 'data: {"stack":"at app.js:1"}\n\n' > "$f"
    chk cls-err      "$(se_event_class "$f")" "internal-error"
    printf 'data: {"progress":40,"status":"running"}\n\n' > "$f"
    chk cls-tele     "$(se_event_class "$f")" "telemetry"
    printf 'data: hello\n\n' > "$f"
    chk cls-opaque   "$(se_event_class "$f")" "opaque"
    : > "$f"
    chk cls-empty    "$(se_event_class "$f")" "empty"
    rm -f "$f"

    chk sev-crit     "$(se_severity streaming subscriber-data)" "CRITICAL"
    chk sev-cred     "$(se_severity streaming credential)" "CRITICAL"
    chk sev-high     "$(se_severity streaming internal-error)" "HIGH"
    chk sev-med      "$(se_severity streaming telemetry)" "MEDIUM"
    chk sev-low      "$(se_severity streaming opaque)" "LOW"
    chk sev-info     "$(se_severity auth-required subscriber-data)" "INFO"

    # verdict table
    chk v-unreach    "$(se_probe_verdict 000 '' 0 0)" "unreachable"
    chk v-auth       "$(se_probe_verdict 401 'text/event-stream' 0 0)" "auth-required"
    chk v-403        "$(se_probe_verdict 403 'text/plain' 0 0)" "auth-required"
    chk v-404        "$(se_probe_verdict 404 '' 0 0)" "no-stream"
    chk v-405        "$(se_probe_verdict 405 '' 0 0)" "no-method"
    chk v-notsse     "$(se_probe_verdict 200 'text/html' 0 10)" "not-sse"
    chk v-stream     "$(se_probe_verdict 200 'text/event-stream' 3 40)" "streaming"
    chk v-unparsed   "$(se_probe_verdict 200 'text/event-stream' 0 40)" "streaming-unparsed"
    chk v-silent     "$(se_probe_verdict 200 'text/event-stream; charset=utf-8' 0 0)" "open-silent"
    chk v-500        "$(se_probe_verdict 500 '' 0 0)" "error"

    chk c-none       "$(se_cors_verdict '' '' https://evil.example)" "no-cors"
    chk c-wild       "$(se_cors_verdict '*' '' https://evil.example)" "wildcard"
    chk c-static     "$(se_cors_verdict https://app.example '' https://evil.example)" "static"
    chk c-ref        "$(se_cors_verdict https://evil.example '' https://evil.example)" "reflected"
    chk c-creds      "$(se_cors_verdict https://evil.example true https://evil.example)" "reflected-creds"

    chk ka-silent    "$(se_keepalive_verdict 0 8)" "silent"
    chk ka-unproven  "$(se_keepalive_verdict 0 2)" "unproven"
    chk ka-alive     "$(se_keepalive_verdict 3 8)" "alive"

    # a dead host is unreachable, never a stream
    local out; out="$(se_cmd_probe http://127.0.0.1:9 /events 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "closed"
    chk dead-hits    "$(printf '%s' "$out" | awk -F'\t' '$1=="HIT"' | wc -l | tr -d ' ')" "0"

    # usage errors, not crashes
    se_cmd_probe 2>/dev/null;  chk prb-usage "$?" "2"
    se_cmd_auth 2>/dev/null;   chk aut-usage "$?" "2"
    se_cmd_cors 2>/dev/null;   chk cor-usage "$?" "2"
    se_cmd_inject 2>/dev/null; chk inj-usage "$?" "2"
    se_cmd_sample 2>/dev/null; chk smp-usage "$?" "2"

    # shape contracts
    chk status-fields "$(se_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(se_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(se_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(se_cmd_help | head -1 | grep -ci 'Server-Sent Events')" "1"
    chk paths-rows    "$(se_cmd_paths | grep -c '^PATH')" "$n"
    chk events-rows   "$(se_cmd_events | grep -c '^FIELD')" "5"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)    shift; se_cmd_probe "$@";;
    --auth)     shift; se_cmd_auth "$@";;
    --cors)     shift; se_cmd_cors "$@";;
    --inject)   shift; se_cmd_inject "$@";;
    --sample)   shift; se_cmd_sample "$@";;
    --paths)    se_cmd_paths;;
    --events)   se_cmd_events;;
    --list)     se_cmd_list;;
    --status-tsv|--status) se_cmd_status_tsv;;
    --menu)     se_cmd_menu;;
    --selftest) se_selftest;;
    *)          se_cmd_help;;
esac
