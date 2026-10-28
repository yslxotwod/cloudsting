#!/usr/bin/env bash
# 69_bfuzz.sh — cloudsting module 69: the schema says one type, the decoder trusts another
# Verbs: --detect | --probe | --fuzz | --varint | --packed | --any | --truncate
#        | --techniques | --mutations | --list | --status-tsv | --menu
#        | --selftest | --help
#
# 56_grpc finds the service and asks whether it wants auth. This module takes a
# schema it already has and asks a different question: when a field carries a
# value the schema forbids, does the decoder refuse it or does the handler
# believe it. A protobuf decoder is deliberately permissive — unknown fields are
# skipped, enum values outside the range are kept as ints, a length prefix is
# just a number — so everything below is a disagreement between the wire and
# the type, not a memory bug.
set -u
umask 077

# A parent that sourced the core exports CS_MOD_DIR; this module derives its own.
unset CS_MOD_DIR

MODULE_ID="69_bfuzz"
MOD_NAME="Binary / Protobuf Fuzzing (the value the schema forbids)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/bfuzz"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${BF_TIMEOUT:=10}"
: "${BF_FOLLOW:=0}"
: "${BF_PATH:=/}"
: "${BF_METHOD:=POST}"
: "${BF_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/69}"

bf_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── wire types ───────────────────────────────────────────────────
#   <n>\t<name>\t<what a decoder does with it>
bf_wire_types() {
    cat <<'WIRE'
0	varint	any 64-bit integer, sign-extended to ten bytes when negative
1	i64	exactly eight bytes, little endian
2	len	one varint length then that many bytes
5	i32	exactly four bytes, little endian
3	sgroup	deprecated group start — most decoders skip to the matching end
4	egroup	deprecated group end
6	invalid	no such wire type: a strict decoder errors, a lenient one guesses
7	invalid	no such wire type
WIRE
}

# ── the mutations ────────────────────────────────────────────────
# Each row asks one question of the decoder. The "what a hit means" column is
# the finding, phrased as the behaviour observed rather than the bug inferred.
#   <id>\t<class>\t<what it sends>\t<what acceptance means>
bf_mutations() {
    cat <<'MUTATIONS'
zero-length	truncation	a length-delimited field with no bytes	an empty message is a valid message with defaults
truncated-varint	varint	a varint whose high bit is set and then the buffer ends	a decoder reading past its buffer does not notice
huge-varint	varint	the maximum uint64 as a length prefix	a length the buffer cannot hold was accepted
neg-int32	varint	-1 encoded as ten bytes into a 32-bit field	a negative where a count belongs
int32-max	varint	2147483647 into the same field	arithmetic past the check
int32-max-plus	varint	2147483648, which does not fit a signed 32	a value the type cannot hold still lands
enum-out-of-range	enum	a field number that is an enum fed 99	a branch the schema never defined
enum-negative	enum	the same enum fed -1	a switch that falls through to default
packed-unpacked	packing	a repeated field sent unpacked where the schema says packed	a decoder that only handles one form
unpacked-packed	packing	the reverse: packed where unpacked	a length prefix read as an element
any-mismatch	any	google.protobuf.Any with a type_url the server never packs	a dynamic type resolution the caller chooses
any-empty-type	any	Any with an empty type_url	an empty string resolving to something
wire6	wire-type	field 1 with wire type 6	an invalid wire type accepted
group-unterminated	group	a start-group with no end-group	a parser waiting for a byte the caller controls
unknown-field	unknown	field 19000 with a value	unknown fields preserved and reflected back
duplicate-field	duplicate	the same field number twice with different values	last-wins vs first-wins disagreement between layers
MUTATIONS
}

# ── encoding primitives ──────────────────────────────────────────
# A protobuf message is bytes. Bytes that contain NUL cannot survive a bash
# command substitution, so every builder below writes STRAIGHT TO A FILE and
# the caller never sees the message as a string. This is the same rule 56_grpc
# learned the hard way.
#
#   bf_varint <file> <value>     append an unsigned varint
bf_varint() {
    local f="$1" v="${2:-0}"
    local -a out=()
    local b
    python3 - "$v" <<'PY'
import sys
v = int(sys.argv[1]) & 0xFFFFFFFFFFFFFFFF
out = bytearray()
while True:
    b = v & 0x7F
    v >>= 7
    if v:
        out.append(b | 0x80)
    else:
        out.append(b)
        break
sys.stdout.buffer.write(bytes(out))
PY
}

#   bf_tag <field> <wire>       -> the tag varint as raw bytes
bf_tag() { bf_varint - "$(( (${1:-1} << 3) | ${2:-2} ))"; }

#   bf_ld <file> <field> <len>  append tag(2) + length prefix
bf_ld() {
    local f="$1" field="${2:-1}" len="${3:-0}"
    { bf_tag "$field" 2; bf_varint - "$len"; } >> "$f"
}

#   bf_str <field> <text>       append a length-delimited string field
bf_str() {
    local field="${1:-1}" text="${2:-}"
    bf_ld - "$field" "${#text}"
    printf '%s' "$text"
}

#   bf_hex <file> <hex>         append raw bytes described as hex
bf_hex() {
    local f="$1" hex="$2"
    printf '%s' "$hex" | tr -d ' \n' | while read -r -n2 pair; do
        [[ -z "$pair" ]] && continue
        printf "\\x$pair"
    done >> "$f"
}

# ── building a message for one mutation ──────────────────────────
#   bf_build <mutation-id> <out-file>
# Every message targets field 1 unless the mutation is about field identity, so
# the tests differ in exactly one thing and a difference in the response can be
# attributed.
bf_build() {
    local id="$1" out="$2"
    : > "$out"
    case "$id" in
        zero-length)
            { bf_tag 1 2; bf_varint - 0; } >> "$out"
            ;;
        truncated-varint)
            { bf_tag 1 0; printf '\x80\x80\x80'; } >> "$out"
            ;;
        huge-varint)
            { bf_tag 1 2; printf '\xff\xff\xff\xff\x0f'; } >> "$out"
            ;;
        neg-int32)
            { bf_tag 1 0; printf '\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01'; } >> "$out"
            ;;
        int32-max)
            { bf_tag 1 0; bf_varint - 2147483647; } >> "$out"
            ;;
        int32-max-plus)
            { bf_tag 1 0; bf_varint - 2147483648; } >> "$out"
            ;;
        enum-out-of-range)
            { bf_tag 1 0; bf_varint - 99; } >> "$out"
            ;;
        enum-negative)
            { bf_tag 1 0; printf '\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01'; } >> "$out"
            ;;
        packed-unpacked)
            # repeated int32 declared packed, sent as three separate tags
            { for i in 1 2 3; do bf_tag 1 0; bf_varint - "$i"; done; } >> "$out"
            ;;
        unpacked-packed)
            # the same field sent as one length-delimited blob of varints
            { bf_tag 1 2; bf_varint - 3; bf_varint - 1; bf_varint - 2; bf_varint - 3; } >> "$out"
            ;;
        any-mismatch)
            { bf_str 1 "type.googleapis.com/cloudsting.NeverPacked" ; bf_str 2 "AAAA"; } >> "$out"
            ;;
        any-empty-type)
            { bf_str 1 ""; bf_str 2 "AAAA"; } >> "$out"
            ;;
        wire6)
            { bf_tag 1 6; printf '\x00'; } >> "$out"
            ;;
        group-unterminated)
            { bf_tag 1 3; printf '\x08\x01'; } >> "$out"
            ;;
        unknown-field)
            { bf_tag 19000 0; bf_varint - 7; } >> "$out"
            ;;
        duplicate-field)
            { bf_tag 1 0; bf_varint - 1; bf_tag 1 0; bf_varint - 2; } >> "$out"
            ;;
        *)
            { bf_tag 1 2; bf_varint - 0; } >> "$out"
            ;;
    esac
}

#   bf_frame <file>   five-byte gRPC frame prefix: compressed flag then the
#                     four-byte big-endian length of the message that follows
bf_frame() {
    local f="$1" len
    len="$(wc -c < "$f" | tr -d ' ')"
    printf '\x00'
    printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
        $(( (len >> 24) & 255 )) $(( (len >> 16) & 255 )) \
        $(( (len >> 8) & 255 )) $(( len & 255 )))"
    cat "$f"
}

# ── send and read the answer ─────────────────────────────────────
#   bf_send <url> <body-file> [content-type] [extra-header]
#   -> code \x1f bytes \x1f secs \x1f hash \x1f body-path
# curl never expands \t or \036 in a --write-out format: it emits the literal
# text, so the split below is on a SPACE and the fields are re-joined by awk.
bf_send() {
    local url="$1" body="$2" ctype="${3:-application/grpc}" hdr="${4:-}"
    local outf; outf="$(mktemp "$CS_SCRATCH/bf.XXXXXX")" 2>/dev/null || outf="$OUT_DIR/.bf.$$"
    local -a args=(-sS -o "$outf" -w '%{http_code} %{time_total}' -m "$BF_TIMEOUT"
                   -A "$BF_UA" -X "$BF_METHOD" -H "content-type: $ctype")
    args+=(--data-binary "@$body")
    [ -n "$hdr" ] && args+=(-H "$hdr")
    [ "$BF_FOLLOW" = "1" ] && args+=(-L)

    local meta code secs
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)"
    read -r code secs <<<"${meta:-000 0}"
    [[ -z "$code" ]] && code="000"
    local bytes hash
    bytes="$(wc -c < "$outf" 2>/dev/null | tr -d ' ')"
    hash="$(sha1sum "$outf" 2>/dev/null | cut -c1-12)"
    [[ -z "$hash" ]] && hash="$(cs_fingerprint "$(cat "$outf" 2>/dev/null)")"
    printf '%s\037%s\037%s\037%s\037%s\n' "$code" "${bytes:-0}" "$secs" "$hash" "$outf"
}

# gRPC puts its real status in the trailing frame and the grpc-status trailer.
#   bf_status <body-file>
bf_status() {
    local f="$1"
    [[ -s "$f" ]] || { printf ''; return; }
    local hex
    hex="$(od -An -v -tx1 "$f" 2>/dev/null | tr -d ' \n')"
    # a grpc-status-0 frame is 0x00 + length + message; a body that is pure
    # JSON or pure text was never a gRPC answer
    case "$hex" in
        00*) printf 'framed' ;;
        *)   printf 'unframed' ;;
    esac
}

#   bf_error_class <body-file>
# A decoder that refuses says so. A handler that refuses a VALUE also says so,
# but differently — and a handler that accepted the value says nothing and
# answers normally. Telling those three apart is the whole module.
bf_error_class() {
    local f="$1"
    [[ -s "$f" ]] || { printf 'empty'; return; }
    if grep -qa -m1 -iE 'invalid wire type|wiretype|proto: |cannot parse|unmarshal|unexpected EOF|illegal tag|parse error|invalid length|exceeds' "$f" 2>/dev/null; then
        printf 'decoder-refused'; return
    fi
    if grep -qa -m1 -iE 'invalid argument|out of range|out-of-range|invalid enum|unknown enum|bad request|validation' "$f" 2>/dev/null; then
        printf 'handler-refused'; return
    fi
    if grep -qa -m1 -iE 'panic|stack trace|goroutine|Exception|NullPointer|Traceback|internal server error' "$f" 2>/dev/null; then
        printf 'crashed'; return
    fi
    printf 'accepted'
}

#   bf_verdict <ctl-code> <ctl-class> <probe-code> <probe-class> <mutation-class>
# The verdict is a DELTA against a control message of the same shape. Without
# the control, a server that answers 400 to everything reads as ten findings.
bf_verdict() {
    local cc="$1" cclass="$2" pc="$3" pclass="$4" mclass="${5:-}"
    [[ "$cc" == "000" ]] && { printf 'unreachable'; return; }
    [[ "$pc" == "000" ]] && { printf 'unreachable'; return; }

    # the control itself was refused: the endpoint does not take this shape at
    # all, so every difference below would be measuring the refusal
    case "$cclass" in
        decoder-refused|handler-refused|crashed)
            printf 'control-refused'; return ;;
    esac

    # the BODY is read first, because it says WHO decided, and the code only
    # says that someone did. A 500 whose body names a parser is a decoder crash;
    # a 400 whose body says "invalid argument" is the handler validating; a 4xx
    # with nothing readable is still a refusal, and a 5xx with nothing readable
    # is the server breaking on our bytes
    case "$pclass" in
        crashed)          printf 'decoder-crash'; return ;;
        decoder-refused)  printf 'rejected'; return ;;
        handler-refused)  printf 'validated'; return ;;
        empty)
            [[ "$pc" =~ ^5 ]] && { printf 'server-error'; return; }
            [[ "$pc" =~ ^4 ]] && { printf 'rejected'; return; }
            # an empty answer where the control had one is a silent refusal,
            # which for a length prefix means a read past the buffer
            case "$mclass" in
                truncation|varint) printf 'silent-truncation'; return ;;
                *)                 printf 'empty-response'; return ;;
            esac ;;
    esac

    [[ "$pc" =~ ^5 ]] && { printf 'server-error'; return; }
    [[ "$pc" =~ ^4 ]] && { printf 'rejected'; return; }

    # accepted, and the control was accepted too: was the answer the same
    printf 'accepted'
}

# A silent truncation is the interesting one. A truncation that changes the
# answer is a real disagreement between the wire and the type; one that returns
# byte-identical output means the decoder never looked.
#   bf_severity <verdict> <mutation-class> <same-as-control?>
bf_severity() {
    local v="$1" class="$2" same="${3:-no}"
    case "$v" in
        decoder-crash)      printf 'CRITICAL' ;;
        silent-truncation)  [[ "$same" == "yes" ]] && printf 'MEDIUM' || printf 'HIGH' ;;
        accepted)
            case "$class" in
                enum|any|wire-type|group|packing) printf 'HIGH' ;;
                varint|truncation)                printf 'MEDIUM' ;;
                *)                                printf 'LOW' ;;
            esac ;;
        server-error)       printf 'HIGH' ;;
        validated)          printf 'INFO' ;;
        *)                  printf 'INFO' ;;
    esac
}

bf_findings() { cs_findings_row "$MODULE_ID" "WEBAPI" "$1" "$2" "$3"; }

# ── verbs ────────────────────────────────────────────────────────

# --detect <url>: is this endpoint even parsing a binary body
bf_cmd_detect() {
    local url="${1:-}"
    [[ -z "$url" ]] && { bf_log "usage: --detect <url>"; return 2; }
    cs_row TARGET "$url"

    local probe; probe="$(mktemp "$CS_SCRATCH/bfd.XXXXXX")"
    printf 'cloudsting-bfuzz' > "$probe"
    local c1 b1 s1 h1 f1
    cs_split "$(bf_send "$url" "$probe" "application/octet-stream")" c1 b1 s1 h1 f1
    cs_row BINARY "code=$c1" "bytes=$b1"
    local cls1; cls1="$(bf_error_class "$f1")"
    cs_row BINARY-CLASS "$cls1"
    rm -f "$f1"

    bf_build zero-length "$probe"
    local c2 b2 s2 h2 f2
    cs_split "$(bf_send "$url" "$probe")" c2 b2 s2 h2 f2
    cs_row PROTO "code=$c2" "bytes=$b2" "framed=$(bf_status "$f2")"
    local cls2; cls2="$(bf_error_class "$f2")"
    cs_row PROTO-CLASS "$cls2"
    rm -f "$f2" "$probe"

    local v="not-binary"
    if [[ "$c2" =~ ^2 ]]; then v="proto-accepted"
    elif [[ "$c2" == "415" || "$c2" == "404" ]]; then v="no-binary-endpoint"
    elif [[ "$cls2" == "decoder-refused" ]]; then v="proto-parsed-refused"
    elif [[ "$c1" == "000" ]]; then v="unreachable"
    fi
    cs_row VERDICT "$v"
    cs_row SUMMARY "code=$c2 verdict=$v"
    return 0
}

# --probe <url>: the control and one truncation, to see which side of the
# decoder the endpoint lives. Small enough to run against anything.
bf_cmd_probe() {
    local url="${1:-}"
    [[ -z "$url" ]] && { bf_log "usage: --probe <url>"; return 2; }
    cs_row TARGET "$url"

    local ctl; ctl="$(mktemp "$CS_SCRATCH/bfc.XXXXXX")"
    bf_build zero-length "$ctl"
    local cc cb cs ch cf
    cs_split "$(bf_send "$url" "$ctl")" cc cb cs ch cf
    local cclass; cclass="$(bf_error_class "$cf")"
    cs_row CONTROL "code=$cc" "class=$cclass" "framed=$(bf_status "$cf")"
    rm -f "$cf"

    local p; p="$(mktemp "$CS_SCRATCH/bfp.XXXXXX")"
    bf_build truncated-varint "$p"
    local pc pb ps ph pf
    cs_split "$(bf_send "$url" "$p")" pc pb ps ph pf
    local pclass; pclass="$(bf_error_class "$pf")"
    cs_row PROBE "code=$pc" "class=$pclass" "bytes=$pb"
    rm -f "$pf" "$p" "$ctl"

    local v; v="$(bf_verdict "$cc" "$cclass" "$pc" "$pclass" truncation)"
    cs_row VERDICT "$v"
    if [[ "$v" == "accepted" || "$v" == "silent-truncation" || "$v" == "decoder-crash" ]]; then
        local sev; sev="$(bf_severity "$v" truncation no)"
        cs_row FINDING "$sev" "bfuzz-truncation"
        bf_findings "$url" "$sev" "protobuf-truncation" \
            "a varint cut mid-buffer was answered rather than refused — the decoder read past what it was given"
    fi
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --fuzz <url> [class]: every mutation, each against the same control.
bf_cmd_fuzz() {
    local url="${1:-}" only="${2:-}"
    [[ -z "$url" ]] && { bf_log "usage: --fuzz <url> [class]"; return 2; }
    cs_row TARGET "$url"
    cs_row CLASS "${only:-all}"
    : > "$PROBE_FILE"

    local ctl; ctl="$(mktemp "$CS_SCRATCH/bfc.XXXXXX")"
    bf_build zero-length "$ctl"
    local cc cb cs ch cf
    cs_split "$(bf_send "$url" "$ctl")" cc cb cs ch cf
    local cclass; cclass="$(bf_error_class "$cf")"
    local chash; chash="$(sha1sum "$cf" 2>/dev/null | cut -c1-12)"
    cs_row CONTROL "code=$cc" "class=$cclass" "bytes=$cb"
    rm -f "$cf"

    if [[ "$cc" == "000" ]]; then
        cs_row VERDICT "unreachable"
        cs_row SUMMARY "code=000"
        rm -f "$ctl"; return 0
    fi
    case "$cclass" in
        decoder-refused|handler-refused|crashed)
            cs_row VERDICT "control-refused" "the endpoint refused an empty well-formed message"
            cs_row SUMMARY "control=$cc"
            rm -f "$ctl"; return 0 ;;
    esac

    local hits=0 tried=0
    local id class what
    while IFS=$'\t' read -r id class what; do
        [[ -z "$id" ]] && continue
        [[ -n "$only" && "$only" != "all" && "$class" != "$only" ]] && continue
        tried=$((tried + 1))

        local p; p="$(mktemp "$CS_SCRATCH/bfm.XXXXXX")"
        bf_build "$id" "$p"
        local pc pb ps ph pf
        cs_split "$(bf_send "$url" "$p")" pc pb ps ph pf
        local pclass; pclass="$(bf_error_class "$pf")"
        local phash; phash="$(sha1sum "$pf" 2>/dev/null | cut -c1-12)"
        rm -f "$pf" "$p"

        local same="no"
        [[ -n "$chash" && "$phash" == "$chash" ]] && same="yes"

        local v; v="$(bf_verdict "$cc" "$cclass" "$pc" "$pclass" "$class")"
        printf 'mutation\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$pc" "$v" "$class" "$pclass" "$same" >> "$PROBE_FILE"

        case "$v" in
            decoder-crash|silent-truncation|accepted)
                # `accepted` only counts when the control did NOT also accept
                # the same bytes; the control is a valid message, so acceptance
                # of an INVALID one is the disagreement
                local sev; sev="$(bf_severity "$v" "$class" "$same")"
                hits=$((hits + 1))
                cs_row HIT "$id" "code=$pc" "verdict=$v" "class=$class" "sev=$sev" "$what"
                printf '%s\t%s\t%s\n' "$id" "$v" "$sev" >> "$HIT_FILE"
                bf_findings "$url" "$sev" "bfuzz-$id" "$what"
                ;;
            *)
                cs_row CASE "$id" "$pc" "$v" "$class"
                ;;
        esac
    done < <(bf_mutations)

    local overall="rejects"; (( hits > 0 )) && overall="accepts-forbidden-values"
    cs_row VERDICT "$overall" "$hits of $tried mutations changed the answer"
    cs_row SUMMARY "mutations=$tried hits=$hits"
    cs_row ARTIFACT "$PROBE_FILE"
    rm -f "$ctl"
    return 0
}

# --varint <url>: the integer family only. A count field that takes -1 is a
# different bug from a decoder that takes a bad wire type.
bf_cmd_varint() {
    local url="${1:-}"
    [[ -z "$url" ]] && { bf_log "usage: --varint <url>"; return 2; }
    cs_row TARGET "$url"

    local ctl; ctl="$(mktemp "$CS_SCRATCH/bfv.XXXXXX")"
    bf_build zero-length "$ctl"
    local cc cb cs ch cf
    cs_split "$(bf_send "$url" "$ctl")" cc cb cs ch cf
    local cclass; cclass="$(bf_error_class "$cf")"
    cs_row CONTROL "code=$cc" "class=$cclass"
    rm -f "$cf"

    local hits=0
    local id
    for id in int32-max int32-max-plus neg-int32 huge-varint; do
        local p; p="$(mktemp "$CS_SCRATCH/bfw.XXXXXX")"
        bf_build "$id" "$p"
        local pc pb ps ph pf
        cs_split "$(bf_send "$url" "$p")" pc pb ps ph pf
        local pclass; pclass="$(bf_error_class "$pf")"
        rm -f "$pf" "$p"
        local v; v="$(bf_verdict "$cc" "$cclass" "$pc" "$pclass" varint)"
        if [[ "$v" == "accepted" || "$v" == "decoder-crash" ]]; then
            hits=$((hits + 1))
            cs_row ACCEPTED "$id" "code=$pc" "$v"
        else
            cs_row REFUSED "$id" "code=$pc" "$v"
        fi
    done
    cs_row VERDICT "$( (( hits > 0 )) && echo integer-unchecked || echo integer-checked )" "$hits of 4"
    cs_row SUMMARY "hits=$hits"
    rm -f "$ctl"
    return 0
}

# --packed <url>: a repeated field in the wrong packing is the classic
# "one side sets packed=true and the other does not" deployment bug.
bf_cmd_packed() {
    local url="${1:-}"
    [[ -z "$url" ]] && { bf_log "usage: --packed <url>"; return 2; }
    cs_row TARGET "$url"
    local ctl; ctl="$(mktemp "$CS_SCRATCH/bfk.XXXXXX")"
    bf_build zero-length "$ctl"
    local cc cb cs ch cf
    cs_split "$(bf_send "$url" "$ctl")" cc cb cs ch cf
    local cclass; cclass="$(bf_error_class "$cf")"
    cs_row CONTROL "code=$cc" "class=$cclass"
    rm -f "$cf"

    local id hits=0
    for id in packed-unpacked unpacked-packed; do
        local p; p="$(mktemp "$CS_SCRATCH/bfp.XXXXXX")"
        bf_build "$id" "$p"
        local pc pb ps ph pf
        cs_split "$(bf_send "$url" "$p")" pc pb ps ph pf
        local pclass; pclass="$(bf_error_class "$pf")"
        rm -f "$pf" "$p"
        local v; v="$(bf_verdict "$cc" "$cclass" "$pc" "$pclass" packing)"
        [[ "$v" == "accepted" ]] && hits=$((hits + 1))
        cs_row CASE "$id" "code=$pc" "$v"
    done
    cs_row VERDICT "$( (( hits > 0 )) && echo packing-ambiguous || echo packing-strict )" "$hits of 2"
    cs_row SUMMARY "hits=$hits"
    rm -f "$ctl"
    return 0
}

# --any <url>: google.protobuf.Any lets the CALLER name the type. If the server
# resolves the name dynamically, the caller chooses which handler runs.
bf_cmd_any() {
    local url="${1:-}"
    [[ -z "$url" ]] && { bf_log "usage: --any <url>"; return 2; }
    cs_row TARGET "$url"
    local ctl; ctl="$(mktemp "$CS_SCRATCH/bfa.XXXXXX")"
    bf_build zero-length "$ctl"
    local cc cb cs ch cf
    cs_split "$(bf_send "$url" "$ctl")" cc cb cs ch cf
    local cclass; cclass="$(bf_error_class "$cf")"
    cs_row CONTROL "code=$cc" "class=$cclass"
    rm -f "$cf"

    local id hits=0
    for id in any-mismatch any-empty-type; do
        local p; p="$(mktemp "$CS_SCRATCH/bfy.XXXXXX")"
        bf_build "$id" "$p"
        local pc pb ps ph pf
        cs_split "$(bf_send "$url" "$p")" pc pb ps ph pf
        local pclass; pclass="$(bf_error_class "$pf")"
        rm -f "$pf" "$p"
        local v; v="$(bf_verdict "$cc" "$cclass" "$pc" "$pclass" any)"
        [[ "$v" == "accepted" || "$v" == "decoder-crash" ]] && hits=$((hits + 1))
        cs_row CASE "$id" "code=$pc" "$v"
        if [[ "$v" == "accepted" ]]; then
            cs_row FINDING "HIGH" "bfuzz-$id"
            bf_findings "$url" "HIGH" "bfuzz-$id" \
                "an Any carrying a type_url the server never packs was resolved instead of refused"
        fi
    done
    cs_row VERDICT "$( (( hits > 0 )) && echo type-resolution-open || echo types-pinned )" "$hits of 2"
    cs_row SUMMARY "hits=$hits"
    rm -f "$ctl"
    return 0
}

# --truncate <url>: every truncation point of a well-formed message. A decoder
# is supposed to stop at the buffer; this finds out whether it does.
bf_cmd_truncate() {
    local url="${1:-}" limit="${2:-8}"
    [[ -z "$url" ]] && { bf_log "usage: --truncate <url> [max-bytes]"; return 2; }
    cs_row TARGET "$url"

    local full; full="$(mktemp "$CS_SCRATCH/bft.XXXXXX")"
    { bf_str 1 "cloudsting"; bf_tag 2 0; bf_varint - 42; } > "$full"
    local total; total="$(wc -c < "$full" | tr -d ' ')"
    cs_row MESSAGE "bytes=$total"

    local ctl; ctl="$(mktemp "$CS_SCRATCH/bfc.XXXXXX")"
    cp "$full" "$ctl"
    local cc cb cs ch cf
    cs_split "$(bf_send "$url" "$ctl")" cc cb cs ch cf
    local cclass; cclass="$(bf_error_class "$cf")"
    cs_row CONTROL "code=$cc" "class=$cclass"
    rm -f "$cf"

    local n=1 accepted=0
    while (( n < total && n <= limit )); do
        local t; t="$(mktemp "$CS_SCRATCH/bfx.XXXXXX")"
        head -c "$n" "$full" > "$t"
        local pc pb ps ph pf
        cs_split "$(bf_send "$url" "$t")" pc pb ps ph pf
        local pclass; pclass="$(bf_error_class "$pf")"
        rm -f "$pf" "$t"
        local v; v="$(bf_verdict "$cc" "$cclass" "$pc" "$pclass" truncation)"
        if [[ "$v" == "accepted" || "$v" == "silent-truncation" ]]; then
            accepted=$((accepted + 1))
            cs_row ACCEPTED "cut-at=$n" "code=$pc" "$v"
        else
            cs_row REFUSED "cut-at=$n" "code=$pc" "$v"
        fi
        n=$((n + 1))
    done
    rm -f "$ctl" "$full"

    cs_row VERDICT "$( (( accepted > 0 )) && echo truncation-accepted || echo truncation-refused )" "$accepted cuts accepted"
    cs_row SUMMARY "accepted=$accepted"
    return 0
}

bf_cmd_techniques() { local id class what; while IFS=$'\t' read -r id class what; do [[ -z "$id" ]] && continue; cs_row TECHNIQUE "$id" "$class" "$what"; done < <(bf_mutations); cs_row SUMMARY "mutations=$(bf_mutations | wc -l | tr -d ' ')"; return 0; }
bf_cmd_mutations()  { bf_cmd_techniques; }
bf_cmd_wire()       { local n name what; while IFS=$'\t' read -r n name what; do [[ -z "$n" ]] && continue; cs_row WIRE "$n" "$name" "$what"; done < <(bf_wire_types); cs_row SUMMARY "wire-types=$(bf_wire_types | wc -l | tr -d ' ')"; return 0; }
bf_cmd_list()       { cs_row LIST "wire-types" "mutations"; cs_row SUMMARY "ok"; return 0; }

bf_cmd_status_tsv() {
    local py cur
    command -v python3 >/dev/null 2>&1 && py="python3-ok" || py="python3-missing"
    command -v curl    >/dev/null 2>&1 && cur="curl-ok"   || cur="curl-missing"
    printf '%s\t%s\t%s\t%s\tmutations-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$py" "$cur" "$(bf_mutations | wc -l | tr -d ' ')"
}

bf_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

bf_cmd_help() {
    cat <<'HELP'
cloudsting module 69 — Binary / Protobuf Fuzzing v1.0.0
  --detect <url>              is this endpoint parsing a binary body at all
  --probe <url>               the control, then one truncated varint
  --fuzz <url> [class]        every mutation against the same control
  --varint <url>              integer fields fed values the type cannot hold
  --packed <url>              a repeated field in the wrong packing
  --any <url>                 a type_url the server never packs
  --truncate <url> [max]      cut a valid message at every point
  --techniques | --wire | --list | --status-tsv | --menu | --selftest | --help

A protobuf decoder is deliberately permissive: unknown fields are skipped,
enum values outside the range are kept as integers, and a length prefix is just
a number. So the finding is never "memory corruption" — it is the moment the
decoder and the type disagree and the handler believes the decoder.

Every verb sends a control message of the same shape first. An endpoint that
refuses a well-formed empty message gets `control-refused`, because every
mutation after that would only be measuring the refusal.

Message bytes are built into FILES, never into shell variables: a NUL byte
cannot survive a command substitution and protobuf length prefixes are full
of them.

Environment: BF_TIMEOUT (10), BF_PATH (/), BF_METHOD (POST), BF_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
bf_selftest() {
    cs_selftest_reset

    local nm; nm="$(bf_mutations | wc -l | tr -d ' ')"
    chk mut-4col    "$(bf_mutations | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk mut-unique  "$(bf_mutations | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nm"
    chk mut-many    "$( (( nm >= 16 )) && echo many || echo few )" "many"
    chk wire-rows   "$(bf_wire_types | wc -l | tr -d ' ')" "8"
    chk wire-3col   "$(bf_wire_types | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"

    # the encoders: a varint is the one thing that must be byte-exact
    chk varint-0    "$(bf_varint - 0 | od -An -v -tx1 | tr -d ' \n')" "00"
    chk varint-1    "$(bf_varint - 1 | od -An -v -tx1 | tr -d ' \n')" "01"
    chk varint-127  "$(bf_varint - 127 | od -An -v -tx1 | tr -d ' \n')" "7f"
    chk varint-128  "$(bf_varint - 128 | od -An -v -tx1 | tr -d ' \n')" "8001"
    chk varint-300  "$(bf_varint - 300 | od -An -v -tx1 | tr -d ' \n')" "ac02"
    chk tag-f1w2    "$(bf_tag 1 2 | od -An -v -tx1 | tr -d ' \n')" "0a"
    chk tag-f2w0    "$(bf_tag 2 0 | od -An -v -tx1 | tr -d ' \n')" "10"

    # every mutation must actually produce bytes
    local id class what bad=0
    while IFS=$'\t' read -r id class what; do
        [[ -z "$id" ]] && continue
        local f; f="$(mktemp "$CS_SCRATCH/bft.XXXXXX")"
        bf_build "$id" "$f"
        [[ -s "$f" ]] || { bad=$((bad + 1)); bf_log "mutation $id produced no bytes"; }
        rm -f "$f"
    done < <(bf_mutations)
    chk mut-bytes "$bad" "0"

    # the frame prefix is five bytes and its length is big endian
    local m; m="$(mktemp "$CS_SCRATCH/bfm.XXXXXX")"
    printf 'ABCDEFGHIJ' > "$m"
    chk frame-prefix "$(bf_frame "$m" | head -c 5 | od -An -v -tx1 | tr -d ' \n')" "000000000a"
    chk frame-total  "$(bf_frame "$m" | wc -c | tr -d ' ')" "15"
    rm -f "$m"

    # the verdict table: the control decides everything
    chk v-unreach   "$(bf_verdict 000 x 200 accepted truncation)" "unreachable"
    chk v-ctlref    "$(bf_verdict 400 decoder-refused 200 accepted truncation)" "control-refused"
    chk v-crash     "$(bf_verdict 200 accepted 500 crashed varint)" "decoder-crash"
    chk v-rejected  "$(bf_verdict 200 accepted 400 decoder-refused varint)" "rejected"
    chk v-validated "$(bf_verdict 200 accepted 400 handler-refused enum)" "validated"
    chk v-accepted  "$(bf_verdict 200 accepted 200 accepted enum)" "accepted"
    chk v-silent    "$(bf_verdict 200 accepted 204 empty truncation)" "silent-truncation"
    chk v-5xx       "$(bf_verdict 200 accepted 503 empty varint)" "server-error"

    chk s-crit      "$(bf_severity decoder-crash enum)" "CRITICAL"
    chk s-high-enum "$(bf_severity accepted enum no)" "HIGH"
    chk s-med-var   "$(bf_severity accepted varint no)" "MEDIUM"
    chk s-low       "$(bf_severity accepted unknown no)" "LOW"
    chk s-info      "$(bf_severity validated enum no)" "INFO"

    # a dead host is unreachable and produces no findings
    local out; out="$(bf_cmd_fuzz http://127.0.0.1:9 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-hits    "$(printf '%s' "$out" | grep -c '^HIT')" "0"
    out="$(bf_cmd_probe http://127.0.0.1:9 2>/dev/null)"
    chk dead-probe   "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    out="$(bf_cmd_truncate http://127.0.0.1:9 3 2>/dev/null)"
    chk dead-trunc   "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "truncation-refused"

    # usage errors
    bf_cmd_detect 2>/dev/null;   chk det-usage "$?" "2"
    bf_cmd_probe 2>/dev/null;    chk prb-usage "$?" "2"
    bf_cmd_fuzz 2>/dev/null;     chk fuz-usage "$?" "2"
    bf_cmd_varint 2>/dev/null;   chk var-usage "$?" "2"
    bf_cmd_packed 2>/dev/null;   chk pak-usage "$?" "2"
    bf_cmd_any 2>/dev/null;      chk any-usage "$?" "2"
    bf_cmd_truncate 2>/dev/null; chk tru-usage "$?" "2"

    chk status-fields "$(bf_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(bf_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(bf_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(bf_cmd_help | head -1 | grep -ci 'Protobuf')" "1"
    chk tech-rows     "$(bf_cmd_techniques | grep -c '^TECHNIQUE')" "$nm"
    chk wire-rows-out "$(bf_cmd_wire | grep -c '^WIRE')" "8"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --detect)     shift; bf_cmd_detect "$@";;
    --probe)      shift; bf_cmd_probe "$@";;
    --fuzz)       shift; bf_cmd_fuzz "$@";;
    --varint)     shift; bf_cmd_varint "$@";;
    --packed)     shift; bf_cmd_packed "$@";;
    --any)        shift; bf_cmd_any "$@";;
    --truncate)   shift; bf_cmd_truncate "$@";;
    --techniques|--mutations) bf_cmd_techniques;;
    --wire)       bf_cmd_wire;;
    --list)       bf_cmd_list;;
    --status-tsv|--status) bf_cmd_status_tsv;;
    --menu)       bf_cmd_menu;;
    --selftest)   bf_selftest;;
    *)            bf_cmd_help;;
esac
