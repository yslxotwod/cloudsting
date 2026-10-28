#!/usr/bin/env bash
# 56_grpc.sh — cloudsting module 56: talk to a service nobody meant to expose
# Verbs: --discover | --reflect | --services | --describe | --auth | --proto
#        | --fuzz | --grpc-status | --port-scan | --list | --status-tsv
#        | --menu | --selftest | --help
#
# grpcurl and protoc are optional. The reflection call itself is a protobuf
# message this module builds by hand and frames for gRPC, so the toolkit can
# recognise a gRPC service on a host that has neither dependency installed.
set -u
umask 077

# A parent that sourced the core exports CS_MOD_DIR; this module derives its own.
unset CS_MOD_DIR

MODULE_ID="56_grpc"
MOD_NAME="gRPC / Protobuf Attack (reflection, method auth and field confusion)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/grpc"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
SVC_FILE="$OUT_DIR/services-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${GR_TIMEOUT:=10}"
: "${GR_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/56}"
: "${GR_PORTS:=50051 443 8443 8080 9090 50052 6565 7050 7051 10000}"
: "${GR_CONCURRENCY:=6}"

gr_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the shapes worth trying ──────────────────────────────────────
# Every row is a way a deployment gets gRPC wrong. The middle column is where
# the mistake lives; the last is what an attacker walks away with.
#   <id>\t<mistake>\t<where>\t<what it hands over>
gr_techniques() {
    cat <<'TECHNIQUES'
reflect-public	reflection enabled without auth	server	every service, method and message in the build
reflect-root	reflection on the default v1alpha path	nginx/gateway	the schema through a door nobody closed
plaintext-tls	the same port answers h2c and h2	server	the bearer token in cleartext
method-no-auth	the interceptor guards some methods	interceptor	one unguarded method is the whole service
metadata-trust	x-user-id / x-tenant from a header	interceptor	any identity the caller claims
enum-confusion	unknown enum value treated as a default	handler	a branch nobody tested
int-overflow	int32 field fed a negative or oversized value	handler	arithmetic past the check
any-unpack	google.protobuf.Any accepted from the client	handler	structural type confusion
field-reuse	deprecated field numbers still parsed	codec	stale semantics the code left in
trailer-leak	grpc-message and grpc-status in cleartext	proxy	internal error strings and stack traces
TECHNIQUES
}

# The gRPC status codes worth telling apart: only one of them means "alive but
# refused", which is what an auth test needs.
gr_codes() {
    cat <<'CODES'
0	OK	the call ran — an auth check either passed or is absent
1	CANCELLED	client gave up
2	UNKNOWN	server failed without saying why
3	INVALID_ARGUMENT	the message parsed but the values were refused
5	NOT_FOUND	the method or the object does not exist
6	ALREADY_EXISTS	conflict
7	PERMISSION_DENIED	authenticated and refused — the auth check is there
8	RESOURCE_EXHAUSTED	throttled
12	UNIMPLEMENTED	the server does not have this service at all
13	INTERNAL	the handler threw
14	UNAVAILABLE	not a gRPC endpoint, or it is down
16	UNAUTHENTICATED	no credential — the auth check is there
CODES
}

# Paths that name the reflection service across the two published spellings
# and the vendored copies that ship inside larger products.
gr_reflect_paths() {
    cat <<'REFLECT'
grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo	v1alpha	the published alpha service
grpc.reflection.v1.ServerReflection/ServerReflectionInfo	v1	the published stable service
grpc.health.v1.Health/Check	health	the health service, present even with reflection off
grpc.health.v1.Health/Watch	health	health as a stream
envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources	xds	an Envoy control plane
REFLECT
}

# ── protobuf on the wire ─────────────────────────────────────────
# A reflection request is three fields, so the encoder is twenty lines rather
# than a protoc dependency.
gr_varint() {
    local n="$1" out=""
    while (( n > 127 )); do
        out+="$(printf '\\x%02x' $(( (n & 0x7f) | 0x80 )))"
        n=$(( n >> 7 ))
    done
    out+="$(printf '\\x%02x' "$n")"
    printf '%b' "$out"
}

# gr_pb_len <field-number> <payload> — a length-delimited field
# Written straight to stdout as one printf: a length of zero is a NUL byte, and
# a NUL cannot survive an intermediate command substitution, which is why this
# is not composed from helper output.
gr_pb_len() {
    local num="$1" payload="$2" len="${#2}" out n
    out="$(printf '\\x%02x' $(( (num << 3) | 2 )))"
    n=$len
    while (( n > 127 )); do
        out+="$(printf '\\x%02x' $(( (n & 0x7f) | 0x80 )))"
        n=$(( n >> 7 ))
    done
    out+="$(printf '\\x%02x' "$n")"
    printf '%b%b' "$out" "$payload"
}

# A gRPC frame is a compression flag, a big-endian length, then the message.
# Composed in one printf because the length bytes are often NUL.
#   gr_frame <message>
gr_frame() {
    local msg="$1" len=${#1}
    printf '%b%b%b%b%b%b' '\x00' \
        "$(printf '\\x%02x' $(( (len >> 24) & 0xff )))" \
        "$(printf '\\x%02x' $(( (len >> 16) & 0xff )))" \
        "$(printf '\\x%02x' $(( (len >> 8) & 0xff )))" \
        "$(printf '\\x%02x' $(( len & 0xff )))" \
        "$msg"
}


# gr_frame_from_file <path> — the 5-byte gRPC prefix, then the file's bytes.
# Reading the message from a file is what keeps an empty length-delimited field
# (a NUL byte) intact; no bash variable can carry one.
gr_frame_from_file() {
    local file="$1" len
    len="$(wc -c < "$file" 2>/dev/null | tr -d ' ')"
    printf '%b%b%b%b%b' '\x00' \
        "$(printf '\\x%02x' $(( (len >> 24) & 0xff )))" \
        "$(printf '\\x%02x' $(( (len >> 16) & 0xff )))" \
        "$(printf '\\x%02x' $(( (len >> 8) & 0xff )))" \
        "$(printf '\\x%02x' $(( len & 0xff )))"
    cat "$file"
}

# The message for a reflection or health call.  Empty-length payloads contain
# NUL bytes, which no bash string survives, so the shape is decided here and
# gr_exchange frames it straight into curl without an intermediate variable.
#   gr_reflect_body <symbol-or-empty> <kind:file|symbol|list|health>
gr_reflect_body() {
    local symbol="${1:-}" kind="${2:-file}"
    case "$kind" in
        health) gr_pb_len 1 '' ;;
        list)   gr_pb_len 7 '' ;;
        symbol) gr_pb_len 3 "$symbol" ;;
        *)      gr_pb_len 4 "$symbol" ;;
    esac
}

# gr_exchange <host:port> <scheme> <path> <symbol-or-empty> [kind]
#   -> http-code \x1f grpc-status \x1f bytes \x1f body-path
# The message is built inside this function, never passed in, because an
# empty-length field contains a NUL byte and no bash string survives one.
gr_exchange() {
    local host="$1" scheme="$2" path="$3" symbol="${4:-}" kind="${5:-file}"
    # the body goes to a file, not a variable: an empty length is a NUL byte
    local body; body="$(mktemp "$CS_SCRATCH/grb.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.grb.$$"
    gr_reflect_body "$symbol" "$kind" > "$body"
    local out; out="$(mktemp "$CS_SCRATCH/gr.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.gr.$$"
    local url="$scheme://$host/$path"
    local -a args=(-s -o "$out" --max-time "$GR_TIMEOUT" -A "$GR_UA"
                   -H 'Content-Type: application/grpc' -H 'TE: trailers'
                   -H 'grpc-accept-encoding: identity'
                   --data-binary @-)
    [[ "$scheme" == "http" ]] && args+=(--http2-prior-knowledge) || args+=(--http2)
    local meta code
    meta="$(gr_frame_from_file "$body" | curl "${args[@]}" \
        --write-out '%{http_code} %{size_download}' "$url" 2>/dev/null)"
    rm -f "$body"
    code="$(awk -v m="$meta" 'BEGIN{n=split(m,f," "); print (n>=1&&f[1]!="")?f[1]:"000"}')"
    local gstat
    gstat="$(gr_trailer "$out")"
    printf '%s\037%s\037%s\037%s\n' "$code" "$gstat" \
        "$(wc -c < "$out" 2>/dev/null | tr -d ' ')" "$out"
}

# grpc answers with HTTP/2 trailers; curl keeps them in the body stream for a
# non-browser client, so the status is grepped out of the captured bytes.
gr_trailer() {
    local file="$1" st=""
    [[ -f "$file" ]] || { printf '-'; return; }
    st="$(grep -ao 'grpc-status:[[:space:]]*[0-9]*' "$file" 2>/dev/null | tail -1 | grep -o '[0-9]*$')"

    # a 5-byte frame with flag 0 and a plausible length means descriptors came back
    if [[ -z "$st" && -s "$file" ]]; then
        local len
        len="$(od -An -tu1 -j1 -N4 "$file" 2>/dev/null | awk '{print $1*16777216+$2*65536+$3*256+$4}')"
        [[ "${len:-0}" -gt 0 ]] && st="0"
    fi
    printf '%s' "${st:--}"
}

# The text form of a descriptor carries .proto file names; that is the proof.
gr_descriptor_files() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    strings -a "$file" 2>/dev/null | grep -oE '[A-Za-z0-9_./-]+\.proto' || true
}

# Service and method names appear in the descriptor's fully-qualified form.
gr_descriptor_services() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    strings -a "$file" 2>/dev/null \
        | grep -oE '\b[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\.[A-Z][A-Za-z0-9_]*\b' || true
}

# ── the verdicts ─────────────────────────────────────────────────
# Reflection is a fact about the response, not about the status code:
#   status ≠ 000 and descriptors with .proto names = open reflection.
#   UNAVAILABLE (14) or a plain 415/404 = not a gRPC endpoint, or it is guarded.
#   UNAUTHENTICATED (16) = reflection exists but wants credentials.
#   gRPC 12 UNIMPLEMENTED = the server speaks gRPC and does not have reflection,
#   which is a fact worth recording because the endpoint is still there.
#   gr_reflect_verdict <http-code> <grpc-status> <n-proto-files>
gr_reflect_verdict() {
    local code="$1" gst="$2" files="$3"
    [[ "$code" == "000" ]] && { printf 'unreachable'; return; }
    case "$code" in
        404|405|415|501) printf 'not-grpc'; return ;;
    esac
    case "$gst" in
        0)  (( files > 0 )) && { printf 'reflection-open'; return; }
            printf 'answered-no-descriptor'; return ;;
        16) printf 'reflection-guarded'; return ;;
        7)  printf 'reflection-forbidden'; return ;;
        12) printf 'no-reflection'; return ;;
        14) printf 'not-grpc'; return ;;
        13|2) printf 'reflection-errors'; return ;;
        -)  printf 'no-grpc-status'; return ;;
    esac
    printf 'indeterminate'
}

# An auth finding on one method needs the pair: the unauthenticated call and
# the same call with a credential. Without a credential the only honest verdict
# is "answers without auth".
#   gr_auth_verdict <gst-anon> <code-anon> <gst-auth>
gr_auth_verdict() {
    local anon="$1" code="$2" auth="${3:--}"
    [[ "$code" == "000" ]] && { printf 'unreachable'; return; }
    if [[ "$anon" == "16" || "$anon" == "7" ]]; then
        printf 'guarded'
        # a credential that does not change the answer proves nothing, so the
        # fall-through case keeps the guarded verdict
        [[ "$auth" == "0" ]] && printf ' (auth-changes-nothing)'
        return
    fi
    if [[ "$anon" == "12" ]]; then printf 'no-method'; return; fi
    if [[ "$anon" == "0" ]]; then
        [[ "$auth" == "0" || "$auth" == "-" ]] && { printf 'unauthenticated-ok'; return; }
        printf 'anonymous-ok'
        return
    fi
    if [[ "$anon" == "3" || "$anon" == "5" ]]; then printf 'reached-handler'; return; fi
    printf 'inconclusive'
}

# ── verbs ────────────────────────────────────────────────────────

# --discover <host[:port] [tls:auto|1|0]>: which ports speak gRPC at all.
gr_cmd_discover() {
    local host="${1:-}" tls="${2:-auto}"
    [[ -z "$host" ]] && { gr_log "usage: --discover <host[:port]> [auto|1|0]"; return 2; }
    local base port
    base="${host%%:*}"
    cs_row TARGET "$host"
    cs_row PORTS "$GR_PORTS"

    local found=0
    for port in $GR_PORTS; do
        [[ "$host" == *:* ]] && port="${host##*:}" && break
        ( gr_tcp "$base" "$port" ) || continue
        local scheme="http"
        case "$tls" in
            1) scheme="https" ;;
            0) scheme="http" ;;
            *) ( gr_tcp "$base" "$port" 1 ) && scheme="https" || scheme="http" ;;
        esac
        local row code gst bytes path
        cs_split "$(gr_exchange "$base:$port" "$scheme" \
            "grpc.health.v1.Health/Check" "" health)" code gst bytes path
        rm -f "$path"
        local verdict
        verdict="$(gr_reflect_verdict "$code" "$gst" 0)"
        cs_row PORT "$port" "scheme=$scheme" "code=$code" "grpc-status=$gst" "verdict=$verdict"
        [[ "$verdict" != "unreachable" && "$verdict" != "not-grpc" ]] && found=$((found + 1))
        [[ "$host" == *:* ]] && break
    done
    cs_row SUMMARY "grpc-ports=$found"
    return 0
}

# one TCP reachability check, because curl's failure is a DNS error or a
# protocol error and the two have different meanings
gr_tcp() {
    local host="$1" port="$2" tls="${3:-0}"
    if (( tls )); then
        timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port 2>/dev/null" 2>/dev/null
    else
        timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port 2>/dev/null" 2>/dev/null
    fi
}

# --reflect <host[:port]> [tls:1|0]: the documented single question.
gr_cmd_reflect() {
    local host="${1:-}" tls="${2:-1}"
    [[ -z "$host" ]] && { gr_log "usage: --reflect <host[:port]> [tls:1|0]"; return 2; }
    local scheme; [[ "$tls" == "1" ]] && scheme="https" || scheme="http"
    [[ "$host" != *:* ]] && host="$host:443" && [[ "$tls" != "1" ]] && host="${host%:443}:50051"
    cs_row TARGET "$host"
    cs_row SCHEME "$scheme"

    local path kind note
    local best="" best_verdict="unreachable" best_files=0
    while IFS=$'\t' read -r path kind note; do
        [[ -z "$path" ]] && continue
        local code gst bytes body
        cs_split "$(gr_exchange "$host" "$scheme" "$path" \
            "grpc.reflection.v1alpha.ServerReflection" "$kind")" code gst bytes body
        local files; files="$(gr_descriptor_files "$body" | wc -l | tr -d ' ')"
        local verdict; verdict="$(gr_reflect_verdict "$code" "$gst" "$files")"
        cs_row PROBE "$path" "code=$code" "grpc-status=$gst" "files=$files" "verdict=$verdict" "$note"
        if [[ "$verdict" == "reflection-open" ]]; then
            best="$path"; best_verdict="$verdict"; best_files="$files"
            gr_descriptor_files "$body" | sort -u >> "$SVC_FILE"
        fi
        rm -f "$body"
    done < <(gr_reflect_paths)

    cs_row VERDICT "$best_verdict" "${best:-no path answered}"
    if [[ "$best_verdict" == "reflection-open" ]]; then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$host" "HIGH" "grpc-reflection-public" \
            "gRPC reflection answered without credentials: $best_files descriptor files on $best"
        printf '%s\t%s\t%s\n' "$host" "$best" "$best_files" >> "$HIT_FILE"
    fi
    cs_row SUMMARY "verdict=$best_verdict files=$best_files"
    return 0
}

# --services <host[:port]> [tls]: every service the descriptor dump names.
gr_cmd_services() {
    local host="${1:-}" tls="${2:-1}"
    [[ -z "$host" ]] && { gr_log "usage: --services <host[:port]> [tls:1|0]"; return 2; }
    local scheme; [[ "$tls" == "1" ]] && scheme="https" || scheme="http"
    cs_row TARGET "$host"
    local code gst bytes body
    cs_split "$(gr_exchange "$host" "$scheme" \
        "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" \
        "grpc.reflection.v1alpha.ServerReflection" file)" \
        code gst bytes body
    if [[ "$code" == "000" ]]; then
        cs_row VERDICT "unreachable"; cs_row SUMMARY "services=0"; rm -f "$body"; return 3
    fi

    local files; files="$(gr_descriptor_files "$body" | sort -u)"
    local f; for f in $files; do cs_row FILE "$f"; done

    local svcs; svcs="$(gr_descriptor_services "$body" | sort -u | head -60)"
    local s n=0
    while read -r s; do
        [[ -z "$s" ]] && continue
        n=$((n + 1))
        cs_row SERVICE "$s" "$(gr_service_risk "$s")"
        printf '%s\t%s\n' "$s" "$(gr_service_risk "$s")" >> "$SVC_FILE"
    done <<<"$svcs"
    rm -f "$body"
    cs_row SUMMARY "services=$n files=$(printf '%s\n' "$files" | grep -c . )"
    return 0
}

# A service name is a hint at what it guards. Nothing here is a finding on its
# own — it decides what to try first.
gr_service_risk() {
    local s="${1,,}"
    case "$s" in
        *admin*|*manage*|*internal*|*debug*) printf 'high admin surface' ;;
        *auth*|*identity*|*user*|*account*|*session*|*token*) printf 'high identity' ;;
        *payment*|*billing*|*wallet*|*balance*|*invoice*) printf 'high money' ;;
        *subscriber*|*msisdn*|*sim*|*cdr*|*usage*) printf 'high telco data' ;;
        *health*|*reflect*|*version*|*metrics*) printf 'low infrastructure' ;;
        *) printf 'medium business' ;;
    esac
}

# --describe <host[:port]> <service> [tls]: what a named service exposes.
gr_cmd_describe() {
    local host="${1:-}" svc="${2:-}" tls="${3:-1}"
    [[ -z "$host" || -z "$svc" ]] && { gr_log "usage: --describe <host[:port]> <service> [tls:1|0]"; return 2; }
    local scheme; [[ "$tls" == "1" ]] && scheme="https" || scheme="http"
    cs_row TARGET "$host"
    cs_row SERVICE "$svc"
    # file_containing_symbol is field 3
    local code gst bytes body
    cs_split "$(gr_exchange "$host" "$scheme" \
        "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" \
        "$svc" symbol)" code gst bytes body
    cs_row RESPONSE "code=$code" "grpc-status=$gst" "bytes=$bytes"
    local files; files="$(gr_descriptor_files "$body" | sort -u)"
    local f; for f in $files; do cs_row FILE "$f"; done
    local methods; methods="$(gr_descriptor_services "$body" | grep -F "$(printf '%s' "$svc" | cut -d. -f1)" | sort -u | head -40)"
    local m n=0
    while read -r m; do
        [[ -z "$m" ]] && continue
        n=$((n + 1)); cs_row METHOD "$m" "$(gr_method_shape "$m")"
    done <<<"$methods"
    rm -f "$body"
    cs_row SUMMARY "methods=$n files=$(printf '%s\n' "$files" | grep -c . )"
    return 0
}

# The verb lives in the method name often enough to be worth naming.
gr_method_shape() {
    local m="${1##*.}"
    case "$m" in
        Get*|List*|Describe*|Fetch*|Read*|Search*|Find*) printf 'read' ;;
        Create*|Add*|Register*|Insert*|Post*|New*) printf 'create' ;;
        Update*|Set*|Modify*|Patch*|Edit*) printf 'update' ;;
        Delete*|Remove*|Drop*|Revoke*|Purge*|Destroy*) printf 'delete' ;;
        Login*|Auth*|Sign*|Token*) printf 'auth' ;;
        Stream*|Watch*|Subscribe*|Listen*) printf 'stream' ;;
        Export*|Dump*|Download*|Backup*) printf 'exfiltrate' ;;
        *) printf 'other' ;;
    esac
}

# --auth <host[:port]> <service> <method> [token] [tls]: the one test that
# matters — does the method answer without a credential.
gr_cmd_auth() {
    local host="${1:-}" svc="${2:-}" method="${3:-}" token="${4:-}" tls="${5:-1}"
    [[ -z "$host" || -z "$svc" || -z "$method" ]] && {
        gr_log "usage: --auth <host[:port]> <service> <method> [token] [tls:1|0]"; return 2; }
    local scheme; [[ "$tls" == "1" ]] && scheme="https" || scheme="http"
    cs_row TARGET "$host"
    cs_row CALL "$svc/$method"
    cs_row CREDENTIAL "$([[ -n "$token" ]] && echo present || echo none)"

    # an empty message is the cheapest legal call; a server that needs a
    # populated one refuses with INVALID_ARGUMENT, which still proves the
    # handler ran
    local body_anon="$(gr_pb_len 1 '')"
    local code_a gst_a bytes_a path_a
    cs_split "$(gr_exchange "$host" "$scheme" "$svc/$method" "$body_anon")" \
        code_a gst_a bytes_a path_a
    rm -f "$path_a"
    local code_b="-" gst_b="-"
    if [[ -n "$token" ]]; then
        local path_b
        # a bearer token rides in the authorization metadata, not the message
        cs_split "$(gr_exchange_auth "$host" "$scheme" "$svc/$method" "$body_anon" "$token")" \
            code_b gst_b bytes_b path_b
        rm -f "$path_b"
    fi

    cs_row ANONYMOUS "code=$code_a" "grpc-status=$gst_a"
    [[ -n "$token" ]] && cs_row AUTHENTICATED "code=$code_b" "grpc-status=$gst_b"
    local verdict; verdict="$(gr_auth_verdict "$gst_a" "$code_a" "$gst_b")"
    cs_row VERDICT "$verdict"

    case "$verdict" in
        unauthenticated-ok|anonymous-ok)
            cs_findings_row "$MODULE_ID" "WEBAPI" "$host" "HIGH" "grpc-method-no-auth" \
                "$svc/$method answered without a credential (grpc-status 0)"
            printf '%s\t%s\t%s\t%s\n' "$host" "$svc" "$method" "$verdict" >> "$HIT_FILE" ;;
        reached-handler)
            cs_row NOTE "the handler ran and refused the empty message — the method exists and is reachable" ;;
        guarded)
            cs_row NOTE "the interceptor refused the anonymous call — this method is guarded" ;;
    esac
    cs_row SUMMARY "verdict=$verdict anon=${gst_a}"
    return 0
}

# the same exchange with a bearer token, kept separate so the anonymous call
# can never accidentally carry one
gr_exchange_auth() {
    local host="$1" scheme="$2" path="$3" msg="$4" token="$5"
    local out; out="$(mktemp "$CS_SCRATCH/gra.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.gra.$$"
    local url="$scheme://$host/$path"
    local -a args=(-s -o "$out" --max-time "$GR_TIMEOUT" -A "$GR_UA"
                   -H 'Content-Type: application/grpc' -H 'TE: trailers'
                   -H "authorization: Bearer $token"
                   --data-binary @-)
    [[ "$scheme" == "http" ]] && args+=(--http2-prior-knowledge) || args+=(--http2)
    local meta code
    meta="$(gr_frame "$msg" | curl "${args[@]}" \
        --write-out '%{http_code} %{size_download}' "$url" 2>/dev/null)"
    code="$(awk -v m="$meta" 'BEGIN{n=split(m,f," "); print (n>=1&&f[1]!="")?f[1]:"000"}')"
    printf '%s\037%s\037%s\037%s\n' "$code" "$(gr_trailer "$out")" \
        "$(wc -c < "$out" 2>/dev/null | tr -d ' ')" "$out"
}

# --fuzz <host[:port]> <service> <method> [tls]: the field-confusion table.
gr_cmd_fuzz() {
    local host="${1:-}" svc="${2:-}" method="${3:-}" tls="${4:-1}"
    [[ -z "$host" || -z "$svc" || -z "$method" ]] && {
        gr_log "usage: --fuzz <host[:port]> <service> <method> [tls:1|0]"; return 2; }
    local scheme; [[ "$tls" == "1" ]] && scheme="https" || scheme="http"
    cs_row TARGET "$host"
    cs_row CALL "$svc/$method"

    local code ctl_gst bytes path
    cs_split "$(gr_exchange "$host" "$scheme" "$svc/$method" "x" symbol)" \
        code ctl_gst bytes path
    rm -f "$path"
    cs_row CONTROL "code=$code" "grpc-status=$ctl_gst"
    if [[ "$code" == "000" ]]; then
        cs_row VERDICT "unreachable"; cs_row SUMMARY "payloads=0"; return 3
    fi

    : > "$PROBE_FILE"
    local id field wire what payload
    while IFS=$'\t' read -r id field wire what payload; do
        [[ -z "$id" ]] && continue
        local body
        case "$wire" in
            varint) body="$(gr_pb_varint "$field" "$payload")" ;;
            neg)    body="$(gr_pb_varint_neg "$field" "$payload")" ;;
            len)    body="$(gr_pb_len "$field" "$payload")" ;;
            empty)  body="$(gr_pb_len "$field" "")" ;;
            *)      continue ;;
        esac
        local p_code p_gst p_bytes p_path
        cs_split "$(gr_exchange "$host" "$scheme" "$svc/$method" "$body")" \
            p_code p_gst p_bytes p_path
        rm -f "$p_path"
        printf '%s\t%s\t%s\t%s\n' "$id" "$p_code" "$p_gst" "$p_bytes" >> "$PROBE_FILE"
        local v; v="$(gr_fuzz_verdict "$ctl_gst" "$p_gst" "$p_code")"
        cs_row PAYLOAD "$id" "$field" "$what" "grpc-status=$p_gst" "verdict=$v"
    done < <(gr_fuzz_table)
    cs_row SUMMARY "payloads=$(wc -l < "$PROBE_FILE" | tr -d ' ')"
    return 0
}

# A field fuzz is only interesting when the server's answer changes shape: the
# same INVALID_ARGUMENT for every payload means the message never parsed.
gr_fuzz_verdict() {
    local ctl="$1" probe="$2" code="$3"
    [[ "$code" == "000" ]] && { printf 'unreachable'; return; }
    [[ "$probe" == "$ctl" ]] && { printf 'same-as-control'; return; }
    case "$probe" in
        0)   printf 'accepted'; return ;;
        13)  printf 'handler-crash'; return ;;
        2)   printf 'unknown-error'; return ;;
        3)   printf 'refused-values'; return ;;
    esac
    printf 'differs'
}

# gr_pb_varint <field> <decimal-value>
gr_pb_varint() {
    local num="$1" val="$2"
    printf '%b%b' "$(printf '\\x%02x' $(( num << 3 )))" "$(gr_varint "$val")"
}

# a negative int32 is encoded as a ten-byte two's-complement varint, which is
# exactly the shape a naive length check fails on
gr_pb_varint_neg() {
    local num="$1" val="$2" n out
    # A negative int32 travels as the ten-byte two's-complement varint, which is
    # simply -1 in 64-bit arithmetic: nine bytes of 0xff and a closing 0x01.
    # No loop is needed and none is wanted — a computed loop shifts a negative
    # and never terminates.
    n=$(( -1 ))
    out="$(printf '\\x%02x' $(( num << 3 )))"
    for _ in 1 2 3 4 5 6 7 8 9; do
        out+="$(printf '\\x%02x' $(( (n & 0x7f) | 0x80 )))"
    done
    out+="$(printf '\\x%02x' 1)"
    printf '%b' "$out"
}

# The confusion table: each row is a value a typed client cannot send but the
# wire format permits.
#   <id>\t<field>\t<wire>\t<what it tries>\t<value>
gr_fuzz_table() {
    cat <<'FUZZ'
int32-max	1	varint	the largest legal int32	2147483647
int32-over	1	varint	one past it	2147483648
int32-neg	1	neg	a negative int32 under a bound	1
enum-unknown	2	varint	an enum value nobody defined	99
enum-huge	2	varint	an enum far outside the range	2147483647
string-empty	3	empty	a required string with no content	
string-huge	3	len	a length prefix larger than the body	4000
bool-2	4	varint	a boolean that is not 0 or 1	2
field-missing	9	varint	a field number the schema may still parse	1
nested-empty	5	empty	an unset submessage	 
FUZZ
}

# --proto <host[:port]> [tls]: pull the descriptor bytes to a file a reader
# can hand to protoc or a protobuf viewer afterwards.
gr_cmd_proto() {
    local host="${1:-}" tls="${2:-1}"
    [[ -z "$host" ]] && { gr_log "usage: --proto <host[:port]> [tls:1|0]"; return 2; }
    local scheme; [[ "$tls" == "1" ]] && scheme="https" || scheme="http"
    local code gst bytes body
    cs_split "$(gr_exchange "$host" "$scheme" \
        "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" \
        "grpc.reflection.v1alpha.ServerReflection" file)" \
        code gst bytes body
    cs_row TARGET "$host"
    cs_row RESPONSE "code=$code" "grpc-status=$gst" "bytes=$bytes"
    if [[ "$code" == "000" ]]; then
        cs_row VERDICT "unreachable"; rm -f "$body"; return 3
    fi
    local dest="$OUT_DIR/descriptor-$RUN_ID.bin"
    if [[ -s "$body" ]]; then
        mv "$body" "$dest"; chmod 600 "$dest" 2>/dev/null || true
        cs_row DESCRIPTOR "$dest" "$(wc -c < "$dest" | tr -d ' ') bytes"
        gr_descriptor_files "$dest" | sort -u | while read -r f; do
            [[ -n "$f" ]] && cs_row FILE "$f"
        done
        cs_row NOTE "the descriptor is length-prefixed gRPC frames; strip the 5-byte prefix per frame to feed protoc --decode_raw"
    else
        rm -f "$body"
        cs_row VERDICT "no-descriptor"
    fi
    return 0
}

# --grpc-status <host[:port]> [tls]: is this a gRPC endpoint at all.
gr_cmd_grpc_status() {
    local host="${1:-}" tls="${2:-1}"
    [[ -z "$host" ]] && { gr_log "usage: --grpc-status <host[:port]> [tls:1|0]"; return 2; }
    local scheme; [[ "$tls" == "1" ]] && scheme="https" || scheme="http"
    cs_row TARGET "$host"
    cs_row SCHEME "$scheme"
    local code gst bytes body
    cs_split "$(gr_exchange "$host" "$scheme" "grpc.health.v1.Health/Check" "$(gr_pb_len 1 '')")" \
        code gst bytes body
    rm -f "$body"
    cs_row HEALTH "code=$code" "grpc-status=$gst"
    local verdict
    if [[ "$code" == "000" ]]; then verdict="unreachable"
    elif [[ "$gst" == "0" ]]; then verdict="serving"
    elif [[ "$gst" == "12" || "$gst" == "14" ]]; then verdict="not-grpc"
    else verdict="grpc-but-refused"; fi
    cs_row VERDICT "$verdict"
    cs_row SUMMARY "verdict=$verdict"
    return 0
}

# --port-scan <host> [tls:auto]: the ports table alone, no reflection attempt.
gr_cmd_port_scan() {
    local host="${1:-}"
    [[ -z "$host" ]] && { gr_log "usage: --port-scan <host>"; return 2; }
    cs_row TARGET "$host"
    local port open=0
    for port in $GR_PORTS; do
        if gr_tcp "$host" "$port"; then
            cs_row OPEN "$port"
            open=$((open + 1))
        fi
    done
    cs_row SUMMARY "open=$open of $GR_PORTSCAN"
    return 0
}

gr_cmd_list() {
    local id mistake where hands
    while IFS=$'\t' read -r id mistake where hands; do
        [[ -z "$id" ]] && continue
        cs_row TECHNIQUE "$id" "$mistake" "$where" "$hands"
    done < <(gr_techniques)
    cs_row SUMMARY "techniques=$(gr_techniques | wc -l | tr -d ' ')"
    return 0
}

gr_cmd_codes() {
    local n name what
    while IFS=$'\t' read -r n name what; do
        [[ -z "$n" ]] && continue
        cs_row CODE "$n" "$name" "$what"
    done < <(gr_codes)
    cs_row SUMMARY "codes=$(gr_codes | wc -l | tr -d ' ')"
    return 0
}

gr_cmd_fuzz_table() {
    local id field wire what payload
    while IFS=$'\t' read -r id field wire what payload; do
        [[ -z "$id" ]] && continue
        cs_row PAYLOAD "$id" "$field" "$wire" "$what"
    done < <(gr_fuzz_table)
    cs_row SUMMARY "payloads=$(gr_fuzz_table | wc -l | tr -d ' ')"
    return 0
}

gr_cmd_status_tsv() {
    local curl_state="curl-missing"
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok"
    local h2="h2-unknown"
    curl --version 2>/dev/null | grep -q 'HTTP2' && h2="h2-ok"
    local grpcurl_state="grpcurl-missing"
    command -v grpcurl >/dev/null 2>&1 && grpcurl_state="grpcurl-ok"
    printf '%s\t%s\t%s\th2-%s\t%s\ttechniques-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "${h2#h2-}" "$grpcurl_state" \
        "$(gr_techniques | wc -l | tr -d ' ')"
}

gr_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

gr_cmd_help() {
    cat <<'HELP'
cloudsting module 56 — gRPC / Protobuf Attack v1.0.0
  --discover <host[:port]> [auto|1|0]     find the ports that speak gRPC
  --reflect <host[:port]> [tls]           is reflection open to the world
  --services <host[:port]> [tls]          every service in the descriptor dump
  --describe <host[:port]> <service> [tls] one service's methods and their verbs
  --auth <host[:port]> <service> <method> [token] [tls]
                                          does the method answer unauthenticated
  --fuzz <host[:port]> <service> <method> [tls]
                                          field confusion against one method
  --proto <host[:port]> [tls]             keep the descriptor bytes
  --grpc-status <host[:port]> [tls]       is this a gRPC endpoint at all
  --port-scan <host>                      the port table alone
  --codes | --payloads | --list | --status-tsv | --menu | --selftest | --help

grpcurl is optional. The reflection request is a protobuf message this module
builds and frames itself, so a host with no gRPC tooling still gets a verdict.
Reflection open is judged by what comes back — descriptor bytes naming .proto
files — not by the HTTP status, because a healthy gRPC server answers 200 to
everything including nonsense.

A method that answers without a credential is the finding. A method that
answers INVALID_ARGUMENT ran its handler and refused the empty message, which
is reported as reachable, not as unauthenticated.

Environment: GR_TIMEOUT (10), GR_PORTS, GR_CONCURRENCY
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
gr_selftest() {
    cs_selftest_reset

    local n; n="$(gr_techniques | wc -l | tr -d ' ')"
    chk tech-many    "$( (( n >= 10 )) && echo many || echo few )" "many"
    chk tech-4col    "$(gr_techniques | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk tech-unique  "$(gr_techniques | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"
    chk codes-count  "$(gr_codes | wc -l | tr -d ' ')" "12"
    chk codes-3col   "$(gr_codes | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk reflect-rows "$(gr_reflect_paths | wc -l | tr -d ' ')" "5"
    chk fuzz-rows    "$(gr_fuzz_table | wc -l | tr -d ' ')" "10"

    # protobuf encoding: a varint of 300 is 0xac 0x02
    chk varint-0     "$(gr_varint 0 | od -An -tx1 | tr -d ' \n')" "00"
    chk varint-127   "$(gr_varint 127 | od -An -tx1 | tr -d ' \n')" "7f"
    chk varint-128   "$(gr_varint 128 | od -An -tx1 | tr -d ' \n')" "8001"
    chk varint-300   "$(gr_varint 300 | od -An -tx1 | tr -d ' \n')" "ac02"

    # a length-delimited field carries tag, length, payload
    chk pb-len-tag   "$(gr_pb_len 3 "abc" | od -An -tx1 | tr -d ' \n')" "1a03616263"
    chk pb-len-empty "$(gr_pb_len 1 "" | od -An -tx1 | tr -d ' \n')" "0a00"

    # a gRPC frame is flag 0, a 4-byte big-endian length, then the message
    chk frame-flag    "$(gr_frame "abc" | od -An -tx1 -N1 | tr -d ' \n')" "00"
    chk frame-len     "$(gr_frame "abc" | od -An -tx1 -j1 -N4 | tr -d ' \n')" "00000003"
    chk frame-payload "$(gr_frame "abc" | od -An -c -j5 -N3 | tr -d ' \n')" "abc"
    chk frame-total   "$(gr_frame "abcdefghij" | wc -c | tr -d ' ')" "15"

    # the frame a reflection call actually puts on the wire: a real server
    # accepted 00 0000002a 22 28 <symbol> from this builder
    gr_reflect_body "grpc.reflection.v1alpha.ServerReflection" file > "$CS_SCRATCH/f.bin"
    chk wire-prefix   "$(gr_frame_from_file "$CS_SCRATCH/f.bin" | od -An -tx1 -N6 | tr -s ' ' | sed 's/^ //')" "00 00 00 00 2a 22"
    chk wire-empty    "$(printf '' > "$CS_SCRATCH/e.bin"; gr_reflect_body "" health > "$CS_SCRATCH/e.bin"; gr_frame_from_file "$CS_SCRATCH/e.bin" | od -An -tx1 | tr -s ' ' | sed 's/^ //')" "00 00 00 00 02 0a 00"
    rm -f "$CS_SCRATCH/f.bin" "$CS_SCRATCH/e.bin"

    # a reflection request names one of three fields
    chk req-file-tag  "$(gr_reflect_body foo file | od -An -tx1 -N1 | tr -d ' \n')" "22"
    chk req-list-tag  "$(gr_reflect_body '' list | od -An -tx1 -N1 | tr -d ' \n')" "3a"
    chk req-sym-tag   "$(gr_reflect_body foo symbol | od -An -tx1 -N1 | tr -d ' \n')" "1a"
    chk req-carries   "$(gr_reflect_body grpc.reflection file | grep -c 'grpc.reflection')" "1"

    # negative int32 is a ten-byte varint
    chk neg-len       "$(gr_pb_varint_neg 1 1 | wc -c | tr -d ' ')" "11"

    # the reflection verdict covers every answer a real server gives
    chk rv-unreach    "$(gr_reflect_verdict 000 - 0)" "unreachable"
    chk rv-open       "$(gr_reflect_verdict 200 0 4)" "reflection-open"
    chk rv-empty      "$(gr_reflect_verdict 200 0 0)" "answered-no-descriptor"
    chk rv-guarded    "$(gr_reflect_verdict 200 16 0)" "reflection-guarded"
    chk rv-forbid     "$(gr_reflect_verdict 200 7 0)" "reflection-forbidden"
    chk rv-noimpl     "$(gr_reflect_verdict 200 12 0)" "no-reflection"
    chk rv-notgrpc    "$(gr_reflect_verdict 200 14 0)" "not-grpc"
    chk rv-415        "$(gr_reflect_verdict 415 - 0)" "not-grpc"
    chk rv-500        "$(gr_reflect_verdict 500 - 0)" "no-grpc-status"
    chk rv-errors     "$(gr_reflect_verdict 500 13 0)" "reflection-errors"

    # the auth verdict is a pair, and an unguarded method is the whole point
    chk av-unreach    "$(gr_auth_verdict - 000 -)" "unreachable"
    chk av-open       "$(gr_auth_verdict 0 200 -)" "unauthenticated-ok"
    chk av-guarded    "$(gr_auth_verdict 16 200 -)" "guarded"
    chk av-7          "$(gr_auth_verdict 7 200 -)" "guarded"
    chk av-reached    "$(gr_auth_verdict 3 200 -)" "reached-handler"
    chk av-nomethod   "$(gr_auth_verdict 12 404 -)" "no-method"

    # field-fuzz verdicts tell an unchanged answer from a changed one
    chk fv-same       "$(gr_fuzz_verdict 3 3 200)" "same-as-control"
    chk fv-accepted   "$(gr_fuzz_verdict 3 0 200)" "accepted"
    chk fv-crash      "$(gr_fuzz_verdict 3 13 200)" "handler-crash"
    chk fv-differs    "$(gr_fuzz_verdict 3 1 200)" "differs"

    # service risk ranking picks admin before health
    chk sr-admin      "$(gr_service_risk a.b.AdminService)" "high admin surface"
    chk sr-health     "$(gr_service_risk a.b.Health)" "low infrastructure"
    chk sr-pay        "$(gr_service_risk a.b.PaymentService)" "high money"
    chk sr-other      "$(gr_service_risk a.b.Inventory)" "medium business"

    # method verbs come from the name
    chk ms-get        "$(gr_method_shape x.y.GetAccount)" "read"
    chk ms-del        "$(gr_method_shape x.y.DeleteAccount)" "delete"
    chk ms-export     "$(gr_method_shape x.y.ExportAll)" "exfiltrate"
    chk ms-login      "$(gr_method_shape x.y.Login)" "auth"

    # a dead host is unreachable, never a finding
    local out; out="$(gr_cmd_reflect 127.0.0.1:9 0 2>/dev/null)"
    chk dead-verdict  "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-hits     "$(printf '%s' "$out" | grep -c '^grpc-reflection-public')" "0"
    gr_cmd_grpc_status 127.0.0.1:9 0 >/dev/null 2>&1
    chk dead-status   "$(gr_cmd_grpc_status 127.0.0.1:9 0 2>/dev/null | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"

    # usage errors, not crashes
    gr_cmd_discover 2>/dev/null;  chk dis-usage "$?" "2"
    gr_cmd_reflect 2>/dev/null;   chk ref-usage "$?" "2"
    gr_cmd_services 2>/dev/null;  chk svc-usage "$?" "2"
    gr_cmd_describe 2>/dev/null;  chk dsc-usage "$?" "2"
    gr_cmd_auth 2>/dev/null;      chk aut-usage "$?" "2"
    gr_cmd_fuzz 2>/dev/null;      chk fuz-usage "$?" "2"
    gr_cmd_proto 2>/dev/null;     chk pro-usage "$?" "2"
    gr_cmd_grpc_status 2>/dev/null; chk gst-usage "$?" "2"
    gr_cmd_port_scan 2>/dev/null; chk psc-usage "$?" "2"

    # shape contracts
    chk status-fields "$(gr_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(gr_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(gr_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(gr_cmd_help | head -1 | grep -ci 'gRPC')" "1"
    chk list-rows     "$(gr_cmd_list | grep -c '^TECHNIQUE')" "$n"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --discover)    shift; gr_cmd_discover "$@";;
    --reflect)     shift; gr_cmd_reflect "$@";;
    --services)    shift; gr_cmd_services "$@";;
    --describe)    shift; gr_cmd_describe "$@";;
    --auth)        shift; gr_cmd_auth "$@";;
    --fuzz)        shift; gr_cmd_fuzz "$@";;
    --proto)       shift; gr_cmd_proto "$@";;
    --grpc-status) shift; gr_cmd_grpc_status "$@";;
    --port-scan)   shift; gr_cmd_port_scan "$@";;
    --codes)       gr_cmd_codes;;
    --payloads)    gr_cmd_fuzz_table;;
    --list)        gr_cmd_list;;
    --status-tsv|--status) gr_cmd_status_tsv;;
    --menu)        gr_cmd_menu;;
    --selftest)    gr_selftest;;
    *)             gr_cmd_help;;
esac
