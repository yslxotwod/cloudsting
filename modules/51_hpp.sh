#!/usr/bin/env bash
# 51_hpp.sh — cloudsting module 51: one parameter, two meanings
# Verbs: --check | --split | --dup | --array | --encoding | --json | --query
#        --smuggle | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# A caller that sources the core hands this module *its* modules directory, so
# the inherited value has to go before the core derives its own.
unset CS_MOD_DIR

MODULE_ID="51_hpp"
MOD_NAME="Parameter Pollution (duplicate, encoded and re-typed parameters)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

HP_RUN_ID="$CS_RUN_ID"
export HP_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/hpp"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${HP_TIMEOUT:=10}"
: "${HP_FOLLOW:=0}"
: "${HP_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/51}"
: "${HP_VALUE:=cloudsting_pp}"
: "${HP_SERVER_VALUE:=server_pp}"

hp_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the injection vectors ────────────────────────────────────────
# Each row: <id>\t<class>\t<what the duplicate pair looks like>.
# The class is what the fix is: a parser that takes the first value, one that
# takes the last, one that joins them, one that walks an array, and the
# encodings that make two proxies disagree about where the parameter ends.
#   <id>\t<class>\t<shape>     (shape uses Q for client value, S for the other)
hp_vectors() {
    cat <<'VECTORS'
dup-last	last-wins	Q=CLIENT&S=SERVER
dup-first	first-wins	S=SERVER&Q=CLIENT
dup-repeat	first-wins	S=SERVER&Q=CLIENT&Q=CLIENT
array-bracket	array	Q[]=CLIENT&S=SERVER
array-nested	array	Q[0]=CLIENT&S=SERVER
array-index	array	Q[1]=CLIENT&S=SERVER
comma-join	join	Q=CLIENT,SERVER
semicolon-join	join	Q=CLIENT;Q=SERVER
amp-encoded	encoding	Q=CLIENT%26Q%3DSERVER
hash-encoded	encoding	Q=CLIENT%23S=SERVER
space-encoded	encoding	Q=CLIENT%20Q=SERVER
null-in-name	encoding	Q%00=SERVER
dash-in-name	encoding	Q-=SERVER
dot-in-name	encoding	Q.=SERVER
case-shift	parser-diff	Q=CLIENT&q=SERVER
unicode-case	parser-diff	Q=CLIENT&Q=SERVER
bare-name	parser-diff	Q&Q=SERVER
VECTORS
}

# Where a polluted parameter is worth planting. These are the names a BSS or
# gateway actually reads: the recipient, the amount, the account, the role.
#   <name>\t<what changing it buys>
hp_params() {
    cat <<'PARAMS'
msisdn	target number on a billable action
recipient	sms destination
amount	value of a charge or transfer
account_id	whose records are read
subscriber	whose line is changed
role	authorization decision
price	promo or package cost
qty	order quantity
email	who the receipt goes to
redirect	where the browser lands
PLAN_ID	which plan is provisioned
limit	quota boundary
balance	credit applied
promo	coupon applied
token	session or code material
user_id	identity the server trusts
PARAMS
}

hp_test_targets() {
    cat <<'TARGETS'
params	one well-known parameter
all	every parameter in the table
TARGETS
}

# ── one request ──────────────────────────────────────────────────
# A response is only interesting when it is not the catch-all. That is decided
# by comparing against a nonsense parameter on the same path, exactly like the
# discovery module does: a SPA that answers 200 to everything must not look
# like a parser that honoured a duplicate.
#   hp_send <url-with-placeholder> <method> [body] [content-type]
#   -> code \x1f bytes \x1f hash \x1f keys \x1f ctype \x1f body-path
hp_send() {
    local url="$1" method="${2:-GET}" body="${3:-}" ctype="${4:-}"
    local out; out="$(mktemp "$CS_SCRATCH/hp.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.hp.$$"
    local -a args=(-s -o "$out" --max-time "$HP_TIMEOUT" -A "$HP_UA" -X "$method")
    (( HP_FOLLOW == 1 )) && args+=(-L)
    [[ -n "$body"  ]] && args+=(--data-binary "$body")
    [[ -n "$ctype" ]] && args+=(-H "Content-Type: $ctype")

    local meta
    meta="$(curl "${args[@]}" --write-out '%{http_code}\t%{size_download}\t%{content_type}' \
                 "$url" 2>/dev/null)" || meta=""
    local code bytes ct
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code bytes ct <<<"$meta" ;;
        *) code="000"; bytes="0"; ct="" ;;
    esac
    local hash keys
    hash="$(cs_fingerprint "$(head -c 65536 "$out" 2>/dev/null)")"
    keys="$(jq -r 'if type=="object" then (keys_unsorted|join(","))
                   elif type=="array" then "array:"+(length|tostring)
                   elif type=="string" then "string:"+(length|tostring)
                   else "scalar" end' "$out" 2>/dev/null)" || keys=""
    printf '%s\037%s\037%s\037%s\037%s\037%s\n' \
        "${code:-000}" "${bytes:-0}" "$hash" "$keys" "${ct:-none}" "$out"
}

# ── verdicts ─────────────────────────────────────────────────────
# The whole point: a duplicate only matters when the server's answer CHANGES
# because of it. Same body, same status, same hash — the parser collapsed it and
# the application never saw two values.
#   hp_verdict <control-code> <control-hash> <variant-code> <variant-hash>
#              <variant-keys> <variant-bytes>
hp_verdict() {
    local cc="$1" ch="$2" vc="$3" vh="$4" vk="$5" vb="$6"
    case "$vc" in
        000) printf 'unreachable'; return ;;
        404|410) printf 'absent'; return ;;
        405) printf 'no-method'; return ;;
        5*) printf 'error'; return ;;
    esac
    if [[ "$cc" != "200" && "$cc" != "201" && "$cc" != "202" && "$cc" != "204" ]]; then
        case "$cc" in
            000) printf 'unreachable'; return ;;
            404|410) printf 'not-there'; return ;;
            401|403) printf 'guarded'; return ;;
        esac
    fi
    if [[ "$vh" == "$ch" ]]; then
        printf 'collapsed'
        return
    fi
    case "$vc" in
        400|415|422) printf 'rejected'; return ;;
        401|403) printf 'guarded'; return ;;
        2*)
            case "$vk" in
                ""|none|scalar) printf 'differs-unstructured'; return ;;
            esac
            if (( ${vb:-0} < 64 )); then
                printf 'differs-tiny'
                return
            fi
            printf 'honoured'
            return
            ;;
    esac
    printf 'differs'
}

# A "honoured" duplicate is only a finding when the second value actually
# reached the application. This reads the response for the marker the caller
# planted, which is the one piece of evidence a parser test can give you.
#   hp_marker_seen <body-path> <marker>
hp_marker_seen() {
    local body="$1" marker="$2"
    [[ -f "$body" ]] || { printf '0'; return; }
    if grep -qa -- "$marker" "$body" 2>/dev/null; then printf '1'; else printf '0'; fi
}

# Same parameter twice with the same name but a different spelling: if the
# server answers differently, something down the chain case-folds.
#   hp_case_verdict <lower-code> <lower-hash> <upper-code> <upper-hash>
hp_case_verdict() {
    local lc="$1" lh="$2" uc="$3" uh="$4"
    case "$lc$uc" in
        *000*) printf 'unreachable'; return ;;
    esac
    if [[ "$lh" == "$uh" && "$lc" == "$uc" ]]; then printf 'same'; return; fi
    if [[ "$uc" == "$lc" ]]; then printf 'differs-same-code'; return; fi
    printf 'differs'
}

# ── shapes ───────────────────────────────────────────────────────
# Build the polluted query string for one vector. Q is the client's value and
# S is the one already on the request — the duplicate is always the attacker's.
#   hp_shape <vector-id> <param> <client-value> <server-value>
hp_shape() {
    local id="$1" param="$2" q="$3" s="$4"
    case "$id" in
        dup-last)        printf '%s=%s&%s=%s' "$param" "$s" "$param" "$q" ;;
        dup-first)       printf '%s=%s&%s=%s' "$param" "$q" "$param" "$s" ;;
        dup-repeat)      printf '%s=%s&%s=%s&%s=%s' "$param" "$s" "$param" "$q" "$param" "$q" ;;
        array-bracket)   printf '%s=%s&%s[]=%s' "$param" "$s" "$param" "$q" ;;
        array-nested)    printf '%s=%s&%s[0]=%s&%s[1]=%s' "$param" "$s" "$param" "$q" "$param" "$q" ;;
        array-index)     printf '%s=%s&%s[1]=%s' "$param" "$s" "$param" "$q" ;;
        idx-last-wins)   printf '%s=%s&%s=%s' "$param" "$s" "$param" "$q" ;;
        comma-join)      printf '%s=%s,%s' "$param" "$s" "$q" ;;
        semicolon-join)  printf '%s=%s;%s=%s' "$param" "$s" "$param" "$q" ;;
        amp-encoded)     printf '%s=%s%%26%s%%3D%s' "$param" "$s" "$param" "$q" ;;
        hash-encoded)    printf '%s=%s%%23%s=%s' "$param" "$s" "$param" "$q" ;;
        space-encoded)   printf '%s=%s%%20%s=%s' "$param" "$s" "$param" "$q" ;;
        null-in-name)    printf '%s%%00=%s&%s=%s' "$param" "$q" "$param" "$s" ;;
        dash-in-name)    printf '%s-=%%s&%s=%s' "$param" "$q" "$param" "$s" ;;
        dot-in-name)     printf '%s.=%s&%s=%s' "$param" "$q" "$param" "$s" ;;
        case-shift)      printf '%s=%s&%s=%s' "$param" "$s" "$(printf '%s' "$param" | tr 'a-z' 'A-Z')" "$q" ;;
        unicode-case)    printf '%s=%s&%sw=%s' "$param" "$s" "$param" "$q" ;;
        bare-name)       printf '%s&%s=%s' "$param" "$param" "$q" ;;
        *)               printf '%s=%s' "$param" "$q" ;;
    esac
}

# A URL is either a query or it is not: a path-only URL gets an `?`, a URL with
# a query gets an `&`. Getting this wrong silently appends to an existing param.
hp_append() {
    local url="$1" qs="$2"
    case "$url" in
        *\?*) printf '%s&%s' "$url" "$qs" ;;
        *)    printf '%s?%s' "$url" "$qs" ;;
    esac
}

# ── verbs ────────────────────────────────────────────────────────

# --check <url> <param>: the baseline and the control, then every vector. One
# parameter, every shape, so a report can name the parser that folded it.
hp_cmd_check() {
    local base="${1:-}" param="${2:-}" q="${3:-$HP_VALUE}" s="${4:-$HP_SERVER_VALUE}"
    if [[ -z "$base" || -z "$param" ]]; then
        hp_log "usage: --check <url> <param> [client-value] [server-value]"
        return 2
    fi
    cs_row TARGET "$base"
    cs_row PARAM "$param"
    cs_row VALUES "client=$q" "server=$s"

    # baseline: a parameter nobody reads. If this answers like a real one, the
    # app is a catch-all and no duplicate result can be trusted.
    local junk; junk="$(cs_fingerprint "$base$param" | head -c 12)"
    local b_code b_bytes b_hash b_keys b_ct b_body
    cs_split "$(hp_send "$(hp_append "$base" "cloudsting_nonsense_$junk=1")")" \
        b_code b_bytes b_hash b_keys b_ct b_body
    local base_is_catchall=0
    rm -f "$b_body"

    # control: the parameter already on the request, once
    local c_code c_bytes c_hash c_keys c_ct c_body
    cs_split "$(hp_send "$(hp_append "$base" "${param}=${s}")")" \
        c_code c_bytes c_hash c_keys c_ct c_body
    rm -f "$c_body"
    cs_row BASE "code=$b_code" "bytes=$b_bytes"
    cs_row CONTROL "code=$c_code" "bytes=$c_bytes" "keys=${c_keys:-none}"

    if [[ "$b_code" == "000" ]]; then
        cs_row VERDICT "unreachable" "nothing answered"
        cs_row SUMMARY "vectors=0 honoured=0"
        return 3
    fi
    if [[ "$c_code" == "000" ]]; then
        cs_row VERDICT "unreachable" "the control did not answer"
        cs_row SUMMARY "vectors=0 honoured=0"
        return 3
    fi
    [[ "$c_code" != "200" && "$c_code" != "201" ]] && base_is_catchall=1

    local tried=0 honoured=0 id class shape
    : > "$HIT_FILE"
    while IFS=$'\t' read -r id class shape; do
        [[ -z "$id" ]] && continue
        local qs; qs="$(hp_shape "$id" "$param" "$q" "$s")"
        local url; url="$(hp_append "$base" "$qs")"

        local v_code v_bytes v_hash v_keys v_ct v_body
        cs_split "$(hp_send "$url")" v_code v_bytes v_hash v_keys v_ct v_body
        local seen; seen="$(hp_marker_seen "$v_body" "$q")"
        rm -f "$v_body"
        tried=$((tried + 1))

        local verdict; verdict="$(hp_verdict "$c_code" "$c_hash" "$v_code" "$v_hash" "${v_keys:-}" "${v_bytes:-0}")"
        printf 'vector\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$class" "$v_code" "$verdict" "$seen" "$url" >> "$PROBE_FILE"

        case "$verdict" in
            honoured)
                honoured=$((honoured + 1))
                local sev="HIGH"
                case "$param" in
                    msisdn|recipient|account_id|subscriber|role|user_id|balance|amount|limit) sev="CRITICAL" ;;
                esac
                cs_row HIT "$id" "class=$class" "code=$v_code" "marker=$seen" "$url"
                printf '%s\t%s\t%s\t%s\n' "$id" "$class" "$v_code" "$q" >> "$HIT_FILE"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "$sev" "param-pollution-$id" \
                    "$param: the $class parser took the attacker value over the server value (marker=$seen)"
                ;;
            differs-same-code|differs)
                cs_row DIFFERS "$id" "class=$class" "code=$v_code" "$verdict"
                ;;
            collapsed)
                cs_row COLLAPSED "$id" "class=$class" "$verdict"
                ;;
            *)
                cs_row VECTOR "$id" "class=$class" "code=$v_code" "$verdict"
                ;;
        esac
    done < <(hp_vectors)

    [[ "$base_is_catchall" == "1" ]] && \
        cs_row NOTE "the control did not answer 2xx — compare with care"

    local sev_verdict="collapsed"
    (( honoured > 0 )) && sev_verdict="honoured"
    cs_row VERDICT "$sev_verdict" "$honoured of $tried vectors"
    cs_row SUMMARY "vectors=$tried honoured=$honoured marker=client"
    cs_row ARTIFACT "$PROBE_FILE" "$HIT_FILE"
    return 0
}

# --split <url> [param]: a duplicate only gets through if the proxy and the app
# disagree about the parameter. Each vector is sent once and the result is
# attributed to the class of parser that would have to be misaligned.
hp_cmd_split() {
    local base="${1:-}" param="${2:-msisdn}"
    [[ -z "$base" ]] && { hp_log "usage: --split <url> [param]"; return 2; }
    cs_row TARGET "$base"
    cs_row PARAM "$param"
    cs_row NOTE "run after --check: this one asks which class folded, not whether it did"

    local id class shape counts_first=0 counts_last=0 counts_join=0 counts_array=0 counts_other=0
    local last_id="" last_class=""
    while IFS=$'\t' read -r id class shape; do
        [[ -z "$id" ]] && continue
        local payload; payload="$(hp_shape "$id" "$param" "$HP_VALUE" "$HP_SERVER_VALUE")"
        local url; url="$(hp_append "$base" "$payload")"
        cs_split "$(hp_send "$url")" _ _ _ _ _ body
        local seen; seen="$(hp_marker_seen "$body" "$HP_VALUE")"
        rm -f "$body"
        if [[ "$seen" == "1" ]]; then
            last_id="$id"; last_class="$class"
            case "$class" in
                first-wins) counts_first=$((counts_first + 1)) ;;
                last-wins)  counts_last=$((counts_last + 1)) ;;
                join)       counts_join=$((counts_join + 1)) ;;
                array)      counts_array=$((counts_array + 1)) ;;
                *)          counts_other=$((counts_other + 1)) ;;
            esac
        fi
    done < <(hp_vectors)

    cs_row FIRST_WINS "$counts_first"
    cs_row LAST_WINS  "$counts_last"
    cs_row JOIN       "$counts_join"
    cs_row ARRAY      "$counts_array"
    cs_row OTHER      "$counts_other"
    if [[ -n "$last_id" ]]; then
        cs_row LEAK "$last_id" "class=$last_class"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "HIGH" "param-split-$last_class" \
            "$param: the $last_class parser read the attacker duplicate ($last_id)"
    fi
    cs_row SUMMARY "classes-known=4 leaked=$(( counts_first + counts_last + counts_join + counts_array + counts_other ))"
    return 0
}

# --dup <url> <param> [client] [server]: the plainest form — same name twice.
# Useful when only one question has to be answered.
hp_cmd_dup() {
    local base="${1:-}" param="${2:-}" q="${3:-$HP_VALUE}" s="${4:-$HP_SERVER_VALUE}"
    if [[ -z "$base" || -z "$param" ]]; then
        hp_log "usage: --dup <url> <param> [client-value] [server-value]"
        return 2
    fi
    local c_body v_body
    cs_split "$(hp_send "$(hp_append "$base" "${param}=${s}")")" c_code _ c_hash c_keys _ c_body
    cs_split "$(hp_send "$(hp_append "$base" "$(hp_shape dup-last "$param" "$q" "$s")")")" \
        v_code _ v_hash v_keys v_bytes v_body
    local seen; seen="$(hp_marker_seen "$v_body" "$q")"
    rm -f "$c_body" "$v_body"

    cs_row CONTROL "code=${c_code:-000}" "keys=${c_keys:-none}"
    cs_row DUP     "code=${v_code:-000}" "keys=${v_keys:-none}" "marker=$seen"
    local verdict; verdict="$(hp_verdict "$c_code" "$c_hash" "$v_code" "$v_hash" "${v_keys:-}" "${v_bytes:-0}")"
    cs_row VERDICT "$verdict"
    [[ "$verdict" == "honoured" ]] && \
        cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "HIGH" "duplicate-parameter" \
            "$param: sending the name twice changed the response (marker=$seen)"
    cs_row SUMMARY "param=$param verdict=$verdict"
    return 0
}

# --array <url> <param>: array syntax and whether it lands as a list.
hp_cmd_array() {
    local base="${1:-}" param="${2:-}"
    [[ -z "$base" || -z "$param" ]] && { hp_log "usage: --array <url> <param>"; return 2; }
    cs_row TARGET "$base"
    local id class shape tried=0 seen_any=0
    while IFS=$'\t' read -r id class shape; do
        case "$class" in array) ;; *) continue ;; esac
        tried=$((tried + 1))
        local url; url="$(hp_append "$base" "$(hp_shape "$id" "$param" "$HP_VALUE" "$HP_SERVER_VALUE")")"
        cs_split "$(hp_send "$url")" code _ _ keys _ body
        local seen; seen="$(hp_marker_seen "$body" "$HP_VALUE")"
        rm -f "$body"
        [[ "$seen" == "1" ]] && seen_any=$((seen_any + 1))
        cs_row ARRAY "$id" "code=${code:-000}" "keys=${keys:-none}" "marker=$seen"
    done < <(hp_vectors)
    cs_row SUMMARY "shapes=$tried landed=$seen_any"
    return 0
}

# --encoding <url> <param>: the proxies that split on & and those that do not.
hp_cmd_encoding() {
    local base="${1:-}" param="${2:-}"
    [[ -z "$base" || -z "$param" ]] && { hp_log "usage: --encoding <url> <param>"; return 2; }
    cs_row TARGET "$base"
    local id class shape tried=0 seen_any=0
    while IFS=$'\t' read -r id class shape; do
        case "$class" in encoding|parser-diff) ;; *) continue ;; esac
        tried=$((tried + 1))
        local url; url="$(hp_append "$base" "$(hp_shape "$id" "$param" "$HP_VALUE" "$HP_SERVER_VALUE")")"
        cs_split "$(hp_send "$url")" code _ _ keys _ body
        local seen; seen="$(hp_marker_seen "$body" "$HP_VALUE")"
        rm -f "$body"
        [[ "$seen" == "1" ]] && seen_any=$((seen_any + 1))
        cs_row ENCODING "$id" "class=$class" "code=${code:-000}" "marker=$seen"
    done < <(hp_vectors)
    cs_row SUMMARY "encodings=$tried honoured=$seen_any"
    return 0
}

# --json <url> <param>: the same name in a JSON body and in the query at once.
# A backend that reads the body and a gateway that reads the query string are
# the canonical pollution pair.
hp_cmd_json() {
    local base="${1:-}" param="${2:-}" q="${3:-$HP_VALUE}" s="${4:-$HP_SERVER_VALUE}"
    if [[ -z "$base" || -z "$param" ]]; then
        hp_log "usage: --json <url> <param> [client-value] [server-value]"
        return 2
    fi
    cs_row TARGET "$base"
    cs_row PARAM "$param"

    local body url code keys seen verdict
    # control: the server value in both places
    body="$(printf '{"%s":"%s"}' "$param" "$s")"
    url="$(hp_append "$base" "${param}=${s}")"
    cs_split "$(hp_send "$url" POST "$body" application/json)" c_code _ c_hash c_keys _ c_body
    rm -f "$c_body"

    cases=(
        "body-wins|$(printf '{"%s":"%s"}' "$param" "$q")|${param}=${s}"
        "query-wins|$(printf '{"%s":"%s"}' "$param" "$s")|${param}=${q}"
        "body-duplicate|$(printf '{"%s":"%s","%s":"%s"}' "$param" "$s" "$param" "$q")|"
        "body-array|$(printf '{"%s":["%s","%s"]}' "$param" "$q" "$s")|"
        "content-type-form|$(printf '%s=%%s&%s=%%s' "$param" "$param" "$q" "$s")|"
    )
    local tried=0 honoured=0 c spec b qs
    for c in "${cases[@]}"; do
        spec="${c#*|}"; b="${spec%%|*}"; qs="${spec##*|}"
        [[ "$b" == *%s* ]] && b="$(printf "$b" "$q" "$s")"
        tried=$((tried + 1))
        if [[ "$c" == content-type-form* ]]; then
            url="$base"
            cs_split "$(hp_send "$url" POST "$b" "application/x-www-form-urlencoded")" code _ _ keys _ body
        else
            url="$base"
            [[ -n "$qs" ]] && url="$(hp_append "$base" "$qs")"
            cs_split "$(hp_send "$url" POST "$b" application/json)" code _ _ keys _ body
        fi
        seen="$(hp_marker_seen "$body" "$q")"
        rm -f "$body"
        verdict="$(hp_verdict "$c_code" "$c_hash" "$code" "$c_hash" "${keys:-}" 0)"
        [[ "$seen" == "1" ]] && honoured=$((honoured + 1))
        cs_row CASE "${c%%|*}" "code=${code:-000}" "keys=${keys:-none}" "marker=$seen"
    done
    cs_row SUMMARY "cases=$tried honoured=$honoured"
    return 0
}

# --query <url> <param> <server-value>: the value the server would have taken,
# to confirm the leak statically. Sends only the plain request.
hp_cmd_query() {
    local base="${1:-}" param="${2:-}" s="${3:-}"
    if [[ -z "$base" || -z "$param" ]]; then
        hp_log "usage: --query <url> <param> [server-value]"
        return 2
    fi
    cs_row TARGET "$base"
    cs_row PARAM "$param"
    local url; url="$(hp_append "$base" "${param}=${s}")"
    local code _b keys _c body
    cs_split "$(hp_send "$url")" code _b _ _ keys body
    local bytes; bytes="$(wc -c < "$body" 2>/dev/null | tr -d ' ')"
    rm -f "$body"
    cs_row RESPONSE "code=${code:-000}" "keys=${keys:-none}" "bytes=${bytes:-0}"
    cs_row SUMMARY "one-shot query against $url"
    return 0
}

# --smuggle <url> [param]: the pair that beats a front-end filter — the value
# the WAF inspects and the value the backend reads are not the same string.
hp_cmd_smuggle() {
    local base="${1:-}" param="${2:-msisdn}"
    [[ -z "$base" ]] && { hp_log "usage: --smuggle <url> [param]"; return 2; }
    cs_row TARGET "$base"

    # the rule being tested: a WAF that blocks a value but not its decoded form
    local pairs=(
        "percent|${HP_VALUE}|${HP_VALUE//_/%5f}"
        "double-percent|${HP_VALUE}|${HP_VALUE//_/%255f}"
        "case|${HP_VALUE}|$(printf '%s' "$HP_VALUE" | tr 'a-z' 'A-Z')"
        "null|${HP_VALUE}|${HP_VALUE}%00"
        "space|${HP_VALUE}|${HP_VALUE}%20"
        "tab|${HP_VALUE}|${HP_VALUE}%09"
    )
    local p id blocked armed code seen verdict tried=0 passed=0
    for p in "${pairs[@]}"; do
        id="${p%%|*}"; armed="${p#*|}"
        tried=$((tried + 1))
        local url; url="$(hp_append "$base" "${param}=${armed}")"
        cs_split "$(hp_send "$url")" code _ _ keys _ body
        seen="$(hp_marker_seen "$body" "$HP_VALUE")"
        rm -f "$body"
        case "$code" in
            403|406|418|429) verdict="filtered" ;;
            2*) verdict="passed"; passed=$((passed + 1)) ;;
            000) verdict="unreachable" ;;
            *) verdict="other" ;;
        esac
        cs_row FILTER "$id" "code=${code:-000}" "$verdict" "marker=$seen"
    done
    cs_row SUMMARY "encodings=$tried passed=$passed"
    return 0
}

hp_cmd_list() {
    local id class shape
    while IFS=$'\t' read -r id class shape; do
        [[ -z "$id" ]] && continue
        cs_row VECTOR "$id" "class=$class" "$shape"
    done < <(hp_vectors)
    cs_row SUMMARY "vectors=$(hp_vectors | wc -l | tr -d ' ')"
    return 0
}

hp_cmd_params() {
    local name what
    while IFS=$'\t' read -r name what; do
        [[ -z "$name" ]] && continue
        cs_row PARAM "$name" "$what"
    done < <(hp_params)
    cs_row SUMMARY "params=$(hp_params | wc -l | tr -d ' ')"
    return 0
}

hp_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    command -v jq   >/dev/null 2>&1 && jq_state="jq-ok"     || jq_state="jq-missing"
    printf '%s\t%s\t%s\t%s\tvectors-%s\tparams-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" \
        "$(hp_vectors | wc -l | tr -d ' ')" "$(hp_params | wc -l | tr -d ' ')"
}

hp_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

hp_cmd_help() {
    cat <<'HELP'
cloudsting module 51 — Parameter Pollution v1.0.0
  --check <url> <param> [client] [server]   every vector against one parameter
  --dup <url> <param> [client] [server]     the plain duplicate, one answer
  --split <url> [param]                     which parser class folded
  --array <url> <param>                     array syntax, and whether it lands
  --encoding <url> <param>                  the encodings proxies disagree about
  --json <url> <param> [client] [server]    body and query at the same time
  --query <url> <param> [server-value]      what the server takes unchallenged
  --smuggle <url> [param]                   the pair a front-end filter misses
  --params | --list | --status-tsv | --menu | --selftest | --help

A duplicate only matters when the answer CHANGES because of it: the control is
the parameter once, the variant is the parameter twice, and an identical hash is
reported as collapsed, never as a finding. A "honoured" verdict also carries
whether the attacker's own marker came back, because a parser can fold the
duplicate and still echo it harmlessly.

Environment: HP_TIMEOUT (10), HP_FOLLOW (0), HP_VALUE, HP_SERVER_VALUE, HP_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
hp_selftest() {
    cs_selftest_reset

    local n; n="$(hp_vectors | wc -l | tr -d ' ')"
    chk vec-many     "$( (( n >= 16 )) && echo many || echo few )" "many"
    chk vec-3col     "$(hp_vectors | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk vec-unique   "$(hp_vectors | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"
    chk vec-classes  "$(hp_vectors | awk -F'\t' '$2 !~ /^(first-wins|last-wins|join|encoding|parser-diff|array)$/{c++} END{print c+0}')" "0"
    chk vec-noclass  "$(hp_vectors | awk -F'\t' '$2==""{c++} END{print c+0}')" "0"
    chk vec-classall "$(hp_vectors | cut -f2 | sort -u | wc -l | tr -d ' ')" "6"

    chk param-count  "$(hp_params | wc -l | tr -d ' ')" "16"
    chk param-2col   "$(hp_params | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk param-msisdn "$(hp_params | awk -F'\t' '$1=="msisdn"{c++} END{print c+0}')" "1"

    # shape grammar
    chk sh-dup-last  "$(hp_shape dup-last id A S)" "id=S&id=A"
    chk sh-dup-first "$(hp_shape dup-first id A S)" "id=A&id=S"
    chk sh-bracket   "$(hp_shape array-bracket id A S)" "id=S&id[]=A"
    chk sh-comma     "$(hp_shape comma-join id A S)" "id=S,A"
    chk sh-semi      "$(hp_shape semicolon-join id A S)" "id=S;id=A"
    chk sh-amp       "$(hp_shape amp-encoded id A S)" "id=S%26id%3DA"
    chk sh-case      "$(hp_shape case-shift id A S)" "id=S&ID=A"
    chk sh-bare      "$(hp_shape bare-name id A S)" "id&id=A"
    chk sh-unknown   "$(hp_shape no-such id A S)" "id=A"

    # append grammar
    chk ap-query     "$(hp_append 'https://h/p' 'a=1')" "https://h/p?a=1"
    chk ap-joined    "$(hp_append 'https://h/p?z=0' 'a=1')" "https://h/p?z=0&a=1"

    # verdict table
    chk v-collapsed  "$(hp_verdict 200 aa 200 aa 'k' 100)" "collapsed"
    chk v-honoured   "$(hp_verdict 200 aa 200 bb 'k' 900)" "honoured"
    chk v-tiny       "$(hp_verdict 200 aa 200 bb 'k' 10)" "differs-tiny"
    chk v-unstruct   "$(hp_verdict 200 aa 200 bb '' 900)" "differs-unstructured"
    chk v-guarded    "$(hp_verdict 401 aa 403 bb '' 0)" "guarded"
    chk v-unreach    "$(hp_verdict 200 aa 000 '' '' 0)" "unreachable"
    chk v-absent     "$(hp_verdict 200 aa 404 '' '' 0)" "absent"
    chk v-nomethod   "$(hp_verdict 200 aa 405 '' '' 0)" "no-method"
    chk v-rejected   "$(hp_verdict 200 aa 400 '' '' 0)" "rejected"
    chk v-error      "$(hp_verdict 200 aa 500 '' '' 0)" "error"
    chk v-not-there  "$(hp_verdict 404 aa 200 bb 'k' 900)" "not-there"

    # case verdict
    chk cv-same      "$(hp_case_verdict 200 aa 200 aa)" "same"
    chk cv-diff      "$(hp_case_verdict 200 aa 200 bb)" "differs-same-code"
    chk cv-reach     "$(hp_case_verdict 000 aa 200 bb)" "unreachable"

    # marker detection on a real file
    local f; f="$(mktemp "$CS_SCRATCH/hp-mark.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.mark.$$"
    printf 'hello %s world\n' "$HP_VALUE" > "$f"
    chk mk-seen      "$(hp_marker_seen "$f" "$HP_VALUE")" "1"
    chk mk-absent    "$(hp_marker_seen "$f" 'not_here_at_all')" "0"
    chk mk-nofile    "$(hp_marker_seen "$f.nope" x)" "0"
    rm -f "$f"

    # a dead host must not read as a finding
    local out; out="$(hp_cmd_check http://127.0.0.1:9 msisdn 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-honour  "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{split($2,a," "); print a[1]}')" "vectors=0"
    chk dead-rc      "$(hp_cmd_check http://127.0.0.1:9 msisdn >/dev/null 2>&1; echo $?)" "3"

    # usage errors, not crashes
    hp_cmd_check 2>/dev/null;  chk chk-usage  "$?" "2"
    hp_cmd_dup 2>/dev/null;    chk dup-usage  "$?" "2"
    hp_cmd_split 2>/dev/null;  chk spl-usage  "$?" "2"
    hp_cmd_array 2>/dev/null;  chk arr-usage  "$?" "2"
    hp_cmd_encoding 2>/dev/null; chk enc-usage "$?" "2"
    hp_cmd_json 2>/dev/null;   chk jsn-usage  "$?" "2"
    hp_cmd_query 2>/dev/null;  chk qry-usage  "$?" "2"
    hp_cmd_smuggle 2>/dev/null; chk smg-usage "$?" "2"

    # shape contracts
    chk status-fields "$(hp_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(hp_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(hp_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(hp_cmd_help | head -1 | grep -ci 'Parameter Pollution')" "1"
    chk list-rows     "$(hp_cmd_list | grep -c '^VECTOR')" "$n"
    chk params-rows   "$(hp_cmd_params | grep -c '^PARAM')" "16"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --check)    shift; hp_cmd_check "$@";;
    --dup)      shift; hp_cmd_dup "$@";;
    --split)    shift; hp_cmd_split "$@";;
    --array)    shift; hp_cmd_array "$@";;
    --encoding) shift; hp_cmd_encoding "$@";;
    --json)     shift; hp_cmd_json "$@";;
    --query)    shift; hp_cmd_query "$@";;
    --smuggle)  shift; hp_cmd_smuggle "$@";;
    --list)     hp_cmd_list;;
    --params)   hp_cmd_params;;
    --status-tsv|--status) hp_cmd_status_tsv;;
    --menu)     hp_cmd_menu;;
    --selftest) hp_selftest;;
    *)          hp_cmd_help;;
esac
