#!/usr/bin/env bash
# 41_api_discovery.sh — cloudsting module 41: find the API endpoints a target forgot it was serving
# Verbs: --discover | --wordlist | --spec | --methods | --all | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# Everything below the header depends on the root, and the root is derived
# from this file only after it is sourced. Clear any inherited value first: a
# caller that itself sources the core would otherwise hand this module *its*
# directory, and the module would read its own name as a path.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV writer,
# the three-state provider gate, redaction and the selftest ledger.
MODULE_ID="41_api_discovery"
MOD_NAME="API Discovery"
MOD_VERSION="0.21.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

# this module stays loadable by another script (selftests source it)
MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

# Back-compat: this module's own run-id variable, from the one run id the core minted.
APID_RUN_ID="$CS_RUN_ID"
export APID_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

# Loot directory for this module: <root>/loot/api_discovery/
OUT_DIR="$CS_LOOT/api_discovery"
mkdir -p "$OUT_DIR" 2>/dev/null || true

# Artifacts this module writes, all under the core's loot tree.
FOUND_FILE="$OUT_DIR/found-$RUN_ID.tsv"
CANDS_FILE="$OUT_DIR/candidates-$RUN_ID.txt"
SPEC_FILE="$OUT_DIR/spec-$RUN_ID.json"

: "${AD_TIMEOUT:=8}"          # per-request wall clock, seconds
: "${AD_CONCURRENCY:=8}"      # parallel workers in --discover
: "${AD_MAX_WORDS:=0}"        # 0 = no cap on the wordlist
: "${AD_FOLLOW:=0}"           # follow redirects (0 keeps the 30x visible)
: "${AD_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/41}"

# ── helpers ──────────────────────────────────────────────────────
ad_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# One curl invocation, one line of parseable result. Everything the discovery
# logic needs from a request lives in this function, so the analysis code
# never shells out and never guesses at curl's output format.
#   ad_probe <method> <url> [body]   ->  <code>\t<len>\t<ct>\t<time_ms>\t<redirect>\t<body_file>
ad_probe() {
    local method="${1:-GET}" url="${2:-}" body="${3:-}"
    local out; out="$(mktemp "$CS_SCRATCH/hit.XXXXXX")" || return 1
    local hdr; hdr="$(mktemp "$CS_SCRATCH/hdr.XXXXXX")" || return 1

    local -a args=(
        --silent --show-error --max-time "$AD_TIMEOUT"
        --user-agent "$AD_UA"
        --output "$out" --dump-header "$hdr"
        --write-out '%{http_code}\t%{size_download}\t%{content_type}\t%{time_total}\t%{redirect_url}'
        -X "$method"
    )
    (( AD_FOLLOW )) && args+=(--location)

    if [[ -n "$body" ]]; then
        args+=(--header 'Content-Type: application/json' --data "$body")
    fi

    local meta
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)" || meta=$'\t\t\t\t'
    printf '%s\t%s\n' "$(cs_esc "$meta")" "$out"
    rm -f "$hdr"
}

# Normalise a target into a scheme://host[:port] base. Accepts what operators
# actually paste: a bare host, a host:port, a URL with a path, a URL with no
# scheme.
ad_base() {
    local t="${1:-}"
    t="${t#http://}"; t="${t#https://}"; t="${t%%/*}"; t="${t%%\?*}"
    [[ -z "$t" ]] && return 1
    printf 'https://%s' "$t"
}

# Body size class. A 404 and a catch-all 200 are the two ways an endpoint
# sweep lies: the catch-all returns 200 for everything, so the signal is not
# the code but whether the body differs from the baseline.
ad_len_class() {
    local n="${1:-0}"
    if (( n == 0 ));      then printf 'empty'
    elif (( n < 512 ));   then printf 'tiny'
    elif (( n < 4096 ));  then printf 'small'
    elif (( n < 32768 )); then printf 'medium'
    else                       printf 'large'
    fi
}

# Content-type family, provider-tagged. The family is what tells a JSON API
# from an HTML fallback page from a binary blob.
ad_ct_class() {
    local ct="${1:-}"
    ct="${ct,,}"
    case "$ct" in
        *graphql*)           printf 'graphql' ;;
        *json*)              printf 'json' ;;
        *xml*)               printf 'xml' ;;
        *text/html*)         printf 'html' ;;
        *javascript*)        printf 'js' ;;
        *plain*)             printf 'text' ;;
        *octet-stream*)      printf 'binary' ;;
        *protobuf*|*grpc*)   printf 'protobuf' ;;
        '')                  printf 'none' ;;
        *)                   printf 'other' ;;
    esac
}

# Is this URL-shaped string an API endpoint worth keeping? Rejects the
# static-asset noise a wordlist sweep drags in.
ad_is_api_path() {
    local p="${1:-}"
    case "$p" in
        *.css|*.png|*.jpg|*.jpeg|*.gif|*.svg|*.ico|*.woff|*.woff2|*.ttf|*.map) return 1 ;;
        *.js)  return 1 ;;
        */robots.txt|*/favicon.ico|*/sitemap.xml) return 1 ;;
    esac
    return 0
}

# Compare a candidate response against the baseline catch-all: same code and a
# body length within 2% means the endpoint is the fallback, not a route.
ad_is_baseline() {
    local code="$1" len="$2" bcode="$3" blen="$4"
    [[ "$code" != "$bcode" ]] && return 1
    local delta=$(( len - blen ))
    (( delta < 0 )) && delta=$(( -delta ))
    (( blen > 0 )) && (( delta * 50 <= blen )) && return 0
    (( blen == 0 && len == 0 )) && return 0
    return 1
}

# ── wordlist ─────────────────────────────────────────────────────
# The list is in the module, not in a file, so a copy of the script is a copy
# of the whole capability. Ordered by what actually shows up: the common API
# roots first, then versioned forms, then framework-specific paths.
ad_wordlist() {
    cat <<'WORDS'
/
/api
/api/v1
/api/v2
/api/v3
/api/v4
/api/v5
/api/1
/api/2
/api/2.0
/api/rest
/api/json
/api/public
/api/private
/api/internal
/api/admin
/api/user
/api/users
/api/account
/api/auth
/api/login
/api/token
/api/health
/api/status
/api/metrics
/api/docs
/api/swagger
/api/openapi.json
/api/graphql
/graphql
/graphiql
/playground
/v1
/v2
/v3
/v4
/rest
/rest/v1
/rest/v2
/rpc
/jsonrpc
/xmlrpc
/soap
/services
/endpoints
/routes
/openapi.json
/openapi.yaml
/swagger.json
/swagger.yaml
/swagger/v1/swagger.json
/api-docs
/api-docs.json
/v1/api-docs
/v2/api-docs
/swagger-ui.html
/swagger-ui/
/actuator
/actuator/health
/actuator/info
/actuator/env
/actuator/mappings
/actuator/metrics
/actuator/beans
/actuator/configprops
/actuator/heapdump
/health
/healthz
/readyz
/livez
/status
/metrics
/debug
/console
/admin
/admin/api
/internal
/private
/dev
/test
/staging
/uat
/beta
/v1/users
/v1/orders
/v1/products
/v1/accounts
/v1/customers
/v1/config
/v2/users
/v2/orders
/oauth
/oauth/token
/oauth/authorize
/auth
/auth/login
/auth/token
/auth/callback
/sso
/saml
/callback
/webhook
/webhooks
/events
/hooks
/meta
/.well-known/openapi.json
/.well-known/security.txt
/api/.well-known/openapi.json
WORDS
}

# ── discovery ────────────────────────────────────────────────────
ad_cmd_discover() {
    local target="${1:-}"
    [[ -z "$target" ]] && { printf 'usage: 41_api_discovery.sh --discover <host|url> [--base <probe-path>]\n' >&2; return 2; }
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    local base; base="$(ad_base "$target")" || { cs_row ERROR "unparseable target: $target"; return 2; }
    cs_row TARGET "$base"
    cs_row RUN_ID "$CS_RUN_ID"

    # Baseline first. A server that returns its SPA index for every path will
    # return a 200 with a constant body for a nonsense path too; measuring it
    # once makes every later comparison meaningful.
    local baseline_path="/__cloudsting_baseline_$$"
    local probe; probe="$(ad_probe GET "${base}${baseline_path}")"
    local meta="${probe%%$'\t'*}" hitfile="${probe##*$'\t'}"
    local bcode blen bct btime bredir
    cs_split "$meta" bcode blen bct btime bredir
    rm -f "$hitfile"
    cs_row BASELINE "${bcode:-0}" "${blen:-0}" "$(ad_ct_class "${bct:-}")"

    local words_file="$CS_SCRATCH/words.txt"
    ad_wordlist > "$words_file"
    if (( AD_MAX_WORDS > 0 )); then head -n "$AD_MAX_WORDS" "$words_file" > "$words_file.cut" && mv "$words_file.cut" "$words_file"; fi

    : > "$CANDS_FILE"
    : > "$FOUND_FILE"

    local -a results=()
    # Bounded fan-out. Each worker writes one line: path<TAB>code<TAB>len<TAB>ct<TAB>ms<TAB>redirect
    _ad_one() {
        local p="$1" b="$2"
        local r; r="$(ad_probe GET "${b}${p}")"
        local m="${r%%$'\t'*}" f="${r##*$'\t'}"
        local c l t tm rd
        cs_split "$m" c l t tm rd
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "${c:-0}" "${l:-0}" "${t:-}" "${tm:-0}" "${rd:-}"
        rm -f "$f"
    }
    export -f _ad_one ad_probe cs_split cs_esc ad_ct_class 2>/dev/null || true

    local running=0
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        ( _ad_one "$p" "$base" >> "$CS_SCRATCH/raw.tsv" ) &
        running=$((running + 1))
        if (( running >= AD_CONCURRENCY )); then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
    done < "$words_file"
    wait

    local total=0 kept=0
    while IFS=$'\t' read -r p c l t tm rd; do
        total=$((total + 1))
        [[ -z "$p" ]] && continue
        ad_is_api_path "$p" || continue

        # classification, in order of how much it means
        local verdict=""
        if ad_is_baseline "$c" "$l" "${bcode:-0}" "${blen:-0}"; then
            # identical to the catch-all: the route does not exist, the server
            # just answers everything
            continue
        fi
        case "$c" in
            200|201|202|204) verdict="open" ;;
            301|302|303|307|308) verdict="redirect" ;;
            401) verdict="auth" ;;
            403) verdict="forbidden" ;;
            405) verdict="exists-method" ;;
            400|422) verdict="exists-badreq" ;;
            500|502|503|504) verdict="error-leak" ;;
            *) continue ;;
        esac
        # a 200 that is the SPA's HTML shell is not an API
        local fam; fam="$(ad_ct_class "$t")"
        if [[ "$verdict" == "open" && "$fam" == "html" ]] && ! ad_looks_like_api "$p"; then
            verdict="html-shell"
        fi

        kept=$((kept + 1))
        cs_row PATH "$p" "$verdict" "$c" "$(ad_len_class "$l")" "$fam" "${rd:-}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$c" "$verdict" "$l" "$fam" "${rd:-}" >> "$FOUND_FILE"
        printf '%s\n' "$p" >> "$CANDS_FILE"
    done < "$CS_SCRATCH/raw.tsv"

    cs_row SUMMARY "$total" "$kept"
    cs_row ARTIFACT "$FOUND_FILE"
    cs_row ARTIFACT "$CANDS_FILE"

    # Feed the findings store one row per real route.
    local sev verdict
    while IFS=$'\t' read -r p c v l fam rd; do
        case "$v" in
            open)           sev="MEDIUM" ;;
            redirect)       sev="LOW" ;;
            auth)           sev="INFO" ;;
            forbidden)      sev="LOW" ;;
            exists-method)  sev="LOW" ;;
            exists-badreq)  sev="LOW" ;;
            error-leak)     sev="HIGH" ;;
            *)              continue ;;
        esac
        cs_findings_row "$MODULE_ID" "API" "$base" "$sev" "$v:$p" "${rd:-no redirect}"
    done < "$FOUND_FILE" 2>/dev/null || true

    return 0
}

# Does a path look like an API rather than a web page? Used only to keep a SPA
# shell from being recorded as an endpoint.
ad_looks_like_api() {
    local p="${1:-}"
    case "$p" in
        *api*|*v1*|*v2*|*v3*|*rest*|*graphql*|*rpc*|*json*|*openapi*|*swagger*|*actuator*) return 0 ;;
    esac
    return 1
}

# ── spec discovery ───────────────────────────────────────────────
# A spec is the whole API in one document. Finding one is worth more than a
# thousand wordlist hits, so it gets its own verb and its own confidence.
ad_cmd_spec() {
    local target="${1:-}"
    [[ -z "$target" ]] && { printf 'usage: 41_api_discovery.sh --spec <host|url>\n' >&2; return 2; }
    local base; base="$(ad_base "$target")" || return 2
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }
    command -v jq >/dev/null 2>&1 || { cs_row ERROR "missing tool: jq"; return 3; }

    cs_row TARGET "$base"
    : > "$SPEC_FILE"

    local p
    for p in /openapi.json /openapi.yaml /swagger.json /api-docs /v2/api-docs \
             /v3/api-docs /api/openapi.json /api/swagger.json /spec/openapi.json \
             /.well-known/openapi.json /swagger/v1/swagger.json; do
        local r; r="$(ad_probe GET "${base}${p}")"
        local m="${r%%$'\t'*}" f="${r##*$'\t'}"
        local c l t tm rd
        cs_split "$m" c l t tm rd
        if [[ "$c" == "200" ]] && (( ${l:-0} > 40 )); then
            # a spec parses as JSON and names its own version
            if jq -e '.openapi // .swagger // .paths' "$f" >/dev/null 2>&1; then
                local ver paths title
                ver="$(jq -r '.openapi // .swagger // "unknown"' "$f" 2>/dev/null)"
                paths="$(jq -r '.paths // {} | length' "$f" 2>/dev/null)"
                title="$(jq -r '.info.title // "-"' "$f" 2>/dev/null)"
                cs_row SPEC "$p" "$ver" "$paths" "$title"
                cp "$f" "$SPEC_FILE" 2>/dev/null || true
                cs_findings_row "$MODULE_ID" "API" "$base" "HIGH" "openapi-spec:$p" \
                    "spec v$ver exposes $paths paths"
            fi
        fi
        rm -f "$f"
    done
    [[ -s "$SPEC_FILE" ]] || cs_row SPEC "none" "-" "0" "-"
    cs_row ARTIFACT "$SPEC_FILE"
    return 0
}

# ── method matrix ────────────────────────────────────────────────
# An endpoint that 401s on GET but answers on PUT is the classic auth-gap. The
# matrix is per-path and only runs on paths discovered first.
ad_cmd_methods() {
    local target="${1:-}" path="${2:-/}"
    [[ -z "$target" ]] && { printf 'usage: 41_api_discovery.sh --methods <host|url> [path]\n' >&2; return 2; }
    local base; base="$(ad_base "$target")" || return 2
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    cs_row TARGET "$base"
    cs_row PATH "$path"
    local m
    for m in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
        local r; r="$(ad_probe "$m" "${base}${path}")"
        local meta="${r%%$'\t'*}" f="${r##*$'\t'}"
        local c l t tm rd
        cs_split "$meta" c l t tm rd
        cs_row METHOD "$m" "${c:-0}" "$(ad_len_class "${l:-0}")" "$(ad_ct_class "${t:-}")"
        # TRACE answering with 200 is a reflection bug worth naming
        if [[ "$m" == "TRACE" && "$c" == "200" ]]; then
            cs_findings_row "$MODULE_ID" "API" "$base" "HIGH" "trace-enabled:$path" "TRACE returns 200"
        fi
        if [[ "$m" == "PUT" || "$m" == "DELETE" ]] && [[ "$c" == "200" || "$c" == "204" ]]; then
            cs_findings_row "$MODULE_ID" "API" "$base" "HIGH" "write-method-open:$path" \
                "$m allowed without auth"
        fi
        rm -f "$f"
    done
    return 0
}

ad_cmd_wordlist() { ad_wordlist; }

ad_cmd_all() {
    local t="${1:-}"
    ad_cmd_discover "$t"
    ad_cmd_spec "$t"
}

ad_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    command -v jq   >/dev/null 2>&1 && jq_state="ok"   || jq_state="missing"
    printf '%s\t%s\tcurl-%s\tjq-%s\n' "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state"
}

ad_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ad_cmd_help() {
    cat <<'HELP'
cloudsting module 41 — API Discovery v0.21.0
  --discover <host|url>     sweep for API roots, spec files and debug endpoints
  --spec <host|url>         look only for OpenAPI/Swagger documents and read them
  --methods <host|url> [p]  method matrix for one path (default /)
  --wordlist                print the built-in wordlist
  --all <host|url>          discover + spec
  --status-tsv              module status
  --menu                    menu entry
  --selftest                run selftests
  --help                    this message

Baseline first: the module measures what the server returns for a nonsense
path, so a SPA that answers 200 to everything does not produce a thousand
fake endpoints. A hit is a path whose response differs from that baseline.

Environment: AD_TIMEOUT (8), AD_CONCURRENCY (8), AD_MAX_WORDS (0=all)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ad_selftest() {
    cs_selftest_reset

    # wordlist is embedded and non-trivial
    local n; n="$(ad_wordlist | wc -l)"
    chk wordlist-size "$( (( n > 60 )) && echo big || echo small )" "big"
    chk wordlist-has-graphql "$(ad_wordlist | grep -c '^/graphql$')" "1"
    chk wordlist-has-openapi "$(ad_wordlist | grep -c 'openapi')" "5"

    # target normalisation
    chk base-bare-host "$(ad_base example.com)"        "https://example.com"
    chk base-with-path  "$(ad_base example.com/x/y)"   "https://example.com"
    chk base-with-port  "$(ad_base example.com:8443)"  "https://example.com:8443"
    chk base-http-strip "$(ad_base http://a.b/c)"      "https://a.b"
    chk base-query-strip "$(ad_base a.b?x=1)"          "https://a.b"
    ad_base "" >/dev/null 2>&1; chk base-empty-rc "$?" "1"

    # content-type families
    chk ct-json  "$(ad_ct_class 'application/json; charset=utf-8')" "json"
    chk ct-gql   "$(ad_ct_class 'application/graphql-response+json')" "graphql"
    chk ct-html  "$(ad_ct_class 'text/html')" "html"
    chk ct-none  "$(ad_ct_class '')" "none"
    chk ct-proto "$(ad_ct_class 'application/grpc+proto')" "protobuf"
    chk ct-binary "$(ad_ct_class 'application/octet-stream')" "binary"

    # size classes at the boundaries
    chk len-empty "$(ad_len_class 0)"    "empty"
    chk len-tiny  "$(ad_len_class 511)"  "tiny"
    chk len-small "$(ad_len_class 512)"  "small"
    chk len-med   "$(ad_len_class 4096)" "medium"
    chk len-large "$(ad_len_class 32768)" "large"

    # baseline comparison: identical code+len is the catch-all, a 2% drift is not
    ad_is_baseline 200 1000 200 1000; chk baseline-exact "$?" "0"
    ad_is_baseline 200 1010 200 1000; chk baseline-drift "$?" "0"
    ad_is_baseline 200 2000 200 1000; chk baseline-differs "$?" "1"
    ad_is_baseline 404 0 200 0;      chk baseline-code-differs "$?" "1"
    ad_is_baseline 200 0 200 0;      chk baseline-both-empty "$?" "0"

    # noise filter
    ad_is_api_path /api/v1;      chk path-keeps-api "$?" "0"
    ad_is_api_path /style.css;   chk path-drops-css "$?" "1"
    ad_is_api_path /app.js;      chk path-drops-js  "$?" "1"
    ad_is_api_path /robots.txt;  chk path-drops-robots "$?" "1"

    # api-shaped path detector
    ad_looks_like_api /api/v2/users; chk looks-api "$?" "0"
    ad_looks_like_api /about;        chk looks-not-api "$?" "1"

    # status/menu/help shapes
    chk status-fields "$(ad_cmd_status_tsv | awk -F'\t' '{print NF}')" "4"
    chk status-module "$(ad_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ad_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ad_cmd_help | head -1 | grep -ci 'API Discovery')" "1"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --discover)   shift; ad_cmd_discover "$@";;
    --spec)       shift; ad_cmd_spec "$@";;
    --methods)    shift; ad_cmd_methods "$@";;
    --wordlist)   ad_cmd_wordlist;;
    --all)        shift; ad_cmd_all "$@";;
    --status-tsv|--status) ad_cmd_status_tsv;;
    --menu)       ad_cmd_menu;;
    --selftest)   ad_selftest;;
    *)            ad_cmd_help;;
esac
