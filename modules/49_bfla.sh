#!/usr/bin/env bash
# 49_bfla.sh — cloudsting module 49: function-level authorization — what an admin does that a customer can also do
# Verbs: --sweep | --methods | --object | --diff | --check | --functions | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own name as
# a path.
unset CS_MOD_DIR

MODULE_ID="49_bfla"
MOD_NAME="BFLA (function-level authorization across admin and customer verbs)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

BFLA_RUN_ID="$CS_RUN_ID"
export BFLA_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/bfla"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${BF_TIMEOUT:=10}"       # per-request wall clock, seconds
: "${BF_FOLLOW:=0}"         # follow redirects (0 keeps a login bounce visible)
: "${BF_LIMIT:=0}"          # 0 = every function in the table
: "${BF_UA:=Mozilla/5.0 (Linux; Android 13) cloudsting/49}"

bf_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the function table ───────────────────────────────────────────
# One row per privileged function a BSS/OSS portal exposes:
#   <function>\t<path>\t<method>\t<tier>\t<why-it-matters>
# tier is what the function is *supposed* to require:
#   customer  — a self-service verb; no leak if a customer reaches it
#   agent     — a retail-agent verb; a customer should not reach it
#   admin     — an operator verb; nobody unauthenticated should reach it
bf_functions() {
    cat <<'FUNCS'
subscribers-list	/api/admin/subscribers	GET	admin	the full subscriber base in one call
subscriber-read	/api/admin/subscriber/{id}	GET	admin	any subscriber by id
subscriber-write	/api/admin/subscriber/{id}	PUT	admin	mutate any subscriber profile
subscriber-delete	/api/admin/subscriber/{id}	DELETE	admin	terminate any line
sim-provision	/api/admin/sim/provision	POST	admin	mint a new sim against any imsi
sim-swap	/api/admin/sim/swap	POST	admin	move a number onto an attacker sim
sim-suspend	/api/admin/sim/suspend	POST	admin	deny service to any subscriber
number-port	/api/admin/port/request	POST	admin	steal a number by porting it out
balance-credit	/api/admin/balance/credit	POST	admin	write money onto any account
balance-debit	/api/admin/balance/debit	POST	admin	remove money from any account
tariff-change	/api/admin/tariff/change	POST	admin	repricing an account
invoice-read	/api/billing/invoice/{id}	GET	agent	any invoice
payment-refund	/api/billing/refund	POST	agent	refund another customer's payment
usage-adjust	/api/billing/usage/adjust	POST	admin	forgive or fabricate usage
role-assign	/api/admin/users/{id}/roles	PUT	admin	grant yourself agent or admin
user-create	/api/admin/users	POST	admin	make an account
user-reset	/api/admin/users/{id}/password	POST	admin	take over any operator login
api-key-issue	/api/admin/apikeys	POST	admin	long-lived credential mint
audit-read	/api/admin/audit	GET	admin	what the operator did, and what you did
export-dump	/api/admin/export	GET	admin	the whole customer base as a file
agents-list	/api/agent/agents	GET	agent	every retail agent
agent-verify	/api/agent/verify	POST	agent	approve an unauthorised sim registration
cdr-read	/api/cdr/{id}	GET	admin	call detail records — who called whom
sms-send	/api/sms/send	POST	agent	send as the operator
ussd-push	/api/ussd/push	POST	agent	prompt any subscriber's handset
promo-apply	/api/admin/promo/apply	POST	admin	apply credit or airtime
blacklist-read	/api/admin/blacklist	GET	admin	subscribers flagged for fraud
whitelist-write	/api/admin/whitelist	POST	admin	unblock a barred number
config-read	/api/admin/config	GET	admin	the portal's own secrets and endpoints
feature-flag	/api/admin/features	PUT	admin	turn a control on or off
FUNCS
}

# The version prefixes every portal ships. The bug is almost always that the
# old prefix answers without the guard the new one has.
bf_bases() {
    cat <<'BASES'
/api/v1
/api/v2
/api/v3
/api/admin
/api/admin/v1
/api/admin/v2
/api/agent/v1
/api/internal
/api/portal
/rest
/rest/api
/selfcare/api/v1
BASES
}

# Which verbs to add to a path when probing, per function method.
bf_probe_methods() { printf '%s\n' GET POST PUT PATCH DELETE; }

# ── one request ──────────────────────────────────────────────────
#   bf_get <method> <url> [token] [body]
#   -> <code>\t<hash>\t<len>\t<keys>\t<body-path>
bf_get() {
    local method="$1" url="$2" token="${3:-}" body_in="${4:-}"
    local body; body="$(mktemp "$CS_SCRATCH/bf.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.bf.$$"
    local -a args=(--silent --show-error --max-time "$BF_TIMEOUT" -X "$method"
                   --write-out '%{http_code}\t%{size_download}' --output "$body"
                   -A "$BF_UA" -H 'Accept: application/json, text/plain, */*')
    [[ "$BF_FOLLOW" == "1" ]] && args+=(-L)
    [[ -n "$token" ]] && args+=(-H "Authorization: Bearer $token")
    [[ -n "$body_in" ]] && args+=(-H 'Content-Type: application/json' --data "$body_in")

    local meta code len
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)" || meta=""
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code len <<<"$meta" ;;
        *) code="000"; len=0 ;;
    esac

    local keys="" hash
    [[ -s "$body" ]] || : > "$body" 2>/dev/null || true
    if head -c 1 "$body" 2>/dev/null | grep -q '[{\[]'; then
        keys="$(jq -r 'if type=="object" then (keys_unsorted | join(","))
                       elif type=="array" then "array:" + (length|tostring)
                       else "scalar" end' "$body" 2>/dev/null | head -c 400)"
    fi
    hash="$(cs_fingerprint "$(cat "$body" 2>/dev/null)")"
    # Fields are separated with U+001F, not a tab: tab is IFS whitespace, so an
    # empty middle column (a body with no JSON keys is exactly that) collapses
    # and the body path slides one field to the left.
    printf '%s\037%s\037%s\037%s\037%s\n' "${code:-000}" "$hash" "${len:-0}" "$keys" "$body"
}

# ── the verdict ──────────────────────────────────────────────────
# BFLA is not "the request succeeded". It is "the request succeeded in doing a
# thing a lower tier must not do". Three signals, in order of strength:
#   1. a successful non-GET that a read-only tier should never get (202/204/201
#      with a body that is not an error envelope)
#   2. a GET on an admin path that returns an admin-shaped object rather than
#      a login bounce or a permission denial
#   3. a method that answers anything other than 401/403/404 while its GET
#      sibling answers 401/403 — a verb that slipped the guard
#   bf_verdict <method> <tier> <code> <keys> <guard-code> <guard-keys>
bf_verdict() {
    local method="$1" tier="$2" code="$3" keys="$4" gcode="${5:-}" gkeys="${6:-}"

    case "$code" in
        000)     printf 'unreachable\ttimeout-or-refused\n'; return ;;
        401|403) printf 'guarded\tcode-%s\n' "$code"; return ;;
        404|410) printf 'absent\tno-such-function\n'; return ;;
        405)     printf 'no-method\tnethod-not-claimed\n'; return ;;
        400|415|422) printf 'rejected\tvalidation-%s\n' "$code"; return ;;
        5*)      printf 'error\tserver-%s\n' "$code"; return ;;
    esac

    case "$code" in
        200|201|202|204) ;;
        *) printf 'other\tcode-%s\n' "$code"; return ;;
    esac

    # An error envelope in a 200 is still a refusal. Portals that answer 200
    # with {"error":"unauthorized"} or {"success":false} would otherwise read
    # as a hit on every single function.
    if printf '%s' "$keys" | grep -qiE '(^|,)(error|errors|success|message|denied|unauthorized|forbidden)(,|$)'; then
        if printf '%s' "$keys" | grep -qiE '(^|,)(error|errors|success|denied|unauthorized|forbidden|message)(,|$)'; then
            printf 'refused\terror-envelope\n'; return
        fi
    fi

    if [[ -z "$keys" ]]; then
        printf 'no-structure\thtml-or-empty\n'; return
    fi

    # strength 3: this verb answers where its sibling verb does not
    if [[ -n "$gcode" && ( "$gcode" == "401" || "$gcode" == "403" ) && "$code" != 401 && "$code" != 403 ]]; then
        printf 'verb-gap\tsibling-guarded-%s\n' "$gcode"; return
    fi

    # strength 1: a write verb landed
    case "$method" in
        POST|PUT|PATCH|DELETE)
            printf 'write-allowed\t%s-%s\n' "$tier" "${keys:0:40}"; return ;;
    esac

    # strength 2: an admin-tier read returned admin-shaped data
    if [[ "$tier" == "admin" ]]; then
        if [[ "$keys" == "array:"* ]]; then
            local n="${keys#array:}"
            if (( n > 1 )); then printf 'admin-data\tarray-of-%s\n' "$n"; return; fi
        fi
        printf 'admin-data\tobject-with-guard-keys\n'
        return
    fi

    printf 'customer-ok\t%s-tier-verb\n' "$tier"
}

# ── verbs ────────────────────────────────────────────────────────
# --functions: the table, so an operator can prune it before a run.
bf_cmd_functions() {
    local fn path method tier why n=0
    while IFS=$'\t' read -r fn path method tier why; do
        [[ -z "$fn" ]] && continue
        cs_row FUNCTION "$fn" "$path" "$method" "$tier" "$why"
        n=$((n + 1))
    done < <(bf_functions)
    cs_row SUMMARY "functions=$n bases=$(bf_bases | wc -l | tr -d ' ')"
    return 0
}

# --check: one function against one base with and without a token.
#   bf_check <base> <function|path> <method> [token]
bf_cmd_check() {
    local base="${1:-}" fn="${2:-}" method="${3:-GET}" token="${4:-}"
    if [[ -z "$base" || -z "$fn" ]]; then
        bf_log "usage: --check <base-url> <function|path> <method> [bearer-token]"
        return 2
    fi

    local tier why path
    tier="$(bf_functions | awk -F'\t' -v f="$fn" '$1==f{print $4}')"
    why="$(bf_functions | awk -F'\t' -v f="$fn" '$1==f{print $5}')"
    path="$(bf_functions | awk -F'\t' -v f="$fn" '$1==f{print $2}')"
    if [[ -z "$path" ]]; then
        case "$fn" in
            /*) path="$fn"; tier="unknown"; why="explicit path" ;;
            *) bf_log "unknown function: $fn"; return 2 ;;
        esac
    fi
    path="${path//\{id\}/1}"
    local url="${base%/}${path}"

    # the sibling probe: same path, GET, so a verb that slipped its guard is
    # visible even when nothing else differs
    local gcode gkeys
    if [[ "$method" != "GET" ]]; then
        local gbody
        local -a gfld; cs_split "$(bf_get GET "$url" "$token")" gfld
        gcode="${gfld[0]:-000}"; gkeys="${gfld[3]:-}"; gbody="${gfld[4]:-}"
        rm -f "$gbody" 2>/dev/null
    fi

    local code hash len keys body
    local payload=""
    case "$method" in
        POST|PUT|PATCH) payload='{}' ;;
    esac
    local -a fld; cs_split "$(bf_get "$method" "$url" "$token" "$payload")" fld
    code="${fld[0]:-000}"; hash="${fld[1]:-}"; len="${fld[2]:-0}"; keys="${fld[3]:-}"; body="${fld[4]:-}"

    local verdict reason
    IFS=$'\t' read -r verdict reason <<<"$(bf_verdict "$method" "$tier" "$code" "$keys" "$gcode" "$gkeys")"

    cs_row TARGET "$url"
    cs_row FUNCTION "$fn" "tier=$tier" "$method"
    cs_row INTENT "${why:-unspecified}"
    cs_row RESPONSE "$code" "$len"
    cs_row SHAPE "${keys:-none}"
    cs_row VERDICT "$verdict" "$reason"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$fn" "$tier" "$method" "$url" "$code" "$verdict" "$reason" >> "$PROBE_FILE"

    case "$verdict" in
        write-allowed|admin-data|verb-gap)
            printf '%s\t%s\t%s\t%s\t%s\n' "$fn" "$method" "$url" "$verdict" "$reason" >> "$HIT_FILE"
            cs_row HIT "$fn" "$method" "$verdict" "$reason"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "CRITICAL" "function-authorization" \
                "$method $fn ($tier tier) answered $code: $why ($verdict)"
            rm -f "$body" 2>/dev/null
            return 0 ;;
    esac
    rm -f "$body" 2>/dev/null
    return 1
}

# --sweep: the run. Every base, every function, its own method, plus a GET on
# the same path so a verb gap is caught even when the declared method is
# guarded.
bf_cmd_sweep() {
    local base="${1:-}" token="${2:-}"
    [[ -z "$base" ]] && { bf_log "usage: --sweep <base-url|host> [bearer-token]"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    : > "$PROBE_FILE"
    local hits=0 checked=0
    local -a bases; mapfile -t bases < <(bf_bases)
    local b fn path method tier why
    for b in "${bases[@]}"; do
        while IFS=$'\t' read -r fn path method tier why; do
            [[ -z "$fn" ]] && continue
            (( BF_LIMIT > 0 && checked >= BF_LIMIT )) && break
            checked=$((checked + 1))
            if bf_cmd_check "${base%/}$b" "$fn" "$method" "$token" >/dev/null 2>&1; then
                hits=$((hits + 1))
                cs_row LEAK "$fn" "$method" "${base%/}$b"
            fi
        done < <(bf_functions)
    done

    cs_row SUMMARY "checked=$checked hits=$hits"
    [[ "$hits" -gt 0 ]] && cs_row ARTIFACT "$HIT_FILE"
    return 0
}

# --compare: the whole point of the session pair. Run the same sweep twice,
# once with a customer token and once with an agent token, and the functions
# that answer to both are the finding. Two artifacts, one intersection.
#   bf_cmd_compare <base> <customer-token> <agent-token>
bf_cmd_compare() {
    local base="${1:-}" cust="${2:-}" agent="${3:-}"
    if [[ -z "$base" || -z "$cust" || -z "$agent" ]]; then
        bf_log "usage: --compare <base-url> <customer-token> <agent-token>"
        return 2
    fi

    local cfile="$OUT_DIR/compare-customer-$RUN_ID.tsv"
    local afile="$OUT_DIR/compare-agent-$RUN_ID.tsv"
    : > "$cfile"; : > "$afile"

    local fn path method tier why
    while IFS=$'\t' read -r fn path method tier why; do
        [[ -z "$fn" ]] && continue
        [[ "$tier" == "customer" ]] && continue

        local url="${base%/}${path//\{id\}/1}"
        local ccode chash clen ckeys cbody acode ahash alen akeys abody
        local -a cfld afld
        cs_split "$(bf_get "$method" "$url" "$cust" '{}')" cfld
        cs_split "$(bf_get "$method" "$url" "$agent" '{}')" afld
        ccode="${cfld[0]:-000}"; ckeys="${cfld[3]:-}"; cbody="${cfld[4]:-}"
        acode="${afld[0]:-000}"; akeys="${afld[3]:-}"; abody="${afld[4]:-}"
        rm -f "$cbody" "$abody" 2>/dev/null

        printf '%s\t%s\t%s\t%s\n' "$fn" "$tier" "$method" "$ccode" >> "$cfile"
        printf '%s\t%s\t%s\t%s\n' "$fn" "$tier" "$method" "$acode" >> "$afile"

        # the finding: the customer token reaches a function the agent token
        # also reaches, and the response is not a refusal envelope
        case "$ccode" in
            200|201|202|204) ;;
            *) continue ;;
        esac
        case "$acode" in
            200|201|202|204) ;;
            *) continue ;;
        esac
        if printf '%s' "$ckeys" | grep -qiE '(^|,)error(,|$)'; then continue; fi

        cs_row ESCALATION "$fn" "$tier" "$method" "customer-$ccode/agent-$acode"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "HIGH" "function-escalation" \
            "$fn ($tier) answers to a customer token and an agent token alike"
    done < <(bf_functions)

    cs_row ARTIFACT "$cfile" "$afile"
    return 0
}

# --methods: method matrix on one path. Cheap, and it is how the "GET is
# guarded but PUT is not" class gets caught before a full sweep.
bf_cmd_methods() {
    local base="${1:-}" path="${2:-/}" token="${3:-}"
    [[ -z "$base" ]] && { bf_log "usage: --methods <base-url> [path] [token]"; return 2; }
    local url="${base%/}${path}"
    local m code hash len keys body verdict reason
    for m in $(bf_probe_methods); do
        local -a mfld; cs_split "$(bf_get "$m" "$url" "$token" '{}')" mfld
        code="${mfld[0]:-000}"; len="${mfld[2]:-0}"; keys="${mfld[3]:-}"; body="${mfld[4]:-}"
        rm -f "$body" 2>/dev/null
        IFS=$'\t' read -r verdict reason <<<"$(bf_verdict "$m" admin "$code" "$keys")"
        cs_row METHOD "$m" "$code" "$len" "$verdict" "${keys:0:80}"
    done
    return 0
}

# --object: the BFLA twin of BOLA. Same object path, two different sessions,
# and the question is whether the object verb is scoped at all.
#   bf_cmd_object <base> <path-template> <id> <token-a> <token-b>
bf_cmd_object() {
    local base="${1:-}" tmpl="${2:-}" id="${3:-}" ta="${4:-}" tb="${5:-}"
    if [[ -z "$base" || -z "$tmpl" || -z "$id" ]]; then
        bf_log "usage: --object <base-url> <path-with-{id}> <id> <token-a> [token-b]"
        return 2
    fi
    local url="${base%/}${tmpl//\{id\}/$id}"
    local m code hash len keys body
    for m in $(bf_probe_methods); do
        local -a ofld
        cs_split "$(bf_get "$m" "$url" "$ta" '{}')" ofld
        code="${ofld[0]:-000}"; len="${ofld[2]:-0}"; keys="${ofld[3]:-}"; body="${ofld[4]:-}"
        rm -f "$body" 2>/dev/null
        cs_row "A-$m" "$code" "$len" "${keys:0:80}"
        if [[ -n "$tb" ]]; then
            cs_split "$(bf_get "$m" "$url" "$tb" '{}')" ofld
            code="${ofld[0]:-000}"; len="${ofld[2]:-0}"; keys="${ofld[3]:-}"; body="${ofld[4]:-}"
            rm -f "$body" 2>/dev/null
            cs_row "B-$m" "$code" "$len" "${keys:0:80}"
        fi
    done
    return 0
}

bf_cmd_list() {
    local fn path method tier why
    while IFS=$'\t' read -r fn path method tier why; do
        [[ -z "$fn" ]] && continue
        printf '%s\t%s\t%s\t%s\n' "$fn" "$tier" "$method" "$path"
    done < <(bf_functions)
    return 0
}

bf_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    command -v jq   >/dev/null 2>&1 && jq_state="ok"   || jq_state="missing"
    printf '%s\t%s\tcurl-%s\tjq-%s\tfunctions-%s\tbases-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" \
        "$(bf_functions | wc -l | tr -d ' ')" "$(bf_bases | wc -l | tr -d ' ')"
}

bf_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

bf_cmd_help() {
    cat <<'HELP'
cloudsting module 49 — BFLA v1.0.0
  --check <base> <function|path> <method> [token]  one function, one verdict
  --sweep <base> [token]                           every base × every function
  --compare <base> <customer-tok> <agent-tok>      the escalation intersection
  --methods <base> [path] [token]                  method matrix on one path
  --object <base> <path-{id}> <id> <tokA> [tokB]   object verb across sessions
  --functions                                      the function table
  --list | --status-tsv | --menu | --selftest | --help

A hit is a privileged function that answered a lower tier: a write verb that
landed, an admin path that returned admin-shaped data, or a verb that answers
while its GET sibling is 401/403. A 200 carrying {"error":...} or
{"success":false} is a refusal, not a hit — portals that envelope their
errors would otherwise light up every function on the page.

Tiers: customer (self-service), agent (retail agent), admin (operator).
31 functions across subscriber, sim, balance, billing, user, agent, cdr,
sms, ussd, audit, export and config families.

Environment: BF_TIMEOUT (10), BF_FOLLOW (0), BF_LIMIT (0=all), BF_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
bf_selftest() {
    cs_selftest_reset

    local n; n="$(bf_functions | wc -l | tr -d ' ')"
    chk functions-many   "$( (( n >= 28 )) && echo many || echo few )" "many"
    chk functions-5col   "$(bf_functions | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk functions-path   "$(bf_functions | awk -F'\t' '$2 !~ /^\//{c++} END{print c+0}')" "0"
    chk functions-unique "$(bf_functions | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"
    chk functions-tier   "$(bf_functions | awk -F'\t' '$4 !~ /^(customer|agent|admin)$/{c++} END{print c+0}')" "0"
    chk functions-why    "$(bf_functions | awk -F'\t' '$5==""{c++} END{print c+0}')" "0"
    chk functions-verb   "$(bf_functions | awk -F'\t' '$3 !~ /^(GET|POST|PUT|PATCH|DELETE)$/{c++} END{print c+0}')" "0"
    chk bases-many       "$( (( $(bf_bases | wc -l) >= 10 )) && echo many || echo few )" "many"
    chk bases-path       "$(bf_bases | awk '$1 !~ /^\//{c++} END{print c+0}')" "0"

    # every write verb in the table is a tier above customer — a customer-tier
    # write would make the whole module blind to its own case
    chk no-customer-write "$(bf_functions | awk -F'\t' '$3!="GET" && $4=="customer"{c++} END{print c+0}')" "0"

    local fn
    for fn in subscriber-write role-assign user-reset sim-swap; do
        chk "has-$fn" "$(bf_functions | cut -f1 | grep -cx "$fn")" "1"
    done

    # the verdict, on synthetic answers
    chk v-unreach    "$(bf_verdict GET admin 000 '' | cut -f1)" "unreachable"
    chk v-guarded    "$(bf_verdict GET admin 403 'id' | cut -f1)" "guarded"
    chk v-guarded401 "$(bf_verdict POST admin 401 'id' | cut -f1)" "guarded"
    chk v-absent     "$(bf_verdict GET admin 404 '' | cut -f1)" "absent"
    chk v-nomethod   "$(bf_verdict PUT admin 405 '' | cut -f1)" "no-method"
    chk v-validation "$(bf_verdict POST admin 422 'errors' | cut -f1)" "rejected"
    chk v-server     "$(bf_verdict POST admin 500 '' | cut -f1)" "error"
    chk v-envelope   "$(bf_verdict GET admin 200 'error' | cut -f1)" "refused"
    chk v-envelope-s "$(bf_verdict POST admin 200 'success' | cut -f1)" "refused"
    chk v-html       "$(bf_verdict GET admin 200 '' | cut -f1)" "no-structure"
    chk v-write      "$(bf_verdict POST admin 200 'id,status' | cut -f1)" "write-allowed"
    chk v-write-put  "$(bf_verdict PUT admin 204 '' | cut -f1)" "no-structure"
    chk v-write-del  "$(bf_verdict DELETE agent 200 'ok' | cut -f1)" "write-allowed"
    chk v-admin-arr  "$(bf_verdict GET admin 200 'array:9' | cut -f1)" "admin-data"
    chk v-admin-obj  "$(bf_verdict GET admin 200 'id,msisdn' | cut -f1)" "admin-data"
    chk v-admin-one  "$(bf_verdict GET admin 200 'array:1' | cut -f1)" "admin-data"
    chk v-cust-ok    "$(bf_verdict GET customer 200 'id,plan' | cut -f1)" "customer-ok"
    chk v-verb-gap   "$(bf_verdict PUT admin 200 'id' 403 'id' | cut -f1)" "verb-gap"
    chk v-gap-noguard "$(bf_verdict PUT admin 200 'id' 200 'id' | cut -f1)" "write-allowed"

    # usage errors, not crashes
    local rc
    bf_cmd_check 2>/dev/null; rc=$?
    chk check-usage   "$rc" "2"
    bf_cmd_sweep 2>/dev/null; rc=$?
    chk sweep-usage   "$rc" "2"
    bf_cmd_compare 2>/dev/null; rc=$?
    chk compare-usage "$rc" "2"
    bf_cmd_methods 2>/dev/null; rc=$?
    chk methods-usage "$rc" "2"
    bf_cmd_object 2>/dev/null; rc=$?
    chk object-usage  "$rc" "2"
    bf_cmd_check http://127.0.0.1:9 nosuchfn GET 2>/dev/null; rc=$?
    chk check-unknown "$rc" "2"

    # a dead host is unreachable and never a hit
    local out
    out="$(bf_cmd_check http://127.0.0.1:9 subscriber-write POST 2>/dev/null)"
    chk dead-unreach "$(printf '%s' "$out" | grep -c 'unreachable')" "1"
    chk dead-nohit   "$(printf '%s' "$out" | grep -c '^HIT')" "0"

    # an explicit path still works, and is marked unknown-tier
    out="$(bf_cmd_check http://127.0.0.1:9 /api/admin/whatever GET 2>/dev/null)"
    chk explicit-tier "$(printf '%s' "$out" | awk -F'\t' '$1=="FUNCTION"{print $3}')" "tier=unknown"

    # shape contracts
    chk status-fields "$(bf_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(bf_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(bf_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(bf_cmd_help | head -1 | grep -ci 'BFLA')" "1"
    chk list-fields   "$(bf_cmd_list | awk -F'\t' '{print NF}' | sort -u | tr '\n' ' ')" "4 "
    chk methods-all   "$(bf_probe_methods | wc -l | tr -d ' ')" "5"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --check)     shift; bf_cmd_check "$@";;
    --sweep)     shift; bf_cmd_sweep "$@";;
    --compare)   shift; bf_cmd_compare "$@";;
    --methods)   shift; bf_cmd_methods "$@";;
    --object)    shift; bf_cmd_object "$@";;
    --functions) bf_cmd_functions;;
    --list)      bf_cmd_list;;
    --status-tsv|--status) bf_cmd_status_tsv;;
    --menu)      bf_cmd_menu;;
    --selftest)  bf_selftest;;
    *)           bf_cmd_help;;
esac
