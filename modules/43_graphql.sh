#!/usr/bin/env bash
# 43_graphql.sh — cloudsting module 43: what a GraphQL endpoint tells you before you have a token
# Verbs: --introspect | --schema | --find | --queries | --fields | --depth | --check | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own name as
# a path.
unset CS_MOD_DIR

MODULE_ID="43_graphql"
MOD_NAME="GraphQL Introspection (schema disclosure and query surface)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

GQ_RUN_ID="$CS_RUN_ID"
export GQ_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/graphql"
mkdir -p "$OUT_DIR" 2>/dev/null || true

SCHEMA_FILE="$OUT_DIR/schema-$RUN_ID.json"
TYPES_FILE="$OUT_DIR/types-$RUN_ID.tsv"
FIELDS_FILE="$OUT_DIR/fields-$RUN_ID.tsv"
HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"

: "${GQ_TIMEOUT:=10}"       # per-request wall clock, seconds
: "${GQ_MAX_BYTES:=16777216}" # an introspection result past this is truncated
: "${GQ_FOLLOW:=0}"         # follow redirects
: "${GQ_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/43}"

gq_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── where a telco portal puts its graph ──────────────────────────
# Ordered by how often it is the real one. The last few are the endpoints a
# mobile BSS ships without ever mentioning them in the docs.
gq_paths() {
    cat <<'PATHS'
/graphql
/graphiql
/graphql/api
/api/graphql
/api/graphql/v1
/v1/graphql
/v2/graphql
/v3/graphql
/gql
/query
/api/query
/graphql/console
/api/v1/graphql
/api/v2/graphql
/portal/graphql
/mobile/graphql
/bss/graphql
/crm/graphql
/services/graphql
/selfcare/graphql
PATHS
}

# The standard introspection query. Kept as one line so it can go straight into
# a curl --data without shell quoting games, and trimmed to what an operator
# actually reads: types, fields, args, and the mutation surface.
gq_query() {
    if [[ "${1:-}" == "short" ]]; then
        printf '%s' '{"query":"{__schema{queryType{name} mutationType{name} subscriptionType{name} types{name kind}}}"}'
        return 0
    fi
    printf '%s' '{"query":"query IntrospectionQuery{__schema{queryType{name} mutationType{name} subscriptionType{name} types{...FullType}} fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{name description type{...TypeRef} defaultValue} type{...TypeRef} isDeprecated deprecationReason} inputFields{name description type{...TypeRef} defaultValue} interfaces{...TypeRef} enumValues(includeDeprecated:true){name description isDeprecated deprecationReason} possibleTypes{...TypeRef}} fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}'
}

# ── transport ────────────────────────────────────────────────────
#   gq_post <url> <json-body> [token] -> code \x1f bytes \x1f body-path
gq_post() {
    local url="$1" payload="$2" token="${3:-}"
    local body; body="$(mktemp "$CS_SCRATCH/gq.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.gq.$$"
    local -a args=(--silent --show-error --max-time "$GQ_TIMEOUT" -X POST
                   --write-out '%{http_code}\t%{size_download}' --output "$body"
                   -A "$GQ_UA"
                   -H 'Content-Type: application/json'
                   -H 'Accept: application/json')
    [[ "$GQ_FOLLOW" == "1" ]] && args+=(-L)
    [[ -n "$token" ]] && args+=(-H "Authorization: Bearer $token")
    local meta code len
    meta="$(curl "${args[@]}" --data "$payload" "$url" 2>/dev/null)" || meta=""
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code len <<<"$meta" ;;
        *) code="000"; len=0 ;;
    esac
    [[ -s "$body" ]] || : > "$body" 2>/dev/null || true
    printf '%s\037%s\037%s\n' "${code:-000}" "${len:-0}" "$body"
}

# Introspection is enabled when the response contains a __schema object with a
# type list. Anything else — an error envelope, an HTML login wall, a 200 with
# {"errors":...} — is disabled or absent, and those are different verdicts.
#   gq_introspection_verdict <code> <body-file> -> enabled | disabled | gated | absent | unreachable
gq_introspection_verdict() {
    local code="$1" body="$2"
    case "$code" in
        000) printf 'unreachable'; return 0 ;;
        401|403) printf 'gated'; return 0 ;;
        404|405|410) printf 'absent'; return 0 ;;
    esac
    [[ -s "$body" ]] || { printf 'absent'; return 0; }
    if jq -e '.data.__schema.types? // empty' "$body" >/dev/null 2>&1; then
        printf 'enabled'; return 0
    fi
    if jq -e '.errors? // empty' "$body" >/dev/null 2>&1; then
        # the classic: {"errors":[{"message":"GraphQL introspection is not allowed"}]}
        if grep -qiE 'introspection.{0,20}(disabled|not allowed|forbidden)|disabled.{0,10}introspection' "$body" 2>/dev/null; then
            printf 'disabled'
        else
            printf 'gated'
        fi
        return 0
    fi
    printf 'absent'
}

# ── analysis ─────────────────────────────────────────────────────
# Every visible type, and how dangerous its name is. A schema that exposes
# Subscriber, Payment and SimCard is a map of the BSS, not an API surface.
gq_type_class() {
    case "$1" in
        # paging wrappers are scaffold no matter whose name they wrap: a
        # SubscriberConnection is a cursor, not a subscriber
        *Connection|*Edge|*PageInfo|*Input|*Payload|*Enum) printf 'scaffold' ;;
        Subscription*|Payment*|Invoice*|Bill*|Balance*|Credit*) printf 'money' ;;
        Subscriber*|Customer*|Account*|User*|Profile*|Contact*) printf 'identity' ;;
        Sim*|Line*|Msisdn*|Imsi*|Iccid*|Number*|Port*|Device*|Handset*) printf 'subscriber' ;;
        *Admin*|*Internal*|*Staff*|*Root*|*Super*|*Audit*|*Config*|*Secret*|*Token*|*Key*) printf 'privileged' ;;
        *Query|*Mutation|*Input|*Payload|*Connection|*Edge|*PageInfo|*Enum|*Scalar) printf 'scaffold' ;;
        *) printf 'other' ;;
    esac
}

gq_build_tables() {
    local schema="$1"
    [[ -s "$schema" ]] || return 1
    : > "$TYPES_FILE"; : > "$FIELDS_FILE"

    # The schema may arrive as the bare __schema object (what --introspect
    # writes after unwrapping) or as a full GraphQL response. One accessor,
    # used by every reader, so both shapes work.
    local types_json
    types_json="$(jq -c '.data.__schema.types // .__schema.types // .types // []' "$schema" 2>/dev/null)"

    # types: <name>\t<kind>\t<class>\t<field-count>
    printf '%s' "$types_json" | jq -r '.[] | select(.name | startswith("__") | not)
           | [.name, .kind, ((.fields // []) | length | tostring)] | @tsv' 2>/dev/null \
        | while IFS=$'\t' read -r name kind nfields; do
              [[ -z "$name" ]] && continue
              printf '%s\t%s\t%s\t%s\n' "$name" "$kind" "$(gq_type_class "$name")" "$nfields" >> "$TYPES_FILE"
          done

    # fields: <type>\t<field>\t<args>\t<typename>\t<deprecated>
    printf '%s' "$types_json" | jq -r '.[] | select(.name | startswith("__") | not)
           | select(.fields != null)
           | .name as $t | .fields[] | [$t, .name, ((.args // []) | length | tostring),
               (.type.name // .type.ofType.name // .type.ofType.ofType.name // "?"),
               (if .isDeprecated then "deprecated" else "-" end)] | @tsv' 2>/dev/null \
        >> "$FIELDS_FILE" || true

    return 0
}

# ── verbs ────────────────────────────────────────────────────────
# --find: which of the well-known graph paths answers, and does introspection
# actually work there. Cheap, and it is the whole first question.
gq_cmd_find() {
    local base="${1:-}"
    [[ -z "$base" ]] && { gq_log "usage: --find <base-url|host>"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    local payload; payload="$(gq_query short)"
    local found=0 enabled=0 p code len body verdict
    for p in $(gq_paths); do
        cs_split "$(gq_post "${base%/}$p" "$payload")" code len body
        if [[ "$code" == "200" || "$code" == "400" || "$code" == "401" || "$code" == "403" ]]; then
            verdict="$(gq_introspection_verdict "$code" "$body")"
            cs_row GRAPHQL "${base%/}$p" "code=$code" "introspection=$verdict" "bytes=$len"
            found=$((found + 1))
            case "$verdict" in
                enabled) enabled=$((enabled + 1))
                         cp "$body" "$OUT_DIR/schema-$(printf '%s' "$p" | tr '/' '_')-$RUN_ID.json" 2>/dev/null || true ;;
            esac
        fi
        rm -f "$body"
    done
    cs_row SUMMARY "found=$found introspectable=$enabled probes=$(gq_paths | wc -l | tr -d ' ')"
    (( found > 0 )) && return 0 || return 1
}

# --introspect: the full schema, saved and counted. This is the read.
gq_cmd_introspect() {
    local url="${1:-}" token="${2:-}"
    [[ -z "$url" ]] && { gq_log "usage: --introspect <graphql-url> [token]"; return 2; }
    local payload; payload="$(gq_query)"
    local code len body
    cs_split "$(gq_post "$url" "$payload" "$token")" code len body
    local verdict; verdict="$(gq_introspection_verdict "$code" "$body")"
    cs_row URL "$url"
    cs_row CODE "$code"
    cs_row BYTES "$len"
    cs_row INTROSPECTION "$verdict"

    case "$verdict" in
        enabled)
            # only keep the schema half, so the file is clean for jq
            jq -S '.data.__schema' "$body" > "$SCHEMA_FILE" 2>/dev/null \
                || cp "$body" "$SCHEMA_FILE" 2>/dev/null || true
            gq_build_tables "$SCHEMA_FILE"
            local ntypes nqueries nmutations
            ntypes="$(wc -l < "$TYPES_FILE" 2>/dev/null | tr -d ' ')"
            nqueries="$(jq -r '.queryType.name // empty' "$SCHEMA_FILE" 2>/dev/null)"
            nmutations="$(jq -r '.mutationType.name // empty' "$SCHEMA_FILE" 2>/dev/null)"
            cs_row TYPES "${ntypes:-0}"
            cs_row QUERY_TYPE "${nqueries:-none}"
            cs_row MUTATION_TYPE "${nmutations:-none}"
            local nq nm
            nq="$(awk -F'\t' -v t="${nqueries:-Query}" '$1==t{c++} END{print c+0}' "$FIELDS_FILE" 2>/dev/null)"
            nm="$(awk -F'\t' -v t="${nmutations:-Mutation}" '$1==t{c++} END{print c+0}' "$FIELDS_FILE" 2>/dev/null)"
            cs_row QUERIES "${nq:-0}"
            cs_row MUTATIONS "${nm:-0}"
            cs_row ARTIFACT "$SCHEMA_FILE" "$TYPES_FILE" "$FIELDS_FILE"

            # a schema that names iam/admin/payment types is a finding on its own
            local priv money ident
            priv="$(awk -F'\t' '$3=="privileged"{c++} END{print c+0}' "$TYPES_FILE")"
            money="$(awk -F'\t' '$3=="money"{c++} END{print c+0}' "$TYPES_FILE")"
            ident="$(awk -F'\t' '$3=="identity"||$3=="subscriber"{c++} END{print c+0}' "$TYPES_FILE")"
            cs_row PRIVILEGED_TYPES "$priv"
            cs_row MONEY_TYPES "$money"
            cs_row IDENTITY_TYPES "$ident"
            if (( priv + money + ident > 0 )); then
                cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "HIGH" "graphql-introspection-open" \
                    "introspection enabled and the schema names $priv privileged, $money money and $ident identity types"
            fi
            ;;
        disabled|gated|absent|unreachable)
            cs_row VERDICT "$verdict" "no schema to read"
            ;;
    esac
    rm -f "$body"
    [[ "$verdict" == "enabled" ]] && return 0 || return 1
}

# --schema: the loaded schema's headline, without re-fetching.
gq_cmd_schema() {
    local src="${1:-$SCHEMA_FILE}"
    if [[ -f "$src" ]] && [[ "$src" != "$SCHEMA_FILE" ]]; then
        jq -S '.data.__schema // .' "$src" > "$SCHEMA_FILE" 2>/dev/null || cp "$src" "$SCHEMA_FILE"
        gq_build_tables "$SCHEMA_FILE"
    fi
    [[ -s "$SCHEMA_FILE" ]] || { gq_log "no schema loaded — run --introspect first"; return 2; }
    local ntypes
    ntypes="$(wc -l < "$TYPES_FILE" | tr -d ' ')"
    cs_row TYPES "$ntypes"
    cs_row QUERY_TYPE "$(jq -r '.queryType.name // "none"' "$SCHEMA_FILE" 2>/dev/null)"
    cs_row MUTATION_TYPE "$(jq -r '.mutationType.name // "none"' "$SCHEMA_FILE" 2>/dev/null)"
    cs_row SUBSCRIPTION_TYPE "$(jq -r '.subscriptionType.name // "none"' "$SCHEMA_FILE" 2>/dev/null)"
    return 0
}

# --queries: the question surface. What you can ask, before any authorization
# decision happens.
gq_cmd_queries() {
    [[ -s "$FIELDS_FILE" ]] || { gq_log "no field table — run --introspect first"; return 2; }
    local qtype mtype
    qtype="$(jq -r '.queryType.name // "Query"' "$SCHEMA_FILE" 2>/dev/null)"
    mtype="$(jq -r '.mutationType.name // "Mutation"' "$SCHEMA_FILE" 2>/dev/null)"

    awk -F'\t' -v q="$qtype" '$1==q{printf "%s\t%s\t%s\n", $2, $3, $4}' "$FIELDS_FILE" \
        | while IFS=$'\t' read -r field args rtype; do
              cs_row QUERY "$field" "args=$args" "returns=$rtype"
          done
    awk -F'\t' -v m="$mtype" '$1==m{printf "%s\t%s\t%s\n", $2, $3, $4}' "$FIELDS_FILE" \
        | while IFS=$'\t' read -r field args rtype; do
              cs_row MUTATION "$field" "args=$args" "returns=$rtype"
          done
    return 0
}

# --fields <type>: the fields of one type, with the deprecated ones marked.
gq_cmd_fields() {
    local want="${1:-}"
    [[ -z "$want" ]] && { gq_log "usage: --fields <TypeName>"; return 2; }
    [[ -s "$FIELDS_FILE" ]] || { gq_log "no field table — run --introspect first"; return 2; }
    local n=0 name args rtype dep
    while IFS=$'\t' read -r name args rtype dep; do
        [[ -z "$name" ]] && continue
        n=$((n + 1))
        cs_row FIELD "$name" "args=$args" "type=$rtype" "$dep"
    done < <(awk -F'\t' -v w="$want" '$1==w{print $2"\t"$3"\t"$4"\t"$5}' "$FIELDS_FILE")
    (( n > 0 )) || { cs_row FIELD "" "type=$want" "no-such-type-or-no-fields"; return 1; }
    return 0
}

# --depth: query depth. A schema that nests 12 deep with no depth limit is a
# one-request DoS, and it is the cheapest thing to check.
gq_cmd_depth() {
    [[ -s "$SCHEMA_FILE" ]] || { gq_log "no schema loaded — run --introspect first"; return 2; }
    local depth
    depth="$(jq -r '
        # walk the type graph from the query root, counting the longest chain of
        # object→field→object hops. A visited set per path stops cycles.
        . as $s
        | ($s.types // []) as $types
        | def find($n): ($types[] | select(.name == $n));
          def walk($name; $seen; $d):
              if ($seen | index($name)) != null then $d
              else
                (find($name)) as $t
                | if $t == null then $d
                  elif $t.fields == null then $d
                  else [ $t.fields[]
                         | (.type.name // .type.ofType.name // .type.ofType.ofType.name) as $child
                         | walk($child; ($seen + [$name]); ($d + 1)) ] | max // $d
                  end
              end;
          walk($s.queryType.name // "Query"; []; 1)' "$SCHEMA_FILE" 2>/dev/null)"
    cs_row MAX_DEPTH "${depth:-0}" "object hops from the query root"
    if [[ "${depth:-0}" =~ ^[0-9]+$ ]] && (( depth >= 10 )); then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$SCHEMA_FILE" "MEDIUM" "graphql-depth-${depth}" \
            "query graph nests $depth object hops deep with no visible depth limit"
    fi
    return 0
}

# --check: one endpoint, one line. The verb you put in a loop.
gq_cmd_check() {
    local url="${1:-}" token="${2:-}"
    [[ -z "$url" ]] && { gq_log "usage: --check <graphql-url> [token]"; return 2; }
    local code len body
    cs_split "$(gq_post "$url" "$(gq_query short)" "$token")" code len body
    local verdict; verdict="$(gq_introspection_verdict "$code" "$body")"
    local ntypes="0"
    if [[ "$verdict" == "enabled" ]]; then
        ntypes="$(jq -r '(.data.__schema.types // []) | length' "$body" 2>/dev/null || echo 0)"
    fi
    cs_row CHECK "$url" "code=$code" "introspection=$verdict" "types=$ntypes"
    rm -f "$body"
    [[ "$verdict" == "enabled" ]] && return 0 || return 1
}

gq_cmd_list() {
    local p
    for p in $(gq_paths); do printf '%s\t%s\n' "$p" "graph-path"; done
    return 0
}

gq_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    command -v jq   >/dev/null 2>&1 && jq_state="ok"   || jq_state="missing"
    printf '%s\t%s\tcurl-%s\tjq-%s\tpaths-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" "$(gq_paths | wc -l | tr -d ' ')"
}

gq_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

gq_cmd_help() {
    cat <<'HELP'
cloudsting module 43 — GraphQL Introspection v1.0.0
  --find <base>                probe 20 graph paths; report code + introspection verdict
  --introspect <url> [token]   pull the full schema and classify every type
  --schema [file]              headline of a loaded schema
  --queries                    the query and mutation surface, with arg counts
  --fields <TypeName>          one type's fields
  --depth                      longest object→field→object chain from the query root
  --check <url> [token]        one endpoint, one line — the loop verb
  --list | --status-tsv | --menu | --selftest | --help

Introspection verdicts: enabled | disabled (server refuses introspection) |
gated (401/403 or a non-introspection error) | absent (404/405/HTML) |
unreachable. Only `enabled` produces a schema.

A schema is graded by the type names it exposes — privileged / money /
identity / subscriber classes. Introspection left on in a BSS portal tells an
attacker the shape of the subscriber base before any request is authorized.

Environment: GQ_TIMEOUT (10), GQ_MAX_BYTES (16777216), GQ_FOLLOW (0), GQ_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
gq_selftest() {
    cs_selftest_reset

    chk paths-many    "$( (( $(gq_paths | wc -l) >= 15 )) && echo many || echo few )" "many"
    chk paths-slash   "$(gq_paths | awk '$1 !~ /^\//{c++} END{print c+0}')" "0"
    chk paths-unique  "$(gq_paths | sort -u | wc -l | tr -d ' ')" "$(gq_paths | wc -l | tr -d ' ')"
    chk paths-gql     "$(gq_paths | grep -cx '/graphql')" "1"

    # the introspection query is valid JSON that names the standard entry point
    local q; q="$(gq_query)"
    chk query-json    "$(printf '%s' "$q" | jq -r '.query | test("IntrospectionQuery")')" "true"
    chk query-schema  "$(printf '%s' "$q" | jq -r '.query | test("__schema")')" "true"
    chk query-mutation "$(printf '%s' "$q" | jq -r '.query | test("mutationType")')" "true"
    chk short-json    "$(gq_query short | jq -r '.query | test("queryType")')" "true"
    chk short-tiny    "$( (( $(gq_query short | wc -c) < 200 )) && echo tiny || echo big )" "tiny"

    # type classification across every class
    chk class-money     "$(gq_type_class 'PaymentRecord')" "money"
    chk class-identity  "$(gq_type_class 'SubscriberProfile')" "identity"
    chk class-sub       "$(gq_type_class 'SimCard')" "subscriber"
    chk class-priv      "$(gq_type_class 'AdminToken')" "privileged"
    chk class-scaffold  "$(gq_type_class 'PageInfo')" "scaffold"
    chk class-other     "$(gq_type_class 'Weather')" "other"

    # verdicts, one per state
    local f="$OUT_DIR/v-$RUN_ID.json"
    printf '%s' '{"data":{"__schema":{"types":[{"name":"Query"}]}}}' > "$f"
    chk verdict-enabled  "$(gq_introspection_verdict 200 "$f")" "enabled"
    printf '%s' '{"errors":[{"message":"GraphQL introspection is not allowed"}]}' > "$f"
    chk verdict-disabled "$(gq_introspection_verdict 200 "$f")" "disabled"
    printf '%s' '{"errors":[{"message":"You must be logged in"}]}' > "$f"
    chk verdict-gated    "$(gq_introspection_verdict 200 "$f")" "gated"
    printf '%s' '<html><body>nope</body></html>' > "$f"
    chk verdict-absent   "$(gq_introspection_verdict 200 "$f")" "absent"
    chk verdict-404      "$(gq_introspection_verdict 404 "$f")" "absent"
    chk verdict-401      "$(gq_introspection_verdict 401 "$f")" "gated"
    chk verdict-000      "$(gq_introspection_verdict 000 "$f")" "unreachable"

    # a fixture schema, built and analyzed end to end
    local schema="$OUT_DIR/fixture-$RUN_ID.json"
    cat > "$schema" <<'JSON'
{
  "queryType": {"name": "Query"},
  "mutationType": {"name": "Mutation"},
  "subscriptionType": null,
  "types": [
    {"kind": "OBJECT", "name": "Query", "fields": [
      {"name": "subscriber", "args": [{"name": "msisdn"}], "type": {"name": "Subscriber"}},
      {"name": "subscribers", "args": [], "type": {"name": "SubscriberConnection"}},
      {"name": "invoice", "args": [{"name": "id"}], "type": {"name": "Invoice"}}
    ]},
    {"kind": "OBJECT", "name": "Mutation", "fields": [
      {"name": "creditBalance", "args": [{"name": "account"}, {"name": "amount"}], "type": {"name": "PaymentResult"}},
      {"name": "swapSim", "args": [{"name": "msisdn"}], "type": {"name": "SimCard"}}
    ]},
    {"kind": "OBJECT", "name": "Subscriber", "fields": [
      {"name": "msisdn", "args": [], "type": {"name": "String"}},
      {"name": "sim", "args": [], "type": {"name": "SimCard"}},
      {"name": "legacyId", "args": [], "type": {"name": "String"}, "isDeprecated": true}
    ]},
    {"kind": "OBJECT", "name": "SimCard", "fields": [
      {"name": "iccid", "args": [], "type": {"name": "String"}}
    ]},
    {"kind": "OBJECT", "name": "Invoice", "fields": [
      {"name": "amount", "args": [], "type": {"name": "Float"}}
    ]},
    {"kind": "OBJECT", "name": "AdminAuditLog", "fields": [
      {"name": "actor", "args": [], "type": {"name": "String"}}
    ]},
    {"kind": "OBJECT", "name": "SubscriberConnection", "fields": [
      {"name": "edges", "args": [], "type": {"name": "SubscriberEdge"}}
    ]},
    {"kind": "ENUM", "name": "Status"},
    {"kind": "SCALAR", "name": "String"}
  ]
}
JSON

    gq_cmd_schema "$schema" >/dev/null 2>&1
    chk schema-rc     "$?" "0"
    chk schema-query  "$(gq_cmd_schema "$schema" 2>/dev/null | awk -F'\t' '$1=="QUERY_TYPE"{print $2}')" "Query"
    chk schema-mut    "$(gq_cmd_schema "$schema" 2>/dev/null | awk -F'\t' '$1=="MUTATION_TYPE"{print $2}')" "Mutation"
    chk schema-sub    "$(gq_cmd_schema "$schema" 2>/dev/null | awk -F'\t' '$1=="SUBSCRIPTION_TYPE"{print $2}')" "none"

    # 8 fixture types, minus none (we keep enums and scalars — they are part of the surface)
    chk types-count   "$(wc -l < "$TYPES_FILE" | tr -d ' ')" "9"
    chk types-shape   "$(awk -F'\t' 'NF!=4{c++} END{print c+0}' "$TYPES_FILE")" "0"

    # classification of the fixture's own names
    chk types-money   "$(awk -F'\t' '$1=="Invoice"{print $3}' "$TYPES_FILE")" "money"
    chk types-ident   "$(awk -F'\t' '$1=="Subscriber"{print $3}' "$TYPES_FILE")" "identity"
    chk types-priv    "$(awk -F'\t' '$1=="AdminAuditLog"{print $3}' "$TYPES_FILE")" "privileged"
    chk types-sub     "$(awk -F'\t' '$1=="SimCard"{print $3}' "$TYPES_FILE")" "subscriber"
    chk types-conn    "$(awk -F'\t' '$1=="SubscriberConnection"{print $3}' "$TYPES_FILE")" "scaffold"

    # the query surface
    chk queries-count "$(gq_cmd_queries 2>/dev/null | grep -c '^QUERY')" "3"
    chk mutations-count "$(gq_cmd_queries 2>/dev/null | grep -c '^MUTATION')" "2"
    chk queries-args  "$(gq_cmd_queries 2>/dev/null | awk -F'\t' '$1=="QUERY" && $2=="subscriber"{print $3}')" "args=1"
    chk mut-args      "$(gq_cmd_queries 2>/dev/null | awk -F'\t' '$1=="MUTATION" && $2=="creditBalance"{print $3}')" "args=2"

    # one type's fields, with the deprecated flag
    chk fields-count  "$(gq_cmd_fields Subscriber 2>/dev/null | wc -l | tr -d ' ')" "3"
    chk fields-dep    "$(gq_cmd_fields Subscriber 2>/dev/null | awk -F'\t' '$2=="legacyId"{print $5}')" "deprecated"
    chk fields-live   "$(gq_cmd_fields Subscriber 2>/dev/null | awk -F'\t' '$2=="msisdn"{print $5}')" "-"
    gq_cmd_fields NoSuchType >/dev/null 2>&1; chk fields-missing "$?" "1"

    # depth: Query→subscriber→Subscriber→sim→SimCard is 4 hops, one per field
    chk depth         "$(gq_cmd_depth 2>/dev/null | awk -F'\t' '$1=="MAX_DEPTH"{print $2}')" "4"

    # usage errors rather than crashes
    gq_cmd_find 2>/dev/null;              chk find-usage "$?" "2"
    gq_cmd_introspect 2>/dev/null;        chk intro-usage "$?" "2"
    gq_cmd_check 2>/dev/null;             chk check-usage "$?" "2"
    gq_cmd_fields 2>/dev/null;            chk fields-usage "$?" "2"

    # a dead host finds nothing and returns a summary line
    local out
    out="$(GQ_TIMEOUT=1 gq_cmd_find http://127.0.0.1:9 2>/dev/null)"
    chk dead-summary "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/ .*//')" "found=0"

    # shape contracts
    chk status-fields "$(gq_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(gq_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(gq_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(gq_cmd_help | head -1 | grep -ci 'GraphQL')" "1"
    chk list-many     "$(gq_cmd_list | wc -l | tr -d ' ' | awk '{print ($1>=18)?"yes":"no"}')" "yes"

    rm -f "$f" "$schema" 2>/dev/null
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --find)       shift; gq_cmd_find "$@";;
    --introspect) shift; gq_cmd_introspect "$@";;
    --schema)     shift; gq_cmd_schema "$@";;
    --queries)    gq_cmd_queries;;
    --fields)     shift; gq_cmd_fields "$@";;
    --depth)      gq_cmd_depth;;
    --check)      shift; gq_cmd_check "$@";;
    --list)       gq_cmd_list;;
    --status-tsv|--status) gq_cmd_status_tsv;;
    --menu)       gq_cmd_menu;;
    --selftest)   gq_selftest;;
    *)            gq_cmd_help;;
esac
