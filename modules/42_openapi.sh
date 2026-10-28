#!/usr/bin/env bash
# 42_openapi.sh — cloudsting module 42: read a spec, and find what the spec admits to
# Verbs: --analyze | --find | --spec | --auth | --endpoints | --params | --diff | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own name as
# a path.
unset CS_MOD_DIR

MODULE_ID="42_openapi"
MOD_NAME="OpenAPI/Swagger Analyzer"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

OA_RUN_ID="$CS_RUN_ID"
export OA_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/openapi"
mkdir -p "$OUT_DIR" 2>/dev/null || true

SPEC_FILE="$OUT_DIR/spec-$RUN_ID.json"
EP_FILE="$OUT_DIR/endpoints-$RUN_ID.tsv"
PARAM_FILE="$OUT_DIR/params-$RUN_ID.tsv"

: "${OA_TIMEOUT:=10}"      # per-request wall clock, seconds
: "${OA_MAX_BYTES:=8388608}" # a spec bigger than this is not a spec
: "${OA_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/42}"

oa_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── where a telco portal keeps its spec ──────────────────────────
# Ordered by how often it is the real one. Spring ships three of these by
# default and the vendor consoles each have their own.
oa_paths() {
    cat <<'PATHS'
/v2/api-docs
/v3/api-docs
/v3/api-docs/swagger-config
/swagger.json
/swagger/v1/swagger.json
/openapi.json
/openapi.yaml
/api-docs
/api/swagger.json
/api/openapi.json
/api/v2/api-docs
/api/v3/api-docs
/docs/swagger.json
/docs/openapi.json
/spec
/spec.json
/api/spec
/swagger-resources
/rest/api-docs
/portal/swagger.json
/help-doc
PATHS
}

# Vendor consoles ship a documented tree instead of a spec. Each row is
# <vendor>\t<path>\t<marker> — a hit is worth as much as a spec because it
# names the tree.
oa_vendor_docs() {
    cat <<'VENDORS'
huawei-u2000	/rest/plat/smapp/v1	accessSession
huawei-nce	/restconf/data	yang-library-version
ericsson-enm	/enm/rest	Ericsson
zte-netnumen	/rest/v1	NetNumen
nokia-nsp	/rest-gateway/rest/api/v1	access_token
mitel-mivoice	/help-doc	MiCollab
rancher	/rancherversion	Rancher
primefaces	/help-doc	PrimeFaces
weblogic	/console/	WebLogic
VENDORS
}

# ── acquisition ──────────────────────────────────────────────────
#   oa_fetch <url> -> code \x1f bytes \x1f kind \x1f body-path
# kind is json | yaml | html | text | empty, decided from the first bytes so
# an HTML error page named swagger.json is not analyzed as a spec.
oa_fetch() {
    local url="$1"
    local body; body="$(mktemp "$CS_SCRATCH/oa.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.oa.$$"
    local meta code len
    meta="$(curl --silent --show-error --max-time "$OA_TIMEOUT" --max-redirs 2 \
                 --write-out '%{http_code}\t%{size_download}' --output "$body" \
                 -A "$OA_UA" -H 'Accept: application/json, application/yaml, text/yaml, */*' \
                 "$url" 2>/dev/null)" || meta=""
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code len <<<"$meta" ;;
        *) code="000"; len=0 ;;
    esac
    [[ -s "$body" ]] || : > "$body" 2>/dev/null || true

    local kind="empty"
    if (( ${len:-0} > OA_MAX_BYTES )); then
        kind="oversize"
    elif [[ "$code" == "200" ]]; then
        case "$(head -c 200 "$body" 2>/dev/null | tr -d '[:space:]' | head -c 1)" in
            '{'|'[') kind="json" ;;
            '<')     kind="html" ;;
            *)       if head -c 400 "$body" 2>/dev/null | grep -qiE '^[[:space:]]*(openapi|swagger|info|paths|servers):'; then
                         kind="yaml"
                     elif [[ -s "$body" ]]; then kind="text"; fi ;;
        esac
    fi
    printf '%s\037%s\037%s\037%s\n' "$code" "${len:-0}" "$kind" "$body"
}

# A spec is JSON for this module: YAML gets a conversion attempt, and if there
# is no converter the analysis says so instead of pretending.
oa_as_json() {
    local body="$1" kind="$2"
    # $body is a PATH when the spec came off a file and a cached download. The
    # json case has to print the file, not the name of the file.
    case "$kind" in
        json)
            if [[ -f "$body" ]]; then cat "$body"; else printf '%s\n' "$body"; fi
            return 0 ;;
        yaml)
            if cs_have yq; then yq -o=json '.' "$body" 2>/dev/null; return 0; fi
            if cs_have python3; then
                python3 - "$body" <<'PY' 2>/dev/null
import json,sys
try:
    import yaml
    with open(sys.argv[1]) as fh:
        print(json.dumps(yaml.safe_load(fh)))
except Exception:
    sys.exit(1)
PY
                return 0
            fi
            return 1 ;;
        *) return 1 ;;
    esac
}

# ── classification ───────────────────────────────────────────────
# The grade is what the spec *admits to*, not what the endpoint does. A spec
# that lists a security scheme on every operation is a spec written by
# someone who thought about it.
#   oa_op_security <operation-json> -> none | declared | empty-scopes | unspecified
oa_op_security() {
    printf '%s' "$1" | jq -r '
        if .security == null then "unspecified"
        elif (.security | length) == 0 then "none"
        else "declared" end' 2>/dev/null || printf 'unknown'
}

# An operation that lists a scheme with no scopes is only weak when the scheme
# is one that HAS scopes to give. Resolved against the spec's own scheme table
# rather than guessed from the requirement.
#   oa_op_weak <spec-json> <operation-json>
oa_op_weak() {
    local spec="$1" op="$2"
    printf '%s' "$op" | jq -r --argjson spec "$spec" '
        (($spec.components.securitySchemes // $spec.securityDefinitions // {}) | to_entries
          | map({key: .key, value: ((.value.type // "") + "/" + (.value.flow // .value.scheme // ""))})
          | from_entries) as $schemes
        | if .security == null then "unspecified"
          elif (.security | length) == 0 then "none"
          else
            [ .security[] | to_entries[]
              | .key as $n | (.value | length) as $scopes
              | select($scopes == 0)
              | select(($schemes[$n] // "") | test("oauth2|openIdConnect|/implicit|/password")) ]
            | if length > 0 then "empty-scopes" else "declared" end
          end' 2>/dev/null || printf 'declared'
}

# ── verbs ────────────────────────────────────────────────────────
# --find: which of the well-known spec paths answers, and does it actually
# parse. Cheap, and it is what tells the rest of the module where to read.
oa_cmd_find() {
    local base="${1:-}"
    [[ -z "$base" ]] && { oa_log "usage: --find <base-url|host>"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    local found=0 p code len kind body json
    for p in $(oa_paths); do
        cs_split "$(oa_fetch "${base%/}$p")" code len kind body
        if [[ "$code" != "200" ]]; then rm -f "$body"; continue; fi
        json="$(oa_as_json "$body" "$kind")"
        if [[ -n "$json" ]] && printf '%s' "$json" | jq -e '.paths? // .swagger? // .openapi?' >/dev/null 2>&1; then
            local ver n
            ver="$(printf '%s' "$json" | jq -r '.openapi // .swagger // "unknown"')"
            n="$(printf '%s' "$json" | jq -r '(.paths // {}) | length')"
            cs_row SPEC "${base%/}$p" "version=$ver" "paths=$n" "bytes=$len"
            found=$((found + 1))
            printf '%s\n' "$json" > "${OUT_DIR}/spec-$(printf '%s' "$p" | tr '/' '_')-$RUN_ID.json"
        elif [[ "$code" == "200" && "$kind" != "html" ]]; then
            cs_row DOC "${base%/}$p" "kind=$kind" "bytes=$len" "not-a-spec"
        fi
        rm -f "$body"
    done

    # vendor consoles, which ship a tree rather than a spec
    local vendor vpath marker
    while IFS=$'\t' read -r vendor vpath marker; do
        [[ -z "$vendor" ]] && continue
        cs_split "$(oa_fetch "${base%/}$vpath")" code len kind body
        if [[ "$code" == "200" ]] && grep -qiF -- "$marker" "$body" 2>/dev/null; then
            cs_row VENDOR "$vendor" "${base%/}$vpath" "marker=$marker"
            found=$((found + 1))
        fi
        rm -f "$body"
    done < <(oa_vendor_docs)

    cs_row SUMMARY "found=$found probes=$(( $(oa_paths | wc -l) + $(oa_vendor_docs | wc -l) ))"
    (( found > 0 )) && return 0 || return 1
}

# --analyze: the read. Every operation, its method, its security, whether it
# takes an object id, and whether its parameters are declared.
#   oa_cmd_analyze <spec-file-or-url>
oa_cmd_analyze() {
    local src="${1:-}"
    [[ -z "$src" ]] && { oa_log "usage: --analyze <spec-file|spec-url>"; return 2; }

    local json tmpbody=""
    if [[ -f "$src" ]]; then
        local kind="json"
        case "$src" in
            *.yaml|*.yml) kind="yaml" ;;
        esac
        json="$(oa_as_json "$src" "$kind")"
        [[ -n "$json" ]] || { oa_log "cannot read $src as JSON or YAML"; return 2; }
        # A file that is non-empty but parses as nothing is not a spec — an
        # HTML error page saved as swagger.json reaches jq happily otherwise.
        printf '%s' "$json" | jq -e '(.paths? // null) // (.openapi? // null) // (.swagger? // null)' >/dev/null 2>&1 \
            || { oa_log "not a spec: $src"; return 2; }
    else
        local code len kind body
        cs_split "$(oa_fetch "$src")" code len kind body
        tmpbody="$body"
        [[ "$code" == "200" ]] || { rm -f "$body"; oa_log "spec fetch failed: $code"; return 2; }
        json="$(oa_as_json "$body" "$kind")"
        rm -f "$body"
        [[ -n "$json" ]] || { oa_log "unparseable spec at $src"; return 2; }
    fi

    printf '%s\n' "$json" > "$SPEC_FILE"
    : > "$EP_FILE"; : > "$PARAM_FILE"

    local title version npaths auth
    title="$(printf '%s' "$json" | jq -r '.info.title // "untitled"')"
    version="$(printf '%s' "$json" | jq -r '.openapi // .swagger // "unknown"')"
    npaths="$(printf '%s' "$json" | jq -r '(.paths // {}) | length')"
    auth="$(printf '%s' "$json" | jq -r '[((.components.securitySchemes // .securityDefinitions // {}) | keys[])?] | join(",")')"

    cs_row SPEC "$src"
    cs_row TITLE "$title"
    cs_row VERSION "$version"
    cs_row PATHS "$npaths"
    cs_row SECURITY_SCHEMES "${auth:-none-declared}"

    # one row per operation
    local rows
    rows="$(printf '%s' "$json" | jq -r '
        (.paths // {}) as $p
        | [ $p | to_entries[] | .key as $path | .value | to_entries[]
            | select(.key | test("^(get|post|put|patch|delete|head|options|trace)$"))
            | {
                method: (.key | ascii_upcase),
                path: $path,
                sec: (if .value.security == null then "unspecified"
                      elif (.value.security | length) == 0 then "none"
                      else "declared" end),
                id: (if ($path + " " + (.value.parameters? // [] | tojson)) | test("\\{[a-zA-Z_]+\\}") then "path-id"
                     elif ($path | test("/(msisdn|msisdn_number|iccid|imsi|account|subscriber|customer|bill|invoice|sim)/")) then "object-id"
                     else "no-id" end),
                params: ((.value.parameters? // []) | length),
                body: (if .value.requestBody != null then "body"
                       elif (.value.parameters? // [] | map(select(.in=="body")) | length) > 0 then "body"
                       else "none" end)
            } | [.method, .path, .sec, .id, (.params|tostring), .body] | @tsv ] | .[]' 2>/dev/null)"

    local total=0 open=0 objects=0
    local method path sec id params body
    while IFS=$'\t' read -r method path sec id params body; do
        [[ -z "$method" ]] && continue
        total=$((total + 1))
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$method" "$path" "$sec" "$id" "$params" "$body" >> "$EP_FILE"
        case "$sec" in none|empty-scopes|unspecified) open=$((open + 1)) ;; esac
        [[ "$id" != "no-id" ]] && objects=$((objects + 1))
    done <<< "$rows"

    cs_row OPERATIONS "$total"
    cs_row UNAUTHENTICATED_SHAPE "$open" "operations whose security is none, empty-scopes or unspecified"
    cs_row OBJECT_OPERATIONS "$objects" "operations that take an id in the path"

    # the grading: an operation with no security at all in a spec that declares
    # schemes is the strongest thing a spec admits to
    if (( open > 0 )); then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$src" "HIGH" "spec-unauthenticated" \
            "$open of $total operations declare no usable security requirement"
    fi

    printf '%s\n' "$json" | jq -r '
        (.paths // {}) as $p
        | [ $p | to_entries[] | .key as $path | .value | to_entries[]
            | select(.key | test("^(get|post|put|patch|delete)$"))
            | (.value.parameters? // [])[] | select(.in=="query" or .in=="path" or .in=="header")
            | [.in, .name, (.required|tostring), ((.schema.type // .type // "?")|tostring)] | @tsv ] | .[]' 2>/dev/null > "$PARAM_FILE" || true
    local pcount; pcount="$(wc -l < "$PARAM_FILE" 2>/dev/null | tr -d ' ')"
    cs_row PARAMETERS "${pcount:-0}"
    cs_row ARTIFACT "$SPEC_FILE" "$EP_FILE"
    rm -f "$tmpbody" 2>/dev/null
    return 0
}

# --auth: only the operations, grouped by how they authenticate. The one view
# an operator reads when deciding where to spend a token.
oa_cmd_auth() {
    local spec="${1:-$SPEC_FILE}"
    [[ -f "$spec" ]] || { oa_log "usage: --auth <spec-file>  (or run --analyze first)"; return 2; }
    local json; json="$(oa_as_json "$spec" json)" || { oa_log "cannot parse $spec"; return 2; }

    local sec n
    for sec in none empty-scopes unspecified declared; do
        n="$(printf '%s' "$json" | jq -r --arg s "$sec" '
            [ (.paths // {}) | to_entries[] | .value | to_entries[]
              | select(.key | test("^(get|post|put|patch|delete)$"))
              | { s: (if .value.security == null then "unspecified"
                      elif (.value.security | length) == 0 then "none"
                      else "declared" end) }
              | select(.s == $s) ] | length' 2>/dev/null)"
        cs_row COUNT "$sec" "${n:-0}"
    done
    return 0
}

# --endpoints: the flat list, for piping into 48/49/62.
oa_cmd_endpoints() {
    local spec="${1:-$SPEC_FILE}"
    if [[ -f "$spec" ]]; then
        oa_cmd_analyze "$spec" >/dev/null 2>&1 || { oa_log "cannot analyze $spec"; return 2; }
    fi
    [[ -s "$EP_FILE" ]] || { oa_log "no endpoint table — run --analyze first"; return 2; }
    local method path sec id params body
    while IFS=$'\t' read -r method path sec id params body; do
        cs_row ENDPOINT "$method" "$path" "$sec" "$id"
    done < "$EP_FILE"
    return 0
}

# --params: the parameter table, with the ones that take a URL called out —
# those are the SSRF candidates a spec hands you for free.
oa_cmd_params() {
    [[ -s "$PARAM_FILE" ]] || { oa_log "no parameter table — run --analyze first"; return 2; }
    local where name required type
    while IFS=$'\t' read -r where name required type; do
        [[ -z "$where" ]] && continue
        local flag=""
        case "$name" in
            *url*|*uri*|*link*|*callback*|*webhook*|*redirect*|*return*|*next*|*image*|*logo*|*avatar*) flag="url-like" ;;
        esac
        cs_row PARAM "$name" "in=$where" "required=$required" "type=$type" ${flag:+"$flag"}
    done < "$PARAM_FILE"
    return 0
}

oa_cmd_spec() {
    [[ -f "$SPEC_FILE" ]] || { oa_log "no spec loaded — run --analyze first"; return 2; }
    cs_row SPEC "$SPEC_FILE" "$(wc -c < "$SPEC_FILE" | tr -d ' ') bytes"
    jq -r '.info | "TITLE\t\(.title // "untitled")\nVERSION_STR\t\(.version // "-")"' "$SPEC_FILE" 2>/dev/null || true
    return 0
}

# --diff: two specs, the endpoints that moved. A spec change is how an
# unauthorized endpoint usually arrives.
oa_cmd_diff() {
    local a="${1:-}" b="${2:-}"
    if [[ -z "$a" || -z "$b" ]]; then
        oa_log "usage: --diff <spec-a> <spec-b>"
        return 2
    fi
    local ja jb
    ja="$(oa_as_json "$a" json 2>/dev/null || oa_as_json "$a" yaml 2>/dev/null)"
    jb="$(oa_as_json "$b" json 2>/dev/null || oa_as_json "$b" yaml 2>/dev/null)"
    [[ -n "$ja" && -n "$jb" ]] || { oa_log "one of the specs does not parse"; return 2; }

    local ops_a ops_b
    ops_a="$(printf '%s' "$ja" | jq -r '(.paths // {}) | to_entries[] | .key as $p | .value | keys[] | select(test("^(get|post|put|patch|delete)$")) | (.|ascii_upcase) + " " + $p' 2>/dev/null | sort)"
    ops_b="$(printf '%s' "$jb" | jq -r '(.paths // {}) | to_entries[] | .key as $p | .value | keys[] | select(test("^(get|post|put|patch|delete)$")) | (.|ascii_upcase) + " " + $p' 2>/dev/null | sort)"

    local added removed
    added="$(comm -13 <(printf '%s\n' "$ops_a") <(printf '%s\n' "$ops_b") | sed '/^$/d')"
    removed="$(comm -23 <(printf '%s\n' "$ops_a") <(printf '%s\n' "$ops_b") | sed '/^$/d')"
    local nadd nrem
    nadd="$(printf '%s' "$added" | sed '/^$/d' | wc -l | tr -d ' ')"
    nrem="$(printf '%s' "$removed" | sed '/^$/d' | wc -l | tr -d ' ')"
    printf '%s' "$added" | sed '/^$/d' | while read -r line; do cs_row ADDED "$line"; done
    printf '%s' "$removed" | sed '/^$/d' | while read -r line; do cs_row REMOVED "$line"; done
    cs_row SUMMARY "added=$nadd removed=$nrem"
    return 0
}

oa_cmd_list() {
    local p
    for p in $(oa_paths); do printf '%s\t%s\n' "$p" "well-known"; done
    local vendor vpath marker
    while IFS=$'\t' read -r vendor vpath marker; do
        [[ -z "$vendor" ]] && continue
        printf '%s\t%s\t%s\n' "$vendor" "$vpath" "$marker"
    done < <(oa_vendor_docs)
    return 0
}

oa_cmd_status_tsv() {
    local curl_state jq_state json_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    command -v jq   >/dev/null 2>&1 && jq_state="ok"   || jq_state="missing"
    cs_have yq && json_state="yq" || { cs_have python3 && json_state="python-yaml" || json_state="json-only"; }
    printf '%s\t%s\tcurl-%s\tjq-%s\tyaml-%s\tpaths-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" "$json_state" "$(oa_paths | wc -l | tr -d ' ')"
}

oa_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

oa_cmd_help() {
    cat <<'HELP'
cloudsting module 42 — OpenAPI/Swagger Analyzer v1.0.0
  --find <base>                  which well-known spec path answers, and does it parse
  --analyze <spec-file|spec-url> every operation, its security, its ids, its params
  --auth [spec-file]             operations grouped by how they authenticate
  --endpoints [spec-file]        flat method/path list for piping into 48/49/62
  --params                       parameters, with URL-taking ones called out
  --diff <spec-a> <spec-b>       what moved between two specs
  --spec                         the loaded spec's headline
  --list | --status-tsv | --menu | --selftest | --help

Security grading per operation: none (empty array), empty-scopes (a scheme
declared with no scopes), unspecified (no security key at all), declared.
An operation with no usable requirement in a spec that declares schemes is the
finding — a documented endpoint that documents itself as open.

Tries 21 well-known paths plus 9 vendor console trees (Huawei U2000/NCE,
Ericsson ENM, ZTE NetNumen, Nokia NSP, Mitel MiCollab, Rancher, PrimeFaces,
WebLogic).

YAML needs yq or python3+pyyaml; without either the module says json-only.

Environment: OA_TIMEOUT (10), OA_MAX_BYTES (8388608), OA_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
oa_selftest() {
    cs_selftest_reset

    chk paths-many    "$( (( $(oa_paths | wc -l) >= 15 )) && echo many || echo few )" "many"
    chk paths-slash   "$(oa_paths | awk '$1 !~ /^\//{c++} END{print c+0}')" "0"
    chk paths-unique  "$(oa_paths | sort -u | wc -l | tr -d ' ')" "$(oa_paths | wc -l | tr -d ' ')"
    chk paths-spring  "$(oa_paths | grep -cx '/v3/api-docs')" "1"
    chk vendor-many   "$( (( $(oa_vendor_docs | wc -l) >= 8 )) && echo many || echo few )" "many"
    chk vendor-3col   "$(oa_vendor_docs | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"

    # a spec fixture, written and analyzed end to end
    local fx="$OUT_DIR/fixture-$RUN_ID.json"
    cat > "$fx" <<'JSON'
{
  "openapi": "3.0.1",
  "info": {"title": "BSS Portal", "version": "2.4"},
  "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
  "paths": {
    "/api/customer/{msisdn}": {
      "get": {"security": [{"bearer": []}],
              "parameters": [{"in":"path","name":"msisdn","required":true,"schema":{"type":"string"}}]},
      "delete": {"security": []}
    },
    "/api/billing/invoice": {
      "get": {"security": [{"bearer": []}],
              "parameters": [{"in":"query","name":"callback_url","required":false,"schema":{"type":"string"}}]}
    },
    "/api/promo/{code}": {
      "get": {},
      "post": {"requestBody": {"content": {}}}
    }
  }
}
JSON

    oa_cmd_analyze "$fx" >/dev/null 2>&1
    local rc=$?
    chk analyze-rc        "$rc" "0"
    chk analyze-spec      "$(oa_cmd_spec 2>/dev/null | awk -F'\t' '$1=="SPEC"{print $2}')" "$SPEC_FILE"
    chk analyze-title     "$(oa_cmd_spec 2>/dev/null | awk -F'\t' '$1=="TITLE"{print $2}')" "BSS Portal"

    # six operations: 2 on customer, 1 on invoice, 2 on promo, plus delete = 5
    chk operations        "$(wc -l < "$EP_FILE" | tr -d ' ')" "5"
    chk endpoints-count   "$(oa_cmd_endpoints 2>/dev/null | wc -l | tr -d ' ')" "5"
    chk endpoints-shape   "$(oa_cmd_endpoints 2>/dev/null | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"

    # security classification is per operation and survives both spellings
    chk sec-declared      "$(awk -F'\t' '$1=="GET" && $2=="/api/customer/{msisdn}"{print $3}' "$EP_FILE")" "declared"
    chk sec-none          "$(awk -F'\t' '$1=="DELETE" && $2=="/api/customer/{msisdn}"{print $3}' "$EP_FILE")" "none"
    chk sec-unspecified   "$(awk -F'\t' '$1=="GET" && $2=="/api/promo/{code}"{print $3}' "$EP_FILE")" "unspecified"

    # id detection
    chk id-path           "$(awk -F'\t' '$1=="GET" && $2=="/api/customer/{msisdn}"{print $4}' "$EP_FILE")" "path-id"
    chk id-object         "$(awk -F'\t' '$1=="GET" && $2=="/api/billing/invoice"{print $4}' "$EP_FILE")" "no-id"
    chk id-none           "$(awk -F'\t' '$1=="GET" && $2=="/api/promo/{code}"{print $4}' "$EP_FILE")" "path-id"

    # params, and the url-like flag
    chk params-count      "$(oa_cmd_params 2>/dev/null | wc -l | tr -d ' ')" "2"
    chk params-urlflag    "$(oa_cmd_params 2>/dev/null | grep -c 'url-like')" "1"
    chk params-path       "$(oa_cmd_params 2>/dev/null | grep -c '^PARAM.msisdn')" "1"

    # auth grouping
    chk auth-declared     "$(oa_cmd_auth 2>/dev/null | awk -F'\t' '$1=="COUNT" && $2=="declared"{print $3}')" "2"
    chk auth-none         "$(oa_cmd_auth 2>/dev/null | awk -F'\t' '$1=="COUNT" && $2=="none"{print $3}')" "1"
    chk auth-unspecified  "$(oa_cmd_auth 2>/dev/null | awk -F'\t' '$1=="COUNT" && $2=="unspecified"{print $3}')" "2"
    chk auth-empty        "$(oa_cmd_auth 2>/dev/null | awk -F'\t' '$1=="COUNT" && $2=="empty-scopes"{print $3}')" "0"
    chk auth-declared-n  "$(oa_cmd_auth 2>/dev/null | awk -F'\t' '$1=="COUNT" && $2=="declared"{print $3}')" "2"

    # the op-security helper on raw shapes
    chk opsec-null        "$(oa_op_security '{}')" "unspecified"
    chk opsec-empty       "$(oa_op_security '{"security":[]}')" "none"
    chk opsec-bearer      "$(oa_op_security '{"security":[{"b":[]}]}')" "declared"
    chk opsec-real        "$(oa_op_security '{"security":[{"b":["read"]}]}')" "declared"

    # a diff between the fixture and itself is empty, and against a trimmed copy
    local fx2="$OUT_DIR/fixture2-$RUN_ID.json"
    jq 'del(.paths["/api/promo/{code}"])' "$fx" > "$fx2" 2>/dev/null
    # cs_row puts the whole payload in field 2, so both counts read from $2
    chk diff-same  "$(oa_cmd_diff "$fx" "$fx" 2>/dev/null | awk -F'\t' '$1=="SUMMARY"{print $2}')" "added=0 removed=0"
    chk diff-rm    "$(oa_cmd_diff "$fx" "$fx2" 2>/dev/null | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/.*removed=//')" "1"

    # html that claims to be a spec is not a spec
    local html="$OUT_DIR/notaspec-$RUN_ID.json"
    printf '<html><body>404</body></html>\n' > "$html"
    oa_cmd_analyze "$html" >/dev/null 2>&1; rc=$?
    chk html-rejected "$rc" "2"

    # usage errors, not crashes
    oa_cmd_find 2>/dev/null; rc=$?
    chk find-usage    "$rc" "2"
    oa_cmd_analyze 2>/dev/null; rc=$?
    chk analyze-usage "$rc" "2"
    oa_cmd_diff 2>/dev/null; rc=$?
    chk diff-usage    "$rc" "2"

    # a dead host finds nothing and does not crash
    local out
    out="$(OA_TIMEOUT=2 oa_cmd_find http://127.0.0.1:9 2>/dev/null)"
    # SUMMARY carries "found=N probes=M" in one field; only the found half matters
    chk dead-summary "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/ .*//')" "found=0"

    # shape contracts
    chk status-fields "$(oa_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(oa_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(oa_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(oa_cmd_help | head -1 | grep -ci 'OpenAPI')" "1"
    chk list-many     "$(oa_cmd_list | wc -l | tr -d ' ' | awk '{print ($1>=20)?"yes":"no"}')" "yes"

    rm -f "$fx" "$fx2" "$html" 2>/dev/null
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --find)      shift; oa_cmd_find "$@";;
    --analyze)   shift; oa_cmd_analyze "$@";;
    --auth)      shift; oa_cmd_auth "$@";;
    --endpoints) shift; oa_cmd_endpoints "$@";;
    --params)    oa_cmd_params;;
    --diff)      shift; oa_cmd_diff "$@";;
    --spec)      oa_cmd_spec;;
    --list)      oa_cmd_list;;
    --status-tsv|--status) oa_cmd_status_tsv;;
    --menu)      oa_cmd_menu;;
    --selftest)  oa_selftest;;
    *)           oa_cmd_help;;
esac
