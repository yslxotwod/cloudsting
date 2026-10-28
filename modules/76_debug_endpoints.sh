#!/usr/bin/env bash
# 76_debug_endpoints.sh — cloudsting module 76: find the health, status and debug surfaces a target left open
# Verbs: --scan <host|url> | --check <url> | --actuator <host> | --docs <host> | --env <host> | --list | --all | --status-tsv | --menu | --selftest
set -u
umask 077

# The root is derived after the core is sourced. An inherited CS_MOD_DIR is a
# caller's directory, not this module's, and would corrupt every loot path.
unset CS_MOD_DIR

MODULE_ID="76_debug_endpoints"
MOD_NAME="Debug Endpoint Discovery"
MOD_VERSION="0.21.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

DE_RUN_ID="$CS_RUN_ID"
export DE_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/debug_endpoints"
mkdir -p "$OUT_DIR" 2>/dev/null || true

FOUND_FILE="$OUT_DIR/found-$RUN_ID.tsv"
LEAK_FILE="$OUT_DIR/leaks-$RUN_ID.tsv"

: "${DE_TIMEOUT:=8}"        # per-request wall clock
: "${DE_CONCURRENCY:=8}"    # parallel workers
: "${DE_MAX_PATHS:=0}"      # 0 = the whole embedded list
: "${DE_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/76}"

# ── helpers ──────────────────────────────────────────────────────
de_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

de_base() {
    local t="${1:-}"
    t="${t#http://}"; t="${t#https://}"; t="${t%%/*}"; t="${t%%\?*}"
    [[ -z "$t" ]] && return 0
    printf 'https://%s' "$t"
}

# One request, everything the analysis needs in one row.
#   de_probe <url>  ->  <code>\t<bytes>\t<ct>\t<ms>
de_probe() {
    local url="${1:-}"
    command -v curl >/dev/null 2>&1 || { printf '000\t0\tnone\t0'; return 3; }
    local body; body="$(mktemp "$CS_SCRATCH/de.XXXXXX")" || return 1
    local meta
    meta="$(curl --silent --show-error --max-time "$DE_TIMEOUT" \
                 --user-agent "$DE_UA" \
                 --output "$body" \
                 --write-out '%{http_code}\t%{size_download}\t%{content_type}\t%{time_total}' \
                 "$url" 2>/dev/null)" || meta=$'000\t0\tnone\t0'
    printf '%s\t%s\n' "$(cs_esc "$meta")" "$body"
}

# Health endpoints are only interesting when they carry state. A bare "OK" is
# a liveness probe and means nothing once found; a JSON body listing
# dependencies is a map of the internal network.
de_verdict_health() {
    local code="$1" bytes="$2" ct="$3" body="$4"
    [[ "$code" != "200" ]] && { printf 'absent'; return 0; }
    (( bytes < 4 )) && { printf 'absent'; return 0; }
    local lower_ct="${ct,,}"
    if [[ "$lower_ct" == *json* ]]; then
        # a JSON health body names its dependencies
        local keys
        keys="$(grep -oE '"[a-zA-Z_.-]+"[[:space:]]*:' "$body" 2>/dev/null | wc -l | tr -d ' ')"
        if (( keys >= 3 )); then printf 'verbose'; else printf 'json-minimal'; fi
        return 0
    fi
    # plain text that mentions a dependency or a version is not a bare OK
    if grep -qiE '(database|redis|postgres|mysql|mongo|kafka|rabbit|uptime|build|version)[[:space:]]*:' "$body" 2>/dev/null; then
        printf 'verbose'
        return 0
    fi
    (( bytes > 200 )) && { printf 'body'; return 0; }
    printf 'minimal'
}

# Debug and env endpoints are only worth a finding if they print something
# that looks like configuration. This is the classifier that keeps a 200 on
# /debug (which is often just a 404 page returning 200) out of the report.
de_verdict_debug() {
    local code="$1" bytes="$2" body="$3"
    [[ "$code" != "200" ]] && { printf 'absent'; return 0; }
    (( bytes < 16 )) && { printf 'absent'; return 0; }
    local hits=0
    grep -qE '"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"' "$body" 2>/dev/null && hits=$((hits + 3))
    grep -qiE 'jdbc:|mysql://|postgres(ql)?://|mongodb://|redis://|amqp://' "$body" 2>/dev/null && hits=$((hits + 3))
    grep -qiE 'spring\.datasource|server\.port|management\.endpoints|aws_|azure_|google_' "$body" 2>/dev/null && hits=$((hits + 2))
    grep -qiE 'heap|thread ?dump|gc ?roots|classloader|system\.properties|environment' "$body" 2>/dev/null && hits=$((hits + 1))
    if (( hits >= 3 )); then printf 'config-leak'
    elif (( hits >= 1 )); then printf 'debug-verbose'
    elif (( bytes > 800 )); then printf 'debug-body'
    else printf 'minimal'
    fi
}

# A telco management surface answers with a product string, a version, a
# cluster list or a token shape. A bare 200 on /webui is a login page and is
# not a finding, so the verdict needs evidence in the body, not the status.
de_verdict_telco() {
    local code="$1" bytes="$2" body="$3"
    [[ "$code" != "200" ]] && { printf 'absent'; return 0; }
    (( bytes < 8 )) && { printf 'absent'; return 0; }
    local hits=0
    grep -qiE 'rancher|kubernetes|cattle' "$body" 2>/dev/null && hits=$((hits + 2))
    grep -qiE 'huawei|u2000|imanager|itau|zanhui' "$body" 2>/dev/null && hits=$((hits + 3))
    grep -qiE 'ericsson|enm|oss-rc|nokia|netact|zte|netnumen' "$body" 2>/dev/null && hits=$((hits + 3))
    grep -qiE 'powerdns|pdns|recursor' "$body" 2>/dev/null && hits=$((hits + 2))
    grep -qiE 'openstack|keystone|horizon|nova|glance' "$body" 2>/dev/null && hits=$((hits + 2))
    grep -qiE '"(version|release|build|appVersion|serverVersion)"[[:space:]]*:' "$body" 2>/dev/null && hits=$((hits + 1))
    grep -qiE '"(servers|clusters|nodes|queries|zones|data)"[[:space:]]*:' "$body" 2>/dev/null && hits=$((hits + 1))
    grep -qiE 'accessSession|access_token|X-Auth-Token|"token"[[:space:]]*:' "$body" 2>/dev/null && hits=$((hits + 3))
    if (( hits >= 3 )); then printf 'mgmt-exposed'
    elif (( hits >= 1 )); then printf 'mgmt-listing'
    else printf 'minimal'
    fi
}

# The path list. Grouped so a caller can ask for one family: health, actuator,
# docs, env, telco, or the lot. Ordered by how often each one is actually open.
de_paths() {
    local group="${1:-all}"
    case "$group" in
        health)
            cat <<'P'
/health
/healthz
/health/live
/health/ready
/healthcheck
/health-check
/_health
/api/health
/api/healthz
/api/v1/health
/status
/statusz
/ready
/readyz
/live
/livez
/ping
/_ping
/uptime
/version
/api/version
/build-info
/info
/system/info
/status/health
P
            ;;
        actuator)
            cat <<'P'
/actuator
/actuator/health
/actuator/info
/actuator/env
/actuator/configprops
/actuator/beans
/actuator/mappings
/actuator/metrics
/actuator/threaddump
/actuator/heapdump
/actuator/loggers
/actuator/httptrace
/actuator/auditevents
/actuator/scheduledtasks
/actuator/startup
/actuator/liquibase
/actuator/flyway
/actuator/prometheus
/actuator/caches
/actuator/conditions
/actuator/sbom
/actuator/shutdown
P
            ;;
        docs)
            cat <<'P'
/docs
/doc
/documentation
/swagger-ui.html
/swagger-ui/
/swagger-ui/index.html
/swagger
/swagger/index.html
/swagger-resources
/api-docs
/api-docs/
/v2/api-docs
/v3/api-docs
/v3/api-docs/swagger-config
/openapi.json
/openapi.yaml
/openapi
/redoc
/graphiql
/graphql/playground
/playground
/api/graphql
/altair
/browser/
P
            ;;
        env)
            cat <<'P'
/.env
/.env.local
/.env.production
/.env.backup
/.env.example
/env
/environment
/api/env
/config
/config.json
/config.js
/configuration
/appsettings.json
/web.config
/phpinfo.php
/info.php
/server-status
/server-info
/.git/config
/.git/HEAD
/.svn/entries
/.DS_Store
/robots.txt
/sitemap.xml
/crossdomain.xml
/.well-known/security.txt
/trace
/debug
/debug/
/debug/vars
/debug/pprof/
/debug/pprof/heap
/debug/pprof/goroutine
/__debug__
/_debug
/console
/h2-console
/druid/index.html
/jolokia
/jolokia/list
P
            ;;
        telco)
            cat <<'P'
/rancherversion
/v3-public/localProviders/local?action=login
/v1/management.cattle.io.clusters
/monitor/queries
/monitor/api/docs
/api/v1/servers/localhost
/rancher/v2.x
/rest/plat/smapp/v1/version
/rest/plat/smapp/v1/sessions
/restconf/data
/enm/rest
/enm/version
/rest/v1/version
/rest/login
/help-doc
/help-doc/
/webui
/webui/
/nmc
/nmc/
/cgi-bin/
/cgi-bin/status
/cgi-bin/health
/admin
/admin/
/portal/
/portal/rest/
/cacti/
/nagios/
/zabbix/
/openstack
/horizon/auth/login/
/identity/v3/auth/tokens
/afs
/h2-console/login.jsp
P
            ;;
        *)
            de_paths health
            de_paths actuator
            de_paths docs
            de_paths env
            de_paths telco
            ;;
    esac
}

# Classify a path into one of the four families so the result says what kind
# of surface it is, not just that it answered.
de_family() {
    local p="${1:-}"
    case "$p" in
        /actuator*)              printf 'actuator' ;;
        */swagger*|*/api-docs*|*/openapi*|*/graphi*|*/playground*|/docs*|/redoc*|*/altair*) printf 'docs' ;;
        /.env*|/env*|/config*|/phpinfo*|/server-*|/.git*|/.svn*|/trace*|/jolokia*|/h2-console*|/druid*|/__debug__*|/_debug*|/debug*) printf 'debug' ;;
        /health*|/healthz*|/ready*|/live*|/ping*|/_ping*|/status*|/version*|/info*|/build-info*|/uptime*|/system/info*) printf 'health' ;;
        /rancher*|/v3-public*|/v1/management*|/monitor*|/rest/plat*|/restconf*|/enm*|/rest/v1*|/rest/login*|/help-doc*|/webui*|/nmc*|/cgi-bin*|/admin*|/portal*|/cacti*|/nagios*|/zabbix*|/openstack*|/horizon*|/identity/v3*|/afs*|/h2-console*) printf 'telco' ;;
        *) printf 'other' ;;
    esac
}

# ── scan ─────────────────────────────────────────────────────────
de_cmd_scan() {
    local target="${1:-}" group="${2:-all}"
    [[ -z "$target" ]] && { printf 'usage: 76_debug_endpoints.sh --scan <host|url> [all|health|actuator|docs|env]\n' >&2; return 2; }
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    local base; base="$(de_base "$target")"
    [[ -z "$base" ]] && { cs_row ERROR "unparseable target: $target"; return 2; }
    cs_row TARGET "$base"
    cs_row FAMILY "$group"

    local paths="$CS_SCRATCH/de-paths.txt"
    de_paths "$group" | sort -u > "$paths"
    if (( DE_MAX_PATHS > 0 )); then
        head -n "$DE_MAX_PATHS" "$paths" > "$paths.cut" && mv "$paths.cut" "$paths"
    fi
    local total; total="$(wc -l < "$paths" | tr -d ' ')"
    cs_row PATHS "$total"

    : > "$FOUND_FILE"
    : > "$LEAK_FILE"
    local raw="$CS_SCRATCH/de-raw.tsv"
    : > "$raw"

    local running=0 p
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        (
            local r; r="$(de_probe "${base}${p}")"
            local meta="${r%%$'\t'*}" body="${r##*$'\t'}"
            local code bytes ct ms
            cs_split "$meta" code bytes ct ms
            local fam; fam="$(de_family "$p")"
            local verdict="absent"
            case "$fam" in
                health)   verdict="$(de_verdict_health "${code:-0}" "${bytes:-0}" "${ct:-}" "$body")" ;;
                debug)    verdict="$(de_verdict_debug "${code:-0}" "${bytes:-0}" "$body")" ;;
                actuator)
                    if [[ "${code:-0}" == "200" ]]; then
                        if (( ${bytes:-0} > 40 )); then verdict="verbose"; else verdict="minimal"; fi
                    fi
                    ;;
                telco)    verdict="$(de_verdict_telco "${code:-0}" "${bytes:-0}" "$body")" ;;
                docs)
                    if [[ "${code:-0}" == "200" ]] && (( ${bytes:-0} > 200 )); then verdict="open"; fi
                    ;;
                *) if [[ "${code:-0}" == "200" ]]; then verdict="open"; fi ;;
            esac
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$p" "${code:-0}" "${bytes:-0}" "${ct:-}" "${fam}" "$verdict" "$body" >> "$raw"
        ) &
        running=$((running + 1))
        if (( running >= DE_CONCURRENCY )); then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
    done < "$paths"
    wait

    local found=0 leaks=0
    while IFS=$'\t' read -r p code bytes ct fam verdict body; do
        [[ -z "$p" ]] && continue
        [[ "$verdict" == "absent" ]] && { rm -f "$body"; continue; }
        found=$((found + 1))
        cs_row ENDPOINT "$p" "$fam" "$verdict" "$code" "$bytes"
        printf '%s\t%s\t%s\t%s\t%s\n' "$p" "$fam" "$verdict" "$code" "$bytes" >> "$FOUND_FILE"

        case "$verdict" in
            config-leak)
                leaks=$((leaks + 1))
                cs_row LEAK "$p" "$fam" "$bytes"
                cp "$body" "$LEAK_FILE.$(printf '%s' "$p" | tr '/' '_')" 2>/dev/null || true
                cs_findings_row "$MODULE_ID" "EXPOSURE" "$base$p" "CRITICAL" "config-leak:$fam" \
                    "$p prints configuration ($bytes bytes)"
                ;;
            verbose)
                if [[ "$fam" == "actuator" ]]; then
                    # /actuator/env and /actuator/heapdump are the two that
                    # hand over a credential rather than a health check
                    case "$p" in
                        */env|*/heapdump|*/configprops|*/threaddump)
                            leaks=$((leaks + 1))
                            cs_row LEAK "$p" "$fam" "$bytes"
                            cp "$body" "$LEAK_FILE.$(printf '%s' "$p" | tr '/' '_')" 2>/dev/null || true
                            cs_findings_row "$MODULE_ID" "EXPOSURE" "$base$p" "CRITICAL" "actuator-exposed:$p" \
                                "$p readable at $bytes bytes"
                            ;;
                        *)
                            cs_findings_row "$MODULE_ID" "EXPOSURE" "$base$p" "HIGH" "actuator-open:$p" \
                                "$p answers with $bytes bytes"
                            ;;
                    esac
                else
                    cs_findings_row "$MODULE_ID" "EXPOSURE" "$base$p" "MEDIUM" "verbose-health:$fam" \
                        "$p describes the deployment"
                fi
                ;;
            debug-verbose|debug-body|body)
                cs_findings_row "$MODULE_ID" "EXPOSURE" "$base$p" "MEDIUM" "debug-surface:$fam" \
                    "$p answers $bytes bytes"
                ;;
            open)
                cs_findings_row "$MODULE_ID" "EXPOSURE" "$base$p" "MEDIUM" "docs-open:$fam" \
                    "API documentation published"
                ;;
            json-minimal|minimal)
                cs_findings_row "$MODULE_ID" "EXPOSURE" "$base$p" "LOW" "endpoint-found:$fam" \
                    "$p exists"
                ;;
        esac
        rm -f "$body"
    done < "$raw"

    cs_row SUMMARY "$total" "$found" "$leaks"
    cs_row ARTIFACT "$FOUND_FILE"
    return 0
}

de_cmd_check() {
    local url="${1:-}"
    [[ -z "$url" ]] && { printf 'usage: 76_debug_endpoints.sh --check <url>\n' >&2; return 2; }
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    local r; r="$(de_probe "$url")"
    local meta="${r%%$'\t'*}" body="${r##*$'\t'}"
    local code bytes ct ms
    cs_split "$meta" code bytes ct ms
    local fam; fam="$(de_family "${url#*://*/}")"
    [[ "$fam" == "other" ]] && fam="$(de_family "/$(printf '%s' "$url" | sed -E 's|^[a-z]+://[^/]+/?||')")"

    cs_row URL "$url"
    cs_row FAMILY "$fam"
    cs_row RESPONSE "${code:-0}"
    cs_row BYTES "${bytes:-0}"
    cs_row TYPE "${ct:-none}"
    cs_row MS "${ms:-0}"

    local verdict="absent"
    case "$fam" in
        health)   verdict="$(de_verdict_health "${code:-0}" "${bytes:-0}" "${ct:-}" "$body")" ;;
        debug)    verdict="$(de_verdict_debug "${code:-0}" "${bytes:-0}" "$body")" ;;
        actuator) [[ "${code:-0}" == "200" ]] && verdict="verbose" ;;
        docs)     [[ "${code:-0}" == "200" ]] && verdict="open" ;;
        *)        [[ "${code:-0}" == "200" ]] && verdict="open" ;;
    esac
    cs_row VERDICT "$verdict"
    rm -f "$body"
    return 0
}

# Convenience families: one verb per surface so a caller does not have to
# remember which list a path lives in.
de_cmd_actuator() { de_cmd_scan "${1:-}" actuator; }
de_cmd_docs()     { de_cmd_scan "${1:-}" docs; }
de_cmd_env()      { de_cmd_scan "${1:-}" env; }
de_cmd_health()   { de_cmd_scan "${1:-}" health; }

de_cmd_list() {
    local group="${1:-all}"
    cs_row GROUP "$group"
    local n=0 p
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        n=$((n + 1))
        cs_row PATH "$p" "$(de_family "$p")"
    done < <(de_paths "$group" | sort -u)
    cs_row SUMMARY "$n"
    return 0
}

de_cmd_all() {
    local t="${1:-}"
    de_cmd_scan "$t" all
}

de_cmd_status_tsv() {
    local c
    command -v curl >/dev/null 2>&1 && c="ok" || c="missing"
    printf '%s\t%s\tcurl-%s\tpaths-%s\n' "$MODULE_ID" "$MOD_NAME" "$c" "$(de_paths all | sort -u | wc -l | tr -d ' ')"
}

de_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

de_cmd_help() {
    cat <<'HELP'
cloudsting module 76 — Debug Endpoint Discovery v0.21.0
  --scan <host|url> [family]  sweep every debug surface, or one family
  --health <host|url>         only the health/status/version paths
  --actuator <host|url>       only the Spring Boot actuator paths
  --docs <host|url>           only the Swagger/OpenAPI/GraphiQL paths
  --env <host|url>            only the .env/config/.git/server-status paths
  --check <url>               one URL, full classification, no sweep
  --list [family]             print the path list without probing
  --all <host|url>            the whole sweep
  --status-tsv                module status
  --menu                      menu entry
  --selftest                  run selftests
  --help                      this message

A 200 is not a finding. Each family has its own classifier: a health body
that names its dependencies is a map of the internal network, while a plain
"OK" is a liveness probe and is recorded as low. /actuator/env and
/actuator/heapdump are graded critical because they hand over configuration.

Every rejected response is deleted as it is classified, so a sweep does not
fill the disk with 404 pages.

Environment: DE_TIMEOUT (8), DE_CONCURRENCY (8), DE_MAX_PATHS (0=all)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
de_selftest() {
    cs_selftest_reset

    # path families
    local all_n; all_n="$(de_paths all | sort -u | wc -l | tr -d ' ')"
    chk paths-many   "$( (( all_n > 100 )) && echo many || echo few )" "many"
    chk health-any   "$(de_paths health | grep -c '^/health$')" "1"
    chk actuator-any "$(de_paths actuator | grep -c '^/actuator/env$')" "1"
    chk docs-any     "$( (( $(de_paths docs | grep -c '^/swagger-ui') >= 1 )) && echo yes || echo no )" "yes"
    chk env-dotenv   "$(de_paths env | grep -c '^/\.env$')" "1"
    chk paths-unique "$(de_paths all | sort | uniq -d | wc -l | tr -d ' ')" "0"

    # family classification
    chk family-health   "$(de_family /health)"            "health"
    chk family-healthz  "$(de_family /health/ready)"      "health"
    chk family-actuator "$(de_family /actuator/env)"      "actuator"
    chk family-docs     "$(de_family /v3/api-docs)"       "docs"
    chk family-docs2    "$(de_family /swagger-ui/index.html)" "docs"
    chk family-debug    "$(de_family /.env)"              "debug"
    chk family-debug2   "$(de_family /debug/pprof/heap)"  "debug"
    chk family-other    "$(de_family /about)"             "other"

    # base normalisation
    chk base-bare "$(de_base example.com)"        "https://example.com"
    chk base-path "$(de_base example.com/a/b)"    "https://example.com"
    chk base-port "$(de_base example.com:8443)"   "https://example.com:8443"
    chk base-http "$(de_base http://x.y/z)"       "https://x.y"
    chk base-empty "$(de_base '')"                ""

    # health classifier: a bare OK is minimal, a dependency map is verbose
    local b="$CS_SCRATCH/hb.txt"
    printf 'OK' > "$b"
    chk health-bare "$(de_verdict_health 200 2 text/plain "$b")" "absent"
    printf 'status: UP\n' > "$b"
    chk health-tiny "$(de_verdict_health 200 11 text/plain "$b")" "minimal"
    printf '{"status":"UP","db":{"status":"UP"},"redis":{"status":"UP"},"kafka":{"status":"DOWN"}}\n' > "$b"
    chk health-json-verbose "$(de_verdict_health 200 95 application/json "$b")" "verbose"
    printf '{"status":"UP"}\n' > "$b"
    chk health-json-min "$(de_verdict_health 200 17 application/json "$b")" "json-minimal"
    printf 'application status: healthy\nversion: 2.14.0\nuptime: 99123s\n' > "$b"
    chk health-text-verbose "$(de_verdict_health 200 60 text/plain "$b")" "verbose"
    chk health-404 "$(de_verdict_health 404 0 text/plain "$b")" "absent"

    # debug classifier: configuration is the signal, a 200 is not
    printf '{"password":"hunter2","jdbc":"mysql://x/y","api_key":"abc"}\n' > "$b"
    chk debug-config "$(de_verdict_debug 200 60 "$b")" "config-leak"
    printf 'hello\n' > "$b"
    chk debug-thin  "$(de_verdict_debug 200 6 "$b")" "absent"
    printf '{"system.properties":{},"classloader":"app"}\n' > "$b"
    chk debug-verbose "$(de_verdict_debug 200 47 "$b")" "debug-verbose"
    chk debug-404 "$(de_verdict_debug 404 100 "$b")" "absent"

    # shape contracts
    chk status-fields "$(de_cmd_status_tsv | awk -F'\t' '{print NF}')" "4"
    chk status-module "$(de_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(de_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(de_cmd_help | head -1 | grep -ci 'Debug Endpoint')" "1"
    chk list-shape    "$(de_cmd_list health | grep -c '^PATH')" "$(de_paths health | sort -u | wc -l | tr -d ' ')"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --scan)     shift; de_cmd_scan "$@";;
    --health)   shift; de_cmd_health "$@";;
    --actuator) shift; de_cmd_actuator "$@";;
    --docs)     shift; de_cmd_docs "$@";;
    --env)      shift; de_cmd_env "$@";;
    --check)    shift; de_cmd_check "$@";;
    --list)     shift; de_cmd_list "$@";;
    --all)      shift; de_cmd_all "$@";;
    --status-tsv|--status) de_cmd_status_tsv;;
    --menu)     de_cmd_menu;;
    --selftest) de_selftest;;
    *)          de_cmd_help;;
esac
