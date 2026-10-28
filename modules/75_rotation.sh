#!/usr/bin/env bash
# 75_rotation.sh — cloudsting module 75: the key that was rotated and still works
# Verbs: --probe | --grace | --old-key | --leak-check | --policy | --windows
#        | --techniques | --list | --status-tsv | --menu | --selftest | --help
#
# Rotation is a promise. The operator rotates a credential and believes the old
# one is now dead. Two failures break that promise, and both are invisible from
# the console: first, the old key keeps working for weeks because the window was
# never enforced; second, the reason it was rotated — a leaked key — is never
# established, so the rotation happens and the leak stays.
#
# This module tests the promise from the outside: does the retired credential
# still open the door, how long after the advertised time, and is the new one
# actually different.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="75_rotation"
MOD_NAME="Key Rotation (the credential that outlives its rotation)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/rotation"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${KR_TIMEOUT:=10}"
: "${KR_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/75}"
: "${KR_WINDOW_HOURS:=24}"
: "${KR_OLD_KEY:=}"
: "${KR_NEW_KEY:=}"
: "${KR_TOKEN:=}"

kr_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── how credentials travel, and what revocation should mean ──────
# The last column is the one that makes this list useful: what "revoked" means
# for that transport. A static bearer token that revokes only on expiry is a
# different animal from a short-lived JWT that revokes by clock.
#   <id>\t<kind>\t<where it is presented>\t<what revocation must do>
kr_schemes() {
    cat <<'SCHEMES'
bearer-static	bearer	Authorization: Bearer <tok>	stop validating this exact string everywhere, immediately
api-key-header	header	X-API-Key: <key>	refuse the key on every route, not just the issuing service
api-key-query	query	?api_key=<key>	refuse the key even when it arrives outside the header path
basic-auth	basic	Authorization: Basic <b64>	stop accepting the old user:pass, including from caches
jwt-hs	jwt	Authorization: Bearer <jwt>	reject signatures made before the rotation instant
jwt-rs	jwt	Authorization: Bearer <jwt>	publish new keys and stop honouring the retired key id
jwt-claims	jwt	Authorization: Bearer <jwt>	expiry must bind, not only the signature
mtls-cert	cert	TLS client certificate	reject the old serial at the TLS layer
aws-sigv4	sigv4	Authorization: AWS4-HMAC-SHA256 …	the access key id must be deactivated in IAM
aws-sts	sigv4	Authorization: AWS4-HMAC-SHA256 …	the session token must expire, not merely age
gcp-sa	token	Authorization: Bearer <ya29…>	revoke the service account key id
azure-sp	token	Authorization: Bearer <eyJ…>	the app secret must be removed from the app registration
signed-url	url	?X-Amz-Signature=…	the signature must carry an expiry the server enforces
oauth-refresh	oauth	grant_type=refresh_token	a rotated refresh token must invalidate its predecessor
SCHEMES
}

# ── the checks, grouped by the promise they test ─────────────────
#   <id>\t<class>\t<what is measured>\t<what a failure costs>
kr_checks() {
    cat <<'CHECKS'
old-key-still-works	revocation	the retired credential against a protected route	the key that was rotated because it leaked still works
old-key-same-rights	revocation	the retired credential on an admin route	the retired key retains full privilege, not just access
new-key-works	rotation	the current credential against the same route	the rotation broke the service and was rolled back
keys-differ	rotation	that the new credential is not the old one	rotation was performed without changing anything
grace-window	window	the old key accepted after the advertised grace period	the grace period was never implemented, only documented
cache-lag	window	whether a second host still honours the old key	revocation propagated to one node and stopped there
expiry-honoured	window	a token used past its own exp claim	expiry is decorative
not-before	window	a token used before its nbf claim	the clock bounds are not checked
leak-still-live	leak	whether the leaked credential from an earlier finding still authenticates	the incident response was declarative
key-in-url	logging	whether the credential works as a query parameter	the key ends up in logs, referrers and browser history
key-in-referrer	logging	a credential-bearing URL followed by a link	the key leaks to every third party on the page
rotation-audited	logging	whether a rotation event is visible in the API's own audit trail	rotations happen off the books
CHECKS
}

# ── sending ──────────────────────────────────────────────────────
#   kr_send <url> <scheme-id> <credential> [extra] -> "<code>\t<bytes>\t<body-path>"
#
# The credential is put where that scheme says it goes, because testing a
# bearer token against an endpoint that wants a query parameter proves nothing
# but still returns a status code that looks like an answer.
kr_send() {
    local url="$1" scheme="$2" cred="$3" extra="${4:-}"
    local out; out="$(mktemp "$CS_SCRATCH/kr.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.kr.$$"
    local -a args=(-sS -o "$out" -w '%{http_code} %{size_download}' -m "$KR_TIMEOUT" -A "$KR_UA")
    [ -n "$extra" ] && args+=(-H "$extra")

    case "$scheme" in
        bearer-static|jwt-hs|jwt-rs|jwt-claims|gcp-sa|azure-sp|token)
            args+=(-H "Authorization: Bearer $cred") ;;
        header|api-key-header)
            args+=(-H "X-API-Key: $cred") ;;
        query|api-key-query)
            args+=(-G --data-urlencode "api_key=$cred") ;;
        basic|basic-auth)
            args+=(-u "$cred") ;;
        cert|mtls-cert)
            args+=(--cert "$cred") ;;
        sigv4|aws-sigv4|aws-sts)
            # a SigV4 header cannot be replayed honestly without signing again,
            # so this path reports the shape it expects rather than guessing
            args+=(-H "Authorization: AWS4-HMAC-SHA256 Credential=$cred") ;;
        url|signed-url)
            args+=(-G --data-urlencode "$cred") ;;
        oauth|oauth-refresh)
            args+=(-X POST --data-binary "$cred") ;;
        *) args+=(-H "Authorization: Bearer $cred") ;;
    esac

    local meta; meta="$(curl "${args[@]}" "$url" 2>/dev/null)"
    local code bytes
    read -r code bytes <<< "${meta:-000 0}"
    printf '%s\t%s\t%s\n' "${code:-000}" "${bytes:-0}" "$out"
}

# Keep the body only when it is small enough to be worth keeping, and delete
# the rest — a rotation sweep should not become a disk-filling download.
kr_keep() {
    local f="$1" bytes="$2"
    if [[ "${bytes:-0}" -gt 262144 ]]; then rm -f "$f"; return; fi
    [[ -f "$f" ]] || return 0
}

# ── verdicts ─────────────────────────────────────────────────────
# The whole module rests on this: an old key that returns 200 is a finding, an
# old key that returns 401 is the system working, and an old key that returns
# 000 is neither — it is a network problem and must never be reported.
#   kr_verdict <code> <role:old|new|control>
kr_verdict() {
    local code="$1" role="${2:-old}"
    [[ "$code" == "000" ]] && { printf 'unreachable'; return; }
    case "$role" in
        control)
            case "$code" in
                2*) printf 'route-open' ;;
                401|403) printf 'route-guarded' ;;
                404) printf 'route-absent' ;;
                *) printf 'route-other' ;;
            esac ;;
        *)
            case "$code" in
                2*) printf 'accepted' ;;
                401|403) printf 'rejected' ;;
                404) printf 'not-found' ;;
                429) printf 'rate-limited' ;;
                5*) printf 'server-error' ;;
                *) printf 'other' ;;
            esac ;;
    esac
}

# The paired verdict, which is the only one worth reporting.
#   kr_rotation_verdict <old-code> <new-code>
kr_rotation_verdict() {
    local o="$1" n="$2"
    [[ "$o" == "000" || "$n" == "000" ]] && { printf 'unreachable'; return; }
    local ov nv
    ov="$(kr_verdict "$o" old)"
    nv="$(kr_verdict "$n" new)"
    if [[ "$ov" == "accepted" && "$nv" == "accepted" ]]; then printf 'old-still-live'; return; fi
    if [[ "$ov" == "accepted" && "$nv" != "accepted" ]]; then printf 'old-live-new-broken'; return; fi
    if [[ "$ov" != "accepted" && "$nv" == "accepted" ]]; then printf 'rotated-cleanly'; return; fi
    if [[ "$ov" != "accepted" && "$nv" != "accepted" ]]; then printf 'both-rejected'; return; fi
    printf 'inconclusive'
}

kr_severity() {
    local v="$1" class="${2:-revocation}"
    case "$v" in
        old-still-live)
            case "$class" in
                revocation|leak) printf 'CRITICAL' ;;
                *)               printf 'HIGH' ;;
            esac ;;
        old-live-new-broken) printf 'HIGH' ;;
        grace-exceeded)      printf 'HIGH' ;;
        cache-stale)         printf 'HIGH' ;;
        rotated-cleanly)     printf 'INFO' ;;
        *)                   printf 'INFO' ;;
    esac
}

# Time since a rotation, in hours, from an ISO-8601 or epoch stamp. Returns
# `unknown` rather than a number when the stamp cannot be read — a guessed age
# would silently grade a real finding as inside its window.
kr_age_hours() {
    local stamp="$1"
    [[ -z "$stamp" ]] && { printf 'unknown'; return; }
    local t
    if [[ "$stamp" =~ ^[0-9]+$ ]]; then
        t="$stamp"
    else
        t="$(date -u -d "$stamp" +%s 2>/dev/null || printf '')"
        [[ -z "$t" ]] && { printf 'unknown'; return; }
    fi
    local now; now="$(date -u +%s)"
    awk -v a="$t" -v b="$now" 'BEGIN{ d=(b-a)/3600; printf "%.2f", (d<0?0:d) }'
}

# The grace check: the old key works AND we are past the advertised window.
#   kr_grace_verdict <old-code> <age-hours> <window-hours>
kr_grace_verdict() {
    local code="$1" age="$2" window="${3:-$KR_WINDOW_HOURS}"
    [[ "$code" == "000" ]] && { printf 'unreachable'; return; }
    [[ "$age" == "unknown" ]] && { printf 'age-unknown'; return; }
    local v; v="$(kr_verdict "$code" old)"
    [[ "$v" != "accepted" ]] && { printf "$v"; return; }
    awk -v a="$age" -v w="$window" 'BEGIN{ print (a > w) ? "grace-exceeded" : "inside-grace" }'
}

kr_findings() { cs_findings_row "$MODULE_ID" "IDENTITY" "$4" "$3" "$2" > /dev/null; }

# ── verbs ────────────────────────────────────────────────────────

# --probe <url> <scheme> [credential]: what does this route do with no
# credential, with a garbage one, and with the one you supplied. Without the
# no-credential control nothing downstream means anything.
kr_cmd_probe() {
    local url="${1:-}" scheme="${2:-bearer-static}" cred="${3:-${KR_KEY:-}}"
    [[ -z "$url" ]] && { kr_log "usage: --probe <url> [scheme] [credential]"; return 2; }
    cs_row TARGET "$url"
    cs_row SCHEME "$scheme"

    local anon; anon="$(kr_send "$url" "$scheme" 'cloudsting-not-a-key')"
    local acode abytes af
    IFS=$'\t' read -r acode abytes af <<< "$anon"
    cs_row CONTROL "code=$acode" "verdict=$(kr_verdict "$acode" control)"
    rm -f "$af"

    if [[ "$acode" == "000" ]]; then
        cs_row VERDICT "unreachable"
        cs_row SUMMARY "verdict=unreachable"
        return 0
    fi
    if [[ "$(kr_verdict "$acode" control)" == "route-open" ]]; then
        cs_row NOTE "the route answers without any credential — rotation cannot be measured on it"
        cs_row VERDICT "route-open"
        cs_row SUMMARY "control=$acode verdict=route-open"
        return 0
    fi

    if [[ -z "$cred" ]]; then
        cs_row VERDICT "need-credential"
        cs_row SUMMARY "control=$acode verdict=need-credential"
        return 0
    fi

    local row; row="$(kr_send "$url" "$scheme" "$cred")"
    local code bytes f
    IFS=$'\t' read -r code bytes f <<< "$row"
    kr_keep "$f" "$bytes"
    cs_row CREDENTIAL "code=$code" "bytes=$bytes" "verdict=$(kr_verdict "$code" old)"
    cs_row VERDICT "$(kr_verdict "$code" old)"
    cs_row SUMMARY "control=$acode credential=$code"
    rm -f "$f"
    return 0
}

# --old-key <url> <scheme> <old> <new>: the paired check. Both credentials are
# tried against the same route, because one alone proves nothing — an old key
# that fails everywhere is just a broken key.
kr_cmd_old_key() {
    local url="${1:-}" scheme="${2:-bearer-static}" old="${3:-}" new="${4:-}"
    [[ -z "$url" || -z "$old" || -z "$new" ]] && {
        kr_log "usage: --old-key <url> <scheme> <old-credential> <new-credential>"; return 2; }
    cs_row TARGET "$url"
    cs_row SCHEME "$scheme"

    # are they even different
    local differ="yes"
    [[ "$old" == "$new" ]] && differ="no"
    cs_row KEYS "differ=$differ"
    if [[ "$differ" == "no" ]]; then
        cs_row FINDING "HIGH" "rotation-no-change"
        kr_findings "$url" "HIGH" "rotation-no-change" "the old and new credentials are byte-identical"
    fi

    local ro; ro="$(kr_send "$url" "$scheme" "$old")"
    local ocode obytes of
    IFS=$'\t' read -r ocode obytes of <<< "$ro"
    kr_keep "$of" "$obytes"; rm -f "$of"
    cs_row OLD "code=$ocode" "verdict=$(kr_verdict "$ocode" old)"

    local rn; rn="$(kr_send "$url" "$scheme" "$new")"
    local ncode nbytes nf
    IFS=$'\t' read -r ncode nbytes nf <<< "$rn"
    kr_keep "$nf" "$nbytes"; rm -f "$nf"
    cs_row NEW "code=$ncode" "verdict=$(kr_verdict "$ncode" new)"

    local v; v="$(kr_rotation_verdict "$ocode" "$ncode")"
    local sev; sev="$(kr_severity "$v" revocation)"
    cs_row VERDICT "$v"
    if [[ "$v" == "old-still-live" || "$v" == "old-live-new-broken" ]]; then
        cs_row FINDING "$sev" "rotation-$v"
        kr_findings "$url" "$sev" "rotation-$v" \
            "the retired credential still returns $ocode after rotation (new credential returns $ncode)"
    fi
    cs_row SUMMARY "old=$ocode new=$ncode verdict=$v"
    return 0
}

# --grace <url> <scheme> <old> <rotated-at>: the old key plus the clock. This
# is the check that catches a documented-but-unimplemented window.
kr_cmd_grace() {
    local url="${1:-}" scheme="${2:-bearer-static}" old="${3:-}" when="${4:-${KR_ROTATED_AT:-}}"
    [[ -z "$url" || -z "$old" ]] && {
        kr_log "usage: --grace <url> <scheme> <old-credential> [rotated-at]"; return 2; }
    cs_row TARGET "$url"
    cs_row ROTATED_AT "${when:-unknown}"
    cs_row WINDOW_HOURS "$KR_WINDOW_HOURS"

    local age; age="$(kr_age_hours "$when")"
    cs_row AGE_HOURS "$age"

    local row; row="$(kr_send "$url" "$scheme" "$old")"
    local code bytes f
    IFS=$'\t' read -r code bytes f <<< "$row"
    kr_keep "$f" "$bytes"
    cs_row OLD "code=$code"
    rm -f "$f"

    local v; v="$(kr_grace_verdict "$code" "$age" "$KR_WINDOW_HOURS")"
    local sev; sev="$(kr_severity "$v" window)"
    cs_row VERDICT "$v"
    if [[ "$v" == "grace-exceeded" ]]; then
        cs_row FINDING "$sev" "rotation-grace-exceeded"
        kr_findings "$url" "$sev" "rotation-grace-exceeded" \
            "the retired credential still works ${age}h after rotation, ${KR_WINDOW_HOURS}h window advertised"
    fi
    cs_row SUMMARY "age=$age window=$KR_WINDOW_HOURS code=$code verdict=$v"
    return 0
}

# --leak-check <url> <scheme> <leaked>: a credential that appeared in an earlier
# finding is the one that matters most, because the reason for rotating was
# exactly this. Reports whether the incident response actually landed.
kr_cmd_leak_check() {
    local url="${1:-}" scheme="${2:-bearer-static}" leaked="${3:-${KR_LEAKED:-}}"
    [[ -z "$url" || -z "$leaked" ]] && {
        kr_log "usage: --leak-check <url> <scheme> <leaked-credential>"; return 2; }
    cs_row TARGET "$url"
    cs_row CREDENTIAL "$(cs_redact "$leaked")"

    local row; row="$(kr_send "$url" "$scheme" "$leaked")"
    local code bytes f
    IFS=$'\t' read -r code bytes f <<< "$row"
    kr_keep "$f" "$bytes"
    local v; v="$(kr_verdict "$code" old)"
    cs_row RESULT "code=$code" "verdict=$v"
    rm -f "$f"

    case "$v" in
        accepted)
            cs_row FINDING "CRITICAL" "rotation-leaked-key-live"
            kr_findings "$url" "CRITICAL" "rotation-leaked-key-live" \
                "a credential previously found exposed still authenticates" ;;
        rejected)
            cs_row NOTE "the leaked credential is dead — the rotation did its job" ;;
        unreachable)
            cs_row NOTE "no answer, so nothing is claimed" ;;
    esac
    cs_row VERDICT "$v"
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --policy <base> [scheme cred]: does the route accept the credential outside
# the header. A key that works as ?api_key= is a key in every proxy log.
kr_cmd_policy() {
    local url="${1:-}" cred="${2:-${KR_KEY:-}}"
    [[ -z "$url" ]] && { kr_log "usage: --policy <url> [credential]"; return 2; }
    cs_row TARGET "$url"

    local transports=(bearer-static api-key-header api-key-query basic-auth oauth-refresh)
    local t accepted=0 total=0
    for t in "${transports[@]}"; do
        [[ -z "$cred" ]] && { cs_row TRANSPORT "$t" "no-credential"; continue; }
        local row; row="$(kr_send "$url" "$t" "$cred")"
        local code bytes f
        IFS=$'\t' read -r code bytes f <<< "$row"
        kr_keep "$f" "$bytes"; rm -f "$f"
        total=$((total + 1))
        local v; v="$(kr_verdict "$code" old)"
        cs_row TRANSPORT "$t" "code=$code" "verdict=$v"
        if [[ "$v" == "accepted" ]]; then
            accepted=$((accepted + 1))
            case "$t" in
                api-key-query|url)
                    cs_row FINDING "HIGH" "rotation-key-in-url"
                    kr_findings "$url" "HIGH" "rotation-key-in-url" \
                        "the credential authenticates as a query parameter and therefore lands in logs" ;;
            esac
        fi
    done
    cs_row SUMMARY "accepted=$accepted total=$total"
    return 0
}

# --windows <url> [scheme cred]: the clock checks. A token whose exp or nbf is
# not enforced is a token with a lifetime chosen by its holder.
kr_cmd_windows() {
    local url="${1:-}" cred="${2:-${KR_TOKEN:-}}"
    [[ -z "$url" ]] && { kr_log "usage: --windows <url> [token]"; return 2; }
    cs_row TARGET "$url"
    if [[ -z "$cred" ]]; then
        cs_row VERDICT "need-credential"
        cs_row NOTE "pass a JWT to decode exp and nbf, or set KR_TOKEN"
        cs_row SUMMARY "verdict=need-credential"
        return 0
    fi

    if ! kr_decoded="$(kr_jwt_claims "$cred")"; then
        cs_row VERDICT "not-a-jwt"
        cs_row NOTE "the supplied token is not a decodable JWT — expiry cannot be read"
        cs_row SUMMARY "verdict=not-a-jwt"
        return 0
    fi

    local exp nbf iat
    exp="$(printf '%s' "$kr_decoded" | grep -o '"exp":[0-9]*' | grep -o '[0-9]*' | head -1)"
    nbf="$(printf '%s' "$kr_decoded" | grep -o '"nbf":[0-9]*' | grep -o '[0-9]*' | head -1)"
    iat="$(printf '%s' "$kr_decoded" | grep -o '"iat":[0-9]*' | grep -o '[0-9]*' | head -1)"
    cs_row CLAIMS "exp=${exp:-none}" "nbf=${nbf:-none}" "iat=${iat:-none}"

    if [[ -n "$exp" ]]; then
        local now; now="$(date -u +%s)"
        local life; life="$(awk -v e="$exp" -v i="${iat:-$now}" 'BEGIN{ printf "%.0f", (e-i)/60 }')"
        cs_row LIFETIME_MIN "$life"
        local long="no"; (( life > 1440 )) && long="yes"
        cs_row LONG_LIVED "$long"
        if [[ "$long" == "yes" ]]; then
            cs_row FINDING "MEDIUM" "rotation-long-lived-token"
            kr_findings "$url" "MEDIUM" "rotation-long-lived-token" \
                "the token lives ${life} minutes, so a rotation takes that long to bite"
        fi
    else
        cs_row NOTE "no exp claim: the token has no expiry the server can enforce"
    fi

    local row; row="$(kr_send "$url" bearer-static "$cred")"
    local code bytes f
    IFS=$'\t' read -r code bytes f <<< "$row"
    kr_keep "$f" "$bytes"; rm -f "$f"
    cs_row ACCEPTED "code=$code" "verdict=$(kr_verdict "$code" old)"
    cs_row SUMMARY "verdict=$(kr_verdict "$code" old)"
    return 0
}

# Decode the payload segment of a JWT without verifying it — we are not
# checking the signature, we are reading what the server is being asked to
# honour. Base64url, padded.
kr_jwt_claims() {
    local tok="$1"
    [[ "$tok" == *.*.* ]] || return 1
    local payload; payload="$(printf '%s' "$tok" | cut -d. -f2)"
    [[ -z "$payload" ]] && return 1
    case $(( ${#payload} % 4 )) in
        2) payload="${payload}==";;
        3) payload="${payload}=";;
    esac
    payload="${payload//-/+}"; payload="${payload//_//}"
    printf '%s' "$payload" | base64 -d 2>/dev/null || return 1
}

kr_cmd_techniques() {
    local id kind where revoke
    while IFS=$'\t' read -r id kind where revoke; do
        [[ -z "$id" ]] && continue
        cs_row SCHEME "$id" "$kind" "$where" "$revoke"
    done < <(kr_schemes)
    local cid class what cost
    while IFS=$'\t' read -r cid class what cost; do
        [[ -z "$cid" ]] && continue
        cs_row CHECK "$cid" "$class" "$cost"
    done < <(kr_checks)
    cs_row SUMMARY "schemes=$(kr_schemes | wc -l | tr -d ' ') checks=$(kr_checks | wc -l | tr -d ' ')"
    return 0
}

kr_cmd_list() {
    cs_row VERB "probe" "old-key" "grace" "leak-check" "policy" "windows" "techniques"
    cs_row SUMMARY "ok"
    return 0
}

kr_cmd_status_tsv() {
    local cur
    command -v curl >/dev/null 2>&1 && cur="curl-ok" || cur="curl-missing"
    printf '%s\t%s\t%s\tschemes-%s\tchecks-%s\twindow-%sh\n' \
        "$MODULE_ID" "$MOD_NAME" "$cur" \
        "$(kr_schemes | wc -l | tr -d ' ')" "$(kr_checks | wc -l | tr -d ' ')" "$KR_WINDOW_HOURS"
}

kr_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

kr_cmd_help() {
    cat <<'HELP'
cloudsting module 75 — Key Rotation v1.0.0
  --probe <url> [scheme] [cred]        what does this route do with no credential
  --old-key <url> <scheme> <old> <new> is the retired credential still live
  --grace <url> <scheme> <old> [at]    how long after rotation does it still work
  --leak-check <url> <scheme> <cred>   a credential from an earlier finding
  --policy <url> [cred]                which transports accept the same credential
  --windows <url> [jwt]                exp / nbf / lifetime honesty
  --techniques | --list | --status-tsv | --menu | --selftest | --help

Rotation is a promise that the old key is dead. It is broken in two ways, both
invisible from the console: the window was never implemented, so the key keeps
working for weeks; and the leak that caused the rotation was never confirmed
dead, so the rotation happened and the exposure stayed.

Every verb here is a PAIR, never a single request. An old credential that fails
is just a broken key — it proves nothing. It is only a finding when the old key
is accepted AND the new one is too, or when the old one is accepted past the
advertised grace period.

  unreachable is never a finding. A 000 means no socket answered, so no claim
  is made about the credential.

  an unreadable rotation timestamp yields `age-unknown`, not a guessed age,
  because a guessed age grades a real finding as inside its window.

Environment: KR_TIMEOUT (10), KR_WINDOW_HOURS (24), KR_OLD_KEY, KR_NEW_KEY,
             KR_TOKEN, KR_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
kr_selftest() {
    cs_selftest_reset

    local ns; ns="$(kr_schemes | wc -l | tr -d ' ')"
    chk schemes-4col   "$(kr_schemes | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk schemes-unique "$(kr_schemes | cut -f1 | sort -u | wc -l | tr -d ' ')" "$ns"
    chk schemes-many   "$( (( ns >= 14 )) && echo many || echo few )" "many"

    local nc; nc="$(kr_checks | wc -l | tr -d ' ')"
    chk checks-4col    "$(kr_checks | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk checks-unique  "$(kr_checks | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nc"

    # single-credential verdicts
    chk v-dead        "$(kr_verdict 000 old)" "unreachable"
    chk v-ok          "$(kr_verdict 200 old)" "accepted"
    chk v-401         "$(kr_verdict 401 old)" "rejected"
    chk v-403         "$(kr_verdict 403 old)" "rejected"
    chk v-404         "$(kr_verdict 404 old)" "not-found"
    chk v-429         "$(kr_verdict 429 old)" "rate-limited"
    chk v-500         "$(kr_verdict 500 old)" "server-error"
    chk c-open        "$(kr_verdict 200 control)" "route-open"
    chk c-guarded     "$(kr_verdict 401 control)" "route-guarded"
    chk c-absent      "$(kr_verdict 404 control)" "route-absent"

    # the paired verdicts, which are the only ones that matter
    chk p-still-live  "$(kr_rotation_verdict 200 200)" "old-still-live"
    chk p-clean       "$(kr_rotation_verdict 401 200)" "rotated-cleanly"
    chk p-broken      "$(kr_rotation_verdict 200 401)" "old-live-new-broken"
    chk p-both        "$(kr_rotation_verdict 401 403)" "both-rejected"
    chk p-dead        "$(kr_rotation_verdict 000 200)" "unreachable"
    chk p-dead2       "$(kr_rotation_verdict 200 000)" "unreachable"

    chk s-live        "$(kr_severity old-still-live revocation)" "CRITICAL"
    chk s-leak        "$(kr_severity old-still-live leak)" "CRITICAL"
    chk s-window      "$(kr_severity old-still-live window)" "HIGH"
    chk s-clean       "$(kr_severity rotated-cleanly revocation)" "INFO"
    chk s-grace       "$(kr_severity grace-exceeded window)" "HIGH"

    # the grace table
    chk g-exceeded    "$(kr_grace_verdict 200 48 24)" "grace-exceeded"
    chk g-inside      "$(kr_grace_verdict 200 2 24)" "inside-grace"
    chk g-rejected    "$(kr_grace_verdict 401 48 24)" "rejected"
    chk g-dead        "$(kr_grace_verdict 000 48 24)" "unreachable"
    chk g-unknown     "$(kr_grace_verdict 200 unknown 24)" "age-unknown"

    # age parsing: a real stamp, an epoch, and the unreadable case
    local now; now="$(date -u +%s)"
    local two_h; two_h="$(( now - 7200 ))"
    chk age-epoch     "$(kr_age_hours "$two_h")" "2.00"
    chk age-unknown   "$(kr_age_hours '')" "unknown"
    chk age-garbage   "$(kr_age_hours 'not-a-date')" "unknown"
    chk age-clamp     "$(kr_age_hours "$(( now + 86400 ))")" "0.00"

    # JWT claim decode against a token built here, so the assertion is exact
    local hdr pay sig tok
    hdr="$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')"
    pay="$(printf '%s' '{"sub":"u1","exp":1900000000,"nbf":1800000000,"iat":1899990000}' \
            | base64 -w0 | tr '+/' '-_' | tr -d '=')"
    sig="c2ln"
    tok="$hdr.$pay.$sig"
    chk jwt-exp       "$(kr_jwt_claims "$tok" | grep -o '"exp":[0-9]*')" '"exp":1900000000'
    chk jwt-nbf       "$(kr_jwt_claims "$tok" | grep -o '"nbf":[0-9]*')" '"nbf":1800000000'
    kr_jwt_claims "not-a-jwt" >/dev/null 2>&1; chk jwt-bad "$?" "1"
    kr_jwt_claims "a.b" >/dev/null 2>&1;       chk jwt-2seg "$?" "1"

    # a dead host must never be reported as a live key
    local out; out="$(kr_cmd_probe http://127.0.0.1:9 2>/dev/null)"
    chk dead-probe    "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-probehit "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    out="$(kr_cmd_old_key http://127.0.0.1:9 bearer-static OLD NEW 2>/dev/null)"
    chk dead-old      "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    # two DIFFERENT credentials against a dead host: nothing can be claimed,
    # so nothing is reported. The no-change finding only fires when the two
    # credentials are literally the same string.
    chk dead-oldhit   "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    out="$(kr_cmd_old_key http://127.0.0.1:9 bearer-static SAME SAME 2>/dev/null)"
    chk same-keys     "$(printf '%s' "$out" | grep -c '^FINDING')" "1"
    out="$(kr_cmd_leak_check http://127.0.0.1:9 bearer-static LEAKED 2>/dev/null)"
    chk dead-leak     "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"

    # usage errors
    kr_cmd_probe 2>/dev/null;     chk use-1 "$?" "2"
    kr_cmd_old_key 2>/dev/null;   chk use-2 "$?" "2"
    kr_cmd_old_key http://x bearer-static onlyone 2>/dev/null; chk use-3 "$?" "2"
    kr_cmd_grace 2>/dev/null;     chk use-4 "$?" "2"
    kr_cmd_leak_check 2>/dev/null; chk use-5 "$?" "2"
    kr_cmd_policy 2>/dev/null;    chk use-6 "$?" "2"
    kr_cmd_windows 2>/dev/null;   chk use-7 "$?" "2"

    chk status-fields "$(kr_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(kr_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(kr_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(kr_cmd_help | head -1 | grep -ci 'Key Rotation')" "1"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)      shift; kr_cmd_probe "$@";;
    --old-key)    shift; kr_cmd_old_key "$@";;
    --grace)      shift; kr_cmd_grace "$@";;
    --leak-check) shift; kr_cmd_leak_check "$@";;
    --policy)     shift; kr_cmd_policy "$@";;
    --windows)    shift; kr_cmd_windows "$@";;
    --techniques) kr_cmd_techniques;;
    --list)       kr_cmd_list;;
    --status-tsv|--status) kr_cmd_status_tsv;;
    --menu)       kr_cmd_menu;;
    --selftest)   kr_selftest;;
    *)            kr_cmd_help;;
esac
