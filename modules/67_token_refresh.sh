#!/usr/bin/env bash
# 67_token_refresh.sh — cloudsting module 67: the token that outlives the logout
# Verbs: --probe | --rotate | --replay | --revoke | --fixation | --window
#        | --scopes | --verdicts | --list | --status-tsv | --menu | --selftest
#        | --help
#
# A refresh token is a second key to the same door, and most implementations
# hand it out and then never take it back. Rotation without invalidation, a
# logout that only clears the cookie, and a refresh that survives a password
# change are three different bugs that all read as "the session is still alive".
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="67_token_refresh"
MOD_NAME="Token Refresh & Session Hijack (the token that outlives the logout)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/token_refresh"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"
TOK_FILE="$OUT_DIR/tokens-$RUN_ID.json"

: "${TR_TIMEOUT:=10}"
: "${TR_FOLLOW:=0}"
: "${TR_GRANT:=refresh_token}"
: "${TR_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/67}"

tr_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── what a token endpoint forgets ────────────────────────────────
#   <id>\t<class>\t<what the server fails to do>\t<what an attacker gets>
tr_vectors() {
    cat <<'VECTORS'
rotate-not-invalidate	rotation	issues a new refresh token and keeps the old one valid	a captured refresh token is a permanent key
rotate-blank	rotation	issues a new one and the old one still works after N rotations	the whole chain, replayed from any point
no-logout-invalidate	revocation	clears the cookie but leaves the token live at the endpoint	any harvested token survives the victim's logout
no-revoke-on-password	revocation	a password change does not revoke issued refresh tokens	one reset does not evict an intruder
replay-after-use	reuse	a consumed refresh token is accepted a second time	the classic stolen-token replay
race-refresh	reuse	one token exchanged concurrently yields two valid access tokens	double the session from one artifact
refresh-cross-ip	context	refresh works from an unrelated address and agent	a token is portable off the victim's machine
refresh-no-expiry	expiry	a refresh token with no expiry is accepted	long after any sane session end
refresh-long-expiry	expiry	a refresh token still works past its stated window	the window is decorative
access-after-revoke	expiry	an access token minted before revocation keeps working	for the rest of its lifetime
scope-escalation	scope	the refresh grants more scope than was originally issued	a low-privilege token elevated at refresh time
scope-retained	scope	a downscoped refresh restores the original scope	attenuation is not honoured
fixation-pre	context	the server accepts a refresh token it did not issue	external control of issue
cookie-no-httponly	context	the refresh cookie is readable from script	one XSS exfiltrates everything
VECTORS
}

# The grant types worth walking. A server that implements the deprecated one is
# a server with an older auth stack, and older stacks forget more.
#   <grant>\t<what to send>\t<status as it stands>
tr_grants() {
    cat <<'GRANTS'
refresh_token	the documented modern grant	recommended
password	resource owner password credentials — deprecated by RFC 6749 §4.3	if it still works, the stack predates the modern one
implicit	response_type=token — no refresh token at all, but a long-lived access token	deprecated, sometimes still served
client_credentials	no user, so a leaked client secret is a permanent machine session	check whether a user token can be issued this way
device_code	slow grants tend to have no refresh rotation at all	common on set-top boxes and portals
GRANTS
}

# ── the verdicts ─────────────────────────────────────────────────
# The control is "the token I was given actually refreshes". If that fails the
# endpoint is not what we think it is, and every other reading is noise.
#   tr_verdict <ctl-code> <var-code> <same-token-count> <vector-id>
tr_verdict() {
    local cc="$1" vc="$2" same="${3:-0}" id="${4:-}"
    [[ "$cc" == "000" || "$vc" == "000" ]] && { printf 'unreachable'; return; }
    [[ "$cc" =~ ^2 ]] || { printf 'control-refused'; return; }
    case "$vc" in
        401|403) printf 'revoked'; return ;;
        400|422) printf 'rejected'; return ;;
        5*)      printf 'error'; return ;;
    esac
    [[ "$vc" =~ ^2 ]] || { printf 'differs'; return; }
    case "$id" in
        rotate-not-invalidate)  (( same >= 2 )) && { printf 'old-still-valid'; return; } ;;
        rotate-blank)           (( same >= 3 )) && { printf 'chain-replayable'; return; } ;;
        replay-after-use)       printf 'replayed'; return ;;
        race-refresh)           printf 'double-issued'; return ;;
        no-logout-invalidate)   printf 'survives-logout'; return ;;
        no-revoke-on-password)  printf 'survives-password-change'; return ;;
        refresh-cross-ip)       printf 'portable'; return ;;
        refresh-no-expiry)      printf 'no-expiry'; return ;;
        refresh-long-expiry)    printf 'expiry-ignored'; return ;;
        access-after-revoke)    printf 'access-lingers'; return ;;
        scope-escalation)       printf 'scope-escalated'; return ;;
        scope-retained)         printf 'scope-retained'; return ;;
        fixation-pre)           printf 'external-token-accepted'; return ;;
        cookie-no-httponly)     printf 'cookie-readable'; return ;;
    esac
    printf 'accepted'
}

tr_severity() {
    local v="$1"
    case "$v" in
        old-still-valid|chain-replayable|replayed|survives-logout|\
        survives-password-change|portable|no-expiry|access-lingers|\
        scope-escalated|scope-retained|external-token-accepted) printf 'CRITICAL' ;;
        double-issued|expiry-ignored|cookie-readable)             printf 'HIGH' ;;
        accepted)                                                 printf 'MEDIUM' ;;
        *)                                                        printf 'INFO' ;;
    esac
}

tr_findings() {
    cs_findings_row "$MODULE_ID" "WEBAPI" "$1" "$2" "$3" "$4"
}

# ── talking to the token endpoint ────────────────────────────────
#   tr_post <url> <data> [extra-header]
#   -> code \x1f bytes \x1f hash \x1f body-path
tr_post() {
    local url="$1" data="$2" hdr="${3:-}"
    local outf; outf="$(mktemp "$CS_SCRATCH/tr.XXXXXX")" 2>/dev/null || outf="$OUT_DIR/.tr.$$"
    local -a args=(-sS -o "$outf" -w '%{http_code} %{time_total}' -m "$TR_TIMEOUT"
                   -A "$TR_UA" -X POST
                   -H 'Content-Type: application/x-www-form-urlencoded'
                   --data "$data")
    [[ -n "$hdr" ]] && args+=(-H "$hdr")
    [ "$TR_FOLLOW" = "1" ] && args+=(-L)
    local meta code="" secs="0"
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)"
    read -r code secs <<<"${meta:-000 0}"
    [[ -z "$code" ]] && code="000"
    local bytes hash
    bytes="$(wc -c < "$outf" 2>/dev/null | tr -d ' ')"
    hash="$(sha1sum "$outf" 2>/dev/null | cut -c1-12)"
    printf '%s\037%s\037%s\037%s\n' "$code" "${bytes:-0}" "$hash" "$outf"
}

# Pull a field out of a token response. jq when the body is JSON, a grep when a
# server answers form-encoded, and empty when it is neither — an empty token is
# an answer, not an error.
tr_field() {
    local bodyf="$1" name="$2"
    [[ -s "$bodyf" ]] || { printf ''; return; }
    local v
    v="$(jq -r --arg n "$name" '.[$n] // empty' "$bodyf" 2>/dev/null)"
    if [[ -z "$v" ]]; then
        v="$(grep -aoE "(^|[&\"',{ ])$name[\"']?[:=][\"']?[^&\"',} ]+" "$bodyf" 2>/dev/null \
             | head -1 | sed -E "s/.*$name[\"']?[:=][\"']?//")"
    fi
    printf '%s' "$v"
}

# A response is only a refresh if it carries a new access token. Anything else
# is a refusal wearing a 200.
tr_is_token() {
    local bodyf="$1"
    local at rt
    at="$(tr_field "$bodyf" access_token)"
    rt="$(tr_field "$bodyf" refresh_token)"
    [[ -n "$at" || -n "$rt" ]] && printf 'token' || printf 'no-token'
}

# ── verbs ────────────────────────────────────────────────────────

# --probe <url> [refresh-token-file]: does the token endpoint work with the
# artifact we hold. This is the control for everything else in the module.
tr_cmd_probe() {
    local url="${1:-}" tokf="${2:-}"
    [[ -z "$url" ]] && { tr_log "usage: --probe <token-endpoint> [refresh-token-file]"; return 2; }

    local tok=""
    if [[ -n "$tokf" ]]; then
        [[ -f "$tokf" ]] || { tr_log "no such file: $tokf"; return 2; }
        tok="$(tr -d '\r\n' < "$tokf")"
    fi
    if [[ -z "$tok" ]]; then
        cs_row TARGET "$url"
        cs_row ERROR "no refresh token supplied — pass the file holding one"
        cs_row USAGE "cloudsting run 67 --probe https://idp/token /path/to/refresh.txt"
        cs_row VERDICT "no-token-supplied"
        return 0
    fi

    cs_row TARGET "$url"
    cs_row TOKEN "length=${#tok}" "fingerprint=$(cs_fingerprint <<<"$tok")"

    local data="grant_type=$TR_GRANT&refresh_token=$(printf '%s' "$tok" | jq -sRr @uri 2>/dev/null || printf '%s' "$tok")"
    local code bytes hash body
    cs_split "$(tr_post "$url" "$data")" code bytes hash body
    local kind; kind="$(tr_is_token "$body")"
    local rt; rt="$(tr_field "$body" refresh_token)"
    local at; at="$(tr_field "$body" access_token)"

    cs_row RESPONSE "code=$code" "bytes=$bytes" "kind=$kind"
    [[ -n "$at" ]] && cs_row ACCESS "length=${#at}"
    [[ -n "$rt" ]] && cs_row REFRESH "length=${#rt}" "same=$([[ "$rt" == "$tok" ]] && echo yes || echo no)"

    local v
    if [[ "$code" == "000" ]]; then v="unreachable"
    elif [[ "$code" =~ ^2 && "$kind" == "token" ]]; then v="refreshes"
    elif [[ "$code" =~ ^2 ]]; then v="answers-no-token"
    elif [[ "$code" == "400" || "$code" == "422" ]]; then v="rejected"
    elif [[ "$code" == "401" || "$code" == "403" ]]; then v="refused"
    else v="inconclusive"; fi

    cs_row VERDICT "$v"
    cs_row SUMMARY "code=$code verdict=$v"
    rm -f "$body"
    return 0
}

# --rotate <url> <token-file> [rounds]: exchange the token repeatedly, keeping
# each refresh token and re-using it. A server that rotates correctly gives a
# new one each time and kills the old; one that does not keeps the same token
# valid forever.
tr_cmd_rotate() {
    local url="${1:-}" tokf="${2:-}" rounds="${3:-5}"
    [[ -z "$url" || -z "$tokf" ]] && { tr_log "usage: --rotate <token-endpoint> <refresh-token-file> [rounds]"; return 2; }
    [[ -f "$tokf" ]] || { tr_log "no such file: $tokf"; return 2; }

    local cur; cur="$(tr -d '\r\n' < "$tokf")"
    local orig="$cur"
    cs_row TARGET "$url"
    cs_row ROUNDS "$rounds"
    : > "$PROBE_FILE"

    local i same=0 fresh=0 dead=0 last_code="000"
    for (( i = 1; i <= rounds; i++ )); do
        local data="grant_type=$TR_GRANT&refresh_token=$(printf '%s' "$cur" | jq -sRr @uri 2>/dev/null || printf '%s' "$cur")"
        local code bytes hash body
        cs_split "$(tr_post "$url" "$data")" code bytes hash body
        last_code="$code"
        local rt; rt="$(tr_field "$body" refresh_token)"

        if [[ "$code" =~ ^2 ]] && [[ -n "$rt" ]]; then
            if [[ "$rt" == "$orig" ]]; then
                same=$((same + 1)); cs_row ROUND "$i" "code=$code" "refresh=same"
            else
                fresh=$((fresh + 1)); cs_row ROUND "$i" "code=$code" "refresh=new"
            fi
            printf 'round\t%s\t%s\t%s\n' "$i" "$code" "${rt:0:6}" >> "$PROBE_FILE"
            cur="$rt"
        else
            dead=$((dead + 1))
            cs_row ROUND "$i" "code=$code" "refresh=none"
            break
        fi
        rm -f "$body"
    done

    # the decisive test: the ORIGINAL token, offered again at the end. A server
    # that rotated properly refuses it. One that never invalidated takes it back.
    local o_code o_bytes o_hash o_body
    local odata="grant_type=$TR_GRANT&refresh_token=$(printf '%s' "$orig" | jq -sRr @uri 2>/dev/null || printf '%s' "$orig")"
    cs_split "$(tr_post "$url" "$odata")" o_code o_bytes o_hash o_body
    local o_kind; o_kind="$(tr_is_token "$o_body")"
    rm -f "$o_body"

    cs_row ORIGINAL "code=$o_code" "kind=$o_kind"
    local v
    if [[ "$last_code" == "000" || "$o_code" == "000" ]]; then
        # nothing answered; a silent host refused nothing, so this is not
        # "rejected" — rejected would mean the server looked at the token
        v="inconclusive"
    elif [[ "$same" -ge 3 ]]; then
        v="chain-replayable"
    elif [[ "$same" -ge 1 ]]; then
        v="old-still-valid"
    elif [[ "$o_code" =~ ^2 && "$o_kind" == "token" ]]; then
        v="old-still-valid"
    elif [[ "$fresh" -ge 1 ]]; then
        v="rotates-correctly"
    elif [[ "$dead" -ge 1 ]]; then
        v="rejected"
    else
        v="inconclusive"
    fi

    cs_row VERDICT "$v" "same=$same new=$fresh dead=$dead"
    if [[ "$v" == "old-still-valid" || "$v" == "chain-replayable" ]]; then
        local sev; sev="$(tr_severity "$v")"
        tr_findings "$url" "$sev" "refresh-$v" \
            "the original refresh token was still accepted after $fresh rotation(s) — a captured token never expires"
        cs_row FINDING "$sev" "refresh-$v"
    fi
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --replay <url> <token-file>: use one refresh token twice in a row. The second
# use is the attack, and a server that answers it has no reuse detection.
tr_cmd_replay() {
    local url="${1:-}" tokf="${2:-}"
    [[ -z "$url" || -z "$tokf" ]] && { tr_log "usage: --replay <token-endpoint> <refresh-token-file>"; return 2; }
    [[ -f "$tokf" ]] || { tr_log "no such file: $tokf"; return 2; }

    local tok; tok="$(tr -d '\r\n' < "$tokf")"
    cs_row TARGET "$url"
    local data="grant_type=$TR_GRANT&refresh_token=$(printf '%s' "$tok" | jq -sRr @uri 2>/dev/null || printf '%s' "$tok")"

    local c1 b1 h1 f1 c2 b2 h2 f2
    cs_split "$(tr_post "$url" "$data")" c1 b1 h1 f1
    local k1; k1="$(tr_is_token "$f1")"
    cs_row USE "first" "code=$c1" "kind=$k1"

    cs_split "$(tr_post "$url" "$data")" c2 b2 h2 f2
    local k2; k2="$(tr_is_token "$f2")"
    cs_row USE "second" "code=$c2" "kind=$k2"

    local v; v="$(tr_verdict "$c1" "$c2" 0 replay-after-use)"
    # a second exchange that returns the SAME access token is a cache, not a
    # second session; only a different token means the replay really worked
    if [[ "$v" == "replayed" && "$h1" == "$h2" ]]; then v="replayed-cached"; fi
    rm -f "$f1" "$f2"

    cs_row VERDICT "$v" "first=$c1 second=$c2"
    if [[ "$v" == "replayed" ]]; then
        tr_findings "$url" "CRITICAL" "refresh-replay" \
            "one refresh token was exchanged twice and both returned fresh credentials — no reuse detection"
        cs_row FINDING "CRITICAL" "refresh-replay"
    elif [[ "$v" == "replayed-cached" ]]; then
        cs_row NOTE "the second exchange returned the identical response — a cache, not a second session"
    fi
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --logout <token-url> <refresh-token-file> [revoke-url] [access-token]: the
# question is never "did logout return 200", it is "does the token still work
# afterwards".
tr_cmd_revoke() {
    local tok_url="${1:-}" tokf="${2:-}" rev_url="${3:-}" access="${4:-}"
    [[ -z "$tok_url" || -z "$tokf" ]] && {
        tr_log "usage: --revoke <token-endpoint> <refresh-token-file> [revoke-url] [access-token]"
        return 2; }
    [[ -f "$tokf" ]] || { tr_log "no such file: $tokf"; return 2; }

    local tok; tok="$(tr -d '\r\n' < "$tokf")"
    cs_row TARGET "$tok_url"
    [[ -n "$rev_url" ]] && cs_row REVOKE "$rev_url"

    # 0. it works at all
    local data="grant_type=$TR_GRANT&refresh_token=$(printf '%s' "$tok" | jq -sRr @uri 2>/dev/null || printf '%s' "$tok")"
    local c0 b0 h0 f0
    cs_split "$(tr_post "$tok_url" "$data")" c0 b0 h0 f0
    local k0; k0="$(tr_is_token "$f0")"; rm -f "$f0"
    cs_row BEFORE "code=$c0" "kind=$k0"

    # 1. revoke, by RFC 7009 form or by whatever URL was supplied
    local rev_target="${rev_url:-$tok_url}"
    local rcode="skip"
    if [[ -n "$rev_url" ]]; then
        local rdata="token=$(printf '%s' "$tok" | jq -sRr @uri 2>/dev/null || printf '%s' "$tok")&token_type_hint=refresh_token"
        rcode="$(curl -sS -o /dev/null -w '%{http_code}' -m "$TR_TIMEOUT" -A "$TR_UA" \
                 -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
                 --data "$rdata" "$rev_target" 2>/dev/null)"
        [[ -z "$rcode" ]] && rcode="000"
    fi
    cs_row REVOKED "code=$rcode"

    # 2. the only reading that matters: does it still refresh
    local c1 b1 h1 f1
    cs_split "$(tr_post "$tok_url" "$data")" c1 b1 h1 f1
    local k1; k1="$(tr_is_token "$f1")"; rm -f "$f1"
    cs_row AFTER "code=$c1" "kind=$k1"

    local v
    if [[ "$c0" == "000" ]]; then v="unreachable"
    elif [[ ! "$c0" =~ ^2 || "$k0" != "token" ]]; then v="control-refused"
    elif [[ "$c1" =~ ^2 && "$k1" == "token" ]]; then v="survives-logout"
    elif [[ "$c1" == "400" || "$c1" == "401" || "$c1" == "403" ]]; then v="revoked"
    else v="inconclusive"; fi

    cs_row VERDICT "$v" "before=$c0 after=$c1"
    if [[ "$v" == "survives-logout" ]]; then
        tr_findings "$tok_url" "CRITICAL" "refresh-survives-logout" \
            "the refresh token still minted credentials after revocation — logout only cleared the client's copy"
        cs_row FINDING "CRITICAL" "refresh-survives-logout"
    fi
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --fixation <token-url> <candidate-file>: a refresh token that we did not get
# from an authorization flow, but can make the server accept. The server should
# only honour tokens it issued, so acceptance means the token is not verified
# at all — only looked up.
tr_cmd_fixation() {
    local url="${1:-}" tokf="${2:-}"
    [[ -z "$url" || -z "$tokf" ]] && { tr_log "usage: --fixation <token-endpoint> <candidate-token-file>"; return 2; }
    [[ -f "$tokf" ]] || { tr_log "no such file: $tokf"; return 2; }

    local tok; tok="$(tr -d '\r\n' < "$tokf")"
    cs_row TARGET "$url"
    cs_row CANDIDATE "length=${#tok}" "fingerprint=$(cs_fingerprint <<<"$tok")"

    local data="grant_type=$TR_GRANT&refresh_token=$(printf '%s' "$tok" | jq -sRr @uri 2>/dev/null || printf '%s' "$tok")"
    local code bytes hash body
    cs_split "$(tr_post "$url" "$data")" code bytes hash body
    local kind; kind="$(tr_is_token "$body")"
    cs_row RESPONSE "code=$code" "kind=$kind"
    rm -f "$body"

    local v
    if [[ "$code" == "000" ]]; then v="unreachable"
    elif [[ "$code" =~ ^2 && "$kind" == "token" ]]; then v="external-token-accepted"
    else v="refused"; fi

    cs_row VERDICT "$v"
    if [[ "$v" == "external-token-accepted" ]]; then
        tr_findings "$url" "CRITICAL" "refresh-fixation" \
            "a refresh token the server never issued was exchanged for credentials"
        cs_row FINDING "CRITICAL" "refresh-fixation"
    fi
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --scopes <token-url> <token-file> [scope]: ask for more than we were given.
# A refresh that grants scope it was never authorised for is an escalation
# hiding inside a routine call.
tr_cmd_scopes() {
    local url="${1:-}" tokf="${2:-}" want="${3:-}"
    [[ -z "$url" || -z "$tokf" ]] && { tr_log "usage: --scopes <token-endpoint> <token-file> [scope]"; return 2; }
    [[ -f "$tokf" ]] || { tr_log "no such file: $tokf"; return 2; }

    local tok; tok="$(tr -d '\r\n' < "$tokf")"
    cs_row TARGET "$url"

    local base="grant_type=$TR_GRANT&refresh_token=$(printf '%s' "$tok" | jq -sRr @uri 2>/dev/null || printf '%s' "$tok")"

    # 0. what a plain refresh returns
    local c0 b0 h0 f0
    cs_split "$(tr_post "$url" "$base")" c0 b0 h0 f0
    local s0; s0="$(tr_field "$f0" scope)"; rm -f "$f0"
    cs_row BASELINE "code=$c0" "scope=${s0:-none}"

    if [[ -z "$want" ]]; then
        cs_row VERDICT "scope-reported" "baseline scope=${s0:-none}"
        cs_row SUMMARY "scope=${s0:-none}"
        return 0
    fi

    # 1. ask for more
    local esc="$base&scope=$(printf '%s' "$want" | jq -sRr @uri 2>/dev/null || printf '%s' "$want")"
    local c1 b1 h1 f1
    cs_split "$(tr_post "$url" "$esc")" c1 b1 h1 f1
    local s1; s1="$(tr_field "$f1" scope)"; rm -f "$f1"
    cs_row REQUESTED "scope=$want" "code=$c1" "granted=${s1:-none}"

    local v
    if [[ "$c0" == "000" ]]; then v="unreachable"
    elif [[ ! "$c0" =~ ^2 ]]; then v="control-refused"
    elif [[ -z "$s1" ]]; then v="scope-absent"
    elif [[ "$s1" == "$want" ]]; then v="scope-escalated"
    elif [[ "$s1" == "$s0" ]]; then v="scope-retained"
    else v="scope-partial"; fi

    cs_row VERDICT "$v" "baseline=${s0:-none} granted=${s1:-none}"
    if [[ "$v" == "scope-escalated" ]]; then
        tr_findings "$url" "CRITICAL" "refresh-scope-escalation" \
            "a refresh token originally scoped to '${s0:-none}' was granted '$s1' on request"
        cs_row FINDING "CRITICAL" "refresh-scope-escalation"
    fi
    cs_row SUMMARY "verdict=$v"
    return 0
}

tr_cmd_window() {
    local url="${1:-}" tokf="${2:-}"
    [[ -z "$url" || -z "$tokf" ]] && { tr_log "usage: --window <token-endpoint> <token-file>"; return 2; }
    [[ -f "$tokf" ]] || { tr_log "no such file: $tokf"; return 2; }
    local tok; tok="$(tr -d '\r\n' < "$tokf")"
    cs_row TARGET "$url"

    local data="grant_type=$TR_GRANT&refresh_token=$(printf '%s' "$tok" | jq -sRr @uri 2>/dev/null || printf '%s' "$tok")"
    local code bytes hash body
    cs_split "$(tr_post "$url" "$data")" code bytes hash body
    local exp; exp="$(tr_field "$body" refresh_token_expires_in)"
    local iexp; iexp="$(tr_field "$body" refresh_expires_in)"
    local kind; kind="$(tr_is_token "$body")"
    rm -f "$body"

    cs_row RESPONSE "code=$code" "kind=$kind"
    if [[ -n "$exp" ]] || [[ -n "$iexp" ]]; then
        cs_row EXPIRY "refresh_ttl=${exp:-${iexp:-}}"  
        local v="expiry-stated"
        case "${exp:-$iexp}" in
            0) v="no-expiry" ;;
        esac
        cs_row VERDICT "$v"
        [[ "$v" == "no-expiry" ]] && tr_findings "$url" "CRITICAL" "refresh-no-expiry" \
            "the token endpoint advertises an unlimited refresh lifetime"
    else
        cs_row NOTE "the response states no refresh lifetime — expiry may still be enforced server-side"
        cs_row VERDICT "expiry-unstated"
    fi
    cs_row SUMMARY "verdict=expiry-seen"
    return 0
}

tr_cmd_verdicts() {
    local v sev
    for v in old-still-valid chain-replayable replayed double-issued survives-logout \
             survives-password-change portable no-expiry expiry-ignored \
             access-lingers scope-escalated scope-retained external-token-accepted \
             cookie-readable accepted revoked rejected unreachable control-refused; do
        sev="$(tr_severity "$v")"
        cs_row VERDICT "$v" "$sev"
    done
    cs_row SUMMARY "verdicts=19"
    return 0
}

tr_cmd_scopes_table() { tr_cmd_verdicts; }

tr_cmd_list() {
    local id class what gets
    while IFS=$'\t' read -r id class what gets; do
        [[ -z "$id" ]] && continue
        cs_row VECTOR "$id" "$class" "$what"
        [[ -n "$gets" ]] && cs_row WHAT "$id" "$gets"
    done < <(tr_vectors)
    cs_row SUMMARY "vectors=$(tr_vectors | wc -l | tr -d ' ')"
    return 0
}

tr_cmd_grants() {
    local g what status
    while IFS=$'\t' read -r g what status; do
        [[ -z "$g" ]] && continue
        cs_row GRANT "$g" "$status" "$what"
    done < <(tr_grants)
    cs_row SUMMARY "grants=$(tr_grants | wc -l | tr -d ' ')"
    return 0
}

tr_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    command -v jq   >/dev/null 2>&1 && jq_state="jq-ok"     || jq_state="jq-missing"
    printf '%s\t%s\t%s\t%s\tvectors-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" "$(tr_vectors | wc -l | tr -d ' ')"
}

tr_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

tr_cmd_help() {
    cat <<'HELP'
cloudsting module 67 — Token Refresh & Session Hijack v1.0.0
  --probe <token-endpoint> [refresh-token-file]
                                   does the token work at all — the control
  --rotate <endpoint> <file> [n]   exchange repeatedly, then offer the ORIGINAL again
  --replay <endpoint> <file>       the same refresh token, twice
  --revoke <endpoint> <file> [revoke-url] [access-token]
                                   does it still work after revocation
  --scopes <endpoint> <file> [scope]
                                   ask for more scope than was granted
  --fixation <endpoint> <file>     a token the server never issued
  --window <endpoint> <file>       what lifetime the endpoint admits to
  --vectors | --grants | --verdicts | --list | --status-tsv | --menu
  --selftest | --help

A refresh token is a second key to the same door, and most stacks hand it out
and never take it back. The question is never "did logout return 200" — it is
"does the artifact still work afterwards", which is why --revoke refreshes
BEFORE revocation, revokes, then refreshes again.

`--rotate` is the decisive one: it walks the chain, then offers the ORIGINAL
token a final time. A server that rotated properly refuses it. One that never
invalidated hands it back, and that means a captured refresh token is permanent.

Every verb sends a control first. A token that does not refresh at all produces
`control-refused`, never a finding — an expired artifact and a broken endpoint
are not a vulnerability.

Environment: TR_TIMEOUT (10), TR_GRANT (refresh_token), TR_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
tr_selftest() {
    cs_selftest_reset

    local nv; nv="$(tr_vectors | wc -l | tr -d ' ')"
    chk vec-many    "$( (( nv >= 14 )) && echo many || echo few )" "many"
    chk vec-4col    "$(tr_vectors | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk vec-unique  "$(tr_vectors | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nv"
    local ng; ng="$(tr_grants | wc -l | tr -d ' ')"
    chk grn-3col    "$(tr_grants | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk grn-many    "$( (( ng >= 5 )) && echo many || echo few )" "many"

    # the verdict table
    chk v-unreach   "$(tr_verdict 200 000 0)" "unreachable"
    chk v-ctlref    "$(tr_verdict 401 200 0)" "control-refused"
    chk v-revoked   "$(tr_verdict 200 401 0)" "revoked"
    chk v-reject    "$(tr_verdict 200 400 0)" "rejected"
    chk v-old       "$(tr_verdict 200 200 2 rotate-not-invalidate)" "old-still-valid"
    chk v-chain     "$(tr_verdict 200 200 3 rotate-blank)" "chain-replayable"
    chk v-replay    "$(tr_verdict 200 200 0 replay-after-use)" "replayed"
    chk v-sm         "$(tr_verdict 200 200 0 no-logout-invalidate)" "survives-logout"
    chk v-port       "$(tr_verdict 200 200 0 refresh-cross-ip)" "portable"
    chk v-scope      "$(tr_verdict 200 200 0 scope-escalation)" "scope-escalated"
    chk v-fix        "$(tr_verdict 200 200 0 fixation-pre)" "external-token-accepted"
    chk v-generic    "$(tr_verdict 200 200 0 unknown-vector)" "accepted"

    chk s-crit      "$(tr_severity old-still-valid)" "CRITICAL"
    chk s-replay    "$(tr_severity replayed)" "CRITICAL"
    chk s-sm        "$(tr_severity survives-logout)" "CRITICAL"
    chk s-port      "$(tr_severity portable)" "CRITICAL"
    chk s-high      "$(tr_severity double-issued)" "HIGH"
    chk s-med       "$(tr_severity accepted)" "MEDIUM"
    chk s-info      "$(tr_severity revoked)" "INFO"

    # token extraction from both body shapes
    local f; f="$(mktemp "$CS_SCRATCH/tr-f.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.f.$$"
    printf '{"access_token":"AAA","refresh_token":"RRR","expires_in":3600}' > "$f"
    chk fld-json-at "$(tr_field "$f" access_token)" "AAA"
    chk fld-json-rt "$(tr_field "$f" refresh_token)" "RRR"
    chk fld-missing "$(tr_field "$f" nope | wc -c | tr -d ' ')" "0"
    chk tok-json    "$(tr_is_token "$f")" "token"
    printf 'access_token=BBB&refresh_token=SSS&expires_in=60' > "$f"
    chk fld-form-at "$(tr_field "$f" access_token)" "BBB"
    chk tok-form    "$(tr_is_token "$f")" "token"
    printf '{"error":"invalid_grant"}' > "$f"
    chk tok-err     "$(tr_is_token "$f")" "no-token"
    : > "$f"
    chk tok-empty   "$(tr_is_token "$f")" "no-token"
    rm -f "$f"

    # a dead endpoint is unreachable, never a hijack
    local out; out="$(tr_cmd_rotate http://127.0.0.1:9 rtx 2>/dev/null)"
    chk dead-usage  "$?" "2"
    printf 'sometoken' > "${OUT_DIR}/.testtok"
    out="$(tr_cmd_rotate http://127.0.0.1:9 "${OUT_DIR}/.testtok" 2 2>/dev/null)"
    chk dead-rotate "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "inconclusive"
    out="$(tr_cmd_replay http://127.0.0.1:9 "${OUT_DIR}/.testtok" 2>/dev/null)"
    chk dead-replay "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    out="$(tr_cmd_revoke http://127.0.0.1:9 "${OUT_DIR}/.testtok" 2>/dev/null)"
    chk dead-revoke "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    out="$(tr_cmd_fixation http://127.0.0.1:9 "${OUT_DIR}/.testtok" 2>/dev/null)"
    chk dead-fix    "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    rm -f "${OUT_DIR}/.testtok"

    # a probe with no token says so instead of guessing
    out="$(tr_cmd_probe http://127.0.0.1:9 2>/dev/null)"
    chk probe-notok "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "no-token-supplied"

    # usage errors
    tr_cmd_probe 2>/dev/null;    chk prb-usage "$?" "2"
    tr_cmd_rotate 2>/dev/null;   chk rot-usage "$?" "2"
    tr_cmd_replay 2>/dev/null;   chk rep-usage "$?" "2"
    tr_cmd_revoke 2>/dev/null;   chk rev-usage "$?" "2"
    tr_cmd_fixation 2>/dev/null; chk fix-usage "$?" "2"
    tr_cmd_scopes 2>/dev/null;   chk sco-usage "$?" "2"
    tr_cmd_window 2>/dev/null;   chk win-usage "$?" "2"

    chk status-fields "$(tr_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(tr_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(tr_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(tr_cmd_help | head -1 | grep -ci 'Token Refresh')" "1"
    chk list-rows     "$(tr_cmd_list | grep -c '^VECTOR')" "$nv"
    chk grn-rows      "$(tr_cmd_grants | grep -c '^GRANT')" "$ng"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)    shift; tr_cmd_probe "$@";;
    --rotate)   shift; tr_cmd_rotate "$@";;
    --replay)   shift; tr_cmd_replay "$@";;
    --revoke|--logout) shift; tr_cmd_revoke "$@";;
    --fixation) shift; tr_cmd_fixation "$@";;
    --scopes)   shift; tr_cmd_scopes "$@";;
    --window)   shift; tr_cmd_window "$@";;
    --vectors)  tr_cmd_list;;
    --grants)   tr_cmd_grants;;
    --verdicts) tr_cmd_verdicts;;
    --list)     tr_cmd_list;;
    --status-tsv|--status) tr_cmd_status_tsv;;
    --menu)     tr_cmd_menu;;
    --selftest) tr_selftest;;
    *)          tr_cmd_help;;
esac
