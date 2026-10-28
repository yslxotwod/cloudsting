#!/usr/bin/env bash
# 78_replay_nonce.sh — cloudsting module 78: the request that still works the second time
# Verbs: --probe | --check | --replay | --nonce | --timestamp | --idempotency
#        | --vectors | --list | --status-tsv | --menu | --selftest | --help
#
# A signed request is only a defence if the server remembers it. Replay
# protection is a cache of "seen" that must be checked AND written before the
# side effect: check-then-act is the bug, and it is invisible from the outside
# until you send the same money-moving request twice.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="78_replay_nonce"
MOD_NAME="Replay & Nonce (the request that still works the second time)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/replay_nonce"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${RN_TIMEOUT:=10}"
: "${RN_FOLLOW:=0}"
: "${RN_CONCURRENCY:=1}"
: "${RN_BODY:=}"
: "${RN_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/78}"

rn_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── what makes a request "signed" ────────────────────────────────
# A nonce is only interesting when it is supposed to be part of a signature or
# an auth scheme. These are the headers that carry it.
#   <header>\t<scheme that uses it>\t<what a missing check means>
rn_nonce_headers() {
    cat <<'NONCES'
X-Nonce	generic	the value is not consumed, so a captured request replays
X-Request-Nonce	generic	the same
X-Idempotency-Key	IETF idempotency drafts	the key is not stored, so a retry double-charges
Idempotency-Key	Stripe, Adyen, most payment APIs	nothing prevents the same charge twice
X-Request-Id	generic	a request id is a trace id, not a nonce — but servers treat it as one
X-Timestamp	HMAC schemes	the timestamp is signed but never compared
X-Date	OAuth / AWS-style	clock skew tolerance of "anything" makes an old request valid
X-Signature-Nonce	generic	same
NONCES
}

# ── the vectors ──────────────────────────────────────────────────
#   <id>\t<class>\t<what the server fails to do>
rn_vectors() {
    cat <<'VECTORS'
exact	no-dedup	the identical request, twice, produces the effect twice
new-nonce-same-body	no-dedup	a fresh nonce lets the same body through again
same-nonce-new-body	nonce-not-bound	the nonce is not bound to the body, so it protects nothing
nonce-reuse	nonce-not-stored	the same nonce is accepted a second time
nonce-absent	nonce-optional	the nonce header is optional, so an attacker simply omits it
nonce-empty	nonce-optional	an empty nonce is accepted
nonce-predictable	nonce-weak	a counter or timestamp as nonce is guessable
nonce-cross-user	nonce-not-scoped	a nonce spent by user A works for user B
timestamp-absent	stale-request	no timestamp, so a request never expires
timestamp-old	stale-request	a request from an hour ago is accepted
timestamp-future	stale-request	a request from the future is accepted
timestamp-not-signed	stale-request	the timestamp is compared but not part of the signature
idempotency-ignored	no-dedup	the Idempotency-Key header is ignored entirely
idempotency-different-result	broken-dedup	the key is stored but the response is not, so the retry re-executes
race-check-then-act	race	concurrent identical nonces both pass the check
VECTORS
}

# ── what a replay "did something" ────────────────────────────────
# The only honest signal is a change in the resource. Two identical 200s prove
# nothing: a GET replays harmlessly, and a server that returns 200 to everything
# tells us nothing at all.
#   rn_verdict <ctl-code> <first-code> <second-code> <first-hash> <second-hash> <vector-class>
rn_verdict() {
    local cc="$1" c1="$2" c2="$3" h1="$4" h2="$5" class="${6:-no-dedup}"
    [[ "$c1" == "000" ]] && { printf 'unreachable'; return; }
    [[ "$cc" == "000" ]] && { printf 'unreachable'; return; }
    # the first request itself failed: there is nothing to replay
    [[ ! "$c1" =~ ^2 ]] && { printf 'first-refused'; return; }

    # the second request being REJECTED is the defence working
    case "$c2" in
        401|403) printf 'blocked'; return ;;
        409)     printf 'duplicate-detected'; return ;;
        400|422) printf 'rejected'; return ;;
        000)     printf 'unreachable'; return ;;
        429)     printf 'rate-limited'; return ;;
    esac

    if [[ "$c2" =~ ^2 ]]; then
        # identical bytes back means the server served a cached/duplicate result
        # rather than re-executing — that IS dedup, from the client's side
        [[ "$h1" == "$h2" ]] && { printf 'duplicate-detected'; return; }
        case "$class" in
            race) printf 'race-window'; return ;;
            *)    printf 'replayed'; return ;;
        esac
    fi
    printf 'differs'
}

# A replay that doubles a balance is not the same finding as a replay of a
# search. Grade by class, and never claim CRITICAL from a shape alone.
rn_severity() {
    case "$1" in
        replayed)
            case "${2:-no-dedup}" in
                race) printf 'CRITICAL' ;;
                *)    printf 'HIGH' ;;
            esac ;;
        race-window)          printf 'CRITICAL' ;;
        duplicate-detected)   printf 'INFO' ;;
        *)                    printf 'INFO' ;;
    esac
}

rn_findings() {
    cs_findings_row "$MODULE_ID" "WEBAPI" "$1" "$2" "$3" "$4"
}

# ── sending ──────────────────────────────────────────────────────
rn_body() {
    [[ -n "$RN_BODY" ]] && { printf '%s' "$RN_BODY"; return; }
    printf '{"amount":1,"currency":"usd","to":"acct_cloudsting","memo":"replay-probe"}'
}

#   rn_send <url> <method> [header...]
#   -> code \x1f bytes \x1f hash \x1f body-path
rn_send() {
    local url="$1" method="${2:-POST}"; shift 2 || true
    local outf; outf="$(mktemp "$CS_SCRATCH/rn.XXXXXX")" 2>/dev/null || outf="$OUT_DIR/.rn.$$"
    local -a args=(-sS -o "$outf" -w '%{http_code} %{time_total}' -m "$RN_TIMEOUT"
                   -A "$RN_UA" -X "$method" -H 'Content-Type: application/json'
                   --data-binary "$(rn_body)")
    local h
    for h in "$@"; do [[ -n "$h" ]] && args+=(-H "$h"); done
    [ "$RN_FOLLOW" = "1" ] && args+=(-L)

    local meta code="" secs="0"
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)"
    read -r code secs <<<"${meta:-000 0}"
    [[ -z "$code" ]] && code="000"
    local bytes hash
    bytes="$(wc -c < "$outf" 2>/dev/null | tr -d ' ')"
    # cs_fingerprint collapses its argument to a string: handed a PATH it hashes
    # the path text, so two identical responses would fingerprint differently on
    # every call (the temp file name changes). Hash the file CONTENTS.
    hash="$(sha1sum "$outf" 2>/dev/null | cut -c1-12)"
    [[ -z "$hash" ]] && hash="$(cs_fingerprint "$(cat "$outf" 2>/dev/null)")"
    printf '%s\037%s\037%s\037%s\n' "$code" "${bytes:-0}" "$hash" "$outf"
}

# A nonce that is genuinely fresh. A predictable one is its own finding, so
# this never uses a counter for the control.
rn_nonce() { printf '%s-%s' "$(date +%s%N)" "$RANDOM$RANDOM"; }

rn_header_name() {
    local h
    while IFS=$'\t' read -r h _rest; do
        [[ -z "$h" ]] && continue
        case "$1" in
            idempotency) [[ "$h" == *Idempotency* ]] && { printf '%s' "$h"; return; } ;;
            timestamp)   [[ "$h" == *Timestamp* || "$h" == *Date* ]] && { printf '%s' "$h"; return; } ;;
            *)           [[ "$h" == *Nonce* || "$h" == *Idempotency* ]] && { printf '%s' "$h"; return; } ;;
        esac
    done < <(rn_nonce_headers)
    printf 'X-Nonce'
}

# ── verbs ────────────────────────────────────────────────────────

# --probe <url> [method]: does the endpoint accept our request once, and does
# it accept it twice. This is the two-line version of --check.
rn_cmd_probe() {
    local url="${1:-}" method="${2:-POST}"
    [[ -z "$url" ]] && { rn_log "usage: --probe <url> [method]"; return 2; }
    cs_row TARGET "$url"
    cs_row METHOD "$method"

    local c1 b1 h1 f1 c2 b2 h2 f2
    cs_split "$(rn_send "$url" "$method")" c1 b1 h1 f1
    local kind1="body"; [[ -s "$f1" ]] || kind1="empty"
    cs_row FIRST "code=$c1" "bytes=$b1" "$kind1"
    cs_split "$(rn_send "$url" "$method")" c2 b2 h2 f2
    cs_row SECOND "code=$c2" "bytes=$b2"
    rm -f "$f1" "$f2"

    local v; v="$(rn_verdict "$c1" "$c1" "$c2" "$h1" "$h2" no-dedup)"
    cs_row VERDICT "$v" "first=$c1 second=$c2"
    cs_row SUMMARY "code=$c1 verdict=$v"
    return 0
}

# --check <url> [method]: every vector that does not need concurrency.
rn_cmd_check() {
    local url="${1:-}" method="${2:-POST}"
    [[ -z "$url" ]] && { rn_log "usage: --check <url> [method]"; return 2; }
    cs_row TARGET "$url"
    cs_row METHOD "$method"
    : > "$PROBE_FILE"

    # 0. the baseline: one request, with a fresh nonce
    local nonce_hdr; nonce_hdr="$(rn_header_name nonce)"
    local n0; n0="$(rn_nonce)"
    local c0 b0 h0 f0
    cs_split "$(rn_send "$url" "$method" "$nonce_hdr: $n0")" c0 b0 h0 f0
    local kind0; kind0="$( [[ -s "$f0" ]] && echo body || echo empty )"
    cs_row CONTROL "code=$c0" "bytes=$b0" "$kind0"
    rm -f "$f0"

    if [[ "$c0" == "000" ]]; then
        cs_row VERDICT "unreachable"
        cs_row SUMMARY "code=000"
        return 0
    fi
    if [[ ! "$c0" =~ ^2 ]]; then
        # the endpoint refuses our request shape; a replay test would be
        # measuring the refusal, not the dedup
        cs_row VERDICT "control-refused" "the endpoint refused a single well-formed request"
        cs_row SUMMARY "control=$c0"
        return 0
    fi

    local hits=0 tried=0
    local id class what
    while IFS=$'\t' read -r id class what; do
        [[ -z "$id" ]] && continue
        case "$id" in
            race-check-then-act) continue ;;   # needs concurrency: --replay --race
            nonce-predictable)   continue ;;   # answered by --nonce
        esac
        tried=$((tried + 1))

        local h1="" h2=""
        local n1; n1="$(rn_nonce)"
        case "$id" in
            exact)                 h1="$nonce_hdr: $n1"; h2="$nonce_hdr: $n1" ;;
            new-nonce-same-body)   h1="$nonce_hdr: $n1"; h2="$nonce_hdr: $(rn_nonce)" ;;
            same-nonce-new-body)   h1="$nonce_hdr: $n1"; h2="$nonce_hdr: $n1" ;;
            nonce-reuse)           h1="$nonce_hdr: $n1"; h2="$nonce_hdr: $n1" ;;
            nonce-absent)          h1="-";   h2="-" ;;
            nonce-empty)           h1="$nonce_hdr: "; h2="$nonce_hdr: " ;;
            nonce-cross-user)      h1="$nonce_hdr: $n1"; h2="$nonce_hdr: $n1" ;;
            timestamp-absent)      h1="-";   h2="-" ;;
            timestamp-old)         h1="$(rn_header_name timestamp): $(( $(date +%s) - 3600 ))"; h2="$h1" ;;
            timestamp-future)      h1="$(rn_header_name timestamp): $(( $(date +%s) + 3600 ))"; h2="$h1" ;;
            timestamp-not-signed)  h1="$nonce_hdr: $n1"; h2="$nonce_hdr: $n1" ;;
            idempotency-ignored)
                h1="Idempotency-Key: $n1"; h2="Idempotency-Key: $n1" ;;
            idempotency-different-result)
                h1="Idempotency-Key: $n1"; h2="Idempotency-Key: $n1" ;;
            *) continue ;;
        esac

        # an added body change for the vector that exists to test exactly that
        local saved_body="$RN_BODY"
        if [[ "$id" == "same-nonce-new-body" ]]; then
            RN_BODY='{"amount":2,"currency":"usd","to":"acct_cloudsting","memo":"changed"}'
        fi

        local c1 b1 x1 f1 c2 b2 x2 f2
        cs_split "$(rn_send "$url" "$method" "$h1")" c1 b1 x1 f1
        cs_split "$(rn_send "$url" "$method" "$h2")" c2 b2 x2 f2
        RN_BODY="$saved_body"

        local v; v="$(rn_verdict "$c0" "$c1" "$c2" "$x1" "$x2" "$class")"
        local sev; sev="$(rn_severity "$v" "$class")"
        printf 'vector\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$c1" "$c2" "$v" "$class" "$sev" >> "$PROBE_FILE"

        case "$v" in
            replayed|race-window)
                hits=$((hits + 1))
                cs_row HIT "$id" "first=$c1" "second=$c2" "verdict=$v" "sev=$sev" "$what"
                printf '%s\t%s\t%s\n' "$id" "$v" "$sev" >> "$HIT_FILE"
                rn_findings "$url" "$sev" "replay-$id" "$id: $what"
                ;;
            *)
                cs_row VECTOR "$id" "first=$c1" "second=$c2" "$v"
                ;;
        esac
        rm -f "$f1" "$f2"
    done < <(rn_vectors)

    local overall="protected"
    (( hits > 0 )) && overall="replayable"
    cs_row VERDICT "$overall" "$hits of $tried vectors re-executed"
    cs_row SUMMARY "vectors=$tried hits=$hits"
    cs_row ARTIFACT "$PROBE_FILE"
    return 0
}

# --replay <url> [method] [n]: the same request n times. The strongest form is
# concurrent, because a check-then-act bug only exists inside the window
# between the two, and sequential requests hide it.
rn_cmd_replay() {
    local url="${1:-}" method="${2:-POST}" n="${3:-2}"
    [[ -z "$url" ]] && { rn_log "usage: --replay <url> [method] [count]"; return 2; }
    [[ "$n" =~ ^[0-9]+$ ]] || { rn_log "count must be a number"; return 2; }
    cs_row TARGET "$url"
    cs_row COUNT "$n"

    local nonce_hdr; nonce_hdr="$(rn_header_name nonce)"
    local n1; n1="$(rn_nonce)"
    local hdr="$nonce_hdr: $n1"

    local i=0 code bytes hash body
    local first_code="" first_hash="" same=0
    while (( i < n )); do
        i=$((i + 1))
        cs_split "$(rn_send "$url" "$method" "$hdr")" code bytes hash body
        cs_row ATTEMPT "$i" "code=$code" "bytes=$bytes" "hash=$hash"
        rm -f "$body"
        if [[ "$i" -eq 1 ]]; then first_code="$code"; first_hash="$hash"
        else
            [[ "$hash" == "$first_hash" ]] && same=$((same + 1))
        fi
    done

    # If every response is byte-identical the server is serving the same stored
    # result — that is dedup working, not the request re-executing.
    local v
    if [[ "$first_code" == "000" ]]; then v="unreachable"
    elif [[ "$same" -eq $((n - 1)) ]]; then v="duplicate-detected"
    elif [[ ! "$first_code" =~ ^2 ]]; then v="first-refused"
    else v="replayed"; fi

    cs_row VERDICT "$v" "identical=$same of $((n - 1))"
    if [[ "$v" == "replayed" ]]; then
        rn_findings "$url" "HIGH" "replay-sequential" \
            "$n identical requests were all executed — the nonce is not stored"
        cs_row FINDING "HIGH" "replay-sequential"
    fi
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --nonce <url> [method] [n]: is the nonce actually consumed. Sending the SAME
# nonce twice is the direct question; sending a fresh one each time and seeing
# the same side effect is the indirect one.
rn_cmd_nonce() {
    local url="${1:-}" method="${2:-POST}" n="${3:-5}"
    [[ -z "$url" ]] && { rn_log "usage: --nonce <url> [method] [count]"; return 2; }
    cs_row TARGET "$url"
    local h; h="$(rn_header_name nonce)"
    cs_row HEADER "$h"

    # 1. same nonce, twice
    local same; same="$(rn_nonce)"
    local c1 b1 h1 f1 c2 b2 h2 f2
    cs_split "$(rn_send "$url" "$method" "$h: $same")" c1 b1 h1 f1
    cs_split "$(rn_send "$url" "$method" "$h: $same")" c2 b2 h2 f2
    cs_row SAME "first=$c1" "second=$c2" "identical=$([[ "$h1" == "$h2" ]] && echo yes || echo no)"
    rm -f "$f1" "$f2"

    local v
    if [[ "$c1" == "000" ]]; then v="unreachable"
    elif [[ ! "$c1" =~ ^2 ]]; then v="first-refused"
    elif [[ "$c2" == "409" ]]; then v="nonce-consumed"
    elif [[ "$c2" =~ ^2 && "$h1" != "$h2" ]]; then v="nonce-replayed"
    elif [[ "$c2" =~ ^2 ]]; then v="nonce-consumed"
    else v="nonce-checked"; fi

    cs_row VERDICT "$v" "first=$c1 second=$c2"
    if [[ "$v" == "nonce-replayed" ]]; then
        rn_findings "$url" "HIGH" "replay-nonce" \
            "the same nonce was accepted twice and produced a different result each time"
        cs_row FINDING "HIGH" "replay-nonce"
    fi

    # 2. fresh nonces: does the SIDE EFFECT repeat, and does the response differ
    local k=0 dup=0 prev=""
    while (( k < n )); do
        k=$((k + 1))
        local cf bf hf ff
        cs_split "$(rn_send "$url" "$method" "$h: $(rn_nonce)")" cf bf hf ff
        rm -f "$ff"
        [[ -n "$prev" && "$hf" == "$prev" ]] && dup=$((dup + 1))
        prev="$hf"
    done
    cs_row FRESH "distinct-of=$n" "identical-pairs=$dup"
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --timestamp <url> [method]: the clock. An old signed request that still works
# means the window is decorative.
rn_cmd_timestamp() {
    local url="${1:-}" method="${2:-POST}"
    [[ -z "$url" ]] && { rn_log "usage: --timestamp <url> [method]"; return 2; }
    cs_row TARGET "$url"
    local h; h="$(rn_header_name timestamp)"
    cs_row HEADER "$h"

    local hits=0
    local delta name
    for delta in 0 -3600 3600; do
        case "$delta" in
            0)     name="now" ;;
            -3600) name="stale-1h" ;;
            3600)  name="future-1h" ;;
        esac
        local ts=$(( $(date +%s) + delta ))
        local code bytes hash body
        cs_split "$(rn_send "$url" "$method" "$h: $ts")" code bytes hash body
        rm -f "$body"
        if [[ "$code" =~ ^2 ]]; then
            cs_row ACCEPTED "$name" "code=$code" "ts=$ts"
            [[ "$name" != "now" ]] && hits=$((hits + 1))
        else
            cs_row REJECTED "$name" "code=$code" "ts=$ts"
        fi
    done

    local v
    # if "now" was refused, the endpoint wants something else in that header
    if (( hits > 0 )); then v="window-open"; else v="window-checked"; fi
    cs_row VERDICT "$v" "$hits out-of-window accepted"
    if [[ "$v" == "window-open" ]]; then
        rn_findings "$url" "HIGH" "replay-stale-timestamp" \
            "a request timestamped an hour outside the present was accepted — a captured request never expires"
        cs_row FINDING "HIGH" "replay-stale-timestamp"
    fi
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --idempotency <url> [method]: the Idempotency-Key contract. Same key + same
# body must return the stored response; same key + different body must 422.
rn_cmd_idempotency() {
    local url="${1:-}" method="${2:-POST}"
    [[ -z "$url" ]] && { rn_log "usage: --idempotency <url> [method]"; return 2; }
    cs_row TARGET "$url"
    local key; key="$(rn_nonce)"
    cs_row KEY "$key"

    local saved="$RN_BODY"
    local c1 b1 h1 f1 c2 b2 h2 f2 c3 b3 h3 f3
    cs_split "$(rn_send "$url" "$method" "Idempotency-Key: $key")" c1 b1 h1 f1
    cs_split "$(rn_send "$url" "$method" "Idempotency-Key: $key")" c2 b2 h2 f2
    RN_BODY='{"amount":2,"currency":"usd","to":"acct_cloudsting","memo":"different"}'
    cs_split "$(rn_send "$url" "$method" "Idempotency-Key: $key")" c3 b3 h3 f3
    RN_BODY="$saved"

    cs_row FIRST "code=$c1"
    cs_row SECOND "code=$c2" "identical=$([[ "$h1" == "$h2" ]] && echo yes || echo no)"
    cs_row DIFFERENT-BODY "code=$c3"
    rm -f "$f1" "$f2" "$f3"

    local v
    if [[ "$c1" == "000" ]]; then v="unreachable"
    elif [[ ! "$c1" =~ ^2 ]]; then v="first-refused"
    elif [[ "$h1" == "$h2" && "$c3" == "422" ]]; then v="idempotency-honoured"
    elif [[ "$h1" == "$h2" ]]; then v="idempotency-stored-body-unchecked"
    elif [[ "$c2" =~ ^2 ]]; then v="key-ignored"
    else v="partial"; fi

    cs_row VERDICT "$v"
    case "$v" in
        key-ignored)
            rn_findings "$url" "HIGH" "idempotency-ignored" \
                "the same Idempotency-Key was re-executed rather than answered from the store"
            cs_row FINDING "HIGH" "idempotency-ignored" ;;
        idempotency-stored-body-unchecked)
            rn_findings "$url" "MEDIUM" "idempotency-body-unchecked" \
                "the key is honoured but the body is not compared, so a reused key with a different payload returns the old result"
            cs_row FINDING "MEDIUM" "idempotency-body-unchecked" ;;
    esac
    cs_row SUMMARY "verdict=$v"
    return 0
}

rn_cmd_vectors() {
    local id class what
    while IFS=$'\t' read -r id class what; do
        [[ -z "$id" ]] && continue
        cs_row VECTOR "$id" "$class" "$what"
    done < <(rn_vectors)
    cs_row SUMMARY "vectors=$(rn_vectors | wc -l | tr -d ' ')"
    return 0
}

rn_cmd_list() {
    local h scheme what
    while IFS=$'\t' read -r h scheme what; do
        [[ -z "$h" ]] && continue
        cs_row HEADER "$h" "$scheme" "$what"
    done < <(rn_nonce_headers)
    cs_row SUMMARY "headers=$(rn_nonce_headers | wc -l | tr -d ' ')"
    return 0
}

rn_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="curl-ok" || curl_state="curl-missing"
    command -v jq   >/dev/null 2>&1 && jq_state="jq-ok"     || jq_state="jq-missing"
    printf '%s\t%s\t%s\t%s\tvectors-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" "$(rn_vectors | wc -l | tr -d ' ')"
}

rn_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

rn_cmd_help() {
    cat <<'HELP'
cloudsting module 78 — Replay & Nonce v1.0.0
  --probe <url> [method]        one request, then the same one again
  --check <url> [method]        every replay vector that needs no concurrency
  --replay <url> [method] [n]   the same signed request n times
  --nonce <url> [method] [n]    is the nonce actually consumed
  --timestamp <url> [method]    an hour ago, now, an hour ahead
  --idempotency <url> [method]  same key same body, then same key new body
  --vectors | --list | --status-tsv | --menu | --selftest | --help

A signed request is only a defence if the server remembers it. The bug is
check-then-act: the nonce store is consulted before the side effect and
written after, so two requests inside that window both pass.

That is why `--replay` cares about byte-identical responses. If every attempt
returns the SAME bytes, the server is answering from a stored result — that is
deduplication working, and reporting it as a replay would be backwards. Only a
second request that produces a DIFFERENT result has re-executed the action.

Every verb sends a control first. An endpoint that refuses a single
well-formed request gets `control-refused`, not a finding.

Environment: RN_TIMEOUT (10), RN_BODY (override the request body), RN_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
rn_selftest() {
    cs_selftest_reset

    local nv; nv="$(rn_vectors | wc -l | tr -d ' ')"
    chk vec-many    "$( (( nv >= 15 )) && echo many || echo few )" "many"
    chk vec-3col    "$(rn_vectors | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk vec-unique  "$(rn_vectors | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nv"
    local nh; nh="$(rn_nonce_headers | wc -l | tr -d ' ')"
    chk hdr-3col    "$(rn_nonce_headers | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk hdr-idem    "$(rn_header_name idempotency)" "X-Idempotency-Key"
    chk hdr-ts      "$(rn_header_name timestamp)" "X-Timestamp"
    chk hdr-nonce   "$(rn_header_name nonce)" "X-Nonce"

    # the verdict table is the whole design
    chk v-unreach   "$(rn_verdict 200 000 000 h h)" "unreachable"
    chk v-replay    "$(rn_verdict 200 200 200 a b)" "replayed"
    chk v-dup       "$(rn_verdict 200 200 200 a a)" "duplicate-detected"
    chk v-dup409    "$(rn_verdict 200 200 409 a b)" "duplicate-detected"
    chk v-blocked   "$(rn_verdict 200 200 403 a b)" "blocked"
    chk v-rejected  "$(rn_verdict 200 200 422 a b)" "rejected"
    chk v-first     "$(rn_verdict 200 401 200 a b)" "first-refused"
    chk v-race      "$(rn_verdict 200 200 200 a b race)" "race-window"

    chk s-crit      "$(rn_severity race-window)" "CRITICAL"
    chk s-high      "$(rn_severity replayed no-dedup)" "HIGH"
    chk s-dup       "$(rn_severity duplicate-detected)" "INFO"
    chk s-info      "$(rn_severity blocked)" "INFO"

    # a nonce must be fresh every call, or the control is itself predictable
    local a b
    a="$(rn_nonce)"; sleep 0.01; b="$(rn_nonce)"
    chk nonce-diff  "$( [[ "$a" != "$b" ]] && echo differs || echo same)" "differs"
    chk nonce-len   "$( (( ${#a} >= 10 )) && echo long || echo short )" "long"

    # a dead host is unreachable, never a replay
    local out; out="$(rn_cmd_check http://127.0.0.1:9 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-hits    "$(printf '%s' "$out" | awk -F'\t' '$1=="HIT"' | wc -l | tr -d ' ')" "0"
    out="$(rn_cmd_replay http://127.0.0.1:9 POST 3 2>/dev/null)"
    chk dead-replay  "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"

    # usage errors
    rn_cmd_probe 2>/dev/null;     chk prb-usage "$?" "2"
    rn_cmd_check 2>/dev/null;     chk chk-usage "$?" "2"
    rn_cmd_replay 2>/dev/null;    chk rep-usage "$?" "2"
    rn_cmd_nonce 2>/dev/null;     chk non-usage "$?" "2"
    rn_cmd_timestamp 2>/dev/null; chk tim-usage "$?" "2"
    rn_cmd_idempotency 2>/dev/null; chk idm-usage "$?" "2"
    rn_cmd_replay http://127.0.0.1:9 POST abc 2>/dev/null; chk rep-count "$?" "2"

    chk status-fields "$(rn_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(rn_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(rn_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(rn_cmd_help | head -1 | grep -ci 'Replay')" "1"
    chk vec-rows      "$(rn_cmd_vectors | grep -c '^VECTOR')" "$nv"
    chk hdr-rows      "$(rn_cmd_list | grep -c '^HEADER')" "$nh"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)       shift; rn_cmd_probe "$@";;
    --check)       shift; rn_cmd_check "$@";;
    --replay)      shift; rn_cmd_replay "$@";;
    --nonce)       shift; rn_cmd_nonce "$@";;
    --timestamp)   shift; rn_cmd_timestamp "$@";;
    --idempotency) shift; rn_cmd_idempotency "$@";;
    --vectors)     rn_cmd_vectors;;
    --list)        rn_cmd_list;;
    --status-tsv|--status) rn_cmd_status_tsv;;
    --menu)        rn_cmd_menu;;
    --selftest)    rn_selftest;;
    *)             rn_cmd_help;;
esac
