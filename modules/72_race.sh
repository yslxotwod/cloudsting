#!/usr/bin/env bash
# 72_race.sh — cloudsting module 72: two requests that each pass a check neither should
# Verbs: --probe | --fire | --double-spend | --coupon | --limit | --gate
#        | --techniques | --list | --status-tsv | --menu | --selftest | --help
#
# A race condition in an API is not a timing curiosity — it is check-then-act
# split across two connections. The balance check reads, the write happens, and
# both requests read the same balance. Sequential testing can never see it: the
# first request finishes before the second starts, so the window is closed by
# the test itself. This module fires concurrently, always.
set -u
umask 077

# A parent that sourced the core exports CS_MOD_DIR; this module derives its own.
unset CS_MOD_DIR

MODULE_ID="72_race"
MOD_NAME="Race Condition (two requests that each pass a check neither should)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/race"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${RC_TIMEOUT:=15}"
: "${RC_WORKERS:=20}"
: "${RC_BODY:=}"
: "${RC_METHOD:=POST}"
: "${RC_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/72}"

rc_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the shapes worth racing ──────────────────────────────────────
# Every row is a place where a check and a write are two statements. The last
# column is what a successful race costs the operator, which is the only thing
# that decides whether the bug is worth reporting.
#   <id>\t<class>\t<the check and the act> / <what winning gives you>
rc_techniques() {
    cat <<'TECHNIQUES'
double-spend	money	a balance read then a debit — a withdrawal that leaves a negative balance
coupon-reuse	money	a coupon marked used after validation — one code used N times
limit-bypass	money	a daily limit counted then charged — a transfer above the limit
referral-abuse	money	a reward credited per signup — N signups that are one person
stock-oversell	inventory	a quantity read then decremented — more sold than exists
seat-double-book	inventory	a seat checked then assigned — the same seat sold twice
unique-constraint	state	an existence check then an insert — two rows that should be one
state-transition	state	a status read then written — two transitions from one state
otp-reuse	auth	a one-time code validated then cleared — the same code twice
token-mint	auth	a single-use token exchanged twice — two sessions from one grant
vote-astroturf	social	a per-user limit counted then stored — the same vote N times
rate-window	social	a rolling counter incremented after the check — N requests in one window
TECHNIQUES
}

# ── sending concurrently ─────────────────────────────────────────
# Sequential curl calls would each finish before the next starts, which closes
# the exact window we are trying to hit. Every worker is backgrounded with the
# same start barrier and released together, so the requests land in the same
# millisecond rather than in order.
#
#   rc_fire <url> <count> [body] [header]
#   -> writes "<index>\t<code>\t<hash>\t<bytes>" lines to stdout
rc_fire() {
    local url="$1" count="${2:-$RC_WORKERS}" body="${3:-}" hdr="${4:-}"
    [[ -z "$body" ]] && body="$(rc_body)"
    local dir; dir="$(mktemp -d "$CS_SCRATCH/race.XXXXXX")" 2>/dev/null || dir="$OUT_DIR/.race.$$"
    mkdir -p "$dir"
    local gate="$dir/go"

    local i=0
    while (( i < count )); do
        i=$((i + 1))
        (
            # barrier: every worker waits for the file, then all proceed at once
            while [[ ! -e "$gate" ]]; do :; done
            local -a args=(-sS -o "$dir/out.$i" -w '%{http_code}' -m "$RC_TIMEOUT"
                           -A "$RC_UA" -X "$RC_METHOD" -H 'Content-Type: application/json'
                           --data-binary "$body")
            [ -n "$hdr" ] && args+=(-H "$hdr")
            # -o writes the body; if the socket never opens there is no body,
            # so create the file first rather than letting curl complain about
            # a path it cannot create after the fact.
            : > "$dir/out.$i"
            local code; code="$(curl "${args[@]}" "$url" 2>/dev/null)"
            printf '%s\t%s\n' "$i" "${code:-000}" > "$dir/code.$i"
        ) &
    done

    # release them together
    sleep 0.05
    : > "$gate"
    wait

    local n
    for n in $(seq 1 "$count"); do
        local code hash bytes
        code="$(cut -f2 "$dir/code.$n" 2>/dev/null)"
        [[ -z "$code" ]] && code="000"
        hash="$(sha1sum "$dir/out.$n" 2>/dev/null | cut -c1-12)"
        [[ -z "$hash" ]] && hash="none"
        bytes="$(wc -c < "$dir/out.$n" 2>/dev/null | tr -d ' ')"
        printf '%s\t%s\t%s\t%s\n' "$n" "$code" "$hash" "${bytes:-0}"
    done
    rm -rf "$dir"
}

# A second, cheaper way to measure the window: send the same request twice with
# a tiny gap and see whether the second one is answered from a check that the
# first already invalidated.
#   rc_verdict <success-count> <total> <distinct-identities> <sequential-outcome>
rc_verdict() {
    local ok="$1" total="$2" distinct="${3:-0}" seq="${4:-}"
    [[ "$total" -eq 0 ]] && { printf 'unreachable'; return; }
    # The control run is read FIRST. A control that never got an answer means
    # the target is gone and nothing else can be measured; a control that was
    # refused means the race has no baseline to beat.
    if [[ "$seq" == "dead" ]]; then printf 'unreachable'; return; fi
    if [[ "$seq" == "refused" ]]; then printf 'control-refused'; return; fi

    # Every worker refused is NOT the same as a dead host. The sockets answered;
    # they said no. Distinguishing the two is the difference between "the lock
    # worked" and "I could not reach the server", and only one of those is good
    # news for the operator.
    [[ "$ok" -eq 0 ]] && { printf 'all-refused'; return; }

    if [[ "$ok" -ge "$total" ]]; then
        # every request succeeded. In a race that IS the finding when only one
        # should have; the caller decides by class, so report the shape.
        printf 'all-succeeded'
        return
    fi
    [[ "$ok" -gt 1 ]] && { printf 'partial-race'; return; }
    # exactly one of N succeeded — the lock worked
    printf 'serialised'
}

# The honest grading rule: a race is only a finding when the effect is
# duplicated, not merely when requests failed. A 500 on a lock conflict is the
# defence, and reporting it would be backwards.
#   rc_severity <verdict> <class> <success-count>
rc_severity() {
    local v="$1" class="$2" ok="${3:-0}"
    case "$v" in
        all-succeeded)
            case "$class" in
                money)     printf 'CRITICAL' ;;
                inventory) printf 'CRITICAL' ;;
                auth)      printf 'CRITICAL' ;;
                *)         printf 'HIGH' ;;
            esac ;;
        partial-race)  printf 'HIGH' ;;
        serialised)    printf 'INFO' ;;
        all-refused)   printf 'INFO' ;;
        control-refused) printf 'INFO' ;;
        *)             printf 'INFO' ;;
    esac
}

rc_findings() { cs_findings_row "$MODULE_ID" "WEBAPI" "$1" "$2" "$3" > /dev/null; }

rc_body() {
    [[ -n "$RC_BODY" ]] && { printf '%s' "$RC_BODY"; return; }
    printf '{"amount":1,"idempotency_hint":"cloudsting-race","memo":"race"}'
}

# ── verbs ────────────────────────────────────────────────────────

# --probe <url> [n]: one request alone, then n together. The contrast is the
# finding: if one succeeds and twenty also succeed, the guard is per-request.
rc_cmd_probe() {
    local url="${1:-}" n="${2:-$RC_WORKERS}"
    [[ -z "$url" ]] && { rc_log "usage: --probe <url> [count]"; return 2; }
    cs_row TARGET "$url"
    cs_row WORKERS "$n"

    # control: ONE request on its own, against fresh state
    local body; body="$(rc_body)"
    local dir; dir="$(mktemp -d "$CS_SCRATCH/rcp.XXXXXX")" 2>/dev/null || dir="$OUT_DIR/.rcp.$$"
    mkdir -p "$dir"
    local ccode
    ccode="$(curl -sS -o "$dir/one" -w '%{http_code}' -m "$RC_TIMEOUT" -A "$RC_UA" \
                  -X "$RC_METHOD" -H 'Content-Type: application/json' \
                  --data-binary "$body" "$url" 2>/dev/null)"
    cs_row CONTROL "code=${ccode:-000}" "bytes=$(wc -c < "$dir/one" 2>/dev/null | tr -d ' ')"
    rm -rf "$dir"

    local seq="ok"
    [[ "${ccode:-000}" == "000" ]] && seq="dead"
    [[ ! "${ccode:-000}" =~ ^2 && "${ccode:-000}" != "000" ]] && seq="refused"
    cs_row SEQUENTIAL "$seq" "one request, alone"

    # concurrent: n requests released together
    local fired; fired="$(rc_fire "$url" "$n" "$body")"
    local ok=0 total=0 hashes="" silent=0
    local idx code hash bytes
    while IFS=$'\t' read -r idx code hash bytes; do
        [[ -z "$idx" ]] && continue
        total=$((total + 1))
        [[ "$code" == "000" ]] && silent=$((silent + 1))
        [[ "$code" =~ ^2 ]] && ok=$((ok + 1))
        hashes="$hashes$hash"$'\n'
    done <<< "$fired"
    local distinct; distinct="$(printf '%s' "$hashes" | sort -u | grep -c . || true)"
    cs_row CONCURRENT "succeeded=$ok/$total" "distinct-responses=${distinct:-0}" "silent=$silent"
    # nothing answered at all: that is a dead target, not a working lock
    if [[ "$silent" -eq "$total" && "$total" -gt 0 ]]; then
        cs_row VERDICT "unreachable" "no socket answered"
        cs_row SUMMARY "ok=0 total=$total verdict=unreachable"
        return 0
    fi

    local v; v="$(rc_verdict "$ok" "$total" "${distinct:-0}" "$seq")"
    local sev; sev="$(rc_severity "$v" money "$ok")"
    cs_row VERDICT "$v" "single=$ccode"
    if [[ "$v" == "all-succeeded" || "$v" == "partial-race" ]]; then
        cs_row FINDING "$sev" "race-$( [[ "$v" == all-succeeded ]] && echo all || echo partial )"
        rc_findings "$url" "$sev" "race-condition" \
            "$ok of $total concurrent identical requests were all accepted — the check and the act are not one statement"
    fi
    cs_row SUMMARY "ok=$ok total=$total verdict=$v"
    return 0
}

# --fire <url> [n] [body]: raw concurrency, no interpretation. For anything
# that is not money, this is the primitive.
rc_cmd_fire() {
    local url="${1:-}" n="${2:-$RC_WORKERS}" body="${3:-}"
    [[ -z "$url" ]] && { rc_log "usage: --fire <url> [count] [body]"; return 2; }
    cs_row TARGET "$url"
    cs_row WORKERS "$n"
    local fired; fired="$(rc_fire "$url" "$n" "$body")"
    local ok=0 total=0 distinct=0
    local idx code hash bytes
    : > "$PROBE_FILE"
    while IFS=$'\t' read -r idx code hash bytes; do
        [[ -z "$idx" ]] && continue
        total=$((total + 1))
        [[ "$code" =~ ^2 ]] && ok=$((ok + 1))
        printf '%s\t%s\t%s\t%s\n' "$idx" "$code" "$hash" "$bytes" >> "$PROBE_FILE"
        cs_row RESPONSE "$idx" "code=$code" "bytes=$bytes" "hash=$hash"
    done <<< "$fired"
    distinct="$(awk -F'\t' '{print $3}' "$PROBE_FILE" | sort -u | wc -l | tr -d ' ')"
    cs_row DISTINCT "$distinct"
    local v="serialised"
    [[ "$ok" -ge "$total" && "$total" -gt 1 ]] && v="all-succeeded"
    [[ "$ok" -gt 1 && "$ok" -lt "$total" ]] && v="partial-race"
    [[ "$ok" -le 1 ]] && v="serialised"
    cs_row VERDICT "$v" "$ok of $total accepted"
    cs_row SUMMARY "ok=$ok total=$total distinct=$distinct"
    cs_row ARTIFACT "$PROBE_FILE"
    return 0
}

# --double-spend <url> [n]: the money case, graded as such. The control request
# is spent first so the "one is allowed" baseline is real.
rc_cmd_double_spend() {
    local url="${1:-}" n="${2:-$RC_WORKERS}"
    [[ -z "$url" ]] && { rc_log "usage: --double-spend <url> [count]"; return 2; }
    cs_row TARGET "$url"
    local body; body="$(rc_body)"

    local dir; dir="$(mktemp -d "$CS_SCRATCH/rcs.XXXXXX")" 2>/dev/null || dir="$OUT_DIR/.rcs.$$"
    mkdir -p "$dir"
    local ccode
    ccode="$(curl -sS -o "$dir/one" -w '%{http_code}' -m "$RC_TIMEOUT" -A "$RC_UA" \
                  -X "$RC_METHOD" -H 'Content-Type: application/json' \
                  --data-binary "$body" "$url" 2>/dev/null)"
    cs_row CONTROL "code=${ccode:-000}"
    rm -rf "$dir"
    if [[ ! "${ccode:-000}" =~ ^2 ]]; then
        cs_row VERDICT "control-refused" "one request alone was refused; the race cannot be measured"
        cs_row SUMMARY "control=$ccode"
        return 0
    fi

    local fired; fired="$(rc_fire "$url" "$n" "$body")"
    local ok=0 total=0
    local idx code hash bytes
    while IFS=$'\t' read -r idx code hash bytes; do
        [[ -z "$idx" ]] && continue
        total=$((total + 1))
        [[ "$code" =~ ^2 ]] && ok=$((ok + 1))
    done <<< "$fired"

    local v; v="$(rc_verdict "$ok" "$total" 0 ok)"
    local sev; sev="$(rc_severity "$v" money "$ok")"
    cs_row CONCURRENT "succeeded=$ok/$total"
    cs_row VERDICT "$v"
    if [[ "$v" == "all-succeeded" || "$v" == "partial-race" ]]; then
        cs_row FINDING "$sev" "race-double-spend"
        rc_findings "$url" "$sev" "race-double-spend" \
            "$ok of $total concurrent debits were all accepted after the same balance read"
    fi
    cs_row SUMMARY "ok=$ok total=$total verdict=$v"
    return 0
}

# --coupon <url> <code> [n]: a coupon is validated and then marked used, which
# is the textbook split. Two sets of headers make it obvious whether the same
# code can be spent by two sessions.
rc_cmd_coupon() {
    local url="${1:-}" code="${2:-}" n="${3:-$RC_WORKERS}"
    [[ -z "$url" || -z "$code" ]] && { rc_log "usage: --coupon <url> <code> [count]"; return 2; }
    cs_row TARGET "$url"
    cs_row CODE "$code"
    local body; body="$(printf '{"code":"%s","memo":"race"}' "$code")"
    RC_BODY="$body"

    local fired; fired="$(rc_fire "$url" "$n" "$body")"
    local ok=0 total=0
    local idx c hash bytes
    : > "$PROBE_FILE"
    while IFS=$'\t' read -r idx c hash bytes; do
        [[ -z "$idx" ]] && continue
        total=$((total + 1))
        [[ "$c" =~ ^2 ]] && ok=$((ok + 1))
        printf '%s\t%s\t%s\n' "$idx" "$c" "$hash" >> "$PROBE_FILE"
    done <<< "$fired"

    local v; v="$(rc_verdict "$ok" "$total" 0 ok)"
    cs_row CONCURRENT "succeeded=$ok/$total"
    cs_row VERDICT "$v"
    if [[ "$v" == "all-succeeded" ]] && [[ "$total" -gt 1 ]]; then
        cs_row FINDING "CRITICAL" "race-coupon-reuse"
        rc_findings "$url" "CRITICAL" "race-coupon-reuse" \
            "the coupon '$code' was accepted $ok times concurrently"
    fi
    cs_row SUMMARY "ok=$ok total=$total verdict=$v"
    return 0
}

# --limit <url> [n]: a daily limit counted before the charge. The finding is
# that the counter is not the thing being enforced.
rc_cmd_limit() {
    local url="${1:-}" n="${2:-$RC_WORKERS}"
    [[ -z "$url" ]] && { rc_log "usage: --limit <url> [count]"; return 2; }
    cs_row TARGET "$url"
    local body; body="$(rc_body)"
    local fired; fired="$(rc_fire "$url" "$n" "$body")"
    local ok=0 total=0 limited=0
    local idx c hash bytes
    while IFS=$'\t' read -r idx c hash bytes; do
        [[ -z "$idx" ]] && continue
        total=$((total + 1))
        [[ "$c" =~ ^2 ]] && ok=$((ok + 1))
        [[ "$c" == "429" ]] && limited=$((limited + 1))
    done <<< "$fired"
    cs_row CONCURRENT "succeeded=$ok/$total" "rate-limited=$limited"
    local v="serialised"
    [[ "$ok" -ge "$total" && "$total" -gt 1 ]] && v="all-succeeded"
    [[ "$ok" -gt 1 && "$ok" -lt "$total" ]] && v="partial-race"
    cs_row VERDICT "$v"
    if [[ "$limited" -eq 0 && "$ok" -ge "$total" && "$total" -gt 1 ]]; then
        cs_row FINDING "HIGH" "race-limit-window"
        rc_findings "$url" "HIGH" "race-limit-window" \
            "$ok concurrent requests all passed a window that should have admitted fewer"
    fi
    cs_row SUMMARY "ok=$ok total=$total limited=$limited"
    return 0
}

# --gate <url> [n]: does the endpoint serialise at all. Some frameworks hold a
# lock and answer 409; the honest answer is the number of distinct response
# bodies, because a lock produces one winner and N refusals.
rc_cmd_gate() {
    local url="${1:-}" n="${2:-$RC_WORKERS}"
    [[ -z "$url" ]] && { rc_log "usage: --gate <url> [count]"; return 2; }
    cs_row TARGET "$url"
    local fired; fired="$(rc_fire "$url" "$n")"
    local ok=0 total=0
    local hashes=""
    local idx c hash bytes
    while IFS=$'\t' read -r idx c hash bytes; do
        [[ -z "$idx" ]] && continue
        total=$((total + 1))
        [[ "$c" =~ ^2 ]] && ok=$((ok + 1))
        hashes="$hashes$c:$hash"$'\n'
    done <<< "$fired"
    local distinct; distinct="$(printf '%s' "$hashes" | sort -u | grep -c . || true)"
    cs_row RESPONSES "total=$total" "succeeded=$ok" "distinct=${distinct:-0}"
    local v="ungated"
    [[ "$distinct" -le 1 && "$total" -gt 1 ]] && v="uniform-response"
    [[ "$ok" -le 1 ]] && v="gated"
    cs_row VERDICT "$v"
    cs_row SUMMARY "ok=$ok total=$total distinct=${distinct:-0}"
    return 0
}

rc_cmd_techniques() { local id class w; while IFS=$'\t' read -r id class w; do [[ -z "$id" ]] && continue; cs_row TECHNIQUE "$id" "$class" "$w"; done < <(rc_techniques); cs_row SUMMARY "techniques=$(rc_techniques | wc -l | tr -d ' ')"; return 0; }
rc_cmd_list()       { cs_row VERB "probe" "fire" "double-spend" "coupon" "limit" "gate" "techniques"; cs_row SUMMARY "ok"; return 0; }

rc_cmd_status_tsv() {
    local cur
    command -v curl >/dev/null 2>&1 && cur="curl-ok" || cur="curl-missing"
    printf '%s\t%s\t%s\tworkers-%s\ttechniques-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$cur" "$RC_WORKERS" "$(rc_techniques | wc -l | tr -d ' ')"
}

rc_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

rc_cmd_help() {
    cat <<'HELP'
cloudsting module 72 — Race Condition v1.0.0
  --probe <url> [n]            one request alone, then n together
  --fire <url> [n] [body]      raw concurrency, no interpretation
  --double-spend <url> [n]     the money case, graded as such
  --coupon <url> <code> [n]    one code, n concurrent redemptions
  --limit <url> [n]            a rolling window fired at once
  --gate <url> [n]             does the endpoint serialise at all
  --techniques | --list | --status-tsv | --menu | --selftest | --help

Sequential testing can never find a race condition: the first request finishes
before the second starts, so the test closes the very window it is looking for.
Every verb here releases all workers through a start barrier so they land in
the same millisecond.

The verdict is a comparison, not an absolute. A single request that fails means
`control-refused` and nothing else is reported — the concurrent run would only
measure the refusal. A 409 or a 500 on a lock conflict is the DEFENCE working,
so `serialised` is INFO, never a finding.

Grading follows the consequence: money, inventory and auth classes are
CRITICAL when every request wins, because "all twenty debits succeeded" and
"all twenty were sequential costs" are the same test with different bills.

Environment: RC_WORKERS (20), RC_TIMEOUT (15), RC_BODY, RC_METHOD (POST), RC_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
rc_selftest() {
    cs_selftest_reset

    local nt; nt="$(rc_techniques | wc -l | tr -d ' ')"
    chk tech-3col    "$(rc_techniques | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk tech-unique  "$(rc_techniques | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nt"
    chk tech-many    "$( (( nt >= 12 )) && echo many || echo few )" "many"
    chk tech-classes "$(rc_techniques | cut -f2 | sort -u | wc -l | tr -d ' ')" "5"

    # the verdict table
    chk v-unreach   "$(rc_verdict 0 20 0 dead)" "unreachable"
    chk v-refused   "$(rc_verdict 20 20 0 refused)" "control-refused"
    chk v-all       "$(rc_verdict 20 20 3 ok)" "all-succeeded"
    chk v-partial   "$(rc_verdict 5 20 3 ok)" "partial-race"
    chk v-serial    "$(rc_verdict 1 20 3 ok)" "serialised"
    chk v-zero      "$(rc_verdict 0 0 0 ok)" "unreachable"
    chk v-allrefused "$(rc_verdict 0 20 1 ok)" "all-refused"

    chk s-money     "$(rc_severity all-succeeded money 20)" "CRITICAL"
    chk s-inv       "$(rc_severity all-succeeded inventory 20)" "CRITICAL"
    chk s-auth      "$(rc_severity all-succeeded auth 20)" "CRITICAL"
    chk s-other     "$(rc_severity all-succeeded social 20)" "HIGH"
    chk s-partial   "$(rc_severity partial-race money 5)" "HIGH"
    chk s-serial    "$(rc_severity serialised money 1)" "INFO"
    chk s-ctlref    "$(rc_severity control-refused money 0)" "INFO"

    # firing against a dead host must produce codes, never a finding
    local out; out="$(rc_cmd_probe http://127.0.0.1:9 3 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-control "$(printf '%s' "$out" | awk -F'\t' '$1=="CONTROL"{print $2}')" "code=000"
    chk dead-hits    "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    out="$(rc_cmd_fire http://127.0.0.1:9 3 2>/dev/null)"
    chk dead-fire    "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "serialised"

    # usage errors
    rc_cmd_probe 2>/dev/null;       chk use-1 "$?" "2"
    rc_cmd_fire 2>/dev/null;        chk use-2 "$?" "2"
    rc_cmd_double_spend 2>/dev/null; chk use-3 "$?" "2"
    rc_cmd_coupon 2>/dev/null;      chk use-4 "$?" "2"
    rc_cmd_coupon http://127.0.0.1:9 2>/dev/null; chk use-5 "$?" "2"
    rc_cmd_limit 2>/dev/null;       chk use-6 "$?" "2"
    rc_cmd_gate 2>/dev/null;        chk use-7 "$?" "2"

    chk status-fields "$(rc_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(rc_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(rc_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(rc_cmd_help | head -1 | grep -ci 'Race')" "1"
    chk tech-rows     "$(rc_cmd_techniques | grep -c '^TECHNIQUE')" "$nt"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)        shift; rc_cmd_probe "$@";;
    --fire)         shift; rc_cmd_fire "$@";;
    --double-spend) shift; rc_cmd_double_spend "$@";;
    --coupon)       shift; rc_cmd_coupon "$@";;
    --limit)        shift; rc_cmd_limit "$@";;
    --gate)         shift; rc_cmd_gate "$@";;
    --techniques)   rc_cmd_techniques;;
    --list)         rc_cmd_list;;
    --status-tsv|--status) rc_cmd_status_tsv;;
    --menu)         rc_cmd_menu;;
    --selftest)     rc_selftest;;
    *)              rc_cmd_help;;
esac
