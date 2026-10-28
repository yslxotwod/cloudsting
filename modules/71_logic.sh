#!/usr/bin/env bash
# 71_logic.sh — cloudsting module 71: the rule nobody wrote down
# Verbs: --probe | --price | --quantity | --sequence | --discount | --trial
#        | --techniques | --list | --status-tsv | --menu | --selftest | --help
#
# Business logic bugs are the only class where the server is doing exactly what
# it was told. There is no injection, no missing header, no crash — the code
# enforces a rule, and the rule is wrong. Automated scanners cannot see these
# because nothing about the request is malformed; the REQUEST IS VALID and the
# ORDER OF VALID REQUESTS is the exploit.
#
# So this module never fuzzes. It performs a legal transaction, changes exactly
# one number or one step, and reports whether the server's arithmetic survives
# contact with reality.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="71_logic"
MOD_NAME="Business Logic (the rule nobody wrote down)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/business_logic"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${BL_TIMEOUT:=15}"
: "${BL_METHOD:=POST}"
: "${BL_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/71}"

bl_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the shapes worth trying ──────────────────────────────────────
# The last two columns are the whole point: what the app intends, and what the
# app actually does when the client says something slightly different. A row is
# only worth testing when those two differ in a way somebody could bill for.
#   <id>\t<family>\t<what the client changes>\t<the rule the app meant>\t<what the bug pays>
bl_techniques() {
    cat <<'TECHNIQUES'
negative-quantity	quantity	a quantity of -1	the total must be positive	the order credits you instead of charging you
zero-quantity	quantity	a quantity of 0	an order contains something	a free line that still ships
integer-overflow	quantity	99999999999999999	price times quantity fits	the multiplication wraps and the total goes small or negative
fractional-unit	quantity	0.0001 of a unit	a unit is indivisible	a tiny order that rounds into a full one
negative-price	price	a negative line price	prices come from the server	the cart total drops below zero
price-override	price	a price field the client owns	prices come from the server	you name your own price
currency-swap	price	the currency code on a priced item	the amount and currency travel together	a cheap currency charged at a rich price
rounding-abuse	price	many items each rounding down	a cent lost per line is noise	two hundred lines of one cent each
quantity-reset	sequence	the same cart emptied and refilled	the discount applies once	the discount reapplies per refill
trial-restart	sequence	a new signup on the same identity	one trial per person	unlimited free service
cancel-reorder	sequence	cancel after shipping, then reorder	the cancellation stops the goods	goods and a refund
discount-stack	discount	two coupons that both apply	at most one discount per order	the price goes negative
discount-repeat	discount	the same coupon submitted twice	one use per coupon	the coupon spends twice
coupon-swap	discount	the coupon id in the cart after validation	the coupon is bound to the cart	another coupon's value
gift-card-loop	discount	a gift card bought with itself	a card is bought with money	value created from nothing
trial-premium	trial	the plan field during a trial	the trial is the free tier	premium features on the free trial
refund-overflow	trial	refunding more than was paid	a refund is at most the payment	money from nowhere
TECHNIQUES
}

# ── sending and reading ──────────────────────────────────────────
#   bl_send <url> <body> [method] [header]
#   -> "<code>\t<bytes>\t<total>"
#
# The third field is the ONE number that matters for this class: what the app
# says the transaction costs. Every verb below is a comparison of that number
# against the number it should have been.
bl_send() {
    local url="$1" body="$2" method="${3:-$BL_METHOD}" hdr="${4:-}"
    local out; out="$(mktemp "$CS_SCRATCH/bl.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.bl.$$"
    local -a args=(-sS -o "$out" -w '%{http_code} %{size_download}' -m "$BL_TIMEOUT"
                   -A "$BL_UA" -X "$method" -H 'Content-Type: application/json'
                   --data-binary "$body")
    [ -n "$hdr" ] && args+=(-H "$hdr")
    local meta; meta="$(curl "${args[@]}" "$url" 2>/dev/null)"
    local code bytes
    read -r code bytes <<< "${meta:-000 0}"
    local total; total="$(bl_total "$out")"
    printf '%s\t%s\t%s\n' "${code:-000}" "${bytes:-0}" "${total:-none}"
    rm -f "$out"
}

# Pull the money out of a response, whatever the app called it. A total is a
# number the app is willing to be bound by, so it is normally a top-level field
# near the words total, amount, price, subtotal or balance.
bl_total() {
    local f="$1"
    [[ -s "$f" ]] || { printf 'none'; return; }
    if command -v jq >/dev/null 2>&1; then
        local v
        v="$(jq -r '
            [ .. | objects | to_entries[]
              | select(.key|test("^(total|grand_total|amount|subtotal|price|balance|charge)$"; "i"))
              | .value | numbers ] | first // empty
        ' "$f" 2>/dev/null)"
        [[ -n "$v" ]] && { printf '%s' "$v"; return; }
    fi
    # form-ish or prose responses
    grep -oaiE '(total|amount|price|subtotal|balance)[^0-9-]{0,12}-?[0-9]+(\.[0-9]+)?' "$f" 2>/dev/null \
        | head -1 | grep -oE -- '-?[0-9]+(\.[0-9]+)?' | head -1 || printf 'none'
}

# The verdict for a money comparison. The design decision that makes this
# module honest: a total that simply CHANGED is not a bug. Prices vary with
# quantity, tax and rounding, so only three shapes are findings:
#   cheaper    — the manipulated order costs less than one unit
#   negative   — the app owes the buyer
#   free       — a positive order costs nothing
bl_money_verdict() {
    local got="$1" baseline="$2"
    [[ "$got" == "none" ]] && { printf 'unreadable'; return; }
    [[ "$baseline" == "none" ]] && { printf 'no-baseline'; return; }
    awk -v g="$got" -v b="$baseline" 'BEGIN{
        if (b <= 0)      { print "no-baseline"; exit }
        if (g < 0)       { print "negative";    exit }
        if (g == 0)      { print "free";        exit }
        if (g < b)       { print "cheaper";     exit }
        if (g > b * 1.5) { print "charged-more"; exit }
        print "consistent"
    }'
}

bl_severity() {
    local v="$1" fam="$2"
    case "$v" in
        negative)     printf 'CRITICAL' ;;
        free)         printf 'CRITICAL' ;;
        cheaper)      case "$fam" in price|quantity) printf 'HIGH' ;; *) printf 'MEDIUM' ;; esac ;;
        charged-more) printf 'LOW' ;;
        accepted)     printf 'HIGH' ;;
        *)            printf 'INFO' ;;
    esac
}

bl_findings() { cs_findings_row "$MODULE_ID" "WEBAPI" "$4" "$3" "$2" > /dev/null; }

# ── verbs ────────────────────────────────────────────────────────

# --probe <url> [body]: is this even a priced endpoint. Without a baseline no
# other verb in this module can say anything, so this runs first and says so.
bl_cmd_probe() {
    local url="${1:-}" body="${2:-}"
    [[ -z "$url" ]] && { bl_log "usage: --probe <url> [body]"; return 2; }
    [[ -z "$body" ]] && body='{"item":"standard","quantity":1}'
    cs_row TARGET "$url"
    cs_row BODY "$body"

    local row; row="$(bl_send "$url" "$body")"
    local code bytes total
    IFS=$'\t' read -r code bytes total <<< "$row"
    cs_row RESPONSE "code=$code" "bytes=$bytes"
    cs_row TOTAL "$total"

    local v
    if [[ "$code" == "000" ]]; then v="unreachable"
    elif [[ ! "$code" =~ ^2 ]]; then v="refused"
    elif [[ "$total" == "none" ]]; then v="no-number"
    else v="priced"; fi
    cs_row VERDICT "$v"

    if [[ "$v" == "priced" ]]; then
        cs_row BASELINE "$total" "one unit, untouched — every other verb compares to this"
        cs_row SUMMARY "total=$total verdict=priced"
    elif [[ "$v" == "no-number" ]]; then
        cs_row NOTE "the response carries no total, amount or price — the money verbs cannot grade this endpoint"
        cs_row SUMMARY "verdict=no-number"
    else
        cs_row SUMMARY "verdict=$v"
    fi
    return 0
}

# --quantity <url> [body-template]: the negative/zero/overflow family. Each
# variation is compared to the one-unit baseline established here.
bl_cmd_quantity() {
    local url="${1:-}" tpl="${2:-}"
    [[ -z "$url" ]] && { bl_log "usage: --quantity <url> [body-template]"; return 2; }
    cs_row TARGET "$url"
    [[ -z "$tpl" ]] && tpl='{"item":"standard","quantity":@Q@}'

    local base; base="$(bl_send "$url" "${tpl//@Q@/1}")"
    local bcode bbytes btotal
    IFS=$'\t' read -r bcode bbytes btotal <<< "$base"
    cs_row BASELINE "qty=1 total=$btotal code=$bcode"
    if [[ "$bcode" == "000" ]]; then
        cs_row VERDICT "unreachable"; cs_row SUMMARY "verdict=unreachable"; return 0
    fi
    if [[ "$btotal" == "none" ]]; then
        cs_row VERDICT "no-baseline" "response carries no total"
        cs_row SUMMARY "verdict=no-baseline"; return 0
    fi

    local id fam what meant payoff
    while IFS=$'\t' read -r id fam what meant payoff; do
        case "$fam" in quantity) ;; *) continue;; esac
        local q
        case "$id" in
            negative-quantity) q="-1" ;;
            zero-quantity)     q="0" ;;
            integer-overflow)  q="99999999999999999" ;;
            fractional-unit)   q="0.0001" ;;
            *) continue ;;
        esac
        local row; row="$(bl_send "$url" "${tpl//@Q@/$q}")"
        local code bytes total
        IFS=$'\t' read -r code bytes total <<< "$row"
        local v; v="$(bl_money_verdict "$total" "$btotal")"
        [[ "$code" == "000" ]] && v="unreachable"
        [[ ! "$code" =~ ^2 ]] && [[ "$v" != "unreachable" ]] && v="refused"
        local sev; sev="$(bl_severity "$v" "$fam")"
        cs_row QUANTITY "$id" "qty=$q" "code=$code" "total=$total" "verdict=$v"
        if [[ "$v" == "negative" || "$v" == "free" || "$v" == "cheaper" ]]; then
            cs_row FINDING "$sev" "logic-$id"
            bl_findings "$url" "$sev" "logic-$id" "$payoff (qty=$q, total=$total vs baseline $btotal)"
        fi
    done < <(bl_techniques)
    cs_row SUMMARY "baseline=$btotal"
    return 0
}

# --price <url> [body-template]: does the client own the price. Also the
# currency-swap case, which is the same bug wearing a different field.
bl_cmd_price() {
    local url="${1:-}" tpl="${2:-}"
    [[ -z "$url" ]] && { bl_log "usage: --price <url> [body-template]"; return 2; }
    cs_row TARGET "$url"
    [[ -z "$tpl" ]] && tpl='{"item":"standard","quantity":1,"price":@P@}'

    local base; base="$(bl_send "$url" "${tpl//@P@/100}")"
    local bcode bbytes btotal
    IFS=$'\t' read -r bcode bbytes btotal <<< "$base"
    cs_row BASELINE "client_price=100 total=$btotal code=$bcode"
    if [[ "$bcode" == "000" ]]; then cs_row VERDICT "unreachable"; cs_row SUMMARY "verdict=unreachable"; return 0; fi
    if [[ "$btotal" == "none" ]]; then cs_row VERDICT "no-baseline"; cs_row SUMMARY "verdict=no-baseline"; return 0; fi

    local p
    for p in 1 0 -100 0.01; do
        local row; row="$(bl_send "$url" "${tpl//@P@/$p}")"
        local code bytes total
        IFS=$'\t' read -r code bytes total <<< "$row"
        local v; v="$(bl_money_verdict "$total" "$btotal")"
        [[ "$code" == "000" ]] && v="unreachable"
        [[ ! "$code" =~ ^2 && "$v" != "unreachable" ]] && v="refused"
        local sev; sev="$(bl_severity "$v" price)"
        cs_row PRICE "client=$p" "code=$code" "total=$total" "verdict=$v"
        # the pair that proves the client owns the price: the total tracks the
        # client's number rather than ignoring it
        if [[ "$v" == "negative" || "$v" == "free" || "$v" == "cheaper" ]]; then
            cs_row FINDING "$sev" "logic-price-override"
            bl_findings "$url" "$sev" "logic-price-override" \
                "the client price $p produced a total of $total against a baseline of $btotal"
        fi
    done
    # currency swap: same amount, cheaper currency
    local swap; swap="$(bl_send "$url" '{"item":"standard","quantity":1,"price":100,"currency":"IDR"}')"
    local scode sbytes stotal
    IFS=$'\t' read -r scode sbytes stotal <<< "$swap"
    cs_row CURRENCY "code=$scode" "total=$stotal" "baseline=$btotal"
    local sv; sv="$(bl_money_verdict "$stotal" "$btotal")"
    if [[ "$sv" == "cheaper" ]]; then
        cs_row FINDING "HIGH" "logic-currency-swap"
        bl_findings "$url" "HIGH" "logic-currency-swap" \
            "changing the currency code alone dropped the total from $btotal to $stotal"
    fi
    cs_row SUMMARY "baseline=$btotal"
    return 0
}

# --sequence <url>…: the verbs that need more than one request. Each step is a
# legitimate action; only the ORDER is the attack.
bl_cmd_sequence() {
    local url="${1:-}" extra="${2:-}"
    [[ -z "$url" ]] && { bl_log "usage: --sequence <url> [second-url]"; return 2; }
    cs_row TARGET "$url"
    [[ -n "$extra" ]] && cs_row SECOND "$extra"

    # trial restart: sign up twice with the same identity. The second signup
    # should be refused; if it is granted, the trial is per-request.
    local a b
    a="$(bl_send "$url" '{"email":"cloudsting-trial@example.invalid","plan":"trial"}')"
    b="$(bl_send "$url" '{"email":"cloudsting-trial@example.invalid","plan":"trial"}')"
    local acode abytes atotal bcode bbytes btotal
    IFS=$'\t' read -r acode abytes atotal <<< "$a"
    IFS=$'\t' read -r bcode bbytes btotal <<< "$b"
    cs_row STEP "signup-1" "code=$acode"
    cs_row STEP "signup-2" "code=$bcode" "same-identity"
    local v="refused"
    if [[ "$acode" == "000" || "$bcode" == "000" ]]; then v="unreachable"
    elif [[ "$acode" =~ ^2 && "$bcode" =~ ^2 ]]; then v="trial-restart"
    elif [[ ! "$acode" =~ ^2 ]]; then v="control-refused"
    fi
    cs_row VERDICT "$v"
    if [[ "$v" == "trial-restart" ]]; then
        cs_row FINDING "HIGH" "logic-trial-restart"
        bl_findings "$url" "HIGH" "logic-trial-restart" \
            "the same identity was granted a trial twice"
    fi
    cs_row SUMMARY "signup1=$acode signup2=$bcode verdict=$v"
    return 0
}

# --discount <url> [coupon]: stack and repeat. The finding is the total going
# below what one discount alone could produce.
bl_cmd_discount() {
    local url="${1:-}" coupon="${2:-cloudsting10}"
    [[ -z "$url" ]] && { bl_log "usage: --discount <url> [coupon]"; return 2; }
    cs_row TARGET "$url"
    cs_row COUPON "$coupon"

    local plain; plain="$(bl_send "$url" '{"item":"standard","quantity":1}')"
    local pcode pbytes ptotal
    IFS=$'\t' read -r pcode pbytes ptotal <<< "$plain"
    cs_row BASELINE "no-coupon total=$ptotal code=$pcode"
    if [[ "$pcode" == "000" ]]; then cs_row VERDICT "unreachable"; cs_row SUMMARY "verdict=unreachable"; return 0; fi

    # one coupon: the honest price
    local one; one="$(bl_send "$url" "{\"item\":\"standard\",\"quantity\":1,\"coupon\":\"$coupon\"}")"
    local ocode obytes ototal
    IFS=$'\t' read -r ocode obytes ototal <<< "$one"
    cs_row BASELINE "one-coupon total=$ototal code=$ocode"

    # the same coupon twice
    local twice; twice="$(bl_send "$url" "{\"item\":\"standard\",\"quantity\":1,\"coupons\":[\"$coupon\",\"$coupon\"]}")"
    local tcode tbytes ttotal
    IFS=$'\t' read -r tcode tbytes ttotal <<< "$twice"
    cs_row REPEAT "code=$tcode" "total=$ttotal"

    local v="checked"
    if [[ "$tcode" == "000" ]]; then v="unreachable"
    elif [[ ! "$tcode" =~ ^2 ]]; then v="repeat-refused"
    elif [[ "$ototal" != "none" && "$ttotal" != "none" ]]; then
        v="$(awk -v t="$ttotal" -v o="$ototal" 'BEGIN{ if (t < o) print "repeat-applied"; else print "repeat-ignored" }')"
    fi
    cs_row VERDICT "$v"
    if [[ "$v" == "repeat-applied" ]]; then
        cs_row FINDING "HIGH" "logic-discount-repeat"
        bl_findings "$url" "HIGH" "logic-discount-repeat" \
            "the same coupon applied twice: $ototal became $ttotal"
    fi

    # stacking: two DIFFERENT coupons
    local stack; stack="$(bl_send "$url" "{\"item\":\"standard\",\"quantity\":1,\"coupons\":[\"$coupon\",\"${coupon}b\"]}")"
    local scode sbytes stotal
    IFS=$'\t' read -r scode sbytes stotal <<< "$stack"
    cs_row STACK "code=$scode" "total=$stotal"
    if [[ "$scode" =~ ^2 && "$stotal" != "none" && "$ototal" != "none" ]]; then
        local neg; neg="$(awk -v s="$stotal" 'BEGIN{print (s < 0) ? "yes" : "no"}')"
        if [[ "$neg" == "yes" ]]; then
            cs_row FINDING "CRITICAL" "logic-discount-stack"
            bl_findings "$url" "CRITICAL" "logic-discount-stack" \
                "two stacked coupons drove the total to $stotal"
        fi
    fi
    cs_row SUMMARY "plain=$ptotal one=$ototal twice=$ttotal stack=$stotal verdict=$v"
    return 0
}

# --trial <url>: the refund and premium cases, both of which are about a
# quantity the client names and the server believes.
bl_cmd_trial() {
    local url="${1:-}"
    [[ -z "$url" ]] && { bl_log "usage: --trial <url>"; return 2; }
    cs_row TARGET "$url"

    local pay; pay="$(bl_send "$url" '{"action":"pay","amount":10}')"
    local pcode pbytes ptotal
    IFS=$'\t' read -r pcode pbytes ptotal <<< "$pay"
    cs_row STEP "pay" "code=$pcode" "total=$ptotal"
    if [[ "$pcode" == "000" ]]; then cs_row VERDICT "unreachable"; cs_row SUMMARY "verdict=unreachable"; return 0; fi

    local ref; ref="$(bl_send "$url" '{"action":"refund","amount":1000}')"
    local rcode rbytes rtotal
    IFS=$'\t' read -r rcode rbytes rtotal <<< "$ref"
    cs_row STEP "refund" "code=$rcode" "amount=1000" "total=$rtotal"
    local v="checked"
    if [[ ! "$rcode" =~ ^2 ]]; then v="refund-refused"
    else v="refund-over-payment"; fi
    cs_row VERDICT "$v"
    if [[ "$v" == "refund-over-payment" ]]; then
        cs_row FINDING "CRITICAL" "logic-refund-overflow"
        bl_findings "$url" "CRITICAL" "logic-refund-overflow" \
            "a refund of 1000 was accepted against a payment of 10"
    fi

    local prem; prem="$(bl_send "$url" '{"plan":"premium","trial":true}')"
    local mcode mbytes mtotal
    IFS=$'\t' read -r mcode mbytes mtotal <<< "$prem"
    cs_row STEP "trial-premium" "code=$mcode"
    if [[ "$mcode" =~ ^2 ]]; then
        cs_row FINDING "MEDIUM" "logic-trial-premium"
        bl_findings "$url" "MEDIUM" "logic-trial-premium" \
            "a premium plan was granted on a trial request"
    fi
    cs_row SUMMARY "verdict=$v"
    return 0
}

bl_cmd_techniques() {
    local id fam what meant payoff
    while IFS=$'\t' read -r id fam what meant payoff; do
        [[ -z "$id" ]] && continue
        cs_row TECHNIQUE "$id" "$fam" "$payoff"
    done < <(bl_techniques)
    cs_row SUMMARY "techniques=$(bl_techniques | wc -l | tr -d ' ')"
    return 0
}

bl_cmd_list() {
    cs_row VERB "probe" "quantity" "price" "sequence" "discount" "trial" "techniques"
    cs_row SUMMARY "ok"
    return 0
}

bl_cmd_status_tsv() {
    local cur
    command -v curl >/dev/null 2>&1 && cur="curl-ok" || cur="curl-missing"
    printf '%s\t%s\t%s\ttechniques-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$cur" "$(bl_techniques | wc -l | tr -d ' ')"
}

bl_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

bl_cmd_help() {
    cat <<'HELP'
cloudsting module 71 — Business Logic v1.0.0
  --probe <url> [body]            is this a priced endpoint, and what is one unit
  --quantity <url> [body]         negative, zero, overflowing and fractional amounts
  --price <url> [body]            does the client own the price or the currency
  --sequence <url>                two legitimate actions whose ORDER is the attack
  --discount <url> [coupon]       the same coupon twice, and two coupons at once
  --trial <url>                   refund above payment, premium on a trial
  --techniques | --list | --status-tsv | --menu | --selftest | --help

This is the only class where the server is doing what it was told. Nothing is
malformed, so nothing is detected as malformed: the request is valid and the
SEQUENCE of valid requests is the exploit. There is no payload table here
because there is nothing to inject.

The grading rule is a comparison against a baseline this module measures first.
A total that merely changed is not a finding — prices move with quantity, tax
and rounding. Only three shapes are reported:

  negative    the app now owes the buyer              CRITICAL
  free        a positive order costs nothing          CRITICAL
  cheaper     the manipulated order costs less than
              the untouched one                     HIGH/MEDIUM

A verb whose baseline cannot be measured says so (`no-baseline`, `no-number`,
`unreachable`) and reports nothing. Saying nothing is the correct answer when
the endpoint does not price anything.

Environment: BL_TIMEOUT (15), BL_METHOD (POST), BL_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
bl_selftest() {
    cs_selftest_reset

    local nt; nt="$(bl_techniques | wc -l | tr -d ' ')"
    chk tech-5col   "$(bl_techniques | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk tech-unique "$(bl_techniques | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nt"
    chk tech-many   "$( (( nt >= 16 )) && echo many || echo few )" "many"
    chk tech-fams   "$(bl_techniques | cut -f2 | sort -u | tr -d '\n')" "discountpricequantitysequencetrial"

    chk m-neg       "$(bl_money_verdict -5 100)" "negative"
    chk m-zero      "$(bl_money_verdict 0 100)" "free"
    chk m-cheap     "$(bl_money_verdict 40 100)" "cheaper"
    chk m-same      "$(bl_money_verdict 100 100)" "consistent"
    chk m-more      "$(bl_money_verdict 900 100)" "charged-more"
    chk m-nodata    "$(bl_money_verdict none 100)" "unreadable"
    chk m-nobase    "$(bl_money_verdict 40 none)" "no-baseline"
    chk m-zerobase  "$(bl_money_verdict 40 0)" "no-baseline"

    chk s-neg       "$(bl_severity negative quantity)" "CRITICAL"
    chk s-free      "$(bl_severity free price)" "CRITICAL"
    chk s-cheap     "$(bl_severity cheaper price)" "HIGH"
    chk s-cheapseq  "$(bl_severity cheaper trial)" "MEDIUM"
    chk s-more      "$(bl_severity charged-more price)" "LOW"

    # total extraction from the message shapes a real app returns
    local d; d="$(mktemp -d "$CS_SCRATCH/blt.XXXXXX")" 2>/dev/null || d="$OUT_DIR/.blt.$$"
    mkdir -p "$d"
    printf '{"ok":true,"total":42.5}' > "$d/a"
    chk t-json    "$(bl_total "$d/a")" "42.5"
    printf '{"data":{"order":{"grand_total":7}}}' > "$d/b"
    chk t-nested  "$(bl_total "$d/b")" "7"
    printf 'Total: $19.99\n' > "$d/c"
    chk t-prose   "$(bl_total "$d/c")" "19.99"
    : > "$d/d"
    chk t-empty   "$(bl_total "$d/d")" "none"
    rm -rf "$d"

    # a dead host must report reachability, never a pricing bug
    local out; out="$(bl_cmd_probe http://127.0.0.1:9 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-hits    "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    out="$(bl_cmd_quantity http://127.0.0.1:9 2>/dev/null)"
    chk dead-qty     "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-qtyhits "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    out="$(bl_cmd_price http://127.0.0.1:9 2>/dev/null)"
    chk dead-price   "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"

    # usage errors
    bl_cmd_probe 2>/dev/null;    chk use-1 "$?" "2"
    bl_cmd_quantity 2>/dev/null; chk use-2 "$?" "2"
    bl_cmd_price 2>/dev/null;    chk use-3 "$?" "2"
    bl_cmd_sequence 2>/dev/null; chk use-4 "$?" "2"
    bl_cmd_discount 2>/dev/null; chk use-5 "$?" "2"
    bl_cmd_trial 2>/dev/null;    chk use-6 "$?" "2"

    chk status-fields "$(bl_cmd_status_tsv | awk -F'\t' '{print NF}')" "4"
    chk status-module "$(bl_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(bl_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(bl_cmd_help | head -1 | grep -ci 'Business Logic')" "1"
    chk tech-rows     "$(bl_cmd_techniques | grep -c '^TECHNIQUE')" "$nt"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)      shift; bl_cmd_probe "$@";;
    --quantity)   shift; bl_cmd_quantity "$@";;
    --price)      shift; bl_cmd_price "$@";;
    --sequence)   shift; bl_cmd_sequence "$@";;
    --discount)   shift; bl_cmd_discount "$@";;
    --trial)      shift; bl_cmd_trial "$@";;
    --techniques) bl_cmd_techniques;;
    --list)       bl_cmd_list;;
    --status-tsv|--status) bl_cmd_status_tsv;;
    --menu)       bl_cmd_menu;;
    --selftest)   bl_selftest;;
    *)            bl_cmd_help;;
esac
