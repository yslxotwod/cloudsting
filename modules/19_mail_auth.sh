#!/usr/bin/env bash
# 19_mail_auth.sh — cloudsting module 19: send as the tenant, and read its mailboxes
# Verbs: --domain <d> | --spoof <d> [from] | --relay <host[:port]> | --enum <d> | --providers | --selectors | --status-tsv | --menu | --selftest
set -u
umask 077

# An inherited CS_MOD_DIR is a caller's directory; deriving it after the core
# is sourced is what keeps every loot path inside this checkout.
unset CS_MOD_DIR

MODULE_ID="19_mail_auth"
MOD_NAME="Mail Authentication"
MOD_VERSION="0.1.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/mail_auth"
mkdir -p "$OUT_DIR" 2>/dev/null || true

POSTURE_FILE="$OUT_DIR/posture-$RUN_ID.tsv"

: "${MA_DNS_TIMEOUT:=3}"    # per lookup
: "${MA_SMTP_TIMEOUT:=10}"  # per SMTP dialogue

# ── helpers ──────────────────────────────────────────────────────
ma_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# One DNS lookup, with three states. An empty answer from a server that
# answered is "no such record"; a dead resolver is not the same thing and must
# never be read as a missing SPF.
#   ma_txt <name>  → uses MA_RAW / MA_STATE
MA_RAW=""; MA_STATE=""
ma_query() {
    local qtype="${1:?type}" name="${2:?name}"
    MA_RAW=""; MA_STATE=""
    # A fixture database replaces the resolver for the whole chain, so a
    # selftest exercises the parsing and the verdicts rather than stubbing the
    # answer in front of them. Lines are TYPE<TAB>NAME<TAB>STATE<TAB>RAW, and a
    # raw field holding @NL@ is turned back into separate record lines.
    if [[ -n "${MA_FIXTURE_DB:-}" && -f "${MA_FIXTURE_DB:-}" ]]; then
        local hit
        hit="$(awk -F'\t' -v t="$qtype" -v n="$name" '$1==t && $2==n {print $3"\t"$4; exit}' "$MA_FIXTURE_DB")"
        if [[ -n "$hit" ]]; then
            MA_STATE="${hit%%$'\t'*}"
            MA_RAW="${hit#*$'\t'}"
            [[ "$MA_RAW" == "-" ]] && MA_RAW=""
            MA_RAW="${MA_RAW//@NL@/$'\n'}"
            return 0
        fi
    fi
    if ! cs_have dig; then MA_STATE="no-dig"; return 0; fi
    local out rc
    out="$(timeout $((MA_DNS_TIMEOUT + 2)) dig +short +time="$MA_DNS_TIMEOUT" +tries=1 "$qtype" "$name" 2>/dev/null)"
    rc=$?
    if (( rc != 0 )); then MA_STATE="error"; return 0; fi
    # dig prints nothing for a name that exists without that record type, and
    # nothing for NXDOMAIN too, so ask once more whether the name exists at all
    if [[ -z "$out" ]]; then
        local any
        any="$(timeout $((MA_DNS_TIMEOUT + 2)) dig +short +time="$MA_DNS_TIMEOUT" +tries=1 NS "$name" 2>/dev/null)"
        if [[ -n "$any" ]]; then MA_STATE="no-record"; else MA_STATE="nxdomain"; fi
        return 0
    fi
    MA_RAW="$out"; MA_STATE="ok"
}

ma_txt() { ma_query TXT "${1:?}"; }
ma_mx()  { ma_query MX  "${1:?}"; }

# TXT answers arrive quoted, sometimes split across adjacent chunks.
ma_unquote() {
    sed -e 's/" "//g' -e 's/^"//' -e 's/"$//' | tr -d '\r'
}

ma_spf_raw() {
    ma_txt "${1:?}"
    [[ "$MA_STATE" == "ok" ]] || return 0
    printf '%s' "$MA_RAW" | ma_unquote | grep -i '^v=spf1' | head -4
}

# ── SPF ──────────────────────────────────────────────────────────
# A second SPF record is a permanent error, not a better one: receivers are
# required to treat multiple records as permerror, which fails open in the
# sense that the domain has no usable policy.
ma_spf_count() { local r; r="$(ma_spf_raw "${1:?}")"; [[ -z "$r" ]] && { printf '0'; return 0; }; printf '%s\n' "$r" | grep -c .; }

ma_spf_all() {
    local r; r="$(ma_spf_raw "${1:?}")"
    [[ -z "$r" ]] && return 0
    # the qualifier on the all mechanism, defaulting to + when absent
    printf '%s\n' "$r" | head -1 | tr ' ' '\n' \
        | grep -E '^[-+~?]?all$' | head -1 \
        | sed -E 's/^all$/+all/'
}

# DNS lookups an SPF record costs. Receivers are allowed ten; an eleventh is a
# permerror, which most receivers handle by dropping the policy entirely.
ma_spf_lookups() {
    local r; r="$(ma_spf_raw "${1:?}")"
    [[ -z "$r" ]] && { printf '0'; return 0; }
    local n=0 tok
    for tok in $(printf '%s\n' "$r" | head -1 | tr ' ' '\n'); do
        case "${tok#[+\-~?]}" in
            include:*|a|a:*|a/*|mx|mx:*|mx/*|ptr|ptr:*|exists:*|redirect=*) n=$((n+1)) ;;
        esac
    done
    printf '%s' "$n"
}

ma_spf_includes() {
    local r; r="$(ma_spf_raw "${1:?}")"
    [[ -z "$r" ]] && return 0
    printf '%s\n' "$r" | head -1 | tr ' ' '\n' \
        | sed -n 's/^[-+~?]\{0,1\}include://p' \
        | sed 's/[[:space:]]*$//' | grep . | sort -u
}

# The one question that matters for spoofing: does a message claiming to be
# this domain fail SPF? ~all and ?all allow it to pass as "softfail/neutral",
# and most receivers still deliver a softfail.
ma_spf_verdict() {
    local d="${1:?}" n all
    n="$(ma_spf_count "$d")"
    if [[ "$n" == "0" ]]; then printf 'no-spf'; return 0; fi
    if (( n > 1 )); then printf 'permerror-multiple'; return 0; fi
    all="$(ma_spf_all "$d")"
    if (( $(ma_spf_lookups "$d") > 10 )); then printf 'permerror-lookups'; return 0; fi
    case "$all" in
        -all) printf 'strict' ;;
        ~all) printf 'softfail' ;;
        '?all') printf 'neutral' ;;
        +all) printf 'open' ;;
        *)    printf 'no-all' ;;
    esac
}

# ── DMARC ────────────────────────────────────────────────────────
ma_dmarc_raw() {
    ma_txt "_dmarc.${1:?}"
    [[ "$MA_STATE" == "ok" ]] || return 0
    printf '%s' "$MA_RAW" | ma_unquote | grep -i '^v=DMARC1' | head -1
}

ma_dmarc_tag() {
    local raw="${1:-}" tag="${2:?}"
    [[ -z "$raw" ]] && return 0
    printf '%s' "$raw" | tr ';' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
        | sed -n "s/^${tag}=//p" | head -1
}

ma_dmarc_policy() {
    local raw; raw="$(ma_dmarc_raw "${1:?}")"
    [[ -z "$raw" ]] && { printf 'none'; return 0; }
    local p; p="$(ma_dmarc_tag "$raw" p)"
    printf '%s' "${p:-none}"
}

ma_dmarc_pct() {
    local raw; raw="$(ma_dmarc_raw "${1:?}")"
    [[ -z "$raw" ]] && { printf '0'; return 0; }
    local pct; pct="$(ma_dmarc_tag "$raw" pct)"
    printf '%s' "${pct:-100}"
}

ma_dmarc_rua() {
    local raw; raw="$(ma_dmarc_raw "${1:?}")"
    [[ -z "$raw" ]] && return 0
    ma_dmarc_tag "$raw" rua
}

# ── DKIM ─────────────────────────────────────────────────────────
# Selectors are not published anywhere: they are named in the signature of a
# message that was sent. The common list is a guess, and a miss proves only
# that nobody used a common name.
ma_selectors() {
    printf 'default\ngoogle\nselector1\nselector2\ns1\ns2\nk1\nk2\nmail\nsmtp\ndkim\ndkimmail\nmandrill\nsmtpapi\namazonses\nsendgrid\nmailchimp\nprotonmail\nzoho\nmxvault\ncm\nmailjet\nresend\npostmark\n20230601\n2024\n'
}

ma_dkim_found() {
    local d="${1:?}" sel ns found=0
    while read -r sel; do
        [[ -z "$sel" ]] && continue
        ma_txt "${sel}._domainkey.${d}"
        case "$MA_STATE" in
            ok) printf '%s\n' "$MA_RAW" | ma_unquote | grep -qi 'v=DKIM1\|p=' && { printf '%s\n' "$sel"; found=$((found+1)); } ;;
        esac
    done < <(ma_selectors)
    return 0
}

# ── hosted-mail fingerprint ──────────────────────────────────────
# Read from the MX record the domain actually publishes.
ma_mx_provider() {
    local d="${1:?}"
    ma_mx "$d"
    [[ "$MA_STATE" == "ok" ]] || { printf 'unknown'; return 0; }
    # the separator join leaves a trailing space, and "." would never match
    # the null-MX arm with one attached
    local h; h="$(printf '%s' "$MA_RAW" | awk '{print $NF}' | tr 'A-Z' 'a-z' | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    case "$h" in
        *google.com*|*googlemail*|*gmail-smtp*)                printf 'google-workspace' ;;
        *protection.outlook*|*mail.protection.outlook*)        printf 'microsoft-365' ;;
        *pphosted*|*proofpoint*)                               printf 'proofpoint' ;;
        *mimecast*)                                            printf 'mimecast' ;;
        *barracudanetworks*|*barracuda*)                       printf 'barracuda' ;;
        *sophos*|*reflexion*)                                  printf 'sophos' ;;
        *trendmicro*|*tmes*)                                   printf 'trend-micro' ;;
        *messagelabs*|*broadcom*|*symantec*)                   printf 'symantec' ;;
        *amazonses*|*amazonaws*|*awsapps*)                     printf 'amazon-workmail-ses' ;;
        *mailgun*|*mailgun.org*)                               printf 'mailgun' ;;
        *sendgrid*|*sendgrid.net*)                             printf 'sendgrid' ;;
        *zoho*|*zohomail*)                                     printf 'zoho' ;;
        *yandex*)                                              printf 'yandex' ;;
        *qq.com*|*exmail*)                                     printf 'tencent' ;;
        *aliyun*|*alibaba*|*mxhichina*)                        printf 'alibaba' ;;
        *secureserver*|*godaddy*)                              printf 'godaddy' ;;
        *improvmx*|*forwardemail*)                             printf 'forwarder' ;;
        .|-)                                                   printf 'null-mx' ;;
        *)                                                     printf 'self-hosted-or-other' ;;
    esac
}

# ── the spoof verdict ────────────────────────────────────────────
# This is the module's central judgement and it has to be conservative. A
# display-name spoof needs no technical weakness at all, so it is never
# counted here: the question is only whether a message claiming this domain in
# the From: header survives SPF and DMARC.
ma_spoof_verdict() {
    local d="${1:?}"
    local spf dmarc pct
    spf="$(ma_spf_verdict "$d")"
    dmarc="$(ma_dmarc_policy "$d")"
    pct="$(ma_dmarc_pct "$d")"

    # What the verdicts mean, in the terms the finding is written in:
    #   hardened  p=reject and a usable SPF — a forgery fails
    #   partial   p=reject with a weak SPF, or p=quarantine at full coverage —
    #             a forgery lands in junk rather than the inbox, so the domain
    #             IS enforcing and no finding is raised
    #   weak      quarantine at a pct below 100, or p=none with a strict SPF —
    #             one signal fires and nothing consequential follows from it
    #   spoofable p=none or absent with a permissive SPF — a forgery is delivered
    case "$dmarc" in
        reject)
            # softfail and neutral are failures for DMARC's purposes, so only
            # an SPF that a forged sender can actually PASS weakens reject
            case "$spf" in
                open|permerror-multiple|permerror-lookups) printf 'partial' ;;
                *)                                         printf 'hardened' ;;
            esac
            return 0 ;;
        quarantine)
            if (( pct >= 100 )); then printf 'partial'; else printf 'weak'; fi
            return 0 ;;
        none)
            case "$spf" in
                strict) printf 'weak' ;;   # spf alone, and dmarc does not enforce it
                *)      printf 'spoofable' ;;
            esac
            return 0 ;;
        *)
            printf 'spoofable'
            return 0 ;;
    esac
}

# The sentence an operator reads next to the verdict. It is derived from the
# verdict itself so the two cannot disagree.
ma_spoof_why() {
    local d="${1:?}" v spf dmarc pct
    v="$(ma_spoof_verdict "$d")"
    spf="$(ma_spf_verdict "$d")"
    dmarc="$(ma_dmarc_policy "$d")"
    pct="$(ma_dmarc_pct "$d")"
    case "$v" in
        hardened)
            printf 'WHY\tDMARC p=%s and SPF %s: a forged From: fails and is rejected\n' "$dmarc" "$spf" ;;
        partial)
            if [[ "$dmarc" == "reject" ]]; then
                printf 'WHY\tDMARC p=reject, but SPF is %s so a forged sender can pass it; only a DKIM failure still stops the forgery\n' "$spf"
            else
                printf 'WHY\tDMARC p=%s at pct=%s: a forgery is quarantined rather than rejected, so it lands in junk\n' "$dmarc" "$pct"
            fi ;;
        weak)
            if [[ "$dmarc" == "none" ]]; then
                printf 'WHY\tDMARC p=none with SPF %s: SPF may fail and nothing follows from it, so a forgery is delivered\n' "$spf"
            else
                printf 'WHY\tDMARC p=%s covers only pct=%s of mail, so most forgeries are unaffected\n' "$dmarc" "$pct"
            fi ;;
        *)
            printf 'WHY\tDMARC p=%s with SPF %s: nothing rejects or quarantines a forged From:, so it is delivered\n' "$dmarc" "$spf" ;;
    esac
}

ma_posture_rows() {
    local d="${1:?}"
    local spf_raw dmarc_raw

    ma_txt "$d"
    printf 'DNS\t%s\t%s\n' "domain-exists" "$MA_STATE"

    spf_raw="$(ma_spf_raw "$d")"
    printf 'SPF\t%s\t%s\n' "record" "$( [[ -n "$spf_raw" ]] && echo present || echo absent )"
    printf 'SPF\t%s\t%s\n' "count" "$(ma_spf_count "$d")"
    printf 'SPF\t%s\t%s\n' "all" "$(ma_spf_all "$d")"
    printf 'SPF\t%s\t%s\n' "lookups" "$(ma_spf_lookups "$d")"
    printf 'SPF\t%s\t%s\n' "verdict" "$(ma_spf_verdict "$d")"
    local inc; inc="$(ma_spf_includes "$d" | tr '\n' ',' | sed 's/,$//')"
    [[ -n "$inc" ]] && printf 'SPF\t%s\t%s\n' "includes" "$inc"

    dmarc_raw="$(ma_dmarc_raw "$d")"
    printf 'DMARC\t%s\t%s\n' "record" "$( [[ -n "$dmarc_raw" ]] && echo present || echo absent )"
    printf 'DMARC\t%s\t%s\n' "p" "$(ma_dmarc_policy "$d")"
    printf 'DMARC\t%s\t%s\n' "pct" "$(ma_dmarc_pct "$d")"
    printf 'DMARC\t%s\t%s\n' "rua" "$( { ma_dmarc_rua "$d"; } || true )"

    ma_mx "$d"
    printf 'MX\t%s\t%s\n' "state" "$MA_STATE"
    printf 'MX\t%s\t%s\n' "provider" "$(ma_mx_provider "$d")"
    [[ "$MA_STATE" == "ok" ]] && printf 'MX\t%s\t%s\n' "hosts" "$(printf '%s' "$MA_RAW" | awk '{print $NF}' | tr '\n' ',' | sed 's/,$//')"

    local dk; dk="$(ma_dkim_found "$d" | tr '\n' ',' | sed 's/,$//')"
    printf 'DKIM\t%s\t%s\n' "selectors" "${dk:-none-found}"

    ma_txt "_mta-sts.${d}"
    printf 'MTA-STS\t%s\t%s\n' "record" "$( [[ "$MA_STATE" == "ok" ]] && echo present || echo absent )"
    ma_txt "default._bimi.${d}"
    printf 'BIMI\t%s\t%s\n' "record" "$( [[ "$MA_STATE" == "ok" ]] && echo present || echo absent )"

    printf 'VERDICT\t%s\t%s\n' "spoof" "$(ma_spoof_verdict "$d")"
}

# host[:port] → MA_HP_HOST / MA_HP_PORT. Both SMTP verbs parse the same way,
# and a target without a port means the default, not a port of zero.
MA_HP_HOST=""; MA_HP_PORT=25
ma_split_hostport() {
    local t="${1:?target}"
    case "$t" in
        *:*) MA_HP_HOST="${t%%:*}"; MA_HP_PORT="${t##*:}" ;;
        *)   MA_HP_HOST="$t";        MA_HP_PORT=25 ;;
    esac
}

# ── SMTP ─────────────────────────────────────────────────────────
# A small dialogue in python because the reply codes are what matter and bash
# cannot read them without a socket dance that hides the boundary handling.
# Prints one line per step: STEP -> CODE text
ma_smtp_dialog() {
    local host="${1:?}" port="${2:?}"; shift 2
    if ! cs_have python3; then printf 'ERROR\tno-python3\n'; return 3; fi
    MA_SMTP_HOST="$host" MA_SMTP_PORT="$port" MA_SMTP_TIMEOUT="$MA_SMTP_TIMEOUT" \
    MA_SMTP_STEPS="$(printf '%s\n' "$@")" python3 - <<'PY'
import os, socket, sys

host = os.environ["MA_SMTP_HOST"]
port = int(os.environ["MA_SMTP_PORT"])
timeout = float(os.environ["MA_SMTP_TIMEOUT"])
steps = [s for s in os.environ.get("MA_SMTP_STEPS", "").splitlines() if s.strip()]

try:
    s = socket.create_connection((host, port), timeout=timeout)
except Exception as e:
    print("ERROR\t%s" % (str(e).split("]")[-1].strip() or "connect-failed"))
    raise SystemExit(0)

s.settimeout(timeout)
f = s.makefile("rwb", buffering=0)

def read_reply():
    out = []
    while True:
        line = f.readline()
        if not line:
            return None
        text = line.decode("utf-8", "replace").rstrip("\r\n")
        out.append(text)
        # a multi-line reply continues while the fourth character is '-'
        if len(text) < 4 or text[3] != "-":
            break
    code = out[0][:3] if out and out[0][:3].isdigit() else "000"
    return code, " | ".join(out)

try:
    hello = read_reply()
    print("BANNER\t%s\t%s" % (hello[0], hello[1]) if hello else "BANNER\t000\tnone")
    for step in steps:
        f.write((step + "\r\n").encode())
        r = read_reply()
        if r is None:
            print("CLOSED\t000\tconnection closed after %s" % step)
            break
        print("%s\t%s\t%s" % (step.split()[0].upper(), r[0], r[1]))
finally:
    try:
        f.write(b"QUIT\r\n"); f.close()
    except Exception:
        pass
    try: s.close()
    except Exception: pass
PY
}

ma_smtp_codes() { awk -F'\t' '{print $1"="$2}' | tr '\n' ' ' | sed 's/ $//'; }

# An open relay accepts a recipient for a domain it does not host. One accepted
# domain is not enough — some servers accept anything they can queue — so the
# second unrelated domain is the confirmation.
ma_cmd_relay() {
    local target="${1:-}"
    if [[ -z "$target" ]]; then
        printf 'usage: --relay <host[:port]>\n' >&2
        return 2
    fi
    ma_split_hostport "$target"
    local host="$MA_HP_HOST" port="$MA_HP_PORT"
    printf 'RELAY\t%s:%s\n' "$host" "$port"
    local out; out="$(ma_smtp_dialog "$host" "$port" \
        "EHLO cloudsting.invalid" \
        "MAIL FROM:<cs-probe@cloudsting.invalid>" \
        "RCPT TO:<cs-probe@example.net>" \
        "RCPT TO:<cs-probe2@example.org>")"
    printf '%s\n' "$out" | sed 's/^/STEP\t/'
    local c1 c2
    c1="$(printf '%s\n' "$out" | awk -F'\t' '$1=="RCPT"&&!seen++{print $2}')"
    c2="$(printf '%s\n' "$out" | awk -F'\t' '$1=="RCPT"{n++; if(n==2) print $2}')"
    local verdict
    case "${c1:-000}" in
        000|CLOSED) verdict="unreachable" ;;
        250|251)
            case "${c2:-000}" in
                250|251) verdict="open-relay" ;;
                *)       verdict="accepts-one-domain" ;;
            esac ;;
        *) verdict="not-a-relay" ;;
    esac
    printf 'VERDICT\t%s\t%s\n' "$verdict" "$(printf '%s' "$out" | ma_smtp_codes)"
    if [[ "$verdict" == "open-relay" ]]; then
        cs_findings_row "$MODULE_ID" "ATTRITION" "$host:$port" "critical-smtp-open-relay" \
            "the server accepted a recipient for two unrelated external domains, so it will relay mail for anyone" > /dev/null
    fi
}

# Mailbox existence. A catch-all answers every address the same way, which
# makes the whole test worthless, so a random control address is sent first.
ma_enum_candidates() { printf 'admin\nbilling\nnoc\ninfo\nsupport\nfinance\nit\npayroll\n'; }

ma_cmd_enum() {
    local domain="${1:-}" target="${2:-}"
    local host="" port=25
    if [[ -n "$target" ]]; then
        ma_split_hostport "$target"
        host="$MA_HP_HOST"; port="$MA_HP_PORT"
    fi
    if [[ -z "$domain" ]]; then
        printf 'usage: --enum <domain> [mx-host[:port]]\n' >&2
        return 2
    fi
    if [[ -z "$host" ]]; then
        ma_mx "$domain"
        if [[ "$MA_STATE" != "ok" ]]; then
            printf 'SKIP\t%s\tno-mx (%s)\n' "$domain" "$MA_STATE"
            return 0
        fi
        host="$(printf '%s' "$MA_RAW" | awk '{print $NF}' | head -1)"
    fi
    local ctl="cloudsting-no-such-$(date +%s)-$RANDOM"
    printf 'ENUM\t%s\t%s:%s\n' "$domain" "$host" "$port"

    local steps=("EHLO cloudsting.invalid" "MAIL FROM:<cs-probe@cloudsting.invalid>" "RCPT TO:<${ctl}@${domain}>")
    local a
    while read -r a; do
        [[ -z "$a" ]] && continue
        steps+=("RCPT TO:<${a}@${domain}>")
    done < <(ma_enum_candidates)

    local out; out="$(ma_smtp_dialog "$host" "$port" "${steps[@]}")"
    if [[ "$(printf '%s' "$out" | head -1 | cut -f1)" == "ERROR" ]]; then
        printf 'SKIP\t%s\t%s\n' "$domain" "$(printf '%s' "$out" | head -1 | cut -f3)"
        return 0
    fi
    local ctl_code; ctl_code="$(printf '%s\n' "$out" | awk -F'\t' '$1=="RCPT"&&!seen++{print $2}')"
    if [[ "$ctl_code" == "250" || "$ctl_code" == "251" ]]; then
        printf 'VERDICT\tcatch-all\t%s\n' "a random address was accepted, so existence cannot be measured"
        cs_findings_row "$MODULE_ID" "ATTRITION" "$domain" "low-smtp-catch-all" \
            "the mail server accepts a random recipient address, which hides whether any real address exists" > /dev/null
        return 0
    fi
    # the candidate replies are every RCPT after the control, in order, so the
    # address is taken from the list rather than from the server's echo
    local n=0 idx=0 addr
    while read -r addr; do
        [[ -z "$addr" ]] && continue
        idx=$((idx+1))
        local code; code="$(printf '%s\n' "$out" | awk -F'\t' -v i=$((idx+1)) '$1=="RCPT"{n++; if(n==i) print $2}')"
        case "$code" in
            250|251) printf 'MAILBOX\t%s\t%s\n' "$addr@$domain" "exists"; n=$((n+1)) ;;
            550|551|553|554) printf 'MAILBOX\t%s\t%s\n' "$addr@$domain" "rejected" ;;
            450|451|452) printf 'MAILBOX\t%s\t%s\n' "$addr@$domain" "greylisted" ;;
            *) printf 'MAILBOX\t%s\t%s\n' "$addr@$domain" "code-${code:-000}" ;;
        esac
    done < <(ma_enum_candidates)
    printf 'VERDICT\t%s\t%s\n' "enumerable" "$n exist of $(ma_enum_candidates | wc -l | tr -d ' ')"
    if (( n >= 2 )); then
        cs_findings_row "$MODULE_ID" "ATTRITION" "$domain" "medium-mailbox-enumerable" \
            "$n of the probed addresses answer 250 while a random control address is rejected" > /dev/null
    fi
}

# ── verbs ────────────────────────────────────────────────────────
ma_cmd_domain() {
    local d="${1:-}"
    if [[ -z "$d" ]]; then printf 'usage: --domain <domain>\n' >&2; return 2; fi
    d="${d#@}"
    d="$(printf '%s' "$d" | tr 'A-Z' 'a-z' | sed -e 's/^\.//' -e 's/\.$//')"
    case "$d" in www.*) d="${d#www.}" ;; esac
    printf 'DOMAIN\t%s\n' "$d"
    ma_posture_rows "$d" | tee "$POSTURE_FILE"
    printf 'DETAIL\t%s\n' "$POSTURE_FILE"

    local verdict spf dmarc
    verdict="$(ma_spoof_verdict "$d")"
    spf="$(ma_spf_verdict "$d")"
    dmarc="$(ma_dmarc_policy "$d")"
    case "$verdict" in
        spoofable)
            cs_findings_row "$MODULE_ID" "ATTRITION" "$d" "high-mail-spoofable" \
                "SPF is $spf and DMARC p=$dmarc, so a message claiming to be $d survives authentication" > /dev/null ;;
        weak)
            # an enforced domain (partial) is deliberately not a finding: junk
            # is where a forgery belongs, and reporting it would make every
            # properly hardened tenant a false positive
            cs_findings_row "$MODULE_ID" "ATTRITION" "$d" "medium-mail-weak-auth" \
                "spoofing $d is only partly blocked: SPF $spf, DMARC p=$dmarc at pct=$(ma_dmarc_pct "$d")" > /dev/null ;;
    esac
    # a domain with no MX cannot receive, which is worth knowing before
    # judging its DMARC
    ma_mx "$d"
    if [[ "$MA_STATE" == "ok" ]] && printf '%s' "$MA_RAW" | grep -qi '^0 \.-$\|^0$'; then
        cs_findings_row "$MODULE_ID" "ATTRITION" "$d" "low-mail-null-mx" \
            "the domain publishes a null MX, so it explicitly accepts no mail" > /dev/null
    fi
}

ma_cmd_spoof() {
    local d="${1:-}" from="${2:-}"
    if [[ -z "$d" ]]; then printf 'usage: --spoof <domain> [from-address]\n' >&2; return 2; fi
    local verdict; verdict="$(ma_spoof_verdict "$d")"
    printf 'SPOOF\t%s\tverdict=%s\tspf=%s\tdmarc=%s\tpct=%s\n' \
        "$d" "$verdict" "$(ma_spf_verdict "$d")" "$(ma_dmarc_policy "$d")" "$(ma_dmarc_pct "$d")"
    [[ -n "$from" ]] && printf 'FROM\t%s\theader-from\n' "$from"
    ma_spoof_why "$d"
    printf 'NOTE\t%s\n' "a display-name forgery needs no weakness at all and is not counted by this verdict"
}

ma_cmd_providers() {
    printf 'PROVIDER\tMX-HINT\tGATE\n'
    printf 'google-workspace\tgoogle.com\tSPF includes _spf.google.com\n'
    printf 'microsoft-365\tmail.protection.outlook.com\tSPF includes spf.protection.outlook.com\n'
    printf 'proofpoint\tpphosted.com\tnone public; MX tells you\n'
    printf 'mimecast\tmimecast.com\tnone public; MX tells you\n'
    printf 'barracuda\tbarracudanetworks.com\tnone public; MX tells you\n'
    printf 'sophos\tsophos.com\tnone public; MX tells you\n'
    printf 'trend-micro\ttrendmicro.com\tnone public; MX tells you\n'
    printf 'symantec\ta.messagelabs.com\tnone public; MX tells you\n'
    printf 'amazon-workmail-ses\tamazonses.com\tSPF includes amazonses.com\n'
    printf 'mailgun\tmailgun.org\tSPF includes mailgun.org\n'
    printf 'sendgrid\tsendgrid.net\tSPF includes sendgrid.net\n'
    printf 'zoho\tzoho.com\tnone public; MX tells you\n'
    printf 'tencent\tqq.com\tnone public; MX tells you\n'
    printf 'alibaba\tmxhichina.com\tnone public; MX tells you\n'
}

ma_cmd_selectors() {
    printf 'SELECTOR\tNAME\n'
    local s; while read -r s; do [[ -n "$s" ]] && printf '%s\t%s._domainkey.<domain>\n' "$s" "$s"; done < <(ma_selectors)
}

ma_cmd_status_tsv() {
    local d; cs_have dig && d="ok" || d="missing"
    printf '%s\t%s\tdig-%s\tp-%s\tselectors-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$d" "$(cs_have python3 && echo ok || echo missing)" \
        "$(ma_selectors | wc -l | tr -d ' ')"
}

ma_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ma_cmd_help() {
    cat <<'HELP'
cloudsting module 19 — Mail Authentication v0.1.0
  --domain <d>                full posture: SPF, DMARC, DKIM selectors, MX and
                              provider, MTA-STS, BIMI, and the spoof verdict
  --spoof  <d> [from]         the verdict alone, with the reason
  --relay  <host[:port]>      is this SMTP server an open relay
  --enum   <d> [mx]           which mailboxes exist, with a catch-all control
  --providers                 hosted-mail providers and the MX that names them
  --selectors                 the DKIM selectors probed, and why they are guesses
  --status-tsv                module status
  --menu                      menu entry
  --selftest                  run selftests
  --help                      this message

The claim this module makes is narrow on purpose: whether a message that names
this domain in the From: header would survive SPF and DMARC at the receiver. A
display-name forgery — "Microsoft Support <someone@gmail.com>" — needs no
weakness at all and is never counted here, because counting it would make every
domain on earth spoofable and the finding worthless.

The verdicts: hardened (p=reject with an SPF a forgery cannot pass — softfail
and neutral both count as failures to DMARC), partial (p=reject with an open or
permerror SPF, or p=quarantine at pct=100 — junk rather than the inbox, so the domain
is enforcing and no finding is raised), weak (quarantine below pct=100, or p=none
with a strict SPF — one signal fires and nothing follows from it), spoofable (no
enforceable DMARC and a permissive SPF, so a forgery is delivered). Two SPF
records, or more than ten DNS lookups in one, are permerrors: the domain has no
usable policy even though the record looks healthy, and both are reported as
such.

DKIM selectors are not published anywhere; they appear only in the signature of
a sent message. The list here is the set of names that are common, so a miss
means "nobody used a common name", not "no DKIM".

An open relay needs two accepted external domains, not one: plenty of servers
queue a single unfamiliar domain and still refuse to relay. A mailbox test sends
a random address first, because a catch-all makes every existence answer
worthless.

Only dig and python3 are required. No mail is ever sent: every dialogue stops
before DATA.

Environment: MA_DNS_TIMEOUT (3), MA_SMTP_TIMEOUT (10)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ma_selftest() {
    cs_selftest_reset
    local real_loot="$CS_LOOT"
    CS_LOOT="$CS_SCRATCH"
    mkdir -p "$CS_LOOT"

    # ── fixtures ──
    # The fixture database feeds ma_query, so these assertions cover the
    # resolver seam, the record parsing and the verdict logic, not a stub
    # standing in front of them.
    local fdb="$CS_SCRATCH/ma-fixture.db"
    : > "$fdb"
    export MA_FIXTURE_DB="$fdb"
    # _ma_fx TYPE NAME STATE RAW   (RAW of "-" means an empty answer)
    _ma_fx() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:--}" >> "$fdb"; }

    # the record arrives quoted, and adjacent chunks are merged by the receiver
    _ma_fx TXT fixture.test ok '"v=spf1 ip4:203.0.113.0/24 include:_spf.google.com ~all"'
    chk spf-raw   "$(ma_spf_raw fixture.test)" 'v=spf1 ip4:203.0.113.0/24 include:_spf.google.com ~all'
    chk spf-count "$(ma_spf_count fixture.test)" "1"
    chk spf-all   "$(ma_spf_all fixture.test)" "~all"
    chk spf-look  "$(ma_spf_lookups fixture.test)" "1"
    chk spf-inc   "$(ma_spf_includes fixture.test)" "_spf.google.com"
    chk spf-verdict "$(ma_spf_verdict fixture.test)" "softfail"

    # a split chunk is the same record
    _ma_fx TXT split.test ok '"v=spf1 include:_spf.goo" "gle.com -all"'
    chk spf-split "$(ma_spf_raw split.test)" "v=spf1 include:_spf.google.com -all"
    chk spf-split-inc "$(ma_spf_includes split.test)" "_spf.google.com"

    _ma_fx TXT open.test      ok '"v=spf1 +all"'
    chk spf-open    "$(ma_spf_verdict open.test)" "open"
    _ma_fx TXT neutral.test   ok '"v=spf1 ?all"'
    chk spf-neutral "$(ma_spf_verdict neutral.test)" "neutral"
    _ma_fx TXT noall.test     ok '"v=spf1 ip4:198.51.100.1"'
    chk spf-noall   "$(ma_spf_verdict noall.test)" "no-all"
    # a name that exists without an SPF record is not the same as a name that
    # does not exist, and neither is the same as a dead resolver
    _ma_fx TXT nospf.test no-record -
    chk spf-absent  "$(ma_spf_verdict nospf.test)" "no-spf"
    chk spf-nr-name "$(ma_txt nospf.test; printf '%s' "$MA_STATE")" "no-record"
    chk spf-nx-name "$(ma_txt gone.test; printf '%s' "$MA_STATE")" "nxdomain"

    # two records are a permerror; the count has to say so before the verdict
    _ma_fx TXT multi.test ok '"v=spf1 include:a.example -all"@NL@"v=spf1 include:b.example ~all"'
    chk spf-multi-count   "$(ma_spf_count multi.test)" "2"
    chk spf-multi-verdict "$(ma_spf_verdict multi.test)" "permerror-multiple"

    # eleven lookups is a permerror even with a strict all; ten is allowed
    _ma_fx TXT look11.test ok '"v=spf1 include:a1 include:a2 include:a3 include:a4 include:a5 include:a6 include:a7 include:a8 include:a9 include:a10 include:a11 -all"'
    chk spf-look11 "$(ma_spf_lookups look11.test)" "11"
    chk spf-perm   "$(ma_spf_verdict look11.test)" "permerror-lookups"
    _ma_fx TXT look10.test ok '"v=spf1 include:a1 include:a2 include:a3 include:a4 include:a5 include:a6 include:a7 include:a8 include:a9 include:a10 -all"'
    chk spf-look10 "$(ma_spf_lookups look10.test)" "10"
    chk spf-ten-ok "$(ma_spf_verdict look10.test)" "strict"

    # ── DMARC ──
    _ma_fx TXT _dmarc.reject.test ok '"v=DMARC1; p=reject; rua=mailto:dmarc@reject.test; pct=100"'
    chk dmarc-p     "$(ma_dmarc_policy reject.test)" "reject"
    chk dmarc-pct   "$(ma_dmarc_pct reject.test)" "100"
    chk dmarc-rua   "$(ma_dmarc_rua reject.test)" "mailto:dmarc@reject.test"
    _ma_fx TXT _dmarc.q.test ok '"v=DMARC1; p=quarantine; pct=25"'
    chk dmarc-q-pct "$(ma_dmarc_pct q.test)" "25"
    _ma_fx TXT _dmarc.none.test ok '"v=DMARC1; p=none"'
    chk dmarc-none  "$(ma_dmarc_policy none.test)" "none"
    # sp= without p= is not a policy for the domain itself
    _ma_fx TXT _dmarc.sp.test ok '"v=DMARC1; sp=reject"'
    chk dmarc-no-p  "$(ma_dmarc_policy sp.test)" "none"
    # a TXT record at _dmarc that is not DMARC is not a policy either
    _ma_fx TXT _dmarc.other.test ok '"google-site-verification=abc"'
    chk dmarc-other "$(ma_dmarc_policy other.test)" "none"
    chk dmarc-absent "$(ma_dmarc_policy absent.test)" "none"

    # ── the verdict, which is the whole point ──
    _ma_fx TXT v1.test ok '"v=spf1 -all"'
    _ma_fx TXT _dmarc.v1.test ok '"v=DMARC1; p=reject"'
    chk v-hardened "$(ma_spoof_verdict v1.test)" "hardened"
    # reject with no SPF at all still rejects: SPF simply fails, which is what
    # DMARC needs, so the absence of a record does not weaken p=reject
    _ma_fx TXT _dmarc.v2.test ok '"v=DMARC1; p=reject"'
    _ma_fx TXT v2.test no-record -
    chk v-hard-nospf "$(ma_spoof_verdict v2.test)" "hardened"
    _ma_fx TXT v3.test ok '"v=spf1 include:x ~all"'
    chk v-spoof    "$(ma_spoof_verdict v3.test)" "spoofable"
    # quarantine at a low pct is only a partial block
    # quarantine at a tenth of the mail is not enforcement
    _ma_fx TXT v4.test ok '"v=spf1 -all"'
    _ma_fx TXT _dmarc.v4.test ok '"v=DMARC1; p=quarantine; pct=10"'
    chk v-weak-pct "$(ma_spoof_verdict v4.test)" "weak"
    # quarantine at full coverage IS enforcement: junk, not the inbox
    _ma_fx TXT v5.test ok '"v=spf1 -all"'
    _ma_fx TXT _dmarc.v5.test ok '"v=DMARC1; p=quarantine"'
    chk v-partial-q "$(ma_spoof_verdict v5.test)" "partial"
    # p=none with a strict SPF: the signal fires and nothing follows from it
    _ma_fx TXT v6.test ok '"v=spf1 -all"'
    _ma_fx TXT _dmarc.v6.test ok '"v=DMARC1; p=none"'
    chk v-weak-none "$(ma_spoof_verdict v6.test)" "weak"
    # reject with an open SPF still enforces: a forged sender can PASS that
    # SPF but its DKIM will not align
    _ma_fx TXT v8.test ok '"v=spf1 +all"'
    _ma_fx TXT _dmarc.v8.test ok '"v=DMARC1; p=reject"'
    chk v-partial-open "$(ma_spoof_verdict v8.test)" "partial"
    # softfail under reject is full enforcement: softfail is a failure to
    # DMARC, which is the mistake that would call every hardened tenant weak
    _ma_fx TXT v9.test ok '"v=spf1 include:x ~all"'
    _ma_fx TXT _dmarc.v9.test ok '"v=DMARC1; p=reject"'
    chk v-hard-soft "$(ma_spoof_verdict v9.test)" "hardened"
    _ma_fx TXT v10.test ok '"v=spf1 ?all"'
    _ma_fx TXT _dmarc.v10.test ok '"v=DMARC1; p=reject"'
    chk v-hard-neut "$(ma_spoof_verdict v10.test)" "hardened"
    # a permerror SPF cannot stop anything, so reject is only partial
    _ma_fx TXT v11.test ok '"v=spf1 include:a1 include:a2 include:a3 include:a4 include:a5 include:a6 include:a7 include:a8 include:a9 include:a10 include:a11 -all"'
    _ma_fx TXT _dmarc.v11.test ok '"v=DMARC1; p=reject"'
    chk v-partial-perm "$(ma_spoof_verdict v11.test)" "partial"
    # the reason sentence follows the verdict
    chk why-hard "$(ma_spoof_why v1.test | grep -c 'is rejected')" "1"
    chk why-part "$(ma_spoof_why v8.test | grep -c 'can pass it')" "1"
    chk why-spoof "$(ma_spoof_why v7.test | grep -c 'it is delivered')" "1"
    chk why-weak "$(ma_spoof_why v6.test | grep -c 'nothing follows')" "1"
    _ma_fx TXT v7.test ok '"v=spf1 +all"'
    _ma_fx TXT _dmarc.v7.test ok '"v=DMARC1; p=none"'
    chk v-spoof-none "$(ma_spoof_verdict v7.test)" "spoofable"
    chk v-none     "$(ma_spoof_verdict absent.test)" "spoofable"

    # ── MX provider fingerprint from the record, not from the hostname ──
    _ma_fx MX mx1.test ok "5 gmail-smtp-in.l.google.com."
    chk mx-google "$(ma_mx_provider mx1.test)" "google-workspace"
    _ma_fx MX mx2.test ok "10 corp-com.mail.protection.outlook.com."
    chk mx-msft   "$(ma_mx_provider mx2.test)" "microsoft-365"
    _ma_fx MX mx3.test ok "10 mx1.pphosted.com."
    chk mx-pp     "$(ma_mx_provider mx3.test)" "proofpoint"
    _ma_fx MX mx4.test ok "10 mx.mimecast.com."
    chk mx-mime   "$(ma_mx_provider mx4.test)" "mimecast"
    _ma_fx MX mx5.test ok "0 ."
    chk mx-null   "$(ma_mx_provider mx5.test)" "null-mx"
    _ma_fx MX mx6.test ok "10 mail.tenant.example."
    chk mx-other  "$(ma_mx_provider mx6.test)" "self-hosted-or-other"
    chk mx-unknown "$(ma_mx_provider gone.test)" "unknown"

    # ── the posture table is what the GUI and the operator read ──
    local prow
    prow="$(ma_posture_rows v1.test)"
    chk posture-fields  "$(printf '%s\n' "$prow" | awk -F'\t' '$1=="VERDICT"{print NF}')" "3"
    chk posture-spf-n   "$(printf '%s\n' "$prow" | grep -c '^SPF' | awk '{print ($1>=5)?"many":"few"}')" "many"
    chk posture-spf-all "$(printf '%s\n' "$prow" | awk -F'\t' '$1=="SPF"&&$2=="all"{print $3}')" "-all"
    chk posture-dmarc  "$(printf '%s\n' "$prow" | awk -F'\t' '$1=="DMARC"&&$2=="p"{print $3}')" "reject"
    chk posture-verdict "$(printf '%s\n' "$prow" | awk -F'\t' '$1=="VERDICT"{print $3}')" "hardened"
    chk posture-mta    "$(printf '%s\n' "$prow" | awk -F'\t' '$1=="MTA-STS"{print $3}')" "absent"
    chk posture-dkim   "$(printf '%s\n' "$prow" | awk -F'\t' '$1=="DKIM"{print $3}')" "none-found"
    # every row is three fields, because the GUI splits on the separator
    chk posture-wid    "$(printf '%s\n' "$prow" | awk -F'\t' 'NF!=3' | wc -l | tr -d ' ')" "0"

    # ── the selector list is a guess, and it has to say so ──
    chk sel-many  "$(ma_selectors | wc -l | tr -d ' ' | awk '{print ($1>=20)?"many":"few"}')" "many"
    chk sel-uniq  "$(ma_selectors | sort -u | wc -l | tr -d ' ')" "$(ma_selectors | wc -l | tr -d ' ')"
    chk sel-has-g "$(ma_selectors | grep -cx 'google')" "1"
    chk sel-has-s "$(ma_selectors | grep -cx 'selector1')" "1"
    # a selector search finds only published ones: the fixture has DKIM at
    # google._domainkey.dk.test and nowhere else
    _ma_fx TXT google._domainkey.dk.test ok '"v=DKIM1; k=rsa; p=MIIBIjANBg"'
    chk dkim-found "$(ma_dkim_found dk.test)" "google"

    # ── SMTP dialogues against a local scripted server ──
    local portfile="$CS_SCRATCH/ma-port"
    ma_test_server "open" "$portfile" &
    local srvpid=$!
    local i=0
    while [[ ! -s "$portfile" ]] && (( i < 100 )); do sleep 0.05; i=$((i+1)); done
    local port; port="$(cat "$portfile" 2>/dev/null)"
    if [[ -n "$port" ]]; then
        # an open relay accepts two unrelated external domains
        local out; out="$(ma_smtp_dialog 127.0.0.1 "$port" \
            "EHLO cloudsting.invalid" "MAIL FROM:<a@b.invalid>" \
            "RCPT TO:<x@example.net>" "RCPT TO:<y@example.org>")"
        chk smtp-dialog-lines "$(printf '%s\n' "$out" | awk -F'\t' '$1=="RCPT"' | wc -l | tr -d ' ')" "2"
        chk relay-open "$(printf '%s\n' "$out" | awk -F'\t' '$1=="RCPT"&&!s++{print $2}')" "250"
    else
        chk smtp-port-up "no" "yes"
    fi
    kill $srvpid 2>/dev/null; wait $srvpid 2>/dev/null

    # a server that refuses relaying must not be recorded as one
    portfile="$CS_SCRATCH/ma-port2"
    ma_test_server "closed" "$portfile" &
    srvpid=$!
    i=0; while [[ ! -s "$portfile" ]] && (( i < 100 )); do sleep 0.05; i=$((i+1)); done
    port="$(cat "$portfile" 2>/dev/null)"
    if [[ -n "$port" ]]; then
        out="$(ma_smtp_dialog 127.0.0.1 "$port" \
            "EHLO cloudsting.invalid" "MAIL FROM:<a@b.invalid>" "RCPT TO:<x@example.net>")"
        chk relay-closed-code "$(printf '%s\n' "$out" | awk -F'\t' '$1=="RCPT"{print $2}')" "550"
        chk relay-error-row  "$(ma_smtp_dialog 127.0.0.1 9 "EHLO x" | head -1 | cut -f1)" "ERROR"
    else
        chk smtp-port2-up "no" "yes"
    fi
    kill $srvpid 2>/dev/null; wait $srvpid 2>/dev/null

    # ── argument handling ──
    local rc
    ma_cmd_domain 2>/dev/null; rc=$?
    chk domain-usage "$rc" "2"
    ma_cmd_relay 2>/dev/null; rc=$?
    chk relay-usage "$rc" "2"
    ma_cmd_enum 2>/dev/null; rc=$?
    chk enum-usage "$rc" "2"
    chk enum-cands "$(ma_enum_candidates | wc -l | tr -d ' ' | awk '{print ($1>=6)?"many":"few"}')" "many"
    # a second positional argument is the host, and a host:port form splits
    ma_split_hostport "127.0.0.1:2525"
    chk hp-port "$MA_HP_PORT" "2525"
    chk hp-host "$MA_HP_HOST" "127.0.0.1"
    ma_split_hostport "mail.example.test"
    chk hp-default "$MA_HP_PORT" "25"
    chk hp-no-colon "$(ma_split_hostport mail.example.test; printf '%s' "$MA_HP_HOST")" "mail.example.test"
    # postmaster and abuse are reserved, so they are not in the list: every
    # server answers them and they prove nothing
    chk enum-no-pm "$(ma_enum_candidates | grep -cx 'postmaster\|abuse')" "0"

    # ── shape contracts ──
    chk status-fields "$(ma_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(ma_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ma_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ma_cmd_help | head -1 | grep -ci 'Mail Authentication')" "1"
    chk help-selectors "$(ma_cmd_help | grep -c 'not published anywhere')" "1"
    chk providers-many "$(ma_cmd_providers | tail -n +2 | wc -l | tr -d ' ' | awk '{print ($1>=12)?"many":"few"}')" "many"
    chk selectors-hdr "$(ma_cmd_selectors | head -1 | awk -F'\t' '{print NF}')" "2"

    unset MA_FIXTURE_DB
    CS_LOOT="$real_loot"
    cs_selftest_done
}

# A scripted SMTP peer for the selftest, so the dialogue is tested without a
# network. open: accepts any recipient. closed: refuses to relay.
ma_test_server() {
    local mode="${1:?}" portfile="${2:?}"
    exec python3 - "$mode" "$portfile" <<'PY' 
import socket, sys, threading
mode, portfile = sys.argv[1], sys.argv[2]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0)); srv.listen(5)
open(portfile, "w").write(str(srv.getsockname()[1]))
to = 20
while True:
    try: c, _ = srv.accept()
    except Exception: break
    c.settimeout(to)
    f = c.makefile("rwb", buffering=0)
    def w(s): f.write((s + "\r\n").encode())
    w("220 smoke.test ESMTP")
    try:
        while True:
            line = f.readline()
            if not line: break
            cmd = line.decode("utf-8", "replace").strip()
            up = cmd.upper()
            if up.startswith("EHLO") or up.startswith("HELO"):
                w("250-smoke.test"); w("250 OK")
            elif up.startswith("MAIL FROM"):
                w("250 2.1.0 Ok")
            elif up.startswith("RCPT TO"):
                if mode == "open":
                    w("250 2.1.5 Ok")
                else:
                    w("550 5.7.1 Relaying denied")
            elif up.startswith("QUIT"):
                w("221 Bye"); break
            else:
                w("250 OK")
    except Exception:
        pass
    try: c.close()
    except Exception: pass
PY
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --domain)   shift; ma_cmd_domain "$@";;
    --spoof)    shift; ma_cmd_spoof "$@";;
    --relay)    shift; ma_cmd_relay "$@";;
    --enum)     shift; ma_cmd_enum "$@";;
    --providers) ma_cmd_providers;;
    --selectors) ma_cmd_selectors;;
    --status-tsv|--status) ma_cmd_status_tsv;;
    --menu)     ma_cmd_menu;;
    --selftest) ma_selftest;;
    *)          ma_cmd_help;;
esac
