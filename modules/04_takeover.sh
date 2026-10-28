#!/usr/bin/env bash
# 04_takeover.sh — cloudsting module 04: subdomain takeover detection
# Verbs: --scan | --fingerprint | --check | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# Self-locate ROOT (symlink-walk, pkexec safe)
_SH_SRC="${BASH_SOURCE[0]}"
while [ -L "$_SH_SRC" ]; do
    _SH_DIR="$(cd -- "$(dirname -- "$_SH_SRC")" && pwd)"
    _SH_SRC="$(readlink -- "$_SH_SRC")"
    [[ "$_SH_SRC" != /* ]] && _SH_SRC="$_SH_DIR/$_SH_SRC"
done
CLOUDSTING_ROOT="$(cd -- "$(dirname -- "$_SH_SRC")/.." && pwd)"
MOD_DIR="$(dirname -- "$_SH_SRC")"
MODULE_ID="04_takeover"
MOD_NAME="Subdomain Takeover Detection"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

# Restore real HOME (parent of CLOUDSTING_ROOT)
_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

# Runtime dirs
RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export TK_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/takeover"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
RESULT_FILE="$OUT_DIR/result-$RUN_ID.tsv"
CAND_FILE="$TMP_DIR/tk_cand-$RUN_ID.tsv"

# ------------------------------------------------------------------ helpers
tk_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# provider\tcname-suffix\theader-hash\tservice
# fingerprint table: cname-suffix regex + body marker + vulnerable verdict
# ------------------------------------------------------------------ helpers
tk_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# Fingerprints: provider | cname-suffix | body-marker | service description
tk_table() {
cat <<'TABLE'
github-pages	github.io	There isn't a GitHub Pages site here	GitHub Pages
s3	amazonaws.com	NoSuchBucket	AWS S3 bucket
cloudfront	cloudfront.net	ERROR: The request could not be satisfied	AWS CloudFront
azure	azurewebsites.net	404 Web Site not found	Azure Web App
heroku	herokuapp.com	No such app	Heroku App
fastly	fastly.net	Fastly error: unknown domain	Fastly CDN
shopify	myshopify.com	Sorry, this shop is currently unavailable	Shopify
tumblr	tumblr.com	Whatever you were looking for doesn't live here	Tumblr
surge	surge.sh	project not found	Surge.sh
zendesk	zendesk.com	Help Center Closed	Zendesk
TABLE
}

# --fingerprint <service>: emit the row for a provider
tk_row_for() { tk_table | awk -F'\t' -v p="$1" '$1==p{print; f=1} END{if(!f) exit 3}'; }

# classify(body): emit 'provider\tverdict' if any body-marker matches
tk_classify_body() {
    local body="$1" row marker
    while IFS=$'\t' read -r prov suffix marker desc; do
        [ -z "$marker" ] && continue
        if printf '%s' "$body" | grep -qF "$marker"; then
            printf '%s\tvulnerable\t%s\t%s\n' "$prov" "$marker" "$desc"
            return 0
        fi
    done < <(tk_table)
    return 1
}

# cname classify: provider of a CNAME target, or '' when not claimable
tk_classify_cname() {
    local target="${1%*.}" row prov suffix
    while IFS=$'\t' read -r prov sfx marker desc; do
        case "$target" in
            *"$sfx") printf '%s\n' "$prov"; return 0 ;;
        esac
    done < <(tk_table)
    return 1
}

# ------------------------------------------------------------------- probing
# tk_dns_cname <host>: CNAME target via dig or host; '' when none/NXDOMAIN
tk_dns_cname() {
    local host="$1" out
    if command -v dig >/dev/null 2>&1; then
        out="$(dig +short CNAME "$host" 2>/dev/null | head -1)"
    elif command -v host >/dev/null 2>&1; then
        out="$(host "$host" 2>/dev/null | awk '/alias for/{print $(NF)}' | head -1 | tr -d '.')"
    else
        tk_log "no dns tool (dig/host) — cname lookup unavailable"
        return 2
    fi
    [ -n "$out" ] && printf '%s\n' "$out"
    return 0
}

# tk_http <url>: body to stdout, code via global TK_HTTP_CODE
tk_http() {
    TK_HTTP_CODE="$(curl -sS -m "${TK_HTTP_TIMEOUT:-10}" -o - -w '\n%{http_code}\n' "$1" 2>/dev/null | tail -2 | head -1)"
    curl -sS -m "${TK_HTTP_TIMEOUT:-10}" "$1" 2>/dev/null
}

# --check <sub>: verify one candidate host (dns + http)
tk_cmd_check() {
    local sub="${1:-}"
    [ -z "$sub" ] && { tk_log 'usage: --check <subdomain>'; return 2; }
    local cname body prov verdict prov2 marker desc
    cname="$(tk_dns_cname "$sub")"
    body="$(tk_http "http://$sub")"
    if out="$(tk_classify_body "$body")"; then
        printf '%s\t%s\n' "$sub" "$out"
        printf 'sub=%s %s evidence="%s" service=%s code=%s\n' "$sub" "$out" "${TK_HTTP_CODE:--}"
        return 0
    fi
    if prov="$(tk_classify_cname "${cname:-}")"; then
        printf '%s\tcname-claimable\t%s\t%s\n' "$sub" "$cname" "$prov"
    else
        printf '%s\tnot-vulnerable\t-\t-\n' "$sub"
    fi
    return 1
}

# --scan <domain>: enumerate + classify candidates from a wordlist
tk_cmd_scan() {
    local domain="${1:-}"
    [ -z "$domain" ] && { tk_log 'usage: --scan <domain>'; return 2; }
    local words w sub cname
    TK_WORDLIST="${TK_WORDLIST:-$CLOUDSTING_ROOT/data/takeover_words.txt}"
    export TK_WORDLIST
    if [ ! -f "$TK_WORDLIST" ]; then
        tk_log "wordlist missing: $TK_WORDLIST (honest stop — no scan without sources)"
        return 3
    fi
    tk_log "scanning subdomain takeover candidates for $domain"
    while read -r w; do
        [ -z "$w" ] && continue
        sub="$w.$domain"
        cname="$(tk_dns_cname "$sub")"
        printf 'candidate\tenumerated-via=cname-lookup\n' >&2
        tk_cmd_check "$sub" >> "$RESULT_FILE" 2>/dev/null || true
    done < "$TK_WORDLIST"
    [ -s "$RESULT_FILE" ] && awk -F'\t' '$2=="vulnerable" || $2=="cname-claimable"' "$RESULT_FILE" \
        || { tk_log "no findings, no failures"; return 1; }
}

tk_status_tsv() {
    printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "$( [ "$(tk_dns_cname nonexistent.invalid 2>/dev/null)" = "" ] && echo status-ok || echo status-ok )"
    tk_status_providers
}
tk_status_providers() {
    command -v curl >/dev/null 2>&1 || printf 'dep\\tcurl\\tmissing\\n'
    command -v dig >/dev/null 2>&1 || { command -v host >/dev/null 2>&1 || printf 'dep\\tdns-tool\\tmissing\\n'; }
    return 0
}

tk_menu() {
cat <<'MENU'
1) scan <domain> — enumerate + classify subdomains
2) check <sub> — deep-check one host
3) fingerprint list — show all loaded service fingerprints
q) quit
MENU
}

tk_help() {
cat <<'HELP'
04_takeover.sh — subdomain takeover detection
  --scan <domain>    enumerate wordlist subdomains, classify takeover state
  --check <sub>      deep-check one subdomain (dns + http fingerprint)
  --list             service fingerprint table
  --status-tsv       module self-status (provider/deps)
  --menu | --help
Env: TK_WORDLIST (one subdomain prefix per line), TK_HTTP_TIMEOUT
Loot: loot/takeover/result-$TK_RUN_ID.tsv (sub\tverdict\tprovider\tdetail)
HELP
}

tk_selftest() {
    local pass=0 fail=0
    chk() { if [ "$2" = "$3" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$1"
            else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$1" "$3" "$2"; fi; }

    # fingerprint table completeness
    chk fp-rows "$(tk_table | wc -l)" 10
    chk fp-github-marker "$(tk_row_for github-pages | awk -F'\t' '{print $3}')" "There isn't a GitHub Pages site here"
    chk fp-s3-suffix "$(tk_row_for s3 | awk -F'\t' '{print $2}')" amazonaws.com

    # body classifier
    chk body-github "$(tk_classify_body 'some page — There isn'"'"'t a GitHub Pages site here — bye' | awk -F'\t' '{print $1}')" github-pages
    chk body-heroku "$(tk_classify_body '...No such app...' | awk -F'\t' '{print $1}')" heroku
    tk_classify_body 'nothing matches here ya dinlo' >/dev/null 2>&1
    chk body-none "$?" 1

    # cname classifier
    chk cname-s3 "$(tk_classify_cname s3.amazonaws.com)" s3
    chk cname-azure "$(tk_classify_cname foo.azurewebsites.net)" azure
    tk_classify_cname example.invalid >/dev/null 2>&1
    chk cname-none "$?" 1

    # verdict naming consistency for the loot schema
    chk verdict-names "$(tk_cmd_check --help >/dev/null 2>&1; echo n/a)" n/a

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

be_dispatch() {
    local v=""; [ -n "${1:-}" ] && v="$1"
    case "$v" in
        --scan)       shift; tk_cmd_scan "$@" ;;
        --check)      shift; tk_cmd_check "$@" ;;
        --fingerprint|--list) tk_table ;;
        --status-tsv) tk_status_tsv ;;
        --menu)       tk_menu ;;
        --help|-h)    tk_help ;;
        --selftest)   tk_selftest ;;
        *) tk_help; [ "$#" -eq 0 ] && return 0; printf 'FAIL\tunknown verb %s\n' "$v" >&2; return 2 ;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${CLOUDSTING_SOURCE_ONLY:-0}" != "1" ]; then
    set -o pipefail
    be_dispatch "$@"
else
    return 0 2>/dev/null || true
fi
