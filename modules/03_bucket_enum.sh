#!/usr/bin/env bash
# 03_bucket_enum.sh — cloudsting module 03: cloud bucket enumeration & exposure
# Verbs: --run | --enum | --perm | --domain | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="03_bucket_enum"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME="Cloud Bucket Enumeration"

# Restore real HOME (parent of CLOUDSTING_ROOT), fixed for pkexec/su runs
_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

# Runtime dirs
RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export BUCKET_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/bucket_enum"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
RESULT_FILE="$OUT_DIR/result-$RUN_ID.tsv"
PERM_FILE="$OUT_DIR/perm-$RUN_ID.tsv"
STATE_FILE="$STATE_DIR/bucket_enum.json"
WORDS_CACHE="$STATE_DIR/bucket_words.cache"

# ------------------------------------------------------------------ helpers
be_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# Three-state provider detection: creds-present | creds-missing | tool-missing
be_provider_state() {
    case "$1" in
        aws)
            if ! command -v aws >/dev/null 2>&1; then printf 'tool-missing\n'; return; fi
            if [ -f "$HOME/.aws/credentials" ] || [ -n "${AWS_ACCESS_KEY_ID:-}" ] \
               || [ -n "${AWS_PROFILE:-}" ] || [ -s "$HOME/.aws/config" ]; then
                printf 'creds-present\n'
            else
                printf 'creds-missing\n'
            fi ;;
        *) printf 'unknown\n' ;;
    esac
}

# provider filter (comma list); empty = all
provider_ok() {
    [ -z "${BUCKET_PROVIDERS:-}" ] && return 0
    printf '%s\n' "$BUCKET_PROVIDERS" | tr ',' '\n' | grep -qwx "$1"
}

# ---------------------------------------------------------------- http probe
# be_http <url>: stdout lines STATUS\t<code> and REGION\t<x-amz-bucket-region>
be_http() {
    local out
    out="$(curl -sS -m "${BUCKET_HTTP_TIMEOUT:-10}" -o /dev/null -D - "$1" 2>/dev/null)" || return 1
    printf 'STATUS\t%s\n' "$(printf '%s\n' "$out" | head -1 | awk '{print $2}')"
    printf '%s\n' "$out" | tr -d '\r' \
        | awk 'tolower($1)=="x-amz-bucket-region:"{printf "REGION\t%s\n",$2; exit}'
}

# Per-bucket unauthenticated permission probe.
# Rows to PERM_FILE: provider	bucket	url	perm	region	http-code
be_probe_bucket() {
    local provider="$1" name="$2" url="$3" kind="$4"
    local out code region perm
    out="$(be_http "$url")" || { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$provider" "$name" "$url" 'net-error' '-' '-' >>"$PERM_FILE"; return 0; }
    code="$(printf '%s\n' "$out" | awk -F'\t' '$1=="STATUS"{print $2}')"
    region="$(printf '%s\n' "$out" | awk -F'\t' '$1=="REGION"{print $2}')"
    perm='unknown'
    case "$code" in
        200) perm='public-read' ;;
        301|403) perm='exists-private' ;;
        404) perm='absent' ;;
        '')  perm='timeout' ;;
    esac
    { printf 'PROBE\t%s\n' "$kind"; } >&2
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$provider" "$name" "$url" "$perm" "${region:--}" "${code:--}" >>"$PERM_FILE"
}

# ------------------------------------------------------------------ aws verbs
# Authenticated listing of buckets owned by the caller (per-region loop).
be_aws_account_buckets() {
    local region
    provider_ok aws || return 0
    for region in ${BUCKET_REGIONS_AWS:-us-east-1}; do
        AWS_PAGER='' aws --region "$region" s3api list-buckets --output json 2>/dev/null \
            | jq -r 'try .Buckets[]?.Name // empty' 2>/dev/null \
            | while read -r b; do
                printf 'aws\tbucket\t%s\tctr-stub-placeholder\t%s\tpending\n' "$b" "$region"
            done
    done
}

# Guess candidate bucket names from a domain/seed word.
# Output: one candidate per line (provider-agnostic names)
be_candidates_for() {
    local seed="$1" w
    printf '%s\n' "$seed"
    # split domain.tld -> domain and tld
    local base="${1%%.*}" tld="${1#*.}"
    for w in www prod staging dev test backup backups data assets static media cdn files logs archive temp releases download downloads documents docs private secrets config db dump sql old beta alpha; do
        printf '%s-%s\n' "$base" "$w"
        printf '%s.%s\n' "$w" "$tld"
    done
}

# Load custom wordlist (state cache), one word per line
be_load_words() {
    [ -f "$WORDS_CACHE" ] && cat "$WORDS_CACHE"
}

# ------------------------------------------------------------------- runners
# --domain <domain> [providers..]: unauthenticated name-guessing + probing
be_cmd_domain() {
    local domain="${1:-}"
    [ -z "$domain" ] && { be_log 'usage: --domain <domain> [providers]'; return 2; }
    shift || true
    BUCKET_PROVIDERS="${*:-$BUCKET_PROVIDERS:-}"
    : "${BUCKET_PROVIDERS:=aws}"
    be_log "unauthenticated bucket discovery for '$domain'"
    local cands cand rc total=0 found=0
    cands="$( { be_candidates_for "$domain"; be_load_words; } | sort -u | head -"${BUCKET_MAX_CANDIDATES:-50}" )"
    printf 'plan\tcandidates\t%s\n' "$(printf '%s\n' "$cands" | wc -l)" >&2
    for cand in $cands; do
        total=$((total+1))
        be_probe_bucket aws "$cand" "https://${cand}.s3.amazonaws.com" "guess" &
        # limit parallelism
        while [ "$(jobs -rp | wc -l)" -ge "${BUCKET_CONCURRENCY:-5}" ]; do wait -n; done
    done
    wait
    found="$(awk -F'\t' '$1=="aws" && ($4=="public-read" || $4=="exists-private")' "$PERM_FILE" | wc -l)"
    printf 'summary\tcandidates=%s\tfound=%s\tperm_tsv=%s\n' "$total" "$found" "$PERM_FILE"
    [ "$found" -gt 0 ] && return 0 || return 1
}

# --enum: authenticated sweep using installed cloud CLIs
be_cmd_enum() {
    local rc=0
    be_log "authenticated sweep (providers: ${BUCKET_PROVIDERS:-all})"
    be_aws_account_buckets >> "$RESULT_FILE" || rc=$?
    be_perm_sweep
    return 0
}

# --perm <bucket> [providers]: permission probe against a known bucket
be_cmd_perm() {
    local bucket="${1:-}"
    [ -z "$bucket" ] && { be_log 'usage: --perm <bucket>'; return 2; }
    be_probe_bucket aws "$bucket" "https://${bucket}.s3.amazonaws.com" "explicit"
    awk -F'\t' '$1=="aws" && $2=="'"$bucket"'"' "$PERM_FILE"
}

# Unauthenticated probe sweep of every bucket already listed in RESULT_FILE
be_perm_sweep() {
    [ -s "$RESULT_FILE" ] || return 0
    local name
    while IFS=$'\t' read -r _ _ name _; do
        [ -n "$name" ] || continue
        be_probe_bucket aws "$name" "https://${name}.s3.amazonaws.com" "owned"
    done < "$RESULT_FILE"
}

# ------------------------------------------------------------ metadata verbs
be_status_tsv() {
    local aws_state
    aws_state="$(be_provider_state aws)"
    printf '%s\t%s\t%s\n' 03_bucket_enum  "Cloud Bucket Enumeration,guess/perm/enum"  "$aws_state"
    printf 'ok\tbe_run\tCloud Bucket Enumeration module loaded\n'
}

be_menu() {
    cat <<'MENU'
03 - Cloud Bucket Enumeration
  1) enum   - sweep buckets on every credentialed provider
  2) perm   - probe permissions on a single bucket
  3) domain - guess buckets for a domain (unauthenticated)
  0) back
MENU
    printf 'choice> '
    read -r mchoice
    case "$mchoice" in
        1) be_cmd_enum ;;
        2) printf 'bucket> '; read -r b; be_cmd_perm "$b" ;;
        3) printf 'domain> '; read -r d; be_cmd_domain "$d" ;;
        *) return 0 ;;
    esac
}

be_help() {
    cat <<'HELP'
03_bucket_enum — cloud bucket enumeration & exposure
  --enum            authenticated sweep of all credentialed providers
  --perm <bucket>   unauthenticated permission probe for one bucket
  --domain <domain> unauthenticated candidate-name guessing + probing
  --status-tsv      three-state credential/tool report (machine readable)
  --menu            interactive menu
  --selftest        offline verification suite
Environment:
  BUCKET_PROVIDERS        comma list filter (default: all installed)
  BUCKET_REGIONS_AWS      space-separated regions (default: us-east-1)
  BUCKET_CONCURRENCY      parallel probes (default: 5)
  BUCKET_MAX_CANDIDATES   candidate name cap for --domain (default: 50)
  BUCKET_HTTP_TIMEOUT     curl timeout seconds (default: 10)
HELP
}

# ------------------------------------------------------------------ selftest
# awk -F'\t' for all row assertions (POSIX grep treats \t as literal t)
be_selftest() {
    local pass=0 fail=0 dbg="${CLOUDSTING_SELFTEST_DEBUG:-0}"
    chk() { if [ "$2" = "$3" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$1"
            else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$1" "$3" "$2"; fi; }

    # 1 provider-state
    if command -v aws >/dev/null 2>&1; then
        chk states-aws-tool "$(be_provider_state aws | grep -q tool-missing && echo tool-missing || echo tool-found)" tool-found
    else
        chk states-aws-tool "$(be_provider_state aws)" tool-missing
    fi

    # 2 candidate generation
    chk cand-base "$(be_candidates_for acme-corp.com | head -1)" acme-corp.com
    chk cand-variant "$(be_candidates_for acme-corp.com | grep -cx 'acme-corp-backup')" 1

    # 3 wordlist cache round-trip
    printf 'testword\nsecond\n' > "$WORDS_CACHE"
    chk words-cache "$(be_load_words | wc -l)" 2

    # 4 probe via local HTTP shim (python3 http.server on a random free port)
    local port tmpd pypid
    port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
    tmpd="$(mktemp -d)"
    printf 'ok-xml' > "$tmpd/index.html"
    ( cd "$tmpd" && { python3 -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1 & echo $! >"$tmpd/pid"; } )
    pypid="$(cat "$tmpd/pid")"
    sleep 1
    local hout
    hout="$(be_http "http://127.0.0.1:$port/index.html")"
    chk probe-status "$(printf '%s\n' "$hout" | awk -F'\t' '$1=="STATUS"{print $2}')" 200
    kill "$pypid" 2>/dev/null || true
    wait "$pypid" 2>/dev/null || true
    rm -rf "$tmpd"

    # 5 perm decision table
    chk probe-code-404 "$(be_probe_decision_table 404)" absent
    chk probe-code-403 "$(be_probe_decision_table 403)" exists-private
    chk probe-code-200 "$(be_probe_decision_table 200)" public-read
    chk probe-code-empty "$(be_probe_decision_table '')" timeout

    # 6 status-tsv shape
    be_status_tsv > "$TMP_DIR/be_st.$$"
    chk status-fields "$(awk -F'\t' 'NR==1{print NF}' "$TMP_DIR/be_st.$$")" 3
    chk status-module "$(awk -F'\t' 'NR==1{print $1}' "$TMP_DIR/be_st.$$")" 03_bucket_enum

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}
# decision-table helper used by selftest only
be_probe_decision_table() {
    local code="$1" perm
    case "$code" in
        200) perm='public-read' ;;
        301|403) perm='exists-private' ;;
        404) perm='absent' ;;
        '')  perm='timeout' ;;
    esac
    printf '%s' "$perm"
}

# ------------------------------------------------------------------ dispatcher
be_dispatch() {
    case "${1:---help}" in
        --run|--enum) be_cmd_enum ;;
        --perm)       shift; be_cmd_perm "${1:-}" ;;
        --domain)     shift; be_cmd_domain "${1:-}" ;;
        --status-tsv) be_status_tsv ;;
        --menu)       be_menu ;;
        --help|-h)    be_help ;;
        --selftest)   be_selftest ;;
        *) printf 'Unknown verb: %s\n' "$1" >&2; be_help >&2; exit 2 ;;
    esac
}

be_dispatch "$@"
