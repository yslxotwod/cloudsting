#!/usr/bin/env bash
# 08_secrets_scan.sh — cloudsting module 08: secrets scanner (git repo / files / env dumps)
# Verbs: --scan | --detect | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="08_secrets_scan"
MOD_NAME="Secrets Scanner"
MOD_VERSION="0.3.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export SS_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/secrets_scan"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
FINDINGS_FILE="$OUT_DIR/findings-$RUN_ID.tsv"

ss_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# Secret detection fingerprint knowledge base.
# Row: provider<TAB>pattern(regex)<TAB>entropy-hint<needed(e/o/n)>\tseverity
#   e = entropy-gate, o = online-exfil risk, n = none
ss_list_signatures() {
cat <<'SIGS'
aws-access-key-id	AKIA[0-9A-Z]{16}	high
aws-secret-access-key	aws_secret_access_key[ =]+[A-Za-z0-9/+=]{40}	high
gcp-api-key	AIza[0-9A-Za-z_-]{35}	high
github-token	gh[pousr]_[-A-Za-z0-9_]{20,255}	high
gitlab-token	glpat-[-A-Za-z0-9_]{20}	high
slack-token	xox[baprs]-[-A-Za-z0-9-]{10,}	high
stripe-live-key	(sk_live_|rk_live_)[-A-Za-z0-9]{20,}	high
stripe-test-key	(sk_test_|rk_test_)[-A-Za-z0-9]{20,}	medium
anthropic-key	sk-ant-[-A-Za-z0-9-]{40,}	high
openai-key	sk-proj-[-A-Za-z0-9_]{60,}	high
heroku-api-key	HEROKU_API_KEY=[-A-Za-z0-9]{36}	high
twilio-sid	SK[0-9a-f]{32}	medium
google-refresh-token	1//[-A-Za-z0-9_]{20,}	high
jwt-token	ey[J][-A-Za-z0-9_]{10,}\.[-A-Za-z0-9_]{10,}\.[-A-Za-z0-9_]{10,}	medium
private-key-block	-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)	critical
password-in-config	PASSWORD=|SECRET=|TOKEN=	medium
SIGS
}

# ss_scan_file <file> — emit findings rows: finding<TAB>file<TAB>provider<TAB>severity<TAB>redacted-match
ss_scan_file() {
    local f="$1"
    [ -f "$f" ] || { ss_log "not a file: $f"; return 2; }
    local prov pattern sev
    while IFS=$'\t' read -r prov pattern sev; do
        [ -z "$prov" ] && continue
        grep -nE -- "$pattern" "$f" 2>/dev/null | while IFS= read -r line; do
            local lineno="${line%%:*}"
            local match="${line#*:}"   # strip lineno:
            match="$(printf '%s' "$match" | cut -c1-48)"
            printf 'finding\t%s\t%s\t%s\t%s\n' "$f" "$prov" "$sev" "$(printf '%s' "$match" | cut -c1-8)'...-redacted'"
        done
    done <<EOSIGS
$(ss_list_signatures)
EOSIGS
}

# ss_scan_dir <dir>
ss_scan_dir() {
    local dir="${1:?usage: --scan <dir>}"
    [ -d "$dir" ] || { ss_log "not a directory: $dir"; return 2; }
    local f
    find "$dir" -type f -not -path '*/.git/*' 2>/dev/null | while read -r f; do
        ss_scan_file "$f"
    done
}

# --scan <path> (file or dir), filters > severity, writes loot
ss_cmd_scan() {
    local target="${1:?usage: --scan <file-or-dir>}"
    local sev_min="${SS_MIN_SEVERITY:-medium}"
    local rank=0 medium=1 high=2 critical=3
    case "$sev_min" in low) rank=0;; medium) rank=1;; high) rank=2;; critical) rank=3;; esac
    if [ -f "$target" ]; then
        ss_scan_file "$target"
    elif [ -d "$target" ]; then
        ss_scan_dir "$target"
    else
        ss_log "no such target: $target"
        return 2
    fi | awk -F'\t' -v r="$rank" '
        ($4=="low" && 0>=r) || ($4=="medium" && 1>=r) || ($4=="high" && 2>=r) || ($4=="critical" && 3>=r)' \
        | tee -a "$FINDINGS_FILE"
    ss_log "findings -> $FINDINGS_FILE"
}

# --detect <string | ->: fingerprint a raw token (or stdin), no file I/O
ss_cmd_detect() {
    local tok="${1:-}"
    if [ -z "$tok" ] || [ "$tok" = "-" ]; then tok="$(cat)"; fi
    [ -z "$tok" ] && { ss_log 'feed a token on stdin or as arg'; return 2; }
    local prov pattern _n sev
    while IFS=$'\t' read -r prov pattern sev; do
        [ -z "$prov" ] && continue
        if printf '%s' "$tok" | grep -qE -- "$pattern"; then
            printf 'detected\t%s\t%s\n' "$prov" "$sev"
        fi
    done <<EOSIGS
$(ss_list_signatures)
EOSIGS
}

# --list
ss_cmd_list() { ss_list_signatures; }

# --status-tsv: 3 fields
ss_cmd_status_tsv() { printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "offline-ok"; }

# --menu
ss_cmd_menu() { printf 'menu\t%s\t[%s]\n' "$MODULE_ID" "$MOD_NAME"; }

# --help
ss_cmd_help() {
cat <<HELP
$MODULE_ID v$MOD_VERSION — $MOD_NAME
VERBS
  --scan <file-or-dir>   fingerprint secrets on the fs, severity-filter SS_MIN_SEVERITY
  --detect <tok | ->     classify one raw token (or stdin)
  --list                 show all signatures (provider, regex, severity)
  --status-tsv           three-field status
  --menu | --selftest | --help
ENV
  SS_MIN_SEVERITY (default medium) — minimum severity to keep: low|medium|high|critical
LOOT
  loot/secrets_scan/findings-$SS_RUN_ID.tsv rows: finding<TAB>file<TAB>provider<TAB>severity<TAB>redacted
HELP
}

# selftest
ss_selftest() {
    local pass=0 fail=0
    chk() { local n="$1" got="$2" want="$3"
            if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$n"
            else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$n" "$want" "$got"; fi; }
chk sig-count "$(ss_list_signatures | grep -c .)" 16
chk sig-fields "$(ss_list_signatures | awk -F'\t' 'NF!=3' | wc -l)" 0
chk has-aws "$(ss_list_signatures | awk -F'\t' '$1=="aws-access-key-id"' | wc -l)" 1 has-aws-sig
chk has-private-key "$(ss_list_signatures | awk -F'\t' '$1=="private-key-block"' | wc -l)" 1 has-private-key-sig

    local tmpf="$TMP_DIR/ss_test_$$".txt
    cat > "$tmpf" <<'EOF'
aws_key = AKIAIOSFODNN7EXAMPLE
sk_live_abc123def456ghi789jkl0
-----BEGIN RSA PRIVATE KEY-----
EOF
chk aws-key-detected "$(ss_scan_file "$tmpf" 2>/dev/null | awk -F'\t' '$3=="aws-access-key-id"' | wc -l)" 1
    chk stripe-detected "$(ss_scan_file "$tmpf" 2>/dev/null | awk -F'\t' '$3=="stripe-live-key"' | wc -l)" 1
    chk privkey-detected "$(ss_scan_file "$tmpf" 2>/dev/null | awk -F'\t' '$3=="private-key-block"' | wc -l)" 1
    rm -f "$tmpf"
chk detect-github "$(ss_cmd_detect ghp_EXAMPLETOKENAAAAAAAAAAAAAAAAAAAAAA 2>/dev/null | awk -F'\t' '$2=="github-token"' | wc -l)" 1 detect-github
chk detect-unknown "$(ss_cmd_detect totally-innocuous | wc -l)" 0 detect-unknown
chk detect-jwt "$(ss_cmd_detect eyJhbGciOiJIUzI1NiJ9.payloadsignaturepiecemore.signatureXX 2>/dev/null | awk -F'\t' '{print $2}')" jwt-token detect-jwt
chk status-shape "$(ss_cmd_status_tsv | awk -F'\t' '{print NF}')" 3 status-fields
chk status-module "$(ss_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID" status-module

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# dispatcher
ss_dispatch() {
    local verb="${1:---help}"
    shift || true
    case "$verb" in
        --scan)       ss_cmd_scan "$@" ;;
        --detect)     ss_cmd_detect "$@" ;;
        --list)       ss_cmd_list ;;
        --status-tsv) ss_cmd_status_tsv ;;
        --menu)       ss_cmd_menu ;;
        --selftest)   ss_selftest ;;
        --help|-h)    ss_cmd_help ;;
        *)            ss_log "unknown verb: $verb"; ss_cmd_help; return 2 ;;
    esac
}

if [ "${CLOUDSTING_SOURCE_ONLY:-0}" != "0" ]; then
    return 0 2>/dev/null || true
fi
[ "${BASH_SOURCE[0]}" = "$0" ] && ss_dispatch "$@"
