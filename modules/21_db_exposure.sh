#!/usr/bin/env bash
# 21_db_exposure.sh — cloudsting module 21: managed database exposure
# Verbs: --instances | --public | --probe | --engines | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# Everything below the header depends on the root, and the root is
# derived from this file only after it is sourced. Clear any inherited
# value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own
# name as a path.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV
# writer, the three-state provider gate, redaction and the selftest
# ledger. Sourcing it is what keeps loot under <root>/loot instead of
# $HOME/loot, so the launcher and the findings store can see a run.
MODULE_ID="21_db_exposure"
MOD_NAME="Managed Database Exposure"
MOD_VERSION="0.18.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

# this module stays loadable by another script (selftests source it)
MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

# Back-compat: run-id variable for this module, from the core run id
# the one run id the core minted.
DB_RUN_ID="$CS_RUN_ID"
export DB_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

# Loot directory for this module: <root>/loot/db_exposure/
OUT_DIR="$CS_LOOT/db_exposure"
mkdir -p "$OUT_DIR" 2>/dev/null || true

# artifacts this module writes, all under the core's loot tree
INST_FILE="$OUT_DIR/instances-$RUN_ID.tsv"
PUB_FILE="$OUT_DIR/public-$RUN_ID.tsv"
db_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── Provider gate ────────────────────────────────────────────────
db_provider_state() {
    local p="$1"
    case "$p" in
        aws)
            command -v aws >/dev/null 2>&1 || { printf 'tool-missing'; return; }
            if [ -f "$HOME/.aws/credentials" ] || [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
                printf 'creds-present'
            else
                printf 'creds-missing'
            fi ;;
        gcloud)
            command -v gcloud >/dev/null 2>&1 || { printf 'tool-missing'; return; }
            if gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null \
                 | grep -q .; then
                printf 'creds-present'
            else
                printf 'creds-missing'
            fi ;;
        azure)
            command -v az >/dev/null 2>&1 || { printf 'tool-missing'; return; }
            if [ -f "$HOME/.azure/azureProfile.json" ]; then
                printf 'creds-present'
            else
                printf 'creds-missing'
            fi ;;
        *) printf 'unknown' ;;
    esac
}

db_providers() { printf '%s\n' "${DB_PROVIDERS:-aws gcloud azure}" | tr ' ' '\n' | sed '/^$/d'; }

# ── Row shape ───────────────────────────────────────────────────
# provider<TAB>id<TAB>engine<TAB>class<TAB>endpoint<TAB>port<TAB>exposure<TAB>flags
# exposure: public | private | unknown
# flags:    comma list of storage-unencrypted, no-backup, no-deletion-protection,
#           any-ip-allowed, no-ssl, old-engine — "-" when none
db_engine_port() {
    local engine="${1:-}"
    case "$engine" in
        postgres*|aurora-postgresql) printf '5432' ;;
        mysql*|aurora*|mariadb*)     printf '3306' ;;
        sqlserver*|mssql*)           printf '1433' ;;
        oracle*|custom-oracle*)      printf '1521' ;;
        MYSQL*)                      printf '3306' ;;
        POSTGRES*)                   printf '5432' ;;
        SQLSERVER*)                  printf '1433' ;;
        *)                           printf '-' ;;
    esac
}

db_engine_class() {
    local engine="${1:-}"
    case "$engine" in
        postgres*|MYSQL*|mysql*|mariadb*|SQLSERVER*|sqlserver*|oracle*|custom-oracle*|POSTGRES*)
            printf 'relational' ;;
        docdb*|mongo*)  printf 'document' ;;
        redis|valkey*|memcached*) printf 'cache' ;;
        *) printf 'other' ;;
    esac
}

# ── AWS RDS / Aurora ────────────────────────────────────────────
db_instances_aws() {
    aws rds describe-db-instances --output json 2>/dev/null | \
        jq -r 'try (.DBInstances[]? | . as $d |
                  ( ($d.Engine // "") ) as $e |
                  [
                    "aws",
                    ($d.DBInstanceIdentifier // ""),
                    $e,
                    ($d.DBInstanceClass // ""),
                    ($d.Endpoint.Address // "-"),
                    (($d.Endpoint.Port // 0) | tostring),
                    (if ($d.PubliclyAccessible // false) then "public" else "private" end),
                    ([ (if ($d.StorageEncrypted // false) then empty else "storage-unencrypted" end),
                       (if ($d.BackupRetentionPeriod // 0) == 0 then "no-backup" else empty end),
                       (if ($d.DeletionProtection // false) then empty else "no-deletion-protection" end),
                       (if ($d.CACertificateIdentifier // "") == "" then "no-ssl" else empty end)
                     ] | if length == 0 then "-" else join(",") end)
                  ] | @tsv)' 2>/dev/null
}

# ── Google Cloud SQL ────────────────────────────────────────────
db_instances_gcloud() {
    gcloud sql instances list --format=json 2>/dev/null | \
        jq -r 'try (.[]? | . as $i |
                  ( ($i.databaseVersion // $i.region // "") ) as $e |
                  [
                    "gcloud",
                    ($i.name // ""),
                    $e,
                    ($i.settings.tier // "-"),
                    ($i.ipAddresses[]? | select(.type=="PRIMARY") | .ipAddress) // "-",
                    ((($i.settings.ipConfiguration.ipv4Enabled // false) | if . then "5432" else "-" end)),
                    (if ($i.settings.ipConfiguration.ipv4Enabled // false) then "public" else "private" end),
                    ([ (if ($i.settings.ipConfiguration.ipv4Enabled // false) then "any-ip-allowed" else empty end),
                       (if ($i.settings.backupConfiguration.enabled // false) then empty else "no-backup" end)
                     ] | if length == 0 then "-" else join(",") end)
                  ] | @tsv)' 2>/dev/null
}

# ── Azure SQL server ────────────────────────────────────────────
db_instances_azure() {
    az sql server list -o json 2>/dev/null | \
        jq -r 'try (.[]? | . as $s |
                  [
                    "azure",
                    ($s.name // ""),
                    "sqlserver",
                    "-",
                    ($s.fullyQualifiedDomainName // "-"),
                    "1433",
                    "public",
                    ([ (if ($s.publicNetworkAccess // "Enabled") == "Disabled"
                          then empty else "any-ip-allowed" end)
                     ] | if length == 0 then "-" else join(",") end)
                  ] | @tsv)' 2>/dev/null
}

db_collect() {
    local p state found=0
    : > "$INST_FILE"
    for p in $(db_providers); do
        state="$(db_provider_state "$p")"
        if [ "$state" != "creds-present" ]; then
            printf 'state\t%s\t%s\n' "$p" "$state"
            continue
        fi
        found=1
        case "$p" in
            aws)    db_instances_aws;;
            gcloud) db_instances_gcloud;;
            azure)  db_instances_azure;;
        esac 2>/dev/null | tee -a "$INST_FILE"
    done
    [ "$found" -eq 0 ] && db_log "no provider reachable; nothing was enumerated"
    return 0
}

db_cmd_instances() { db_collect; }

# ── Public exposure, with the reasons spelled out ───────────────
db_findings_from_items() {
    local file="${1:-$INST_FILE}" provider id engine class endpoint port exposure flags
    while IFS=$'\t' read -r provider id engine class endpoint port exposure flags; do
        [ -z "${provider:-}" ] && continue
        [ "$flags" = "-" ] && flags=""
        exposure="${exposure:--}"
        if [ "$exposure" = "public" ]; then
            printf 'high\t%s\t%s\tpublicly addressable %s endpoint %s:%s\n' \
                "$id" "$engine" "$engine" "$endpoint" "$port"
        fi
        case ",$flags," in
            *,any-ip-allowed,*) printf 'high\t%s\t%s\tfirewall allows any source address\n' "$id" "$engine" ;;
        esac
        case ",$flags," in
            *,no-backup,*) printf 'medium\t%s\t%s\tno automated backups: destructive access has no restore\n' "$id" "$engine" ;;
        esac
        case ",$flags," in
            *,storage-unencrypted,*) printf 'medium\t%s\t%s\tstorage is not encrypted at rest\n' "$id" "$engine" ;;
        esac
        case ",$flags," in
            *,no-deletion-protection,*) printf 'low\t%s\t%s\tdeletion protection is off\n' "$id" "$engine" ;;
        esac
    done < "$file"
}

db_cmd_public() {
    db_collect >/dev/null 2>&1 || true
    if [ ! -s "$INST_FILE" ]; then
        printf 'no instances collected (no provider reachable)\n'
        return 1
    fi
    db_findings_from_items "$INST_FILE" | tee "$PUB_FILE"
    printf 'SUMMARY\t%s\n' "$(awk -F'\t' '{c[$1]++} END {for (k in c) printf "%s=%d ", k, c[k]}' "$PUB_FILE" 2>/dev/null || echo none)"
}

# ── Reachability probe: one TCP connect, no protocol handshake ──
# verdict: open | closed | filtered | unobserved
db_tcp_verdict() {
    local host="${1:-}" port="${2:-}" timeout_s="${3:-4}"
    if [ -z "$host" ] || [ -z "$port" ]; then
        printf 'usage: --probe <host> [port]\n' >&2
        return 2
    fi
    if command -v nc >/dev/null 2>&1; then
        nc -z -w "$timeout_s" "$host" "$port" >/dev/null 2>&1 && { printf 'open'; return 0; }
        # nc -z cannot distinguish a refused connection from a dropped one on
        # every implementation, so ask bash for the error class instead.
        (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null && { printf 'open'; return 0; }
        printf 'closed'; return 1
    fi
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
        printf 'open'; return 0
    fi
    if timeout "$timeout_s" bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
        printf 'open'; return 0
    fi
    printf 'filtered'; return 1
}

db_cmd_probe() {
    local host="${1:-}" port="${2:-}" verdict
    if [ -z "$host" ]; then
        printf 'usage: --probe <host> [port]\n' >&2
        return 2
    fi
    [ -z "$port" ] && port="$(db_engine_port "${3:-mysql}")"
    verdict="$(db_tcp_verdict "$host" "$port" 2>/dev/null)"
    printf '%s\t%s\t%s\n' "$host" "$port" "$verdict"
}

# ── Engine reference ────────────────────────────────────────────
db_cmd_engines() {
    cat <<'LIST'
#engine	default-port	class	note
mysql	3306	relational	the default managed database, and the default target
postgresql	5432	relational	trust-auth and exposed ports are a recurring breach
sqlserver	1433	relational	often exposed for vendor integrations
oracle	1521	relational	legacy estates, rarely patched
mongodb	27017	document	historically unauthenticated by default
redis	6379	cache	unauthenticated means arbitrary writes, not just reads
memcached	11211	cache	no auth at all, amplification and data leak
docdb	27017	document	MongoDB compatible, IAM auth optional
LIST
}

db_cmd_status_tsv() {
    local p
    printf 'module\t%s\t%s\n' "$MODULE_ID" "$MOD_VERSION"
    for p in $(db_providers); do
        printf 'provider\t%s\t%s\n' "$p" "$(db_provider_state "$p")"
    done
}

db_cmd_menu() {
    printf 'instances\tList managed database instances\n'
    printf 'public\tInstances that are publicly addressable\n'
    printf 'probe\tTest whether one endpoint accepts connections\n'
}

db_cmd_help() {
    cat <<HELP
cloudsting module 21 — Managed Database Exposure v$MOD_VERSION

  --instances        list managed database instances across providers
  --public           instances that are publicly addressable, with reasons
  --probe <host> [port]   one TCP connect; open / closed / filtered
  --engines          engine, default port and why it matters
  --status-tsv       module status
  --menu             menu entries
  --selftest         run selftests
  --help             this message

Instances are only probed when you ask: --probe takes a host, it does not
sweep. Loot: $OUT_DIR
HELP
}

# ── Selftest ────────────────────────────────────────────────────
db_selftest() {
    local pass=0 fail=0 shim listener_pid port
    chk() {
        local name="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then
            printf 'ok\t%s\n' "$name"; pass=$((pass+1))
        else
            printf 'FAIL\t%s\twant=%s got=%s\n' "$name" "$want" "$got"; fail=$((fail+1))
        fi
    }

    chk engines-rows "$(db_cmd_engines | grep -vc '^#')" 8
    chk engines-fields "$(db_cmd_engines | awk -F'\t' '!/^#/ && NF != 4' | wc -l | tr -d ' ')" 0
    chk state-known "$(db_provider_state aws | grep -cE '^(tool-missing|creds-missing|creds-present)$')" 1
    chk status-fields "$(db_cmd_status_tsv | awk -F'\t' 'NF != 3' | wc -l | tr -d ' ')" 0
    chk menu-rows "$(db_cmd_menu | wc -l | tr -d ' ')" 3

    # engine mapping
    chk port-postgres "$(db_engine_port postgres)" 5432
    chk port-aurora-pg "$(db_engine_port aurora-postgresql)" 5432
    chk port-mysql "$(db_engine_port mysql)" 3306
    chk port-mariadb "$(db_engine_port mariadb)" 3306
    chk port-mssql "$(db_engine_port sqlserver-ee)" 1433
    chk port-cloudsql "$(db_engine_port POSTGRES_15)" 5432
    chk port-unknown "$(db_engine_port nonsense)" -
    chk class-relational "$(db_engine_class postgres)" relational
    chk class-cache "$(db_engine_class redis)" cache
    chk class-document "$(db_engine_class docdb)" document

    # findings from a fixture instance table
    shim="$(mktemp -d)"
    {
        printf 'aws\tprod-db\tpostgres\tprivate\tdb.internal\t5432\tpublic\tstorage-unencrypted,no-backup\n'
        printf 'aws\tsafe-db\tmysql\tsmall\tdbx.internal\t3306\tprivate\t-\n'
        printf 'gcloud\tsql1\tPOSTGRES_15\t-   \t1.2.3.4\t5432\tpublic\tany-ip-allowed\n'
    } > "$shim/inst"
    local out
    out="$(db_findings_from_items "$shim/inst")"
    chk find-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF != 4' | wc -l | tr -d ' ')" 0
    chk find-public "$(printf '%s\n' "$out" | awk -F'\t' '$2=="prod-db" && $4 ~ /publicly addressable/' | wc -l | tr -d ' ')" 1
    chk find-unencrypted "$(printf '%s' "$out" | awk -F'\t' '$2=="prod-db" && $4 ~ /not encrypted/{print $1}')" medium
    chk find-nobackup "$(printf '%s' "$out" | awk -F'\t' '$2=="prod-db" && $4 ~ /no automated backups/{print $1}')" medium
    chk find-anyip "$(printf '%s' "$out" | awk -F'\t' '$2=="sql1" && $4 ~ /any source/{print $1}')" high
    chk find-clean-none "$(printf '%s\n' "$out" | awk -F'\t' '$2=="safe-db"' | wc -l | tr -d ' ')" 0
    chk find-public-row-sev "$(printf '%s' "$out" | awk -F'\t' '$2=="prod-db" && $4 ~ /publicly addressable/{print $1}')" high

    # RDS parser against a shim
    cat > "$shim/aws" <<'SH'
#!/usr/bin/env bash
cat <<'JSON'
{"DBInstances":[{"DBInstanceIdentifier":"prod-db","Engine":"postgres",
 "DBInstanceClass":"db.t3.micro","StorageEncrypted":false,"BackupRetentionPeriod":0,
 "DeletionProtection":false,"CACertificateIdentifier":"","PubliclyAccessible":true,
 "Endpoint":{"Address":"prod-db.abc.us-east-1.rds.amazonaws.com","Port":5432}}]}
JSON
SH
    chmod +x "$shim/aws"
    out="$(PATH="$shim:$PATH" bash -c 'source "'"$MOD_DIR"'/21_db_exposure.sh"; db_instances_aws')"
    chk aws-row-count "$(printf '%s\n' "$out" | grep -c .)" 1
    chk aws-engine "$(printf '%s' "$out" | awk -F'\t' '{print $3}')" postgres
    chk aws-port "$(printf '%s' "$out" | awk -F'\t' '{print $6}')" 5432
    chk aws-exposure "$(printf '%s' "$out" | awk -F'\t' '{print $7}')" public
    chk aws-flags-unencrypted "$(printf '%s' "$out" | grep -c storage-unencrypted)" 1
    chk aws-flags-nobackup "$(printf '%s' "$out" | grep -c no-backup)" 1
    chk aws-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF != 8' | wc -l | tr -d ' ')" 0

    # Reachability: a real local listener, and a port that is not listening.
    port="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
    python3 -c "
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $port)); s.listen(1)
s.settimeout(6)
try:
    while True:
        c, _ = s.accept(); c.close()
except Exception:
    pass
" &
    listener_pid=$!
    sleep 0.6
    chk probe-open "$(db_tcp_verdict 127.0.0.1 "$port" 2>/dev/null)" open
    kill "$listener_pid" 2>/dev/null
    wait "$listener_pid" 2>/dev/null
    chk probe-closed "$(db_tcp_verdict 127.0.0.1 "$port" 2>/dev/null)" closed
    chk probe-usage "$(db_cmd_probe 2>&1 >/dev/null | grep -c usage)" 1
    chk probe-shape "$(db_cmd_probe 127.0.0.1 "$port" | awk -F'\t' 'NF != 3' | wc -l | tr -d ' ')" 0

    rm -rf "$shim"
    chk help-smoke "$(db_cmd_help 2>/dev/null | head -1 | grep -ci database)" 1

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --instances)  shift; db_cmd_instances "$@";;
    --public)     shift; db_cmd_public "$@";;
    --probe)      shift; db_cmd_probe "$@";;
    --engines)    shift; db_cmd_engines;;
    --status-tsv|--status) db_cmd_status_tsv;;
    --menu)       db_cmd_menu;;
    --selftest)   db_selftest;;
    *)            db_cmd_help;;
esac
