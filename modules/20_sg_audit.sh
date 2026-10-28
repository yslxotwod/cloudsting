#!/usr/bin/env bash
# 20_sg_audit.sh — cloudsting module 20: security group / firewall audit
# Verbs: --rules | --audit | --explain | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

_SH_SRC="${BASH_SOURCE[0]}"
while [ -L "$_SH_SRC" ]; do
    _SH_DIR="$(cd -- "$(dirname -- "$_SH_SRC")" && pwd)"
    _SH_SRC="$(readlink -- "$_SH_SRC")"
    [[ "$_SH_SRC" != /* ]] && _SH_SRC="$_SH_DIR/$_SH_SRC"
done
CLOUDSTING_ROOT="$(cd -- "$(dirname -- "$_SH_SRC")/.." && pwd)"
MOD_DIR="$(dirname -- "$_SH_SRC")"
MODULE_ID="20_sg_audit"
MOD_NAME="Security Group & Firewall Audit"
MOD_VERSION="0.17.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export SG_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/sg_audit"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
RULE_FILE="$OUT_DIR/rules-$RUN_ID.tsv"
FIND_FILE="$OUT_DIR/findings-$RUN_ID.tsv"

sg_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── Provider gate ────────────────────────────────────────────────
sg_provider_state() {
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

sg_providers() { printf '%s\n' "${SG_PROVIDERS:-aws gcloud azure}" | tr ' ' '\n' | sed '/^$/d'; }

# ── Rule rows: group<TAB>direction<TAB>proto<TAB>from<TAB>to<TAB>cidr<TAB>note
sg_rules_aws() {
    aws ec2 describe-security-groups --output json 2>/dev/null | \
        jq -r 'try (.SecurityGroups[]? | . as $g |
                  ( ($g.GroupId // "") + "/" + ($g.GroupName // "") ) as $id |
                  ( $g.IpPermissions[]? |
                    [ $id, "ingress",
                      (.IpProtocol // ""),
                      (if .FromPort == null then "-" else (.FromPort | tostring) end),
                      (if .ToPort == null then "-" else (.ToPort | tostring) end),
                      (([.IpRanges[]?.CidrIp, .Ipv6Ranges[]?.CidrIpv6,
                         .UserIdGroupPairs[]?.GroupId] | map(select(. != null)) | join(",")) as $c
                       | if $c == "" then "-" else $c end),
                      ((.IpProtocol // "") | if . == "-1" then "all-traffic" else "-" end)
                    ] | @tsv ),
                  ( $g.IpPermissionsEgress[]? |
                    [ $id, "egress",
                      (.IpProtocol // ""),
                      (if .FromPort == null then "-" else (.FromPort | tostring) end),
                      (if .ToPort == null then "-" else (.ToPort | tostring) end),
                      (([.IpRanges[]?.CidrIp, .Ipv6Ranges[]?.CidrIpv6,
                         .UserIdGroupPairs[]?.GroupId] | map(select(. != null)) | join(",")) as $c
                       | if $c == "" then "-" else $c end),
                      "-"
                    ] | @tsv ) )' 2>/dev/null
}

sg_rules_gcloud() {
    gcloud compute firewall-rules list --format=json 2>/dev/null | \
        jq -r 'try (.[]? | . as $r |
                  ( ($r.name // "") + "/fw" ) as $id |
                  [ $id,
                    (if ($r.direction // "INGRESS") == "INGRESS" then "ingress" else "egress" end),
                    (($r.allowed // []) | map(.IPProtocol) | join(",")),
                    (([($r.allowed // [])[]?.ports[]?] | map(tostring) | join(",")) // ""),
                    "",
                    (([$r.sourceRanges[]?] | join(",")) // ""),
                    (($r.disabled // false) | if . then "disabled" else "" end)
                  ] | @tsv)' 2>/dev/null
}

sg_rules_azure() {
    az network nsg list -o json 2>/dev/null | \
        jq -r 'try (.[]? | . as $n |
                  ( ($n.resourceGroup // "") + "/" + ($n.name // "") ) as $id |
                  ( ($n.securityRules // [])[]? |
                    [ $id,
                      (.direction // "" | ascii_downcase),
                      (.protocol // ""),
                      (.destinationPortRange // ((.destinationPortRanges // []) | join(",")) // ""),
                      "",
                      (.sourceAddressPrefix // ((.sourceAddressPrefixes // []) | join(",")) // ""),
                      (if (.access // "") == "Allow" then "" else "deny" end)
                    ] | @tsv ) )' 2>/dev/null
}

# ── Rule collection, honest per provider ────────────────────────
sg_collect() {
    local p state found=0
    : > "$RULE_FILE"
    for p in $(sg_providers); do
        state="$(sg_provider_state "$p")"
        if [ "$state" != "creds-present" ]; then
            printf 'state\t%s\t%s\n' "$p" "$state"
            continue
        fi
        found=1
        case "$p" in
            aws)    sg_rules_aws;;
            gcloud) sg_rules_gcloud;;
            azure)  sg_rules_azure;;
        esac 2>/dev/null | tee -a "$RULE_FILE"
    done
    [ "$found" -eq 0 ] && sg_log "no provider reachable; nothing was collected"
    return 0
}

sg_cmd_rules() {
    local group dir proto from to cidr note
    sg_collect | while IFS=$'\t' read -r group dir proto from to cidr note; do
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$group" "$dir" "$proto" "$from" "$to" "$cidr" "$note"
    done
}

# ── Port classification ─────────────────────────────────────────
# A world-open admin/database port is a different finding from a world-open
# 443. The list is deliberately short: these are the ones that end up in
# incident reports.
sg_port_severity() {
    local port="${1:-}"
    case "$port" in
        22|2222|3389|5985|5986)          printf 'critical' ;;   # remote shells
        3306|5432|1433|1521|27017|27018) printf 'critical' ;;   # databases
        6379|9200|9300|11211|5672|15672) printf 'critical' ;;   # unauth datastores
        23|21|512|513|514)               printf 'critical' ;;   # cleartext legacy
        445|139|2049)                    printf 'high' ;;       # file sharing
        2375|2376|6443|10250|10255)      printf 'high' ;;       # container/k8s control
        8080|8443|8000|8888|9000|5601)   printf 'medium' ;;     # alt web / dashboards
        80|443)                          printf 'low' ;;        # intended to be public
        *)                               printf 'medium' ;;
    esac
}

# A range is graded by the worst port it contains: 0-65535 is not "port 0".
sg_range_severity() {
    local from="${1:-}" to="${2:-}" port sev worst="low"
    [ -z "$to" ] && to="$from"
    for port in 22 2222 3389 5985 5986 3306 5432 1433 1521 27017 27018 \
                6379 9200 9300 11211 5672 15672 23 21 512 513 514 \
                445 139 2049 2375 2376 6443 10250 10255; do
        [ "$port" -ge "$from" ] 2>/dev/null && [ "$port" -le "$to" ] 2>/dev/null || continue
        sev="$(sg_port_severity "$port")"
        case "$sev" in
            critical) printf 'critical'; return 0 ;;
            high)     worst="high" ;;
        esac
    done
    printf '%s' "$worst"
}

sg_is_world() {
    local cidr="${1:-}"
    case "$cidr" in
        *"0.0.0.0/0"*|*"::/0"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Does a rule cover a given port? Handles ranges and the -1 all-traffic protocol.
sg_covers_port() {
    local proto="${1:-}" from="${2:-}" to="${3:-}" port="${4:-}"
    [ "$port" = "-" ] && return 0
    case "$proto" in
        -1|all|tcp|6|"") ;;
        udp|17|icmp|1) return 1 ;;
        *) return 1 ;;
    esac
    case "$proto" in
        tcp|6|""|-1|all) ;;
        *) return 1 ;;
    esac
    [ -z "$from" ] && return 0            # -1 protocol: every port
    [ "$from" = "-1" ] && return 0
    [ -z "$to" ] && to="$from"
    [ "$from" -le "$port" ] 2>/dev/null && [ "$port" -le "$to" ] 2>/dev/null
}

# ── Findings ────────────────────────────────────────────────────
sg_findings_from_rules() {
    local file="${1:-$RULE_FILE}" group dir proto from to cidr note port sev
    local seen_ports=""
    while IFS=$'\t' read -r group dir proto from to cidr note; do
        [ -z "${group:-}" ] && continue
        [ "$from" = "-" ] && from=""
        [ "$to" = "-" ] && to=""
        [ "$cidr" = "-" ] && cidr=""
        [ "$note" = "-" ] && note=""
        [ "$dir" = "egress" ] && continue
        [ "$note" = "disabled" ] && continue
        sg_is_world "$cidr" || continue
        if [ -z "$from" ] || [ "$from" = "-1" ]; then
            printf 'critical\t%s\tall\tworld-open: every port and protocol\n' "$group"
            continue
        fi
        port="$from"
        if [ "$to" != "$from" ] && [ -n "$to" ]; then
            sev="$(sg_range_severity "$from" "$to")"
            printf '%s\t%s\t%s-%s\tworld-open range %s-%s\n' "$sev" "$group" "$from" "$to" "$from" "$to"
        else
            sev="$(sg_port_severity "$port")"
            printf '%s\t%s\t%s\tworld-open port %s\n' "$sev" "$group" "$port" "$port"
        fi
    done < "$file"
}

sg_cmd_audit() {
    local counts
    sg_collect >/dev/null 2>&1 || true
    if [ ! -s "$RULE_FILE" ]; then
        printf 'no rules collected (no provider reachable)\n'
        return 1
    fi
    sg_findings_from_rules "$RULE_FILE" | tee "$FIND_FILE"
    counts="$(awk -F'\t' '{c[$1]++} END {for (k in c) printf "%s=%d ", k, c[k]}' "$FIND_FILE" 2>/dev/null)"
    printf 'SUMMARY\t%s\n' "${counts:-none}"
}

# ── Explain one port ────────────────────────────────────────────
sg_cmd_explain() {
    local port="${1:-}"
    if [ -z "$port" ]; then
        printf 'usage: --explain <port>\n' >&2
        return 2
    fi
    local sev
    sev="$(sg_port_severity "$port")"
    printf 'port\t%s\n' "$port"
    printf 'severity-if-world-open\t%s\n' "$sev"
    case "$port" in
        22|2222) printf 'why\tSSH to the internet is the single most-scanned port there is\n' ;;
        3389)    printf 'why\tRDP exposed to the internet is an active ransomware entry point\n' ;;
        3306|5432|1433|1521) printf 'why\ta database port open to the world is usually an unauthenticated breach\n' ;;
        6379|9200|11211|27017) printf 'why\tthese datastores historically shipped without authentication\n' ;;
        2375|6443|10250) printf 'why\tcontainer and cluster control planes grant host-level control\n' ;;
        80|443)  printf 'why\tintended to be public; the finding is what sits behind it\n' ;;
        *)       printf 'why\tno specific knowledge for this port; treated by protocol class\n' ;;
    esac
}

sg_cmd_list() {
    cat <<'LIST'
#port-class	default-severity	note
remote-shell	critical	22, 2222, 3389, 5985, 5986
databases	critical	3306, 5432, 1433, 1521, 27017, 27018
unauth-datastores	critical	6379, 9200, 9300, 11211, 5672, 15672
legacy-cleartext	critical	23, 21, 512, 513, 514
file-sharing	high	445, 139, 2049
container-control	high	2375, 2376, 6443, 10250, 10255
alt-web	medium	8080, 8443, 8000, 8888, 9000, 5601
web	low	80, 443
LIST
}

sg_cmd_status_tsv() {
    local p
    printf 'module\t%s\t%s\n' "$MODULE_ID" "$MOD_VERSION"
    for p in $(sg_providers); do
        printf 'provider\t%s\t%s\n' "$p" "$(sg_provider_state "$p")"
    done
}

sg_cmd_menu() {
    printf 'rules\tCollect rules from every provider\n'
    printf 'audit\tWorld-open findings by severity\n'
    printf 'explain\tWhat one port means when it is world-open\n'
}

sg_cmd_help() {
    cat <<HELP
cloudsting module 20 — Security Group & Firewall Audit v$MOD_VERSION

  --rules              collect ingress/egress rules from every provider
  --audit              world-open rules, graded by port class, with a summary
  --explain <port>     why a port matters when it faces the internet
  --list               port-class reference table
  --status-tsv         module status
  --menu               menu entries
  --selftest           run selftests
  --help               this message

Rows are group/direction/protocol/from/to/cidr/note. Loot: $OUT_DIR
HELP
}

# ── Selftest ────────────────────────────────────────────────────
sg_selftest() {
    local pass=0 fail=0 shim
    chk() {
        local name="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then
            printf 'ok\t%s\n' "$name"; pass=$((pass+1))
        else
            printf 'FAIL\t%s\twant=%s got=%s\n' "$name" "$want" "$got"; fail=$((fail+1))
        fi
    }

    chk list-rows "$(sg_cmd_list | grep -vc '^#')" 8
    chk list-fields "$(sg_cmd_list | awk -F'\t' '!/^#/ && NF != 3' | wc -l | tr -d ' ')" 0
    chk state-known "$(sg_provider_state aws | grep -cE '^(tool-missing|creds-missing|creds-present)$')" 1
    chk status-fields "$(sg_cmd_status_tsv | awk -F'\t' 'NF != 3' | wc -l | tr -d ' ')" 0
    chk menu-rows "$(sg_cmd_menu | wc -l | tr -d ' ')" 3

    # port classes
    chk sev-ssh "$(sg_port_severity 22)" critical
    chk sev-rdp "$(sg_port_severity 3389)" critical
    chk sev-mysql "$(sg_port_severity 3306)" critical
    chk sev-redis "$(sg_port_severity 6379)" critical
    chk sev-smb "$(sg_port_severity 445)" high
    chk sev-k8s "$(sg_port_severity 6443)" high
    chk sev-8080 "$(sg_port_severity 8080)" medium
    chk sev-https "$(sg_port_severity 443)" low

    # world-open detection
    sg_is_world "0.0.0.0/0" && chk world-v4 ok ok
    sg_is_world "::/0" && chk world-v6 ok ok
    sg_is_world "10.0.0.0/8" || chk world-private ok ok

    # port coverage
    sg_covers_port tcp 22 22 22 && chk covers-exact ok ok
    sg_covers_port tcp 20 30 25 && chk covers-range ok ok
    sg_covers_port tcp 20 30 40 || chk covers-outside ok ok
    sg_covers_port -1 "" "" 22 && chk covers-all-traffic ok ok
    sg_covers_port udp 53 53 22 || chk covers-udp-no ok ok

    # findings against a fixture rule table
    shim="$(mktemp -d)"
    {
        printf 'sg-open/ssh\t%s\ttcp\t22\t22\t0.0.0.0/0\t-\n' ingress    # world-open SSH
        printf 'sg-open/wide\t%s\ttcp\t0\t65535\t0.0.0.0/0\t-\n' ingress  # everything
        printf 'sg-open/any\t%s\t-1\t-\t-\t0.0.0.0/0\tall-traffic\n' ingress  # -1 protocol
        printf 'sg-private\tingress\ttcp\t3306\t3306\t10.0.0.0/8\t-\n'    # not world
        printf 'sg-egress\tegress\ttcp\t443\t443\t0.0.0.0/0\t-\n'         # egress, ignored
    } > "$shim/rules"
    local out
    out="$(sg_findings_from_rules "$shim/rules")"
    chk find-count "$(printf '%s\n' "$out" | grep -c .)" 3
    chk find-ssh "$(printf '%s' "$out" | awk -F'\t' '$2=="sg-open/ssh"{print $1}')" critical
    chk find-wide "$(printf '%s' "$out" | awk -F'\t' '$2=="sg-open/wide"{print $1}')" critical
    chk find-any "$(printf '%s' "$out" | awk -F'\t' '$2=="sg-open/any"{print $3}')" all
    chk find-private-absent "$(printf '%s' "$out" | awk -F'\t' '$2=="sg-private"' | wc -l | tr -d ' ')" 0
    chk find-egress-absent "$(printf '%s' "$out" | awk -F'\t' '$2=="sg-egress"' | wc -l | tr -d ' ')" 0
    chk find-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF != 4' | wc -l | tr -d ' ')" 0
    rm -rf "$shim"

    # parser against a describe-security-groups shim
    shim="$(mktemp -d)"
    cat > "$shim/aws" <<'SH'
#!/usr/bin/env bash
cat <<'JSON'
{"SecurityGroups":[{"GroupId":"sg-1","GroupName":"web",
 "IpPermissions":[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,
   "IpRanges":[{"CidrIp":"0.0.0.0/0"}]}],
 "IpPermissionsEgress":[{"IpProtocol":"-1",
   "IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]}]}
JSON
SH
    chmod +x "$shim/aws"
    out="$(PATH="$shim:$PATH" bash -c 'source "'"$MOD_DIR"'/20_sg_audit.sh"; sg_rules_aws')"
    chk aws-rule-rows "$(printf '%s\n' "$out" | grep -c .)" 2
    chk aws-rule-sg "$(printf '%s' "$out" | awk -F'\t' 'NR==1{print $1}')" "sg-1/web"
    chk aws-rule-direction "$(printf '%s' "$out" | awk -F'\t' 'NR==2{print $2}')" "egress"
    chk aws-rule-cidr "$(printf '%s' "$out" | awk -F'\t' 'NR==1{print $6}')" "0.0.0.0/0"
    chk aws-rule-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF != 7' | wc -l | tr -d ' ')" 0
    rm -rf "$shim"

    chk explain-usage "$(sg_cmd_explain 2>&1 >/dev/null | grep -c usage)" 1
    chk explain-ssh "$(sg_cmd_explain 22 | awk -F'\t' '$1=="severity-if-world-open"{print $2}')" critical
    chk help-smoke "$(sg_cmd_help 2>/dev/null | head -1 | grep -ci security)" 1

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --rules)      shift; sg_cmd_rules "$@";;
    --audit)      shift; sg_cmd_audit "$@";;
    --explain)    shift; sg_cmd_explain "$@";;
    --list)       shift; sg_cmd_list;;
    --status-tsv|--status) sg_cmd_status_tsv;;
    --menu)       sg_cmd_menu;;
    --selftest)   sg_selftest;;
    *)            sg_cmd_help;;
esac
