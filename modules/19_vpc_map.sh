#!/usr/bin/env bash
# 19_vpc_map.sh — cloudsting module 19: VPC / network topology mapper
# Verbs: --vpcs | --subnets | --routes | --gateways | --map | --list | --status-tsv | --menu | --selftest | --help
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
MODULE_ID="19_vpc_map"
MOD_NAME="VPC & Network Topology Mapper"
MOD_VERSION="0.16.0"
export CLOUDSTING_ROOT MOD_DIR MOD_NAME

_HOMEP="$(dirname -- "$CLOUDSTING_ROOT")"
[ -d "$_HOMEP" ] && HOME="$_HOMEP"
export HOME

RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
export VM_RUN_ID="$RUN_ID"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$HOME/loot/cloudsting}"
: "${STATE_DIR:=$TMP_DIR/state}"
OUT_DIR="$LOOT_DIR/vpc_map"
mkdir -p "$TMP_DIR" "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true
VPC_FILE="$OUT_DIR/vpcs-$RUN_ID.tsv"
SUB_FILE="$OUT_DIR/subnets-$RUN_ID.tsv"
ROUTE_FILE="$OUT_DIR/routes-$RUN_ID.tsv"
GW_FILE="$OUT_DIR/gateways-$RUN_ID.tsv"

vm_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── Provider gate — three states, never collapsed ────────────────
vm_provider_state() {
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

vm_providers() { printf '%s\n' "${VM_PROVIDERS:-aws gcloud azure}" | tr ' ' '\n' | sed '/^$/d'; }

# ── AWS ──────────────────────────────────────────────────────────
# vpc<TAB>id<TAB>cidr<TAB>default<TAB>state
vm_vpcs_aws() {
    aws ec2 describe-vpcs --output json 2>/dev/null | \
        jq -r 'try (.Vpcs[]? | [
                    "aws",
                    (.VpcId // ""),
                    (([.CidrBlockAssociationSet[]?.CidrBlock] | join(",")) // ""),
                    (if .IsDefault then "default" else "custom" end),
                    (.State // "")
               ] | @tsv)' 2>/dev/null
}

# vpc<TAB>subnet-id<TAB>cidr<TAB>az<TAB>public<TAB>state
# public is decided by MapPublicIpOnLaunch, not guessed from the route table.
vm_subnets_aws() {
    aws ec2 describe-subnets --output json 2>/dev/null | \
        jq -r 'try (.Subnets[]? | [
                    (.VpcId // ""),
                    (.SubnetId // ""),
                    (.CidrBlock // ""),
                    (.AvailabilityZone // ""),
                    (if .MapPublicIpOnLaunch then "public" else "private" end),
                    (.State // "")
               ] | @tsv)' 2>/dev/null
}

# vpc<TAB>route-table-id<TAB>destination<TAB>target<TAB>gateway-kind
vm_routes_aws() {
    aws ec2 describe-route-tables --output json 2>/dev/null | \
        jq -r 'try (.RouteTables[]? | . as $t | $t.Routes[]? |
                  (.GatewayId // .NatGatewayId // .InstanceId
                   // .VpcPeeringConnectionId // .TransitGatewayId
                   // .NetworkInterfaceId // .EgressOnlyInternetGatewayId // "") as $target |
                  [ ($t.VpcId // ""),
                    ($t.RouteTableId // ""),
                    (.DestinationCidrBlock // .DestinationIpv6CidrBlock // ""),
                    $target,
                    (if   $target == ""      then "none"
                     elif $target == "local" then "local"
                     elif ($target | startswith("igw-"))  then "internet-gateway"
                     elif ($target | startswith("vgw-"))  then "vpn-gateway"
                     elif ($target | startswith("nat-"))  then "nat-gateway"
                     elif ($target | startswith("pcx-"))  then "peering"
                     elif ($target | startswith("tgw-"))  then "transit-gateway"
                     elif ($target | startswith("eni-"))  then "interface"
                     elif ($target | startswith("vpce-")) then "endpoint"
                     else "other" end)
                  ] | @tsv)' 2>/dev/null
}

# kind<TAB>id<TAB>vpc<TAB>state  — internet / nat / vpn / peering
vm_gateways_aws() {
    aws ec2 describe-internet-gateways --output json 2>/dev/null | \
        jq -r 'try (.InternetGateways[]? | [
                    "internet",
                    (.InternetGatewayId // ""),
                    ([.Attachments[]?.VpcId] | join(",")),
                    "attached"
               ] | @tsv)' 2>/dev/null
    aws ec2 describe-nat-gateways --output json 2>/dev/null | \
        jq -r 'try (.NatGateways[]? | [
                    "nat",
                    (.NatGatewayId // ""),
                    (.VpcId // ""),
                    (.State // "")
               ] | @tsv)' 2>/dev/null
    aws ec2 describe-vpc-peering-connections --output json 2>/dev/null | \
        jq -r 'try (.VpcPeeringConnections[]? | [
                    "peering",
                    (.VpcPeeringConnectionId // ""),
                    ((.RequesterVpcInfo.VpcId // "") + "->" + (.AccepterVpcInfo.VpcId // "")),
                    (.Status.Code // "")
               ] | @tsv)' 2>/dev/null
}

# ── Google Cloud ────────────────────────────────────────────────
vm_vpcs_gcloud() {
    gcloud compute networks list --format=json 2>/dev/null | \
        jq -r 'try (.[]? | [
                    "gcloud",
                    (.name // ""),
                    ([.subnetworks[]? | split("/") | last] | join(",")),
                    (if (.autoCreateSubnetworks // false) then "auto" else "custom" end),
                    "present"
               ] | @tsv)' 2>/dev/null
}

vm_subnets_gcloud() {
    gcloud compute networks subnets list --format=json 2>/dev/null | \
        jq -r 'try (.[]? | [
                    ((.network // "") | split("/") | last),
                    (.name // ""),
                    (.ipCidrRange // ""),
                    (.region // "" | split("/") | last),
                    (if (.privateIpGoogleAccess // false) then "private" else "public" end),
                    (.purpose // "PRIVATE")
               ] | @tsv)' 2>/dev/null
}

# ── Azure ───────────────────────────────────────────────────────
vm_vpcs_azure() {
    az network vnet list -o json 2>/dev/null | \
        jq -r 'try (.[]? | [
                    "azure",
                    (.name // ""),
                    (([.addressSpace.addressPrefixes[]?] | join(",")) // ""),
                    (if (.enableDdosProtection // false) then "ddos" else "custom" end),
                    (.provisioningState // "")
               ] | @tsv)' 2>/dev/null
}

vm_subnets_azure() {
    az network vnet subnet list --vnet-name "${VM_VNET:-}" -g "${VM_RG:-}" -o json 2>/dev/null | \
        jq -r 'try (.[]? | [
                    (.vnetName // ""),
                    (.name // ""),
                    (.addressPrefix // ([.addressPrefixes[]?] | join(",")) // ""),
                    (.routeTable.id // "" | split("/") | last),
                    "private",
                    (.provisioningState // "")
               ] | @tsv)' 2>/dev/null
}

# ── Verbs ───────────────────────────────────────────────────────
vm_emit() {
    local kind="$1" file="$2" p state found=0
    shift 2
    : > "$file"
    for p in $(vm_providers); do
        state="$(vm_provider_state "$p")"
        if [ "$state" != "creds-present" ]; then
            printf 'state\t%s\t%s\t%s\n' "$kind" "$p" "$state"
            continue
        fi
        found=1
        case "$p" in
            aws)    "vm_${kind}_aws";;
            gcloud) "vm_${kind}_gcloud";;
            azure)  "vm_${kind}_azure";;
            *)      ;;
        esac 2>/dev/null | tee -a "$file"
    done
    [ "$found" -eq 0 ] && vm_log "$kind: no provider reachable"
    return 0
}

vm_cmd_vpcs()     { vm_emit vpcs "$VPC_FILE"; }
vm_cmd_subnets()  { vm_emit subnets "$SUB_FILE"; }
vm_cmd_gateways() { vm_emit gateways "$GW_FILE"; }
vm_cmd_routes()   { vm_emit routes "$ROUTE_FILE"; }

# ── Classification: what a topology actually exposes ────────────
# findings: <severity><TAB><area><TAB><detail>
vm_classify() {
    local sub_file="${1:-$SUB_FILE}" route_file="${2:-$ROUTE_FILE}" gw="$3"
    local public_subnets open_routes
    public_subnets="$(awk -F'\t' '$5=="public"' "$sub_file" 2>/dev/null | wc -l | tr -d ' ')"
    open_routes="$(awk -F'\t' '$3=="0.0.0.0/0" && $5=="internet-gateway"' "$route_file" 2>/dev/null \
                   | wc -l | tr -d ' ')"
    [ "${public_subnets:-0}" -gt 0 ] && \
        printf 'info\tpublic-subnets\t%s subnet(s) auto-assign public IPs\n' "$public_subnets"
    [ "${open_routes:-0}" -gt 0 ] && \
        printf 'info\tdefault-route\t%s route table(s) send 0.0.0.0/0 to an internet gateway\n' "$open_routes"
    if [ "${open_routes:-0}" -gt 0 ] && [ "${public_subnets:-0}" -eq 0 ]; then
        printf 'ok\tdetached\tdefault route exists but no subnet auto-assigns public IPs\n'
    fi
    [ -n "${gw:-}" ] && [ -s "$gw" ] && \
        printf 'info\tpeering\t%s peering/nat/internet entries\n' "$(wc -l < "$gw" | tr -d ' ')"
    return 0
}

vm_cmd_map() {
    printf '=== providers\n'
    vm_cmd_status_tsv | awk -F'\t' '$1=="provider"{printf "%s\t%s\n", $2, $3}'
    vm_cmd_vpcs     >/dev/null 2>&1
    vm_cmd_subnets  >/dev/null 2>&1
    vm_cmd_routes   >/dev/null 2>&1
    vm_cmd_gateways >/dev/null 2>&1
    printf '=== vpcs (%s)\n' "$(wc -l < "$VPC_FILE" 2>/dev/null | tr -d ' ')"
    cat "$VPC_FILE" 2>/dev/null
    printf '=== subnets (%s)\n' "$(wc -l < "$SUB_FILE" 2>/dev/null | tr -d ' ')"
    cat "$SUB_FILE" 2>/dev/null
    printf '=== routes (%s)\n' "$(wc -l < "$ROUTE_FILE" 2>/dev/null | tr -d ' ')"
    cat "$ROUTE_FILE" 2>/dev/null
    printf '=== gateways (%s)\n' "$(wc -l < "$GW_FILE" 2>/dev/null | tr -d ' ')"
    cat "$GW_FILE" 2>/dev/null
    printf '=== findings\n'
    vm_classify "$SUB_FILE" "$ROUTE_FILE" "$GW_FILE"
}

vm_cmd_list() {
    cat <<'LIST'
#verb	what-it-shows	why-it-matters
vpcs	virtual networks and their address space	the blast radius of one credential
subnets	per-AZ ranges and whether they auto-assign public IPs	where a foothold becomes reachable
routes	route tables and their targets	which subnet can egress to the internet
gateways	internet, NAT and peering attachments	the paths between your network and an attacker
map	all four plus the findings	one picture of what is exposed
LIST
}

vm_cmd_status_tsv() {
    local p
    printf 'module\t%s\t%s\n' "$MODULE_ID" "$MOD_VERSION"
    for p in $(vm_providers); do
        printf 'provider\t%s\t%s\n' "$p" "$(vm_provider_state "$p")"
    done
}

vm_cmd_menu() {
    printf 'map\tFull topology with findings\n'
    printf 'vpcs\tVirtual networks only\n'
    printf 'subnets\tSubnets only\n'
    printf 'routes\tRoute tables only\n'
}

vm_cmd_help() {
    cat <<HELP
cloudsting module 19 — VPC & Network Topology Mapper v$MOD_VERSION

  --vpcs        virtual networks and their address space
  --subnets     subnets, per-AZ ranges, public/private by IP-assignment policy
  --routes      route tables, destinations and targets
  --gateways    internet / NAT / peering attachments
  --map         all of the above plus exposure findings
  --list        verb reference
  --status-tsv  module status
  --menu        menu entries
  --selftest    run selftests
  --help        this message

Azure subnet listing needs VM_RG and VM_VNET (resource group and network name).
Loot: $OUT_DIR
HELP
}

# ── Selftest ────────────────────────────────────────────────────
vm_selftest() {
    local pass=0 fail=0 shim
    chk() {
        local name="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then
            printf 'ok\t%s\n' "$name"; pass=$((pass+1))
        else
            printf 'FAIL\t%s\twant=%s got=%s\n' "$name" "$want" "$got"; fail=$((fail+1))
        fi
    }

    chk list-rows "$(vm_cmd_list | grep -vc '^#')" 5
    chk list-fields "$(vm_cmd_list | awk -F'\t' '!/^#/ && NF != 3' | wc -l | tr -d ' ')" 0
    chk state-known "$(vm_provider_state aws | grep -cE '^(tool-missing|creds-missing|creds-present)$')" 1
    chk status-fields "$(vm_cmd_status_tsv | awk -F'\t' 'NF != 3' | wc -l | tr -d ' ')" 0
    chk menu-rows "$(vm_cmd_menu | wc -l | tr -d ' ')" 4

    # Parsers against canned provider output, through a PATH shim.
    shim="$(mktemp -d)"
    cat > "$shim/aws" <<'SH'
#!/usr/bin/env bash
case "$1 $2" in
"ec2 describe-vpcs") cat <<'JSON'
{"Vpcs":[{"VpcId":"vpc-1","CidrBlock":"10.0.0.0/16","IsDefault":false,"State":"available",
 "CidrBlockAssociationSet":[{"CidrBlock":"10.0.0.0/16"}]}]}
JSON
;;
"ec2 describe-subnets") cat <<'JSON'
{"Subnets":[{"VpcId":"vpc-1","SubnetId":"subnet-pub","CidrBlock":"10.0.1.0/24",
 "AvailabilityZone":"us-east-1a","MapPublicIpOnLaunch":true,"State":"available"},
 {"VpcId":"vpc-1","SubnetId":"subnet-priv","CidrBlock":"10.0.2.0/24",
 "AvailabilityZone":"us-east-1b","MapPublicIpOnLaunch":false,"State":"available"}]}
JSON
;;
"ec2 describe-route-tables") cat <<'JSON'
{"RouteTables":[{"VpcId":"vpc-1","RouteTableId":"rtb-1","Routes":[
 {"DestinationCidrBlock":"0.0.0.0/0","GatewayId":"igw-1"},
 {"DestinationCidrBlock":"10.0.0.0/16","GatewayId":"local"}]}]}
JSON
;;
"ec2 describe-internet-gateways") echo '{"InternetGateways":[{"InternetGatewayId":"igw-1","Attachments":[{"VpcId":"vpc-1"}]}]}';;
"ec2 describe-nat-gateways") echo '{"NatGateways":[]}';;
"ec2 describe-vpc-peering-connections") echo '{"VpcPeeringConnections":[]}';;
*) echo '{}';;
esac
SH
    chmod +x "$shim/aws"

    local out
    out="$(PATH="$shim:$PATH" AWS_ACCESS_KEY_ID=dummy bash -c '
        source "'"$MOD_DIR"'/19_vpc_map.sh"
        vm_vpcs_aws')"
    chk aws-vpc-row "$(printf '%s' "$out" | awk -F'\t' '$2=="vpc-1"' | wc -l | tr -d ' ')" 1
    chk aws-vpc-cidr "$(printf '%s' "$out" | awk -F'\t' '{print $3}')" "10.0.0.0/16"

    out="$(PATH="$shim:$PATH" AWS_ACCESS_KEY_ID=dummy bash -c '
        source "'"$MOD_DIR"'/19_vpc_map.sh"
        vm_subnets_aws')"
    chk aws-subnet-count "$(printf '%s\n' "$out" | grep -c .)" 2
    chk aws-subnet-public "$(printf '%s' "$out" | awk -F'\t' '$5=="public"{print $2}')" "subnet-pub"
    chk aws-subnet-private "$(printf '%s' "$out" | awk -F'\t' '$5=="private"{print $2}')" "subnet-priv"

    out="$(PATH="$shim:$PATH" AWS_ACCESS_KEY_ID=dummy bash -c '
        source "'"$MOD_DIR"'/19_vpc_map.sh"
        vm_routes_aws')"
    chk aws-route-count "$(printf '%s\n' "$out" | grep -c .)" 2
    chk aws-route-igw "$(printf '%s' "$out" | awk -F'\t' '$3=="0.0.0.0/0"{print $5}')" "internet-gateway"
    chk aws-route-local "$(printf '%s' "$out" | awk -F'\t' '$3=="10.0.0.0/16"{print $5}')" "local"

    # Classifier: public subnets + default route are both stated as findings.
    printf 'aws\tvpc-1\tsubnet-pub\t10.0.1.0/24\tpublic\n' > "$shim/sub"
    printf 'vpc-1\trtb-1\t0.0.0.0/0\tigw-1\tinternet-gateway\n' > "$shim/rt"
    out="$(vm_classify "$shim/sub" "$shim/rt" "")"
    chk classify-public "$(printf '%s' "$out" | awk -F'\t' '$2=="public-subnets"' | wc -l | tr -d ' ')" 1
    chk classify-default "$(printf '%s' "$out" | awk -F'\t' '$2=="default-route"' | wc -l | tr -d ' ')" 1
    chk classify-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF != 3' | wc -l | tr -d ' ')" 0

    # No public subnet but an open route: detached, and said so.
    printf 'aws\tvpc-1\tsubnet-priv\t10.0.2.0/24\tprivate\n' > "$shim/sub"
    out="$(vm_classify "$shim/sub" "$shim/rt" "")"
    chk classify-detached "$(printf '%s' "$out" | awk -F'\t' '$2=="detached"' | wc -l | tr -d ' ')" 1
    chk classify-no-public "$(printf '%s' "$out" | awk -F'\t' '$2=="public-subnets"' | wc -l | tr -d ' ')" 0

    rm -rf "$shim"
    chk help-smoke "$(vm_cmd_help 2>/dev/null | head -1 | grep -ci vpc)" 1

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --vpcs)       shift; vm_cmd_vpcs "$@";;
    --subnets)    shift; vm_cmd_subnets "$@";;
    --routes)     shift; vm_cmd_routes "$@";;
    --gateways)   shift; vm_cmd_gateways "$@";;
    --map)        shift; vm_cmd_map "$@";;
    --list)       shift; vm_cmd_list;;
    --status-tsv|--status) vm_cmd_status_tsv;;
    --menu)       vm_cmd_menu;;
    --selftest)   vm_selftest;;
    *)            vm_cmd_help;;
esac
