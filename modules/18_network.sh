#!/usr/bin/env bash
# 18_network.sh — cloudsting module 18: the cloud network, from DNS to subnets to world-open rules
# Verbs: --zones | --records | --resolve | --dangling | --axfr | --vpcs | --subnets | --routes | --gateways | --rules | --audit | --map | --all | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file after the core is sourced. An inherited
# CS_MOD_DIR is a caller's directory, not this module's.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV writer,
# the three-state provider gate, redaction, the findings store and the
# selftest ledger.
MODULE_ID="18_network"
MOD_NAME="Cloud Network (DNS → subnets → firewall)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

NW_RUN_ID="$CS_RUN_ID"
export NW_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/network"
mkdir -p "$OUT_DIR" 2>/dev/null || true

ZONE_FILE="$OUT_DIR/zones-$RUN_ID.tsv"
RECORD_FILE="$OUT_DIR/records-$RUN_ID.tsv"
VPC_FILE="$OUT_DIR/vpcs-$RUN_ID.tsv"
SUBNET_FILE="$OUT_DIR/subnets-$RUN_ID.tsv"
ROUTE_FILE="$OUT_DIR/routes-$RUN_ID.tsv"
GW_FILE="$OUT_DIR/gateways-$RUN_ID.tsv"
RULE_FILE="$OUT_DIR/rules-$RUN_ID.tsv"
FIND_FILE="$OUT_DIR/findings-$RUN_ID.tsv"

: "${NW_TIMEOUT:=10}"   # DNS resolution and per-call timeout
: "${NW_DNS:=}"         # override the resolver, e.g. 1.1.1.1

nw_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── provider gates ───────────────────────────────────────────────
nw_has_aws() { command -v aws >/dev/null 2>&1 && aws sts get-caller-identity >/dev/null 2>&1; }
nw_has_gcp() { command -v gcloud >/dev/null 2>&1 && gcloud config get-value project >/dev/null 2>&1; }
nw_has_az()  { command -v az >/dev/null 2>&1 && az account show >/dev/null 2>&1; }

nw_providers() { printf 'aws gcp az'; }

nw_provider_state() {
    local p="$1"
    case "$p" in
        aws) if nw_has_aws; then printf 'creds-present'
             elif command -v aws >/dev/null 2>&1; then printf 'creds-missing'
             else printf 'tool-missing'; fi ;;
        gcp) if nw_has_gcp; then printf 'creds-present'
             elif command -v gcloud >/dev/null 2>&1; then printf 'creds-missing'
             else printf 'tool-missing'; fi ;;
        az)  if nw_has_az; then printf 'creds-present'
             elif command -v az >/dev/null 2>&1; then printf 'creds-missing'
             else printf 'tool-missing'; fi ;;
        *)   printf 'unknown' ;;
    esac
}

# Is there any resolver to ask? Three states.
nw_dns_tool() {
    if [[ -n "$NW_DNS" ]]; then printf 'explicit'; return 0; fi
    if command -v dig >/dev/null 2>&1;    then printf 'dig';    return 0; fi
    if command -v host >/dev/null 2>&1;   then printf 'host';   return 0; fi
    if command -v nslookup >/dev/null 2>&1; then printf 'nslookup'; return 0; fi
    if command -v getent >/dev/null 2>&1; then printf 'getent'; return 0; fi
    printf 'missing'
}

# ── DNS ──────────────────────────────────────────────────────────
# One question, answered by whichever resolver exists on this box.
#   nw_query <name> <type>  ->  one answer per line, no trailing dot
nw_query() {
    local name="$1" type="${2:-A}" out=""
    local tool; tool="$(nw_dns_tool)"
    local -a server=()
    [[ -n "$NW_DNS" ]] && server=("@$NW_DNS")

    case "$tool" in
        dig|explicit)
            out="$(dig +short "+time=$NW_TIMEOUT" +tries=1 "${server[@]}" "$name" "$type" 2>/dev/null)"
            ;;
        host)
            out="$(host -W "$NW_TIMEOUT" -t "$type" "$name" 2>/dev/null | \
                   awk '{print $NF}' | grep -vE '^$')"
            ;;
        nslookup)
            out="$(nslookup -timeout="$NW_TIMEOUT" -type="$type" "$name" 2>/dev/null | \
                   awk '/^Address: /{print $2}' | tail -n +2)"
            ;;
        getent)
            # getent only does A/AAAA, and only through the local resolver.
            out="$(getent ahosts "$name" 2>/dev/null | awk '{print $1}' | sort -u)"
            ;;
        *)
            return 3
            ;;
    esac
    printf '%s\n' "$out" | sed 's/\.$//' | grep -v '^$' | sort -u
}

# Zones per provider: the authoritative side. A zone I control that is
# pointed at a host I do not is the takeover half.
nw_zones_aws() {
    nw_has_aws || return 0
    aws route53 list-hosted-zones --output json 2>/dev/null | \
        jq -r '.HostedZones[]? | ["aws", (.Name // "" | rtrimstr(".")), (.Id // "" | sub(".*/"; "")), (.Config.PrivateZone | tostring), (.ResourceRecordSetCount | tostring)] | @tsv' 2>/dev/null
}

nw_zones_gcp() {
    nw_has_gcp || return 0
    local project; project="$(gcloud config get-value project 2>/dev/null)"
    [[ -z "$project" || "$project" == "(unset)" ]] && return 0
    gcloud dns managed-zones list --project "$project" \
        --format='csv[no-heading](NAME,DNS_NAME,VISIBILITY)' 2>/dev/null | \
        while IFS=, read -r name dns vis; do
            [[ -z "$name" ]] && continue
            printf 'gcp\t%s\t%s\t%s\t-\n' "${dns%.}" "$name" "$vis"
        done
}

nw_zones_az() {
    nw_has_az || return 0
    az network dns zone list -o json 2>/dev/null | \
        jq -r '.[]? | ["az", (.name // ""), (.resourceGroup // ""), "-", (.numberOfRecordSets // "-" | tostring)] | @tsv' 2>/dev/null
}

nw_cmd_zones() {
    : > "$ZONE_FILE"
    local n=0 out line
    for collector in nw_zones_aws nw_zones_gcp nw_zones_az; do
        out="$("$collector")"
        [[ -z "$out" ]] && continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            n=$((n + 1))
            cs_row ZONE "$line"
            printf '%s\n' "$line" >> "$ZONE_FILE"
        done <<< "$out"
    done
    if [[ "$n" -eq 0 ]]; then
        cs_row PROVIDER all absent "$(nw_provider_summary)"
    fi
    cs_row SUMMARY "$n"
    [[ "$n" -gt 0 ]] && cs_row ARTIFACT "$ZONE_FILE"
    return 0
}

nw_provider_summary() {
    local p s out=""
    for p in $(nw_providers); do
        s="$(nw_provider_state "$p")"
        [[ "$s" == "creds-present" ]] && out="${out}${p}-ok " || out="${out}${p}-${s} "
    done
    printf '%s' "${out% }"
}

# Records for one zone. AWS wants a zone id, GCP wants a managed zone name,
# Azure wants zone and resource group — all three are normalised to
# name<TAB>type<TAB>value.
nw_records_aws() {
    local zone="$1"
    nw_has_aws || { cs_row PROVIDER aws absent "aws credentials unavailable"; return 0; }
    aws route53 list-resource-record-sets --hosted-zone-id "$zone" --output json 2>/dev/null | \
        jq -r '.ResourceRecordSets[]? | [.Name, .Type, ((.ResourceRecords // []) | map(.Value) | join(",")), (.AliasTarget.DNSName // "")] | @tsv' 2>/dev/null | \
        sed 's/\.$//' | head -n 2000
}

nw_records_gcp() {
    local zone="$1" project="$2"
    nw_has_gcp || { cs_row PROVIDER gcp absent "gcloud not authenticated"; return 0; }
    [[ -z "$project" ]] && project="$(gcloud config get-value project 2>/dev/null)"
    gcloud dns record-sets list --zone "$zone" --project "$project" \
        --format='csv[no-heading](NAME,TYPE,DATA)' 2>/dev/null | head -n 2000
}

nw_records_az() {
    local zone="$1" rg="$2"
    nw_has_az || { cs_row PROVIDER az absent "az not authenticated"; return 0; }
    az network dns record-set list -g "$rg" -z "$zone" -o json 2>/dev/null | \
        jq -r '.[]? | [(.fqdn // .name), (.type // "-"), ((.ARecords // .CNAMERecord // .TxtRecords // []) | tostring)] | @tsv' 2>/dev/null | head -n 2000
}

nw_cmd_records() {
    local zone="${1:-}" provider="${2:-}"
    if [[ -z "$zone" ]]; then
        nw_log "usage: --records <zone-id|zone-name> [provider] [resource-group]"
        return 2
    fi
    : > "$RECORD_FILE"
    local out=""
    case "${provider:-aws}" in
        aws) out="$(nw_records_aws "$zone")" ;;
        gcp) out="$(nw_records_gcp "$zone" "${3:-}")" ;;
        az)  out="$(nw_records_az "$zone" "${3:-}")" ;;
        *)   nw_log "unknown provider: $provider"; return 2 ;;
    esac
    if [[ -z "$out" ]]; then
        cs_row VERDICT "no-records" "$zone" "${provider:-aws}"
        return 0
    fi
    local n=0 name type value alias
    while IFS=$'\t' read -r name type value alias; do
        [[ -z "$name" ]] && continue
        n=$((n + 1))
        cs_row RECORD "$name" "$type" "${value:--}" "${alias:--}"
        printf '%s\t%s\t%s\t%s\n' "$name" "$type" "${value:--}" "${alias:--}" >> "$RECORD_FILE"
        # A CNAME into a host that does not exist is a takeover candidate, and
        # the finding is filed here so it does not depend on module 04 running.
        if [[ "$type" == "CNAME" && -n "$value" ]]; then
            local target="${value%,}"
            if [[ "$(nw_query "$target" A | head -1)" == "" ]]; then
                cs_row DANGLING "$name" "$target"
                cs_findings_row "$MODULE_ID" "TAKEOVER" "$name" "HIGH" "cname-dangling" \
                    "CNAME points at $target, which does not resolve"
            fi
        fi
    done <<< "$out"
    cs_row SUMMARY "$n"
    cs_row ARTIFACT "$RECORD_FILE"
    return 0
}

# What does this hostname resolve to, and does it still exist?
nw_cmd_resolve() {
    local name="${1:-}"
    [[ -z "$name" ]] && { nw_log "usage: --resolve <hostname>"; return 2; }
    local tool; tool="$(nw_dns_tool)"
    cs_row HOST "$name"
    cs_row RESOLVER "$tool"
    [[ "$tool" == "missing" ]] && { cs_row VERDICT "tool-missing"; return 0; }

    local type answers n=0
    for type in A AAAA CNAME MX TXT NS; do
        answers="$(nw_query "$name" "$type")"
        [[ -z "$answers" ]] && continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            n=$((n + 1))
            cs_row ANSWER "$type" "$line"
        done <<< "$answers"
    done
    if [[ "$n" -eq 0 ]]; then
        cs_row VERDICT "does-not-resolve"
        cs_findings_row "$MODULE_ID" "TAKEOVER" "$name" "MEDIUM" "name-not-resolving" \
            "hostname has no DNS answer, so whoever claims it gets the traffic"
    else
        cs_row VERDICT "resolves"
    fi
    cs_row SUMMARY "$n"
    return 0
}

# CNAMEs and NS delegations pointing at providers that will hand the name to
# the next person who asks for it.
nw_cmd_dangling() {
    local domain="${1:-}"
    [[ -z "$domain" ]] && { nw_log "usage: --dangling <domain>"; return 2; }
    local tool; tool="$(nw_dns_tool)"
    [[ "$tool" == "missing" ]] && { cs_row VERDICT "tool-missing"; return 0; }

    cs_row DOMAIN "$domain"
    cs_row RESOLVER "$tool"

    # Takeover fingerprints: the provider answers 404/no-such-bucket for a name
    # it does not own, which is exactly the gap a takeover lives in.
    local -a subs=(www api app cdn static assets img media files upload storage bucket
                   dev staging test demo shop blog docs support help status)
    local sub fqdn answer target n=0
    for sub in "${subs[@]}"; do
        fqdn="$sub.$domain"
        answer="$(nw_query "$fqdn" CNAME | head -1)"
        [[ -z "$answer" ]] && continue
        n=$((n + 1))
        cs_row CNAME "$fqdn" "$answer"
        case "$answer" in
            *.s3.amazonaws.com|*.s3.*.amazonaws.com|*.cloudfront.net|\
            *.azurewebsites.net|*.blob.core.windows.net|*.trafficmanager.net|\
            *.herokuapp.com|*.netlify.app|*.vercel.app|*.github.io|\
            *.fastly.net|*.edgekey.net|*.zendesk.com|*.readme.io|*.statuspage.io)
                target="$answer"
                if ! nw_query "$target" A | grep -q .; then
                    cs_row DANGLING "$fqdn" "$answer"
                    cs_findings_row "$MODULE_ID" "TAKEOVER" "$fqdn" "CRITICAL" "subdomain-takeover" \
                        "$sub.$domain points at $answer, a third-party host that no longer exists"
                else
                    cs_row TAKEOVER_RISK "$fqdn" "$answer"
                    cs_findings_row "$MODULE_ID" "TAKEOVER" "$fqdn" "MEDIUM" "takeover-candidate" \
                        "$sub.$domain points at takeover-prone host $answer"
                fi
                ;;
        esac
    done
    cs_row SUMMARY "$n"
    return 0
}

# ── subdomain takeover ───────────────────────────────────────────
# A host that the provider no longer claims is a hole with the tenant's name on
# it: whoever registers the target gets the certificate for the subdomain.
#   <id>\t<cname-suffix>\t<body-marker>\t<service>\t<how-the-claim-works>
nw_takeover_fingerprints() {
cat <<'TK'
github-pages	github.io	There isn't a GitHub Pages site here	GitHub Pages	claim the repo name
s3	amazonaws.com	NoSuchBucket	AWS S3 bucket	register the globally unique bucket name
s3-regional	s3.	NoSuchBucket	AWS S3 (regional)	register the bucket name
cloudfront	cloudfront.net	ERROR: The request could not be satisfied	AWS CloudFront	create a distribution with the same CNAME
azure	azurewebsites.net	404 Web Site not found	Azure Web App	register the app service name
azure-traffic	trafficmanager.net	Not Found	Azure Traffic Manager	create the profile name
heroku	herokuapp.com	No such app	Heroku App	claim the app name
fastly	fastly.net	Fastly error: unknown domain	Fastly CDN	attach the domain to a service
shopify	myshopify.com	Sorry, this shop is currently unavailable	Shopify	register the store handle
tumblr	tumblr.com	Whatever you were looking for doesn't live here	Tumblr	register the blog name
surge	surge.sh	project not found	Surge.sh	publish a project under the name
zendesk	zendesk.com	Help Center Closed	Zendesk	create the subdomain
netlify	netlify.app	Not Found - Request ID	Netlify	claim the site name
vercel	vercel.app	The deployment could not be found	Vercel	claim the project name
readme	readme.io	Project doesnt exist... yet!	ReadMe	create the project
statuspage	statuspage.io	Nothing to see here	Statuspage	create the status page
bitbucket	bitbucket.io	Repository not found	Bitbucket	claim the workspace
wordpress	wordpress.com	doesn’t exist	WordPress.com	claim the site name
cargo	cargocollective.com	404 Not Found	Cargo	claim the portfolio
uservoice	uservoice.com	This UserVoice subdomain is available!	UserVoice	claim the subdomain
instapage	instapage.com	The page you were looking for doesn't exist	Instapage	claim the page
pingdom	pingdom.com	This domain is not configured	Pingdom	claim the check
survey	surveymonkey.com	We couldn't find that survey	SurveyMonkey	claim the survey
TK

}

# What service does this CNAME point at, and does anything still answer for it?
#   nw_takeover_owner <cname>  ->  <id>\t<service>\t<claim>  (empty when unknown)
nw_takeover_owner() {
    local target="$1" id suffix marker service claim
    while IFS=$'\t' read -r id suffix marker service claim; do
        [[ -z "$suffix" ]] && continue
        case "$target" in
            *"$suffix"*) printf '%s\t%s\t%s\n' "$id" "$service" "$claim"; return 0 ;;
        esac
    done < <(nw_takeover_fingerprints)
    return 1
}

# The body marker is the proof. A CNAME to a dead host is a strong signal; a CNAME
# whose HTTP body says "No such app" is a confirmed claim-able hole.
#   nw_takeover_marker <cname-id> <body>  ->  <service>  or nothing
nw_takeover_marker() {
    local want="$1" body="$2" id suffix marker service claim
    while IFS=$'\t' read -r id suffix marker service claim; do
        [[ "$id" != "$want" || -z "$marker" ]] && continue
        if printf '%s' "$body" | grep -qF "$marker"; then
            printf '%s\n' "$service"
            return 0
        fi
    done < <(nw_takeover_fingerprints)
    return 1
}

# --takeover <domain>: the dangling half of --dangling plus the body proof.
nw_cmd_takeover() {
    local domain="${1:-}"
    [[ -z "$domain" ]] && { nw_log "usage: --takeover <domain>"; return 2; }
    local tool; tool="$(nw_dns_tool)"
    [[ "$tool" == "missing" ]] && { cs_row VERDICT "tool-missing"; return 0; }

    cs_row DOMAIN "$domain"
    cs_row RESOLVER "$tool"

    local -a subs=(www api app web app2 cdn static assets img images media files upload
                   storage bucket docs wiki support help status portal admin dev staging
                   stage test demo shop blog mail vpn)
    local sub fqdn answer owner n=0 hits=0 id service claim
    for sub in "${subs[@]}"; do
        fqdn="$sub.$domain"
        answer="$(nw_query "$fqdn" CNAME | head -1)"
        [[ -z "$answer" ]] && continue
        n=$((n + 1))
        cs_row CNAME "$fqdn" "$answer"

        owner="$(nw_takeover_owner "$answer")" || continue
        cs_split "$owner" id service claim

        # Does the target still resolve? A CNAME to a name nobody answers for is
        # claim-able without any HTTP at all.
        if ! nw_query "$answer" A | grep -q . ; then
            hits=$((hits + 1))
            cs_row CLAIMABLE "$fqdn" "$service" "target $answer does not resolve"
            cs_findings_row "$MODULE_ID" "DNS" "$fqdn" "CRITICAL" "subdomain-takeover" \
                "$fqdn points at $answer ($service), which nobody answers for — $claim"
            continue
        fi

        # It resolves, so the body decides: the provider saying "not my name"
        # means the name is free.
        local body code
        code="$(curl --silent --show-error --max-time "$NW_TIMEOUT" --output "$CS_SCRATCH/tk.$$" \
                    --write-out '%{http_code}' -A 'Mozilla/5.0 cloudsting/18' \
                    "https://$fqdn/" 2>/dev/null)" || code="000"
        body="$(head -c 65536 "$CS_SCRATCH/tk.$$" 2>/dev/null)"
        rm -f "$CS_SCRATCH/tk.$$"

        local marker
        if marker="$(nw_takeover_marker "$id" "$body")"; then
            hits=$((hits + 1))
            cs_row CLAIMABLE "$fqdn" "$service" "body says: $marker"
            cs_findings_row "$MODULE_ID" "DNS" "$fqdn" "CRITICAL" "subdomain-takeover" \
                "$fqdn points at $service and the target answers with its unclaimed page — $claim"
        else
            cs_row RISK "$fqdn" "$service" "code=$code" "$claim"
            cs_findings_row "$MODULE_ID" "DNS" "$fqdn" "MEDIUM" "takeover-candidate" \
                "$fqdn points at $service; target still claims the name but the trust is one lapse away"
        fi
    done
    cs_row SUMMARY "cnames=$n claimable=$hits"
    return 0
}

# --claim <url>: one host, no enumeration — what would I get if I registered it.
nw_cmd_claim() {
    local host="${1:-}"
    [[ -z "$host" ]] && { nw_log "usage: --claim <sub.domain.tld>"; return 2; }
    local tool; tool="$(nw_dns_tool)"
    [[ "$tool" == "missing" ]] && { cs_row VERDICT "tool-missing"; return 0; }

    cs_row HOST "$host"
    local cname; cname="$(nw_query "$host" CNAME | head -1)"
    if [[ -z "$cname" ]]; then
        cs_row CNAME "none"
        cs_row VERDICT "no-cname" "an A record cannot be taken over this way"
        return 1
    fi
    cs_row CNAME "$cname"

    local owner id service claim
    if ! owner="$(nw_takeover_owner "$cname")"; then
        cs_row SERVICE "unknown"
        cs_row VERDICT "not-claimable" "the target is not on the takeover-prone list"
        return 1
    fi
    cs_split "$owner" id service claim
    cs_row SERVICE "$service" "$id"
    cs_row CLAIM_METHOD "$claim"

    if ! nw_query "$cname" A | grep -q .; then
        cs_row VERDICT "vulnerable" "target does not resolve"
        cs_findings_row "$MODULE_ID" "DNS" "$host" "CRITICAL" "subdomain-takeover" \
            "$host → $cname ($service) does not resolve — $claim"
        return 0
    fi

    local body code
    code="$(curl --silent --show-error --max-time "$NW_TIMEOUT" --output "$CS_SCRATCH/cl.$$" \
                --write-out '%{http_code}' -A 'Mozilla/5.0 cloudsting/18' \
                "https://$host/" 2>/dev/null)" || code="000"
    body="$(head -c 65536 "$CS_SCRATCH/cl.$$" 2>/dev/null)"
    rm -f "$CS_SCRATCH/cl.$$"

    local marker
    if marker="$(nw_takeover_marker "$id" "$body")"; then
        cs_row VERDICT "vulnerable" "body: $marker"
        cs_findings_row "$MODULE_ID" "DNS" "$host" "CRITICAL" "subdomain-takeover" \
            "$host → $cname ($service) answers with its unclaimed page — $claim"
        return 0
    fi
    cs_row VERDICT "claimed" "target answers with its own content (code=$code)"
    return 1
}

# A zone transfer hands over the entire namespace in one answer. Rare, and
# catastrophic when open.
nw_cmd_axfr() {
    local domain="${1:-}" ns
    [[ -z "$domain" ]] && { nw_log "usage: --axfr <domain>"; return 2; }
    command -v dig >/dev/null 2>&1 || { cs_row VERDICT "tool-missing" "dig required for AXFR"; return 0; }
    [[ -z "$NW_DNS" ]] && { cs_row VERDICT "skipped" "set NW_DNS to the nameserver to test"; return 0; }

    cs_row DOMAIN "$domain"
    cs_row NAMESERVER "$NW_DNS"
    local out; out="$(dig +time="$NW_TIMEOUT" +tries=1 AXFR "$domain" "@$NW_DNS" 2>/dev/null)"
    if printf '%s' "$out" | grep -qE 'Transfer failed|communications error|SERVFAIL|REFUSED'; then
        cs_row AXFR "denied"
        return 0
    fi
    local n; n="$(printf '%s\n' "$out" | grep -cvE '^(;|$)' | tr -d ' ')"
    if [[ "${n:-0}" -eq 0 ]]; then
        cs_row AXFR "denied"
        return 0
    fi
    cs_row AXFR "open" "$n"
    printf '%s\n' "$out" | grep -vE '^(;|$)' | head -n 50 | while IFS= read -r line; do
        cs_row TRANSFER "$line"
    done
    cs_findings_row "$MODULE_ID" "EXPOSURE" "$domain" "CRITICAL" "axfr-open" \
        "zone transfer against $NW_DNS returned ${n} records"
    return 0
}

# ── VPC / subnet / route ─────────────────────────────────────────
nw_vpcs_aws() {
    nw_has_aws || return 0
    aws ec2 describe-vpcs --output json 2>/dev/null | \
        jq -r '.Vpcs[]? | ["aws", .VpcId, (.CidrBlock // "-"), (.IsDefault | tostring), (.State // "-"), (.Tags[]? | select(.Key=="Name") | .Value) // "-"] | @tsv' 2>/dev/null
}
nw_vpcs_gcp() {
    nw_has_gcp || return 0
    gcloud compute networks list --format='csv[no-heading](NAME,SUBNET_MODE,AUTO_SUBNET_MODE)' 2>/dev/null | \
        while IFS=, read -r name mode auto; do
            [[ -z "$name" ]] && continue
            printf 'gcp\t%s\t%s\t%s\t-\t-\n' "$name" "$mode" "$auto"
        done
}
nw_vpcs_az() {
    nw_has_az || return 0
    az network vnet list -o json 2>/dev/null | \
        jq -r '.[]? | ["az", .name, ((.addressSpace.addressPrefixes // []) | join(",")), "-", "-", (.resourceGroup // "-")] | @tsv' 2>/dev/null
}

nw_cmd_vpcs() {
    : > "$VPC_FILE"
    local n=0 out line
    for collector in nw_vpcs_aws nw_vpcs_gcp nw_vpcs_az; do
        out="$("$collector")"
        [[ -z "$out" ]] && continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            n=$((n + 1))
            cs_row VPC "$line"
            printf '%s\n' "$line" >> "$VPC_FILE"
        done <<< "$out"
    done
    [[ "$n" -eq 0 ]] && cs_row PROVIDER all absent "$(nw_provider_summary)"
    cs_row SUMMARY "$n"
    [[ "$n" -gt 0 ]] && cs_row ARTIFACT "$VPC_FILE"
    return 0
}

nw_subnets_aws() {
    nw_has_aws || return 0
    aws ec2 describe-subnets --output json 2>/dev/null | \
        jq -r '.Subnets[]? | ["aws", .VpcId, .SubnetId, (.CidrBlock // "-"), (.AvailabilityZone // "-"), (.MapPublicIpOnLaunch | tostring), (.Tags[]? | select(.Key=="Name") | .Value) // "-"] | @tsv' 2>/dev/null
}
nw_subnets_gcp() {
    nw_has_gcp || return 0
    gcloud compute networks subnets list --format='csv[no-heading](NAME,REGION,NETWORK,RANGE,PRIVATE_IP_GOOGLE_ACCESS)' 2>/dev/null | \
        while IFS=, read -r name region network range priv; do
            [[ -z "$name" ]] && continue
            printf 'gcp\t%s\t%s\t%s\t%s\t%s\n' "$network" "$name" "$range" "$region" "$priv"
        done
}
nw_subnets_az() {
    nw_has_az || return 0
    az network vnet subnet list --ids "$(az network vnet list --query '[].id' -o tsv 2>/dev/null | tr '\n' ' ')" -o json 2>/dev/null | \
        jq -r '.[]? | ["az", (.id | split("/vnet/")[0] | split("/")[-1]), .name, ((.addressPrefix // (.addressPrefixes | join(","))) // "-"), "-", "-"] | @tsv' 2>/dev/null
}

nw_cmd_subnets() {
    : > "$SUBNET_FILE"
    local n=0 out line
    for collector in nw_subnets_aws nw_subnets_gcp nw_subnets_az; do
        out="$("$collector")"
        [[ -z "$out" ]] && continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            n=$((n + 1))
            cs_row SUBNET "$line"
            printf '%s\n' "$line" >> "$SUBNET_FILE"
            # A subnet that auto-assigns public addresses is a subnet whose
            # workloads are one security group mistake from the internet.
            local autopub
            autopub="$(printf '%s' "$line" | awk -F'\t' '{print $6}')"
            if [[ "$autopub" == "true" ]]; then
                cs_findings_row "$MODULE_ID" "SURFACE" "$(printf '%s' "$line" | awk -F'\t' '{print $3}')" "MEDIUM" \
                    "subnet-auto-public-ip" "subnet assigns public addresses on launch"
            fi
        done <<< "$out"
    done
    [[ "$n" -eq 0 ]] && cs_row PROVIDER all absent "$(nw_provider_summary)"
    cs_row SUMMARY "$n"
    [[ "$n" -gt 0 ]] && cs_row ARTIFACT "$SUBNET_FILE"
    return 0
}

nw_routes_aws() {
    nw_has_aws || return 0
    aws ec2 describe-route-tables --output json 2>/dev/null | \
        jq -r '.RouteTables[]? | . as $t | .Routes[]? |
            ["aws", $t.VpcId, $t.RouteTableId,
             (.DestinationCidrBlock // .DestinationIpv6CidrBlock // .DestinationPrefixListId // "-"),
             (.GatewayId // .NatGatewayId // .TransitGatewayId // .VpcPeeringConnectionId // .NetworkInterfaceId // .InstanceId // "local"),
             (.State // "-")] | @tsv' 2>/dev/null
}
nw_routes_gcp() {
    nw_has_gcp || return 0
    gcloud compute routes list --format='csv[no-heading](NAME,NETWORK,DEST_RANGE,NEXT_HOP_GATEWAY,NEXT_HOP_INSTANCE,PRIORITY)' 2>/dev/null | \
        while IFS=, read -r name network dest gw inst prio; do
            [[ -z "$name" ]] && continue
            printf 'gcp\t%s\t%s\t%s\t%s\t%s\n' "$network" "$name" "$dest" "${gw:-${inst:--}}" "$prio"
        done
}

nw_cmd_routes() {
    : > "$ROUTE_FILE"
    local n=0 out line
    for collector in nw_routes_aws nw_routes_gcp; do
        out="$("$collector")"
        [[ -z "$out" ]] && continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            n=$((n + 1))
            cs_row ROUTE "$line"
            printf '%s\n' "$line" >> "$ROUTE_FILE"
        done <<< "$out"
    done
    [[ "$n" -eq 0 ]] && cs_row PROVIDER all absent "$(nw_provider_summary)"
    cs_row SUMMARY "$n"
    [[ "$n" -gt 0 ]] && cs_row ARTIFACT "$ROUTE_FILE"
    return 0
}

# Gateways are the doors: internet gateway means the VPC is routable from
# outside, peering and transit mean it reaches somewhere it should not.
nw_gateways_aws() {
    nw_has_aws || return 0
    aws ec2 describe-internet-gateways --output json 2>/dev/null | \
        jq -r '.InternetGateways[]? | ["internet-gateway", .InternetGatewayId, (([.Attachments[]?.VpcId] | join(",")) // "-"), (.State // "-")] | @tsv' 2>/dev/null
    aws ec2 describe-transit-gateways --output json 2>/dev/null | \
        jq -r '.TransitGateways[]? | ["transit-gateway", .TransitGatewayId, .State, (.Description // "-")] | @tsv' 2>/dev/null
    aws ec2 describe-nat-gateways --output json 2>/dev/null | \
        jq -r '.NatGateways[]? | ["nat-gateway", .NatGatewayId, (.VpcId // "-"), (.State // "-")] | @tsv' 2>/dev/null
    aws ec2 describe-vpc-peering-connections --output json 2>/dev/null | \
        jq -r '.VpcPeeringConnections[]? | ["vpc-peering", .VpcPeeringConnectionId, ((.RequesterVpcInfo.VpcId // "-") + "->" + (.AccepterVpcInfo.VpcId // "-")), (.Status.Code // "-")] | @tsv' 2>/dev/null
}

nw_cmd_gateways() {
    : > "$GW_FILE"
    local n=0 out line
    out="$(nw_gateways_aws)"
    if [[ -n "$out" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            n=$((n + 1))
            cs_row GATEWAY "$line"
            printf '%s\n' "$line" >> "$GW_FILE"
            local kind
            kind="$(printf '%s' "$line" | awk -F'\t' '{print $1}')"
            case "$kind" in
                internet-gateway)
                    cs_findings_row "$MODULE_ID" "SURFACE" "$(printf '%s' "$line" | awk -F'\t' '{print $2}')" "INFO" \
                        "internet-gateway" "VPC has a direct internet path"
                    ;;
                vpc-peering)
                    cs_findings_row "$MODULE_ID" "SURFACE" "$(printf '%s' "$line" | awk -F'\t' '{print $3}')" "MEDIUM" \
                        "vpc-peering" "a peering connection crosses a trust boundary"
                    ;;
            esac
        done <<< "$out"
    fi
    [[ "$n" -eq 0 ]] && cs_row PROVIDER aws absent "$(nw_provider_state aws)"
    cs_row SUMMARY "$n"
    [[ "$n" -gt 0 ]] && cs_row ARTIFACT "$GW_FILE"
    return 0
}

# ── firewall rules ───────────────────────────────────────────────
nw_rules_aws() {
    nw_has_aws || return 0
    aws ec2 describe-security-groups --output json 2>/dev/null | \
        jq -r 'try (.SecurityGroups[]? | . as $g |
                  ( ($g.GroupId // "") + "/" + ($g.GroupName // "") ) as $id |
                  ( $g.IpPermissions[]? |
                    [ $id, "ingress", (.IpProtocol // ""),
                      (if .FromPort == null then "-" else (.FromPort | tostring) end),
                      (if .ToPort == null then "-" else (.ToPort | tostring) end),
                      (([.IpRanges[]?.CidrIp, .Ipv6Ranges[]?.CidrIpv6, .UserIdGroupPairs[]?.GroupId]
                        | map(select(. != null)) | join(",")) as $c | if $c == "" then "-" else $c end),
                      ((.IpProtocol // "") | if . == "-1" then "all-traffic" else "-" end)
                    ] | @tsv ) )' 2>/dev/null
}

nw_rules_gcp() {
    nw_has_gcp || return 0
    gcloud compute firewall-rules list --format=json 2>/dev/null | \
        jq -r 'try (.[]? | . as $r |
                  ( ($r.name // "") + "/fw" ) as $id |
                  [ $id, (if ($r.direction // "INGRESS") == "INGRESS" then "ingress" else "egress" end),
                    (($r.allowed // []) | map(.IPProtocol) | join(",")),
                    (([($r.allowed // [])[]?.ports[]?] | map(tostring) | join(",")) // ""),
                    "",
                    (([$r.sourceRanges[]?] | join(",")) // ""),
                    (($r.disabled // false) | if . then "disabled" else "-" end)
                  ] | @tsv)' 2>/dev/null
}

nw_rules_az() {
    nw_has_az || return 0
    az network nsg list -o json 2>/dev/null | \
        jq -r 'try (.[]? | . as $n |
                  ( ($n.resourceGroup // "") + "/" + ($n.name // "") ) as $id |
                  ( ($n.securityRules // [])[]? |
                    [ $id, (.direction // "" | ascii_downcase), (.protocol // ""),
                      (.destinationPortRange // ((.destinationPortRanges // []) | join(",")) // "-"),
                      "",
                      (.sourceAddressPrefix // ((.sourceAddressPrefixes // []) | join(",")) // "-"),
                      (if (.access // "") == "Allow" then "-" else "deny" end)
                    ] | @tsv ) )' 2>/dev/null
}

nw_collect_rules() {
    local p state found=0
    : > "$RULE_FILE"
    for p in $(nw_providers); do
        state="$(nw_provider_state "$p")"
        if [[ "$state" != "creds-present" ]]; then
            cs_row PROVIDER "$p" "$state"
            continue
        fi
        found=1
        case "$p" in
            aws) nw_rules_aws ;;
            gcp) nw_rules_gcp ;;
            az)  nw_rules_az ;;
        esac 2>/dev/null | tee -a "$RULE_FILE"
    done
    [[ "$found" -eq 0 ]] && cs_row NOTE "no provider reachable; nothing collected"
    return 0
}

nw_cmd_rules() {
    local n=0 line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$line" == PROVIDER$'\t'* || "$line" == NOTE$'\t'* ]]; then
            printf '%s\n' "$line"
            continue
        fi
        n=$((n + 1))
        cs_row RULE "$line"
    done < <(nw_collect_rules)
    cs_row SUMMARY "$n"
    [[ -n "$RULE_FILE" && -s "$RULE_FILE" ]] && cs_row ARTIFACT "$RULE_FILE"
    return 0
}

# A world-open admin or database port is a different finding from a
# world-open 443. This list is short on purpose: these are the ones that end
# up in incident reports.
nw_port_severity() {
    case "${1:-}" in
        22|2222|3389|5985|5986)          printf 'critical' ;;
        3306|5432|1433|1521|27017|27018) printf 'critical' ;;
        6379|9200|9300|11211|5672|15672) printf 'critical' ;;
        23|21|512|513|514)               printf 'critical' ;;
        445|139|2049)                    printf 'high' ;;
        2375|2376|6443|10250|10255)      printf 'high' ;;
        8080|8443|8000|8888|9000|5601)   printf 'medium' ;;
        80|443)                          printf 'low' ;;
        *)                               printf 'medium' ;;
    esac
}

# A range is graded by the worst port it contains: 0-65535 is not "port 0".
nw_range_severity() {
    local from="${1:-}" to="${2:-}" port sev worst="low"
    [[ -z "$to" || "$to" == "-" ]] && to="$from"
    for port in 22 2222 3389 5985 5986 3306 5432 1433 1521 27017 27018 \
                6379 9200 9300 11211 5672 15672 23 21 512 513 514 \
                445 139 2049 2375 2376 6443 10250 10255; do
        [[ "$port" -ge "$from" ]] 2>/dev/null && [[ "$port" -le "$to" ]] 2>/dev/null || continue
        sev="$(nw_port_severity "$port")"
        case "$sev" in
            critical) printf 'critical'; return 0 ;;
            high)     worst="high" ;;
        esac
    done
    printf '%s' "$worst"
}

nw_is_world() {
    case "${1:-}" in
        *"0.0.0.0/0"*|*"::/0"*) return 0 ;;
        *) return 1 ;;
    esac
}

nw_cmd_audit() {
    nw_collect_rules > /dev/null 2>&1 || true
    if [[ ! -s "$RULE_FILE" ]]; then
        cs_row VERDICT "no-rules-collected" "$(nw_provider_summary)"
        return 0
    fi

    : > "$FIND_FILE"
    local group dir proto from to cidr note sev port total=0
    while IFS=$'\t' read -r group dir proto from to cidr note; do
        [[ -z "${group:-}" ]] && continue
        [[ "$dir" == "egress" ]] && continue
        [[ "$note" == "disabled" || "$note" == "deny" ]] && continue
        [[ "$from" == "-" ]] && from=""
        [[ "$to" == "-" ]] && to=""
        [[ "$cidr" == "-" ]] && cidr=""
        nw_is_world "$cidr" || continue

        if [[ -z "$from" ]]; then
            sev="critical"; port="all"
            printf '%s\t%s\t%s\tworld-open: every port and protocol\n' "$sev" "$group" "$port" >> "$FIND_FILE"
        elif [[ "$to" != "$from" && -n "$to" ]]; then
            sev="$(nw_range_severity "$from" "$to")"; port="$from-$to"
            printf '%s\t%s\t%s\tworld-open range %s-%s\n' "$sev" "$group" "$port" "$from" "$to" >> "$FIND_FILE"
        else
            sev="$(nw_port_severity "$from")"; port="$from"
            printf '%s\t%s\t%s\tworld-open port %s\n' "$sev" "$group" "$port" "$from" >> "$FIND_FILE"
        fi
        total=$((total + 1))
    done < "$RULE_FILE"

    if [[ "$total" -eq 0 ]]; then
        cs_row VERDICT "clean" "no world-open ingress rules"
        cs_findings_row "$MODULE_ID" "EXPOSURE" "firewall" "clean" "no-world-open" \
            "no security group admits 0.0.0.0/0 on ingress"
        return 0
    fi

    local s c
    while IFS=$'\t' read -r s c port note; do
        cs_row RULE_FINDING "$s" "$c" "$port" "$note"
        cs_findings_row "$MODULE_ID" "EXPOSURE" "$c" "$s" "world-open-$port" "$note"
    done < "$FIND_FILE"

    local counts
    counts="$(awk -F'\t' '{c[$1]++} END {for (k in c) printf "%s=%d ", k, c[k]}' "$FIND_FILE" 2>/dev/null)"
    cs_row SUMMARY "${counts:-none}"
    cs_row ARTIFACT "$FIND_FILE"
    return 0
}

# The network in one view: which subnets are public, which rules admit the
# world, and which gateways make it routable.
nw_cmd_map() {
    cs_row SECTION "subnets"
    nw_cmd_subnets
    cs_row SECTION "gateways"
    nw_cmd_gateways
    cs_row SECTION "firewall"
    nw_cmd_audit
    return 0
}

nw_cmd_all() {
    cs_row SECTION "zones"
    nw_cmd_zones
    cs_row SECTION "vpc"
    nw_cmd_vpcs
    cs_row SECTION "map"
    nw_cmd_map
    return 0
}

nw_cmd_list() {
    cs_row GROUP "naming"      "zones records resolve dangling axfr"
    cs_row GROUP "topology"    "vpcs subnets routes gateways"
    cs_row GROUP "exposure"    "rules audit map"
    return 0
}

nw_cmd_status_tsv() {
    printf '%s\t%s\tdns-%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "$(nw_dns_tool)" "$(nw_provider_summary)"
}

nw_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

nw_cmd_help() {
    cat <<'HELP'
cloudsting module 18 — Cloud Network v1.0.0
 naming
  --zones                        hosted zones (Route53, Cloud DNS, Azure DNS)
  --records <zone> [prov] [rg]   records in a zone; CNAMEs are checked
  --resolve <hostname>           A/AAAA/CNAME/MX/TXT/NS for one name
  --dangling <domain>            subdomains pointed at takeover-prone hosts
  --takeover <domain>            DNS sweep + body proof of a claimable subdomain
  --claim <sub.domain>           one host: what would I get if I registered it
  --fingerprints                 the takeover table (24 services)
  --axfr <domain>                zone transfer attempt (needs NW_DNS)
 topology
  --vpcs                         VPCs / VNets across clouds
  --subnets                      subnets, flags auto-public subnets
  --routes                       route tables and their next hops
  --gateways                     IGWs, NATs, transit gateways, peerings
 exposure
  --rules                        every firewall rule, normalised
  --audit                        world-open ingress, graded by port
  --map                          subnets + gateways + firewall, one view
  --all                          everything above
 shape
  --list | --status-tsv | --menu | --selftest | --help

DNS, VPC and firewall are one network seen at three layers. --dangling finds
the name that points nowhere, --audit finds the rule that admits the world,
--map ties them together: a public subnet with a world-open database port and
a subdomain pointing at it is a single finding, not three. --audit grades by
port, because a world-open 443 is the point and a world-open 5432 is an
incident.

Environment: NW_TIMEOUT (10), NW_DNS (resolver to query; required for --axfr)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
nw_selftest() {
    cs_selftest_reset

    # resolver detection always answers
    chk dns-tool "$(nw_dns_tool | grep -cE '^(dig|host|nslookup|getent|explicit|missing)$')" "1"

    # provider gate answers for all three
    chk prov-lines "$(for p in $(nw_providers); do nw_provider_state "$p"; echo; done | grep -c .)" "3"
    chk prov-state "$(for p in $(nw_providers); do nw_provider_state "$p"; echo; done | grep -cE '^(creds-present|creds-missing|tool-missing|unknown)$')" "3"

    # port grading: the list that matters
    chk port-ssh      "$(nw_port_severity 22)"    "critical"
    chk port-rdp      "$(nw_port_severity 3389)"  "critical"
    chk port-mysql    "$(nw_port_severity 3306)"  "critical"
    chk port-redis    "$(nw_port_severity 6379)"  "critical"
    chk port-https    "$(nw_port_severity 443)"   "low"
    chk port-docker   "$(nw_port_severity 2375)"  "high"
    chk port-9050     "$(nw_port_severity 9050)"  "medium"

    # a range is graded by its worst port, not its first
    chk range-all-db  "$(nw_range_severity 0 65535)"   "critical"
    chk range-web     "$(nw_range_severity 80 80)"     "low"
    # 80-443 spans 139 and 445, so it is graded high on purpose: a range is
    # only as safe as the worst port inside it, and the first port is a lie.
    chk range-web-445 "$(nw_range_severity 80 443)"    "high"
    chk range-quiet   "$(nw_range_severity 400 440)"   "low"

    # world detection
    nw_is_world "0.0.0.0/0";  chk world-v4 "$?" "0"
    nw_is_world "::/0";       chk world-v6 "$?" "0"
    nw_is_world "10.0.0.0/8"; chk world-private "$?" "1"

    # collection degrades honestly without credentials
    local out; out="$(nw_cmd_audit 2>/dev/null)"
    chk audit-runs "$(printf '%s' "$out" | awk -F'\t' 'NF<2{c++} END{print c+0}')" "0"
    chk audit-verdict "$(printf '%s' "$out" | grep -c '^VERDICT')" "1"

    # usage errors
    local rc
    nw_cmd_records 2>/dev/null; rc=$?
    chk records-usage "$rc" "2"
    nw_cmd_resolve 2>/dev/null; rc=$?
    chk resolve-usage "$rc" "2"
    nw_cmd_dangling 2>/dev/null; rc=$?
    chk dangling-usage "$rc" "2"
    nw_cmd_takeover 2>/dev/null; rc=$?
    chk takeover-usage "$rc" "2"
    nw_cmd_claim 2>/dev/null; rc=$?
    chk claim-usage "$rc" "2"

    # the takeover table: every row is five columns and the suffix is real
    chk tk-rows    "$(nw_takeover_fingerprints | grep -c .)" "23"
    chk tk-cols    "$(nw_takeover_fingerprints | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk tk-github  "$(nw_takeover_owner 'acme.github.io' | cut -f2)" "GitHub Pages"
    chk tk-s3      "$(nw_takeover_owner 'acme-assets.s3.amazonaws.com' | cut -f2)" "AWS S3 bucket"
    chk tk-heroku  "$(nw_takeover_owner 'acme-prod.herokuapp.com' | cut -f2)" "Heroku App"
    nw_takeover_owner 'acme.example.com'
    chk tk-unknown "$?" "1"
    chk tk-marker    "$(nw_takeover_marker s3 'Error: NoSuchBucket the bucket does not exist')" "AWS S3 bucket"
    chk tk-marker-no "$(nw_takeover_marker s3 '<html><title>Welcome</title></html>' | wc -l | tr -d ' ')" "0"

    # shape contracts
    chk status-fields "$(nw_cmd_status_tsv | awk -F'\t' '{print NF}')" "4"
    chk status-module "$(nw_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(nw_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(nw_cmd_help | head -1 | grep -ci 'Cloud Network')" "1"
    chk list-groups   "$(nw_cmd_list | grep -c '^GROUP')" "3"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --zones)     shift; nw_cmd_zones "$@";;
    --records)   shift; nw_cmd_records "$@";;
    --resolve)   shift; nw_cmd_resolve "$@";;
    --dangling)  shift; nw_cmd_dangling "$@";;
    --takeover)  shift; nw_cmd_takeover "$@";;
    --claim)     shift; nw_cmd_claim "$@";;
    --fingerprints|--services) nw_takeover_fingerprints;;
    --axfr)      shift; nw_cmd_axfr "$@";;
    --vpcs)      shift; nw_cmd_vpcs "$@";;
    --subnets)   shift; nw_cmd_subnets "$@";;
    --routes)    shift; nw_cmd_routes "$@";;
    --gateways)  shift; nw_cmd_gateways "$@";;
    --rules)     shift; nw_cmd_rules "$@";;
    --audit)     shift; nw_cmd_audit "$@";;
    --map)       shift; nw_cmd_map "$@";;
    --all)       nw_cmd_all;;
    --list)      nw_cmd_list;;
    --status-tsv|--status) nw_cmd_status_tsv;;
    --menu)      nw_cmd_menu;;
    --selftest)  nw_selftest;;
    *)           nw_cmd_help;;
esac
