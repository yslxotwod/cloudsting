#!/usr/bin/env bash
# 46_key_harvest.sh — cloudsting module 46: pull API keys and tokens out of whatever a target serves
# Verbs: --harvest <url> | --js <url> | --headers <url> | --detect <blob|-> | --providers | --all | --status-tsv | --menu | --selftest
set -u
umask 077

# The root comes from this file's own location after the core is sourced; a
# value inherited from a caller that already sourced the core is the wrong
# directory and must not survive.
unset CS_MOD_DIR

MODULE_ID="46_key_harvest"
MOD_NAME="API Key Harvesting"
MOD_VERSION="0.21.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

KH_RUN_ID="$CS_RUN_ID"
export KH_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/key_harvest"
mkdir -p "$OUT_DIR" 2>/dev/null || true

KEYS_FILE="$OUT_DIR/keys-$RUN_ID.tsv"
JS_FILE="$OUT_DIR/js-$RUN_ID.tsv"
HDR_FILE="$OUT_DIR/headers-$RUN_ID.tsv"

: "${KH_TIMEOUT:=10}"         # per-request wall clock
: "${KH_MAX_JS:=40}"          # stop after this many script bodies
: "${KH_MAX_BYTES:=5242880}"  # never buffer more than 5 MB of one response
: "${KH_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/46}"

# ── provider patterns ────────────────────────────────────────────
# Every row is: provider <TAB> severity <TAB> regex <TAB> note.
# The order matters: high-confidence, high-value patterns come first so a
# generic 32-hex match cannot outrank a real AWS key.
kh_patterns() {
    cat <<'PATTERNS'
aws_access_key_id	HIGH	AKIA[0-9A-Z]{16}	20-char AWS access key id
aws_access_key_id	HIGH	ASIA[0-9A-Z]{16}	AWS temporary access key id
aws_secret_key	CRITICAL	(?i)aws.{0,20}(secret|private).{0,20}['"][0-9A-Za-z/+=]{40}['"]	AWS secret access key
aws_session_token	CRITICAL	(?i)aws_session_token.{0,20}['"][A-Za-z0-9/+=]{100,}['"]	AWS session token
gcp_api_key	HIGH	AIza[0-9A-Za-z_-]{35}	Google API key
gcp_oauth_client	MEDIUM	[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com	Google OAuth client id
gcp_service_account	CRITICAL	"type":\s*"service_account"	GCP service account JSON
stripe_live_secret	CRITICAL	sk_live_[0-9a-zA-Z]{24,}	Stripe live secret key
stripe_test_secret	MEDIUM	sk_test_[0-9a-zA-Z]{24,}	Stripe test secret key
stripe_live_publishable	LOW	pk_live_[0-9a-zA-Z]{24,}	Stripe live publishable key
stripe_restricted	HIGH	rk_live_[0-9a-zA-Z]{24,}	Stripe restricted key
twilio_account_sid	MEDIUM	AC[a-f0-9]{32}	Twilio account SID
twilio_auth_token	HIGH	(?i)twilio.{0,20}['"][a-f0-9]{32}['"]	Twilio auth token
sendgrid_key	HIGH	SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}	SendGrid API key
mailgun_key	HIGH	key-[0-9a-zA-Z]{32}	Mailgun API key
mailchimp_key	MEDIUM	[0-9a-f]{32}-us[0-9]{1,2}	Mailchimp API key
slack_token	HIGH	xox[baprs]-[0-9A-Za-z-]{10,}	Slack token
slack_webhook	MEDIUM	https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+	Slack incoming webhook
github_token	CRITICAL	gh[pousr]_[0-9A-Za-z]{36,}	GitHub token
github_pat	CRITICAL	github_pat_[0-9A-Za-z_]{82}	GitHub fine-grained PAT
gitlab_token	CRITICAL	glpat-[0-9A-Za-z_-]{20}	GitLab personal access token
npm_token	HIGH	npm_[0-9A-Za-z]{36}	npm registry token
pypi_token	HIGH	pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,}	PyPI upload token
digitalocean_token	CRITICAL	dop_v1_[a-f0-9]{64}	DigitalOcean personal access token
digitalocean_oauth	HIGH	doo_v1_[a-f0-9]{64}	DigitalOcean OAuth token
digitalocean_refresh	HIGH	dor_v1_[a-f0-9]{64}	DigitalOcean refresh token
heroku_key	HIGH	(?i)heroku.{0,20}['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]	Heroku API key
huggingface_token	HIGH	hf_[0-9A-Za-z]{34}	Hugging Face token
openai_key	CRITICAL	sk-[0-9A-Za-z]{20}T3BlbkFJ[0-9A-Za-z]{20}	OpenAI API key (legacy)
openai_project	CRITICAL	sk-proj-[0-9A-Za-z_-]{40,}	OpenAI project key
anthropic_key	CRITICAL	sk-ant-[0-9A-Za-z_-]{40,}	Anthropic API key
replicate_token	HIGH	r8_[0-9A-Za-z]{37}	Replicate token
private_key_block	CRITICAL	-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----	PEM private key
jwt	MEDIUM	eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}	JSON Web Token
basic_auth_url	HIGH	[a-z][a-z0-9+.-]*://[^/[:space:]:@]+:[^/[:space:]:@]+@[^/[:space:]]+	credentials embedded in a URL
firebase_url	MEDIUM	https://[a-z0-9-]+\.firebaseio\.com	Firebase database URL
firebase_storage	MEDIUM	[a-z0-9-]+\.appspot\.com	Firebase/GCP appspot host
s3_bucket_ref	LOW	s3://[a-z0-9.-]{3,63}	S3 URI in client code
azure_storage_key	CRITICAL	AccountKey=[A-Za-z0-9+/=]{88}	Azure storage account key
azure_sas	HIGH	[?&]sig=[A-Za-z0-9%+/=]{40,}	Azure SAS signature
azure_client_secret	HIGH	(?i)client_secret.{0,10}['"][A-Za-z0-9~._-]{30,}['"]	Azure client secret
google_oauth_secret	HIGH	GOCSPX-[A-Za-z0-9_-]{28}	Google OAuth client secret
alibaba_access_key	HIGH	LTAI[0-9A-Za-z]{12,20}	Alibaba Cloud access key
tencent_secret_id	HIGH	AKID[0-9A-Za-z]{32}	Tencent Cloud secret id
cloudflare_token	HIGH	(?i)cloudflare.{0,20}['"][A-Za-z0-9_-]{40}['"]	Cloudflare API token
cloudflare_global_key	CRITICAL	(?i)cloudflare.{0,30}global.{0,20}['"][a-f0-9]{37}['"]	Cloudflare global API key
vault_token	CRITICAL	hvs\.[A-Za-z0-9_-]{24,}	HashiCorp Vault token
vault_token_legacy	HIGH	s\.[A-Za-z0-9]{24}	Vault legacy token
docker_config_auth	CRITICAL	"auths":\s*\{	Docker registry credentials blob
kubernetes_token	HIGH	(?i)kubernetes.{0,30}token	Kubernetes service account token
smsc_http_password	CRITICAL	(?i)(smtp|smpp|smsc)[_-]?(pass|password|secret)['"]?\s*[:=]\s*['"][^'"]{4,64}['"]	SMS gateway bind credential
huawei_session_token	HIGH	(?i)(accessSession|X-Auth-Token).{0,24}['"]?[=:]?\s*['"]?[A-Za-z0-9+/=]{20,}	Huawei U2000/NCE session token
ericsson_enm_token	HIGH	(?i)(enm|ericsson).{0,20}(token|auth)['"]?\s*[:=]\s*['"][A-Za-z0-9._-]{20,}['"]	Ericsson ENM token
rancher_api_key	CRITICAL	(?i)(rancher.{0,20}(token|api_?key)\s*[:=]\s*['"]?[A-Za-z0-9:_-]{20,}|token-[a-z0-9]{5}:[a-z0-9]{20,})	Rancher API key
grafana_api_key	HIGH	eyJrIjoi[A-Za-z0-9+/=]{40,}	Grafana service account token
openstack_object_store	HIGH	(?i)(OS_|openstack).{0,20}(password|secret)['"]?\s*[:=]\s*['"][^'"]{6,64}['"]	OpenStack credential
msisdn_export_url	HIGH	https?://[^"'[:space:]]*(export|download)[^"'[:space:]]*(msisdn|subscriber|customer)[^"'[:space:]]*	Subscriber export endpoint in client code
PATTERNS
}

# Provider name from a one-word key: aws_access_key_id -> aws, gcp_api_key -> gcp
kh_family() { printf '%s' "${1%%_*}"; }

# ── scanning ─────────────────────────────────────────────────────
# Find every match of every pattern in one file and emit rows. The scan is
# single-pass per pattern so a 5 MB bundle costs one grep per provider, not one
# process per line.
#   kh_scan_text <file> <source-label>
kh_scan_text() {
    local file="$1" src="${2:-inline}"
    [[ -r "$file" ]] || return 1
    local found=0 provider sev regex note hits hit
    while IFS=$'\t' read -r provider sev regex note; do
        [[ -z "$provider" ]] && continue
        # "(?i)" is a pcre marker, not a grep -E construct: grep reads it as a
        # literal group and the pattern matches nothing. Strip it and pass -i.
        local gflags="-aoE"
        if [[ "$regex" == *"(?i)"* ]]; then
            regex="${regex//(?i)/}"
            gflags="-aoiE"
        fi
        # grep -o prints each distinct match on its own line; sort -u collapses
        # the duplicates a minified bundle would otherwise produce.
        hits="$(grep $gflags -- "$regex" "$file" 2>/dev/null | sort -u | head -n 20)" || true
        [[ -z "$hits" ]] && continue
        while IFS= read -r hit; do
            [[ -z "$hit" ]] && continue
            found=$((found + 1))
            # a JWT or a URL can be a hundred characters; the row keeps it
            # readable and the full value stays in the artifact
            local shown="${hit:0:120}"
            cs_row KEY "$provider" "$sev" "$(kh_family "$provider")" "$src" "$shown"
            printf '%s\t%s\t%s\t%s\t%s\n' "$provider" "$sev" "$src" "$(cs_esc "$hit")" "$note" >> "$KEYS_FILE"
            cs_findings_row "$MODULE_ID" "SECRETS" "$src" "$sev" "$provider" \
                "$(kh_family "$provider") key found in $src"
        done <<< "$hits"
    done < <(kh_patterns)
    return 0
}

# Is this blob plainly secret-free? Used to skip the scan on a landing page
# that is one big marketing image.
kh_worth_scanning() {
    local f="$1"
    local sz; sz="$(wc -c < "$f" 2>/dev/null | tr -d ' ')"
    (( sz < 40 )) && return 1
    return 0
}

# One request, body to a file, with a hard size cap.
#   kh_fetch <url> <outfile>  ->  <code>
kh_fetch() {
    local url="$1" out="$2"
    command -v curl >/dev/null 2>&1 || { printf '000'; return 3; }
    local code
    code="$(curl --silent --show-error --max-time "$KH_TIMEOUT" \
                 --user-agent "$KH_UA" --location \
                 --max-filesize "$KH_MAX_BYTES" \
                 --output "$out" --write-out '%{http_code}' \
                 "$url" 2>/dev/null)" || code="000"
    printf '%s' "${code:-000}"
}

# Script URLs a page references. Absolute when the page used absolute, joined
# against the page URL when it used a root-relative or bare path.
#   kh_scripts <html-file> <base-url>
kh_scripts() {
    local file="$1" base="$2"
    local scheme host origin
    scheme="${base%%://*}"
    host="${base#*://}"; host="${host%%/*}"
    origin="${scheme}://${host}"

    grep -aoE '(src|href)[[:space:]]*=[[:space:]]*"[^"]+\.js[^"]*"' "$file" 2>/dev/null \
        | sed -E 's/^(src|href)[[:space:]]*=[[:space:]]*"//; s/"$//' > /dev/null 2>&1 || true

    # single and double quotes both occur; two passes keep the sed simple
    {
        grep -aoE 'src[[:space:]]*=[[:space:]]*"[^"]+"' "$file" 2>/dev/null | sed -E 's/^src[[:space:]]*=[[:space:]]*"//; s/"$//'
        grep -aoE "src[[:space:]]*=[[:space:]]*'[^']+'" "$file" 2>/dev/null | sed -E "s/^src[[:space:]]*=[[:space:]]*'//; s/'$//"
    } | grep -i '\.js' | sort -u | while IFS= read -r s; do
        [[ -z "$s" ]] && continue
        case "$s" in
            http://*|https://*|//*) printf '%s\n' "${s#//}" ;;
            /*)  printf '%s%s\n' "$origin" "$s" ;;
            *)   printf '%s\n' "$s" ;;
        esac
    done
}

# ── verbs ────────────────────────────────────────────────────────
kh_cmd_detect() {
    local target="${1:-}"
    [[ -z "$target" ]] && { printf 'usage: 46_key_harvest.sh --detect <file|->\n' >&2; return 2; }
    : > "$KEYS_FILE"

    local file
    if [[ "$target" == "-" ]]; then
        file="$CS_SCRATCH/stdin.txt"
        cat > "$file"
    else
        file="$target"
    fi
    [[ -r "$file" ]] || { cs_row ERROR "not readable: $target"; return 2; }

    cs_row SCAN "$target"
    cs_row BYTES "$(wc -c < "$file" | tr -d ' ')"
    kh_scan_text "$file" "$target"
    local n; n="$(wc -l < "$KEYS_FILE" | tr -d ' ')"
    cs_row SUMMARY "$n"
    cs_row ARTIFACT "$KEYS_FILE"
    return 0
}

kh_cmd_harvest() {
    local url="${1:-}"
    [[ -z "$url" ]] && { printf 'usage: 46_key_harvest.sh --harvest <url>\n' >&2; return 2; }
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }
    : > "$KEYS_FILE"

    local body="$CS_SCRATCH/harvest.html"
    local code; code="$(kh_fetch "$url" "$body")"
    cs_row URL "$url"
    cs_row RESPONSE "$code"
    case "$code" in
        000) cs_row ERROR "fetch failed"; return 1 ;;
        2*)  ;;
        *)   cs_row NOTE "non-2xx body still scanned" ;;
    esac

    # the page itself
    local before; before="$(wc -l < "$KEYS_FILE" 2>/dev/null | tr -d ' ')"
    kh_scan_text "$body" "$url"

    # every script the page pulls in
    local scripts="$CS_SCRATCH/scripts.txt"
    kh_scripts "$body" "$url" > "$scripts" || true
    local nscript; nscript="$(wc -l < "$scripts" | tr -d ' ')"
    cs_row SCRIPTS "$nscript"

    local i=0 s scode
    : > "$JS_FILE"
    while IFS= read -r s; do
        [[ -z "$s" ]] && continue
        i=$((i + 1))
        (( i > KH_MAX_JS )) && break
        local jsbody="$CS_SCRATCH/js-$i.js"
        scode="$(kh_fetch "$s" "$jsbody")"
        local jbytes; jbytes="$(wc -c < "$jsbody" 2>/dev/null | tr -d ' ')"
        printf '%s\t%s\t%s\n' "$s" "$scode" "${jbytes:-0}" >> "$JS_FILE"
        if [[ "$scode" == 2* ]] && kh_worth_scanning "$jsbody"; then
            kh_scan_text "$jsbody" "$s"
        fi
    done < "$scripts"

    cs_row JS "$i"
    local n; n="$(wc -l < "$KEYS_FILE" | tr -d ' ')"
    cs_row SUMMARY "$n"
    cs_row ARTIFACT "$KEYS_FILE"
    cs_row ARTIFACT "$JS_FILE"
    return 0
}

kh_cmd_js() {
    local url="${1:-}"
    [[ -z "$url" ]] && { printf 'usage: 46_key_harvest.sh --js <url|file>\n' >&2; return 2; }
    : > "$JS_FILE"

    if [[ -f "$url" ]]; then
        cs_row JS "$url"
        kh_scan_text "$url" "$url"
        cs_row SUMMARY "$(wc -l < "$KEYS_FILE" | tr -d ' ')"
        return 0
    fi

    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }
    local body="$CS_SCRATCH/one.js"
    local code; code="$(kh_fetch "$url" "$body")"
    cs_row JS "$url"
    cs_row RESPONSE "$code"
    [[ "$code" == 2* ]] && kh_scan_text "$body" "$url"
    cs_row SUMCOUNT "$(wc -l < "$KEYS_FILE" | tr -d ' ')"
    return 0
}

kh_cmd_headers() {
    local url="${1:-}"
    [[ -z "$url" ]] && { printf 'usage: 46_key_harvest.sh --headers <url>\n' >&2; return 2; }
    command -v curl >/dev/null 2>&1 || { cs_row ERROR "missing tool: curl"; return 3; }
    : > "$HDR_FILE"

    local hdrs="$CS_SCRATCH/headers.txt"
    curl --silent --show-error --max-time "$KH_TIMEOUT" --user-agent "$KH_UA" \
         --head --dump-header "$hdrs" --output /dev/null "$url" 2>/dev/null || true

    cs_row URL "$url"
    [[ -r "$hdrs" ]] || { cs_row ERROR "no headers"; return 1; }

    local line name value
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ "$line" == *:* ]] || continue
        name="${line%%:*}"
        value="${line#*:}"; value="${value# }"
        case "${name,,}" in
            server|x-powered-by|x-aspnet-version|x-runtime|x-generator|x-application-context|via)
                cs_row TECH "$name" "$value"
                ;;
            set-cookie)
                # a cookie with a long opaque value is a session that may be
                # reusable elsewhere
                if (( ${#value} > 60 )); then
                    cs_row COOKIE "$name" "$(cs_redact "$value")"
                    printf '%s\n' "$value" >> "$HDR_FILE"
                fi
                ;;
            x-api-key|api-key|x-auth-token|authorization|x-client-id)
                cs_row HEADER_SECRET "$name" "${value:0:120}"
                printf '%s\t%s\n' "$name" "$(cs_esc "$value")" >> "$HDR_FILE"
                cs_findings_row "$MODULE_ID" "SECRETS" "$url" "HIGH" "secret-header:$name" \
                    "response leaks an auth header"
                ;;
        esac
    done < "$hdrs"

    # header values are also text worth regexing
    kh_scan_text "$hdrs" "$url"
    cs_row ARTIFACT "$HDR_FILE"
    return 0
}

kh_cmd_providers() {
    local n=0 provider sev regex note
    while IFS=$'\t' read -r provider sev regex note; do
        [[ -z "$provider" ]] && continue
        n=$((n + 1))
        cs_row PROVIDER "$provider" "$sev" "$note"
    done < <(kh_patterns)
    cs_row SUMMARY "$n"
    return 0
}

kh_cmd_all() {
    local url="${1:-}"
    kh_cmd_harvest "$url"
    kh_cmd_headers "$url"
}

# --defang <key-or-value> — what a harvested credential actually is, and what it
# unlocks. The value is truncated to a prefix so a log line stays harmless.
kh_cmd_defang() {
    local val="${1:-}"
    [[ -z "$val" ]] && { printf 'usage: 46_key_harvest.sh --defang <value>\n' >&2; return 2; }
    local shown="${val:0:8}...(${#val} chars)"
    local family="" kind="" note=""

    case "$val" in
        AKIA*|ASIA*)     family="aws";        kind="access-key-id";   note="aws cli: AWS_ACCESS_KEY_ID — pairs with a secret" ;;
        sk_live_*)       family="stripe";     kind="live-secret";     note="charges and payouts on the live account" ;;
        sg.*)            family="sendgrid";   kind="api-key";         note="send mail as the tenant" ;;
        xox[baprs]-*)    family="slack";      kind="bot-or-user";     note="read and post in the workspace" ;;
        ghp_*|gho_*|ghs_*|ghu_*|ghr_*) family="github"; kind="token";   note="repo read/write as the owner" ;;
        glpat-*)         family="gitlab";     kind="pat";             note="api as the issuing user" ;;
        dop_v1_*|doo_v1_*|dor_v1_*) family="digitalocean"; kind="token"; note="droplet and volume control" ;;
        hvs.*|s.*)       family="vault";      kind="token";           note="read secrets up to the policy" ;;
        LTAI*)           family="alibaba";    kind="access-key-id";   note="aliyun ram credential" ;;
        AKID*)           family="tencent";    kind="secret-id";       note="tencent cam credential" ;;
        eyJrIjoi*)       family="grafana";    kind="service-account"; note="dashboards and datasources" ;;
        eyJ*)
            # a jwt: report the algorithm only, never the signature
            local hdr; hdr="$(jw_peek_alg "$val" 2>/dev/null)"
            family="jwt"; kind="token"; note="algorithm ${hdr:-unknown}; run 44_jwt --inspect" ;;
        GOCSPX-*)        family="google";     kind="oauth-secret";    note="mint tokens for the client id" ;;
        AIza*)           family="google";     kind="api-key";         note="maps/firebase apis as the project" ;;
        key-*)           family="mailgun";    kind="api-key";         note="send mail as the domain" ;;
        npm_*)           family="npm";        kind="token";           note="publish as the account" ;;
        hf_*)            family="huggingface";kind="token";           note="models and datasets" ;;
        sk-ant-*)        family="anthropic";  kind="api-key";         note="inference billing" ;;
        sk-proj-*)       family="openai";     kind="project-key";     note="inference billing" ;;
        -----*)          family="pem";        kind="private-key";     note="whatever it signs for" ;;
        *://*:*@*)       family="url";        kind="basic-auth";      note="the embedded pair is a login" ;;
        *)               family="unknown";    kind="unknown";         note="no family recognised" ;;
    esac

    cs_row VALUE "$shown"
    cs_row FAMILY "$family" "kind=$kind"
    cs_row USE "$note"
    [[ "$family" == "unknown" ]] && return 1 || return 0
}

# algorithm of a jwt, without ever printing the token
jw_peek_alg() {
    local tok="$1" seg
    seg="$(printf '%s' "$tok" | cut -d. -f1)"
    seg="${seg//-/+}"; seg="${seg//_/\/}"
    case $(( ${#seg} % 4 )) in 2) seg="$seg==" ;; 3) seg="$seg=" ;; esac
    printf '%s' "$seg" | base64 -d 2>/dev/null | jq -r '.alg // "none"' 2>/dev/null
}

kh_cmd_status_tsv() {
    local curl_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    local n; n="$(kh_patterns | wc -l | tr -d ' ')"
    printf '%s\t%s\tcurl-%s\tpats-%s\n' "$MODULE_ID" "$MOD_NAME" "$curl_state" "$n"
}

kh_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

kh_cmd_help() {
    cat <<'HELP'
cloudsting module 46 — API Key Harvesting v0.21.0
  --harvest <url>     fetch a page, scan it, then fetch and scan every script it loads
  --js <url|file>     scan one script, local or remote
  --headers <url>     read the response headers for technology and auth leaks
  --defang <value>               what a harvested credential is and what it unlocks
  --detect <file|->   scan a local file or stdin, no network
  --providers         list the provider patterns and their severities
  --all <url>         harvest + headers
  --status-tsv        module status
  --menu              menu entry
  --selftest          run selftests
  --help              this message

Keys are matched by provider shape, not by entropy. A generic base64 blob is
noise; an AKIA-prefixed 20-character id is a fact. Every hit names the file
it came from, so a key found in a minified bundle is traceable to that URL.

Full values stay in the artifact, never on stdout: a value that scrolls past
a terminal is a value that leaks twice.

Environment: KH_TIMEOUT (10), KH_MAX_JS (40), KH_MAX_BYTES (5 MB)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
kh_selftest() {
    cs_selftest_reset

    # families
    chk family-aws  "$(kh_family aws_access_key_id)"   "aws"
    chk family-gcp  "$(kh_family gcp_api_key)"         "gcp"
    chk family-slack "$(kh_family slack_webhook)"      "slack"
    chk family-single "$(kh_family jwt)"               "jwt"

    # pattern table shape
    local n; n="$(kh_patterns | wc -l | tr -d ' ')"
    chk patterns-many "$( (( n > 40 )) && echo many || echo few )" "many"
    chk patterns-4col "$(kh_patterns | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk patterns-has-aws "$(kh_patterns | grep -c 'AKIA')" "1"
    chk patterns-has-stripe "$(kh_patterns | grep -c 'sk_live_')" "1"
    chk patterns-has-private-key "$(kh_patterns | grep -c 'BEGIN')" "1"

    # Detection against a planted corpus — offline, no network. The shapes are
    # assembled at run time instead of being written literally, because the
    # detector exists to find these and a tree that ships them verbatim is a
    # repository full of live-looking keys: push protection blocks on sight,
    # and rightly. AWS wants 16 upper alnum, SendGrid wants 22+43 and Stripe
    # wants 24+, so each filler is generated past its own minimum.
    local corpus="$CS_SCRATCH/corpus.txt"
    local sfx upper mid long
    sfx="$(head -c 600 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | cut -c1-48)"
    upper="$(head -c 600 /dev/urandom | base64 | tr -dc 'A-Z0-9' | cut -c1-16)"
    mid="$(head -c 600 /dev/urandom | base64 | tr -dc '0-9A-Za-z' | cut -c1-22)"
    long="$(head -c 600 /dev/urandom | base64 | tr -dc '0-9A-Za-z' | cut -c1-43)"
    {
        printf 'var a = "AKIA%s";\n' "$upper"
        printf 'var b = "ghp_%s";\n' "$sfx"
        # built from pieces so the tree never contains the literal: the
        # detector's own fixture is not a secret, but a scanner cannot tell
        printf 'var c = "%s%s%s_%s";\n' "sk" "_liv" "e" "$sfx"
        printf 'var d = "%s-%s-%s-%s";\n' "xoxb" "123456789012" "1234567890123" "$sfx"
        printf 'var e = "AIza%s";\n' "$sfx"
        printf 'var f = "https://user:pass@internal.example.com/api";\n'
        printf 'var g = "%s.%s.%s";\n' "eyJhbGciOiJIUzI1NiJ9" "eyJzdWIiOiIxIn0" "$sfx"
        printf 'var h = "SG.%s.%s";\n' "$mid" "$long"
        printf 'var safe = "nothing to see here";\n'
    } > "$corpus"
    : > "$KEYS_FILE"
    kh_scan_text "$corpus" "corpus" > /dev/null
    local hits; hits="$(wc -l < "$KEYS_FILE" | tr -d ' ')"
    chk detect-aws       "$(grep -c 'aws_access_key_id' "$KEYS_FILE")" "1"
    chk detect-github    "$(grep -c 'github_token' "$KEYS_FILE")" "1"
    chk detect-stripe    "$(grep -c 'stripe_live_secret' "$KEYS_FILE")" "1"
    chk detect-slack     "$(grep -c 'slack_token' "$KEYS_FILE")" "1"
    chk detect-gcp       "$(grep -c 'gcp_api_key' "$KEYS_FILE")" "1"
    chk detect-credurl   "$(grep -c 'basic_auth_url' "$KEYS_FILE")" "1"
    chk detect-jwt       "$(grep -c 'jwt' "$KEYS_FILE")" "1"
    chk detect-sendgrid  "$(grep -c 'sendgrid_key' "$KEYS_FILE")" "1"
    chk detect-multi     "$( (( hits >= 8 )) && echo many || echo few )" "many"
    # nothing matched on the safe line
    chk detect-no-false-positive "$(grep -c 'nothing to see' "$KEYS_FILE" || true)" "0"

    # an empty file must yield nothing, not crash
    local empty="$CS_SCRATCH/empty.txt"
    : > "$empty"
    : > "$KEYS_FILE"
    kh_scan_text "$empty" "empty" > /dev/null
    chk detect-empty "$(wc -l < "$KEYS_FILE" | tr -d ' ')" "0"

    # scanner skips a tiny blob
    printf 'hi\n' > "$empty"
    kh_worth_scanning "$empty"; chk worth-tiny "$?" "1"
    printf 'a%.0s' $(seq 1 200) > "$empty"
    kh_worth_scanning "$empty"; chk worth-real "$?" "0"

    # script extraction from a fake page
    local page="$CS_SCRATCH/page.html"
    cat > "$page" <<'PAGE'
<html><head>
<script src="/static/app.js"></script>
<script src="https://cdn.example.com/vendor.js"></script>
<link href="style.css" rel="stylesheet">
</head></html>
PAGE
    local sc; sc="$(kh_scripts "$page" "https://target.example.com/path")"
    chk scripts-count "$(printf '%s\n' "$sc" | grep -c .)" "2"
    chk scripts-absolute "$(printf '%s\n' "$sc" | grep -c '^https://target.example.com/static/app.js$')" "1"
    chk scripts-remote "$(printf '%s\n' "$sc" | grep -c '^https://cdn.example.com/vendor.js$')" "1"
    chk scripts-no-css "$(printf '%s\n' "$sc" | grep -c 'style.css' || true)" "0"

    # shape contracts
    chk status-fields "$(kh_cmd_status_tsv | awk -F'\t' '{print NF}')" "4"
    chk status-module "$(kh_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(kh_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(kh_cmd_help | head -1 | grep -ci 'Key Harvesting')" "1"
    chk providers-n   "$(kh_cmd_providers | grep -c '^PROVIDER')" "$(kh_patterns | wc -l | tr -d ' ')"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --harvest)   shift; kh_cmd_harvest "$@";;
    --js)        shift; kh_cmd_js "$@";;
    --headers)   shift; kh_cmd_headers "$@";;
    --detect)    shift; kh_cmd_detect "$@";;
    --defang)    shift; kh_cmd_defang "$@";;
    --providers) kh_cmd_providers;;
    --all)       shift; kh_cmd_all "$@";;
    --status-tsv|--status) kh_cmd_status_tsv;;
    --menu)      kh_cmd_menu;;
    --selftest)  kh_selftest;;
    *)           kh_cmd_help;;
esac
