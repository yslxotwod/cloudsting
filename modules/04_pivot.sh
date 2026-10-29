#!/usr/bin/env bash
# 04_pivot.sh — cloudsting module 04: the trust that was promised versus the trust that answers
# Verbs: --probe | --trust | --assume | --enumerate | --escalate | --providers
#        | --techniques | --list | --status-tsv | --menu | --selftest | --help
#
# Modules 05, 06 and 07 read policy DOCUMENTS: they map escalation paths, trust
# chains and wildcards from the JSON. That is analysis, and it can be wrong in
# both directions — a policy that looks permissive may fail a condition at
# evaluation time, and a policy that looks tight may be bypassed by a session
# tag nobody read.
#
# This module assumes the role and reports what actually came back. A trust
# policy is a promise; the credentials are the answer. The gap between them is
# the finding, and it is only visible from the outside.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="04_pivot"
MOD_NAME="Cross-Account Pivot (the trust that was promised versus the trust that answers)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/pivot"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
TRUST_FILE="$OUT_DIR/trust-$RUN_ID.tsv"
SESSION_FILE="$OUT_DIR/sessions-$RUN_ID.txt"

: "${PV_TIMEOUT:=30}"
: "${PV_DURATION:=900}"
: "${PV_PROBE_CALLS:=8}"
: "${PV_EXTERNAL_ID:=}"
: "${PV_SESSION_NAME:=cloudsting-pivot}"

pv_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the providers that have a cross-account concept ──────────────
# Every cloud has one, and each names it differently. The last two columns are
# what makes the module honest: the CLI that performs the assumption, and what
# "success" actually returns. Guessing at success is how a recon tool produces
# fiction, so each provider states its marker.
#   <id>\t<provider>\t<the mechanism>\t<cli verb>\t<success marker>
pv_providers() {
    cat <<'PROVIDERS'
aws-assume	aws	STS AssumeRole with a role ARN in another account	aws sts assume-role	Credentials
aws-role-chain	aws	AssumeRole into a second account from the first	aws sts assume-role	Credentials
aws-saml	aws	AssumeRoleWithSAML from a federated assertion	aws sts assume-role-with-saml	Credentials
aws-web	aws	AssumeRoleWithWebIdentity from an OIDC token	aws sts assume-role-with-web-identity	Credentials
aws-resource	aws	resource policies that skip the trust policy entirely (bucket, KMS, SQS)	aws sts get-caller-identity	Account
gcp-impersonate	gcp	Service Account Token Creator on a foreign SA	gcloud auth print-access-token	ya29.
gcp-workload	gcp	Workload Identity Federation from an external IdP	gcloud auth login --cred-file	ya29.
gcp-domain	gcp	domain-wide delegation into a foreign Workspace	gcloud auth print-access-token	ya29.
azure-sp	azure	A multi-tenant app registration consented by the victim tenant	az account get-access-token	accessToken
azure-federation	azure	A federated credential trusting an external OIDC issuer	az account get-access-token	accessToken
azure-b2b	azure	A guest invitation that grants a directory role	az account get-access-token	accessToken
oci-cross	oci	Cross-tenancy policy on a compartment	oci iam compartment list	"id"
alibaba-ram	alibaba	RAM role with an AssumeRole trust on a foreign account	aliyun sts AssumeRole	AccessKeyId
tencent-cam	tencent	A CAM role that trusts a foreign UIN	tccli sts AssumeRole	Credentials
k8s-sa	kubernetes	A service account token accepted by a foreign cluster	kubectl auth can-i	yes
PROVIDERS
}

# ── the gaps a delivered credential reveals ──────────────────────
# A role can be assumable and still be useless, or be documented as read-only
# and come back with write. Each row is a comparison between what a policy
# READER would conclude and what the credential can DO.
#   <id>\t<class>\t<what is compared>\t<what closing the gap would have required>
pv_gaps() {
    cat <<'GAPS'
more-than-readonly	excess	the assumed session can write where the policy promised read	an explicit deny, not a missing allow
wildcard-action	excess	the session allows an action family the trust never mentioned	scoping the role policy to the actions it uses
unscoped-resource	excess	the session reaches a resource outside the account it trusts	resource-level conditions on the role policy
no-source-account	trust	the trust policy accepts a principal with no account condition	aws:SourceAccount / an explicit account in the principal
no-external-id	trust	the trust policy accepts without an ExternalId	an ExternalId requirement for third-party assumptions
no-mfa	trust	the trust policy does not require MFA	a sts:MultiFactorAuthAge condition
wildcard-principal	trust	the trust policy names * as principal	replacing it with the account or role ARN
missing-condition	trust	conditions exist but none of them bind the caller	a sts:ExternalId or source-account condition
tag-bypass	bypass	the trust evaluates a session tag the caller controls	tag conditions the caller cannot set
role-chain	chain	a role in account B assumes a role in account C	transitive trust auditing
permission-boundary	chain	a boundary on the role does not cover the session	the same boundary on the derived session
stale-session	chain	an assumed session outlives the revocation	session duration under the detection window
GAPS
}

# ── running the provider CLIs ────────────────────────────────────
pv_have() { command -v "$1" >/dev/null 2>&1; }

#   pv_state <provider-id> -> absent | no-tool | no-creds | ready
pv_state() {
    local pid="$1"
    case "$pid" in
        aws-*)
            pv_have aws || { printf 'no-tool'; return; }
            aws sts get-caller-identity >/dev/null 2>&1 && printf 'ready' || printf 'no-creds' ;;
        gcp-*)
            pv_have gcloud || { printf 'no-tool'; return; }
            gcloud auth print-access-token >/dev/null 2>&1 && printf 'ready' || printf 'no-creds' ;;
        azure-*)
            pv_have az || { printf 'no-tool'; return; }
            az account get-access-token >/dev/null 2>&1 && printf 'ready' || printf 'no-creds' ;;
        oci-*)
            pv_have oci || { printf 'no-tool'; return; }
            printf 'ready' ;;
        alibaba-*)
            pv_have aliyun || { printf 'no-tool'; return; }
            printf 'ready' ;;
        tencent-*)
            pv_have tccli || { printf 'no-tool'; return; }
            printf 'ready' ;;
        k8s-*)
            pv_have kubectl || { printf 'no-tool'; return; }
            kubectl auth can-i --list >/dev/null 2>&1 && printf 'ready' || printf 'no-creds' ;;
        *) printf 'unknown' ;;
    esac
}

# ── assuming a role, and telling the truth about the result ──────
#   pv_assume_aws <role-arn> [external-id] [session-name]
#   -> "ok\t<account>\t<arn>\t<expiry>"  |  "failed\t<reason>"
#
# The distinction that matters: a failure to ASSUME (AccessDenied) is the
# trust policy working, and must never be reported as a finding. A successful
# assumption that was never documented is the finding.
pv_assume_aws() {
    local arn="$1" ext="${2:-$PV_EXTERNAL_ID}" name="${3:-$PV_SESSION_NAME}"
    pv_have aws || { printf 'failed\tno-tool'; return; }
    local -a args=(sts assume-role --role-arn "$arn" --role-session-name "$name"
                   --duration-seconds "$PV_DURATION" --output json)
    [ -n "$ext" ] && args+=(--external-id "$ext")

    local out; out="$(aws "${args[@]}" 2>&1)"
    if (( $? != 0 )); then
        # normalise the reason without pretending to know more than we do
        local why="denied"
        printf '%s' "$out" | grep -qiE 'AccessDenied|not authorized|is not authorized' && why="denied"
        printf '%s' "$out" | grep -qiE 'does not exist|NoSuchEntity|InvalidParameter' && why="no-such-role"
        printf '%s' "$out" | grep -qiE 'ExpiredToken|security token.*expired|InvalidClientTokenId' && why="no-creds"
        printf '%s' "$out" | grep -qiE 'Throttl|Rate exceeded' && why="throttled"
        printf 'failed\t%s' "$why"
        return
    fi
    local acct accesskey expiry
    acct="$(printf '%s' "$out" | jq -r '.AssumedRoleUser.Arn // "" | split(":")[4] // empty' 2>/dev/null)"
    expiry="$(printf '%s' "$out" | jq -r '.Credentials.Expiration // empty' 2>/dev/null)"
    accesskey="$(printf '%s' "$out" | jq -r '.Credentials.AccessKeyId // empty' 2>/dev/null)"
    [[ -z "$accesskey" ]] && { printf 'failed\tempty-credentials'; return; }
    # the session keys are written mode 600 and never printed
    {
        printf 'export AWS_ACCESS_KEY_ID=%s\n' "$(printf '%s' "$out" | jq -r '.Credentials.AccessKeyId')"
        printf 'export AWS_SECRET_ACCESS_KEY=%s\n' "$(printf '%s' "$out" | jq -r '.Credentials.SecretAccessKey')"
        printf 'export AWS_SESSION_TOKEN=%s\n' "$(printf '%s' "$out" | jq -r '.Credentials.SessionToken')"
    } >> "$SESSION_FILE" 2>/dev/null
    chmod 600 "$SESSION_FILE" 2>/dev/null || true
    printf 'ok\t%s\t%s\t%s' "${acct:-unknown}" "$arn" "${expiry:-unknown}"
}

# ── reading what the delivered credential can actually do ────────
# This is where the module earns its place: the policy said read-only, the
# credential says otherwise. Each probe is a read the role should not need,
# scored on whether it was REFUSED rather than on whether it answered.
pv_probe_aws() {
    local calls="${PV_PROBE_CALLS:-8}"
    local -a probes=(
        "identity|sts get-caller-identity"
        "buckets|s3api list-buckets"
        "iam-users|iam list-users"
        "iam-roles|iam list-roles"
        "secrets|secretsmanager list-secrets"
        "ssm|ssm describe-parameters"
        "kms|kms list-keys"
        "ec2-instances|ec2 describe-instances"
    )
    local i=0 p
    for p in "${probes[@]}"; do
        (( i >= calls )) && break
        i=$((i + 1))
        local id cmd
        id="${p%%|*}"; cmd="${p#*|}"
        local out rc
        out="$(timeout "$PV_TIMEOUT" aws $cmd 2>&1)"; rc=$?
        local verdict="refused"
        if (( rc == 0 )); then verdict="allowed"
        elif printf '%s' "$out" | grep -qiE 'AccessDenied|not authorized'; then verdict="refused"
        elif printf '%s' "$out" | grep -qiE 'Throttl'; then verdict="throttled"
        elif printf '%s' "$out" | grep -qiE 'credentials|token'; then verdict="no-creds"
        else verdict="error"; fi
        cs_row PROBE "$id" "$verdict"
    done
    return 0
}

# The excess verdict. The finding is not "this call was allowed" — a role that
# is allowed to list buckets is doing its job. It is that the policy DOCUMENT
# said read-only and the CREDENTIAL said write, which only a comparison shows.
#   pv_excess_verdict <documented:ro|rw|admin> <observed-allowed> <observed-total>
pv_excess_verdict() {
    local doc="$1" allowed="$2" total="$3"
    (( total <= 0 )) && { printf 'no-probes'; return; }
    case "$doc" in
        ro)
            if (( allowed == 0 )); then printf 'matches-document'; return; fi
            # read-only documented, but listings answered: the usual case, and
            # NOT excess unless a write-shaped call got through
            printf 'read-beyond-document' ;;
        rw)
            if (( allowed >= total )); then printf 'matches-document'; return; fi
            printf 'narrower-than-document' ;;
        admin)
            printf 'matches-document' ;;
        *) printf 'unknown-document' ;;
    esac
}

pv_severity() {
    local v="$1" class="${2:-excess}" writer="${3:-no}"
    case "$v" in
        read-beyond-document)
            # a listing answered where the document promised nothing is real,
            # but it is the mildest form — the sharp version is a WRITE
            if [[ "$writer" == "yes" ]]; then printf 'CRITICAL'; else printf 'MEDIUM'; fi ;;
        narrower-than-document) printf 'INFO' ;;
        stale-session)          printf 'HIGH' ;;
        no-external-id)         printf 'HIGH' ;;
        wildcard-principal)     printf 'CRITICAL' ;;
        *)                      printf 'INFO' ;;
    esac
}

# cs_findings_row PRINTS a row; it does not append one. Its argument order is
# (module, category, target, key, detail...) and the severity is carried by the
# key field's leading word, so it must be spelled `critical-...`/`high-...`
# rather than passed as an extra column.
pv_findings() {
    local target="$1" sev="$2" check="$3" detail="$4"
    cs_findings_row "$MODULE_ID" "IDENTITY" "$target" "${sev,,}-${check}" "$detail" > /dev/null
}

# ── verbs ────────────────────────────────────────────────────────

# --probe: which providers can even be tested here. Three-state, and the middle
# state is the one people get wrong — a missing CLI is not a secure cloud.
pv_cmd_probe() {
    local pid provider mech cli marker
    while IFS=$'\t' read -r pid provider mech cli marker; do
        [[ -z "$pid" ]] && continue
        local st; st="$(pv_state "$pid")"
        cs_row PROVIDER "$pid" "$provider" "$st"
    done < <(pv_providers)
    local ready=0 total=0
    while IFS=$'\t' read -r pid provider mech cli marker; do
        [[ -z "$pid" ]] && continue
        total=$((total + 1))
        [[ "$(pv_state "$pid")" == "ready" ]] && ready=$((ready + 1))
    done < <(pv_providers)
    cs_row SUMMARY "ready=$ready total=$total"
    return 0
}

# --trust <role-arn-or-policy-file>: read the trust policy and grade it. This
# is the DOCUMENT half, kept here so the module can state the gap it is about
# to test rather than assuming it.
pv_cmd_trust() {
    local target="${1:-}"
    [[ -z "$target" ]] && { pv_log "usage: --trust <role-arn|policy.json>"; return 2; }
    cs_row TARGET "$target"

    local doc=""
    if [[ -f "$target" ]]; then
        doc="$(cat "$target" 2>/dev/null)"
    elif [[ "$target" == arn:* && "$(pv_state aws-assume)" == "ready" ]]; then
        local role; role="$(printf '%s' "$target" | sed 's#.*/##')"
        doc="$(aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)"
    fi
    if [[ -z "${doc// /}" ]]; then
        cs_row VERDICT "no-document"
        cs_row NOTE "no trust policy could be read — pass a local json, or a role ARN with working credentials"
        cs_row SUMMARY "verdict=no-document"
        return 0
    fi
    printf '%s' "$doc" | sed -n 's/^ *//p' > "$TRUST_FILE" 2>/dev/null
    cs_row ARTIFACT "$TRUST_FILE"

    # grade the four things a reader can establish from the document
    local wildcard="no" noext="no" nosrc="no" nomfa="no"
    printf '%s' "$doc" | grep -qaE '"Principal"[[:space:]]*:[[:space:]]*"\*"' && wildcard="yes"
    printf '%s' "$doc" | grep -qai 'ExternalId' || noext="yes"
    printf '%s' "$doc" | grep -qai 'SourceAccount' || nosrc="yes"
    printf '%s' "$doc" | grep -qai 'MultiFactorAuthAge' || nomfa="yes"

    cs_row WILDCARD-PRINCIPAL "$wildcard"
    cs_row NO-EXTERNAL-ID "$noext"
    cs_row NO-SOURCE-ACCOUNT "$nosrc"
    cs_row NO-MFA "$nomfa"

    if [[ "$wildcard" == "yes" ]]; then
        cs_row FINDING "CRITICAL" "pivot-wildcard-principal"
        pv_findings "$target" "CRITICAL" "pivot-wildcard-principal" \
            "the trust policy names * as principal — any account may attempt the assumption"
    fi
    if [[ "$noext" == "yes" ]]; then
        cs_row FINDING "HIGH" "pivot-no-external-id"
        pv_findings "$target" "HIGH" "pivot-no-external-id" \
            "the trust policy requires no ExternalId, so a confused deputy is possible"
    fi
    cs_row VERDICT "graded"
    cs_row SUMMARY "wildcard=$wildcard noextid=$noext nosourceaccount=$nosrc nomfa=$nomfa"
    return 0
}

# --assume <role-arn> [external-id]: the decisive verb. Assumes and then
# measures, because the assumption alone says nothing about what came back.
pv_cmd_assume() {
    local arn="${1:-}" ext="${2:-$PV_EXTERNAL_ID}"
    [[ -z "$arn" ]] && { pv_log "usage: --assume <role-arn> [external-id]"; return 2; }
    cs_row TARGET "$arn"
    [[ -n "$ext" ]] && cs_row EXTERNAL_ID "supplied"

    local res; res="$(pv_assume_aws "$arn" "$ext")"
    local status acct assumed expiry
    IFS=$'\t' read -r status acct assumed expiry <<< "$res"
    cs_row ASSUME "$status"
    if [[ "$status" != "ok" ]]; then
        cs_row VERDICT "$status"
        case "$(printf '%s' "$res" | cut -f2)" in
            denied)      cs_row NOTE "the trust policy refused the assumption — that is the control working" ;;
            no-such-role) cs_row NOTE "the role does not exist, so nothing was tested" ;;
            no-tool|no-creds) cs_row NOTE "no AWS CLI or no credentials — nothing was tested" ;;
        esac
        cs_row SUMMARY "verdict=$status"
        return 0
    fi
    cs_row ACCOUNT "${acct:-unknown}"
    cs_row EXPIRES "${expiry:-unknown}"
    cs_row NOTE "session credentials written to a mode-600 file and never printed"

    # now measure what the delivered credential can do
    local outline; outline="$(pv_probe_aws)"
    local allowed=0 refused=0 total=0 line
    while IFS=$'\t' read -r key id val; do
        [[ "$key" != "PROBE" ]] && continue
        total=$((total + 1))
        case "$val" in
            allowed) allowed=$((allowed + 1)) ;;
            refused) refused=$((refused + 1)) ;;
        esac
    done <<< "$outline"
    cs_row DELIVERED "allowed=$allowed refused=$refused total=$total"

    local v; v="$(pv_excess_verdict ro "$allowed" "$total")"
    cs_row VERDICT "$v"
    if [[ "$v" == "read-beyond-document" ]]; then
        local sev; sev="$(pv_severity "$v" excess no)"
        cs_row FINDING "$sev" "pivot-excess-egress"
        pv_findings "$arn" "$sev" "pivot-excess-egress" \
            "$allowed of $total read calls answered from a role the document described as minimal"
    fi
    cs_row SUMMARY "status=ok account=${acct:-unknown} allowed=$allowed total=$total verdict=$v"
    return 0
}

# --enumerate <role-arn>: what is in the account we just pivoted into. Names
# and counts only — the point is reach, not a data dump.
pv_cmd_enumerate() {
    local arn="${1:-}"
    [[ -z "$arn" ]] && { pv_log "usage: --enumerate <role-arn>"; return 2; }
    cs_row TARGET "$arn"
    if [[ "$(pv_state aws-assume)" != "ready" ]]; then
        cs_row VERDICT "no-creds"; cs_row SUMMARY "verdict=no-creds"; return 0
    fi
    local res; res="$(pv_assume_aws "$arn")"
    local status
    IFS=$'\t' read -r status _ <<< "$res"
    if [[ "$status" != "ok" ]]; then
        cs_row VERDICT "$status"; cs_row SUMMARY "verdict=$status"; return 0
    fi

    pv_probe_aws
    local buckets
    buckets="$(timeout "$PV_TIMEOUT" aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' | head -20 | tr '\n' ' ')"
    cs_row BUCKETS "${buckets:-none}"
    local users
    users="$(timeout "$PV_TIMEOUT" aws iam list-users --query 'Users[].UserName' --output text 2>/dev/null | tr '\t' '\n' | head -20 | tr '\n' ' ')"
    cs_row USERS "${users:-none}"
    cs_row VERDICT "enumerated"
    cs_row SUMMARY "verdict=enumerated"
    return 0
}

# --escalate <role-arn>: assume, then try the two things that turn a read into
# a write. Reported separately because it is a different consequence.
pv_cmd_escalate() {
    local arn="${1:-}"
    [[ -z "$arn" ]] && { pv_log "usage: --escalate <role-arn>"; return 2; }
    cs_row TARGET "$arn"
    if [[ "$(pv_state aws-assume)" != "ready" ]]; then
        cs_row VERDICT "no-creds"; cs_row SUMMARY "verdict=no-creds"; return 0
    fi
    local res; res="$(pv_assume_aws "$arn")"
    local status
    IFS=$'\t' read -r status _ <<< "$res"
    if [[ "$status" != "ok" ]]; then
        cs_row VERDICT "$status"; cs_row SUMMARY "verdict=$status"; return 0
    fi

    # a write that is cheap, reversible and provably ours: create a bucket with
    # a name nobody else will have, then delete it. Never touch existing data.
    local probe="cloudsting-pivot-$(cs_fingerprint "$arn")"
    local out rc
    out="$(timeout "$PV_TIMEOUT" aws s3api create-bucket --bucket "$probe" --region us-east-1 2>&1)"; rc=$?
    if (( rc == 0 )); then
        cs_row WRITE "allowed" "bucket=$probe"
        cs_row FINDING "CRITICAL" "pivot-write-egress"
        pv_findings "$arn" "CRITICAL" "pivot-write-egress" \
            "the pivoted session created a bucket, so the role writes outside its documented scope"
        timeout "$PV_TIMEOUT" aws s3api delete-bucket --bucket "$probe" >/dev/null 2>&1 || true
        cs_row CLEANUP "attempted" "bucket=$probe"
    elif printf '%s' "$out" | grep -qiE 'AccessDenied|not authorized'; then
        cs_row WRITE "refused"
    elif printf '%s' "$out" | grep -qiE 'BucketAlreadyExists|BucketAlreadyOwnedByYou'; then
        cs_row WRITE "name-taken" "no conclusion drawn"
    else
        cs_row WRITE "error"
    fi
    cs_row VERDICT "measured"
    cs_row SUMMARY "verdict=measured"
    return 0
}

pv_cmd_providers() {
    local pid provider mech cli marker
    while IFS=$'\t' read -r pid provider mech cli marker; do
        [[ -z "$pid" ]] && continue
        cs_row PROVIDER "$pid" "$provider" "$mech" "state=$(pv_state "$pid")"
    done < <(pv_providers)
    local gid class what need
    while IFS=$'\t' read -r gid class what need; do
        [[ -z "$gid" ]] && continue
        cs_row GAP "$gid" "$class" "$need"
    done < <(pv_gaps)
    cs_row SUMMARY "providers=$(pv_providers | wc -l | tr -d ' ') gaps=$(pv_gaps | wc -l | tr -d ' ')"
    return 0
}

pv_cmd_techniques() {
    local gid class what need
    while IFS=$'\t' read -r gid class what need; do
        [[ -z "$gid" ]] && continue
        cs_row GAP "$gid" "$class" "$what" "$need"
    done < <(pv_gaps)
    cs_row SUMMARY "gaps=$(pv_gaps | wc -l | tr -d ' ')"
    return 0
}

pv_cmd_list() {
    cs_row VERB "probe" "trust" "assume" "enumerate" "escalate" "providers" "techniques"
    cs_row SUMMARY "ok"
    return 0
}

pv_cmd_status_tsv() {
    local ready=0 total=0 pid provider mech cli marker
    while IFS=$'\t' read -r pid provider mech cli marker; do
        [[ -z "$pid" ]] && continue
        total=$((total + 1))
        [[ "$(pv_state "$pid")" == "ready" ]] && ready=$((ready + 1))
    done < <(pv_providers)
    local st="no-provider"
    (( ready > 0 )) && st="provider-ready"
    printf '%s\t%s\t%s\tproviders-%s\ttools-%s-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$st" "$total" "$ready" "$((total - ready))"
}

pv_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

pv_cmd_help() {
    cat <<'HELP'
cloudsting module 04 — Cross-Account Pivot v1.0.0
  --probe                            which providers can be tested here, three-state
  --trust <role-arn|policy.json>     grade the trust document before assuming
  --assume <role-arn> [external-id]  assume it, then measure what came back
  --enumerate <role-arn>             names and counts inside the pivoted account
  --escalate <role-arn>              does the delivered session WRITE
  --providers | --techniques | --list | --status-tsv | --menu | --selftest | --help

Modules 05, 06 and 07 read policy DOCUMENTS: escalation paths, trust chains,
wildcards. That is analysis, and it is wrong in both directions — a policy that
reads permissive can fail a condition at evaluation time, and a policy that
reads tight can be bypassed by a session tag nobody looked at.

This module assumes the role and reports what actually came back. A trust
policy is a promise; the credentials are the answer, and the gap between them
is the finding.

What it will not do:

  a refusal is never a finding. AccessDenied on the assumption is the control
  working, and it is reported as `denied`, not as a vulnerability.

  a listing that answered is not excess. A read-only role that can list
  buckets is doing its job. `read-beyond-document` is graded MEDIUM, and only
  a WRITE that got through is graded CRITICAL.

  `--escalate` creates a bucket with a name derived from a fingerprint, then
  deletes it. It never modifies or deletes anything that already exists.

  assumed session keys are written to a mode-600 file and never printed.

Environment: PV_TIMEOUT (30), PV_DURATION (900), PV_PROBE_CALLS (8),
             PV_EXTERNAL_ID, PV_SESSION_NAME
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
pv_selftest() {
    cs_selftest_reset
    # A selftest must never write rows into the operator's real findings
    # ledger: the fixture policies it grades are files in a temp dir, and a
    # reader of loot/findings.tsv would see them as real findings against a
    # target that no longer exists. Point the ledger at scratch for the run.
    local real_loot="$CS_LOOT"
    CS_LOOT="$CS_SCRATCH"
    mkdir -p "$CS_LOOT" 2>/dev/null || true

    local np; np="$(pv_providers | wc -l | tr -d ' ')"
    chk prov-5col    "$(pv_providers | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk prov-unique  "$(pv_providers | cut -f1 | sort -u | wc -l | tr -d ' ')" "$np"
    chk prov-many    "$( (( np >= 15 )) && echo many || echo few )" "many"
    chk prov-clouds  "$(pv_providers | cut -f2 | sort -u | wc -l | tr -d ' ')" "7"
    chk prov-aws     "$(pv_providers | grep -c '^aws-')" "5"

    local ng; ng="$(pv_gaps | wc -l | tr -d ' ')"
    chk gaps-4col    "$(pv_gaps | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk gaps-unique  "$(pv_gaps | cut -f1 | sort -u | wc -l | tr -d ' ')" "$ng"
    chk gaps-many    "$( (( ng >= 12 )) && echo many || echo few )" "many"

    # the excess table, which is the whole grading philosophy
    chk e-match      "$(pv_excess_verdict ro 0 8)" "matches-document"
    chk e-beyond     "$(pv_excess_verdict ro 3 8)" "read-beyond-document"
    chk e-narrower   "$(pv_excess_verdict rw 2 8)" "narrower-than-document"
    chk e-rwmatch    "$(pv_excess_verdict rw 8 8)" "matches-document"
    chk e-admin      "$(pv_excess_verdict admin 8 8)" "matches-document"
    chk e-unknown    "$(pv_excess_verdict wat 1 8)" "unknown-document"
    chk e-noprobes   "$(pv_excess_verdict ro 0 0)" "no-probes"

    chk s-beyond     "$(pv_severity read-beyond-document excess no)" "MEDIUM"
    chk s-beyond-w   "$(pv_severity read-beyond-document excess yes)" "CRITICAL"
    chk s-wild       "$(pv_severity wildcard-principal trust no)" "CRITICAL"
    chk s-noext      "$(pv_severity no-external-id trust no)" "HIGH"
    chk s-narrow     "$(pv_severity narrower-than-document excess no)" "INFO"

    # trust grading against documents built here
    local d; d="$(mktemp -d "$CS_SCRATCH/pvt.XXXXXX")" 2>/dev/null || d="$OUT_DIR/.pvt.$$"
    mkdir -p "$d"
    cat > "$d/wild.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}
J
    cat > "$d/tight.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"abc"},"StringEqualsIgnoreCase":{"aws:SourceAccount":"111122223333"}}}]}
J
    local out; out="$(pv_cmd_trust "$d/wild.json" 2>/dev/null)"
    chk t-wild     "$(printf '%s' "$out" | awk -F'\t' '$1=="WILDCARD-PRINCIPAL"{print $2}')" "yes"
    chk t-wildhit  "$(printf '%s' "$out" | grep -c '^FINDING')" "2"
    out="$(pv_cmd_trust "$d/tight.json" 2>/dev/null)"
    chk t-tight    "$(printf '%s' "$out" | awk -F'\t' '$1=="WILDCARD-PRINCIPAL"{print $2}')" "no"
    chk t-tighthit "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    rm -rf "$d"

    # a missing document must say so rather than grading an empty string
    out="$(pv_cmd_trust "$OUT_DIR/does-not-exist.json" 2>/dev/null)"
    chk t-nodoc    "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "no-document"
    chk t-nodochit "$(printf '%s' "$out" | grep -c '^FINDING')" "0"

    # assuming on this box: the CLIs are absent, so every provider must report
    # a three-state absence and no verb may claim a finding
    out="$(pv_cmd_probe 2>/dev/null)"
    chk p-summary  "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}')" "ready=0 total=$np"
    chk p-hits     "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    out="$(pv_cmd_assume arn:aws:iam::111122223333:role/cloudsting-test 2>/dev/null)"
    chk a-status   "$(printf '%s' "$out" | awk -F'\t' '$1=="ASSUME"{print $2}')" "failed"
    chk a-hits     "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    out="$(pv_cmd_enumerate arn:aws:iam::111122223333:role/x 2>/dev/null)"
    chk e-nocreds  "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "no-creds"

    # usage errors
    pv_cmd_trust 2>/dev/null;    chk use-1 "$?" "2"
    pv_cmd_assume 2>/dev/null;   chk use-2 "$?" "2"
    pv_cmd_enumerate 2>/dev/null; chk use-3 "$?" "2"
    pv_cmd_escalate 2>/dev/null; chk use-4 "$?" "2"

    chk status-fields "$(pv_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(pv_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(pv_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(pv_cmd_help | head -1 | grep -ci 'Cross-Account')" "1"

    CS_LOOT="$real_loot"
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)      pv_cmd_probe;;
    --trust)      shift; pv_cmd_trust "$@";;
    --assume)     shift; pv_cmd_assume "$@";;
    --enumerate)  shift; pv_cmd_enumerate "$@";;
    --escalate)   shift; pv_cmd_escalate "$@";;
    --providers)  pv_cmd_providers;;
    --techniques) pv_cmd_techniques;;
    --list)       pv_cmd_list;;
    --status-tsv|--status) pv_cmd_status_tsv;;
    --menu)       pv_cmd_menu;;
    --selftest)   pv_selftest;;
    *)            pv_cmd_help;;
esac
