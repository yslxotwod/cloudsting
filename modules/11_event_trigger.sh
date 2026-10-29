#!/usr/bin/env bash
# 11_event_trigger.sh — cloudsting module 11: make a legitimate event fire on your terms
# Verbs: --probe | --sources | --rules | --forge | --inject | --trust | --payload
#        | --techniques | --list | --status-tsv | --menu | --selftest | --help
#
# Every cloud runs work in response to events: an object lands in a bucket, a
# message arrives on a queue, a schedule fires, a webhook posts. The pattern is
# always the same — a SOURCE produces an event, a RULE matches it, a TARGET
# runs something with an identity.
#
# The finding lives in the gap between "the source is trusted" and "the rule
# does not check who wrote it". A Lambda triggered by s3:ObjectCreated can be
# fed by any bucket in any account that has a PutObject grant, and the
# function's own logs will show a legitimate event.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="11_event_trigger"
MOD_NAME="Event Trigger Abuse (make a legitimate event fire on your terms)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/event_trigger"
mkdir -p "$OUT_DIR" 2>/dev/null || true

RULE_FILE="$OUT_DIR/rules-$RUN_ID.tsv"
INJECT_FILE="$OUT_DIR/inject-$RUN_ID.tsv"

: "${EV_TIMEOUT:=30}"
: "${EV_MAX:=200}"
: "${EV_MARKER:=cloudsting-event}"

ev_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the event source classes ─────────────────────────────────────
# Grouped by WHO can put an event on the bus. The first column is the thing
# that matters: an external source is one a stranger can write to.
#   <id>\t<provider>\t<source>\t<who can trigger it>\t<what the rule usually trusts>
ev_sources() {
    cat <<'SOURCES'
aws-s3	aws	s3:ObjectCreated:*	any principal with s3:PutObject — including another account	bucket name only, never the account-id
aws-s3-delete	aws	s3:ObjectRemoved:*	any principal with s3:DeleteObject	bucket name only
aws-sns	aws	SNS topic subscription	the topic's resource policy; a wildcard principal means anyone	the topic ARN, not the publisher
aws-sqs	aws	SQS message arrival	the queue's resource policy	the queue ARN
aws-eventbridge	aws	EventBridge rule	any PutEvents caller the rule's event pattern matches	the event `source` field, which the caller sets
aws-schedule	aws	EventBridge schedule	nobody external — but a stolen role can rewrite it	nothing
aws-apigw	aws	API Gateway invocation	any caller the route's authorizer allows	the authorizer result, not the caller identity
aws-cognito	aws	Cognito post-confirmation	the user pool itself	the pool, but attributes come from the signup request
aws-cloudtrail	aws	CloudTrail log delivery	a tampered trail	the bucket, not the trail's integrity
aws-codecommit	aws	CodeCommit push	any principal with git access	the repo, not the pusher
azure-blob	azure	BlobCreated	any principal with a SAS or role grant	the container, not the account
azure-eventhub	azure	Event Hub message	the namespace's authorization rules	the hub
azure-servicebus	azure	Service Bus message	the namespace's authorization rules	the queue
azure-timer	azure	Timer trigger	nobody external	nothing
gcp-pubsub	gcp	Pub/Sub message	any principal with roles/pubsub.publisher on the topic	the topic, not the publisher
gcp-storage	gcp	object.finalize	any principal with storage.objects.create	the bucket
gcp-scheduler	gcp	Cloud Scheduler	nobody external	nothing
gcp-eventarc	gcp	Eventarc trigger	depends on the upstream service	the event attributes
webhook-generic	generic	inbound HTTP webhook	whoever knows the URL	the URL's secrecy
webhook-github	generic	GitHub webhook	whoever has the secret	the HMAC, if configured
webhook-stripe	generic	Stripe webhook	whoever has the signing secret	the signature
webhook-twilio	generic	Twilio webhook	anyone — the URL is the only control	the URL
kafka-topic	kafka	Topic message	any producer with access	the topic, not the producer
rabbit-queue	rabbit	Queue message	any publisher with access	the queue
mqtt-topic	mqtt	Topic publish	any client with access unless ACLs are set	the topic
SOURCES
}

# ── the trust gaps worth testing ────────────────────────────────
# Each row is a question you can answer about a trigger without breaking
# anything: does the rule check WHO, or only WHAT.
#   <id>\t<class>\t<the question>\t<what a yes costs>
ev_gaps() {
    cat <<'GAPS'
no-source-account	identity	does the trigger check the source ACCOUNT, not just the bucket/topic name?	any account with a matching name can inject
wildcard-principal	identity	does the source's resource policy name * ?	anyone may publish
event-field-trusted	content	does the handler branch on an event field the caller sets?	the caller chooses the code path
payload-passthrough	content	does the event body reach a parser, a shell or a template untouched?	injection through the queue
retry-amplification	cost	does a failing event retry without a cap?	a single injected event becomes thousands
dlq-absent	reliability	does a failed event go somewhere you can read?	failures are silent and unattributable
replay-window-open	identity	does the handler reject an event it has already seen?	replay any captured event
signature-optional	identity	does the handler accept an unsigned event when a signature is present in others?	downgrade to no signature
handler-role-overbroad	identity	does the handler's role reach beyond what the event needs?	the event becomes a pivot
cross-tenant-arn	identity	does the rule's target ARN accept a foreign account's identifier?	invoke another tenant's function
schedule-mutable	identity	can a low-privilege principal rewrite the schedule?	persistence without an event
callback-url-private	content	does the event contain an attacker-controlled URL the handler will fetch?	SSRF from inside the trusted context
GAPS
}

# ── the verdicts ────────────────────────────────────────────────
# A trigger is "reachable" only when we proved an event of our making arrived.
# Everything weaker is stated plainly.
#   ev_reach_verdict <control-code> <probe-code> <marker-seen:yes|no> <auth-required:yes|no>
ev_reach_verdict() {
    local ctl="$1" probe="$2" marker="${3:-no}" auth="${4:-no}"
    [[ "$ctl" == "000" && "$probe" == "000" ]] && { printf 'unreachable'; return; }
    [[ "$auth" == "yes" ]] && { printf 'auth-required'; return; }
    case "$probe" in
        401|403) printf 'auth-required'; return ;;
        404)     printf 'absent'; return ;;
        429)     printf 'rate-limited'; return ;;
        400|415|422) printf 'rejected'; return ;;
        5*)      printf 'handler-error'; return ;;
    esac
    [[ "$marker" == "yes" ]] && { printf 'injected'; return; }
    case "$probe" in
        200|201|202|204) printf 'accepted-unverified'; return ;;
    esac
    printf 'inconclusive'
}

# The severity depends on what the injected event REACHES, not on the fact
# that it was accepted. An accepted webhook that does nothing is not a finding.
#   ev_inject_severity <verdict> <target-class:function|queue|db|email|shell|unknown>
ev_inject_severity() {
    local v="$1" cls="${2:-unknown}"
    case "$v" in
        injected)
            case "$cls" in
                shell|function) printf 'CRITICAL' ;;
                db|queue)       printf 'HIGH' ;;
                email)          printf 'MEDIUM' ;;
                *)              printf 'HIGH' ;;
            esac ;;
        accepted-unverified) printf 'MEDIUM' ;;
        *)                   printf 'INFO' ;;
    esac
}

# what a target probably is, from its name or ARN
ev_target_class() {
    local t="${1,,}"
    case "$t" in
        *shell*|*exec*|*cmd*|*system*)     printf 'shell'; return ;;
        *email*|*ses*|*mail*|*notify*|*sms*) printf 'email'; return ;;
        *db*|*sql*|*rds*|*dynamo*|*firestore*) printf 'db'; return ;;
        *queue*|*sqs*|*topic*|*pubsub*|*kafka*) printf 'queue'; return ;;
        *lambda*|*function*|*func*|*worker*) printf 'function'; return ;;
    esac
    printf 'unknown'
}

# ── provider gates ──────────────────────────────────────────────
ev_have() { command -v "$1" >/dev/null 2>&1; }

ev_state_aws() {
    ev_have aws || { printf 'no-tool'; return; }
    aws sts get-caller-identity >/dev/null 2>&1 && printf 'ready' || printf 'no-creds'
}
ev_state_gcp() {
    ev_have gcloud || { printf 'no-tool'; return; }
    gcloud auth print-access-token >/dev/null 2>&1 && printf 'ready' || printf 'no-creds'
}
ev_state_azure() {
    ev_have az || { printf 'no-tool'; return; }
    az account get-access-token >/dev/null 2>&1 && printf 'ready' || printf 'no-creds'
}

# ── live half ───────────────────────────────────────────────────

# --rules: every trigger wired to a target, and the target's class
ev_cmd_rules() {
    local st; st="$(ev_state_aws)"
    cs_row PROVIDER "aws" "$st"
    if [[ "$st" != "ready" ]]; then
        cs_row VERDICT "$st"; cs_row SUMMARY "verdict=$st rules=0"; return 0
    fi

    local n=0
    : > "$RULE_FILE"

    # S3 → anything
    local buckets b
    buckets="$(timeout "$EV_TIMEOUT" aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' | head -"$EV_MAX")"
    for b in $buckets; do
        [[ -z "$b" ]] && continue
        local nc
        nc="$(timeout "$EV_TIMEOUT" aws s3api get-bucket-notification-configuration --bucket "$b" 2>/dev/null)"
        [[ -z "$nc" || "$nc" == "{}" ]] && continue
        local arn
        arn="$(printf '%s' "$nc" | jq -r '
            (.LambdaFunctionConfigurations[]?.LambdaFunctionArn),
            (.QueueConfigurations[]?.QueueArn),
            (.TopicConfigurations[]?.TopicArn) | select(. != null)' 2>/dev/null | head -20)"
        local a
        for a in $arn; do
            [[ -z "$a" ]] && continue
            n=$((n + 1))
            local cls; cls="$(ev_target_class "$a")"
            printf 's3\t%s\t%s\t%s\n' "$b" "$a" "$cls" >> "$RULE_FILE"
            cs_row RULE "s3:ObjectCreated" "$b → $a" "target=$cls"
        done
    done

    # EventBridge rules
    local buses bus
    buses="$(timeout "$EV_TIMEOUT" aws events list-event-buses --query 'EventBuses[].Name' --output text 2>/dev/null | tr '\t' '\n')"
    for bus in $buses; do
        [[ -z "$bus" ]] && continue
        local rules r
        rules="$(timeout "$EV_TIMEOUT" aws events list-rules --event-bus-name "$bus" --query 'Rules[].[Name,State,EventPattern]' --output text 2>/dev/null | head -50)"
        while IFS=$'\t' read -r r state pattern; do
            [[ -z "$r" ]] && continue
            n=$((n + 1))
            printf 'eventbridge\t%s/%s\t%s\t%s\n' "$bus" "$r" "$state" "eventbridge" >> "$RULE_FILE"
            cs_row RULE "eventbridge" "$bus/$r" "state=$state"
            # a rule whose pattern is absent matches EVERY event on the bus
            if [[ -z "$pattern" || "$pattern" == "None" || "$pattern" == "{}" ]]; then
                cs_row FINDING "HIGH" "event-match-everything"
                ev_findings "$bus/$r" "HIGH" "event-match-everything" \
                    "the rule has no event pattern, so every event on the bus reaches the target"
            fi
        done <<< "$rules"
    done

    cs_row ARTIFACT "$RULE_FILE"
    cs_row VERDICT "enumerated"
    cs_row SUMMARY "verdict=enumerated rules=$n"
    return 0
}

# --trust <policy-json-or-url>: grade the source's resource policy. This is
# where an injection actually becomes possible, so it is graded on its own.
ev_cmd_trust() {
    local target="${1:-}"
    [[ -z "$target" ]] && { ev_log "usage: --trust <policy.json|sns-topic-arn|sqs-queue-url>"; return 2; }
    cs_row TARGET "$target"

    local doc=""
    if [[ -f "$target" ]]; then
        doc="$(cat "$target" 2>/dev/null)"
    elif [[ "$target" == arn:aws:sns:* ]]; then
        doc="$(timeout "$EV_TIMEOUT" aws sns get-topic-attributes --topic-arn "$target" \
            --query 'Attributes.Policy' --output text 2>/dev/null)"
    elif [[ "$target" == https://sqs.* ]]; then
        doc="$(timeout "$EV_TIMEOUT" aws sqs get-queue-attributes --queue-url "$target" \
            --attribute-names Policy --query 'Attributes.Policy' --output text 2>/dev/null)"
    fi

    if [[ -z "${doc// /}" || "$doc" == "None" ]]; then
        cs_row VERDICT "no-document"
        cs_row NOTE "no resource policy readable — pass a local json or an ARN with working credentials"
        cs_row SUMMARY "verdict=no-document"
        return 0
    fi

    local wildcard="no" noaccount="no" crossacct="no"
    printf '%s' "$doc" | grep -qaE '"Principal"[[:space:]]*:[[:space:]]*"\*"' && wildcard="yes"
    printf '%s' "$doc" | grep -qa 'SourceAccount' || noaccount="yes"
    printf '%s' "$doc" | grep -qaE '"AWS"[[:space:]]*:[[:space:]]*"arn:aws:iam::[0-9]+:root"' && crossacct="yes"

    cs_row WILDCARD-PRINCIPAL "$wildcard"
    cs_row NO-SOURCE-ACCOUNT "$noaccount"

    if [[ "$wildcard" == "yes" ]]; then
        cs_row FINDING "CRITICAL" "event-wildcard-principal"
        ev_findings "$target" "CRITICAL" "event-wildcard-principal" \
            "the source's resource policy names * as principal: any account may publish an event"
    fi
    if [[ "$wildcard" == "yes" && "$noaccount" == "yes" ]]; then
        cs_row FINDING "CRITICAL" "event-no-source-account"
        ev_findings "$target" "CRITICAL" "event-no-source-account" \
            "the policy admits anyone AND does not bind aws:SourceAccount, so a foreign account's event is indistinguishable"
    fi
    cs_row VERDICT "graded"
    cs_row SUMMARY "verdict=graded wildcard=$wildcard nosourceaccount=$noaccount"
    return 0
}

# --forge <kind>: print a realistic event body, so the operator can send it
# with whatever client the target speaks. Never sends anything itself.
ev_cmd_forge() {
    local kind="${1:-s3}"
    cs_row KIND "$kind"
    case "$kind" in
        s3)
            cat <<JSON | cs_row PAYLOAD "$(cat)"
{"Records":[{"eventSource":"aws:s3","eventName":"ObjectCreated:Put","awsRegion":"us-east-1",
"s3":{"bucket":{"name":"cloudsting-target","ownerIdentity":{"principalId":"CLOUDSTING"}},
"object":{"key":"probe.txt","size":11,"eTag":"00000000000000000000000000000000"}}}]}
JSON
            ;;
        sns)
            cat <<JSON | cs_row PAYLOAD "$(cat)"
{"Type":"Notification","MessageId":"00000000-0000-0000-0000-000000000000",
"TopicArn":"arn:aws:sns:us-east-1:111122223333:cloudsting","Subject":"cloudsting",
"Message":"{\"marker\":\"cloudsting-event\"}"}
JSON
            ;;
        eventbridge)
            cat <<JSON | cs_row PAYLOAD "$(cat)"
{"Source":"cloudsting.test","DetailType":"probe","Detail":"{\"marker\":\"cloudsting-event\"}",
"EventBusName":"default","Resources":[]}
JSON
            ;;
        webhook)
            cat <<JSON | cs_row PAYLOAD "$(cat)"
{"event":"probe","data":{"marker":"cloudsting-event"}}
JSON
            ;;
        *)
            cs_row VERDICT "unknown-kind"
            cs_row NOTE "kinds: s3 sns eventbridge webhook"
            cs_row SUMMARY "verdict=unknown-kind"
            return 0
            ;;
    esac
    cs_row VERDICT "forged"
    cs_row NOTE "printed only — this verb never sends an event"
    cs_row SUMMARY "verdict=forged kind=$kind"
    return 0
}

# --inject <url>: post a forged event to a webhook-style receiver and report
# what came back. The marker must appear in the response for a hit.
ev_cmd_inject() {
    local url="${1:-}" token="${2:-}"
    [[ -z "$url" ]] && { ev_log "usage: --inject <url> [bearer-token]"; return 2; }
    cs_row TARGET "$url"

    local -a hdr=(-H 'Content-Type: application/json')
    [[ -n "$token" ]] && hdr+=(-H "Authorization: Bearer $token")

    local body; body='{"event":"probe","data":{"marker":"'"$EV_MARKER"'"}}'

    # control first: a request with no marker tells us the baseline
    local cmeta ccode
    cmeta="$(timeout "$EV_TIMEOUT" curl -sk -o /dev/null -w '%{http_code} %{size_download}' \
        -X POST "${hdr[@]}" --data '{"event":"control"}' "$url" 2>/dev/null)"
    ccode="${cmeta%% *}"; ccode="${ccode:-000}"
    cs_row CONTROL "code=$ccode"

    local probe_out="$CS_SCRATCH/ev-probe.json"
    local pcode
    pcode="$(timeout "$EV_TIMEOUT" curl -sk -o "$probe_out" -w '%{http_code}' \
        -X POST "${hdr[@]}" --data "$body" "$url" 2>/dev/null)"
    pcode="${pcode:-000}"
    cs_row PROBE "code=$pcode"

    local marker="no"
    [[ -s "$probe_out" ]] && grep -qaF "$EV_MARKER" "$probe_out" 2>/dev/null && marker="yes"
    cs_row MARKER "$marker"

    local auth="no"
    [[ "$pcode" == "401" || "$pcode" == "403" ]] && auth="yes"
    local v; v="$(ev_reach_verdict "$ccode" "$pcode" "$marker" "$auth")"
    cs_row VERDICT "$v"

    if [[ "$v" == "injected" || "$v" == "accepted-unverified" ]]; then
        local cls; cls="$(ev_target_class "$url")"
        local sev; sev="$(ev_inject_severity "$v" "$cls")"
        cs_row HIT "$v" "marker=$marker" "target=$cls" "sev=$sev"
        ev_findings "$url" "$sev" "event-$v" \
            "a forged event was accepted with no source check; marker echoed=$marker, target class=$cls"
    fi
    cs_row SUMMARY "verdict=$v control=$ccode probe=$pcode marker=$marker"
    return 0
}

# --payload <kind>: does the handler trust an event field the caller sets
ev_cmd_payload() {
    local kind="${1:-s3}"
    cs_row KIND "$kind"
    local id class question cost
    while IFS=$'\t' read -r id cls question cost; do
        [[ -z "$id" ]] && continue
        [[ "$cls" != "content" && "$cls" != "identity" ]] && continue
        cs_row GAP "$id" "$cls" "$question" "$cost"
    done < <(ev_gaps)
    cs_row SUMMARY "kind=$kind gaps=$(ev_gaps | awk -F'\t' '$2=="content"' | wc -l | tr -d ' ')"
    return 0
}

ev_cmd_probe() {
    local id prov source who trusts
    while IFS=$'\t' read -r id prov source who trusts; do
        [[ -z "$id" ]] && continue
        local st="unknown"
        case "$prov" in
            aws)   st="$(ev_state_aws)" ;;
            gcp)   st="$(ev_state_gcp)" ;;
            azure) st="$(ev_state_azure)" ;;
            *)     st="n/a" ;;
        esac
        cs_row SOURCE "$id" "$prov" "$st"
    done < <(ev_sources)
    local aws_st; aws_st="$(ev_state_aws)"
    cs_row SUMMARY "aws=$aws_st sources=$(ev_sources | wc -l | tr -d ' ')"
    return 0
}

ev_cmd_sources() {
    local id prov source who trusts
    while IFS=$'\t' read -r id prov source who trusts; do
        [[ -z "$id" ]] && continue
        cs_row SOURCE "$id" "$prov" "$source" "$who"
    done < <(ev_sources)
    cs_row SUMMARY "sources=$(ev_sources | wc -l | tr -d ' ')"
    return 0
}

ev_cmd_techniques() {
    local id cls question cost
    while IFS=$'\t' read -r id cls question cost; do
        [[ -z "$id" ]] && continue
        cs_row GAP "$id" "$cls" "$question" "$cost"
    done < <(ev_gaps)
    cs_row SUMMARY "gaps=$(ev_gaps | wc -l | tr -d ' ')"
    return 0
}

ev_cmd_list() {
    cs_row VERB "probe" "sources" "rules" "forge" "inject" "trust" "payload" "techniques"
    cs_row SUMMARY "ok"
    return 0
}

ev_findings() {
    local target="$1" sev="$2" check="$3" detail="$4"
    cs_findings_row "$MODULE_ID" "COMPUTE" "$target" "${sev,,}-${check}" "$detail" > /dev/null
}

ev_cmd_status_tsv() {
    local aws_st; aws_st="$(ev_state_aws)"
    local st="no-provider"
    [[ "$aws_st" == "ready" ]] && st="provider-ready"
    [[ "$aws_st" == "no-tool" ]] && st="tool-missing"
    printf '%s\t%s\t%s\taws-%s\tsources-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$st" "$aws_st" "$(ev_sources | wc -l | tr -d ' ')"
}

ev_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ev_cmd_help() {
    cat <<'HELP'
cloudsting module 11 — Event Trigger Abuse v1.0.0
  --rules                            every trigger wired to a target
  --trust <policy.json|arn|url>      grade the source's resource policy
  --forge <s3|sns|eventbridge|webhook>  print a realistic event body
  --inject <url> [token]             post a forged event, report what came back
  --payload [kind]                   does the handler trust a caller-set field
  --probe | --sources | --techniques | --list | --status-tsv | --menu | --selftest | --help

Every cloud runs work in response to events: an object lands, a message
arrives, a schedule fires, a webhook posts. A SOURCE produces an event, a RULE
matches it, a TARGET runs something with an identity.

The finding lives in the gap between "the source is trusted" and "the rule does
not check who wrote it". A function triggered by s3:ObjectCreated can be fed by
any bucket in any account holding a PutObject grant, and the function's own
logs will show a legitimate event.

What it will not do:

  `--forge` prints a body and sends nothing. `--inject` posts and reports.

  a 200 is not a finding. Only an event carrying our marker reaching a handler
  we can see is `injected`; a bare 200 is `accepted-unverified` at MEDIUM.

  an accepted event that reaches nothing is not a finding either — the
  severity comes from the target class, and an unknown target grades MEDIUM.

Environment: EV_TIMEOUT (30), EV_MAX (200), EV_MARKER (cloudsting-event)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ev_selftest() {
    cs_selftest_reset
    local real_loot="$CS_LOOT"
    CS_LOOT="$CS_SCRATCH"
    mkdir -p "$CS_LOOT" 2>/dev/null || true

    local nsrc; nsrc="$(ev_sources | wc -l | tr -d ' ')"
    chk src-5col   "$(ev_sources | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk src-many   "$( (( nsrc >= 20 )) && echo many || echo few )" "many"
    chk src-unique "$(ev_sources | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nsrc"
    chk src-provs  "$(ev_sources | cut -f2 | sort -u | wc -l | tr -d ' ')" "7"

    local ng; ng="$(ev_gaps | wc -l | tr -d ' ')"
    chk gaps-4col  "$(ev_gaps | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk gaps-unique "$(ev_gaps | cut -f1 | sort -u | wc -l | tr -d ' ')" "$ng"
    chk gaps-many  "$( (( ng >= 12 )) && echo many || echo few )" "many"

    # the verdict table — an unreachable host is never "injected"
    chk r-unreach  "$(ev_reach_verdict 000 000 no no)" "unreachable"
    chk r-auth     "$(ev_reach_verdict 401 403 no yes)" "auth-required"
    chk r-absent   "$(ev_reach_verdict 200 404 no no)" "absent"
    chk r-rejected "$(ev_reach_verdict 200 422 no no)" "rejected"
    chk r-err      "$(ev_reach_verdict 200 500 no no)" "handler-error"
    chk r-injected "$(ev_reach_verdict 200 200 yes no)" "injected"
    chk r-unverif  "$(ev_reach_verdict 200 200 no no)" "accepted-unverified"
    chk r-202      "$(ev_reach_verdict 200 202 no no)" "accepted-unverified"

    # the severity ladder — reach matters, not acceptance
    chk s-shell    "$(ev_inject_severity injected shell)" "CRITICAL"
    chk s-func     "$(ev_inject_severity injected function)" "CRITICAL"
    chk s-db       "$(ev_inject_severity injected db)" "HIGH"
    chk s-email    "$(ev_inject_severity injected email)" "MEDIUM"
    chk s-unk      "$(ev_inject_severity injected unknown)" "HIGH"
    chk s-unverif  "$(ev_inject_severity accepted-unverified shell)" "MEDIUM"

    # the target classifier
    chk t-shell    "$(ev_target_class 'arn:aws:lambda:us-east-1:1:function:shell-runner')" "shell"
    chk t-func     "$(ev_target_class 'arn:aws:lambda:us-east-1:1:function:worker')" "function"
    chk t-queue    "$(ev_target_class 'arn:aws:sqs:us-east-1:1:jobs')" "queue"
    chk t-db       "$(ev_target_class 'arn:aws:rds:us-east-1:1:db:orders')" "db"
    chk t-email    "$(ev_target_class 'arn:aws:ses:us-east-1:1:notify')" "email"
    chk t-unk      "$(ev_target_class 'arn:aws:sns:us-east-1:1:mystery')" "unknown"

    # forge produces parseable json for every kind
    local k
    for k in s3 sns eventbridge webhook; do
        local out; out="$(ev_cmd_forge "$k" 2>/dev/null)"
        local payload
        payload="$(printf '%s' "$out" | awk -F'\t' '$1=="PAYLOAD"{print $2}')"
        chk "f-$k" "$(printf '%s' "$payload" | jq -e . >/dev/null 2>&1 && echo valid || echo invalid)" "valid"
        chk "f-$k-hits" "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    done
    ev_cmd_forge nonsense 2>/dev/null >/dev/null; chk f-unknown "$?" "0"

    # trust grading
    local d="$CS_SCRATCH/evt.$$"; mkdir -p "$d"
    cat > "$d/wild.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Publish","Resource":"*"}]}
J
    cat > "$d/tight.json" <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sns:Publish","Condition":{"StringEquals":{"aws:SourceAccount":"111122223333"}}}]}
J
    local out
    out="$(ev_cmd_trust "$d/wild.json" 2>/dev/null)"
    chk t-wild   "$(printf '%s' "$out" | awk -F'\t' '$1=="WILDCARD-PRINCIPAL"{print $2}')" "yes"
    chk t-wildhits "$(printf '%s' "$out" | grep -c '^FINDING')" "2"
    out="$(ev_cmd_trust "$d/tight.json" 2>/dev/null)"
    chk t-tight  "$(printf '%s' "$out" | awk -F'\t' '$1=="WILDCARD-PRINCIPAL"{print $2}')" "no"
    chk t-tighthits "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    out="$(ev_cmd_trust "$d/missing.json" 2>/dev/null)"
    chk t-nodoc  "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "no-document"

    # a dead host: control, probe, and NO finding
    out="$(ev_cmd_inject "http://127.0.0.1:9/probe" 2>/dev/null)"
    chk i-unreach "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk i-nohits "$(printf '%s' "$out" | grep -c '^FINDING')" "0"

    # no AWS here
    out="$(ev_cmd_rules 2>/dev/null)"
    chk l-state  "$(printf '%s' "$out" | awk -F'\t' '$1=="PROVIDER"{print $3}')" "no-tool"
    chk l-nohits "$(printf '%s' "$out" | grep -c '^FINDING')" "0"

    # usage
    ev_cmd_trust 2>/dev/null;  chk use-1 "$?" "2"
    ev_cmd_inject 2>/dev/null; chk use-2 "$?" "2"

    chk status-fields "$(ev_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(ev_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ev_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ev_cmd_help | head -1 | grep -ci 'Event Trigger')" "1"

    rm -rf "$d" 2>/dev/null || true
    CS_LOOT="$real_loot"
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --rules)      ev_cmd_rules;;
    --trust)      shift; ev_cmd_trust "$@";;
    --forge)      shift; ev_cmd_forge "$@";;
    --inject)     shift; ev_cmd_inject "$@";;
    --payload)    shift; ev_cmd_payload "$@";;
    --probe)      ev_cmd_probe;;
    --sources)    ev_cmd_sources;;
    --techniques) ev_cmd_techniques;;
    --list)       ev_cmd_list;;
    --status-tsv|--status) ev_cmd_status_tsv;;
    --menu)       ev_cmd_menu;;
    --selftest)   ev_selftest;;
    *)            ev_cmd_help;;
esac
