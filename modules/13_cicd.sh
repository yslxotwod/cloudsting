#!/usr/bin/env bash
# 13_cicd.sh — cloudsting module 13: from a commit to the runner to the credential
# Verbs: --probe | --pipelines | --runner | --secrets | --oidc | --branch
#        | --forge | --techniques | --list | --status-tsv | --menu | --selftest | --help
#
# A CI system is a machine that runs code from a repository with an identity
# richer than most humans have. The attack is never "break into CI" — it is
# "make CI run something", which is a much lower bar.
#
# Three doors, in ascending order of how little they need:
#   1. a pipeline file that a low-privilege contributor can edit
#   2. a runner that picks up work from a source it cannot authenticate
#   3. a long-lived cloud credential sitting in the CI secret store
#
# The finding is the DOOR, and each door has a different fix.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="13_cicd"
MOD_NAME="CI/CD Supply Chain (a commit, a runner, and the credential behind them)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/cicd"
mkdir -p "$OUT_DIR" 2>/dev/null || true

PIPE_FILE="$OUT_DIR/pipelines-$RUN_ID.tsv"
SECRET_FILE="$OUT_DIR/secrets-$RUN_ID.tsv"

: "${CI_TIMEOUT:=20}"
: "${CI_MAX_REPOS:=50}"

ci_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the CI systems worth looking at ─────────────────────────────
#   <id>\t<system>\t<where its config lives>\t<how you make it run code>
ci_systems() {
    cat <<'SYSTEMS'
github-actions	GitHub Actions	.github/workflows/*.yml	a pull_request from a fork, or a push to a branch the workflow watches
gitlab-ci	GitLab CI	.gitlab-ci.yml	a merge request, or a scheduled pipeline
jenkins	Jenkins	Jenkinsfile (or the job config)	anything that reaches the job's SCM
circleci	CircleCI	.circleci/config.yml	a push or an API trigger token
travis	Travis CI	.travis.yml	a push
azure-devops	Azure DevOps	azure-pipelines.yml	a PR validation build
bitbucket	Bitbucket Pipelines	bitbucket-pipelines.yml	a push or a PR
drone	Drone	.drone.yml	the webhook, which the repo controls
buildkite	Buildkite	.buildkite/pipeline.yml	the pipeline upload token
argo	Argo Workflows	a WorkflowTemplate in the cluster	cluster access
tekton	Tekton	a PipelineRun in the cluster	cluster access
cloudbuild	GCP Cloud Build	cloudbuild.yaml	a trigger on a repo, or a manual submit
codebuild	AWS CodeBuild	buildspec.yml	a CodePipeline or a manual start
SYSTEMS
}

# ── the doors ───────────────────────────────────────────────────
# Each row is something you can establish by READING config or hitting an
# endpoint, with no exploitation required.
#   <id>\t<door>\t<the question>\t<what a yes gives you>
ci_doors() {
    cat <<'DOORS'
fork-pr-runs	code	does CI run on pull requests from forks?	a stranger's code executes with the repo's token
fork-pr-secrets	secrets	does a fork PR get access to repository secrets?	a stranger's code reads the secrets
workflow-edit	code	can a contributor who is not an admin edit the workflow file?	merge a change that runs arbitrary code
unpinned-action	code	does the workflow use an action by tag rather than commit SHA?	the action's maintainer can change what runs
script-injection	code	does the workflow interpolate an issue/PR title into a shell step?	a title containing $(...) runs
cache-poison	cache	can a fork PR write the shared dependency cache?	poison artifacts used by the main branch
artifact-to-main	artifacts	can an untrusted job's artifact be consumed by a privileged job?	code crosses the trust boundary
self-hosted-runner	runner	does the repo use a self-hosted runner?	untrusted code lands on your network
runner-pool-open	runner	does the runner accept jobs from repos that are not yours?	anyone can queue work
runner-root	runner	does the runner execute as root or with a docker socket?	container escape straight to the host
long-lived-secret	secrets	does the CI store a static cloud access key?	exfiltrating it outlives the pipeline
oidc-untrusted-sub	secrets	does the OIDC trust accept any repository or any branch?	a fork can assume the deploy role
env-leak-in-logs	secrets	does the job echo environment variables into the log?	secrets in build logs forever
pr-target-checkout	code	does the workflow check out the PR head, not the base?	a fork's code runs where the base's did
DOORS
}

# ── the verdicts ────────────────────────────────────────────────
#   ci_fork_verdict <triggers-on-fork:yes|no> <secrets-given:yes|no|unknown> <approval:yes|no>
ci_fork_verdict() {
    local trig="${1:-no}" secrets="${2:-unknown}" approval="${3:-no}"
    [[ "$trig" != "yes" ]] && { printf 'no-fork-trigger'; return; }
    [[ "$approval" == "yes" ]] && { printf 'fork-gated'; return; }
    case "$secrets" in
        yes)     printf 'fork-with-secrets'; return ;;
        no)      printf 'fork-no-secrets'; return ;;
        unknown) printf 'fork-unknown-secrets'; return ;;
    esac
    printf 'fork-unknown-secrets'
}

# The ladder: a fork PR that runs without secrets is normal, deliberate
# open-source behaviour and is graded LOW. It only becomes an escalation when
# the same job can also reach the cache, an artifact, or the runner host.
ci_fork_severity() {
    local v="$1" self_hosted="${2:-no}"
    case "$v" in
        fork-with-secrets)      printf 'CRITICAL'; return ;;
        fork-unknown-secrets)   printf 'HIGH'; return ;;
        fork-no-secrets)
            [[ "$self_hosted" == "yes" ]] && { printf 'CRITICAL'; return; }
            printf 'LOW'; return ;;
        fork-gated)             printf 'INFO'; return ;;
        *)                      printf 'INFO'; return ;;
    esac
}

# the OIDC trust, which is where modern CI gets its cloud credentials
#   ci_oidc_verdict <sub-claim> <aud-claim>
ci_oidc_verdict() {
    local sub="${1:-}" aud="${2:-}"
    [[ -z "$sub" && -z "$aud" ]] && { printf 'no-oidc'; return; }
    if [[ -z "$aud" ]]; then printf 'oidc-no-audience'; return; fi
    case "$sub" in
        *'*'*)
            # a wildcard in the subject is fine if it is scoped to a repo
            # Test with a REGEX: inside a case glob the literal `repo:*` is
            # just characters in the pattern, so this never matched.
            if [[ "$sub" =~ repo: ]]; then
                printf 'oidc-wildcard'; return
            fi
            printf 'oidc-any-subject'; return ;;
        *':pull_request'*|*':pull_request_target'*)
            printf 'oidc-fork-reachable'; return ;;
    esac
    printf 'oidc-scoped'
}

# ── reading workflow files ──────────────────────────────────────
# Static analysis of the YAML a repository actually publishes. This is the half
# that works with no credentials at all, and it is where most real findings are.
ci_is_workflow() {
    local f="$1"
    [[ -f "$f" ]] || return 1
    case "$f" in
        *.yml|*.yaml|*Jenkinsfile|*.gitlab-ci*|*buildspec*|*cloudbuild*|*drone*) return 0 ;;
    esac
    return 1
}

#   ci_scan_file <path> -> rows of "<door>\t<severity>\t<evidence>"
ci_scan_file() {
    local f="$1"
    [[ -r "$f" ]] || return 1

    # fork PRs
    if grep -qE '^\s*pull_request(_target)?\s*:' "$f" 2>/dev/null; then
        local target="no"
        grep -qE '^\s*pull_request_target\s*:' "$f" 2>/dev/null && target="yes"
        if [[ "$target" == "yes" ]]; then
            printf 'fork-pr-runs\tCRITICAL\t%s\n' "uses pull_request_target, which runs in the base repo's context with its secrets"
            printf 'pr-target-checkout\tCRITICAL\t%s\n' "pull_request_target combined with a checkout of the PR head runs fork code with base secrets"
        else
            printf 'fork-pr-runs\tLOW\t%s\n' "runs on pull_request (fork code, base-repo token withheld by default)"
        fi
    fi

    # an action pinned by tag, not by SHA
    # An action is pinned ONLY by a full 40-hex commit SHA. A tag (v4) or a
    # branch (main) both move. Read the ref after the @ and decide from its
    # shape: the first version of this test used `@v?[0-9]`, which every SHA
    # starting with a digit matched, so a correctly pinned action was reported
    # unpinned and an honest workflow produced a finding.
    local uses
    while IFS= read -r uses; do
        [[ -z "$uses" ]] && continue
        local ref="${uses##*@}"
        ref="${ref%%[[:space:]]*}"
        [[ "$ref" =~ ^[0-9a-f]{40}$ ]] && continue   # pinned to a commit
        case "$ref" in
            main|master|latest|HEAD|develop|trunk)
                printf 'unpinned-action\tHIGH\t%s\n' "action pinned to the moving branch '$ref'" ;;
            *)
                printf 'unpinned-action\tMEDIUM\t%s\n' "action pinned to the tag '$ref', which its maintainer can retarget" ;;
        esac
    done < <(grep -oE '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[^#[:space:]]+' "$f" 2>/dev/null | sed 's/^[^u]*uses:[[:space:]]*//')
    if grep -qE '^\s*-?\s*uses:\s*[^#]*@(main|master|latest)' "$f" 2>/dev/null; then
        printf 'unpinned-action\tHIGH\t%s\n' "an action is pinned to a moving branch"
    fi

    # interpolation into a shell step
    if grep -qE '\$\{\{\s*github\.event\.(issue|pull_request|comment|head_ref)' "$f" 2>/dev/null; then
        if grep -qE '^\s*-?\s*run:\s*\|' "$f" 2>/dev/null; then
            printf 'script-injection\tCRITICAL\t%s\n' "a caller-controlled value is interpolated into a multi-line shell step"
        else
            printf 'script-injection\tHIGH\t%s\n' "a caller-controlled value is interpolated into a shell command"
        fi
    fi

    # cache poisoning
    if grep -qE '^\s*uses:\s*actions/cache' "$f" 2>/dev/null; then
        printf 'cache-poison\tMEDIUM\t%s\n' "actions/cache without a fork guard lets a PR seed the shared cache"
    fi

    # artifacts crossing into a privileged job
    if grep -qE '^\s*uses:\s*actions/(download|upload)-artifact' "$f" 2>/dev/null; then
        printf 'artifact-to-main\tMEDIUM\t%s\n' "an artifact is shared between jobs; check the consumer's privilege"
    fi

    # self-hosted runners
    if grep -qE 'runs-on:.*self-hosted' "$f" 2>/dev/null; then
        printf 'self-hosted-runner\tHIGH\t%s\n' "a self-hosted runner executes here; check what it can reach"
    fi

    # secrets in env / echo
    if grep -qE '^\s*env:' "$f" 2>/dev/null && grep -qE 'secrets\.' "$f" 2>/dev/null; then
        printf 'env-leak-in-logs\tMEDIUM\t%s\n' "repository secrets are placed in env, where any echo of the environment prints them"
    fi

    # a static cloud key, which is the thing OIDC exists to remove
    if grep -qE 'AWS_ACCESS_KEY_ID|AZURE_CLIENT_SECRET|GCP_SA_KEY|GOOGLE_APPLICATION_CREDENTIALS' "$f" 2>/dev/null; then
        printf 'long-lived-secret\tHIGH\t%s\n' "the pipeline references a static cloud credential instead of OIDC"
    fi

    # OIDC trust, if this file configures it
    local sub aud
    sub="$(grep -oE 'sub[":= ]+[^,}]*' "$f" 2>/dev/null | head -1)"
    aud="$(grep -oE 'aud[":= ]+[^,}]*' "$f" 2>/dev/null | head -1)"
    if [[ -n "$sub" ]]; then
        local v; v="$(ci_oidc_verdict "$sub" "$aud")"
        case "$v" in
            oidc-any-subject) printf 'oidc-untrusted-sub\tCRITICAL\t%s\n' "the OIDC sub claim has a wildcard that is not repository-scoped: $sub" ;;
            oidc-wildcard)    printf 'oidc-untrusted-sub\tMEDIUM\t%s\n' "the OIDC sub claim is wildcarded within a repository: $sub" ;;
            oidc-fork-reachable) printf 'oidc-untrusted-sub\tCRITICAL\t%s\n' "the OIDC trust accepts a pull_request subject, so a fork reaches it: $sub" ;;
            oidc-no-audience) printf 'oidc-untrusted-sub\tHIGH\t%s\n' "the OIDC trust sets no audience, so a token minted for another service is accepted" ;;
        esac
    fi
    return 0
}

# ── live half: what the forge will tell us ─────────────────────
ci_have() { command -v "$1" >/dev/null 2>&1; }

ci_state_gh() {
    ci_have gh || { printf 'no-tool'; return; }
    gh auth status >/dev/null 2>&1 && printf 'ready' || printf 'no-creds'
}
ci_state_glab() {
    ci_have glab || { printf 'no-tool'; return; }
    glab auth status >/dev/null 2>&1 && printf 'ready' || printf 'no-creds'
}

# --pipelines [owner]: list repos and whether their workflows run on forks
ci_cmd_pipelines() {
    local owner="${1:-}"
    cs_row OWNER "${owner:-auto}"
    local st; st="$(ci_state_gh)"
    cs_row PROVIDER "github" "$st"
    if [[ "$st" != "ready" ]]; then
        cs_row VERDICT "$st"; cs_row SUMMARY "verdict=$st repos=0"; return 0
    fi

    local -a args=(repo list --limit "$CI_MAX_REPOS" --json nameWithOwner,visibility,isFork)
    [[ -n "$owner" ]] && args+=(--owner "$owner")
    local repos
    repos="$(timeout "$CI_TIMEOUT" gh "${args[@]}" 2>/dev/null)"
    if [[ -z "$repos" ]]; then
        cs_row VERDICT "no-repos"; cs_row SUMMARY "verdict=no-repos"; return 0
    fi

    local n=0
    : > "$PIPE_FILE"
    local repo vis
    while IFS=$'\t' read -r repo vis; do
        [[ -z "$repo" ]] && continue
        n=$((n + 1))
        # the workflow list is metadata only; the files are read by --secrets
        local wf
        wf="$(timeout "$CI_TIMEOUT" gh api "repos/$repo/actions/workflows" \
            --jq '.workflows[]? | "\(.name)\t\(.path)"' 2>/dev/null | head -20)"
        printf '%s\t%s\t%s\n' "$repo" "$vis" "$(printf '%s' "$wf" | wc -l | tr -d ' ')" >> "$PIPE_FILE"
        cs_row REPO "$repo" "visibility=$vis" "workflows=$(printf '%s' "$wf" | wc -l | tr -d ' ')"
    done < <(printf '%s' "$repos" | jq -r '.[] | "\(.nameWithOwner)\t\(.visibility)"' 2>/dev/null)

    cs_row ARTIFACT "$PIPE_FILE"
    cs_row VERDICT "enumerated"
    cs_row SUMMARY "verdict=enumerated repos=$n"
    return 0
}

# --branch <repo>: what a non-admin contributor could merge
ci_cmd_branch() {
    local repo="${1:-}"
    [[ -z "$repo" ]] && { ci_log "usage: --branch <owner/repo>"; return 2; }
    cs_row TARGET "$repo"
    local st; st="$(ci_state_gh)"
    if [[ "$st" != "ready" ]]; then
        cs_row VERDICT "$st"; cs_row SUMMARY "verdict=$st"; return 0
    fi
    local prot
    prot="$(timeout "$CI_TIMEOUT" gh api "repos/$repo/branches/main/protection" 2>&1)"
    if printf '%s' "$prot" | grep -qi 'Branch not protected\|Not Found'; then
        cs_row PROTECTED "no"
        cs_row FINDING "HIGH" "cicd-branch-unprotected"
        ci_findings "$repo" "HIGH" "cicd-branch-unprotected" \
            "main is unprotected: a contributor can push straight to the branch the deploy workflow watches"
    else
        cs_row PROTECTED "yes"
        local reviews
        reviews="$(printf '%s' "$prot" | jq -r '.required_pull_request_reviews.required_approving_review_count // 0' 2>/dev/null)"
        cs_row REQUIRED-REVIEWS "${reviews:-0}"
        if [[ "${reviews:-0}" == "0" ]]; then
            cs_row FINDING "MEDIUM" "cicd-no-review-required"
            ci_findings "$repo" "MEDIUM" "cicd-no-review-required" \
                "the branch is protected but requires no approving review, so a contributor can self-merge"
        fi
    fi
    cs_row VERDICT "graded"
    cs_row SUMMARY "verdict=graded protected=${prot:+checked}"
    return 0
}

# --secrets [workflow-file-or-dir]: the static half, and the strongest verb
ci_cmd_secrets() {
    local target="${1:-}"
    [[ -z "$target" ]] && { ci_log "usage: --secrets <workflow-file|directory>"; return 2; }
    cs_row TARGET "$target"

    local -a files=()
    if [[ -d "$target" ]]; then
        while IFS= read -r f; do files+=("$f"); done < <(
            find "$target" -maxdepth 4 -type f \
                \( -name '*.yml' -o -name '*.yaml' -o -name 'Jenkinsfile' -o -name 'buildspec*' -o -name 'cloudbuild*' \) \
                2>/dev/null | head -200
        )
    else
        files=("$target")
    fi

    if (( ${#files[@]} == 0 )); then
        cs_row VERDICT "no-workflows"
        cs_row SUMMARY "verdict=no-workflows files=0"
        return 0
    fi

    local hits=0 f
    : > "$SECRET_FILE"
    for f in "${files[@]}"; do
        local rows; rows="$(ci_scan_file "$f" 2>/dev/null)"
        [[ -z "$rows" ]] && continue
        local door sev evidence
        while IFS=$'\t' read -r door sev evidence; do
            [[ -z "$door" ]] && continue
            hits=$((hits + 1))
            printf '%s\t%s\t%s\t%s\n' "$f" "$door" "$sev" "$evidence" >> "$SECRET_FILE"
            cs_row DOOR "$door" "$(basename "$f")" "sev=$sev" "$evidence"
            ci_findings "$f" "$sev" "cicd-$door" "$evidence"
        done <<< "$rows"
    done

    cs_row ARTIFACT "$SECRET_FILE"
    cs_row VERDICT "scanned"
    cs_row SUMMARY "verdict=scanned files=${#files[@]} doors=$hits"
    return 0
}

# --runner [url]: is a self-hosted runner reachable and does it take anyone's job
ci_cmd_runner() {
    local url="${1:-}"
    [[ -z "$url" ]] && { ci_log "usage: --runner <base-url>"; return 2; }
    cs_row TARGET "$url"

    local code
    code="$(timeout "$CI_TIMEOUT" curl -sk -o /dev/null -w '%{http_code}' "${url%/}/" 2>/dev/null)"
    code="${code:-000}"
    cs_row REACHABLE "$code"
    case "$code" in
        000)    cs_row VERDICT "unreachable" ;;
        401|403) cs_row VERDICT "auth-required" ;;
        200|301|302) cs_row VERDICT "responding" ;;
        *)      cs_row VERDICT "responding" ;;
    esac
    # the runner's own registration endpoint, which reveals whether it accepts
    # registration tokens from anywhere
    local reg
    reg="$(timeout "$CI_TIMEOUT" curl -sk -o /dev/null -w '%{http_code}' "${url%/}/api/v4/runners/all" 2>/dev/null)"
    cs_row RUNNER-API "${reg:-000}"
    cs_row SUMMARY "verdict=$(cs_row 2>/dev/null; printf '%s' "$code" | grep -q '^000$' && echo unreachable || echo responding)"
    return 0
}

# --oidc [trust-policy-json]: the CI→cloud bridge, graded on its own
ci_cmd_oidc() {
    local target="${1:-}"
    [[ -z "$target" ]] && { ci_log "usage: --oidc <trust-policy.json>"; return 2; }
    cs_row TARGET "$target"
    if [[ ! -r "$target" ]]; then
        cs_row VERDICT "absent"; cs_row SUMMARY "verdict=absent"; return 0
    fi
    local doc; doc="$(cat "$target" 2>/dev/null)"
    local sub aud
    # A real trust policy spells these `<issuer>:sub` and `<issuer>:aud`, so
    # take the whole key AND its value; a bare "sub" property never appears.
    # Two spellings occur: a flattened `"<issuer>:sub": "*"` and the nested
    # `"token.actions.githubusercontent.com:sub": "*"`. Take the value after
    # the first colon that FOLLOWS the `:sub` marker.
    sub="$(printf '%s' "$doc" | grep -oE '"[^"]*:sub"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/^"[^"]*"[[:space:]]*:[[:space:]]*"//; s/"$//')"
    aud="$(printf '%s' "$doc" | grep -oE '"[^"]*:aud"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/^"[^"]*"[[:space:]]*:[[:space:]]*"//; s/"$//')"
    cs_row SUB "${sub:-none}"
    cs_row AUD "${aud:-none}"
    local v; v="$(ci_oidc_verdict "$sub" "$aud")"
    cs_row VERDICT "$v"
    case "$v" in
        oidc-any-subject|oidc-fork-reachable)
            cs_row FINDING "CRITICAL" "cicd-$v"
            ci_findings "$target" "CRITICAL" "cicd-$v" \
                "the CI OIDC trust accepts a subject a fork can obtain: ${sub:-none}" ;;
        oidc-no-audience)
            cs_row FINDING "HIGH" "cicd-$v"
            ci_findings "$target" "HIGH" "cicd-$v" \
                "no audience is set, so any service can present a token for this role" ;;
        oidc-wildcard)
            cs_row FINDING "MEDIUM" "cicd-$v"
            ci_findings "$target" "MEDIUM" "cicd-$v" \
                "the OIDC subject is wildcarded within a repository: ${sub:-none}" ;;
    esac
    cs_row SUMMARY "verdict=$v"
    return 0
}

# --forge <system>: print a minimal workflow that would do the thing, so the
# operator can test whether the pipeline would actually accept it.
ci_cmd_forge() {
    local sys="${1:-github-actions}"
    cs_row SYSTEM "$sys"
    case "$sys" in
        github-actions)
            cat <<'YAML' | cs_row WORKFLOW "$(cat)"
name: probe
on:
  pull_request_target:
    types: [opened]
jobs:
  p:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: id && env | sort
YAML
            ;;
        gitlab-ci)
            cat <<'YAML' | cs_row WORKFLOW "$(cat)"
probe:
  script:
    - id
    - env | sort
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
YAML
            ;;
        jenkinsfile)
            cat <<'JENKINS' | cs_row WORKFLOW "$(cat)"
pipeline {
  agent any
  stages { stage('probe') { steps { sh 'id && env | sort' } } }
}
JENKINS
            ;;
        *)
            cs_row VERDICT "unknown-system"
            cs_row NOTE "systems: github-actions gitlab-ci jenkinsfile"
            cs_row SUMMARY "verdict=unknown-system"
            return 0
            ;;
    esac
    cs_row VERDICT "forged"
    cs_row SUMMARY "verdict=forged system=$sys"
    return 0
}

ci_cmd_probe() {
    local gh; gh="$(ci_state_gh)"
    local gl; gl="$(ci_state_glab)"
    cs_row PROVIDER "github" "$gh"
    cs_row PROVIDER "gitlab" "$gl"
    cs_row PROVIDER "yaml-reader" "$(ci_have yq && printf 'ready' || printf 'no-tool')"
    cs_row SUMMARY "github=$gh gitlab=$gl systems=$(ci_systems | wc -l | tr -d ' ')"
    return 0
}

ci_cmd_techniques() {
    local id door question cost
    while IFS=$'\t' read -r id door question cost; do
        [[ -z "$id" ]] && continue
        cs_row DOOR "$id" "$door" "$question" "$cost"
    done < <(ci_doors)
    local sid system where how
    while IFS=$'\t' read -r sid system where how; do
        [[ -z "$sid" ]] && continue
        cs_row SYSTEM "$sid" "$where" "$how"
    done < <(ci_systems)
    cs_row SUMMARY "doors=$(ci_doors | wc -l | tr -d ' ') systems=$(ci_systems | wc -l | tr -d ' ')"
    return 0
}

ci_cmd_list() {
    cs_row VERB "probe" "pipelines" "runner" "secrets" "oidc" "branch" "forge" "techniques"
    cs_row SUMMARY "ok"
    return 0
}

ci_findings() {
    local target="$1" sev="$2" check="$3" detail="$4"
    cs_findings_row "$MODULE_ID" "COMPUTE" "$target" "${sev,,}-${check}" "$detail" > /dev/null
}

ci_cmd_status_tsv() {
    local gh; gh="$(ci_state_gh)"
    local st="no-provider"
    [[ "$gh" == "ready" ]] && st="provider-ready"
    [[ "$gh" == "no-tool" ]] && st="tool-missing"
    printf '%s\t%s\t%s\tgh-%s\tdoors-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$st" "$gh" "$(ci_doors | wc -l | tr -d ' ')"
}

ci_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ci_cmd_help() {
    cat <<'HELP'
cloudsting module 13 — CI/CD Supply Chain v1.0.0
  --secrets <file|dir>               static analysis of workflow files (no creds needed)
  --pipelines [owner]                repos and their workflows, via gh
  --branch <owner/repo>              is the branch the deploy watches protected
  --oidc <trust-policy.json>         grader for the CI-to-cloud OIDC trust
  --runner <base-url>                is a self-hosted runner reachable
  --forge <github-actions|gitlab-ci|jenkinsfile>  print a minimal proof workflow
  --probe | --techniques | --list | --status-tsv | --menu | --selftest | --help

A CI system is a machine that runs code from a repository with an identity
richer than most humans have. The attack is never "break into CI" — it is "make
CI run something", which is a much lower bar.

Three doors: a pipeline file a low-privilege contributor can edit; a runner
that picks up work it cannot authenticate; a long-lived cloud key in the CI
secret store.

What it will not do:

  `--forge` prints a workflow; it never pushes one, and it never opens a PR.

  a fork PR that runs without secrets is normal open-source behaviour and is
  graded LOW. It only escalates when the same job can also reach a cache, an
  artifact, or a self-hosted runner — which is why `pull_request_target` with
  a head checkout is CRITICAL and plain `pull_request` is not.

  `--secrets` reads files the operator already has. It does not clone, and it
  does not call any API to fetch them.

Environment: CI_TIMEOUT (20), CI_MAX_REPOS (50)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ci_selftest() {
    cs_selftest_reset
    local real_loot="$CS_LOOT"
    CS_LOOT="$CS_SCRATCH"
    mkdir -p "$CS_LOOT" 2>/dev/null || true

    local nd; nd="$(ci_doors | wc -l | tr -d ' ')"
    chk doors-4col  "$(ci_doors | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk doors-unique "$(ci_doors | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nd"
    chk doors-many  "$( (( nd >= 12 )) && echo many || echo few )" "many"

    local ns; ns="$(ci_systems | wc -l | tr -d ' ')"
    chk sys-4col    "$(ci_systems | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk sys-many    "$( (( ns >= 10 )) && echo many || echo few )" "many"

    # fork verdicts
    chk f-none      "$(ci_fork_verdict no no no)" "no-fork-trigger"
    chk f-gated     "$(ci_fork_verdict yes yes yes)" "fork-gated"
    chk f-secrets   "$(ci_fork_verdict yes yes no)" "fork-with-secrets"
    chk f-nosecret  "$(ci_fork_verdict yes no no)" "fork-no-secrets"
    chk f-unknown   "$(ci_fork_verdict yes unknown no)" "fork-unknown-secrets"

    # severities — the open-source case must stay LOW
    chk s-secrets   "$(ci_fork_severity fork-with-secrets no)" "CRITICAL"
    chk s-nosecret  "$(ci_fork_severity fork-no-secrets no)" "LOW"
    chk s-selfhost  "$(ci_fork_severity fork-no-secrets yes)" "CRITICAL"
    chk s-unknown   "$(ci_fork_severity fork-unknown-secrets no)" "HIGH"
    chk s-gated     "$(ci_fork_severity fork-gated no)" "INFO"

    # OIDC
    chk o-none      "$(ci_oidc_verdict "" "")" "no-oidc"
    chk o-noaud     "$(ci_oidc_verdict 'sub=repo:x' "")" "oidc-no-audience"
    chk o-scoped    "$(ci_oidc_verdict 'sub=repo:acme/app:ref:refs/heads/main' 'aud=sts.amazonaws.com')" "oidc-scoped"
    chk o-repo-wild "$(ci_oidc_verdict 'sub=repo:acme/app:*' 'aud=x')" "oidc-wildcard"
    chk o-any       "$(ci_oidc_verdict 'sub=*' 'aud=x')" "oidc-any-subject"
    chk o-fork      "$(ci_oidc_verdict 'sub=repo:acme/app:pull_request' 'aud=x')" "oidc-fork-reachable"

    # static scanning against files we write here
    local d="$CS_SCRATCH/cicd.$$"; mkdir -p "$d"

    cat > "$d/bad.yml" <<'YAML'
on:
  pull_request_target:
    types: [opened]
jobs:
  p:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/cache@v4
      - run: |
          echo "${{ github.event.pull_request.title }}"
      - run: echo $AWS_ACCESS_KEY_ID
YAML
    local out; out="$(ci_cmd_secrets "$d/bad.yml" 2>/dev/null)"
    local n; n="$(printf '%s' "$out" | grep -c '^DOOR')"
    chk s-doors    "$( (( n >= 5 )) && echo many || echo few )" "many"
    chk s-prtarget "$(printf '%s' "$out" | grep -c 'fork-pr-runs')" "1"
    chk s-selfhost "$(printf '%s' "$out" | grep -c 'self-hosted-runner')" "1"
    chk s-inject   "$(printf '%s' "$out" | grep -c 'script-injection')" "1"
        chk s-pinned   "$( (( $(printf '%s' "$out" | grep -c 'unpinned-action') >= 2 )) && echo many || echo few )" "many"
    chk s-static   "$(printf '%s' "$out" | grep -c 'long-lived-secret')" "1"
    chk s-verdict  "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "scanned"
    chk s-findings "$( (( $(printf '%s' "$out" | grep -c '^DOOR') > 0 )) && echo yes || echo no )" "yes"

    # a clean workflow must produce nothing
    cat > "$d/good.yml" <<'YAML'
on:
  push:
    branches: [main]
jobs:
  p:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: make test
YAML
    out="$(ci_cmd_secrets "$d/good.yml" 2>/dev/null)"
    chk s-clean    "$(printf '%s' "$out" | grep -c '^DOOR')" "0"

    # a plain pull_request trigger is LOW, not CRITICAL
    cat > "$d/fork.yml" <<'YAML'
on:
  pull_request:
jobs:
  p:
    runs-on: ubuntu-latest
    steps:
      - run: make test
YAML
    out="$(ci_cmd_secrets "$d/fork.yml" 2>/dev/null)"
        chk s-forklow  "$(printf '%s' "$out" | awk -F'\t' '$1=="DOOR" && $2=="fork-pr-runs"{print $4; exit}' | sed 's/^sev=//')" "LOW"

    # an empty dir is no-workflows, not clean
    local e="$CS_SCRATCH/empty.$$"; mkdir -p "$e"
    out="$(ci_cmd_secrets "$e" 2>/dev/null)"
    chk s-nowf     "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "no-workflows"

    # OIDC verb on a file
    # a wildcard subject WITH an audience is the "any repo may assume this
    # role" case; without one it is the lesser missing-audience case, so the
    # fixture must carry both keys to exercise the CRITICAL arm.
    printf '{"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"*","token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}\n' > "$d/oidc.json"
    out="$(ci_cmd_oidc "$d/oidc.json" 2>/dev/null)"
    chk o-verb     "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "oidc-any-subject"
    chk o-hit      "$(printf '%s' "$out" | grep -c '^FINDING')" "1"
    out="$(ci_cmd_oidc "$d/nothere.json" 2>/dev/null)"
    chk o-absent   "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "absent"

    # forge produces yaml for each system
    local sys
    for sys in github-actions gitlab-ci jenkinsfile; do
        out="$(ci_cmd_forge "$sys" 2>/dev/null)"
        chk "for-$sys" "$(printf '%s' "$out" | grep -c '^WORKFLOW')" "1"
    done
    ci_cmd_forge nope 2>/dev/null >/dev/null; chk for-unknown "$?" "0"

    # no gh here
    out="$(ci_cmd_probe 2>/dev/null)"
    chk p-gh       "$(printf '%s' "$out" | awk -F'\t' '$1=="PROVIDER" && $2=="github"{print (($3=="ready"||$3=="no-creds"||$3=="no-tool")?"three-state":"bad")}')" "three-state"
    out="$(ci_cmd_pipelines 2>/dev/null)"
    chk p-pipes    "$(printf '%s' "$out" | grep -c '^FINDING')" "0"

    # usage
    ci_cmd_secrets 2>/dev/null; chk use-1 "$?" "2"
    ci_cmd_oidc 2>/dev/null;    chk use-2 "$?" "2"
    ci_cmd_branch 2>/dev/null;  chk use-3 "$?" "2"

    chk status-fields "$(ci_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(ci_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ci_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ci_cmd_help | head -1 | grep -ci 'CI/CD')" "1"

    rm -rf "$d" "$e" 2>/dev/null || true
    CS_LOOT="$real_loot"
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --pipelines)  shift; ci_cmd_pipelines "$@";;
    --secrets)    shift; ci_cmd_secrets "$@";;
    --branch)     shift; ci_cmd_branch "$@";;
    --oidc)       shift; ci_cmd_oidc "$@";;
    --runner)     shift; ci_cmd_runner "$@";;
    --forge)      shift; ci_cmd_forge "$@";;
    --probe)      ci_cmd_probe;;
    --techniques) ci_cmd_techniques;;
    --list)       ci_cmd_list;;
    --status-tsv|--status) ci_cmd_status_tsv;;
    --menu)       ci_cmd_menu;;
    --selftest)   ci_selftest;;
    *)            ci_cmd_help;;
esac
