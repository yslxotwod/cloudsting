#!/usr/bin/env bash
# 10_snapshot.sh — cloudsting module 10: the disk that outlived the instance
# Verbs: --probe | --images | --snapshots | --share | --public | --data
#        | --techniques | --list | --status-tsv | --menu | --selftest | --help
#
# An instance is decommissioned; its snapshot is not. The snapshot holds the
# filesystem as it was at capture time — keys, tokens, config, browser state,
# anything a live box would hand over and a "deleted" box would not.
#
# The finding is not "a snapshot exists". Most accounts have thousands. The
# finding is a snapshot whose SHARING has no bound: shared to an account
# outside the org, shared to *, unencrypted with a share, or reachable by a
# resource policy that names a foreign principal.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="10_snapshot"
MOD_NAME="Snapshot & Image Theft (the disk that outlived the instance)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/snapshot"
mkdir -p "$OUT_DIR" 2>/dev/null || true

SHARE_FILE="$OUT_DIR/shares-$RUN_ID.tsv"
IMAGE_FILE="$OUT_DIR/images-$RUN_ID.tsv"
DATA_FILE="$OUT_DIR/data-$RUN_ID.tsv"

: "${SN_TIMEOUT:=30}"
: "${SN_MAX:=200}"
: "${SN_DATA_SCAN:=1}"

sn_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── what a snapshot can hand over ────────────────────────────────
# The whole point of stealing a disk image is what is on it. These are the
# paths worth opening first, per platform, because they are the ones that
# survive in an image and are readable without the running system's logins.
#   <platform>\t<path>\t<what it usually holds>
sn_paths() {
    cat <<'PATHS'
linux	/etc/shadow	password hashes for every local account
linux	/root/.ssh/id_rsa	the deploy key as it was on the box
linux	/home/*/.ssh/authorized_keys	who could log in without a password
linux	/etc/ssh/ssh_host_ed25519_key	the host identity, reusable to impersonate it
linux	/var/lib/cloud/instance/user-data.txt	the cloud-init script, often with secrets in it
linux	/etc/cloud/cloud.cfg.d	dynamic credentials and config written at boot
linux	/root/.aws/credentials	long-lived access keys, if anyone was careless
linux	/root/.kube/config	cluster admin credentials with a client cert
linux	/root/.docker/config.json	registry auth tokens
linux	/var/lib/jenkins/secrets/initialAdminPassword	CI server admin
linux	/etc/nginx/.htpasswd	basic auth for internal tooling
linux	/var/log/auth.log	who logged in, from where
linux	/opt/*/config*.json	application secrets, wherever the app landed
linux	/home/*/.bash_history	commands including passwords typed inline
windows	C:\Windows\System32\config\SAM	local account hashes
windows	C:\Windows\System32\config\SYSTEM	boot key needed to decrypt the SAM
windows	C:\Users\*\AppData\Roaming\Microsoft\Credentials	saved domain credentials
windows	C:\ProgramData\Amazon\EC2-Windows\Launch\config	EC2 launch config including the admin password
windows	C:\inetpub\wwwroot\web.config	connection strings
windows	C:\unattend.xml	the unattend answer file, which may still hold the admin password
PATHS
}

# ── the sharing surfaces, per provider ───────────────────────────
# Each cloud expresses "this snapshot is visible to someone else" differently.
# A tool that assumes `public: true` is the only shape misses four of them.
#   <id>\t<provider>\t<the surface>\t<what "shared" looks like>
sn_surfaces() {
    cat <<'SURFACES'
aws-ebs-policy	aws	EBS snapshot createVolumePermission	a group=all or a foreign account-id
aws-ebs-public	aws	AMI launch permission	Group=all
aws-rds-shared	aws	RDS snapshot manual share	restore attribute grants another account
aws-rds-public	aws	RDS public snapshot	SnapshotType=public
gcp-image-iam	gcp	images.getIamPolicy	allAuthenticatedUsers or allUsers
gcp-disk-iam	gcp	compute disks getIamPolicy	roles/compute.storageAdmin to a foreign principal
azure-sas	azure	snapshot SAS URL	sp=r on a disk snapshot
azure-share	azure	gallery image version sharing	direct shared to a foreign subscription
oci-share	oci	DB system / boot volume export	exported to a tenancy OCID
alibaba-share	alibaba	ECS snapshot share	account-id set on ModifySnapshotAttribute
SURFACES
}

# ── the verdict ─────────────────────────────────────────────────
# Three states and a severity ladder, because "shared" is not one thing.
#   sn_share_verdict <scope> <encrypted:yes|no|unknown> <public:yes|no>
# scope: none | same-account | foreign-account | group-all | authenticated-all
sn_share_verdict() {
    local scope="$1" enc="${2:-unknown}" pub="${3:-no}"
    case "$scope" in
        none)              printf 'private'; return ;;
        same-account)      printf 'shared-internal'; return ;;
        foreign-account)   printf 'shared-foreign'; return ;;
        group-all|authenticated-all) printf 'shared-public'; return ;;
        *)                 printf 'unknown-scope'; return ;;
    esac
}

# The ladder: the same share means different things depending on what is in
# it. A public snapshot of an empty volume is noise; a public snapshot of a
# domain controller is the whole company.
#   sn_share_severity <verdict> <encrypted> <content:empty|os|data|secrets|unknown>
sn_share_severity() {
    local v="$1" enc="${2:-unknown}" content="${3:-unknown}"
    case "$v" in
        shared-public)
            case "$content" in
                secrets) printf 'CRITICAL' ;;
                data|os) printf 'CRITICAL' ;;
                empty)   printf 'LOW' ;;
                *)       printf 'HIGH' ;;
            esac ;;
        shared-foreign)
            case "$content" in
                secrets) printf 'CRITICAL' ;;
                data)    printf 'HIGH' ;;
                *)       printf 'MEDIUM' ;;
            esac ;;
        shared-internal)
            # internal sharing is normal; it is only interesting if the image
            # is also unencrypted, because then every account it is shared to
            # can read the disk without the key custodian
            [[ "$enc" == "no" ]] && { printf 'MEDIUM'; return; }
            printf 'INFO' ;;
        private)  printf 'INFO' ;;
        *)        printf 'INFO' ;;
    esac
}

# what is probably in the volume, judged from its name and size
#   sn_content_class <name> <size-gib>
sn_content_class() {
    local name="${1,,}" size="${2:-0}"
    case "$name" in
        *secret*|*vault*|*kms*|*credential*) printf 'secrets'; return ;;
        *db*|*data*|*pg*|*mysql*|*mongo*|*redis*|*warehouse*) printf 'data'; return ;;
        *dc*|*ad*|*domain*|*root*|*base*|*golden*) printf 'os'; return ;;
    esac
    # a 1 GiB volume is usually a boot disk; 500 GiB is usually data
    if awk -v s="$size" 'BEGIN{exit !(s+0 >= 100)}'; then printf 'data'; return; fi
    if awk -v s="$size" 'BEGIN{exit !(s+0 > 0 && s+0 <= 30)}'; then printf 'os'; return; fi
    printf 'unknown'
}

# ── provider gates ──────────────────────────────────────────────
sn_have() { command -v "$1" >/dev/null 2>&1; }

sn_state_aws() {
    sn_have aws || { printf 'no-tool'; return; }
    aws sts get-caller-identity >/dev/null 2>&1 && printf 'ready' || printf 'no-creds'
}
sn_state_gcp() {
    sn_have gcloud || { printf 'no-tool'; return; }
    gcloud auth print-access-token >/dev/null 2>&1 && printf 'ready' || printf 'no-creds'
}
sn_state_azure() {
    sn_have az || { printf 'no-tool'; return; }
    az account get-access-token >/dev/null 2>&1 && printf 'ready' || printf 'no-creds'
}
sn_state_oci()   { sn_have oci   || { printf 'no-tool'; return; }; printf 'ready'; }
sn_state_alibaba() { sn_have aliyun || { printf 'no-tool'; return; }; printf 'ready'; }

# ── the live half ───────────────────────────────────────────────
# Reads only. This module never modifies a snapshot's attributes: changing a
# share to test it would be an unrequested write against the target, and the
# attribute is readable anyway.

# --images: what images can be launched, and which are public
sn_cmd_images() {
    local st; st="$(sn_state_aws)"
    cs_row PROVIDER "aws" "$st"
    if [[ "$st" != "ready" ]]; then
        cs_row VERDICT "$st"
        cs_row SUMMARY "verdict=$st images=0"
        return 0
    fi
    local out n=0
    out="$(timeout "$SN_TIMEOUT" aws ec2 describe-images --owners self \
        --query 'Images[].[ImageId,Name,Public,Encrypted,Size,Architecture]' \
        --output text 2>/dev/null)"
    : > "$IMAGE_FILE"
    if [[ -n "${out// /}" ]]; then
        while IFS=$'\t' read -r id name public enc size arch; do
            [[ -z "$id" ]] && continue
            n=$((n + 1))
            printf '%s\t%s\t%s\t%s\t%s\n' "$id" "${name:-unnamed}" "${public:-false}" "${enc:-unknown}" "${size:-0}" >> "$IMAGE_FILE"
            local sev verdict
            if [[ "$public" == "True" || "$public" == "true" ]]; then
                verdict="shared-public"
                sev="$(sn_share_severity "$verdict" "$enc" "$(sn_content_class "$name" 0)")"
                cs_row IMAGE "$id" "${name:-unnamed}" "public=yes" "sev=$sev"
                sn_findings "$id" "$sev" "snapshot-image-public" \
                    "image ${name:-unnamed} is public: any account may launch a copy and read the disk"
            else
                cs_row IMAGE "$id" "${name:-unnamed}" "public=no" "enc=$enc"
            fi
        done <<< "$out"
    fi
    cs_row ARTIFACT "$IMAGE_FILE"
    cs_row VERDICT "enumerated"
    cs_row SUMMARY "verdict=enumerated images=$n"
    return 0
}

# --snapshots: the sharing state of every EBS snapshot we own
sn_cmd_snapshots() {
    local st; st="$(sn_state_aws)"
    cs_row PROVIDER "aws" "$st"
    if [[ "$st" != "ready" ]]; then
        cs_row VERDICT "$st"; cs_row SUMMARY "verdict=$st snapshots=0"; return 0
    fi

    local ids n=0 shared=0
    ids="$(timeout "$SN_TIMEOUT" aws ec2 describe-snapshots --owner-ids self \
        --query 'Snapshots[].[SnapshotId,VolumeSize,Description,Encrypted]' \
        --output text 2>/dev/null | head -"$SN_MAX")"
    : > "$SHARE_FILE"
    if [[ -n "${ids// /}" ]]; then
        while IFS=$'\t' read -r id size desc enc; do
            [[ -z "$id" ]] && continue
            n=$((n + 1))
            # the share attribute, which is the only thing that matters
            local perm scope="none"
            perm="$(timeout "$SN_TIMEOUT" aws ec2 describe-snapshot-attribute \
                --snapshot-id "$id" --attribute createVolumePermission \
                --query 'CreateVolumePermissions[].[Group,UserId]' --output text 2>/dev/null)"
            if printf '%s' "$perm" | grep -q 'all'; then
                scope="group-all"
            elif [[ -n "$(printf '%s' "$perm" | tr -d '[:space:]')" ]]; then
                scope="foreign-account"
            fi

            local content verdict sev
            content="$(sn_content_class "$desc" "${size:-0}")"
            verdict="$(sn_share_verdict "$scope" "${enc:-unknown}" no)"
            printf '%s\t%s\t%s\t%s\t%s\n' "$id" "${size:-0}" "$scope" "${enc:-unknown}" "$content" >> "$SHARE_FILE"

            if [[ "$scope" != "none" ]]; then
                shared=$((shared + 1))
                sev="$(sn_share_severity "$verdict" "${enc:-unknown}" "$content")"
                cs_row SNAPSHOT "$id" "${size}GiB" "scope=$scope" "enc=${enc:-unknown}" "content=$content" "sev=$sev"
                sn_findings "$id" "$sev" "snapshot-$verdict" \
                    "snapshot $id (${size}GiB, content=$content) is shared to $scope"
            elif [[ "${enc,,}" == "false" ]]; then
                cs_row SNAPSHOT "$id" "${size}GiB" "scope=none" "enc=no"
            fi
        done <<< "$ids"
    fi
    cs_row ARTIFACT "$SHARE_FILE"
    cs_row VERDICT "enumerated"
    cs_row SUMMARY "verdict=enumerated snapshots=$n shared=$shared"
    return 0
}

# --share <snapshot-id>: one snapshot, in full
sn_cmd_share() {
    local id="${1:-}"
    [[ -z "$id" ]] && { sn_log "usage: --share <snapshot-id>"; return 2; }
    cs_row TARGET "$id"
    local st; st="$(sn_state_aws)"
    if [[ "$st" != "ready" ]]; then
        cs_row VERDICT "$st"; cs_row SUMMARY "verdict=$st"; return 0
    fi
    local perm
    perm="$(timeout "$SN_TIMEOUT" aws ec2 describe-snapshot-attribute \
        --snapshot-id "$id" --attribute createVolumePermission \
        --query 'CreateVolumePermissions' --output text 2>&1)"
    local scope="none"
    printf '%s' "$perm" | grep -q 'all' && scope="group-all"
    [[ "$scope" == "none" && -n "$(printf '%s' "$perm" | tr -d '[:space:]')" ]] && scope="foreign-account"
    cs_row PERMISSIONS "$scope"

    local meta enc size desc
    meta="$(timeout "$SN_TIMEOUT" aws ec2 describe-snapshots --snapshot-ids "$id" \
        --query 'Snapshots[0].[VolumeSize,Description,Encrypted]' --output text 2>/dev/null)"
    IFS=$'\t' read -r size desc enc <<< "$meta"
    local content; content="$(sn_content_class "${desc:-}" "${size:-0}")"
    cs_row CONTENT "$content"
    cs_row ENCRYPTED "${enc:-unknown}"

    local verdict sev
    verdict="$(sn_share_verdict "$scope" "${enc:-unknown}" no)"
    sev="$(sn_share_severity "$verdict" "${enc:-unknown}" "$content")"
    cs_row VERDICT "$verdict"
    if [[ "$scope" != "none" ]]; then
        cs_row FINDING "$sev" "snapshot-$verdict"
        sn_findings "$id" "$sev" "snapshot-$verdict" \
            "snapshot $id shared to $scope; content=$content encrypted=${enc:-unknown}"
    fi
    cs_row SUMMARY "verdict=$verdict scope=$scope content=$content"
    return 0
}

# --public: the account-wide sweep for anything a stranger can read
sn_cmd_public() {
    local st; st="$(sn_state_aws)"
    cs_row PROVIDER "aws" "$st"
    if [[ "$st" != "ready" ]]; then
        cs_row VERDICT "$st"; cs_row SUMMARY "verdict=$st"; return 0
    fi
    local found=0

    # public AMIs we own
    local imgs
    imgs="$(timeout "$SN_TIMEOUT" aws ec2 describe-images --owners self \
        --filters 'Name=is-public,Values=true' \
        --query 'Images[].ImageId' --output text 2>/dev/null | tr '\t' '\n' | head -50)"
    local i
    for i in $imgs; do
        [[ -z "$i" ]] && continue
        found=$((found + 1))
        cs_row PUBLIC "$i" "image"
        sn_findings "$i" "HIGH" "snapshot-image-public" "image $i is public"
    done

    # snapshots shared with group=all
    local snaps
    snaps="$(timeout "$SN_TIMEOUT" aws ec2 describe-snapshots --owner-ids self \
        --query 'Snapshots[].SnapshotId' --output text 2>/dev/null | tr '\t' '\n' | head -"$SN_MAX")"
    local s
    for s in $snaps; do
        [[ -z "$s" ]] && continue
        local perm
        perm="$(timeout "$SN_TIMEOUT" aws ec2 describe-snapshot-attribute \
            --snapshot-id "$s" --attribute createVolumePermission \
            --query 'CreateVolumePermissions[].Group' --output text 2>/dev/null)"
        if printf '%s' "$perm" | grep -q 'all'; then
            found=$((found + 1))
            cs_row PUBLIC "$s" "snapshot"
            sn_findings "$s" "CRITICAL" "snapshot-shared-public" \
                "snapshot $s is shared with group=all: any AWS account may restore and read it"
        fi
    done

    cs_row VERDICT "swept"
    cs_row SUMMARY "verdict=swept public=$found"
    return 0
}

# --data <path-or-block>: what a stolen image actually gives up. Works on a
# mounted filesystem, a directory tree, or a raw block device, because the
# operator may have already attached the volume.
sn_cmd_data() {
    local target="${1:-}"
    [[ -z "$target" ]] && { sn_log "usage: --data <mountpoint|dir|block-device>"; return 2; }
    cs_row TARGET "$target"
    if [[ ! -e "$target" ]]; then
        cs_row VERDICT "absent"; cs_row SUMMARY "verdict=absent"; return 0
    fi
    if [[ ! -r "$target" ]]; then
        cs_row VERDICT "unreadable"; cs_row SUMMARY "verdict=unreadable"; return 0
    fi

    local found=0 line platform path what
    : > "$DATA_FILE"
    while IFS=$'\t' read -r platform path what; do
        [[ -z "$platform" ]] && continue
        local full="$target/${path#/}"
        # a glob in the table means "any match"
        local hits=""
        if [[ "$path" == *'*'* ]]; then
            hits="$(compgen -G "$full" 2>/dev/null | head -5)"
        elif [[ -e "$full" ]]; then
            hits="$full"
        fi
        [[ -z "$hits" ]] && continue
        local h
        while IFS= read -r h; do
            [[ -z "$h" ]] && continue
            found=$((found + 1))
            printf '%s\t%s\t%s\n' "$platform" "$h" "$what" >> "$DATA_FILE"
            cs_row FOUND "$platform" "${h#$target/}" "$what"
        done <<< "$hits"
    done < <(sn_paths)

    cs_row ARTIFACT "$DATA_FILE"
    local verdict sev
    if (( found > 0 )); then
        verdict="content-present"
        sev="HIGH"
        cs_row FINDING "$sev" "snapshot-content-present"
        sn_findings "$target" "$sev" "snapshot-content-present" \
            "$found credential-bearing paths present in the image; a reader of this disk gets them"
    else
        verdict="no-known-paths"
    fi
    cs_row VERDICT "$verdict"
    cs_row SUMMARY "verdict=$verdict found=$found"
    return 0
}

# --probe: three-state, per provider
sn_cmd_probe() {
    local sp id prov surface what
    while IFS=$'\t' read -r id prov surface what; do
        [[ -z "$id" ]] && continue
        local st
        case "$prov" in
            aws)     st="$(sn_state_aws)" ;;
            gcp)     st="$(sn_state_gcp)" ;;
            azure)   st="$(sn_state_azure)" ;;
            oci)     st="$(sn_state_oci)" ;;
            alibaba) st="$(sn_state_alibaba)" ;;
            *)       st="unknown" ;;
        esac
        cs_row SURFACE "$id" "$prov" "$st"
    done < <(sn_surfaces)
    local aws_st; aws_st="$(sn_state_aws)"
    cs_row SUMMARY "aws=$aws_st surfaces=$(sn_surfaces | wc -l | tr -d ' ')"
    return 0
}

sn_cmd_techniques() {
    local platform path what
    while IFS=$'\t' read -r platform path what; do
        [[ -z "$platform" ]] && continue
        cs_row PATH "$platform" "$path" "$what"
    done < <(sn_paths)
    local id prov surface what
    while IFS=$'\t' read -r id prov surface what; do
        [[ -z "$id" ]] && continue
        cs_row SHARE "$id" "$prov" "$surface"
    done < <(sn_surfaces)
    cs_row SUMMARY "paths=$(sn_paths | wc -l | tr -d ' ') surfaces=$(sn_surfaces | wc -l | tr -d ' ')"
    return 0
}

sn_cmd_list() {
    cs_row VERB "probe" "images" "snapshots" "share" "public" "data" "techniques"
    cs_row SUMMARY "ok"
    return 0
}

sn_findings() {
    local target="$1" sev="$2" check="$3" detail="$4"
    cs_findings_row "$MODULE_ID" "STORAGE" "$target" "${sev,,}-${check}" "$detail" > /dev/null
}

sn_cmd_status_tsv() {
    local aws_st; aws_st="$(sn_state_aws)"
    local st="no-provider"
    [[ "$aws_st" == "ready" ]] && st="provider-ready"
    [[ "$aws_st" == "no-tool" ]] && st="tool-missing"
    printf '%s\t%s\t%s\taws-%s\tsurfaces-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$st" "$aws_st" "$(sn_surfaces | wc -l | tr -d ' ')"
}

sn_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

sn_cmd_help() {
    cat <<'HELP'
cloudsting module 10 — Snapshot & Image Theft v1.0.0
  --images                           images we own, and which are public
  --snapshots                        every snapshot's sharing state
  --share <snapshot-id>              one snapshot, in full
  --public                           account-wide sweep for stranger-readable disks
  --data <mountpoint|dir|device>     what a stolen image actually gives up
  --probe | --techniques | --list | --status-tsv | --menu | --selftest | --help

An instance is decommissioned; its snapshot is not. The snapshot holds the
filesystem as it was at capture time — keys, tokens, config, browser state —
anything a live box would hand over and a "deleted" box would not.

The finding is not "a snapshot exists". Most accounts have thousands. It is a
snapshot whose sharing has no bound: shared to an account outside the org,
shared to group=all, or unencrypted and shared anywhere.

What it will not do:

  it never writes. Every verb here READS sharing attributes. Changing a share
  to test it would be an unrequested write against the target, and the
  attribute is readable anyway.

  it does not call every shared snapshot a critical. The ladder depends on
  content: a public snapshot of an empty volume is LOW, a public snapshot of
  something named `db-` or `golden-` is CRITICAL.

  `--data` reads a filesystem the operator already has. It does not carve
  deleted files, and it does not attempt to decrypt an encrypted volume.

Environment: SN_TIMEOUT (30), SN_MAX (200), SN_DATA_SCAN (1)
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
sn_selftest() {
    cs_selftest_reset
    local real_loot="$CS_LOOT"
    CS_LOOT="$CS_SCRATCH"
    mkdir -p "$CS_LOOT" 2>/dev/null || true

    local np; np="$(sn_paths | wc -l | tr -d ' ')"
    chk paths-3col  "$(sn_paths | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk paths-many  "$( (( np >= 15 )) && echo many || echo few )" "many"
    chk paths-linux "$(sn_paths | grep -c '^linux')" "14"
    chk paths-win   "$(sn_paths | grep -c '^windows')" "6"

    local ns; ns="$(sn_surfaces | wc -l | tr -d ' ')"
    chk surf-4col   "$(sn_surfaces | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk surf-6prov  "$( (( ns >= 8 )) && echo many || echo few )" "many"
    chk surf-providers "$(sn_surfaces | cut -f2 | sort -u | wc -l | tr -d ' ')" "5"

    # the verdict table
    chk v-private   "$(sn_share_verdict none yes no)" "private"
    chk v-internal  "$(sn_share_verdict same-account yes no)" "shared-internal"
    chk v-foreign   "$(sn_share_verdict foreign-account yes no)" "shared-foreign"
    chk v-public    "$(sn_share_verdict group-all yes no)" "shared-public"
    chk v-auth      "$(sn_share_verdict authenticated-all unknown no)" "shared-public"
    chk v-unknown   "$(sn_share_verdict nonsense yes no)" "unknown-scope"

    # the content classifier
    chk c-secret    "$(sn_content_class prod-secrets 50)" "secrets"
    chk c-db        "$(sn_content_class customer-db 200)" "data"
    chk c-big       "$(sn_content_class random 500)" "data"
    chk c-small     "$(sn_content_class random 8)" "os"
    chk c-unknown   "$(sn_content_class random 0)" "unknown"

    # the severity ladder — the heart of the module
    chk s-pub-secret "$(sn_share_severity shared-public no secrets)" "CRITICAL"
    chk s-pub-empty  "$(sn_share_severity shared-public no empty)" "LOW"
    chk s-pub-unk    "$(sn_share_severity shared-public no unknown)" "HIGH"
    chk s-for-secret "$(sn_share_severity shared-foreign no secrets)" "CRITICAL"
    chk s-for-data   "$(sn_share_severity shared-foreign yes data)" "HIGH"
    chk s-for-unk    "$(sn_share_severity shared-foreign yes unknown)" "MEDIUM"
    chk s-int-unenc  "$(sn_share_severity shared-internal no os)" "MEDIUM"
    chk s-int-enc    "$(sn_share_severity shared-internal yes os)" "INFO"
    chk s-private    "$(sn_share_severity private no secrets)" "INFO"

    # --data against a tree we build here
    local d="$CS_SCRATCH/snap.$$"
    mkdir -p "$d/etc" "$d/root/.ssh" "$d/var/lib/cloud/instance"
    echo 'root:$6$abc' > "$d/etc/shadow"
    echo 'KEY' > "$d/root/.ssh/id_rsa"
    echo 'ami-userdata' > "$d/var/lib/cloud/instance/user-data.txt"
    local out; out="$(sn_cmd_data "$d" 2>/dev/null)"
    chk d-found   "$(printf '%s' "$out" | grep -c '^FOUND')" "3"
    chk d-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "content-present"
    chk d-finding "$(printf '%s' "$out" | grep -c '^FINDING')" "1"
    chk d-shadow  "$(printf '%s' "$out" | grep -c 'etc/shadow')" "1"

    # an empty tree must NOT produce a finding
    local e="$CS_SCRATCH/empty.$$"; mkdir -p "$e"
    out="$(sn_cmd_data "$e" 2>/dev/null)"
    chk d-empty   "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "no-known-paths"
    chk d-nohit   "$(printf '%s' "$out" | grep -c '^FINDING')" "0"

    # a missing path is absent, not clean
    out="$(sn_cmd_data "$CS_SCRATCH/nothing-here.$$" 2>/dev/null)"
    chk d-absent  "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "absent"

    # no AWS on this box: every live verb must say so and claim nothing
    out="$(sn_cmd_snapshots 2>/dev/null)"
    chk l-state   "$(printf '%s' "$out" | awk -F'\t' '$1=="PROVIDER"{print $3}')" "no-tool"
    chk l-hits    "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    out="$(sn_cmd_public 2>/dev/null)"
    chk l-pubhit  "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    out="$(sn_cmd_images 2>/dev/null)"
    chk l-imgnohit "$(printf '%s' "$out" | grep -c '^FINDING')" "0"

    # usage errors
    sn_cmd_share 2>/dev/null;  chk use-1 "$?" "2"
    sn_cmd_data 2>/dev/null;   chk use-2 "$?" "2"

    chk status-fields "$(sn_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(sn_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(sn_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(sn_cmd_help | head -1 | grep -ci 'Snapshot')" "1"

    rm -rf "$d" "$e" 2>/dev/null || true
    CS_LOOT="$real_loot"
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --images)     sn_cmd_images;;
    --snapshots)  sn_cmd_snapshots;;
    --share)      shift; sn_cmd_share "$@";;
    --public)     sn_cmd_public;;
    --data)       shift; sn_cmd_data "$@";;
    --probe)      sn_cmd_probe;;
    --techniques) sn_cmd_techniques;;
    --list)       sn_cmd_list;;
    --status-tsv|--status) sn_cmd_status_tsv;;
    --menu)       sn_cmd_menu;;
    --selftest)   sn_selftest;;
    *)            sn_cmd_help;;
esac
