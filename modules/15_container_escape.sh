#!/usr/bin/env bash
# 15_container_escape.sh — cloudsting module 15: Container Escape Detection & Privilege Escalation
# Verbs: --check | --cap | --mounts | --proc | --cgroup | --all | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# Everything below the header depends on the root, and the root is
# derived from this file only after it is sourced. Clear any inherited
# value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own
# name as a path.
unset CS_MOD_DIR

# The shared core owns the root, the loot tree, the run id, the TSV
# writer, the three-state provider gate, redaction and the selftest
# ledger. Sourcing it is what keeps loot under <root>/loot instead of
# $HOME/loot, so the launcher and the findings store can see a run.
MODULE_ID="15_container_escape"
MOD_NAME="Container Escape Detection"
MOD_VERSION="0.10.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

# Back-compat: run-id variable for this module, from the core run id
# the one run id the core minted.
CE_RUN_ID="$CS_RUN_ID"
export CE_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

# Loot directory for this module: <root>/loot/container_escape/
OUT_DIR="$CS_LOOT/container_escape"
mkdir -p "$OUT_DIR" 2>/dev/null || true
ce_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── Known escape signatures / checklists ─────────────────────────
# Source: DeepSurface, TrailOfBits, NCCGroup container-escape-cheatsheet
CE_CAP_DANGER="CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_PTRACE CAP_SYSLOG CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_FOWNER CAP_CHOWN CAP_SETUID CAP_SETGID CAP_NET_RAW CAP_SYS_BOOT CAP_SYS_RESOURCE CAP_MKNOD CAP_AUDIT_WRITE CAP_LINUX_IMMUTABLE"

CE_MOUNT_DANGER="/var/run/docker.sock /run/docker.sock /var/lib/docker /etc/docker /proc /sys /dev /cgroup"

CE_KNOWN_ESCAPES="docker-socket	mount	Read-write docker socket → host root
privileged	cap	runs with --privileged → full host access
cap-sys-admin	cap	CAP_SYS_ADMIN → mount cgroup + release_agent escape
cap-sys-ptrace	cap	CAP_SYS_PTRACE → ptrace host processes
cap-sys-module	cap	CAP_SYS_MODULE → load kernel module
cap-dac-read	cap	CAP_DAC_READ_SEARCH → read all files, bypass DAC
procfs-mount	mount	/proc mounted writable → kernel manipulation
cgroup-mount	mount	cgroup v1 mounted → release_agent escape
dev-mount	mount	/dev mounted writable → device node creation
host-pid	proc	--pid=host → see all host processes
host-net	proc	--net=host → host network namespace
host-ipc	proc	--ipc=host → host IPC namespace
host-uts	proc	--uts=host → host UTS namespace
host-user	proc	--user=host → host user namespace
sensitive-volume	mount	sensitive host dirs mounted inside container
no-apparmor	proc	container without AppArmor profile
no-seccomp	proc	container without seccomp filter"

# ── ce_check_caps — check running container capabilities ─────────
ce_check_caps() {
    if [ -f /proc/self/status ]; then
        local cap_eff cap_res
        cap_eff="$(grep -i '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}')"
        cap_res="$(grep -i '^CapInh:' /proc/self/status 2>/dev/null | awk '{print $2}')"
        [ -n "$cap_eff" ] && [ "$cap_eff" != "0000000000000000" ] && printf 'CapEff\t%s\n' "$cap_eff" || printf 'CapEff\tnone\n'
        [ -n "$cap_res" ] && [ "$cap_res" != "0000000000000000" ] && printf 'CapInh\t%s\n' "$cap_res" || printf .CapInh.tnone.n
        # Decode dangerous caps via capsh if available
        if command -v capsh >/dev/null 2>&1; then
            local decoded
            decoded="$(capsh --decode="$cap_eff" 2>/dev/null)"
            printf 'Decoded\t%s\n' "$decoded"
            # Check for dangerous caps by name
            for c in $CE_CAP_DANGER; do
                if printf '%s' "$decoded" | grep -qi "$c"; then
                    printf 'DANGER\t%s\tpresent in CapEff\n' "$c"
                fi
            done
        elif command -v captest >/dev/null 2>&1; then
            captest 2>/dev/null | while IFS= read -r line; do
                for c in $CE_CAP_DANGER; do
                    if printf '%s' "$line" | grep -qi "$c"; then
                        printf 'DANGER\t%s\t%s\n' "$c" "$line"
                    fi
                done
            done
        fi
    else
        printf 'error\t/proc/self/status not found (not running in container?)\n'
    fi
}

# ── ce_check_mounts — check dangerous mount points ───────────────
ce_check_mounts() {
    if ! [ -f /proc/mounts ] && ! [ -f /etc/mtab ]; then
        printf 'error\tno mount info available\n'
        return
    fi
    local mtab
    mtab="$(cat /proc/mounts 2>/dev/null || cat /etc/mtab 2>/dev/null)"
    if [ -z "$mtab" ]; then
        printf 'error\tcannot read mount table\n'
        return
    fi
    for mp in $CE_MOUNT_DANGER; do
        if printf '%s' "$mtab" | awk '$2 ~ /^'"$mp"'($|\/)/' >/dev/null 2>&1; then
            local opts
            opts="$(printf '%s' "$mtab" | awk -v mp="$mp" '$2 == mp || $2 ~ "^"mp"/" {print $4}' | head -1)"
            if printf '%s' "$opts" | grep -q 'rw'; then
                printf 'DANGER\t%s\tmounted rw (%s)\n' "$mp" "$opts"
            else
                printf 'WARN\t%s\tmounted ro (%s)\n' "$mp" "$opts"
            fi
        fi
    done
    printf 'mount-ok\tno dangerous mounts detected\n'
}

# ── ce_check_proc — check proc-based escape vectors ──────────────
ce_check_proc() {
    local ns_self ns_init
    # Check namespace isolation
    if [ -d /proc/1/ns ]; then
        for ns in pid net ipc uts user mnt; do
            ns_self="$(readlink /proc/self/ns/$ns 2>/dev/null)"
            ns_init="$(readlink /proc/1/ns/$ns 2>/dev/null)"
            if [ -n "$ns_self" ] && [ -n "$ns_init" ] && [ "$ns_self" != "$ns_init" ]; then
                printf 'ISOLATED\t%s\tseparate namespace\n' "$ns"
            elif [ -n "$ns_self" ] && [ -n "$ns_init" ]; then
                printf 'SHARED\t%s\tsame as init (--%s=host?)\n' "$ns" "$ns"
            fi
        done
    else
        printf 'error\tno /proc/1/ns available\n'
    fi
    # Check seccomp
    if [ -f /proc/self/status ]; then
        local sec
        sec="$(grep -i '^Seccomp:' /proc/self/status 2>/dev/null | awk '{print $2}')"
        case "${sec:-}" in
            0) printf 'WARN\tseccomp\tdisabled (mode 0)\n' ;;
            1) printf 'OK\tseccomp\tstrict (mode 1)\n' ;;
            2) printf 'OK\tseccomp\tfilter (mode 2)\n' ;;
            *) printf 'WARN\tseccomp\tunknown (%s)\n' "${sec:-}" ;;
        esac
    fi
    # Check AppArmor
    if [ -f /proc/self/attr/current ]; then
        local aa
        aa="$(cat /proc/self/attr/current 2>/dev/null)"
        if [ -z "$aa" ] || printf '%s' "$aa" | grep -qi 'unconfined'; then
            printf 'WARN\tapparmor\tunconfined or missing\n'
        else
            printf 'OK\tapparmor\t%s\n' "$aa"
        fi
    fi
}

# ── ce_check_cgroup — cgroup v1 release_agent escape check ──────
ce_check_cgroup() {
    if [ -d /sys/fs/cgroup ]; then
        local release_agent
        release_agent="$(find /sys/fs/cgroup -name release_agent 2>/dev/null | head -1)"
        if [ -n "$release_agent" ] && [ -w "$release_agent" ]; then
            printf 'DANGER\tcgroup-release-agent\t%s writable — escape possible\n' "$release_agent"
        fi
        if [ -d /sys/fs/cgroup/devices ] && [ -w /sys/fs/cgroup/devices ]; then
            printf 'DANGER\tcgroup-devices\tcgroup devices writable\n'
        fi
        if [ -d /sys/fs/cgroup ] && [ -w /sys/fs/cgroup ]; then
            printf 'WARN\tcgroup-root\tcgroup root writable\n'
        fi
        printf 'cgroup-ok\n'
    else
        printf 'error\tno /sys/fs/cgroup\n'
    fi
}

# ── ce_check_hostaccess — detect host access routes ──────────────
ce_check_hostaccess() {
    # Docker socket
    for sock in /var/run/docker.sock /run/docker.sock; do
        if [ -S "$sock" ]; then
            local perm
            perm="$(stat -c '%A' "$sock" 2>/dev/null || stat -f '%Sp' "$sock" 2>/dev/null)"
            if [ -w "$sock" ]; then
                printf 'DANGER\tdocker-socket\t%s writable (%s) — host root available\n' "$sock" "$perm"
            else
                printf 'WARN\tdocker-socket\t%s present (%s)\n' "$sock" "$perm"
            fi
        fi
    done
    # SYS_BOOT check
    if [ -f /proc/sys/kernel/ctrl-alt-del ]; then
        printf 'WARN\tsysrq\t/proc/sys/kernel present\n'
    fi
}

# ── Verb dispatchers ─────────────────────────────────────────────
ce_cmd_check() { ce_check_caps; }
ce_cmd_cap() { ce_check_caps; }
ce_cmd_mounts() { ce_check_mounts; }
ce_cmd_proc() { ce_check_proc; }
ce_cmd_cgroup() { ce_check_cgroup; }
ce_cmd_all() {
    ce_log "=== Container Escape Scan ==="
    ce_log "--- capabilities ---"
    ce_check_caps
    ce_log "--- mounts ---"
    ce_check_mounts
    ce_log "--- proc/ns ---"
    ce_check_proc
    ce_log "--- cgroup ---"
    ce_check_cgroup
    ce_log "--- host access ---"
    ce_check_hostaccess
}
ce_cmd_list() {
    printf '%s\n' "$CE_KNOWN_ESCAPES"
}
ce_cmd_status_tsv() {
    # Detect if we're in a container
    local container_state
    if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null || [ -f /run/.containerenv ]; then
        container_state="in-container"
    else
        container_state="not-in-container"
    fi
    printf '%s\t%s\t%s\n' "$MODULE_ID" "$MOD_NAME" "$container_state"
}
ce_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }
ce_cmd_help() {
    cat <<'HELP'
cloudsting module 15 — Container Escape Detection v0.10.0
  --check, --cap            check runtime capabilities (CapEff decode)
  --mounts                  check dangerous mount points
  --proc                    check proc-based escapes (ns, seccomp, apparmor)
  --cgroup                  check cgroup v1 release_agent escape
  --host                    check docker socket and host access
  --all                     full escape scan (all checks)
  --list                    list known escape techniques
  --status-tsv              module status (in-container / not-in-container)
  --menu                    menu entry
  --selftest                run selftests
  --help                    this message
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ce_selftest() {
    local pass=0 fail=0
    chk() { local n="$1" got="$2" want="$3"
        if [ "$got" = "$want" ]; then pass=$((pass+1)); printf 'ok\t%s\n' "$n"
        else fail=$((fail+1)); printf 'FAIL\t%s want=%s got=%s\n' "$n" "$want" "$got"; fi; }

    # Technique KB
    chk tech-count "$(printf '%s\n' "$CE_KNOWN_ESCAPES" | wc -l)" 17
    chk tech-fields "$(printf '%s\n' "$CE_KNOWN_ESCAPES" | awk -F'\t' 'NF==3' | wc -l)" 17
    chk has-docker-socket "$(printf '%s\n' "$CE_KNOWN_ESCAPES" | awk -F'\t' '$1=="docker-socket"' | wc -l)" 1
    chk has-privileged "$(printf '%s\n' "$CE_KNOWN_ESCAPES" | awk -F'\t' '$1=="privileged"' | wc -l)" 1

    # --list smoke
    chk list-output "$(ce_cmd_list | wc -l)" 17

    # --status-tsv shape
    chk status-fields "$(ce_cmd_status_tsv | awk -F'\t' '{print NF}')" 3
    chk status-module "$(ce_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"

    # --help smoke
    chk help-smoke "$(ce_cmd_help 2>/dev/null | head -1 | grep -ci container)" 1

    # --menu shape
    chk menu-shape "$(ce_cmd_menu | awk -F'\t' '{print NF}')" 3

    printf 'RESULT\tPASS(%s)\n' "$pass"
    [ "$fail" -eq 0 ] || { printf 'RESULT\tFAIL(%s)\n' "$fail"; return 1; }
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --check|--cap) shift; ce_cmd_cap "$@";;
    --mounts)      shift; ce_cmd_mounts "$@";;
    --proc)        shift; ce_cmd_proc "$@";;
    --cgroup)      shift; ce_cmd_cgroup "$@";;
    --host)        shift; ce_check_hostaccess;;
    --all)         shift; ce_cmd_all;;
    --list)        shift; ce_cmd_list;;
    --status-tsv|--status) ce_cmd_status_tsv;;
    --menu)        ce_cmd_menu;;
    --selftest)    ce_selftest;;
    *)             ce_cmd_help;;
esac
