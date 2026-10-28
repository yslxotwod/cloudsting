#!/usr/bin/env bash
# Cloudsting dependency manager
# ── self-locate CLOUDSTING_ROOT ──
# When launched via pkexec, HOME is /root and any $HOME-relative path
# would land in the wrong place. Resolve CLOUDSTING_ROOT from this
# script's own path so state / loot / logs always end up in the
# project tree regardless of who runs us.
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

# Under pkexec, HOME=/root even though we're writing to the invoking
# user's tree. CLOUDSTING_ROOT is <real_home>/cloudsting, so its parent
# is the real home. Reset HOME so downstream $HOME-relative defaults
# (LOOT_DIR, LOGS_DIR, XDG_CONFIG_HOME, etc.) resolve to the user's
# paths instead of /root.
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
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR" "$STATE_DIR" 2>/dev/null

# ═══════════════════════════════════════════════════════════════════
#  distro detection
# ═══════════════════════════════════════════════════════════════════

deps_detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

# ID_LIKE names the families a derivative belongs to. Linux Mint reports
# "ubuntu debian", so matching on it covers every Debian and Ubuntu
# derivative without enumerating them.
deps_detect_like() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        printf '%s' "${ID_LIKE:-}"
    fi
}

deps_pkg_manager() {
    local id like
    id="$(deps_detect_distro)"
    like="$(deps_detect_like)"

    case "$id" in
        debian|ubuntu|kali|parrot|raspbian|linuxmint|lmde|pop|elementary|zorin|neon|devuan|mx|antix|deepin|bodhi) echo "apt" ;;
        fedora|rhel|centos|rocky|alma|nobara)      echo "dnf" ;;
        arch|manjaro|endeavouros|garuda|artix)     echo "pacman" ;;
        opensuse*|sles|sled)                       echo "zypper" ;;
        alpine)                                    echo "apk" ;;
        *)
            case "$like" in
                *debian*|*ubuntu*) echo "apt" ;;
                *fedora*|*rhel*)   echo "dnf" ;;
                *arch*)            echo "pacman" ;;
                *suse*)            echo "zypper" ;;
                *)                 echo "unknown" ;;
            esac ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
#  tool registry
#  name, package-per-distro, group, min-version (optional)
#
# Groups:
#   critical — the toolkit core will not run without these
#   optional — used by specific modules, fine to be absent
#   build    — needed to build the native GUI
# ═══════════════════════════════════════════════════════════════════

declare -A DEPS_GROUP=(
    # core — everything is curl + jq at heart
    [curl]=critical [jq]=critical [python3]=critical [bash]=critical
    [openssl]=critical [git]=critical
    # cloud CLIs — one per provider, all optional
    [aws]=optional [gcloud]=optional [az]=optional
    [doctl]=optional [oc]=optional
    [heroku]=optional [linode-cli]=optional
    [aliyun]=optional [kubectl]=optional [helm]=optional
    # api testing
    [httpie]=optional [grpcurl]=optional [nuclei]=optional [ffuf]=optional
    [arjun]=optional [kiterunner]=optional
    # token / secret analysis
    [jwt_tool]=optional [trufflehog]=optional [gitleaks]=optional
    # cloud audit
    [scoutsuite]=optional [prowler]=optional [kube-hunter]=optional
    [peirates]=optional
    # container
    [docker]=optional [podman]=optional [trivy]=optional
    # build
    [cmake]=build [meson]=build [ninja]=build [pkg-config]=build
    [gcc]=build [make]=build
)

declare -A DEPS_APT=(
    [curl]=curl [jq]=jq [python3]=python3 [bash]=bash
    [openssl]=openssl [git]=git
    [aws]=awscli [gcloud]=google-cloud-cli [az]=azure-cli
    [doctl]=doctl [oc]=openshift-clients
    [kubectl]=kubectl [helm]=helm
    [httpie]=httpie [grpcurl]=grpcurl
    [docker]=docker.io [podman]=podman [trivy]=trivy
    [cmake]=cmake [meson]=meson [ninja]=ninja-build [pkg-config]=pkg-config
    [gcc]=gcc [make]=make
    [jwt_tool]=jwt-tool
)

declare -A DEPS_DNF=(
    [curl]=curl [jq]=jq [python3]=python3 [bash]=bash
    [openssl]=openssl [git]=git
    [aws]=awscli [az]=azure-cli
    [kubectl]=kubectl [helm]=helm
    [httpie]=httpie [grpcurl]=grpcurl
    [docker]=docker [podman]=podman
    [cmake]=cmake [meson]=meson [ninja]=ninja-build [pkg-config]=pkgconf-pkg-config
    [gcc]=gcc [make]=make
)

declare -A DEPS_PACMAN=(
    [curl]=curl [jq]=jq [python3]=python [bash]=bash
    [openssl]=openssl [git]=git
    [aws]=aws-cli [az]=azure-cli
    [kubectl]=kubectl [helm]=helm
    [httpie]=httpie [grpcurl]=grpcurl
    [docker]=docker [podman]=podman
    [cmake]=cmake [meson]=meson [ninja]=ninja [pkg-config]=pkgconf
    [gcc]=gcc [make]=make
)

# Tools installed via pipx with no distro package (or whose package lags
# upstream badly). Format: pipx-name|command-name
DEPS_PIPX_TOOLS=(
    "scoutsuite|scout"
    "prowler|prowler"
    "nuclei|nuclei"
    "arjun|arjun"
    "jwt-tool|jwt_tool"
)

# Git-cloned tools that have no package anywhere. Format: name|repo-path
DEPS_GIT_TOOLS=(
    "trufflehog|trufflehog"
)

# Build-time LIBRARIES (for the native GUI) — checked via pkg-config
declare -A DEPS_LIBS=(
    [gtk4]=libgtk-4-dev
    [vte-2.91-gtk4]=libvte-2.91-gtk4-dev
    [gdk-pixbuf-2.0]=libgdk-pixbuf-2.0-dev
)
declare -A DEPS_LIBS_PACMAN=(
    [gtk4]=gtk4 [vte-2.91-gtk4]=vte4 [gdk-pixbuf-2.0]=gdk-pixbuf2
)
declare -A DEPS_LIBS_DNF=(
    [gtk4]=gtk4-devel [vte-2.91-gtk4]=vte291-gtk4-devel [gdk-pixbuf-2.0]=gdk-pixbuf2-devel
)

deps_check_lib() { pkg-config --exists "$1" 2>/dev/null; }

deps_lib_pkg_for() {
    local lib="$1"
    case "$(deps_pkg_manager)" in
        apt)    echo "${DEPS_LIBS[$lib]:-}" ;;
        dnf)    echo "${DEPS_LIBS_DNF[$lib]:-${DEPS_LIBS[$lib]:-}}" ;;
        pacman) echo "${DEPS_LIBS_PACMAN[$lib]:-${DEPS_LIBS[$lib]:-}}" ;;
        *)      echo "${DEPS_LIBS[$lib]:-}" ;;
    esac
}

# Version floor for a few critical tools. `--check-versions` verifies these.
declare -A DEPS_MIN_VERSION=(
    [bash]="4.2"
    [python3]="3.8"
    [curl]="7.68"
    [jq]="1.6"
    [openssl]="1.1.1"
    [cmake]="3.20"
    [meson]="0.60"
    [ninja]="1.10"
    [pkg-config]="0.29"
)

deps_pkg_for() {
    local tool="$1"
    local mgr
    mgr=$(deps_pkg_manager)
    case "$mgr" in
        apt)    echo "${DEPS_APT[$tool]:-}" ;;
        dnf)    echo "${DEPS_DNF[$tool]:-${DEPS_APT[$tool]:-}}" ;;
        pacman) echo "${DEPS_PACMAN[$tool]:-${DEPS_APT[$tool]:-}}" ;;
        *)      echo "" ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
#  presence / version probing
# ═══════════════════════════════════════════════════════════════════

deps_check_one() { command -v "$1" >/dev/null 2>&1; }

deps_tool_version() {
    local tool="$1"
    local out=""
    case "$tool" in
        gcloud)   out=$("$tool" --version 2>&1 | head -1) ;;
        az)       out=$("$tool" version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
        aws)      out=$("$tool" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
        docker)   out=$("$tool" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
        python3)  out=$("$tool" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
        bash)     out=$(bash --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
        *)        out=$("$tool" --version 2>&1 | head -1) ;;
    esac
    printf '%s\n' "$out" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1
}

deps_version_ge() {
    local a="$1" b="$2"
    [[ -z "$a" || -z "$b" ]] && return 0
    printf '%s\n%s\n' "$b" "$a" | sort -V -C
    return $?
}

# ═══════════════════════════════════════════════════════════════════
#  status TSV
# ═══════════════════════════════════════════════════════════════════

deps_status_tsv() {
    local tool group pkg state
    local rows=""
    for tool in $(printf '%s\n' "${!DEPS_GROUP[@]}" | sort); do
        group="${DEPS_GROUP[$tool]}"
        pkg=$(deps_pkg_for "$tool")
        if deps_check_one "$tool"; then
            state="installed"
        else
            state="missing"
        fi
        rows+="$(printf '%s\t%s\t%s\t%s\n' "$tool" "${pkg:-?}" "$group" "$state")"$'\n'
    done

    local lib
    for lib in $(printf '%s\n' "${!DEPS_LIBS[@]}" | sort); do
        if ! command -v pkg-config >/dev/null 2>&1; then
            state="unknown"
        elif deps_check_lib "$lib"; then
            state="installed"
        else
            state="missing"
        fi
        rows+="$(printf '%s\t%s\t%s\t%s\n' "$lib" "$(deps_lib_pkg_for "$lib")" "build-lib" "$state")"$'\n'
    done

    printf '%s' "$rows" | LC_ALL=C sort
}

deps_check_versions_tsv() {
    local tool min cur ok
    local issues=0
    for tool in $(printf '%s\n' "${!DEPS_MIN_VERSION[@]}" | sort); do
        min="${DEPS_MIN_VERSION[$tool]}"
        deps_check_one "$tool" || continue
        cur=$(deps_tool_version "$tool")
        if [[ -z "$cur" ]]; then
            printf 'VERSION_UNKNOWN\t%s\t%s\n' "$tool" "$min"
            continue
        fi
        if deps_version_ge "$cur" "$min"; then
            ok="ok"
        else
            ok="too_old"
            issues=$((issues+1))
        fi
        printf '%s\t%s\t%s\t%s\n' "$ok" "$tool" "$cur" "$min"
    done
    printf 'ISSUES\t%s\n' "$issues"
}

# ═══════════════════════════════════════════════════════════════════
#  install paths
# ═══════════════════════════════════════════════════════════════════

deps_missing_packages() {
    local tool pkg
    for tool in "${!DEPS_GROUP[@]}"; do
        deps_check_one "$tool" && continue
        pkg=$(deps_pkg_for "$tool")
        [[ -n "$pkg" ]] && printf '%s\n' "$pkg"
    done | sort -u
}

deps_install_pipx_tools() {
    command -v pipx >/dev/null 2>&1 || {
        command -v apt >/dev/null 2>&1 && sudo apt install -y pipx 2>/dev/null
    }
    command -v pipx >/dev/null 2>&1 || {
        printf 'MISSING\tpipx\n'; return 1
    }
    pipx ensurepath >/dev/null 2>&1 || true

    local entry name cmd
    for entry in "${DEPS_PIPX_TOOLS[@]}"; do
        name="${entry%%|*}"
        cmd="${entry##*|}"
        if command -v "$cmd" >/dev/null 2>&1; then
            printf 'HAVE\t%s\n' "$cmd"
            continue
        fi
        info "pipx install $name"
        pipx install "$name" 2>&1 | tail -5 || \
            printf 'FAILED\t%s\n' "$name"
    done
}

deps_install_git_tools() {
    local entry name dir
    local root="$CLOUDSTING_ROOT"
    for entry in "${DEPS_GIT_TOOLS[@]}"; do
        name="${entry%%|*}"
        dir="$root/external/$name"
        if [[ -d "$dir" ]]; then
            printf 'HAVE\t%s\n' "$name"
            continue
        fi
        command -v git >/dev/null 2>&1 || { printf 'MISSING\tgit\n'; return 1; }
        mkdir -p "$root/external"
        info "cloning $name"
        case "$name" in
            trufflehog)
                # trufflehog ships a universal installer now
                curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$HOME/.local/bin" && \
                    printf 'INSTALLED\t%s\n' "$HOME/.local/bin/trufflehog" || \
                    printf 'FAILED\t%s\n' "$name"
                ;;
            *)
                printf 'UNKNOWN\t%s\n' "$name"
                ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════════════
#  privilege wrapper
# ═══════════════════════════════════════════════════════════════════

deps_run_privileged() {
    local packages=("$@")
    local mgr script
    ((${#packages[@]} > 0)) || {
        printf 'Everything requested is already installed.\n'
        return 0
    }
    mgr=$(deps_pkg_manager)
    [[ "$mgr" == "unknown" ]] && {
        printf 'Unsupported distro — install manually: %s\n' "${packages[*]}" >&2
        return 1
    }

    if (( EUID == 0 )); then
        deps_privileged_install "${packages[@]}"
        return
    fi

    script=$(readlink -f "${BASH_SOURCE[0]}")
    if command -v pkexec >/dev/null 2>&1; then
        exec pkexec "$script" privileged-install "${packages[@]}"
    fi

    printf 'pkexec is required for package installation.\n' >&2
    return 1
}

deps_privileged_install() {
    local packages=("$@")
    local mgr pkg failed=()
    (( EUID == 0 )) || { printf 'root required\n' >&2; return 1; }
    ((${#packages[@]} > 0)) || return 0

    mgr=$(deps_pkg_manager)
    case "$mgr" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update || return 1
            for pkg in "${packages[@]}"; do
                printf '\nInstalling %s...\n' "$pkg"
                apt-get install -y -- "$pkg" || failed+=("$pkg")
            done ;;
        dnf)
            for pkg in "${packages[@]}"; do
                printf '\nInstalling %s...\n' "$pkg"
                dnf install -y "$pkg" || failed+=("$pkg")
            done ;;
        pacman)
            pacman -Sy --noconfirm || true
            for pkg in "${packages[@]}"; do
                printf '\nInstalling %s...\n' "$pkg"
                pacman -S --noconfirm --needed "$pkg" || failed+=("$pkg")
            done ;;
        *)
            printf 'Unsupported pkg manager\n' >&2; return 1 ;;
    esac

    if ((${#failed[@]} > 0)); then
        printf '\nFailed packages: %s\n' "${failed[*]}" >&2
        return 1
    fi
    printf '\nDependency operation completed.\n'
}

deps_install_packages() {
    local req=("$@") pkg unique=() seen=()
    ((${#req[@]} > 0)) || { printf 'No package specified.\n' >&2; return 2; }
    for pkg in "${req[@]}"; do
        local found=0
        for f in "${unique[@]}"; do [[ "$f" == "$pkg" ]] && { found=1; break; }; done
        (( found == 0 )) && unique+=("$pkg")
    done
    deps_run_privileged "${unique[@]}"
}

deps_install_missing_backend() {
    local packages=()
    mapfile -t packages < <(deps_missing_packages)
    deps_run_privileged "${packages[@]}"
}

deps_install_all_backend() {
    local packages=()
    mapfile -t packages < <(
        for tool in "${!DEPS_GROUP[@]}"; do
            deps_pkg_for "$tool"
        done | sort -u | grep -v '^$'
    )
    deps_run_privileged "${packages[@]}"
}

# ═══════════════════════════════════════════════════════════════════
#  preflight — one page, everything a first run needs to know
# ═══════════════════════════════════════════════════════════════════

deps_preflight() {
    local tool state
    local crit_missing=0 opt_missing=0
    printf '%s\n' "── cloudsting preflight ─────────────────────────────"
    for tool in $(printf '%s\n' "${!DEPS_GROUP[@]}" | sort); do
        state=$([[ "${DEPS_GROUP[$tool]}" == build ]] && printf 'build' || true)
        if deps_check_one "$tool"; then
            state="ok"
        else
            case "${DEPS_GROUP[$tool]}" in
                critical) state="MISSING (critical)"; crit_missing=$((crit_missing+1)) ;;
                optional) state="missing (optional)"; opt_missing=$((opt_missing+1)) ;;
                build)    state="missing (build)" ;;
            esac
        fi
        printf '  %-16s %s\n' "$tool" "$state"
    done
    printf '%s\n' "─────────────────────────────────────────────────────"
    printf 'summary: %d critical missing, %d optional missing\n' "$crit_missing" "$opt_missing"
    (( crit_missing == 0 ))
}

# ═══════════════════════════════════════════════════════════════════
#  self-test
# ═══════════════════════════════════════════════════════════════════

deps_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rcount() { printf '%s\n' "$1" | grep -c . ; }

    local out rc

    # 1. distro detection
    local id want
    id=$(deps_detect_distro)
    chk distro-id-shape "$(printf '%s' "$id" | grep -cE '^[a-z0-9._-]+$')" 1
    chk distro-id-matches-os-release "$id" \
        "$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | head -1)"
    case "$id" in
        debian|ubuntu|kali|parrot|raspbian) want=apt ;;
        fedora|rhel|centos|rocky|alma)     want=dnf ;;
        arch|manjaro|endeavouros)          want=pacman ;;
        alpine)                            want=apk ;;
        *)                                 want=unknown ;;
    esac
    chk pkg-manager-for-distro "$(deps_pkg_manager)" "$want"

    # 2. tool -> package mapping
    if [[ "$(deps_pkg_manager)" == "apt" ]]; then
        chk pkg-curl       "$(deps_pkg_for curl)"       curl
        chk pkg-jq         "$(deps_pkg_for jq)"         jq
        chk pkg-python3    "$(deps_pkg_for python3)"    python3
        chk pkg-docker     "$(deps_pkg_for docker)"     docker.io
    fi
    chk pkg-unknown-tool "$(deps_pkg_for definitely-not-a-tool)" ""

    # every critical tool must be installable, or install-missing lies
    local t missing_crit=0
    for t in "${!DEPS_GROUP[@]}"; do
        [[ "${DEPS_GROUP[$t]}" == "critical" ]] || continue
        [[ -n "$(deps_pkg_for "$t")" ]] || { missing_crit=$((missing_crit+1)); printf 'NOTE\tno package mapping for critical tool %s\n' "$t"; }
    done
    chk pkg-all-critical-mapped "$missing_crit" 0
    chk pipx-table-shape "$(printf '%s\n' "${DEPS_PIPX_TOOLS[@]}" | grep -cE '^[^|]+\|[^|]+$')" "${#DEPS_PIPX_TOOLS[@]}"

    # 3. presence probe
    chk check-one-present "$(deps_check_one bash && echo yes || echo no)" yes
    chk check-one-absent  "$(deps_check_one definitely-not-a-tool-xyz && echo yes || echo no)" no

    # 4. version comparison
    chk vge-equal      "$(deps_version_ge 6.0 6.0; echo $?)" 0
    chk vge-newer      "$(deps_version_ge 6.1 6.0; echo $?)" 0
    chk vge-older      "$(deps_version_ge 5.9 6.0; echo $?)" 1
    chk vge-numeric-10 "$(deps_version_ge 1.10 1.9; echo $?)" 0
    chk vge-numeric-9  "$(deps_version_ge 1.9 1.10; echo $?)" 1
    chk vge-empty-cur  "$(deps_version_ge "" 6.0; echo $?)" 0
    chk vge-empty-min  "$(deps_version_ge 6.0 ""; echo $?)" 0

    # 5. version extraction
    chk tool-version-python3 "$(deps_tool_version python3 | grep -cE '^[0-9]+\.[0-9]+')" 1
    chk tool-version-absent  "$(deps_tool_version definitely-not-a-tool-xyz)" ""

    # 6. status TSV shape
    out=$(deps_status_tsv)
    chk status-rows     "$(rcount "$out")" "$(( ${#DEPS_GROUP[@]} + ${#DEPS_LIBS[@]} ))"
    chk status-fields   "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=4 || $2=="" || $3=="" || $4==""{c++} END{print c+0}')" 0
    chk status-groups   "$(printf '%s\n' "$out" | awk -F'\t' '$3!="critical" && $3!="optional" && $3!="build" && $3!="build-lib"{c++} END{print c+0}')" 0
    chk status-states   "$(printf '%s\n' "$out" | awk -F'\t' '$4!="installed" && $4!="missing" && $4!="unknown"{c++} END{print c+0}')" 0
    chk status-sorted   "$(printf '%s\n' "$out" | cut -f1 | LC_ALL=C sort -c 2>/dev/null; echo $?)" 0
    for tool in curl jq git; do
        chk "status-state-$tool" "$(printf '%s\n' "$out" | awk -F'\t' -v t="$tool" '$1==t{print $4}')" \
            "$(command -v "$tool" >/dev/null 2>&1 && echo installed || echo missing)"
    done

    # 7. missing-package list is deduplicated and sorted
    out=$(deps_missing_packages)
    chk missing-unique "$(printf '%s\n' "$out" | sort -u | md5sum)" "$(printf '%s\n' "$out" | md5sum)"
    chk missing-nonempty "$(printf '%s\n' "$out" | grep -c '^$')" 0

    # 8. preflight summary consistency
    out=$(deps_preflight 2>&1 || true)
    chk preflight-has-summary "$(printf '%s\n' "$out" | grep -c 'summary:')" 1

    # 9. install entry points: only the guards that return before acting
    out=$(deps_install_packages 2>&1); rc=$?
    chk install-noargs-rc  "$rc" 2
    chk install-noargs-msg "$(printf '%s\n' "$out" | grep -c 'No package specified.')" 1
    out=$(deps_run_privileged); rc=$?
    chk privileged-nopkgs-rc   "$rc" 0
    chk privileged-nopkgs-msg  "$(printf '%s\n' "$out" | grep -c 'already installed')" 1

    # 10. dispatch
    out=$(deps_main --distro-info); rc=$?
    chk main-distroinfo-rc   "$rc" 0
    chk main-distroinfo-rows "$(rcount "$out")" 2
    chk main-distroinfo-keys "$(printf '%s\n' "$out" | cut -f1 | tr '\n' ' ')" "distro pkg_manager "
    deps_main --help >/dev/null 2>&1;      chk main-help-rc "$?" 0
    deps_main definitely-not-a-verb >/dev/null 2>&1; chk main-unknown-rc "$?" 2

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

deps_usage() {
    cat <<EOF
Usage:
  $(basename "$0") status | --status-tsv
  $(basename "$0") --preflight
  install PACKAGE [PACKAGE...]
  $(basename "$0") install-missing | --install-missing
  $(basename "$0") install-all | --install-all
  $(basename "$0") --install-pipx
  $(basename "$0") --install-git
  $(basename "$0") --distro-info
  $(basename "$0") --selftest
EOF
}

deps_main() {
    local command="${1:-}"
    (($# > 0)) && shift
    case "$command" in
        status|--status|--status-tsv)   deps_status_tsv ;;
        --preflight)                    deps_preflight ;;
        install|install-package|--install-package) deps_install_packages "$@" ;;
        install-missing|--install-missing) deps_install_missing_backend ;;
        install-all|--install-all)      deps_install_all_backend ;;
        --install-pipx)                 deps_install_pipx_tools ;;
        --install-git)                 deps_install_git_tools ;;
        --distro-info)                  printf 'distro\t%s\npkg_manager\t%s\n' \
                                            "$(deps_detect_distro)" "$(deps_pkg_manager)" ;;
        --selftest)                     deps_selftest ;;
        privileged-install|--privileged-install) deps_privileged_install "$@" ;;
        help|--help|-h)                 deps_usage ;;
        *) deps_usage >&2; return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    deps_main "$@"
fi
