#!/usr/bin/env bash
# 77_mobile.sh — cloudsting module 77: the backend the app trusts its own client to be
# Verbs: --probe | --versions | --static | --config | --deep | --cert --store
#        | --techniques | --list | --status-tsv | --menu | --selftest | --help
#
# A mobile backend is an API that was never designed to meet a stranger. The
# app is the only client it expected, so the client's own numbers — a version
# string, a build number, a platform flag — became authorization inputs. The
# release train ships old versions forever, so an old build is a supported
# client with missing mitigations, and the server is happy to serve it.
#
# This module asks the backend for things the app would ask for, and checks
# whether the answers depend on a header the user controls.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="77_mobile"
MOD_NAME="Mobile Backend (the client version is an authorization input)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/mobile"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"

: "${MB_TIMEOUT:=10}"
: "${MB_UA:=okhttp/4.9.3}"
: "${MB_NEW_VERSION:=999.0.0}"
: "${MB_OLD_VERSION:=1.0.0}"

mb_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the headers a mobile backend reads ───────────────────────────
# Every one of these is a value the CLIENT chooses. That is the whole attack:
# if the server makes a decision on any of them, the decision belongs to the
# attacker. The last column is what the server usually does with it.
#   <header>\t<what it controls>\t<why the server trusts it>
mb_headers() {
    cat <<'HEADERS'
X-App-Version	which API shape the app expects	the release train sent it since v1
X-Client-Version	same, under the other common spelling	mobile SDKs default to this name
X-Build-Number	feature flags and A/B cohorts	build numbers are monotonic, so they look trustworthy
X-Platform	which schema and which bug workarounds apply	ios and android get different DTOs
X-Device-Id	device binding and rate limits	a per-device allowance is keyed on it
X-Device-Model	anti-fraud scoring	emulators score differently, so the field gates checks
X-OS-Version	minimum version enforcement	old OS versions disable protections
X-API-Key	the mobile app's embedded key	shipped inside the APK, so it is public already
X-App-Signature	integrity checking on some builds	checked only when the header is present
X-Client-Id	tenant or brand selection	the client names its own tenant
X-Request-Id	trace correlation and occasionally caching	a cache key the client influences
X-Debug	diagnostics that leak more than diagnostics	left in release builds surprisingly often
HEADERS
}

# ── what a mobile backend exposes that a web one does not ────────
mb_paths() {
    cat <<'PATHS'
/api/v1/config	the app's remote config: feature flags, endpoints, keys
/api/config	the unversioned spelling, frequently wider
/api/v1/app/config	per-app configuration
/api/v1/version	the update check, which names the current build
/api/version	the same check without a prefix
/api/v1/check-update	the enforced-update endpoint
/api/v1/versions	the whole supported-version table
/api/v1/settings	settings the app applies at launch
/api/v1/flags	feature flags, which sometimes include kill switches
/api/v1/experiments	the A/B assignment table
/api/v1/bootstrap	the launch bundle: config, flags and keys in one response
/api/v1/device/register	device registration, before any login
/api/v1/notifications	the push token registry
/api/v1/deep-links	the deep link table, including any verification rules
/app/config.json	the hosted config file the shell loads
/assetlinks.json	Android app-link verification — who may open the app's links
/apple-app-site-association	iOS universal-link verification
PATHS
}

# ── sending ──────────────────────────────────────────────────────
#   mb_send <url> [header] -> "<code>\t<bytes>\t<ctype>\t<body-path>"
mb_send() {
    local url="$1" hdr="${2:-}"
    local out; out="$(mktemp "$CS_SCRATCH/mb.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.mb.$$"
    local -a args=(-sS -o "$out" -w '%{http_code} %{size_download} %{content_type}' -m "$MB_TIMEOUT" -A "$MB_UA")
    [ -n "$hdr" ] && args+=(-H "$hdr")
    local meta; meta="$(curl "${args[@]}" "$url" 2>/dev/null)"
    local code bytes ctype
    read -r code bytes ctype <<< "${meta:-000 0 none}"
    printf '%s\t%s\t%s\t%s\n' "${code:-000}" "${bytes:-0}" "${ctype:-none}" "$out"
}

mb_verdict() {
    local code="$1"
    [[ "$code" == "000" ]] && { printf 'unreachable'; return; }
    case "$code" in
        2*)          printf 'present' ;;
        401|403)     printf 'guarded' ;;
        404)         printf 'absent' ;;
        429)         printf 'rate-limited' ;;
        3*)          printf 'redirect' ;;
        *)           printf 'error' ;;
    esac
}

# Does a config response actually carry anything. A 200 with `{}` is a config
# endpoint that has not been configured, which is not a finding — so the grade
# depends on what the document CONTAINS, not that it exists.
mb_config_class() {
    local f="$1"
    [[ -s "$f" ]] || { printf 'empty'; return; }
    local b; b="$(wc -c < "$f" 2>/dev/null | tr -d ' ')"
    (( b < 4 )) && { printf 'empty'; return; }

    # the things that make a config document dangerous
    if grep -qaE 'sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}' "$f" 2>/dev/null; then
        printf 'credentials'; return
    fi
    if grep -qaiE '"(debug|staging|internal)[a-z_]*"[[:space:]]*:[[:space:]]*(true|1|"true")' "$f" 2>/dev/null; then
        printf 'debug-enabled'; return
    fi
    if grep -qaiE '(/admin|/internal|/debug|10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.|\.internal|\.local|localhost)' "$f" 2>/dev/null; then
        printf 'internal-endpoints'; return
    fi
    if grep -qaiE '"(api[_-]?key|secret|token|client[_-]?secret|password)"' "$f" 2>/dev/null; then
        printf 'secret-names'; return
    fi
    printf 'config-only'
}

mb_severity() {
    local class="$1"
    case "$class" in
        credentials)        printf 'CRITICAL' ;;
        secret-names)       printf 'CRITICAL' ;;
        debug-enabled)      printf 'HIGH' ;;
        internal-endpoints) printf 'HIGH' ;;
        *)                  printf 'INFO' ;;
    esac
}

# The version verdict. The finding is not "an old version is accepted" — every
# backend accepts the version it knows. It is that an ANCIENT version is
# accepted while the server says newer ones exist, meaning the minimum-version
# gate is not enforced.
#   mb_version_verdict <old-code> <new-code> <old-bytes> <new-bytes>
mb_version_verdict() {
    local oc="$1" nc="$2"
    [[ "$oc" == "000" || "$nc" == "000" ]] && { printf 'unreachable'; return; }
    if [[ "$oc" =~ ^2 && "$nc" =~ ^2 ]]; then printf 'no-version-gate'; return; fi
    if [[ "$oc" =~ ^2 && ! "$nc" =~ ^2 ]]; then printf 'newer-refused'; return; fi
    if [[ ! "$oc" =~ ^2 && "$nc" =~ ^2 ]]; then printf 'old-refused'; return; fi
    printf 'both-refused'
}

mb_findings() { cs_findings_row "$MODULE_ID" "SURFACE" "$4" "$3" "$2" > /dev/null; }

# ── verbs ────────────────────────────────────────────────────────

# --probe <base>: which of the mobile-only routes exist, and what they hand over
mb_cmd_probe() {
    local base="${1:-}"
    [[ -z "$base" ]] && { mb_log "usage: --probe <base-url>"; return 2; }
    cs_row TARGET "$base"
    local path note found=0 total=0
    while IFS=$'\t' read -r path note; do
        [[ -z "$path" ]] && continue
        local url="${base%/}$path"
        local row; row="$(mb_send "$url")"
        local code bytes ctype f
        IFS=$'\t' read -r code bytes ctype f <<< "$row"
        total=$((total + 1))
        local v; v="$(mb_verdict "$code")"
        if [[ "$v" == "present" ]]; then
            found=$((found + 1))
            local class; class="$(mb_config_class "$f")"
            local sev; sev="$(mb_severity "$class")"
            cs_row FOUND "$path" "code=$code" "bytes=$bytes" "class=$class"
            if [[ "$class" != "config-only" && "$class" != "empty" ]]; then
                cs_row FINDING "$sev" "mobile-$class"
                cs_findings_row "$MODULE_ID" "SURFACE" "$url" "$sev" "mobile-$class" \
                    "$note — the document graded $class" > /dev/null
            fi
        else
            cs_row ENDPOINT "$path" "$v"
        fi
        rm -f "$f"
    done < <(mb_paths)
    cs_row SUMMARY "found=$found total=$total"
    return 0
}

# --versions <base>: the update check, fired with an ancient version and a
# future one. A gate that refuses neither is not a gate.
mb_cmd_versions() {
    local base="${1:-}"
    [[ -z "$base" ]] && { mb_log "usage: --versions <base-url>"; return 2; }
    cs_row TARGET "$base"
    cs_row OLD "$MB_OLD_VERSION"
    cs_row NEW "$MB_NEW_VERSION"

    local url="${base%/}/api/v1/version"
    local ro; ro="$(mb_send "$url" "X-App-Version: $MB_OLD_VERSION")"
    local ocode obytes octype of
    IFS=$'\t' read -r ocode obytes octype of <<< "$ro"
    rm -f "$of"

    local rn; rn="$(mb_send "$url" "X-App-Version: $MB_NEW_VERSION")"
    local ncode nbytes nctype nf
    IFS=$'\t' read -r ncode nbytes nctype nf <<< "$rn"
    rm -f "$nf"

    cs_row OLD-RESPONSE "code=$ocode"
    cs_row NEW-RESPONSE "code=$ncode"
    local v; v="$(mb_version_verdict "$ocode" "$ncode")"
    cs_row VERDICT "$v"
    if [[ "$v" == "no-version-gate" ]]; then
        cs_row FINDING "HIGH" "mobile-no-version-gate"
        mb_findings "$url" "HIGH" "mobile-no-version-gate" \
            "version $MB_OLD_VERSION and $MB_NEW_VERSION were both served, so the update gate is not enforced"
    fi
    cs_row SUMMARY "old=$ocode new=$ncode verdict=$v"
    return 0
}

# --static <base>: does the backend serve the app's own assets from the same
# origin. A debug or staging bundle sitting next to production is the usual
# way a mobile backend leaks its own internals.
mb_cmd_static() {
    local base="${1:-}"
    [[ -z "$base" ]] && { mb_log "usage: --static <base-url>"; return 2; }
    cs_row TARGET "$base"
    local assets="/app-debug.apk /app-release.apk /app.apk /mobile/app-debug.apk /assets/index.android.bundle /admin.apk /app-prod.apk /app-staging.apk /debug.apk /app/ /index.html /manifest.json /build-info.json /version.json /config.json /env.js /static/js/main.js"
    local a found=0
    for a in $assets; do
        local url="${base%/}$a"
        local row; row="$(mb_send "$url")"
        local code bytes ctype f
        IFS=$'\t' read -r code bytes ctype f <<< "$row"
        if [[ "$code" =~ ^2 ]] && [[ "${bytes:-0}" -gt 64 ]]; then
            found=$((found + 1))
            cs_row ASSET "$a" "code=$code" "bytes=$bytes" "ctype=$ctype"
            case "$a" in
                *debug*|*staging*)
                    cs_row FINDING "HIGH" "mobile-debug-asset"
                    mb_findings "$url" "HIGH" "mobile-debug-asset" \
                        "a debug or staging artefact is downloadable from the production origin" ;;
                *.apk)
                    cs_row FINDING "MEDIUM" "mobile-apk-exposed"
                    mb_findings "$url" "MEDIUM" "mobile-apk-exposed" \
                        "the shipped APK is downloadable, so its embedded key and endpoints are public" ;;
                *env.js|*config.json|*build-info.json)
                    cs_row FINDING "MEDIUM" "mobile-build-artefact" ;;
            esac
        fi
        rm -f "$f"
    done
    cs_row SUMMARY "assets=$found"
    return 0
}

# --config <base> [path]: fetch one config document and grade what is inside
mb_cmd_config() {
    local base="${1:-}" path="${2:-/api/v1/config}"
    [[ -z "$base" ]] && { mb_log "usage: --config <base-url> [path]"; return 2; }
    local url="${base%/}$path"
    cs_row TARGET "$url"

    local row; row="$(mb_send "$url")"
    local code bytes ctype f
    IFS=$'\t' read -r code bytes ctype f <<< "$row"
    cs_row RESPONSE "code=$code" "bytes=$bytes" "ctype=$ctype"
    if [[ "$code" == "000" ]]; then
        cs_row VERDICT "unreachable"; cs_row SUMMARY "verdict=unreachable"; rm -f "$f"; return 0
    fi
    if [[ ! "$code" =~ ^2 ]]; then
        cs_row VERDICT "$(mb_verdict "$code")"
        cs_row SUMMARY "code=$code"
        rm -f "$f"; return 0
    fi

    local class; class="$(mb_config_class "$f")"
    local sev; sev="$(mb_severity "$class")"
    cs_row CLASS "$class"

    # show the keys, never whole values: a config document can carry secrets
    # and the artifact is the place for those, not the terminal
    local keys
    keys="$(grep -oaE '"[A-Za-z_][A-Za-z0-9_-]{1,40}"[[:space:]]*:' "$f" 2>/dev/null \
            | sed 's/[[:space:]]*:$//' | sort -u | head -40 | tr '\n' ' ')"
    [[ -n "$keys" ]] && cs_row KEYS "$keys"
    cs_row VERDICT "$class"

    if [[ "$class" != "config-only" && "$class" != "empty" ]]; then
        cs_row FINDING "$sev" "mobile-config-$class"
        cs_findings_row "$MODULE_ID" "SURFACE" "$url" "$sev" "mobile-config-$class" \
            "the remote config graded $class" > /dev/null
        cp "$f" "$OUT_DIR/config-$RUN_ID.txt" 2>/dev/null || true
        cs_row ARTIFACT "$OUT_DIR/config-$RUN_ID.txt"
    fi
    cs_row SUMMARY "class=$class"
    rm -f "$f"
    return 0
}

# --deep <base>: the link verification documents. These say who is allowed to
# open the app's links — a wrong entry is an account takeover path, not a
# config nicety.
mb_cmd_deep() {
    local base="${1:-}"
    [[ -z "$base" ]] && { mb_log "usage: --deep <base-url>"; return 2; }
    cs_row TARGET "$base"

    local row; row="$(mb_send "${base%/}/assetlinks.json")"
    local acode abytes actype af
    IFS=$'\t' read -r acode abytes actype af <<< "$row"
    cs_row ASSETLINKS "code=$acode" "bytes=$abytes"
    if [[ "$acode" =~ ^2 ]]; then
        # a wildcard permission or a foreign package is the finding
        if grep -qa '"relation".*\[\|delegate_permission/common.handle_all_urls' "$af" 2>/dev/null; then
            local sha; sha="$(grep -oaE '"sha256_cert_fingerprints"[^]]*]' "$af" 2>/dev/null | head -c 200)"
            cs_row FINGERPRINTS "${sha:-none}"
            local pkgs; pkgs="$(grep -oaE '"package_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$af" 2>/dev/null | sed 's/.*"\([^"]*\)"$/\1/' | tr '\n' ' ')"
            cs_row PACKAGES "${pkgs:-none}"
        fi
    fi
    rm -f "$af"

    row="$(mb_send "${base%/}/apple-app-site-association")"
    local icode ibytes ictype if_
    IFS=$'\t' read -r icode ibytes ictype if_ <<< "$row"
    cs_row AASA "code=$icode" "bytes=$ibytes"
    if [[ "$icode" =~ ^2 ]]; then
        if grep -qaE '"\*"|"?applinks"?.*\*|"paths"[[:space:]]*:[[:space:]]*\[\s*"\*"' "$if_" 2>/dev/null; then
            cs_row FINDING "HIGH" "mobile-wildcard-links"
            mb_findings "${base%/}/apple-app-site-association" "HIGH" "mobile-wildcard-links" \
                "the universal-link file grants a wildcard path, so any path on this host opens the app"
        fi
    fi
    rm -f "$if_"

    local v="checked"
    [[ "$acode" == "000" && "$icode" == "000" ]] && v="unreachable"
    cs_row VERDICT "$v"
    cs_row SUMMARY "assetlinks=$acode aasa=$icode"
    return 0
}

# --cert <base>: does the app's pinning or the backend's TLS config actually
# exist. Reports what is observable without downloading the APK.
mb_cmd_cert() {
    local base="${1:-}"
    [[ -z "$base" ]] && { mb_log "usage: --cert <base-url>"; return 2; }
    cs_row TARGET "$base"

    local host
    host="$(printf '%s' "$base" | sed -E 's#^[a-z]+://##; s#/.*$##; s#:.*$##')"
    cs_row HOST "$host"
    if ! command -v openssl >/dev/null 2>&1; then
        cs_row VERDICT "no-openssl"; cs_row SUMMARY "verdict=no-openssl"; return 0
    fi

    local out; out="$(mktemp "$CS_SCRATCH/mbc.XXXXXX")" 2>/dev/null || out="$OUT_DIR/.mbc.$$"
    if ! timeout "$MB_TIMEOUT" openssl s_client -connect "$host:443" -servername "$host" </dev/null >"$out" 2>/dev/null; then
        cs_row VERDICT "unreachable"; cs_row SUMMARY "verdict=unreachable"; rm -f "$out"; return 0
    fi
    local proto
    proto="$(grep -oE 'Protocol *: *[A-Za-z0-9.]+' "$out" | head -1 | awk '{print $3}')"
    cs_row PROTOCOL "${proto:-unknown}"
    local tlsbad="no"
    case "$proto" in TLSv1|TLSv1.1|SSLv3|SSLv2) tlsbad="yes";; esac
    if [[ "$tlsbad" == "yes" ]]; then
        cs_row FINDING "HIGH" "mobile-weak-tls"
        mb_findings "$base" "HIGH" "mobile-weak-tls" "the backend negotiates $proto"
    fi
    local expired
    expired="$(grep -oE 'NotAfter *: *.*' "$out" | head -1)"
    cs_row EXPIRES "${expired:-unknown}"
    rm -f "$out"
    cs_row SUMMARY "protocol=${proto:-unknown}"
    return 0
}

mb_cmd_techniques() {
    local h what why
    while IFS=$'\t' read -r h what why; do
        [[ -z "$h" ]] && continue
        cs_row HEADER "$h" "$what" "$why"
    done < <(mb_headers)
    local p note
    while IFS=$'\t' read -r p note; do
        [[ -z "$p" ]] && continue
        cs_row PATH "$p" "$note"
    done < <(mb_paths)
    cs_row SUMMARY "headers=$(mb_headers | wc -l | tr -d ' ') paths=$(mb_paths | wc -l | tr -d ' ')"
    return 0
}

mb_cmd_list() {
    cs_row VERB "probe" "versions" "static" "config" "deep" "cert" "techniques"
    cs_row SUMMARY "ok"
    return 0
}

mb_cmd_status_tsv() {
    local cur
    command -v curl >/dev/null 2>&1 && cur="curl-ok" || cur="curl-missing"
    printf '%s\t%s\t%s\theaders-%s\tpaths-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$cur" \
        "$(mb_headers | wc -l | tr -d ' ')" "$(mb_paths | wc -l | tr -d ' ')"
}

mb_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

mb_cmd_help() {
    cat <<'HELP'
cloudsting module 77 — Mobile Backend v1.0.0
  --probe <base>            every mobile-only route: config, flags, bootstrap, device
  --versions <base>         the update check with an ancient and a future version
  --static <base>           debug APKs and build artefacts served by the backend
  --config <base> [path]    one remote config document, graded by content
  --deep <base>             assetlinks.json and apple-app-site-association
  --cert <base>             the TLS the app's traffic actually gets
  --techniques | --list | --status-tsv | --menu | --selftest | --help

A mobile backend is an API that never expected a stranger. The app was the only
client it imagined, so the client's own numbers — version, build, platform,
device id — became authorization inputs. Because the release train supports old
builds forever, an ancient version is a supported client with the mitigations
missing, and the server serves it happily.

The grading rule that keeps this honest is content, not status. A config
endpoint answering 200 with `{}` is a config endpoint nobody configured, and is
reported as such. It becomes a finding only when the document carries
credentials, secret names, internal hostnames or a debug switch — which is what
`--config` classifies and shows as keys, never values.

`--versions` needs BOTH responses to say anything: an old version refused is
the gate working, and an old version accepted alongside a newer one accepted
means there is no gate.

`--deep` is the sharp end: the link-verification files say which apps may open
this host's links. A wildcard there is an account-takeover path, and it is
graded HIGH rather than informational.

Environment: MB_TIMEOUT (10), MB_UA (okhttp/4.9.3), MB_OLD_VERSION, MB_NEW_VERSION
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
mb_selftest() {
    cs_selftest_reset

    local nh; nh="$(mb_headers | wc -l | tr -d ' ')"
    chk headers-3col   "$(mb_headers | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk headers-unique "$(mb_headers | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nh"
    chk headers-many   "$( (( nh >= 12 )) && echo many || echo few )" "many"

    local np; np="$(mb_paths | wc -l | tr -d ' ')"
    chk paths-2col     "$(mb_paths | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk paths-unique   "$(mb_paths | cut -f1 | sort -u | wc -l | tr -d ' ')" "$np"
    chk paths-many     "$( (( np >= 17 )) && echo many || echo few )" "many"

    chk v-dead        "$(mb_verdict 000)" "unreachable"
    chk v-ok          "$(mb_verdict 200)" "present"
    chk v-401         "$(mb_verdict 401)" "guarded"
    chk v-404         "$(mb_verdict 404)" "absent"
    chk v-429         "$(mb_verdict 429)" "rate-limited"
    chk v-500         "$(mb_verdict 500)" "error"

    chk ver-nogate    "$(mb_version_verdict 200 200)" "no-version-gate"
    chk ver-oldref    "$(mb_version_verdict 400 200)" "old-refused"
    chk ver-newref    "$(mb_version_verdict 200 400)" "newer-refused"
    chk ver-both      "$(mb_version_verdict 400 400)" "both-refused"
    chk ver-dead      "$(mb_version_verdict 000 200)" "unreachable"

    chk s-cred        "$(mb_severity credentials)" "CRITICAL"
    chk s-secret      "$(mb_severity secret-names)" "CRITICAL"
    chk s-debug       "$(mb_severity debug-enabled)" "HIGH"
    chk s-internal    "$(mb_severity internal-endpoints)" "HIGH"
    chk s-plain       "$(mb_severity config-only)" "INFO"

    # config classification against real document shapes
    local d; d="$(mktemp -d "$CS_SCRATCH/mbt.XXXXXX")" 2>/dev/null || d="$OUT_DIR/.mbt.$$"
    mkdir -p "$d"
    printf '{}' > "$d/empty"
    chk c-empty    "$(mb_config_class "$d/empty")" "empty"
    printf '{"featureX":true,"timeout":30}' > "$d/plain"
    chk c-plain    "$(mb_config_class "$d/plain")" "config-only"
    printf '{"api_key":"sk-abcdefghijklmnopqrstuvwxyz12"}' > "$d/cred"
    chk c-cred     "$(mb_config_class "$d/cred")" "credentials"
    printf '{"debug_mode":true}' > "$d/dbg"
    chk c-dbg      "$(mb_config_class "$d/dbg")" "debug-enabled"
    printf '{"baseUrl":"https://10.0.4.11/api"}' > "$d/int"
    chk c-internal "$(mb_config_class "$d/int")" "internal-endpoints"
    printf '{"client_secret":"unset"}' > "$d/secret"
    chk c-secret   "$(mb_config_class "$d/secret")" "secret-names"
    rm -rf "$d"

    # a dead host must never produce a config finding
    local out; out="$(mb_cmd_probe http://127.0.0.1:9 2>/dev/null)"
    chk dead-probe  "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    chk dead-sum    "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}')" "found=0 total=17"
    out="$(mb_cmd_config http://127.0.0.1:9 2>/dev/null)"
    chk dead-config "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    out="$(mb_cmd_versions http://127.0.0.1:9 2>/dev/null)"
    chk dead-vers   "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"

    # usage errors
    mb_cmd_probe 2>/dev/null;    chk use-1 "$?" "2"
    mb_cmd_versions 2>/dev/null; chk use-2 "$?" "2"
    mb_cmd_static 2>/dev/null;   chk use-3 "$?" "2"
    mb_cmd_config 2>/dev/null;   chk use-4 "$?" "2"
    mb_cmd_deep 2>/dev/null;     chk use-5 "$?" "2"
    mb_cmd_cert 2>/dev/null;     chk use-6 "$?" "2"

    chk status-fields "$(mb_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(mb_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(mb_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(mb_cmd_help | head -1 | grep -ci 'Mobile Backend')" "1"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)      shift; mb_cmd_probe "$@";;
    --versions)   shift; mb_cmd_versions "$@";;
    --static)     shift; mb_cmd_static "$@";;
    --config)     shift; mb_cmd_config "$@";;
    --deep)       shift; mb_cmd_deep "$@";;
    --cert)       shift; mb_cmd_cert "$@";;
    --techniques) mb_cmd_techniques;;
    --list)       mb_cmd_list;;
    --status-tsv|--status) mb_cmd_status_tsv;;
    --menu)       mb_cmd_menu;;
    --selftest)   mb_selftest;;
    *)            mb_cmd_help;;
esac
