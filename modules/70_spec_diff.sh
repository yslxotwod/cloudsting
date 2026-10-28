#!/usr/bin/env bash
# 70_spec_diff.sh — cloudsting module 70: what changed, and which change added a door
# Verbs: --diff | --auth | --new | --params | --deprecated | --snapshot
#        | --classes | --list | --status-tsv | --menu | --selftest | --help
#
# 42_openapi reads ONE spec and asks how bad it is. This module reads TWO and
# asks what moved. The interesting diff is never "an endpoint was added" — it is
# "an endpoint was added without the security block its neighbours carry", which
# is a one-line omission in a pull request and a permanent hole in production.
set -u
umask 077

# A parent that sourced the core exports CS_MOD_DIR; this module derives its own.
unset CS_MOD_DIR

MODULE_ID="70_spec_diff"
MOD_NAME="Spec Diff (what changed, and which change added a door)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/spec_diff"
mkdir -p "$OUT_DIR" 2>/dev/null || true

DIFF_FILE="$OUT_DIR/diff-$RUN_ID.tsv"
: > "$DIFF_FILE"

: "${SD_TIMEOUT:=15}"
: "${SD_FOLLOW:=0}"
: "${SD_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/70}"

sd_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── the classes of change ────────────────────────────────────────
#   <class>\t<what changed>\t<why it matters>
sd_classes() {
    cat <<'CLASSES'
added	an endpoint that did not exist — usually undocumented, reviewed by nobody
removed	an endpoint that existed — a client still calls it; what answers now
auth-weakened	security on an endpoint loosened — the door was locked and is not
auth-strengthened	security tightened — worth knowing, never a finding
params-changed	the parameter count moved — every new one is an injection candidate
deprecated-changed	an endpoint was or was not marked for removal — auth stops being maintained
type-changed	a field changed type — the client and server disagree about the bytes
server-changed	a new base URL or hostname — a shadow deployment nobody watches
new-endpoint	an endpoint with no security, graded against its siblings
removed-endpoint	an operation disappeared while a client may still call it
CLASSES
}

# ── fetching a spec ──────────────────────────────────────────────
# A spec argument is a URL, a path, or "-" for stdin. Everything downstream
# assumes a file, so --snapshot turns a URL into one and a diff may be given
# two files directly.
#   sd_fetch <url|path|->  -> path to a local JSON file
sd_fetch() {
    local src="$1"
    if [[ "$src" == "-" ]]; then
        local f; f="$(mktemp "$CS_SCRATCH/sd.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.sd.$$"
        cat > "$f"
        printf '%s' "$f"; return 0
    fi
    if [[ -f "$src" ]]; then printf '%s' "$src"; return 0; fi
    case "$src" in
        http://*|https://*)
            local f; f="$(mktemp "$CS_SCRATCH/sdu.XXXXXX")" 2>/dev/null || f="$OUT_DIR/.sdu.$$"
            local -a args=(-sS -m "$SD_TIMEOUT" -A "$SD_UA" -o "$f" -w '%{http_code}')
            [ "$SD_FOLLOW" = "1" ] && args+=(-L)
            local code; code="$(curl "${args[@]}" "$src" 2>/dev/null)"
            if [[ ! "$code" =~ ^2 ]]; then sd_log "fetch $src -> $code"; rm -f "$f"; printf ''; return 1; fi
            printf '%s' "$f"; return 0 ;;
        *)  printf ''; return 1 ;;
    esac
}

# ── flattening ───────────────────────────────────────────────────
# Both dialects are read the same way: paths -> methods -> the shape of each
# operation. Everything the diff cares about fits in six fields, so the
# comparison is a join on the path+method key rather than a document walk.
#   <path>\t<method>\t<auth: none|scheme|unspecified>\t<param-count>\t<deprecated:0|1>\t<request-type>
#
#   sd_flatten <spec-file>  -> TSV rows on stdout
sd_flatten() {
    local f="$1"
    [[ -s "$f" ]] || return 1
    python3 - "$f" <<'PY'
import json, sys, re

path = sys.argv[1]
try:
    doc = json.load(open(path, 'rb'))
except Exception as e:
    sys.stderr.write("not-json: %s\n" % e)
    sys.exit(1)

METHODS = ('get','put','post','delete','options','head','patch','trace')

def global_auth(doc):
    # Swagger 2: securityDefinitions + a top-level `security`
    # OpenAPI 3: components.securitySchemes + the same top-level key
    return bool(doc.get('security'))

def op_auth(op, has_global):
    sec = op.get('security')
    if sec is None:
        return ('none' if not has_global else 'unspecified')
    if sec == [] or sec == [{}]:
        return 'none'
    try:
        schemes = [k for d in sec for k in d.keys()]
    except Exception:
        return 'unspecified'
    return ','.join(sorted(set(schemes))) if schemes else 'none'

def param_count(op, path_item):
    n = 0
    for holder in (path_item, op):
        for p in (holder.get('parameters') or []):
            if isinstance(p, dict):
                n += 1
    body = op.get('requestBody') or (op.get('x-request-body') or {})
    if isinstance(body, dict) and body.get('content'):
        n += len(body.get('content') or {})
    return n

def req_type(op):
    body = op.get('requestBody')
    if isinstance(body, dict):
        c = body.get('content') or {}
        if c: return ','.join(sorted(c.keys()))
    for p in (op.get('parameters') or []):
        if isinstance(p, dict) and p.get('in') == 'body':
            s = p.get('schema') or {}
            return s.get('$ref') or s.get('type') or 'body'
    return '-'

has_global = global_auth(doc)
paths = doc.get('paths') or {}
for p, item in paths.items():
    if not isinstance(item, dict):
        continue
    for m in METHODS:
        op = item.get(m)
        if not isinstance(op, dict):
            continue
        auth = op_auth(op, has_global)
        dep = '1' if op.get('deprecated') in (True, 'true') else '0'
        print('\t'.join([p, m.upper(), auth, str(param_count(op, item)), dep, req_type(op)]))

servers = []
for s in (doc.get('servers') or []):
    if isinstance(s, dict) and s.get('url'):
        servers.append(s['url'])
for h in (doc.get('host'),):
    if h: servers.append(h)
for s in servers:
    print('\t'.join(['@server', '-', '-', '0', '0', s]))
PY
}

# ── comparing ────────────────────────────────────────────────────
#   sd_diff_rows <old.tsv> <new.tsv>  -> one row per change
sd_diff_rows() {
    local old="$1" new="$2"
    awk -F'\t' '
        FNR==NR { if ($1=="@server") { osrv[$6]=1 } else { o[$1"\t"$2]=$0 } ; next }
        $1=="@server" { if (!($6 in osrv)) print "added\t@server\t-\tserver-added\t0\t" $6; next }
        {
            k=$1"\t"$2
            if (!(k in o)) { print "added\t" $1 "\t" $2 "\tnew-endpoint\t" $3 "\t" $0; next }
            split(o[k], f, "\t")
            seen[k]=1
            if (f[3] != $3) {
                if (f[3]=="none")        print "strengthened\t" $1 "\t" $2 "\tauth-strengthened\t" $3 "\t" f[3] " -> " $3
                else                     print "weakened\t" $1 "\t" $2 "\tauth-weakened\t" $3 "\t" f[3] " -> " $3
            }
            if (f[4] != $4)  print "params\t" $1 "\t" $2 "\tparams-changed\t" $3 "\t" f[4] " -> " $4
            if (f[5] != $5)  print "deprecated\t" $1 "\t" $2 "\tdeprecated-changed\t" $3 "\t" f[5] " -> " $5
            if (f[6] != $6)  print "type\t" $1 "\t" $2 "\ttype-changed\t" $3 "\t" f[6] " -> " $6
        }
        END {
            for (k in o) {
                if (!(k in seen)) {
                    split(o[k], f, "\t")
                    print "removed\t" f[1] "\t" f[2] "\tremoved-endpoint\t" f[3] "\t-"
                }
            }
        }
    ' "$old" "$new"
}

# ── grading ──────────────────────────────────────────────────────
# The finding is never "an endpoint is new". It is "an endpoint is new AND it
# has no security while its neighbours do" — that is what a leaked staging spec
# looks like just before it becomes an incident.
#   sd_grade <change-class> <new-auth> <sibling-auth> <path> <method>
sd_grade() {
    local class="$1" auth="$2" sib="${3:-none}" path="$4" method="${5:-}"
    case "$class" in
        auth-weakened)
            [[ "$auth" == "none" ]] && { printf 'CRITICAL'; return; }
            printf 'HIGH' ;;
        new-endpoint)
            if [[ "$auth" == "none" ]]; then
                case "$path" in
                    */admin/*|*/admin*|*/internal/*|*/_debug/*|*/metrics*|*/export*|*/config*)
                        printf 'CRITICAL' ;;
                    *)  [[ "$sib" == "guarded" ]] && printf 'HIGH' || printf 'MEDIUM' ;;
                esac
            elif [[ "$auth" == "unspecified" ]]; then
                printf 'MEDIUM'
            else
                printf 'INFO'
            fi ;;
        removed-endpoint)  printf 'LOW' ;;
        params-changed)    printf 'MEDIUM' ;;
        deprecated-changed) printf 'MEDIUM' ;;
        type-changed)      printf 'HIGH' ;;
        server-changed)    printf 'MEDIUM' ;;
        *)                 printf 'INFO' ;;
    esac
}

# The sibling question: does the AVERAGE of this spec carry auth. A spec where
# everything is open is a design, not an omission, and grading it CRITICAL
# would be noise.
#   sd_sibling_auth <flat.tsv> <path>
sd_sibling_auth() {
    local flat="$1" path="$2"
    local dir; dir="$(dirname "$path")"
    awk -F'\t' -v d="$dir" '
        $1 ~ /^@/ { next }
        {
            if (d == "/" || d == "." ) { if ($3 != "none" && $3 != "unspecified") yes++; n++; next }
            if (index($1, d "/") == 1 || $1 == d) { if ($3 != "none" && $3 != "unspecified") yes++; n++ }
        }
        END { if (n == 0) { print "unknown" } else if (yes*2 >= n) { print "guarded" } else { print "open" } }
    ' "$flat"
}

# ── verbs ────────────────────────────────────────────────────────

# --diff <old> <new>: every change, graded.
sd_cmd_diff() {
    local old_src="${1:-}" new_src="${2:-}"
    [[ -z "$old_src" || -z "$new_src" ]] && { sd_log "usage: --diff <old-spec> <new-spec>"; return 2; }

    local of nf
    of="$(sd_fetch "$old_src")" || { cs_row VERDICT "unreachable" "old spec not readable"; cs_row SUMMARY "fail=old"; return 0; }
    nf="$(sd_fetch "$new_src")" || { cs_row VERDICT "unreachable" "new spec not readable"; cs_row SUMMARY "fail=new"; return 0; }

    cs_row OLD "$old_src"
    cs_row NEW "$new_src"

    local oflat nflat
    oflat="$(mktemp "$CS_SCRATCH/sdo.XXXXXX")"
    nflat="$(mktemp "$CS_SCRATCH/sdn.XXXXXX")"
    local rc_o=0 rc_n=0
    sd_flatten "$of" > "$oflat" 2>/dev/null || rc_o=1
    sd_flatten "$nf" > "$nflat" 2>/dev/null || rc_n=1

    local on nnew
    on="$(awk -F'\t' '$1 !~ /^@/' "$oflat" | wc -l | tr -d ' ')"
    nnew="$(awk -F'\t' '$1 !~ /^@/' "$nflat" | wc -l | tr -d ' ')"
    cs_row OPERATIONS "old=${on:-0}" "new=${nnew:-0}"
    # a document that does not parse is not a document with no changes: the
    # difference between "nothing moved" and "I could not read this" is the
    # whole value of the tool
    if [[ "$rc_o" != "0" || "$rc_n" != "0" ]]; then
        local which="both"; [[ "$rc_o" == "0" ]] && which="new"; [[ "$rc_n" == "0" ]] && which="old"
        cs_row VERDICT "unreadable" "$which did not parse as JSON"
        cs_row SUMMARY "old=$on new=$nnew unreadable=$which"
        rm -f "$oflat" "$nflat" "$of" "$nf"
        return 0
    fi
    if [[ "${on:-0}" == "0" && "${nnew:-0}" == "0" ]]; then
        cs_row VERDICT "unreadable" "neither side flattened to any operation"
        cs_row SUMMARY "old=0 new=0"
        rm -f "$oflat" "$nflat" "$of" "$nf"
        return 0
    fi

    local changes; changes="$(sd_diff_rows "$oflat" "$nflat")"
    local total; total="$(printf '%s' "$changes" | grep -c . || true)"
    cs_row CHANGES "${total:-0}"
    : > "$DIFF_FILE"

    local hits=0 crit=0
    local class path method cclass auth detail
    while IFS=$'\t' read -r class path method cclass auth detail; do
        [[ -z "$class" ]] && continue
        local sib; sib="$(sd_sibling_auth "$nflat" "$path")"
        local sev; sev="$(sd_grade "$cclass" "$auth" "$sib" "$path" "$method")"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$class" "$path" "$method" "$cclass" "$auth" "$sev" "$detail" >> "$DIFF_FILE"

        case "$sev" in
            CRITICAL|HIGH)
                hits=$((hits + 1))
                [[ "$sev" == "CRITICAL" ]] && crit=$((crit + 1))
                cs_row HIT "$cclass" "$method $path" "sev=$sev" "auth=${auth}" "siblings=$sib" "$detail"
                cs_findings_row "$MODULE_ID" "WEBAPI" "$path" "$sev" "spec-$cclass" \
                    "$method $path: $cclass (auth=$auth, siblings=$sib)" >> "$DIFF_FILE"
                ;;
            *)  cs_row CHANGE "$cclass" "$method $path" "sev=$sev" "$detail" ;;
        esac
    done <<< "$changes"

    local v="no-security-change"
    (( hits > 0 )) && v="security-regressed"
    cs_row VERDICT "$v" "$hits graded HIGH or above of ${total:-0} changes"
    cs_row SUMMARY "changes=${total:-0} hits=$hits critical=$crit"
    cs_row ARTIFACT "$DIFF_FILE"
    rm -f "$oflat" "$nflat"
    [[ "$of" != "$old_src" ]] && rm -f "$of"
    [[ "$nf" != "$new_src" ]] && rm -f "$nf"
    return 0
}

# --auth <old> <new>: only the auth column. A spec diff is 95% noise; this is
# the 5% that matters, isolated.
sd_cmd_auth() {
    local old_src="${1:-}" new_src="${2:-}"
    [[ -z "$old_src" || -z "$new_src" ]] && { sd_log "usage: --auth <old> <new>"; return 2; }
    local of nf
    of="$(sd_fetch "$old_src")"; nf="$(sd_fetch "$new_src")"
    [[ -z "$of" || -z "$nf" ]] && { cs_row VERDICT "unreachable"; cs_row SUMMARY "fail=fetch"; return 0; }
    local oflat nflat
    oflat="$(mktemp "$CS_SCRATCH/sdo.XXXXXX")"; nflat="$(mktemp "$CS_SCRATCH/sdn.XXXXXX")"
    sd_flatten "$of" > "$oflat" 2>/dev/null
    sd_flatten "$nf" > "$nflat" 2>/dev/null

    local open_old open_new
    open_old="$(awk -F'\t' '$1 !~ /^@/ && ($3=="none"||$3=="unspecified")' "$oflat" | wc -l | tr -d ' ')"
    open_new="$(awk -F'\t' '$1 !~ /^@/ && ($3=="none"||$3=="unspecified")' "$nflat" | wc -l | tr -d ' ')"
    local tot_old tot_new
    tot_old="$(grep -vc '^@' "$oflat" 2>/dev/null | tr -d ' ')"
    tot_new="$(grep -vc '^@' "$nflat" 2>/dev/null | tr -d ' ')"

    cs_row UNGUARDED "old=${open_old:-0}/${tot_old:-0}" "new=${open_new:-0}/${tot_new:-0}"

    local diff; diff="$(sd_diff_rows "$oflat" "$nflat" | awk -F'\t' '$4 ~ /auth/')"
    local n; n="$(printf '%s' "$diff" | grep -c . || true)"
    cs_row AUTH-CHANGES "${n:-0}"
    local class path method cclass auth detail
    while IFS=$'\t' read -r class path method cclass auth detail; do
        [[ -z "$class" ]] && continue
        local sev; sev="$(sd_grade "$cclass" "$auth" open "$path" "$method")"
        cs_row "$([[ "$class" == weakened ]] && echo WEAKENED || echo STRENGTHENED)" "$method $path" "sev=$sev" "$detail"
        [[ "$class" == weakened ]] && cs_findings_row "$MODULE_ID" "WEBAPI" "$path" "$sev" "spec-auth-weakened" "$method $path: $detail"
    done <<< "$diff"

    local v="auth-unchanged"
    [[ "${open_new:-0}" -gt "${open_old:-0}" ]] && v="more-unguarded"
    cs_row VERDICT "$v"
    cs_row SUMMARY "open-old=${open_old:-0} open-new=${open_new:-0} changes=${n:-0}"
    rm -f "$oflat" "$nflat"
    [[ "$of" != "$old_src" ]] && rm -f "$of"
    [[ "$nf" != "$new_src" ]] && rm -f "$nf"
    return 0
}

# --new <old> <new>: only endpoints that did not exist, graded against their
# siblings. This is the one verb you run on every pull request.
sd_cmd_new() {
    local old_src="${1:-}" new_src="${2:-}"
    [[ -z "$old_src" || -z "$new_src" ]] && { sd_log "usage: --new <old> <new>"; return 2; }
    local of nf
    of="$(sd_fetch "$old_src")"; nf="$(sd_fetch "$new_src")"
    [[ -z "$of" || -z "$nf" ]] && { cs_row VERDICT "unreachable"; cs_row SUMMARY "fail=fetch"; return 0; }
    local oflat nflat
    oflat="$(mktemp "$CS_SCRATCH/sdo.XXXXXX")"; nflat="$(mktemp "$CS_SCRATCH/sdn.XXXXXX")"
    sd_flatten "$of" > "$oflat" 2>/dev/null
    sd_flatten "$nf" > "$nflat" 2>/dev/null

    local hits=0 n=0
    local path method auth params dep rtype
    # a path only in the new spec
    while IFS=$'\t' read -r path method auth params dep rtype; do
        [[ "$path" == "@server" ]] && continue
        grep -qF "$path"$'\t'"$method" "$oflat" && continue
        n=$((n + 1))
        local sib; sib="$(sd_sibling_auth "$nflat" "$path")"
        local sev; sev="$(sd_grade new-endpoint "$auth" "$sib" "$path" "$method")"
        case "$sev" in
            CRITICAL|HIGH) hits=$((hits + 1));
                cs_row HIT "$path" "$method" "sev=$sev" "auth=${auth}" "siblings=$sib" ;;
            *) cs_row NEW "$path" "$method" "sev=$sev" "auth=${auth}" ;;
        esac
        cs_findings_row "$MODULE_ID" "WEBAPI" "$path" "$sev" "spec-new-endpoint" \
            "$method $path added with auth=$auth (siblings=$sib)" >> "$DIFF_FILE"
    done < <(awk -F'\t' '$1 !~ /^@/' "$nflat")

    local v="no-new-endpoints"; (( n > 0 )) && v="new-endpoints"; (( hits > 0 )) && v="new-unguarded-endpoint"
    cs_row VERDICT "$v" "$n added, $hits unguarded"
    cs_row SUMMARY "new=$n hits=$hits"
    rm -f "$oflat" "$nflat"
    [[ "$of" != "$old_src" ]] && rm -f "$of"
    [[ "$nf" != "$new_src" ]] && rm -f "$nf"
    return 0
}

# --params <old> <new>: parameters are the injection surface, and one added in
# a hurry is the one nobody fuzzed.
sd_cmd_params() {
    local old_src="${1:-}" new_src="${2:-}"
    [[ -z "$old_src" || -z "$new_src" ]] && { sd_log "usage: --params <old> <new>"; return 2; }
    local of nf; of="$(sd_fetch "$old_src")"; nf="$(sd_fetch "$new_src")"
    [[ -z "$of" || -z "$nf" ]] && { cs_row VERDICT "unreachable"; return 0; }
    local oflat nflat
    oflat="$(mktemp "$CS_SCRATCH/sdo.XXXXXX")"; nflat="$(mktemp "$CS_SCRATCH/sdn.XXXXXX")"
    sd_flatten "$of" > "$oflat" 2>/dev/null; sd_flatten "$nf" > "$nflat" 2>/dev/null
    local out; out="$(sd_diff_rows "$oflat" "$nflat" | awk -F'\t' '$4=="params-changed"')"
    local n; n="$(printf '%s' "$out" | grep -c . || true)"
    cs_row AXIS "$old_src -> $new_src"
    while IFS=$'\t' read -r class path method cclass auth detail; do
        [[ -z "$class" ]] && continue
        cs_row "$([[ "$auth" -gt 0 ]] 2>/dev/null && echo GREW || echo SHRANK)" "$method $path" "$detail"
    done <<< "$out"
    cs_row VERDICT "$( (( n > 0 )) && echo parameter-surface-changed || echo parameter-surface-stable )" "$n endpoints"
    cs_row SUMMARY "param-changes=${n:-0}"
    rm -f "$oflat" "$nflat"
    [[ "$of" != "$old_src" ]] && rm -f "$of"
    [[ "$nf" != "$new_src" ]] && rm -f "$nf"
    return 0
}

# --deprecated <spec>: deprecated endpoints are the security debt that never
# gets paid. On its own it is a list; the question is whether they are guarded.
sd_cmd_deprecated() {
    local src="${1:-}"
    [[ -z "$src" ]] && { sd_log "usage: --deprecated <spec>"; return 2; }
    local f; f="$(sd_fetch "$src")"
    [[ -z "$f" ]] && { cs_row VERDICT "unreachable"; cs_row SUMMARY "fail=fetch"; return 0; }
    local flat; flat="$(mktemp "$CS_SCRATCH/sdp.XXXXXX")"
    sd_flatten "$f" > "$flat" 2>/dev/null

    local n=0 open=0
    local path method auth params dep rtype
    while IFS=$'\t' read -r path method auth params dep rtype; do
        [[ "$path" == "@server" ]] && continue
        [[ "$dep" == "1" ]] || continue
        n=$((n + 1))
        local sev="INFO"
        if [[ "$auth" == "none" ]]; then
            open=$((open + 1)); sev="HIGH"
            cs_findings_row "$MODULE_ID" "WEBAPI" "$path" "HIGH" "spec-deprecated-open" \
                "$method $path is deprecated and carries no security" > /dev/null
        fi
        cs_row DEPRECATED "$method $path" "$sev" "auth=$auth"
    done < <(awk -F'\t' '$1 !~ /^@/' "$flat")

    cs_row VERDICT "$( (( open > 0 )) && echo deprecated-unguarded || echo deprecated-clean )" "$open of $n unguarded"
    cs_row SUMMARY "deprecated=$n unguarded=$open"
    rm -f "$flat"
    [[ "$f" != "$src" ]] && rm -f "$f"
    return 0
}

# --snapshot <spec> [out]: freeze a spec so tomorrow's diff has a baseline.
sd_cmd_snapshot() {
    local src="${1:-}" out="${2:-}"
    [[ -z "$src" ]] && { sd_log "usage: --snapshot <spec> [outfile]"; return 2; }
    local f; f="$(sd_fetch "$src")"
    [[ -z "$f" ]] && { cs_row VERDICT "unreachable"; cs_row SUMMARY "fail=fetch"; return 0; }
    if [[ -z "$out" ]]; then
        out="$OUT_DIR/spec-$RUN_ID.json"
    fi
    cp "$f" "$out"
    chmod 600 "$out" 2>/dev/null || true
    local ops; ops="$(sd_flatten "$f" 2>/dev/null | grep -vc '^@')"
    cs_row SOURCE "$src"
    cs_row SNAPSHOT "$out"
    cs_row OPERATIONS "${ops:-0}"
    cs_row VERDICT "saved"
    cs_row SUMMARY "ops=${ops:-0}"
    rm -f "$f"
    return 0
}

sd_cmd_classes() { local c w; while IFS=$'\t' read -r c w; do [[ -z "$c" ]] && continue; cs_row CLASS "$c" "$w"; done < <(sd_classes); cs_row SUMMARY "classes=$(sd_classes | wc -l | tr -d ' ')"; return 0; }
sd_cmd_list()    { cs_row VERB "diff" "auth" "new" "params" "deprecated" "snapshot" "classes"; cs_row SUMMARY "ok"; return 0; }

sd_cmd_status_tsv() {
    local py cur
    command -v python3 >/dev/null 2>&1 && py="python3-ok" || py="python3-missing"
    command -v curl    >/dev/null 2>&1 && cur="curl-ok"   || cur="curl-missing"
    printf '%s\t%s\t%s\t%s\tclasses-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$py" "$cur" "$(sd_classes | wc -l | tr -d ' ')"
}

sd_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

sd_cmd_help() {
    cat <<'HELP'
cloudsting module 70 — Spec Diff v1.0.0
  --diff <old> <new>        every change, graded against its siblings
  --auth <old> <new>        only the security column
  --new <old> <new>         only endpoints that did not exist
  --params <old> <new>      only the parameter surface
  --deprecated <spec>       deprecated endpoints, and whether they are guarded
  --snapshot <spec> [out]   freeze a spec as tomorrow's baseline
  --classes | --list | --status-tsv | --menu | --selftest | --help

<old> and <new> are URLs, file paths, or `-` for stdin. Both OpenAPI 3
(`security`/`components.securitySchemes`) and Swagger 2
(`security`/`securityDefinitions`) are flattened the same way, so a migration
from one to the other diffs cleanly.

The finding is never "an endpoint is new". It is "an endpoint is new AND has no
security while its siblings do" — that is a one-line omission in a pull request
and a permanent hole in production. `--new` reports exactly that, and grades an
unguarded `/admin`, `/internal`, `/metrics` or `/export` path CRITICAL.

A spec where EVERYTHING is open is a design decision, not an omission, so the
sibling check looks at the share of operations in the same directory that carry
security before it calls an unguarded one a regression.

Environment: SD_TIMEOUT (15), SD_FOLLOW (0), SD_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
sd_selftest() {
    cs_selftest_reset

    local nc; nc="$(sd_classes | wc -l | tr -d ' ')"
    chk cls-2col   "$(sd_classes | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk cls-unique "$(sd_classes | cut -f1 | sort -u | wc -l | tr -d ' ')" "$nc"
    chk cls-many   "$( (( nc >= 10 )) && echo many || echo few )" "many"

    # two specs that differ in exactly one way each, built as files
    local old new
    old="$(mktemp "$CS_SCRATCH/sds.XXXXXX")"
    new="$(mktemp "$CS_SCRATCH/sds.XXXXXX")"
    cat > "$old" <<'J'
{"openapi":"3.0.0","security":[{"bearer":[]}],
 "paths":{"/api/users":{"get":{"security":[{"bearer":[]}],"parameters":[{"in":"query","name":"q"}]}},
          "/api/legacy":{"get":{"security":[{"bearer":[]}]}}}}
J
    cat > "$new" <<'J'
{"openapi":"3.0.0","security":[{"bearer":[]}],
 "paths":{"/api/users":{"get":{"security":[{"bearer":[]}],"parameters":[{"in":"query","name":"q"},{"in":"query","name":"x"}]}},
          "/api/legacy":{"get":{"security":[]}},
          "/api/admin/export":{"get":{"security":[]}},
          "/api/orders":{"get":{"security":[{"bearer":[]}]}}}}
J

    chk flat-ops    "$(sd_flatten "$old" | grep -vc '^@')" "2"
    chk flat-new    "$(sd_flatten "$new" | grep -vc '^@')" "4"
    chk flat-auth   "$(sd_flatten "$new" | awk -F'\t' '$1=="/api/admin/export"{print $3}')" "none"
    chk flat-dep    "$(sd_flatten "$old" | awk -F'\t' '$1=="/api/users"{print $5}')" "0"

    local changes; changes="$(sd_diff_rows <(sd_flatten "$old") <(sd_flatten "$new"))"
    chk diff-added   "$(printf '%s\n' "$changes" | awk -F'\t' '$1=="added"' | wc -l | tr -d ' ')" "2"
    chk diff-weakened "$(printf '%s\n' "$changes" | awk -F'\t' '$1=="weakened"' | wc -l | tr -d ' ')" "1"
    chk diff-params  "$(printf '%s\n' "$changes" | awk -F'\t' '$4=="params-changed"' | wc -l | tr -d ' ')" "1"

    # grading: the sibling matters
    chk g-crit      "$(sd_grade new-endpoint none guarded /api/admin/export GET)" "CRITICAL"
    chk g-high      "$(sd_grade new-endpoint none guarded /api/orders GET)" "HIGH"
    chk g-med-open  "$(sd_grade new-endpoint none open /api/orders GET)" "MEDIUM"
    chk g-med-uns   "$(sd_grade new-endpoint unspecified guarded /api/x GET)" "MEDIUM"
    chk g-info      "$(sd_grade new-endpoint bearer guarded /api/x GET)" "INFO"
    chk g-weakened  "$(sd_grade auth-weakened none none /a GET)" "CRITICAL"
    chk g-weakhard  "$(sd_grade auth-weakened bearer none /a GET)" "HIGH"
    chk g-type      "$(sd_grade type-changed bearer none /a GET)" "HIGH"

    chk sib-guarded "$(sd_sibling_auth <(sd_flatten "$new") /api/orders)" "guarded"
    chk sib-open    "$(sd_sibling_auth <(sd_flatten "$new") /nope/none)" "unknown"

    # end to end through the real verb
    local out; out="$(sd_cmd_diff "$old" "$new" 2>/dev/null)"
    chk e2e-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "security-regressed"
    # /api/legacy lost its security (CRITICAL) and /api/admin/export is new and
    # unguarded (CRITICAL too) — two criticals is the correct answer
    chk e2e-critical "$(printf '%s' "$out" | awk -F'\t' '$1=="HIT" && $4=="sev=CRITICAL"' | wc -l | tr -d ' ')" "2"
    chk e2e-hits     "$(printf '%s' "$out" | grep -c '^HIT')" "2"

    out="$(sd_cmd_new "$old" "$new" 2>/dev/null)"
    chk new-verdict  "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "new-unguarded-endpoint"
    chk new-count    "$(printf '%s' "$out" | awk -F'\t' '$1=="SUMMARY"{print $2}' | cut -d' ' -f1)" "new=2"

    out="$(sd_cmd_auth "$old" "$new" 2>/dev/null)"
    chk auth-w       "$(printf '%s' "$out" | grep -c '^WEAKENED')" "1"

    # identical specs produce no security change
    out="$(sd_cmd_diff "$old" "$old" 2>/dev/null)"
    chk same-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "no-security-change"
    chk same-changes "$(printf '%s' "$out" | awk -F'\t' '$1=="CHANGES"{print $2}')" "0"

    # a non-spec file is not a crash
    local junk; junk="$(mktemp "$CS_SCRATCH/sdj.XXXXXX")"
    printf 'not json at all\n' > "$junk"
    out="$(sd_cmd_diff "$junk" "$new" 2>/dev/null)"
    chk junk-verdict "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreadable"
    rm -f "$junk"

    # a missing file is unreachable, never a finding
    out="$(sd_cmd_diff /nonexistent.json "$new" 2>/dev/null)"
    chk missing      "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"
    chk missing-hits "$(printf '%s' "$out" | grep -c '^HIT')" "0"

    # deps
    sd_cmd_diff 2>/dev/null;       chk use-1 "$?" "2"
    sd_cmd_auth 2>/dev/null;       chk use-2 "$?" "2"
    sd_cmd_new 2>/dev/null;        chk use-3 "$?" "2"
    sd_cmd_params 2>/dev/null;     chk use-4 "$?" "2"
    sd_cmd_deprecated 2>/dev/null; chk use-5 "$?" "2"
    sd_cmd_snapshot 2>/dev/null;   chk use-6 "$?" "2"

    chk status-fields "$(sd_cmd_status_tsv | awk -F'\t' '{print NF}')" "5"
    chk status-module "$(sd_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields   "$(sd_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first    "$(sd_cmd_help | head -1 | grep -ci 'Spec Diff')" "1"
    chk cls-rows      "$(sd_cmd_classes | grep -c '^CLASS')" "$nc"

    # snapshot writes a readable copy
    local snap; snap="$CS_SCRATCH/snap-$$.json"
    out="$(sd_cmd_snapshot "$old" "$snap" 2>/dev/null)"
    chk snap-verdict  "$(printf '%s' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" "saved"
    chk snap-exists   "$( [[ -s "$snap" ]] && echo yes || echo no )" "yes"
    rm -f "$snap" "$old" "$new"

    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --diff)       shift; sd_cmd_diff "$@";;
    --auth)       shift; sd_cmd_auth "$@";;
    --new)        shift; sd_cmd_new "$@";;
    --params)     shift; sd_cmd_params "$@";;
    --deprecated) shift; sd_cmd_deprecated "$@";;
    --snapshot)   shift; sd_cmd_snapshot "$@";;
    --classes)    sd_cmd_classes;;
    --list)       sd_cmd_list;;
    --status-tsv|--status) sd_cmd_status_tsv;;
    --menu)       sd_cmd_menu;;
    --selftest)   sd_selftest;;
    *)            sd_cmd_help;;
esac
