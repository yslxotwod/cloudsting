#!/usr/bin/env bash
# tools/core_adopt.sh — replace the per-module boilerplate with data/lib/core.sh
#
# Every module between 03 and 23 carried the same forty lines: a symlink walk,
# a HOME reset, a run-id, `LOOT_DIR:=$HOME/loot/cloudsting`, four mkdir calls,
# a log helper and a private chk(). That copy is where the bug lived: loot
# landed in $HOME/loot/cloudsting instead of <root>/loot, so the launcher's
# `loot` verb and the findings store could not see a run.
#
# This rewrites the header of each module to source data/lib/core.sh and keeps
# two things the core cannot know: the module's own name and its short prefix
# for back-compat env vars (BUCKET_RUN_ID, TK_RUN_ID, …).
#
# Idempotent: a module that already sources the core is skipped. A backup is
# written next to the original the first time. --dry-run prints instead.
set -Eeuo pipefail
IFS=$'\n\t'

DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODS="$ROOT/modules"
CORE_REL='$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh'

changed=0
skipped=0

for f in "$MODS"/*.sh; do
    [[ -e "$f" ]] || continue
    slug="$(basename "$f" .sh)"
    num="${slug%%_*}"

    # 00-02 already use CLOUDSTING_ROOT-relative loot; 24+ are written against
    # the core from the start. Only migrate the pre-core generation.
    if ! [[ "$num" =~ ^[0-9]+$ ]] || (( 10#$num < 3 )) || (( 10#$num > 23 )); then
        skipped=$((skipped + 1)); continue
    fi
    if grep -q 'data/lib/core.sh' "$f"; then
        skipped=$((skipped + 1)); continue
    fi

    # where does the hand-written header end? the first function definition.
    boundary="$(grep -n '^[a-zA-Z_][a-zA-Z0-9_]*()' "$f" | head -1 | cut -d: -f1)"
    [[ -n "$boundary" ]] || { printf 'skip\t%s\tno function boundary\n' "$slug" >&2; skipped=$((skipped+1)); continue; }

    # the module's own short prefix and human name, read from its header
    prefix="$(sed -n '1,45p' "$f" | { grep -oE 'export [A-Z]+_RUN_ID' || true; } | head -1 | sed -E 's/export ([A-Z]+)_RUN_ID/\1/')"
    modname="$(sed -n '1,45p' "$f" | { grep -oE 'MOD_NAME="[^"]*"' || true; } | head -1 | sed -E 's/^MOD_NAME="(.*)"$/\1/')"
    [[ -n "$prefix" ]] || prefix="${slug%%_*}"
    [[ -n "$modname" ]] || modname="$slug"

    # the two comment lines above the shebang, kept verbatim
    head_comment="$(sed -n '2,3p' "$f")"
    verbs_comment="$(sed -n '3p' "$f")"

    new="$(
        printf '#!/usr/bin/env bash\n'
        printf '%s\n' "$head_comment"
        printf 'set -u\numask 077\n\n'
        printf '# Everything below the header depends on the root, and the root is\n'
        printf '# derived from this file only after it is sourced. Clear any inherited\n'
        printf '# value first: a caller that itself sources the core would otherwise\n'
        printf '# hand this module *its* directory, and the module would read its own\n'
        printf '# name as a path.\n'
        printf 'unset CS_MOD_DIR\n\n'
        printf '# The shared core owns the root, the loot tree, the run id, the TSV\n'
        printf '# writer, the three-state provider gate, redaction and the selftest\n'
        printf '# ledger. Sourcing it is what keeps loot under <root>/loot instead of\n'
        printf '# $HOME/loot, so the launcher and the findings store can see a run.\n'
        printf 'MODULE_ID="%s"\n' "$slug"
        printf 'MOD_NAME="%s"\n' "$modname"
        printf '# shellcheck source=../data/lib/core.sh\n'
        printf 'source "%s"\n\n' "$CORE_REL"
        printf '# Back-compat: run-id variable for this module, from the core run id\n'
        printf '# the one run id the core minted.\n'
        printf '%s_RUN_ID="$CS_RUN_ID"\n' "$prefix"
        printf 'export %s_RUN_ID\n' "$prefix"
        printf 'RUN_ID="$CS_RUN_ID"\nexport RUN_ID\n\n'
        printf '# Loot directory for this module: <root>/loot/%s/\n' "${slug#*_}"
        printf 'OUT_DIR="$CS_LOOT/%s"\nmkdir -p "$OUT_DIR" 2>/dev/null || true\n' "${slug#*_}"
        sed -n "${boundary},\$p" "$f"
    )"

    if (( DRY )); then
        printf 'dry\t%s\tlines %s..%s replaced\n' "$slug" "1" "$((boundary - 1))"
        printf '%s\n' "$new" | sed -n '1,22p' | sed 's/^/    /'
        continue
    fi

    [[ -e "$f.orig" ]] || cp -- "$f" "$f.orig"
    printf '%s\n' "$new" > "$f"
    chmod +x "$f"
    changed=$((changed + 1))
    printf 'rewrote\t%s\t(header 1..%s)\n' "$slug" "$((boundary - 1))"
done

printf '\nchanged=%s skipped=%s\n' "$changed" "$skipped"
