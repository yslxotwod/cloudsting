
## Findings — the rule every module must follow

`cs_findings_row` in `data/lib/core.sh` **appends the row to
`loot/findings.tsv` itself** and also prints it. Call it directly:

```bash
cs_findings_row "$MODULE_ID" "CATEGORY" "$target" "critical-my-check" "$detail" > /dev/null
```

- The severity rides on the **key** as a leading word (`critical-`, `high-`,
  `medium-`, `low-`), not as a separate column. The core parses the key's first
  word to decide the severity column.
- Redirect to `> /dev/null` unless you want the row on stdout too. Do **not**
  append it to the ledger yourself — the core already did, and a second
  `>> "$f"` writes the row twice.
- Before this rule was enforced, 41 modules called it with no redirect and
  their findings went to stdout and were discarded. If you add a module and
  `loot/findings.tsv` does not grow, the call never reached the core.

A selftest must **never** write to the real ledger. Every selftest that calls a
findings-producing verb saves `CS_LOOT`, points it at `$CS_SCRATCH` for the
duration, and restores it before `cs_selftest_done`:

```bash
local real_loot="$CS_LOOT"
CS_LOOT="$CS_SCRATCH"
mkdir -p "$CS_LOOT"
...
CS_LOOT="$real_loot"
cs_selftest_done
```

### The schema

`ts  module  category  severity  target  check  detail  evidence  run`

`run` is last so every earlier index keeps its meaning. It carries
`$CS_RUN_ID`, which is how you tell runs apart in the ledger. An older
eight-column ledger is upgraded in place by `cs_findings_ensure`, so a reader
can always index the same field.

### Duplicates

The core **skips an exact repeat** of a row (same module, category, severity,
target, check and detail). Two scans of one target used to append two
identical rows and make the ledger unreadable. `CS_FINDINGS_NO_DEDUP=1`
forces the write when you deliberately want history. `findings ingest`
reports `NEW` and `DUPLICATE` separately for this reason.

### Categories — there is one vocabulary

`SETUP CREDS IDENTITY ATTRITION DNS STORAGE COMPUTE NETWORK SURFACE WEBAPI TOOLING`

`cs_findings_category` normalises on the way in: known words pass through,
retired spellings (`CREDENTIALS`, `SECRETS`, `RECON`, `API`, …) are
translated, and **anything else is answered by the module's registered
category in `data/registry.tsv`** — so a module cannot invent a bucket by
passing a new word. `findings normalise` rewrites existing rows through the
same table.

### One HTTP helper

Use `cs_http` instead of writing another curl wrapper. 33 modules had their
own, and the same two bugs kept appearing in them:

```bash
r="$(cs_http POST "$url" -d "$body" -c application/json -m 10 -L)"
cs_split "$r" code secs bytes hash ctype location body err
```

It prints one `U+001F`-separated record — `code secs bytes sha1-12
content-type location body-path error`. Split it with `cs_split`, never
`read`. Flags: `-H 'K: v'` (repeatable), `-d <body>`, `-f <file>` (body from
a file, bytes preserved exactly), `-c <ctype>`, `-m <secs>`, `-L`, `-k`,
`-A <ua>`, `-b <cookie>`, `-t <token>`, `-o <path>`.

Why it looks the way it does:

- **curl does not expand `\t` or `\036` inside `--write-out`.** A format with
  a tab emits a literal backslash-t, so `IFS=$'\t' read` never splits and the
  whole meta string lands in the status code. Two modules compared garbage for
  weeks while looking healthy. Only three always-numeric, space-separated
  fields ride the format string here.
- **Content-Type contains a space**, so it cannot ride the format string
  either — it is read back out of the header dump, from what the server
  actually sent. `Location` likewise.
- **The error is a field, not a global.** The normal call is `$(cs_http …)`,
  and a command substitution runs in a subshell: a global set in there never
  reaches the caller.
- **`-f` preserves trailing newlines.** Signing `$(cat file)` instead of
  sending the file was silently breaking every forged webhook signature —
  the bytes signed differed from the bytes sent.

