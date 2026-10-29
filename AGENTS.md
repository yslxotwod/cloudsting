
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
