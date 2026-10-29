# cloudsting

A GTK4 cloud and API attack-surface toolkit for Linux, with a full CLI behind
it. Shell modules covering cloud credentials, asset inventory, storage exposure,
IAM privilege escalation, instance metadata, containers, Kubernetes and the
REST/GraphQL surfaces that sit in front of them.

![dashboard](assets/screenshot-dashboard.png)

Every module is a standalone script. The GUI is a view over them, not a
container — nothing is locked behind the interface.

> **v1.0.0.** Thirty-seven modules exist and every one is selftested green. The
> API family is the current front: authentication, object- and function-level
> authorization, injection, parameter pollution, smuggling, CORS, OAuth, JWT,
> versioning and upload. Modules that need provider credentials report what they
> are missing rather than pretending to succeed, and every module ships a
> `--selftest` that runs offline.

---

## Why this exists

Cloud attack tooling is split by provider and by verb. `prowler` audits AWS,
`scoutsuite` sweeps multi-cloud, `nuclei` fuzzes the web layer, `kube-hunter`
looks at clusters, and `trufflehog` looks for keys. Each has its own output
shape, its own idea of what "found nothing" means, and none of them agree on
what a finding is.

This tree is wide on purpose: one desk, one launcher, one place where a credential
sweep, a bucket exposure probe, an IAM escalation path and a Lambda dump all land
in the same TSV.

The other thing it does differently: **most tools tell you they worked.** This
one is built to tell you when they didn't. Every module has a `--selftest`, the
credential-gated ones name the tool or the credential they are missing instead of
returning an empty result, and a module that cannot do its job exits non-zero
rather than reporting success.

**No module has an approval gate.** Nothing refuses because a flag or an
environment variable was not set first. There is no `--i-have-authorisation`
and no `ARMED` variable to remember.

---

## How to run it

Any module runs directly, with no launcher and no installation:

```bash
./modules/00_deps.sh --preflight              # what this box has, one page
./modules/01_cred_validate.sh --detect        # what kind of credential is this
./modules/03_bucket_enum.sh --domain example.com
./modules/05_iam_privesc.sh --list            # the technique knowledge base
./modules/07_policy_audit.sh --audit policy.json
./modules/15_container_escape.sh --all        # escape primitives in this container
```

Every module also has `--selftest`, `--status-tsv`, `--menu` and `--help`:

```bash
for m in modules/*.sh; do printf '%s: ' "$m"; bash "$m" --selftest | tail -1; done
```

### The launcher

One entry point, `cloudsting.sh`, over every module. It owns the module metadata
(`data/registry.tsv`) — the GUI reads it rather than carrying its own copy, so a
module added to the registry appears in both places at once.

```bash
./cloudsting.sh menu                    # every module, grouped by category
./cloudsting.sh list                    # id, slug, title, category — TSV
./cloudsting.sh info 3                  # everything known about one module
./cloudsting.sh run 03 --domain example.com
./cloudsting.sh selftest                # every module's selftest, one summary line
./cloudsting.sh selftest 15             # one module
./cloudsting.sh status all              # each module's own status report
./cloudsting.sh loot                    # newest artifacts first
./cloudsting.sh session                 # which provider is actually authenticated
```

A module reference resolves by number (`3`, `03`), by slug (`03_bucket_enum`,
`bucket_enum`) or by title. `run` is an `exec` passthrough: the module's exit code
is the launcher's exit code, so it composes.

| Verb | What it does |
|---|---|
| `menu` | Grouped module list, every drawer open |
| `list` | `id<TAB>slug<TAB>title<TAB>category` |
| `info <ref>` | Path, verbs, selftest count, phase, loot directory |
| `run <ref> [args…]` | Execute the module, preserving its exit code |
| `selftest [ref\|all]` | Run selftests, one line per module, then a summary |
| `status [ref\|all]` | The module's `--status-tsv` rows, slug-prefixed |
| `session [--tsv\|--json\|--summary]` | Credential identity and provider state |
| `loot [ref] [n]` | Newest artifacts across the loot tree |
| `playbook [name]` | Run a named pipeline of modules |
| `findings <verb>` | The unified findings store (see below) |
| `registry [--tsv\|--json\|--header\|--generate]` | The module registry |
| `deps` | What this box has and what it is missing |
| `completion bash\|zsh` | Shell completion |
| `man` | Manual page on stdout |
| `version`, `help` | — |

`bin/` holds thin wrappers so the tools work from any directory:

| Wrapper | For |
|---|---|
| `bin/cloudsting` | The launcher, resolvable through a symlink on `PATH` |
| `bin/cloudsting-gui` | The GTK4 window, with the root exported before it starts |
| `bin/cloudsting-tui` | A terminal view: module list, per-module run, live output |

### The shared core

Every module sources `data/lib/core.sh`. It owns the paths, the run id, the TSV
writer, the three-state provider gate, redaction, the selftest ledger and the exit
trap — the things twenty-three modules used to each carry their own copy of, and
drift on.

```bash
MODULE_ID="24_snapshot_theft"
source "$(dirname "${BASH_SOURCE[0]}")/../data/lib/core.sh"
```

What it guarantees:

* **Loot lives under the project**, never under `$HOME`. `$CS_LOOT/<slug with the
  number stripped>`. A run under `pkexec` writes to the same tree as a run by the
  operator.
* **One TSV writer.** `cs_row KEY VALUE…` escapes tabs, CRs and newlines out of
  every field, so a value can never shift a later column.
* **One three-state gate.** `cs_provider_state aws` returns `tool-missing`,
  `creds-missing` or `creds-present` — never a fourth state, never a boolean.
* **One selftest ledger.** `chk name got want` plus `cs_selftest_done`, which
  prints the `RESULT\tPASS(n)` line every caller already parses.

The recurring bug classes are designed out rather than remembered: tab is IFS
whitespace so `IFS=$'\t' read -r a b c` collapses empty fields and shifts every
later column — `cs_split` splits on a sentinel instead. `grep '\t'` matches a
literal `t`; `awk -F'\t'` does not.

### The GUI

```bash
cd native
meson setup build
ninja -C build
./build/cloudsting
```

`meson` and `ninja` are only needed for the GUI. The modules are plain bash and
run without them.

**Module output streams.** A verb's stdout and stderr are piped line by line into
the page as they arrive — stderr prefixed and coloured — instead of appearing in
one dump when the process exits. The status bar beside the pane counts lines while
it runs and ends on `done · exit 0 · 412 ms`.

**The session panel reads the launcher.** It calls `cloudsting.sh session --tsv`,
so the account, region, identity, per-provider state and last inventory are the
same values the CLI reports. A provider that is missing reads `tool-missing` — the
panel says `no tool` rather than inventing an empty string.

**Module metadata comes from the registry.** `native/src/main1.c` carries no
module list; it loads `cloudsting registry --tsv` at startup and maps category to
icon. Adding module 24 is a registry row, not a C edit.

### Dependencies

**Required:** `bash` 4.2+, `curl`, `jq`, `python3`, `openssl`, `git`.

```bash
# Debian / Ubuntu
sudo apt install bash curl jq python3 openssl git

# Arch
sudo pacman -S bash curl jq python3 openssl git
```

**Optional, used by specific modules:** the provider CLIs (`aws`, `gcloud`, `az`,
`doctl`, `oci`), the Kubernetes set (`kubectl`, `helm`), container tooling
(`docker`, `podman`, `trivy`), API and exploit tools (`nuclei`, `ffuf`, `httpie`,
`grpcurl`, `kiterunner`, `arjun`), audits (`scoutsuite`, `prowler`,
`kube-hunter`, `peirates`) and secret scanners (`trufflehog`, `gitleaks`).

`00_deps` reports what is present and what is missing, and distinguishes a tool
that is installed from a cloud that is actually authenticated:

```bash
./modules/00_deps.sh --status-tsv     # tool status, one row per tool
./modules/00_deps.sh --preflight      # one page: everything a first run needs
./modules/00_deps.sh --install-missing
```

| Verb | What it does |
|---|---|
| `--status-tsv` | One row per tool: `name`, `state`, `version` |
| `--preflight` | One page: build tools, cloud CLIs, authenticated providers, regions |
| `--distro-info` | Detected distribution and package manager |
| `install <package>` | Install one package through the detected package manager (pkexec) |
| `--install-missing` | Install every missing critical tool |
| `--install-all` | Install missing critical tools plus the optional set |
| `--install-pipx`, `--install-git` | Install one tool from its upstream source |

---

## Playbooks

A playbook is a pipeline: an ordered list of modules where each step's rows are
handed to the next step on stdin, and every artifact lands under one run
directory. The point is that a recon sweep produces **one record** instead of
five unrelated files.

```bash
./cloudsting.sh playbook                      # list the playbooks
./cloudsting.sh playbook recon-only           # run one
./cloudsting.sh loot playbooks                # its artifacts, newest first
```

| Playbook | Steps |
|---|---|
| `recon-only` | inventory → buckets → DNS → VPC |
| `identity` | credential validate → IAM privesc → role chains → policy audit |
| `storage` | inventory → buckets → user-data → secrets |
| `imds` | SSRF probe → IMDSv2 bypass → user-data |
| `container` | container escape → registry recon → k8s surface → k8s secrets |
| `api-surface` | serverless → registry → DNS |
| `full-desk` | everything, in dependency order |

Format, in `data/playbooks/*.play`:

```
#desc: Storage exposure end to end
set TARGET=example.com
module 02_inventory
module 03_bucket_enum --sweep
stop-on-fail
module 16_kubernetes
```

`set` defines a variable for every later step, `stop-on-fail` ends the playbook
on a non-zero exit (`continue` is the default), and each step's stdout is written
to `loot/playbooks/<run-id>/<n>-<slug>.tsv` with its stderr beside it as `.err`.

## The findings store

Every module speaks TSV for one reader: the operator watching a terminal. A
sweep needs a second reader — something that can answer *what is actually wrong,
worst first*, across modules.

```bash
./cloudsting.sh findings ingest 03 loot/bucket_enum/result-*.tsv example.com
./cloudsting.sh findings top 20
./cloudsting.sh findings stats
./cloudsting.sh findings correlate
```

The store is one append-only TSV at `loot/findings.tsv`:

```
ts  module  category  severity  target  check  detail  evidence
```

**Severity is assigned by rule, not by the module that emitted the row.**
`data/findings.map` holds ordered glob rules — `<module> <key> <value>
<severity>`, first match wins — so a public bucket is critical because it is a
public bucket, whether module 03 or module 02 surfaced it. A row the module
already graded (`CRIT…`, `HIGH…`, `WARN…`) keeps that grade. A value that reads
`none`, `not found` or `tool-missing` is recorded as `clean`, not as a finding —
absence of a control that works is not the same fact as a control that failed,
and the store keeps them apart.

`correlate` is the reason the schema exists: it groups rows by
`target` + `check` and reports only those reported by more than one module. A
public bucket, a wildcard role trust and a disabled audit trail on the same
account become one incident with three witnesses.

Ingest skips what is not a row — a module's help banner, an indented `--flag
description` line — so a playbook artifact with a header in it is safe to feed.

---

### The interface

The GUI opens on a **Dashboard** — every module as a card, grouped by the
category the module declares. Click a card and the module opens in its own tab.
Three tabs are permanent: **Dashboard**, **Loot** and **Help**. The module drawer
on the left lists every module by category; `Ctrl+T` opens a raw terminal inside
the app.

![module page](assets/screenshot-module.png)

A module tab has its own submenu of pages, and **every verb the module documents
has a control on one of them**:

| Page kind | What it holds |
|---|---|
| **Overview** | Module identity, the script path, live `--status-tsv`, and a self-test button |
| **Action pages** | The module's verbs as cards, grouped by what they do — Probe / Sweep / Reference, Discover / Trace, Enumerate / Function |
| **Output** | Each action page owns its own output pane, colourised by severity |

Verbs are never rendered as CLI text: a button says what the job is ("Guess
buckets for a domain"), and the field next to it says what it wants
(`example.com`, `bucket-name`, `namespace secret`). Verbs that need root are
marked and run through `pkexec`, so the password prompt happens per action rather
than once at startup.

The bottom dock is **Events / Log**: every command, its start, its exit state and
a filter by severity.

---

## Modules

Twenty-four modules, grouped by the categories the application itself uses, so
this list and the Dashboard cannot drift apart.

### System

| Module | Description | Selftest |
|---|---|---|
| `00_deps` | Dependency manager: what is installed, what is missing, what is authenticated | 41 checks |

### Credentials and inventory

| Module | Description | Selftest |
|---|---|---|
| `01_cred_validate` | Detect a credential's provider from its shape, validate the format offline, then probe it live where that is possible | 19 checks |
| `02_inventory` | Enumerate reachable assets per provider, three-state per provider | 11 checks |

### Module inventory

Thirty-one modules, grouped by what job they do. Every module ships
standalone, carries its own `--selftest`, and writes TSV.

#### Setup

| Module | Description | Selftest |
|---|---|---|
| `00_deps` | What this box has, what it is missing, and what is actually authenticated | 41 checks |

#### Credentials

| Module | Description | Selftest |
|---|---|---|
| `01_cred_validate` | Identify a credential from its shape, validate it offline, probe it live — cloud keys and 23 telco vendor auth oracles | 19 checks |
| `08_secrets_scan` | Key and token patterns in files, directories and streams | 12 checks |

#### Surface

| Module | Description | Selftest |
|---|---|---|
| `02_inventory` | Enumerate what the account actually holds across providers | 11 checks |
| `41_api_discovery` | Endpoints on a host or a spec, with a baseline so a catch-all page yields nothing | 35 checks |
| `46_key_harvest` | Key and token patterns in pages, script bundles, headers and specs | 31 checks |
| `76_debug_endpoints` | Health, actuator, docs and env endpoints that answer when they should not | 34 checks |

#### Storage

| Module | Description | Selftest |
|---|---|---|
| `03_bucket_enum` | Storage buckets, their permissions, and their public exposure | 11 checks |
| `14_registry_recon` | Registries, repositories, tags, and image layers worth pulling apart | 8 checks |
| `21_db_exposure` | Managed database instances and which of them answer from the world | 34 checks |

#### DNS

| Module | Description | Selftest |
|---|---|---|
| `27_rebinding` | A name that resolves twice — the validator reads the name, the fetcher talks to the address | 58 checks |
| `39_tenant_enum` | Tenant ids, bucket namespaces, exposed APIs, certificate transparency and PTR sweeps | 27 checks |

#### Identity

| Module | Description | Selftest |
|---|---|---|
| `04_pivot` | Assume a foreign role and measure what the credential returns | 39 checks |
| `05_iam_privesc` | Known escalation paths out of the current principal | 11 checks |
| `06_role_chains` | Role trust policies and the chains they permit | 7 checks |
| `07_policy_audit` | Wildcard actions, wildcard resources, missing conditions | 12 checks |
| `10_snapshot` | Shared snapshots, public images, and what a stolen disk gives up | 44 checks |
| `23_persistence` | Footholds that outlive the session, per provider | 23 checks |

#### Compute

| Module | Description | Selftest |
|---|---|---|
| `09_imds` | SSRF to IMDSv1, IMDSv2 bypass, user-data, and the credentials in them | 22 checks |
| `12_serverless` | List, dump env, find invoke URLs, pull the code | 16 checks |
| `15_container_escape` | Capabilities, mounts, cgroups and host namespace reachability | 9 checks |
| `16_kubernetes` | Clusters, RBAC, who can do what, and the secrets behind it | 13 checks |

#### Network

| Module | Description | Selftest |
|---|---|---|
| `18_network` | DNS, dangling records and claimable subdomains, subnets, routes and firewall exposure | 37 checks |

#### Attrition

| Module | Description | Selftest |
|---|---|---|
| `22_audit_evasion` | What the provider records, and where the trail has holes | 27 checks |

#### Web API

| Module | Description | Selftest |
|---|---|---|
| `42_openapi` | Reads a spec and reports what it admits to: per-operation security, ids, url-taking params | 42 checks |
| `43_graphql` | Probes graph paths and reads a schema the server never meant to hand out | 52 checks |
| `44_jwt` | Alg:none, key confusion, kid injection and offline cracking against a token | 58 checks |
| `45_oauth` | Redirect_uri, state, PKCE, scope and prompt — every gate the flow passes | 69 checks |
| `48_bola` | Object-level authorization across subscriber, account and sim ids | 48 checks |
| `49_bfla` | Function-level authorization across admin, agent and customer verbs | 48 checks |
| `50_mass_assign` | Fields the server trusts because the client sent them | 46 checks |
| `51_hpp` | One parameter, two meanings — the duplicate, array and encoding shapes a parser folds | 54 checks |
| `52_rate_limit` | Forwarding-header rotation against a limit that trusts the header | 48 checks |
| `53_injection` | A value the interpreter reads as code — SQL, NoSQL, command, template, LDAP and XPath | 64 checks |
| `54_ssrf` | Makes a server fetch metadata, loopback or a local file, and proves it by content | 43 checks |
| `56_grpc` | Reflection, method auth and field confusion — speaks the protobuf framing itself | 69 checks |
| `57_websocket` | Handshake auth, per-message auth and CSWSH — the origin check is the whole guard | 56 checks |
| `59_smuggling` | The front end and the back end disagree about how much of the stream is this request | 45 checks |
| `61_cors` | Origin reflection, null origin and regex bypass — with the cookie riding along | 52 checks |
| `63_pagination` | A list endpoint that will hand over the table — measured, not assumed | 55 checks |
| `60_resp_smuggle` | A second response spliced into the first — and a cache willing to serve it | 45 checks |
| `58_sse` | A stream nobody authenticated, judged per event | 56 checks |
| `68_graphql_dos` | Depth, aliases, batching and fragments — the curve between a cheap query and a ruinous one | 55 checks |
| `62_version_bypass` | The old version answers while the new one is locked | 38 checks |
| `64_file_upload` | Walks the extension and content-type matrix an upload filter forgets | 53 checks |
| `65_deserialization` | The object the server rebuilt — a payload that is a data structure, not a string | 55 checks |
| `66_webhook_sig` | The signature nobody checked — the control runs first, so `checked` means something | 47 checks |
| `67_token_refresh` | The token that outlives the logout — rotation, replay and revocation, measured | 51 checks |
| `78_replay_nonce` | The request that still works the second time — check-then-act and the missing nonce store | 37 checks |
| `69_bfuzz` | The value the schema forbids — what the protobuf decoder accepts, the handler believes | 45 checks |
| `70_spec_diff` | What changed between two specs, and which change added a door nobody locked | 44 checks |
| `71_logic` | The rule nobody wrote down — a valid request in the wrong order, and the arithmetic that follows it | 37 checks |
| `72_race` | Two requests that each pass a check neither should — the window is the bug | 34 checks |
| `74_llm` | The model box is an API with a budget — prompt lease, instruction channel and an open proxy | 53 checks |
| `75_rotation` | The credential that outlives its own rotation — a promise tested from the outside | 56 checks |
| `77_mobile` | The client version is an authorization input, and the app is the only client it expected | 42 checks |

### Verb reference

Each module's own `--help` is the authority; this is the map.

```
00_deps              --distro-info --install-all --install-git --install-missing --install-pipx
                     --preflight --selftest --status-tsv
01_cred_validate     --defaults --detect --detect-vendor --help --list-formats --login --menu
                     --selftest --status-tsv --sweep --validate --vendors
02_inventory         --help --menu --regions --run --selftest --status-tsv
03_bucket_enum       --domain --enum --menu --perm --selftest --status-tsv
04_pivot             --assume --enumerate --escalate --help --list --menu --probe
                     --providers --selftest --status-tsv --techniques --trust
10_snapshot          --data --help --images --list --menu --probe --public
                     --selftest --share --snapshots --status-tsv --techniques
05_iam_privesc       --check --explain --help --list --map --menu --selftest --status-tsv
06_role_chains       --chain --help --list --menu --scan --selftest --status-tsv --whoami
07_policy_audit      --audit --check --explain --help --list --menu --selftest --status-tsv
08_secrets_scan      --detect --help --list --menu --scan --selftest --status-tsv
09_imds              --all --check --creds --endpoints --exec --help --keys --list --menu
                     --probe --selftest --status-tsv --techniques --token --userdata
12_serverless        --all --download --download-all --dump --env --help --invoke --list --menu
                     --selftest --status-tsv --urls
14_registry_recon    --dhl --help --images --list --menu --pull --scan --selftest --status-tsv
                     --tags
15_container_escape  --all --cap --cgroup --check --help --host --list --menu --mounts --proc
                     --selftest --status-tsv
16_kubernetes        --abuse --all --clusters --decode --extract --help --kubeconfig --list
                     --menu --nodes --pods --rbac --sa-tokens --secrets --selftest --status-tsv
18_network           --all --audit --axfr --claim --dangling --fingerprints --gateways --help
                     --list --map --menu --records --resolve --routes --rules --selftest
                     --status-tsv --subnets --takeover --vpcs --zones
21_db_exposure       --engines --help --instances --menu --probe --public --selftest
                     --status-tsv
22_audit_evasion     --blind --explain --help --list --menu --posture --selftest --status-tsv
23_persistence       --explain --footholds --help --list --menu --selftest --status-tsv
27_rebinding         --addresses --api --check --help --hosts --list --menu --metadata --pin
                     --profiles --rebind --responder --selftest --status-tsv --targets --ttl
39_tenant_enum       --all --apis --azure --buckets --crt --help --menu --projects --ptr
                     --selftest --status-tsv --tenant
41_api_discovery     --all --discover --help --menu --methods --selftest --spec --status-tsv
                     --wordlist
42_openapi           --analyze --auth --diff --endpoints --find --help --list --menu --params
                     --selftest --spec --status-tsv
43_graphql           --check --depth --fields --find --help --introspect --list --menu --queries
                     --schema --selftest --status-tsv
44_jwt               --alg --check --claims --crack --forge --help --inspect --jku --keys --kid
                     --list --menu --selftest --status-tsv
45_oauth             --check --cursor --discover --help --implicit --list --login-hint --menu
                     --paths --pkce --redirect --redirects --scope --selftest --state
                     --status-tsv --tests
46_key_harvest       --all --defang --detect --harvest --headers --help --js --menu --providers
                     --selftest --status-tsv
48_bola              --check --enumerate --help --idlist --list --matrix --menu --patterns
                     --selftest --status-tsv --sweep
49_bfla              --check --compare --functions --help --list --menu --methods --object
                     --selftest --status-tsv --sweep
50_mass_assign       --check --fields --help --list --menu --selftest --shadow --status-tsv
                     --sweep --verdicts
51_hpp               --array --check --dup --encoding --help --json --list --menu --params
                     --query --selftest --smuggle --split --status-tsv
52_rate_limit        --check --headers --help --list --menu --modes --probe --rotate --selftest
                     --status-tsv
53_injection         --check --cmdi --families --help --ldap --list --menu --nosqli --params
                     --payloads --selftest --sqli --ssti --status-tsv --xpath
54_ssrf              --callback --check --help --list --menu --params --parse --probe --save
                     --selftest --status-tsv --sweep --targets --vendors
56_grpc              --auth --codes --describe --discover --fuzz --grpc-status --help --list
                     --menu --payloads --port-scan --proto --reflect --selftest --services --status-tsv
57_websocket         --auth --cswsh --discover --frames --fuzz --handshake --help --list --messages
                     --menu --origins --paths --payloads --selftest --status-tsv
59_smuggling         --clcl --clte --desync --downgrade --framing --h2cl --h2te --help --list
                     --menu --probe --selftest --status-tsv --te --teobfusc --techniques
61_cors              --check --creds --headers --help --list --menu --methods --null --origins
                     --poc --regex --selftest --status-tsv --suffix
62_version_bypass    --compare --headers --help --list --matrix --menu --normalise --probe
                     --selftest --status-tsv --sweep --versions
64_file_upload       --check --endpoints --extensions --help --list --magic --menu --name
                     --polyglot --probe --selftest --status-tsv --sweep --types
63_pagination       --cursor --help --inject --limits --list --menu --params
                    --probe --selftest --status-tsv --verdicts --walk
65_deserialization  --check --detect --formats --gadgets --help --list --markers
                    --menu --payloads --probe --scan --selftest --status-tsv
66_webhook_sig      --check --confusion --help --list --menu --probe --replay
                    --schemes --selftest --status-tsv --vectors --window
67_token_refresh    --fixation --grants --help --list --menu --probe --replay
                    --revoke --rotate --scopes --selftest --status-tsv
                    --vectors --verdicts --window
78_replay_nonce     --check --help --idempotency --list --menu --nonce --probe
                    --replay --selftest --status-tsv --timestamp --vectors
69_bfuzz            --any --detect --fuzz --help --list --menu --packed --probe
                    --selftest --status-tsv --techniques --truncate --varint --wire
70_spec_diff        --auth --classes --deprecated --diff --help --list --menu --new
                    --params --selftest --snapshot --status-tsv
71_logic            --discount --help --list --menu --price --probe --quantity
                    --selftest --sequence --status-tsv --techniques --trial
72_race             --coupon --double-spend --fire --gate --help --limit --list
                    --menu --probe --selftest --status-tsv --techniques
74_llm              --cost --help --inject --keys --lease --lease-scan --list
                    --menu --probe --selftest --status-tsv --techniques --tools
75_rotation         --grace --help --leak-check --list --menu --old-key --policy
                    --probe --selftest --status-tsv --techniques --windows
77_mobile           --cert --config --deep --help --list --menu --probe --selftest
                    --static --status-tsv --techniques --versions
60_resp_smuggle     --cache --headers --help --leak --list --menu --params
                    --probe --reflect --selftest --split --status-tsv --vectors
58_sse              --auth --cors --events --help --inject --list --menu --paths
                    --probe --sample --selftest --status-tsv
68_graphql_dos       --aliases --batched --cost --depth --directive --fragment --help --list
                     --menu --mutate --probe --rungs --selftest --status-tsv --techniques
76_debug_endpoints   --actuator --all --check --docs --env --health --help --list --menu --scan
                     --selftest --status-tsv

### Not built yet

The long tail is still open, but the campaign modules that matter land first.
Built so far spans setup, credentials, surface, storage, DNS, identity, compute,
network, attrition and the first eleven of the web-API family.

| Range | Planned |
|---|---|
| 24–34 | Cross-account trust, snapshot theft, event/webhook abuse, metadata DNS rebinding, CI/CD attack, WAF bypass, edge exploitation, vault extraction, provider API fuzzing, mail abuse, console hijack |
| 35–45 | Fleet sync, cryptojacking, backup ransom, cloud AD, canary hunting, auth bypass, HPP, injection, webhook abuse, gRPC, WebSocket |
| 51–61 | Request smuggling, response leaks, CORS, pagination abuse, deserialization, webhook signatures, session and refresh abuse, GraphQL DoS, binary fuzzing, spec diffing, business logic |
| 63–84 | Race conditions, API DNS rebinding, LLM endpoints, key rotation, mobile backends, replay, gateway recon, IAM-derived API keys, event injection, log injection, token forging |

---

### How to audit it yourself

```bash
# every module, offline, one summary line
./cloudsting.sh selftest

# the raw loop, if you want per-module lines
for m in modules/*.sh; do printf '%-32s ' "$m"; bash "$m" --selftest | tail -1; done

# what each module thinks its own state is
for m in modules/*.sh; do bash "$m" --status-tsv; done

# what the box can actually reach
./modules/00_deps.sh --preflight
```

---

## How it is put together

The GUI is a view over the scripts in `modules/`. Nothing is locked behind it:

```bash
./modules/03_bucket_enum.sh --domain example.com
./modules/05_iam_privesc.sh --explain PassRole
./modules/16_kubernetes.sh --secrets
```

Each module is a self-locating script: it resolves its own path, so it runs from
any directory and from any symlink, and it never depends on the caller's
environment. The modules whose selftest has to reach a parser directly are safe to
`source`: `CLOUDSTING_SOURCE_ONLY=1` makes the file define its functions and
return before dispatching, which is how those selftests test the parser instead
of the dispatch path.

A module is a small state machine with the same shape everywhere:

```
lib header      MODULE_ID + source data/lib/core.sh (paths, run id, TSV writer)
knowledge base  the tables the module reasons over (techniques, signatures, endpoints)
collectors      one function per provider or per check, each emitting rows
verbs           --run / --check / --probe / --scan / --map, each honest about absence
selftest        chk() assertions against shims and fixtures
dispatch        --status-tsv, --menu, --selftest, --help
```

### Conventions
Read TSV with `awk -F'\t'`, never `grep '\t'`: POSIX grep treats `\t` as a
literal `t`, so `grep -c '^aws\tec2'` silently matches nothing. And because tab
is an IFS whitespace character, `IFS=$'\t' read -r a b c` collapses runs of
empty fields — emit an explicit `-` placeholder for "no value" and normalise it
after reading, or every row with a hole in it shifts.

Every module follows the same contract, and the rules exist because ignoring them
produced a real bug at least once:

- **TSV out on stdout, one row per finding.** Diagnostics go to stderr, so a
  pipeline stays clean.
- **Three states, never collapsed.** `tool-missing` (no CLI on this box),
  `creds-missing` (CLI present, no credentials), `creds-present` (both). A module
  with no AWS CLI does not report "no buckets" — it reports that it could not
  look.
- **Distinct exit codes:** `0` success, `1` refused or nothing found, `2` usage.
- **`chk()`-based selftests with known answers**, not self-consistent ones: the
  expectation is written next to the assertion, and a parser that changes shape
  fails the test.
- **`awk -F'\t'` for row assertions, never `grep '\t'`.** POSIX grep treats `\t`
  as the letter `t`, which silently matched nothing and cost a day of debugging
  in module 02.
- **No approval gates and no armed variables.** A module either has what it needs
  or it says what it is missing.
- **No module hardcodes a path.** `data/lib/core.sh` sets `$CS_LOOT`,
  `$CS_STATE_DIR`, `$CS_TMP_DIR` and `$CS_RUN_ID` from the file's own location, so
  the same module writes the same tree whether it ran from the launcher, the GUI,
  `pkexec` or a cron job.

---

## Directories

The toolkit creates `tmp/`, `loot/` and `state/` on first run. Nothing needs to
pre-exist.

**`loot/` is where results land** — one subdirectory per module, one run-record
per invocation:

```
loot/cred_validate/     result-<run>.tsv, raw.last (mode 600)
loot/bucket_enum/       result-<run>.tsv, perm-<run>.tsv
loot/takeover/          result-<run>.tsv
loot/iam_privesc/       result-<run>.tsv
loot/k8s_secrets/       ...
```

Everything in `loot/` came off a target and is **not redacted**. Credential
modules record a SHA-1 prefix rather than the secret itself, but the raw value is
in `raw.last` when a module had to hold it. Treat a copy of `loot/` the way you
would treat the credential it came from. Do not commit it, sync it, or email it.

**`state/` is what the GUI remembers** — window geometry, favourites, recent
modules, open tabs, and each module's own working data (`state/inventory.json`,
`state/bucket_words.cache`, …). Delete a file and that preference resets to its
default; the toolkit writes it again on the next change.

**`data/` holds reference data** the modules reason over. It is text, versioned,
and small enough to diff:

| File | Holds |
|---|---|
| `data/registry.tsv` | The module registry — id, slug, title, category, mission, verbs, selftest count, phase. The GUI loads this; it is the only module list. |
| `data/lib/core.sh` | The shared core every module sources. |
| `data/findings.map` | Severity rules: `<module> <key> <value> <severity>`, first match wins. |
| `data/playbooks/*.play` | Pipelines: an ordered module list with `set` variables and a failure policy. |

Two more live under `loot/` because they are output, not reference:
`loot/findings.tsv` (the findings store) and
`loot/playbooks/<run-id>/` (one directory per playbook run, one file per step).

---

## Troubleshooting

**"The module says OK but nothing happened."**
The failure worth reporting. Say which module, which verb, what you expected, and
what the target actually did.

**"It reports `creds-missing` for a provider I am logged into."**
Check what the module looks for: `~/.aws/credentials` or `AWS_ACCESS_KEY_ID` for
AWS, `gcloud auth list` for GCP, `~/.azure/azureProfile.json` for Azure,
`doctl auth list` for DigitalOcean. `cs_provider_state` in `data/lib/core.sh` is
the one implementation of that check — if it says `tool-missing`, the CLI is not
on `PATH` for this process, which under `pkexec` means a different `PATH` than
your shell's. `./cloudsting.sh session --summary` prints what each provider
reports, and `./modules/00_deps.sh --preflight` prints what the box can reach.

**"The GUI window is empty."**
It loaded no modules. It reads `cloudsting registry --tsv`; run that by hand. If
it prints rows and the window is still empty, the launcher is not executable from
where the GUI thinks the root is — `bin/cloudsting-gui` exports
`CLOUDSTING_ROOT` before launching for exactly that reason.

**"A module's output appears all at once at the end."**
It should not, for a verb run from a page: output streams line by line. A module
that buffers its own stdout (a `python3 -c` block without `-u`, a command piped
through `sort`) will still arrive in chunks — the streaming reader shows what the
process actually writes.

**A selftest fails after a change.**
Run it before anything else:

```bash
./modules/03_bucket_enum.sh --selftest
```

The checks name what broke. If a check fails only when the module is run as a
script but passes when sourced, the bug is in the dispatch, not the parser.

**The GUI shows a module as "not registered".**
That module has a script but no entry in the GUI's module table. The page says so
instead of showing an empty tab.

---

## Contributing

One module per concern, in `modules/NN_name.sh`, following the contract above: a
`--selftest` with known answers, three-state provider reporting, TSV out, and a
`--status-tsv` that tells the truth about what the module could not see.

Two rules above the rest: **a module must never report success it did not
achieve,** and **a verb that exists must have a control on the module's page.**

## Credits

Modelled on the shape of [wifisting](https://github.com/yslxotwod/wifisting) and
[IMSIsting](https://github.com/yslxotwod/IMSIsting): same module contract, same
honesty rules, same dashboard-as-a-view-of-the-scripts design.

Built with GTK4 and VTE.
