# Roadmap

What is not built yet, and why each item is worth building. Numbers are slots,
not identities — the slug names the attack.

## Slots still free

`17` `19` `20` `29` `30` `31` `32` `33` `34` `35` `36` `37` `38` `40` `55`
`79` `80` `81` `82` `83` `84`

Four of these hold attack content from the original plan; the rest either reuse
a merged-away number or were never assigned.

## Planned attacks — still to build

| Good slot | Attack | Why it is its own module |
|---|---|---|
| 29 | Cloud WAF / API gateway bypass | The gateway is a different parser from the app behind it. Encoding, oversized headers, and rule-ID gaps are its own failure mode. |
| 30 | CDN / edge function | Edge workers hold secrets and run attacker-reachable code; the origin is only as protected as the edge's routing. |
| 31 | Vault / secrets manager | Where the credentials live. Lease abuse, path traversal in the API, and unauthenticated `sys/` endpoints. |
| 32 | Provider API fuzzing | The provider's own control plane takes attacker input through resource names, tags and metadata. |
| 33 | Mail / SES abuse | Sending reputation is an asset: identity verification gaps, sandbox escape, DMARC bypass. |
| 34 | Console hijack | The web console is a separate auth surface from the API, with its own session model. |
| 36 | Cost / cryptojacking | Spending the victim's budget is impact without a shell. |
| 37 | Backup / snapshot ransom | Delete-protection, retention locks, and whether the backup credential is separate from the data credential. |
| 38 | Directory / AD enumeration | The identity provider behind the cloud: Azure AD, Okta, LDAP. |
| 79 | Gateway + function URL recon | Cloud API Gateway routes and serverless function URLs are one enumeration with a `kind` column. Merged from 79+80. |
| 81 | IAM → API key extraction | The permission that lets one credential mint another. |
| 82 | Event injection | Overlaps `11_event_trigger`; keep only if it adds a distinct surface. |
| 84 | Token forge | Signing a token the platform will accept (SAML assertion, GCP service-account JWT, Azure token exchange). |

## New ideas — not from the original list

These came out of reading the code rather than the plan.

**`55` — Credential spray, lockout-aware.** `01` validates credentials you
already hold and `44` attacks JWT structure; nothing sprays low-and-slow
against a login endpoint with the control that actually matters: does attempt
N lock the account. For telco portals and M365 this is the most common real
path in, and it is missing entirely.

**Container image layer mining.** `14 --pull` is `docker pull` plus `inspect`
— the layers are never opened. A layer walker finds secrets baked into a
build: the container equivalent of `10_snapshot`, and a real gap.

**Object-level storage harvesting.** `03` lists buckets and permissions but
never asks what is *inside* or how much. "This bucket is public" and "this
bucket holds 4 TB of subscriber records" are different findings with
different severity.

**A TOOLING module.** The category is defined and empty. A toolkit that
assumes roles and forges requests needs its own signing helper — SigV4
reconstruction for arbitrary requests, kubeconfig builder, credential format
conversion. Not an attack, but every other module would use it.

## Flagged as advisory, not built

`35` fleet sync, `40` canary deployment, `83` log injection. These describe a
defender's controls rather than an attacker's move. They are worth having only
if they are built as posture checks (`22_audit_evasion --posture` is the
model) rather than as attacks.

## Known gaps in what exists

- `03_bucket_enum`, `05_iam_privesc`, `06_role_chains`, `07_policy_audit` are
  AWS-only. `21`, `22`, `23` already do multi-provider correctly and are the
  pattern to copy.
- `16_kubernetes` has essentially no direct kubelet `10250` or etcd probing.
- `55` (webhook/callback intercept) is covered by `54_ssrf --callback` — no
  separate module is coming, and the README should say so.
- `findings correlate` matches on target plus check name, and modules do not
  agree on check names, so it finds almost nothing. The category vocabulary is
  now enforced; check names are the next contract worth enforcing.
