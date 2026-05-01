# Why Statebound

The long version of the README, for people who would like to know why
this exists before they `git clone` it.

## The actual day-to-day pain

You are a Platform Engineer at a regulated company. Authorization for
production currently lives in:

- A Confluence page nobody trusts (last edited "by Greg").
- A spreadsheet that is the actual source of truth (column AC is
  highlighted yellow because of "an incident in 2023").
- A folder of email threads with the subject prefix "RE: RE: RE:".
- A directory of `sudoers.d` snippets in a Git repo, but only the
  ones somebody remembered to commit.
- An IdP whose group memberships drifted from the spreadsheet on day
  three of the spreadsheet's existence.

Your auditor lands on Tuesday and wants to know:

1. **What access should exist?** ("Show me the source of truth.")
2. **Who approved it?** ("Show me the approval, not the Slack
   thread.")
3. **What changed?** ("Diff Q3 vs Q2.")
4. **What access exists in reality?** ("Now show me the host.")
5. **Where is the drift?** ("Why is `db-ops` in the actual sudoers
   list but not in your spreadsheet?")
6. **What evidence can we give for the entire quarter?** ("Hand me a
   PDF, please.")

You currently answer (1)–(6) by spending three weeks of a Platform
Engineer's time generating screenshots, writing a Confluence summary,
and praying.

## What Statebound replaces

Statebound is what you'd get if you took the parts of `terraform` that
work (versioned desired state, plans, approvals, drift detection) and
applied them to the access-governance problem instead of the
infrastructure-provisioning problem.

You write what access should exist as YAML:

```yaml
entitlements:
  - name: payments-prod-readonly
    owner: payments-team
    purpose: Read-only production troubleshooting
    authorizations:
      - type: linux.sudo
        scope: prod-linux
        asUser: root
        commands:
          allow:
            - /usr/bin/systemctl status payments
            - /usr/bin/journalctl -u payments --since today
```

You commit it as a ChangeSet. OPA evaluates it. A second human approves
it. The result is an immutable `ApprovedVersion` with a content hash.
Plans for connectors (sudoers fragments, Postgres GRANTs) come out of
that approved version deterministically — same inputs, same bytes,
same SHA-256. Drift scans compare the approved version to what's
actually on the host. Evidence packs render the whole story (approval,
diff, policy verdict, audit chain, drift findings) as Markdown the
auditor can actually read.

Every state transition is in a hash-chained audit log. `statebound
audit verify` walks it.

## How is this different from what we already have?

| Concern                               | Statebound | IGA (Saviynt, SailPoint…) | PAM (CyberArk, Teleport…) | Plain OPA | Spreadsheet |
|---------------------------------------|:----------:|:-------------------------:|:-------------------------:|:---------:|:-----------:|
| Versioned desired-state YAML          |     ✓      |          partial           |             —             |     —     |  sort of   |
| Four-eyes approval, audit-trailed     |     ✓      |            ✓               |          partial          |     —     |     ✗      |
| Diff between versions                 |     ✓      |          partial           |             —             |     —     |     ✗      |
| Drift detection vs target system      |     ✓      |          partial           |             ✓             |     —     |     ✗      |
| Evidence packs (deterministic, hashed)|     ✓      |          exports           |          partial          |     —     |     ✗      |
| Policy-as-code at submit + approve    |     ✓      |             —              |             —             |     ✓     |     ✗      |
| Apply gated by signature verification |     ✓      |             —              |          partial          |     —     |     ✗      |
| Self-governs its own AI assist        |     ✓      |             —              |             —             |     —     |     ✗      |
| Open source, runs on your laptop      |     ✓      |             ✗              |          varies           |     ✓     |     ✓      |

The honest summary: **IGA tools own identity lifecycle**
(joiners/leavers/access reviews) and Statebound does not. **PAM tools
own credential vaulting and session brokering** and Statebound does
not. **OPA owns policy evaluation** and Statebound uses it. What
Statebound owns is the *authorization governance layer* — the
spreadsheet replacement — that sits between all of those and the
auditor.

You probably still have an IGA. Statebound is the thing that
makes its outputs reviewable, diff-able, and auditable on the
sudoers and Postgres-grant level your IGA does not reach.

## What Statebound is not

- **Not an IGA replacement.** No joiner/leaver workflows, no
  access certification campaigns, no quarterly review automation.
  v1.0 has none of that.
- **Not a PAM replacement.** Statebound does not vault credentials,
  broker sessions, record terminals, or rotate keys. The Postgres
  connector executes SQL using a DSN you provide; the Linux sudo
  connector emits sudoers fragments you deploy yourself.
- **Not a CMDB.** Statebound does not discover assets. You declare
  them in YAML.
- **Not a SIEM.** Statebound emits structured audit events and OTel
  spans; ship them to your existing SIEM.
- **Not a magic AI thing that reads your `/etc/sudoers` and tells
  you what's wrong.** The optional reasoning add-on
  (`statebound-reason`) can *propose* drafts from a pattern library,
  but humans and OPA decide. Hard line.

## Who this is for

- **Platform Engineers** at regulated companies who currently maintain
  the spreadsheet by hand. Statebound was designed for them first.
- **Auditors and compliance partners** who need exportable, hashed,
  reproducible evidence rather than screenshots.
- **Security architects** who need a defensible model for their
  authorization governance layer, including AI assist.
- **IAM Engineers** managing service accounts and machine identities
  that the IGA's "human-friendly" UI doesn't model well.

## Who this is not for

- Teams whose entire access surface is "AWS IAM in one account, Okta
  for the SaaS apps, no on-host access". Statebound is overkill.
- Teams without a Postgres in their stack. (You technically can run
  it on SQLite-by-way-of-pgx, but nobody would.)
- Teams who want a hosted SaaS. v1.0 is open source, runs on your own
  Postgres, and does not phone home.

## What's interesting architecturally

Three properties that are not on most competitors' shelves:

1. **The audit log is tamper-evident at the database level.** Every
   row's hash is `SHA256(prev_hash || canonical_json(event))`,
   computed by the SQL function `audit_event_hash()`. There is no
   "trust the application" assumption — `statebound audit verify`
   walks the chain and reports the first mismatch.

2. **Evidence packs are byte-deterministic.** Two calls to
   `statebound evidence export --version <seq>` against the same
   approved version produce byte-identical bytes and the same
   SHA-256. You can hand an auditor a hash today and re-prove the
   pack tomorrow.

3. **Agents are governed by the same primitives they observe.**
   Every AI agent in the optional add-on is a registered
   ServiceAccount with a versioned, approved entitlement scope. Adding
   an agent is itself a ChangeSet. The audit log records every
   invocation with prompt hash + input hash + output hash + tool-call
   trace. You can ask the Auditor agent "list every action any agent
   took in Q3" and get deterministic data, not vibes.

The third property is, as far as we can tell, unique in the space.
Most products that ship AI assist do not subject their AI to the same
governance rigor they sell to customers.

## Status

- **Core (`statebound`):** v1.0 — feature-complete.
- **Reasoning add-on (`statebound-reason`):** R-track begins now that
  core v1.0 has shipped. Phases R1–R5 cover Modeler → Drift Analyst
  → Reviewer → Auditor + Evidence Narrator + Policy Author →
  hardening.
- **Trademark:** "Statebound" is the working name pending formal
  attorney clearance. Do not use it on anything public-facing
  (domain, social handle, README of a public-facing repo) until
  cleared.

## Where to next

- [`README.md`](../README.md) — the short version with the
  60-second quickstart.
- [`docs/architecture.md`](architecture.md) — three planes, two
  deployment shapes.
- [`docs/golden-path.md`](golden-path.md) — full eight-step demo.
- [`docs/roadmap.md`](roadmap.md) — what's next, including the R-track.
