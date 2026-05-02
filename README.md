# Statebound

[![CI](https://github.com/rupivbluegreen/statebound/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rupivbluegreen/statebound/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/rupivbluegreen/statebound)](https://github.com/rupivbluegreen/statebound/releases/latest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.25-00ADD8.svg)](go.mod)

> **Status: v1.0 — deterministic core feature-complete.** The product
> name "Statebound" is the working name pending trademark clearance —
> do not use in public-facing artifacts (per the rename ADR).

## What you have today

A spreadsheet of who can `sudo` to prod. A Slack thread that ends in
"lgtm 👍". An audit email subject line that begins with
"RE: RE: RE: Re: FW:". Nobody quite remembers who approved which
sudoers line in 2024 Q3, only that "Greg said it was fine, but Greg
left in October."

The auditor lands on Tuesday.

## What Statebound is

Statebound is what `terraform` would be if it governed authorization
instead of infrastructure. You write what access **should** exist in
YAML, two humans look at it, [OPA](https://www.openpolicyagent.org/)
looks at it, the resulting state is immutable, and you can ask the
binary to print an audit-ready Markdown report at any time.

It runs in your terminal, talks to a Postgres, and ships a small Helm
chart. The deterministic core is a complete product on its own; an
**optional** reasoning add-on (`statebound-reason`) adds bounded AI
assist that proposes drafts but never decides. (More on the
"never decides" part below.)

**Statebound is not** an IGA replacement, a PAM, or a generic IAM
portal. See [`docs/why-statebound.md`](docs/why-statebound.md) for the
long version, including how it compares to those.

## What's in the box (v1.0)

- **Authorization model** — Products, Assets, AssetScopes,
  Entitlements, ServiceAccounts, GlobalObjects, Authorizations. YAML
  in, validated, versioned.
- **ChangeSets + four-eyes approval** — diffable drafts, immutable
  approved versions, hash-chained audit log (the SQL function
  `audit_event_hash()` is the single source of truth, and
  `statebound audit verify` walks the chain).
- **OPA + Rego built-in rule library** — nine rules out of the box
  (wildcard sudo, root-equiv, prod-requires-approval, four-eyes,
  service-account / entitlement metadata, scope-nonempty,
  unapproved-apply, RBAC capability check), 41 unit tests, plus
  `statebound policy test/eval`.
- **Evidence engine** — deterministic JSON + auditor-friendly
  Markdown. Re-export the same approved version, get byte-identical
  bytes, get the same SHA-256.
- **Connectors** — Linux sudo, Linux SSH (plan-only), PostgreSQL
  (plan + collect + compare + apply with SQL DCL inside a
  transaction).
- **Drift detection** — `statebound drift scan` produces
  deterministic findings; the summary hash is reproducible.
- **Apply** — `statebound apply <plan> [--dry-run | --apply]`. Refuses
  unsigned plans. Refuses without an admin role. OPA re-evaluates at
  apply time.
- **RBAC** — five roles (viewer, requester, approver, operator,
  admin), bootstrap-once gate.
- **Ed25519-signed plan bundles** — keys are disable-able; signatures
  in the audit log; mandatory unless dev-mode is explicitly enabled.
- **OpenTelemetry tracing** — opt-in via env var, no PII by default.
- **HTTP API** — `statebound api serve` with OpenAPI 3.1 + OIDC
  bearer auth (or dev-token); 22 read-only endpoints. This is the
  surface the reasoning add-on calls into.
- **Distroless Docker image** (~55 MB, runs as nonroot) and Helm
  chart with NetworkPolicy, runAsNonRoot, secret-backed signing key.

## What an evidence pack looks like

`statebound evidence export --product payments-api --format markdown`
produces this (excerpt — full pack covers every audit event, every
policy decision, every drift scan):

```markdown
# Evidence Pack — payments-api v1

- Generated: 2026-05-01T12:52:00.565092Z
- Approved by: bob (human)
- Approved at: 2026-05-01T12:52:00.565092Z
- Snapshot hash: sha256:d913d5471a55
- Source change set: 3879c88f-8933-4a20-aabf-c5b7d4a45919

## Approvals
| Actor | Decision | Reason | Decided at |
|-------|----------|--------|------------|
| bob (human) | approved | — | 2026-05-01T12:52:00.572101Z |

## Policy decisions

### approve — escalate_required
- Bundle hash: sha256:7f339e4afdae

| Rule | Outcome | Message |
|------|---------|---------|
| prod_requires_approval | escalate_required | production change requires approved approval before apply |

## Audit events
| # | Kind | Actor | Resource | Hash |
|---|------|-------|----------|------|
| 1 | changeset.created    | alice (human) | change_set/3879c88f | c35159c1989e |
| 2 | policy.evaluated     | alice (human) | change_set/3879c88f | 00594ad919e8 |
| 3 | changeset.submitted  | alice (human) | change_set/3879c88f | 03fed90bd4e9 |
| 4 | policy.evaluated     | bob (human)   | change_set/3879c88f | 0e4c249b65c1 |
| 5 | approval.recorded    | bob (human)   | approval/ab199f09   | 4aa2fb34ba0c |
| 6 | approved_version.created | bob (human) | approved_version/afcf423b | b6cec1940eb7 |
| 7 | changeset.approved   | bob (human)   | change_set/3879c88f | b96a510bc4f3 |
```

This is what you hand the auditor. They read Markdown. They like
hashes. They love that two re-exports return the same bytes.

## Quickstart (60 seconds)

```bash
git clone https://github.com/rupivbluegreen/statebound
cd statebound
make docker-app-up                      # Postgres + API container
curl -fsS http://localhost:8080/healthz # → 200 OK
curl -fsS -H "Authorization: Bearer local-dev" \
     http://localhost:8080/v1/products
```

For the full eight-step golden path (model import, OPA gating,
plan generation, evidence export, audit verify),
see [`docs/golden-path.md`](docs/golden-path.md).

## Agents propose, humans and OPA decide

Statebound is built so that the optional reasoning add-on
(`statebound-reason`) can be removed, replaced, or never installed
without affecting core behavior. When the add-on is present, every
agent is a registered ServiceAccount with versioned, approved
entitlements; every agent invocation is audited with model identity,
prompt hash, input hash, output hash, tool-call trace, and any OPA
decisions referenced. Agents draft, classify, summarize, and narrate.
**Agents never approve, apply, or modify approved state** — that
boundary is enforced in OPA, not just absent from code.

In other words: the AI does not get to write its own access policies,
and the audit trail can prove it.

The add-on R-track (`R1`-`R5`: Modeler, Drift Analyst, Reviewer,
Auditor + Evidence Narrator + Policy Author, hardening) begins now
that core v1.0 has shipped.

## Where to learn more

- [`docs/why-statebound.md`](docs/why-statebound.md) — long-form
  pitch, comparison vs IGA / PAM / OPA-only / spreadsheet, who this
  is and isn't for.
- [`docs/architecture.md`](docs/architecture.md) — three-plane
  architecture, two deployment shapes.
- [`docs/security-model.md`](docs/security-model.md) — security
  pillars, OIDC, RBAC, signing, audit, OpenTelemetry.
- [`docs/threat-model.md`](docs/threat-model.md) — full Phase 1–8
  threat surfaces and mitigations.
- [`docs/observability.md`](docs/observability.md) — tracing posture
  and span attribute conventions.
- [`docs/roadmap.md`](docs/roadmap.md) — core and add-on release
  plans.
- [`docs/golden-path.md`](docs/golden-path.md) — end-to-end demo from
  spec §30.
- [`deploy/helm/statebound/README.md`](deploy/helm/statebound/README.md) —
  Helm chart values, install recipes, the migrations gap.

## Repo layout

```
statebound/
  cmd/statebound/        # CLI + TUI + API binary
  internal/{domain, api, authz, evidence, drift, signing, telemetry, ...}
  migrations/            # 11 Goose migrations
  schemas/openapi.yaml   # public HTTP API contract
  policies/              # built-in Rego + Rego tests
  examples/              # payments-api, payments-postgres
  docs/                  # see "Where to learn more"
  deploy/
    docker-compose/      # local dev: Postgres + API
    helm/statebound/     # production-grade chart
  Dockerfile             # distroless static, runs as nonroot
  Makefile
```

## Prerequisites

- Docker (for Postgres, the project's `golang` Docker wrapper, and
  `make docker-app-up`).
- git.
- Helm (optional; only needed to deploy the chart).
- Go is **optional**: `scripts/go.sh` wraps the official `golang`
  Docker image so contributors don't need a host toolchain.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
