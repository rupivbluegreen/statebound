# Statebound

[![CI](https://github.com/rupivbluegreen/statebound/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rupivbluegreen/statebound/actions/workflows/ci.yml)

> **Status: v1.0 — deterministic core feature-complete.** ChangeSets,
> four-eyes approval, immutable approved versions, hash-chained audit
> log, OPA + Rego built-in rule library, decision-log fanout, evidence
> engine, Linux sudo/SSH and PostgreSQL connectors with drift
> detection, RBAC, Ed25519-signed plan bundles, OpenTelemetry,
> read-only HTTP API, Helm chart, and a distroless container image.
> The product name "Statebound" is the working name and is pending
> trademark clearance — do not use in public-facing artifacts (per
> the rename changelog in the project spec).

## What is Statebound

Statebound is a terminal-native, open-source desired-state authorization
governance platform for regulated infrastructure and applications. It
replaces spreadsheet-based authorization matrices with versioned,
approvable, reconcilable, evidence-producing authorization models. The
deterministic core (`statebound`) is a complete product on its own; an
optional reasoning add-on (`statebound-reason`) adds bounded AI assist
that proposes but never decides.

## Status

v1.0 of the deterministic core. The **reasoning add-on
(`statebound-reason`) ships separately** on its own release cadence;
core v1.0 is the gate, so the add-on R-track can begin (`docs/roadmap.md`).

## Prerequisites

- Docker (for Postgres, the project's `golang` Docker wrapper, and
  `make docker-app-up`).
- git.
- Helm (optional; only needed to deploy the chart in
  `deploy/helm/statebound/`).
- Go is **optional**: `scripts/go.sh` wraps the official `golang` Docker
  image so contributors do not need a host toolchain.

## Quickstart

```
git clone <this-repo> statebound
cd statebound
make docker-up        # local Postgres
make build            # ./bin/statebound
./bin/statebound version
```

To run the full stack (Postgres + API container) in one command:

```
make docker-app-up
curl -fsS http://localhost:8080/healthz
make docker-app-down
```

## Golden path demo (v1.0)

The deterministic core demo from the project spec §30, end to end:

```
# 1. Bring up local Postgres + apply migrations.
make docker-up
make migrate-up

# 2. Build the binary.
make build

# 3. Bootstrap an admin role for our operator (one-shot).
./bin/statebound role grant --bootstrap \
  --actor human:alice@example.com --role admin \
  --note "v1.0 demo bootstrap"

# 4. Mint an Ed25519 signing keypair. The private half stays on disk;
#    the public half is registered via a ChangeSet (auto-approved here
#    because we set STATEBOUND_DEV_AUTO_APPROVE).
mkdir -p ~/.statebound
STATEBOUND_ACTOR=human:alice@example.com \
STATEBOUND_DEV_AUTO_APPROVE=true \
  ./bin/statebound key generate \
    --key-id demo \
    --output ~/.statebound/demo.pem

export STATEBOUND_SIGNING_KEY_ID=demo
export STATEBOUND_ACTOR=human:alice@example.com

# 5. Import an authorization model — produces a draft ChangeSet, OPA
#    evaluates it, four-eyes is satisfied via dev auto-approve, and the
#    result is an immutable ApprovedVersion.
STATEBOUND_DEV_AUTO_APPROVE=true \
  ./bin/statebound model import \
    -f examples/payments-api/model.yaml \
    --auto-approve

# 6. Project the approved version into a deterministic Linux sudo plan.
./bin/statebound plan \
  --product payments-api \
  --connector linux-sudo \
  --output /tmp/plan.json

# 7. Export an evidence pack with audit-ready Markdown.
./bin/statebound evidence export \
  --product payments-api \
  --format markdown \
  --output /tmp/evidence.md

# 8. Verify the audit log hash chain.
./bin/statebound audit verify
```

Every step writes audit events. Every state transition was OPA-evaluated.
Every plan is byte-identical given the same approved version + connector
version. Repeat `./bin/statebound evidence export` and the resulting
JSON is byte-identical to the prior export.

The same demo can be driven against the API container instead of the
host binary — `make docker-app-up`, then `curl -H "Authorization: Bearer
local-dev" http://localhost:8080/v1/products`.

## What's next

- The reasoning add-on (`statebound-reason`) phases R1–R5 begin now
  that core v1.0 has shipped a stable HTTP API + evidence engine. The
  add-on adds bounded AI assist — agents that propose ChangeSets, narrate
  evidence, cluster drift, and answer auditor questions — but never decide.
  See `docs/roadmap.md` and the project spec §29 R-track.
- Connector breadth: Kubernetes RBAC and LDAP are the next two
  priority connectors after v1.0.
- Operator UX: a dedicated `statebound-migrations` image bundling the
  migrations directory will close the documented gap in the Helm chart.

## Repo layout

The repository is organized around a hard boundary between the
deterministic core (this repo / module) and the optional reasoning
add-on (a sibling module shipped separately). Below is the core layout
only; the add-on layout is documented in the project spec §8.

```
statebound/
  cmd/statebound/        # CLI + TUI + API binary
  internal/
    domain/              # core types, no I/O
    app/                 # use cases
    api/                 # HTTP handlers, OpenAPI 3.1
    authz/               # OPA integration, Rego embed
    approval/
    audit/               # append-only, hash-chained
    evidence/
    drift/
    graph/
    policy/              # built-in Rego rules
    storage/             # pgx + sqlc
    telemetry/           # OpenTelemetry wiring
    tui/
    cli/
    connectors/
  migrations/            # core schema only — no agent tables
  schemas/               # OpenAPI + JSON schemas
  policies/              # built-in Rego + Rego tests
  examples/
  docs/
  deploy/
    docker-compose/      # local dev: Postgres + API
    helm/statebound/     # production-grade Helm chart
  scripts/
  Dockerfile
  Makefile
```

## Where to learn more

- `docs/architecture.md` — three-plane architecture, two deployment
  shapes.
- `docs/security-model.md` — security pillars, OIDC, RBAC, signing,
  audit, OTel.
- `docs/threat-model.md` — full Phase 1–8 threat surfaces and
  mitigations.
- `docs/observability.md` — OpenTelemetry tracing posture.
- `docs/roadmap.md` — core and add-on release plans.
- `docs/adr/` — accepted decision records.
- `deploy/helm/statebound/README.md` — Helm chart values, install
  recipes, migrations gap.

## License

Apache 2.0. See `LICENSE`.
