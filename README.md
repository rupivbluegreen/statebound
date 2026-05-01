# Statebound

> **Status: pre-release, Phase 0.** The product name "Statebound" is the
> working name and is pending trademark clearance — do not use in
> public-facing artifacts (per `the project spec` rename changelog).

## What is Statebound

Statebound is a terminal-native, open-source desired-state authorization
governance platform for regulated infrastructure and applications. It
replaces spreadsheet-based authorization matrices with versioned,
approvable, reconcilable, evidence-producing authorization models. The
deterministic core (`statebound`) is a complete product on its own; an
optional reasoning add-on (`statebound-reason`) adds bounded AI assist
that proposes but never decides.

## Status

Phase 0 — project skeleton. The repository contains only docs, decision
records, and the bootstrap scripts that future phases will build on. No
runtime code yet. See `docs/roadmap.md`.

## Prerequisites

- Docker (for Postgres and the project's `golang` Docker wrapper).
- git.
- Go is **optional**: `scripts/go.sh` wraps the official `golang` Docker
  image so contributors do not need a host toolchain.

## Quickstart

```
git clone <this-repo> statebound
cd statebound
make docker-up        # local Postgres
make test
statebound version
```

The expected initial demo (from `the project spec` §28) once Phase 0 code lands:

```
make test
make docker-up
make run-api
statebound version
statebound tui
```

## Repo layout

The repository is organized around a hard boundary between the
deterministic core (this repo / module) and the optional reasoning
add-on (a sibling module shipped separately). Below is the core layout
only; the add-on layout is documented in `the project spec` §8.

```
statebound/
  cmd/statebound/        # CLI + TUI + API binary
  internal/
    domain/              # core types, no I/O
    app/                 # use cases
    api/                 # HTTP handlers
    authz/               # OPA integration
    approval/
    audit/               # append-only, hash-chained
    evidence/
    drift/
    graph/
    policy/              # built-in Rego rules
    storage/             # pgx + sqlc
    tui/
    cli/
    connectors/
  migrations/            # core schema only — no agent tables
  schemas/               # OpenAPI + JSON schemas
  policies/              # built-in Rego + Rego tests
  examples/
  docs/
  deploy/
  scripts/
  Makefile
```

## Where to learn more

- `the project spec` — full operating manual and product spec.
- `docs/architecture.md` — three-plane architecture, two deployment
  shapes.
- `docs/security-model.md` — security pillars.
- `docs/threat-model.md` — Phase 0 threat surfaces and mitigations.
- `docs/roadmap.md` — core and add-on release plans.
- `docs/adr/` — accepted decision records.

## License

Apache 2.0. See `LICENSE`.
