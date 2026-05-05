# Contributing to Statebound

Thank you for considering a contribution to Statebound. This document
covers what we expect from a contribution and how to make the
maintainers' life easy.

If you are reporting a **security vulnerability**, please do not file
a public issue. See [`SECURITY.md`](SECURITY.md).

If you are unsure whether your idea fits, file a draft issue with the
problem you are trying to solve and we'll work out the design in the
thread before any code is written.

## Code of conduct

This project adheres to the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md).
By participating you agree to abide by its terms.

## Sign your commits (DCO)

Statebound uses the [Developer Certificate of Origin](https://developercertificate.org)
in lieu of a CLA. Every commit must carry a `Signed-off-by:` trailer
asserting that you wrote the change (or have the right to submit it
under the project's Apache 2.0 license):

```
git commit -s -m "your commit message"
```

Pull requests without sign-off will be asked to rebase before merge.
There is no separate CLA to sign — the sign-off is the agreement.

## Development environment

The host requires only:

- Docker (for Postgres + the project's `golang` Docker wrapper)
- `git`
- `make`

Go itself is **optional**. `scripts/go.sh` wraps the official
`golang:1.25-alpine` image so contributors don't need a local
toolchain. If you prefer a native Go install, anything ≥ 1.25 works.

```bash
git clone https://github.com/rupivbluegreen/statebound
cd statebound
make docker-up        # local Postgres
make build            # ./bin/statebound
make test             # full Go test suite
make policy-test      # Rego unit tests via the OPA tester
```

For the full demo path see [`docs/golden-path.md`](docs/golden-path.md).

## What changes are in scope

- Bug fixes against any v1.0 capability.
- New connectors (Kubernetes RBAC and LDAP are the next two on the
  list — see [`docs/roadmap.md`](docs/roadmap.md)).
- New built-in Rego rules with unit tests.
- Documentation improvements.
- Helm chart hardening (the v0.1 chart-version has known gaps
  documented in [`deploy/helm/statebound/README.md`](deploy/helm/statebound/README.md)).

## What changes are NOT in scope (without a design discussion first)

- Anything that weakens audit-log integrity, four-eyes, OPA-as-sole-gate,
  signed plan bundles, or the no-secrets-in-DB rule. These pillars are
  documented in [`docs/security-model.md`](docs/security-model.md);
  they are non-negotiable.
- Changes to the public HTTP API contract without an accompanying
  OpenAPI spec update in `schemas/openapi.yaml`.
- Reasoning-add-on (`statebound-reason`) features in the core repo.
  The add-on lives in a sibling Go module per
  [`docs/adr/0001-reasoning-as-addon.md`](docs/adr/0001-reasoning-as-addon.md).
- Trademark-bearing UI surfaces while the working name is still
  pending clearance — see
  [`docs/adr/0002-product-name-statebound.md`](docs/adr/0002-product-name-statebound.md).

## Style

### Go

- `gofmt` and `goimports` clean. The CI lint job enforces both.
- `golangci-lint` clean against `.golangci.yml` (one-time pass per PR).
- Small functions; explicit domain types over raw strings.
- No global mutable state. No `init()` side-effects beyond connector
  registration.
- Errors wrapped with `%w` and named when the caller may need to
  branch on them (`errors.Is`).
- Tests live alongside the code (`_test.go`), not in a separate
  package unless interface-only testing requires it.
- Deterministic ordering everywhere (sorted keys, sorted slices,
  canonical JSON). This is a hard requirement for plans, evidence
  packs, and drift findings — they are hashed.

### Rego

- `import rego.v1` at the top of every rule file.
- Each rule package emits a `decision` set whose elements have the
  fields `rule_id`, `outcome` (`deny|escalate_required|allow`),
  `message`, `severity` (`info|warning|high|critical`), and optional
  `metadata`. See `policies/builtin/four_eyes.rego` for the canonical
  shape.
- Every rule ships a unit test in `policies/tests/`. The test names
  describe the scenario (`test_fires_on_self_approval`,
  `test_silent_when_different_actor`).

### Commit messages

Conventional Commits prefix when natural; freeform is fine for one-off
work:

- `feat(api): add /v1/products/{id}/audit endpoint`
- `fix(plan): reuse existing plan id on idempotent re-plan`
- `docs: cross-reference and consistency pass`
- `chore: bump goose to v3.28.0`
- `refactor(connectors): hoist sudo command-risk classifier`

Squash on merge is the default. Keep the title under 72 characters;
put the why in the body.

## Required CI checks

Every PR runs the `build-test` job: `go vet`, `golangci-lint run`,
`go build`, `go test ./... -count=1 -race`, the OPA test runner,
migrations round-trip, and the CLI smoke. The `docker-build` job
builds the distroless image and smokes `statebound version` inside
the container. Both must be green before merge.

If your change touches a Rego rule or a connector, also run locally:

```bash
make policy-test
./scripts/go.sh test ./internal/connectors/<your-connector>/... -count=1
```

If your change touches a migration, run:

```bash
make migrate-up && make migrate-down && make migrate-up
```

## Reviewing a PR you didn't open

The same maintainer (`@rupivbluegreen` per `.github/CODEOWNERS`)
currently triages every PR. Community reviews are welcome — leave
them as comments rather than blocking approvals while we settle the
review-bandwidth model.

## Releasing

The maintainer cuts releases. The flow:

1. Bump the chart `version` and `appVersion` if needed
   (`deploy/helm/statebound/Chart.yaml`).
2. Add a `CHANGELOG.md` entry under a new `## [X.Y.Z] - YYYY-MM-DD` heading.
3. `git tag -a vX.Y.Z -m "Statebound vX.Y.Z"` and push the tag.
4. The release workflow (`.github/workflows/release.yml`) handles the
   binary builds, container push, signing, and GitHub release upload.

## Getting help

- Bugs / feature requests: GitHub Issues.
- Questions: GitHub Discussions.
- Vulnerabilities: see [`SECURITY.md`](SECURITY.md).
