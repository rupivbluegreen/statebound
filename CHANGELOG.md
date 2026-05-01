# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-01

The deterministic core is feature-complete. Approved versions can be
generated, approved (four-eyes), gated by OPA, exported as
reproducible evidence packs, projected into deterministic plans for
Linux sudo/SSH and PostgreSQL connectors, and applied to PostgreSQL
with full audit trail. Operators get RBAC, Ed25519-signed plan
bundles, OpenTelemetry tracing, and a read-only HTTP API the optional
reasoning add-on can call into.

### Added (Phase 8 wave C)

- `Dockerfile` — multi-stage build producing a distroless, non-root,
  static `statebound` container at `gcr.io/distroless/static-debian12`.
- `deploy/helm/statebound/` — production-grade Helm chart with
  Deployment, Service, ConfigMap, Secret (dev-token only),
  ServiceAccount, NetworkPolicy, optional Ingress, optional
  HorizontalPodAutoscaler, pre-install migrations Job, and a
  helm-test pod that curls `/healthz` + `/readyz`.
- `deploy/docker-compose/docker-compose.yml` — extended to launch the
  statebound API container alongside Postgres so `make docker-app-up`
  brings the full stack online with one command.
- `make docker-build`, `make docker-app-up`, `make docker-app-down`
  Makefile targets.
- `.dockerignore` keeping the build context lean.
- CI: new `docker-build` job builds the image and smoke-tests
  `statebound version` + `statebound --help` inside the container.
- README: v1.0 status banner plus a step-by-step golden-path demo
  matching the spec §30.
- `docs/threat-model.md`: comprehensive rewrite covering every
  Phase 1–8 mitigation (audit forgery, approve-after-self-request,
  wildcard sudo escalation, apply-without-approval, stale-plan apply,
  stolen signing key, API token spoofing, RBAC escalation, OPA
  bypass, undetected drift) and explicit out-of-scope items.
- `docs/security-model.md`: final consolidation pass adding
  signed plan bundles, OIDC bearer auth, OpenTelemetry posture, and
  the deployment-time security guarantees the chart enforces.

### Added (Phase 8 wave B)

- HTTP API server (`statebound api serve`) with OpenAPI 3.1 spec,
  OIDC bearer auth, and a `STATEBOUND_DEV_TOKEN` dev mode for local
  development. 22 read-only endpoints across products, change sets,
  audit, evidence, plans, drift, policy decisions, signing keys, and
  apply records.
- `/healthz` (process liveness) and `/readyz` (database reachable)
  public probes; `/openapi.yaml` serves the embedded spec.

### Added (Phase 8 wave A)

- Operator RBAC: five non-hierarchical roles (`viewer`, `requester`,
  `approver`, `operator`, `admin`) with single-source-of-truth
  capability mapping in `domain.RolesForCapability`. Bootstrap
  one-shot grant via `--bootstrap`; subsequent grants require
  `role:manage` (admin only).
- Ed25519-signed plan bundles. `statebound key generate` mints a
  named keypair; the public key half is registered in the database
  via a ChangeSet; private keys never leave the operator's host.
  Plans are signed at `plan.ready` time and the signature is
  verified at apply time, with content hashes pinning the plan.
- OpenTelemetry tracing, off by default. Set `STATEBOUND_OTEL_*`
  env vars to enable OTLP gRPC, OTLP HTTP, or stdout exporters.
  PII-safe span attributes; opt-in actor attribution.

### Added (Phase 6)

- PostgreSQL connector: desired-state model for roles + grants,
  deterministic SQL DCL plan generation, optional apply with
  full audit trail. Drift collected from `pg_catalog`.

### Added (Phase 4 / 4')

- Linux `sudo`/`ssh` plan-only connector. Generated sudoers
  fragments and SSHD config snippets are deterministic given the
  same approved version and connector version.
- Drift detection: connector `CollectActualState` interface, Linux
  sudo drift parser, `DriftFinding` model, TUI drift view, evidence
  integration. `statebound drift scan` returns deterministic
  `summary_hash`.

### Added (Phase 3)

- Evidence engine: deterministic evidence packs (JSON + Markdown)
  with stable content hashes, references to the approved version,
  approvals, diff, drift findings, and OPA decisions.
- `statebound evidence export` and `statebound evidence list`.

### Added (Phase 2)

- ChangeSets, diff engine, four-eyes approval flow, immutable
  approved versions.
- OPA / Rego built-in rule library:
  `four_eyes`, `wildcard_sudo`, `service_account_metadata`,
  `entitlement_metadata`, `production_requires_approval`,
  `prod_scope_nonempty`, `root_equivalent`, `rbac_role_required`.
- Decision-log fan-out: every OPA decision becomes an audit event
  with a stable cross-reference id.
- Hash-chained `audit_events` (`current_event_hash = SHA256(prev || canonical_json(event))`)
  and `statebound audit verify` to detect tampering.
- `statebound policy test` and `statebound policy eval --change-set`.

### Added (Phase 1)

- Authorization model domain types: `Product`, `Asset`, `AssetScope`,
  `Entitlement`, `ServiceAccount`, `GlobalObject`, `Authorization`.
- YAML import/export (`statebound model import|export`), validation
  (`statebound validate`).

### Added (Phase 0)

- Go module skeleton (`go.mod` declared, no source code yet).
- Cobra CLI skeleton with `version` and `tui` subcommands.
- Bubble Tea placeholder TUI.
- PostgreSQL `docker-compose` for local development.
- Initial database migration creating `products` and `audit_events`.
- Storage interface with a Postgres implementation skeleton (`pgx`).
- Makefile with `dev`, `test`, `fmt`, `lint`, `migrate-up`,
  `migrate-down`, `run-api`, `run-tui`, `policy-test`, `docker-up`,
  `docker-down` targets.
- README quickstart.
- ADR 0001: reasoning is an add-on, not a dependency.
- ADR 0002: product name "Statebound" adopted as the working name
  pending formal trademark clearance.

## [0.0.0] - 2026-05-01

Phase 0 skeleton (preserved here for historical continuity; see the
1.0.0 entry above for the cumulative description).
