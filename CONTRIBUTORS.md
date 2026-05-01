# Contributors

Statebound's deterministic core (v1.0) was implemented through a
multi-phase autonomous build run during 2026-04 → 2026-05, with
[Claude Code](https://claude.com/claude-code) acting as the primary
implementer across every phase from project skeleton (Phase 0) to
v1.0 hardening (Phase 8 wave C). The work is recorded in
`CHANGELOG.md` and the per-phase commit history.

## Acknowledgements

- **[Claude Code](https://claude.com/claude-code)** — implementation
  across Phases 0 through 8 (domain model, OPA + Rego rule library,
  evidence engine, Linux sudo/SSH and PostgreSQL connectors, drift
  detection, RBAC, Ed25519-signed plan bundles, OpenTelemetry,
  HTTP API + OpenAPI 3.1, Helm chart, distroless Docker image,
  threat model). Roughly 50 commits across 11 migrations, 41 Rego
  unit tests, and the full Go test suite. Spec design,
  decision-record approval, scope tradeoffs, and naming all stayed
  with the human maintainer.

## How to be listed here

Open a PR against this file with your preferred attribution (name,
optional link, optional one-line description of contribution).
External contributors are welcome — see `CONTRIBUTING.md` for the
process.
