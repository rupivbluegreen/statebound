# Architecture

This document is a one-page summary. The authoritative source is
`the project spec` — see specifically §6 (architecture), §7 (stack), §8
(layout), §16 (connector contract), and §17 (reasoning contracts).

## Three planes, hard boundaries

Statebound is structured as three planes with strict interfaces:

- **Decision Plane.** The only plane that holds state of record. Pure
  Go, deterministic, replayable. Owns the domain model, OPA policy
  evaluation, ChangeSets, ApprovedVersions, the audit log, and the
  evidence engine. Side-effect-free except for its own database, OPA,
  and audit log.
- **Connector Plane.** The only plane that touches target systems.
  Connectors translate desired state into target-system Plans and
  Applies, and collect actual state for drift comparison. Connector
  failures cannot corrupt the core model. See `the project spec` §16 for the
  interface.
- **Reasoning Plane.** Bounded AI agents that propose, classify, and
  narrate. They never decide. The Reasoning Plane has no privileged
  access; it interacts with the Decision Plane through the same public
  HTTP/JSON API exposed to humans, scoped by per-agent ServiceAccount
  entitlements. Every interaction is OPA-evaluated and audited
  identically to a human action. See `the project spec` §17 for the agent and
  inference-backend contracts.

## Two deployment artifacts

The Decision and Connector Planes ship together in the **core** binary
`statebound`. The Reasoning Plane ships as a separate, optional add-on
binary `statebound-reason`. The architectural commitments around this
split are recorded in ADR 0001.

```
=================  statebound-reason  (OPTIONAL ADD-ON)  ============
|                    REASONING PLANE                              |
|  Modeler | Reviewer | Drift Analyst | Auditor |                 |
|  Policy Author | Evidence Narrator                              |
|  Local-first inference (Ollama / vLLM / llama.cpp)              |
|  Cloud backends opt-in per agent                                |
|  Authenticates to core API as its own ServiceAccount            |
====================================================================
                              |
                              | (public HTTP/JSON API, mTLS or OIDC,
                              |  every call scoped + OPA-evaluated + audited)
                              v
=====================  statebound  (CORE — REQUIRED)  ================
|                    DECISION PLANE                               |
|  Domain model | OPA policy engine | ChangeSets |                |
|  ApprovedVersions | Audit log | Evidence engine                 |
+-----------------------------------------------------------------+
|                   CONNECTOR PLANE                               |
|  Linux sudo/SSH | PostgreSQL | Kubernetes | LDAP | ...          |
|  Plan, Apply (approved-only), CollectActualState, Compare       |
====================================================================
                              |
                              v
                       Target Systems
```

## Two supported deployment shapes

- **Shape A — Core only.** `statebound` plus PostgreSQL. Engineers
  author YAML, read diffs, and run their own queries. Nothing is
  degraded. Suitable for regulated buyers in their first year,
  air-gapped environments, and any organization where AI is not yet
  approved for use.
- **Shape B — Core + Reasoning add-on.** Same core, plus
  `statebound-reason` running as a separate process (sidecar, separate
  pod, or separate node). The add-on authenticates to the core as a
  registered ServiceAccount and registers each agent through the
  standard ChangeSet flow. Removing the add-on returns the deployment
  to Shape A with no data loss.

## Stack at a glance

Go for everything except where a target-system constraint makes it
impractical (e.g., a connector for a system with only a Python SDK).
Cobra for CLI, Bubble Tea + Lip Gloss + Bubbles for TUI, chi or stdlib
for HTTP, OpenAPI 3.1 for the API spec, PostgreSQL with Goose for
migrations, sqlc with pgx for SQL access, OPA / Rego as the primary
policy engine, slog for logging. See `the project spec` §7 for full details.

## Layout

The core repository layout is summarized in the README and detailed in
`the project spec` §8. The hard rule: domain logic stays separate from API,
CLI, TUI, connectors, and reasoning. The Reasoning Plane talks to the
Decision Plane through `internal/api`, never directly to
`internal/domain` or `internal/storage`.

## Cross-references

- `the project spec` §6 — three-plane architecture and deployment shapes.
- `the project spec` §7 — recommended technical stack.
- `the project spec` §8 — repository layout and boundary rules.
- `the project spec` §16 — connector contract.
- `the project spec` §17 — agent runtime, inference backend, tool dispatch,
  prompt bundle contracts.
- `docs/adr/0001-reasoning-as-addon.md` — the add-on separation
  decision record.
