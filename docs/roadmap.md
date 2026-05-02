# Roadmap

Statebound releases as **two independent products** on **independent
cadences**. The deterministic core ships first and is usable on its
own. The reasoning add-on is optional and gated on core ≥ v0.3. This
doc is a distilled view of `CLAUDE.md` §29 — see that section for the
authoritative phase definitions.

## Core releases (`statebound`, v0.1 → v1.0)

| Version | Theme | Key deliverables | Acceptance signal |
|---------|-------|------------------|-------------------|
| v0.1 | Authorization model | Products, Assets, AssetScopes, Entitlements, ServiceAccounts, GlobalObjects, Authorizations; YAML import/export; validation. | Create product from CLI, import YAML model, list objects in TUI, invalid models fail validation cleanly. |
| v0.2 | Versioning, approval, OPA pillar | Draft ChangeSets, diff engine, approval flow, immutable ApprovedVersion, audit events, OPA integrated as primary gate, built-in Rego rule library, Rego unit-test framework in CI, OPA decision logs in audit stream. | Four-eyes enforced, approved version immutable, every state transition produces an audit event, OPA evaluates every ChangeSet. |
| v0.3 | Evidence engine | EvidencePack model, JSON + Markdown export, deterministic content hash, links to approved version, approvals, diff, drift findings, OPA decision references. | `statebound evidence export` produces a deterministic, reproducible bundle. _Gate for the reasoning add-on._ |
| v0.4 | Linux plan-only connector | Linux desired-state mapping for SSH groups, sudo allowlists, local groups; plan-only connector; generated sudoers and SSHD snippets; command-risk validation through OPA. | Plan generated from approved version, refused from unapproved draft, generated files deterministic. |
| v0.5 | Linux drift detection | Connector collect interface, Linux sudo drift parser, DriftFinding model, TUI drift view, evidence integration. _No agent — flat findings only._ | `statebound drift scan` produces deterministic findings, exportable in evidence packs. |
| v0.6 | PostgreSQL connector | Desired-state model for Postgres roles/grants, plan generator, SQL DCL generation, optional apply with approved version + explicit confirmation, drift collection from system catalogs. | GRANT/REVOKE plan generated, extra grants detected, apply requires approved version. |
| v1.0 | Core hardening | OIDC login, RBAC for Statebound itself, signed plan bundles, tamper-evident audit log (hash chain enforced), OpenTelemetry, Helm chart, security documentation, demo dataset. | Security model documented, threat model reviewed, all critical paths tested, Docker Compose and Helm deploys work. |

## Reasoning add-on releases (`statebound-reason`, v0.1 → v1.0; requires core >= v0.3)

| Version | Theme | Key deliverables | Acceptance signal |
|---------|-------|------------------|-------------------|
| v0.1 | Bootstrap + Modeler | Agent runtime in separate binary, Ollama backend, OpenAI-compatible backend (opt-in), prompt bundle format and signing, AgentInvocation provenance records, Modeler agent, extension migrations for agent tables, agent registration via core ChangeSet flow, separate Helm chart. | `statebound-reason` runs as a separate process, Modeler returns YAML drafts (never commits), agent has no apply or approve rights (verified by integration test), uninstalling the add-on returns the deployment to a clean core-only state. |
| v0.2 | Drift Analyst | Drift Analyst agent: clusters findings by likely cause, proposes corrective and backfill ChangeSets as drafts, all audited. | Drift Analyst proposes drafts but never commits; clustering is deterministic given identical input. |
| v0.3 | Reviewer | Reviewer agent: annotates submitted ChangeSets with risk narrative, peer comparison, candidate SoD findings. | Reviewer annotations appear on every ChangeSet but never gate approval; OPA gates approval; annotations clearly marked as derived. |
| v0.4 | Auditor + Evidence Narrator + Policy Author | Read-only Q&A over approved versions, audit log, evidence packs (Auditor); auditor-friendly Markdown narratives (Evidence Narrator); Rego rule co-pilot (Policy Author). | Every output labeled as derived; raw artifacts and hashes preserved alongside narratives; Auditor returns only data backed by structured queries, no opinions. |
| v1.0 | Add-on hardening | Signed agent invocations, signed prompt bundles, agent SBOM exports, EU AI Act alignment notes (`docs/eu-ai-act-alignment.md`), Helm chart hardening, demo dataset, agent-augmented golden path demo. _Requires core >= v1.0._ | Every invocation produces an evidence-grade record; prompt bundles refuse to load if unsigned in production; SBOM export covers every agent version, prompt hash, model identity, and dependency tree. |

## Independence guarantee

The core ships independently of the add-on. A deployment can run core
v1.0 with no add-on installed forever, and that is a fully supported
configuration. The core's release calendar is not blocked by the
add-on's release calendar, and the add-on can iterate quickly without
destabilizing the core. The architectural commitments that make this
possible are recorded in `docs/adr/0001-reasoning-as-addon.md`.
