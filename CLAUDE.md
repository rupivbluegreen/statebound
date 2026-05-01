# CLAUDE.md (v2.2)

This file is the operating manual for Claude Code and other coding agents building **Statebound**.

Statebound is a terminal-native, open-source desired-state authorization governance platform for regulated infrastructure and applications. It replaces spreadsheet-based authorization matrices with versioned, approvable, reconcilable, evidence-producing authorization models.

The product ships in two independent parts:

- **`statebound`** — the deterministic core. Authorization model, OPA-gated approvals, immutable approved versions, connectors, drift detection, evidence engine. Fully functional standalone.
- **`statebound-reason`** — an optional reasoning add-on. A bounded fleet of local-first AI agents that propose, classify, and narrate, but never decide. Talks to the core only through the public API as a registered ServiceAccount. Never required.

Statebound is vendor-neutral and host-control-system agnostic. It does not depend on any proprietary authorization product, agent, or terminology.

**Changelog vs v2.1:** the project was renamed to **Statebound**. The rename was driven by trademark proximity to an established identity-and-access product in the same buyer segment, phonetic confusion with the OpenSLO specification project, and weak inherent distinctiveness of the prior mark. See `docs/adr/0002-product-name-statebound.md` for the decision record. **Trademark clearance is pending formal attorney review;** the name is committed in-repo as the working name and should not be used in any public-facing artifact (GitHub repo, domain, social handle, README of a public repo) until clearance is confirmed.

**Changelog vs v2:** the reasoning plane was clarified from an in-tree sidecar to a fully optional, separately-shipped, separately-versioned add-on. The core has zero compile-time, runtime, or schema dependency on the add-on. See §6 (architecture), §8 (repo layout), §29 (roadmap), and `docs/adr/0001-reasoning-as-addon.md` for the decision record.

-----

## 1. Product mission

Build the open-source control plane for authorization governance across infrastructure and applications, with deterministic guarantees at the core and **optional, bounded** AI assistance available as a separately-shipped add-on.

The core product is complete and useful without the reasoning add-on. The add-on extends the core for teams that want AI assist; it never replaces or undermines deterministic behavior.

Statebound helps regulated engineering teams answer:

- What access should exist?
- Who approved it?
- What changed?
- What access exists in reality?
- Where is the drift?
- What evidence can we give auditors?
- And — uniquely — what can our AI assistants see, do, and say, with the same governance applied to them as to humans?

Statebound is **not** a generic IAM portal, an IGA replacement, or a PAM. It is a desired-state authorization governance, drift, and evidence system with a self-governing AI assist layer.

-----

## 2. Product principles

1. **TUI-first, API-first, CLI-native.**
- No operator Web UI in the initial product.
- The first-class human interface is the TUI.
- The first-class automation interface is the CLI/API.
- Approval channels (Slack, email, web) are a post-MVP integration point, not a Web UI for operators.
1. **Vendor-neutral.**
- Do not depend on any proprietary authorization, host-control, or IGA product.
- All target-system behavior is implemented through open, adapter-based connectors.
1. **Desired state before enforcement.**
- The core product stores and versions what access should exist.
- Provisioning and reconciliation are adapter-based and optional.
1. **Evidence-first.**
- Every approval, version, drift scan, plan, apply, and agent invocation must produce audit evidence.
1. **Immutable approved state.**
- Approved authorization versions are immutable.
- Any change creates a new draft, change set, or version.
1. **Safe by default.**
- Default to read-only, plan-only, dry-run behavior.
- Applying changes requires explicit `--apply` or equivalent TUI confirmation and an approved version.
1. **No secret storage.**
- Never store passwords, private keys, tokens, or database credentials in Statebound.
- Integrate with Vault, PAM, or secret managers by reference only.
1. **Explainable authorization.**
- Every permission must be traceable from product → entitlement or service account → authorization → resource scope → target system.
1. **Connector isolation.**
- Connectors run with least privilege.
- Connector failures must not corrupt the core model.
1. **OSS-friendly.**
- Apache 2.0 license.
- Simple local development.
- Docker Compose first, Helm later.
- Clear examples and demo data.
1. **Agents propose, OPA and humans decide.** *(The hard boundary.)*
- Agents draft, classify, summarize, and narrate. Agents never approve, apply, or modify approved state.
- Every agent invocation is audited with model identity, prompt hash, input hash, output hash, tool-call trace, and any OPA decisions referenced.
- Agent outputs are never the decision of record. They are clearly labeled as derived artifacts and never substitute for OPA evaluation or human approval.
- No agent has apply rights to any connector. No agent output enters an evidence pack unlabeled.
1. **Self-governance.**
- Statebound governs its own agents using its own primitives.
- Every agent is a registered ServiceAccount with versioned, approved entitlements and a bounded capability scope.
- Adding, modifying, or upgrading an agent is itself a ChangeSet that must be approved.
1. **Local-first reasoning.**
- Default inference backend is local (Ollama, vLLM, llama.cpp).
- Cloud LLM backends are opt-in per agent and require explicit policy approval.
- The product must remain fully functional with local-only inference.
1. **Reasoning is an add-on, not a dependency.**
- The deterministic core is a complete product on its own. It must be fully functional, fully supported, and feature-complete without the reasoning add-on installed.
- The reasoning add-on (`statebound-reason`) is a separate binary, separate Docker image, separate Helm chart, and separate Apache 2.0 codebase. It may live in a sibling repository or as a sub-module with its own `go.mod`.
- The core has zero compile-time, runtime, or schema dependency on the add-on. Agent-related schema lives in extension migrations shipped with the add-on.
- The TUI and CLI gracefully degrade: agent-related views surface a clear “reasoning add-on not installed” message rather than failing.
- Anything in this document that describes agents or the Reasoning Plane describes the add-on, not the core.

-----

## 3. Primary users

### Platform Engineer *(primary persona for MVP)*

Needs terminal-native workflows, GitOps compatibility, plans and diffs, connectors, safe apply semantics, and AI assist that reduces toil without obscuring decisions.

### Auditor and Compliance Partner *(primary outcome receiver for MVP)*

Needs exportable evidence, immutable audit trail, version history, approvals, drift status, and a clear, complete provenance record for any AI-assisted artifact.

### Security Architect *(secondary)*

Needs control model, policy authoring, segregation-of-duties detection, evidence, and a defensible architecture story including AI governance.

### IAM Engineer *(secondary)*

Needs entitlement modeling, service-account and non-personal-account lifecycle, approval flows, identity provider integrations, and access-review support.

### Application or Product Owner *(secondary)*

Needs to understand what access their product exposes and approve or review changes.

Build the MVP for Platform Engineer + Auditor. Other personas are valid users but should not drive MVP scope decisions.

-----

## 4. Core domain language

Use these generic terms in code, schemas, and docs:

### Authorization model

- `Product`: application, service, platform, or system whose access is governed.
- `Asset`: concrete target resource such as host, database, namespace, bucket, cluster, application, or service.
- `AssetScope`: selector or grouping of assets, similar to a hostgroup but generic.
- `Entitlement`: human-facing access package that may map to groups, roles, or access-request systems.
- `ServiceAccount`: non-personal account, workload identity, machine identity, or application account. **Agents are a subtype of ServiceAccount.**
- `GlobalObject`: reusable access object such as group, role, policy, ACL, grant, or command group.
- `Authorization`: specific permission attached to an entitlement, service account, or global object.
- `Blueprint`: reusable template for standard authorization models.

### Change and evidence

- `ChangeSet`: draft set of changes before approval.
- `Approval`: four-eyes or policy-based approval record.
- `ApprovedVersion`: immutable approved desired state.
- `Plan`: proposed target-system changes derived from desired state.
- `Apply`: execution of an approved plan through a connector.
- `DriftFinding`: mismatch between desired state and actual state.
- `EvidencePack`: exportable audit bundle.

### Reasoning plane

- `Agent`: a registered, versioned, ServiceAccount-backed reasoning component with a single declared purpose and a bounded capability scope.
- `AgentInvocation`: a single execution of an agent, recorded with full provenance.
- `AgentProposal`: any draft artifact produced by an agent (ChangeSet draft, drift remediation, evidence narrative, Rego candidate, etc.).
- `ToolCall`: a discrete API call made by an agent during an invocation, scoped by the agent’s entitlements and OPA-evaluated.
- `ModelBackend`: an inference backend (local or cloud) registered as a connector with declared capabilities.
- `PromptBundle`: versioned, signed prompts and tool definitions an agent uses, treated as policy-equivalent artifacts.

Avoid vendor-specific terms in core domain objects.

-----

## 5. Non-goals for MVP

Do not build these in v0.1–v0.2:

- Operator Web UI.
- Full IGA replacement.
- Full PAM replacement.
- Secret vault.
- Session recording.
- SIEM.
- CMDB.
- Every possible connector.
- Multi-tenant SaaS billing.
- Any agent.

Agents arrive in v0.3 and later, **not** before the deterministic core is solid. They must not pollute the v0.1–v0.2 architecture.

-----

## 6. Three-plane architecture, two deployment artifacts

Statebound is structured as three planes with strict interfaces between them. The Decision and Connector Planes ship together in the **core** binary (`statebound`). The Reasoning Plane ships as a separate, optional **add-on** binary (`statebound-reason`).

```text
=================  statebound-reason  (OPTIONAL ADD-ON)  ============
|                    REASONING PLANE                              |
|  Modeler | Reviewer | Drift Analyst | Auditor |                 |
|  Policy Author | Evidence Narrator                              |
|                                                                 |
|  Local-first inference (Ollama / vLLM / llama.cpp)              |
|  Cloud backends opt-in per agent                                |
|                                                                 |
|  Authenticates to core API as its own ServiceAccount            |
|  Each agent is a registered, capability-scoped sub-account      |
====================================================================
                              |
                              | (public HTTP/JSON API, mTLS or OIDC,
                              |  every call scoped + OPA-evaluated + audited)
                              v
=====================  statebound  (CORE — REQUIRED)  ================
|                    DECISION PLANE                               |
|  Domain model | OPA policy engine | ChangeSets |                |
|  ApprovedVersions | Audit log | Evidence engine                 |
|                                                                 |
|  Pure Go, deterministic, replayable, single source of truth     |
+-----------------------------------------------------------------+
|                   CONNECTOR PLANE                               |
|  Linux sudo/SSH | PostgreSQL | Kubernetes | LDAP | ...          |
|                                                                 |
|  Plan, Apply (approved-only), CollectActualState, Compare       |
====================================================================
                              |
                              v
                       Target Systems
```

### Plane invariants

**Decision Plane** is the only plane that holds state of record. Pure Go, side-effect-free except for its own database, OPA, and audit log. Replaying its event log reproduces its state exactly.

**Connector Plane** is the only plane that touches target systems. Connectors do not own domain objects; they translate between desired state and actual state. Connector failures cannot corrupt the core model.

**Reasoning Plane** has no privileged access. It interacts with the Decision Plane through the same public API exposed to humans and external clients, scoped by per-agent ServiceAccount entitlements. Every interaction is OPA-evaluated and audited identically to a human action. **The add-on can be uninstalled, replaced, or never installed without affecting core behavior.**

### Two supported deployment shapes

**Shape A — Core only.** Engineers author YAML by hand, read diffs themselves, get flat drift findings, and run their own queries. Nothing is degraded; this is how infrastructure tools have always worked. Suitable for: regulated buyers in their first year, air-gapped environments without GPUs, environments where AI is not yet approved for use.

```text
statebound → PostgreSQL
```

**Shape B — Core + Reasoning add-on.** Same core, plus the agent fleet for AI assist. The add-on runs as a separate process (sidecar, separate pod, or separate node), authenticates to the core as a registered ServiceAccount, and registers each agent through the standard ChangeSet flow. Removing it returns the deployment to Shape A with no data loss.

```text
statebound-reason ──API──→ statebound → PostgreSQL
       │
       └─→ local inference (Ollama / vLLM / llama.cpp)
```

This is the architectural commitment that makes the agent layer safe and adoptable: there is no backdoor, and there is no dependency.

-----

## 7. Recommended technical stack

Use Go for everything except where a target-system constraint makes it impractical (e.g., a connector for a system with only a Python SDK).

### Decision Plane

- Language: Go.
- CLI: Cobra.
- TUI: Bubble Tea + Lip Gloss + Bubbles.
- HTTP router: chi or standard library.
- API spec: OpenAPI 3.1.
- DB: PostgreSQL.
- Migrations: Goose.
- SQL access: sqlc, with pgx for dynamic cases.
- Policy: **OPA / Rego as the primary policy engine.** Decision logs wired into the audit pipeline. Cedar abstraction kept as an interface for future use, not a parallel implementation.
- Config: YAML + environment variables.
- Logging: slog.
- Telemetry: OpenTelemetry-ready, optional in MVP.

### Connector Plane

- Go-native connector framework with a small interface (see §17).
- Connectors run as separate processes or sidecars; never linked into the core binary unless trivial.
- Network egress for connectors is opt-in and policy-gated.

### Reasoning Plane *(ships in `statebound-reason`, not in core)*

- Go-native agent runtime. Do **not** import a Python orchestration framework. Implementation must be Go, deterministic in state machine, with its own `go.mod`.
- Lives in a separate binary. May live in the same repository as a separate Go module, or in a sibling repository — the maintainer’s choice. Either way: no shared internal packages with the core, no shared schema migrations, no shared release cadence.
- Reference patterns from LangGraph-style runtimes are fine for inspiration only.
- Tool calls follow MCP (Model Context Protocol) semantics over the core’s public HTTP API.
- Inference backend interface supports:
  - Ollama (default for development and local deployment).
  - llama.cpp / GGUF (recommended for air-gapped).
  - vLLM (recommended for self-hosted GPU).
  - OpenAI-compatible cloud (opt-in per agent, policy-gated).
- Prompt bundles are versioned files in the add-on repo, signed at release.

### Packaging

- Two independent binaries: `statebound` (core, required) and `statebound-reason` (add-on, optional).
- Two independent Docker images. Two independent Helm charts (or one umbrella chart with the add-on disabled by default).
- The core deploys and runs without the add-on. Removing or never installing the add-on does not degrade core functionality.
- Docker Compose for local dev. Helm chart for v1.0.

-----

## 8. Repository layout

The product is two repositories (or one repository with two independent Go modules — maintainer’s choice). Either way, the boundary between them is hard.

### Core repository — `statebound`

```text
statebound/                          # go.mod #1
  cmd/
    statebound/                      # CLI + TUI + API binary
      main.go
  internal/
    domain/                        # core types, no I/O
    app/                           # use cases / services
    api/                           # HTTP handlers, OpenAPI-driven
    authz/                         # OPA integration, decision log fanout
    approval/
    audit/                         # append-only event log, hash chain
    evidence/
    drift/
    graph/                         # explainability traversal
    policy/                        # built-in Rego rule library
    storage/                       # pgx + sqlc
    tui/
    cli/
    connectors/
      linux_sudo/
      linux_ssh/
      postgres/
      kubernetes/
  migrations/                      # core schema only — no agent tables
  schemas/
    openapi.yaml                   # public API including agent-facing endpoints
    authorization-model.schema.json
    evidence-pack.schema.json
    connector-contract.schema.json
  policies/
    builtin/                       # built-in Rego rules shipped with the core
    tests/                         # Rego unit tests
  examples/
    payments-api/
    linux-sudo/
    postgres-grants/
  docs/
    architecture.md
    threat-model.md
    security-model.md
    roadmap.md
    adr/
      0001-reasoning-as-addon.md
  deploy/
    docker-compose/                # core only
    helm/                          # core chart
  Makefile
  README.md
  CLAUDE.md
```

### Add-on repository — `statebound-reason`

```text
statebound-reason/                   # go.mod #2 (separate module)
  cmd/
    statebound-reason/               # agent runtime binary
      main.go
  internal/
    runtime/                       # state machines, tool dispatch, provenance
    agents/
      modeler/
      reviewer/
      drift_analyst/
      auditor/
      policy_author/
      evidence_narrator/
    inference/                     # ollama, vllm, llamacpp, openai-compatible
    prompts/                       # versioned, signed prompt bundles
    apiclient/                     # generated Go client for statebound public API
  migrations/                      # extension migrations: agent tables only
  schemas/
    agent-registration.schema.json
    agent-invocation.schema.json
  examples/
    agent-modeler/                 # example registration + transcripts
  docs/
    agent-governance.md
    eu-ai-act-alignment.md
  deploy/
    docker-compose/                # core + add-on combined for local dev
    helm/                          # add-on chart, depends on core chart
  Makefile
  README.md
  CLAUDE.md                        # add-on-specific operating manual
```

### Boundary rules

- The add-on imports the core **only** as a generated API client (`apiclient/`). It does not import core internal packages.
- The add-on owns its own schema migrations. Core migrations never reference agent tables.
- The add-on can be deleted from disk without breaking the core build, the core tests, or the core deployment.
- If the maintainer chooses to keep both modules in one repository for v0.x convenience, the directory boundary still applies: `internal/reasoning/` becomes a sub-module with its own `go.mod` and is treated as if it were a sibling repo.

Keep domain logic separate from API, CLI, TUI, connectors, and reasoning. The Reasoning Plane talks to the Decision Plane through `internal/api`, never directly to `internal/domain` or `internal/storage`.

-----

## 9. Phased roadmap

The roadmap is split: Phase 0–4, 4’, and 6 are **core** phases shipped in the `statebound` binary. Reasoning add-on phases R1–R4 are shipped in the `statebound-reason` binary on an independent cadence. Add-on phases assume core ≥ v0.3 (evidence engine).

### Core phases

#### Phase 0 — Project skeleton (core v0.0)

Goal: project is buildable and understandable.

Deliverables: Go module, Cobra CLI skeleton, Bubble Tea TUI skeleton, Postgres Docker Compose, Makefile, initial migrations, README quickstart, architecture doc, threat-model draft, **`docs/adr/0001-reasoning-as-addon.md`** committed before any agent code is written.

Acceptance: `make test` passes, `make dev` starts local Postgres and API, `statebound version` works, `statebound tui` launches.

#### Phase 1 — Authorization model (core v0.1)

Goal: define and persist the core desired-state model.

Deliverables: Products, Assets, AssetScopes, Entitlements, ServiceAccounts, GlobalObjects, Authorizations. YAML import/export. Validation with clear error messages.

Acceptance: create product from CLI, import YAML model, list objects in TUI, invalid models fail validation cleanly.

#### Phase 2 — Versioning, diff, approval, OPA pillar (core v0.2)

Goal: changes are reviewable, approvable, and policy-gated.

Deliverables: draft ChangeSets, diff engine, approval request flow, approval records, immutable ApprovedVersion, audit events for all actions, **OPA policy engine integrated as the primary gate for ChangeSet admission**, **built-in Rego rule library** (§15), **Rego unit-test framework in CI**, **OPA decision logs wired into the audit stream**.

Acceptance: user can create, view, approve or reject draft changes. Requester cannot self-approve in four-eyes mode. Approved version is immutable. Every state transition produces an audit event. OPA evaluates every ChangeSet. Decision logs appear in audit log with stable cross-reference.

#### Phase 3 — Evidence engine (core v0.3)

Goal: produce compliance-ready evidence.

Deliverables: EvidencePack data model, JSON export, Markdown export, deterministic content hash, links to approved version, approvals, diff, drift findings, and OPA decision references.

Acceptance: `statebound evidence export --product payments-api --version latest` produces a deterministic, reproducible bundle. Bundle hash is reproducible across machines.

**Note:** Phase 3 is the gate for the reasoning add-on. The add-on cannot ship until the core’s public API surface is stable enough to support external clients and the evidence engine exists for the agents to operate on.

#### Phase 4 — Linux sudo/SSH plan-only connector (core v0.4)

Goal: prove vendor-neutral Linux authorization governance.

Deliverables: Linux desired-state mapping for SSH access groups, sudo command allowlists, local groups. Plan-only connector. Generated sudoers fragments and SSHD config snippets. Command-risk validation through OPA.

Acceptance: plan generated from approved version, plan refused from unapproved draft, wildcard privileged commands flagged by Rego, generated files deterministic.

#### Phase 4’ — Drift detection (core v0.5)

Goal: compare actual state to desired state.

Deliverables: connector collect interface, Linux sudo drift parser, DriftFinding model, TUI drift view, evidence integration. **No agent; flat findings only.**

Acceptance: `statebound drift scan` produces deterministic findings. Findings exportable in evidence packs.

#### Phase 6 — PostgreSQL connector (core v0.6)

Goal: database authorization governance.

Deliverables: desired-state model for Postgres roles/grants, plan generator, SQL DCL generation, optional apply mode with approved version + explicit confirmation, drift collection from system catalogs.

Acceptance: GRANT/REVOKE plan generated, extra grants detected, apply requires approved version.

#### Phase 8 — Core hardening (core v1.0)

Goal: credible for regulated environments.

Deliverables: OIDC login for API, RBAC for Statebound itself, signed plan bundles, tamper-evident audit log (hash chain enforced), OpenTelemetry, Helm chart, security documentation, demo dataset.

Acceptance: security model documented, threat model reviewed, all critical paths tested, Docker Compose and Helm deploys work.

-----

### Reasoning add-on phases *(separate binary, separate release cadence)*

#### Phase R1 — Add-on bootstrap + Modeler (`statebound-reason` v0.1)

Prerequisite: core ≥ v0.3.

Goal: ship the optional reasoning layer with its first agent.

Deliverables: agent runtime in separate binary, Ollama backend, OpenAI-compatible backend (opt-in), prompt bundle format and signing, **AgentInvocation provenance records** (model id, prompt hash, input hash, output hash, tool-call trace), Modeler agent, extension migrations for agent tables, agent registration as ServiceAccount through the core’s standard ChangeSet flow, separate Helm chart.

Acceptance: `statebound-reason` runs as a separate process. `statebound agent invoke modeler --intent "..."` (CLI subcommand provided by the add-on) produces a YAML draft, never a committed ChangeSet. Every invocation is audited in the **core’s** audit log via the public API. Agent has no apply or approve rights — verified by integration test that attempts both. **Uninstalling the add-on returns the deployment to a clean core-only state.**

#### Phase R2 — Drift Analyst (`statebound-reason` v0.2)

Goal: AI-assisted drift remediation.

Deliverables: Drift Analyst agent that clusters findings by likely cause and proposes corrective or backfill ChangeSets — all as drafts, all audited.

Acceptance: Drift Analyst proposes ChangeSets but never commits them. Findings cluster deterministically given identical input.

#### Phase R3 — Reviewer (`statebound-reason` v0.3)

Goal: AI-assisted change review.

Deliverables: Reviewer agent that annotates submitted ChangeSets with risk narrative, peer comparison, and SoD candidate findings.

Acceptance: Reviewer annotations appear on every ChangeSet but never gate approval — OPA gates approval. Annotations are clearly marked as derived.

#### Phase R4 — Auditor + Evidence Narrator + Policy Author (`statebound-reason` v0.4)

Goal: complete the agent fleet.

Deliverables: read-only Q&A over approved versions, audit log, evidence packs (Auditor). Auditor-friendly Markdown narratives derived from raw evidence (Evidence Narrator). Rego rule co-pilot (Policy Author).

Acceptance: every agent output is labeled as derived. Raw artifacts and hashes preserved alongside narratives. Auditor agent never returns an opinion — only data backed by structured queries.

#### Phase R5 — Add-on hardening (`statebound-reason` v1.0)

Prerequisite: core ≥ v1.0.

Goal: production-ready reasoning add-on for regulated environments.

Deliverables: signed agent invocations, signed prompt bundles, agent SBOM exports, **EU AI Act alignment notes** (`docs/eu-ai-act-alignment.md`), Helm chart hardening, demo dataset, agent-augmented golden path demo.

Acceptance: every agent invocation produces an evidence-grade record. Prompt bundles refuse to load if unsigned in production mode. SBOM export includes every agent version, prompt hash, model identity, and dependency tree.

-----

## 10. Initial CLI design

```bash
# core
statebound version
statebound init
statebound product create <name>
statebound product list
statebound model import -f model.yaml
statebound model export --product <name>
statebound validate -f model.yaml
statebound diff --product <name>

# approvals
statebound approval request --product <name>
statebound approval approve <change-set-id>
statebound approval reject <change-set-id>

# connectors
statebound plan --product <name> --connector <connector-name>
statebound apply --plan <plan-id>
statebound drift scan --product <name> --connector <connector-name>

# evidence
statebound evidence export --product <name> --version latest --format json

# policy
statebound policy test
statebound policy eval --change-set <id>

# agents — provided by the statebound-reason add-on, surfaced under `statebound agent ...`
# when the add-on is installed; otherwise these subcommands return a "not installed" message.
statebound agent list
statebound agent register -f agent.yaml
statebound agent invoke <agent-name> --intent "..." [--input-file ...]
statebound agent invocations --agent <name> --since <duration>
statebound agent transcript <invocation-id>

# inference backends — provided by the add-on
statebound inference list
statebound inference register -f backend.yaml

# tui
statebound tui
```

`apply` is never a default. Agent invocations never write to approved state — verified by missing CLI surface, missing Go API, and missing OPA permission. The core CLI ships with the `agent` and `inference` subcommands as discoverable stubs that print *“reasoning add-on not installed”* when the add-on is absent.

-----

## 11. TUI design

The TUI should feel like k9s or lazygit for authorization governance.

Top-level sections:

- Products
- Assets
- Asset Scopes
- Entitlements
- Service Accounts (includes Agents as a subtype, clearly tagged)
- Global Objects
- Authorizations
- Change Sets (with Reviewer annotations inline once available)
- Approvals
- Plans
- Drift Findings (with Drift Analyst proposals inline once available)
- Evidence Packs
- Connectors
- Inference Backends *(visible only when reasoning add-on installed)*
- Agents *(visible only when reasoning add-on installed)*
- Agent Invocations *(visible only when reasoning add-on installed)*
- Audit Log
- Policy (Rego rule browser + decision log viewer)

TUI behaviors:

- Keyboard-first navigation.
- Clear status labels: DRAFT, PENDING_APPROVAL, APPROVED, REJECTED, CONFLICTED, DRIFTING.
- Diff view must be excellent.
- Risk warnings visible before approval or apply.
- Destructive actions require explicit confirmation.
- Agent-derived content must be visually distinguishable from human-authored or deterministic content (e.g., a leading marker, a distinct color, and a footer with model id + invocation id).
- **Graceful degradation:** when the reasoning add-on is not installed, agent-related sections show a single neutral panel: *“Reasoning add-on not installed. See docs/agent-governance.md to enable optional AI assist.”* Never an error, never a missing-feature warning, never a nag.

-----

## 12. Data model guidance

### Core tables

- `products`
- `assets`
- `asset_scopes`
- `entitlements`
- `service_accounts`
- `global_objects`
- `authorizations`
- `change_sets`
- `change_set_items`
- `approvals`
- `approved_versions`
- `approved_version_snapshots`
- `plans`
- `plan_items`
- `drift_scans`
- `drift_findings`
- `evidence_packs`
- `audit_events`
- `connectors`

### Reasoning add-on tables *(installed by `statebound-reason`, not by core)*

These tables are created by **extension migrations shipped with the reasoning add-on**, not by core migrations. The core never references them. The add-on’s migrations live in `statebound-reason/migrations/` and are applied separately when the add-on is installed.

If the add-on is uninstalled, these tables can be safely dropped without affecting core operation. If reinstalled later, migrations re-create them.

- `agents` — registered agents (always backed by a row in core’s `service_accounts`).
- `agent_versions` — versioned agent definitions (prompts, tools, model backend, capability scope).
- `prompt_bundles` — content-addressed, signed prompt bundles.
- `inference_backends` — registered model backends with declared capabilities and policy gates.
- `agent_invocations` — one row per invocation: agent_version_id, backend_id, input_hash, output_hash, prompt_hash, tool_call_summary, opa_decisions_referenced, started_at, finished_at, actor (the human who invoked it).
- `tool_calls` — one row per tool call within an invocation, linked to the API request audited in core’s `audit_events`.

Use UUID primary keys. Include `created_at`, `updated_at`, and actor fields where relevant. Approved-version snapshots preserve the full model as JSONB for immutability and reproducibility. Agent invocation records preserve enough to reproduce the run deterministically given the same backend and seed.

**Note:** core’s `service_accounts` table holds rows for both human-backed accounts and agent-backed accounts. This is intentional — agents are a kind of ServiceAccount, and the core treats them uniformly. The agent-specific metadata (prompts, models, capability scopes) lives in the add-on’s tables.

### Audit log fanout

The core’s `audit_events` table receives events from both the core and (when installed) the add-on, written through the public API as authenticated calls. The audit log itself is core-owned. The add-on never writes to it directly.

-----

## 13. Audit log rules

All of these create audit events:

- product created / updated / deleted
- model imported
- change set created / updated / submitted
- approval requested / approved / rejected
- approved version created
- plan generated
- apply started / succeeded / failed
- drift scan started / succeeded / failed
- evidence exported
- policy violation detected
- OPA decision returned (deny or non-trivial allow)
- agent registered / version updated / disabled
- agent invocation started / finished / failed
- tool call made by an agent
- inference backend registered / updated / disabled
- prompt bundle signed / verified / rejected

Audit events are append-only. Implement hash chaining from v0.2 onward:

```text
current_event_hash = SHA256(previous_event_hash || canonical_json(event))
```

Decision logs from OPA are mirrored into the audit stream with a stable cross-reference (decision id) so an evidence pack can reproduce both the Statebound state and the policy verdict that gated it.

-----

## 14. Agent invocation provenance

Every `agent_invocations` row must capture enough to satisfy a regulator asking “what did the AI do, why, and on whose behalf”:

- Agent identity: `agent_id`, `agent_version_id`, `service_account_id`.
- Human actor: `invoked_by_user_id` (or upstream ChangeSet trigger).
- Backend identity: `inference_backend_id`, model name, model version or digest.
- Inputs: canonical input hash; raw inputs stored only if policy permits (default: store, encrypted; redactions applied for secrets).
- Prompts: `prompt_bundle_id`, prompt hash.
- Tool calls: ordered list of API calls with arguments, results (hashed), and the OPA decision id for each.
- Outputs: canonical output hash; raw output stored under the same policy as inputs.
- OPA references: any decisions the agent triggered or that gated its tool calls.
- Timing: started_at, finished_at, latency, token counts, cost (if cloud).
- Status: succeeded / failed / refused-by-policy / cancelled.

This record is what auditors and the EU AI Act expect. Treat it as evidence-grade from day one.

-----

## 15. Policy and risk rules

OPA / Rego is the primary policy engine. Build a **built-in rule library** in `policies/builtin/` so users get value without writing Rego, with Rego authoring as the escape hatch.

### Initial rules (Phase 2)

- Requester cannot approve their own change in four-eyes mode.
- Unapproved versions cannot be applied.
- Wildcard sudo commands require high-risk flag and elevated approval.
- Root-equivalent authorization requires elevated approval.
- Production changes require approval.
- Service accounts must declare owner, purpose, and usage pattern.
- Entitlements must declare owner and purpose.
- Asset scopes cannot be empty for production authorizations.

### Later core rules (core v0.5+)

- Toxic combinations / segregation of duties.
- Time-bound break-glass.
- Environment separation (no entitlement spans dev + prod).
- Privileged command shell-escape detection.

### Agent-specific rules *(shipped with the reasoning add-on, evaluated by core OPA)*

- Agents can never call `/v1/approvals/approve` or `/v1/plans/apply` — enforced at OPA layer, not just absent in code.
- Agents can never modify approved versions.
- Agents can never escalate their own entitlements via ChangeSet — every agent-proposed ChangeSet that touches an agent’s own ServiceAccount requires elevated human approval.
- Agents using cloud inference backends must be explicitly policy-approved per agent.
- Tool-call rate and quota limits per agent invocation.
- Prompt bundles must be signed and version-pinned for production agents.

These rules ship as Rego files in the add-on’s repo. When the add-on is installed, its registration ChangeSet pushes them into the core’s `policies/` namespace through the normal policy-update flow. Core enforces them; add-on does not bypass.

### Compliance mapping (core v1.0)

- DORA, NIS2, ISO 27001, SOC 2, EU AI Act *(EU AI Act applies once the add-on is installed)*.

Every Rego rule ships with unit tests. `make policy-test` runs the Rego test suite and must pass in CI.

-----

## 16. Connector contract

```go
type Connector interface {
    Name() string
    Capabilities() []Capability
    ValidateDesiredState(ctx context.Context, state ApprovedState) ([]ValidationFinding, error)
    Plan(ctx context.Context, state ApprovedState) (*Plan, error)
    Apply(ctx context.Context, plan Plan) (*ApplyResult, error)
    CollectActualState(ctx context.Context, scope CollectionScope) (*ActualState, error)
    Compare(ctx context.Context, desired ApprovedState, actual ActualState) ([]DriftFinding, error)
}
```

Rules:

- `Plan` is deterministic.
- `Apply` requires an approved plan.
- `CollectActualState` must not collect secrets.
- Connector-specific state must not leak into core domain objects unless represented generically.
- Connectors expose no surface to the Reasoning Plane. Agents that need connector data go through the public API, which goes through OPA.

-----

## 17. Reasoning add-on contracts

*(These contracts live in the `statebound-reason` add-on repo. The core has no awareness of them.)*

### Agent runtime contract

```go
type Agent interface {
    Name() string
    Version() string
    ServiceAccountRef() string
    Capabilities() AgentCapabilities
    DefaultBackend() InferenceBackendRef
    Run(ctx context.Context, input AgentInput) (*AgentInvocation, error)
}

type AgentCapabilities struct {
    AllowedTools     []string  // API endpoints the agent may call
    DeniedTools      []string  // explicit denials, evaluated first
    MaxToolCalls     int
    MaxTokens        int
    MaxLatency       time.Duration
    AllowedBackends  []string  // backends this agent may use; empty = default only
    OutputKinds      []string  // change_set_draft | rego_draft | narrative | query_result
    NetworkEgress    bool      // false by default
}
```

### Inference backend contract

```go
type InferenceBackend interface {
    Name() string
    Kind() BackendKind     // local | cloud
    Capabilities() BackendCapabilities
    Generate(ctx context.Context, req GenerateRequest) (*GenerateResponse, error)
}
```

### Tool dispatch

Agents call tools via an MCP-compatible dispatcher. Every tool call:

1. Is checked against the agent’s `AllowedTools` / `DeniedTools`.
1. Is OPA-evaluated against the agent’s ServiceAccount entitlements.
1. Is executed through the public API as that ServiceAccount.
1. Records a `tool_calls` row linked to the parent `agent_invocations` row.
1. Returns sanitized, hashed results into the agent’s context.

If any step fails, the invocation continues with the failure surfaced to the agent — never silently bypassed.

### Prompt bundles

Prompt bundles are versioned files in `internal/reasoning/prompts/`. Each bundle:

- Has a content-addressed id (SHA-256).
- Is signed at release.
- Declares the agent it belongs to and the schema version.
- Is verified at runtime; mismatched or unsigned bundles refuse to load in production mode.

-----

## 18. The agent fleet

Six agents, each with one job. All operate under Principle #11.

### Modeler (add-on R1)

**Job:** Translate natural-language intent into ChangeSet YAML drafts using the blueprint library as tools.
**Input:** intent string, target product, optional reference entitlements.
**Tools:** `model.read`, `blueprint.read`, `validate`.
**Output kind:** `change_set_draft`.
**Cannot:** submit, approve, apply, escalate.

### Reviewer (add-on R3)

**Job:** Annotate submitted ChangeSets with risk narrative, peer comparison, candidate SoD findings.
**Input:** change_set_id.
**Tools:** `change_set.read`, `model.read`, `audit.read`, `policy.eval` (read-only).
**Output kind:** `narrative` attached to the ChangeSet.
**Cannot:** gate approval. OPA gates. Reviewer informs.

### Drift Analyst (add-on R2)

**Job:** Cluster drift findings by likely cause; propose corrective or backfill ChangeSets as drafts.
**Input:** drift_scan_id.
**Tools:** `drift.read`, `model.read`, `audit.read`, `change_set.create_draft`.
**Output kind:** `change_set_draft` + `narrative`.
**Cannot:** submit ChangeSets — only create drafts that a human submits.

### Auditor (add-on R4)

**Job:** Read-only natural-language Q&A over approved versions, audit log, evidence packs.
**Input:** question string, optional time window or product scope.
**Tools:** `approved_version.read`, `audit.read`, `evidence.read`, `query.execute`.
**Output kind:** `query_result` + `narrative`.
**Cannot:** opine. Returns data with provenance, not interpretation.

### Policy Author (add-on R4)

**Job:** Co-pilot Rego rule authoring from compliance framework references and observed patterns.
**Input:** intent string, optional framework reference, optional observed-pattern set.
**Tools:** `policy.read`, `audit.read`, `policy.test_dryrun`.
**Output kind:** `rego_draft` + tests.
**Cannot:** install rules — drafts go through normal ChangeSet flow.

### Evidence Narrator (add-on R4)

**Job:** Render raw evidence packs into auditor-friendly Markdown narratives.
**Input:** evidence_pack_id.
**Tools:** `evidence.read`, `approved_version.read`.
**Output kind:** `narrative` packaged alongside (never replacing) the raw pack.
**Cannot:** modify the pack. Hashes of source artifacts are preserved and referenced inline.

-----

## 19. Self-governance *(applies when the reasoning add-on is installed)*

When the add-on is installed, Statebound governs its own agents using its own primitives. This is the architectural commitment that makes the agent layer audit-defensible.

- Every agent is a row in core’s `service_accounts` plus rows in the add-on’s `agents` and `agent_versions` tables.
- Adding a new agent requires a ChangeSet that declares the agent, its capability scope, its prompt bundle id, and its allowed backends. The ChangeSet is approved through the core’s standard flow like any other.
- Updating an agent (new prompt bundle, new model, expanded scope) is a new agent version, requiring a new ChangeSet and approval.
- Disabling an agent is a ChangeSet.
- An auditor can run `statebound agent describe <name> --as-of <date>` and get the exact agent version, prompt hash, backend, and capability scope effective on that date.
- An auditor can ask the Auditor agent: *“List every action any agent took in Q3, grouped by agent and outcome.”* The query returns deterministic data from `agent_invocations` and `tool_calls`, with cross-references to OPA decisions.

This is the differentiator. No competitor in the IGA or governance space currently treats their AI assist with the same governance rigor they sell to customers. Statebound does — and uniquely, the customer can choose not to install the AI at all and still get the entire governance product.

-----

## 20. Example desired-state YAML

```yaml
apiVersion: statebound.dev/v1alpha1
kind: ProductAuthorizationModel
metadata:
  product: payments-api
  owner: platform-security
spec:
  assets:
    - name: pay-linux-01
      type: linux-host
      environment: prod
      labels:
        app: payments
        region: eu

  assetScopes:
    - name: prod-linux
      selector:
        type: linux-host
        environment: prod
        app: payments

  entitlements:
    - name: payments-prod-readonly
      owner: payments-team
      purpose: Read-only production troubleshooting
      authorizations:
        - type: linux.ssh
          scope: prod-linux
          methods: [ssh]
        - type: linux.sudo
          scope: prod-linux
          asUser: root
          commands:
            allow:
              - /usr/bin/systemctl status payments
              - /usr/bin/journalctl -u payments --since today
            deny: []

  serviceAccounts:
    - name: payments-batch
      owner: payments-team
      usagePattern: system-to-system
      purpose: Runs scheduled settlement jobs
      authorizations:
        - type: linux.local-group
          scope: prod-linux
          group: payments-runtime
```

-----

## 21. Example agent registration YAML

```yaml
apiVersion: statebound.dev/v1alpha1
kind: AgentRegistration
metadata:
  name: modeler
  owner: platform-security
spec:
  purpose: |
    Drafts ChangeSet YAML from natural-language intent using the
    blueprint library. Output is always a draft; never submits.
  serviceAccount:
    name: agent-modeler
    usagePattern: agent
  version: "0.3.0"
  promptBundle:
    id: "sha256:9f2c1a..."
    signedBy: "release-key-2026-q1"
  capabilities:
    allowedTools:
      - model.read
      - blueprint.read
      - validate
    deniedTools:
      - approval.approve
      - plan.apply
      - approved_version.modify
    maxToolCalls: 50
    maxTokens: 16000
    maxLatency: 60s
    allowedBackends:
      - ollama-local-llama-3
    outputKinds:
      - change_set_draft
    networkEgress: false
```

The registration becomes a ChangeSet on submission. OPA evaluates it. A human approves it. Only then can `statebound agent invoke modeler ...` succeed.

-----

## 22. Security requirements

Coding agents must preserve these:

- Never log secrets.
- Never put secrets in evidence packs.
- Never put secrets in agent invocation records — apply redaction before hashing if necessary; document the redaction.
- Never store connector or backend credentials in the database unless encrypted and explicitly designed for it.
- Default connector behavior: read-only or plan-only.
- Applying target-system changes: requires approved version.
- Approved snapshots: immutable.
- Audit events: append-only, hash-chained from v0.2.
- Generated plans: reviewable before apply.
- Destructive changes: explicit.
- No unsafe shell-out. Sanitize or avoid shell commands.
- Context timeouts on every external call.
- Every connector has dry-run tests.
- **No agent has apply or approve scope. Enforced in OPA, not just absent in code.**
- **Cloud inference backends require per-agent policy approval.**
- **Prompt bundles are signed in production mode.**
- **Agent invocation records are evidence-grade from day one.**

-----

## 23. EU AI Act and agent provenance

Statebound is designed so a regulated organization can adopt the agent fleet without taking on opaque AI risk. The alignment story:

- **Transparency:** every agent has a versioned, approved registration that declares its purpose, scope, and backend.
- **Human oversight:** Principle #11 makes humans the decision of record. OPA is the enforcement of that boundary.
- **Logging:** every invocation is logged with reproducible provenance (§14).
- **Risk classification:** agents that touch production governance flows are treated as high-risk and require elevated approval at registration time and at every version upgrade.
- **Data governance:** local-first inference is the default; cloud routes are explicit, per-agent, policy-gated.
- **SBOM:** v1.0 ships agent SBOM exports listing each agent version, prompt hash, model identity, and backend dependency tree.

`docs/eu-ai-act-alignment.md` walks through specific articles and shows the Statebound feature that addresses each.

-----

## 24. Testing requirements

Minimum test categories:

- Unit tests for domain rules.
- Diff engine tests.
- Approval rule tests.
- Evidence hash reproducibility tests.
- YAML validation tests.
- Connector plan generation tests.
- Drift comparison tests.
- CLI command tests where practical.
- Rego unit tests for every shipped rule.
- Agent runtime tests:
  - Capability-scope enforcement (allowed and denied tools).
  - OPA gating of every tool call.
  - Provenance record completeness.
  - Refuse-on-unsigned-prompt-bundle in production mode.
  - Determinism: same input + same backend + same seed → same canonical output hash.
  - Negative tests: agents cannot reach `approve`, `apply`, or modify approved versions.

Run before committing:

```bash
gofmt -w .
go test ./...
go vet ./...
make policy-test
```

-----

## 25. Development commands

The Makefile exposes:

### Core Makefile (`statebound`)

```bash
make dev
make test
make fmt
make lint
make migrate-up
make migrate-down
make run-api
make run-tui
make policy-test
make docker-up
make docker-down
```

### Add-on Makefile (`statebound-reason`)

```bash
make build              # builds the statebound-reason binary
make test               # add-on tests, including capability-scope and negative tests
make migrate-up         # applies extension migrations to core's database
make run-reason         # starts the add-on against a running core
make docker-up          # brings up core + add-on for local dev
```

Create them as each project evolves.

-----

## 26. Definition of done

A feature is not done unless:

- It has tests.
- It is documented.
- It has clear CLI or TUI access if user-facing.
- It emits audit events if it changes state.
- It does not weaken safe-by-default behavior.
- It does not introduce an operator Web UI dependency.
- It does not introduce a proprietary product dependency.
- **If it lives in the core: it does not import, reference, or depend on any add-on package or add-on schema. The core test suite must pass with the add-on entirely absent.**
- **If it lives in the reasoning add-on: it respects Principle #11, has provenance records, has capability-scope tests, has at least one negative test proving the agent cannot escape its scope, and does not introduce a hard requirement on cloud inference backends.**

-----

## 27. Coding style

- Small functions.
- Explicit domain types over raw strings.
- Pure core domain where possible.
- No global mutable state.
- Interfaces at boundaries, not everywhere.
- Typed errors where useful.
- Structured logging.
- Stable JSON canonicalization for evidence and provenance hashes.
- Deterministic ordering in diffs, plans, exports, and agent outputs.

-----

## 28. First build task

Start with the Decision Plane skeleton. **Do not** build any agent until Phase 3.

1. Initialize Go module.
1. Add Cobra CLI with `version` and `tui` commands.
1. Add Bubble Tea placeholder TUI.
1. Add Docker Compose with PostgreSQL.
1. Add first migration for `products` and `audit_events`.
1. Add storage interface and Postgres implementation skeleton.
1. Add Makefile.
1. Add README quickstart.
1. Add tests for `version` command and product domain object.

Expected initial demo:

```bash
make test
make docker-up
make run-api
statebound version
statebound tui
```

-----

## 29. Product roadmap summary

Statebound releases as **two independent products** on **independent cadences**.

### Core (`statebound`) — required, always shipped first

- **v0.1** Authorization model, CLI import/export, TUI browse, validation.
- **v0.2** ChangeSets, diff, approval, immutable approved versions, audit events, OPA pillar with built-in Rego rule library.
- **v0.3** Evidence engine. *(Stable public API surface — gate for the add-on.)*
- **v0.4** Linux plan-only connector.
- **v0.5** Linux drift detection (flat findings, no AI).
- **v0.6** PostgreSQL connector.
- **v1.0** Enterprise hardening: OIDC, RBAC, signed plans, hash-chain audit, OpenTelemetry, Helm chart, demo.

### Reasoning add-on (`statebound-reason`) — optional, separately versioned

Requires core ≥ v0.3. Versioned independently from core.

- **v0.1** Agent runtime, Modeler agent, agent self-governance, Ollama backend, AgentInvocation provenance.
- **v0.2** Drift Analyst agent.
- **v0.3** Reviewer agent.
- **v0.4** Auditor + Evidence Narrator + Policy Author agents.
- **v1.0** Signed agent invocations, signed prompt bundles, EU AI Act alignment docs, agent SBOM exports, agent-augmented golden path demo. Requires core ≥ v1.0.

The core can ship v1.0 without the add-on having shipped v1.0. A deployment can run core v1.0 with no add-on installed forever — that is a fully supported configuration.

-----

## 30. Golden path demos

### Deterministic golden path (always green from v0.5)

1. Create product `payments-api`.
1. Import desired-state YAML.
1. View entitlements and service accounts in TUI.
1. Create ChangeSet.
1. Show diff.
1. OPA evaluates ChangeSet.
1. Request approval.
1. Approve change.
1. Generate ApprovedVersion.
1. Generate Linux plan.
1. Run drift scan.
1. Export evidence pack.

### Agent-augmented golden path (from v0.7)

1. Engineer types: `statebound agent invoke modeler --intent "read-only prod troubleshooting for payments"`.
1. Modeler returns YAML draft. Engineer reviews, edits, commits.
1. Engineer submits ChangeSet.
1. **Reviewer** annotates with risk narrative and SoD candidate findings.
1. OPA evaluates. Built-in rules pass; one elevated-approval rule fires.
1. Approver opens TUI, sees diff + Reviewer narrative + OPA verdict, approves.
1. ApprovedVersion created. Plan generated. Drift scan runs.
1. **Drift Analyst** clusters new findings, proposes one corrective ChangeSet (revoke) and one backfill ChangeSet (codify).
1. Engineer accepts the backfill, submits, gets it approved.
1. Auditor opens the **Auditor agent**: *“What changed for payments-api in the last 30 days, and which agents touched any of it?”*
1. Auditor agent returns deterministic data, with every agent invocation, model id, prompt hash, and OPA decision id referenced.
1. **Evidence Narrator** generates the audit-ready Markdown for the period. Raw evidence pack is attached, hashes preserved.

This is the north star until v1.0. Deterministic core, bounded agents, full provenance, no surprises.
