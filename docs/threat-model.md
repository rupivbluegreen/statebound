# Threat Model (v1.0 review)

> **Status: v1.0 review complete.** This document covers every
> mitigation Statebound ships across Phase 1 through Phase 8 of the
> deterministic core. Reasoning add-on threats are tracked at the end
> of this document and revisited per add-on phase. See the project
> spec §22 (security requirements) and §29 (roadmap).

The product separates into a deterministic core (`statebound`) and an
optional reasoning add-on (`statebound-reason`). The core is feature-
complete at v1.0 and is the subject of this review; the add-on is
covered in §6 below as a forward-looking section.

## Trust boundaries

Statebound's trust boundaries are:

1. **Operator identity ↔ CLI / API.** The CLI authenticates by
   environment-supplied actor (host-trust); the API authenticates by
   OIDC bearer or a single-tenant dev token.
2. **CLI / API ↔ Postgres.** The database is the state of record. A
   compromised Postgres operator can read approved versions, the
   audit log, and signed plan public keys — but the audit log hash
   chain detects in-place tampering.
3. **CLI / API ↔ connectors.** Connectors run with target-system
   credentials that Statebound never sees; they communicate state via
   structured Plan / ApplyResult / DriftFinding records.
4. **Connectors ↔ target systems.** The blast radius of a compromised
   connector is bounded by its target-system credentials.
5. **Reasoning add-on ↔ core HTTP API.** When the add-on is installed,
   it authenticates as a registered ServiceAccount using the same
   OIDC pipeline humans use; every request is OPA-evaluated and
   audited identically.

## 1. API surface (core)

**Threats.**

- Authentication bypass: unauthenticated callers reaching state-changing
  endpoints.
- Authorization bypass: authenticated callers escaping their assigned
  scope (including agent ServiceAccounts trying to reach `approve` or
  `apply`).
- OPA bypass: state transitions occurring without an OPA decision
  being logged.
- Replay: captured request bundles re-submitted to re-trigger
  approvals, plans, or applies.
- Token spoofing: forged bearer tokens accepted by the API.

**Mitigations.**

- All v1.0 HTTP endpoints sit behind a bearer-auth middleware that
  validates either an OIDC token (issuer/audience/expiry/signature) or
  a single-tenant `STATEBOUND_DEV_TOKEN`. Public endpoints
  (`/healthz`, `/readyz`, `/openapi.yaml`) are explicitly allowlisted.
- All state transitions go through `internal/api`; OPA evaluates every
  request, and decision logs are mirrored into `audit_events` with
  stable cross-references (the project spec §13).
- The `apply` and `approve` endpoints are unreachable to any
  ServiceAccount whose entitlements deny them — enforced in OPA, not
  just absent in code (the project spec §22).
- v1.0 ships at parity: OIDC bearer auth + dev-token mode, plus
  signed plan bundles. Plans submitted to `apply` carry an Ed25519
  signature whose public key is registered via a ChangeSet and whose
  content hash pins the plan body.
- Audit events are append-only and hash-chained from v0.2 onward.
- Replay protection: every state-changing request mints a fresh
  audit event; idempotency keys are not required because the OPA
  layer rejects duplicate-state-transition attempts.

## 2. Database (core)

**Threats.**

- Audit-log tampering: rows deleted or rewritten to hide a
  state transition.
- Snapshot mutation: an approved version is altered after approval.
- Secret leakage through stored model content: a contributor accidentally
  embeds a credential in a YAML model that gets persisted.
- Out-of-band schema modification by a privileged Postgres operator.

**Mitigations.**

- `audit_events` is append-only with a SHA-256 hash chain
  (`current_event_hash = SHA256(previous_event_hash || canonical_json(event))`,
  the project spec §13). The chain is computed in a SQL function
  (`audit_event_hash()`) and verified by `statebound audit verify`.
  A privileged operator who deletes or modifies a row breaks the
  chain at the next verification.
- `approved_version_snapshots` stores the full model as JSONB and is
  immutable by domain rule. Any change creates a new draft and a new
  approved version (the project spec §2 principle 5).
- Statebound never stores secrets. Secret managers are referenced, not
  copied (the project spec §2 principle 7, §22). YAML import validation
  refuses fields that look like inline credentials and emits clear
  errors.
- Plan public keys are stored in `signing_keys`; private keys never
  enter the database.
- Out-of-band schema mutation is out of scope: a Postgres-superuser
  threat is mitigated by infrastructure controls (managed RDS, IAM,
  VPC isolation), not by Statebound itself.

## 3. RBAC and approvals

**Threats.**

- Approve-after-self-request: a user submits a ChangeSet and approves
  it themselves.
- Privilege escalation through RBAC: a non-admin grants themselves
  `admin` via the role-grant API.
- RBAC bootstrap exploitation: an attacker reaches the empty-binding
  bootstrap state on a freshly-installed system.

**Mitigations.**

- Four-eyes is enforced both in domain code and in the
  `four_eyes` Rego rule. The submitter and approver must be different
  identities; OPA returns deny if they match.
- `role:manage` requires the `admin` role in
  `domain.RolesForCapability`. Both the Go pre-check
  (`requireCapability`) and the `rbac_role_required` Rego rule consult
  the same mapping, so a UI-bypass attempt fails identically.
- The `--bootstrap` flag is single-use: it refuses to run once any
  admin binding exists in `actor_role_bindings`. Operators are
  documented to grant the first admin before exposing the system to
  non-trusted operators (`docs/security-model.md`).
- Every role grant and revoke is an audit event; `rbac.denied` is
  emitted on a denied operator action so a regulator can see the
  attempt.

## 4. Plan / Apply lifecycle

**Threats.**

- Privilege escalation through Plan or Apply: a connector is tricked
  into executing a Plan derived from an unapproved version.
- Apply with a stale or modified plan: a Plan body is mutated between
  generation and apply.
- Stolen signing key: an attacker mints valid plan signatures.
- Wildcard sudo escalation: a ChangeSet adds a wildcard sudo command
  that grants effective root.
- Secret leakage during `CollectActualState`: a connector pulls and
  stores credentials from a target system.

**Mitigations.**

- `Apply` requires a `Ready` Plan; Plans derived from drafts never
  reach Ready. The plan state machine is enforced in domain code.
- Plans are signed at `plan.ready` time with an operator-registered
  Ed25519 keypair. The signature covers a SHA-256 content hash of
  the canonicalized plan body. Apply re-hashes the plan and verifies
  the signature; mismatches abort with an audit event.
- Stolen signing key: the operator disables the key via a ChangeSet
  (`statebound key disable --key-id ...`), which marks the public
  key revoked in the database. Plans signed by the disabled key are
  refused at apply. Every signing-key state change is audited.
- The `wildcard_sudo` Rego rule flags any sudo command that contains
  a wildcard or unbounded argument, requiring elevated approval.
- `CollectActualState` is required by contract not to collect secrets;
  the Linux sudo and Postgres connectors are reviewed for compliance
  and ship with negative tests.

## 5. Drift detection

**Threats.**

- Drift undetected: actual-state changes that do not surface as
  findings, leaving the operator blind to silent privilege creep.
- Drift evidence omitted from evidence packs.

**Mitigations.**

- `drift scan` is deterministic; the same input produces the same
  `summary_hash`. Operators schedule scans and compare hashes over
  time to detect new findings.
- Evidence packs include drift-finding references, so an auditor
  pulling an evidence pack sees the as-of-now drift status alongside
  the approved version.

## 6. Reasoning plane (add-on)

**Status:** the reasoning add-on does not ship as part of core v1.0.
This section describes the threats that the add-on must mitigate when
it ships in `statebound-reason` v0.1+.

**Threats.**

- Prompt injection: an attacker embeds adversarial instructions in
  inputs the agent reads (drift findings, model YAML, tickets) and
  causes the agent to misbehave.
- Capability-scope escape: an agent attempts a tool call outside its
  declared `AllowedTools`.
- Model exfiltration of sensitive context: an agent's output channel
  carries inputs the policy intended to redact.
- Supply-chain risk on prompt bundles: a tampered or unsigned prompt
  bundle is loaded.
- Cloud inference exfiltration: an agent quietly routes context to a
  cloud backend.

**Mitigations.**

- Agents are bounded ServiceAccounts. Every tool call is OPA-evaluated
  against the agent's entitlements and recorded in `tool_calls`
  (the project spec §17).
- Agents have no `approve` or `apply` scope, enforced at OPA, not just
  absent in code (the project spec §22).
- Prompt bundles are content-addressed, signed at release, and refuse
  to load if unsigned in production mode (the project spec §17, §22).
- Cloud inference backends require per-agent policy approval; local
  inference is the default (the project spec §2 principle 13, §22).
- Every invocation produces an evidence-grade record (model id,
  prompt hash, input hash, output hash, tool-call trace, OPA
  decisions) — the project spec §14.
- Inputs and outputs are redacted before hashing where policy
  requires; redactions are documented (the project spec §22).

## 7. Build and release

**Threats.**

- Signed-artifact tampering: a release binary or Helm chart is replaced
  in transit or at the registry.
- Dependency confusion: a malicious package squats on a name imported
  by the build.
- Container-image tampering at registry-push time.

**Mitigations.**

- The v1.0 Helm chart, container image, and binary are released
  together with the same git tag. The container image is built
  from the multi-stage Dockerfile that pins
  `gcr.io/distroless/static-debian12:nonroot` as the runtime layer.
- Go module pinning and checksum verification, plus dependency
  review at PR time. CI verifies `go.mod` is tidy on every push.
- The Helm chart fails to render if both auth modes are missing or
  if `signing.devSkip=true` is combined with real OIDC — making
  silent insecure deployments hard to ship.

## 8. Deployment-time guarantees

**Threats.**

- Privilege escalation inside the cluster: a compromised statebound
  pod escalates through host-namespace volumes.
- Network exfiltration from a compromised pod.

**Mitigations.**

- The Helm chart sets the container security context to non-root,
  read-only root filesystem, no privilege escalation, all Linux
  capabilities dropped, and a `RuntimeDefault` seccomp profile.
- A NetworkPolicy is enabled by default with same-namespace ingress
  only. Egress is unrestricted by default (because operators wire
  to many external dependencies — Postgres, OIDC, OTel collector,
  KMS), but the chart exposes a clear extension point operators use
  to tighten egress.
- The distroless image has no shell, package manager, or libc, so
  post-exploitation pivots are limited to what the statebound binary
  itself can do.

## Out of scope for v1.0

- KMS-backed signing keys. v1.0 ships file-on-disk Ed25519 keys; KMS
  integration is a v1.1 candidate.
- Multi-tenant row-level security inside a single Postgres instance.
- SLSA-level supply-chain attestations and reproducible-build proofs.
- Per-connector fine-grained threat profiles (Kubernetes RBAC, LDAP).
- Privacy impact assessment.

These are tracked for the v1.x security review.

## References

- the project spec §13 — audit log rules.
- the project spec §14 — agent invocation provenance.
- the project spec §16 — connector contract.
- the project spec §17 — reasoning add-on contracts.
- the project spec §22 — security requirements.
- the project spec §23 — EU AI Act and agent provenance.
- `docs/security-model.md` — the security pillars summarized.
- `deploy/helm/statebound/README.md` — chart-level guarantees.
