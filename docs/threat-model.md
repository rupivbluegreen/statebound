# Threat Model (Phase 0 draft)

> **Status: draft.** This is the Phase 0 starter. A full review is
> scheduled for Phase 8 (core v1.0). Sections marked _draft_ will be
> expanded as the relevant subsystems land. See `the project spec` §22
> (security requirements) and §29 (roadmap).

The product separates into a deterministic core (`statebound`) and an
optional reasoning add-on (`statebound-reason`). The threat surfaces
below are organized by subsystem boundary rather than by attacker
profile, which we expect to formalize in the Phase 8 review.

## 1. API surface (core) _draft_

**Threats.**

- Authentication bypass: unauthenticated callers reaching state-changing
  endpoints.
- Authorization bypass: authenticated callers escaping their assigned
  scope (including agent ServiceAccounts trying to reach `approve` or
  `apply`).
- OPA bypass: state transitions occurring without an OPA decision being
  logged.
- Replay: captured request bundles re-submitted to re-trigger
  approvals, plans, or applies.

**Mitigations.**

- All state transitions go through `internal/api`; OPA evaluates every
  request, and decision logs are mirrored into `audit_events` with
  stable cross-references (`the project spec` §13).
- The `apply` and `approve` endpoints are unreachable to any
  ServiceAccount whose entitlements deny them — enforced in OPA, not
  just absent in code (`the project spec` §22).
- v1.0 introduces OIDC login and signed plan bundles; until then,
  development deployments rely on local-only access.
- Audit events are append-only and hash-chained from v0.2 onward.

## 2. Database (core) _draft_

**Threats.**

- Audit-log tampering: rows deleted or rewritten to hide a
  state transition.
- Snapshot mutation: an approved version is altered after approval.
- Secret leakage through stored model content: a contributor accidentally
  embeds a credential in a YAML model that gets persisted.

**Mitigations.**

- `audit_events` is append-only with a SHA-256 hash chain
  (`current_event_hash = SHA256(previous_event_hash || canonical_json(event))`,
  `the project spec` §13).
- `approved_version_snapshots` stores the full model as JSONB and is
  immutable by domain rule. Any change creates a new draft and a new
  approved version (`the project spec` §2 principle 5).
- Statebound never stores secrets. Secret managers are referenced, not
  copied (`the project spec` §2 principle 7, §22). YAML import validation
  refuses fields that look like inline credentials and emits clear
  errors.

## 3. Connector boundary _draft_

**Threats.**

- Privilege escalation through Plan or Apply: a connector is tricked
  into executing a Plan derived from an unapproved version.
- Secret leakage during `CollectActualState`: a connector pulls and
  stores credentials from a target system.
- Connector compromise propagating into core domain objects.

**Mitigations.**

- `Apply` requires an approved Plan (`the project spec` §16). Plans derived
  from drafts are refused.
- `CollectActualState` must not collect secrets — this is part of the
  connector contract and is verified per connector (`the project spec` §16,
  §22).
- Connectors run in least-privilege processes, isolated from the core
  binary unless trivial (`the project spec` §7). Connector-specific state
  cannot leak into core domain objects unless represented generically.

## 4. Reasoning plane (add-on) _draft_

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
  (`the project spec` §17).
- Agents have no `approve` or `apply` scope, enforced at OPA, not just
  absent in code (`the project spec` §22).
- Prompt bundles are content-addressed, signed at release, and refuse
  to load if unsigned in production mode (`the project spec` §17, §22).
- Cloud inference backends require per-agent policy approval; local
  inference is the default (`the project spec` §2 principle 13, §22).
- Every invocation produces an evidence-grade record (model id,
  prompt hash, input hash, output hash, tool-call trace, OPA
  decisions) — `the project spec` §14.
- Inputs and outputs are redacted before hashing where policy
  requires; redactions are documented (`the project spec` §22).

## 5. Build and release _draft_

**Threats.**

- Signed-artifact tampering: a release binary or Helm chart is replaced
  in transit or at the registry.
- Dependency confusion: a malicious package squats on a name imported
  by the build.
- Prompt-bundle tampering at build time.

**Mitigations.**

- v1.0 ships signed plan bundles and signed agent invocations.
- The add-on's prompt bundles are signed at release; runtime verifies
  signatures in production mode (`the project spec` §17, §22).
- Go module pinning and checksum verification, plus dependency
  review at PR time. SBOM exports for the add-on at v1.0 cover agent
  versions, prompt hashes, and model identities (`the project spec` §23).
- Reviewer guidance: every new permission or new dependency requires
  explicit justification in the PR description.

## Out of scope for Phase 0

- Formal STRIDE per endpoint.
- Privacy impact assessment.
- Per-connector threat profiles.
- Quantitative risk scoring.

These are tracked for Phase 8 and the v1.0 security review.

## References

- `the project spec` §13 — audit log rules.
- `the project spec` §14 — agent invocation provenance.
- `the project spec` §16 — connector contract.
- `the project spec` §17 — reasoning add-on contracts.
- `the project spec` §22 — security requirements.
- `the project spec` §23 — EU AI Act and agent provenance.
- `docs/security-model.md` — the seven security pillars summarized.
