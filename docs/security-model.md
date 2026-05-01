# Security Model

This document summarizes the security pillars that Statebound is built
around. The authoritative list of requirements is `the project spec` §22; this
document gives one paragraph of context per pillar so contributors can
reason about why a given rule exists.

## Immutable approved versions

An `ApprovedVersion` is the desired-state snapshot that has cleared
four-eyes approval and OPA evaluation. It is immutable by domain rule:
any change creates a new draft, change set, or version. Apply
operations target an approved version, never a draft. This is what
makes Statebound replayable and what gives auditors a stable artifact
to point at. See `the project spec` §2 principles 3 and 5, §22.

## Four-eyes approval

Submitter and approver must be different identities in four-eyes mode.
The rule is enforced by OPA, not just by UI affordance, so it cannot
be bypassed by a direct API call. Elevated approval applies for
high-risk changes (root-equivalent authorizations, wildcard sudo,
production scopes). See `the project spec` §15.

## OPA as the sole policy gate

OPA / Rego is the primary policy engine and the only gate on ChangeSet
admission, plan-to-apply transitions, and agent tool dispatch. There is
no "fast path" that bypasses OPA. Every decision is logged and mirrored
into the audit stream with a stable cross-reference, so an evidence pack
can reproduce the verdict that gated each transition. Built-in Rego
rules ship in `policies/builtin/`; custom rules are authored by the
operator. See `the project spec` §13, §15.

## Append-only, hash-chained audit log

`audit_events` is append-only. Starting at v0.2, every event hashes the
previous event into its own hash:
`current_event_hash = SHA256(previous_event_hash || canonical_json(event))`.
This makes silent tampering detectable: any inserted, deleted, or
modified row breaks the chain at the verification step. OPA decision
logs are mirrored into this stream so that policy verdicts and product
state share one tamper-evident timeline. See `the project spec` §13, §22.

## No secret storage

Statebound never stores passwords, private keys, tokens, or database
credentials. Connectors and inference backends integrate with Vault,
PAM, or secret managers by reference only. This keeps the database
out of scope for credential-leak threats and simplifies the
compliance story. The same rule extends to evidence packs and agent
invocation records: redact before hashing if a secret might appear
in inputs or outputs, and document the redaction. See `the project spec` §2
principle 7, §22.

## Connector least privilege

Connectors run in isolated processes (or sidecars) with the minimum
target-system privilege required to plan, apply, or collect actual
state. Network egress is opt-in and policy-gated. Connector failures
must not corrupt the core model — connectors do not own domain
objects, they only translate. Every connector ships with dry-run
tests. See `the project spec` §2 principle 9, §16, §22.

## Agent self-governance

When the reasoning add-on is installed, every agent is a registered
ServiceAccount with versioned, approved entitlements and a bounded
capability scope. Adding, modifying, or upgrading an agent is itself
a ChangeSet that goes through the same approval and OPA flow as any
other change. No agent has `approve` or `apply` scope — enforced at
OPA, not just absent in code. Cloud inference backends require
per-agent policy approval. Prompt bundles are signed in production
mode. Every invocation produces an evidence-grade provenance record.
This is what makes the AI layer audit-defensible and what makes the
self-governance claim honest. See `the project spec` §2 principles 11–14,
§14, §17, §19, §22.

## References

- `the project spec` §22 — full security requirements list.
- `the project spec` §13 — audit log rules.
- `the project spec` §14 — agent invocation provenance.
- `the project spec` §15 — policy and risk rules.
- `docs/threat-model.md` — Phase 0 threat surfaces and mitigations.
- `docs/adr/0001-reasoning-as-addon.md` — why the AI layer is
  separable.
