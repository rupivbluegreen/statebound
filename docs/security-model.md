# Security Model

This document summarizes the security pillars that Statebound is built
around. The authoritative list of requirements is the project spec §22;
this document gives a paragraph of context per pillar so contributors
can reason about why a given rule exists. Phase 8 wave C consolidated
the v1.0 picture: the pillars below describe what a v1.0 deployment
actually delivers.

## Immutable approved versions

An `ApprovedVersion` is the desired-state snapshot that has cleared
four-eyes approval and OPA evaluation. It is immutable by domain rule:
any change creates a new draft, change set, or version. Apply
operations target an approved version, never a draft. This is what
makes Statebound replayable and what gives auditors a stable artifact
to point at. See the project spec §2 principles 3 and 5, §22.

## Four-eyes approval

Submitter and approver must be different identities in four-eyes mode.
The rule is enforced by OPA, not just by UI affordance, so it cannot
be bypassed by a direct API call. Elevated approval applies for
high-risk changes (root-equivalent authorizations, wildcard sudo,
production scopes). See the project spec §15.

## OPA as the sole policy gate

OPA / Rego is the primary policy engine and the only gate on ChangeSet
admission, plan-to-apply transitions, and agent tool dispatch. There is
no "fast path" that bypasses OPA. Every decision is logged and mirrored
into the audit stream with a stable cross-reference, so an evidence pack
can reproduce the verdict that gated each transition. Built-in Rego
rules ship in `policies/builtin/`; custom rules are authored by the
operator. The Rego bundle is embedded into the binary via `go:embed`,
so an attacker cannot swap in a permissive rule by writing to the
container's filesystem. See the project spec §13, §15.

## Append-only, hash-chained audit log

`audit_events` is append-only. Starting at v0.2, every event hashes the
previous event into its own hash:
`current_event_hash = SHA256(previous_event_hash || canonical_json(event))`.
This makes silent tampering detectable: any inserted, deleted, or
modified row breaks the chain at the verification step
(`statebound audit verify`). OPA decision logs are mirrored into this
stream so that policy verdicts and product state share one tamper-
evident timeline. See the project spec §13, §22.

## No secret storage

Statebound never stores passwords, private keys, tokens, or database
credentials. Connectors and inference backends integrate with Vault,
PAM, or secret managers by reference only. This keeps the database
out of scope for credential-leak threats and simplifies the
compliance story. The same rule extends to evidence packs and agent
invocation records: redact before hashing if a secret might appear
in inputs or outputs, and document the redaction. The Helm chart
mirrors this rule — it accepts secret *references* (`passwordSecretRef`,
`privateKeySecretRef`) and never inlines values. See the project spec
§2 principle 7, §22.

## Connector least privilege

Connectors run in isolated processes (or sidecars) with the minimum
target-system privilege required to plan, apply, or collect actual
state. Network egress is opt-in and policy-gated. Connector failures
must not corrupt the core model — connectors do not own domain
objects, they only translate. Every connector ships with dry-run
tests. See the project spec §2 principle 9, §16, §22.

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
self-governance claim honest. See the project spec §2 principles 11–14,
§14, §17, §19, §22.

## Operator RBAC (Phase 8 wave A)

Statebound ships five non-hierarchical operator roles: `viewer`,
`requester`, `approver`, `operator`, and `admin`. Each gated CLI
command (model import, approval request/approve/reject, plan, drift
scan, apply --dry-run, apply --apply, role grant/revoke) calls a
small Go pre-check helper (`internal/cli.requireCapability`) that
intersects the actor's currently-active roles with the roles that
grant the requested capability. The check fires before any
transaction opens; on denial it emits an `rbac.denied` audit event
and returns an actionable error.

Roles are non-hierarchical on purpose — `admin` does NOT auto-imply
`approver` so segregation-of-duties detection stays clean. An actor
that needs both responsibilities is granted both roles explicitly,
and the audit log records both grants.

The same mapping is exposed to OPA as `input.capability_roles` and
checked by the built-in `rbac_role_required` rule
(`policies/builtin/rbac.rego`). The Go pre-check is the authoritative
gate; the Rego rule is the policy-decision-log audit trail. Both
paths read `domain.RolesForCapability` so the mapping has a single
source of truth.

### Bootstrap path (known weakness)

When `actor_role_bindings` is empty Statebound opens the gate for
every operation and writes a stderr warning: this is the bootstrap
state, where no admin yet exists to grant the first role. Operators
seed the first admin via:

```
statebound role grant --bootstrap --actor human:alice@example.com --role admin
```

`--bootstrap` refuses once any admin binding exists, so the escape
hatch is single-use. **In production rollouts the first admin must
be granted before the system is exposed to non-trusted operators.**

## Signed plan bundles (Phase 8 wave A)

Every Plan is signed at `plan.ready` time with an Ed25519 keypair
minted by `statebound key generate`. The private half stays on disk
(or in a secret manager referenced by the operator); the public half
is registered via a ChangeSet and stored in the `signing_keys` table.
The signature covers a SHA-256 content hash of the canonicalized
plan body, so any post-signing mutation is detected on apply.

Apply re-hashes the plan, looks up the public key, and verifies the
signature before executing the connector. A revoked or unknown key
aborts apply with an audit event. `STATEBOUND_DEV_SKIP_PLAN_SIGNATURE`
exists for local development only — the Helm chart refuses to render
when this is combined with real OIDC, so the production posture
cannot quietly regress.

## OIDC bearer auth + dev token (Phase 8 wave B)

The HTTP API authenticates every request via the
`internal/api/middleware.go` bearer-auth pipeline. Two authentication
modes are supported, mutually exclusive at deployment time:

1. **OIDC.** `STATEBOUND_OIDC_ISSUER` + `STATEBOUND_OIDC_AUDIENCE`
   enable OIDC discovery, JWKS fetch, and per-request signature +
   expiry + audience validation. The actor identity comes from the
   token's `sub` claim. This is the production path.
2. **Dev token.** `STATEBOUND_DEV_TOKEN` is a single bearer that
   maps every request to `STATEBOUND_DEV_ACTOR`. Local development
   only. The Helm chart will set this only when no OIDC issuer is
   configured.

`/healthz`, `/readyz`, and `/openapi.yaml` are explicit public-route
allowlists; every other endpoint refuses unauthenticated requests
with `401`.

## OpenTelemetry tracing (Phase 8 wave A)

OpenTelemetry tracing is OFF by default. Enable it by setting
`STATEBOUND_OTEL_EXPORTER` to `otlp-grpc`, `otlp-http`, or `stdout`.
Span attributes are PII-safe by default — actor identity is omitted
unless the operator opts in via `STATEBOUND_OTEL_ATTR_ACTOR=true`.
This is the same posture documented in `docs/observability.md`. OTel
init failures never abort the run: observability should never break
the control plane.

## Deployment-time security (Phase 8 wave C)

The v1.0 container and Helm chart enforce these defaults:

- **Distroless runtime.** The image is
  `gcr.io/distroless/static-debian12:nonroot`. No shell, no package
  manager, no libc. The attack surface is the statebound binary.
- **Non-root, read-only filesystem.** The Pod and container security
  contexts assert `runAsNonRoot: true`, `runAsUser: 65532`,
  `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`,
  all Linux capabilities dropped, `seccompProfile: RuntimeDefault`.
- **Default-deny ingress.** A NetworkPolicy is enabled by default
  with same-namespace ingress only.
- **Single-bearer-token Secret.** When the operator picks dev-token
  mode, the chart provisions one Kubernetes Secret holding the token.
  Production deployments use OIDC and never render the Secret at all.
- **Sanity-check fail-fast.** The chart fails to render if neither
  OIDC nor a dev token is set, and refuses to combine
  `signing.devSkip=true` with real OIDC.

## References

- the project spec §22 — full security requirements list.
- the project spec §13 — audit log rules.
- the project spec §14 — agent invocation provenance.
- the project spec §15 — policy and risk rules.
- `docs/threat-model.md` — Phase 1–8 threat surfaces and mitigations.
- `docs/observability.md` — OpenTelemetry tracing posture (off by
  default; PII-safe defaults; opt-in actor attribution).
- `docs/adr/0001-reasoning-as-addon.md` — why the AI layer is
  separable.
- `deploy/helm/statebound/README.md` — chart-level guarantees.
