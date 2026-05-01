# ADR 0001: Reasoning is an add-on, not a dependency

- Status: Accepted
- Date: 2026-05-01

## Context

Earlier drafts of the product (CLAUDE.md v2 and prior) described the
reasoning plane as an in-tree sidecar that shipped alongside the
deterministic core. CLAUDE.md v2.1 clarified this: the reasoning plane
is fully optional, separately shipped, and separately versioned. It is
not part of the core product.

The motivating constraints:

- Regulated buyers (finance, healthcare, public sector) want to adopt
  the deterministic governance product without simultaneously taking on
  the procurement, risk, and compliance burden of an AI system.
- Air-gapped and no-GPU environments must be fully supported.
- The "self-governance" claim — that Statebound governs its own AI
  assistants with the same primitives it sells to customers — is only
  honest if the AI layer is structurally separable from the core.
- Independent release cadence lets the core stabilize at v1.0 without
  being held back by AI features, and lets the add-on iterate quickly
  without destabilizing the core.

Reference: CLAUDE.md preamble ("Changelog vs v2"), §6, §8, §29.

## Decision

The reasoning plane ships as a separate product, `statebound-reason`,
with the following hard commitments:

1. **Separate binary.** `statebound-reason` is its own executable. The
   `statebound` core binary builds and runs without it.
2. **Separate Docker image.** Two independent images. Operators pull
   only what they deploy.
3. **Separate Helm chart.** Either two independent charts or one
   umbrella chart with the add-on disabled by default.
4. **Separate `go.mod`.** The add-on is its own Go module — either a
   sibling repository or a sub-module in the same repo. Either way,
   no shared internal packages.
5. **No compile-time dependency from core to add-on.** The core does
   not import any add-on package, ever.
6. **No runtime dependency from core to add-on.** The core does not
   call out to the add-on, watch for it, or branch on its presence
   except to render graceful-degradation messages.
7. **No schema dependency from core to add-on.** Agent-related tables
   (`agents`, `agent_versions`, `prompt_bundles`, `inference_backends`,
   `agent_invocations`, `tool_calls`) live in extension migrations
   shipped with the add-on. Core migrations never reference them.
8. **Add-on talks to core only through the public API.** The add-on
   authenticates as a registered ServiceAccount over the same
   HTTP/JSON API exposed to humans and external clients. Every call
   is OPA-evaluated and audited identically.
9. **TUI/CLI gracefully degrade.** Agent-related views and
   subcommands exist as stubs in the core that return a neutral
   "reasoning add-on not installed" message. They never error and
   never nag.

## Consequences

### Positive

- Regulated buyers can adopt the core product without taking on AI
  risk. Procurement and compliance review scope is bounded.
- Air-gapped and no-GPU deployments are first-class. No feature is
  marked "degraded" for them.
- Self-governance is structurally honest: the same governance
  primitives gate the AI layer, and uninstalling the AI layer leaves
  no privileged residue.
- Release cadences decouple. Core can ship v1.0 long before the
  add-on does.

### Negative

- Some configuration is duplicated across core and add-on (database
  connection strings, OIDC settings). Tooling will need to keep both
  in sync for combined deployments.
- Auditors must verify in practice that uninstalling the add-on
  leaves the core clean. The architecture supports this; the test
  harness must prove it.
- Release coordination overhead: a feature that touches both
  surfaces (e.g., a new tool the agent needs) requires a coordinated
  core API change and an add-on consumer change, on different
  release timelines.
- Documentation must be careful to mark which features belong to
  which artifact. Mixing them in user docs creates the impression of
  a single product.

## References

- CLAUDE.md §6 (three-plane architecture, two deployment artifacts).
- CLAUDE.md §8 (repository layout and boundary rules).
- CLAUDE.md §29 (independent release cadences).
