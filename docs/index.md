---
hide:
  - navigation
  - toc
---

# Statebound

<p style="font-size: 1.15rem; line-height: 1.6; max-width: 42rem;">
<strong>Terminal-native authorization governance for regulated
infrastructure.</strong> Statebound replaces the spreadsheet,
the <code>RE: RE: RE:</code> approval thread, and the
"who-approved-this-in-2024-Q3" auditor question with versioned,
OPA-gated, hash-chained authorization models that emit reproducible
evidence packs on demand.
</p>

[Get started in 60 seconds :material-rocket-launch:](golden-path.md){ .md-button .md-button--primary }
[Why Statebound :material-help-circle-outline:](why-statebound.md){ .md-button }

---

## What you have today

A spreadsheet of who can `sudo` to prod. A Slack thread that ends in
"lgtm 👍". An audit email subject line that begins with
"RE: RE: RE: Re: FW:". Nobody quite remembers who approved which
sudoers line in 2024 Q3, only that "Greg said it was fine, but Greg
left in October."

The auditor lands on Tuesday.

## What Statebound is

Statebound is what `terraform` would be if it governed authorization
instead of infrastructure. You write what access **should** exist in
YAML, two humans look at it, [OPA](https://www.openpolicyagent.org/)
looks at it, the resulting state is immutable, and you can ask the
binary to print an audit-ready Markdown report at any time.

It runs in your terminal, talks to a Postgres, and ships a small Helm
chart. The deterministic core is a complete product on its own; an
**optional** reasoning add-on (`statebound-reason`) adds bounded AI
assist that proposes drafts but never decides.

!!! info "Statebound is not"
    An IGA replacement, a PAM, or a generic IAM portal. See
    [Why Statebound](why-statebound.md) for the long version,
    including how it compares to those.

## What's in v1.0

<div class="grid cards" markdown>

-   :material-file-tree:{ .lg .middle } **Authorization model**

    ---

    Products, Assets, AssetScopes, Entitlements, ServiceAccounts,
    GlobalObjects, Authorizations. YAML in, validated, versioned.

-   :material-source-pull:{ .lg .middle } **ChangeSets + four-eyes**

    ---

    Diffable drafts, immutable approved versions, hash-chained audit
    log. `statebound audit verify` walks the chain.

-   :material-shield-check:{ .lg .middle } **OPA + Rego**

    ---

    Nine built-in rules (wildcard sudo, root-equiv, prod-requires-
    approval, four-eyes, RBAC…), 41 unit tests, `policy test/eval`.

-   :material-file-document-multiple:{ .lg .middle } **Evidence engine**

    ---

    Deterministic JSON + Markdown export. Re-export the same approved
    version, get byte-identical bytes, get the same SHA-256.

-   :material-connection:{ .lg .middle } **Connectors**

    ---

    Linux sudo, Linux SSH (plan-only), PostgreSQL (plan + collect +
    compare + apply with SQL DCL inside a transaction).

-   :material-radar:{ .lg .middle } **Drift detection**

    ---

    `statebound drift scan` produces deterministic findings with a
    reproducible summary hash.

-   :material-lock-check:{ .lg .middle } **Apply gate**

    ---

    Refuses unsigned plans. Refuses without admin role. OPA
    re-evaluates at apply time.

-   :material-account-key:{ .lg .middle } **RBAC + signed plans**

    ---

    Five non-hierarchical roles, bootstrap-once gate. Ed25519-signed
    plan bundles with disable-able keys.

-   :material-eye-outline:{ .lg .middle } **OpenTelemetry**

    ---

    Opt-in tracing, no PII by default, `statebound.*` attribute
    conventions.

-   :material-api:{ .lg .middle } **HTTP API**

    ---

    `statebound api serve` with OpenAPI 3.1 + OIDC bearer auth. 22
    read-only endpoints. The surface the reasoning add-on calls
    into.

-   :material-docker:{ .lg .middle } **Distroless image**

    ---

    ~55 MB, runs as nonroot uid 65532. Helm chart with NetworkPolicy,
    runAsNonRoot, secret-backed signing key.

-   :material-robot-outline:{ .lg .middle } **Self-governed AI**

    ---

    The optional reasoning add-on subjects every agent to the same
    governance rigor it sells to customers. Agents propose, OPA and
    humans decide.

</div>

## What an evidence pack looks like

`statebound evidence export --product payments-api --format markdown`
produces this — full pack covers every audit event, every policy
decision, every drift scan.

```markdown
# Evidence Pack — payments-api v1

- Generated: 2026-05-01T12:52:00.565092Z
- Approved by: bob (human)
- Approved at: 2026-05-01T12:52:00.565092Z
- Snapshot hash: sha256:d913d5471a55
- Source change set: 3879c88f-8933-4a20-aabf-c5b7d4a45919

## Approvals
| Actor       | Decision | Reason | Decided at |
|-------------|----------|--------|------------|
| bob (human) | approved | —      | 2026-05-01T12:52:00.572101Z |

## Policy decisions

### approve — escalate_required
- Bundle hash: sha256:7f339e4afdae

| Rule                   | Outcome             | Message                                                        |
|------------------------|---------------------|----------------------------------------------------------------|
| prod_requires_approval | escalate_required   | production change requires approved approval before apply     |

## Audit events
| # | Kind                     | Actor         | Resource                  | Hash         |
|---|--------------------------|---------------|---------------------------|--------------|
| 1 | changeset.created        | alice (human) | change_set/3879c88f       | c35159c1989e |
| 2 | policy.evaluated         | alice (human) | change_set/3879c88f       | 00594ad919e8 |
| 3 | changeset.submitted      | alice (human) | change_set/3879c88f       | 03fed90bd4e9 |
| 4 | policy.evaluated         | bob (human)   | change_set/3879c88f       | 0e4c249b65c1 |
| 5 | approval.recorded        | bob (human)   | approval/ab199f09         | 4aa2fb34ba0c |
| 6 | approved_version.created | bob (human)   | approved_version/afcf423b | b6cec1940eb7 |
| 7 | changeset.approved       | bob (human)   | change_set/3879c88f       | b96a510bc4f3 |
```

This is what you hand the auditor. They read Markdown. They like
hashes. They love that two re-exports return the same bytes.

## Quickstart (60 seconds)

```bash
git clone https://github.com/rupivbluegreen/statebound
cd statebound
make docker-app-up                           # Postgres + API container
curl -fsS http://localhost:8080/healthz      # → 200 OK
curl -fsS -H "Authorization: Bearer local-dev" \
     http://localhost:8080/v1/products
```

For the full eight-step walk that exercises every capability,
see the [Golden path](golden-path.md).

## Agents propose, humans and OPA decide

Statebound is built so that the optional reasoning add-on
(`statebound-reason`) can be removed, replaced, or never installed
without affecting core behavior. When the add-on is present, every
agent is a registered ServiceAccount with versioned, approved
entitlements; every agent invocation is audited with model identity,
prompt hash, input hash, output hash, tool-call trace, and any OPA
decisions referenced.

!!! warning "The hard line"
    Agents draft, classify, summarize, and narrate. **Agents never
    approve, apply, or modify approved state.** The boundary is
    enforced in OPA, not just absent from code.

In other words: the AI does not get to write its own access policies,
and the audit trail can prove it.

## Get involved

- :material-bug: Bugs and feature requests: [GitHub Issues](https://github.com/rupivbluegreen/statebound/issues)
- :material-shield-bug: Vulnerabilities: see [SECURITY.md](https://github.com/rupivbluegreen/statebound/blob/main/SECURITY.md)
- :material-source-fork: Pull requests: see [CONTRIBUTING.md](https://github.com/rupivbluegreen/statebound/blob/main/CONTRIBUTING.md)
- :material-source-branch: License: Apache 2.0
