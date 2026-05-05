# Security policy

Statebound is a security-governance product. Vulnerability reports
are taken seriously and triaged ahead of feature work.

## Reporting a vulnerability

**Do not file a public GitHub issue.** Public reporting tips off
attackers before users have a chance to upgrade.

Email a description of the issue to:

```
security@statebound.dev
```

(GPG / age public keys will be published here once we have them
attorney-cleared. Until then, plain email is acceptable for the
initial contact; the maintainer will arrange an encrypted channel for
sensitive details before you transmit them.)

Please include:

- A description of the vulnerability and the affected component
  (core CLI, HTTP API, Rego rule library, connector, Helm chart).
- The Statebound version and commit SHA you reproduced against.
- Steps to reproduce, ideally a minimal test case or PoC.
- The impact you observed and your assessment of severity.
- Whether the issue is publicly known elsewhere.
- Your preferred public credit name (or "anonymous").

You will receive an acknowledgement within **3 business days**.

## Disclosure timeline

Statebound follows a **90-day coordinated disclosure** window from
the date of acknowledgement:

| Day  | Milestone                                                                |
|------|--------------------------------------------------------------------------|
| 0    | Vulnerability acknowledged by maintainer.                                |
| 7    | Severity classified; remediation plan drafted; reporter informed.        |
| 30   | Patch in progress; reporter informed of ETA.                             |
| 60   | Patch released or, if unreleasable in time, a coordinated extension.    |
| 90   | Public disclosure: CVE filed, advisory published, release notes updated.|

Critical vulnerabilities (RCE, signing-key compromise, audit-log
forgery) may compress the timeline; reporter is consulted before the
timeline shifts.

## In scope

- The `statebound` core binary (CLI, TUI, HTTP API).
- The `statebound-reason` add-on once it ships.
- The Rego rule library (`policies/builtin/`).
- The Linux sudo, Linux SSH, and PostgreSQL connectors shipped in
  `internal/connectors/`.
- The Docker image published to `ghcr.io/rupivbluegreen/statebound`.
- The Helm chart in `deploy/helm/statebound/`.
- The OpenAPI 3.1 spec at `schemas/openapi.yaml`.

## Out of scope

- Vulnerabilities in third-party dependencies — please report
  upstream. We monitor advisories via Dependabot and ship updates
  promptly when an upstream patch is available.
- Hypothetical issues that depend on the operator running with a
  privileged Postgres superuser account, mounting a writable
  `/etc/sudoers` directly, or otherwise bypassing the standard
  deployment posture documented in
  [`docs/security-model.md`](docs/security-model.md).
- Denial-of-service through resource exhaustion of a system that
  does not have rate limits or quotas configured. The Helm chart
  ships a `LimitRange`-friendly default; misuse without those is
  out of scope.
- Social-engineering attacks against project maintainers.
- Public information disclosure (e.g. version numbers, public
  endpoint enumeration).

If you are unsure whether your finding is in scope, send the report
anyway. We would rather triage an out-of-scope report than miss a
valid one.

## Safe-harbor commitment

We will not pursue legal action against researchers who:

- Make a good-faith effort to follow this policy.
- Avoid privacy violations, destruction of data, or interruption of
  service.
- Test only against their own deployments — not against any
  third-party Statebound instance you do not control.

## Past advisories

None yet. As advisories are published they will be linked here
and from the GitHub Security Advisories tab.

## Cryptographic primitives

For reference: Statebound uses Ed25519 for plan-bundle signatures,
SHA-256 for content hashes, and the SQL-side `audit_event_hash()`
function (pgcrypto) for audit-chain integrity. If you find a
weakness in our use of these primitives — not in the primitives
themselves — that is in scope.
