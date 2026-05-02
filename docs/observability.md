# Observability

Statebound's CLI emits OpenTelemetry traces on every plan, apply, drift
scan, evidence export, approval, and policy evaluation. **Tracing is
off by default.** With no `STATEBOUND_OTEL_*` environment variable
set, the SDK installs a no-op tracer and the per-span overhead in the
CLI hot paths is one nil-method call. Operators opt in by setting the
exporter env var; everything else has a sensible default.

v1.0 ships **traces only**. Metrics (Prometheus exporter, RED
counters, host-process metrics) and storage-layer pgx instrumentation
(`otel-pgx`) are deferred to a future v1.x release.

## What is traced

| Span name           | Emitted by                      | Notes |
|---------------------|---------------------------------|-------|
| `plan.generate`     | `statebound plan`               | One per CLI invocation. Children: `connector.plan`, `policy.evaluate`, `plan.persist`. |
| `connector.plan`    | inside `plan.generate`          | Wraps `Connector.ValidateDesiredState` + `Connector.Plan`. Carries connector + version. |
| `apply.execute`     | `statebound apply`              | One per CLI invocation. Child: `connector.apply`. |
| `connector.apply`   | inside `apply.execute`          | Wraps `Connector.Apply`. Carries dry-run flag and item count. |
| `drift.scan`        | `statebound drift scan`         | One per CLI invocation. Child: `connector.drift_scan`. |
| `connector.drift_scan` | inside `drift.scan`          | Wraps `CollectActualState` + `Compare`. Carries finding count. |
| `evidence.export`   | `statebound evidence export`    | One per CLI invocation. Carries pack id + content hash. |
| `approval.approve`  | `statebound approval approve`   | One per CLI invocation. Carries change-set id and resulting sequence. |
| `policy.evaluate`   | every OPA gate                  | Carries phase (`submit`/`approve`/`plan`/`apply`) and outcome. |

Spans never carry secrets. Plan content, evidence content, drift
finding bodies — none of those flow into span attributes.

## What is NOT traced (yet)

- Storage-layer pgx queries (deferred to a future v1.x release).
- HTTP API endpoints (the v1.0 `statebound api serve` middleware
  records request-id + slog access logs but does not yet emit OTel
  spans for inbound HTTP requests; planned for a future v1.x).
- Connector internals (deliberate — keeps the connector contract
  observability-agnostic).
- The reasoning add-on. Agent invocations are traced separately by
  `statebound-reason` once it ships.

## Enabling traces

Set one or more of these env vars:

| Variable | Values | Default | Meaning |
|----------|--------|---------|---------|
| `STATEBOUND_OTEL_EXPORTER` | `otlp-grpc`, `otlp-http`, `stdout`, `""` (off) | `""` | Picks the exporter. Empty disables tracing. |
| `STATEBOUND_OTEL_ENDPOINT` | host:port (gRPC) or URL (HTTP) | `localhost:4317` (gRPC) / `http://localhost:4318` (HTTP) | Collector endpoint. Ignored for `stdout`. |
| `STATEBOUND_OTEL_SERVICE_NAME` | string | `statebound` | OTel `service.name` resource attribute. |
| `STATEBOUND_OTEL_INSECURE` | `true`/`false` | `true` | gRPC: skip TLS. Default true since the local-collector pattern is usually plaintext. |
| `STATEBOUND_OTEL_SAMPLER` | `""`, `always`, `never`, `ratio:N` | `""` (parent-based always-on) | Trace sampler. |
| `STATEBOUND_OTEL_INCLUDE_ACTOR` | `true`/`false` | `false` | Opt-in to attaching `statebound.actor_kind` and `statebound.actor_subject` to spans. **Off by default — actor subjects can be PII.** |

The standard OTel envs (`OTEL_RESOURCE_ATTRIBUTES`, etc.) are also
honoured by the SDK so operators can layer additional resource
attributes without a code change.

## How to consume traces

### Local development (stdout)

```sh
STATEBOUND_OTEL_EXPORTER=stdout statebound plan \
  --product payments-api --connector linux-sudo --output /tmp/plan.json
```

Spans print to the binary's stdout as JSON. Pipe to `jq` to inspect.

### Local collector (Jaeger / Tempo / OTel Collector)

```sh
docker run --rm -d -p 4317:4317 -p 16686:16686 jaegertracing/all-in-one
STATEBOUND_OTEL_EXPORTER=otlp-grpc \
STATEBOUND_OTEL_ENDPOINT=localhost:4317 \
  statebound plan --product payments-api --connector linux-sudo
```

Browse the trace at <http://localhost:16686>.

### Production (TLS-fronted collector)

```sh
STATEBOUND_OTEL_EXPORTER=otlp-grpc \
STATEBOUND_OTEL_ENDPOINT=collector.example:4317 \
STATEBOUND_OTEL_INSECURE=false \
STATEBOUND_OTEL_SAMPLER=ratio:0.1 \
  statebound apply <plan-id> --apply
```

`STATEBOUND_OTEL_SAMPLER=ratio:0.1` keeps cost predictable on
high-volume CI fleets while preserving full traces for the 10% sample.

## Span attribute conventions

All Statebound-specific keys carry the `statebound.` prefix. Keys are
chosen to be **low-cardinality** so a future metrics layer can reuse
them as labels without explosion. UUID-shaped attributes
(`statebound.plan_id`, `statebound.change_set_id`, etc.) are present
on spans for debuggability but **must not become metric labels** when
the future metrics layer lands; switch to enums (e.g. policy outcome)
for metric dimensions.

| Attribute | Cardinality | Notes |
|-----------|-------------|-------|
| `statebound.connector` | low | e.g. `linux-sudo`, `postgres` |
| `statebound.connector_version` | low | one per release |
| `statebound.product` | low–medium | product name |
| `statebound.product_id` | high | UUID; span only |
| `statebound.approved_version` | low per product | sequence number |
| `statebound.change_set_id` | high | UUID; span only |
| `statebound.plan_id` | high | UUID; span only |
| `statebound.apply_id` | high | UUID; span only |
| `statebound.drift_scan_id` | high | UUID; span only |
| `statebound.evidence_pack_id` | high | UUID; span only |
| `statebound.policy_outcome` | low | `allow` / `deny` / `escalate_required` |
| `statebound.policy_phase` | low | `submit` / `approve` / `plan` / `apply` |
| `statebound.evidence_format` | low | `json` / `markdown` |
| `statebound.apply_dry_run` | low | bool |
| `statebound.finding_count` | low | small integer |
| `statebound.item_count` | low | small integer |
| `statebound.actor_kind` | low | opt-in via `STATEBOUND_OTEL_INCLUDE_ACTOR=true` |
| `statebound.actor_subject` | high | opt-in only — PII |

## PII posture

By default, no actor identifier flows through the OTel collector. The
core `audit_events` table is the authoritative trail of *who did
what*; traces are about *what happened and how long it took*. An
operator who wants the actor on the span (e.g. for cross-referencing a
trace with the audit log in a debugger UI) sets
`STATEBOUND_OTEL_INCLUDE_ACTOR=true` per invocation, and the policy
review for that operator's collector deployment becomes the
gating control rather than the binary.

Plan content, evidence pack bytes, drift finding bodies, and
ChangeSet items are **never** attached as span attributes — only
their content hashes (`statebound.plan_content_hash`,
`statebound.evidence_content_hash`).

## References

- CLAUDE.md §7 — recommended technical stack: "OpenTelemetry-ready, optional in MVP".
- CLAUDE.md §22 — security requirements (no secrets in logs).
- CLAUDE.md §28 — definition of done for instrumented features.
- `internal/telemetry/` — implementation.
- `cmd/statebound/main.go` — process-level wiring.
