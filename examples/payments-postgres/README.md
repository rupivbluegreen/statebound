# payments-postgres example

This example exercises the Phase 6 PostgreSQL connector end-to-end:
import a desired-state model, generate a deterministic plan, dry-run the
apply (preview the SQL DCL), execute the real apply against a target
Postgres, then run a drift scan to confirm the target matches.

The model declares one read-only entitlement (`payments-readonly`,
backed by a `postgres.grant`) and one service-account login role
(`payments-batch`, backed by a `postgres.role`).

## Prerequisites

- A running Statebound deployment (the local `make docker-up` Postgres
  is fine for the control plane).
- A separate Postgres database to use as the *target* of the apply.
  Phase 6 does not co-tenant the target with the Statebound metadata
  database — `apply --target` is the connector's DSN to the target.
  In CI we create a side database (`payments_test`) on the same
  Postgres instance for convenience.

## Walkthrough

```bash
# 1. Import the YAML and auto-approve (dev shortcut). Production users
#    skip --auto-approve and run `statebound approval approve <cs-id>`
#    instead.
STATEBOUND_DEV_AUTO_APPROVE=true ./bin/statebound model import \
  -f examples/payments-postgres/model.yaml --auto-approve

# 2. Generate a deterministic plan via the postgres connector. The same
#    inputs (approved version + connector version) yield byte-identical
#    output — diff /tmp/plan-pg.json across runs proves it.
./bin/statebound plan \
  --product payments-postgres \
  --connector postgres \
  --output /tmp/plan-pg.json

# 3. Find the latest plan id (the plan command prints it on stderr; the
#    audit log carries it as plan.ready).
PG_PLAN_ID=$(./bin/statebound audit list --kind plan.ready --resource-type plan \
  --limit 1 | tail -1 | awk '{print $4}' | cut -d/ -f2)

# 4. Dry-run apply: builds the SQL DCL but does not execute. Plan stays
#    Ready. Repeat as many times as you like — each invocation creates
#    its own PlanApplyRecord, but the target is untouched.
./bin/statebound apply "$PG_PLAN_ID" \
  --target "postgres://statebound:statebound@localhost:5432/payments_test?sslmode=disable" \
  --dry-run \
  --output /tmp/apply-pg-dryrun.json

jq '.result.items[] | {sequence, status, statements}' /tmp/apply-pg-dryrun.json

# 5. Real apply (when ready). --apply is required to mutate the target.
#    On success the parent Plan transitions to Applied and apply.succeeded
#    fires in the audit log.
./bin/statebound apply "$PG_PLAN_ID" \
  --target "postgres://statebound:statebound@localhost:5432/payments_test?sslmode=disable" \
  --apply \
  --output /tmp/apply-pg-real.json

# 6. Drift scan: confirm the target now matches the desired state.
./bin/statebound drift scan \
  --product payments-postgres \
  --connector postgres \
  --source "postgres://statebound:statebound@localhost:5432/payments_test?sslmode=disable" \
  --output /tmp/drift-pg.json

# 7. Audit chain still good.
./bin/statebound audit verify
```

## What's in the model

- **`postgres.grant` (entitlement)** — `payments_readonly` role gets
  `SELECT` on `public.accounts` and `public.transactions` in the
  `payments` database.
- **`postgres.role` (service account)** — `payments_batch` is a
  `LOGIN` role with `connection_limit=10`, used by the settlement
  batch jobs.

## Safety notes

- `apply` defaults to `--dry-run`. Mutating the target requires the
  explicit `--apply` flag. `--dry-run` and `--apply` are mutually
  exclusive.
- A real apply against a production database is gated by the same
  ChangeSet/approval flow as everything else in Statebound: the plan
  must come from an `ApprovedVersion`, OPA must allow it, and the plan
  must be in `Ready` state. None of that is bypassed by running
  `statebound apply` — apply is the *executor*, not a bypass.
- Statebound never persists the `--target` DSN. The DSN appears in the
  apply record's `target` field for audit and in the audit event
  payload, but Statebound never reaches into the connection string for
  credentials. Use `pgpass` or environment variable substitution in
  your shell to keep the password out of CI logs.
