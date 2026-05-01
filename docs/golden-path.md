# Golden path demo (v1.0)

The deterministic core demo from the project spec §30, end to end.
This is the eight-step walk that exercises every Phase 1–8 capability
against the local stack: bring up Postgres, mint a signing key, import
a model, watch OPA evaluate it, generate a deterministic plan, export
an evidence pack, verify the audit chain.

```bash
# 1. Bring up local Postgres + apply migrations.
make docker-up
make migrate-up

# 2. Build the binary.
make build

# 3. Bootstrap an admin role for our operator (one-shot).
./bin/statebound role grant --bootstrap \
  --actor human:alice@example.com --role admin \
  --note "v1.0 demo bootstrap"

# 4. Mint an Ed25519 signing keypair. The private half stays on disk
#    (mode 0600); the public half + fingerprint go into the database.
mkdir -p ~/.statebound
STATEBOUND_ACTOR=human:alice@example.com \
STATEBOUND_DEV_AUTO_APPROVE=true \
  ./bin/statebound key generate \
    --key-id demo \
    --output ~/.statebound/demo.pem

export STATEBOUND_SIGNING_KEY_ID=demo
export STATEBOUND_ACTOR=human:alice@example.com

# 5. Import an authorization model. Produces a draft ChangeSet, OPA
#    evaluates it, four-eyes is satisfied via dev auto-approve, and
#    the result is an immutable ApprovedVersion.
STATEBOUND_DEV_AUTO_APPROVE=true \
  ./bin/statebound model import \
    -f examples/payments-api/model.yaml \
    --auto-approve

# 6. Project the approved version into a deterministic Linux sudo
#    plan. The plan is signed under `demo` automatically because
#    STATEBOUND_SIGNING_KEY_ID is set.
./bin/statebound plan \
  --product payments-api \
  --connector linux-sudo \
  --output /tmp/plan.json

# 7. Export an evidence pack with audit-ready Markdown.
./bin/statebound evidence export \
  --product payments-api \
  --format markdown \
  --output /tmp/evidence.md

# 8. Verify the audit log hash chain.
./bin/statebound audit verify
```

Every step writes audit events. Every state transition was
OPA-evaluated. Every plan is byte-identical given the same approved
version + connector version. Re-run step 7 and the resulting bytes are
byte-identical to the prior export — same SHA-256, same evidence pack.

## The same demo against the API container

```bash
make docker-app-up                          # Postgres + API in one go
curl -fsS http://localhost:8080/healthz
curl -fsS -H "Authorization: Bearer local-dev" \
     http://localhost:8080/v1/products
curl -fsS -H "Authorization: Bearer local-dev" \
     http://localhost:8080/v1/audit-events/verify
make docker-app-down
```

## What you should see

- Step 5: `auto-approved change set ...; created version payments-api:v1`
- Step 6: `plan <id> signed by demo (<fingerprint>)` followed by
  `plan <id> (linux-sudo, sha256:<hash>) for payments-api:v1: ready;
  2 items`. Re-run with the same inputs and the SHA-256 is identical.
- Step 7: `evidence pack <id> (markdown, sha256:<hash>) for payments-api:v1`.
  Re-run and the SHA-256 is identical.
- Step 8: `OK: <N> events, chain verified`.

If any of those don't match, file an issue — those are the
acceptance criteria for v1.0.

## Try the Postgres connector

`examples/payments-postgres/` ships a second product whose
authorizations target a Postgres database. Walk through it as in
step 5–8 with `--connector postgres`, then `apply --dry-run` against
a test database to see the canonical SQL DCL the connector would
emit.

## Want to break things?

```bash
# Tamper with an audit event (don't do this in production).
docker exec statebound-postgres psql -U statebound -d statebound \
  -c "UPDATE audit_events SET payload = '{\"hi\": \"there\"}'::jsonb WHERE id = (SELECT id FROM audit_events LIMIT 1);"

./bin/statebound audit verify
# → reports the first mismatch and the event id

# Disable a signing key, then try to apply a plan it signed.
./bin/statebound key disable --key-id demo
./bin/statebound apply <plan-id> --target ... --apply
# → refuses with plan.signature.failed in the audit log
```

These are the kinds of demos that close auditor questions in the
meeting, not in a follow-up.
