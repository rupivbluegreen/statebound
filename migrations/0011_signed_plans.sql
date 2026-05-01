-- 0011_signed_plans.sql
--
-- Phase 8 wave A: signed plan bundles.
--
-- Tables:
--   signing_keys     -- one row per logically-named Ed25519 keypair.
--                       Only the public half lives here. The private
--                       half is loaded on demand from a private_key_ref
--                       (file:<path> or env:<name>); the database NEVER
--                       holds the secret. This is intentional: the
--                       signing key IS the security boundary, not a
--                       credential to an external system, so the
--                       no-secret-storage rule applies in the strictest
--                       form here — encrypt-at-rest and KMS-backed
--                       references are Phase 8 wave C.
--
--   plan_signatures  -- one row per (plan_id, key_id, signature). Multi
--                       signer flows are supported; the apply gate
--                       requires at least one valid signature unless
--                       STATEBOUND_DEV_SKIP_PLAN_SIGNATURE is set. The
--                       FK to signing_keys is RESTRICT on delete: a
--                       signing key with live signatures cannot be
--                       deleted, only disabled.
--
-- The CHECK constraints are belt-and-suspenders complements to
-- domain.NewSigningKey / domain.NewPlanSignature: the application layer
-- validates first, but a corrupted insert from a future migration cannot
-- silently land malformed bytes in either table.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE signing_keys (
    key_id             TEXT PRIMARY KEY CHECK (key_id <> ''),
    algorithm          TEXT NOT NULL CHECK (algorithm = 'ed25519'),
    public_key         BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    fingerprint        TEXT NOT NULL CHECK (fingerprint <> ''),
    private_key_ref    TEXT NOT NULL CHECK (private_key_ref <> ''),
    created_by_kind    TEXT NOT NULL,
    created_by_subject TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ,
    disabled           BOOLEAN NOT NULL DEFAULT FALSE,
    note               TEXT NOT NULL DEFAULT '',
    last_used_at       TIMESTAMPTZ
);
CREATE INDEX signing_keys_active_idx
    ON signing_keys(disabled, expires_at);

CREATE TABLE plan_signatures (
    id                UUID PRIMARY KEY,
    plan_id           UUID NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    key_id            TEXT NOT NULL REFERENCES signing_keys(key_id) ON DELETE RESTRICT,
    algorithm         TEXT NOT NULL CHECK (algorithm = 'ed25519'),
    signature         BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    signed_by_kind    TEXT NOT NULL,
    signed_by_subject TEXT NOT NULL,
    signed_at         TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (plan_id, key_id, signature)
);
CREATE INDEX plan_signatures_plan_idx ON plan_signatures(plan_id, signed_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS plan_signatures;
DROP TABLE IF EXISTS signing_keys;
-- +goose StatementEnd
