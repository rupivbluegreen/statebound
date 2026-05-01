-- 0001_init.sql
--
-- Initial Statebound core schema (Phase 0).
--
-- Creates two tables:
--   products      -- top-level governed unit per the project spec section 4.
--   audit_events  -- append-only event log per the project spec section 13.
--
-- See the project spec section 12 for the full Phase 0..v1.0 data model.
-- Hash-chain columns (prev_hash, hash) exist now but stay empty until v0.2.
-- Agent / reasoning add-on tables are intentionally absent: they ship in
-- statebound-reason extension migrations, never in core.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE products (
    id          UUID        PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE
                CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    owner       TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE audit_events (
    id            UUID        PRIMARY KEY,
    kind          TEXT        NOT NULL,
    actor_kind    TEXT        NOT NULL,
    actor_subject TEXT        NOT NULL,
    resource_type TEXT        NOT NULL,
    resource_id   TEXT        NOT NULL,
    payload       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    occurred_at   TIMESTAMPTZ NOT NULL,
    prev_hash     TEXT        NOT NULL DEFAULT '',
    hash          TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX audit_events_resource_idx
    ON audit_events (resource_type, resource_id, occurred_at DESC);

CREATE INDEX audit_events_kind_idx
    ON audit_events (kind, occurred_at DESC);

CREATE INDEX audit_events_occurred_at_idx
    ON audit_events (occurred_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS products;
-- +goose StatementEnd
