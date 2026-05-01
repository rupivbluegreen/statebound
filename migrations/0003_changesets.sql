-- 0003_changesets.sql
--
-- Phase 2 wave A: change-set lifecycle, approvals, and immutable approved
-- versions, plus activation of the audit-event hash chain.
--
-- Tables created:
--   change_sets                -- draft/submitted/approved/rejected/conflicted lifecycle
--   change_set_items           -- per-resource add/update/delete records
--   approved_version_snapshots -- content-addressed, immutable model snapshots
--   approved_versions          -- per-product monotonic, immutable approved revisions
--   approvals                  -- four-eyes / policy decision records
--
-- Forward-reference loop:
--   change_sets.parent_approved_version_id -> approved_versions(id)
--   approved_versions.source_change_set_id -> change_sets(id)
-- Resolved by creating both tables without those FKs, then adding the FK
-- constraints with ALTER TABLE once both exist.
--
-- Immutability:
--   approved_version_snapshots and approved_versions have no application UPDATE
--   pathway. Application-level enforcement; no SQL UPDATE trigger here. Snapshot
--   content_hash is UNIQUE so the same canonical model imported twice yields the
--   same row.
--
-- Hash chain (audit_events) — Phase 2 definition:
--   This migration enables the hash chain begun as empty columns in 0001.
--   Definition (used identically by Postgres-side backfill and Go-side append):
--     audit_event_hash(prev_hash, kind, actor_kind, actor_subject,
--                      resource_type, resource_id, payload, occurred_at) :=
--       sha256_hex( concat_ws('|', prev_hash, kind, actor_kind, actor_subject,
--                             resource_type, resource_id, payload::text,
--                             occurred_at::text) )
--   payload::text uses Postgres's default jsonb-to-text rendering, which sorts
--   object keys; this canonicalization is what makes the chain reproducible.
--   Empty audit_events tables are fine; the constraint added below disallows
--   future empty-hash inserts.

-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_event_hash(
    prev_hash     TEXT,
    kind          TEXT,
    actor_kind    TEXT,
    actor_subject TEXT,
    resource_type TEXT,
    resource_id   TEXT,
    payload       JSONB,
    occurred_at   TIMESTAMPTZ
) RETURNS TEXT
    LANGUAGE SQL
    IMMUTABLE
AS $func$
    SELECT encode(
        digest(
            concat_ws('|',
                prev_hash,
                kind,
                actor_kind,
                actor_subject,
                resource_type,
                resource_id,
                payload::text,
                occurred_at::text
            ),
            'sha256'
        ),
        'hex'
    );
$func$;
-- +goose StatementEnd

-- Backfill the chain over any pre-existing audit_events rows in deterministic
-- order so the post-migration NOT-EMPTY constraint passes.
-- +goose StatementBegin
DO $$
DECLARE
    r          RECORD;
    last_hash  TEXT := '';
    new_hash   TEXT;
BEGIN
    FOR r IN
        SELECT id, kind, actor_kind, actor_subject, resource_type, resource_id,
               payload, occurred_at
          FROM audit_events
         ORDER BY occurred_at ASC, id ASC
    LOOP
        new_hash := audit_event_hash(
            last_hash,
            r.kind,
            r.actor_kind,
            r.actor_subject,
            r.resource_type,
            r.resource_id,
            r.payload,
            r.occurred_at
        );
        UPDATE audit_events
           SET prev_hash = last_hash,
               hash      = new_hash
         WHERE id = r.id;
        last_hash := new_hash;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_hash_nonempty CHECK (hash <> '');
-- +goose StatementEnd

-- Snapshots first: approved_versions references them.
-- +goose StatementBegin
CREATE TABLE approved_version_snapshots (
    id           UUID        PRIMARY KEY,
    content      JSONB       NOT NULL,
    content_hash TEXT        NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL
);
-- +goose StatementEnd

-- change_sets: created without the parent_approved_version_id FK to break the
-- forward-reference cycle with approved_versions.
-- +goose StatementBegin
CREATE TABLE change_sets (
    id                         UUID        PRIMARY KEY,
    product_id                 UUID        NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    state                      TEXT        NOT NULL
                               CHECK (state IN (
                                   'draft',
                                   'submitted',
                                   'approved',
                                   'rejected',
                                   'conflicted'
                               )),
    parent_approved_version_id UUID        NULL,
    title                      TEXT        NOT NULL,
    description                TEXT        NOT NULL DEFAULT '',
    requested_by_kind          TEXT        NOT NULL
                               CHECK (requested_by_kind IN (
                                   'human',
                                   'service_account',
                                   'system'
                               )),
    requested_by_subject       TEXT        NOT NULL,
    submitted_at               TIMESTAMPTZ NULL,
    decided_at                 TIMESTAMPTZ NULL,
    decision_reason            TEXT        NOT NULL DEFAULT '',
    created_at                 TIMESTAMPTZ NOT NULL,
    updated_at                 TIMESTAMPTZ NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX change_sets_product_state_created_idx
    ON change_sets (product_id, state, created_at DESC);
-- +goose StatementEnd

-- Pending-approvals query lookup.
-- +goose StatementBegin
CREATE INDEX change_sets_pending_idx
    ON change_sets (state, created_at DESC)
    WHERE state = 'submitted';
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE change_set_items (
    id            UUID        PRIMARY KEY,
    change_set_id UUID        NOT NULL REFERENCES change_sets(id) ON DELETE CASCADE,
    kind          TEXT        NOT NULL
                  CHECK (kind IN (
                      'product',
                      'asset',
                      'asset_scope',
                      'entitlement',
                      'service_account',
                      'global_object',
                      'authorization'
                  )),
    action        TEXT        NOT NULL
                  CHECK (action IN ('add', 'update', 'delete')),
    resource_name TEXT        NOT NULL,
    before        JSONB       NULL,
    after         JSONB       NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    CHECK (
        (action = 'add'    AND before IS NULL     AND after IS NOT NULL) OR
        (action = 'delete' AND before IS NOT NULL AND after IS NULL)     OR
        (action = 'update' AND before IS NOT NULL AND after IS NOT NULL)
    )
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX change_set_items_change_set_idx
    ON change_set_items (change_set_id);
-- +goose StatementEnd

-- approved_versions: created without the source_change_set_id FK to break the
-- forward-reference cycle. snapshot_id FK is fine because snapshots already
-- exist. Immutable: no application UPDATE pathway; do not add one.
-- +goose StatementBegin
CREATE TABLE approved_versions (
    id                   UUID        PRIMARY KEY,
    product_id           UUID        NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    sequence             BIGINT      NOT NULL CHECK (sequence >= 1),
    parent_version_id    UUID        NULL REFERENCES approved_versions(id) ON DELETE RESTRICT,
    source_change_set_id UUID        NOT NULL,
    snapshot_id          UUID        NOT NULL REFERENCES approved_version_snapshots(id) ON DELETE RESTRICT,
    approved_by_kind     TEXT        NOT NULL,
    approved_by_subject  TEXT        NOT NULL,
    description          TEXT        NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL,
    UNIQUE (product_id, sequence)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX approved_versions_product_sequence_idx
    ON approved_versions (product_id, sequence DESC);
-- +goose StatementEnd

-- Now both tables exist; close the FK loop.
-- +goose StatementBegin
ALTER TABLE change_sets
    ADD CONSTRAINT change_sets_parent_approved_version_fk
    FOREIGN KEY (parent_approved_version_id)
    REFERENCES approved_versions(id) ON DELETE RESTRICT;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE approved_versions
    ADD CONSTRAINT approved_versions_source_change_set_fk
    FOREIGN KEY (source_change_set_id)
    REFERENCES change_sets(id) ON DELETE RESTRICT;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE approvals (
    id               UUID        PRIMARY KEY,
    change_set_id    UUID        NOT NULL REFERENCES change_sets(id) ON DELETE RESTRICT,
    approver_kind    TEXT        NOT NULL,
    approver_subject TEXT        NOT NULL,
    decision         TEXT        NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reason           TEXT        NOT NULL DEFAULT '',
    decided_at       TIMESTAMPTZ NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX approvals_change_set_decided_idx
    ON approvals (change_set_id, decided_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS approvals_change_set_decided_idx;
DROP TABLE IF EXISTS approvals;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE IF EXISTS approved_versions
    DROP CONSTRAINT IF EXISTS approved_versions_source_change_set_fk;
ALTER TABLE IF EXISTS change_sets
    DROP CONSTRAINT IF EXISTS change_sets_parent_approved_version_fk;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS approved_versions_product_sequence_idx;
DROP TABLE IF EXISTS approved_versions;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS change_set_items_change_set_idx;
DROP TABLE IF EXISTS change_set_items;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS change_sets_pending_idx;
DROP INDEX IF EXISTS change_sets_product_state_created_idx;
DROP TABLE IF EXISTS change_sets;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS approved_version_snapshots;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE IF EXISTS audit_events
    DROP CONSTRAINT IF EXISTS audit_events_hash_nonempty;
-- +goose StatementEnd

-- +goose StatementBegin
DROP FUNCTION IF EXISTS audit_event_hash(
    TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, TIMESTAMPTZ
);
-- +goose StatementEnd
