-- 0006_plans.sql
--
-- Phase 4: persist connector-generated Plans and their PlanItems.
--
-- Tables created:
--   plans       -- one row per (approved_version, connector_name, content_hash)
--   plan_items  -- one row per logical change inside a plan
--
-- A Plan is a connector's proposal of changes to bring a target system
-- into line with an ApprovedVersion. Plans are read-only artifacts in
-- Phase 4 (no apply yet) and are deterministic: re-running plan with
-- identical (approved_version, connector_version) inputs produces a
-- byte-identical content payload, and therefore an identical
-- content_hash. The unique index on (approved_version_id,
-- connector_name, content_hash) makes AppendPlan idempotent for
-- deterministic re-plans: callers may safely INSERT ... ON CONFLICT DO
-- NOTHING.
--
-- The state column mirrors domain.PlanState: 'draft' | 'ready' |
-- 'refused' | 'applied' | 'failed'. Applied/failed are reserved for
-- Phase 6 when the apply flow lands. The CHECK constraint is the
-- belt-and-suspenders complement to domain.IsValidPlanState.
--
-- Indexes:
--   plans_version_connector_hash_idx -- idempotency key (UNIQUE)
--   plans_product_idx                -- "show me plans for this product, newest first"
--   plans_state_idx                  -- partial index for the active set (draft|ready)
--   plan_items_plan_idx              -- ordered fetch of items for a plan

-- +goose Up
-- +goose StatementBegin
CREATE TABLE plans (
    id                   UUID PRIMARY KEY,
    product_id           UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    approved_version_id  UUID NOT NULL REFERENCES approved_versions(id) ON DELETE CASCADE,
    sequence             BIGINT NOT NULL CHECK (sequence > 0),
    connector_name       TEXT NOT NULL CHECK (connector_name <> ''),
    connector_version    TEXT NOT NULL CHECK (connector_version <> ''),
    state                TEXT NOT NULL CHECK (state IN ('draft','ready','refused','applied','failed')),
    summary              TEXT NOT NULL,
    content_hash         TEXT NOT NULL CHECK (content_hash <> ''),
    content              JSONB NOT NULL,
    refused_reason       TEXT NOT NULL DEFAULT '',
    generated_at         TIMESTAMPTZ NOT NULL,
    generated_by_kind    TEXT NOT NULL,
    generated_by_subject TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX plans_version_connector_hash_idx
    ON plans(approved_version_id, connector_name, content_hash);
CREATE INDEX plans_product_idx
    ON plans(product_id, generated_at DESC);
CREATE INDEX plans_state_idx
    ON plans(state) WHERE state IN ('draft','ready');

CREATE TABLE plan_items (
    id            UUID PRIMARY KEY,
    plan_id       UUID NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    sequence      INTEGER NOT NULL CHECK (sequence > 0),
    action        TEXT NOT NULL CHECK (action IN ('create','update','delete')),
    resource_kind TEXT NOT NULL CHECK (resource_kind <> ''),
    resource_ref  TEXT NOT NULL CHECK (resource_ref <> ''),
    body          JSONB NOT NULL,
    risk          TEXT NOT NULL CHECK (risk IN ('low','medium','high','critical')),
    note          TEXT NOT NULL DEFAULT '',
    UNIQUE (plan_id, sequence)
);
CREATE INDEX plan_items_plan_idx ON plan_items(plan_id, sequence);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS plan_items;
DROP TABLE IF EXISTS plans;
-- +goose StatementEnd
