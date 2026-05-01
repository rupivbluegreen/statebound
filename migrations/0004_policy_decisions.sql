-- 0004_policy_decisions.sql
--
-- Phase 2 wave B: persist OPA policy decisions evaluated against ChangeSets.
--
-- Tables created:
--   policy_decisions  -- one row per OPA evaluation, preserved for audit/replay
--
-- Each row records the canonical Rules and Input JSON produced by
-- internal/authz so a decision can be reproduced byte-for-byte given the same
-- bundle hash. The table starts empty; no backfill is needed.
--
-- Phase indicates which lifecycle gate triggered the evaluation:
--   submit  -- evaluation at change-set submission
--   approve -- evaluation at approval time
--
-- Outcome mirrors the OPA verdict:
--   allow              -- policy permits the action
--   deny               -- policy refuses the action
--   escalate_required  -- policy permits only with elevated approval
--
-- The partial outcome index supports the most common audit query: "show me
-- every non-allow decision in <window>". The composite (change_set_id,
-- evaluated_at DESC) index supports the per-change-set replay view.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE policy_decisions (
    id            UUID PRIMARY KEY,
    change_set_id UUID NOT NULL REFERENCES change_sets(id) ON DELETE CASCADE,
    phase         TEXT NOT NULL CHECK (phase IN ('submit','approve')),
    outcome       TEXT NOT NULL CHECK (outcome IN ('allow','deny','escalate_required')),
    rules         JSONB NOT NULL,
    input         JSONB NOT NULL,
    bundle_hash   TEXT NOT NULL CHECK (bundle_hash <> ''),
    evaluated_at  TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX policy_decisions_change_set_idx
    ON policy_decisions(change_set_id, evaluated_at DESC);
CREATE INDEX policy_decisions_outcome_idx
    ON policy_decisions(outcome) WHERE outcome <> 'allow';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS policy_decisions;
-- +goose StatementEnd
