-- 0008_plan_apply.sql
--
-- Phase 6: persist Plan apply executions.
--
-- A PlanApplyRecord is one execution of a connector's Apply against a
-- target system. Records begin in 'running' state via
-- AppendPlanApplyRecord and land in exactly one terminal state
-- ('succeeded' | 'failed') via UpdatePlanApplyRecord. The state column
-- mirrors domain.PlanApplyState; the CHECK constraint is the
-- belt-and-suspenders complement to domain.IsValidPlanApplyState.
--
-- summary_hash is the SHA-256 hex of the canonical JSON of the per-item
-- results stored in the output column, recorded so an evidence pack can
-- prove the apply content has not been retouched after the fact.
--
-- Dry-run executions (dry_run = TRUE) follow the same lifecycle but do
-- not transition the parent plan to applied/failed — that contract is
-- enforced in the application layer; the schema simply records the
-- flag so audit can replay the intended behaviour.
--
-- Indexes:
--   plan_apply_plan_idx     -- "show me applies for this plan, newest first"
--   plan_apply_state_idx    -- partial index for the active set (running)

-- +goose Up
-- +goose StatementBegin
CREATE TABLE plan_apply_records (
    id              UUID PRIMARY KEY,
    plan_id         UUID NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    state           TEXT NOT NULL CHECK (state IN ('running','succeeded','failed')),
    started_at      TIMESTAMPTZ NOT NULL,
    finished_at     TIMESTAMPTZ,
    actor_kind      TEXT NOT NULL,
    actor_subject   TEXT NOT NULL,
    target          TEXT NOT NULL CHECK (target <> ''),
    dry_run         BOOLEAN NOT NULL DEFAULT FALSE,
    applied_items   INTEGER NOT NULL DEFAULT 0 CHECK (applied_items >= 0),
    failed_items    INTEGER NOT NULL DEFAULT 0 CHECK (failed_items >= 0),
    failure_message TEXT NOT NULL DEFAULT '',
    summary_hash    TEXT NOT NULL DEFAULT '',
    output          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX plan_apply_plan_idx ON plan_apply_records(plan_id, started_at DESC);
CREATE INDEX plan_apply_state_idx ON plan_apply_records(state) WHERE state = 'running';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS plan_apply_records;
-- +goose StatementEnd
