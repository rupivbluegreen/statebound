-- 0007_drift.sql
--
-- Phase 4': persist connector-driven drift scans and their findings.
--
-- Tables created:
--   drift_scans     -- one row per CollectActualState + Compare cycle
--   drift_findings  -- one row per logical mismatch within a scan
--
-- A DriftScan begins in 'running' state, lands in exactly one terminal
-- state ('succeeded' | 'failed') via UpdateDriftScan, and the
-- accompanying findings are appended in bulk via AppendDriftFindings.
-- The state column mirrors domain.DriftScanState; the CHECK constraint
-- is the belt-and-suspenders complement to domain.IsValidDriftScanState.
--
-- summary_hash is the SHA-256 hex of the canonical findings list,
-- recorded so an evidence pack can prove the scan content has not been
-- retouched after the fact.
--
-- Indexes:
--   drift_scans_product_idx     -- "show me scans for this product, newest first"
--   drift_scans_av_idx          -- "what was the latest scan against av-N"
--   drift_scans_state_idx       -- partial index for the active set (running)
--   drift_findings_scan_idx     -- ordered fetch of findings for a scan
--   drift_findings_severity_idx -- partial index for hot-list severities

-- +goose Up
-- +goose StatementBegin
CREATE TABLE drift_scans (
    id                   UUID PRIMARY KEY,
    product_id           UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    approved_version_id  UUID NOT NULL REFERENCES approved_versions(id) ON DELETE CASCADE,
    sequence             BIGINT NOT NULL CHECK (sequence > 0),
    connector_name       TEXT NOT NULL CHECK (connector_name <> ''),
    connector_version    TEXT NOT NULL CHECK (connector_version <> ''),
    state                TEXT NOT NULL CHECK (state IN ('running','succeeded','failed')),
    source_ref           TEXT NOT NULL CHECK (source_ref <> ''),
    started_at           TIMESTAMPTZ NOT NULL,
    finished_at          TIMESTAMPTZ,
    initiated_by_kind    TEXT NOT NULL,
    initiated_by_subject TEXT NOT NULL,
    failure_message      TEXT NOT NULL DEFAULT '',
    summary_hash         TEXT NOT NULL DEFAULT '',
    finding_count        INTEGER NOT NULL DEFAULT 0 CHECK (finding_count >= 0),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX drift_scans_product_idx
    ON drift_scans(product_id, started_at DESC);
CREATE INDEX drift_scans_av_idx
    ON drift_scans(approved_version_id, started_at DESC);
CREATE INDEX drift_scans_state_idx
    ON drift_scans(state) WHERE state = 'running';

CREATE TABLE drift_findings (
    id            UUID PRIMARY KEY,
    scan_id       UUID NOT NULL REFERENCES drift_scans(id) ON DELETE CASCADE,
    sequence      INTEGER NOT NULL CHECK (sequence > 0),
    kind          TEXT NOT NULL CHECK (kind IN ('missing','unexpected','modified')),
    severity      TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    resource_kind TEXT NOT NULL CHECK (resource_kind <> ''),
    resource_ref  TEXT NOT NULL CHECK (resource_ref <> ''),
    desired       JSONB,
    actual        JSONB,
    diff          JSONB NOT NULL,
    message       TEXT NOT NULL DEFAULT '',
    detected_at   TIMESTAMPTZ NOT NULL,
    UNIQUE (scan_id, sequence)
);
CREATE INDEX drift_findings_scan_idx ON drift_findings(scan_id, sequence);
CREATE INDEX drift_findings_severity_idx ON drift_findings(severity)
    WHERE severity IN ('high','critical');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS drift_findings;
DROP TABLE IF EXISTS drift_scans;
-- +goose StatementEnd
