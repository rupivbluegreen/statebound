-- 0005_evidence_packs.sql
--
-- Phase 3: persist evidence packs exported per ApprovedVersion.
--
-- Tables created:
--   evidence_packs  -- one row per (approved_version, format, content_hash) export
--
-- An EvidencePack is the auditable bundle exported per ApprovedVersion. The
-- pack is deterministic (same input -> byte-identical content hash) and
-- immutable (one row per (approved_version, format, content_hash); we
-- re-export rather than mutate). Both JSON and Markdown formats are stored as
-- JSONB. The Markdown form is wrapped in a JSON envelope by the engine
-- (e.g. {"format":"markdown","body":"..."}) so the content column is always
-- parseable JSON; the content_hash is the SHA-256 of the canonical JSON bytes
-- the storage layer received.
--
-- The unique index on (approved_version_id, format, content_hash) makes
-- AppendEvidencePack idempotent for deterministic re-exports: callers may
-- safely INSERT ... ON CONFLICT DO NOTHING. The product/generated_at index
-- supports the most common audit query: "show me every evidence export for
-- this product in <window>".

-- +goose Up
-- +goose StatementBegin
CREATE TABLE evidence_packs (
    id                   UUID PRIMARY KEY,
    product_id           UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    approved_version_id  UUID NOT NULL REFERENCES approved_versions(id) ON DELETE CASCADE,
    sequence             BIGINT NOT NULL CHECK (sequence > 0),
    format               TEXT NOT NULL CHECK (format IN ('json','markdown')),
    content_hash         TEXT NOT NULL CHECK (content_hash <> ''),
    content              JSONB NOT NULL,
    generated_at         TIMESTAMPTZ NOT NULL,
    generated_by_kind    TEXT NOT NULL,
    generated_by_subject TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX evidence_packs_version_format_hash_idx
    ON evidence_packs(approved_version_id, format, content_hash);
CREATE INDEX evidence_packs_product_idx
    ON evidence_packs(product_id, generated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS evidence_packs;
-- +goose StatementEnd
