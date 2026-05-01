-- Migration 0009 widens the authorizations.type CHECK constraint to admit
-- `postgres.role` (Phase 6, v0.6). The original constraint shipped with
-- migration 0002 enumerated only `postgres.grant`; the Postgres connector
-- now also emits `postgres.role` items for service-account role
-- declarations (LOGIN, INHERIT, CONNECTION LIMIT, etc.). Existing 0002
-- rows are untouched — the CHECK is the only thing changing.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE authorizations DROP CONSTRAINT IF EXISTS authorizations_type_check;
ALTER TABLE authorizations
    ADD CONSTRAINT authorizations_type_check
    CHECK (type IN (
        'linux.ssh',
        'linux.sudo',
        'linux.local-group',
        'postgres.grant',
        'postgres.role',
        'kubernetes.role-binding'
    ));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE authorizations DROP CONSTRAINT IF EXISTS authorizations_type_check;
ALTER TABLE authorizations
    ADD CONSTRAINT authorizations_type_check
    CHECK (type IN (
        'linux.ssh',
        'linux.sudo',
        'linux.local-group',
        'postgres.grant',
        'kubernetes.role-binding'
    ));
-- +goose StatementEnd
