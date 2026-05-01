-- 0002_authz_model.sql
--
-- Phase 1 authorization model.
--
-- Creates the six tables that wire up Statebound's permission graph:
--   assets           -- concrete target resources owned by a product
--   asset_scopes     -- named, reusable selectors over assets within a product
--   entitlements    -- human-facing access packages
--   service_accounts -- non-personal / agent identities
--   global_objects   -- reusable access primitives (groups, roles, policies),
--                       optionally cross-product
--   authorizations   -- granular permission links: (parent) --> (asset_scope OR
--                       global_object) typed by AuthorizationType
--
-- See the project spec section 12 for the full v1.0 data model. This migration
-- covers exactly the Phase 1 slice. Approved versions, plans, drift scans, and
-- evidence packs land in later migrations.
--
-- Naming: every Name is the cross-cutting kebab-slug regex
-- ^[a-z0-9][a-z0-9-]{0,62}$ enforced both here (CHECK) and in the domain layer.
-- Keep the two in sync.
--
-- Authorizations.parent_id is intentionally not a foreign key: it can reference
-- any of three tables (entitlements, service_accounts, global_objects) keyed by
-- parent_kind. Application-level integrity covers this for Phase 1; Phase 2 may
-- swap in a check trigger or partial FKs.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE assets (
    id          UUID        PRIMARY KEY,
    name        TEXT        NOT NULL
                CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    type        TEXT        NOT NULL
                CHECK (type IN (
                    'linux-host',
                    'postgres-database',
                    'kubernetes-namespace',
                    'kubernetes-cluster',
                    'service',
                    'bucket'
                )),
    product_id  UUID        NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    environment TEXT        NOT NULL
                CHECK (environment IN ('dev', 'staging', 'prod')),
    labels      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    description TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    UNIQUE (product_id, name)
);

CREATE INDEX assets_product_env_type_idx
    ON assets (product_id, environment, type);

CREATE TABLE asset_scopes (
    id          UUID        PRIMARY KEY,
    name        TEXT        NOT NULL
                CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    product_id  UUID        NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    selector    JSONB       NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    UNIQUE (product_id, name)
);

CREATE INDEX asset_scopes_product_idx
    ON asset_scopes (product_id, name);

CREATE TABLE entitlements (
    id          UUID        PRIMARY KEY,
    name        TEXT        NOT NULL
                CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    product_id  UUID        NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    owner       TEXT        NOT NULL,
    purpose     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    UNIQUE (product_id, name)
);

CREATE INDEX entitlements_product_idx
    ON entitlements (product_id, name);

CREATE TABLE service_accounts (
    id            UUID        PRIMARY KEY,
    name          TEXT        NOT NULL
                  CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    product_id    UUID        NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    owner         TEXT        NOT NULL,
    purpose       TEXT        NOT NULL,
    usage_pattern TEXT        NOT NULL
                  CHECK (usage_pattern IN (
                      'system-to-system',
                      'agent',
                      'human-shared',
                      'deploy',
                      'monitoring'
                  )),
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    UNIQUE (product_id, name)
);

CREATE INDEX service_accounts_product_idx
    ON service_accounts (product_id, name);

CREATE TABLE global_objects (
    id          UUID        PRIMARY KEY,
    name        TEXT        NOT NULL
                CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    type        TEXT        NOT NULL
                CHECK (type IN (
                    'linux-group',
                    'linux-sudoers-fragment',
                    'postgres-role',
                    'kubernetes-role-binding',
                    'rego-policy'
                )),
    product_id  UUID        NULL REFERENCES products(id) ON DELETE RESTRICT,
    spec        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    UNIQUE (product_id, name)
);

CREATE INDEX global_objects_type_idx
    ON global_objects (type, name);

CREATE TABLE authorizations (
    id               UUID        PRIMARY KEY,
    parent_kind      TEXT        NOT NULL
                     CHECK (parent_kind IN (
                         'entitlement',
                         'service-account',
                         'global-object'
                     )),
    parent_id        UUID        NOT NULL,
    type             TEXT        NOT NULL
                     CHECK (type IN (
                         'linux.ssh',
                         'linux.sudo',
                         'linux.local-group',
                         'postgres.grant',
                         'kubernetes.role-binding'
                     )),
    asset_scope_id   UUID        NULL REFERENCES asset_scopes(id) ON DELETE RESTRICT,
    global_object_id UUID        NULL REFERENCES global_objects(id) ON DELETE RESTRICT,
    spec             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    CHECK ((asset_scope_id IS NULL) <> (global_object_id IS NULL))
);

CREATE INDEX authorizations_parent_idx
    ON authorizations (parent_kind, parent_id);

CREATE INDEX authorizations_asset_scope_idx
    ON authorizations (asset_scope_id)
    WHERE asset_scope_id IS NOT NULL;

CREATE INDEX authorizations_global_object_idx
    ON authorizations (global_object_id)
    WHERE global_object_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS authorizations;
DROP TABLE IF EXISTS global_objects;
DROP TABLE IF EXISTS service_accounts;
DROP TABLE IF EXISTS entitlements;
DROP TABLE IF EXISTS asset_scopes;
DROP TABLE IF EXISTS assets;
-- +goose StatementEnd
