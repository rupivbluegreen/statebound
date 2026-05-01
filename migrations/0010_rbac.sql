-- 0010_rbac.sql
--
-- Phase 8 wave A: operator role-based access control.
--
-- A binding is the (Actor, Role) tuple persisted by Statebound. Five
-- non-hierarchical roles (viewer, requester, approver, operator, admin)
-- gate the CLI commands listed in capabilityRoles in
-- internal/domain/rbac.go. The CHECK on role mirrors that mapping; the
-- regex on actor_kind / actor_subject mirrors domain.Actor.Validate.
--
-- ListActiveRolesForActor is the hot path on every CLI invocation, so
-- a partial index covers active bindings (no expiry OR expiry in the
-- future). The other two indexes back point lookups by actor and by
-- role for the role list/grant CLI surface.
--
-- Bindings are append-and-revoke (no UPDATE in the storage interface);
-- a revoke is just a DELETE. The audit log is the source of truth for
-- "who held what role when" — bindings themselves are not historised
-- in this table.
--
-- The UNIQUE (actor_kind, actor_subject, role) constraint is what
-- AppendActorRoleBinding hooks ON CONFLICT DO NOTHING into; the storage
-- layer translates the conflict into ErrRoleBindingDuplicate so role
-- grants stay auditable rather than silently no-op.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE actor_role_bindings (
    id                 UUID PRIMARY KEY,
    actor_kind         TEXT NOT NULL CHECK (actor_kind <> ''),
    actor_subject      TEXT NOT NULL CHECK (actor_subject <> ''),
    role               TEXT NOT NULL CHECK (role IN ('viewer','requester','approver','operator','admin')),
    granted_by_kind    TEXT NOT NULL,
    granted_by_subject TEXT NOT NULL,
    granted_at         TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ,
    note               TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (actor_kind, actor_subject, role)
);
CREATE INDEX actor_role_bindings_actor_idx
    ON actor_role_bindings(actor_kind, actor_subject);
CREATE INDEX actor_role_bindings_role_idx
    ON actor_role_bindings(role);
-- Active-binding partial index. Postgres rejects `now()` in a predicate
-- because it is STABLE, not IMMUTABLE — so we cover both shapes:
--   - rows with NULL expiry (the common case) get the partial index;
--   - rows with non-NULL expiry are filtered at query time using the
--     (actor_kind, actor_subject) index above plus a WHERE clause.
-- The active-set hot path "list active roles for actor" still uses
-- this index for the NULL-expiry rows it cares about most.
CREATE INDEX actor_role_bindings_active_idx
    ON actor_role_bindings(actor_kind, actor_subject, role)
    WHERE expires_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS actor_role_bindings;
-- +goose StatementEnd
