// Package postgres implements the Phase 6 PostgreSQL authorization
// governance connector. Unlike the Phase 4 linux-sudo / linux-ssh
// connectors which are plan-only file emitters, the Postgres
// connector is the first to advertise the full Plan / Collect /
// Compare / Apply matrix:
//
//   - Plan walks the approved-state model and emits PlanItems for
//     postgres.role and postgres.grant authorizations.
//   - CollectActualState dials the target database via pgx, queries
//     pg_roles and information_schema.role_table_grants, and emits a
//     deterministic ActualState snapshot.
//   - Compare diffs the desired plan against the observed snapshot
//     and emits drift findings.
//   - Apply translates the plan into idempotent SQL DCL (CREATE ROLE
//     wrapped in DO blocks; consolidated GRANT/REVOKE statements) and
//     executes them in a single transaction. DryRun mode populates
//     Statements without touching the target.
//
// Connectors do NOT touch the database that backs Statebound itself
// — the Apply path opens its own pgx connection to the *target*
// Postgres declared via ApplyOptions.Target. The connector never
// reads or writes the core's audit log directly; the CLI/service
// layer translates ApplyResult into PlanApplyRecord rows.
//
// Phase 6 keeps the scope tight: roles + table grants. Schema-level
// USAGE, function/sequence grants, default privileges, and replication
// privileges land in Phase 8 hardening.
package postgres

import (
	"statebound.dev/statebound/internal/connectors"
)

// Connector identity. Bump connectorVersion on any change to plan
// output shape (so content_hash divergence is observable in audit
// logs) or to apply SQL generation (so re-applies with a newer
// connector are explicit).
const (
	connectorName    = "postgres"
	connectorVersion = "0.6.0"
	schemaVersion    = "postgres.statebound.dev/v0alpha1"
)

// Connector is the Postgres plan + drift + apply connector. It is
// stateless — the underlying pgx connection is opened per Collect or
// Apply call from the supplied DSN, never cached in the Connector
// value. Phase 6 makes this the first connector to advertise every
// capability on the connector contract; no Unsupported* helpers are
// embedded.
type Connector struct{}

// New returns a fresh Connector. Stateless; safe to share.
func New() *Connector { return &Connector{} }

// Name returns the stable registry key.
func (*Connector) Name() string { return connectorName }

// Version returns the connector semver.
func (*Connector) Version() string { return connectorVersion }

// Capabilities reports the full Phase 6 matrix: Plan, Apply,
// CollectActualState, and Compare. The order matches the canonical
// listing in connectors.Capability so it is stable for display.
func (*Connector) Capabilities() []connectors.Capability {
	return []connectors.Capability{
		connectors.CapabilityPlan,
		connectors.CapabilityApply,
		connectors.CapabilityCollectActual,
		connectors.CapabilityCompare,
	}
}
