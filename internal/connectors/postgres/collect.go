// Phase 6 drift collection: CollectActualState dials the target
// Postgres via pgx and captures the live role + table-grant catalog
// into a deterministic ActualState snapshot. Two collects of the
// same target with the same scope MUST produce byte-identical Items
// (sorted ascending by ResourceKind, ResourceRef).
//
// Scope:
//   - postgres.role: every non-system role (excluding pg_* internal
//     roles).
//   - postgres.grant: every (grantee, schema, table) tuple in
//     information_schema.role_table_grants, aggregated by
//     (grantee, schema, table) so privileges land as a single sorted
//     list per item rather than one row per privilege.
//   - Sequences, functions, schema-level USAGE, and default
//     privileges land in Phase 8 hardening.
//
// CollectionScope.Path is unused (Postgres is host-based, not file-based).
// CollectionScope.Host is the DSN. CollectionScope.Selectors is reserved
// for future filtering (specific schemas, specific roles).
//
// Credentials are never logged. SourceRef is built from the parsed DSN
// without the password component so it can land in evidence packs.

package postgres

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"statebound.dev/statebound/internal/connectors"
)

// CollectActualState reads the target Postgres' role catalog and
// table-grant catalog, and emits one ActualStateItem per role and per
// (grantee, schema, table) tuple. Two collects against the same
// target with no intervening DDL produce byte-identical Items.
func (*Connector) CollectActualState(ctx context.Context, scope connectors.CollectionScope) (*connectors.ActualState, error) {
	target := scope.Host
	if target == "" {
		return nil, fmt.Errorf("postgres collect: scope.Host (DSN) is required")
	}

	conn, err := pgx.Connect(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("postgres collect: connect: %w", redactDSNErr(target, err))
	}
	defer conn.Close(ctx)

	host, port, database, sourceRef := parseDSNParts(target)

	roles, err := collectRoles(ctx, conn, host, database)
	if err != nil {
		return nil, err
	}
	grants, err := collectTableGrants(ctx, conn, host, database)
	if err != nil {
		return nil, err
	}

	items := append([]connectors.ActualStateItem(nil), roles...)
	items = append(items, grants...)

	// Deterministic ordering: ResourceKind ASC, ResourceRef ASC.
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ResourceKind != items[j].ResourceKind {
			return items[i].ResourceKind < items[j].ResourceKind
		}
		return items[i].ResourceRef < items[j].ResourceRef
	})

	_ = port // currently informational only; reserved for future SourceRef shapes

	return &connectors.ActualState{
		ConnectorName:    connectorName,
		ConnectorVersion: connectorVersion,
		SourceRef:        sourceRef,
		CollectedAt:      time.Now().UTC(),
		Items:            items,
	}, nil
}

// collectRoles reads pg_roles and emits one ActualStateItem per
// non-system role. System roles whose name begins with "pg_" are
// excluded; they are managed by Postgres itself and never appear in
// our desired-state model.
func collectRoles(ctx context.Context, conn *pgx.Conn, host, database string) ([]connectors.ActualStateItem, error) {
	const q = `
SELECT rolname, rolcanlogin, rolinherit, rolconnlimit
FROM pg_roles
WHERE rolname NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY rolname
`
	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("postgres collect: query roles: %w", err)
	}
	defer rows.Close()

	var out []connectors.ActualStateItem
	for rows.Next() {
		var (
			name      string
			canLogin  bool
			inherit   bool
			connLimit int
		)
		if err := rows.Scan(&name, &canLogin, &inherit, &connLimit); err != nil {
			return nil, fmt.Errorf("postgres collect: scan role: %w", err)
		}
		body := map[string]any{
			"role":             name,
			"login":            canLogin,
			"inherit":          inherit,
			"connection_limit": connLimit,
			"database":         database,
		}
		out = append(out, connectors.ActualStateItem{
			ResourceKind: "postgres.role",
			ResourceRef:  fmt.Sprintf("%s:%s:role:%s", host, database, name),
			Body:         body,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres collect: iterate roles: %w", err)
	}
	return out, nil
}

// collectTableGrants queries information_schema.role_table_grants and
// aggregates rows by (grantee, schema, table) into one ActualStateItem
// per tuple, with privileges as a sorted []string.
//
// The query excludes well-known system grantees (PUBLIC, postgres,
// rds_*) so noise from cloud-provider managed roles does not pollute
// drift findings.
func collectTableGrants(ctx context.Context, conn *pgx.Conn, host, database string) ([]connectors.ActualStateItem, error) {
	const q = `
SELECT grantee, table_schema, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee NOT IN ('PUBLIC', 'postgres')
  AND grantee NOT LIKE 'rds\_%' ESCAPE '\'
  AND grantee NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY grantee, table_schema, table_name, privilege_type
`
	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("postgres collect: query grants: %w", err)
	}
	defer rows.Close()

	type key struct{ grantee, schema, table string }
	bucket := make(map[key]map[string]struct{})
	for rows.Next() {
		var grantee, schema, table, priv string
		if err := rows.Scan(&grantee, &schema, &table, &priv); err != nil {
			return nil, fmt.Errorf("postgres collect: scan grant: %w", err)
		}
		k := key{grantee: grantee, schema: schema, table: table}
		if _, ok := bucket[k]; !ok {
			bucket[k] = make(map[string]struct{})
		}
		bucket[k][strings.ToUpper(priv)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres collect: iterate grants: %w", err)
	}

	out := make([]connectors.ActualStateItem, 0, len(bucket))
	for k, privSet := range bucket {
		privs := make([]string, 0, len(privSet))
		for p := range privSet {
			privs = append(privs, p)
		}
		sort.Strings(privs)
		body := map[string]any{
			"as_role":    k.grantee,
			"database":   database,
			"schema":     k.schema,
			"privileges": privs,
			"objects": map[string]any{
				"tables": []string{k.table},
			},
		}
		out = append(out, connectors.ActualStateItem{
			ResourceKind: "postgres.grant",
			ResourceRef:  fmt.Sprintf("%s:%s:%s:grant:%s:tables:%s", host, database, k.schema, k.grantee, k.table),
			Body:         body,
		})
	}
	// Deterministic order across map iterations.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ResourceRef < out[j].ResourceRef
	})
	return out, nil
}

// parseDSNParts pulls the host, port, and database out of a Postgres
// DSN. Tolerates both URL-form ("postgres://user:pass@host:port/db?...")
// and the keyword form ("host=... dbname=..."). For URL form the
// returned sourceRef strips the password before display.
//
// Returns sensible defaults ("localhost", 5432, "") when parsing fails
// — the connector still works against an unparseable DSN, it just
// loses the host/database labelling.
func parseDSNParts(dsn string) (host, port, database, sourceRef string) {
	host = "localhost"
	port = "5432"

	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err == nil {
			if u.Hostname() != "" {
				host = u.Hostname()
			}
			if u.Port() != "" {
				port = u.Port()
			}
			database = strings.TrimPrefix(u.Path, "/")
			// Build a credential-stripped source ref.
			cleaned := *u
			cleaned.User = nil
			cleaned.RawQuery = ""
			sourceRef = cleaned.String()
			return
		}
	}

	// Keyword form parser — split on whitespace, look for key=value tokens.
	for _, tok := range strings.Fields(dsn) {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		key, val := tok[:eq], tok[eq+1:]
		switch strings.ToLower(key) {
		case "host":
			host = val
		case "port":
			port = val
		case "dbname", "database":
			database = val
		}
	}
	sourceRef = fmt.Sprintf("postgres://%s:%s/%s", host, port, database)
	return
}

// redactDSNErr returns an error wrapping err where any literal copy
// of the DSN's password component has been stripped from the message.
// Best-effort; if the DSN cannot be parsed the error is returned
// unchanged.
func redactDSNErr(dsn string, err error) error {
	u, parseErr := url.Parse(dsn)
	if parseErr != nil || u.User == nil {
		return err
	}
	pw, hasPW := u.User.Password()
	if !hasPW || pw == "" {
		return err
	}
	msg := strings.ReplaceAll(err.Error(), pw, "***")
	return fmt.Errorf("%s", msg)
}
