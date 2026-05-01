// SQL DCL generation helpers for the Postgres connector. The helpers
// are pure: they take normalised inputs (sorted privilege/table lists,
// quoted identifiers) and return the literal SQL strings that Apply
// will execute. Two calls with identical inputs return identical
// strings so plan/apply are deterministic and apply transcripts are
// reproducible.
//
// Identifier quoting goes through pgx.Identifier{...}.Sanitize() which
// emits a properly double-quoted identifier with embedded quotes
// escaped (e.g. `payments"role` becomes `"payments""role"`). This is
// the same path used by the standard pgx driver, so any role name a
// user can put in the YAML can be safely passed here.
//
// Idempotency strategy:
//   - CREATE ROLE has no IF NOT EXISTS in Postgres. We wrap it in a
//     DO block that catches duplicate_object so Apply can run twice
//     without failing.
//   - GRANT is naturally idempotent in Postgres; re-granting the same
//     privilege is a no-op. No wrapper is needed.
//   - REVOKE on a missing privilege is also a no-op.
//
// Apply builds Statements as the literal SQL it would execute (or did
// execute). DryRun mode returns the same strings without dispatching
// them to the target server.

package postgres

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// quoteIdent escapes a SQL identifier (role name, schema, table) by
// delegating to pgx. Identifier{name}.Sanitize() returns the
// double-quoted, embedded-quote-escaped form.
func quoteIdent(name string) string {
	return pgx.Identifier{name}.Sanitize()
}

// quoteQualified joins schema and table into a properly-escaped
// "schema"."table" pair. An empty schema falls back to a single
// "table" identifier (use sparingly — Postgres requires a schema for
// table-level grants in practice, but this keeps the helper composable).
func quoteQualified(schema, table string) string {
	if schema == "" {
		return quoteIdent(table)
	}
	return quoteIdent(schema) + "." + quoteIdent(table)
}

// BuildCreateRoleSQL returns the SQL statements that create a role
// idempotently. The first statement is a DO block that catches the
// duplicate_object exception so re-running on a database that already
// has the role is a no-op. A subsequent ALTER ROLE statement applies
// the LOGIN/INHERIT/CONNECTION LIMIT options so the role's settings
// match desired even when the role already existed.
//
// Returned slice is non-empty; the first element creates the role,
// the second (when emitted) aligns its options. Statements are
// suitable for pgx Conn.Exec.
func BuildCreateRoleSQL(role string, login, inherit bool, connLimit int) []string {
	if role == "" {
		return nil
	}
	ident := quoteIdent(role)

	// DO-block-wrapped CREATE ROLE that swallows duplicate_object so
	// the apply is idempotent. Single-quoted role literal is escaped
	// the same way Postgres expects (double single-quotes for embedded
	// apostrophes).
	createBlock := fmt.Sprintf(
		"DO $$ BEGIN CREATE ROLE %s; EXCEPTION WHEN duplicate_object THEN NULL; END $$;",
		ident,
	)

	// ALTER ROLE pinning options. We always emit the alter statement
	// even when the role is fresh: it is cheap and keeps the apply
	// idempotent across "create then drift" cycles.
	alter := buildAlterRoleStatement(ident, login, inherit, connLimit)

	return []string{createBlock, alter}
}

// BuildAlterRoleSQL returns a single ALTER ROLE statement aligning a
// role's LOGIN / INHERIT / CONNECTION LIMIT to the desired values.
// Used by drift remediation. Returns a one-element slice for symmetry
// with the other helpers.
func BuildAlterRoleSQL(role string, login, inherit bool, connLimit int) []string {
	if role == "" {
		return nil
	}
	return []string{buildAlterRoleStatement(quoteIdent(role), login, inherit, connLimit)}
}

// buildAlterRoleStatement is the shared formatter for create + alter.
func buildAlterRoleStatement(ident string, login, inherit bool, connLimit int) string {
	parts := []string{"ALTER ROLE", ident, "WITH"}
	if login {
		parts = append(parts, "LOGIN")
	} else {
		parts = append(parts, "NOLOGIN")
	}
	if inherit {
		parts = append(parts, "INHERIT")
	} else {
		parts = append(parts, "NOINHERIT")
	}
	if connLimit < 0 {
		parts = append(parts, "CONNECTION LIMIT -1")
	} else {
		parts = append(parts, fmt.Sprintf("CONNECTION LIMIT %d", connLimit))
	}
	return strings.Join(parts, " ") + ";"
}

// BuildGrantSQL returns one GRANT statement per (schema, table) pair.
// Privileges are joined into a single comma-separated clause (Postgres
// supports multi-privilege GRANTs) so the generated SQL is compact:
//
//	GRANT SELECT, UPDATE ON TABLE "public"."accounts" TO "payments_rw";
//
// privileges and tables are sorted before iteration so two calls with
// equivalent (set-equal) inputs produce identical statements.
//
// schema is required; if empty the helper returns nil because GRANT ON
// TABLE without a schema reference is ambiguous in Postgres. asRole is
// the role being granted to; database is informational only (the
// connection itself selects the database).
func BuildGrantSQL(asRole, _ /*database*/, schema string, privileges, tables []string) []string {
	if asRole == "" || schema == "" || len(privileges) == 0 || len(tables) == 0 {
		return nil
	}
	privs := append([]string(nil), privileges...)
	for i := range privs {
		privs[i] = strings.ToUpper(strings.TrimSpace(privs[i]))
	}
	sort.Strings(privs)
	tbls := append([]string(nil), tables...)
	sort.Strings(tbls)
	privClause := strings.Join(privs, ", ")
	roleIdent := quoteIdent(asRole)

	stmts := make([]string, 0, len(tbls))
	for _, t := range tbls {
		stmts = append(stmts, fmt.Sprintf(
			"GRANT %s ON TABLE %s TO %s;",
			privClause, quoteQualified(schema, t), roleIdent,
		))
	}
	return stmts
}

// BuildRevokeSQL mirrors BuildGrantSQL but emits REVOKE statements.
// Used by drift remediation and by Apply when a desired grant is being
// shrunk (a privilege removed from the model).
func BuildRevokeSQL(asRole, _ /*database*/, schema string, privileges, tables []string) []string {
	if asRole == "" || schema == "" || len(privileges) == 0 || len(tables) == 0 {
		return nil
	}
	privs := append([]string(nil), privileges...)
	for i := range privs {
		privs[i] = strings.ToUpper(strings.TrimSpace(privs[i]))
	}
	sort.Strings(privs)
	tbls := append([]string(nil), tables...)
	sort.Strings(tbls)
	privClause := strings.Join(privs, ", ")
	roleIdent := quoteIdent(asRole)

	stmts := make([]string, 0, len(tbls))
	for _, t := range tbls {
		stmts = append(stmts, fmt.Sprintf(
			"REVOKE %s ON TABLE %s FROM %s;",
			privClause, quoteQualified(schema, t), roleIdent,
		))
	}
	return stmts
}
