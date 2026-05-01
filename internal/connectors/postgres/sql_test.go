package postgres

import (
	"strings"
	"testing"
)

func TestBuildCreateRoleSQL_BasicLogin(t *testing.T) {
	stmts := BuildCreateRoleSQL("payments_rw", true, true, 10)
	if len(stmts) != 2 {
		t.Fatalf("len = %d, want 2", len(stmts))
	}
	if !strings.Contains(stmts[0], `CREATE ROLE "payments_rw"`) {
		t.Errorf("create stmt missing quoted role name: %q", stmts[0])
	}
	if !strings.Contains(stmts[0], "duplicate_object") {
		t.Errorf("create stmt missing duplicate_object guard: %q", stmts[0])
	}
	if !strings.Contains(stmts[1], `ALTER ROLE "payments_rw" WITH LOGIN INHERIT CONNECTION LIMIT 10;`) {
		t.Errorf("alter stmt mismatch: %q", stmts[1])
	}
}

func TestBuildCreateRoleSQL_NoLoginUnlimited(t *testing.T) {
	stmts := BuildCreateRoleSQL("ops_readonly", false, false, -1)
	if len(stmts) != 2 {
		t.Fatalf("len = %d, want 2", len(stmts))
	}
	if !strings.Contains(stmts[1], "NOLOGIN") {
		t.Errorf("expected NOLOGIN: %q", stmts[1])
	}
	if !strings.Contains(stmts[1], "NOINHERIT") {
		t.Errorf("expected NOINHERIT: %q", stmts[1])
	}
	if !strings.Contains(stmts[1], "CONNECTION LIMIT -1") {
		t.Errorf("expected unlimited conn limit: %q", stmts[1])
	}
}

func TestBuildCreateRoleSQL_QuotesEmbeddedQuote(t *testing.T) {
	// Role names with embedded double quotes should round-trip via
	// pgx.Identifier sanitization.
	stmts := BuildCreateRoleSQL(`weird"role`, true, true, -1)
	if len(stmts) != 2 {
		t.Fatalf("len = %d, want 2", len(stmts))
	}
	// pgx escapes embedded " by doubling: weird"role -> "weird""role"
	if !strings.Contains(stmts[0], `"weird""role"`) {
		t.Errorf("expected sanitised role name in create stmt: %q", stmts[0])
	}
}

func TestBuildCreateRoleSQL_EmptyRoleNoStmts(t *testing.T) {
	if got := BuildCreateRoleSQL("", true, true, -1); got != nil {
		t.Errorf("empty role returned %v, want nil", got)
	}
}

func TestBuildAlterRoleSQL_Single(t *testing.T) {
	stmts := BuildAlterRoleSQL("svc_acct", true, false, 5)
	if len(stmts) != 1 {
		t.Fatalf("len = %d, want 1", len(stmts))
	}
	want := `ALTER ROLE "svc_acct" WITH LOGIN NOINHERIT CONNECTION LIMIT 5;`
	if stmts[0] != want {
		t.Errorf("alter mismatch:\n got %q\nwant %q", stmts[0], want)
	}
}

func TestBuildGrantSQL_ConsolidatedPrivileges(t *testing.T) {
	stmts := BuildGrantSQL(
		"payments_rw", "payments", "public",
		[]string{"SELECT", "UPDATE"},
		[]string{"accounts", "transactions"},
	)
	if len(stmts) != 2 {
		t.Fatalf("len = %d, want 2 (one per table)", len(stmts))
	}
	// Privileges should appear together in a single GRANT clause.
	for _, s := range stmts {
		if !strings.HasPrefix(s, "GRANT SELECT, UPDATE ON TABLE ") {
			t.Errorf("grant stmt does not consolidate privileges: %q", s)
		}
	}
	// Tables should be lex-sorted.
	if !strings.Contains(stmts[0], `"public"."accounts"`) {
		t.Errorf("first stmt should target accounts (sorted): %q", stmts[0])
	}
	if !strings.Contains(stmts[1], `"public"."transactions"`) {
		t.Errorf("second stmt should target transactions: %q", stmts[1])
	}
	// Role identifier quoted.
	for _, s := range stmts {
		if !strings.HasSuffix(s, `TO "payments_rw";`) {
			t.Errorf("grant stmt missing quoted role: %q", s)
		}
	}
}

func TestBuildGrantSQL_DeterministicAcrossInputOrder(t *testing.T) {
	a := BuildGrantSQL("r", "db", "s", []string{"UPDATE", "SELECT"}, []string{"t2", "t1"})
	b := BuildGrantSQL("r", "db", "s", []string{"SELECT", "UPDATE"}, []string{"t1", "t2"})
	if len(a) != len(b) {
		t.Fatalf("len mismatch %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("statement %d differs:\n a=%q\n b=%q", i, a[i], b[i])
		}
	}
}

func TestBuildGrantSQL_GuardClauses(t *testing.T) {
	cases := []struct {
		name    string
		asRole  string
		schema  string
		privs   []string
		tables  []string
		wantNil bool
	}{
		{"empty role", "", "public", []string{"SELECT"}, []string{"t"}, true},
		{"empty schema", "r", "", []string{"SELECT"}, []string{"t"}, true},
		{"empty privs", "r", "public", []string{}, []string{"t"}, true},
		{"empty tables", "r", "public", []string{"SELECT"}, []string{}, true},
		{"happy", "r", "public", []string{"SELECT"}, []string{"t"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildGrantSQL(tc.asRole, "db", tc.schema, tc.privs, tc.tables)
			if tc.wantNil && got != nil {
				t.Errorf("expected nil, got %v", got)
			}
			if !tc.wantNil && got == nil {
				t.Errorf("expected non-nil")
			}
		})
	}
}

func TestBuildRevokeSQL_MirrorsGrant(t *testing.T) {
	stmts := BuildRevokeSQL(
		"payments_rw", "payments", "public",
		[]string{"SELECT"},
		[]string{"accounts"},
	)
	if len(stmts) != 1 {
		t.Fatalf("len = %d, want 1", len(stmts))
	}
	want := `REVOKE SELECT ON TABLE "public"."accounts" FROM "payments_rw";`
	if stmts[0] != want {
		t.Errorf("revoke mismatch:\n got %q\nwant %q", stmts[0], want)
	}
}

func TestQuoteIdent_HandlesEmbeddedQuote(t *testing.T) {
	// pgx.Identifier should sanitise embedded quotes — double them.
	got := quoteIdent(`evil"ident`)
	want := `"evil""ident"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestQuoteQualified_SchemaTable(t *testing.T) {
	got := quoteQualified("public", "accounts")
	want := `"public"."accounts"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// Empty schema falls back to plain identifier.
	got2 := quoteQualified("", "loners")
	want2 := `"loners"`
	if got2 != want2 {
		t.Errorf("got %q, want %q", got2, want2)
	}
}
