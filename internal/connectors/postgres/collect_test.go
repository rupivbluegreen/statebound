package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"statebound.dev/statebound/internal/connectors"
)

// TestCollect_LiveTarget connects to the target Postgres declared by
// STATEBOUND_PG_TARGET_DSN, ensures a known role + grant exist, then
// verifies CollectActualState surfaces both. Skipped when the env var
// is unset so CI passes without a target.
//
// The test seeds an isolated role/table so it does not race with other
// data on the database; cleanup at the end leaves the database empty.
//
// To run:
//
//	STATEBOUND_PG_TARGET_DSN="postgres://statebound:statebound@localhost:5432/postgres?sslmode=disable" \
//	  ./scripts/go.sh test ./internal/connectors/postgres/...
func TestCollect_LiveTarget(t *testing.T) {
	dsn := os.Getenv(targetDSNEnv)
	if dsn == "" {
		t.Skipf("set %s to enable live-target collect tests", targetDSNEnv)
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	const (
		seedRole   = "statebound_collect_test_role"
		seedTable  = "statebound_collect_test_table"
		seedSchema = "public"
	)

	// Seed: create role + table + grant.
	for _, q := range []string{
		fmt.Sprintf(`DO $$ BEGIN CREATE ROLE %s LOGIN INHERIT CONNECTION LIMIT 5; EXCEPTION WHEN duplicate_object THEN NULL; END $$;`, quoteIdent(seedRole)),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.%s (id int);`, quoteIdent(seedSchema), quoteIdent(seedTable)),
		fmt.Sprintf(`GRANT SELECT ON TABLE %s.%s TO %s;`, quoteIdent(seedSchema), quoteIdent(seedTable), quoteIdent(seedRole)),
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	// Cleanup at end.
	t.Cleanup(func() {
		ctx := context.Background()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			return
		}
		defer conn.Close(ctx)
		// Order matters: revoke before drop role.
		for _, q := range []string{
			fmt.Sprintf(`REVOKE SELECT ON TABLE %s.%s FROM %s;`, quoteIdent(seedSchema), quoteIdent(seedTable), quoteIdent(seedRole)),
			fmt.Sprintf(`DROP TABLE IF EXISTS %s.%s;`, quoteIdent(seedSchema), quoteIdent(seedTable)),
			fmt.Sprintf(`DROP ROLE IF EXISTS %s;`, quoteIdent(seedRole)),
		} {
			_, _ = conn.Exec(ctx, q)
		}
	})

	c := New()
	state, err := c.CollectActualState(ctx, connectors.CollectionScope{Host: dsn})
	if err != nil {
		t.Fatalf("CollectActualState: %v", err)
	}

	// Should observe at least one role item (our seed) and one grant item.
	var sawRole, sawGrant bool
	for _, it := range state.Items {
		switch it.ResourceKind {
		case "postgres.role":
			if name, _ := it.Body["role"].(string); name == seedRole {
				sawRole = true
				if login, _ := it.Body["login"].(bool); !login {
					t.Errorf("seed role login = false, want true")
				}
			}
		case "postgres.grant":
			if asRole, _ := it.Body["as_role"].(string); asRole == seedRole {
				sawGrant = true
			}
		}
	}
	if !sawRole {
		t.Errorf("did not see seed role %q in actual state items", seedRole)
	}
	if !sawGrant {
		t.Errorf("did not see seed grant for role %q", seedRole)
	}

	// Determinism: re-collect, confirm Items align.
	state2, err := c.CollectActualState(ctx, connectors.CollectionScope{Host: dsn})
	if err != nil {
		t.Fatalf("CollectActualState 2nd call: %v", err)
	}
	if len(state.Items) != len(state2.Items) {
		t.Fatalf("len(Items) differs across collects: %d vs %d", len(state.Items), len(state2.Items))
	}
	for i := range state.Items {
		if state.Items[i].ResourceRef != state2.Items[i].ResourceRef {
			t.Errorf("ResourceRef[%d] differs across collects: %q vs %q",
				i, state.Items[i].ResourceRef, state2.Items[i].ResourceRef)
		}
	}
}

func TestCollect_MissingDSN(t *testing.T) {
	_, err := New().CollectActualState(context.Background(), connectors.CollectionScope{})
	if err == nil {
		t.Fatal("CollectActualState({}) returned no error")
	}
}

func TestParseDSNParts_URLForm(t *testing.T) {
	host, port, db, sourceRef := parseDSNParts("postgres://user:pw@example.com:6543/payments?sslmode=disable")
	if host != "example.com" || port != "6543" || db != "payments" {
		t.Errorf("got host=%q port=%q db=%q", host, port, db)
	}
	// SourceRef must NOT contain the password.
	if want, got := "postgres://example.com:6543/payments", sourceRef; got != want {
		t.Errorf("sourceRef = %q, want %q", got, want)
	}
}

func TestParseDSNParts_KeywordForm(t *testing.T) {
	host, port, db, _ := parseDSNParts("host=db.local port=5444 dbname=ops user=u password=secret")
	if host != "db.local" || port != "5444" || db != "ops" {
		t.Errorf("got host=%q port=%q db=%q", host, port, db)
	}
}

// cleanupAppliedTargets is invoked by apply_test.go's live tests to
// strip whatever the synthetic plan installed (role payments_batch
// + GRANT SELECT for payments_readonly) so a subsequent run starts
// clean. Best-effort — ignores errors because the plan may have
// failed mid-way and not all rows exist.
func cleanupAppliedTargets(t *testing.T, dsn string, _ *connectors.PlanForApply) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return
	}
	defer conn.Close(ctx)
	stmts := []string{
		`DROP ROLE IF EXISTS payments_batch;`,
		`DROP ROLE IF EXISTS payments_readonly;`,
	}
	for _, s := range stmts {
		_, _ = conn.Exec(ctx, s)
	}
}
