package postgres

import (
	"context"
	"strings"
	"testing"

	"statebound.dev/statebound/internal/connectors"
)

// actualFromPlan rebuilds an ActualState whose items would canonical-key
// onto the desired plan items. Compare keys grants by
// (database, schema, asRole, table) and roles by (database, role), so
// the host portion of the actual ResourceRef does not affect alignment.
func actualFromPlan(plan *connectors.PlanResult) *connectors.ActualState {
	items := make([]connectors.ActualStateItem, 0)
	for _, p := range plan.Items {
		switch p.ResourceKind {
		case "postgres.role":
			db, _ := p.Body["database"].(string)
			role, _ := p.Body["role"].(string)
			items = append(items, connectors.ActualStateItem{
				ResourceKind: "postgres.role",
				ResourceRef:  "host:" + db + ":role:" + role,
				Body: map[string]any{
					"role":             role,
					"login":            p.Body["login"],
					"inherit":          p.Body["inherit"],
					"connection_limit": p.Body["connection_limit"],
					"database":         db,
				},
			})
		case "postgres.grant":
			db, _ := p.Body["database"].(string)
			schema, _ := p.Body["schema"].(string)
			asRole, _ := p.Body["as_role"].(string)
			tables := tablesFromBody(p.Body)
			privs := privilegesFromBody(p.Body)
			for _, tbl := range tables {
				items = append(items, connectors.ActualStateItem{
					ResourceKind: "postgres.grant",
					ResourceRef:  "host:" + db + ":" + schema + ":grant:" + asRole + ":tables:" + tbl,
					Body: map[string]any{
						"as_role":    asRole,
						"database":   db,
						"schema":     schema,
						"privileges": append([]string(nil), privs...),
						"objects": map[string]any{
							"tables": []string{tbl},
						},
					},
				})
			}
		}
	}
	return &connectors.ActualState{
		ConnectorName:    "postgres",
		ConnectorVersion: "0.6.0",
		Items:            items,
	}
}

func TestCompare_NoDrift(t *testing.T) {
	c := New()
	state := syntheticState()
	plan, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	actual := actualFromPlan(plan)
	findings, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCompare_NilActual(t *testing.T) {
	_, err := New().Compare(context.Background(), syntheticState(), nil)
	if err == nil {
		t.Fatal("Compare(nil actual) returned no error")
	}
}

func TestCompare_MissingRole(t *testing.T) {
	c := New()
	state := syntheticState()
	plan, _ := c.Plan(context.Background(), state)
	actual := actualFromPlan(plan)
	// Drop role item from actual.
	out := make([]connectors.ActualStateItem, 0, len(actual.Items))
	for _, it := range actual.Items {
		if it.ResourceKind != "postgres.role" {
			out = append(out, it)
		}
	}
	actual.Items = out

	findings, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Kind != "missing" {
		t.Errorf("Kind = %q, want missing", f.Kind)
	}
	if f.ResourceKind != "postgres.role" {
		t.Errorf("ResourceKind = %q", f.ResourceKind)
	}
}

func TestCompare_UnexpectedGrant(t *testing.T) {
	c := New()
	state := syntheticState()
	plan, _ := c.Plan(context.Background(), state)
	actual := actualFromPlan(plan)
	// Add an extra (unexpected) grant on the target.
	actual.Items = append(actual.Items, connectors.ActualStateItem{
		ResourceKind: "postgres.grant",
		ResourceRef:  "host:payments:public:grant:rogue_role:tables:secrets",
		Body: map[string]any{
			"as_role":    "rogue_role",
			"database":   "payments",
			"schema":     "public",
			"privileges": []string{"DELETE"},
			"objects":    map[string]any{"tables": []string{"secrets"}},
		},
	})
	findings, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Kind != "unexpected" {
		t.Errorf("Kind = %q, want unexpected", f.Kind)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want high (DELETE present)", f.Severity)
	}
}

func TestCompare_PrivilegesAdded(t *testing.T) {
	c := New()
	state := syntheticState()
	plan, _ := c.Plan(context.Background(), state)
	actual := actualFromPlan(plan)
	// Bump privileges on every actual grant to include DELETE.
	for i, it := range actual.Items {
		if it.ResourceKind == "postgres.grant" {
			privs := privilegesFromBody(it.Body)
			privs = append(privs, "DELETE")
			actual.Items[i].Body["privileges"] = privs
		}
	}
	findings, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected privilege-drift finding")
	}
	got := false
	for _, f := range findings {
		if f.Kind == "modified" && f.Severity == "high" && strings.Contains(f.Message, "drifted") {
			got = true
		}
	}
	if !got {
		t.Errorf("expected high-severity modified finding, got %+v", findings)
	}
}

func TestCompare_RoleLoginDrift(t *testing.T) {
	c := New()
	state := syntheticState()
	plan, _ := c.Plan(context.Background(), state)
	actual := actualFromPlan(plan)
	// Flip login on the actual role.
	for i, it := range actual.Items {
		if it.ResourceKind == "postgres.role" {
			actual.Items[i].Body["login"] = false
		}
	}
	findings, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	got := false
	for _, f := range findings {
		if f.Kind == "modified" && strings.Contains(f.Message, "login changed") {
			got = true
			if f.Severity != "high" {
				t.Errorf("Severity = %q, want high", f.Severity)
			}
		}
	}
	if !got {
		t.Errorf("expected login-changed finding, got %+v", findings)
	}
}

func TestCompare_DeterministicOrdering(t *testing.T) {
	c := New()
	state := syntheticState()
	plan, _ := c.Plan(context.Background(), state)
	actual := actualFromPlan(plan)
	// Drop everything to maximize findings.
	actual.Items = nil
	a, _ := c.Compare(context.Background(), state, actual)
	b, _ := c.Compare(context.Background(), state, actual)
	if len(a) != len(b) {
		t.Fatalf("len mismatch %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ResourceRef != b[i].ResourceRef || a[i].Kind != b[i].Kind {
			t.Errorf("ordering differs at %d", i)
		}
	}
}
