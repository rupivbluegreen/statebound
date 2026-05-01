package linux_sudo

import (
	"context"
	"reflect"
	"testing"

	"statebound.dev/statebound/internal/connectors"
)

// actualFromPlan rebuilds an ActualState that matches the desired plan
// exactly. Used by no-drift round-trip tests.
func actualFromPlan(t *testing.T, plan *connectors.PlanResult) *connectors.ActualState {
	t.Helper()
	items := make([]connectors.ActualStateItem, 0, len(plan.Items))
	for _, p := range plan.Items {
		items = append(items, connectors.ActualStateItem{
			ResourceKind: p.ResourceKind,
			ResourceRef:  p.ResourceRef,
			Body:         actualBodyFromPlanItem(p),
		})
	}
	return &connectors.ActualState{
		ConnectorName:    "linux-sudo",
		ConnectorVersion: "0.4.0",
		Items:            items,
	}
}

// actualBodyFromPlanItem constructs a body that mirrors what a fresh
// CollectActualState run would produce for this plan item.
func actualBodyFromPlanItem(p connectors.PlanItem) map[string]any {
	switch p.ResourceKind {
	case "linux.sudoers-fragment":
		// Re-derive allows/denies from the rendered content so the
		// "actual" side carries the same canonical lists Compare
		// expects.
		content, _ := p.Body["content"].(string)
		parsed := parseSudoersFragment([]byte(content))
		return map[string]any{
			"path":        p.Body["path"],
			"scope":       p.Body["scope"],
			"entitlement": p.Body["entitlement"],
			"as_user":     p.Body["as_user"],
			"content":     content,
			"allows":      parsed.allows,
			"denies":      parsed.denies,
		}
	case "linux.local-group-membership":
		// Local-group bodies are already in the right shape.
		members, _ := p.Body["members"].([]string)
		return map[string]any{
			"scope":   p.Body["scope"],
			"group":   p.Body["group"],
			"members": members,
		}
	default:
		return p.Body
	}
}

func TestCompare_NoDrift(t *testing.T) {
	c := New()
	state := fixtureState(t)
	plan, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	actual := actualFromPlan(t, plan)
	findings, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCompare_MissingResource(t *testing.T) {
	c := New()
	state := fixtureState(t)
	plan, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// Drop the first plan item from actual.
	actual := actualFromPlan(t, plan)
	actual.Items = actual.Items[1:]

	findings, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Kind != "missing" {
		t.Errorf("Kind = %q, want missing", findings[0].Kind)
	}
	if findings[0].ResourceRef != plan.Items[0].ResourceRef {
		t.Errorf("ResourceRef = %q, want %q", findings[0].ResourceRef, plan.Items[0].ResourceRef)
	}
}

func TestCompare_UnexpectedResource(t *testing.T) {
	c := New()
	state := fixtureState(t)
	plan, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	actual := actualFromPlan(t, plan)
	// Add a stray item not present in desired.
	actual.Items = append(actual.Items, connectors.ActualStateItem{
		ResourceKind: "linux.sudoers-fragment",
		ResourceRef:  "prod-linux:/etc/sudoers.d/stray",
		Body: map[string]any{
			"path":        "/etc/sudoers.d/stray",
			"scope":       "prod-linux",
			"entitlement": "stray",
			"as_user":     "root",
			"allows":      []string{"/usr/bin/ls"},
			"denies":      []string{},
		},
	})
	findings, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Kind != "unexpected" {
		t.Errorf("Kind = %q, want unexpected", findings[0].Kind)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("Severity = %q, want medium", findings[0].Severity)
	}
	if findings[0].ResourceRef != "prod-linux:/etc/sudoers.d/stray" {
		t.Errorf("ResourceRef = %q", findings[0].ResourceRef)
	}
}

func TestCompare_ModifiedAllows(t *testing.T) {
	c := New()
	state := fixtureState(t)
	plan, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// Build actual with allows=[A,C] when desired=[journalctl, systemctl].
	// We mutate the first sudoers-fragment item: drop systemctl,
	// add an unrelated allow.
	actual := actualFromPlan(t, plan)
	for i := range actual.Items {
		if actual.Items[i].ResourceKind != "linux.sudoers-fragment" {
			continue
		}
		actual.Items[i].Body["allows"] = []string{
			"/usr/bin/journalctl -u payments --since today",
			"/usr/bin/whoami",
		}
		break
	}
	findings, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Kind != "modified" {
		t.Errorf("Kind = %q, want modified", f.Kind)
	}
	added, _ := f.Diff["added_allows"].([]string)
	removed, _ := f.Diff["removed_allows"].([]string)
	if !reflect.DeepEqual(added, []string{"/usr/bin/whoami"}) {
		t.Errorf("added_allows = %v", added)
	}
	if !reflect.DeepEqual(removed, []string{"/usr/bin/systemctl status payments"}) {
		t.Errorf("removed_allows = %v", removed)
	}
}

func TestCompare_RootEscalation(t *testing.T) {
	c := New()
	// Build a synthetic model with as_user=alice.
	m := newSyntheticSudoModel("scope-a", "alice", []any{"/usr/bin/ls"}, []any{})
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	plan, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// Mutate actual to as_user=root.
	actual := actualFromPlan(t, plan)
	for i := range actual.Items {
		actual.Items[i].Body["as_user"] = "root"
	}
	findings, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for as_user mismatch")
	}
	var asUserFinding *connectors.DriftFinding
	for i := range findings {
		if findings[i].Diff["field"] == "as_user" {
			asUserFinding = &findings[i]
			break
		}
	}
	if asUserFinding == nil {
		t.Fatalf("no as_user finding in %+v", findings)
	}
	if asUserFinding.Severity != "high" && asUserFinding.Severity != "critical" {
		t.Errorf("Severity = %q, want high or critical", asUserFinding.Severity)
	}
}

func TestCompare_NilActual(t *testing.T) {
	c := New()
	state := fixtureState(t)
	_, err := c.Compare(context.Background(), state, nil)
	if err == nil {
		t.Fatal("expected error for nil actual, got nil")
	}
}

func TestCompare_Deterministic(t *testing.T) {
	c := New()
	state := fixtureState(t)
	plan, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	actual := actualFromPlan(t, plan)
	// Mutate to produce some drift.
	actual.Items[0].Body["allows"] = []string{"/usr/bin/whoami"}

	a, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare #1: %v", err)
	}
	b, err := c.Compare(context.Background(), state, actual)
	if err != nil {
		t.Fatalf("Compare #2: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("findings differ across runs.\nA=%+v\nB=%+v", a, b)
	}
}

func TestCompare_AllowsWildcardCriticalOnAdd(t *testing.T) {
	// When an added allow is a wildcard, severity must be critical.
	added := []string{"/usr/bin/foo *"}
	removed := []string{}
	if got := allowChangeSeverity(added, removed); got != "critical" {
		t.Errorf("allowChangeSeverity = %q, want critical", got)
	}
}

func TestCompare_AllowsRootHighOnAdd(t *testing.T) {
	added := []string{"/usr/bin/su root"}
	removed := []string{}
	if got := allowChangeSeverity(added, removed); got != "high" {
		t.Errorf("allowChangeSeverity = %q, want high", got)
	}
}
