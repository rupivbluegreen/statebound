package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
)

// syntheticModel builds a minimal ProductAuthorizationModel with one
// postgres.role authorization on a service account and one
// postgres.grant authorization on an entitlement, both targeting the
// same prod-scoped asset.
func syntheticModel() *model.ProductAuthorizationModel {
	return &model.ProductAuthorizationModel{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata:   model.ProductMetadata{Product: "payments-api", Owner: "platform-security"},
		Spec: model.ProductSpec{
			Assets: []model.YAMLAsset{
				{Name: "pay-postgres-01", Type: "postgres-database", Environment: "prod",
					Labels: map[string]string{"database": "payments", "cluster": "pay-pg"}},
			},
			AssetScopes: []model.YAMLAssetScope{
				{Name: "prod-postgres-payments", Selector: model.YAMLAssetSelector{
					Type: "postgres-database", Environment: "prod",
				}},
			},
			Entitlements: []model.YAMLEntitlement{
				{
					Name:    "payments-readonly",
					Owner:   "payments-team",
					Purpose: "Read-only DB access",
					Authorizations: []model.YAMLAuthorization{
						{
							Type:  "postgres.grant",
							Scope: "prod-postgres-payments",
							Spec: map[string]any{
								"database":   "payments",
								"schema":     "public",
								"as_role":    "payments_readonly",
								"privileges": []any{"SELECT"},
								"objects": map[string]any{
									"tables": []any{"accounts", "transactions"},
								},
							},
						},
					},
				},
			},
			ServiceAccounts: []model.YAMLServiceAccount{
				{
					Name:         "payments-batch",
					Owner:        "payments-team",
					UsagePattern: "system-to-system",
					Purpose:      "Settlement jobs",
					Authorizations: []model.YAMLAuthorization{
						{
							Type:  "postgres.role",
							Scope: "prod-postgres-payments",
							Spec: map[string]any{
								"database":         "payments",
								"role":             "payments_batch",
								"login":            true,
								"inherit":          true,
								"connection_limit": 10,
								"password_ref":     "vault:/payments/batch",
							},
						},
					},
				},
			},
		},
	}
}

func syntheticState() connectors.ApprovedState {
	m := syntheticModel()
	return connectors.ApprovedState{
		Product:           &domain.Product{ID: domain.ID("test-product"), Name: m.Metadata.Product},
		ApprovedVersionID: domain.ID("test-av"),
		Sequence:          1,
		Model:             m,
	}
}

func TestPlan_BasicShape(t *testing.T) {
	c := New()
	res, err := c.Plan(context.Background(), syntheticState())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if res.ConnectorName != "postgres" {
		t.Errorf("ConnectorName = %q", res.ConnectorName)
	}
	if res.ConnectorVersion != "0.6.0" {
		t.Errorf("ConnectorVersion = %q", res.ConnectorVersion)
	}
	if len(res.Items) != 2 {
		t.Fatalf("len(Items) = %d, want 2", len(res.Items))
	}

	// Item 1: postgres.role (service account first, before entitlement grants).
	first := res.Items[0]
	if first.ResourceKind != "postgres.role" {
		t.Errorf("Items[0].ResourceKind = %q, want postgres.role", first.ResourceKind)
	}
	wantRoleRef := "prod-postgres-payments:payments:role:payments_batch"
	if first.ResourceRef != wantRoleRef {
		t.Errorf("Items[0].ResourceRef = %q, want %q", first.ResourceRef, wantRoleRef)
	}
	if first.Action != "create" {
		t.Errorf("Items[0].Action = %q, want create", first.Action)
	}
	if first.Risk != "high" {
		t.Errorf("Items[0].Risk = %q, want high (prod scope)", first.Risk)
	}
	if got, want := first.Body["role"], "payments_batch"; got != want {
		t.Errorf("Body.role = %v, want %v", got, want)
	}

	// Item 2: postgres.grant.
	second := res.Items[1]
	if second.ResourceKind != "postgres.grant" {
		t.Errorf("Items[1].ResourceKind = %q, want postgres.grant", second.ResourceKind)
	}
	if !strings.Contains(second.ResourceRef, "grant:payments_readonly:SELECT:accounts,transactions") {
		t.Errorf("Items[1].ResourceRef = %q (missing canonical key)", second.ResourceRef)
	}
	if second.Risk != "high" {
		// Prod scope bumps to high even for SELECT-only.
		t.Errorf("Items[1].Risk = %q, want high (prod scope)", second.Risk)
	}
	privs, ok := second.Body["privileges"].([]string)
	if !ok {
		t.Fatalf("Body.privileges not []string: %T", second.Body["privileges"])
	}
	if !reflect.DeepEqual(privs, []string{"SELECT"}) {
		t.Errorf("Body.privileges = %v", privs)
	}
}

func TestPlan_Deterministic(t *testing.T) {
	c := New()
	state := syntheticState()
	a, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan #1: %v", err)
	}
	b, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan #2: %v", err)
	}
	if !reflect.DeepEqual(a.Content, b.Content) {
		t.Fatalf("Content not deeply equal between Plan calls")
	}
	aJSON, err := json.Marshal(a.Content)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	bJSON, err := json.Marshal(b.Content)
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	if string(aJSON) != string(bJSON) {
		t.Fatalf("JSON differs across runs:\nA=%s\nB=%s", aJSON, bJSON)
	}
}

func TestPlan_DeterministicUnderInputReorder(t *testing.T) {
	c := New()
	m := syntheticModel()
	// Reorder privileges + tables in the source: should produce identical plan.
	auth := &m.Spec.Entitlements[0].Authorizations[0]
	auth.Spec["privileges"] = []any{"SELECT"}
	if objs, ok := auth.Spec["objects"].(map[string]any); ok {
		objs["tables"] = []any{"transactions", "accounts"}
	}
	state1 := connectors.ApprovedState{Sequence: 1, Model: m}

	m2 := syntheticModel()
	state2 := connectors.ApprovedState{Sequence: 1, Model: m2}

	a, _ := c.Plan(context.Background(), state1)
	b, _ := c.Plan(context.Background(), state2)
	aJSON, _ := json.Marshal(a.Content)
	bJSON, _ := json.Marshal(b.Content)
	if string(aJSON) != string(bJSON) {
		t.Errorf("plan output differs after reordering equivalent inputs:\nA=%s\nB=%s", aJSON, bJSON)
	}
}

func TestPlan_NilModelReturnsError(t *testing.T) {
	_, err := New().Plan(context.Background(), connectors.ApprovedState{})
	if err == nil {
		t.Fatal("Plan(nil model) returned no error")
	}
}

func TestValidateDesiredState_Happy(t *testing.T) {
	findings, err := New().ValidateDesiredState(context.Background(), syntheticState())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "error" {
			t.Errorf("unexpected error finding: %+v", f)
		}
	}
}

func TestValidateDesiredState_MissingDatabase(t *testing.T) {
	m := syntheticModel()
	delete(m.Spec.Entitlements[0].Authorizations[0].Spec, "database")
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, err := New().ValidateDesiredState(context.Background(), state)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := false
	for _, f := range findings {
		if f.Severity == "error" && strings.Contains(f.Message, "database") {
			got = true
		}
	}
	if !got {
		t.Errorf("expected database-required error finding; got %+v", findings)
	}
}

func TestValidateDesiredState_MissingPrivileges(t *testing.T) {
	m := syntheticModel()
	m.Spec.Entitlements[0].Authorizations[0].Spec["privileges"] = []any{}
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, _ := New().ValidateDesiredState(context.Background(), state)
	got := false
	for _, f := range findings {
		if f.Severity == "error" && strings.Contains(f.Message, "privileges") {
			got = true
		}
	}
	if !got {
		t.Errorf("expected privileges-required error finding; got %+v", findings)
	}
}

func TestValidateDesiredState_MissingRole(t *testing.T) {
	m := syntheticModel()
	delete(m.Spec.ServiceAccounts[0].Authorizations[0].Spec, "role")
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, _ := New().ValidateDesiredState(context.Background(), state)
	got := false
	for _, f := range findings {
		if f.Severity == "error" && strings.Contains(f.Message, "role") {
			got = true
		}
	}
	if !got {
		t.Errorf("expected role-required error finding; got %+v", findings)
	}
}

func TestValidateDesiredState_AllPrivilegesWarns(t *testing.T) {
	m := syntheticModel()
	m.Spec.Entitlements[0].Authorizations[0].Spec["privileges"] = []any{"ALL"}
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, _ := New().ValidateDesiredState(context.Background(), state)
	got := false
	for _, f := range findings {
		if f.Severity == "warning" && strings.Contains(strings.ToLower(f.Message), "all") {
			got = true
		}
	}
	if !got {
		t.Errorf("expected ALL warning, got %+v", findings)
	}
}

func TestValidateDesiredState_LoginWithoutPasswordRefWarns(t *testing.T) {
	m := syntheticModel()
	delete(m.Spec.ServiceAccounts[0].Authorizations[0].Spec, "password_ref")
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, _ := New().ValidateDesiredState(context.Background(), state)
	got := false
	for _, f := range findings {
		if f.Severity == "warning" && strings.Contains(f.Path, "password_ref") {
			got = true
		}
	}
	if !got {
		t.Errorf("expected password_ref warning, got %+v", findings)
	}
}

func TestValidateDesiredState_DanglingScope(t *testing.T) {
	m := syntheticModel()
	m.Spec.Entitlements[0].Authorizations[0].Scope = "no-such-scope"
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, _ := New().ValidateDesiredState(context.Background(), state)
	got := false
	for _, f := range findings {
		if f.Severity == "error" && strings.Contains(f.Message, "scope") {
			got = true
		}
	}
	if !got {
		t.Errorf("expected dangling scope error, got %+v", findings)
	}
}

func TestPlan_AdvertisesAllCapabilities(t *testing.T) {
	caps := New().Capabilities()
	want := map[connectors.Capability]bool{
		connectors.CapabilityPlan:           true,
		connectors.CapabilityApply:          true,
		connectors.CapabilityCollectActual:  true,
		connectors.CapabilityCompare:        true,
	}
	for _, c := range caps {
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("missing capabilities: %v", want)
	}
}
