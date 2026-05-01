package linux_ssh

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
)

func loadPaymentsAPIFixture(t *testing.T) *model.ProductAuthorizationModel {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	yamlPath := filepath.Join(repoRoot, "examples", "payments-api", "model.yaml")

	raw, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read fixture %q: %v", yamlPath, err)
	}
	var m model.ProductAuthorizationModel
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return &m
}

func fixtureState(t *testing.T) connectors.ApprovedState {
	t.Helper()
	m := loadPaymentsAPIFixture(t)
	return connectors.ApprovedState{
		Product:           &domain.Product{ID: domain.ID("test-product"), Name: m.Metadata.Product},
		ApprovedVersionID: domain.ID("test-av"),
		Sequence:          1,
		Model:             m,
	}
}

func TestSSHPlan_PaymentsApiFixture(t *testing.T) {
	c := New()
	state := fixtureState(t)
	res, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if res.ConnectorName != "linux-ssh" {
		t.Errorf("ConnectorName = %q, want linux-ssh", res.ConnectorName)
	}
	if res.ConnectorVersion != "0.4.0" {
		t.Errorf("ConnectorVersion = %q, want 0.4.0", res.ConnectorVersion)
	}
	// One linux.ssh authorization in the fixture: payments-prod-readonly
	// with methods [ssh] on prod-linux scope. Service account has no
	// linux.ssh authorization.
	if len(res.Items) != 1 {
		t.Fatalf("len(Items) = %d, want 1; items=%+v", len(res.Items), res.Items)
	}
	first := res.Items[0]
	if first.ResourceKind != "linux.ssh-access-list" {
		t.Errorf("Items[0].ResourceKind = %q, want linux.ssh-access-list", first.ResourceKind)
	}
	if first.ResourceRef != "prod-linux:ssh:payments-prod-readonly" {
		t.Errorf("Items[0].ResourceRef = %q", first.ResourceRef)
	}
	if first.Risk != "medium" {
		t.Errorf("Items[0].Risk = %q, want medium (prod scope)", first.Risk)
	}
	if first.Note != "principals resolved at apply time (Phase 6+)" {
		t.Errorf("Items[0].Note = %q", first.Note)
	}
	body := first.Body
	if got, want := body["scope"], "prod-linux"; got != want {
		t.Errorf("Body.scope = %q, want %q", got, want)
	}
	if got, want := body["entitlement"], "payments-prod-readonly"; got != want {
		t.Errorf("Body.entitlement = %q, want %q", got, want)
	}
	gotMethods, ok := body["methods"].([]string)
	if !ok {
		t.Fatalf("Body.methods type = %T, want []string", body["methods"])
	}
	if !reflect.DeepEqual(gotMethods, []string{"ssh"}) {
		t.Errorf("Body.methods = %v, want [ssh]", gotMethods)
	}
	gotPrincipals, ok := body["principals"].([]string)
	if !ok {
		t.Fatalf("Body.principals type = %T, want []string", body["principals"])
	}
	if len(gotPrincipals) != 0 {
		t.Errorf("Body.principals = %v, want empty (Phase 6+ resolves humans)", gotPrincipals)
	}
}

func TestSSHPlan_Deterministic(t *testing.T) {
	c := New()
	state := fixtureState(t)

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
		t.Fatalf("JSON differs across runs")
	}
}

func TestSSHPlan_ServiceAccountPrincipal(t *testing.T) {
	m := &model.ProductAuthorizationModel{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata:   model.ProductMetadata{Product: "synth", Owner: "team"},
		Spec: model.ProductSpec{
			AssetScopes: []model.YAMLAssetScope{{Name: "dev-linux"}},
			ServiceAccounts: []model.YAMLServiceAccount{
				{
					Name:  "ci-runner",
					Owner: "team",
					Authorizations: []model.YAMLAuthorization{
						{
							Type:  "linux.ssh",
							Scope: "dev-linux",
							Spec: map[string]any{
								"methods": []any{"ssh"},
							},
						},
					},
				},
			},
		},
	}
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	res, err := New().Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("len(Items) = %d, want 1", len(res.Items))
	}
	it := res.Items[0]
	if it.Risk != "low" {
		t.Errorf("Risk = %q, want low (non-prod scope)", it.Risk)
	}
	if it.Note != "" {
		t.Errorf("Note = %q, want empty for SA item", it.Note)
	}
	gotPrincipals, ok := it.Body["principals"].([]string)
	if !ok {
		t.Fatalf("Body.principals type = %T", it.Body["principals"])
	}
	if !reflect.DeepEqual(gotPrincipals, []string{"ci-runner"}) {
		t.Errorf("Body.principals = %v, want [ci-runner]", gotPrincipals)
	}
}

func TestSSHValidate_ProdWarning(t *testing.T) {
	m := &model.ProductAuthorizationModel{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata:   model.ProductMetadata{Product: "synth", Owner: "team"},
		Spec: model.ProductSpec{
			AssetScopes: []model.YAMLAssetScope{{Name: "prod-linux"}},
			Entitlements: []model.YAMLEntitlement{
				{
					Name:  "ssh-ent",
					Owner: "team",
					Authorizations: []model.YAMLAuthorization{
						{Type: "linux.ssh", Scope: "prod-linux", Spec: map[string]any{"methods": []any{"ssh"}}},
					},
				},
			},
		},
	}
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, err := New().ValidateDesiredState(context.Background(), state)
	if err != nil {
		t.Fatalf("ValidateDesiredState: %v", err)
	}
	if !containsFinding(findings, "warning", "prod-scoped SSH access") {
		t.Errorf("expected prod warning; got %+v", findings)
	}
}

func TestSSHValidate_MissingScope(t *testing.T) {
	m := &model.ProductAuthorizationModel{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata:   model.ProductMetadata{Product: "synth", Owner: "team"},
		Spec: model.ProductSpec{
			AssetScopes: nil,
			Entitlements: []model.YAMLEntitlement{
				{
					Name:  "ssh-ent",
					Owner: "team",
					Authorizations: []model.YAMLAuthorization{
						{Type: "linux.ssh", Scope: "missing", Spec: map[string]any{"methods": []any{"ssh"}}},
					},
				},
			},
		},
	}
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, err := New().ValidateDesiredState(context.Background(), state)
	if err != nil {
		t.Fatalf("ValidateDesiredState: %v", err)
	}
	if !containsFinding(findings, "error", `asset scope "missing" not defined in model`) {
		t.Errorf("expected missing-scope error; got %+v", findings)
	}
}

func containsFinding(findings []connectors.ValidationFinding, severity, msgSubstr string) bool {
	for _, f := range findings {
		if f.Severity == severity && strings.Contains(f.Message, msgSubstr) {
			return true
		}
	}
	return false
}
