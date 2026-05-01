package linux_sudo

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

// loadPaymentsAPIFixture parses examples/payments-api/model.yaml into a
// *model.ProductAuthorizationModel. The fixture path is resolved relative
// to this test file so the test works regardless of test cwd.
func loadPaymentsAPIFixture(t *testing.T) *model.ProductAuthorizationModel {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	// thisFile = .../internal/connectors/linux_sudo/sudo_test.go
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

// fixtureState builds a connectors.ApprovedState around the fixture model
// with a deterministic Sequence so plan output is reproducible.
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

func TestSudoPlan_PaymentsApiFixture(t *testing.T) {
	c := New()
	state := fixtureState(t)
	res, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if res.ConnectorName != "linux-sudo" {
		t.Errorf("ConnectorName = %q, want linux-sudo", res.ConnectorName)
	}
	if res.ConnectorVersion != "0.4.0" {
		t.Errorf("ConnectorVersion = %q, want 0.4.0", res.ConnectorVersion)
	}
	// Two items: sudoers fragment for payments-prod-readonly, local-group
	// membership for payments-batch.
	if len(res.Items) != 2 {
		t.Fatalf("len(Items) = %d, want 2; items=%+v", len(res.Items), res.Items)
	}

	// Item 1: sudoers fragment.
	first := res.Items[0]
	if first.Sequence != 1 {
		t.Errorf("Items[0].Sequence = %d, want 1", first.Sequence)
	}
	if first.Action != "create" {
		t.Errorf("Items[0].Action = %q, want create", first.Action)
	}
	if first.ResourceKind != "linux.sudoers-fragment" {
		t.Errorf("Items[0].ResourceKind = %q, want linux.sudoers-fragment", first.ResourceKind)
	}
	if first.ResourceRef != "prod-linux:/etc/sudoers.d/payments-prod-readonly" {
		t.Errorf("Items[0].ResourceRef = %q", first.ResourceRef)
	}
	// asUser=root, no wildcards => Risk == "high".
	if first.Risk != "high" {
		t.Errorf("Items[0].Risk = %q, want high", first.Risk)
	}
	if first.Note != "2 commands allowed; 0 denied" {
		t.Errorf("Items[0].Note = %q", first.Note)
	}
	body := first.Body
	if got, want := body["path"], "/etc/sudoers.d/payments-prod-readonly"; got != want {
		t.Errorf("Body.path = %q, want %q", got, want)
	}
	if got, want := body["scope"], "prod-linux"; got != want {
		t.Errorf("Body.scope = %q, want %q", got, want)
	}
	if got, want := body["as_user"], "root"; got != want {
		t.Errorf("Body.as_user = %q, want %q", got, want)
	}
	content, ok := body["content"].(string)
	if !ok {
		t.Fatalf("Body.content not a string: %T", body["content"])
	}
	if !strings.Contains(content, "%payments-prod-readonly ALL=(root)") {
		t.Errorf("rendered fragment missing principal/asUser line.\n---\n%s\n---", content)
	}
	// Commands sorted alphabetically: journalctl < systemctl in ASCII order.
	idxJournal := strings.Index(content, "/usr/bin/journalctl -u payments --since today")
	idxSystem := strings.Index(content, "/usr/bin/systemctl status payments")
	if idxJournal == -1 || idxSystem == -1 {
		t.Errorf("rendered fragment missing one or both commands.\n---\n%s\n---", content)
	}
	if idxJournal > idxSystem {
		t.Errorf("commands not lex-sorted (journalctl should precede systemctl).\n---\n%s\n---", content)
	}

	// Item 2: local-group membership.
	second := res.Items[1]
	if second.Sequence != 2 {
		t.Errorf("Items[1].Sequence = %d, want 2", second.Sequence)
	}
	if second.ResourceKind != "linux.local-group-membership" {
		t.Errorf("Items[1].ResourceKind = %q, want linux.local-group-membership", second.ResourceKind)
	}
	if second.Risk != "medium" {
		t.Errorf("Items[1].Risk = %q, want medium (prod-scoped)", second.Risk)
	}
	if got, want := second.Body["group"], "payments-runtime"; got != want {
		t.Errorf("Body.group = %q, want %q", got, want)
	}
	gotMembers, ok := second.Body["members"].([]string)
	if !ok {
		t.Fatalf("Body.members type = %T, want []string", second.Body["members"])
	}
	if !reflect.DeepEqual(gotMembers, []string{"payments-batch"}) {
		t.Errorf("Body.members = %v, want [payments-batch]", gotMembers)
	}
	if second.ResourceRef != "prod-linux:payments-runtime" {
		t.Errorf("Items[1].ResourceRef = %q", second.ResourceRef)
	}

	// Content envelope sanity check.
	if got, want := res.Content["connector"], "linux-sudo"; got != want {
		t.Errorf("Content.connector = %v, want %v", got, want)
	}
	if got, want := res.Content["version"], "0.4.0"; got != want {
		t.Errorf("Content.version = %v, want %v", got, want)
	}
	if got, want := res.Content["schema_version"], "linux-sudo.statebound.dev/v0alpha1"; got != want {
		t.Errorf("Content.schema_version = %v, want %v", got, want)
	}
}

func TestSudoPlan_Deterministic(t *testing.T) {
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
		t.Fatalf("JSON differs across runs:\nA=%s\nB=%s", aJSON, bJSON)
	}
}

func TestSudoPlan_WildcardEscalates(t *testing.T) {
	m := &model.ProductAuthorizationModel{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata:   model.ProductMetadata{Product: "wild", Owner: "team"},
		Spec: model.ProductSpec{
			AssetScopes: []model.YAMLAssetScope{{Name: "scope-a"}},
			Entitlements: []model.YAMLEntitlement{
				{
					Name:  "wild-ent",
					Owner: "team",
					Authorizations: []model.YAMLAuthorization{
						{
							Type:  "linux.sudo",
							Scope: "scope-a",
							Spec: map[string]any{
								"asUser": "appuser",
								"commands": map[string]any{
									"allow": []any{"*"},
									"deny":  []any{},
								},
							},
						},
					},
				},
			},
		},
	}
	state := connectors.ApprovedState{
		Product:  &domain.Product{Name: "wild"},
		Sequence: 1,
		Model:    m,
	}
	res, err := New().Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("len(Items) = %d, want 1", len(res.Items))
	}
	if res.Items[0].Risk != "critical" {
		t.Errorf("Risk = %q, want critical (wildcard allow)", res.Items[0].Risk)
	}
}

func TestSudoPlan_WildcardSubstringEscalates(t *testing.T) {
	m := newSyntheticSudoModel("scope-a", "appuser", []any{"/usr/bin/foo *"}, []any{})
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	res, err := New().Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if res.Items[0].Risk != "critical" {
		t.Errorf("Risk = %q, want critical (substring wildcard)", res.Items[0].Risk)
	}
}

func TestSudoValidate_WildcardWarning(t *testing.T) {
	m := newSyntheticSudoModel("scope-a", "appuser", []any{"/usr/bin/foo *"}, []any{})
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, err := New().ValidateDesiredState(context.Background(), state)
	if err != nil {
		t.Fatalf("ValidateDesiredState: %v", err)
	}
	if !containsFinding(findings, "warning", "wildcard sudo command flagged for elevated approval") {
		t.Errorf("expected wildcard warning; got %+v", findings)
	}
}

func TestSudoValidate_RootWarning(t *testing.T) {
	m := newSyntheticSudoModel("scope-a", "root", []any{"/usr/bin/ls"}, []any{})
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, err := New().ValidateDesiredState(context.Background(), state)
	if err != nil {
		t.Fatalf("ValidateDesiredState: %v", err)
	}
	if !containsFinding(findings, "warning", "root-equivalent grant") {
		t.Errorf("expected root warning; got %+v", findings)
	}
}

func TestSudoValidate_EmptyAllowAndDeny(t *testing.T) {
	m := newSyntheticSudoModel("scope-a", "appuser", []any{}, []any{})
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, err := New().ValidateDesiredState(context.Background(), state)
	if err != nil {
		t.Fatalf("ValidateDesiredState: %v", err)
	}
	if !containsFinding(findings, "error", "linux.sudo authorization has empty allow and deny lists") {
		t.Errorf("expected empty-allow-and-deny error; got %+v", findings)
	}
}

func TestSudoValidate_MissingScope(t *testing.T) {
	m := newSyntheticSudoModel("does-not-exist", "appuser", []any{"/usr/bin/ls"}, []any{})
	// Replace AssetScopes so the reference dangles.
	m.Spec.AssetScopes = nil
	state := connectors.ApprovedState{Sequence: 1, Model: m}
	findings, err := New().ValidateDesiredState(context.Background(), state)
	if err != nil {
		t.Fatalf("ValidateDesiredState: %v", err)
	}
	if !containsFinding(findings, "error", `asset scope "does-not-exist" not defined in model`) {
		t.Errorf("expected missing-scope error; got %+v", findings)
	}
}

// newSyntheticSudoModel builds a one-entitlement model with one
// linux.sudo authorization. Used by validation and risk tests.
func newSyntheticSudoModel(scope, asUser string, allow, deny []any) *model.ProductAuthorizationModel {
	return &model.ProductAuthorizationModel{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata:   model.ProductMetadata{Product: "synth", Owner: "team"},
		Spec: model.ProductSpec{
			AssetScopes: []model.YAMLAssetScope{{Name: scope}},
			Entitlements: []model.YAMLEntitlement{
				{
					Name:  "synth-ent",
					Owner: "team",
					Authorizations: []model.YAMLAuthorization{
						{
							Type:  "linux.sudo",
							Scope: scope,
							Spec: map[string]any{
								"asUser": asUser,
								"commands": map[string]any{
									"allow": allow,
									"deny":  deny,
								},
							},
						},
					},
				},
			},
		},
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
