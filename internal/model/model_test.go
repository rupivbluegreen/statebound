package model_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
)

// validYAML is the §20 example with metadata.description added.
const validYAML = `apiVersion: statebound.dev/v1alpha1
kind: ProductAuthorizationModel
metadata:
  product: payments-api
  owner: platform-security
  description: Card-payments API governance baseline
spec:
  assets:
    - name: pay-linux-01
      type: linux-host
      environment: prod
      labels:
        app: payments
        region: eu

  assetScopes:
    - name: prod-linux
      selector:
        type: linux-host
        environment: prod
        app: payments

  entitlements:
    - name: payments-prod-readonly
      owner: payments-team
      purpose: Read-only production troubleshooting
      authorizations:
        - type: linux.ssh
          scope: prod-linux
          methods: [ssh]
        - type: linux.sudo
          scope: prod-linux
          asUser: root
          commands:
            allow:
              - /usr/bin/systemctl status payments
              - /usr/bin/journalctl -u payments --since today
            deny: []

  serviceAccounts:
    - name: payments-batch
      owner: payments-team
      usagePattern: system-to-system
      purpose: Runs scheduled settlement jobs
      authorizations:
        - type: linux.local-group
          scope: prod-linux
          group: payments-runtime
`

func TestUnmarshalYAML_Example(t *testing.T) {
	var doc model.ProductAuthorizationModel
	if err := yaml.Unmarshal([]byte(validYAML), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if doc.APIVersion != model.APIVersion {
		t.Errorf("APIVersion = %q, want %q", doc.APIVersion, model.APIVersion)
	}
	if doc.Kind != model.Kind {
		t.Errorf("Kind = %q, want %q", doc.Kind, model.Kind)
	}
	if doc.Metadata.Product != "payments-api" {
		t.Errorf("metadata.product = %q", doc.Metadata.Product)
	}
	if doc.Metadata.Owner != "platform-security" {
		t.Errorf("metadata.owner = %q", doc.Metadata.Owner)
	}
	if doc.Metadata.Description == "" {
		t.Errorf("metadata.description was empty")
	}

	if got, want := len(doc.Spec.Assets), 1; got != want {
		t.Fatalf("len(assets) = %d, want %d", got, want)
	}
	asset := doc.Spec.Assets[0]
	if asset.Name != "pay-linux-01" || asset.Type != "linux-host" || asset.Environment != "prod" {
		t.Errorf("asset = %+v", asset)
	}
	if asset.Labels["app"] != "payments" || asset.Labels["region"] != "eu" {
		t.Errorf("asset labels = %+v", asset.Labels)
	}

	if got, want := len(doc.Spec.AssetScopes), 1; got != want {
		t.Fatalf("len(assetScopes) = %d, want %d", got, want)
	}
	scope := doc.Spec.AssetScopes[0]
	if scope.Name != "prod-linux" {
		t.Errorf("scope.Name = %q", scope.Name)
	}
	if scope.Selector.Type != "linux-host" || scope.Selector.Environment != "prod" {
		t.Errorf("selector = %+v", scope.Selector)
	}
	if scope.Selector.Labels["app"] != "payments" {
		t.Errorf("selector labels missing app=payments: %+v", scope.Selector.Labels)
	}
	// "type" and "environment" must NOT be captured as labels.
	if _, leaked := scope.Selector.Labels["type"]; leaked {
		t.Errorf("selector labels leaked %q key", "type")
	}
	if _, leaked := scope.Selector.Labels["environment"]; leaked {
		t.Errorf("selector labels leaked %q key", "environment")
	}

	if got, want := len(doc.Spec.Entitlements), 1; got != want {
		t.Fatalf("len(entitlements) = %d, want %d", got, want)
	}
	ent := doc.Spec.Entitlements[0]
	if ent.Name != "payments-prod-readonly" || ent.Owner != "payments-team" {
		t.Errorf("entitlement = %+v", ent)
	}
	if got, want := len(ent.Authorizations), 2; got != want {
		t.Fatalf("len(entitlement auths) = %d, want %d", got, want)
	}
	ssh := ent.Authorizations[0]
	if ssh.Type != "linux.ssh" || ssh.Scope != "prod-linux" {
		t.Errorf("ssh auth = %+v", ssh)
	}
	methods, ok := ssh.Spec["methods"].([]any)
	if !ok || len(methods) != 1 || methods[0] != "ssh" {
		t.Errorf("ssh.methods = %#v", ssh.Spec["methods"])
	}
	sudo := ent.Authorizations[1]
	if sudo.Type != "linux.sudo" || sudo.Spec["asUser"] != "root" {
		t.Errorf("sudo auth = %+v", sudo)
	}
	commands, ok := sudo.Spec["commands"].(map[string]any)
	if !ok {
		t.Fatalf("sudo.commands not a map: %#v", sudo.Spec["commands"])
	}
	allow, ok := commands["allow"].([]any)
	if !ok || len(allow) != 2 {
		t.Errorf("sudo.commands.allow = %#v", commands["allow"])
	}

	if got, want := len(doc.Spec.ServiceAccounts), 1; got != want {
		t.Fatalf("len(serviceAccounts) = %d, want %d", got, want)
	}
	sa := doc.Spec.ServiceAccounts[0]
	if sa.Name != "payments-batch" || sa.UsagePattern != "system-to-system" {
		t.Errorf("service account = %+v", sa)
	}
	if got, want := len(sa.Authorizations), 1; got != want {
		t.Fatalf("len(sa auths) = %d, want %d", got, want)
	}
	lg := sa.Authorizations[0]
	if lg.Type != "linux.local-group" || lg.Scope != "prod-linux" {
		t.Errorf("local-group auth = %+v", lg)
	}
	if lg.Spec["group"] != "payments-runtime" {
		t.Errorf("local-group.group = %#v", lg.Spec["group"])
	}
}

func TestValidator_Valid(t *testing.T) {
	var doc model.ProductAuthorizationModel
	if err := yaml.Unmarshal([]byte(validYAML), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if findings := model.Validate(&doc); len(findings) != 0 {
		t.Fatalf("expected zero findings, got: %+v", findings)
	}
}

func TestValidator_Bad(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*model.ProductAuthorizationModel)
		wantPath  string
		wantMatch string
	}{
		{
			name:      "wrong apiVersion",
			mutate:    func(m *model.ProductAuthorizationModel) { m.APIVersion = "x/v1" },
			wantPath:  "apiVersion",
			wantMatch: "must equal",
		},
		{
			name:      "wrong kind",
			mutate:    func(m *model.ProductAuthorizationModel) { m.Kind = "Other" },
			wantPath:  "kind",
			wantMatch: "must equal",
		},
		{
			name:      "missing product",
			mutate:    func(m *model.ProductAuthorizationModel) { m.Metadata.Product = "" },
			wantPath:  "metadata.product",
			wantMatch: "required",
		},
		{
			name:      "missing owner",
			mutate:    func(m *model.ProductAuthorizationModel) { m.Metadata.Owner = "" },
			wantPath:  "metadata.owner",
			wantMatch: "required",
		},
		{
			name: "duplicate asset",
			mutate: func(m *model.ProductAuthorizationModel) {
				m.Spec.Assets = append(m.Spec.Assets, m.Spec.Assets[0])
			},
			wantPath:  "spec.assets[1].name",
			wantMatch: "duplicate",
		},
		{
			name: "invalid asset type",
			mutate: func(m *model.ProductAuthorizationModel) {
				m.Spec.Assets[0].Type = "frobnicator"
			},
			wantPath:  "spec.assets[0].type",
			wantMatch: "invalid asset type",
		},
		{
			name: "invalid environment",
			mutate: func(m *model.ProductAuthorizationModel) {
				m.Spec.Assets[0].Environment = "qa"
			},
			wantPath:  "spec.assets[0].environment",
			wantMatch: "must be one of",
		},
		{
			name: "scope references missing asset",
			mutate: func(m *model.ProductAuthorizationModel) {
				m.Spec.AssetScopes[0].AssetNames = []string{"nope"}
				m.Spec.AssetScopes[0].Selector = model.YAMLAssetSelector{}
			},
			wantPath:  "spec.assetScopes[0].assets[0]",
			wantMatch: "is not declared",
		},
		{
			name: "authorization references missing scope",
			mutate: func(m *model.ProductAuthorizationModel) {
				m.Spec.Entitlements[0].Authorizations[0].Scope = "no-such-scope"
			},
			wantPath:  "spec.entitlements[0].authorizations[0].scope",
			wantMatch: "is not declared",
		},
		{
			name: "authorization with both targets",
			mutate: func(m *model.ProductAuthorizationModel) {
				m.Spec.Entitlements[0].Authorizations[0].GlobalObject = "go"
			},
			wantPath:  "spec.entitlements[0].authorizations[0]",
			wantMatch: "mutually exclusive",
		},
		{
			name: "linux.local-group missing group",
			mutate: func(m *model.ProductAuthorizationModel) {
				delete(m.Spec.ServiceAccounts[0].Authorizations[0].Spec, "group")
			},
			wantPath:  "spec.serviceAccounts[0].authorizations[0]",
			wantMatch: "group is required",
		},
		{
			name: "service account invalid usage pattern",
			mutate: func(m *model.ProductAuthorizationModel) {
				m.Spec.ServiceAccounts[0].UsagePattern = "wat"
			},
			wantPath:  "spec.serviceAccounts[0].usagePattern",
			wantMatch: "invalid usage pattern",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var doc model.ProductAuthorizationModel
			if err := yaml.Unmarshal([]byte(validYAML), &doc); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			tc.mutate(&doc)
			findings := model.Validate(&doc)
			if !findingMatches(findings, tc.wantPath, tc.wantMatch) {
				t.Fatalf("expected finding at %q matching %q, got: %+v", tc.wantPath, tc.wantMatch, findings)
			}
		})
	}
}

func findingMatches(findings []model.ValidationError, path, contains string) bool {
	for _, f := range findings {
		if f.Path == path && strings.Contains(f.Message, contains) {
			return true
		}
	}
	return false
}

func TestRoundTrip_YAMLOnly(t *testing.T) {
	var doc1 model.ProductAuthorizationModel
	if err := yaml.Unmarshal([]byte(validYAML), &doc1); err != nil {
		t.Fatalf("first unmarshal: %v", err)
	}
	out, err := yaml.Marshal(&doc1)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc2 model.ProductAuthorizationModel
	if err := yaml.Unmarshal(out, &doc2); err != nil {
		t.Fatalf("second unmarshal: %v\nyaml:\n%s", err, string(out))
	}
	if !reflect.DeepEqual(doc1, doc2) {
		t.Fatalf("round-trip mismatch\nfirst:\n%+v\nsecond:\n%+v\nyaml:\n%s", doc1, doc2, string(out))
	}
}

// loadValid returns a fresh copy of the §20 example for diff tests.
func loadValid(t *testing.T) *model.ProductAuthorizationModel {
	t.Helper()
	var doc model.ProductAuthorizationModel
	if err := yaml.Unmarshal([]byte(validYAML), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &doc
}

func TestComputeDiff_EmptyVsEmpty(t *testing.T) {
	d, err := model.ComputeDiff(nil, nil)
	if err != nil {
		t.Fatalf("ComputeDiff: %v", err)
	}
	if !d.IsEmpty() {
		t.Fatalf("expected empty diff, got %d items", len(d.Items))
	}
}

func TestComputeDiff_FullAdd(t *testing.T) {
	after := loadValid(t)
	d, err := model.ComputeDiff(nil, after)
	if err != nil {
		t.Fatalf("ComputeDiff: %v", err)
	}
	if d.IsEmpty() {
		t.Fatalf("expected non-empty diff")
	}
	for _, it := range d.Items {
		if it.Action != domain.ChangeSetActionAdd {
			t.Errorf("item %q: action=%s, want add", it.ResourceName, it.Action)
		}
		if it.Before != nil {
			t.Errorf("item %q: before should be nil for add", it.ResourceName)
		}
		if it.After == nil {
			t.Errorf("item %q: after must be set for add", it.ResourceName)
		}
	}
	// Ensure product comes first and is the very first item.
	if len(d.Items) == 0 || d.Items[0].Kind != domain.ChangeSetItemKindProduct {
		t.Fatalf("first item should be product; got %+v", d.Items[0])
	}
}

func TestComputeDiff_FullDelete(t *testing.T) {
	before := loadValid(t)
	d, err := model.ComputeDiff(before, nil)
	if err != nil {
		t.Fatalf("ComputeDiff: %v", err)
	}
	if d.IsEmpty() {
		t.Fatalf("expected non-empty diff")
	}
	for _, it := range d.Items {
		if it.Action != domain.ChangeSetActionDelete {
			t.Errorf("item %q: action=%s, want delete", it.ResourceName, it.Action)
		}
		if it.After != nil {
			t.Errorf("item %q: after should be nil for delete", it.ResourceName)
		}
		if it.Before == nil {
			t.Errorf("item %q: before must be set for delete", it.ResourceName)
		}
	}
}

func TestComputeDiff_NoChange(t *testing.T) {
	a := loadValid(t)
	b := loadValid(t)
	d, err := model.ComputeDiff(a, b)
	if err != nil {
		t.Fatalf("ComputeDiff: %v", err)
	}
	if !d.IsEmpty() {
		t.Fatalf("expected empty diff, got %d items: %+v", len(d.Items), d.Items)
	}
}

func TestComputeDiff_SingleEdit(t *testing.T) {
	before := loadValid(t)
	after := loadValid(t)
	after.Spec.Entitlements[0].Purpose = "Edited purpose"

	d, err := model.ComputeDiff(before, after)
	if err != nil {
		t.Fatalf("ComputeDiff: %v", err)
	}
	if len(d.Items) != 1 {
		t.Fatalf("expected exactly 1 diff item, got %d: %+v", len(d.Items), d.Items)
	}
	got := d.Items[0]
	if got.Kind != domain.ChangeSetItemKindEntitlement {
		t.Errorf("kind = %s, want entitlement", got.Kind)
	}
	if got.Action != domain.ChangeSetActionUpdate {
		t.Errorf("action = %s, want update", got.Action)
	}
	wantRes := "entitlement:" + before.Spec.Entitlements[0].Name
	if got.ResourceName != wantRes {
		t.Errorf("resource = %q, want %q", got.ResourceName, wantRes)
	}
	if got.Before["purpose"] != before.Spec.Entitlements[0].Purpose {
		t.Errorf("before.purpose = %v, want %q", got.Before["purpose"], before.Spec.Entitlements[0].Purpose)
	}
	if got.After["purpose"] != "Edited purpose" {
		t.Errorf("after.purpose = %v, want %q", got.After["purpose"], "Edited purpose")
	}
}

func TestComputeDiff_Determinism(t *testing.T) {
	a := loadValid(t)
	b := loadValid(t)
	b.Metadata.Owner = "new-owner"
	b.Spec.Assets[0].Description = "edited"

	d1, err := model.ComputeDiff(a, b)
	if err != nil {
		t.Fatalf("first ComputeDiff: %v", err)
	}
	d2, err := model.ComputeDiff(a, b)
	if err != nil {
		t.Fatalf("second ComputeDiff: %v", err)
	}
	j1, err := json.Marshal(d1.Items)
	if err != nil {
		t.Fatalf("marshal d1: %v", err)
	}
	j2, err := json.Marshal(d2.Items)
	if err != nil {
		t.Fatalf("marshal d2: %v", err)
	}
	if string(j1) != string(j2) {
		t.Fatalf("non-deterministic output:\n%s\nvs\n%s", j1, j2)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	original := loadValid(t)
	content, err := model.ToSnapshotContent(original)
	if err != nil {
		t.Fatalf("ToSnapshotContent: %v", err)
	}
	restored, err := model.FromSnapshot(content)
	if err != nil {
		t.Fatalf("FromSnapshot: %v", err)
	}
	c1, err := model.ToSnapshotContent(original)
	if err != nil {
		t.Fatalf("ToSnapshotContent (1): %v", err)
	}
	c2, err := model.ToSnapshotContent(restored)
	if err != nil {
		t.Fatalf("ToSnapshotContent (2): %v", err)
	}
	j1, _ := json.Marshal(c1)
	j2, _ := json.Marshal(c2)
	if string(j1) != string(j2) {
		t.Fatalf("round-trip mismatch:\n%s\nvs\n%s", j1, j2)
	}
}
