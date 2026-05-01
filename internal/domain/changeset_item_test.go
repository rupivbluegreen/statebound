package domain

import (
	"errors"
	"testing"
)

func TestNewChangeSetItem_Valid(t *testing.T) {
	csID := NewID()
	cases := []struct {
		name   string
		kind   ChangeSetItemKind
		action ChangeSetAction
		before map[string]any
		after  map[string]any
	}{
		{"add product", ChangeSetItemKindProduct, ChangeSetActionAdd, nil, map[string]any{"name": "payments-api"}},
		{"update entitlement", ChangeSetItemKindEntitlement, ChangeSetActionUpdate, map[string]any{"v": 1}, map[string]any{"v": 2}},
		{"delete authorization", ChangeSetItemKindAuthorization, ChangeSetActionDelete, map[string]any{"v": 1}, nil},
		{"add asset_scope", ChangeSetItemKindAssetScope, ChangeSetActionAdd, nil, map[string]any{}},
		{"add service_account", ChangeSetItemKindServiceAccount, ChangeSetActionAdd, nil, map[string]any{}},
		{"add global_object", ChangeSetItemKindGlobalObject, ChangeSetActionAdd, nil, map[string]any{}},
		{"add asset", ChangeSetItemKindAsset, ChangeSetActionAdd, nil, map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item, err := NewChangeSetItem(csID, tc.kind, tc.action, "resource-name", tc.before, tc.after)
			if err != nil {
				t.Fatalf("NewChangeSetItem: %v", err)
			}
			if item.ID == "" {
				t.Error("ID is empty")
			}
			if item.ChangeSetID != csID {
				t.Errorf("ChangeSetID = %q, want %q", item.ChangeSetID, csID)
			}
			if item.Kind != tc.kind {
				t.Errorf("Kind = %q, want %q", item.Kind, tc.kind)
			}
			if item.Action != tc.action {
				t.Errorf("Action = %q, want %q", item.Action, tc.action)
			}
			if item.CreatedAt.IsZero() {
				t.Error("CreatedAt is zero")
			}
		})
	}
}

func TestNewChangeSetItem_Invalid(t *testing.T) {
	csID := NewID()
	cases := []struct {
		name         string
		csID         ID
		kind         ChangeSetItemKind
		action       ChangeSetAction
		resourceName string
		before       map[string]any
		after        map[string]any
		want         error
	}{
		{"empty csID", "", ChangeSetItemKindProduct, ChangeSetActionAdd, "x", nil, map[string]any{}, ErrChangeSetItemChangeSetIDRequired},
		{"invalid kind", csID, ChangeSetItemKind("bogus"), ChangeSetActionAdd, "x", nil, map[string]any{}, ErrChangeSetItemKindInvalid},
		{"invalid action", csID, ChangeSetItemKindProduct, ChangeSetAction("bogus"), "x", nil, map[string]any{}, ErrChangeSetItemActionInvalid},
		{"empty resource name", csID, ChangeSetItemKindProduct, ChangeSetActionAdd, "", nil, map[string]any{}, ErrChangeSetItemResourceNameRequired},
		{"add with before set", csID, ChangeSetItemKindProduct, ChangeSetActionAdd, "x", map[string]any{}, map[string]any{}, ErrChangeSetItemBeforeAfterMismatch},
		{"add with after nil", csID, ChangeSetItemKindProduct, ChangeSetActionAdd, "x", nil, nil, ErrChangeSetItemBeforeAfterMismatch},
		{"delete with after set", csID, ChangeSetItemKindProduct, ChangeSetActionDelete, "x", map[string]any{}, map[string]any{}, ErrChangeSetItemBeforeAfterMismatch},
		{"delete with before nil", csID, ChangeSetItemKindProduct, ChangeSetActionDelete, "x", nil, nil, ErrChangeSetItemBeforeAfterMismatch},
		{"update with before nil", csID, ChangeSetItemKindProduct, ChangeSetActionUpdate, "x", nil, map[string]any{}, ErrChangeSetItemBeforeAfterMismatch},
		{"update with after nil", csID, ChangeSetItemKindProduct, ChangeSetActionUpdate, "x", map[string]any{}, nil, ErrChangeSetItemBeforeAfterMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item, err := NewChangeSetItem(tc.csID, tc.kind, tc.action, tc.resourceName, tc.before, tc.after)
			if err == nil {
				t.Fatalf("NewChangeSetItem succeeded; want %v", tc.want)
			}
			if item != nil {
				t.Errorf("expected nil item on error, got %+v", item)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestIsValidChangeSetAction(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"add", true},
		{"update", true},
		{"delete", true},
		{"", false},
		{"ADD", false},
		{"create", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := IsValidChangeSetAction(tc.in); got != tc.want {
				t.Errorf("IsValidChangeSetAction(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsValidChangeSetItemKind(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"product", true},
		{"asset", true},
		{"asset_scope", true},
		{"entitlement", true},
		{"service_account", true},
		{"global_object", true},
		{"authorization", true},
		{"", false},
		{"PRODUCT", false},
		{"unknown", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := IsValidChangeSetItemKind(tc.in); got != tc.want {
				t.Errorf("IsValidChangeSetItemKind(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
