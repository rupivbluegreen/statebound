package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewAssetScope_Valid(t *testing.T) {
	productID := NewID()
	cases := []struct {
		name string
		sel  AssetSelector
	}{
		{"type only", AssetSelector{Type: AssetTypeLinuxHost}},
		{"env only", AssetSelector{Environment: EnvProd}},
		{"labels only", AssetSelector{Labels: map[string]string{"app": "payments"}}},
		{"asset names only", AssetSelector{AssetNames: []string{"pay-linux-01", "pay-linux-02"}}},
		{"combo", AssetSelector{Type: AssetTypeLinuxHost, Environment: EnvProd, Labels: map[string]string{"app": "payments"}, AssetNames: []string{"pay-linux-01"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewAssetScope(productID, "prod-linux", tc.sel, "scope desc")
			if err != nil {
				t.Fatalf("NewAssetScope error: %v", err)
			}
			if s.ID == "" {
				t.Error("ID empty")
			}
			if s.CreatedAt.Location() != time.UTC {
				t.Errorf("CreatedAt not UTC")
			}
		})
	}
}

func TestNewAssetScope_Invalid(t *testing.T) {
	productID := NewID()
	longDesc := strings.Repeat("d", assetScopeDescriptionMaxLen+1)
	validSel := AssetSelector{Type: AssetTypeLinuxHost}

	cases := []struct {
		name      string
		productID ID
		scopeName string
		sel       AssetSelector
		desc      string
		want      error
	}{
		{"empty product id", "", "ok", validSel, "", ErrAssetScopeProductIDRequired},
		{"empty name", productID, "", validSel, "", ErrAssetScopeNameInvalid},
		{"name too long", productID, strings.Repeat("a", 64), validSel, "", ErrAssetScopeNameInvalid},
		{"description too long", productID, "ok", validSel, longDesc, ErrAssetScopeDescriptionTooLong},
		{"empty selector", productID, "ok", AssetSelector{}, "", ErrAssetScopeSelectorEmpty},
		{"selector bad type", productID, "ok", AssetSelector{Type: "weird"}, "", ErrAssetTypeInvalid},
		{"selector bad env", productID, "ok", AssetSelector{Environment: "qa"}, "", ErrAssetEnvironmentInvalid},
		{"selector bad label key", productID, "ok", AssetSelector{Labels: map[string]string{"BAD": "v"}}, "", ErrAssetLabelKeyInvalid},
		{"selector empty label value", productID, "ok", AssetSelector{Labels: map[string]string{"app": ""}}, "", ErrAssetLabelValueInvalid},
		{"asset name empty entry", productID, "ok", AssetSelector{AssetNames: []string{""}}, "", ErrAssetScopeAssetNameInvalid},
		{"asset name uppercase", productID, "ok", AssetSelector{AssetNames: []string{"BAD"}}, "", ErrAssetScopeAssetNameInvalid},
		{"asset name duplicate", productID, "ok", AssetSelector{AssetNames: []string{"pay-01", "pay-01"}}, "", ErrAssetScopeAssetNameDuplicate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewAssetScope(tc.productID, tc.scopeName, tc.sel, tc.desc)
			if err == nil {
				t.Fatalf("NewAssetScope succeeded; want error %v", tc.want)
			}
			if s != nil {
				t.Errorf("expected nil on error, got %+v", s)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestAssetScope_Validate(t *testing.T) {
	now := time.Now().UTC()
	productID := NewID()
	cases := []struct {
		name string
		s    AssetScope
		want error
	}{
		{
			name: "valid",
			s:    AssetScope{ID: NewID(), Name: "ok", ProductID: productID, Selector: AssetSelector{Type: AssetTypeLinuxHost}, CreatedAt: now, UpdatedAt: now},
			want: nil,
		},
		{
			name: "missing product",
			s:    AssetScope{ID: NewID(), Name: "ok", Selector: AssetSelector{Type: AssetTypeLinuxHost}, CreatedAt: now, UpdatedAt: now},
			want: ErrAssetScopeProductIDRequired,
		},
		{
			name: "bad name",
			s:    AssetScope{ID: NewID(), Name: "BAD", ProductID: productID, Selector: AssetSelector{Type: AssetTypeLinuxHost}, CreatedAt: now, UpdatedAt: now},
			want: ErrAssetScopeNameInvalid,
		},
		{
			name: "empty selector",
			s:    AssetScope{ID: NewID(), Name: "ok", ProductID: productID, Selector: AssetSelector{}, CreatedAt: now, UpdatedAt: now},
			want: ErrAssetScopeSelectorEmpty,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Validate()
			if tc.want == nil {
				if err != nil {
					t.Errorf("Validate returned %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("Validate err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestAssetSelector_Validate(t *testing.T) {
	cases := []struct {
		name string
		sel  AssetSelector
		want error
	}{
		{"valid type", AssetSelector{Type: AssetTypeLinuxHost}, nil},
		{"valid env", AssetSelector{Environment: EnvProd}, nil},
		{"valid labels", AssetSelector{Labels: map[string]string{"app": "payments"}}, nil},
		{"valid names", AssetSelector{AssetNames: []string{"a", "b"}}, nil},
		{"empty", AssetSelector{}, ErrAssetScopeSelectorEmpty},
		{"unique names ok", AssetSelector{AssetNames: []string{"a", "b", "c"}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sel.Validate()
			if tc.want == nil {
				if err != nil {
					t.Errorf("Validate returned %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("Validate err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}
