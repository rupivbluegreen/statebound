package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validLabels() map[string]string {
	return map[string]string{"app": "payments", "region": "eu"}
}

func TestNewAsset_Valid(t *testing.T) {
	productID := NewID()
	cases := []struct {
		name string
		t    AssetType
		env  Environment
	}{
		{"linux-host prod", AssetTypeLinuxHost, EnvProd},
		{"postgres dev", AssetTypePostgresDatabase, EnvDev},
		{"k8s-namespace staging", AssetTypeKubernetesNamespace, EnvStaging},
		{"k8s-cluster prod", AssetTypeKubernetesCluster, EnvProd},
		{"service prod", AssetTypeService, EnvProd},
		{"bucket dev", AssetTypeBucket, EnvDev},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewAsset(productID, "pay-linux-01", tc.t, tc.env, validLabels(), "an asset")
			if err != nil {
				t.Fatalf("NewAsset error: %v", err)
			}
			if a.ID == "" {
				t.Error("ID is empty")
			}
			if a.ProductID != productID {
				t.Errorf("ProductID = %q, want %q", a.ProductID, productID)
			}
			if a.CreatedAt.Location() != time.UTC {
				t.Errorf("CreatedAt location = %v, want UTC", a.CreatedAt.Location())
			}
			if !a.CreatedAt.Equal(a.UpdatedAt) {
				t.Errorf("CreatedAt != UpdatedAt at construction")
			}
		})
	}
}

func TestNewAsset_NilLabelsAllowed(t *testing.T) {
	a, err := NewAsset(NewID(), "host", AssetTypeLinuxHost, EnvDev, nil, "")
	if err != nil {
		t.Fatalf("NewAsset error: %v", err)
	}
	if a == nil {
		t.Fatal("nil asset")
	}
}

func TestNewAsset_Invalid(t *testing.T) {
	productID := NewID()
	longDesc := strings.Repeat("d", assetDescriptionMaxLen+1)
	longLabelValue := strings.Repeat("v", labelValueMaxLen+1)

	cases := []struct {
		name      string
		productID ID
		assetName string
		t         AssetType
		env       Environment
		labels    map[string]string
		desc      string
		want      error
	}{
		{"empty product id", "", "host", AssetTypeLinuxHost, EnvDev, nil, "", ErrAssetProductIDRequired},
		{"empty name", productID, "", AssetTypeLinuxHost, EnvDev, nil, "", ErrAssetNameInvalid},
		{"uppercase name", productID, "Host", AssetTypeLinuxHost, EnvDev, nil, "", ErrAssetNameInvalid},
		{"name too long", productID, strings.Repeat("a", 64), AssetTypeLinuxHost, EnvDev, nil, "", ErrAssetNameInvalid},
		{"bad type", productID, "host", "weird", EnvDev, nil, "", ErrAssetTypeInvalid},
		{"empty type", productID, "host", "", EnvDev, nil, "", ErrAssetTypeInvalid},
		{"bad env", productID, "host", AssetTypeLinuxHost, "qa", nil, "", ErrAssetEnvironmentInvalid},
		{"empty env", productID, "host", AssetTypeLinuxHost, "", nil, "", ErrAssetEnvironmentInvalid},
		{"label key bad", productID, "host", AssetTypeLinuxHost, EnvDev, map[string]string{"BAD": "v"}, "", ErrAssetLabelKeyInvalid},
		{"label key empty", productID, "host", AssetTypeLinuxHost, EnvDev, map[string]string{"": "v"}, "", ErrAssetLabelKeyInvalid},
		{"label value empty", productID, "host", AssetTypeLinuxHost, EnvDev, map[string]string{"app": ""}, "", ErrAssetLabelValueInvalid},
		{"label value too long", productID, "host", AssetTypeLinuxHost, EnvDev, map[string]string{"app": longLabelValue}, "", ErrAssetLabelValueInvalid},
		{"description too long", productID, "host", AssetTypeLinuxHost, EnvDev, nil, longDesc, ErrAssetDescriptionTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewAsset(tc.productID, tc.assetName, tc.t, tc.env, tc.labels, tc.desc)
			if err == nil {
				t.Fatalf("NewAsset succeeded; want error %v", tc.want)
			}
			if a != nil {
				t.Errorf("expected nil on error, got %+v", a)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestAsset_Validate(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name string
		a    Asset
		want error
	}{
		{
			name: "valid",
			a:    Asset{ID: NewID(), Name: "h", Type: AssetTypeLinuxHost, ProductID: NewID(), Environment: EnvDev, CreatedAt: now, UpdatedAt: now},
			want: nil,
		},
		{
			name: "missing product id",
			a:    Asset{ID: NewID(), Name: "h", Type: AssetTypeLinuxHost, Environment: EnvDev, CreatedAt: now, UpdatedAt: now},
			want: ErrAssetProductIDRequired,
		},
		{
			name: "bad name",
			a:    Asset{ID: NewID(), Name: "BAD", Type: AssetTypeLinuxHost, ProductID: NewID(), Environment: EnvDev, CreatedAt: now, UpdatedAt: now},
			want: ErrAssetNameInvalid,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.a.Validate()
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

func TestIsValidAssetType(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"linux-host", true},
		{"postgres-database", true},
		{"kubernetes-namespace", true},
		{"kubernetes-cluster", true},
		{"service", true},
		{"bucket", true},
		{"", false},
		{"linux", false},
		{"LINUX-HOST", false},
	}
	for _, tc := range cases {
		t.Run(tc.s, func(t *testing.T) {
			if got := IsValidAssetType(tc.s); got != tc.want {
				t.Errorf("IsValidAssetType(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}

func TestIsValidLabelKey(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"app", true},
		{"a", true},
		{"app1", true},
		{"app.name", true},
		{"app-name", true},
		{"app_name", true},
		{"app1.foo-bar_baz", true},
		{"", false},
		{"1app", false},
		{"App", false},
		{"-app", false},
		{".app", false},
		{strings.Repeat("a", 63), true},
		{strings.Repeat("a", 64), false},
	}
	for _, tc := range cases {
		t.Run(tc.s, func(t *testing.T) {
			if got := IsValidLabelKey(tc.s); got != tc.want {
				t.Errorf("IsValidLabelKey(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}

func TestIsValidLabelValue(t *testing.T) {
	cases := []struct {
		name string
		s    string
		want bool
	}{
		{"simple", "payments", true},
		{"max len", strings.Repeat("v", labelValueMaxLen), true},
		{"too long", strings.Repeat("v", labelValueMaxLen+1), false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidLabelValue(tc.s); got != tc.want {
				t.Errorf("IsValidLabelValue = %v, want %v", got, tc.want)
			}
		})
	}
}
