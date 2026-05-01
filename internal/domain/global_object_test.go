package domain

import (
	"errors"
	"testing"
	"time"
)

func ptrID(s string) *ID {
	id := ID(s)
	return &id
}

func TestNewGlobalObject_Valid(t *testing.T) {
	cases := []struct {
		name string
		t    GlobalObjectType
		pid  *ID
	}{
		{"linux-group product-scoped", GlobalObjectTypeLinuxGroup, ptrID(string(NewID()))},
		{"sudoers fragment cross-product", GlobalObjectTypeLinuxSudoersFragment, nil},
		{"postgres-role product-scoped", GlobalObjectTypePostgresRole, ptrID(string(NewID()))},
		{"k8s rolebinding cross-product", GlobalObjectTypeKubernetesRoleBinding, nil},
		{"rego-policy cross-product", GlobalObjectTypeRegoPolicy, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := NewGlobalObject("payments-runtime", tc.t, tc.pid, map[string]any{"k": "v"})
			if err != nil {
				t.Fatalf("NewGlobalObject error: %v", err)
			}
			if g.ID == "" {
				t.Error("ID empty")
			}
			if g.CreatedAt.Location() != time.UTC {
				t.Errorf("CreatedAt not UTC")
			}
			if (g.ProductID == nil) != (tc.pid == nil) {
				t.Errorf("ProductID nilness mismatch")
			}
		})
	}
}

func TestNewGlobalObject_Invalid(t *testing.T) {
	cases := []struct {
		name    string
		objName string
		t       GlobalObjectType
		want    error
	}{
		{"empty name", "", GlobalObjectTypeLinuxGroup, ErrGlobalObjectNameInvalid},
		{"bad name", "BAD", GlobalObjectTypeLinuxGroup, ErrGlobalObjectNameInvalid},
		{"empty type", "ok", "", ErrGlobalObjectTypeInvalid},
		{"bad type", "ok", "weird", ErrGlobalObjectTypeInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := NewGlobalObject(tc.objName, tc.t, nil, nil)
			if err == nil {
				t.Fatalf("NewGlobalObject succeeded; want error %v", tc.want)
			}
			if g != nil {
				t.Errorf("expected nil on error, got %+v", g)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestGlobalObject_Validate(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name string
		g    GlobalObject
		want error
	}{
		{
			name: "valid no product",
			g:    GlobalObject{ID: NewID(), Name: "ok", Type: GlobalObjectTypeLinuxGroup, CreatedAt: now, UpdatedAt: now},
			want: nil,
		},
		{
			name: "bad name",
			g:    GlobalObject{ID: NewID(), Name: "BAD", Type: GlobalObjectTypeLinuxGroup, CreatedAt: now, UpdatedAt: now},
			want: ErrGlobalObjectNameInvalid,
		},
		{
			name: "bad type",
			g:    GlobalObject{ID: NewID(), Name: "ok", Type: "weird", CreatedAt: now, UpdatedAt: now},
			want: ErrGlobalObjectTypeInvalid,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.g.Validate()
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

func TestIsValidGlobalObjectType(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"linux-group", true},
		{"linux-sudoers-fragment", true},
		{"postgres-role", true},
		{"kubernetes-role-binding", true},
		{"rego-policy", true},
		{"", false},
		{"unknown", false},
		{"LINUX-GROUP", false},
	}
	for _, tc := range cases {
		t.Run(tc.s, func(t *testing.T) {
			if got := IsValidGlobalObjectType(tc.s); got != tc.want {
				t.Errorf("IsValidGlobalObjectType(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}
