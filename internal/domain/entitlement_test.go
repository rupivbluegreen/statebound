package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewEntitlement_Valid(t *testing.T) {
	productID := NewID()
	e, err := NewEntitlement(productID, "payments-prod-readonly", "payments-team", "Read-only production troubleshooting")
	if err != nil {
		t.Fatalf("NewEntitlement error: %v", err)
	}
	if e.ID == "" {
		t.Error("ID empty")
	}
	if e.ProductID != productID {
		t.Errorf("ProductID = %q, want %q", e.ProductID, productID)
	}
	if e.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt not UTC")
	}
	if !e.CreatedAt.Equal(e.UpdatedAt) {
		t.Errorf("CreatedAt != UpdatedAt at construction")
	}
}

func TestNewEntitlement_Invalid(t *testing.T) {
	productID := NewID()
	longOwner := strings.Repeat("o", entitlementOwnerMaxLen+1)
	longPurpose := strings.Repeat("p", entitlementPurposeMaxLen+1)

	cases := []struct {
		name    string
		pid     ID
		ent     string
		owner   string
		purpose string
		want    error
	}{
		{"empty product", "", "ent", "owner", "purpose", ErrEntitlementProductIDRequired},
		{"empty name", productID, "", "owner", "purpose", ErrEntitlementNameInvalid},
		{"bad name", productID, "BAD", "owner", "purpose", ErrEntitlementNameInvalid},
		{"empty owner", productID, "ent", "", "purpose", ErrEntitlementOwnerRequired},
		{"owner too long", productID, "ent", longOwner, "purpose", ErrEntitlementOwnerTooLong},
		{"empty purpose", productID, "ent", "owner", "", ErrEntitlementPurposeRequired},
		{"purpose too long", productID, "ent", "owner", longPurpose, ErrEntitlementPurposeTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewEntitlement(tc.pid, tc.ent, tc.owner, tc.purpose)
			if err == nil {
				t.Fatalf("NewEntitlement succeeded; want error %v", tc.want)
			}
			if e != nil {
				t.Errorf("expected nil entitlement, got %+v", e)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestEntitlement_Validate(t *testing.T) {
	now := time.Now().UTC()
	productID := NewID()
	cases := []struct {
		name string
		e    Entitlement
		want error
	}{
		{
			name: "valid",
			e:    Entitlement{ID: NewID(), Name: "ent", ProductID: productID, Owner: "o", Purpose: "p", CreatedAt: now, UpdatedAt: now},
			want: nil,
		},
		{
			name: "missing product",
			e:    Entitlement{ID: NewID(), Name: "ent", Owner: "o", Purpose: "p", CreatedAt: now, UpdatedAt: now},
			want: ErrEntitlementProductIDRequired,
		},
		{
			name: "bad name",
			e:    Entitlement{ID: NewID(), Name: "BAD", ProductID: productID, Owner: "o", Purpose: "p", CreatedAt: now, UpdatedAt: now},
			want: ErrEntitlementNameInvalid,
		},
		{
			name: "missing purpose",
			e:    Entitlement{ID: NewID(), Name: "ent", ProductID: productID, Owner: "o", CreatedAt: now, UpdatedAt: now},
			want: ErrEntitlementPurposeRequired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.e.Validate()
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
