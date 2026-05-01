package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewProduct_Valid(t *testing.T) {
	cases := []struct {
		name        string
		productName string
		owner       string
		description string
	}{
		{"simple slug", "payments-api", "platform-security", "Payments API"},
		{"digits only", "1234", "ops", ""},
		{"single char", "a", "owner-team", "minimal name"},
		{"max length name", strings.Repeat("a", 63), "owner-team", "63-char slug"},
		{"empty description", "billing", "fin-team", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProduct(tc.productName, tc.owner, tc.description)
			if err != nil {
				t.Fatalf("NewProduct returned error: %v", err)
			}
			if p == nil {
				t.Fatal("NewProduct returned nil product")
			}
			if p.ID == "" {
				t.Error("expected non-empty ID")
			}
			if p.Name != tc.productName {
				t.Errorf("Name = %q, want %q", p.Name, tc.productName)
			}
			if p.Owner != tc.owner {
				t.Errorf("Owner = %q, want %q", p.Owner, tc.owner)
			}
			if p.Description != tc.description {
				t.Errorf("Description = %q, want %q", p.Description, tc.description)
			}
			if p.CreatedAt.IsZero() {
				t.Error("CreatedAt is zero")
			}
			if p.UpdatedAt.IsZero() {
				t.Error("UpdatedAt is zero")
			}
			if !p.CreatedAt.Equal(p.UpdatedAt) {
				t.Errorf("CreatedAt (%v) != UpdatedAt (%v) on construction", p.CreatedAt, p.UpdatedAt)
			}
		})
	}
}

func TestNewProduct_Invalid(t *testing.T) {
	longDesc := strings.Repeat("x", productDescriptionMaxLen+1)

	cases := []struct {
		name        string
		productName string
		owner       string
		description string
		want        error
	}{
		{"empty name", "", "owner", "", ErrProductNameInvalid},
		{"uppercase name", "PaymentsAPI", "owner", "", ErrProductNameInvalid},
		{"leading hyphen", "-payments", "owner", "", ErrProductNameInvalid},
		{"too long name", strings.Repeat("a", 64), "owner", "", ErrProductNameInvalid},
		{"underscore name", "payments_api", "owner", "", ErrProductNameInvalid},
		{"empty owner", "payments-api", "", "", ErrProductOwnerRequired},
		{"description too long", "payments-api", "owner", longDesc, ErrProductDescriptionTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProduct(tc.productName, tc.owner, tc.description)
			if err == nil {
				t.Fatalf("NewProduct succeeded; want error %v", tc.want)
			}
			if p != nil {
				t.Errorf("expected nil product on error, got %+v", p)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestProduct_Validate(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name string
		p    Product
		want error
	}{
		{
			name: "valid",
			p:    Product{ID: NewID(), Name: "billing", Owner: "fin", Description: "ok", CreatedAt: now, UpdatedAt: now},
			want: nil,
		},
		{
			name: "invalid name",
			p:    Product{ID: NewID(), Name: "Bad Name", Owner: "fin", CreatedAt: now, UpdatedAt: now},
			want: ErrProductNameInvalid,
		},
		{
			name: "missing owner",
			p:    Product{ID: NewID(), Name: "billing", Owner: "", CreatedAt: now, UpdatedAt: now},
			want: ErrProductOwnerRequired,
		},
		{
			name: "description too long",
			p: Product{
				ID:          NewID(),
				Name:        "billing",
				Owner:       "fin",
				Description: strings.Repeat("y", productDescriptionMaxLen+1),
				CreatedAt:   now,
				UpdatedAt:   now,
			},
			want: ErrProductDescriptionTooLong,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
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

func TestIsValidProductName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"single char letter", "a", true},
		{"single digit", "9", true},
		{"63 chars", strings.Repeat("a", 63), true},
		{"64 chars rejected", strings.Repeat("a", 64), false},
		{"trailing hyphen accepted", "payments-", true},
		{"leading hyphen rejected", "-payments", false},
		{"digits only", "12345", true},
		{"empty rejected", "", false},
		{"uppercase rejected", "Payments", false},
		{"underscore rejected", "pay_ments", false},
		{"space rejected", "pay ments", false},
		{"dot rejected", "pay.ments", false},
		{"hyphen-only at start rejected", "-", false},
		{"valid kebab", "payments-api-v2", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValidProductName(tc.input)
			if got != tc.want {
				t.Errorf("IsValidProductName(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestNewProduct_TimeUTC(t *testing.T) {
	p, err := NewProduct("payments-api", "owner", "desc")
	if err != nil {
		t.Fatalf("NewProduct error: %v", err)
	}
	if p.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", p.CreatedAt.Location())
	}
	if p.UpdatedAt.Location() != time.UTC {
		t.Errorf("UpdatedAt location = %v, want UTC", p.UpdatedAt.Location())
	}
}
