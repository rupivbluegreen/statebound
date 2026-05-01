package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewServiceAccount_Valid(t *testing.T) {
	productID := NewID()
	patterns := []UsagePattern{UsageSystemToSystem, UsageAgent, UsageHumanShared, UsageDeploy, UsageMonitoring}
	for _, u := range patterns {
		t.Run(string(u), func(t *testing.T) {
			s, err := NewServiceAccount(productID, "payments-batch", "payments-team", "Runs scheduled jobs", u)
			if err != nil {
				t.Fatalf("NewServiceAccount error: %v", err)
			}
			if s.ID == "" {
				t.Error("ID empty")
			}
			if s.UsagePattern != u {
				t.Errorf("UsagePattern = %q, want %q", s.UsagePattern, u)
			}
			if s.CreatedAt.Location() != time.UTC {
				t.Errorf("CreatedAt not UTC")
			}
		})
	}
}

func TestNewServiceAccount_Invalid(t *testing.T) {
	productID := NewID()
	longOwner := strings.Repeat("o", serviceAccountOwnerMaxLen+1)
	longPurpose := strings.Repeat("p", serviceAccountPurposeMaxLen+1)

	cases := []struct {
		name    string
		pid     ID
		sa      string
		owner   string
		purpose string
		u       UsagePattern
		want    error
	}{
		{"empty product", "", "sa", "o", "p", UsageAgent, ErrServiceAccountProductIDRequired},
		{"empty name", productID, "", "o", "p", UsageAgent, ErrServiceAccountNameInvalid},
		{"bad name", productID, "BAD", "o", "p", UsageAgent, ErrServiceAccountNameInvalid},
		{"empty owner", productID, "sa", "", "p", UsageAgent, ErrServiceAccountOwnerRequired},
		{"owner too long", productID, "sa", longOwner, "p", UsageAgent, ErrServiceAccountOwnerTooLong},
		{"empty purpose", productID, "sa", "o", "", UsageAgent, ErrServiceAccountPurposeRequired},
		{"purpose too long", productID, "sa", "o", longPurpose, UsageAgent, ErrServiceAccountPurposeTooLong},
		{"empty usage", productID, "sa", "o", "p", "", ErrServiceAccountUsagePatternRequired},
		{"bad usage", productID, "sa", "o", "p", "bogus", ErrServiceAccountUsagePatternInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewServiceAccount(tc.pid, tc.sa, tc.owner, tc.purpose, tc.u)
			if err == nil {
				t.Fatalf("NewServiceAccount succeeded; want error %v", tc.want)
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

func TestServiceAccount_Validate(t *testing.T) {
	now := time.Now().UTC()
	productID := NewID()
	cases := []struct {
		name string
		s    ServiceAccount
		want error
	}{
		{
			name: "valid",
			s:    ServiceAccount{ID: NewID(), Name: "sa", ProductID: productID, Owner: "o", Purpose: "p", UsagePattern: UsageAgent, CreatedAt: now, UpdatedAt: now},
			want: nil,
		},
		{
			name: "missing product",
			s:    ServiceAccount{ID: NewID(), Name: "sa", Owner: "o", Purpose: "p", UsagePattern: UsageAgent, CreatedAt: now, UpdatedAt: now},
			want: ErrServiceAccountProductIDRequired,
		},
		{
			name: "missing usage",
			s:    ServiceAccount{ID: NewID(), Name: "sa", ProductID: productID, Owner: "o", Purpose: "p", CreatedAt: now, UpdatedAt: now},
			want: ErrServiceAccountUsagePatternRequired,
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

func TestIsValidUsagePattern(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"system-to-system", true},
		{"agent", true},
		{"human-shared", true},
		{"deploy", true},
		{"monitoring", true},
		{"", false},
		{"AGENT", false},
		{"unknown", false},
	}
	for _, tc := range cases {
		t.Run(tc.s, func(t *testing.T) {
			if got := IsValidUsagePattern(tc.s); got != tc.want {
				t.Errorf("IsValidUsagePattern(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}
