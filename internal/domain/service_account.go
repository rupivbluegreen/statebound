package domain

import (
	"errors"
	"fmt"
	"time"
)

// UsagePattern enumerates the categories of ServiceAccount usage.
type UsagePattern string

const (
	UsageSystemToSystem UsagePattern = "system-to-system"
	UsageAgent          UsagePattern = "agent"
	UsageHumanShared    UsagePattern = "human-shared"
	UsageDeploy         UsagePattern = "deploy"
	UsageMonitoring     UsagePattern = "monitoring"
)

const (
	serviceAccountOwnerMaxLen   = 255
	serviceAccountPurposeMaxLen = 1024
)

// Sentinel errors for ServiceAccount validation.
var (
	ErrServiceAccountNameInvalid          = errors.New("domain: service account name must be a lower-kebab slug, 1..63 chars, [a-z0-9-]")
	ErrServiceAccountOwnerRequired        = errors.New("domain: service account owner is required")
	ErrServiceAccountOwnerTooLong         = errors.New("domain: service account owner exceeds 255 characters")
	ErrServiceAccountPurposeRequired      = errors.New("domain: service account purpose is required")
	ErrServiceAccountPurposeTooLong       = errors.New("domain: service account purpose exceeds 1024 characters")
	ErrServiceAccountUsagePatternInvalid  = errors.New("domain: service account usage pattern is invalid")
	ErrServiceAccountUsagePatternRequired = errors.New("domain: service account usage pattern is required")
	ErrServiceAccountProductIDRequired    = errors.New("domain: service account product id is required")
)

// ServiceAccount is a non-personal account, workload identity, or agent identity.
// Owner, Purpose, and UsagePattern are all required for governance traceability.
type ServiceAccount struct {
	ID           ID
	Name         string
	ProductID    ID
	Owner        string
	Purpose      string
	UsagePattern UsagePattern
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// IsValidUsagePattern reports whether s is one of the UsagePattern constants.
func IsValidUsagePattern(s string) bool {
	switch UsagePattern(s) {
	case UsageSystemToSystem, UsageAgent, UsageHumanShared, UsageDeploy, UsageMonitoring:
		return true
	}
	return false
}

// NewServiceAccount constructs and validates a ServiceAccount.
func NewServiceAccount(productID ID, name, owner, purpose string, u UsagePattern) (*ServiceAccount, error) {
	now := time.Now().UTC()
	s := &ServiceAccount{
		ID:           NewID(),
		Name:         name,
		ProductID:    productID,
		Owner:        owner,
		Purpose:      purpose,
		UsagePattern: u,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Validate enforces ServiceAccount invariants.
func (s *ServiceAccount) Validate() error {
	if s.ProductID == "" {
		return ErrServiceAccountProductIDRequired
	}
	if !validName(s.Name) {
		return ErrServiceAccountNameInvalid
	}
	if s.Owner == "" {
		return ErrServiceAccountOwnerRequired
	}
	if len(s.Owner) > serviceAccountOwnerMaxLen {
		return ErrServiceAccountOwnerTooLong
	}
	if s.Purpose == "" {
		return ErrServiceAccountPurposeRequired
	}
	if len(s.Purpose) > serviceAccountPurposeMaxLen {
		return ErrServiceAccountPurposeTooLong
	}
	if s.UsagePattern == "" {
		return ErrServiceAccountUsagePatternRequired
	}
	if !IsValidUsagePattern(string(s.UsagePattern)) {
		return fmt.Errorf("%w: %q", ErrServiceAccountUsagePatternInvalid, string(s.UsagePattern))
	}
	return nil
}
