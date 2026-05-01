package domain

import (
	"errors"
	"time"
)

const (
	entitlementOwnerMaxLen   = 255
	entitlementPurposeMaxLen = 1024
)

// Sentinel errors for Entitlement validation.
var (
	ErrEntitlementNameInvalid       = errors.New("domain: entitlement name must be a lower-kebab slug, 1..63 chars, [a-z0-9-]")
	ErrEntitlementOwnerRequired     = errors.New("domain: entitlement owner is required")
	ErrEntitlementOwnerTooLong      = errors.New("domain: entitlement owner exceeds 255 characters")
	ErrEntitlementPurposeRequired   = errors.New("domain: entitlement purpose is required")
	ErrEntitlementPurposeTooLong    = errors.New("domain: entitlement purpose exceeds 1024 characters")
	ErrEntitlementProductIDRequired = errors.New("domain: entitlement product id is required")
)

// Entitlement is the human-facing access package per the project spec.
// Owner and Purpose are required for governance traceability.
type Entitlement struct {
	ID        ID
	Name      string
	ProductID ID
	Owner     string
	Purpose   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewEntitlement constructs and validates an Entitlement, assigning a fresh ID and timestamps.
func NewEntitlement(productID ID, name, owner, purpose string) (*Entitlement, error) {
	now := time.Now().UTC()
	e := &Entitlement{
		ID:        NewID(),
		Name:      name,
		ProductID: productID,
		Owner:     owner,
		Purpose:   purpose,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// Validate enforces Entitlement invariants.
func (e *Entitlement) Validate() error {
	if e.ProductID == "" {
		return ErrEntitlementProductIDRequired
	}
	if !validName(e.Name) {
		return ErrEntitlementNameInvalid
	}
	if e.Owner == "" {
		return ErrEntitlementOwnerRequired
	}
	if len(e.Owner) > entitlementOwnerMaxLen {
		return ErrEntitlementOwnerTooLong
	}
	if e.Purpose == "" {
		return ErrEntitlementPurposeRequired
	}
	if len(e.Purpose) > entitlementPurposeMaxLen {
		return ErrEntitlementPurposeTooLong
	}
	return nil
}
