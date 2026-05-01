package domain

import (
	"errors"
	"time"
)

const productDescriptionMaxLen = 1024

// Sentinel errors for Product validation.
var (
	ErrProductNameInvalid        = errors.New("domain: product name must be a lower-kebab slug, 1..63 chars, [a-z0-9-]")
	ErrProductOwnerRequired      = errors.New("domain: product owner is required")
	ErrProductDescriptionTooLong = errors.New("domain: product description exceeds 1024 characters")
)

// Product is the top-level governed unit per the project spec section 4.
type Product struct {
	ID          ID
	Name        string
	Owner       string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IsValidProductName reports whether s satisfies the product name slug rules.
func IsValidProductName(s string) bool {
	return validName(s)
}

// NewProduct constructs and validates a Product, assigning a fresh ID and timestamps.
func NewProduct(name, owner, description string) (*Product, error) {
	now := time.Now().UTC()
	p := &Product{
		ID:          NewID(),
		Name:        name,
		Owner:       owner,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// Validate enforces Product invariants.
func (p *Product) Validate() error {
	if !IsValidProductName(p.Name) {
		return ErrProductNameInvalid
	}
	if p.Owner == "" {
		return ErrProductOwnerRequired
	}
	if len(p.Description) > productDescriptionMaxLen {
		return ErrProductDescriptionTooLong
	}
	return nil
}
