package domain

import (
	"errors"
	"fmt"
	"time"
)

const assetScopeDescriptionMaxLen = 1024

// Sentinel errors for AssetScope and AssetSelector validation.
var (
	ErrAssetScopeNameInvalid        = errors.New("domain: asset scope name must be a lower-kebab slug, 1..63 chars, [a-z0-9-]")
	ErrAssetScopeProductIDRequired  = errors.New("domain: asset scope product id is required")
	ErrAssetScopeDescriptionTooLong = errors.New("domain: asset scope description exceeds 1024 characters")
	ErrAssetScopeSelectorEmpty      = errors.New("domain: asset scope selector must specify at least one of type, environment, labels, or asset names")
	ErrAssetScopeAssetNameInvalid   = errors.New("domain: asset scope asset name must be a lower-kebab slug, 1..63 chars, [a-z0-9-]")
	ErrAssetScopeAssetNameDuplicate = errors.New("domain: asset scope asset name appears more than once")
)

// AssetSelector picks a set of Assets. Type and Environment zero-values mean "any".
// Labels means "all of these key-value pairs must match". AssetNames is an explicit
// list overriding the rest of the selector when set.
type AssetSelector struct {
	Type        AssetType
	Environment Environment
	Labels      map[string]string
	AssetNames  []string
}

// AssetScope is a named, reusable selector for assets within a product.
type AssetScope struct {
	ID          ID
	Name        string
	ProductID   ID
	Selector    AssetSelector
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Validate enforces AssetSelector invariants. An empty selector (no type, no env,
// no labels, no asset names) is rejected.
func (sel AssetSelector) Validate() error {
	hasType := sel.Type != ""
	hasEnv := sel.Environment != ""
	hasLabels := len(sel.Labels) > 0
	hasNames := len(sel.AssetNames) > 0

	if !hasType && !hasEnv && !hasLabels && !hasNames {
		return ErrAssetScopeSelectorEmpty
	}
	if hasType && !IsValidAssetType(string(sel.Type)) {
		return fmt.Errorf("%w: %q", ErrAssetTypeInvalid, string(sel.Type))
	}
	if hasEnv && !isValidEnvironment(sel.Environment) {
		return fmt.Errorf("%w: %q", ErrAssetEnvironmentInvalid, string(sel.Environment))
	}
	for k, v := range sel.Labels {
		if !IsValidLabelKey(k) {
			return fmt.Errorf("%w: %q", ErrAssetLabelKeyInvalid, k)
		}
		if !IsValidLabelValue(v) {
			return fmt.Errorf("%w: key %q", ErrAssetLabelValueInvalid, k)
		}
	}
	if hasNames {
		seen := make(map[string]struct{}, len(sel.AssetNames))
		for _, n := range sel.AssetNames {
			if !validName(n) {
				return fmt.Errorf("%w: %q", ErrAssetScopeAssetNameInvalid, n)
			}
			if _, dup := seen[n]; dup {
				return fmt.Errorf("%w: %q", ErrAssetScopeAssetNameDuplicate, n)
			}
			seen[n] = struct{}{}
		}
	}
	return nil
}

// NewAssetScope constructs and validates an AssetScope, assigning a fresh ID and timestamps.
func NewAssetScope(productID ID, name string, sel AssetSelector, description string) (*AssetScope, error) {
	now := time.Now().UTC()
	s := &AssetScope{
		ID:          NewID(),
		Name:        name,
		ProductID:   productID,
		Selector:    sel,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Validate enforces AssetScope invariants.
func (s *AssetScope) Validate() error {
	if s.ProductID == "" {
		return ErrAssetScopeProductIDRequired
	}
	if !validName(s.Name) {
		return ErrAssetScopeNameInvalid
	}
	if len(s.Description) > assetScopeDescriptionMaxLen {
		return ErrAssetScopeDescriptionTooLong
	}
	return s.Selector.Validate()
}
