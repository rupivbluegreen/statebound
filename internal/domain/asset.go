package domain

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// AssetType enumerates the kinds of concrete target resources Statebound governs.
type AssetType string

const (
	AssetTypeLinuxHost           AssetType = "linux-host"
	AssetTypePostgresDatabase    AssetType = "postgres-database"
	AssetTypeKubernetesNamespace AssetType = "kubernetes-namespace"
	AssetTypeKubernetesCluster   AssetType = "kubernetes-cluster"
	AssetTypeService             AssetType = "service"
	AssetTypeBucket              AssetType = "bucket"
)

const (
	assetDescriptionMaxLen = 1024
	labelValueMaxLen       = 255
)

// labelKeyRe matches label keys: lowercase, starts with a letter, then [a-z0-9._-], up to 63 chars.
var labelKeyRe = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)

// Sentinel errors for Asset validation.
var (
	ErrAssetNameInvalid        = errors.New("domain: asset name must be a lower-kebab slug, 1..63 chars, [a-z0-9-]")
	ErrAssetTypeInvalid        = errors.New("domain: asset type is invalid")
	ErrAssetEnvironmentInvalid = errors.New("domain: asset environment is invalid")
	ErrAssetLabelKeyInvalid    = errors.New("domain: asset label key is invalid")
	ErrAssetLabelValueInvalid  = errors.New("domain: asset label value is invalid")
	ErrAssetDescriptionTooLong = errors.New("domain: asset description exceeds 1024 characters")
	ErrAssetProductIDRequired  = errors.New("domain: asset product id is required")
)

// Asset is a concrete target resource governed by a Product.
type Asset struct {
	ID          ID
	Name        string
	Type        AssetType
	ProductID   ID
	Environment Environment
	Labels      map[string]string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IsValidAssetType reports whether s is one of the AssetType constants.
func IsValidAssetType(s string) bool {
	switch AssetType(s) {
	case AssetTypeLinuxHost,
		AssetTypePostgresDatabase,
		AssetTypeKubernetesNamespace,
		AssetTypeKubernetesCluster,
		AssetTypeService,
		AssetTypeBucket:
		return true
	}
	return false
}

// IsValidLabelKey reports whether s is a valid label key.
func IsValidLabelKey(s string) bool {
	return labelKeyRe.MatchString(s)
}

// IsValidLabelValue reports whether s is a valid label value: non-empty, <= 255 chars.
func IsValidLabelValue(s string) bool {
	return s != "" && len(s) <= labelValueMaxLen
}

// isValidEnvironment is private because Environment validation only happens through types that own one.
func isValidEnvironment(e Environment) bool {
	switch e {
	case EnvDev, EnvStaging, EnvProd:
		return true
	}
	return false
}

// NewAsset constructs and validates an Asset, assigning a fresh ID and timestamps.
func NewAsset(productID ID, name string, t AssetType, env Environment, labels map[string]string, description string) (*Asset, error) {
	now := time.Now().UTC()
	a := &Asset{
		ID:          NewID(),
		Name:        name,
		Type:        t,
		ProductID:   productID,
		Environment: env,
		Labels:      labels,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return a, nil
}

// Validate enforces Asset invariants.
func (a *Asset) Validate() error {
	if a.ProductID == "" {
		return ErrAssetProductIDRequired
	}
	if !validName(a.Name) {
		return ErrAssetNameInvalid
	}
	if !IsValidAssetType(string(a.Type)) {
		return fmt.Errorf("%w: %q", ErrAssetTypeInvalid, string(a.Type))
	}
	if !isValidEnvironment(a.Environment) {
		return fmt.Errorf("%w: %q", ErrAssetEnvironmentInvalid, string(a.Environment))
	}
	if len(a.Description) > assetDescriptionMaxLen {
		return ErrAssetDescriptionTooLong
	}
	for k, v := range a.Labels {
		if !IsValidLabelKey(k) {
			return fmt.Errorf("%w: %q", ErrAssetLabelKeyInvalid, k)
		}
		if !IsValidLabelValue(v) {
			return fmt.Errorf("%w: key %q", ErrAssetLabelValueInvalid, k)
		}
	}
	return nil
}
