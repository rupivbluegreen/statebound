package domain

import (
	"errors"
	"fmt"
	"time"
)

// GlobalObjectType enumerates reusable access objects.
type GlobalObjectType string

const (
	GlobalObjectTypeLinuxGroup            GlobalObjectType = "linux-group"
	GlobalObjectTypeLinuxSudoersFragment  GlobalObjectType = "linux-sudoers-fragment"
	GlobalObjectTypePostgresRole          GlobalObjectType = "postgres-role"
	GlobalObjectTypeKubernetesRoleBinding GlobalObjectType = "kubernetes-role-binding"
	GlobalObjectTypeRegoPolicy            GlobalObjectType = "rego-policy"
)

// Sentinel errors for GlobalObject validation.
var (
	ErrGlobalObjectNameInvalid = errors.New("domain: global object name must be a lower-kebab slug, 1..63 chars, [a-z0-9-]")
	ErrGlobalObjectTypeInvalid = errors.New("domain: global object type is invalid")
)

// GlobalObject is a reusable access object such as a group, role, or policy.
// ProductID is nullable: nil means "cross-product reusable".
type GlobalObject struct {
	ID        ID
	Name      string
	Type      GlobalObjectType
	ProductID *ID
	Spec      map[string]any
	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsValidGlobalObjectType reports whether s is one of the GlobalObjectType constants.
func IsValidGlobalObjectType(s string) bool {
	switch GlobalObjectType(s) {
	case GlobalObjectTypeLinuxGroup,
		GlobalObjectTypeLinuxSudoersFragment,
		GlobalObjectTypePostgresRole,
		GlobalObjectTypeKubernetesRoleBinding,
		GlobalObjectTypeRegoPolicy:
		return true
	}
	return false
}

// NewGlobalObject constructs and validates a GlobalObject.
func NewGlobalObject(name string, t GlobalObjectType, productID *ID, spec map[string]any) (*GlobalObject, error) {
	now := time.Now().UTC()
	g := &GlobalObject{
		ID:        NewID(),
		Name:      name,
		Type:      t,
		ProductID: productID,
		Spec:      spec,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return g, nil
}

// Validate enforces GlobalObject invariants.
func (g *GlobalObject) Validate() error {
	if !validName(g.Name) {
		return ErrGlobalObjectNameInvalid
	}
	if !IsValidGlobalObjectType(string(g.Type)) {
		return fmt.Errorf("%w: %q", ErrGlobalObjectTypeInvalid, string(g.Type))
	}
	return nil
}
