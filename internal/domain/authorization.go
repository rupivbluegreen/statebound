package domain

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// AuthorizationParentKind enumerates the kinds of objects an Authorization can hang off.
type AuthorizationParentKind string

const (
	AuthParentEntitlement    AuthorizationParentKind = "entitlement"
	AuthParentServiceAccount AuthorizationParentKind = "service-account"
	AuthParentGlobalObject   AuthorizationParentKind = "global-object"
)

// AuthorizationType enumerates the granular permission shapes Statebound governs in v0.1.
type AuthorizationType string

const (
	AuthTypeLinuxSSH              AuthorizationType = "linux.ssh"
	AuthTypeLinuxSudo             AuthorizationType = "linux.sudo"
	AuthTypeLinuxLocalGroup       AuthorizationType = "linux.local-group"
	AuthTypePostgresGrant         AuthorizationType = "postgres.grant"
	AuthTypeKubernetesRoleBinding AuthorizationType = "kubernetes.role-binding"
)

const (
	linuxSudoCommandMaxLen = 4096
	linuxGroupNameMaxLen   = 32
)

// linuxGroupRe matches POSIX-ish Linux group names: starts with [a-z_], remainder [a-z0-9_-].
var linuxGroupRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// Sentinel errors for Authorization validation.
var (
	ErrAuthorizationParentKindInvalid = errors.New("domain: authorization parent kind is invalid")
	ErrAuthorizationTypeInvalid       = errors.New("domain: authorization type is invalid")
	ErrAuthorizationParentIDRequired  = errors.New("domain: authorization parent id is required")
	ErrAuthorizationTargetExclusivity = errors.New("domain: authorization must set exactly one of AssetScopeID or GlobalObjectID")
	ErrAuthorizationSpecInvalid       = errors.New("domain: authorization spec invalid")
)

// Authorization is a granular permission link attaching a Type to either an asset
// scope or a global object, owned by an entitlement, service account, or global object.
type Authorization struct {
	ID             ID
	ParentKind     AuthorizationParentKind
	ParentID       ID
	Type           AuthorizationType
	AssetScopeID   *ID
	GlobalObjectID *ID
	Spec           map[string]any
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// IsValidAuthorizationParentKind reports whether s is one of the parent-kind constants.
func IsValidAuthorizationParentKind(s string) bool {
	switch AuthorizationParentKind(s) {
	case AuthParentEntitlement, AuthParentServiceAccount, AuthParentGlobalObject:
		return true
	}
	return false
}

// IsValidAuthorizationType reports whether s is one of the AuthorizationType constants.
func IsValidAuthorizationType(s string) bool {
	switch AuthorizationType(s) {
	case AuthTypeLinuxSSH,
		AuthTypeLinuxSudo,
		AuthTypeLinuxLocalGroup,
		AuthTypePostgresGrant,
		AuthTypeKubernetesRoleBinding:
		return true
	}
	return false
}

// NewAuthorization constructs and validates an Authorization.
func NewAuthorization(parentKind AuthorizationParentKind, parentID ID, t AuthorizationType, scopeID, globalID *ID, spec map[string]any) (*Authorization, error) {
	now := time.Now().UTC()
	a := &Authorization{
		ID:             NewID(),
		ParentKind:     parentKind,
		ParentID:       parentID,
		Type:           t,
		AssetScopeID:   scopeID,
		GlobalObjectID: globalID,
		Spec:           spec,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return a, nil
}

// Validate enforces Authorization invariants, including the per-Type spec rules.
func (a *Authorization) Validate() error {
	if !IsValidAuthorizationParentKind(string(a.ParentKind)) {
		return fmt.Errorf("%w: %q", ErrAuthorizationParentKindInvalid, string(a.ParentKind))
	}
	if a.ParentID == "" {
		return ErrAuthorizationParentIDRequired
	}
	if !IsValidAuthorizationType(string(a.Type)) {
		return fmt.Errorf("%w: %q", ErrAuthorizationTypeInvalid, string(a.Type))
	}
	scopeSet := a.AssetScopeID != nil && *a.AssetScopeID != ""
	globalSet := a.GlobalObjectID != nil && *a.GlobalObjectID != ""
	if scopeSet == globalSet {
		// Both set, or neither set: invalid either way.
		return ErrAuthorizationTargetExclusivity
	}
	if err := validateAuthSpec(a.Type, a.Spec); err != nil {
		// Wrap so callers can pattern-match the canonical sentinel via errors.Is,
		// while preserving the per-type descriptive cause in the message.
		return fmt.Errorf("%w for %s: %s", ErrAuthorizationSpecInvalid, a.Type, err.Error())
	}
	return nil
}

// validateAuthSpec dispatches to the per-Type spec validator. Unknown types pass
// through (Type is already validated above), but in practice every constant has a validator.
func validateAuthSpec(t AuthorizationType, spec map[string]any) error {
	switch t {
	case AuthTypeLinuxSSH:
		return validateLinuxSSHSpec(spec)
	case AuthTypeLinuxSudo:
		return validateLinuxSudoSpec(spec)
	case AuthTypeLinuxLocalGroup:
		return validateLinuxLocalGroupSpec(spec)
	case AuthTypePostgresGrant:
		return validatePostgresGrantSpec(spec)
	case AuthTypeKubernetesRoleBinding:
		return validateKubernetesRoleBindingSpec(spec)
	}
	return nil
}

func validateLinuxSSHSpec(spec map[string]any) error {
	methods, err := requireStringSlice(spec, "methods")
	if err != nil {
		return err
	}
	if len(methods) == 0 {
		return errors.New("methods must be a non-empty list")
	}
	for _, m := range methods {
		if m != "ssh" {
			return fmt.Errorf("unsupported method %q (allowed: ssh)", m)
		}
	}
	return nil
}

func validateLinuxSudoSpec(spec map[string]any) error {
	asUser, err := requireString(spec, "asUser")
	if err != nil {
		return err
	}
	if asUser == "" {
		return errors.New("asUser must be non-empty")
	}
	commandsRaw, ok := spec["commands"]
	if !ok || commandsRaw == nil {
		return errors.New("commands is required")
	}
	commands, ok := commandsRaw.(map[string]any)
	if !ok {
		return errors.New("commands must be an object")
	}
	for _, key := range []string{"allow", "deny"} {
		listRaw, ok := commands[key]
		if !ok || listRaw == nil {
			return fmt.Errorf("commands.%s must be a list (may be empty)", key)
		}
		list, err := toStringSlice(listRaw)
		if err != nil {
			return fmt.Errorf("commands.%s: %w", key, err)
		}
		for _, cmd := range list {
			if len(cmd) == 0 {
				return fmt.Errorf("commands.%s entry must be non-empty", key)
			}
			if cmd[0] != '/' {
				return fmt.Errorf("commands.%s entry %q must be an absolute path", key, cmd)
			}
			if len(cmd) > linuxSudoCommandMaxLen {
				return fmt.Errorf("commands.%s entry exceeds %d characters", key, linuxSudoCommandMaxLen)
			}
		}
	}
	return nil
}

func validateLinuxLocalGroupSpec(spec map[string]any) error {
	group, err := requireString(spec, "group")
	if err != nil {
		return err
	}
	if group == "" {
		return errors.New("group must be non-empty")
	}
	if len(group) > linuxGroupNameMaxLen {
		return fmt.Errorf("group exceeds %d characters", linuxGroupNameMaxLen)
	}
	if !linuxGroupRe.MatchString(group) {
		return fmt.Errorf("group %q is not a valid Linux group name", group)
	}
	return nil
}

func validatePostgresGrantSpec(spec map[string]any) error {
	privs, err := requireStringSlice(spec, "privileges")
	if err != nil {
		return err
	}
	if len(privs) == 0 {
		return errors.New("privileges must be a non-empty list")
	}
	objs, err := requireStringSlice(spec, "objects")
	if err != nil {
		return err
	}
	if len(objs) == 0 {
		return errors.New("objects must be a non-empty list")
	}
	return nil
}

func validateKubernetesRoleBindingSpec(spec map[string]any) error {
	role, err := requireString(spec, "role")
	if err != nil {
		return err
	}
	if role == "" {
		return errors.New("role must be non-empty")
	}
	subjectsRaw, ok := spec["subjects"]
	if !ok || subjectsRaw == nil {
		return errors.New("subjects must be a non-empty list")
	}
	subjects, ok := subjectsRaw.([]any)
	if !ok {
		// Allow a typed slice too, but for now keep [] any as the canonical shape.
		return errors.New("subjects must be a list")
	}
	if len(subjects) == 0 {
		return errors.New("subjects must be a non-empty list")
	}
	return nil
}

// requireString fetches a string field or returns a descriptive error.
func requireString(spec map[string]any, key string) (string, error) {
	raw, ok := spec[key]
	if !ok || raw == nil {
		return "", fmt.Errorf("%s is required", key)
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return s, nil
}

// requireStringSlice fetches a list-of-strings field or returns a descriptive error.
func requireStringSlice(spec map[string]any, key string) ([]string, error) {
	raw, ok := spec[key]
	if !ok || raw == nil {
		return nil, fmt.Errorf("%s is required", key)
	}
	out, err := toStringSlice(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return out, nil
}

// toStringSlice coerces a JSON-decoded value into []string. Accepts []any of strings or []string.
func toStringSlice(raw any) ([]string, error) {
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("entry %d is not a string", i)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, errors.New("must be a list of strings")
	}
}
