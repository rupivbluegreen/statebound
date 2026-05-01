// rbac.go
//
// Phase 8 wave A — operator RBAC.
//
// Five non-hierarchical roles bind to a domain.Actor (humans + service
// accounts). A binding grants an Actor exactly one Role; an Actor that
// needs multiple roles needs multiple bindings.
//
// The Capability layer is the stable wire identifier for an action that
// requires authorization. capabilityRoles maps each Capability to the
// roles that grant it; absence from the map is "deny by default".
//
// RBAC is enforced through two complementary paths:
//   1. A tiny Go pre-check helper (internal/cli.requireCapability) that
//      runs before every gated CLI command and emits an audit event on
//      denial.
//   2. A built-in Rego rule (policies/builtin/rbac.rego) that evaluates
//      the same mapping during ChangeSet submit/approve.
//
// Both paths read RolesForCapability so the mapping has a single source
// of truth in this file.

package domain

import (
	"errors"
	"fmt"
	"time"
)

// Role is one of the five built-in operator roles.
type Role string

const (
	// RoleViewer grants read-only access — list products, view ChangeSets,
	// view audit, view evidence.
	RoleViewer Role = "viewer"
	// RoleRequester grants ChangeSet authoring (create + submit) but not
	// approval or apply.
	RoleRequester Role = "requester"
	// RoleApprover grants approve/reject on ChangeSets. Still subject to
	// four-eyes — an approver cannot approve their own ChangeSet.
	RoleApprover Role = "approver"
	// RoleOperator grants plan generation, drift scans, and dry-run apply.
	// It does NOT grant --apply (real mutation) — that requires admin.
	RoleOperator Role = "operator"
	// RoleAdmin grants apply (--apply), role binding management, and any
	// future agent management. Admin does NOT auto-imply other roles —
	// each role is granted explicitly to keep SoD detection clean.
	RoleAdmin Role = "admin"
)

// Capability is a stable string id for an action that may require RBAC.
// New capabilities should follow the "<resource>:<verb>" convention so
// they read naturally in error messages.
type Capability string

const (
	CapabilityProductRead     Capability = "product:read"
	CapabilityChangeSetCreate Capability = "changeset:create"
	CapabilityChangeSetSubmit Capability = "changeset:submit"
	CapabilityApprove         Capability = "changeset:approve"
	CapabilityReject          Capability = "changeset:reject"
	CapabilityPlanGenerate    Capability = "plan:generate"
	CapabilityDriftScan       Capability = "drift:scan"
	CapabilityApplyDryRun     Capability = "apply:dry-run"
	CapabilityApply           Capability = "apply:execute"
	CapabilityRoleManage      Capability = "rbac:manage"
)

// capabilityRoles maps each Capability to the set of Roles that grant
// it. Multiple roles on the right means "any of them is sufficient".
//
// The mapping is intentionally explicit and small. Adding a new
// capability without updating this map makes the action default-deny —
// RolesForCapability returns the empty slice and requireCapability
// refuses to authorize anyone. That is the safe failure mode.
var capabilityRoles = map[Capability][]Role{
	CapabilityProductRead:     {RoleViewer, RoleRequester, RoleApprover, RoleOperator, RoleAdmin},
	CapabilityChangeSetCreate: {RoleRequester, RoleAdmin},
	CapabilityChangeSetSubmit: {RoleRequester, RoleAdmin},
	CapabilityApprove:         {RoleApprover, RoleAdmin},
	CapabilityReject:          {RoleApprover, RoleAdmin},
	CapabilityPlanGenerate:    {RoleOperator, RoleAdmin},
	CapabilityDriftScan:       {RoleOperator, RoleAdmin},
	CapabilityApplyDryRun:     {RoleOperator, RoleAdmin},
	CapabilityApply:           {RoleAdmin},
	CapabilityRoleManage:      {RoleAdmin},
}

// Sentinel errors for RBAC validation.
var (
	ErrRoleInvalid          = errors.New("domain: role is invalid")
	ErrCapabilityInvalid    = errors.New("domain: capability is invalid")
	ErrRoleBindingNotFound  = errors.New("domain: role binding not found")
	ErrRoleBindingDuplicate = errors.New("domain: role binding already exists")
)

// IsValidRole reports whether r is one of the five built-in roles.
func IsValidRole(r Role) bool {
	switch r {
	case RoleViewer, RoleRequester, RoleApprover, RoleOperator, RoleAdmin:
		return true
	}
	return false
}

// IsValidCapability reports whether c has been registered in the
// capabilityRoles map. Unregistered capabilities are default-deny.
func IsValidCapability(c Capability) bool {
	_, ok := capabilityRoles[c]
	return ok
}

// RolesForCapability returns the slice of Roles that grant the given
// Capability. Returns an empty slice (NOT nil) when the capability is
// not registered, so callers can range over the result without
// nil-checking. Empty result means "no role grants this capability" —
// requireCapability treats that as deny-by-default.
//
// The returned slice is a defensive copy so callers cannot mutate the
// internal mapping.
func RolesForCapability(c Capability) []Role {
	roles, ok := capabilityRoles[c]
	if !ok {
		return []Role{}
	}
	out := make([]Role, len(roles))
	copy(out, roles)
	return out
}

// AllRoles returns every built-in role in canonical order. Useful for
// CLI flag validation and for documentation generators.
func AllRoles() []Role {
	return []Role{RoleViewer, RoleRequester, RoleApprover, RoleOperator, RoleAdmin}
}

// AllCapabilities returns every registered capability in deterministic
// (alphabetical-ish, hand-curated) order. Useful for the rego input
// payload, which needs a stable enumeration.
func AllCapabilities() []Capability {
	return []Capability{
		CapabilityApply,
		CapabilityApplyDryRun,
		CapabilityApprove,
		CapabilityChangeSetCreate,
		CapabilityChangeSetSubmit,
		CapabilityDriftScan,
		CapabilityPlanGenerate,
		CapabilityProductRead,
		CapabilityReject,
		CapabilityRoleManage,
	}
}

// CapabilityRolesMap returns a copy of the full capability-to-roles
// mapping. The CLI uses this to populate authz.Input.CapabilityRoles
// for the rego rule. We return a copy so external mutation cannot
// poison the in-process source of truth.
func CapabilityRolesMap() map[Capability][]Role {
	out := make(map[Capability][]Role, len(capabilityRoles))
	for k, v := range capabilityRoles {
		cp := make([]Role, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// ActorRoleBinding is the (Actor, Role) tuple persisted in storage. A
// binding is created with a grantor (the human or service account that
// approved the grant) and an optional expiry; ListActiveRolesForActor
// filters out expired bindings on the read path.
type ActorRoleBinding struct {
	ID        ID
	Actor     Actor
	Role      Role
	GrantedBy Actor
	GrantedAt time.Time
	ExpiresAt *time.Time
	Note      string
}

// noteMaxLen caps the optional note field. The audit log replays the
// note inline, so a misuse with a megabyte payload would bloat every
// downstream evidence pack.
const noteMaxLen = 4096

// NewActorRoleBinding constructs and validates a binding, stamping a
// fresh ID and the current timestamp. Returns ErrRoleInvalid if role is
// not a recognized built-in. Actor and GrantedBy are validated via
// Actor.Validate so an empty subject or unknown kind is rejected before
// the binding ever reaches storage.
func NewActorRoleBinding(actor Actor, role Role, grantedBy Actor, expiresAt *time.Time, note string) (*ActorRoleBinding, error) {
	if !IsValidRole(role) {
		return nil, fmt.Errorf("%w: %q", ErrRoleInvalid, string(role))
	}
	if err := actor.Validate(); err != nil {
		return nil, fmt.Errorf("binding actor: %w", err)
	}
	if err := grantedBy.Validate(); err != nil {
		return nil, fmt.Errorf("binding granted_by: %w", err)
	}
	if len(note) > noteMaxLen {
		return nil, fmt.Errorf("binding note exceeds %d characters", noteMaxLen)
	}
	if expiresAt != nil {
		// Coerce to UTC for stable storage; callers supplying naive
		// local time should not be surprised at evidence pack render.
		t := expiresAt.UTC()
		expiresAt = &t
	}
	return &ActorRoleBinding{
		ID:        NewID(),
		Actor:     actor,
		Role:      role,
		GrantedBy: grantedBy,
		GrantedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Note:      note,
	}, nil
}

// IsActive reports whether the binding is currently in force at t. A
// binding with no expiry is always active; an expired binding is not.
func (b *ActorRoleBinding) IsActive(t time.Time) bool {
	if b.ExpiresAt == nil {
		return true
	}
	return t.Before(*b.ExpiresAt)
}
