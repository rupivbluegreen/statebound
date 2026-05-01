package domain

import (
	"errors"
	"time"
)

// EventKind enumerates the audit event kinds emitted by Statebound.
// Hash-chain population (PrevHash, Hash) lands from v0.2; Phase 0 leaves them empty.
type EventKind string

const (
	EventApprovalRecorded       EventKind = "approval.recorded"
	EventApprovedVersionCreated EventKind = "approved_version.created"
	EventAssetCreated           EventKind = "asset.created"
	EventAssetDeleted           EventKind = "asset.deleted"
	EventAssetScopeCreated      EventKind = "asset_scope.created"
	EventAssetScopeDeleted      EventKind = "asset_scope.deleted"
	EventAssetScopeUpdated      EventKind = "asset_scope.updated"
	EventAssetUpdated           EventKind = "asset.updated"
	EventAuthorizationCreated   EventKind = "authorization.created"
	EventAuthorizationDeleted   EventKind = "authorization.deleted"
	EventAuthorizationUpdated   EventKind = "authorization.updated"
	EventChangeSetApproved      EventKind = "changeset.approved"
	EventChangeSetConflicted    EventKind = "changeset.conflicted"
	EventChangeSetCreated       EventKind = "changeset.created"
	EventChangeSetRejected      EventKind = "changeset.rejected"
	EventChangeSetSubmitted     EventKind = "changeset.submitted"
	EventEntitlementCreated     EventKind = "entitlement.created"
	EventEntitlementDeleted     EventKind = "entitlement.deleted"
	EventEntitlementUpdated     EventKind = "entitlement.updated"
	EventGlobalObjectCreated    EventKind = "global_object.created"
	EventGlobalObjectDeleted    EventKind = "global_object.deleted"
	EventGlobalObjectUpdated    EventKind = "global_object.updated"
	EventModelImported          EventKind = "model.imported"
	EventProductCreated         EventKind = "product.created"
	EventProductDeleted         EventKind = "product.deleted"
	EventProductUpdated         EventKind = "product.updated"
	EventServiceAccountCreated  EventKind = "service_account.created"
	EventServiceAccountDeleted  EventKind = "service_account.deleted"
	EventServiceAccountUpdated  EventKind = "service_account.updated"
)

// Sentinel errors for AuditEvent validation.
var (
	ErrAuditKindRequired         = errors.New("domain: audit event kind is required")
	ErrAuditResourceTypeRequired = errors.New("domain: audit event resource type is required")
	ErrAuditResourceIDRequired   = errors.New("domain: audit event resource id is required")
)

// AuditEvent is an append-only record of something that happened.
// PrevHash and Hash are hex-encoded SHA-256 strings populated from v0.2 onward.
type AuditEvent struct {
	ID           ID
	Kind         EventKind
	Actor        Actor
	ResourceType string
	ResourceID   string
	Payload      map[string]any
	OccurredAt   time.Time
	PrevHash     string
	Hash         string
}

// NewAuditEvent constructs and validates an AuditEvent with a fresh ID and timestamp.
func NewAuditEvent(kind EventKind, actor Actor, resourceType, resourceID string, payload map[string]any) (*AuditEvent, error) {
	e := &AuditEvent{
		ID:           NewID(),
		Kind:         kind,
		Actor:        actor,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Payload:      payload,
		OccurredAt:   time.Now().UTC(),
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// Validate enforces AuditEvent invariants.
func (e *AuditEvent) Validate() error {
	if string(e.Kind) == "" {
		return ErrAuditKindRequired
	}
	if err := e.Actor.Validate(); err != nil {
		return err
	}
	if e.ResourceType == "" {
		return ErrAuditResourceTypeRequired
	}
	if e.ResourceID == "" {
		return ErrAuditResourceIDRequired
	}
	return nil
}
