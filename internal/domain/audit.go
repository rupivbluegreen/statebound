package domain

import (
	"errors"
	"time"
)

// EventKind enumerates the audit event kinds emitted by Statebound.
// Hash-chain population (PrevHash, Hash) lands from v0.2; Phase 0 leaves them empty.
type EventKind string

const (
	EventProductCreated EventKind = "product.created"
	EventProductUpdated EventKind = "product.updated"
	EventProductDeleted EventKind = "product.deleted"
	EventModelImported  EventKind = "model.imported"
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
