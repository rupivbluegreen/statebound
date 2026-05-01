package domain

import (
	"errors"
	"time"
)

// EventKind enumerates the audit event kinds emitted by Statebound.
// Hash-chain population (PrevHash, Hash) lands from v0.2; Phase 0 leaves them empty.
type EventKind string

const (
	EventApplyFailed            EventKind = "apply.failed"
	EventApplyStarted           EventKind = "apply.started"
	EventApplySucceeded         EventKind = "apply.succeeded"
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
	EventDriftFindingDetected   EventKind = "drift.finding.detected"
	EventDriftScanFailed        EventKind = "drift.scan.failed"
	EventDriftScanStarted       EventKind = "drift.scan.started"
	EventDriftScanSucceeded     EventKind = "drift.scan.succeeded"
	EventEntitlementCreated     EventKind = "entitlement.created"
	EventEntitlementDeleted     EventKind = "entitlement.deleted"
	EventEntitlementUpdated     EventKind = "entitlement.updated"
	EventEvidenceCreated        EventKind = "evidence.created"
	EventEvidenceExported       EventKind = "evidence.exported"
	EventGlobalObjectCreated    EventKind = "global_object.created"
	EventGlobalObjectDeleted    EventKind = "global_object.deleted"
	EventGlobalObjectUpdated    EventKind = "global_object.updated"
	EventModelImported          EventKind = "model.imported"
	EventPlanGenerated          EventKind = "plan.generated"
	EventPlanReady              EventKind = "plan.ready"
	EventPlanRefused            EventKind = "plan.refused"
	// Phase 8 wave A — signed plan bundles. Plan signing happens at plan
	// generation time; verification gates the apply path. Key lifecycle
	// events cover generate/disable/expire so an auditor can prove which
	// keys were live when a given signature was issued.
	EventPlanSigned            EventKind = "plan.signed"
	EventPlanSignatureVerified EventKind = "plan.signature.verified"
	EventPlanSignatureFailed   EventKind = "plan.signature.failed"
	EventSigningKeyGenerated   EventKind = "signing.key.generated"
	EventSigningKeyDisabled    EventKind = "signing.key.disabled"
	EventSigningKeyExpired     EventKind = "signing.key.expired"
	// EventPolicyEvaluated is emitted by internal/authz after every OPA
	// evaluation of a ChangeSet (Phase 2 wave B). The payload carries the
	// decision id, change set id, phase, outcome, bundle hash, and a compact
	// per-rule summary; the full canonical rules/input live in the
	// policy_decisions row referenced by decision id. EventPolicyDecisionDeny
	// and EventPolicyDecisionEscalation are reserved for future per-rule fanout
	// and not emitted by Phase 2 wave B.
	EventPolicyDecisionDeny       EventKind = "policy.decision.deny"
	EventPolicyDecisionEscalation EventKind = "policy.decision.escalation_required"
	EventPolicyEvaluated          EventKind = "policy.evaluated"
	EventProductCreated           EventKind = "product.created"
	EventProductDeleted           EventKind = "product.deleted"
	EventProductUpdated           EventKind = "product.updated"
	// EventRBACDenied is emitted by internal/cli.requireCapability when the
	// pre-check rejects an actor for a capability they do not hold. The
	// payload carries the actor, the capability, the required roles, and
	// the actor's currently granted roles. Phase 8 wave A.
	EventRBACDenied EventKind = "rbac.denied"
	// EventRoleBindingGranted is emitted when an admin (or the bootstrap
	// flag) creates a new actor_role_bindings row.
	EventRoleBindingGranted EventKind = "rbac.binding.granted"
	// EventRoleBindingRevoked is emitted when an admin deletes an
	// actor_role_bindings row.
	EventRoleBindingRevoked    EventKind = "rbac.binding.revoked"
	EventServiceAccountCreated EventKind = "service_account.created"
	EventServiceAccountDeleted EventKind = "service_account.deleted"
	EventServiceAccountUpdated EventKind = "service_account.updated"
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
