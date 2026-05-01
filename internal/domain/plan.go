package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// PlanState enumerates the lifecycle states of a connector-generated Plan.
//
// Phase 4 ships only Draft/Refused/Ready: plans are read-only artifacts —
// no Apply yet. Applied/Failed are reserved for Phase 6 when the apply
// flow lands. Keep the SQL CHECK constraint in
// migrations/0006_plans.sql in sync with this list.
type PlanState string

const (
	// PlanStateDraft is the freshly-built state. The connector has produced
	// items and content but the plan has not yet been admitted by policy.
	PlanStateDraft PlanState = "draft"
	// PlanStateReady means OPA accepted the plan and (Phase 6+) it is
	// eligible for apply. Phase 4 connectors stop at Ready.
	PlanStateReady PlanState = "ready"
	// PlanStateRefused means OPA denied the plan or the underlying
	// ApprovedVersion was rejected/superseded. RefusedReason carries the
	// human-readable cause.
	PlanStateRefused PlanState = "refused"
	// PlanStateApplied is reserved for Phase 6+ when Apply lands.
	PlanStateApplied PlanState = "applied"
	// PlanStateFailed is reserved for Phase 6+: an apply that began but
	// did not complete cleanly.
	PlanStateFailed PlanState = "failed"
)

// Sentinel errors for Plan validation and state machine.
var (
	ErrPlanNotFound          = errors.New("domain: plan not found")
	ErrPlanInvalid           = errors.New("domain: plan invalid")
	ErrPlanStateInvalid      = errors.New("domain: plan state is invalid")
	ErrPlanInvalidTransition = errors.New("domain: plan state transition is not allowed")

	ErrPlanProductIDRequired         = errors.New("domain: plan product id is required")
	ErrPlanApprovedVersionIDRequired = errors.New("domain: plan approved version id is required")
	ErrPlanSequenceInvalid           = errors.New("domain: plan sequence must be >= 1")
	ErrPlanConnectorNameRequired     = errors.New("domain: plan connector name is required")
	ErrPlanConnectorVersionRequired  = errors.New("domain: plan connector version is required")
	ErrPlanContentEmpty              = errors.New("domain: plan content is empty")
	ErrPlanContentNotJSON            = errors.New("domain: plan content is not valid JSON")
	ErrPlanRefusedReasonRequired     = errors.New("domain: plan refused reason is required when transitioning to refused")
)

// Plan is a connector's proposal of changes to bring a target system in
// line with an ApprovedVersion. Plans are read-only artifacts in Phase 4
// (no apply yet). They are deterministic given identical
// (ApprovedVersion, connector_version) input — re-running plan produces
// byte-identical content_hash, which the storage layer uses as the
// idempotency key.
type Plan struct {
	ID                ID
	ProductID         ID
	ApprovedVersionID ID
	Sequence          int64           // mirrors ApprovedVersion.Sequence
	ConnectorName     string          // e.g. "linux-sudo", "linux-ssh"
	ConnectorVersion  string          // e.g. "0.4.0"
	State             PlanState
	Summary           string          // one-line human-readable
	ContentHash       string          // SHA-256 hex of canonical content bytes
	Content           json.RawMessage // canonical JSON of plan items + generated artifacts
	GeneratedAt       time.Time
	GeneratedBy       Actor
	RefusedReason     string
}

// PlanItem is one logical change in a plan: e.g. "add user 'alice' to
// group 'payments-runtime' on host pay-linux-01". Items are persisted
// alongside the plan for query/UI but Plan.Content (JSONB) is the
// canonical source for hashing — connectors must include the
// items inside the content payload before construction.
type PlanItem struct {
	ID           ID
	PlanID       ID
	Sequence     int             // 1-based ordinal within the plan
	Action       string          // "create" | "update" | "delete"
	ResourceKind string          // "linux.local-group-membership" | "linux.sudoers-fragment" | "linux.ssh-authorized-keys" | ...
	ResourceRef  string          // stable identifier inside the target system (e.g. "pay-linux-01:/etc/sudoers.d/payments")
	Body         json.RawMessage // canonical JSON describing the item (e.g. fragment text, members list)
	Risk         string          // "low" | "medium" | "high" | "critical"
	Note         string          // free-form connector note
}

// IsValidPlanState reports whether s is one of the PlanState constants.
func IsValidPlanState(s string) bool {
	switch PlanState(s) {
	case PlanStateDraft,
		PlanStateReady,
		PlanStateRefused,
		PlanStateApplied,
		PlanStateFailed:
		return true
	}
	return false
}

// NewPlan constructs and validates a Plan in Draft state. The content
// hash is computed from a defensive copy of content so callers cannot
// mutate Content out from under the persisted hash. The id is freshly
// generated and GeneratedAt is set to UTC now.
func NewPlan(productID, approvedVersionID ID, sequence int64,
	connectorName, connectorVersion string, content json.RawMessage,
	summary string, generatedBy Actor) (*Plan, error) {
	if productID == "" {
		return nil, ErrPlanProductIDRequired
	}
	if approvedVersionID == "" {
		return nil, ErrPlanApprovedVersionIDRequired
	}
	if sequence < 1 {
		return nil, ErrPlanSequenceInvalid
	}
	if connectorName == "" {
		return nil, ErrPlanConnectorNameRequired
	}
	if connectorVersion == "" {
		return nil, ErrPlanConnectorVersionRequired
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrPlanInvalid, ErrPlanContentEmpty)
	}
	if !json.Valid(content) {
		return nil, fmt.Errorf("%w: %w", ErrPlanInvalid, ErrPlanContentNotJSON)
	}
	if err := generatedBy.Validate(); err != nil {
		return nil, err
	}

	// Defensive copy of content: callers cannot mutate Content out from
	// under the persisted hash.
	buf := make([]byte, len(content))
	copy(buf, content)

	sum := sha256.Sum256(buf)
	return &Plan{
		ID:                NewID(),
		ProductID:         productID,
		ApprovedVersionID: approvedVersionID,
		Sequence:          sequence,
		ConnectorName:     connectorName,
		ConnectorVersion:  connectorVersion,
		State:             PlanStateDraft,
		Summary:           summary,
		ContentHash:       hex.EncodeToString(sum[:]),
		Content:           buf,
		GeneratedAt:       time.Now().UTC(),
		GeneratedBy:       generatedBy,
	}, nil
}

// Hash recomputes the SHA-256 hex of Content. Defense-in-depth: tests
// use this to assert the persisted ContentHash matches the bytes on
// hand. If the bytes have been mutated post-construction the recomputed
// value will diverge.
func (p *Plan) Hash() string {
	if p == nil {
		return ""
	}
	sum := sha256.Sum256(p.Content)
	return hex.EncodeToString(sum[:])
}

// CanTransitionTo reports whether moving from the receiver's state to
// target is a legal state-machine edge.
//
// Legal edges:
//   - Draft   -> Ready
//   - Draft   -> Refused
//   - Ready   -> Applied  (reserved for Phase 6+)
//   - Ready   -> Failed   (reserved for Phase 6+)
//   - Ready   -> Refused  (e.g. apply re-evaluated and OPA flipped to deny)
func (p *Plan) CanTransitionTo(target PlanState) bool {
	if p == nil {
		return false
	}
	switch p.State {
	case PlanStateDraft:
		return target == PlanStateReady || target == PlanStateRefused
	case PlanStateReady:
		return target == PlanStateApplied ||
			target == PlanStateFailed ||
			target == PlanStateRefused
	}
	return false
}

// Transition advances the Plan to target if the edge is legal. A non-empty
// reason is required when transitioning to Refused; the reason is stored
// in RefusedReason so audit can answer "why was this plan turned away".
func (p *Plan) Transition(target PlanState, reason string) error {
	if p == nil {
		return ErrPlanInvalid
	}
	if !IsValidPlanState(string(target)) {
		return fmt.Errorf("%w: %q", ErrPlanStateInvalid, string(target))
	}
	if !p.CanTransitionTo(target) {
		return fmt.Errorf("%w: %s -> %s", ErrPlanInvalidTransition, p.State, target)
	}
	if target == PlanStateRefused && reason == "" {
		return ErrPlanRefusedReasonRequired
	}
	p.State = target
	if target == PlanStateRefused {
		p.RefusedReason = reason
	}
	return nil
}
