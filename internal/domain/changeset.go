package domain

import (
	"errors"
	"fmt"
	"time"
)

// ChangeSetState enumerates the lifecycle states of a ChangeSet.
type ChangeSetState string

const (
	ChangeSetStateDraft     ChangeSetState = "draft"
	ChangeSetStateSubmitted ChangeSetState = "submitted"
	ChangeSetStateApproved  ChangeSetState = "approved"
	ChangeSetStateRejected  ChangeSetState = "rejected"
	// ChangeSetStateConflicted means an approved ChangeSet's parent version was
	// superseded by a sibling that landed first.
	ChangeSetStateConflicted ChangeSetState = "conflicted"
)

const (
	changeSetTitleMaxLen       = 255
	changeSetDescriptionMaxLen = 4096
	changeSetReasonMaxLen      = 4096
)

// Sentinel errors for ChangeSet validation and state machine.
var (
	ErrChangeSetTitleRequired       = errors.New("domain: change set title is required")
	ErrChangeSetTitleTooLong        = errors.New("domain: change set title exceeds 255 characters")
	ErrChangeSetDescriptionTooLong  = errors.New("domain: change set description exceeds 4096 characters")
	ErrChangeSetProductIDRequired   = errors.New("domain: change set product id is required")
	ErrChangeSetStateInvalid        = errors.New("domain: change set state is invalid")
	ErrChangeSetInvalidTransition   = errors.New("domain: change set state transition is not allowed")
	ErrChangeSetReasonTooLong       = errors.New("domain: change set decision reason exceeds 4096 characters")
)

// ChangeSet is a draft set of changes awaiting review and approval.
type ChangeSet struct {
	ID                      ID
	ProductID               ID
	State                   ChangeSetState
	ParentApprovedVersionID *ID
	Title                   string
	Description             string
	RequestedBy             Actor
	SubmittedAt             *time.Time
	DecidedAt               *time.Time
	DecisionReason          string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

// IsValidChangeSetState reports whether s is one of the ChangeSetState constants.
func IsValidChangeSetState(s string) bool {
	switch ChangeSetState(s) {
	case ChangeSetStateDraft,
		ChangeSetStateSubmitted,
		ChangeSetStateApproved,
		ChangeSetStateRejected,
		ChangeSetStateConflicted:
		return true
	}
	return false
}

// NewChangeSet constructs and validates a ChangeSet in Draft state.
func NewChangeSet(productID ID, parentVersion *ID, title, description string, requestedBy Actor) (*ChangeSet, error) {
	now := time.Now().UTC()
	cs := &ChangeSet{
		ID:                      NewID(),
		ProductID:               productID,
		State:                   ChangeSetStateDraft,
		ParentApprovedVersionID: parentVersion,
		Title:                   title,
		Description:             description,
		RequestedBy:             requestedBy,
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	if err := cs.Validate(); err != nil {
		return nil, err
	}
	return cs, nil
}

// Validate enforces ChangeSet invariants.
func (cs *ChangeSet) Validate() error {
	if cs.ProductID == "" {
		return ErrChangeSetProductIDRequired
	}
	if cs.Title == "" {
		return ErrChangeSetTitleRequired
	}
	if len(cs.Title) > changeSetTitleMaxLen {
		return ErrChangeSetTitleTooLong
	}
	if len(cs.Description) > changeSetDescriptionMaxLen {
		return ErrChangeSetDescriptionTooLong
	}
	if err := cs.RequestedBy.Validate(); err != nil {
		return err
	}
	if !IsValidChangeSetState(string(cs.State)) {
		return fmt.Errorf("%w: %q", ErrChangeSetStateInvalid, string(cs.State))
	}
	if len(cs.DecisionReason) > changeSetReasonMaxLen {
		return ErrChangeSetReasonTooLong
	}
	return nil
}

// CanTransitionTo reports whether moving from s to target is a legal state-machine edge.
// Legal edges: Draft->Submitted, Draft->Rejected (cancel), Submitted->Approved,
// Submitted->Rejected, Approved->Conflicted. Anything else is invalid.
func (s ChangeSetState) CanTransitionTo(target ChangeSetState) bool {
	switch s {
	case ChangeSetStateDraft:
		return target == ChangeSetStateSubmitted || target == ChangeSetStateRejected
	case ChangeSetStateSubmitted:
		return target == ChangeSetStateApproved || target == ChangeSetStateRejected
	case ChangeSetStateApproved:
		return target == ChangeSetStateConflicted
	}
	return false
}

// Transition advances the ChangeSet to target if the edge is legal, recording
// the decision reason and timestamp. Submitted sets SubmittedAt; terminal
// transitions set DecidedAt.
func (cs *ChangeSet) Transition(target ChangeSetState, reason string, at time.Time) error {
	if !IsValidChangeSetState(string(target)) {
		return fmt.Errorf("%w: %q", ErrChangeSetStateInvalid, string(target))
	}
	if !cs.State.CanTransitionTo(target) {
		return fmt.Errorf("%w: %s -> %s", ErrChangeSetInvalidTransition, cs.State, target)
	}
	if len(reason) > changeSetReasonMaxLen {
		return ErrChangeSetReasonTooLong
	}
	at = at.UTC()
	cs.State = target
	cs.UpdatedAt = at
	if reason != "" {
		cs.DecisionReason = reason
	}
	switch target {
	case ChangeSetStateSubmitted:
		t := at
		cs.SubmittedAt = &t
	case ChangeSetStateApproved, ChangeSetStateRejected, ChangeSetStateConflicted:
		t := at
		cs.DecidedAt = &t
	}
	return nil
}
