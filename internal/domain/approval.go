package domain

import (
	"errors"
	"fmt"
	"time"
)

// ApprovalDecision enumerates the outcomes a reviewer can record on a ChangeSet.
type ApprovalDecision string

const (
	ApprovalDecisionApproved ApprovalDecision = "approved"
	ApprovalDecisionRejected ApprovalDecision = "rejected"
)

const approvalReasonMaxLen = 4096

// Sentinel errors for Approval validation.
var (
	ErrApprovalChangeSetIDRequired = errors.New("domain: approval change set id is required")
	ErrApprovalDecisionInvalid     = errors.New("domain: approval decision is invalid")
	ErrApprovalReasonRequired      = errors.New("domain: approval reason is required when rejecting")
	ErrApprovalReasonTooLong       = errors.New("domain: approval reason exceeds 4096 characters")
)

// Approval is the four-eyes / policy-based decision attached to a ChangeSet.
type Approval struct {
	ID          ID
	ChangeSetID ID
	Approver    Actor
	Decision    ApprovalDecision
	Reason      string
	DecidedAt   time.Time
}

// IsValidApprovalDecision reports whether s is one of the ApprovalDecision constants.
func IsValidApprovalDecision(s string) bool {
	switch ApprovalDecision(s) {
	case ApprovalDecisionApproved, ApprovalDecisionRejected:
		return true
	}
	return false
}

// NewApproval constructs and validates an Approval, stamping a fresh ID and
// timestamp.
func NewApproval(csID ID, approver Actor, decision ApprovalDecision, reason string) (*Approval, error) {
	a := &Approval{
		ID:          NewID(),
		ChangeSetID: csID,
		Approver:    approver,
		Decision:    decision,
		Reason:      reason,
		DecidedAt:   time.Now().UTC(),
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return a, nil
}

// Validate enforces Approval invariants.
func (a *Approval) Validate() error {
	if a.ChangeSetID == "" {
		return ErrApprovalChangeSetIDRequired
	}
	if err := a.Approver.Validate(); err != nil {
		return err
	}
	if !IsValidApprovalDecision(string(a.Decision)) {
		return fmt.Errorf("%w: %q", ErrApprovalDecisionInvalid, string(a.Decision))
	}
	if len(a.Reason) > approvalReasonMaxLen {
		return ErrApprovalReasonTooLong
	}
	if a.Decision == ApprovalDecisionRejected && a.Reason == "" {
		return ErrApprovalReasonRequired
	}
	return nil
}
