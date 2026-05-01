package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// PlanApplyState enumerates the lifecycle of a single apply execution.
//
// A PlanApplyRecord starts in Running when AppendPlanApplyRecord is
// called and lands in exactly one terminal state (Succeeded | Failed)
// via Transition. Dry-run executions follow the same lifecycle but do
// not affect the parent plan's PlanState (Phase 6 contract: a dry-run
// never moves a plan to Applied/Failed).
//
// Keep the values in sync with the SQL CHECK constraint on
// plan_apply_records.state in migrations/0008_plan_apply.sql.
type PlanApplyState string

const (
	// PlanApplyStateRunning is the initial state when an apply begins.
	PlanApplyStateRunning PlanApplyState = "running"
	// PlanApplyStateSucceeded is the terminal success state. Every item
	// completed (or was skipped) without raising an error.
	PlanApplyStateSucceeded PlanApplyState = "succeeded"
	// PlanApplyStateFailed is the terminal failure state. At least one
	// item raised an error or the connector aborted the run; the
	// FailureMessage carries the human-readable cause.
	PlanApplyStateFailed PlanApplyState = "failed"
)

// Sentinel errors for PlanApplyRecord validation and state machine.
var (
	ErrPlanApplyRecordNotFound    = errors.New("domain: plan apply record not found")
	ErrPlanApplyInvalid           = errors.New("domain: plan apply record invalid")
	ErrPlanApplyInvalidTransition = errors.New("domain: plan apply state transition is not allowed")

	ErrPlanApplyPlanIDRequired       = errors.New("domain: plan apply record plan id is required")
	ErrPlanApplyTargetRequired       = errors.New("domain: plan apply record target is required")
	ErrPlanApplyAppliedItemsNegative = errors.New("domain: plan apply record applied items must be >= 0")
	ErrPlanApplyFailedItemsNegative  = errors.New("domain: plan apply record failed items must be >= 0")
	ErrPlanApplyStateInvalid         = errors.New("domain: plan apply state is invalid")
)

// PlanApplyRecord is one execution attempt of a Plan against a target
// system. Records are append-only after the terminal transition: callers
// AppendPlanApplyRecord in Running, then UpdatePlanApplyRecord exactly
// once with the terminal Succeeded/Failed snapshot.
//
// DryRun = true means this record describes a what-if execution: the
// connector did not mutate the target system and the parent Plan is
// not transitioned to Applied/Failed. The record itself still lands in
// a terminal state so an auditor can replay the intended changes.
//
// SummaryHash is the SHA-256 hex of the canonical JSON of Output.Items.
// Two re-runs of the same plan against the same target with byte-equal
// per-item results MUST produce the same SummaryHash so an evidence
// pack can prove the apply content has not been retouched.
type PlanApplyRecord struct {
	ID             ID
	PlanID         ID
	State          PlanApplyState
	StartedAt      time.Time
	FinishedAt     *time.Time
	Actor          Actor
	Target         string // free-form connector-specific (e.g. "postgres://host/payments")
	DryRun         bool
	AppliedItems   int
	FailedItems    int
	FailureMessage string
	SummaryHash    string
	Output         json.RawMessage // canonical per-item results
}

// IsValidPlanApplyState reports whether s is one of the PlanApplyState
// constants.
func IsValidPlanApplyState(s string) bool {
	switch PlanApplyState(s) {
	case PlanApplyStateRunning,
		PlanApplyStateSucceeded,
		PlanApplyStateFailed:
		return true
	}
	return false
}

// NewPlanApplyRecord constructs a PlanApplyRecord in Running state with
// a freshly minted id and StartedAt = UTC now. The caller passes the
// initiating Actor (the human or service account that triggered the
// apply) and the connector-specific Target string.
//
// The record begins with empty AppliedItems / FailedItems / Output /
// SummaryHash; those land via Transition once the connector returns.
func NewPlanApplyRecord(planID ID, actor Actor, target string, dryRun bool) (*PlanApplyRecord, error) {
	if planID == "" {
		return nil, ErrPlanApplyPlanIDRequired
	}
	if target == "" {
		return nil, ErrPlanApplyTargetRequired
	}
	if err := actor.Validate(); err != nil {
		return nil, err
	}
	return &PlanApplyRecord{
		ID:        NewID(),
		PlanID:    planID,
		State:     PlanApplyStateRunning,
		StartedAt: time.Now().UTC(),
		Actor:     actor,
		Target:    target,
		DryRun:    dryRun,
		Output:    json.RawMessage("{}"),
	}, nil
}

// CanTransitionTo reports whether moving from the receiver's state to
// target is a legal state-machine edge.
//
// Legal edges:
//   - Running -> Succeeded
//   - Running -> Failed
//
// Succeeded and Failed are terminal: any further transition is rejected.
func (r *PlanApplyRecord) CanTransitionTo(target PlanApplyState) bool {
	if r == nil {
		return false
	}
	if r.State != PlanApplyStateRunning {
		return false
	}
	return target == PlanApplyStateSucceeded || target == PlanApplyStateFailed
}

// Transition advances the record to target, populating finishedAt and
// the per-item summary fields. Callers pass:
//   - target: PlanApplyStateSucceeded or PlanApplyStateFailed
//   - finishedAt: when the apply ended (UTC)
//   - summaryHash: SHA-256 hex of canonical(output)
//   - output: canonical JSON-serialisable per-item results
//   - applied: count of items that succeeded or were skipped without error
//   - failed: count of items that raised an error
//   - failureMessage: human-readable cause; required when target == Failed
//
// Returns ErrPlanApplyInvalidTransition if the edge is not legal,
// ErrPlanApplyStateInvalid if target is not a known state.
func (r *PlanApplyRecord) Transition(
	target PlanApplyState,
	finishedAt time.Time,
	summaryHash string,
	output json.RawMessage,
	applied, failed int,
	failureMessage string,
) error {
	if r == nil {
		return ErrPlanApplyInvalid
	}
	if !IsValidPlanApplyState(string(target)) {
		return fmt.Errorf("%w: %q", ErrPlanApplyStateInvalid, string(target))
	}
	if !r.CanTransitionTo(target) {
		return fmt.Errorf("%w: %s -> %s", ErrPlanApplyInvalidTransition, r.State, target)
	}
	if applied < 0 {
		return ErrPlanApplyAppliedItemsNegative
	}
	if failed < 0 {
		return ErrPlanApplyFailedItemsNegative
	}
	r.State = target
	finished := finishedAt.UTC()
	r.FinishedAt = &finished
	r.SummaryHash = summaryHash
	if len(output) > 0 {
		buf := make([]byte, len(output))
		copy(buf, output)
		r.Output = buf
	}
	r.AppliedItems = applied
	r.FailedItems = failed
	r.FailureMessage = failureMessage
	return nil
}
