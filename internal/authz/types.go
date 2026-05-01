// Package authz wraps Open Policy Agent (OPA) so the rest of Statebound can
// evaluate the built-in Rego rule library, persist the resulting decisions,
// and fan them out into the audit log without ever importing OPA itself.
//
// Phase 2 wave B owns this package. The rule files are authored in
// policies/builtin/*.rego and synced into internal/authz/bundle/ at build
// time so they can be embed.FS-ed (Go forbids parent-relative embed paths).
//
// Spec reference: CLAUDE.md §13 (audit log rules) and §15 (policy rules).
package authz

import (
	"context"
	"encoding/json"
	"time"

	"statebound.dev/statebound/internal/domain"
)

// DecisionOutcome enumerates the verdicts a single rule (or the aggregate
// PolicyResult) can produce. Values match both the Rego schema and the
// CHECK constraint on the policy_decisions.outcome column (migration 0004).
type DecisionOutcome string

const (
	// DecisionAllow means the rule did not object. Rules that emit "allow"
	// are uncommon in the built-in library; absence of a fired rule already
	// implies allow at the aggregate level.
	DecisionAllow DecisionOutcome = "allow"
	// DecisionDeny means the rule refuses the action outright. Any deny
	// short-circuits the aggregate to deny.
	DecisionDeny DecisionOutcome = "deny"
	// DecisionEscalateRequired means the rule permits the action only with
	// elevated approval. Escalations bubble up to the aggregate unless a
	// deny supersedes them.
	DecisionEscalateRequired DecisionOutcome = "escalate_required"
)

// Severity tags how loud a rule decision should be. The audit pipeline and
// the TUI use this to decide colour, sort order, and whether to surface a
// banner.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// EvalPhase is the lifecycle gate that triggered an evaluation. The Rego
// rules read input.phase to decide which checks apply (some rules only run
// at submit, some only at approve, most run at both).
type EvalPhase string

const (
	PhaseSubmit  EvalPhase = "submit"
	PhaseApprove EvalPhase = "approve"
)

// RuleDecision is exactly one rule firing inside a PolicyResult. JSON tags
// match the shape Rego emits via the aggregator package
// data.statebound.aggregate.decisions; do not rename them without also
// updating every rule file in policies/builtin/.
type RuleDecision struct {
	RuleID   string          `json:"rule_id"`
	Outcome  DecisionOutcome `json:"outcome"`
	Message  string          `json:"message"`
	Severity Severity        `json:"severity"`
	Metadata map[string]any  `json:"metadata,omitempty"`
}

// PolicyResult is the aggregate output of a single Evaluate call. Rules is
// sorted deterministically (deny before escalate before allow, then RuleID,
// then Message) so the canonical JSON of PolicyResult is stable across runs
// — this matters because the audit event payload feeds the hash chain.
type PolicyResult struct {
	DecisionID  domain.ID       `json:"decision_id"`
	ChangeSetID domain.ID       `json:"change_set_id"`
	Phase       EvalPhase       `json:"phase"`
	Outcome     DecisionOutcome `json:"outcome"`
	Rules       []RuleDecision  `json:"rules"`
	Input       json.RawMessage `json:"input"`
	BundleHash  string          `json:"bundle_hash"`
	EvaluatedAt time.Time       `json:"evaluated_at"`
}

// Input is what callers assemble before invoking Evaluate. Approver is nil
// during PhaseSubmit; BeforeModel/AfterModel are optional model snapshots
// that some rules may consult once the rule library grows beyond the
// initial eight (Phase 2 rules look only at items + approvals).
type Input struct {
	Phase       EvalPhase
	Product     domain.Product
	ChangeSet   domain.ChangeSet
	Items       []*domain.ChangeSetItem
	Approvals   []*domain.Approval
	Approver    *domain.Actor
	BeforeModel map[string]any
	AfterModel  map[string]any
}

// Evaluator runs the embedded Rego bundle against an Input. Implementations
// must be safe for concurrent use; the standard implementation is
// opaEvaluator, returned by NewOPAEvaluator.
type Evaluator interface {
	Evaluate(ctx context.Context, in Input) (*PolicyResult, error)
	BundleHash() string
}

// outcomeRank orders outcomes for deterministic Rules sorting: lower rank
// surfaces first. Deny is highest priority (lowest rank), then escalate,
// then allow, then anything unknown.
func outcomeRank(o DecisionOutcome) int {
	switch o {
	case DecisionDeny:
		return 0
	case DecisionEscalateRequired:
		return 1
	case DecisionAllow:
		return 2
	}
	return 3
}

// aggregateOutcome derives the PolicyResult.Outcome from its Rules slice.
// Empty rules (nothing fired) collapses to allow.
func aggregateOutcome(rules []RuleDecision) DecisionOutcome {
	worst := DecisionAllow
	worstRank := outcomeRank(DecisionAllow)
	for _, r := range rules {
		rank := outcomeRank(r.Outcome)
		if rank < worstRank {
			worst = r.Outcome
			worstRank = rank
		}
	}
	return worst
}
