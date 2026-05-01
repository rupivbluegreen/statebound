package cli

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/codes"

	"statebound.dev/statebound/internal/authz"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
	"statebound.dev/statebound/internal/telemetry"
)

// evaluatorOnce caches the prepared OPA evaluator across all CLI invocations
// in this process. PrepareForEval is non-trivial (it parses every Rego file
// and ASTs the bundle); we pay it once.
var (
	evaluatorOnce sync.Once
	evaluatorVal  authz.Evaluator
	evaluatorErr  error
)

func defaultEvaluator(ctx context.Context) (authz.Evaluator, error) {
	evaluatorOnce.Do(func() {
		evaluatorVal, evaluatorErr = authz.NewOPAEvaluator(ctx)
	})
	return evaluatorVal, evaluatorErr
}

// evaluatePolicyGate is the indirection point used by submit/approve flows.
// Tests that exercise the surrounding state machine (four-eyes etc.) without
// caring about Rego results can swap this for a stub that returns Allow.
var evaluatePolicyGate = evaluateAndRecord

// evaluateAndRecord runs the OPA gate for a ChangeSet, persists the result,
// and fans the decision out to the audit log via authz.Record. The result
// is returned so the caller can decide whether to abort (Deny) or proceed.
//
// store may be a transaction or the top-level pool — Record uses the same
// interface either way, so wrapping in WithTx makes the gate atomic with
// the surrounding state transition.
//
// Wave A telemetry: every gate evaluation runs inside a "policy.evaluate"
// span tagged with phase + change_set_id; outcome is recorded once
// evaluation succeeds. Errors set span status to Error.
func evaluateAndRecord(
	ctx context.Context,
	store storage.Storage,
	phase authz.EvalPhase,
	cs *domain.ChangeSet,
	actor domain.Actor,
) (*authz.PolicyResult, error) {
	ctx, span := telemetry.StartSpan(ctx, "policy.evaluate",
		telemetry.AttrPolicyPhase.String(string(phase)),
		telemetry.AttrChangeSetID.String(string(cs.ID)),
	)
	defer span.End()
	recordErr := func(err error) error {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	product, err := store.GetProductByID(ctx, cs.ProductID)
	if err != nil {
		return nil, recordErr(fmt.Errorf("policy gate: get product: %w", err))
	}
	items, err := store.ListChangeSetItems(ctx, cs.ID)
	if err != nil {
		return nil, recordErr(fmt.Errorf("policy gate: list items: %w", err))
	}
	approvals, err := store.ListApprovalsByChangeSet(ctx, cs.ID)
	if err != nil {
		return nil, recordErr(fmt.Errorf("policy gate: list approvals: %w", err))
	}

	in := authz.Input{
		Phase:     phase,
		Product:   *product,
		ChangeSet: *cs,
		Items:     items,
		Approvals: approvals,
	}
	if phase == authz.PhaseApprove {
		a := actor
		in.Approver = &a
	}

	eval, err := defaultEvaluator(ctx)
	if err != nil {
		return nil, recordErr(fmt.Errorf("policy gate: load evaluator: %w", err))
	}
	result, err := eval.Evaluate(ctx, in)
	if err != nil {
		return nil, recordErr(fmt.Errorf("policy gate: evaluate: %w", err))
	}
	result.ChangeSetID = cs.ID
	span.SetAttributes(telemetry.AttrPolicyOutcome.String(string(result.Outcome)))

	if err := authz.Record(ctx, store, actor, result); err != nil {
		return nil, recordErr(fmt.Errorf("policy gate: record decision: %w", err))
	}
	return result, nil
}

// enforcePolicy converts a PolicyResult into a CLI-shaped error when the
// outcome is Deny. EscalateRequired is allowed to proceed for Phase 2 wave
// B — the decision row is still persisted, so future phases can wire the
// elevated-approval flow without changing this gate.
func enforcePolicy(result *authz.PolicyResult) error {
	if result.Outcome != authz.DecisionDeny {
		return nil
	}
	var ids []string
	for _, r := range result.Rules {
		if r.Outcome == authz.DecisionDeny {
			ids = append(ids, r.RuleID)
		}
	}
	return fmt.Errorf("policy denied: %s", strings.Join(ids, ", "))
}
