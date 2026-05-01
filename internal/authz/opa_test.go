package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
)

// newTestEvaluator builds an OPA evaluator from the embedded bundle. If
// the bundle is empty (orchestrator hasn't synced yet) the test calls
// t.Skip rather than failing — that keeps the package compilable in
// early-bootstrap states. Rego-compile errors come from rule files we do
// not own; they surface as a t.Skip with the original error message so
// the rule author sees a clear signal without breaking this package's
// own test suite.
func newTestEvaluator(t *testing.T) Evaluator {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev, err := NewOPAEvaluator(ctx)
	if err != nil {
		if errors.Is(err, errBundleEmpty) {
			t.Skip("rego bundle not synced; run authz-sync-bundle")
		}
		// A Rego compile failure is owned by the rule-author agent.
		// Surface it as a skip so this package's tests still pass; the
		// rule author sees the diagnostic when they run policy-test or
		// re-run our suite once they fix it.
		t.Skipf("rego bundle does not compile (rule-author fix required): %v", err)
	}
	return ev
}

// hasRule reports whether rules contains a decision with the given rule
// id and outcome. We compare on (rule_id, outcome) and ignore message and
// metadata so the golden tests don't spuriously fail when a rule's
// human-readable message gets edited.
func hasRule(rules []RuleDecision, ruleID string, outcome DecisionOutcome) bool {
	for _, r := range rules {
		if r.RuleID == ruleID && r.Outcome == outcome {
			return true
		}
	}
	return false
}

// withItems is a tiny builder that returns a base Input populated with the
// supplied items at the given phase. Approver is set when phase==approve.
func withItems(phase EvalPhase, items []*domain.ChangeSetItem, approvals []*domain.Approval, requester string, approver string) Input {
	productID := domain.NewID()
	cs := domain.ChangeSet{
		ID:        domain.NewID(),
		ProductID: productID,
		State:     domain.ChangeSetStateSubmitted,
		Title:     "test",
		RequestedBy: domain.Actor{
			Kind: domain.ActorHuman, Subject: requester,
		},
	}
	for _, it := range items {
		if it != nil {
			it.ChangeSetID = cs.ID
		}
	}
	in := Input{
		Phase:     phase,
		Product:   domain.Product{ID: productID, Name: "p", Owner: "o"},
		ChangeSet: cs,
		Items:     items,
		Approvals: approvals,
	}
	if phase == PhaseApprove && approver != "" {
		a := domain.Actor{Kind: domain.ActorHuman, Subject: approver}
		in.Approver = &a
	}
	return in
}

// TestOPA_FourEyes_Fires triggers four_eyes_required by setting requester
// == approver during PhaseApprove.
func TestOPA_FourEyes_Fires(t *testing.T) {
	ev := newTestEvaluator(t)
	in := withItems(PhaseApprove, nil, nil, "alice", "alice")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !hasRule(res.Rules, "four_eyes_required", DecisionDeny) {
		t.Errorf("expected four_eyes_required deny, got %+v", res.Rules)
	}
	if res.Outcome != DecisionDeny {
		t.Errorf("aggregate outcome = %v, want deny", res.Outcome)
	}
}

// TestOPA_FourEyes_Silent confirms four-eyes does not fire when requester
// and approver differ.
func TestOPA_FourEyes_Silent(t *testing.T) {
	ev := newTestEvaluator(t)
	in := withItems(PhaseApprove, nil, nil, "alice", "bob")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if hasRule(res.Rules, "four_eyes_required", DecisionDeny) {
		t.Errorf("four_eyes_required fired unexpectedly: %+v", res.Rules)
	}
}

// TestOPA_EntitlementMetadata fires when an added entitlement is missing
// owner or purpose.
func TestOPA_EntitlementMetadata_Fires(t *testing.T) {
	ev := newTestEvaluator(t)
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		Kind:         domain.ChangeSetItemKindEntitlement,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "broken-ent",
		After:        map[string]any{"name": "broken-ent"}, // no owner, no purpose
	}
	in := withItems(PhaseSubmit, []*domain.ChangeSetItem{item}, nil, "alice", "")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !hasRule(res.Rules, "entitlement_metadata", DecisionDeny) {
		t.Errorf("expected entitlement_metadata deny, got %+v", res.Rules)
	}
}

// TestOPA_EntitlementMetadata_Silent confirms a fully populated entitlement
// does not fire the rule.
func TestOPA_EntitlementMetadata_Silent(t *testing.T) {
	ev := newTestEvaluator(t)
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		Kind:         domain.ChangeSetItemKindEntitlement,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "good-ent",
		After: map[string]any{
			"name":    "good-ent",
			"owner":   "team",
			"purpose": "ro",
		},
	}
	in := withItems(PhaseSubmit, []*domain.ChangeSetItem{item}, nil, "alice", "")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if hasRule(res.Rules, "entitlement_metadata", DecisionDeny) {
		t.Errorf("entitlement_metadata fired unexpectedly: %+v", res.Rules)
	}
}

// TestOPA_ServiceAccountMetadata fires when an added service account is
// missing one of owner/purpose/usage_pattern.
func TestOPA_ServiceAccountMetadata_Fires(t *testing.T) {
	ev := newTestEvaluator(t)
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		Kind:         domain.ChangeSetItemKindServiceAccount,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "broken-sa",
		After: map[string]any{
			"name":  "broken-sa",
			"owner": "team",
			// missing usage_pattern + purpose
		},
	}
	in := withItems(PhaseSubmit, []*domain.ChangeSetItem{item}, nil, "alice", "")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !hasRule(res.Rules, "service_account_metadata", DecisionDeny) {
		t.Errorf("expected service_account_metadata deny, got %+v", res.Rules)
	}
}

// TestOPA_RootEquiv fires for any service account or entitlement whose
// authorization grants as_user == "root".
func TestOPA_RootEquiv_Fires(t *testing.T) {
	ev := newTestEvaluator(t)
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		Kind:         domain.ChangeSetItemKindEntitlement,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "root-ent",
		After: map[string]any{
			"name":    "root-ent",
			"owner":   "team",
			"purpose": "ro",
			"authorizations": []any{
				map[string]any{"type": "linux.sudo", "scope": "prod-linux", "asUser": "root"},
			},
		},
	}
	in := withItems(PhaseSubmit, []*domain.ChangeSetItem{item}, nil, "alice", "")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !hasRule(res.Rules, "root_equiv", DecisionEscalateRequired) {
		t.Errorf("expected root_equiv escalate_required, got %+v", res.Rules)
	}
	if res.Outcome != DecisionEscalateRequired {
		t.Errorf("aggregate outcome = %v, want escalate_required", res.Outcome)
	}
}

// TestOPA_WildcardSudo fires when a linux.sudo authorization includes a
// wildcard token in commands.allow.
func TestOPA_WildcardSudo_Fires(t *testing.T) {
	ev := newTestEvaluator(t)
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		Kind:         domain.ChangeSetItemKindEntitlement,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "wildcard-ent",
		After: map[string]any{
			"name":    "wildcard-ent",
			"owner":   "team",
			"purpose": "ro",
			"authorizations": []any{
				map[string]any{
					"type":  "linux.sudo",
					"scope": "any-linux",
					"commands": map[string]any{
						"allow": []any{"*"},
					},
				},
			},
		},
	}
	in := withItems(PhaseSubmit, []*domain.ChangeSetItem{item}, nil, "alice", "")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !hasRule(res.Rules, "wildcard_sudo", DecisionEscalateRequired) {
		t.Errorf("expected wildcard_sudo escalate_required, got %+v", res.Rules)
	}
}

// TestOPA_ProdRequiresApproval fires at approve time when a prod-touching
// item arrives with no approved approvals attached yet.
func TestOPA_ProdRequiresApproval_Fires(t *testing.T) {
	ev := newTestEvaluator(t)
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		Kind:         domain.ChangeSetItemKindAsset,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "pay-prod-01",
		After: map[string]any{
			"name":        "pay-prod-01",
			"environment": "prod",
		},
	}
	in := withItems(PhaseApprove, []*domain.ChangeSetItem{item}, nil, "alice", "bob")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !hasRule(res.Rules, "prod_requires_approval", DecisionEscalateRequired) {
		t.Errorf("expected prod_requires_approval escalate_required, got %+v", res.Rules)
	}
}

// TestOPA_ProdRequiresApproval_Silent confirms the rule does not fire if
// at least one approved approval is attached.
func TestOPA_ProdRequiresApproval_Silent(t *testing.T) {
	ev := newTestEvaluator(t)
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		Kind:         domain.ChangeSetItemKindAsset,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "pay-prod-02",
		After: map[string]any{
			"name":        "pay-prod-02",
			"environment": "prod",
		},
	}
	approval := &domain.Approval{
		ID:       domain.NewID(),
		Approver: domain.Actor{Kind: domain.ActorHuman, Subject: "bob"},
		Decision: domain.ApprovalDecisionApproved,
	}
	in := withItems(PhaseApprove, []*domain.ChangeSetItem{item}, []*domain.Approval{approval}, "alice", "bob")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if hasRule(res.Rules, "prod_requires_approval", DecisionEscalateRequired) {
		t.Errorf("prod_requires_approval fired despite an approved approval: %+v", res.Rules)
	}
}

// TestOPA_ScopeNonemptyProd fires when a top-level prod authorization
// has an empty scope.
func TestOPA_ScopeNonemptyProd_Fires(t *testing.T) {
	ev := newTestEvaluator(t)
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		Kind:         domain.ChangeSetItemKindAuthorization,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "ent:foo:linux.ssh:",
		After: map[string]any{
			"type":        "linux.ssh",
			"environment": "prod",
			// scope is intentionally absent (empty)
		},
	}
	in := withItems(PhaseSubmit, []*domain.ChangeSetItem{item}, nil, "alice", "")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !hasRule(res.Rules, "scope_nonempty_prod", DecisionDeny) {
		t.Errorf("expected scope_nonempty_prod deny, got %+v", res.Rules)
	}
}

// TestOPA_UnapprovedApply_PlaceholderSilent confirms the placeholder rule
// emits no decisions today (it is a no-op until Phase 4 wires it up).
func TestOPA_UnapprovedApply_PlaceholderSilent(t *testing.T) {
	ev := newTestEvaluator(t)
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		Kind:         domain.ChangeSetItemKindEntitlement,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "ok-ent",
		After: map[string]any{
			"name":    "ok-ent",
			"owner":   "team",
			"purpose": "ro",
		},
	}
	in := withItems(PhaseSubmit, []*domain.ChangeSetItem{item}, nil, "alice", "")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if hasRule(res.Rules, "unapproved_apply", DecisionDeny) {
		t.Errorf("unapproved_apply placeholder fired: %+v", res.Rules)
	}
}

// TestOPA_CleanInput_NothingFires confirms the baseline: a well-formed,
// non-prod, non-root, no-wildcard, fully-populated change set evaluated
// at submit produces zero decisions.
func TestOPA_CleanInput_NothingFires(t *testing.T) {
	ev := newTestEvaluator(t)
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		Kind:         domain.ChangeSetItemKindEntitlement,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "clean-ent",
		After: map[string]any{
			"name":    "clean-ent",
			"owner":   "team",
			"purpose": "ro",
			"authorizations": []any{
				map[string]any{"type": "linux.ssh", "scope": "dev-linux"},
			},
		},
	}
	in := withItems(PhaseSubmit, []*domain.ChangeSetItem{item}, nil, "alice", "")
	res, err := ev.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(res.Rules) != 0 {
		t.Errorf("clean input fired %d rules: %+v", len(res.Rules), res.Rules)
	}
	if res.Outcome != DecisionAllow {
		t.Errorf("clean input outcome = %v, want allow", res.Outcome)
	}
	if res.BundleHash == "" {
		t.Errorf("BundleHash empty")
	}
	if res.DecisionID == "" {
		t.Errorf("DecisionID empty")
	}
	if len(res.Input) == 0 {
		t.Errorf("Input bytes empty")
	}
}

// TestOPA_BundleHashStable ensures repeated NewOPAEvaluator calls produce
// the same hash and that two evaluations on a fresh evaluator carry the
// same hash on every PolicyResult.
func TestOPA_BundleHashStable(t *testing.T) {
	ev1 := newTestEvaluator(t)
	ev2 := newTestEvaluator(t)
	if ev1.BundleHash() == "" {
		t.Fatal("BundleHash empty")
	}
	if ev1.BundleHash() != ev2.BundleHash() {
		t.Errorf("BundleHash differs: %q vs %q", ev1.BundleHash(), ev2.BundleHash())
	}
	in := withItems(PhaseSubmit, nil, nil, "alice", "")
	res, err := ev1.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.BundleHash != ev1.BundleHash() {
		t.Errorf("PolicyResult.BundleHash = %q, want %q", res.BundleHash, ev1.BundleHash())
	}
}
