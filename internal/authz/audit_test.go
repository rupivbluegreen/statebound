package authz

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// fakePolicyStore is a tiny in-memory satisfier of PolicyResultRecorder.
// It records every call so the test can assert on what Record did.
type fakePolicyStore struct {
	decisions []*storage.PolicyDecisionRecord
	events    []*domain.AuditEvent
	failOn    string // "decision" | "event" | ""
}

func (f *fakePolicyStore) AppendPolicyDecision(_ context.Context, rec *storage.PolicyDecisionRecord) error {
	if f.failOn == "decision" {
		return errors.New("decision write failed")
	}
	f.decisions = append(f.decisions, rec)
	return nil
}

func (f *fakePolicyStore) ListPolicyDecisionsByChangeSet(_ context.Context, csID domain.ID) ([]*storage.PolicyDecisionRecord, error) {
	var out []*storage.PolicyDecisionRecord
	for _, r := range f.decisions {
		if r.ChangeSetID == csID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakePolicyStore) GetPolicyDecisionByID(_ context.Context, id domain.ID) (*storage.PolicyDecisionRecord, error) {
	for _, r := range f.decisions {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (f *fakePolicyStore) AppendAuditEvent(_ context.Context, e *domain.AuditEvent) error {
	if f.failOn == "event" {
		return errors.New("event write failed")
	}
	f.events = append(f.events, e)
	return nil
}

func (f *fakePolicyStore) ListAuditEvents(_ context.Context, _ storage.AuditFilter) ([]*domain.AuditEvent, error) {
	return f.events, nil
}

// sampleResult builds a PolicyResult whose shape exercises all of the
// fields Record reads. We do not run the OPA evaluator here so this test
// stays cheap and offline.
func sampleResult(t *testing.T) *PolicyResult {
	t.Helper()
	return &PolicyResult{
		DecisionID:  domain.NewID(),
		ChangeSetID: domain.NewID(),
		Phase:       PhaseApprove,
		Outcome:     DecisionDeny,
		Rules: []RuleDecision{
			{
				RuleID:   "four_eyes_required",
				Outcome:  DecisionDeny,
				Message:  "requester cannot approve their own change set",
				Severity: SeverityHigh,
				Metadata: map[string]any{"requested_by": "alice", "approver": "alice"},
			},
		},
		Input:       json.RawMessage(`{"phase":"approve"}`),
		BundleHash:  "abc123",
		EvaluatedAt: time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC),
	}
}

func TestRecord_WritesDecisionAndAuditEvent(t *testing.T) {
	store := &fakePolicyStore{}
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "bob"}
	res := sampleResult(t)

	if err := Record(context.Background(), store, actor, res); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if got := len(store.decisions); got != 1 {
		t.Fatalf("decisions written = %d, want 1", got)
	}
	rec := store.decisions[0]
	if rec.ID != res.DecisionID {
		t.Errorf("decision id = %q, want %q", rec.ID, res.DecisionID)
	}
	if rec.ChangeSetID != res.ChangeSetID {
		t.Errorf("decision change_set_id = %q, want %q", rec.ChangeSetID, res.ChangeSetID)
	}
	if rec.Phase != string(res.Phase) {
		t.Errorf("decision phase = %q, want %q", rec.Phase, res.Phase)
	}
	if rec.Outcome != string(res.Outcome) {
		t.Errorf("decision outcome = %q, want %q", rec.Outcome, res.Outcome)
	}
	if rec.BundleHash != res.BundleHash {
		t.Errorf("decision bundle_hash = %q, want %q", rec.BundleHash, res.BundleHash)
	}
	if !rec.EvaluatedAt.Equal(res.EvaluatedAt) {
		t.Errorf("decision evaluated_at = %v, want %v", rec.EvaluatedAt, res.EvaluatedAt)
	}
	// Rules must round-trip as JSON containing the rule_id we inserted.
	if !contains(string(rec.Rules), "four_eyes_required") {
		t.Errorf("decision rules JSON missing rule_id: %s", rec.Rules)
	}

	if got := len(store.events); got != 1 {
		t.Fatalf("audit events written = %d, want 1", got)
	}
	ev := store.events[0]
	if ev.Kind != domain.EventPolicyEvaluated {
		t.Errorf("audit event kind = %q, want %q", ev.Kind, domain.EventPolicyEvaluated)
	}
	if ev.ResourceType != "change_set" {
		t.Errorf("audit event resource type = %q, want change_set", ev.ResourceType)
	}
	if ev.ResourceID != string(res.ChangeSetID) {
		t.Errorf("audit event resource id = %q, want %q", ev.ResourceID, res.ChangeSetID)
	}
	if ev.Actor.Subject != "bob" {
		t.Errorf("audit event actor = %+v, want subject=bob", ev.Actor)
	}
	if got := ev.Payload["decision_id"]; got != string(res.DecisionID) {
		t.Errorf("payload decision_id = %v, want %v", got, res.DecisionID)
	}
	if got := ev.Payload["bundle_hash"]; got != res.BundleHash {
		t.Errorf("payload bundle_hash = %v, want %v", got, res.BundleHash)
	}
	if got := ev.Payload["rules_count"]; got != 1 {
		t.Errorf("payload rules_count = %v, want 1", got)
	}
	rules, ok := ev.Payload["rules"].([]map[string]any)
	if !ok {
		t.Fatalf("payload rules has type %T, want []map[string]any", ev.Payload["rules"])
	}
	if len(rules) != 1 {
		t.Fatalf("payload rules len = %d, want 1", len(rules))
	}
	if got := rules[0]["rule_id"]; got != "four_eyes_required" {
		t.Errorf("payload rules[0].rule_id = %v, want four_eyes_required", got)
	}
	// The compact audit payload should not carry the per-rule message.
	if _, ok := rules[0]["message"]; ok {
		t.Errorf("payload rules[0] should not carry message, got %v", rules[0])
	}
}

// TestRecord_NilResult is a tiny guardrail.
func TestRecord_NilResult(t *testing.T) {
	store := &fakePolicyStore{}
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "bob"}
	if err := Record(context.Background(), store, actor, nil); err == nil {
		t.Fatal("Record(nil) succeeded; want error")
	}
}

// TestRecord_PropagatesStoreError verifies a failure on the decision write
// surfaces and prevents an audit event from leaking.
func TestRecord_PropagatesStoreError(t *testing.T) {
	store := &fakePolicyStore{failOn: "decision"}
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "bob"}
	res := sampleResult(t)
	if err := Record(context.Background(), store, actor, res); err == nil {
		t.Fatal("expected error from decision write")
	}
	if len(store.events) != 0 {
		t.Errorf("audit event leaked despite decision failure: %+v", store.events)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
