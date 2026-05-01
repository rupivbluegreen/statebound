package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func validPlanGeneratedBy() Actor {
	return Actor{Kind: ActorHuman, Subject: "engineer@example.com"}
}

func TestNewPlan_Valid(t *testing.T) {
	productID := NewID()
	avID := NewID()
	body := json.RawMessage(`{"items":[{"action":"create","ref":"pay-linux-01:/etc/sudoers.d/payments"}]}`)

	p, err := NewPlan(productID, avID, 1, "linux-sudo", "0.4.0", body, "1 sudoers fragment", validPlanGeneratedBy())
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	if p.ID == "" {
		t.Error("ID empty")
	}
	if p.ProductID != productID {
		t.Errorf("ProductID = %q, want %q", p.ProductID, productID)
	}
	if p.ApprovedVersionID != avID {
		t.Errorf("ApprovedVersionID = %q, want %q", p.ApprovedVersionID, avID)
	}
	if p.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", p.Sequence)
	}
	if p.ConnectorName != "linux-sudo" {
		t.Errorf("ConnectorName = %q, want linux-sudo", p.ConnectorName)
	}
	if p.ConnectorVersion != "0.4.0" {
		t.Errorf("ConnectorVersion = %q, want 0.4.0", p.ConnectorVersion)
	}
	if p.State != PlanStateDraft {
		t.Errorf("State = %q, want draft", p.State)
	}
	if p.Summary != "1 sudoers fragment" {
		t.Errorf("Summary = %q, want %q", p.Summary, "1 sudoers fragment")
	}
	if p.GeneratedAt.IsZero() {
		t.Error("GeneratedAt zero")
	}
	if p.GeneratedAt.Location() != time.UTC {
		t.Errorf("GeneratedAt location = %v, want UTC", p.GeneratedAt.Location())
	}
	if len(p.ContentHash) != 64 {
		t.Errorf("ContentHash length = %d, want 64", len(p.ContentHash))
	}
	if p.RefusedReason != "" {
		t.Errorf("RefusedReason = %q, want empty", p.RefusedReason)
	}

	// SHA-256 of the canonical bytes must match what NewPlan persisted.
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	if p.ContentHash != want {
		t.Errorf("ContentHash = %q, want %q", p.ContentHash, want)
	}
	if got := p.Hash(); got != p.ContentHash {
		t.Errorf("Hash() = %q, want %q", got, p.ContentHash)
	}
}

func TestNewPlan_Invalid(t *testing.T) {
	productID := NewID()
	avID := NewID()
	body := json.RawMessage(`{"items":[]}`)
	by := validPlanGeneratedBy()

	cases := []struct {
		name             string
		productID        ID
		avID             ID
		sequence         int64
		connectorName    string
		connectorVersion string
		content          json.RawMessage
		generatedBy      Actor
		wantErr          error
	}{
		{"empty product", "", avID, 1, "linux-sudo", "0.4.0", body, by, ErrPlanProductIDRequired},
		{"empty av", productID, "", 1, "linux-sudo", "0.4.0", body, by, ErrPlanApprovedVersionIDRequired},
		{"sequence zero", productID, avID, 0, "linux-sudo", "0.4.0", body, by, ErrPlanSequenceInvalid},
		{"sequence negative", productID, avID, -1, "linux-sudo", "0.4.0", body, by, ErrPlanSequenceInvalid},
		{"empty connector name", productID, avID, 1, "", "0.4.0", body, by, ErrPlanConnectorNameRequired},
		{"empty connector version", productID, avID, 1, "linux-sudo", "", body, by, ErrPlanConnectorVersionRequired},
		{"empty content", productID, avID, 1, "linux-sudo", "0.4.0", json.RawMessage{}, by, ErrPlanContentEmpty},
		{"invalid json", productID, avID, 1, "linux-sudo", "0.4.0", json.RawMessage(`{not-json`), by, ErrPlanContentNotJSON},
		{"invalid actor", productID, avID, 1, "linux-sudo", "0.4.0", body, Actor{}, ErrActorKindInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPlan(tc.productID, tc.avID, tc.sequence,
				tc.connectorName, tc.connectorVersion, tc.content,
				"summary", tc.generatedBy)
			if err == nil {
				t.Fatalf("NewPlan succeeded; want error %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.wantErr)
			}
		})
	}
}

func TestPlan_Hash_DefensiveCopy(t *testing.T) {
	body := json.RawMessage(`{"k":1}`)
	p, err := NewPlan(NewID(), NewID(), 1, "linux-sudo", "0.4.0", body, "", validPlanGeneratedBy())
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	original := p.ContentHash

	// Mutating the input slice after construction must not affect the
	// persisted hash, because NewPlan made a defensive copy.
	body[1] = 'x'
	if p.Hash() != original {
		t.Errorf("Hash changed after mutating caller's content slice: got %q want %q", p.Hash(), original)
	}
}

func TestNewPlan_DeterministicHash(t *testing.T) {
	productID := NewID()
	avID := NewID()
	body := json.RawMessage(`{"items":[{"action":"create"}]}`)

	first, err := NewPlan(productID, avID, 1, "linux-sudo", "0.4.0", body, "summary", validPlanGeneratedBy())
	if err != nil {
		t.Fatalf("first NewPlan: %v", err)
	}
	second, err := NewPlan(productID, avID, 1, "linux-sudo", "0.4.0", body, "summary", validPlanGeneratedBy())
	if err != nil {
		t.Fatalf("second NewPlan: %v", err)
	}
	if first.ContentHash != second.ContentHash {
		t.Errorf("ContentHash differs: %q vs %q", first.ContentHash, second.ContentHash)
	}
	if first.ID == second.ID {
		t.Errorf("IDs collide: %q == %q (must be fresh per call)", first.ID, second.ID)
	}
}

func TestPlan_StateMachine_LegalTransitions(t *testing.T) {
	// Build a single Draft plan and walk it through the legal edges.
	mk := func(state PlanState) *Plan {
		p, err := NewPlan(NewID(), NewID(), 1, "linux-sudo", "0.4.0",
			json.RawMessage(`{"k":1}`), "", validPlanGeneratedBy())
		if err != nil {
			t.Fatalf("NewPlan: %v", err)
		}
		p.State = state
		return p
	}

	cases := []struct {
		name      string
		from      PlanState
		to        PlanState
		reason    string
		wantState PlanState
	}{
		{"draft -> ready", PlanStateDraft, PlanStateReady, "", PlanStateReady},
		{"draft -> refused", PlanStateDraft, PlanStateRefused, "policy denied", PlanStateRefused},
		{"ready -> applied", PlanStateReady, PlanStateApplied, "", PlanStateApplied},
		{"ready -> failed", PlanStateReady, PlanStateFailed, "", PlanStateFailed},
		{"ready -> refused", PlanStateReady, PlanStateRefused, "re-eval flipped to deny", PlanStateRefused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mk(tc.from)
			if !p.CanTransitionTo(tc.to) {
				t.Fatalf("CanTransitionTo(%s) returned false", tc.to)
			}
			if err := p.Transition(tc.to, tc.reason); err != nil {
				t.Fatalf("Transition(%s, %q): %v", tc.to, tc.reason, err)
			}
			if p.State != tc.wantState {
				t.Errorf("State = %q, want %q", p.State, tc.wantState)
			}
			if tc.to == PlanStateRefused && p.RefusedReason != tc.reason {
				t.Errorf("RefusedReason = %q, want %q", p.RefusedReason, tc.reason)
			}
		})
	}
}

func TestPlan_StateMachine_IllegalTransitions(t *testing.T) {
	// Every transition not in the legal-edges table above must reject.
	type edge struct{ from, to PlanState }
	all := []PlanState{PlanStateDraft, PlanStateReady, PlanStateRefused, PlanStateApplied, PlanStateFailed}
	legal := map[edge]struct{}{
		{PlanStateDraft, PlanStateReady}:    {},
		{PlanStateDraft, PlanStateRefused}:  {},
		{PlanStateReady, PlanStateApplied}:  {},
		{PlanStateReady, PlanStateFailed}:   {},
		{PlanStateReady, PlanStateRefused}:  {},
	}

	for _, from := range all {
		for _, to := range all {
			if from == to {
				continue
			}
			if _, ok := legal[edge{from, to}]; ok {
				continue
			}
			t.Run(string(from)+"->"+string(to), func(t *testing.T) {
				p, err := NewPlan(NewID(), NewID(), 1, "linux-sudo", "0.4.0",
					json.RawMessage(`{"k":1}`), "", validPlanGeneratedBy())
				if err != nil {
					t.Fatalf("NewPlan: %v", err)
				}
				p.State = from
				if p.CanTransitionTo(to) {
					t.Fatalf("CanTransitionTo(%s) returned true; want false", to)
				}
				err = p.Transition(to, "reason")
				if err == nil {
					t.Fatalf("Transition(%s, %q) succeeded; want error", to, "reason")
				}
				if !errors.Is(err, ErrPlanInvalidTransition) {
					t.Errorf("err = %v, want errors.Is == ErrPlanInvalidTransition", err)
				}
			})
		}
	}
}

func TestPlan_Transition_RefusedRequiresReason(t *testing.T) {
	p, err := NewPlan(NewID(), NewID(), 1, "linux-sudo", "0.4.0",
		json.RawMessage(`{"k":1}`), "", validPlanGeneratedBy())
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	err = p.Transition(PlanStateRefused, "")
	if !errors.Is(err, ErrPlanRefusedReasonRequired) {
		t.Errorf("err = %v, want errors.Is == ErrPlanRefusedReasonRequired", err)
	}
}

func TestPlan_Transition_InvalidTargetState(t *testing.T) {
	p, err := NewPlan(NewID(), NewID(), 1, "linux-sudo", "0.4.0",
		json.RawMessage(`{"k":1}`), "", validPlanGeneratedBy())
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	err = p.Transition(PlanState("bogus"), "")
	if !errors.Is(err, ErrPlanStateInvalid) {
		t.Errorf("err = %v, want errors.Is == ErrPlanStateInvalid", err)
	}
}

func TestIsValidPlanState(t *testing.T) {
	for _, s := range []PlanState{
		PlanStateDraft, PlanStateReady, PlanStateRefused, PlanStateApplied, PlanStateFailed,
	} {
		if !IsValidPlanState(string(s)) {
			t.Errorf("IsValidPlanState(%q) = false, want true", s)
		}
	}
	if IsValidPlanState("") || IsValidPlanState("bogus") {
		t.Errorf("IsValidPlanState accepted invalid input")
	}
}
