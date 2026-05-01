package domain

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func validApplyActor() Actor {
	return Actor{Kind: ActorHuman, Subject: "engineer@example.com"}
}

func TestNewPlanApplyRecord_Valid(t *testing.T) {
	planID := NewID()
	target := "postgres://host:5432/payments"

	r, err := NewPlanApplyRecord(planID, validApplyActor(), target, false)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord: %v", err)
	}
	if r.ID == "" {
		t.Error("ID empty")
	}
	if r.PlanID != planID {
		t.Errorf("PlanID = %q, want %q", r.PlanID, planID)
	}
	if r.State != PlanApplyStateRunning {
		t.Errorf("State = %q, want running", r.State)
	}
	if r.Target != target {
		t.Errorf("Target = %q, want %q", r.Target, target)
	}
	if r.DryRun {
		t.Error("DryRun = true, want false")
	}
	if r.StartedAt.IsZero() {
		t.Error("StartedAt zero")
	}
	if r.StartedAt.Location() != time.UTC {
		t.Errorf("StartedAt location = %v, want UTC", r.StartedAt.Location())
	}
	if r.FinishedAt != nil {
		t.Errorf("FinishedAt = %v, want nil", r.FinishedAt)
	}
	if r.AppliedItems != 0 {
		t.Errorf("AppliedItems = %d, want 0", r.AppliedItems)
	}
	if r.FailedItems != 0 {
		t.Errorf("FailedItems = %d, want 0", r.FailedItems)
	}
	if string(r.Output) != "{}" {
		t.Errorf("Output = %s, want {}", string(r.Output))
	}
}

func TestNewPlanApplyRecord_DryRun(t *testing.T) {
	r, err := NewPlanApplyRecord(NewID(), validApplyActor(), "target", true)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord: %v", err)
	}
	if !r.DryRun {
		t.Error("DryRun = false, want true")
	}
}

func TestNewPlanApplyRecord_Invalid(t *testing.T) {
	planID := NewID()
	good := validApplyActor()

	cases := []struct {
		name    string
		planID  ID
		actor   Actor
		target  string
		wantErr error
	}{
		{"empty plan id", "", good, "target", ErrPlanApplyPlanIDRequired},
		{"empty target", planID, good, "", ErrPlanApplyTargetRequired},
		{"actor invalid kind", planID, Actor{Kind: "weird", Subject: "x"}, "target", ErrActorKindInvalid},
		{"actor missing subject", planID, Actor{Kind: ActorHuman}, "target", ErrActorSubjectMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPlanApplyRecord(tc.planID, tc.actor, tc.target, false)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.wantErr)
			}
		})
	}
}

func TestPlanApplyRecord_Transition_RunningToSucceeded(t *testing.T) {
	r, err := NewPlanApplyRecord(NewID(), validApplyActor(), "target", false)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord: %v", err)
	}
	if !r.CanTransitionTo(PlanApplyStateSucceeded) {
		t.Fatal("CanTransitionTo(succeeded) returned false")
	}

	finishedAt := time.Now().UTC()
	output := json.RawMessage(`{"items":[{"sequence":1,"status":"applied"}]}`)
	if err := r.Transition(PlanApplyStateSucceeded, finishedAt, "abc123", output, 1, 0, ""); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if r.State != PlanApplyStateSucceeded {
		t.Errorf("State = %q, want succeeded", r.State)
	}
	if r.FinishedAt == nil {
		t.Fatal("FinishedAt nil")
	}
	if r.FinishedAt.Location() != time.UTC {
		t.Errorf("FinishedAt location = %v, want UTC", r.FinishedAt.Location())
	}
	if r.SummaryHash != "abc123" {
		t.Errorf("SummaryHash = %q, want abc123", r.SummaryHash)
	}
	if string(r.Output) != string(output) {
		t.Errorf("Output = %s, want %s", string(r.Output), string(output))
	}
	if r.AppliedItems != 1 {
		t.Errorf("AppliedItems = %d, want 1", r.AppliedItems)
	}
	if r.FailedItems != 0 {
		t.Errorf("FailedItems = %d, want 0", r.FailedItems)
	}
}

func TestPlanApplyRecord_Transition_RunningToFailed(t *testing.T) {
	r, err := NewPlanApplyRecord(NewID(), validApplyActor(), "target", false)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord: %v", err)
	}
	if !r.CanTransitionTo(PlanApplyStateFailed) {
		t.Fatal("CanTransitionTo(failed) returned false")
	}

	finishedAt := time.Now().UTC()
	output := json.RawMessage(`{"items":[{"sequence":1,"status":"failed","error":"connection refused"}]}`)
	if err := r.Transition(PlanApplyStateFailed, finishedAt, "deadbeef", output, 0, 1, "connection refused"); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if r.State != PlanApplyStateFailed {
		t.Errorf("State = %q, want failed", r.State)
	}
	if r.FailureMessage != "connection refused" {
		t.Errorf("FailureMessage = %q, want %q", r.FailureMessage, "connection refused")
	}
	if r.AppliedItems != 0 {
		t.Errorf("AppliedItems = %d, want 0", r.AppliedItems)
	}
	if r.FailedItems != 1 {
		t.Errorf("FailedItems = %d, want 1", r.FailedItems)
	}
}

func TestPlanApplyRecord_Transition_TerminalRejectsFurther(t *testing.T) {
	terminals := []PlanApplyState{PlanApplyStateSucceeded, PlanApplyStateFailed}
	for _, term := range terminals {
		t.Run(string(term), func(t *testing.T) {
			r, err := NewPlanApplyRecord(NewID(), validApplyActor(), "target", false)
			if err != nil {
				t.Fatalf("NewPlanApplyRecord: %v", err)
			}
			finishedAt := time.Now().UTC()
			if err := r.Transition(term, finishedAt, "h", json.RawMessage(`{}`), 0, 0, ""); err != nil {
				t.Fatalf("first Transition(%s): %v", term, err)
			}
			// Now try every other state.
			for _, next := range []PlanApplyState{PlanApplyStateRunning, PlanApplyStateSucceeded, PlanApplyStateFailed} {
				if r.CanTransitionTo(next) {
					t.Errorf("CanTransitionTo(%s) returned true after terminal %s; want false", next, term)
				}
				err := r.Transition(next, finishedAt, "h", json.RawMessage(`{}`), 0, 0, "")
				if !errors.Is(err, ErrPlanApplyInvalidTransition) {
					t.Errorf("Transition(%s) err = %v, want ErrPlanApplyInvalidTransition", next, err)
				}
			}
		})
	}
}

func TestPlanApplyRecord_Transition_InvalidTargetState(t *testing.T) {
	r, err := NewPlanApplyRecord(NewID(), validApplyActor(), "target", false)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord: %v", err)
	}
	err = r.Transition(PlanApplyState("bogus"), time.Now().UTC(), "", json.RawMessage(`{}`), 0, 0, "")
	if !errors.Is(err, ErrPlanApplyStateInvalid) {
		t.Errorf("err = %v, want ErrPlanApplyStateInvalid", err)
	}
}

func TestPlanApplyRecord_Transition_NegativeCounts(t *testing.T) {
	cases := []struct {
		name           string
		applied, failed int
		wantErr        error
	}{
		{"negative applied", -1, 0, ErrPlanApplyAppliedItemsNegative},
		{"negative failed", 0, -1, ErrPlanApplyFailedItemsNegative},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewPlanApplyRecord(NewID(), validApplyActor(), "target", false)
			if err != nil {
				t.Fatalf("NewPlanApplyRecord: %v", err)
			}
			err = r.Transition(PlanApplyStateSucceeded, time.Now().UTC(), "h",
				json.RawMessage(`{}`), tc.applied, tc.failed, "")
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestIsValidPlanApplyState(t *testing.T) {
	for _, s := range []PlanApplyState{
		PlanApplyStateRunning, PlanApplyStateSucceeded, PlanApplyStateFailed,
	} {
		if !IsValidPlanApplyState(string(s)) {
			t.Errorf("IsValidPlanApplyState(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "bogus", "applied"} {
		if IsValidPlanApplyState(s) {
			t.Errorf("IsValidPlanApplyState(%q) = true, want false", s)
		}
	}
}
