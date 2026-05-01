package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validApprover(t *testing.T) Actor {
	t.Helper()
	return Actor{Kind: ActorHuman, Subject: "bob@example.com"}
}

func TestNewApproval_Valid(t *testing.T) {
	csID := NewID()
	cases := []struct {
		name     string
		decision ApprovalDecision
		reason   string
	}{
		{"approved without reason", ApprovalDecisionApproved, ""},
		{"approved with reason", ApprovalDecisionApproved, "looks good"},
		{"rejected with reason", ApprovalDecisionRejected, "missing owner field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewApproval(csID, validApprover(t), tc.decision, tc.reason)
			if err != nil {
				t.Fatalf("NewApproval error: %v", err)
			}
			if a.ID == "" {
				t.Error("ID is empty")
			}
			if a.ChangeSetID != csID {
				t.Errorf("ChangeSetID = %q, want %q", a.ChangeSetID, csID)
			}
			if a.Decision != tc.decision {
				t.Errorf("Decision = %q, want %q", a.Decision, tc.decision)
			}
			if a.DecidedAt.IsZero() {
				t.Error("DecidedAt is zero")
			}
			if a.DecidedAt.Location() != time.UTC {
				t.Errorf("DecidedAt location = %v, want UTC", a.DecidedAt.Location())
			}
		})
	}
}

func TestNewApproval_Invalid(t *testing.T) {
	csID := NewID()
	cases := []struct {
		name     string
		csID     ID
		approver Actor
		decision ApprovalDecision
		reason   string
		want     error
	}{
		{"empty csID", "", validApprover(t), ApprovalDecisionApproved, "", ErrApprovalChangeSetIDRequired},
		{"actor missing kind", csID, Actor{Subject: "x"}, ApprovalDecisionApproved, "", ErrActorKindInvalid},
		{"actor missing subject", csID, Actor{Kind: ActorHuman}, ApprovalDecisionApproved, "", ErrActorSubjectMissing},
		{"invalid decision", csID, validApprover(t), ApprovalDecision("bogus"), "", ErrApprovalDecisionInvalid},
		{"rejected without reason", csID, validApprover(t), ApprovalDecisionRejected, "", ErrApprovalReasonRequired},
		{"reason too long", csID, validApprover(t), ApprovalDecisionApproved, strings.Repeat("r", approvalReasonMaxLen+1), ErrApprovalReasonTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewApproval(tc.csID, tc.approver, tc.decision, tc.reason)
			if err == nil {
				t.Fatalf("NewApproval succeeded; want %v", tc.want)
			}
			if a != nil {
				t.Errorf("expected nil approval on error, got %+v", a)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestIsValidApprovalDecision(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"approved", true},
		{"rejected", true},
		{"", false},
		{"APPROVED", false},
		{"pending", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := IsValidApprovalDecision(tc.in); got != tc.want {
				t.Errorf("IsValidApprovalDecision(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
