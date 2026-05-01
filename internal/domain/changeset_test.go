package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validRequester(t *testing.T) Actor {
	t.Helper()
	return Actor{Kind: ActorHuman, Subject: "carol@example.com"}
}

func TestNewChangeSet_Valid(t *testing.T) {
	cases := []struct {
		name    string
		title   string
		descr   string
		parent  *ID
	}{
		{"first changeset, no parent", "Initial model", "Bootstrap product authorization", nil},
		{"with parent version", "Add prod-readonly", "", func() *ID { id := NewID(); return &id }()},
		{"max length title", strings.Repeat("a", changeSetTitleMaxLen), "", nil},
		{"max length description", "Title", strings.Repeat("d", changeSetDescriptionMaxLen), nil},
		{"empty description ok", "Title", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := NewChangeSet(NewID(), tc.parent, tc.title, tc.descr, validRequester(t))
			if err != nil {
				t.Fatalf("NewChangeSet error: %v", err)
			}
			if cs == nil {
				t.Fatal("NewChangeSet returned nil")
			}
			if cs.ID == "" {
				t.Error("ID is empty")
			}
			if cs.State != ChangeSetStateDraft {
				t.Errorf("State = %q, want %q", cs.State, ChangeSetStateDraft)
			}
			if cs.CreatedAt.IsZero() {
				t.Error("CreatedAt is zero")
			}
			if cs.CreatedAt.Location() != time.UTC {
				t.Errorf("CreatedAt location = %v, want UTC", cs.CreatedAt.Location())
			}
			if !cs.CreatedAt.Equal(cs.UpdatedAt) {
				t.Errorf("CreatedAt != UpdatedAt at construction")
			}
			if cs.SubmittedAt != nil {
				t.Errorf("SubmittedAt should be nil for draft, got %v", *cs.SubmittedAt)
			}
			if cs.DecidedAt != nil {
				t.Errorf("DecidedAt should be nil for draft, got %v", *cs.DecidedAt)
			}
		})
	}
}

func TestNewChangeSet_Invalid(t *testing.T) {
	cases := []struct {
		name      string
		productID ID
		title     string
		descr     string
		actor     Actor
		want      error
	}{
		{"empty productID", "", "Title", "", validRequester(t), ErrChangeSetProductIDRequired},
		{"empty title", NewID(), "", "", validRequester(t), ErrChangeSetTitleRequired},
		{"title too long", NewID(), strings.Repeat("a", changeSetTitleMaxLen+1), "", validRequester(t), ErrChangeSetTitleTooLong},
		{"description too long", NewID(), "Title", strings.Repeat("d", changeSetDescriptionMaxLen+1), validRequester(t), ErrChangeSetDescriptionTooLong},
		{"actor missing kind", NewID(), "Title", "", Actor{Subject: "x"}, ErrActorKindInvalid},
		{"actor missing subject", NewID(), "Title", "", Actor{Kind: ActorHuman}, ErrActorSubjectMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := NewChangeSet(tc.productID, nil, tc.title, tc.descr, tc.actor)
			if err == nil {
				t.Fatalf("NewChangeSet succeeded; want %v", tc.want)
			}
			if cs != nil {
				t.Errorf("expected nil change set on error, got %+v", cs)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestIsValidChangeSetState(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"draft", true},
		{"submitted", true},
		{"approved", true},
		{"rejected", true},
		{"conflicted", true},
		{"", false},
		{"DRAFT", false},
		{"unknown", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := IsValidChangeSetState(tc.in); got != tc.want {
				t.Errorf("IsValidChangeSetState(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestChangeSetState_CanTransitionTo(t *testing.T) {
	all := []ChangeSetState{
		ChangeSetStateDraft,
		ChangeSetStateSubmitted,
		ChangeSetStateApproved,
		ChangeSetStateRejected,
		ChangeSetStateConflicted,
	}
	allowed := map[ChangeSetState]map[ChangeSetState]bool{
		ChangeSetStateDraft: {
			ChangeSetStateSubmitted: true,
			ChangeSetStateRejected:  true,
		},
		ChangeSetStateSubmitted: {
			ChangeSetStateApproved: true,
			ChangeSetStateRejected: true,
		},
		ChangeSetStateApproved: {
			ChangeSetStateConflicted: true,
		},
		ChangeSetStateRejected:   {},
		ChangeSetStateConflicted: {},
	}
	for _, from := range all {
		for _, to := range all {
			from, to := from, to
			t.Run(string(from)+"->"+string(to), func(t *testing.T) {
				want := allowed[from][to]
				got := from.CanTransitionTo(to)
				if got != want {
					t.Errorf("(%s).CanTransitionTo(%s) = %v, want %v", from, to, got, want)
				}
			})
		}
	}
}

func TestChangeSet_Transition_Legal(t *testing.T) {
	at := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	t.Run("draft to submitted sets SubmittedAt", func(t *testing.T) {
		cs, err := NewChangeSet(NewID(), nil, "Title", "", validRequester(t))
		if err != nil {
			t.Fatalf("NewChangeSet: %v", err)
		}
		if err := cs.Transition(ChangeSetStateSubmitted, "", at); err != nil {
			t.Fatalf("Transition: %v", err)
		}
		if cs.State != ChangeSetStateSubmitted {
			t.Errorf("State = %q, want %q", cs.State, ChangeSetStateSubmitted)
		}
		if cs.SubmittedAt == nil || !cs.SubmittedAt.Equal(at) {
			t.Errorf("SubmittedAt = %v, want %v", cs.SubmittedAt, at)
		}
		if cs.DecidedAt != nil {
			t.Errorf("DecidedAt should be nil after submit, got %v", *cs.DecidedAt)
		}
		if !cs.UpdatedAt.Equal(at) {
			t.Errorf("UpdatedAt = %v, want %v", cs.UpdatedAt, at)
		}
	})

	t.Run("submitted to approved sets DecidedAt and reason", func(t *testing.T) {
		cs, err := NewChangeSet(NewID(), nil, "Title", "", validRequester(t))
		if err != nil {
			t.Fatalf("NewChangeSet: %v", err)
		}
		if err := cs.Transition(ChangeSetStateSubmitted, "", at); err != nil {
			t.Fatalf("submit: %v", err)
		}
		later := at.Add(time.Hour)
		if err := cs.Transition(ChangeSetStateApproved, "looks good", later); err != nil {
			t.Fatalf("approve: %v", err)
		}
		if cs.State != ChangeSetStateApproved {
			t.Errorf("State = %q, want %q", cs.State, ChangeSetStateApproved)
		}
		if cs.DecidedAt == nil || !cs.DecidedAt.Equal(later) {
			t.Errorf("DecidedAt = %v, want %v", cs.DecidedAt, later)
		}
		if cs.DecisionReason != "looks good" {
			t.Errorf("DecisionReason = %q, want %q", cs.DecisionReason, "looks good")
		}
	})

	t.Run("approved to conflicted sets DecidedAt", func(t *testing.T) {
		cs, err := NewChangeSet(NewID(), nil, "Title", "", validRequester(t))
		if err != nil {
			t.Fatalf("NewChangeSet: %v", err)
		}
		if err := cs.Transition(ChangeSetStateSubmitted, "", at); err != nil {
			t.Fatalf("submit: %v", err)
		}
		if err := cs.Transition(ChangeSetStateApproved, "", at); err != nil {
			t.Fatalf("approve: %v", err)
		}
		conflictAt := at.Add(2 * time.Hour)
		if err := cs.Transition(ChangeSetStateConflicted, "sibling landed first", conflictAt); err != nil {
			t.Fatalf("conflict: %v", err)
		}
		if cs.State != ChangeSetStateConflicted {
			t.Errorf("State = %q, want %q", cs.State, ChangeSetStateConflicted)
		}
		if cs.DecidedAt == nil || !cs.DecidedAt.Equal(conflictAt) {
			t.Errorf("DecidedAt = %v, want %v", cs.DecidedAt, conflictAt)
		}
	})

	t.Run("draft to rejected (cancel)", func(t *testing.T) {
		cs, err := NewChangeSet(NewID(), nil, "Title", "", validRequester(t))
		if err != nil {
			t.Fatalf("NewChangeSet: %v", err)
		}
		if err := cs.Transition(ChangeSetStateRejected, "cancelled by author", at); err != nil {
			t.Fatalf("reject: %v", err)
		}
		if cs.State != ChangeSetStateRejected {
			t.Errorf("State = %q, want %q", cs.State, ChangeSetStateRejected)
		}
		if cs.DecidedAt == nil {
			t.Error("DecidedAt should be set on reject")
		}
	})
}

func TestChangeSet_Transition_Illegal(t *testing.T) {
	at := time.Now().UTC()
	cs, err := NewChangeSet(NewID(), nil, "Title", "", validRequester(t))
	if err != nil {
		t.Fatalf("NewChangeSet: %v", err)
	}
	// Draft cannot go directly to Approved.
	err = cs.Transition(ChangeSetStateApproved, "", at)
	if err == nil {
		t.Fatal("expected error transitioning Draft -> Approved")
	}
	if !errors.Is(err, ErrChangeSetInvalidTransition) {
		t.Errorf("err = %v, want ErrChangeSetInvalidTransition", err)
	}
	// Unknown target.
	err = cs.Transition(ChangeSetState("bogus"), "", at)
	if !errors.Is(err, ErrChangeSetStateInvalid) {
		t.Errorf("err = %v, want ErrChangeSetStateInvalid", err)
	}
	// Reason too long.
	tooLong := strings.Repeat("r", changeSetReasonMaxLen+1)
	err = cs.Transition(ChangeSetStateSubmitted, tooLong, at)
	if !errors.Is(err, ErrChangeSetReasonTooLong) {
		t.Errorf("err = %v, want ErrChangeSetReasonTooLong", err)
	}
}

func TestChangeSet_Validate(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name string
		cs   ChangeSet
		want error
	}{
		{
			name: "valid draft",
			cs: ChangeSet{
				ID: NewID(), ProductID: NewID(), State: ChangeSetStateDraft,
				Title: "T", RequestedBy: validRequester(t), CreatedAt: now, UpdatedAt: now,
			},
			want: nil,
		},
		{
			name: "invalid state",
			cs: ChangeSet{
				ID: NewID(), ProductID: NewID(), State: ChangeSetState("bogus"),
				Title: "T", RequestedBy: validRequester(t), CreatedAt: now, UpdatedAt: now,
			},
			want: ErrChangeSetStateInvalid,
		},
		{
			name: "decision reason too long",
			cs: ChangeSet{
				ID: NewID(), ProductID: NewID(), State: ChangeSetStateDraft,
				Title: "T", RequestedBy: validRequester(t),
				DecisionReason: strings.Repeat("r", changeSetReasonMaxLen+1),
				CreatedAt:      now, UpdatedAt: now,
			},
			want: ErrChangeSetReasonTooLong,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cs.Validate()
			if tc.want == nil {
				if err != nil {
					t.Errorf("Validate returned %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}
