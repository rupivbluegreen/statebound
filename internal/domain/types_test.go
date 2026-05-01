package domain

import (
	"errors"
	"testing"
)

func TestActor_Validate(t *testing.T) {
	cases := []struct {
		name    string
		actor   Actor
		wantErr error
	}{
		{"human valid", Actor{Kind: ActorHuman, Subject: "alice@example.com"}, nil},
		{"service account valid", Actor{Kind: ActorServiceAccount, Subject: "agent-modeler"}, nil},
		{"system valid", Actor{Kind: ActorSystem, Subject: "migrator"}, nil},
		{"unknown kind", Actor{Kind: "robot", Subject: "x"}, ErrActorKindInvalid},
		{"empty kind", Actor{Kind: "", Subject: "x"}, ErrActorKindInvalid},
		{"empty subject", Actor{Kind: ActorHuman, Subject: ""}, ErrActorSubjectMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.actor.Validate()
			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("Validate returned %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Validate err = %v, want errors.Is == %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewID_Unique(t *testing.T) {
	a := NewID()
	b := NewID()
	if a == "" || b == "" {
		t.Fatal("NewID returned empty string")
	}
	if a == b {
		t.Errorf("NewID returned duplicates: %q == %q", a, b)
	}
}
