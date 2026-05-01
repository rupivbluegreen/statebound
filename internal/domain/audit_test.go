package domain

import (
	"errors"
	"testing"
	"time"
)

func validActor() Actor {
	return Actor{Kind: ActorHuman, Subject: "alice@example.com"}
}

func TestNewAuditEvent_Valid(t *testing.T) {
	kinds := []EventKind{
		EventProductCreated,
		EventProductUpdated,
		EventProductDeleted,
		EventModelImported,
	}
	for _, k := range kinds {
		t.Run(string(k), func(t *testing.T) {
			payload := map[string]any{"foo": "bar"}
			e, err := NewAuditEvent(k, validActor(), "product", "payments-api", payload)
			if err != nil {
				t.Fatalf("NewAuditEvent(%q) error: %v", k, err)
			}
			if e == nil {
				t.Fatal("NewAuditEvent returned nil")
			}
			if e.ID == "" {
				t.Error("ID is empty")
			}
			if e.Kind != k {
				t.Errorf("Kind = %q, want %q", e.Kind, k)
			}
			if e.OccurredAt.IsZero() {
				t.Error("OccurredAt is zero")
			}
			if e.OccurredAt.Location() != time.UTC {
				t.Errorf("OccurredAt location = %v, want UTC", e.OccurredAt.Location())
			}
			if err := e.Validate(); err != nil {
				t.Errorf("Validate after construction: %v", err)
			}
		})
	}
}

func TestNewAuditEvent_Invalid(t *testing.T) {
	cases := []struct {
		name         string
		kind         EventKind
		actor        Actor
		resourceType string
		resourceID   string
		want         error
	}{
		{"empty kind", "", validActor(), "product", "id", ErrAuditKindRequired},
		{"empty resource type", EventProductCreated, validActor(), "", "id", ErrAuditResourceTypeRequired},
		{"empty resource id", EventProductCreated, validActor(), "product", "", ErrAuditResourceIDRequired},
		{"actor kind unset", EventProductCreated, Actor{Subject: "alice"}, "product", "id", ErrActorKindInvalid},
		{"actor subject empty", EventProductCreated, Actor{Kind: ActorHuman}, "product", "id", ErrActorSubjectMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewAuditEvent(tc.kind, tc.actor, tc.resourceType, tc.resourceID, nil)
			if err == nil {
				t.Fatalf("NewAuditEvent succeeded; want error %v", tc.want)
			}
			if e != nil {
				t.Errorf("expected nil event on error, got %+v", e)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestAuditEvent_Validate(t *testing.T) {
	cases := []struct {
		name string
		e    AuditEvent
		want error
	}{
		{
			name: "valid",
			e: AuditEvent{
				ID:           NewID(),
				Kind:         EventProductCreated,
				Actor:        validActor(),
				ResourceType: "product",
				ResourceID:   "payments-api",
				OccurredAt:   time.Now().UTC(),
			},
			want: nil,
		},
		{
			name: "missing kind",
			e: AuditEvent{
				ID:           NewID(),
				Actor:        validActor(),
				ResourceType: "product",
				ResourceID:   "payments-api",
			},
			want: ErrAuditKindRequired,
		},
		{
			name: "bad actor",
			e: AuditEvent{
				ID:           NewID(),
				Kind:         EventProductCreated,
				Actor:        Actor{Kind: "bogus", Subject: "x"},
				ResourceType: "product",
				ResourceID:   "payments-api",
			},
			want: ErrActorKindInvalid,
		},
		{
			name: "missing resource type",
			e: AuditEvent{
				ID:         NewID(),
				Kind:       EventProductCreated,
				Actor:      validActor(),
				ResourceID: "payments-api",
			},
			want: ErrAuditResourceTypeRequired,
		},
		{
			name: "missing resource id",
			e: AuditEvent{
				ID:           NewID(),
				Kind:         EventProductCreated,
				Actor:        validActor(),
				ResourceType: "product",
			},
			want: ErrAuditResourceIDRequired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.e.Validate()
			if tc.want == nil {
				if err != nil {
					t.Errorf("Validate returned %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("Validate err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestAuditEvent_PayloadRoundTrip(t *testing.T) {
	payload := map[string]any{
		"name":  "payments-api",
		"owner": "platform-security",
		"count": 42,
		"nested": map[string]any{
			"k": "v",
		},
	}
	e, err := NewAuditEvent(EventProductCreated, validActor(), "product", "payments-api", payload)
	if err != nil {
		t.Fatalf("NewAuditEvent error: %v", err)
	}
	if e.Payload == nil {
		t.Fatal("Payload is nil")
	}
	if got, want := e.Payload["name"], "payments-api"; got != want {
		t.Errorf("Payload[name] = %v, want %v", got, want)
	}
	if got, want := e.Payload["owner"], "platform-security"; got != want {
		t.Errorf("Payload[owner] = %v, want %v", got, want)
	}
	if got, want := e.Payload["count"], 42; got != want {
		t.Errorf("Payload[count] = %v, want %v", got, want)
	}
	nested, ok := e.Payload["nested"].(map[string]any)
	if !ok {
		t.Fatalf("Payload[nested] is not a map: %T", e.Payload["nested"])
	}
	if got, want := nested["k"], "v"; got != want {
		t.Errorf("Payload[nested][k] = %v, want %v", got, want)
	}
	if got, want := len(e.Payload), len(payload); got != want {
		t.Errorf("len(Payload) = %d, want %d", got, want)
	}
}
