package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validApprovedBy(t *testing.T) Actor {
	t.Helper()
	return Actor{Kind: ActorHuman, Subject: "approver@example.com"}
}

func TestNewApprovedVersion_Valid(t *testing.T) {
	productID := NewID()
	snapshotID := NewID()
	csID := NewID()
	parent := NewID()
	cases := []struct {
		name     string
		seq      int64
		parent   *ID
		descr    string
	}{
		{"first version", 1, nil, "Initial approved model"},
		{"sequence 2 with parent", 2, &parent, ""},
		{"max length description", 3, &parent, strings.Repeat("d", approvedVersionDescriptionMaxLen)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewApprovedVersion(productID, snapshotID, tc.seq, tc.parent, csID, validApprovedBy(t), tc.descr)
			if err != nil {
				t.Fatalf("NewApprovedVersion error: %v", err)
			}
			if v.ID == "" {
				t.Error("ID is empty")
			}
			if v.Sequence != tc.seq {
				t.Errorf("Sequence = %d, want %d", v.Sequence, tc.seq)
			}
			if v.CreatedAt.IsZero() {
				t.Error("CreatedAt is zero")
			}
			if v.CreatedAt.Location() != time.UTC {
				t.Errorf("CreatedAt location = %v, want UTC", v.CreatedAt.Location())
			}
		})
	}
}

func TestNewApprovedVersion_Invalid(t *testing.T) {
	productID := NewID()
	snapshotID := NewID()
	csID := NewID()
	cases := []struct {
		name       string
		productID  ID
		snapshotID ID
		seq        int64
		csID       ID
		actor      Actor
		descr      string
		want       error
	}{
		{"empty productID", "", snapshotID, 1, csID, validApprovedBy(t), "", ErrApprovedVersionProductIDRequired},
		{"sequence zero", productID, snapshotID, 0, csID, validApprovedBy(t), "", ErrApprovedVersionSequenceInvalid},
		{"sequence negative", productID, snapshotID, -1, csID, validApprovedBy(t), "", ErrApprovedVersionSequenceInvalid},
		{"empty source change set", productID, snapshotID, 1, "", validApprovedBy(t), "", ErrApprovedVersionSourceChangeSetRequired},
		{"empty snapshot id", productID, "", 1, csID, validApprovedBy(t), "", ErrApprovedVersionSnapshotIDRequired},
		{"actor missing kind", productID, snapshotID, 1, csID, Actor{Subject: "x"}, "", ErrActorKindInvalid},
		{"actor missing subject", productID, snapshotID, 1, csID, Actor{Kind: ActorHuman}, "", ErrActorSubjectMissing},
		{"description too long", productID, snapshotID, 1, csID, validApprovedBy(t), strings.Repeat("d", approvedVersionDescriptionMaxLen+1), ErrApprovedVersionDescriptionTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewApprovedVersion(tc.productID, tc.snapshotID, tc.seq, nil, tc.csID, tc.actor, tc.descr)
			if err == nil {
				t.Fatalf("NewApprovedVersion succeeded; want %v", tc.want)
			}
			if v != nil {
				t.Errorf("expected nil version on error, got %+v", v)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestNewApprovedVersionSnapshot_HashDeterminism(t *testing.T) {
	a, err := NewApprovedVersionSnapshot(map[string]any{
		"name":  "payments-api",
		"owner": "platform-security",
		"meta":  map[string]any{"env": "prod", "tier": 1},
	})
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	b, err := NewApprovedVersionSnapshot(map[string]any{
		"meta":  map[string]any{"tier": 1, "env": "prod"},
		"owner": "platform-security",
		"name":  "payments-api",
	})
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if a.ContentHash != b.ContentHash {
		t.Errorf("hashes differ across key orderings: %s vs %s", a.ContentHash, b.ContentHash)
	}
	if a.ID == b.ID {
		t.Error("IDs should be unique per snapshot")
	}

	c, err := NewApprovedVersionSnapshot(map[string]any{"name": "payments-api-v2"})
	if err != nil {
		t.Fatalf("third snapshot: %v", err)
	}
	if a.ContentHash == c.ContentHash {
		t.Error("hashes should differ for different content")
	}
	if len(a.ContentHash) != 64 {
		t.Errorf("ContentHash length = %d, want 64 (hex sha256)", len(a.ContentHash))
	}
}

func TestNewApprovedVersionSnapshot_NilContent(t *testing.T) {
	s, err := NewApprovedVersionSnapshot(nil)
	if err == nil {
		t.Fatal("NewApprovedVersionSnapshot(nil) succeeded; want error")
	}
	if s != nil {
		t.Errorf("expected nil snapshot, got %+v", s)
	}
	if !errors.Is(err, ErrApprovedVersionSnapshotContentRequired) {
		t.Errorf("err = %v, want ErrApprovedVersionSnapshotContentRequired", err)
	}
}

func TestNewApprovedVersionSnapshot_NestedDeterminism(t *testing.T) {
	// Same content with nested maps in different declaration orders must hash identically.
	a, err := NewApprovedVersionSnapshot(map[string]any{
		"a": map[string]any{"x": 1, "y": 2},
		"b": []any{map[string]any{"k": "v", "j": "w"}},
	})
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := NewApprovedVersionSnapshot(map[string]any{
		"b": []any{map[string]any{"j": "w", "k": "v"}},
		"a": map[string]any{"y": 2, "x": 1},
	})
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a.ContentHash != b.ContentHash {
		t.Errorf("nested hashes differ: %s vs %s", a.ContentHash, b.ContentHash)
	}
}

func TestCanonicalJSON_PrimitivesAndNull(t *testing.T) {
	out, err := canonicalJSON(map[string]any{
		"n":  nil,
		"b":  true,
		"i":  42,
		"f":  1.5,
		"s":  "hello",
		"xs": []any{1, "two", nil},
	})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	want := `{"b":true,"f":1.5,"i":42,"n":null,"s":"hello","xs":[1,"two",null]}`
	if string(out) != want {
		t.Errorf("canonicalJSON =\n  %s\nwant\n  %s", out, want)
	}
}
