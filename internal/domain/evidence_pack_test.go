package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func validGeneratedBy() Actor {
	return Actor{Kind: ActorHuman, Subject: "auditor@example.com"}
}

func TestNewEvidencePack_Valid(t *testing.T) {
	productID := NewID()
	avID := NewID()
	content := json.RawMessage(`{"approved_version":"abc","sequence":1}`)

	cases := []struct {
		name   string
		format string
		body   json.RawMessage
	}{
		{"json", EvidencePackFormatJSON, content},
		{
			name:   "markdown wrapped",
			format: EvidencePackFormatMarkdown,
			body:   json.RawMessage(`{"format":"markdown","body":"# Approved Version 1\n"}`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewEvidencePack(productID, avID, 1, tc.format, tc.body, validGeneratedBy())
			if err != nil {
				t.Fatalf("NewEvidencePack: %v", err)
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
			if p.Format != tc.format {
				t.Errorf("Format = %q, want %q", p.Format, tc.format)
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
			// Manual SHA-256 hex of the canonical bytes must match.
			sum := sha256.Sum256(tc.body)
			want := hex.EncodeToString(sum[:])
			if p.ContentHash != want {
				t.Errorf("ContentHash = %q, want %q", p.ContentHash, want)
			}
			// Hash() round-trip equality.
			if got := p.Hash(); got != p.ContentHash {
				t.Errorf("Hash() = %q, want %q", got, p.ContentHash)
			}
		})
	}
}

func TestNewEvidencePack_Invalid(t *testing.T) {
	productID := NewID()
	avID := NewID()
	good := json.RawMessage(`{"k":"v"}`)
	cases := []struct {
		name              string
		productID         ID
		approvedVersionID ID
		sequence          int64
		format            string
		content           json.RawMessage
		actor             Actor
		want              error
	}{
		{"empty product id", "", avID, 1, EvidencePackFormatJSON, good, validGeneratedBy(), ErrEvidencePackProductIDRequired},
		{"empty approved version id", productID, "", 1, EvidencePackFormatJSON, good, validGeneratedBy(), ErrEvidencePackVersionIDRequired},
		{"sequence zero", productID, avID, 0, EvidencePackFormatJSON, good, validGeneratedBy(), ErrEvidencePackSequenceInvalid},
		{"sequence negative", productID, avID, -1, EvidencePackFormatJSON, good, validGeneratedBy(), ErrEvidencePackSequenceInvalid},
		{"empty format", productID, avID, 1, "", good, validGeneratedBy(), ErrEvidencePackFormatInvalid},
		{"unknown format", productID, avID, 1, "yaml", good, validGeneratedBy(), ErrEvidencePackFormatInvalid},
		{"empty content", productID, avID, 1, EvidencePackFormatJSON, json.RawMessage(``), validGeneratedBy(), ErrEvidencePackInvalid},
		{"non-json content", productID, avID, 1, EvidencePackFormatJSON, json.RawMessage(`not json{`), validGeneratedBy(), ErrEvidencePackInvalid},
		{"actor missing kind", productID, avID, 1, EvidencePackFormatJSON, good, Actor{Subject: "x"}, ErrActorKindInvalid},
		{"actor missing subject", productID, avID, 1, EvidencePackFormatJSON, good, Actor{Kind: ActorHuman}, ErrActorSubjectMissing},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewEvidencePack(tc.productID, tc.approvedVersionID, tc.sequence, tc.format, tc.content, tc.actor)
			if err == nil {
				t.Fatalf("NewEvidencePack succeeded; want %v", tc.want)
			}
			if p != nil {
				t.Errorf("expected nil pack on error, got %+v", p)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestEvidencePack_HashRoundTrip(t *testing.T) {
	body := json.RawMessage(`{"approved_version":"av-1","items":[1,2,3]}`)
	p, err := NewEvidencePack(NewID(), NewID(), 7, EvidencePackFormatJSON, body, validGeneratedBy())
	if err != nil {
		t.Fatalf("NewEvidencePack: %v", err)
	}
	manual := sha256.Sum256(body)
	want := hex.EncodeToString(manual[:])
	if p.ContentHash != want {
		t.Errorf("ContentHash = %q, want %q", p.ContentHash, want)
	}
	if got := p.Hash(); got != want {
		t.Errorf("Hash() = %q, want %q", got, want)
	}
}

func TestNewEvidencePack_DeterministicHash(t *testing.T) {
	productID := NewID()
	avID := NewID()
	body := json.RawMessage(`{"a":1,"b":[true,null,"x"]}`)

	a, err := NewEvidencePack(productID, avID, 1, EvidencePackFormatJSON, body, validGeneratedBy())
	if err != nil {
		t.Fatalf("first NewEvidencePack: %v", err)
	}
	b, err := NewEvidencePack(productID, avID, 1, EvidencePackFormatJSON, body, validGeneratedBy())
	if err != nil {
		t.Fatalf("second NewEvidencePack: %v", err)
	}
	if a.ContentHash != b.ContentHash {
		t.Errorf("hashes differ across constructions: %s vs %s", a.ContentHash, b.ContentHash)
	}
	if a.ID == b.ID {
		t.Error("IDs should be unique per pack")
	}

	// Different content produces a different hash.
	c, err := NewEvidencePack(productID, avID, 1, EvidencePackFormatJSON, json.RawMessage(`{"a":2}`), validGeneratedBy())
	if err != nil {
		t.Fatalf("third NewEvidencePack: %v", err)
	}
	if a.ContentHash == c.ContentHash {
		t.Errorf("different content produced same hash %q", a.ContentHash)
	}
}

func TestNewEvidencePack_ContentDefensiveCopy(t *testing.T) {
	src := []byte(`{"k":"v"}`)
	p, err := NewEvidencePack(NewID(), NewID(), 1, EvidencePackFormatJSON, json.RawMessage(src), validGeneratedBy())
	if err != nil {
		t.Fatalf("NewEvidencePack: %v", err)
	}
	hashBefore := p.ContentHash
	// Mutate the caller's slice; the persisted Content must be unaffected.
	for i := range src {
		src[i] = 'x'
	}
	if got := p.Hash(); got != hashBefore {
		t.Errorf("post-mutation Hash() = %q, want %q (caller-slice mutation must not affect pack)", got, hashBefore)
	}
}
