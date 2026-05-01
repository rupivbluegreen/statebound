package domain_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
)

func newEd25519Pair(t *testing.T) (pub, priv []byte) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return []byte(pubKey), []byte(privKey)
}

func TestNewPlanSignature_HappyPath(t *testing.T) {
	planID := domain.NewID()
	sig := make([]byte, ed25519.SignatureSize)
	for i := range sig {
		sig[i] = byte(i)
	}
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"}
	got, err := domain.NewPlanSignature(planID, "release-2026-q2", "ed25519", sig, actor)
	if err != nil {
		t.Fatalf("NewPlanSignature: %v", err)
	}
	if got.ID == "" {
		t.Error("ID is empty")
	}
	if got.PlanID != planID {
		t.Errorf("PlanID = %q, want %q", got.PlanID, planID)
	}
	if got.KeyID != "release-2026-q2" {
		t.Errorf("KeyID = %q", got.KeyID)
	}
	if got.Algorithm != "ed25519" {
		t.Errorf("Algorithm = %q", got.Algorithm)
	}
	if len(got.Signature) != ed25519.SignatureSize {
		t.Errorf("Signature size = %d, want %d", len(got.Signature), ed25519.SignatureSize)
	}
	if got.SignedAt.IsZero() {
		t.Error("SignedAt is zero")
	}
	// Defensive copy: mutating caller's bytes does not affect the stored copy.
	sig[0] ^= 0xff
	if got.Signature[0] == sig[0] {
		t.Error("PlanSignature did not defensively copy signature bytes")
	}
}

func TestNewPlanSignature_Validation(t *testing.T) {
	goodPlan := domain.NewID()
	goodSig := make([]byte, ed25519.SignatureSize)
	goodActor := domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"}

	tests := []struct {
		name  string
		plan  domain.ID
		key   string
		alg   string
		sig   []byte
		actor domain.Actor
		want  error
	}{
		{"missing plan id", "", "k", "ed25519", goodSig, goodActor, domain.ErrPlanSignaturePlanIDRequired},
		{"missing key id", goodPlan, "", "ed25519", goodSig, goodActor, domain.ErrPlanSignatureKeyIDRequired},
		{"wrong algorithm", goodPlan, "k", "rsa", goodSig, goodActor, domain.ErrPlanSignatureAlgorithmInvalid},
		{"sig too short", goodPlan, "k", "ed25519", make([]byte, 32), goodActor, domain.ErrPlanSignatureBytesInvalid},
		{"sig too long", goodPlan, "k", "ed25519", make([]byte, 128), goodActor, domain.ErrPlanSignatureBytesInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := domain.NewPlanSignature(tc.plan, tc.key, tc.alg, tc.sig, tc.actor)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewPlanSignature_RejectsInvalidActor(t *testing.T) {
	_, err := domain.NewPlanSignature(domain.NewID(), "k", "ed25519", make([]byte, ed25519.SignatureSize), domain.Actor{})
	if err == nil {
		t.Fatal("expected error from invalid actor")
	}
}

func TestNewSigningKey_HappyPath(t *testing.T) {
	pub, priv := newEd25519Pair(t)
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "ops@example.com"}
	expires := time.Now().Add(90 * 24 * time.Hour).UTC()
	k, err := domain.NewSigningKey(
		"release-2026-q2",
		"ed25519",
		pub,
		priv,
		"sha256:abc",
		"file:/tmp/k.pem",
		actor,
		&expires,
		"quarterly release key",
	)
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	if k.KeyID != "release-2026-q2" {
		t.Errorf("KeyID = %q", k.KeyID)
	}
	if len(k.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("PublicKey size = %d, want %d", len(k.PublicKey), ed25519.PublicKeySize)
	}
	if len(k.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("PrivateKey size = %d, want %d", len(k.PrivateKey), ed25519.PrivateKeySize)
	}
	if k.PrivateKeyRef != "file:/tmp/k.pem" {
		t.Errorf("PrivateKeyRef = %q", k.PrivateKeyRef)
	}
	if !k.IsActive(time.Now()) {
		t.Error("freshly minted key should be active")
	}
}

func TestNewSigningKey_Validation(t *testing.T) {
	pub, priv := newEd25519Pair(t)
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "ops@example.com"}

	tests := []struct {
		name string
		mod  func() error
		want error
	}{
		{"missing key id", func() error {
			_, err := domain.NewSigningKey("", "ed25519", pub, priv, "sha256:f", "file:/tmp/k.pem", actor, nil, "")
			return err
		}, domain.ErrSigningKeyIDRequired},
		{"wrong algorithm", func() error {
			_, err := domain.NewSigningKey("k", "rsa", pub, priv, "sha256:f", "file:/tmp/k.pem", actor, nil, "")
			return err
		}, domain.ErrSigningKeyAlgorithmInvalid},
		{"public key wrong length", func() error {
			_, err := domain.NewSigningKey("k", "ed25519", make([]byte, 16), priv, "sha256:f", "file:/tmp/k.pem", actor, nil, "")
			return err
		}, domain.ErrSigningKeyPublicKeyInvalid},
		{"private key wrong length", func() error {
			_, err := domain.NewSigningKey("k", "ed25519", pub, make([]byte, 16), "sha256:f", "file:/tmp/k.pem", actor, nil, "")
			return err
		}, domain.ErrSigningKeyPrivateKeyInvalid},
		{"missing private key ref", func() error {
			_, err := domain.NewSigningKey("k", "ed25519", pub, priv, "sha256:f", "", actor, nil, "")
			return err
		}, domain.ErrSigningKeyPrivateKeyRefRequired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.mod()
			if err == nil {
				t.Fatalf("expected error %v, got nil", tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSigningKey_IsActive(t *testing.T) {
	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	tests := []struct {
		name string
		k    *domain.SigningKey
		want bool
	}{
		{"nil", nil, false},
		{"fresh", &domain.SigningKey{}, true},
		{"disabled", &domain.SigningKey{Disabled: true}, false},
		{"expired", &domain.SigningKey{ExpiresAt: &past}, false},
		{"expiring future", &domain.SigningKey{ExpiresAt: &future}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.k.IsActive(now); got != tc.want {
				t.Errorf("IsActive = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestSigningKey_AcceptsEmptyPrivateKey(t *testing.T) {
	pub, _ := newEd25519Pair(t)
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "ops@example.com"}
	k, err := domain.NewSigningKey("k", "ed25519", pub, nil, "sha256:f", "file:/tmp/k.pem", actor, nil, "")
	if err != nil {
		t.Fatalf("NewSigningKey with nil private key: %v", err)
	}
	if len(k.PrivateKey) != 0 {
		t.Errorf("PrivateKey should be empty when not supplied, got %d bytes", len(k.PrivateKey))
	}
}
