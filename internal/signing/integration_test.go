package signing_test

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/signing"
)

// TestEndToEnd_SignThenVerify is the in-memory integration test the
// agent prompt asks for: a plan signed and verified end-to-end via an
// in-memory key, plus the negative path (tampered content fails).
func TestEndToEnd_SignThenVerify(t *testing.T) {
	priv, pub, err := signing.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("key sizes wrong: priv=%d pub=%d", len(priv), len(pub))
	}

	// Build a plausible plan content payload (mirrors what the connector
	// would produce). We sign these bytes; verification later rejects any
	// drift.
	planContent := []byte(`{"connector":"linux-sudo","items":[{"action":"create","resource":"alice"}]}`)

	sig, err := signing.Sign(planContent, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("Sign returned %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	// Verify via the public half — the apply path does the same.
	if err := signing.Verify(planContent, sig, pub); err != nil {
		t.Fatalf("Verify (good content): %v", err)
	}

	// Tamper detection: any byte change rejects.
	tampered := append([]byte(nil), planContent...)
	tampered[0] ^= 0x80
	err = signing.Verify(tampered, sig, pub)
	if !errors.Is(err, domain.ErrPlanSignatureVerificationFailed) {
		t.Fatalf("tampered Verify error = %v, want ErrPlanSignatureVerificationFailed", err)
	}

	// Domain wrapper: the PlanSignature type only accepts well-formed
	// inputs, exercising the cross-cutting validation contract.
	planID := domain.NewID()
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"}
	ps, err := domain.NewPlanSignature(planID, "release-2026-q2", domain.AlgorithmEd25519, sig, actor)
	if err != nil {
		t.Fatalf("NewPlanSignature: %v", err)
	}
	if ps.PlanID != planID {
		t.Errorf("PlanID = %q, want %q", ps.PlanID, planID)
	}
	if len(ps.Signature) != ed25519.SignatureSize {
		t.Errorf("PlanSignature.Signature length = %d, want %d", len(ps.Signature), ed25519.SignatureSize)
	}
}
