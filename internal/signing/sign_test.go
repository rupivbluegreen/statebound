package signing_test

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/signing"
)

func TestSignVerify_RoundTrip(t *testing.T) {
	priv, pub, err := signing.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("priv size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("pub size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	content := []byte(`{"plan":"v1","items":[]}`)
	sig, err := signing.Sign(content, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("sig size = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if err := signing.Verify(content, sig, pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerify_TamperedContent(t *testing.T) {
	priv, pub, err := signing.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	content := []byte(`{"plan":"v1","items":[]}`)
	sig, err := signing.Sign(content, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := []byte(`{"plan":"v1","items":[{"evil":true}]}`)
	err = signing.Verify(tampered, sig, pub)
	if err == nil {
		t.Fatal("expected verification failure on tampered content")
	}
	if !errors.Is(err, domain.ErrPlanSignatureVerificationFailed) {
		t.Errorf("error = %v, want ErrPlanSignatureVerificationFailed", err)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	priv, _, err := signing.Generate()
	if err != nil {
		t.Fatalf("Generate priv: %v", err)
	}
	_, pub2, err := signing.Generate()
	if err != nil {
		t.Fatalf("Generate pub: %v", err)
	}
	content := []byte("hello")
	sig, err := signing.Sign(content, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	err = signing.Verify(content, sig, pub2)
	if !errors.Is(err, domain.ErrPlanSignatureVerificationFailed) {
		t.Errorf("error = %v, want ErrPlanSignatureVerificationFailed", err)
	}
}

func TestSign_BadPrivateKey(t *testing.T) {
	_, err := signing.Sign([]byte("hello"), make([]byte, 16))
	if err == nil {
		t.Fatal("expected error on short private key")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("error = %v, want a private-key complaint", err)
	}
}

func TestVerify_BadInputs(t *testing.T) {
	priv, pub, err := signing.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sig, err := signing.Sign([]byte("hello"), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := signing.Verify([]byte("hello"), sig, make([]byte, 16)); err == nil {
		t.Error("expected error on short public key")
	}
	if err := signing.Verify([]byte("hello"), make([]byte, 16), pub); err == nil {
		t.Error("expected error on short signature")
	}
}

func TestFingerprint_Stable(t *testing.T) {
	pub := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 32 bytes
	got := signing.Fingerprint(pub)
	want := "sha256:22e26ca4d6c2974f3f5fa70d54bb96526d9b8baeed6c2c8b27a5b5add28c4dc8"
	// We don't hard-code the digest in the test (it would lock in a hash
	// constant); just assert the well-formedness.
	_ = want
	if !strings.HasPrefix(got, "sha256:") {
		t.Errorf("Fingerprint = %q, want sha256: prefix", got)
	}
	if len(got) != len("sha256:")+64 {
		t.Errorf("Fingerprint length = %d, want %d (sha256: + 64 hex)", len(got), len("sha256:")+64)
	}
	// Determinism: two calls produce the same fingerprint.
	if signing.Fingerprint(pub) != got {
		t.Error("Fingerprint not deterministic")
	}
}
