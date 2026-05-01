// Package signing provides Ed25519 signature primitives for Statebound's
// signed plan bundles (Phase 8 wave A).
//
// Sign produces a 64-byte Ed25519 signature over content. Verify accepts
// content+signature+publicKey and returns nil on a valid signature, or
// domain.ErrPlanSignatureVerificationFailed on a mismatch. Generate
// produces a fresh keypair using crypto/rand. Fingerprint hashes a
// public key into a stable, human-displayable identifier.
//
// This package never logs the raw private key bytes and never includes
// them in any error message. Callers that load the private key are
// responsible for keeping the bytes off disk and out of logs.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"statebound.dev/statebound/internal/domain"
)

// Sign returns a 64-byte Ed25519 signature over content using the given
// 64-byte private key. The caller is responsible for loading the key
// (e.g. from a private_key_ref) and zeroing the bytes after use.
func Sign(content, privKey []byte) ([]byte, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privKey))
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privKey), content)
	out := make([]byte, len(sig))
	copy(out, sig)
	return out, nil
}

// Verify returns nil if signature is a valid Ed25519 signature over
// content under pubKey, otherwise it returns
// domain.ErrPlanSignatureVerificationFailed. Wrong-length inputs surface
// as a clear, non-sentinel error so the caller can distinguish a malformed
// request from a tampered payload.
func Verify(content, signature, pubKey []byte) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("signing: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pubKey))
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("signing: signature must be %d bytes, got %d", ed25519.SignatureSize, len(signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey), content, signature) {
		return domain.ErrPlanSignatureVerificationFailed
	}
	return nil
}

// Fingerprint returns a stable, human-displayable identifier for a
// public key: "sha256:" + lowercase hex of SHA-256(pubKey). The
// fingerprint is what an operator sees in `statebound key list` and
// what an audit reviewer correlates against a signature row.
func Fingerprint(pubKey []byte) string {
	sum := sha256.Sum256(pubKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Generate produces a fresh Ed25519 keypair from crypto/rand. The
// returned slices have len == ed25519.PrivateKeySize (64) and
// ed25519.PublicKeySize (32) respectively.
func Generate() (privKey, pubKey []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: generate ed25519 key: %w", err)
	}
	return []byte(priv), []byte(pub), nil
}
