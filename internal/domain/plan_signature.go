// Package domain — signed plan bundles (Phase 8 wave A).
//
// A PlanSignature is an Ed25519 signature over a plan's canonical content
// bytes (the same bytes that produce Plan.ContentHash). Multiple
// signatures per plan are allowed (multi-signer flow); the Apply gate
// requires at least one valid signature unless
// STATEBOUND_DEV_SKIP_PLAN_SIGNATURE is set.
//
// A SigningKey is a logically-named Ed25519 keypair. Only the public
// half lives in the database; the private half is loaded at signing
// time from a "private_key_ref" string ("file:..." or "env:...") so the
// database never holds the secret. The PrivateKey field on this struct
// is a transient in-memory value used by the CLI between key generation
// and signing — it is never serialised by the storage layer.
package domain

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// PlanSignature is an Ed25519 signature over a plan's canonical content
// bytes. Multiple signatures per plan are allowed; the Apply gate
// requires at least one valid signature unless dev-skip is enabled.
type PlanSignature struct {
	ID        ID
	PlanID    ID
	KeyID     string    // logical key name from the keystore
	Algorithm string    // "ed25519" — only one supported in v0.7
	Signature []byte    // raw signature bytes (64 bytes for ed25519)
	SignedBy  Actor     // human or service account that issued the signature
	SignedAt  time.Time
}

// SigningKey is a logically-named Ed25519 keypair. PrivateKey is a
// transient in-memory value: it is populated only when the key has just
// been generated or freshly loaded from a private_key_ref. The storage
// layer never persists PrivateKey, and PrivateKey MUST NOT appear in
// API responses, audit events, or evidence packs.
type SigningKey struct {
	KeyID         string
	Algorithm     string  // "ed25519"
	PublicKey     []byte  // 32 bytes
	PrivateKey    []byte  // 64 bytes; transient — never persisted, never logged
	Fingerprint   string  // sha256:<hex> of the public key, for human display
	PrivateKeyRef string  // "file:<path>" | "env:<name>"
	CreatedBy     Actor
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	Disabled      bool
	Note          string
	LastUsedAt    *time.Time
}

// Sentinel errors for plan signatures and signing keys.
var (
	ErrPlanSignatureInvalid            = errors.New("domain: plan signature invalid")
	ErrPlanSignatureNotFound           = errors.New("domain: plan signature not found")
	ErrPlanSignatureExpired            = errors.New("domain: plan signature key has expired")
	ErrPlanSignatureVerificationFailed = errors.New("domain: plan signature verification failed")
	ErrSigningKeyNotFound              = errors.New("domain: signing key not found")
	ErrSigningKeyExpired               = errors.New("domain: signing key has expired")
	ErrSigningKeyDisabled              = errors.New("domain: signing key is disabled")

	ErrPlanSignatureKeyIDRequired      = errors.New("domain: plan signature key id is required")
	ErrPlanSignatureAlgorithmInvalid   = errors.New("domain: plan signature algorithm must be ed25519")
	ErrPlanSignatureBytesInvalid       = errors.New("domain: plan signature bytes must be 64 bytes")
	ErrPlanSignaturePlanIDRequired     = errors.New("domain: plan signature plan id is required")

	ErrSigningKeyIDRequired            = errors.New("domain: signing key id is required")
	ErrSigningKeyAlgorithmInvalid      = errors.New("domain: signing key algorithm must be ed25519")
	ErrSigningKeyPublicKeyInvalid      = errors.New("domain: signing key public key must be 32 bytes")
	ErrSigningKeyPrivateKeyInvalid     = errors.New("domain: signing key private key must be 64 bytes when present")
	ErrSigningKeyPrivateKeyRefRequired = errors.New("domain: signing key private_key_ref is required")
)

// AlgorithmEd25519 is the only signature algorithm supported in v0.7.
const AlgorithmEd25519 = "ed25519"

// NewPlanSignature constructs and validates a PlanSignature with a
// fresh ID and a UTC-now SignedAt. Algorithm must be "ed25519", keyID
// must be non-empty, and signature must be exactly 64 bytes (Ed25519
// signature size).
func NewPlanSignature(planID ID, keyID, algorithm string, signature []byte, signedBy Actor) (*PlanSignature, error) {
	if planID == "" {
		return nil, ErrPlanSignaturePlanIDRequired
	}
	if keyID == "" {
		return nil, ErrPlanSignatureKeyIDRequired
	}
	if algorithm != AlgorithmEd25519 {
		return nil, fmt.Errorf("%w: %q", ErrPlanSignatureAlgorithmInvalid, algorithm)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: got %d", ErrPlanSignatureBytesInvalid, len(signature))
	}
	if err := signedBy.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, len(signature))
	copy(buf, signature)
	return &PlanSignature{
		ID:        NewID(),
		PlanID:    planID,
		KeyID:     keyID,
		Algorithm: algorithm,
		Signature: buf,
		SignedBy:  signedBy,
		SignedAt:  time.Now().UTC(),
	}, nil
}

// IsActive reports whether the key may be used to issue new signatures
// at instant t. A nil receiver is never active.
func (k *SigningKey) IsActive(t time.Time) bool {
	if k == nil {
		return false
	}
	if k.Disabled {
		return false
	}
	if k.ExpiresAt != nil && !k.ExpiresAt.After(t) {
		return false
	}
	return true
}

// IsValidForVerification reports whether the key may be used to verify
// a signature at instant t. Callers that want strict apply-time
// behaviour should refuse signatures issued by disabled or expired
// keys; this helper centralises that policy.
func (k *SigningKey) IsValidForVerification(t time.Time) bool {
	return k.IsActive(t)
}

// NewSigningKey constructs and validates a SigningKey. The public key
// must be exactly 32 bytes (ed25519.PublicKeySize). When privateKey is
// supplied (newly-generated key, just-loaded key) it must be exactly
// 64 bytes; the storage layer drops it before persisting. CreatedAt is
// set to UTC now.
func NewSigningKey(keyID, algorithm string, publicKey, privateKey []byte, fingerprint, privateKeyRef string, createdBy Actor, expiresAt *time.Time, note string) (*SigningKey, error) {
	if keyID == "" {
		return nil, ErrSigningKeyIDRequired
	}
	if algorithm != AlgorithmEd25519 {
		return nil, fmt.Errorf("%w: %q", ErrSigningKeyAlgorithmInvalid, algorithm)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d", ErrSigningKeyPublicKeyInvalid, len(publicKey))
	}
	if len(privateKey) != 0 && len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d", ErrSigningKeyPrivateKeyInvalid, len(privateKey))
	}
	if privateKeyRef == "" {
		return nil, ErrSigningKeyPrivateKeyRefRequired
	}
	if fingerprint == "" {
		return nil, fmt.Errorf("%w: fingerprint required", ErrPlanSignatureInvalid)
	}
	if err := createdBy.Validate(); err != nil {
		return nil, err
	}
	pub := make([]byte, len(publicKey))
	copy(pub, publicKey)
	var priv []byte
	if len(privateKey) > 0 {
		priv = make([]byte, len(privateKey))
		copy(priv, privateKey)
	}
	return &SigningKey{
		KeyID:         keyID,
		Algorithm:     algorithm,
		PublicKey:     pub,
		PrivateKey:    priv,
		Fingerprint:   fingerprint,
		PrivateKeyRef: privateKeyRef,
		CreatedBy:     createdBy,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     expiresAt,
		Disabled:      false,
		Note:          note,
	}, nil
}
