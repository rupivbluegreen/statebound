package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// EvidencePackFormat enumerates the persisted on-disk evidence-pack formats.
// Both formats are stored as JSONB rows in evidence_packs; the Markdown form is
// wrapped in a JSON envelope ({"format":"markdown","body":"..."}) so the
// content column is always parseable JSON. The Format string drives the CHECK
// constraint in migrations/0005_evidence_packs.sql.
const (
	EvidencePackFormatJSON     = "json"
	EvidencePackFormatMarkdown = "markdown"
)

// Sentinel errors for EvidencePack validation.
var (
	ErrEvidencePackNotFound             = errors.New("domain: evidence pack not found")
	ErrEvidencePackInvalid              = errors.New("domain: evidence pack invalid")
	ErrEvidencePackFormatInvalid        = errors.New("domain: evidence pack format invalid")
	ErrEvidencePackProductIDRequired    = errors.New("domain: evidence pack product id is required")
	ErrEvidencePackVersionIDRequired    = errors.New("domain: evidence pack approved version id is required")
	ErrEvidencePackSequenceInvalid      = errors.New("domain: evidence pack sequence must be >= 1")
	ErrEvidencePackContentEmpty         = errors.New("domain: evidence pack content is empty")
	ErrEvidencePackContentNotJSON       = errors.New("domain: evidence pack content is not valid JSON")
)

// EvidencePack is the auditable bundle exported per ApprovedVersion. The pack
// is deterministic (same input → byte-identical content hash) and immutable
// (one row per (approved_version_id, format, content_hash) — re-export rather
// than mutate). The Content field is the canonical JSON bytes the storage
// layer persists; the engine package owns how those bytes are produced for
// each Format. ContentHash is the SHA-256 of Content, hex-encoded.
type EvidencePack struct {
	ID                ID
	ProductID         ID
	ApprovedVersionID ID
	Sequence          int64           // mirrors ApprovedVersion.Sequence for fast lookup
	Format            string          // EvidencePackFormatJSON or EvidencePackFormatMarkdown
	ContentHash       string          // SHA-256 hex of Content
	Content           json.RawMessage // canonical JSON bytes (Markdown is wrapped in a JSON envelope)
	GeneratedAt       time.Time
	GeneratedBy       Actor
}

// validEvidencePackFormat reports whether s is one of the persisted formats.
func validEvidencePackFormat(s string) bool {
	switch s {
	case EvidencePackFormatJSON, EvidencePackFormatMarkdown:
		return true
	default:
		return false
	}
}

// NewEvidencePack constructs and validates an EvidencePack with a fresh ID,
// the canonical content hash, and a UTC timestamp. Content must be non-empty
// and parseable JSON; the storage layer enforces JSONB and the same CHECK on
// the format column. Use the result as-is — do not mutate Content afterward,
// or the persisted hash will diverge from the bytes on disk.
func NewEvidencePack(productID, approvedVersionID ID, sequence int64, format string, content json.RawMessage, generatedBy Actor) (*EvidencePack, error) {
	if productID == "" {
		return nil, ErrEvidencePackProductIDRequired
	}
	if approvedVersionID == "" {
		return nil, ErrEvidencePackVersionIDRequired
	}
	if sequence < 1 {
		return nil, ErrEvidencePackSequenceInvalid
	}
	if !validEvidencePackFormat(format) {
		return nil, fmt.Errorf("%w: %q", ErrEvidencePackFormatInvalid, format)
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrEvidencePackInvalid, ErrEvidencePackContentEmpty)
	}
	if !json.Valid(content) {
		return nil, fmt.Errorf("%w: %w", ErrEvidencePackInvalid, ErrEvidencePackContentNotJSON)
	}
	if err := generatedBy.Validate(); err != nil {
		return nil, err
	}

	// Defensive copy of content so the caller cannot mutate Content out from
	// under the persisted hash.
	buf := make([]byte, len(content))
	copy(buf, content)

	sum := sha256.Sum256(buf)
	return &EvidencePack{
		ID:                NewID(),
		ProductID:         productID,
		ApprovedVersionID: approvedVersionID,
		Sequence:          sequence,
		Format:            format,
		ContentHash:       hex.EncodeToString(sum[:]),
		Content:           buf,
		GeneratedAt:       time.Now().UTC(),
		GeneratedBy:       generatedBy,
	}, nil
}

// Hash recomputes the SHA-256 hex of Content. Defense-in-depth: tests use this
// to assert the persisted ContentHash matches the bytes on hand. If the bytes
// have been mutated post-construction the recomputed value will diverge.
func (p *EvidencePack) Hash() string {
	if p == nil {
		return ""
	}
	sum := sha256.Sum256(p.Content)
	return hex.EncodeToString(sum[:])
}
