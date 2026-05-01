package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const approvedVersionDescriptionMaxLen = 4096

// Sentinel errors for ApprovedVersion and ApprovedVersionSnapshot validation.
var (
	ErrApprovedVersionProductIDRequired       = errors.New("domain: approved version product id is required")
	ErrApprovedVersionSequenceInvalid         = errors.New("domain: approved version sequence must be >= 1")
	ErrApprovedVersionSourceChangeSetRequired = errors.New("domain: approved version source change set id is required")
	ErrApprovedVersionSnapshotIDRequired      = errors.New("domain: approved version snapshot id is required")
	ErrApprovedVersionDescriptionTooLong      = errors.New("domain: approved version description exceeds 4096 characters")
	ErrApprovedVersionSnapshotContentRequired = errors.New("domain: approved version snapshot content is required")
)

// ApprovedVersion is an immutable approved desired-state revision for a Product.
// Sequence is monotonic per product, starting at 1. ParentVersionID is nil for
// the first version.
type ApprovedVersion struct {
	ID                ID
	ProductID         ID
	Sequence          int64
	ParentVersionID   *ID
	SourceChangeSetID ID
	ApprovedBy        Actor
	Description       string
	SnapshotID        ID
	CreatedAt         time.Time
}

// ApprovedVersionSnapshot is the full ProductAuthorizationModel content
// captured at approval time. The struct is immutable once constructed: there
// is no Update constructor or method, and callers must not mutate Content
// after NewApprovedVersionSnapshot returns. ContentHash is derived from
// Content via canonical JSON + SHA-256 and is stable across machines.
type ApprovedVersionSnapshot struct {
	ID          ID
	Content     map[string]any
	ContentHash string
	CreatedAt   time.Time
}

// NewApprovedVersion constructs and validates an ApprovedVersion.
func NewApprovedVersion(productID, snapshotID ID, sequence int64, parent *ID, sourceCS ID, approvedBy Actor, description string) (*ApprovedVersion, error) {
	v := &ApprovedVersion{
		ID:                NewID(),
		ProductID:         productID,
		Sequence:          sequence,
		ParentVersionID:   parent,
		SourceChangeSetID: sourceCS,
		ApprovedBy:        approvedBy,
		Description:       description,
		SnapshotID:        snapshotID,
		CreatedAt:         time.Now().UTC(),
	}
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return v, nil
}

// Validate enforces ApprovedVersion invariants.
func (v *ApprovedVersion) Validate() error {
	if v.ProductID == "" {
		return ErrApprovedVersionProductIDRequired
	}
	if v.Sequence < 1 {
		return ErrApprovedVersionSequenceInvalid
	}
	if v.SourceChangeSetID == "" {
		return ErrApprovedVersionSourceChangeSetRequired
	}
	if err := v.ApprovedBy.Validate(); err != nil {
		return err
	}
	if v.SnapshotID == "" {
		return ErrApprovedVersionSnapshotIDRequired
	}
	if len(v.Description) > approvedVersionDescriptionMaxLen {
		return ErrApprovedVersionDescriptionTooLong
	}
	return nil
}

// NewApprovedVersionSnapshot constructs an immutable snapshot, computing the
// canonical-JSON SHA-256 content hash.
func NewApprovedVersionSnapshot(content map[string]any) (*ApprovedVersionSnapshot, error) {
	if content == nil {
		return nil, ErrApprovedVersionSnapshotContentRequired
	}
	raw, err := canonicalJSON(content)
	if err != nil {
		return nil, fmt.Errorf("domain: snapshot canonical json: %w", err)
	}
	sum := sha256.Sum256(raw)
	return &ApprovedVersionSnapshot{
		ID:          NewID(),
		Content:     content,
		ContentHash: hex.EncodeToString(sum[:]),
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// canonicalJSON encodes v as JSON with object keys sorted lexicographically at
// every nesting level. Output is byte-stable across Go runs and machines.
// json.Marshal already sorts map[string]string and map[string]any keys
// alphabetically, but explicit walk-and-encode keeps the contract local.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		// Primitives (string, bool, numeric) and any other JSON-encodable value.
		out, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(out)
		return nil
	}
}
