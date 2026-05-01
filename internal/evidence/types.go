// Package evidence assembles deterministic, auditable EvidencePack content
// from approved-version artifacts. It is read-only against storage: the
// caller (CLI) owns persistence via domain.NewEvidencePack and the
// EvidencePackStore.
//
// The bytes produced by this package are part of the public contract.
// Field order, key names, and types are fixed; changes invalidate every
// previously-emitted ContentHash. Exporters in this package re-canonicalise
// every JSONB blob they pull from storage so the same input yields
// byte-identical bytes regardless of how Postgres or pgx happened to
// serialise the row.
package evidence

import (
	"encoding/json"
	"time"

	"statebound.dev/statebound/internal/domain"
)

// SchemaVersion identifies the on-the-wire shape of a PackContent. Bumping
// this string is a breaking change: every evidence pack hashed under the
// previous version must be regenerated to match the new shape.
const SchemaVersion = "evidence.statebound.dev/v1alpha1"

// PackContent is the canonical JSON shape of an evidence pack's bytes.
//
// Field order is fixed; the encoder relies on Go's struct-field encoding
// order to emit deterministic JSON. Every json.RawMessage in this struct
// (Snapshot, ChangeSetItemRef.Before/After, AuditEventRef.Payload,
// PolicyDecisionRef.Rules) is canonicalised by the builder before it
// reaches a PackContent value, so encoding the same PackContent twice
// yields byte-identical output.
type PackContent struct {
	SchemaVersion   string              `json:"schema_version"`
	GeneratedAt     time.Time           `json:"generated_at"`
	Product         ProductRef          `json:"product"`
	ApprovedVersion ApprovedVersionRef  `json:"approved_version"`
	SourceChangeSet *ChangeSetRef       `json:"source_change_set,omitempty"`
	Snapshot        json.RawMessage     `json:"snapshot"`
	Approvals       []ApprovalRef       `json:"approvals"`
	Items           []ChangeSetItemRef  `json:"items"`
	AuditEvents     []AuditEventRef     `json:"audit_events"`
	PolicyDecisions []PolicyDecisionRef `json:"policy_decisions"`
}

// ProductRef is the Product subset preserved in an evidence pack.
type ProductRef struct {
	ID          domain.ID `json:"id"`
	Name        string    `json:"name"`
	Owner       string    `json:"owner"`
	Description string    `json:"description,omitempty"`
}

// ActorRef is the canonical-JSON projection of a domain.Actor used inside
// an evidence pack. domain.Actor has no JSON tags (it is a pure domain
// type); we project it with snake_case keys so the persisted bytes are
// auditor-friendly and stable independent of any future change to
// domain.Actor's struct shape.
type ActorRef struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
}

// fromDomainActor projects a domain.Actor into the canonical ActorRef.
func fromDomainActor(a domain.Actor) ActorRef {
	return ActorRef{Kind: string(a.Kind), Subject: a.Subject}
}

// ApprovedVersionRef captures the ApprovedVersion identity and the
// approver-of-record. The Reason field is sourced from
// ApprovedVersion.Description (the optional human note attached at
// approval time); callers needing the underlying ChangeSet decision
// reason should look at SourceChangeSet.
type ApprovedVersionRef struct {
	ID                domain.ID  `json:"id"`
	Sequence          int64      `json:"sequence"`
	SnapshotID        domain.ID  `json:"snapshot_id"`
	SnapshotHash      string     `json:"snapshot_hash"`
	ParentVersionID   *domain.ID `json:"parent_version_id,omitempty"`
	SourceChangeSetID domain.ID  `json:"source_change_set_id"`
	ApprovedBy        ActorRef   `json:"approved_by"`
	ApprovedAt        time.Time  `json:"approved_at"`
	Reason            string     `json:"reason,omitempty"`
}

// ChangeSetRef captures the ChangeSet that produced this approved version.
type ChangeSetRef struct {
	ID          domain.ID  `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	State       string     `json:"state"`
	RequestedBy ActorRef   `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
}

// ApprovalRef preserves a single approval decision attached to the source
// ChangeSet.
type ApprovalRef struct {
	ID        domain.ID `json:"id"`
	Decision  string    `json:"decision"`
	Actor     ActorRef  `json:"actor"`
	Reason    string    `json:"reason,omitempty"`
	DecidedAt time.Time `json:"decided_at"`
}

// ChangeSetItemRef preserves a single mutation captured by the source
// ChangeSet. Before and After are canonical JSON; Add items omit Before,
// Delete items omit After.
type ChangeSetItemRef struct {
	ID           domain.ID       `json:"id"`
	Action       string          `json:"action"`
	Kind         string          `json:"kind"`
	ResourceName string          `json:"resource_name"`
	Before       json.RawMessage `json:"before,omitempty"`
	After        json.RawMessage `json:"after,omitempty"`
}

// AuditEventRef preserves a relevant audit event in canonical form. The
// Sequence field is the 1-indexed ordinal position within the pack's
// AuditEvents slice (events are sorted by OccurredAt asc, then ID asc),
// not a column in the audit_events table — the underlying log uses the
// hash chain for ordering integrity.
type AuditEventRef struct {
	ID           domain.ID       `json:"id"`
	Kind         string          `json:"kind"`
	Actor        ActorRef        `json:"actor"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	OccurredAt   time.Time       `json:"occurred_at"`
	Sequence     int64           `json:"sequence"`
	Hash         string          `json:"hash"`
	PrevHash     string          `json:"prev_hash"`
	Payload      json.RawMessage `json:"payload"`
}

// PolicyDecisionRef preserves an OPA evaluation cross-referenced from the
// ChangeSet. Rules is the canonical per-rule verdict array produced by
// internal/authz; the full input is intentionally NOT included in the pack
// to avoid duplicating the ChangeSet body.
type PolicyDecisionRef struct {
	ID          domain.ID       `json:"id"`
	Phase       string          `json:"phase"`
	Outcome     string          `json:"outcome"`
	BundleHash  string          `json:"bundle_hash"`
	Rules       json.RawMessage `json:"rules"`
	EvaluatedAt time.Time       `json:"evaluated_at"`
}
