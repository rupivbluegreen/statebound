// Package handlers — domain → wire JSON projections.
//
// Every API response goes through one of these WireX/ToX helpers so:
//   - Time fields are RFC3339-UTC.
//   - Sensitive fields (private bytes, key refs, password material) are
//     never serialised. SigningKey responses are the canonical example:
//     PrivateKey, PrivateKeyRef are dropped here, not at the handler
//     layer, so a future handler that copy-pastes the wrong projection
//     can't accidentally leak.
//   - Domain shape changes (extra fields on a struct) don't leak into
//     the public API surface unless we add them here.
//
// These types are exported because the api package consumes them too
// (e.g. for tests and for the openapi.yaml generator if we ever build
// one). The encoders themselves are pure — no I/O, no global state.
package handlers

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// rfc3339 returns t formatted as RFC3339 in UTC. Used everywhere we
// emit a timestamp.
func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// rfc3339Ptr returns *string-encoded RFC3339 of t, or nil if t is nil.
// JSON encodes nil as `null` (not "" or omitted) when the field is
// declared as *string in the wire struct.
func rfc3339Ptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := rfc3339(*t)
	return &s
}

// WireActor is the JSON projection of domain.Actor.
type WireActor struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
}

// ToActor projects a domain.Actor to its wire shape.
func ToActor(a domain.Actor) WireActor {
	return WireActor{Kind: string(a.Kind), Subject: a.Subject}
}

// WireProduct is the JSON projection of domain.Product.
type WireProduct struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// ToProduct projects a domain.Product to its wire shape.
func ToProduct(p *domain.Product) WireProduct {
	return WireProduct{
		ID:          string(p.ID),
		Name:        p.Name,
		Owner:       p.Owner,
		Description: p.Description,
		CreatedAt:   rfc3339(p.CreatedAt),
		UpdatedAt:   rfc3339(p.UpdatedAt),
	}
}

// WireChangeSet is the JSON projection of domain.ChangeSet.
type WireChangeSet struct {
	ID                      string    `json:"id"`
	ProductID               string    `json:"product_id"`
	State                   string    `json:"state"`
	Title                   string    `json:"title"`
	Description             string    `json:"description,omitempty"`
	RequestedBy             WireActor `json:"requested_by"`
	ParentApprovedVersionID *string   `json:"parent_approved_version_id"`
	SubmittedAt             *string   `json:"submitted_at"`
	DecidedAt               *string   `json:"decided_at"`
	DecisionReason          string    `json:"decision_reason,omitempty"`
	CreatedAt               string    `json:"created_at"`
	UpdatedAt               string    `json:"updated_at"`
}

// ToChangeSet projects a domain.ChangeSet to its wire shape.
func ToChangeSet(cs *domain.ChangeSet) WireChangeSet {
	v := WireChangeSet{
		ID:             string(cs.ID),
		ProductID:      string(cs.ProductID),
		State:          string(cs.State),
		Title:          cs.Title,
		Description:    cs.Description,
		RequestedBy:    ToActor(cs.RequestedBy),
		SubmittedAt:    rfc3339Ptr(cs.SubmittedAt),
		DecidedAt:      rfc3339Ptr(cs.DecidedAt),
		DecisionReason: cs.DecisionReason,
		CreatedAt:      rfc3339(cs.CreatedAt),
		UpdatedAt:      rfc3339(cs.UpdatedAt),
	}
	if cs.ParentApprovedVersionID != nil {
		s := string(*cs.ParentApprovedVersionID)
		v.ParentApprovedVersionID = &s
	}
	return v
}

// WireChangeSetItem is the JSON projection of domain.ChangeSetItem.
type WireChangeSetItem struct {
	ID           string         `json:"id"`
	ChangeSetID  string         `json:"change_set_id"`
	Kind         string         `json:"kind"`
	Action       string         `json:"action"`
	ResourceName string         `json:"resource_name"`
	Before       map[string]any `json:"before"`
	After        map[string]any `json:"after"`
	CreatedAt    string         `json:"created_at"`
}

// ToChangeSetItem projects a domain.ChangeSetItem to its wire shape.
func ToChangeSetItem(it *domain.ChangeSetItem) WireChangeSetItem {
	return WireChangeSetItem{
		ID:           string(it.ID),
		ChangeSetID:  string(it.ChangeSetID),
		Kind:         string(it.Kind),
		Action:       string(it.Action),
		ResourceName: it.ResourceName,
		Before:       it.Before,
		After:        it.After,
		CreatedAt:    rfc3339(it.CreatedAt),
	}
}

// WireChangeSetDetail is the JSON projection of a ChangeSet plus its
// items. Used by the "get change set" endpoint.
type WireChangeSetDetail struct {
	WireChangeSet
	Items []WireChangeSetItem `json:"items"`
}

// WireAuditEvent is the JSON projection of domain.AuditEvent.
type WireAuditEvent struct {
	ID           string         `json:"id"`
	Kind         string         `json:"kind"`
	Actor        WireActor      `json:"actor"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Payload      map[string]any `json:"payload,omitempty"`
	OccurredAt   string         `json:"occurred_at"`
	PrevHash     string         `json:"prev_hash,omitempty"`
	Hash         string         `json:"hash,omitempty"`
}

// ToAuditEvent projects a domain.AuditEvent to its wire shape.
func ToAuditEvent(e *domain.AuditEvent) WireAuditEvent {
	return WireAuditEvent{
		ID:           string(e.ID),
		Kind:         string(e.Kind),
		Actor:        ToActor(e.Actor),
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		Payload:      e.Payload,
		OccurredAt:   rfc3339(e.OccurredAt),
		PrevHash:     e.PrevHash,
		Hash:         e.Hash,
	}
}

// WireEvidencePack is the JSON projection of domain.EvidencePack.
type WireEvidencePack struct {
	ID                string          `json:"id"`
	ProductID         string          `json:"product_id"`
	ApprovedVersionID string          `json:"approved_version_id"`
	Sequence          int64           `json:"sequence"`
	Format            string          `json:"format"`
	ContentHash       string          `json:"content_hash"`
	Content           json.RawMessage `json:"content,omitempty"`
	GeneratedAt       string          `json:"generated_at"`
	GeneratedBy       WireActor       `json:"generated_by"`
}

// ToEvidencePack returns the metadata projection (no Content). Used by
// list endpoints where content bytes would bloat the response.
func ToEvidencePack(p *domain.EvidencePack) WireEvidencePack {
	return WireEvidencePack{
		ID:                string(p.ID),
		ProductID:         string(p.ProductID),
		ApprovedVersionID: string(p.ApprovedVersionID),
		Sequence:          p.Sequence,
		Format:            p.Format,
		ContentHash:       p.ContentHash,
		GeneratedAt:       rfc3339(p.GeneratedAt),
		GeneratedBy:       ToActor(p.GeneratedBy),
	}
}

// ToEvidencePackWithContent returns the full projection including the
// raw Content bytes. Used by the get-by-id endpoint.
func ToEvidencePackWithContent(p *domain.EvidencePack) WireEvidencePack {
	v := ToEvidencePack(p)
	v.Content = p.Content
	return v
}

// WirePlan is the JSON projection of domain.Plan.
type WirePlan struct {
	ID                string    `json:"id"`
	ProductID         string    `json:"product_id"`
	ApprovedVersionID string    `json:"approved_version_id"`
	Sequence          int64     `json:"sequence"`
	ConnectorName     string    `json:"connector_name"`
	ConnectorVersion  string    `json:"connector_version"`
	State             string    `json:"state"`
	Summary           string    `json:"summary,omitempty"`
	ContentHash       string    `json:"content_hash"`
	GeneratedAt       string    `json:"generated_at"`
	GeneratedBy       WireActor `json:"generated_by"`
	RefusedReason     string    `json:"refused_reason,omitempty"`
}

// ToPlan projects a domain.Plan to its wire shape.
func ToPlan(p *domain.Plan) WirePlan {
	return WirePlan{
		ID:                string(p.ID),
		ProductID:         string(p.ProductID),
		ApprovedVersionID: string(p.ApprovedVersionID),
		Sequence:          p.Sequence,
		ConnectorName:     p.ConnectorName,
		ConnectorVersion:  p.ConnectorVersion,
		State:             string(p.State),
		Summary:           p.Summary,
		ContentHash:       p.ContentHash,
		GeneratedAt:       rfc3339(p.GeneratedAt),
		GeneratedBy:       ToActor(p.GeneratedBy),
		RefusedReason:     p.RefusedReason,
	}
}

// WirePlanItem is the JSON projection of domain.PlanItem.
type WirePlanItem struct {
	ID           string          `json:"id"`
	PlanID       string          `json:"plan_id"`
	Sequence     int             `json:"sequence"`
	Action       string          `json:"action"`
	ResourceKind string          `json:"resource_kind"`
	ResourceRef  string          `json:"resource_ref"`
	Body         json.RawMessage `json:"body,omitempty"`
	Risk         string          `json:"risk,omitempty"`
	Note         string          `json:"note,omitempty"`
}

// ToPlanItem projects a domain.PlanItem to its wire shape.
func ToPlanItem(it *domain.PlanItem) WirePlanItem {
	return WirePlanItem{
		ID:           string(it.ID),
		PlanID:       string(it.PlanID),
		Sequence:     it.Sequence,
		Action:       it.Action,
		ResourceKind: it.ResourceKind,
		ResourceRef:  it.ResourceRef,
		Body:         it.Body,
		Risk:         it.Risk,
		Note:         it.Note,
	}
}

// WirePlanDetail is the JSON projection of a plan + its items.
type WirePlanDetail struct {
	WirePlan
	Items []WirePlanItem `json:"items"`
}

// WireDriftScan is the JSON projection of domain.DriftScan.
type WireDriftScan struct {
	ID                string    `json:"id"`
	ProductID         string    `json:"product_id"`
	ApprovedVersionID string    `json:"approved_version_id"`
	Sequence          int64     `json:"sequence"`
	ConnectorName     string    `json:"connector_name"`
	ConnectorVersion  string    `json:"connector_version"`
	State             string    `json:"state"`
	SourceRef         string    `json:"source_ref"`
	StartedAt         string    `json:"started_at"`
	FinishedAt        *string   `json:"finished_at"`
	InitiatedBy       WireActor `json:"initiated_by"`
	FailureMessage    string    `json:"failure_message,omitempty"`
	SummaryHash       string    `json:"summary_hash,omitempty"`
	FindingCount      int       `json:"finding_count"`
}

// ToDriftScan projects a domain.DriftScan to its wire shape.
func ToDriftScan(d *domain.DriftScan) WireDriftScan {
	return WireDriftScan{
		ID:                string(d.ID),
		ProductID:         string(d.ProductID),
		ApprovedVersionID: string(d.ApprovedVersionID),
		Sequence:          d.Sequence,
		ConnectorName:     d.ConnectorName,
		ConnectorVersion:  d.ConnectorVersion,
		State:             string(d.State),
		SourceRef:         d.SourceRef,
		StartedAt:         rfc3339(d.StartedAt),
		FinishedAt:        rfc3339Ptr(d.FinishedAt),
		InitiatedBy:       ToActor(d.InitiatedBy),
		FailureMessage:    d.FailureMessage,
		SummaryHash:       d.SummaryHash,
		FindingCount:      d.FindingCount,
	}
}

// WireDriftFinding is the JSON projection of domain.DriftFinding.
type WireDriftFinding struct {
	ID           string          `json:"id"`
	ScanID       string          `json:"scan_id"`
	Sequence     int             `json:"sequence"`
	Kind         string          `json:"kind"`
	Severity     string          `json:"severity"`
	ResourceKind string          `json:"resource_kind"`
	ResourceRef  string          `json:"resource_ref"`
	Desired      json.RawMessage `json:"desired,omitempty"`
	Actual       json.RawMessage `json:"actual,omitempty"`
	Diff         json.RawMessage `json:"diff,omitempty"`
	Message      string          `json:"message,omitempty"`
	DetectedAt   string          `json:"detected_at"`
}

// ToDriftFinding projects a domain.DriftFinding to its wire shape.
func ToDriftFinding(f *domain.DriftFinding) WireDriftFinding {
	return WireDriftFinding{
		ID:           string(f.ID),
		ScanID:       string(f.ScanID),
		Sequence:     f.Sequence,
		Kind:         string(f.Kind),
		Severity:     string(f.Severity),
		ResourceKind: f.ResourceKind,
		ResourceRef:  f.ResourceRef,
		Desired:      f.Desired,
		Actual:       f.Actual,
		Diff:         f.Diff,
		Message:      f.Message,
		DetectedAt:   rfc3339(f.DetectedAt),
	}
}

// WireDriftScanDetail is the JSON projection of a drift scan + its
// findings.
type WireDriftScanDetail struct {
	WireDriftScan
	Findings []WireDriftFinding `json:"findings"`
}

// WirePolicyDecision is the JSON projection of
// storage.PolicyDecisionRecord.
type WirePolicyDecision struct {
	ID          string          `json:"id"`
	ChangeSetID string          `json:"change_set_id"`
	Phase       string          `json:"phase"`
	Outcome     string          `json:"outcome"`
	Rules       json.RawMessage `json:"rules,omitempty"`
	Input       json.RawMessage `json:"input,omitempty"`
	BundleHash  string          `json:"bundle_hash"`
	EvaluatedAt string          `json:"evaluated_at"`
}

// ToPolicyDecision projects a storage.PolicyDecisionRecord to its wire
// shape.
func ToPolicyDecision(rec *storage.PolicyDecisionRecord) WirePolicyDecision {
	return WirePolicyDecision{
		ID:          string(rec.ID),
		ChangeSetID: string(rec.ChangeSetID),
		Phase:       rec.Phase,
		Outcome:     rec.Outcome,
		Rules:       rec.Rules,
		Input:       rec.Input,
		BundleHash:  rec.BundleHash,
		EvaluatedAt: rfc3339(rec.EvaluatedAt),
	}
}

// WireSigningKey is the JSON projection of domain.SigningKey.
//
// IMPORTANT: PrivateKey and PrivateKeyRef are NEVER serialised. Adding
// either to this struct would defeat the wave-A "DB never holds secret
// material" invariant.
type WireSigningKey struct {
	KeyID       string    `json:"key_id"`
	Algorithm   string    `json:"algorithm"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   string    `json:"created_at"`
	CreatedBy   WireActor `json:"created_by"`
	ExpiresAt   *string   `json:"expires_at"`
	Disabled    bool      `json:"disabled"`
	Note        string    `json:"note,omitempty"`
	LastUsedAt  *string   `json:"last_used_at"`
}

// ToSigningKey projects a domain.SigningKey to its wire shape. Only
// public material is included; the caller is trusted to pass a
// SigningKey loaded by the storage layer (which never populates
// PrivateKey).
func ToSigningKey(k *domain.SigningKey) WireSigningKey {
	return WireSigningKey{
		KeyID:       k.KeyID,
		Algorithm:   k.Algorithm,
		PublicKey:   base64.StdEncoding.EncodeToString(k.PublicKey),
		Fingerprint: k.Fingerprint,
		CreatedAt:   rfc3339(k.CreatedAt),
		CreatedBy:   ToActor(k.CreatedBy),
		ExpiresAt:   rfc3339Ptr(k.ExpiresAt),
		Disabled:    k.Disabled,
		Note:        k.Note,
		LastUsedAt:  rfc3339Ptr(k.LastUsedAt),
	}
}

// WirePlanApplyRecord is the JSON projection of domain.PlanApplyRecord.
type WirePlanApplyRecord struct {
	ID             string          `json:"id"`
	PlanID         string          `json:"plan_id"`
	State          string          `json:"state"`
	StartedAt      string          `json:"started_at"`
	FinishedAt     *string         `json:"finished_at"`
	Actor          WireActor       `json:"actor"`
	Target         string          `json:"target"`
	DryRun         bool            `json:"dry_run"`
	AppliedItems   int             `json:"applied_items"`
	FailedItems    int             `json:"failed_items"`
	FailureMessage string          `json:"failure_message,omitempty"`
	SummaryHash    string          `json:"summary_hash,omitempty"`
	Output         json.RawMessage `json:"output,omitempty"`
}

// ToPlanApplyRecord projects a domain.PlanApplyRecord to its wire shape.
func ToPlanApplyRecord(r *domain.PlanApplyRecord) WirePlanApplyRecord {
	return WirePlanApplyRecord{
		ID:             string(r.ID),
		PlanID:         string(r.PlanID),
		State:          string(r.State),
		StartedAt:      rfc3339(r.StartedAt),
		FinishedAt:     rfc3339Ptr(r.FinishedAt),
		Actor:          ToActor(r.Actor),
		Target:         r.Target,
		DryRun:         r.DryRun,
		AppliedItems:   r.AppliedItems,
		FailedItems:    r.FailedItems,
		FailureMessage: r.FailureMessage,
		SummaryHash:    r.SummaryHash,
		Output:         r.Output,
	}
}

// Page is the standard paginated wrapper. Cursor-based pagination
// arrives in a later wave; v0.8 uses limit-bounded single-page
// responses with NextCursor always nil.
type Page struct {
	Items      any     `json:"items"`
	Count      int     `json:"count"`
	NextCursor *string `json:"next_cursor"`
}

// PageOf wraps a slice in the standard envelope. Always preserves the
// non-nil "items" array so clients can range without nil-checks.
func PageOf[T any](items []T) Page {
	out := items
	if out == nil {
		out = []T{}
	}
	return Page{Items: out, Count: len(out), NextCursor: nil}
}
