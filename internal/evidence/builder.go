package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// builderClock is the time source the builder uses for PackContent.GeneratedAt.
// Production code uses time.Now; tests inject a fixed clock so the canonical
// bytes are byte-identical across runs.
type builderClock func() time.Time

// BuilderStore is the narrow read-only slice of storage.Storage the
// Builder actually uses. Production code passes a storage.Storage (which
// satisfies this interface implicitly); tests pass a small fake that
// implements only these methods. Defining the interface here keeps the
// dependency surface explicit and avoids coupling tests to the full
// 50-method storage boundary.
type BuilderStore interface {
	GetLatestApprovedVersion(ctx context.Context, productID domain.ID) (*domain.ApprovedVersion, *domain.ApprovedVersionSnapshot, error)
	GetApprovedVersionByID(ctx context.Context, id domain.ID) (*domain.ApprovedVersion, *domain.ApprovedVersionSnapshot, error)
	ListApprovedVersions(ctx context.Context, productID domain.ID, limit int) ([]*domain.ApprovedVersion, error)
	GetProductByID(ctx context.Context, id domain.ID) (*domain.Product, error)
	GetChangeSetByID(ctx context.Context, id domain.ID) (*domain.ChangeSet, error)
	ListChangeSetItems(ctx context.Context, csID domain.ID) ([]*domain.ChangeSetItem, error)
	ListApprovalsByChangeSet(ctx context.Context, csID domain.ID) ([]*domain.Approval, error)
	ListPolicyDecisionsByChangeSet(ctx context.Context, csID domain.ID) ([]*storage.PolicyDecisionRecord, error)
	ListAuditEvents(ctx context.Context, f storage.AuditFilter) ([]*domain.AuditEvent, error)
	// ListDriftScansByProduct returns every drift scan recorded against
	// productID newest first. The builder filters to the pack's approved
	// version and drops any scan that does not match.
	ListDriftScansByProduct(ctx context.Context, productID domain.ID, limit int) ([]*domain.DriftScan, error)
	// GetDriftScanByID is used to load each filtered scan's findings; the
	// list call returns scan metadata only.
	GetDriftScanByID(ctx context.Context, id domain.ID) (*domain.DriftScan, []*domain.DriftFinding, error)
	// ListPlansByApprovedVersion returns every plan generated against the
	// pack's approved version. Phase 6 uses this to find plans whose
	// apply records belong in the pack.
	ListPlansByApprovedVersion(ctx context.Context, approvedVersionID domain.ID) ([]*domain.Plan, error)
	// ListPlanApplyRecordsByPlan returns every apply attempt (dry-run or
	// real) against planID, newest first. Phase 6 uses this to inline
	// applies into the pack alongside the parent plan's drift scans.
	ListPlanApplyRecordsByPlan(ctx context.Context, planID domain.ID) ([]*domain.PlanApplyRecord, error)
}

// Builder assembles a PackContent from the data layer. It is read-only
// against storage and does not write the EvidencePack — the caller (CLI)
// owns persistence via domain.NewEvidencePack and the EvidencePackStore.
//
// A Builder pulls only deterministic, immutable artifacts: the approved
// version snapshot, its source ChangeSet, the items and approvals attached
// to that ChangeSet, the policy decisions evaluated against it, and the
// audit events keyed off those resource ids. Re-running BuildLatest /
// BuildBySequence / BuildByVersionID against the same inputs yields the
// same PackContent, which yields byte-identical bytes from EncodeJSON.
type Builder struct {
	store BuilderStore
	now   builderClock
}

// NewBuilder constructs a Builder backed by store.
func NewBuilder(store BuilderStore) *Builder {
	return &Builder{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// WithClock returns a copy of b that uses now as its time source for
// PackContent.GeneratedAt. Used by tests to pin a fixed timestamp into
// the canonical bytes.
func (b *Builder) WithClock(now func() time.Time) *Builder {
	cp := *b
	cp.now = now
	return &cp
}

// BuildLatest builds a PackContent for the latest approved version of the
// given product. It returns an error if no approved version exists.
func (b *Builder) BuildLatest(ctx context.Context, productID domain.ID) (*PackContent, error) {
	if productID == "" {
		return nil, fmt.Errorf("evidence: build latest: product id is required")
	}
	av, snap, err := b.store.GetLatestApprovedVersion(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("evidence: build latest: load approved version: %w", err)
	}
	product, err := b.store.GetProductByID(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("evidence: build latest: load product: %w", err)
	}
	return b.buildFor(ctx, av, snap, product)
}

// BuildBySequence builds for a specific approved-version sequence within
// the product. It scans ListApprovedVersions for the matching row and
// loads its snapshot via GetApprovedVersionByID.
func (b *Builder) BuildBySequence(ctx context.Context, productID domain.ID, seq int64) (*PackContent, error) {
	if productID == "" {
		return nil, fmt.Errorf("evidence: build by sequence: product id is required")
	}
	if seq < 1 {
		return nil, fmt.Errorf("evidence: build by sequence: sequence must be >= 1")
	}
	versions, err := b.store.ListApprovedVersions(ctx, productID, 0)
	if err != nil {
		return nil, fmt.Errorf("evidence: build by sequence: list approved versions: %w", err)
	}
	var match *domain.ApprovedVersion
	for _, v := range versions {
		if v.Sequence == seq {
			match = v
			break
		}
	}
	if match == nil {
		return nil, fmt.Errorf("evidence: build by sequence: no approved version with sequence %d for product %s: %w", seq, productID, storage.ErrNotFound)
	}
	av, snap, err := b.store.GetApprovedVersionByID(ctx, match.ID)
	if err != nil {
		return nil, fmt.Errorf("evidence: build by sequence: load approved version %s: %w", match.ID, err)
	}
	product, err := b.store.GetProductByID(ctx, av.ProductID)
	if err != nil {
		return nil, fmt.Errorf("evidence: build by sequence: load product: %w", err)
	}
	return b.buildFor(ctx, av, snap, product)
}

// BuildByVersionID builds for a specific approved-version id.
func (b *Builder) BuildByVersionID(ctx context.Context, approvedVersionID domain.ID) (*PackContent, error) {
	if approvedVersionID == "" {
		return nil, fmt.Errorf("evidence: build by version id: approved version id is required")
	}
	av, snap, err := b.store.GetApprovedVersionByID(ctx, approvedVersionID)
	if err != nil {
		return nil, fmt.Errorf("evidence: build by version id: load approved version: %w", err)
	}
	product, err := b.store.GetProductByID(ctx, av.ProductID)
	if err != nil {
		return nil, fmt.Errorf("evidence: build by version id: load product: %w", err)
	}
	return b.buildFor(ctx, av, snap, product)
}

// buildFor is the single assembly path. Every build entry point delegates
// here, so the determinism story has exactly one implementation to verify.
func (b *Builder) buildFor(
	ctx context.Context,
	av *domain.ApprovedVersion,
	snap *domain.ApprovedVersionSnapshot,
	product *domain.Product,
) (*PackContent, error) {
	if av == nil || snap == nil || product == nil {
		return nil, fmt.Errorf("evidence: build for: nil approved version, snapshot, or product")
	}

	// 1. Source ChangeSet.
	cs, err := b.store.GetChangeSetByID(ctx, av.SourceChangeSetID)
	if err != nil {
		return nil, fmt.Errorf("evidence: load source change set %s: %w", av.SourceChangeSetID, err)
	}

	// 2. ChangeSet items.
	items, err := b.store.ListChangeSetItems(ctx, cs.ID)
	if err != nil {
		return nil, fmt.Errorf("evidence: list change set items: %w", err)
	}

	// 3. Approvals.
	approvals, err := b.store.ListApprovalsByChangeSet(ctx, cs.ID)
	if err != nil {
		return nil, fmt.Errorf("evidence: list approvals: %w", err)
	}

	// 4. Policy decisions.
	decisions, err := b.store.ListPolicyDecisionsByChangeSet(ctx, cs.ID)
	if err != nil {
		return nil, fmt.Errorf("evidence: list policy decisions: %w", err)
	}

	// 5. Audit events. Pull every event keyed off the change_set, the
	//    approved_version, and each approval id, then merge, dedupe, and
	//    sort deterministically. We intentionally do NOT pull events
	//    keyed off the product or arbitrary item rows: those would shift
	//    over time and violate the "same input -> same bytes" contract.
	auditEvents, err := b.collectAuditEvents(ctx, cs.ID, av.ID, approvals)
	if err != nil {
		return nil, fmt.Errorf("evidence: collect audit events: %w", err)
	}

	// 6. Canonicalise the snapshot. Storage hands us map[string]any; we
	//    re-encode through the local canonical writer so the snapshot
	//    bytes are stable regardless of map iteration order.
	snapBytes, err := CanonicalizeMap(snap.Content)
	if err != nil {
		return nil, fmt.Errorf("evidence: canonicalize snapshot: %w", err)
	}

	// 7. Build refs.
	pack := &PackContent{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   b.now().UTC(),
		Product: ProductRef{
			ID:          product.ID,
			Name:        product.Name,
			Owner:       product.Owner,
			Description: product.Description,
		},
		ApprovedVersion: ApprovedVersionRef{
			ID:                av.ID,
			Sequence:          av.Sequence,
			SnapshotID:        snap.ID,
			SnapshotHash:      snap.ContentHash,
			ParentVersionID:   av.ParentVersionID,
			SourceChangeSetID: av.SourceChangeSetID,
			ApprovedBy:        fromDomainActor(av.ApprovedBy),
			ApprovedAt:        av.CreatedAt.UTC(),
			Reason:            av.Description,
		},
		SourceChangeSet: changeSetRef(cs),
		Snapshot:        snapBytes,
		Approvals:       approvalRefs(approvals),
	}

	pack.Items, err = changeSetItemRefs(items)
	if err != nil {
		return nil, err
	}
	pack.AuditEvents, err = auditEventRefs(auditEvents)
	if err != nil {
		return nil, err
	}
	pack.PolicyDecisions, err = policyDecisionRefs(decisions)
	if err != nil {
		return nil, err
	}

	// 8. Drift scans (Phase 4'). We list every scan against the product
	//    via ListDriftScansByProduct (limit 0 = no limit) and filter to
	//    those whose ApprovedVersionID matches the pack's. Each scan
	//    matches we re-load via GetDriftScanByID to fetch the findings,
	//    then sort the result deterministically by StartedAt asc.
	pack.DriftScans, err = b.collectDriftScans(ctx, av)
	if err != nil {
		return nil, fmt.Errorf("evidence: collect drift scans: %w", err)
	}

	// 9. Apply records (Phase 6). Plans -> ApplyRecords is one-to-many.
	//    We list every plan against the AV and collect the apply records
	//    for each, then sort the merged result deterministically.
	pack.ApplyRecords, err = b.collectApplyRecords(ctx, av)
	if err != nil {
		return nil, fmt.Errorf("evidence: collect apply records: %w", err)
	}

	return pack, nil
}

// collectApplyRecords gathers every PlanApplyRecord against any plan
// targeting av's approved version. The result is ordered by StartedAt
// asc (then ID asc) so two builds emit byte-identical bytes regardless
// of the storage layer's ordering choices.
//
// Output blobs (rec.Output) are pre-canonicalised so the canonical bytes
// are stable across backends.
func (b *Builder) collectApplyRecords(ctx context.Context, av *domain.ApprovedVersion) ([]ApplyRecordRef, error) {
	plans, err := b.store.ListPlansByApprovedVersion(ctx, av.ID)
	if err != nil {
		return nil, fmt.Errorf("list plans by approved version: %w", err)
	}
	out := make([]ApplyRecordRef, 0)
	for _, plan := range plans {
		if plan == nil {
			continue
		}
		records, err := b.store.ListPlanApplyRecordsByPlan(ctx, plan.ID)
		if err != nil {
			return nil, fmt.Errorf("list plan apply records for plan %s: %w", plan.ID, err)
		}
		for _, rec := range records {
			if rec == nil {
				continue
			}
			ref, err := applyRecordRef(rec)
			if err != nil {
				return nil, err
			}
			out = append(out, ref)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].StartedAt, out[j].StartedAt
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// applyRecordRef projects a PlanApplyRecord into the pack-facing ref.
// The Output blob is canonicalised so the bytes are stable regardless
// of how Postgres serialised the JSONB row.
func applyRecordRef(rec *domain.PlanApplyRecord) (ApplyRecordRef, error) {
	out := ApplyRecordRef{
		ID:             rec.ID,
		PlanID:         rec.PlanID,
		State:          string(rec.State),
		DryRun:         rec.DryRun,
		Target:         rec.Target,
		StartedAt:      rec.StartedAt.UTC(),
		AppliedItems:   rec.AppliedItems,
		FailedItems:    rec.FailedItems,
		SummaryHash:    rec.SummaryHash,
		FailureMessage: rec.FailureMessage,
	}
	if rec.FinishedAt != nil {
		t := rec.FinishedAt.UTC()
		out.FinishedAt = &t
	}
	if len(rec.Output) > 0 {
		canonical, err := Canonicalize(rec.Output)
		if err != nil {
			return ApplyRecordRef{}, fmt.Errorf("canonicalize apply record %s output: %w", rec.ID, err)
		}
		// Empty objects are kept as "{}" so the column is stably present;
		// only nil/empty input becomes the zero RawMessage (omitempty
		// elides it from the wire shape).
		if string(canonical) != "" {
			out.Output = canonical
		}
	}
	return out, nil
}

// collectDriftScans loads every scan against av's product, filters to the
// pack's approved version id, then re-loads each match to fetch findings.
// The result is ordered by StartedAt asc so two builds emit byte-identical
// bytes regardless of the storage layer's ordering choices.
//
// We intentionally drop scans that match a different ApprovedVersionID
// (the same product can have many approved versions, each with their own
// scans). Always emitting an empty slice rather than nil keeps the wire
// shape stable for downstream tooling.
func (b *Builder) collectDriftScans(ctx context.Context, av *domain.ApprovedVersion) ([]DriftScanRef, error) {
	scans, err := b.store.ListDriftScansByProduct(ctx, av.ProductID, 0)
	if err != nil {
		return nil, fmt.Errorf("list drift scans: %w", err)
	}
	matched := make([]*domain.DriftScan, 0, len(scans))
	for _, s := range scans {
		if s == nil {
			continue
		}
		if s.ApprovedVersionID != av.ID {
			continue
		}
		matched = append(matched, s)
	}
	out := make([]DriftScanRef, 0, len(matched))
	for _, scan := range matched {
		_, findings, err := b.store.GetDriftScanByID(ctx, scan.ID)
		if err != nil {
			return nil, fmt.Errorf("load drift scan %s: %w", scan.ID, err)
		}
		ref, err := driftScanRef(scan, findings)
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].StartedAt, out[j].StartedAt
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// driftScanRef projects a domain.DriftScan + its findings into the
// pack-facing DriftScanRef. Finding bodies are canonicalised so the bytes
// are stable regardless of how Postgres serialised the JSONB rows.
func driftScanRef(scan *domain.DriftScan, findings []*domain.DriftFinding) (DriftScanRef, error) {
	ref := DriftScanRef{
		ID:               scan.ID,
		ConnectorName:    scan.ConnectorName,
		ConnectorVersion: scan.ConnectorVersion,
		SourceRef:        scan.SourceRef,
		State:            string(scan.State),
		StartedAt:        scan.StartedAt.UTC(),
		SummaryHash:      scan.SummaryHash,
		FindingCount:     scan.FindingCount,
	}
	if scan.FinishedAt != nil {
		t := scan.FinishedAt.UTC()
		ref.FinishedAt = &t
	}
	out := make([]DriftFindingRef, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		desired, err := canonicaliseRawMessage(f.Desired)
		if err != nil {
			return DriftScanRef{}, fmt.Errorf("canonicalize finding %s desired: %w", f.ID, err)
		}
		actual, err := canonicaliseRawMessage(f.Actual)
		if err != nil {
			return DriftScanRef{}, fmt.Errorf("canonicalize finding %s actual: %w", f.ID, err)
		}
		diff, err := canonicaliseRawMessage(f.Diff)
		if err != nil {
			return DriftScanRef{}, fmt.Errorf("canonicalize finding %s diff: %w", f.ID, err)
		}
		// Diff is NOT NULL in the storage layer; default empty {} for the
		// pack so the field is always present.
		if len(diff) == 0 {
			diff = json.RawMessage("{}")
		}
		out = append(out, DriftFindingRef{
			Sequence:     f.Sequence,
			Kind:         string(f.Kind),
			Severity:     string(f.Severity),
			ResourceKind: f.ResourceKind,
			ResourceRef:  f.ResourceRef,
			Desired:      desired,
			Actual:       actual,
			Diff:         diff,
			Message:      f.Message,
			DetectedAt:   f.DetectedAt.UTC(),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Sequence < out[j].Sequence
	})
	ref.Findings = out
	return ref, nil
}

// canonicaliseRawMessage runs a JSONB blob through the local Canonicalize
// emitter so map keys are sorted at every level. Empty/nil input returns
// nil so omitempty fields elide cleanly at marshal time.
func canonicaliseRawMessage(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	return Canonicalize(raw)
}

// collectAuditEvents fetches every audit event keyed off the change set,
// the approved version, or any of the approvals, then de-duplicates by
// event id and orders the result deterministically (occurred_at asc, then
// id asc).
func (b *Builder) collectAuditEvents(
	ctx context.Context,
	csID domain.ID,
	avID domain.ID,
	approvals []*domain.Approval,
) ([]*domain.AuditEvent, error) {
	type key struct{ rt, rid string }
	keys := []key{
		{"change_set", string(csID)},
		{"approved_version", string(avID)},
	}
	for _, a := range approvals {
		keys = append(keys, key{"approval", string(a.ID)})
	}

	seen := make(map[domain.ID]struct{})
	out := make([]*domain.AuditEvent, 0)
	for _, k := range keys {
		evs, err := b.store.ListAuditEvents(ctx, storage.AuditFilter{
			ResourceType: k.rt,
			ResourceID:   k.rid,
		})
		if err != nil {
			return nil, fmt.Errorf("list audit events for %s/%s: %w", k.rt, k.rid, err)
		}
		for _, e := range evs {
			if _, ok := seen[e.ID]; ok {
				continue
			}
			seen[e.ID] = struct{}{}
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].OccurredAt.UTC(), out[j].OccurredAt.UTC()
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// changeSetRef projects a ChangeSet into the pack-facing ref. Returns nil
// if cs is nil so the caller can omit the SourceChangeSet field cleanly.
func changeSetRef(cs *domain.ChangeSet) *ChangeSetRef {
	if cs == nil {
		return nil
	}
	requested := cs.CreatedAt.UTC()
	if cs.SubmittedAt != nil {
		requested = cs.SubmittedAt.UTC()
	}
	var decided *time.Time
	if cs.DecidedAt != nil {
		t := cs.DecidedAt.UTC()
		decided = &t
	}
	return &ChangeSetRef{
		ID:          cs.ID,
		Title:       cs.Title,
		Description: cs.Description,
		State:       string(cs.State),
		RequestedBy: fromDomainActor(cs.RequestedBy),
		RequestedAt: requested,
		DecidedAt:   decided,
	}
}

// approvalRefs projects an approval list and orders deterministically.
func approvalRefs(approvals []*domain.Approval) []ApprovalRef {
	out := make([]ApprovalRef, 0, len(approvals))
	for _, a := range approvals {
		if a == nil {
			continue
		}
		out = append(out, ApprovalRef{
			ID:        a.ID,
			Decision:  string(a.Decision),
			Actor:     fromDomainActor(a.Approver),
			Reason:    a.Reason,
			DecidedAt: a.DecidedAt.UTC(),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].DecidedAt, out[j].DecidedAt
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// changeSetItemRefs canonicalises every item Before/After blob and orders
// deterministically by (kind, action, resource_name, id).
func changeSetItemRefs(items []*domain.ChangeSetItem) ([]ChangeSetItemRef, error) {
	out := make([]ChangeSetItemRef, 0, len(items))
	for _, it := range items {
		if it == nil {
			continue
		}
		before, err := CanonicalizeMap(it.Before)
		if err != nil {
			return nil, fmt.Errorf("evidence: canonicalize item %s before: %w", it.ID, err)
		}
		after, err := CanonicalizeMap(it.After)
		if err != nil {
			return nil, fmt.Errorf("evidence: canonicalize item %s after: %w", it.ID, err)
		}
		// Drop "null" (i.e., it.Before == nil for an Add) so omitempty
		// can elide the field at marshal time. We keep non-nil maps even
		// if they encode to "{}" for symmetry with Update items.
		if it.Before == nil {
			before = nil
		}
		if it.After == nil {
			after = nil
		}
		out = append(out, ChangeSetItemRef{
			ID:           it.ID,
			Action:       string(it.Action),
			Kind:         string(it.Kind),
			ResourceName: it.ResourceName,
			Before:       before,
			After:        after,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		if out[i].ResourceName != out[j].ResourceName {
			return out[i].ResourceName < out[j].ResourceName
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// auditEventRefs assigns 1-indexed sequence numbers and canonicalises
// payloads. The input slice is assumed to be deterministically ordered by
// the caller (collectAuditEvents).
func auditEventRefs(events []*domain.AuditEvent) ([]AuditEventRef, error) {
	out := make([]AuditEventRef, 0, len(events))
	for i, e := range events {
		if e == nil {
			continue
		}
		payload, err := CanonicalizeMap(e.Payload)
		if err != nil {
			return nil, fmt.Errorf("evidence: canonicalize audit payload %s: %w", e.ID, err)
		}
		// Empty payloads (nil map) become "null" — keep that explicit so
		// the field is always present. Auditors expect the column even
		// when there is nothing to show.
		out = append(out, AuditEventRef{
			ID:           e.ID,
			Kind:         string(e.Kind),
			Actor:        fromDomainActor(e.Actor),
			ResourceType: e.ResourceType,
			ResourceID:   e.ResourceID,
			OccurredAt:   e.OccurredAt.UTC(),
			Sequence:     int64(i + 1),
			Hash:         e.Hash,
			PrevHash:     e.PrevHash,
			Payload:      payload,
		})
	}
	return out, nil
}

// policyDecisionRefs canonicalises Rules blobs and orders by EvaluatedAt
// asc, then id asc, so the pack is reproducible regardless of the storage
// layer's default ordering.
func policyDecisionRefs(decisions []*storage.PolicyDecisionRecord) ([]PolicyDecisionRef, error) {
	out := make([]PolicyDecisionRef, 0, len(decisions))
	for _, d := range decisions {
		if d == nil {
			continue
		}
		var rules json.RawMessage
		if len(d.Rules) > 0 {
			r, err := Canonicalize(d.Rules)
			if err != nil {
				return nil, fmt.Errorf("evidence: canonicalize policy rules %s: %w", d.ID, err)
			}
			rules = r
		} else {
			rules = json.RawMessage("null")
		}
		out = append(out, PolicyDecisionRef{
			ID:          d.ID,
			Phase:       d.Phase,
			Outcome:     d.Outcome,
			BundleHash:  d.BundleHash,
			Rules:       rules,
			EvaluatedAt: d.EvaluatedAt.UTC(),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].EvaluatedAt, out[j].EvaluatedAt
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
