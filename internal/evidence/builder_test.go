package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// fakeStore is a tiny in-memory BuilderStore for the deterministic-build
// tests. Each field is hand-populated by the test fixture below.
type fakeStore struct {
	products         map[domain.ID]*domain.Product
	versions         map[domain.ID]*domain.ApprovedVersion
	snapshots        map[domain.ID]*domain.ApprovedVersionSnapshot
	versionsByProd   map[domain.ID][]*domain.ApprovedVersion
	changeSets       map[domain.ID]*domain.ChangeSet
	itemsByCS        map[domain.ID][]*domain.ChangeSetItem
	approvalsByCS    map[domain.ID][]*domain.Approval
	decisionsByCS    map[domain.ID][]*storage.PolicyDecisionRecord
	auditByResource  map[string][]*domain.AuditEvent // key = resourceType + "|" + resourceID
	driftScansByProd map[domain.ID][]*domain.DriftScan
	driftFindings    map[domain.ID][]*domain.DriftFinding // key = scanID
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		products:         map[domain.ID]*domain.Product{},
		versions:         map[domain.ID]*domain.ApprovedVersion{},
		snapshots:        map[domain.ID]*domain.ApprovedVersionSnapshot{},
		versionsByProd:   map[domain.ID][]*domain.ApprovedVersion{},
		changeSets:       map[domain.ID]*domain.ChangeSet{},
		itemsByCS:        map[domain.ID][]*domain.ChangeSetItem{},
		approvalsByCS:    map[domain.ID][]*domain.Approval{},
		decisionsByCS:    map[domain.ID][]*storage.PolicyDecisionRecord{},
		auditByResource:  map[string][]*domain.AuditEvent{},
		driftScansByProd: map[domain.ID][]*domain.DriftScan{},
		driftFindings:    map[domain.ID][]*domain.DriftFinding{},
	}
}

func (s *fakeStore) GetLatestApprovedVersion(_ context.Context, productID domain.ID) (*domain.ApprovedVersion, *domain.ApprovedVersionSnapshot, error) {
	versions := s.versionsByProd[productID]
	if len(versions) == 0 {
		return nil, nil, storage.ErrNotFound
	}
	var latest *domain.ApprovedVersion
	for _, v := range versions {
		if latest == nil || v.Sequence > latest.Sequence {
			latest = v
		}
	}
	return latest, s.snapshots[latest.SnapshotID], nil
}

func (s *fakeStore) GetApprovedVersionByID(_ context.Context, id domain.ID) (*domain.ApprovedVersion, *domain.ApprovedVersionSnapshot, error) {
	v, ok := s.versions[id]
	if !ok {
		return nil, nil, storage.ErrNotFound
	}
	return v, s.snapshots[v.SnapshotID], nil
}

func (s *fakeStore) ListApprovedVersions(_ context.Context, productID domain.ID, _ int) ([]*domain.ApprovedVersion, error) {
	out := make([]*domain.ApprovedVersion, 0, len(s.versionsByProd[productID]))
	out = append(out, s.versionsByProd[productID]...)
	return out, nil
}

func (s *fakeStore) GetProductByID(_ context.Context, id domain.ID) (*domain.Product, error) {
	p, ok := s.products[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return p, nil
}

func (s *fakeStore) GetChangeSetByID(_ context.Context, id domain.ID) (*domain.ChangeSet, error) {
	cs, ok := s.changeSets[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cs, nil
}

func (s *fakeStore) ListChangeSetItems(_ context.Context, csID domain.ID) ([]*domain.ChangeSetItem, error) {
	out := make([]*domain.ChangeSetItem, 0, len(s.itemsByCS[csID]))
	out = append(out, s.itemsByCS[csID]...)
	return out, nil
}

func (s *fakeStore) ListApprovalsByChangeSet(_ context.Context, csID domain.ID) ([]*domain.Approval, error) {
	out := make([]*domain.Approval, 0, len(s.approvalsByCS[csID]))
	out = append(out, s.approvalsByCS[csID]...)
	return out, nil
}

func (s *fakeStore) ListPolicyDecisionsByChangeSet(_ context.Context, csID domain.ID) ([]*storage.PolicyDecisionRecord, error) {
	out := make([]*storage.PolicyDecisionRecord, 0, len(s.decisionsByCS[csID]))
	out = append(out, s.decisionsByCS[csID]...)
	return out, nil
}

func (s *fakeStore) ListAuditEvents(_ context.Context, f storage.AuditFilter) ([]*domain.AuditEvent, error) {
	if f.ResourceType == "" || f.ResourceID == "" {
		// The builder always passes both; if a future caller doesn't,
		// fail loudly so we notice.
		return nil, storage.ErrInvalidArgument
	}
	key := f.ResourceType + "|" + f.ResourceID
	out := make([]*domain.AuditEvent, 0, len(s.auditByResource[key]))
	out = append(out, s.auditByResource[key]...)
	return out, nil
}

func (s *fakeStore) ListDriftScansByProduct(_ context.Context, productID domain.ID, _ int) ([]*domain.DriftScan, error) {
	out := make([]*domain.DriftScan, 0, len(s.driftScansByProd[productID]))
	out = append(out, s.driftScansByProd[productID]...)
	return out, nil
}

func (s *fakeStore) GetDriftScanByID(_ context.Context, id domain.ID) (*domain.DriftScan, []*domain.DriftFinding, error) {
	for _, scans := range s.driftScansByProd {
		for _, scan := range scans {
			if scan.ID == id {
				return scan, s.driftFindings[id], nil
			}
		}
	}
	return nil, nil, storage.ErrDriftScanNotFound
}

// fixedFixture builds a deterministic fakeStore plus the ids needed to
// exercise the builder. All ids are stable strings so the canonical
// output is reproducible across runs.
func fixedFixture(t *testing.T) (*fakeStore, domain.ID, domain.ID, domain.ID) {
	t.Helper()
	productID := domain.ID("00000000-0000-0000-0000-000000000001")
	avID := domain.ID("00000000-0000-0000-0000-000000000002")
	snapID := domain.ID("00000000-0000-0000-0000-000000000003")
	csID := domain.ID("00000000-0000-0000-0000-000000000004")
	approvalAID := domain.ID("00000000-0000-0000-0000-00000000a001")
	approvalBID := domain.ID("00000000-0000-0000-0000-00000000a002")
	itemID := domain.ID("00000000-0000-0000-0000-00000000b001")
	decisionID := domain.ID("00000000-0000-0000-0000-00000000d001")

	ts := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	requestedAt := ts.Add(-2 * time.Hour)
	submittedAt := ts.Add(-time.Hour)
	decidedAt := ts

	s := newFakeStore()

	s.products[productID] = &domain.Product{
		ID:          productID,
		Name:        "payments-api",
		Owner:       "platform-security",
		Description: "Payments API governance product",
		CreatedAt:   ts.Add(-72 * time.Hour),
		UpdatedAt:   ts.Add(-72 * time.Hour),
	}

	snap := &domain.ApprovedVersionSnapshot{
		ID: snapID,
		Content: map[string]any{
			"apiVersion": "statebound.dev/v1alpha1",
			"kind":       "ProductAuthorizationModel",
			"metadata":   map[string]any{"product": "payments-api", "owner": "platform-security"},
			"spec": map[string]any{
				"entitlements": []any{
					map[string]any{"name": "payments-prod-readonly", "owner": "payments-team"},
				},
			},
		},
		ContentHash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		CreatedAt:   ts,
	}
	s.snapshots[snapID] = snap

	av := &domain.ApprovedVersion{
		ID:                avID,
		ProductID:         productID,
		Sequence:          1,
		ParentVersionID:   nil,
		SourceChangeSetID: csID,
		ApprovedBy:        domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"},
		Description:       "Quarterly access review approved",
		SnapshotID:        snapID,
		CreatedAt:         decidedAt,
	}
	s.versions[avID] = av
	s.versionsByProd[productID] = []*domain.ApprovedVersion{av}

	submitted := submittedAt
	decided := decidedAt
	cs := &domain.ChangeSet{
		ID:             csID,
		ProductID:      productID,
		State:          domain.ChangeSetStateApproved,
		Title:          "Add payments-prod-readonly entitlement",
		Description:    "Read-only production troubleshooting access",
		RequestedBy:    domain.Actor{Kind: domain.ActorHuman, Subject: "bob@example.com"},
		SubmittedAt:    &submitted,
		DecidedAt:      &decided,
		DecisionReason: "approved by alice",
		CreatedAt:      requestedAt,
		UpdatedAt:      decidedAt,
	}
	s.changeSets[csID] = cs

	s.itemsByCS[csID] = []*domain.ChangeSetItem{
		{
			ID:           itemID,
			ChangeSetID:  csID,
			Kind:         domain.ChangeSetItemKindEntitlement,
			Action:       domain.ChangeSetActionAdd,
			ResourceName: "payments-prod-readonly",
			After: map[string]any{
				"name":  "payments-prod-readonly",
				"owner": "payments-team",
			},
			CreatedAt: requestedAt,
		},
	}

	s.approvalsByCS[csID] = []*domain.Approval{
		{
			ID:          approvalAID,
			ChangeSetID: csID,
			Approver:    domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"},
			Decision:    domain.ApprovalDecisionApproved,
			Reason:      "",
			DecidedAt:   decidedAt,
		},
		{
			ID:          approvalBID,
			ChangeSetID: csID,
			Approver:    domain.Actor{Kind: domain.ActorHuman, Subject: "carol@example.com"},
			Decision:    domain.ApprovalDecisionApproved,
			Reason:      "Looks good",
			DecidedAt:   decidedAt.Add(time.Minute),
		},
	}

	s.decisionsByCS[csID] = []*storage.PolicyDecisionRecord{
		{
			ID:          decisionID,
			ChangeSetID: csID,
			Phase:       "submit",
			Outcome:     "escalation_required",
			Rules:       json.RawMessage(`[{"name":"production_requires_approval","outcome":"escalation_required","message":"prod entitlement detected"}]`),
			Input:       json.RawMessage(`{}`),
			BundleHash:  "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			EvaluatedAt: submittedAt,
			CreatedAt:   submittedAt,
		},
	}

	// Three audit events: created (cs), submitted (cs), approved (cs).
	mkEvent := func(id domain.ID, kind domain.EventKind, occurred time.Time, prevHash, hash string, payload map[string]any) *domain.AuditEvent {
		return &domain.AuditEvent{
			ID:           id,
			Kind:         kind,
			Actor:        domain.Actor{Kind: domain.ActorHuman, Subject: "bob@example.com"},
			ResourceType: "change_set",
			ResourceID:   string(csID),
			Payload:      payload,
			OccurredAt:   occurred,
			PrevHash:     prevHash,
			Hash:         hash,
		}
	}
	csEvents := []*domain.AuditEvent{
		mkEvent("00000000-0000-0000-0000-00000000c001", domain.EventChangeSetCreated, requestedAt, "",
			"1111111111111111111111111111111111111111111111111111111111111111",
			map[string]any{"title": "Add payments-prod-readonly entitlement"}),
		mkEvent("00000000-0000-0000-0000-00000000c002", domain.EventChangeSetSubmitted, submittedAt,
			"1111111111111111111111111111111111111111111111111111111111111111",
			"2222222222222222222222222222222222222222222222222222222222222222",
			nil),
		mkEvent("00000000-0000-0000-0000-00000000c003", domain.EventChangeSetApproved, decidedAt,
			"2222222222222222222222222222222222222222222222222222222222222222",
			"3333333333333333333333333333333333333333333333333333333333333333",
			map[string]any{"decision": "approved"}),
	}
	csEvents[2].Actor = domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"}
	s.auditByResource["change_set|"+string(csID)] = csEvents

	// One event keyed off the approved version.
	avEvent := &domain.AuditEvent{
		ID:           "00000000-0000-0000-0000-00000000c004",
		Kind:         domain.EventApprovedVersionCreated,
		Actor:        domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"},
		ResourceType: "approved_version",
		ResourceID:   string(avID),
		OccurredAt:   decidedAt.Add(time.Second),
		PrevHash:     "3333333333333333333333333333333333333333333333333333333333333333",
		Hash:         "4444444444444444444444444444444444444444444444444444444444444444",
		Payload:      map[string]any{"sequence": 1},
	}
	s.auditByResource["approved_version|"+string(avID)] = []*domain.AuditEvent{avEvent}

	return s, productID, avID, csID
}

// fixedClock returns a builderClock that always reports a fixed timestamp
// so PackContent.GeneratedAt is byte-stable across test runs.
func fixedClock() builderClock {
	t := time.Date(2026, 5, 1, 12, 30, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func TestBuilder_DeterministicPackContent(t *testing.T) {
	store, productID, _, _ := fixedFixture(t)
	b := NewBuilder(store).WithClock(fixedClock())

	first, err := b.BuildLatest(context.Background(), productID)
	if err != nil {
		t.Fatalf("BuildLatest #1: %v", err)
	}
	second, err := b.BuildLatest(context.Background(), productID)
	if err != nil {
		t.Fatalf("BuildLatest #2: %v", err)
	}

	encA, err := EncodeJSON(first)
	if err != nil {
		t.Fatalf("EncodeJSON first: %v", err)
	}
	encB, err := EncodeJSON(second)
	if err != nil {
		t.Fatalf("EncodeJSON second: %v", err)
	}
	if !bytes.Equal(encA, encB) {
		t.Fatalf("byte-identical encoding expected; diff:\nA=%s\nB=%s", encA, encB)
	}

	hashA := sha256.Sum256(encA)
	hashB := sha256.Sum256(encB)
	if hashA != hashB {
		t.Fatalf("hashes differ: %s vs %s", hex.EncodeToString(hashA[:]), hex.EncodeToString(hashB[:]))
	}
}

func TestBuilder_BuildBySequence(t *testing.T) {
	store, productID, _, _ := fixedFixture(t)
	b := NewBuilder(store).WithClock(fixedClock())

	pack, err := b.BuildBySequence(context.Background(), productID, 1)
	if err != nil {
		t.Fatalf("BuildBySequence: %v", err)
	}
	if pack.ApprovedVersion.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", pack.ApprovedVersion.Sequence)
	}

	if _, err := b.BuildBySequence(context.Background(), productID, 99); err == nil {
		t.Fatalf("BuildBySequence missing seq should fail")
	}
}

func TestBuilder_BuildByVersionID(t *testing.T) {
	store, _, avID, _ := fixedFixture(t)
	b := NewBuilder(store).WithClock(fixedClock())

	pack, err := b.BuildByVersionID(context.Background(), avID)
	if err != nil {
		t.Fatalf("BuildByVersionID: %v", err)
	}
	if pack.ApprovedVersion.ID != avID {
		t.Errorf("ApprovedVersion.ID = %s, want %s", pack.ApprovedVersion.ID, avID)
	}
}

func TestBuilder_AuditEventsOrderedAndDeduped(t *testing.T) {
	store, productID, avID, csID := fixedFixture(t)
	// Insert a duplicate of the approved-version event under another key
	// (e.g., as if the same event were keyed off two resources). The
	// builder should still see it once after dedupe.
	dup := *store.auditByResource["approved_version|"+string(avID)][0]
	store.auditByResource["change_set|"+string(csID)] = append(
		store.auditByResource["change_set|"+string(csID)],
		&dup,
	)

	b := NewBuilder(store).WithClock(fixedClock())
	pack, err := b.BuildLatest(context.Background(), productID)
	if err != nil {
		t.Fatalf("BuildLatest: %v", err)
	}

	// Expect 4 unique events (3 cs + 1 av), not 5.
	if got, want := len(pack.AuditEvents), 4; got != want {
		t.Fatalf("len(AuditEvents) = %d, want %d", got, want)
	}
	// Ordered ascending by OccurredAt with sequences 1..4.
	for i, e := range pack.AuditEvents {
		if e.Sequence != int64(i+1) {
			t.Errorf("AuditEvents[%d].Sequence = %d, want %d", i, e.Sequence, i+1)
		}
		if i == 0 {
			continue
		}
		if e.OccurredAt.Before(pack.AuditEvents[i-1].OccurredAt) {
			t.Errorf("AuditEvents not ordered: [%d] %s < [%d] %s",
				i, e.OccurredAt, i-1, pack.AuditEvents[i-1].OccurredAt)
		}
	}
}

func TestBuilder_SnapshotCanonicalisationIsStable(t *testing.T) {
	store, productID, _, _ := fixedFixture(t)
	b := NewBuilder(store).WithClock(fixedClock())

	first, err := b.BuildLatest(context.Background(), productID)
	if err != nil {
		t.Fatalf("BuildLatest #1: %v", err)
	}

	// Mutate the underlying snapshot map by re-creating it with a
	// different insertion order. The PackContent's Snapshot bytes
	// should still match.
	store.snapshots["00000000-0000-0000-0000-000000000003"].Content = map[string]any{
		"spec": map[string]any{
			"entitlements": []any{
				map[string]any{"owner": "payments-team", "name": "payments-prod-readonly"},
			},
		},
		"metadata":   map[string]any{"owner": "platform-security", "product": "payments-api"},
		"kind":       "ProductAuthorizationModel",
		"apiVersion": "statebound.dev/v1alpha1",
	}

	second, err := b.BuildLatest(context.Background(), productID)
	if err != nil {
		t.Fatalf("BuildLatest #2: %v", err)
	}

	if !bytes.Equal(first.Snapshot, second.Snapshot) {
		t.Fatalf("snapshot canonicalisation not stable:\n first=%s\nsecond=%s", first.Snapshot, second.Snapshot)
	}
}

func TestBuilder_PolicyDecisionRulesCanonicalised(t *testing.T) {
	store, productID, _, csID := fixedFixture(t)
	// Replace the rules with an out-of-order JSON object body to verify
	// the builder canonicalises it on the way in.
	store.decisionsByCS[csID][0].Rules = json.RawMessage(`[{"outcome":"escalation_required","message":"prod entitlement detected","name":"production_requires_approval"}]`)

	b := NewBuilder(store).WithClock(fixedClock())
	pack, err := b.BuildLatest(context.Background(), productID)
	if err != nil {
		t.Fatalf("BuildLatest: %v", err)
	}
	want := `[{"message":"prod entitlement detected","name":"production_requires_approval","outcome":"escalation_required"}]`
	if string(pack.PolicyDecisions[0].Rules) != want {
		t.Errorf("rules canonical form:\n got %s\nwant %s", pack.PolicyDecisions[0].Rules, want)
	}
}

// TestBuilder_DriftScansEmptyByDefault asserts that a fixture with no
// drift scans yields an empty (not nil) DriftScans slice. The wire shape
// promise depends on this — downstream tooling expects the field to be
// present.
func TestBuilder_DriftScansEmptyByDefault(t *testing.T) {
	store, productID, _, _ := fixedFixture(t)
	b := NewBuilder(store).WithClock(fixedClock())
	pack, err := b.BuildLatest(context.Background(), productID)
	if err != nil {
		t.Fatalf("BuildLatest: %v", err)
	}
	if got, want := len(pack.DriftScans), 0; got != want {
		t.Errorf("len(DriftScans) = %d, want %d", got, want)
	}
	if pack.DriftScans == nil {
		t.Errorf("DriftScans should be a non-nil empty slice; got nil")
	}
}

// TestBuilder_DriftScansPopulated stages a drift scan against the fixture's
// approved version, builds the pack, and asserts the scan + findings
// appear in the canonical bytes with sorted finding sequences and
// canonicalised diff bodies.
func TestBuilder_DriftScansPopulated(t *testing.T) {
	store, productID, avID, _ := fixedFixture(t)

	scanID := domain.ID("00000000-0000-0000-0000-00000000e001")
	finishedAt := time.Date(2026, 5, 1, 12, 5, 0, 0, time.UTC)
	startedAt := time.Date(2026, 5, 1, 12, 4, 0, 0, time.UTC)
	scan := &domain.DriftScan{
		ID:                scanID,
		ProductID:         productID,
		ApprovedVersionID: avID,
		Sequence:          1,
		ConnectorName:     "linux-sudo",
		ConnectorVersion:  "0.4.0",
		State:             domain.DriftScanStateSucceeded,
		SourceRef:         "file:///etc/sudoers.d",
		StartedAt:         startedAt,
		FinishedAt:        &finishedAt,
		InitiatedBy:       domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"},
		SummaryHash:       "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		FindingCount:      1,
	}
	store.driftScansByProd[productID] = []*domain.DriftScan{scan}

	finding := &domain.DriftFinding{
		ID:           "00000000-0000-0000-0000-00000000f001",
		ScanID:       scanID,
		Sequence:     1,
		Kind:         domain.DriftKindUnexpected,
		Severity:     domain.DriftSeverityHigh,
		ResourceKind: "linux.sudoers-fragment",
		ResourceRef:  "/etc/sudoers.d/rogue-elevated",
		Actual:       json.RawMessage(`{"path":"/etc/sudoers.d/rogue-elevated","content":"%rogue-elevated ALL=(root) ALL"}`),
		// Out-of-order keys so we can verify canonicalisation.
		Diff:       json.RawMessage(`{"reason":"unexpected fragment","missing":false}`),
		Message:    "fragment present in actual but not desired",
		DetectedAt: finishedAt,
	}
	store.driftFindings[scanID] = []*domain.DriftFinding{finding}

	b := NewBuilder(store).WithClock(fixedClock())
	pack, err := b.BuildLatest(context.Background(), productID)
	if err != nil {
		t.Fatalf("BuildLatest: %v", err)
	}
	if got, want := len(pack.DriftScans), 1; got != want {
		t.Fatalf("len(DriftScans) = %d, want %d", got, want)
	}
	gotScan := pack.DriftScans[0]
	if gotScan.ID != scanID {
		t.Errorf("Scan.ID = %s, want %s", gotScan.ID, scanID)
	}
	if got, want := gotScan.SummaryHash, scan.SummaryHash; got != want {
		t.Errorf("Scan.SummaryHash = %q, want %q", got, want)
	}
	if got, want := len(gotScan.Findings), 1; got != want {
		t.Fatalf("len(Findings) = %d, want %d", got, want)
	}
	gotFinding := gotScan.Findings[0]
	if gotFinding.Kind != "unexpected" {
		t.Errorf("Finding.Kind = %q, want %q", gotFinding.Kind, "unexpected")
	}
	// Diff should be canonicalised: keys sorted alphabetically.
	wantDiff := `{"missing":false,"reason":"unexpected fragment"}`
	if string(gotFinding.Diff) != wantDiff {
		t.Errorf("Finding.Diff = %s, want %s", gotFinding.Diff, wantDiff)
	}
	if gotFinding.Desired != nil {
		t.Errorf("Finding.Desired should be nil for unexpected kind; got %s", gotFinding.Desired)
	}

	// Two encodes of the same pack must be byte-identical.
	first, err := EncodeJSON(pack)
	if err != nil {
		t.Fatalf("EncodeJSON #1: %v", err)
	}
	pack2, err := b.BuildLatest(context.Background(), productID)
	if err != nil {
		t.Fatalf("BuildLatest #2: %v", err)
	}
	second, err := EncodeJSON(pack2)
	if err != nil {
		t.Fatalf("EncodeJSON #2: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("pack with drift scans not byte-identical across builds:\nfirst=%s\nsecond=%s", first, second)
	}
}

// TestBuilder_DriftScansFilteredByApprovedVersion asserts the builder
// drops scans recorded against a different approved version. The
// pack-shape contract is "scans for this version", not "all scans for the
// product".
func TestBuilder_DriftScansFilteredByApprovedVersion(t *testing.T) {
	store, productID, avID, _ := fixedFixture(t)

	otherAVID := domain.ID("00000000-0000-0000-0000-00000000ffff")
	mineID := domain.ID("00000000-0000-0000-0000-00000000e001")
	otherID := domain.ID("00000000-0000-0000-0000-00000000e002")
	startedAt := time.Date(2026, 5, 1, 12, 4, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Minute)

	mkScan := func(id, av domain.ID) *domain.DriftScan {
		return &domain.DriftScan{
			ID:                id,
			ProductID:         productID,
			ApprovedVersionID: av,
			Sequence:          1,
			ConnectorName:     "linux-sudo",
			ConnectorVersion:  "0.4.0",
			State:             domain.DriftScanStateSucceeded,
			SourceRef:         "file:///etc/sudoers.d",
			StartedAt:         startedAt,
			FinishedAt:        &finishedAt,
			InitiatedBy:       domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"},
			SummaryHash:       "sha256:" + string(id),
			FindingCount:      0,
		}
	}
	store.driftScansByProd[productID] = []*domain.DriftScan{
		mkScan(mineID, avID),
		mkScan(otherID, otherAVID),
	}

	b := NewBuilder(store).WithClock(fixedClock())
	pack, err := b.BuildLatest(context.Background(), productID)
	if err != nil {
		t.Fatalf("BuildLatest: %v", err)
	}
	if got, want := len(pack.DriftScans), 1; got != want {
		t.Fatalf("len(DriftScans) = %d, want %d (scan from another AV should be dropped)", got, want)
	}
	if pack.DriftScans[0].ID != mineID {
		t.Errorf("DriftScans[0].ID = %s, want %s", pack.DriftScans[0].ID, mineID)
	}
}
