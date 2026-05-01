package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
	"statebound.dev/statebound/internal/storage/postgres"
)

// seedDriftProductAndVersion mirrors seedProductAndVersion from
// evidence_packs_test.go but with a drift-flavoured slug. Each call
// uses fresh UUIDs and a unique product slug so parallel test
// invocations do not collide on products UNIQUE(name).
func seedDriftProductAndVersion(ctx context.Context, t *testing.T, store *postgres.Store) (domain.ID, domain.ID, int64) {
	t.Helper()
	slug := uniqueSlug("drift-test")
	product, err := domain.NewProduct(slug, "platform-security", "drift test product")
	if err != nil {
		t.Fatalf("NewProduct: %v", err)
	}
	if err := store.CreateProduct(ctx, product); err != nil {
		t.Fatalf("CreateProduct: %v", err)
	}

	cs, err := domain.NewChangeSet(product.ID, nil,
		"seed drift tests", "", domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"})
	if err != nil {
		t.Fatalf("NewChangeSet: %v", err)
	}
	if err := store.CreateChangeSet(ctx, cs); err != nil {
		t.Fatalf("CreateChangeSet: %v", err)
	}

	snap, err := domain.NewApprovedVersionSnapshot(map[string]any{
		"product":  slug,
		"sequence": 1,
	})
	if err != nil {
		t.Fatalf("NewApprovedVersionSnapshot: %v", err)
	}
	av, err := domain.NewApprovedVersion(product.ID, snap.ID, 1, nil, cs.ID,
		domain.Actor{Kind: domain.ActorHuman, Subject: "approver@example.com"}, "seed")
	if err != nil {
		t.Fatalf("NewApprovedVersion: %v", err)
	}
	if err := store.CreateApprovedVersion(ctx, av, snap); err != nil {
		t.Fatalf("CreateApprovedVersion: %v", err)
	}
	return product.ID, av.ID, av.Sequence
}

func newTestDriftScan(t *testing.T, productID, avID domain.ID, seq int64) *domain.DriftScan {
	t.Helper()
	scan, err := domain.NewDriftScan(productID, avID, seq, "linux-sudo", "0.4.0",
		"file:///etc/sudoers.d", domain.Actor{Kind: domain.ActorHuman, Subject: "engineer@example.com"})
	if err != nil {
		t.Fatalf("NewDriftScan: %v", err)
	}
	return scan
}

func TestAppendDriftScan_AndUpdate_HappyPath(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedDriftProductAndVersion(ctx, t, store)
	scan := newTestDriftScan(t, productID, avID, seq)

	if err := store.AppendDriftScan(ctx, scan); err != nil {
		t.Fatalf("AppendDriftScan: %v", err)
	}

	got, findings, err := store.GetDriftScanByID(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetDriftScanByID: %v", err)
	}
	if got.State != domain.DriftScanStateRunning {
		t.Errorf("State = %q, want running", got.State)
	}
	if got.FinishedAt != nil {
		t.Errorf("FinishedAt = %v, want nil after AppendDriftScan", got.FinishedAt)
	}
	if got.FindingCount != 0 {
		t.Errorf("FindingCount = %d, want 0", got.FindingCount)
	}
	if got.SourceRef != "file:///etc/sudoers.d" {
		t.Errorf("SourceRef = %q", got.SourceRef)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}

	// Transition Running -> Succeeded then UpdateDriftScan.
	finished := time.Now().UTC()
	if err := scan.Transition(domain.DriftScanStateSucceeded, finished, "abcd1234", 2, ""); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if err := store.UpdateDriftScan(ctx, scan); err != nil {
		t.Fatalf("UpdateDriftScan: %v", err)
	}
	got, _, err = store.GetDriftScanByID(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetDriftScanByID after update: %v", err)
	}
	if got.State != domain.DriftScanStateSucceeded {
		t.Errorf("State = %q, want succeeded", got.State)
	}
	if got.FinishedAt == nil || !got.FinishedAt.Equal(finished.Truncate(time.Microsecond)) && !got.FinishedAt.Equal(finished) {
		t.Errorf("FinishedAt = %v, want ~%v", got.FinishedAt, finished)
	}
	if got.FindingCount != 2 {
		t.Errorf("FindingCount = %d, want 2", got.FindingCount)
	}
	if got.SummaryHash != "abcd1234" {
		t.Errorf("SummaryHash = %q", got.SummaryHash)
	}
}

func TestAppendDriftScan_FKMissingProduct(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, avID, seq := seedDriftProductAndVersion(ctx, t, store)
	scan := newTestDriftScan(t, domain.NewID(), avID, seq)

	err := store.AppendDriftScan(ctx, scan)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrNotFound", err)
	}
}

func TestAppendDriftScan_FKMissingApprovedVersion(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, _, seq := seedDriftProductAndVersion(ctx, t, store)
	scan := newTestDriftScan(t, productID, domain.NewID(), seq)

	err := store.AppendDriftScan(ctx, scan)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrNotFound", err)
	}
}

func TestUpdateDriftScan_MissingID(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	scan := &domain.DriftScan{
		ID:           domain.NewID(),
		State:        domain.DriftScanStateSucceeded,
		FindingCount: 0,
	}
	err := store.UpdateDriftScan(ctx, scan)
	if !errors.Is(err, storage.ErrDriftScanNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrDriftScanNotFound", err)
	}
}

func TestAppendDriftFindings_RoundTripInSequenceOrder(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedDriftProductAndVersion(ctx, t, store)
	scan := newTestDriftScan(t, productID, avID, seq)
	if err := store.AppendDriftScan(ctx, scan); err != nil {
		t.Fatalf("AppendDriftScan: %v", err)
	}

	mk := func(seq int, kind domain.DriftKind, severity domain.DriftSeverity, ref string) *domain.DriftFinding {
		desired := json.RawMessage(`{"path":"` + ref + `","content":"want"}`)
		actual := json.RawMessage(`{"path":"` + ref + `","content":"got"}`)
		diff := json.RawMessage(`{"changed":["content"]}`)
		// Missing/unexpected pass nils for the absent side.
		var d, a json.RawMessage
		switch kind {
		case domain.DriftKindMissing:
			d = desired
		case domain.DriftKindUnexpected:
			a = actual
		default:
			d = desired
			a = actual
		}
		f, err := domain.NewDriftFinding(scan.ID, seq, kind, severity,
			"linux.sudoers-fragment", ref, d, a, diff, "test mismatch")
		if err != nil {
			t.Fatalf("NewDriftFinding: %v", err)
		}
		return f
	}

	findings := []*domain.DriftFinding{
		mk(1, domain.DriftKindMissing, domain.DriftSeverityHigh, "/etc/sudoers.d/a"),
		mk(2, domain.DriftKindUnexpected, domain.DriftSeverityMedium, "/etc/sudoers.d/b"),
		mk(3, domain.DriftKindModified, domain.DriftSeverityCritical, "/etc/sudoers.d/c"),
	}
	if err := store.AppendDriftFindings(ctx, findings); err != nil {
		t.Fatalf("AppendDriftFindings: %v", err)
	}

	_, gotFindings, err := store.GetDriftScanByID(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetDriftScanByID: %v", err)
	}
	if len(gotFindings) != 3 {
		t.Fatalf("len(gotFindings) = %d, want 3", len(gotFindings))
	}
	for i, f := range gotFindings {
		if f.Sequence != i+1 {
			t.Errorf("gotFindings[%d].Sequence = %d, want %d", i, f.Sequence, i+1)
		}
		if f.ScanID != scan.ID {
			t.Errorf("gotFindings[%d].ScanID = %q, want %q", i, f.ScanID, scan.ID)
		}
		if string(f.Diff) == "" {
			t.Errorf("gotFindings[%d].Diff is empty", i)
		}
	}
	if gotFindings[0].Kind != domain.DriftKindMissing {
		t.Errorf("gotFindings[0].Kind = %q, want missing", gotFindings[0].Kind)
	}
	if gotFindings[0].Actual != nil {
		t.Errorf("gotFindings[0].Actual = %v, want nil for missing", string(gotFindings[0].Actual))
	}
	if gotFindings[1].Kind != domain.DriftKindUnexpected {
		t.Errorf("gotFindings[1].Kind = %q, want unexpected", gotFindings[1].Kind)
	}
	if gotFindings[1].Desired != nil {
		t.Errorf("gotFindings[1].Desired = %v, want nil for unexpected", string(gotFindings[1].Desired))
	}
	if gotFindings[2].Severity != domain.DriftSeverityCritical {
		t.Errorf("gotFindings[2].Severity = %q, want critical", gotFindings[2].Severity)
	}
}

func TestAppendDriftFindings_FKMissingScan(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bogusScanID := domain.NewID()
	f, err := domain.NewDriftFinding(bogusScanID, 1, domain.DriftKindModified,
		domain.DriftSeverityLow, "linux.sudoers-fragment", "/etc/sudoers.d/x",
		json.RawMessage(`{"k":1}`), json.RawMessage(`{"k":2}`),
		json.RawMessage(`{"diff":1}`), "msg")
	if err != nil {
		t.Fatalf("NewDriftFinding: %v", err)
	}
	err = store.AppendDriftFindings(ctx, []*domain.DriftFinding{f})
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrNotFound", err)
	}
}

func TestAppendDriftFindings_DuplicateSequence(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedDriftProductAndVersion(ctx, t, store)
	scan := newTestDriftScan(t, productID, avID, seq)
	if err := store.AppendDriftScan(ctx, scan); err != nil {
		t.Fatalf("AppendDriftScan: %v", err)
	}

	body := json.RawMessage(`{"k":1}`)
	first, err := domain.NewDriftFinding(scan.ID, 1, domain.DriftKindModified,
		domain.DriftSeverityLow, "linux.sudoers-fragment", "/etc/sudoers.d/x",
		body, body, json.RawMessage(`{}`), "")
	if err != nil {
		t.Fatalf("NewDriftFinding first: %v", err)
	}
	if err := store.AppendDriftFindings(ctx, []*domain.DriftFinding{first}); err != nil {
		t.Fatalf("AppendDriftFindings first: %v", err)
	}

	dup, err := domain.NewDriftFinding(scan.ID, 1, domain.DriftKindModified,
		domain.DriftSeverityLow, "linux.sudoers-fragment", "/etc/sudoers.d/y",
		body, body, json.RawMessage(`{}`), "")
	if err != nil {
		t.Fatalf("NewDriftFinding dup: %v", err)
	}
	err = store.AppendDriftFindings(ctx, []*domain.DriftFinding{dup})
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Errorf("err = %v, want errors.Is == storage.ErrAlreadyExists", err)
	}
}

func TestGetLatestDriftScanByApprovedVersion(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedDriftProductAndVersion(ctx, t, store)

	// Empty case.
	_, _, err := store.GetLatestDriftScanByApprovedVersion(ctx, avID)
	if !errors.Is(err, storage.ErrDriftScanNotFound) {
		t.Errorf("empty err = %v, want errors.Is == storage.ErrDriftScanNotFound", err)
	}

	// Two scans with explicit StartedAt values so ordering is
	// deterministic regardless of insert latency.
	earlier := time.Now().UTC().Add(-2 * time.Minute)
	later := earlier.Add(time.Minute)

	first := newTestDriftScan(t, productID, avID, seq)
	first.StartedAt = earlier
	if err := store.AppendDriftScan(ctx, first); err != nil {
		t.Fatalf("AppendDriftScan first: %v", err)
	}
	second := newTestDriftScan(t, productID, avID, seq)
	second.StartedAt = later
	if err := store.AppendDriftScan(ctx, second); err != nil {
		t.Fatalf("AppendDriftScan second: %v", err)
	}

	// Attach one finding to the latter so we can prove the findings
	// list returns the LATEST scan's findings.
	body := json.RawMessage(`{"k":1}`)
	f, err := domain.NewDriftFinding(second.ID, 1, domain.DriftKindModified,
		domain.DriftSeverityHigh, "linux.sudoers-fragment", "/etc/sudoers.d/x",
		body, body, json.RawMessage(`{"changed":["content"]}`), "tampered")
	if err != nil {
		t.Fatalf("NewDriftFinding: %v", err)
	}
	if err := store.AppendDriftFindings(ctx, []*domain.DriftFinding{f}); err != nil {
		t.Fatalf("AppendDriftFindings: %v", err)
	}

	got, gotFindings, err := store.GetLatestDriftScanByApprovedVersion(ctx, avID)
	if err != nil {
		t.Fatalf("GetLatestDriftScanByApprovedVersion: %v", err)
	}
	if got.ID != second.ID {
		t.Errorf("latest scan id = %q, want %q", got.ID, second.ID)
	}
	if len(gotFindings) != 1 {
		t.Fatalf("len(gotFindings) = %d, want 1", len(gotFindings))
	}
	if gotFindings[0].ID != f.ID {
		t.Errorf("findings[0].ID = %q, want %q", gotFindings[0].ID, f.ID)
	}
}

func TestListDriftScansByProduct_OrderingLimitEmpty(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedDriftProductAndVersion(ctx, t, store)

	// Empty case.
	scans, err := store.ListDriftScansByProduct(ctx, productID, 0)
	if err != nil {
		t.Fatalf("ListDriftScansByProduct (empty): %v", err)
	}
	if len(scans) != 0 {
		t.Errorf("len(scans) = %d, want 0 on empty product", len(scans))
	}

	// Two scans with explicit StartedAt values for deterministic order.
	earlier := time.Now().UTC().Add(-2 * time.Minute)
	later := earlier.Add(time.Minute)

	first := newTestDriftScan(t, productID, avID, seq)
	first.StartedAt = earlier
	if err := store.AppendDriftScan(ctx, first); err != nil {
		t.Fatalf("AppendDriftScan first: %v", err)
	}
	second := newTestDriftScan(t, productID, avID, seq)
	second.StartedAt = later
	if err := store.AppendDriftScan(ctx, second); err != nil {
		t.Fatalf("AppendDriftScan second: %v", err)
	}

	scans, err = store.ListDriftScansByProduct(ctx, productID, 0)
	if err != nil {
		t.Fatalf("ListDriftScansByProduct: %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("len(scans) = %d, want 2", len(scans))
	}
	if scans[0].ID != second.ID {
		t.Errorf("scans[0].ID = %q, want %q (newest first)", scans[0].ID, second.ID)
	}
	if scans[1].ID != first.ID {
		t.Errorf("scans[1].ID = %q, want %q (oldest last)", scans[1].ID, first.ID)
	}

	limited, err := store.ListDriftScansByProduct(ctx, productID, 1)
	if err != nil {
		t.Fatalf("ListDriftScansByProduct limit=1: %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("len(limited) = %d, want 1", len(limited))
	}
	if len(limited) == 1 && limited[0].ID != second.ID {
		t.Errorf("limited[0].ID = %q, want %q (newest)", limited[0].ID, second.ID)
	}
}

func TestGetDriftScanByID_NotFound(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, _, err := store.GetDriftScanByID(ctx, domain.NewID())
	if !errors.Is(err, storage.ErrDriftScanNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrDriftScanNotFound", err)
	}
}
