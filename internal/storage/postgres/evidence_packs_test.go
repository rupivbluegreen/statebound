package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
	"statebound.dev/statebound/internal/storage/postgres"
)

// requireDB skips the test when STATEBOUND_TEST_DB_DSN is unset. The CI
// pipeline points the var at an ephemeral Postgres with all migrations
// applied; locally the developer flips it on with a Compose Postgres.
func requireDB(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := os.Getenv("STATEBOUND_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("STATEBOUND_TEST_DB_DSN not set; skipping postgres integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatalf("postgres.New: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close(context.Background())
	})
	return store
}

// seedProductAndVersion inserts a fresh product, change set, snapshot, and
// approved_version so an evidence_packs row can pass FK checks. Returns the
// product id, approved version id, and approved version sequence the caller
// should mirror into the EvidencePack. Each call uses fresh UUIDs and a
// timestamp-derived product slug so parallel test invocations do not collide.
func seedProductAndVersion(ctx context.Context, t *testing.T, store *postgres.Store) (domain.ID, domain.ID, int64) {
	t.Helper()
	// Unique product slug per call. Lower-case hex of nanos keeps the slug
	// inside the kebab-slug regex enforced by the products CHECK.
	slug := uniqueSlug("ev-pack-test")
	product, err := domain.NewProduct(slug, "platform-security", "evidence pack test product")
	if err != nil {
		t.Fatalf("NewProduct: %v", err)
	}
	if err := store.CreateProduct(ctx, product); err != nil {
		t.Fatalf("CreateProduct: %v", err)
	}

	cs, err := domain.NewChangeSet(product.ID, nil,
		"seed evidence pack tests", "", domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"})
	if err != nil {
		t.Fatalf("NewChangeSet: %v", err)
	}
	if err := store.CreateChangeSet(ctx, cs); err != nil {
		t.Fatalf("CreateChangeSet: %v", err)
	}

	snap, err := domain.NewApprovedVersionSnapshot(map[string]any{
		"product": slug,
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

// uniqueSlug returns a kebab-slug name unique enough to avoid collisions across
// concurrent test runs in the same database. Slug pattern is enforced by the
// products CHECK: ^[a-z0-9][a-z0-9-]{0,62}$.
func uniqueSlug(prefix string) string {
	const hex = "0123456789abcdef"
	n := time.Now().UnixNano()
	out := make([]byte, 0, len(prefix)+1+16)
	out = append(out, prefix...)
	out = append(out, '-')
	for i := 60; i >= 0; i -= 4 {
		out = append(out, hex[(n>>i)&0xF])
	}
	return string(out)
}

func TestAppendEvidencePack_HappyPath(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedProductAndVersion(ctx, t, store)

	body := json.RawMessage(`{"approved_version":"av-1","items":[{"k":"v"}]}`)
	pack, err := domain.NewEvidencePack(productID, avID, seq,
		domain.EvidencePackFormatJSON, body,
		domain.Actor{Kind: domain.ActorHuman, Subject: "auditor@example.com"})
	if err != nil {
		t.Fatalf("NewEvidencePack: %v", err)
	}
	if err := store.AppendEvidencePack(ctx, pack); err != nil {
		t.Fatalf("AppendEvidencePack: %v", err)
	}

	got, err := store.GetEvidencePackByID(ctx, pack.ID)
	if err != nil {
		t.Fatalf("GetEvidencePackByID: %v", err)
	}
	if got.ID != pack.ID {
		t.Errorf("ID = %q, want %q", got.ID, pack.ID)
	}
	if got.ProductID != productID {
		t.Errorf("ProductID = %q, want %q", got.ProductID, productID)
	}
	if got.ApprovedVersionID != avID {
		t.Errorf("ApprovedVersionID = %q, want %q", got.ApprovedVersionID, avID)
	}
	if got.Sequence != seq {
		t.Errorf("Sequence = %d, want %d", got.Sequence, seq)
	}
	if got.Format != domain.EvidencePackFormatJSON {
		t.Errorf("Format = %q, want %q", got.Format, domain.EvidencePackFormatJSON)
	}
	if got.ContentHash != pack.ContentHash {
		t.Errorf("ContentHash = %q, want %q", got.ContentHash, pack.ContentHash)
	}
	if got.GeneratedBy.Kind != domain.ActorHuman {
		t.Errorf("GeneratedBy.Kind = %q, want %q", got.GeneratedBy.Kind, domain.ActorHuman)
	}
	if got.GeneratedBy.Subject != "auditor@example.com" {
		t.Errorf("GeneratedBy.Subject = %q, want %q", got.GeneratedBy.Subject, "auditor@example.com")
	}
	// JSONB round-trip: re-decode and compare a known field. Postgres JSONB
	// normalises whitespace/key order on its way back out, so the recomputed
	// SHA-256 over got.Content will not match pack.ContentHash by design —
	// the persisted content_hash column is the source of truth, and equality
	// of that column is what we assert above. Recomputation determinism is
	// covered by the domain-level Hash() test.
	var roundTrip map[string]any
	if err := json.Unmarshal(got.Content, &roundTrip); err != nil {
		t.Fatalf("json.Unmarshal(got.Content): %v", err)
	}
	if roundTrip["approved_version"] != "av-1" {
		t.Errorf("Content[approved_version] = %v, want av-1", roundTrip["approved_version"])
	}
}

func TestAppendEvidencePack_Idempotent(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedProductAndVersion(ctx, t, store)

	body := json.RawMessage(`{"approved_version":"av-1","determinism":true}`)
	first, err := domain.NewEvidencePack(productID, avID, seq,
		domain.EvidencePackFormatJSON, body,
		domain.Actor{Kind: domain.ActorHuman, Subject: "auditor@example.com"})
	if err != nil {
		t.Fatalf("NewEvidencePack first: %v", err)
	}
	if err := store.AppendEvidencePack(ctx, first); err != nil {
		t.Fatalf("AppendEvidencePack first: %v", err)
	}

	// Second pack constructed with identical bytes -> same content hash but
	// fresh ID. ON CONFLICT (av, format, hash) DO NOTHING means the second
	// insert is a no-op and the original row stands.
	second, err := domain.NewEvidencePack(productID, avID, seq,
		domain.EvidencePackFormatJSON, body,
		domain.Actor{Kind: domain.ActorHuman, Subject: "auditor@example.com"})
	if err != nil {
		t.Fatalf("NewEvidencePack second: %v", err)
	}
	if first.ContentHash != second.ContentHash {
		t.Fatalf("preconditions: hashes differ %q vs %q", first.ContentHash, second.ContentHash)
	}
	if err := store.AppendEvidencePack(ctx, second); err != nil {
		t.Fatalf("AppendEvidencePack second: %v", err)
	}

	// The original row is the only one matching (av, format).
	got, err := store.GetEvidencePackByVersionFormat(ctx, avID, domain.EvidencePackFormatJSON)
	if err != nil {
		t.Fatalf("GetEvidencePackByVersionFormat: %v", err)
	}
	if got.ID != first.ID {
		t.Errorf("idempotent insert clobbered row: got.ID = %q, want %q", got.ID, first.ID)
	}

	// Listing by product confirms exactly one row.
	packs, err := store.ListEvidencePacksByProduct(ctx, productID, 0)
	if err != nil {
		t.Fatalf("ListEvidencePacksByProduct: %v", err)
	}
	if len(packs) != 1 {
		t.Errorf("len(packs) = %d, want 1 (idempotent insert created duplicate row)", len(packs))
	}
}

func TestGetEvidencePackByVersionFormat_NotFound(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, avID, _ := seedProductAndVersion(ctx, t, store)
	_, err := store.GetEvidencePackByVersionFormat(ctx, avID, domain.EvidencePackFormatJSON)
	if !errors.Is(err, storage.ErrEvidencePackNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrEvidencePackNotFound", err)
	}
}

func TestGetEvidencePackByID_NotFound(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := store.GetEvidencePackByID(ctx, domain.NewID())
	if !errors.Is(err, storage.ErrEvidencePackNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrEvidencePackNotFound", err)
	}
}

func TestListEvidencePacksByProduct_OrderingAndEmpty(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedProductAndVersion(ctx, t, store)

	// Empty case first.
	packs, err := store.ListEvidencePacksByProduct(ctx, productID, 0)
	if err != nil {
		t.Fatalf("ListEvidencePacksByProduct (empty): %v", err)
	}
	if len(packs) != 0 {
		t.Errorf("len(packs) = %d, want 0 on empty product", len(packs))
	}

	// Insert two packs with distinct content hashes (one JSON, one Markdown
	// envelope). The DESC ordering by generated_at means the newest insert
	// is at index 0; we set explicit GeneratedAt to keep the test
	// deterministic regardless of insert latency.
	earlier := time.Now().UTC().Add(-2 * time.Minute)
	later := earlier.Add(time.Minute)

	first, err := domain.NewEvidencePack(productID, avID, seq,
		domain.EvidencePackFormatJSON, json.RawMessage(`{"k":1}`),
		domain.Actor{Kind: domain.ActorHuman, Subject: "auditor@example.com"})
	if err != nil {
		t.Fatalf("NewEvidencePack first: %v", err)
	}
	first.GeneratedAt = earlier
	if err := store.AppendEvidencePack(ctx, first); err != nil {
		t.Fatalf("AppendEvidencePack first: %v", err)
	}

	second, err := domain.NewEvidencePack(productID, avID, seq,
		domain.EvidencePackFormatMarkdown,
		json.RawMessage(`{"format":"markdown","body":"# evidence\n"}`),
		domain.Actor{Kind: domain.ActorHuman, Subject: "auditor@example.com"})
	if err != nil {
		t.Fatalf("NewEvidencePack second: %v", err)
	}
	second.GeneratedAt = later
	if err := store.AppendEvidencePack(ctx, second); err != nil {
		t.Fatalf("AppendEvidencePack second: %v", err)
	}

	packs, err = store.ListEvidencePacksByProduct(ctx, productID, 0)
	if err != nil {
		t.Fatalf("ListEvidencePacksByProduct: %v", err)
	}
	if len(packs) != 2 {
		t.Fatalf("len(packs) = %d, want 2", len(packs))
	}
	if packs[0].ID != second.ID {
		t.Errorf("packs[0].ID = %q, want %q (newest first)", packs[0].ID, second.ID)
	}
	if packs[1].ID != first.ID {
		t.Errorf("packs[1].ID = %q, want %q (oldest last)", packs[1].ID, first.ID)
	}

	// limit semantics.
	limited, err := store.ListEvidencePacksByProduct(ctx, productID, 1)
	if err != nil {
		t.Fatalf("ListEvidencePacksByProduct limit=1: %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("len(limited) = %d, want 1", len(limited))
	}
}

func TestAppendEvidencePack_FKMissingApprovedVersion(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, _, seq := seedProductAndVersion(ctx, t, store)

	// Use a never-inserted approved_version_id. The FK on
	// approved_version_id should fire and surface as ErrNotFound.
	pack, err := domain.NewEvidencePack(productID, domain.NewID(), seq,
		domain.EvidencePackFormatJSON, json.RawMessage(`{"k":"v"}`),
		domain.Actor{Kind: domain.ActorHuman, Subject: "auditor@example.com"})
	if err != nil {
		t.Fatalf("NewEvidencePack: %v", err)
	}
	err = store.AppendEvidencePack(ctx, pack)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrNotFound", err)
	}
}
