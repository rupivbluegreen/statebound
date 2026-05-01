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

// seedPlanProductAndVersion mirrors seedProductAndVersion from
// evidence_packs_test.go but with a plan-flavored slug. Each call uses
// fresh UUIDs and a unique product slug so parallel test invocations
// do not collide on the products UNIQUE(name).
func seedPlanProductAndVersion(ctx context.Context, t *testing.T, store *postgres.Store) (domain.ID, domain.ID, int64) {
	t.Helper()
	slug := uniqueSlug("plan-test")
	product, err := domain.NewProduct(slug, "platform-security", "plan test product")
	if err != nil {
		t.Fatalf("NewProduct: %v", err)
	}
	if err := store.CreateProduct(ctx, product); err != nil {
		t.Fatalf("CreateProduct: %v", err)
	}

	cs, err := domain.NewChangeSet(product.ID, nil,
		"seed plan tests", "", domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"})
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

// newPlanWithItems builds a Plan + N PlanItems sharing the supplied
// content. Sequence numbers start at 1.
func newPlanWithItems(t *testing.T, productID, avID domain.ID, seq int64, content json.RawMessage, n int) (*domain.Plan, []*domain.PlanItem) {
	t.Helper()
	p, err := domain.NewPlan(productID, avID, seq, "linux-sudo", "0.4.0",
		content, "test plan", domain.Actor{Kind: domain.ActorHuman, Subject: "engineer@example.com"})
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	items := make([]*domain.PlanItem, 0, n)
	for i := 1; i <= n; i++ {
		body, _ := json.Marshal(map[string]any{"i": i})
		items = append(items, &domain.PlanItem{
			ID:           domain.NewID(),
			PlanID:       p.ID,
			Sequence:     i,
			Action:       "create",
			ResourceKind: "linux.sudoers-fragment",
			ResourceRef:  "pay-linux-01:/etc/sudoers.d/payments",
			Body:         body,
			Risk:         "low",
			Note:         "",
		})
	}
	return p, items
}

func TestAppendPlan_HappyPath(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedPlanProductAndVersion(ctx, t, store)
	body := json.RawMessage(`{"items":[{"action":"create"}],"version":"0.4.0"}`)
	plan, items := newPlanWithItems(t, productID, avID, seq, body, 3)

	if err := store.AppendPlan(ctx, plan, items); err != nil {
		t.Fatalf("AppendPlan: %v", err)
	}

	got, gotItems, err := store.GetPlanByID(ctx, plan.ID)
	if err != nil {
		t.Fatalf("GetPlanByID: %v", err)
	}
	if got.ID != plan.ID {
		t.Errorf("ID = %q, want %q", got.ID, plan.ID)
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
	if got.ConnectorName != "linux-sudo" {
		t.Errorf("ConnectorName = %q, want linux-sudo", got.ConnectorName)
	}
	if got.ConnectorVersion != "0.4.0" {
		t.Errorf("ConnectorVersion = %q, want 0.4.0", got.ConnectorVersion)
	}
	if got.State != domain.PlanStateDraft {
		t.Errorf("State = %q, want draft", got.State)
	}
	if got.ContentHash != plan.ContentHash {
		t.Errorf("ContentHash = %q, want %q", got.ContentHash, plan.ContentHash)
	}
	if got.GeneratedBy.Kind != domain.ActorHuman {
		t.Errorf("GeneratedBy.Kind = %q, want %q", got.GeneratedBy.Kind, domain.ActorHuman)
	}

	// Items round-trip in sequence order.
	if len(gotItems) != 3 {
		t.Fatalf("len(gotItems) = %d, want 3", len(gotItems))
	}
	for i, it := range gotItems {
		if it.Sequence != i+1 {
			t.Errorf("gotItems[%d].Sequence = %d, want %d", i, it.Sequence, i+1)
		}
		if it.PlanID != plan.ID {
			t.Errorf("gotItems[%d].PlanID = %q, want %q", i, it.PlanID, plan.ID)
		}
		if it.ResourceKind != "linux.sudoers-fragment" {
			t.Errorf("gotItems[%d].ResourceKind = %q", i, it.ResourceKind)
		}
		if it.Risk != "low" {
			t.Errorf("gotItems[%d].Risk = %q, want low", i, it.Risk)
		}
	}

	// Content is JSONB: Postgres normalises whitespace/key order on its
	// way back out, so re-hashing got.Content will not match
	// plan.ContentHash. The persisted column is the source of truth and
	// we already asserted equality above. Decode and confirm a known
	// field round-trips.
	var roundTrip map[string]any
	if err := json.Unmarshal(got.Content, &roundTrip); err != nil {
		t.Fatalf("json.Unmarshal(got.Content): %v", err)
	}
	if roundTrip["version"] != "0.4.0" {
		t.Errorf("Content[version] = %v, want 0.4.0", roundTrip["version"])
	}
}

func TestAppendPlan_Idempotent(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedPlanProductAndVersion(ctx, t, store)
	body := json.RawMessage(`{"items":[{"action":"create"}],"determinism":true}`)

	first, firstItems := newPlanWithItems(t, productID, avID, seq, body, 2)
	if err := store.AppendPlan(ctx, first, firstItems); err != nil {
		t.Fatalf("AppendPlan first: %v", err)
	}

	// Same canonical content -> same content_hash, fresh ids. ON
	// CONFLICT (av, connector, hash) DO NOTHING means the second insert
	// is a no-op and the original row stands. Items must NOT be
	// inserted on the conflict path either.
	second, secondItems := newPlanWithItems(t, productID, avID, seq, body, 2)
	if first.ContentHash != second.ContentHash {
		t.Fatalf("preconditions: hashes differ %q vs %q", first.ContentHash, second.ContentHash)
	}
	if err := store.AppendPlan(ctx, second, secondItems); err != nil {
		t.Fatalf("AppendPlan second: %v", err)
	}

	plans, err := store.ListPlansByApprovedVersion(ctx, avID)
	if err != nil {
		t.Fatalf("ListPlansByApprovedVersion: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("len(plans) = %d, want 1 (idempotent insert created duplicate row)", len(plans))
	}
	if plans[0].ID != first.ID {
		t.Errorf("idempotent insert clobbered row: plans[0].ID = %q, want %q", plans[0].ID, first.ID)
	}

	// Item count must be 2 — the second AppendPlan must NOT have added
	// any items even though the plan id differed.
	_, items, err := store.GetPlanByID(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetPlanByID: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("len(items) = %d, want 2 (idempotent insert duplicated items)", len(items))
	}
}

func TestAppendPlan_FKMissingApprovedVersion(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, _, seq := seedPlanProductAndVersion(ctx, t, store)
	body := json.RawMessage(`{"k":"v"}`)
	plan, items := newPlanWithItems(t, productID, domain.NewID(), seq, body, 1)

	err := store.AppendPlan(ctx, plan, items)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrNotFound", err)
	}
}

func TestAppendPlan_FKMissingProduct(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, avID, seq := seedPlanProductAndVersion(ctx, t, store)
	body := json.RawMessage(`{"k":"v"}`)
	plan, items := newPlanWithItems(t, domain.NewID(), avID, seq, body, 1)

	err := store.AppendPlan(ctx, plan, items)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrNotFound", err)
	}
}

func TestListPlansByProduct_OrderingLimitEmpty(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedPlanProductAndVersion(ctx, t, store)

	// Empty case first.
	plans, err := store.ListPlansByProduct(ctx, productID, 0)
	if err != nil {
		t.Fatalf("ListPlansByProduct (empty): %v", err)
	}
	if len(plans) != 0 {
		t.Errorf("len(plans) = %d, want 0 on empty product", len(plans))
	}

	// Two plans with distinct content_hashes and explicit GeneratedAt
	// values so ordering is deterministic regardless of insert latency.
	earlier := time.Now().UTC().Add(-2 * time.Minute)
	later := earlier.Add(time.Minute)

	first, firstItems := newPlanWithItems(t, productID, avID, seq, json.RawMessage(`{"k":1}`), 1)
	first.GeneratedAt = earlier
	if err := store.AppendPlan(ctx, first, firstItems); err != nil {
		t.Fatalf("AppendPlan first: %v", err)
	}
	second, secondItems := newPlanWithItems(t, productID, avID, seq, json.RawMessage(`{"k":2}`), 1)
	second.GeneratedAt = later
	if err := store.AppendPlan(ctx, second, secondItems); err != nil {
		t.Fatalf("AppendPlan second: %v", err)
	}

	plans, err = store.ListPlansByProduct(ctx, productID, 0)
	if err != nil {
		t.Fatalf("ListPlansByProduct: %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("len(plans) = %d, want 2", len(plans))
	}
	if plans[0].ID != second.ID {
		t.Errorf("plans[0].ID = %q, want %q (newest first)", plans[0].ID, second.ID)
	}
	if plans[1].ID != first.ID {
		t.Errorf("plans[1].ID = %q, want %q (oldest last)", plans[1].ID, first.ID)
	}

	// limit semantics.
	limited, err := store.ListPlansByProduct(ctx, productID, 1)
	if err != nil {
		t.Fatalf("ListPlansByProduct limit=1: %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("len(limited) = %d, want 1", len(limited))
	}
	if limited[0].ID != second.ID {
		t.Errorf("limited[0].ID = %q, want %q (newest)", limited[0].ID, second.ID)
	}
}

func TestListPlansByApprovedVersion_FilterAndEmpty(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedPlanProductAndVersion(ctx, t, store)

	plans, err := store.ListPlansByApprovedVersion(ctx, avID)
	if err != nil {
		t.Fatalf("ListPlansByApprovedVersion (empty): %v", err)
	}
	if len(plans) != 0 {
		t.Errorf("len(plans) = %d, want 0", len(plans))
	}

	// One plan against avID; one plan against an unrelated av (we seed
	// a fresh av in a fresh product to keep the filter test honest).
	plan, items := newPlanWithItems(t, productID, avID, seq, json.RawMessage(`{"k":1}`), 1)
	if err := store.AppendPlan(ctx, plan, items); err != nil {
		t.Fatalf("AppendPlan: %v", err)
	}

	otherProductID, otherAVID, otherSeq := seedPlanProductAndVersion(ctx, t, store)
	other, otherItems := newPlanWithItems(t, otherProductID, otherAVID, otherSeq, json.RawMessage(`{"k":2}`), 1)
	if err := store.AppendPlan(ctx, other, otherItems); err != nil {
		t.Fatalf("AppendPlan other: %v", err)
	}

	plans, err = store.ListPlansByApprovedVersion(ctx, avID)
	if err != nil {
		t.Fatalf("ListPlansByApprovedVersion: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("len(plans) = %d, want 1 (filter leaked across approved_versions)", len(plans))
	}
	if plans[0].ID != plan.ID {
		t.Errorf("plans[0].ID = %q, want %q", plans[0].ID, plan.ID)
	}
}

func TestUpdatePlanState_HappyPath(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	productID, avID, seq := seedPlanProductAndVersion(ctx, t, store)
	plan, items := newPlanWithItems(t, productID, avID, seq, json.RawMessage(`{"k":1}`), 1)
	if err := store.AppendPlan(ctx, plan, items); err != nil {
		t.Fatalf("AppendPlan: %v", err)
	}

	// Draft -> Ready, no reason.
	if err := store.UpdatePlanState(ctx, plan.ID, domain.PlanStateReady, ""); err != nil {
		t.Fatalf("UpdatePlanState ready: %v", err)
	}
	got, _, err := store.GetPlanByID(ctx, plan.ID)
	if err != nil {
		t.Fatalf("GetPlanByID: %v", err)
	}
	if got.State != domain.PlanStateReady {
		t.Errorf("State = %q, want ready", got.State)
	}
	if got.RefusedReason != "" {
		t.Errorf("RefusedReason = %q, want empty", got.RefusedReason)
	}

	// Ready -> Refused with a reason.
	if err := store.UpdatePlanState(ctx, plan.ID, domain.PlanStateRefused, "policy denied"); err != nil {
		t.Fatalf("UpdatePlanState refused: %v", err)
	}
	got, _, err = store.GetPlanByID(ctx, plan.ID)
	if err != nil {
		t.Fatalf("GetPlanByID: %v", err)
	}
	if got.State != domain.PlanStateRefused {
		t.Errorf("State = %q, want refused", got.State)
	}
	if got.RefusedReason != "policy denied" {
		t.Errorf("RefusedReason = %q, want %q", got.RefusedReason, "policy denied")
	}
}

func TestUpdatePlanState_MissingID(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := store.UpdatePlanState(ctx, domain.NewID(), domain.PlanStateReady, "")
	if !errors.Is(err, storage.ErrPlanNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrPlanNotFound", err)
	}
}

func TestGetPlanByID_NotFound(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, _, err := store.GetPlanByID(ctx, domain.NewID())
	if !errors.Is(err, storage.ErrPlanNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrPlanNotFound", err)
	}
}
