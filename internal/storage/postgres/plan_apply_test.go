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

// seedPlanForApply produces a fresh product + approved version + plan
// suitable for parenting plan_apply_records rows. Returns the plan id.
func seedPlanForApply(ctx context.Context, t *testing.T, store *postgres.Store) domain.ID {
	t.Helper()
	productID, avID, seq := seedPlanProductAndVersion(ctx, t, store)
	body := json.RawMessage(`{"k":"v"}`)
	plan, items := newPlanWithItems(t, productID, avID, seq, body, 1)
	if err := store.AppendPlan(ctx, plan, items); err != nil {
		t.Fatalf("AppendPlan: %v", err)
	}
	return plan.ID
}

func TestAppendPlanApplyRecord_HappyPath(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	planID := seedPlanForApply(ctx, t, store)
	rec, err := domain.NewPlanApplyRecord(planID,
		domain.Actor{Kind: domain.ActorHuman, Subject: "engineer@example.com"},
		"postgres://host:5432/payments", false)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord: %v", err)
	}
	if err := store.AppendPlanApplyRecord(ctx, rec); err != nil {
		t.Fatalf("AppendPlanApplyRecord: %v", err)
	}

	got, err := store.GetPlanApplyRecordByID(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetPlanApplyRecordByID: %v", err)
	}
	if got.ID != rec.ID {
		t.Errorf("ID = %q, want %q", got.ID, rec.ID)
	}
	if got.PlanID != planID {
		t.Errorf("PlanID = %q, want %q", got.PlanID, planID)
	}
	if got.State != domain.PlanApplyStateRunning {
		t.Errorf("State = %q, want running", got.State)
	}
	if got.Target != "postgres://host:5432/payments" {
		t.Errorf("Target = %q, want postgres://host:5432/payments", got.Target)
	}
	if got.DryRun {
		t.Error("DryRun = true, want false")
	}
	if got.Actor.Kind != domain.ActorHuman {
		t.Errorf("Actor.Kind = %q, want human", got.Actor.Kind)
	}
	if got.Actor.Subject != "engineer@example.com" {
		t.Errorf("Actor.Subject = %q, want engineer@example.com", got.Actor.Subject)
	}
	if got.AppliedItems != 0 {
		t.Errorf("AppliedItems = %d, want 0", got.AppliedItems)
	}
	if got.FailedItems != 0 {
		t.Errorf("FailedItems = %d, want 0", got.FailedItems)
	}
	if got.FinishedAt != nil {
		t.Errorf("FinishedAt = %v, want nil", got.FinishedAt)
	}
}

func TestUpdatePlanApplyRecord_TransitionToSucceeded(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	planID := seedPlanForApply(ctx, t, store)
	rec, err := domain.NewPlanApplyRecord(planID,
		domain.Actor{Kind: domain.ActorHuman, Subject: "engineer@example.com"},
		"target", false)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord: %v", err)
	}
	if err := store.AppendPlanApplyRecord(ctx, rec); err != nil {
		t.Fatalf("AppendPlanApplyRecord: %v", err)
	}

	finishedAt := time.Now().UTC()
	output := json.RawMessage(`{"items":[{"sequence":1,"status":"applied"}]}`)
	if err := rec.Transition(domain.PlanApplyStateSucceeded, finishedAt, "abc123", output, 1, 0, ""); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if err := store.UpdatePlanApplyRecord(ctx, rec); err != nil {
		t.Fatalf("UpdatePlanApplyRecord: %v", err)
	}

	got, err := store.GetPlanApplyRecordByID(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetPlanApplyRecordByID: %v", err)
	}
	if got.State != domain.PlanApplyStateSucceeded {
		t.Errorf("State = %q, want succeeded", got.State)
	}
	if got.FinishedAt == nil {
		t.Fatal("FinishedAt nil; want set")
	}
	if got.AppliedItems != 1 {
		t.Errorf("AppliedItems = %d, want 1", got.AppliedItems)
	}
	if got.FailedItems != 0 {
		t.Errorf("FailedItems = %d, want 0", got.FailedItems)
	}
	if got.SummaryHash != "abc123" {
		t.Errorf("SummaryHash = %q, want abc123", got.SummaryHash)
	}
	// Output round-trips as canonical JSON; compare as decoded values to
	// tolerate Postgres's whitespace normalization.
	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(got.Output, &gotMap); err != nil {
		t.Fatalf("unmarshal got.Output: %v", err)
	}
	if err := json.Unmarshal(output, &wantMap); err != nil {
		t.Fatalf("unmarshal want output: %v", err)
	}
	gotJSON, _ := json.Marshal(gotMap)
	wantJSON, _ := json.Marshal(wantMap)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("Output = %s, want %s", string(gotJSON), string(wantJSON))
	}
}

func TestUpdatePlanApplyRecord_TransitionToFailed(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	planID := seedPlanForApply(ctx, t, store)
	rec, err := domain.NewPlanApplyRecord(planID,
		domain.Actor{Kind: domain.ActorHuman, Subject: "engineer@example.com"},
		"target", false)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord: %v", err)
	}
	if err := store.AppendPlanApplyRecord(ctx, rec); err != nil {
		t.Fatalf("AppendPlanApplyRecord: %v", err)
	}

	finishedAt := time.Now().UTC()
	output := json.RawMessage(`{"items":[{"sequence":1,"status":"failed","error":"connection refused"}]}`)
	if err := rec.Transition(domain.PlanApplyStateFailed, finishedAt, "deadbeef", output, 0, 1, "connection refused"); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if err := store.UpdatePlanApplyRecord(ctx, rec); err != nil {
		t.Fatalf("UpdatePlanApplyRecord: %v", err)
	}

	got, err := store.GetPlanApplyRecordByID(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetPlanApplyRecordByID: %v", err)
	}
	if got.State != domain.PlanApplyStateFailed {
		t.Errorf("State = %q, want failed", got.State)
	}
	if got.FailureMessage != "connection refused" {
		t.Errorf("FailureMessage = %q, want connection refused", got.FailureMessage)
	}
	if got.FailedItems != 1 {
		t.Errorf("FailedItems = %d, want 1", got.FailedItems)
	}
}

func TestUpdatePlanApplyRecord_NotFound(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rec := &domain.PlanApplyRecord{
		ID:     domain.NewID(),
		PlanID: domain.NewID(),
		State:  domain.PlanApplyStateSucceeded,
	}
	err := store.UpdatePlanApplyRecord(ctx, rec)
	if !errors.Is(err, storage.ErrPlanApplyRecordNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrPlanApplyRecordNotFound", err)
	}
}

func TestAppendPlanApplyRecord_FKMissingPlan(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rec, err := domain.NewPlanApplyRecord(domain.NewID(),
		domain.Actor{Kind: domain.ActorHuman, Subject: "engineer@example.com"},
		"target", false)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord: %v", err)
	}
	err = store.AppendPlanApplyRecord(ctx, rec)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrNotFound", err)
	}
}

func TestGetPlanApplyRecordByID_NotFound(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := store.GetPlanApplyRecordByID(ctx, domain.NewID())
	if !errors.Is(err, storage.ErrPlanApplyRecordNotFound) {
		t.Errorf("err = %v, want errors.Is == storage.ErrPlanApplyRecordNotFound", err)
	}
}

func TestListPlanApplyRecordsByPlan_OrderingAndEmpty(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	planID := seedPlanForApply(ctx, t, store)

	// Empty case first.
	got, err := store.ListPlanApplyRecordsByPlan(ctx, planID)
	if err != nil {
		t.Fatalf("ListPlanApplyRecordsByPlan (empty): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0 on empty plan", len(got))
	}

	// Two records with distinct StartedAt values so ordering is
	// deterministic regardless of insert latency.
	earlier := time.Now().UTC().Add(-2 * time.Minute)
	later := earlier.Add(time.Minute)

	first, err := domain.NewPlanApplyRecord(planID,
		domain.Actor{Kind: domain.ActorHuman, Subject: "engineer@example.com"},
		"target-1", false)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord first: %v", err)
	}
	first.StartedAt = earlier
	if err := store.AppendPlanApplyRecord(ctx, first); err != nil {
		t.Fatalf("AppendPlanApplyRecord first: %v", err)
	}

	second, err := domain.NewPlanApplyRecord(planID,
		domain.Actor{Kind: domain.ActorHuman, Subject: "engineer@example.com"},
		"target-2", true)
	if err != nil {
		t.Fatalf("NewPlanApplyRecord second: %v", err)
	}
	second.StartedAt = later
	if err := store.AppendPlanApplyRecord(ctx, second); err != nil {
		t.Fatalf("AppendPlanApplyRecord second: %v", err)
	}

	got, err = store.ListPlanApplyRecordsByPlan(ctx, planID)
	if err != nil {
		t.Fatalf("ListPlanApplyRecordsByPlan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].ID != second.ID {
		t.Errorf("got[0].ID = %q, want %q (newest first)", got[0].ID, second.ID)
	}
	if got[1].ID != first.ID {
		t.Errorf("got[1].ID = %q, want %q (oldest last)", got[1].ID, first.ID)
	}
	if !got[0].DryRun {
		t.Error("got[0].DryRun = false, want true (second was dry-run)")
	}
	if got[1].DryRun {
		t.Error("got[1].DryRun = true, want false (first was real)")
	}
}
