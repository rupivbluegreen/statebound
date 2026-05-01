package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"statebound.dev/statebound/internal/connectors"
)

// targetDSNEnv is the env var that gates the live-target apply tests.
//
// To run the live tests against a docker-compose Postgres, export:
//
//	STATEBOUND_PG_TARGET_DSN="postgres://statebound:statebound@localhost:5432/postgres?sslmode=disable"
//
// Without this env var the tests skip cleanly so CI passes without
// requiring a target Postgres.
const targetDSNEnv = "STATEBOUND_PG_TARGET_DSN"

// planForApplyFromState rebuilds a *connectors.PlanForApply from
// syntheticState() so apply tests don't need access to internal CLI
// glue.
func planForApplyFromState(t *testing.T) *connectors.PlanForApply {
	t.Helper()
	c := New()
	state := syntheticState()
	plan, err := c.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return &connectors.PlanForApply{
		PlanID:            "test-plan",
		ProductID:         "test-product",
		ApprovedVersionID: "test-av",
		Sequence:          state.Sequence,
		ConnectorName:     plan.ConnectorName,
		ConnectorVersion:  plan.ConnectorVersion,
		Items:             plan.Items,
	}
}

func TestApply_GuardClauses(t *testing.T) {
	c := New()
	if _, err := c.Apply(context.Background(), nil, connectors.ApplyOptions{Target: "x"}); err == nil {
		t.Errorf("expected error for nil plan")
	}
	plan := planForApplyFromState(t)
	if _, err := c.Apply(context.Background(), plan, connectors.ApplyOptions{Target: ""}); err == nil {
		t.Errorf("expected error for empty target")
	}
}

func TestApply_DryRun(t *testing.T) {
	c := New()
	plan := planForApplyFromState(t)
	res, err := c.Apply(context.Background(), plan, connectors.ApplyOptions{
		DryRun: true,
		Target: "postgres://example/payments?sslmode=disable", // never dialled in dry run
	})
	if err != nil {
		t.Fatalf("Apply dry-run: %v", err)
	}
	if !res.DryRun {
		t.Errorf("DryRun = false, want true")
	}
	if res.ConnectorName != "postgres" {
		t.Errorf("ConnectorName = %q", res.ConnectorName)
	}
	if len(res.Items) != len(plan.Items) {
		t.Fatalf("len(Items) = %d, want %d", len(res.Items), len(plan.Items))
	}
	for i, it := range res.Items {
		if it.Status != "skipped" {
			t.Errorf("Items[%d].Status = %q, want skipped", i, it.Status)
		}
		if len(it.Statements) == 0 {
			t.Errorf("Items[%d].Statements is empty", i)
		}
	}
	if res.SummaryHash == "" {
		t.Errorf("SummaryHash unset")
	}
	if res.StartedAt.IsZero() || res.FinishedAt.IsZero() {
		t.Errorf("timestamps not set")
	}
	// Spot-check that the role create wraps in a DO block.
	for _, it := range res.Items {
		if it.ResourceKind == "postgres.role" {
			joined := strings.Join(it.Statements, "\n")
			if !strings.Contains(joined, "duplicate_object") {
				t.Errorf("role apply statements missing duplicate_object guard: %s", joined)
			}
		}
	}
}

func TestApply_DryRunDeterministic(t *testing.T) {
	c := New()
	plan := planForApplyFromState(t)
	a, _ := c.Apply(context.Background(), plan, connectors.ApplyOptions{DryRun: true, Target: "postgres://x"})
	b, _ := c.Apply(context.Background(), plan, connectors.ApplyOptions{DryRun: true, Target: "postgres://x"})
	if a.SummaryHash != b.SummaryHash {
		t.Errorf("dry-run SummaryHash differs across runs:\nA=%s\nB=%s", a.SummaryHash, b.SummaryHash)
	}
}

// TestApply_LiveTarget exercises the real Apply path against a live
// Postgres. Requires STATEBOUND_PG_TARGET_DSN. Skipped by default.
//
// The test creates the desired roles, runs Apply, then revokes/drops
// them so a re-run starts clean. We do NOT assert idempotency in the
// strict "apply twice produces zero changes" sense — Phase 6 records
// what was executed, not whether it was a no-op. Re-applies are safe
// because the SQL is idempotent (DO block on CREATE ROLE; GRANT is
// no-op on already-granted privilege).
func TestApply_LiveTarget(t *testing.T) {
	dsn := os.Getenv(targetDSNEnv)
	if dsn == "" {
		t.Skipf("set %s to enable live-target apply tests", targetDSNEnv)
	}
	c := New()
	plan := planForApplyFromState(t)

	// Real apply.
	res, err := c.Apply(context.Background(), plan, connectors.ApplyOptions{
		DryRun: false,
		Target: dsn,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.DryRun {
		t.Errorf("DryRun = true on real apply")
	}
	for i, it := range res.Items {
		if it.Status == "failed" {
			t.Errorf("Items[%d] failed: %s", i, it.Error)
		}
	}
	if res.SummaryHash == "" {
		t.Errorf("SummaryHash unset")
	}

	// Cleanup: revoke + drop role so test is idempotent.
	t.Cleanup(func() { cleanupAppliedTargets(t, dsn, plan) })
}
