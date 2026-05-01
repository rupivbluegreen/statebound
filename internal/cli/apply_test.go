package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/domain"
)

// TestApply_HelpText asserts the Phase 6 apply subcommand renders help text
// listing every documented flag. Help-text rendering is the cheapest
// regression guard for a CLI surface; if a flag is renamed or dropped,
// this test catches it before the integration smoke does.
func TestApply_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addApplyCmd(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"apply", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(apply --help): %v", err)
	}
	out := buf.String()
	for _, want := range []string{"--target", "--dry-run", "--apply", "--output"} {
		if !strings.Contains(out, want) {
			t.Errorf("apply --help output missing %q; got:\n%s", want, out)
		}
	}
}

// TestApply_RequiresPlanID asserts the positional plan-id argument is
// required (cobra.ExactArgs(1)).
func TestApply_RequiresPlanID(t *testing.T) {
	cmd := newApplyCmd()
	if cmd.Args == nil {
		t.Fatal("expected ExactArgs(1) on apply")
	}
	if err := cmd.Args(cmd, nil); err == nil {
		t.Errorf("apply with no positional args should error")
	}
	if err := cmd.Args(cmd, []string{"a", "b"}); err == nil {
		t.Errorf("apply with two positional args should error")
	}
	if err := cmd.Args(cmd, []string{"abc"}); err != nil {
		t.Errorf("apply with one positional arg should not error; got %v", err)
	}
}

// TestApply_FlagDefaults pins the default values for the optional flags
// so a future refactor that flips them trips this test.
func TestApply_FlagDefaults(t *testing.T) {
	cmd := newApplyCmd()
	if got := cmd.Flag("dry-run").DefValue; got != "false" {
		t.Errorf("--dry-run default = %q; want %q", got, "false")
	}
	if got := cmd.Flag("apply").DefValue; got != "false" {
		t.Errorf("--apply default = %q; want %q", got, "false")
	}
	if got := cmd.Flag("output").DefValue; got != "-" {
		t.Errorf("--output default = %q; want %q", got, "-")
	}
}

// TestConnectorSupportsApply sanity-checks the apply gate against a
// connector that advertises CapabilityApply and one that doesn't. We
// build through stubApplyConnector (full Connector interface) so the
// gate can be exercised exactly the way runApply will use it.
func TestConnectorSupportsApply(t *testing.T) {
	yes := stubApplyConnector{caps: []connectors.Capability{connectors.CapabilityPlan, connectors.CapabilityApply}}
	no := stubApplyConnector{caps: []connectors.Capability{connectors.CapabilityPlan}}
	if !connectorSupportsApply(yes) {
		t.Errorf("connector advertising CapabilityApply should support apply")
	}
	if connectorSupportsApply(no) {
		t.Errorf("connector without CapabilityApply should not support apply")
	}
}

// TestClassifyApplyResult_Succeeded verifies a clean run with all items
// applied or skipped lands as Succeeded with the connector's summary
// hash and applied/failed counts derived from item statuses.
func TestClassifyApplyResult_Succeeded(t *testing.T) {
	startedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	res := &connectors.ApplyResult{
		ConnectorName:    "postgres",
		ConnectorVersion: "0.6.0",
		Target:           "postgres://example",
		StartedAt:        startedAt,
		FinishedAt:       finishedAt,
		DryRun:           true,
		Items: []connectors.ApplyItemResult{
			{Sequence: 1, ResourceKind: "postgres.role", ResourceRef: "payments_batch", Status: "applied", Statements: []string{"CREATE ROLE payments_batch"}},
			{Sequence: 2, ResourceKind: "postgres.grant", ResourceRef: "payments_readonly:public.accounts", Status: "skipped", Statements: []string{"-- already granted"}},
		},
		SummaryHash: "sha256:cafebabe",
	}
	state, applied, failed, summaryHash, output, msg := classifyApplyResult(res, nil)
	if state != domain.PlanApplyStateSucceeded {
		t.Errorf("state = %s, want %s", state, domain.PlanApplyStateSucceeded)
	}
	if applied != 2 {
		t.Errorf("applied = %d, want 2", applied)
	}
	if failed != 0 {
		t.Errorf("failed = %d, want 0", failed)
	}
	if summaryHash != "sha256:cafebabe" {
		t.Errorf("summary_hash = %q, want connector-supplied %q", summaryHash, "sha256:cafebabe")
	}
	if msg != "" {
		t.Errorf("failure_message = %q, want empty for success", msg)
	}
	if !json.Valid(output) {
		t.Errorf("output is not valid JSON: %s", output)
	}
}

// TestClassifyApplyResult_FailedItem flags any failed item even when the
// connector itself returned no error. The aggregated failure_message
// references the failed item.
func TestClassifyApplyResult_FailedItem(t *testing.T) {
	res := &connectors.ApplyResult{
		Items: []connectors.ApplyItemResult{
			{Sequence: 1, Status: "applied"},
			{Sequence: 2, ResourceRef: "broken", Status: "failed", Error: "syntax error"},
		},
		SummaryHash: "sha256:abc",
	}
	state, applied, failed, _, _, msg := classifyApplyResult(res, nil)
	if state != domain.PlanApplyStateFailed {
		t.Errorf("state = %s, want Failed", state)
	}
	if applied != 1 {
		t.Errorf("applied = %d, want 1", applied)
	}
	if failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
	if !strings.Contains(msg, "syntax error") {
		t.Errorf("failure_message = %q, want it to mention 'syntax error'", msg)
	}
}

// TestClassifyApplyResult_ConnectorError covers the "connector returned
// nil result + error" path: the apply lands as Failed with the error
// surfaced verbatim as the failure_message.
func TestClassifyApplyResult_ConnectorError(t *testing.T) {
	state, applied, failed, summaryHash, output, msg := classifyApplyResult(nil, errors.New("dial tcp: refused"))
	if state != domain.PlanApplyStateFailed {
		t.Errorf("state = %s, want Failed", state)
	}
	if applied != 0 || failed != 0 {
		t.Errorf("applied/failed = %d/%d, want 0/0", applied, failed)
	}
	if summaryHash != "" {
		t.Errorf("summary_hash = %q, want empty for nil result", summaryHash)
	}
	if !strings.Contains(msg, "dial tcp") {
		t.Errorf("failure_message = %q, want connector error verbatim", msg)
	}
	if string(output) != "{}" {
		t.Errorf("output = %s, want {}", output)
	}
}

// TestSummarizeApply pins the stderr summary line shape so a regression
// in the summary copy trips this test rather than a CI grep.
func TestSummarizeApply(t *testing.T) {
	rec := &domain.PlanApplyRecord{
		ID:           "00000000-0000-0000-0000-aaaaaaaaaaaa",
		PlanID:       "00000000-0000-0000-0000-bbbbbbbbbbbb",
		State:        domain.PlanApplyStateSucceeded,
		Target:       "postgres://x",
		DryRun:       true,
		AppliedItems: 3,
		FailedItems:  0,
	}
	plan := &domain.Plan{
		ID:            "00000000-0000-0000-0000-bbbbbbbbbbbb",
		ConnectorName: "postgres",
	}
	got := summarizeApply(rec, plan)
	for _, want := range []string{"apply", "postgres", "target=postgres://x", "dry-run=true", "succeeded", "3/3"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q; got %q", want, got)
		}
	}
}

// TestBuildApplyOutput_NilResultStillProducesShape ensures the wire
// shape is well-formed even when the connector returned nil (e.g.
// dial-time failure). The result.items field is a non-nil empty slice
// so downstream tooling can iterate without a nil check.
func TestBuildApplyOutput_NilResultStillProducesShape(t *testing.T) {
	rec := &domain.PlanApplyRecord{
		ID:             "00000000-0000-0000-0000-aaaaaaaaaaaa",
		PlanID:         "00000000-0000-0000-0000-bbbbbbbbbbbb",
		State:          domain.PlanApplyStateFailed,
		StartedAt:      time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		Actor:          domain.Actor{Kind: domain.ActorHuman, Subject: "alice"},
		Target:         "postgres://x",
		DryRun:         false,
		AppliedItems:   0,
		FailedItems:    0,
		FailureMessage: "dial tcp: refused",
		Output:         json.RawMessage("{}"),
	}
	out, err := buildApplyOutput(rec, nil)
	if err != nil {
		t.Fatalf("buildApplyOutput: %v", err)
	}
	if out.ApplyRecord.State != "failed" {
		t.Errorf("state = %s, want failed", out.ApplyRecord.State)
	}
	if out.ApplyRecord.FailureMessage != "dial tcp: refused" {
		t.Errorf("failure_message = %q, want dial tcp: refused", out.ApplyRecord.FailureMessage)
	}
	if out.Result.Items == nil {
		t.Errorf("Result.Items should be a non-nil empty slice")
	}
	// Wire shape must be canonical-JSON-serialisable.
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !json.Valid(b) {
		t.Fatalf("output is not valid JSON: %s", b)
	}
}

// TestBuildPlanForApply_RoundTripsItems verifies items survive the
// domain.PlanItem -> connectors.PlanItem translation with their bodies
// re-hydrated as map[string]any.
func TestBuildPlanForApply_RoundTripsItems(t *testing.T) {
	plan := &domain.Plan{
		ID:                "00000000-0000-0000-0000-aaaaaaaaaaaa",
		ProductID:         "00000000-0000-0000-0000-bbbbbbbbbbbb",
		ApprovedVersionID: "00000000-0000-0000-0000-cccccccccccc",
		Sequence:          1,
		ConnectorName:     "postgres",
		ConnectorVersion:  "0.6.0",
	}
	items := []*domain.PlanItem{
		{
			ID:           "00000000-0000-0000-0000-dddddddddddd",
			PlanID:       plan.ID,
			Sequence:     1,
			Action:       "create",
			ResourceKind: "postgres.role",
			ResourceRef:  "payments_batch",
			Body:         json.RawMessage(`{"role":"payments_batch","login":true}`),
			Risk:         "medium",
			Note:         "from desired state",
		},
	}
	got, err := buildPlanForApply(plan, items)
	if err != nil {
		t.Fatalf("buildPlanForApply: %v", err)
	}
	if got.PlanID != string(plan.ID) {
		t.Errorf("PlanID = %q, want %q", got.PlanID, plan.ID)
	}
	if got.ConnectorName != "postgres" {
		t.Errorf("ConnectorName = %q, want postgres", got.ConnectorName)
	}
	if len(got.Items) != 1 {
		t.Fatalf("len(Items) = %d, want 1", len(got.Items))
	}
	body := got.Items[0].Body
	if body["role"] != "payments_batch" {
		t.Errorf("Items[0].Body.role = %v, want payments_batch", body["role"])
	}
	if got.Items[0].Risk != "medium" {
		t.Errorf("Items[0].Risk = %q, want medium", got.Items[0].Risk)
	}
}

// stubApplyConnector is a minimal Connector for exercising the
// capability gate in isolation. It is not registered with the registry
// — connectorSupportsApply only inspects Capabilities() so the
// remaining methods can stay as embedded Unsupported* defaults.
type stubApplyConnector struct {
	connectors.UnsupportedCollectAndCompare
	connectors.UnsupportedApply
	caps []connectors.Capability
}

func (stubApplyConnector) Name() string                            { return "stub" }
func (stubApplyConnector) Version() string                         { return "0.0.0" }
func (s stubApplyConnector) Capabilities() []connectors.Capability { return s.caps }
func (stubApplyConnector) ValidateDesiredState(_ context.Context, _ connectors.ApprovedState) ([]connectors.ValidationFinding, error) {
	return nil, nil
}
func (stubApplyConnector) Plan(_ context.Context, _ connectors.ApprovedState) (*connectors.PlanResult, error) {
	return nil, connectors.ErrCapabilityNotSupported
}
