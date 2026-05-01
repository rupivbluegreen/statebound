// Package cli — apply subcommand. Phase 6 wires connector apply into the
// CLI so operators can execute an OPA-gated, approved Plan against a
// target system. The default behaviour is `--dry-run`: the connector
// produces the same per-item Statements it would otherwise execute but
// does not mutate the target; the parent Plan stays Ready. Passing
// `--apply` (mutually exclusive with `--dry-run`) is required to
// actually mutate the target system; a successful real apply transitions
// the parent Plan to Applied.
//
// Behaviour in order:
//  1. Resolve plan + items via storage.
//  2. Refuse if plan.State != Ready.
//  3. Resolve connector and verify CapabilityApply.
//  4. Re-evaluate OPA against the parent ApprovedVersion (defense in
//     depth) — refuse with EventApplyFailed if denied.
//  5. AppendPlanApplyRecord(running) + EventApplyStarted in one tx.
//  6. Call connector.Apply OUTSIDE any tx (network/I/O work).
//  7. Transition record to Succeeded|Failed, persist, emit terminal
//     audit event, optionally transition Plan -> Applied (real apply
//     only), in a fresh tx.
//  8. Marshal the canonical {apply_record, result} JSON to --output.
//
// Apply is never chained from `plan`. Apply is always its own command
// invocation, and its default behaviour is dry-run-only — passing
// `--apply` is the explicit, auditable confirmation that the operator
// wants to mutate the target system.
package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/codes"

	"statebound.dev/statebound/internal/authz"
	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/connectors/builtins"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
	"statebound.dev/statebound/internal/signing"
	"statebound.dev/statebound/internal/storage"
	"statebound.dev/statebound/internal/telemetry"
)

// signingVerify is an indirection over signing.Verify so an apply test
// can inject a fixture if needed. Phase 8 wave A.
var signingVerify = signing.Verify

// addApplyCmd registers `statebound apply` on parent (root command).
func addApplyCmd(parent *cobra.Command) {
	parent.AddCommand(newApplyCmd())
}

// newApplyCmd builds the cobra.Command for `statebound apply`. Kept as
// its own constructor so the help-text test can exercise it without
// booting the full root tree.
func newApplyCmd() *cobra.Command {
	var (
		target string
		dryRun bool
		apply  bool
		output string
	)
	cmd := &cobra.Command{
		Use:   "apply <plan-id>",
		Short: "Apply an approved, Ready plan to a target system",
		Long: "Executes the named connector's Apply path against a Plan in " +
			"PlanStateReady. Default behaviour is --dry-run: the connector " +
			"builds the per-item Statements (e.g. SQL DCL) but does not " +
			"mutate the target system, and the parent Plan stays Ready. " +
			"Passing --apply is required to mutate the target; a successful " +
			"real apply transitions the parent Plan to Applied. " +
			"--dry-run and --apply are mutually exclusive. The canonical " +
			"{apply_record, result} JSON is written to --output.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			return runApply(cmd.Context(), store, cmd.OutOrStdout(), cmd.ErrOrStderr(), applyArgs{
				planID: domain.ID(args[0]),
				target: target,
				dryRun: dryRun,
				apply:  apply,
				output: output,
				actor:  actor,
			})
		},
	}
	cmd.Flags().StringVar(&target, "target", "",
		"connector-specific target identifier (e.g. postgres DSN); required for connectors that mutate a target")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"build the apply payload but do not execute against the target (default behaviour when neither --dry-run nor --apply is set)")
	cmd.Flags().BoolVar(&apply, "apply", false,
		"actually execute the apply against the target system; mutually exclusive with --dry-run")
	cmd.Flags().StringVarP(&output, "output", "o", "-",
		"write apply result JSON to this path; '-' for stdout (default)")
	return cmd
}

// applyArgs bundles the parsed flags so runApply stays narrow.
type applyArgs struct {
	planID domain.ID
	target string
	dryRun bool
	apply  bool
	output string
	actor  domain.Actor
}

// applyOutput is the canonical wire shape written by `statebound apply`.
// Field order is fixed so two encodes of the same record produce
// byte-identical bytes.
type applyOutput struct {
	ApplyRecord applyRecordView `json:"apply_record"`
	Result      applyResultView `json:"result"`
}

// applyRecordView projects a domain.PlanApplyRecord into the canonical
// JSON shape. We keep this hand-rolled rather than letting domain types
// leak — domain types have no JSON tags and the wire shape is part of
// the public CLI contract.
type applyRecordView struct {
	ID             domain.ID       `json:"id"`
	PlanID         domain.ID       `json:"plan_id"`
	State          string          `json:"state"`
	StartedAt      time.Time       `json:"started_at"`
	FinishedAt     *time.Time      `json:"finished_at,omitempty"`
	ActorKind      string          `json:"actor_kind"`
	ActorSubject   string          `json:"actor_subject"`
	Target         string          `json:"target"`
	DryRun         bool            `json:"dry_run"`
	AppliedItems   int             `json:"applied_items"`
	FailedItems    int             `json:"failed_items"`
	FailureMessage string          `json:"failure_message,omitempty"`
	SummaryHash    string          `json:"summary_hash"`
	Output         json.RawMessage `json:"output,omitempty"`
}

// applyResultView mirrors connectors.ApplyResult on the wire so the
// auditor sees exactly what the connector returned.
type applyResultView struct {
	ConnectorName    string                `json:"connector_name"`
	ConnectorVersion string                `json:"connector_version"`
	Target           string                `json:"target"`
	StartedAt        time.Time             `json:"started_at"`
	FinishedAt       time.Time             `json:"finished_at"`
	DryRun           bool                  `json:"dry_run"`
	SummaryHash      string                `json:"summary_hash"`
	Items            []applyItemResultView `json:"items"`
}

// applyItemResultView mirrors connectors.ApplyItemResult.
type applyItemResultView struct {
	Sequence     int      `json:"sequence"`
	ResourceKind string   `json:"resource_kind"`
	ResourceRef  string   `json:"resource_ref"`
	Status       string   `json:"status"`
	Statements   []string `json:"statements"`
	RowsAffected int      `json:"rows_affected"`
	Error        string   `json:"error,omitempty"`
}

// runApply is the testable handler body. The flow is intentionally
// linear and matches the contract in CLAUDE.md / the agent prompt.
//
// Wave A telemetry: every apply produces a top-level "apply.execute"
// span, with one child span around the connector.Apply call (the only
// step that may do real network I/O). plan_id and dry_run are recorded
// on the parent span; connector identity is added once resolved.
func runApply(ctx context.Context, store storage.Storage, stdout, stderr io.Writer, args applyArgs) error {
	ctx, span := telemetry.StartSpan(ctx, "apply.execute",
		telemetry.AttrPlanID.String(string(args.planID)),
	)
	defer span.End()
	if telemetry.IncludeActor() {
		span.SetAttributes(
			telemetry.AttrActorKind.String(string(args.actor.Kind)),
			telemetry.AttrActorSubject.String(args.actor.Subject),
		)
	}
	recordErr := func(err error) error {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	// 1. Resolve effective dry-run.
	if args.dryRun && args.apply {
		return recordErr(fmt.Errorf("--dry-run and --apply are mutually exclusive"))
	}
	dryRun := args.dryRun
	if !args.apply && !args.dryRun {
		// Default: dry-run with a hint. The user must opt-in to mutation.
		dryRun = true
		_, _ = fmt.Fprintln(stderr,
			"apply requires --apply flag (use --dry-run to preview without --apply); defaulting to --dry-run")
	}
	if !dryRun && !args.apply {
		// Defense-in-depth: spec says without --apply, refuse to mutate.
		// Reachable only if a future refactor changes the dryRun resolution
		// above; keep the explicit check so the contract is local.
		return recordErr(fmt.Errorf("apply requires --apply flag (use --dry-run to preview without --apply)"))
	}
	span.SetAttributes(telemetry.AttrApplyDryRun.Bool(dryRun))

	if args.planID == "" {
		return recordErr(fmt.Errorf("plan id is required"))
	}

	// 1.5. RBAC pre-check: dry-run requires operator/admin; real apply
	// requires admin. We pick the capability after dry-run resolution
	// so a user who passes neither flag still gets the dry-run gate.
	requiredCap := domain.CapabilityApplyDryRun
	if !dryRun {
		requiredCap = domain.CapabilityApply
	}
	if err := requireCapability(ctx, store, stderr, args.actor, requiredCap); err != nil {
		return recordErr(err)
	}

	// 2. Load plan + items.
	plan, planItems, err := store.GetPlanByID(ctx, args.planID)
	if err != nil {
		if errors.Is(err, storage.ErrPlanNotFound) || errors.Is(err, storage.ErrNotFound) {
			return recordErr(fmt.Errorf("plan %s not found", args.planID))
		}
		return recordErr(fmt.Errorf("get plan %s: %w", args.planID, err))
	}
	span.SetAttributes(
		telemetry.AttrConnector.String(plan.ConnectorName),
		telemetry.AttrConnectorVersion.String(plan.ConnectorVersion),
		telemetry.AttrApprovedVersion.Int64(plan.Sequence),
	)

	// 3. Gate on plan state.
	if plan.State != domain.PlanStateReady {
		return recordErr(fmt.Errorf("plan %s is %s; only Ready plans can be applied",
			shortID(plan.ID), plan.State))
	}

	// 4. Connector registry + capability check.
	registry := connectors.NewRegistry()
	builtins.Register(registry)

	conn, ok := registry.Get(plan.ConnectorName)
	if !ok {
		names := make([]string, 0)
		for _, c := range registry.List() {
			names = append(names, c.Name())
		}
		return recordErr(fmt.Errorf("unknown connector %q; available: %s",
			plan.ConnectorName, strings.Join(names, ", ")))
	}
	if !connectorSupportsApply(conn) {
		return recordErr(fmt.Errorf("connector %s does not support apply", conn.Name()))
	}

	// 5. Plan-time OPA re-evaluation against the parent approved version.
	// Mirrors the gate from `plan` so a previously-approved plan whose
	// parent AV has been superseded or whose synthesized rules now deny
	// is refused at apply time. The synthesized input is identical to
	// the one Plan generated, so a previously-Ready plan stays Ready.
	if err := reevaluatePlanPolicy(ctx, store, plan); err != nil {
		// Persist the apply attempt as Failed before surfacing the error
		// so the audit trail records *why* the apply was refused.
		_ = recordApplyRefusal(ctx, store, stderr, plan, args, err.Error())
		return recordErr(err)
	}

	// 5b. Plan-signature gate (Phase 8 wave A). The apply path requires
	// at least one valid Ed25519 signature unless
	// STATEBOUND_DEV_SKIP_PLAN_SIGNATURE=true. Disabled or expired keys
	// do not count.
	if err := verifyPlanSignatures(ctx, store, stderr, plan, args.actor); err != nil {
		_ = recordApplyRefusal(ctx, store, stderr, plan, args, err.Error())
		return recordErr(err)
	}

	// 6. Build connector-side PlanForApply from the persisted items.
	planForApply, err := buildPlanForApply(plan, planItems)
	if err != nil {
		return recordErr(fmt.Errorf("build plan-for-apply: %w", err))
	}

	// 7. Open the apply record + emit apply.started in one tx.
	rec, err := domain.NewPlanApplyRecord(plan.ID, args.actor, args.target, dryRun)
	if err != nil {
		return recordErr(fmt.Errorf("build plan apply record: %w", err))
	}
	if err := store.WithTx(ctx, func(tx storage.Storage) error {
		if err := tx.AppendPlanApplyRecord(ctx, rec); err != nil {
			return fmt.Errorf("append plan apply record: %w", err)
		}
		startedEvt, err := domain.NewAuditEvent(
			domain.EventApplyStarted,
			args.actor,
			"plan_apply",
			string(rec.ID),
			map[string]any{
				"plan_apply_id": string(rec.ID),
				"plan_id":       string(plan.ID),
				"target":        rec.Target,
				"dry_run":       rec.DryRun,
				"connector":     plan.ConnectorName,
			},
		)
		if err != nil {
			return fmt.Errorf("build apply.started audit: %w", err)
		}
		if err := tx.AppendAuditEvent(ctx, startedEvt); err != nil {
			return fmt.Errorf("append apply.started audit: %w", err)
		}
		return nil
	}); err != nil {
		return recordErr(err)
	}
	span.SetAttributes(telemetry.AttrApplyID.String(string(rec.ID)))

	// 8. Call connector.Apply OUTSIDE any tx (it may do network I/O).
	// Wrap it in a child span so operators can see the connector
	// latency separately from our orchestration overhead.
	connCtx, connSpan := telemetry.StartSpan(ctx, "connector.apply",
		telemetry.AttrConnector.String(conn.Name()),
		telemetry.AttrConnectorVersion.String(conn.Version()),
		telemetry.AttrApplyDryRun.Bool(dryRun),
	)
	result, applyErr := conn.Apply(connCtx, planForApply, connectors.ApplyOptions{
		DryRun: dryRun,
		Target: args.target,
	})
	if applyErr != nil {
		connSpan.RecordError(applyErr)
		connSpan.SetStatus(codes.Error, applyErr.Error())
	} else if result != nil {
		connSpan.SetAttributes(telemetry.AttrItemCount.Int(len(result.Items)))
	}
	connSpan.End()

	// 9. Land terminal state in a fresh tx — even if the connector
	// returned an error: the apply record must reach a terminal state.
	finishedAt := time.Now().UTC()
	terminalErr := finalizeApply(ctx, store, plan, rec, result, applyErr, finishedAt, args)
	if terminalErr != nil {
		return recordErr(terminalErr)
	}

	// 10. Write canonical JSON to the sink.
	out, err := buildApplyOutput(rec, result)
	if err != nil {
		return recordErr(fmt.Errorf("build apply output: %w", err))
	}
	if err := writeApplyBytes(stdout, args.output, out); err != nil {
		return recordErr(err)
	}

	// 11. Human summary on stderr.
	if _, err := fmt.Fprintln(stderr, summarizeApply(rec, plan)); err != nil {
		return recordErr(err)
	}

	// 12. If the connector reported a hard error, surface it after the
	// record + audit have been persisted so the operator sees the cause.
	if applyErr != nil {
		return recordErr(applyErr)
	}
	if rec.State == domain.PlanApplyStateFailed {
		return recordErr(fmt.Errorf("apply failed: %s", rec.FailureMessage))
	}
	return nil
}

// connectorSupportsApply reports whether c advertises CapabilityApply.
// We rely on Capabilities() rather than probing for ErrCapabilityNotSupported
// so a connector that advertises but returns the sentinel from Apply (a
// programmer bug) is treated as supporting apply — the bug surfaces in the
// failure mode, not the gate.
func connectorSupportsApply(c connectors.Connector) bool {
	for _, cap := range c.Capabilities() {
		if cap == connectors.CapabilityApply {
			return true
		}
	}
	return false
}

// buildPlanForApply translates persisted domain.PlanItems into the
// connector-side connectors.PlanItem shape. Each item's Body is
// unmarshalled from JSONB into a map[string]any so the connector does
// not need to depend on json.RawMessage shapes.
func buildPlanForApply(plan *domain.Plan, items []*domain.PlanItem) (*connectors.PlanForApply, error) {
	out := &connectors.PlanForApply{
		PlanID:            string(plan.ID),
		ProductID:         string(plan.ProductID),
		ApprovedVersionID: string(plan.ApprovedVersionID),
		Sequence:          plan.Sequence,
		ConnectorName:     plan.ConnectorName,
		ConnectorVersion:  plan.ConnectorVersion,
	}
	out.Items = make([]connectors.PlanItem, 0, len(items))
	for _, it := range items {
		if it == nil {
			continue
		}
		var body map[string]any
		if len(it.Body) > 0 {
			if err := json.Unmarshal(it.Body, &body); err != nil {
				return nil, fmt.Errorf("unmarshal plan item %d body: %w", it.Sequence, err)
			}
		}
		out.Items = append(out.Items, connectors.PlanItem{
			Sequence:     it.Sequence,
			Action:       it.Action,
			ResourceKind: it.ResourceKind,
			ResourceRef:  it.ResourceRef,
			Body:         body,
			Risk:         it.Risk,
			Note:         it.Note,
		})
	}
	return out, nil
}

// reevaluatePlanPolicy reruns the plan-time OPA gate against the
// approved version so an apply against a plan whose parent AV has
// changed risk profile is refused at apply time. Mirrors the synthetic
// input the `plan` subcommand constructs so the verdict stays stable.
func reevaluatePlanPolicy(ctx context.Context, store storage.Storage, plan *domain.Plan) error {
	product, err := store.GetProductByID(ctx, plan.ProductID)
	if err != nil {
		return fmt.Errorf("apply policy gate: get product: %w", err)
	}
	_, snapshot, err := store.GetApprovedVersionByID(ctx, plan.ApprovedVersionID)
	if err != nil {
		return fmt.Errorf("apply policy gate: load approved version: %w", err)
	}
	if snapshot == nil {
		return fmt.Errorf("apply policy gate: approved version %s has no snapshot", plan.ApprovedVersionID)
	}
	pam, err := model.FromSnapshot(snapshot.Content)
	if err != nil {
		return fmt.Errorf("apply policy gate: decode snapshot: %w", err)
	}
	syntheticItems := buildSyntheticPlanItems(pam)
	syntheticCS := domain.ChangeSet{
		ID:        "synthetic-apply-time",
		ProductID: product.ID,
		State:     domain.ChangeSetStateApproved,
		Title:     "synthetic apply-time evaluation",
		RequestedBy: domain.Actor{
			Kind:    domain.ActorSystem,
			Subject: "apply",
		},
	}
	in := authz.Input{
		Phase:     authz.PhaseApprove,
		Product:   *product,
		ChangeSet: syntheticCS,
		Items:     syntheticItems,
		Approvals: nil,
		Approver:  nil,
	}
	eval, err := defaultEvaluator(ctx)
	if err != nil {
		return fmt.Errorf("apply policy gate: load evaluator: %w", err)
	}
	policyResult, err := eval.Evaluate(ctx, in)
	if err != nil {
		return fmt.Errorf("apply policy gate: evaluate: %w", err)
	}
	if policyResult.Outcome == authz.DecisionDeny {
		denyIDs := make([]string, 0)
		for _, r := range policyResult.Rules {
			if r.Outcome == authz.DecisionDeny {
				denyIDs = append(denyIDs, r.RuleID)
			}
		}
		return fmt.Errorf("apply refused by policy: %s", strings.Join(denyIDs, ", "))
	}
	return nil
}

// recordApplyRefusal writes a Failed apply record + apply.failed audit
// event for the cases where the apply is refused before the connector
// is even called (e.g. policy denial). This keeps the audit trail
// complete: every attempt to apply produces a record, even refused ones.
func recordApplyRefusal(
	ctx context.Context,
	store storage.Storage,
	stderr io.Writer,
	plan *domain.Plan,
	args applyArgs,
	failureMessage string,
) error {
	rec, err := domain.NewPlanApplyRecord(plan.ID, args.actor, args.target, !args.apply)
	if err != nil {
		return err
	}
	finishedAt := time.Now().UTC()
	if err := rec.Transition(domain.PlanApplyStateFailed, finishedAt, "", json.RawMessage("{}"), 0, 0, failureMessage); err != nil {
		return err
	}
	return store.WithTx(ctx, func(tx storage.Storage) error {
		if err := tx.AppendPlanApplyRecord(ctx, rec); err != nil {
			return err
		}
		if err := tx.UpdatePlanApplyRecord(ctx, rec); err != nil {
			return err
		}
		failedEvt, err := domain.NewAuditEvent(
			domain.EventApplyFailed,
			args.actor,
			"plan_apply",
			string(rec.ID),
			map[string]any{
				"plan_apply_id":   string(rec.ID),
				"plan_id":         string(plan.ID),
				"failure_message": failureMessage,
				"dry_run":         rec.DryRun,
			},
		)
		if err != nil {
			return err
		}
		if err := tx.AppendAuditEvent(ctx, failedEvt); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stderr,
			"apply %s for plan %s refused before execution: %s\n",
			shortID(rec.ID), shortID(plan.ID), failureMessage)
		return nil
	})
}

// finalizeApply persists the terminal apply record + audit fan-out and,
// when the run was a real (non-dry) success, transitions the parent
// plan to Applied. The function tolerates a nil result when the
// connector errored before producing one — in that path the record
// lands in Failed with applyErr.Error() as the failure message.
func finalizeApply(
	ctx context.Context,
	store storage.Storage,
	plan *domain.Plan,
	rec *domain.PlanApplyRecord,
	result *connectors.ApplyResult,
	applyErr error,
	finishedAt time.Time,
	args applyArgs,
) error {
	state, applied, failed, summaryHash, output, failureMessage := classifyApplyResult(result, applyErr)
	if err := rec.Transition(state, finishedAt, summaryHash, output, applied, failed, failureMessage); err != nil {
		return fmt.Errorf("transition apply record: %w", err)
	}
	return store.WithTx(ctx, func(tx storage.Storage) error {
		if err := tx.UpdatePlanApplyRecord(ctx, rec); err != nil {
			return fmt.Errorf("update plan apply record: %w", err)
		}
		// Real apply that succeeded: transition the parent plan to
		// Applied. Dry-run and failed runs do NOT touch the plan.
		if state == domain.PlanApplyStateSucceeded && !rec.DryRun {
			reason := fmt.Sprintf("applied via plan_apply_record:%s", rec.ID)
			if err := tx.UpdatePlanState(ctx, plan.ID, domain.PlanStateApplied, reason); err != nil {
				return fmt.Errorf("update plan to applied: %w", err)
			}
		}
		var evtKind domain.EventKind
		if state == domain.PlanApplyStateSucceeded {
			evtKind = domain.EventApplySucceeded
		} else {
			evtKind = domain.EventApplyFailed
		}
		payload := map[string]any{
			"plan_apply_id": string(rec.ID),
			"plan_id":       string(plan.ID),
			"applied_items": applied,
			"failed_items":  failed,
			"summary_hash":  summaryHash,
			"dry_run":       rec.DryRun,
		}
		if failureMessage != "" {
			payload["failure_message"] = failureMessage
		}
		evt, err := domain.NewAuditEvent(evtKind, args.actor, "plan_apply", string(rec.ID), payload)
		if err != nil {
			return fmt.Errorf("build %s audit: %w", evtKind, err)
		}
		if err := tx.AppendAuditEvent(ctx, evt); err != nil {
			return fmt.Errorf("append %s audit: %w", evtKind, err)
		}
		return nil
	})
}

// classifyApplyResult maps the connector outcome onto the terminal
// PlanApplyState. The contract is:
//   - applyErr != nil       -> Failed, FailureMessage = applyErr.Error()
//   - any item Status=failed -> Failed, FailureMessage aggregates errors
//   - else                  -> Succeeded
//
// applied counts items in {"applied", "skipped"}; failed counts items
// in {"failed"}. summaryHash and output are derived from result.Items
// canonically; on connector error with no result, they are empty.
func classifyApplyResult(result *connectors.ApplyResult, applyErr error) (
	state domain.PlanApplyState,
	applied, failed int,
	summaryHash string,
	output json.RawMessage,
	failureMessage string,
) {
	if result == nil {
		// Connector failed catastrophically (e.g. couldn't connect).
		state = domain.PlanApplyStateFailed
		summaryHash = ""
		output = json.RawMessage("{}")
		if applyErr != nil {
			failureMessage = applyErr.Error()
		} else {
			failureMessage = "connector returned nil result"
		}
		return
	}

	views := make([]applyItemResultView, 0, len(result.Items))
	failureMsgs := make([]string, 0)
	for _, it := range result.Items {
		switch it.Status {
		case "applied", "skipped":
			applied++
		case "failed":
			failed++
			if it.Error != "" {
				failureMsgs = append(failureMsgs,
					fmt.Sprintf("item %d (%s): %s", it.Sequence, it.ResourceRef, it.Error))
			}
		}
		stmts := it.Statements
		if stmts == nil {
			stmts = []string{}
		}
		views = append(views, applyItemResultView{
			Sequence:     it.Sequence,
			ResourceKind: it.ResourceKind,
			ResourceRef:  it.ResourceRef,
			Status:       it.Status,
			Statements:   stmts,
			RowsAffected: it.RowsAffected,
			Error:        it.Error,
		})
	}

	// Re-derive summary hash from canonical items so it is stable
	// regardless of what the connector chose to put in result.SummaryHash.
	// We still prefer the connector's hash when present (it has more
	// context), but fall back to our local computation if absent.
	summaryHash = result.SummaryHash
	if summaryHash == "" {
		itemsBytes, err := json.Marshal(views)
		if err == nil {
			sum := sha256.Sum256(itemsBytes)
			summaryHash = "sha256:" + hex.EncodeToString(sum[:])
		}
	}

	itemsJSON, err := json.Marshal(views)
	if err != nil {
		// Fall back to an empty object if marshaling somehow fails;
		// the audit trail still has the per-item failure messages.
		itemsJSON = []byte("[]")
	}
	output = json.RawMessage(itemsJSON)

	if applyErr != nil {
		state = domain.PlanApplyStateFailed
		failureMessage = applyErr.Error()
		return
	}
	if failed > 0 {
		state = domain.PlanApplyStateFailed
		if len(failureMsgs) > 0 {
			failureMessage = strings.Join(failureMsgs, "; ")
		} else {
			failureMessage = fmt.Sprintf("%d item(s) failed", failed)
		}
		return
	}
	state = domain.PlanApplyStateSucceeded
	return
}

// buildApplyOutput projects rec + result into the canonical wire shape.
func buildApplyOutput(rec *domain.PlanApplyRecord, result *connectors.ApplyResult) (applyOutput, error) {
	out := applyOutput{
		ApplyRecord: applyRecordView{
			ID:             rec.ID,
			PlanID:         rec.PlanID,
			State:          string(rec.State),
			StartedAt:      rec.StartedAt.UTC(),
			ActorKind:      string(rec.Actor.Kind),
			ActorSubject:   rec.Actor.Subject,
			Target:         rec.Target,
			DryRun:         rec.DryRun,
			AppliedItems:   rec.AppliedItems,
			FailedItems:    rec.FailedItems,
			FailureMessage: rec.FailureMessage,
			SummaryHash:    rec.SummaryHash,
			Output:         rec.Output,
		},
	}
	if rec.FinishedAt != nil {
		t := rec.FinishedAt.UTC()
		out.ApplyRecord.FinishedAt = &t
	}
	if result != nil {
		items := make([]applyItemResultView, 0, len(result.Items))
		for _, it := range result.Items {
			stmts := it.Statements
			if stmts == nil {
				stmts = []string{}
			}
			items = append(items, applyItemResultView{
				Sequence:     it.Sequence,
				ResourceKind: it.ResourceKind,
				ResourceRef:  it.ResourceRef,
				Status:       it.Status,
				Statements:   stmts,
				RowsAffected: it.RowsAffected,
				Error:        it.Error,
			})
		}
		out.Result = applyResultView{
			ConnectorName:    result.ConnectorName,
			ConnectorVersion: result.ConnectorVersion,
			Target:           result.Target,
			StartedAt:        result.StartedAt.UTC(),
			FinishedAt:       result.FinishedAt.UTC(),
			DryRun:           result.DryRun,
			SummaryHash:      result.SummaryHash,
			Items:            items,
		}
	} else {
		out.Result = applyResultView{
			Target: rec.Target,
			DryRun: rec.DryRun,
			Items:  []applyItemResultView{},
		}
	}
	return out, nil
}

// summarizeApply renders the human-readable stderr summary line.
func summarizeApply(rec *domain.PlanApplyRecord, plan *domain.Plan) string {
	total := rec.AppliedItems + rec.FailedItems
	summary := fmt.Sprintf(
		"apply %s (%s, target=%s, dry-run=%t) for plan %s: %s; %d/%d applied",
		shortID(rec.ID), plan.ConnectorName, rec.Target, rec.DryRun,
		shortID(plan.ID), rec.State, rec.AppliedItems, total,
	)
	if rec.FailedItems > 0 {
		summary += fmt.Sprintf(", %d failed", rec.FailedItems)
	}
	if rec.FailureMessage != "" {
		summary += "; reason: " + rec.FailureMessage
	}
	return summary
}

// writeApplyBytes routes the canonical JSON to stdout (output == "-")
// or to a file path. We append a trailing newline for cat/diff
// friendliness.
func writeApplyBytes(stdout io.Writer, output string, out applyOutput) error {
	b, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal apply output: %w", err)
	}
	b = append(b, '\n')
	if output == "" || output == "-" {
		if _, err := stdout.Write(b); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(output, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", output, err)
	}
	return nil
}

// verifyPlanSignatures requires at least one valid Ed25519 signature on
// the plan unless STATEBOUND_DEV_SKIP_PLAN_SIGNATURE=true. Disabled and
// expired keys are skipped (with warnings); a plan whose only signers
// have been disabled or expired is refused. Phase 8 wave A.
//
// On success, emits plan.signature.verified. On every kind of failure
// path emits plan.signature.failed before returning. The caller writes
// an additional plan_apply Failed record via recordApplyRefusal.
func verifyPlanSignatures(
	ctx context.Context,
	store storage.Storage,
	stderr io.Writer,
	plan *domain.Plan,
	actor domain.Actor,
) error {
	if os.Getenv(EnvDevSkipPlanSignature) == "true" {
		_, _ = fmt.Fprintf(stderr,
			"WARNING: %s=true; skipping plan signature verification (dev mode only)\n",
			EnvDevSkipPlanSignature)
		return nil
	}

	signatures, err := store.ListPlanSignaturesByPlan(ctx, plan.ID)
	if err != nil {
		return fmt.Errorf("list plan signatures: %w", err)
	}
	if len(signatures) == 0 {
		reason := fmt.Sprintf("plan %s has no signatures; refusing to apply", shortID(plan.ID))
		_ = emitVerifyFailed(ctx, store, plan, "", actor, reason)
		return fmt.Errorf("%s", reason)
	}

	now := time.Now().UTC()
	validKeys := make([]string, 0)
	for _, sig := range signatures {
		key, err := store.GetSigningKey(ctx, sig.KeyID)
		if err != nil {
			if errors.Is(err, storage.ErrSigningKeyNotFound) {
				_, _ = fmt.Fprintf(stderr,
					"WARNING: plan %s signed by missing key %q; skipping\n",
					shortID(plan.ID), sig.KeyID)
				continue
			}
			return fmt.Errorf("load signing key %s: %w", sig.KeyID, err)
		}
		if !key.IsValidForVerification(now) {
			cause := "disabled"
			if !key.Disabled && key.ExpiresAt != nil && !key.ExpiresAt.After(now) {
				cause = "expired"
			}
			_, _ = fmt.Fprintf(stderr,
				"WARNING: plan %s signature from key %q skipped (%s)\n",
				shortID(plan.ID), key.KeyID, cause)
			continue
		}
		if err := signingVerify(plan.Content, sig.Signature, key.PublicKey); err != nil {
			reason := fmt.Sprintf("plan signature verification failed for key %q: %v", sig.KeyID, err)
			_ = emitVerifyFailed(ctx, store, plan, sig.KeyID, actor, reason)
			return fmt.Errorf("%s", reason)
		}
		validKeys = append(validKeys, sig.KeyID)
	}

	if len(validKeys) == 0 {
		reason := fmt.Sprintf("plan %s has signatures but none are issued by an active key", shortID(plan.ID))
		_ = emitVerifyFailed(ctx, store, plan, "", actor, reason)
		return fmt.Errorf("%s", reason)
	}

	// Best-effort audit: verified.
	payload := map[string]any{
		"plan_id":      string(plan.ID),
		"key_ids":      validKeys,
		"content_hash": plan.ContentHash,
	}
	evt, evtErr := domain.NewAuditEvent(domain.EventPlanSignatureVerified, actor, "plan", string(plan.ID), payload)
	if evtErr == nil {
		_ = store.AppendAuditEvent(ctx, evt)
	}
	return nil
}

// emitVerifyFailed writes plan.signature.failed (apply phase).
func emitVerifyFailed(
	ctx context.Context,
	store storage.Storage,
	plan *domain.Plan,
	keyID string,
	actor domain.Actor,
	reason string,
) error {
	payload := map[string]any{
		"plan_id":         string(plan.ID),
		"key_id":          keyID,
		"failure_message": reason,
		"phase":           "verify",
	}
	evt, err := domain.NewAuditEvent(domain.EventPlanSignatureFailed, actor, "plan", string(plan.ID), payload)
	if err != nil {
		return err
	}
	return store.AppendAuditEvent(ctx, evt)
}
