// Package cli — plan subcommand. Phase 4 wires the connector framework into
// the CLI so operators can produce deterministic, OPA-gated plans against
// approved versions of a product.
//
// Behavior:
//   - Resolve the product and approved version (latest or by sequence).
//   - Decode the snapshot back into a ProductAuthorizationModel.
//   - Hand both to a registered connector's ValidateDesiredState + Plan.
//   - Re-evaluate the plan through OPA (PhaseApprove) as defense-in-depth.
//   - Persist the plan + items idempotently and emit audit events.
//   - Write the canonical plan bytes to --output (- for stdout).
//
// Phase 4 is plan-only: applying a plan to a target system arrives in
// Phase 6+. Plans whose OPA re-evaluation denies are persisted in the
// "refused" state with the deny rule ids in RefusedReason — the audit
// trail is preserved either way.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/authz"
	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/connectors/builtins"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
	"statebound.dev/statebound/internal/storage"
)

// addPlanCmd registers `statebound plan` on parent (root command).
func addPlanCmd(parent *cobra.Command) {
	parent.AddCommand(newPlanCmd())
}

// newPlanCmd builds the cobra.Command for `statebound plan`. Kept as its
// own constructor so the help-text test can exercise it without booting
// the full root tree.
func newPlanCmd() *cobra.Command {
	var (
		productName string
		versionStr  string
		connector   string
		output      string
	)
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Generate a deterministic plan from an approved version via a connector",
		Long: "Plan resolves the named product's approved version (latest or " +
			"by sequence), hands it to the named connector, persists the " +
			"resulting plan + items, runs OPA as defense-in-depth, and writes " +
			"the canonical plan bytes to --output. Plans are idempotent: " +
			"re-running plan with the same approved version + connector " +
			"version yields byte-identical bytes and a no-op insert.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			return runPlan(cmd.Context(), store, cmd.OutOrStdout(), cmd.ErrOrStderr(), planArgs{
				productName:   productName,
				versionStr:    versionStr,
				connectorName: connector,
				output:        output,
				actor:         actor,
			})
		},
	}
	cmd.Flags().StringVar(&productName, "product", "", "product name (required)")
	cmd.Flags().StringVar(&versionStr, "version", "latest",
		"approved-version sequence to plan against, or 'latest' (default)")
	cmd.Flags().StringVar(&connector, "connector", "", "connector name, e.g. linux-sudo (required)")
	cmd.Flags().StringVarP(&output, "output", "o", "-",
		"write plan bytes to this path; '-' for stdout (default)")
	_ = cmd.MarkFlagRequired("product")
	_ = cmd.MarkFlagRequired("connector")
	return cmd
}

// planArgs bundles the parsed flags so runPlan stays narrow.
type planArgs struct {
	productName   string
	versionStr    string
	connectorName string
	output        string
	actor         domain.Actor
}

// runPlan is the testable handler body. It is deliberately the only place
// that orchestrates registry lookup, validation, plan generation, OPA
// re-evaluation, persistence, and audit fan-out.
func runPlan(ctx context.Context, store storage.Storage, stdout, stderr io.Writer, args planArgs) error {
	// 1. Boot connector registry.
	registry := connectors.NewRegistry()
	builtins.Register(registry)

	conn, ok := registry.Get(args.connectorName)
	if !ok {
		names := make([]string, 0)
		for _, c := range registry.List() {
			names = append(names, c.Name())
		}
		return fmt.Errorf("unknown connector %q; available: %s",
			args.connectorName, strings.Join(names, ", "))
	}

	// 2. Resolve product.
	product, err := store.GetProductByName(ctx, args.productName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("product %q not found", args.productName)
		}
		return fmt.Errorf("lookup product %q: %w", args.productName, err)
	}

	// 3. Resolve approved version.
	av, err := resolveApprovedVersion(ctx, store, product.ID, args.productName, args.versionStr)
	if err != nil {
		return err
	}
	if av == nil {
		return fmt.Errorf("%s has no approved versions yet — Plan requires approval first", args.productName)
	}
	_, snapshot, err := store.GetApprovedVersionByID(ctx, av.ID)
	if err != nil {
		return fmt.Errorf("load approved version snapshot: %w", err)
	}
	if snapshot == nil {
		return fmt.Errorf("%s v%d has no snapshot content", args.productName, av.Sequence)
	}

	// 4. Decode snapshot back into the YAML model the connector expects.
	pam, err := model.FromSnapshot(snapshot.Content)
	if err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}

	state := connectors.ApprovedState{
		Product:           product,
		ApprovedVersionID: av.ID,
		Sequence:          av.Sequence,
		Snapshot:          snapshot.Content,
		Model:             pam,
	}

	// 5. Connector pre-flight.
	findings, err := conn.ValidateDesiredState(ctx, state)
	if err != nil {
		return fmt.Errorf("connector validate: %w", err)
	}
	hardError := false
	for _, f := range findings {
		fmt.Fprintf(stderr, "[%s] %s: %s\n", f.Severity, f.Path, f.Message)
		if f.Severity == "error" {
			hardError = true
		}
	}
	if hardError {
		return fmt.Errorf("connector %s reported validation errors; aborting plan", conn.Name())
	}

	// 6. Plan.
	result, err := conn.Plan(ctx, state)
	if err != nil {
		return fmt.Errorf("connector plan: %w", err)
	}
	if result == nil {
		return fmt.Errorf("connector %s returned a nil PlanResult", conn.Name())
	}

	// 7. Marshal canonical content bytes (no MarshalIndent — these bytes
	// feed the SHA-256 idempotency key).
	contentBytes, err := json.Marshal(result.Content)
	if err != nil {
		return fmt.Errorf("marshal plan content: %w", err)
	}

	// 8. Build domain plan + items.
	plan, err := domain.NewPlan(
		product.ID, av.ID, av.Sequence,
		conn.Name(), conn.Version(),
		contentBytes, result.Summary, args.actor,
	)
	if err != nil {
		return fmt.Errorf("build plan: %w", err)
	}
	domainItems := make([]*domain.PlanItem, 0, len(result.Items))
	for i, it := range result.Items {
		body, err := json.Marshal(it.Body)
		if err != nil {
			return fmt.Errorf("marshal plan item %d body: %w", i+1, err)
		}
		domainItems = append(domainItems, &domain.PlanItem{
			ID:           domain.NewID(),
			PlanID:       plan.ID,
			Sequence:     i + 1,
			Action:       it.Action,
			ResourceKind: it.ResourceKind,
			ResourceRef:  it.ResourceRef,
			Body:         body,
			Risk:         it.Risk,
			Note:         it.Note,
		})
	}

	// 9. Plan-time OPA re-evaluation (defense-in-depth). PhaseApprove is
	// reused so wildcard_sudo, root_equiv etc. fire; we tolerate
	// escalate_required because prod_requires_approval will fire on a
	// synthetic empty-approvals input.
	syntheticItems := buildSyntheticPlanItems(pam)
	syntheticCS := domain.ChangeSet{
		ID:        "synthetic-plan-time",
		ProductID: product.ID,
		State:     domain.ChangeSetStateApproved,
		Title:     "synthetic plan-time evaluation",
		RequestedBy: domain.Actor{
			Kind:    domain.ActorSystem,
			Subject: "plan",
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
		return fmt.Errorf("plan-time policy gate: load evaluator: %w", err)
	}
	policyResult, err := eval.Evaluate(ctx, in)
	if err != nil {
		return fmt.Errorf("plan-time policy gate: evaluate: %w", err)
	}

	if policyResult.Outcome == authz.DecisionDeny {
		denyIDs := make([]string, 0)
		for _, r := range policyResult.Rules {
			if r.Outcome == authz.DecisionDeny {
				denyIDs = append(denyIDs, r.RuleID)
			}
		}
		reason := fmt.Sprintf("OPA denied: %s", strings.Join(denyIDs, ", "))
		plan.State = domain.PlanStateRefused
		plan.RefusedReason = reason
	} else {
		plan.State = domain.PlanStateReady
	}

	// 10. Persist plan + items + audit events in one transaction.
	if err := store.WithTx(ctx, func(tx storage.Storage) error {
		if err := tx.AppendPlan(ctx, plan, domainItems); err != nil {
			return fmt.Errorf("append plan: %w", err)
		}
		if plan.State == domain.PlanStateRefused {
			refusedEvt, err := domain.NewAuditEvent(
				domain.EventPlanRefused,
				args.actor,
				"plan",
				string(plan.ID),
				map[string]any{
					"plan_id":             string(plan.ID),
					"refused_reason":      plan.RefusedReason,
					"connector":           plan.ConnectorName,
					"approved_version_id": string(plan.ApprovedVersionID),
				},
			)
			if err != nil {
				return fmt.Errorf("build plan.refused audit: %w", err)
			}
			if err := tx.AppendAuditEvent(ctx, refusedEvt); err != nil {
				return fmt.Errorf("append plan.refused audit: %w", err)
			}
			return nil
		}
		// Ready: emit plan.generated then plan.ready.
		genEvt, err := domain.NewAuditEvent(
			domain.EventPlanGenerated,
			args.actor,
			"plan",
			string(plan.ID),
			map[string]any{
				"plan_id":             string(plan.ID),
				"connector":           plan.ConnectorName,
				"connector_version":   plan.ConnectorVersion,
				"approved_version_id": string(plan.ApprovedVersionID),
				"content_hash":        plan.ContentHash,
				"item_count":          len(domainItems),
			},
		)
		if err != nil {
			return fmt.Errorf("build plan.generated audit: %w", err)
		}
		if err := tx.AppendAuditEvent(ctx, genEvt); err != nil {
			return fmt.Errorf("append plan.generated audit: %w", err)
		}
		readyEvt, err := domain.NewAuditEvent(
			domain.EventPlanReady,
			args.actor,
			"plan",
			string(plan.ID),
			map[string]any{
				"plan_id":             string(plan.ID),
				"connector":           plan.ConnectorName,
				"approved_version_id": string(plan.ApprovedVersionID),
			},
		)
		if err != nil {
			return fmt.Errorf("build plan.ready audit: %w", err)
		}
		if err := tx.AppendAuditEvent(ctx, readyEvt); err != nil {
			return fmt.Errorf("append plan.ready audit: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	// 11. Write content bytes to the sink.
	if err := writePlanBytes(stdout, args.output, contentBytes); err != nil {
		return err
	}

	// 12. Human summary on stderr.
	summary := fmt.Sprintf("plan %s (%s, sha256:%s) for %s:v%d: %s; %d items",
		shortID(plan.ID), plan.ConnectorName, shortHash(plan.ContentHash),
		product.Name, plan.Sequence, plan.State, len(domainItems))
	if plan.State == domain.PlanStateRefused {
		summary += "; refused: " + plan.RefusedReason
	}
	_, err = fmt.Fprintln(stderr, summary)
	return err
}

// buildSyntheticPlanItems re-projects the model's entitlements and service
// accounts into ChangeSetItem-shaped inputs so plan-time OPA can fire the
// same rules it would fire at submit/approve time. We synthesize an
// "add" action because the rules check item.after.* patterns; before is
// nil for adds, which matches the changeset domain invariant.
func buildSyntheticPlanItems(m *model.ProductAuthorizationModel) []*domain.ChangeSetItem {
	if m == nil {
		return nil
	}
	out := make([]*domain.ChangeSetItem, 0)
	for _, ent := range m.Spec.Entitlements {
		after := entitlementToSnakeMap(ent)
		out = append(out, &domain.ChangeSetItem{
			ID:           domain.NewID(),
			ChangeSetID:  "synthetic-plan-time",
			Kind:         domain.ChangeSetItemKindEntitlement,
			Action:       domain.ChangeSetActionAdd,
			ResourceName: ent.Name,
			Before:       nil,
			After:        after,
		})
	}
	for _, sa := range m.Spec.ServiceAccounts {
		after := serviceAccountToSnakeMap(sa)
		out = append(out, &domain.ChangeSetItem{
			ID:           domain.NewID(),
			ChangeSetID:  "synthetic-plan-time",
			Kind:         domain.ChangeSetItemKindServiceAccount,
			Action:       domain.ChangeSetActionAdd,
			ResourceName: sa.Name,
			Before:       nil,
			After:        after,
		})
	}
	return out
}

// entitlementToSnakeMap serializes a YAMLEntitlement into a snake_case map
// so the Rego rules can read item.after.* without surprise camelCase keys.
// authz.canonicalInputJSON would have run snakeKeysAny over us anyway, but
// constructing snake_case up front keeps the synthetic items easy to read.
func entitlementToSnakeMap(e model.YAMLEntitlement) map[string]any {
	auths := make([]any, 0, len(e.Authorizations))
	for _, a := range e.Authorizations {
		auths = append(auths, authorizationToSnakeMap(a))
	}
	return map[string]any{
		"name":           e.Name,
		"owner":          e.Owner,
		"purpose":        e.Purpose,
		"authorizations": auths,
	}
}

// serviceAccountToSnakeMap mirrors entitlementToSnakeMap for service accounts.
func serviceAccountToSnakeMap(s model.YAMLServiceAccount) map[string]any {
	auths := make([]any, 0, len(s.Authorizations))
	for _, a := range s.Authorizations {
		auths = append(auths, authorizationToSnakeMap(a))
	}
	return map[string]any{
		"name":          s.Name,
		"owner":         s.Owner,
		"usage_pattern": s.UsagePattern,
		"purpose":       s.Purpose,
		"authorizations": auths,
	}
}

// authorizationToSnakeMap projects a YAMLAuthorization into a flat snake_case
// map. Reserved keys (type, scope, global_object) sit alongside the spec
// entries; spec keys are recursively snake-cased so nested rules can read
// e.g. commands.allow without any case-mangling surprises.
func authorizationToSnakeMap(a model.YAMLAuthorization) map[string]any {
	out := map[string]any{
		"type":  a.Type,
		"scope": a.Scope,
	}
	if a.GlobalObject != "" {
		out["global_object"] = a.GlobalObject
	}
	for k, v := range a.Spec {
		out[camelToSnakeKey(k)] = snakeKeysRecursive(v)
	}
	return out
}

// snakeKeysRecursive walks a value and rewrites every map key to snake_case.
// This mirrors authz.snakeKeysAny but lives here so plan.go does not import
// authz internals. The two functions converge on the same byte output once
// canonical_input_json runs, so the synthetic items survive a round trip.
func snakeKeysRecursive(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[camelToSnakeKey(k)] = snakeKeysRecursive(vv)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[camelToSnakeKey(fmt.Sprint(k))] = snakeKeysRecursive(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = snakeKeysRecursive(vv)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	default:
		return v
	}
}

// camelToSnakeKey converts a single camelCase identifier to snake_case.
// Already-snake strings pass through.
func camelToSnakeKey(s string) string {
	if s == "" {
		return s
	}
	hasUpper := false
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	runes := []rune(s)
	out := make([]rune, 0, len(runes)+4)
	for i, r := range runes {
		if r >= 'A' && r <= 'Z' {
			lower := r + ('a' - 'A')
			if i == 0 {
				out = append(out, lower)
				continue
			}
			prev := runes[i-1]
			next := rune(0)
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') {
				out = append(out, '_', lower)
				continue
			}
			if (prev >= 'A' && prev <= 'Z') && (next >= 'a' && next <= 'z') {
				out = append(out, '_', lower)
				continue
			}
			out = append(out, lower)
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// writePlanBytes routes b to stdout (output == "-") or to a file path.
func writePlanBytes(stdout io.Writer, output string, b []byte) error {
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
