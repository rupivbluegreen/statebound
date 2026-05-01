package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/tester"
	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/authz"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// addPolicyCmd registers `statebound policy` and its two subcommands on the
// supplied parent (the root command). The subcommands are deliberately small:
// `test` runs Rego unit tests in-process via OPA's tester library; `eval`
// runs the in-process OPA evaluator against a stored ChangeSet without
// persisting any decision row (read-only inspection).
func addPolicyCmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Policy testing and evaluation",
	}
	cmd.AddCommand(newPolicyTestCmd())
	cmd.AddCommand(newPolicyEvalCmd())
	parent.AddCommand(cmd)
}

// ----- test -----

func newPolicyTestCmd() *cobra.Command {
	var (
		bundlePath string
		testsPath  string
		verbose    bool
	)
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run Rego unit tests for the built-in rule library",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyTest(cmd.Context(), cmd.OutOrStdout(), bundlePath, testsPath, verbose)
		},
	}
	cmd.Flags().StringVar(&bundlePath, "bundle", "policies/builtin",
		"directory containing built-in Rego rules")
	cmd.Flags().StringVar(&testsPath, "tests", "policies/tests",
		"directory containing Rego test files")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose test output")
	return cmd
}

// runPolicyTest is the test-friendly handler body. We resolve both directories
// to absolute paths so error output is unambiguous regardless of cwd, then
// hand the paths to OPA's tester package which loads .rego under each path
// and runs every `test_*` rule.
func runPolicyTest(ctx context.Context, w io.Writer, bundle, tests string, verbose bool) error {
	if err := requireDir(bundle, "rule bundle"); err != nil {
		return err
	}
	if err := requireDir(tests, "test bundle"); err != nil {
		return err
	}

	results, err := tester.Run(ctx, bundle, tests)
	if err != nil {
		return fmt.Errorf("run rego tests: %w", err)
	}

	var failed, errored int
	for _, r := range results {
		name := r.Package + "." + r.Name
		switch {
		case r.Error != nil:
			errored++
			fmt.Fprintf(w, "ERROR %s  %v\n", name, r.Error)
		case r.Fail:
			failed++
			if verbose && r.FailedAt != nil {
				fmt.Fprintf(w, "FAIL  %s  failed at %s\n", name, r.FailedAt.Location)
			} else {
				fmt.Fprintf(w, "FAIL  %s\n", name)
			}
		case r.Skip:
			fmt.Fprintf(w, "SKIP  %s\n", name)
		default:
			if verbose {
				fmt.Fprintf(w, "PASS  %s  (%s)\n", name, r.Duration)
			} else {
				fmt.Fprintf(w, "PASS  %s\n", name)
			}
		}
	}
	fmt.Fprintf(w, "\n%d test(s); %d failed, %d errored\n", len(results), failed, errored)
	if failed > 0 || errored > 0 {
		return fmt.Errorf("rego tests failed: %d failures, %d errors", failed, errored)
	}
	return nil
}

// requireDir returns a clear, actionable error when the supplied path does
// not exist or is not a directory. We absolute-path the input first so the
// error message is the same whether the user invoked the CLI from the repo
// root or from a subdirectory.
func requireDir(path, label string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%s path %q: %w", label, path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no rule files found at %s", abs)
		}
		return fmt.Errorf("stat %s: %w", abs, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s path %s is not a directory", label, abs)
	}
	return nil
}

// ----- eval -----

func newPolicyEvalCmd() *cobra.Command {
	var (
		csIDStr string
		phase   string
		format  string
	)
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Evaluate the policy bundle against a ChangeSet (read-only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if csIDStr == "" {
				return fmt.Errorf("--change-set is required")
			}
			normalizedPhase, err := normalizePolicyPhase(phase)
			if err != nil {
				return err
			}

			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			return runPolicyEval(cmd.Context(), store, cmd.OutOrStdout(), domain.ID(csIDStr), normalizedPhase, format, actor)
		},
	}
	cmd.Flags().StringVar(&csIDStr, "change-set", "",
		"id of the ChangeSet to evaluate (required)")
	_ = cmd.MarkFlagRequired("change-set")
	cmd.Flags().StringVar(&phase, "phase", "submit",
		"evaluation phase: submit or approve")
	cmd.Flags().StringVar(&format, "format", "text",
		"output format: text or json")
	return cmd
}

// normalizePolicyPhase maps the CLI phase string to the authz.EvalPhase value.
// Two phases are supported: `submit` (initial admission) and `approve`
// (the four-eyes-and-policy gate at approval time). Anything else is an
// error so misspellings don't silently fall through.
func normalizePolicyPhase(s string) (authz.EvalPhase, error) {
	switch s {
	case "submit":
		return authz.PhaseSubmit, nil
	case "approve":
		return authz.PhaseApprove, nil
	default:
		return "", fmt.Errorf("unknown phase %q (want submit or approve)", s)
	}
}

// runPolicyEval loads the ChangeSet plus its supporting context, builds the
// authz.Input, calls the in-process OPA evaluator, and renders the result.
// It deliberately does NOT persist a policy_decisions row — this is a
// dry-run for inspection. The submit handler in the approval flow remains
// the only writer.
func runPolicyEval(ctx context.Context, store storage.Storage, w io.Writer, csID domain.ID, phase authz.EvalPhase, format string, actor domain.Actor) error {
	cs, err := store.GetChangeSetByID(ctx, csID)
	if err != nil {
		return fmt.Errorf("get change set: %w", err)
	}
	items, err := store.ListChangeSetItems(ctx, csID)
	if err != nil {
		return fmt.Errorf("list change set items: %w", err)
	}
	product, err := store.GetProductByID(ctx, cs.ProductID)
	if err != nil {
		return fmt.Errorf("get product: %w", err)
	}
	approvals, err := store.ListApprovalsByChangeSet(ctx, csID)
	if err != nil {
		return fmt.Errorf("list approvals: %w", err)
	}

	input := authz.Input{
		Phase:     phase,
		Product:   *product,
		ChangeSet: *cs,
		Items:     items,
		Approvals: approvals,
	}
	if phase == authz.PhaseApprove {
		// Pass the current actor as the approver so the four-eyes rule has
		// the data it needs. For `submit`, no approver is in scope.
		a := actor
		input.Approver = &a
	}

	eval, err := authz.NewOPAEvaluator(ctx)
	if err != nil {
		return fmt.Errorf("init opa evaluator: %w", err)
	}
	result, err := eval.Evaluate(ctx, input)
	if err != nil {
		return fmt.Errorf("evaluate policy: %w", err)
	}

	return renderPolicyResult(w, cs, phase, format, result)
}

// renderPolicyResult writes the evaluator output to w in either compact text
// or full json form. The text rendering mirrors what we expect to see in
// reviewer narratives: short id, phase, bundle hash, outcome, then a list of
// fired rules grouped by outcome and severity.
func renderPolicyResult(w io.Writer, cs *domain.ChangeSet, phase authz.EvalPhase, format string, result *authz.PolicyResult) error {
	switch format {
	case "", "text":
		return renderPolicyResultText(w, cs, phase, result)
	case "json":
		b, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal result: %w", err)
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	default:
		return fmt.Errorf("unknown format %q (want text or json)", format)
	}
}

func renderPolicyResultText(w io.Writer, cs *domain.ChangeSet, phase authz.EvalPhase, result *authz.PolicyResult) error {
	fmt.Fprintf(w, "Policy evaluation for change set %s\n", shortID(cs.ID))
	fmt.Fprintf(w, "  Phase: %s\n", phase)
	if result.BundleHash != "" {
		fmt.Fprintf(w, "  Bundle: %s\n", result.BundleHash)
	}
	fmt.Fprintf(w, "  Outcome: %s\n", result.Outcome)
	if len(result.Rules) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  No rules fired.")
		return nil
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Rules fired (%d):\n", len(result.Rules))
	for _, r := range result.Rules {
		fmt.Fprintf(w, "    [%s|%s] %s — %s\n", r.Outcome, r.Severity, r.RuleID, r.Message)
	}
	return nil
}
