// Command opa-test runs the Rego unit tests under the project's policies
// directory using OPA's Go tester library.
//
// It exists so the Makefile target `policy-test` does not depend on the
// statebound CLI binary's init wiring or its database connection. Setting
// STATEBOUND_REGO_BUNDLE / STATEBOUND_REGO_TESTS overrides the defaults.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/tester"
)

func main() {
	bundle := os.Getenv("STATEBOUND_REGO_BUNDLE")
	if bundle == "" {
		bundle = "policies/builtin"
	}
	tests := os.Getenv("STATEBOUND_REGO_TESTS")
	if tests == "" {
		tests = "policies/tests"
	}
	if err := run(context.Background(), os.Stdout, bundle, tests); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run loads every .rego file under bundle and tests, invokes tester.Run, and
// streams pass/fail lines to w. It returns a non-nil error when any test
// fails or any test errors out. Missing directories yield a clear,
// caller-actionable error rather than a panic.
func run(ctx context.Context, w *os.File, bundle, tests string) error {
	if err := mustDir(bundle, "rule bundle"); err != nil {
		return err
	}
	if err := mustDir(tests, "test bundle"); err != nil {
		return err
	}

	results, err := tester.Run(ctx, bundle, tests)
	if err != nil {
		return fmt.Errorf("run rego tests: %w", err)
	}

	var failed, errored int
	for _, r := range results {
		switch {
		case r.Error != nil:
			errored++
			fmt.Fprintf(w, "ERROR %s.%s  %v\n", r.Package, r.Name, r.Error)
		case r.Fail:
			failed++
			fmt.Fprintf(w, "FAIL  %s.%s\n", r.Package, r.Name)
		case r.Skip:
			fmt.Fprintf(w, "SKIP  %s.%s\n", r.Package, r.Name)
		default:
			fmt.Fprintf(w, "PASS  %s.%s\n", r.Package, r.Name)
		}
	}
	fmt.Fprintf(w, "\n%d test(s); %d failed, %d errored\n", len(results), failed, errored)
	if failed > 0 || errored > 0 {
		return fmt.Errorf("rego tests failed: %d failures, %d errors", failed, errored)
	}
	return nil
}

// mustDir returns a clear error when the path is missing or not a directory.
// We resolve to absolute first so the error message points at the same
// location regardless of working directory.
func mustDir(path, label string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%s path %q: %w", label, path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no rule files found at %s (set STATEBOUND_REGO_BUNDLE/TESTS to override)", abs)
		}
		return fmt.Errorf("stat %s: %w", abs, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s path %s is not a directory", label, abs)
	}
	return nil
}
