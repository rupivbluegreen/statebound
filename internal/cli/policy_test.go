package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestPolicyCommand_HelpListsBothSubcommands asserts that `statebound policy --help`
// renders both the `test` and `eval` subcommands. Help-text rendering is the
// only behaviour we can assert without spinning up Postgres or Rego, but it
// catches the most common regression — forgetting to wire a subcommand into
// the parent.
func TestPolicyCommand_HelpListsBothSubcommands(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addPolicyCmd(root)

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"policy", "--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"test", "eval", "Policy testing and evaluation"} {
		if !strings.Contains(out, want) {
			t.Errorf("policy --help output missing %q; got:\n%s", want, out)
		}
	}
}

// TestPolicyTestCommand_FlagDefaults pins the default values for `policy test`
// flags so a future refactor that silently changes them trips the test.
func TestPolicyTestCommand_FlagDefaults(t *testing.T) {
	cmd := newPolicyTestCmd()

	tests := map[string]string{
		"bundle": "policies/builtin",
		"tests":  "policies/tests",
	}
	for flagName, want := range tests {
		f := cmd.Flag(flagName)
		if f == nil {
			t.Fatalf("expected flag --%s on policy test", flagName)
		}
		if f.DefValue != want {
			t.Errorf("--%s default = %q; want %q", flagName, f.DefValue, want)
		}
	}

	if vf := cmd.Flag("verbose"); vf == nil {
		t.Error("expected --verbose flag on policy test")
	}
}

// TestPolicyEvalCommand_RequiresChangeSet ensures the `--change-set` flag is
// marked required so `policy eval` without it errors out before any DB or
// OPA work.
func TestPolicyEvalCommand_RequiresChangeSet(t *testing.T) {
	cmd := newPolicyEvalCmd()
	f := cmd.Flag("change-set")
	if f == nil {
		t.Fatal("expected --change-set flag on policy eval")
	}
	required := false
	for _, a := range f.Annotations[cobra.BashCompOneRequiredFlag] {
		if a == "true" {
			required = true
		}
	}
	if !required {
		t.Errorf("--change-set should be required; annotations = %v", f.Annotations)
	}

	// Phase and format defaults pin the contract.
	if got := cmd.Flag("phase").DefValue; got != "submit" {
		t.Errorf("--phase default = %q; want %q", got, "submit")
	}
	if got := cmd.Flag("format").DefValue; got != "text" {
		t.Errorf("--format default = %q; want %q", got, "text")
	}
}

// TestNormalizePolicyPhase round-trips the supported phase strings and
// rejects anything else.
func TestNormalizePolicyPhase(t *testing.T) {
	if _, err := normalizePolicyPhase("submit"); err != nil {
		t.Errorf("submit: unexpected err %v", err)
	}
	if _, err := normalizePolicyPhase("approve"); err != nil {
		t.Errorf("approve: unexpected err %v", err)
	}
	if _, err := normalizePolicyPhase("nope"); err == nil {
		t.Error("expected error for unknown phase")
	}
}
