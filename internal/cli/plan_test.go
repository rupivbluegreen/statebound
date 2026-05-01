package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestPlan_HelpText asserts the Phase 4 plan subcommand renders help text
// listing every documented flag. Help-text rendering is the cheapest
// regression guard for a CLI surface; if a flag is renamed or dropped,
// this test catches it before the integration smoke does.
func TestPlan_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addPlanCmd(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"plan", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(plan --help): %v", err)
	}
	out := buf.String()
	for _, want := range []string{"--product", "--connector", "--version", "--output"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan --help output missing %q; got:\n%s", want, out)
		}
	}
}

// TestPlan_RequiresProduct asserts --product is marked required so a typo
// does not silently fall through to a query against the empty string.
func TestPlan_RequiresProduct(t *testing.T) {
	cmd := newPlanCmd()
	f := cmd.Flag("product")
	if f == nil {
		t.Fatal("expected --product flag on plan")
	}
	required := false
	for _, a := range f.Annotations[cobra.BashCompOneRequiredFlag] {
		if a == "true" {
			required = true
		}
	}
	if !required {
		t.Errorf("--product should be required; annotations = %v", f.Annotations)
	}
}

// TestPlan_RequiresConnector asserts --connector is marked required.
func TestPlan_RequiresConnector(t *testing.T) {
	cmd := newPlanCmd()
	f := cmd.Flag("connector")
	if f == nil {
		t.Fatal("expected --connector flag on plan")
	}
	required := false
	for _, a := range f.Annotations[cobra.BashCompOneRequiredFlag] {
		if a == "true" {
			required = true
		}
	}
	if !required {
		t.Errorf("--connector should be required; annotations = %v", f.Annotations)
	}
}

// TestPlan_FlagDefaults pins the default values for the optional flags so a
// future refactor that flips them trips this test.
func TestPlan_FlagDefaults(t *testing.T) {
	cmd := newPlanCmd()
	if got := cmd.Flag("version").DefValue; got != "latest" {
		t.Errorf("--version default = %q; want %q", got, "latest")
	}
	if got := cmd.Flag("output").DefValue; got != "-" {
		t.Errorf("--output default = %q; want %q", got, "-")
	}
}

// TestCamelToSnakeKey covers the camelCase->snake_case transform used to
// build the plan-time OPA input. Plain snake stays untouched; mixed-case
// translates per the rules in normalize.go (acronym boundaries preserved).
func TestCamelToSnakeKey(t *testing.T) {
	cases := map[string]string{
		"":             "",
		"name":         "name",
		"usagePattern": "usage_pattern",
		"globalObject": "global_object",
		"already_snake": "already_snake",
		"HTTPServer":   "http_server",
		"asUser":       "as_user",
	}
	for in, want := range cases {
		if got := camelToSnakeKey(in); got != want {
			t.Errorf("camelToSnakeKey(%q) = %q; want %q", in, got, want)
		}
	}
}
