package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestEvidence_HelpText asserts each subcommand renders help text containing
// the documented flags. Help-text rendering is the cheapest regression guard
// for a CLI surface; if a flag rename or removal slips through, this fires
// before the integration smoke does.
func TestEvidence_HelpText(t *testing.T) {
	cases := map[string][]string{
		"evidence":         {"export", "list", "show", "Export, list, and inspect"},
		"evidence export":  {"--product", "--version", "--format", "--output"},
		"evidence list":    {"--product", "--limit", "--format"},
		"evidence show":    {"--output", "--unwrap"},
	}

	for invocation, wants := range cases {
		invocation, wants := invocation, wants
		t.Run(invocation, func(t *testing.T) {
			root := &cobra.Command{Use: "statebound"}
			addEvidenceCmd(root)
			var buf bytes.Buffer
			root.SetOut(&buf)
			root.SetErr(&buf)
			args := append(strings.Fields(invocation), "--help")
			root.SetArgs(args)
			if err := root.Execute(); err != nil {
				t.Fatalf("Execute(%q) returned error: %v", invocation, err)
			}
			out := buf.String()
			for _, want := range wants {
				if !strings.Contains(out, want) {
					t.Errorf("%s --help output missing %q; got:\n%s", invocation, want, out)
				}
			}
		})
	}
}

// TestEvidenceExport_RequiresProduct asserts the --product flag is marked
// required so a user typo does not silently fall through to a query against
// the empty string.
func TestEvidenceExport_RequiresProduct(t *testing.T) {
	cmd := newEvidenceExportCmd()
	f := cmd.Flag("product")
	if f == nil {
		t.Fatal("expected --product flag on evidence export")
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

	// Pin defaults so a future refactor that flips them trips this test.
	if got := cmd.Flag("version").DefValue; got != "latest" {
		t.Errorf("--version default = %q; want %q", got, "latest")
	}
	if got := cmd.Flag("format").DefValue; got != "json" {
		t.Errorf("--format default = %q; want %q", got, "json")
	}
	if got := cmd.Flag("output").DefValue; got != "-" {
		t.Errorf("--output default = %q; want %q", got, "-")
	}
}

// TestEvidenceList_RequiresProduct mirrors the export test for the list
// subcommand: --product is required, --limit defaults to 20, --format to text.
func TestEvidenceList_RequiresProduct(t *testing.T) {
	cmd := newEvidenceListCmd()
	f := cmd.Flag("product")
	if f == nil {
		t.Fatal("expected --product flag on evidence list")
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
	if got := cmd.Flag("limit").DefValue; got != "20" {
		t.Errorf("--limit default = %q; want %q", got, "20")
	}
	if got := cmd.Flag("format").DefValue; got != "text" {
		t.Errorf("--format default = %q; want %q", got, "text")
	}
}

// TestNormalizeEvidenceFormat round-trips the supported formats and rejects
// anything else.
func TestNormalizeEvidenceFormat(t *testing.T) {
	for _, in := range []string{"json", "JSON", " markdown ", "Markdown"} {
		if _, err := normalizeEvidenceFormat(in); err != nil {
			t.Errorf("%q: unexpected err %v", in, err)
		}
	}
	if _, err := normalizeEvidenceFormat("yaml"); err == nil {
		t.Error("expected error for unsupported format yaml")
	}
}

// TestEvidenceSinkLabel pins the canonical sink label embedded in
// evidence.exported audit events.
func TestEvidenceSinkLabel(t *testing.T) {
	cases := map[string]string{
		"":            "stdout",
		"-":           "stdout",
		"/tmp/ev.json": "file:/tmp/ev.json",
	}
	for in, want := range cases {
		if got := evidenceSinkLabel(in); got != want {
			t.Errorf("evidenceSinkLabel(%q) = %q; want %q", in, got, want)
		}
	}
}
