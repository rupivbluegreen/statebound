package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/connectors/builtins"
)

// TestConnectorList_HelpText asserts the connector list subcommand surfaces
// its --format flag in help output.
func TestConnectorList_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addConnectorCmd(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"connector", "list", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(connector list --help): %v", err)
	}
	out := buf.String()
	for _, want := range []string{"--format"} {
		if !strings.Contains(out, want) {
			t.Errorf("connector list --help missing %q; got:\n%s", want, out)
		}
	}
}

// TestConnectorList_RegistersBuiltins asserts that booting a fresh registry
// + builtins.Register yields linux-sudo and linux-ssh, both exposing
// CapabilityPlan. This is the canary for Phase 4: if the built-in list ever
// regresses, this test fires before an end-to-end smoke does.
func TestConnectorList_RegistersBuiltins(t *testing.T) {
	r := connectors.NewRegistry()
	builtins.Register(r)

	for _, name := range []string{"linux-sudo", "linux-ssh"} {
		conn, ok := r.Get(name)
		if !ok {
			t.Fatalf("connector %q not registered by RegisterBuiltins", name)
		}
		hasPlan := false
		for _, c := range conn.Capabilities() {
			if c == connectors.CapabilityPlan {
				hasPlan = true
				break
			}
		}
		if !hasPlan {
			t.Errorf("connector %q missing CapabilityPlan; caps = %v",
				name, conn.Capabilities())
		}
	}
}

// TestRunConnectorList_TextRendersBothBuiltins runs the text-format renderer
// and asserts both built-ins appear in the table. Cheaper than a full
// process-level test and catches table renderer regressions.
func TestRunConnectorList_TextRendersBothBuiltins(t *testing.T) {
	var buf bytes.Buffer
	if err := runConnectorList(&buf, "text"); err != nil {
		t.Fatalf("runConnectorList: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"linux-sudo", "linux-ssh", "plan"} {
		if !strings.Contains(out, want) {
			t.Errorf("connector list text output missing %q; got:\n%s", want, out)
		}
	}
}

// TestRunConnectorList_JSONIsValid asserts JSON output parses and contains
// both built-in names. JSON is the machine-readable contract; if the schema
// ever drifts, downstream tooling breaks silently otherwise.
func TestRunConnectorList_JSONIsValid(t *testing.T) {
	var buf bytes.Buffer
	if err := runConnectorList(&buf, "json"); err != nil {
		t.Fatalf("runConnectorList json: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`"name"`, `"linux-sudo"`, `"linux-ssh"`, `"capabilities"`, `"plan"`} {
		if !strings.Contains(out, want) {
			t.Errorf("connector list json output missing %q; got:\n%s", want, out)
		}
	}
}

// TestRunConnectorList_UnknownFormat asserts unknown format strings produce
// a clear error rather than silently falling through to one of the others.
func TestRunConnectorList_UnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := runConnectorList(&buf, "xml")
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "xml") {
		t.Errorf("error message %q should reference the bad format", err.Error())
	}
}
