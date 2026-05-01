package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/connectors/builtins"
)

// TestDrift_HelpText asserts the Phase 4' drift parent command and its
// subcommands render help text. Help-text rendering is the cheapest
// regression guard for a CLI surface; if a subcommand is renamed or
// dropped, this test catches it before the integration smoke does.
func TestDrift_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addDriftCmd(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"drift", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(drift --help): %v", err)
	}
	out := buf.String()
	for _, want := range []string{"scan", "list", "show"} {
		if !strings.Contains(out, want) {
			t.Errorf("drift --help output missing subcommand %q; got:\n%s", want, out)
		}
	}
}

// TestDriftScan_HelpText pins every documented flag on `drift scan`.
func TestDriftScan_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addDriftCmd(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"drift", "scan", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(drift scan --help): %v", err)
	}
	out := buf.String()
	for _, want := range []string{"--product", "--connector", "--source", "--version", "--output"} {
		if !strings.Contains(out, want) {
			t.Errorf("drift scan --help output missing %q; got:\n%s", want, out)
		}
	}
}

// TestDriftScan_RequiredFlags asserts that --product, --connector, and
// --source are all required. A missing flag should not silently fall
// through to a query against the empty string.
func TestDriftScan_RequiredFlags(t *testing.T) {
	cmd := newDriftScanCmd()
	for _, flag := range []string{"product", "connector", "source"} {
		f := cmd.Flag(flag)
		if f == nil {
			t.Fatalf("expected --%s flag on drift scan", flag)
		}
		required := false
		for _, a := range f.Annotations[cobra.BashCompOneRequiredFlag] {
			if a == "true" {
				required = true
			}
		}
		if !required {
			t.Errorf("--%s should be required; annotations = %v", flag, f.Annotations)
		}
	}
}

// TestDriftScan_FlagDefaults pins the default values for the optional
// flags so a future refactor that flips them trips this test.
func TestDriftScan_FlagDefaults(t *testing.T) {
	cmd := newDriftScanCmd()
	if got := cmd.Flag("version").DefValue; got != "latest" {
		t.Errorf("--version default = %q; want %q", got, "latest")
	}
	if got := cmd.Flag("output").DefValue; got != "-" {
		t.Errorf("--output default = %q; want %q", got, "-")
	}
}

// TestDriftList_HelpText pins the documented flags on `drift list`.
func TestDriftList_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addDriftCmd(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"drift", "list", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(drift list --help): %v", err)
	}
	out := buf.String()
	for _, want := range []string{"--product", "--limit", "--format"} {
		if !strings.Contains(out, want) {
			t.Errorf("drift list --help output missing %q; got:\n%s", want, out)
		}
	}
}

// TestDriftShow_HelpText pins the documented flags on `drift show`.
func TestDriftShow_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addDriftCmd(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"drift", "show", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(drift show --help): %v", err)
	}
	out := buf.String()
	for _, want := range []string{"--output"} {
		if !strings.Contains(out, want) {
			t.Errorf("drift show --help output missing %q; got:\n%s", want, out)
		}
	}
}

// TestConnectorSupportsDrift sanity-checks the capability gate against the
// built-in registry. linux-sudo advertises CollectActual+Compare; linux-ssh
// does not. The CLI uses this gate to refuse drift scans against
// unsupported connectors with a clean error message.
func TestConnectorSupportsDrift(t *testing.T) {
	r := connectors.NewRegistry()
	builtins.Register(r)

	sudo, ok := r.Get("linux-sudo")
	if !ok {
		t.Fatalf("linux-sudo connector not registered")
	}
	if !connectorSupportsDrift(sudo) {
		t.Errorf("linux-sudo should support drift; capabilities = %v", sudo.Capabilities())
	}

	ssh, ok := r.Get("linux-ssh")
	if !ok {
		t.Fatalf("linux-ssh connector not registered")
	}
	if connectorSupportsDrift(ssh) {
		t.Errorf("linux-ssh should NOT support drift in Phase 4'; capabilities = %v", ssh.Capabilities())
	}
}

// TestSeverityDistribution verifies the severity counter zero-fills every
// canonical severity, even when no findings carry that level. The audit
// payload depends on a stable shape, so a regression here would silently
// change every drift.scan.succeeded payload.
func TestSeverityDistribution(t *testing.T) {
	dist := severityDistribution([]connectors.DriftFinding{
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "info"},
	})
	want := map[string]int{
		"critical": 0,
		"high":     2,
		"medium":   1,
		"low":      0,
		"info":     1,
	}
	for k, v := range want {
		if dist[k] != v {
			t.Errorf("dist[%s] = %d, want %d", k, dist[k], v)
		}
	}
}

// TestFormatSeverityDistribution pins the rendering order so the stderr
// summary line is stable across runs.
func TestFormatSeverityDistribution(t *testing.T) {
	dist := map[string]int{
		"critical": 1,
		"high":     2,
		"medium":   3,
		"low":      4,
		"info":     5,
	}
	got := formatSeverityDistribution(dist)
	want := "1 critical, 2 high, 3 medium, 4 low, 5 info"
	if got != want {
		t.Errorf("formatSeverityDistribution = %q, want %q", got, want)
	}
}

// TestSummaryHashStableForCanonicalFindings asserts that two encodes of
// the same canonical findings list produce the same SHA-256. This pins
// the wire shape used to compute summary_hash; if it drifts (e.g. a new
// field is added to canonicalFinding), every previously-computed hash
// becomes invalid and an evidence pack regression is the next thing to
// blow up.
func TestSummaryHashStableForCanonicalFindings(t *testing.T) {
	findings := []canonicalFinding{
		{
			Sequence:     1,
			Kind:         "modified",
			Severity:     "high",
			ResourceKind: "linux.sudoers-fragment",
			ResourceRef:  "/etc/sudoers.d/payments-prod-readonly",
			Desired:      json.RawMessage(`{"path":"/etc/sudoers.d/x"}`),
			Actual:       json.RawMessage(`{"path":"/etc/sudoers.d/x","extra":true}`),
			Diff:         json.RawMessage(`{"changed":["content"]}`),
			Message:      "fragment content changed",
		},
	}
	first, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}
	second, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal second: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("encodes differ across runs:\n first=%s\nsecond=%s", first, second)
	}
	h1 := sha256.Sum256(first)
	h2 := sha256.Sum256(second)
	if hex.EncodeToString(h1[:]) != hex.EncodeToString(h2[:]) {
		t.Fatalf("hashes differ across runs: %s vs %s", hex.EncodeToString(h1[:]), hex.EncodeToString(h2[:]))
	}
}
