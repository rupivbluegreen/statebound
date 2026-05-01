package cli

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestVersionString_Format(t *testing.T) {
	origVersion, origCommit, origBuildDate := Version, Commit, BuildDate
	t.Cleanup(func() {
		Version = origVersion
		Commit = origCommit
		BuildDate = origBuildDate
	})

	Version = "0.0.0-test"
	Commit = "abcd"
	BuildDate = "2026-05-01"

	got := versionString()

	wants := []string{
		"0.0.0-test",
		"abcd",
		"2026-05-01",
		runtime.Version(),
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("versionString() = %q; missing %q", got, w)
		}
	}
}

func TestVersionCommand_RunsWithoutError(t *testing.T) {
	// Build a fresh root command so we don't depend on the package-level rootCmd's state.
	root := &cobra.Command{Use: "statebound"}
	addVersionCmd(root)

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "statebound") {
		t.Errorf("output %q does not contain %q", out, "statebound")
	}
}
