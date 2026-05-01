package cli

import (
	"strings"
	"testing"
)

// TestAPIServeCmd_Help asserts the help text exposes every flag the
// operator-facing docs and CI smoke depend on.
func TestAPIServeCmd_Help(t *testing.T) {
	cmd := newAPIServeCmd()
	out := cmd.UsageString()
	for _, want := range []string{
		"--listen",
		"--oidc-issuer",
		"--oidc-audience",
		"--dev-token",
		"--dev-actor",
		"--read-timeout",
		"--write-timeout",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("api serve usage missing flag %s\n%s", want, out)
		}
	}
}

func TestAPICmd_Subcommand(t *testing.T) {
	// Nothing dramatic — just confirm `api serve` is wired.
	parent := newAPIServeCmd()
	if parent == nil {
		t.Fatalf("nil command")
	}
	if parent.Use != "serve" {
		t.Errorf("unexpected Use: %s", parent.Use)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "x"); got != "x" {
		t.Errorf("got %q", got)
	}
	if got := firstNonEmpty("a", "b"); got != "a" {
		t.Errorf("got %q", got)
	}
	if got := firstNonEmpty(); got != "" {
		t.Errorf("got %q", got)
	}
}
