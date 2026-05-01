package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/signing"
)

func TestKeyCmd_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addKeyCmd(root)

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"key", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(key --help): %v", err)
	}
	out := buf.String()
	for _, w := range []string{"generate", "list", "disable"} {
		if !strings.Contains(out, w) {
			t.Errorf("`key --help` missing %q in:\n%s", w, out)
		}
	}
}

func TestKeyGenerate_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addKeyCmd(root)

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"key", "generate", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(key generate --help): %v", err)
	}
	out := buf.String()
	for _, w := range []string{"--key-id", "--note", "--expires", "--output"} {
		if !strings.Contains(out, w) {
			t.Errorf("`key generate --help` missing %q in:\n%s", w, out)
		}
	}
}

func TestKeyList_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addKeyCmd(root)

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"key", "list", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(key list --help): %v", err)
	}
	out := buf.String()
	for _, w := range []string{"--include-disabled", "--format"} {
		if !strings.Contains(out, w) {
			t.Errorf("`key list --help` missing %q in:\n%s", w, out)
		}
	}
}

func TestKeyDisable_HelpText(t *testing.T) {
	root := &cobra.Command{Use: "statebound"}
	addKeyCmd(root)

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"key", "disable", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(key disable --help): %v", err)
	}
	out := buf.String()
	for _, w := range []string{"--key-id", "--enable"} {
		if !strings.Contains(out, w) {
			t.Errorf("`key disable --help` missing %q in:\n%s", w, out)
		}
	}
}

func TestRenderSigningKeysTable(t *testing.T) {
	priv, pub, err := signing.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_ = priv
	k, err := domain.NewSigningKey(
		"release-2026-q2",
		domain.AlgorithmEd25519,
		pub,
		nil,
		signing.Fingerprint(pub),
		"file:/tmp/release-2026-q2.pem",
		domain.Actor{Kind: domain.ActorHuman, Subject: "ops@example.com"},
		nil,
		"quarterly release key",
	)
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}

	var buf bytes.Buffer
	if err := renderSigningKeys(&buf, []*domain.SigningKey{k}, "table"); err != nil {
		t.Fatalf("renderSigningKeys: %v", err)
	}
	out := buf.String()
	for _, w := range []string{"KEY_ID", "FINGERPRINT", "DISABLED", "EXPIRES", "release-2026-q2", "ops@example.com"} {
		if !strings.Contains(out, w) {
			t.Errorf("table missing %q in:\n%s", w, out)
		}
	}
}

func TestRenderSigningKeys_JSON(t *testing.T) {
	_, pub, err := signing.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	k, err := domain.NewSigningKey(
		"k",
		domain.AlgorithmEd25519,
		pub,
		nil,
		signing.Fingerprint(pub),
		"file:/tmp/k.pem",
		domain.Actor{Kind: domain.ActorHuman, Subject: "ops@example.com"},
		nil,
		"",
	)
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	var buf bytes.Buffer
	if err := renderSigningKeys(&buf, []*domain.SigningKey{k}, "json"); err != nil {
		t.Fatalf("renderSigningKeys json: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"key_id": "k"`) {
		t.Errorf("json output missing key_id field: %s", out)
	}
	if strings.Contains(out, "private_key") && !strings.Contains(out, "private_key_ref") {
		t.Errorf("json output leaked private key bytes: %s", out)
	}
}

func TestShortFingerprint(t *testing.T) {
	full := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got := shortFingerprint(full)
	if !strings.HasPrefix(got, "sha256:") {
		t.Errorf("shortFingerprint(%q) = %q, missing prefix", full, got)
	}
	if len(got) >= len(full) {
		t.Errorf("shortFingerprint did not trim: %q vs %q", got, full)
	}
	if shortFingerprint("") != "" {
		t.Errorf("empty fingerprint should pass through")
	}
}
