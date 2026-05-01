package signing_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/signing"
)

func TestLoadPrivateKey_FileScheme(t *testing.T) {
	priv, _, err := signing.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "k.pem")
	if err := signing.SaveKeyFile(path, priv); err != nil {
		t.Fatalf("SaveKeyFile: %v", err)
	}

	got, err := signing.LoadPrivateKey("file:" + path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if len(got) != ed25519.PrivateKeySize {
		t.Errorf("loaded len = %d, want %d", len(got), ed25519.PrivateKeySize)
	}
	for i := range got {
		if got[i] != priv[i] {
			t.Fatalf("loaded bytes diverge at index %d", i)
		}
	}

	// Mode is 0600.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestSaveKeyFile_RefusesOverwrite(t *testing.T) {
	priv, _, _ := signing.Generate()
	dir := t.TempDir()
	path := filepath.Join(dir, "k.pem")
	if err := signing.SaveKeyFile(path, priv); err != nil {
		t.Fatalf("first SaveKeyFile: %v", err)
	}
	if err := signing.SaveKeyFile(path, priv); err == nil {
		t.Fatal("expected SaveKeyFile to refuse overwriting an existing key")
	}
}

func TestLoadPrivateKey_EnvScheme(t *testing.T) {
	priv, _, err := signing.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(priv)
	t.Setenv("STATEBOUND_TEST_KEY", encoded)
	got, err := signing.LoadPrivateKey("env:STATEBOUND_TEST_KEY")
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if len(got) != ed25519.PrivateKeySize {
		t.Errorf("loaded len = %d, want %d", len(got), ed25519.PrivateKeySize)
	}
	for i := range got {
		if got[i] != priv[i] {
			t.Fatalf("loaded bytes diverge at index %d", i)
		}
	}
}

func TestLoadPrivateKey_EnvMissing(t *testing.T) {
	// Make sure the variable is unset for the duration of the test.
	t.Setenv("STATEBOUND_NO_SUCH_KEY", "")
	_ = os.Unsetenv("STATEBOUND_NO_SUCH_KEY")
	_, err := signing.LoadPrivateKey("env:STATEBOUND_NO_SUCH_KEY")
	if err == nil {
		t.Fatal("expected error when env var is unset")
	}
	if !errors.Is(err, domain.ErrSigningKeyNotFound) {
		t.Errorf("error = %v, want ErrSigningKeyNotFound", err)
	}
}

func TestLoadPrivateKey_FileMissing(t *testing.T) {
	_, err := signing.LoadPrivateKey("file:/nonexistent/" + filepath.Base(t.TempDir()) + "/k.pem")
	if err == nil {
		t.Fatal("expected error when file is missing")
	}
	if !errors.Is(err, domain.ErrSigningKeyNotFound) {
		t.Errorf("error = %v, want ErrSigningKeyNotFound", err)
	}
}

func TestLoadPrivateKey_BadScheme(t *testing.T) {
	cases := []string{
		"",
		"http://example.com",
		"weirdscheme:value",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, err := signing.LoadPrivateKey(c)
			if err == nil {
				t.Errorf("expected error for ref %q", c)
			}
		})
	}
}

func TestLoadPrivateKey_FileWrongPEMType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrong.pem")
	contents := "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAOKnwPYL\n-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := signing.LoadPrivateKey("file:" + path)
	if err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
	if !strings.Contains(err.Error(), "PEM type") {
		t.Errorf("error = %v, want PEM type complaint", err)
	}
}

func TestDefaultPrivateKeyPath(t *testing.T) {
	got := signing.DefaultPrivateKeyPath("/home/me/.statebound", "release-2026-q2")
	want := "/home/me/.statebound/signing-keys/release-2026-q2.pem"
	if got != want {
		t.Errorf("DefaultPrivateKeyPath = %q, want %q", got, want)
	}
}
