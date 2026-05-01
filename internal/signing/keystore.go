// Package signing — private key loading.
//
// The Statebound v0.7 boundary stores ONLY the public half of a signing
// key in the database. The private half lives on disk (file mode 0600)
// or in an env var (CI). LoadPrivateKey resolves a "private_key_ref"
// string into raw 64-byte Ed25519 bytes. The function performs no
// logging — callers MUST NOT log the bytes either.
//
// Supported reference schemes:
//
//   file:<path>      Reads a PEM-encoded "ED25519 PRIVATE KEY" block.
//                    Path may start with "~" to mean $HOME.
//
//   env:<name>       Reads base64-encoded private key from the named
//                    env var (standard or url-safe encoding accepted).
//
// SaveKeyFile writes a PEM-encoded private key block to path with mode
// 0600 (owner read/write only). The file is created with O_EXCL so an
// accidental overwrite of a live key fails fast.

package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"statebound.dev/statebound/internal/domain"
)

// PEM block type for an Ed25519 private key. Standard tooling uses
// "ED25519 PRIVATE KEY"; we follow that convention so a generated key
// can be inspected by `openssl asn1parse` style tools.
const ed25519PrivatePEMType = "ED25519 PRIVATE KEY"

// LoadPrivateKey resolves a private_key_ref to raw 64-byte Ed25519
// private key bytes. The function performs no logging and returns
// domain.ErrSigningKeyNotFound when the reference is unresolvable.
func LoadPrivateKey(ref string) ([]byte, error) {
	if ref == "" {
		return nil, fmt.Errorf("%w: empty ref", domain.ErrSigningKeyNotFound)
	}
	scheme, value, ok := strings.Cut(ref, ":")
	if !ok {
		return nil, fmt.Errorf("signing: malformed private_key_ref %q (want <scheme>:<value>)", ref)
	}
	switch scheme {
	case "file":
		return loadPrivateKeyFromFile(value)
	case "env":
		return loadPrivateKeyFromEnv(value)
	default:
		return nil, fmt.Errorf("signing: unknown private_key_ref scheme %q", scheme)
	}
}

func loadPrivateKeyFromFile(path string) ([]byte, error) {
	expanded, err := expandHome(path)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(expanded)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: file %s", domain.ErrSigningKeyNotFound, expanded)
		}
		return nil, fmt.Errorf("signing: read private key file: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("signing: %s does not contain a PEM block", expanded)
	}
	if block.Type != ed25519PrivatePEMType {
		return nil, fmt.Errorf("signing: %s has PEM type %q, want %q", expanded, block.Type, ed25519PrivatePEMType)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing: %s decodes to %d bytes, want %d",
			expanded, len(block.Bytes), ed25519.PrivateKeySize)
	}
	out := make([]byte, len(block.Bytes))
	copy(out, block.Bytes)
	return out, nil
}

func loadPrivateKeyFromEnv(name string) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("signing: env private_key_ref requires an env var name")
	}
	v := os.Getenv(name)
	if v == "" {
		return nil, fmt.Errorf("%w: env var %s", domain.ErrSigningKeyNotFound, name)
	}
	v = strings.TrimSpace(v)
	// Accept both standard and URL-safe base64 to ease CI configuration.
	decoders := []func(string) ([]byte, error){
		func(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) },
		func(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(s) },
		func(s string) ([]byte, error) { return base64.URLEncoding.DecodeString(s) },
		func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) },
	}
	var (
		decoded []byte
		decErr  error
	)
	for _, d := range decoders {
		b, err := d(v)
		if err == nil {
			decoded = b
			decErr = nil
			break
		}
		decErr = err
	}
	if decoded == nil {
		return nil, fmt.Errorf("signing: env %s is not valid base64: %w", name, decErr)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing: env %s decodes to %d bytes, want %d",
			name, len(decoded), ed25519.PrivateKeySize)
	}
	return decoded, nil
}

// SaveKeyFile writes priv as a PEM-encoded ED25519 PRIVATE KEY to path,
// creating the file with mode 0600 and refusing to overwrite an existing
// file. Parent directories are created with mode 0700 if they do not
// already exist.
func SaveKeyFile(path string, priv []byte) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("signing: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	expanded, err := expandHome(path)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(expanded); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("signing: create key directory: %w", err)
		}
	}
	f, err := os.OpenFile(expanded, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("signing: open %s: %w", expanded, err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: ed25519PrivatePEMType, Bytes: priv}); err != nil {
		return fmt.Errorf("signing: write pem: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("signing: chmod %s: %w", expanded, err)
	}
	return nil
}

// expandHome expands a leading "~" to $HOME. Other path forms pass through.
func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("signing: resolve home: %w", err)
	}
	if path == "~" {
		return home, nil
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

// DefaultPrivateKeyPath returns the conventional disk location for a
// signing key file, given a base directory (typically ~/.statebound).
// Used by the CLI key generate subcommand for the default --output flag.
func DefaultPrivateKeyPath(base, keyID string) string {
	return filepath.Join(base, "signing-keys", keyID+".pem")
}
