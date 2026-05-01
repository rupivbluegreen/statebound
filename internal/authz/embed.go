package authz

import (
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
)

// bundleFS holds the Rego rule library at build time. Go's embed directive
// forbids parent-relative paths, so the rule files live at
// internal/authz/bundle/*.rego — synced from policies/builtin/*.rego by the
// Makefile target authz-sync-bundle. We embed the whole `bundle` directory
// (not a glob) so an empty bundle/ during early bootstrap still compiles;
// the runtime checks for non-empty content and reports a clear error.
//
//go:embed bundle
var bundleFS embed.FS

// bundleSubFS is the bundle directory as a fs.FS. Rooted at "bundle".
const bundleRoot = "bundle"

// computeBundleHash hashes every .rego file under fsys (rooted at the
// bundle directory) in lexicographic order. Each file contributes:
//
//	uint32(len(path))  || path
//	uint32(len(body))  || body
//
// to the SHA-256 stream. Length prefixes prevent path|body collisions
// where one file's body bleeds into the next file's path.
func computeBundleHash(fsys fs.FS) (string, error) {
	type entry struct {
		path string
		body []byte
	}

	var entries []entry
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		// Only Rego rule files. Skip .gitkeep, README, etc.
		if !hasSuffix(path, ".rego") {
			return nil
		}
		body, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return fmt.Errorf("authz: read bundle file %q: %w", path, readErr)
		}
		entries = append(entries, entry{path: path, body: body})
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", errBundleEmpty
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	h := sha256.New()
	var lenBuf [4]byte
	for _, e := range entries {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(e.path)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write([]byte(e.path))
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(e.body)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write(e.body)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// errBundleEmpty signals that the embedded bundle/ directory contains no
// .rego files. Callers (notably tests) may treat this as a skip rather
// than a hard failure during early bootstrap.
var errBundleEmpty = errors.New("authz: rego bundle is empty (run authz-sync-bundle)")

// loadBundleModules reads every .rego file under fsys and returns a slice
// of (filename, content) pairs ready to feed into rego.Module(...). The
// filename here is the in-bundle relative path; OPA uses it for error
// reporting only.
func loadBundleModules(fsys fs.FS) ([]bundleModule, error) {
	var mods []bundleModule
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !hasSuffix(path, ".rego") {
			return nil
		}
		body, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return fmt.Errorf("authz: read bundle file %q: %w", path, readErr)
		}
		mods = append(mods, bundleModule{Filename: path, Source: string(body)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(mods) == 0 {
		return nil, errBundleEmpty
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Filename < mods[j].Filename })
	return mods, nil
}

type bundleModule struct {
	Filename string
	Source   string
}

// hasSuffix is a tiny helper so we don't drag in strings just for one call.
func hasSuffix(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}
