package linux_sudo

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"statebound.dev/statebound/internal/connectors"
)

// writeFile is a tiny helper for tests that need to populate a temp dir.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

// mkdir is a tiny helper for tests that need to create sub-directories.
func mkdir(path string) error {
	return os.MkdirAll(path, 0o755)
}

// fixtureSudoersDir returns the absolute path to the testdata/sudoers.d
// directory shipped with the connector.
func fixtureSudoersDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "testdata", "sudoers.d")
}

func TestCollect_HappyPath(t *testing.T) {
	c := New()
	dir := fixtureSudoersDir(t)
	actual, err := c.CollectActualState(context.Background(), connectors.CollectionScope{Path: dir})
	if err != nil {
		t.Fatalf("CollectActualState: %v", err)
	}
	if actual.ConnectorName != "linux-sudo" {
		t.Errorf("ConnectorName = %q, want linux-sudo", actual.ConnectorName)
	}
	if actual.ConnectorVersion != "0.4.0" {
		t.Errorf("ConnectorVersion = %q, want 0.4.0", actual.ConnectorVersion)
	}
	if len(actual.Items) != 2 {
		t.Fatalf("len(Items) = %d, want 2; items=%+v", len(actual.Items), actual.Items)
	}

	// Verify sort order: ResourceRef ASC. db-ops-prod < payments-prod-readonly.
	first := actual.Items[0]
	second := actual.Items[1]
	if first.ResourceRef >= second.ResourceRef {
		t.Errorf("Items not sorted ascending: %q vs %q", first.ResourceRef, second.ResourceRef)
	}
	if first.ResourceRef != "prod-linux:/etc/sudoers.d/db-ops-prod" {
		t.Errorf("Items[0].ResourceRef = %q", first.ResourceRef)
	}
	if second.ResourceRef != "prod-linux:/etc/sudoers.d/payments-prod-readonly" {
		t.Errorf("Items[1].ResourceRef = %q", second.ResourceRef)
	}

	// Verify second item body shape (the well-known fixture).
	if got, want := second.Body["scope"], "prod-linux"; got != want {
		t.Errorf("second.Body.scope = %v, want %v", got, want)
	}
	if got, want := second.Body["entitlement"], "payments-prod-readonly"; got != want {
		t.Errorf("second.Body.entitlement = %v, want %v", got, want)
	}
	if got, want := second.Body["as_user"], "root"; got != want {
		t.Errorf("second.Body.as_user = %v, want %v", got, want)
	}
	gotAllows, ok := second.Body["allows"].([]string)
	if !ok {
		t.Fatalf("second.Body.allows type = %T, want []string", second.Body["allows"])
	}
	wantAllows := []string{
		"/usr/bin/journalctl -u payments --since today",
		"/usr/bin/systemctl status payments",
	}
	if !reflect.DeepEqual(gotAllows, wantAllows) {
		t.Errorf("second.Body.allows = %v, want %v", gotAllows, wantAllows)
	}
	gotDenies, ok := second.Body["denies"].([]string)
	if !ok {
		t.Fatalf("second.Body.denies type = %T, want []string", second.Body["denies"])
	}
	if len(gotDenies) != 0 {
		t.Errorf("second.Body.denies = %v, want empty", gotDenies)
	}

	// First item: db-ops-prod has a single deny line.
	gotDFAllows, _ := first.Body["allows"].([]string)
	wantDFAllows := []string{"/usr/bin/pg_dump payments", "/usr/bin/psql payments"}
	if !reflect.DeepEqual(gotDFAllows, wantDFAllows) {
		t.Errorf("first.Body.allows = %v, want %v", gotDFAllows, wantDFAllows)
	}
	gotDFDenies, _ := first.Body["denies"].([]string)
	if !reflect.DeepEqual(gotDFDenies, []string{"/usr/bin/rm"}) {
		t.Errorf("first.Body.denies = %v, want [/usr/bin/rm]", gotDFDenies)
	}

	// SourceRef must be a file:// URL.
	if actual.SourceRef == "" {
		t.Error("SourceRef is empty")
	}
}

func TestCollect_EmptyDir(t *testing.T) {
	c := New()
	dir := t.TempDir()
	actual, err := c.CollectActualState(context.Background(), connectors.CollectionScope{Path: dir})
	if err != nil {
		t.Fatalf("CollectActualState: %v", err)
	}
	if len(actual.Items) != 0 {
		t.Errorf("len(Items) = %d, want 0 for empty dir", len(actual.Items))
	}
}

func TestCollect_NoPath(t *testing.T) {
	c := New()
	_, err := c.CollectActualState(context.Background(), connectors.CollectionScope{})
	if err == nil {
		t.Fatal("expected error for empty Path, got nil")
	}
}

func TestCollect_NonExistentPath(t *testing.T) {
	c := New()
	_, err := c.CollectActualState(context.Background(), connectors.CollectionScope{Path: "/nonexistent/path/for/test"})
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
}

func TestCollect_Deterministic(t *testing.T) {
	c := New()
	dir := fixtureSudoersDir(t)
	a, err := c.CollectActualState(context.Background(), connectors.CollectionScope{Path: dir})
	if err != nil {
		t.Fatalf("CollectActualState #1: %v", err)
	}
	b, err := c.CollectActualState(context.Background(), connectors.CollectionScope{Path: dir})
	if err != nil {
		t.Fatalf("CollectActualState #2: %v", err)
	}
	if !reflect.DeepEqual(a.Items, b.Items) {
		t.Fatalf("Items differ across runs.\nA=%+v\nB=%+v", a.Items, b.Items)
	}
	if a.SourceRef != b.SourceRef {
		t.Errorf("SourceRef differs: %q vs %q", a.SourceRef, b.SourceRef)
	}
}

func TestCollect_SkipsSubdirectories(t *testing.T) {
	c := New()
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "good"), "# Source: entitlement=good asset_scope=s\n%good ALL=(root) /usr/bin/ls\n"); err != nil {
		t.Fatal(err)
	}
	if err := mkdir(filepath.Join(dir, "nested-dir")); err != nil {
		t.Fatal(err)
	}
	actual, err := c.CollectActualState(context.Background(), connectors.CollectionScope{Path: dir})
	if err != nil {
		t.Fatalf("CollectActualState: %v", err)
	}
	if len(actual.Items) != 1 {
		t.Errorf("len(Items) = %d, want 1 (subdirectory should be skipped)", len(actual.Items))
	}
}

func TestParseSudoersFragment_MissingHeader(t *testing.T) {
	// No header → entitlement/scope are empty; collector falls back to
	// basename + "unknown".
	parsed := parseSudoersFragment([]byte("%foo ALL=(root) /usr/bin/ls\n"))
	if parsed.entitlement != "" {
		t.Errorf("entitlement = %q, want empty", parsed.entitlement)
	}
	if parsed.scope != "" {
		t.Errorf("scope = %q, want empty", parsed.scope)
	}
	if parsed.asUser != "root" {
		t.Errorf("asUser = %q, want root", parsed.asUser)
	}
	if !reflect.DeepEqual(parsed.allows, []string{"/usr/bin/ls"}) {
		t.Errorf("allows = %v", parsed.allows)
	}
}

func TestParseSudoersFragment_CRLF(t *testing.T) {
	parsed := parseSudoersFragment([]byte("# Source: entitlement=e asset_scope=s\r\n%e ALL=(root) /usr/bin/a\r\n"))
	if parsed.entitlement != "e" || parsed.scope != "s" {
		t.Errorf("header parse failed: %+v", parsed)
	}
	if !reflect.DeepEqual(parsed.allows, []string{"/usr/bin/a"}) {
		t.Errorf("allows = %v", parsed.allows)
	}
}
