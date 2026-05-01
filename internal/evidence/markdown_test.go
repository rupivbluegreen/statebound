package evidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExportMarkdown_Deterministic(t *testing.T) {
	pack := fixedPack(t)
	first, err := ExportMarkdown(pack)
	if err != nil {
		t.Fatalf("ExportMarkdown #1: %v", err)
	}
	second, err := ExportMarkdown(pack)
	if err != nil {
		t.Fatalf("ExportMarkdown #2: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("ExportMarkdown output not byte-identical across runs:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestExportMarkdown_EnvelopeShape(t *testing.T) {
	pack := fixedPack(t)
	out, err := ExportMarkdown(pack)
	if err != nil {
		t.Fatalf("ExportMarkdown: %v", err)
	}
	var env struct {
		Format string `json:"format"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("envelope is not valid JSON: %v\nout:%s", err, out)
	}
	if env.Format != "markdown" {
		t.Errorf("format = %q, want %q", env.Format, "markdown")
	}
	if !strings.HasPrefix(env.Body, "# Evidence Pack") {
		t.Fatalf("body does not start with the evidence pack header; got prefix %q", env.Body[:min(40, len(env.Body))])
	}
}

func TestExportMarkdown_SectionsPresent(t *testing.T) {
	pack := fixedPack(t)
	out, err := ExportMarkdown(pack)
	if err != nil {
		t.Fatalf("ExportMarkdown: %v", err)
	}
	var env struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	body := env.Body
	for _, header := range []string{
		"## Source change set",
		"## Approvals",
		"## Items",
		"## Policy decisions",
		"## Audit events",
		"## Snapshot",
	} {
		if !strings.Contains(body, header) {
			t.Errorf("body missing header %q\nbody:\n%s", header, body)
		}
	}
	// Snapshot section should be wrapped in a yaml fence.
	if !strings.Contains(body, "```yaml") {
		t.Errorf("body missing yaml code fence")
	}
	// Snapshot YAML should mention the apiVersion key from the canonical
	// snapshot. yaml.v3 emits keys at the start of a line.
	if !strings.Contains(body, "apiVersion: statebound.dev/v1alpha1") {
		t.Errorf("body missing apiVersion line; body:\n%s", body)
	}
}

func TestExportMarkdown_TrailingNewline(t *testing.T) {
	pack := fixedPack(t)
	out, err := ExportMarkdown(pack)
	if err != nil {
		t.Fatalf("ExportMarkdown: %v", err)
	}
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Fatalf("envelope output missing trailing newline; tail = %q", string(out[len(out)-3:]))
	}
}

func TestExportMarkdown_PipeEscapeInTableCell(t *testing.T) {
	pack := fixedPack(t)
	pack.Items[0].ResourceName = "pay|ments|prod"
	out, err := ExportMarkdown(pack)
	if err != nil {
		t.Fatalf("ExportMarkdown: %v", err)
	}
	var env struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !strings.Contains(env.Body, `pay\|ments\|prod`) {
		t.Errorf("pipe characters not escaped in table cell; body:\n%s", env.Body)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
