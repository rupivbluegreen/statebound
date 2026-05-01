package telemetry

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

// TestDetect_NoEnvVars asserts the documented "off by default" promise:
// with no STATEBOUND_OTEL_* env vars set, Detect returns a Config that
// reports Enabled() == false and Init installs the no-op provider.
func TestDetect_NoEnvVars(t *testing.T) {
	clearOtelEnv(t)

	cfg := Detect()
	if cfg.Enabled() {
		t.Fatalf("Detect() reports enabled with no env vars: %#v", cfg)
	}
	if cfg.ServiceName != defaultServiceName {
		t.Errorf("ServiceName default = %q; want %q", cfg.ServiceName, defaultServiceName)
	}

	shutdown, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Init(off): %v", err)
	}
	if shutdown == nil {
		t.Fatal("Init(off) returned nil shutdown")
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	// StartSpan with telemetry off must still return a non-nil span
	// that satisfies the trace.Span interface — the no-op span. We
	// also verify the returned context is non-nil.
	ctx, span := StartSpan(context.Background(), "noop.test")
	if ctx == nil {
		t.Fatal("StartSpan returned nil context")
	}
	if span == nil {
		t.Fatal("StartSpan returned nil span when telemetry off")
	}
	span.End() // must not panic
	var _ trace.Span = span
}

// TestInit_StdoutExporter wires the stdouttrace exporter to a buffer
// and asserts a span we create lands as JSON. This is the smoke test
// that the documented operator-facing pattern (export STATEBOUND_OTEL_EXPORTER=stdout)
// actually emits trace data.
func TestInit_StdoutExporter(t *testing.T) {
	clearOtelEnv(t)
	t.Setenv(EnvExporter, "stdout")

	var buf bytes.Buffer
	SetStdoutWriter(&buf)
	t.Cleanup(func() { SetStdoutWriter(nil) })

	cfg := Detect()
	if cfg.Exporter != ExporterStdout {
		t.Fatalf("Detect() Exporter = %q; want %q", cfg.Exporter, ExporterStdout)
	}
	cfg.ServiceVersion = "test-1.2.3"

	shutdown, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Init(stdout): %v", err)
	}

	// Create a span with attributes; End() schedules the export.
	ctx, span := StartSpan(context.Background(), "telemetry.smoke",
		AttrConnector.String("linux-sudo"),
		AttrProductName.String("payments-api"),
	)
	span.SetAttributes(AttrApprovedVersion.Int64(7))
	span.End()

	// Shutdown blocks until the batcher drains, so by the time it
	// returns the buffer holds the exported JSON.
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	_ = ctx

	got := buf.String()
	if got == "" {
		t.Fatal("stdouttrace produced no output")
	}
	wants := []string{
		`"Name":"telemetry.smoke"`,
		`"statebound.connector"`,
		`"linux-sudo"`,
		`"statebound.product"`,
		`"payments-api"`,
		`"statebound.approved_version"`,
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("stdouttrace output missing %q\nfull output:\n%s", w, got)
		}
	}
}

// TestInit_OTLPGRPC_BogusEndpoint exercises the path where OTel is
// asked to export to a collector that isn't there. The contract: Init
// returns without panicking and StartSpan keeps working — the SDK
// queues spans and surfaces export errors via its internal handler.
// We do not block on or assert delivery (no remote in CI).
func TestInit_OTLPGRPC_BogusEndpoint(t *testing.T) {
	clearOtelEnv(t)
	t.Setenv(EnvExporter, "otlp-grpc")
	t.Setenv(EnvEndpoint, "127.0.0.1:1") // closed port

	cfg := Detect()
	shutdown, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Init(otlp-grpc, bogus endpoint): expected graceful init, got error: %v", err)
	}

	ctx, span := StartSpan(context.Background(), "telemetry.bogus")
	span.End()
	_ = ctx

	// Shutdown must return without panic. The exporter may report an
	// error to its internal handler when the collector is unreachable;
	// that is acceptable here — we only assert no panic and no leaked
	// state. We deliberately use a short context so the shutdown does
	// not hang the test on retries.
	shutdownCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = shutdown(shutdownCtx)
}

// TestStartSpan_AttachesAttributes confirms StartSpan accepts the
// variadic attribute slice and the span carries them. This protects
// against a future refactor that drops the WithAttributes call when
// the slice is non-empty.
func TestStartSpan_AttachesAttributes(t *testing.T) {
	clearOtelEnv(t)
	t.Setenv(EnvExporter, "stdout")

	var buf bytes.Buffer
	SetStdoutWriter(&buf)
	t.Cleanup(func() { SetStdoutWriter(nil) })

	shutdown, err := Init(context.Background(), Detect())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	_, span := StartSpan(context.Background(), "attr.test",
		AttrPolicyOutcome.String("allow"),
		AttrPolicyPhase.String("approve"),
	)
	span.End()

	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, `"statebound.policy_outcome"`) {
		t.Errorf("missing statebound.policy_outcome in output:\n%s", got)
	}
	if !strings.Contains(got, `"allow"`) {
		t.Errorf("missing allow value in output:\n%s", got)
	}
}

// TestDetect_IncludeActor confirms the PII-gating env var is plumbed
// through Detect into the active config so call sites can read
// IncludeActor() before attaching actor identifiers.
func TestDetect_IncludeActor(t *testing.T) {
	clearOtelEnv(t)
	t.Setenv(EnvExporter, "stdout")
	t.Setenv(EnvIncludeActor, "true")

	var buf bytes.Buffer
	SetStdoutWriter(&buf)
	t.Cleanup(func() { SetStdoutWriter(nil) })

	cfg := Detect()
	if !cfg.IncludeActor {
		t.Fatalf("IncludeActor = false; want true with env var set")
	}
	shutdown, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !IncludeActor() {
		t.Errorf("IncludeActor() = false after enabled config installed")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if IncludeActor() {
		t.Errorf("IncludeActor() = true after shutdown; expected reset to false")
	}
}

// TestParseSampler covers the documented sampler strings. We don't
// assert sampler internal state — sdktrace.Sampler is an opaque
// interface — only that parsing succeeds for valid inputs and rejects
// bad ones.
func TestParseSampler(t *testing.T) {
	good := []string{"", "always", "never", "ratio:0", "ratio:0.5", "ratio:1"}
	for _, s := range good {
		if _, err := parseSampler(s); err != nil {
			t.Errorf("parseSampler(%q) returned error: %v", s, err)
		}
	}
	bad := []string{"sometimes", "ratio:-1", "ratio:2", "ratio:abc"}
	for _, s := range bad {
		if _, err := parseSampler(s); err == nil {
			t.Errorf("parseSampler(%q) returned nil error; want error", s)
		}
	}
}

// clearOtelEnv unsets every STATEBOUND_OTEL_* env var for the duration
// of the test so a developer running the suite under their own
// telemetry config does not see false positives.
func clearOtelEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		EnvExporter,
		EnvEndpoint,
		EnvServiceName,
		EnvInsecure,
		EnvSampler,
		EnvIncludeActor,
	} {
		t.Setenv(k, "")
	}
}
