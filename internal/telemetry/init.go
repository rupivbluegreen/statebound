package telemetry

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// tracerName is the instrumentation library identifier reported on every
// span produced by this package. Operators searching their trace store
// can filter on this name to isolate statebound-emitted spans from
// future library-emitted ones.
const tracerName = "statebound.dev/statebound/internal/telemetry"

// stdoutWriter is overridable for tests so we can capture the
// stdouttrace exporter output without grabbing the process's real
// stdout. Production code never sets it; Init falls back to os.Stdout
// when the value is nil.
var stdoutWriter atomic.Value // io.Writer

// SetStdoutWriter swaps the writer used by the stdout exporter. Tests
// call this before Init to capture span output; pass nil to clear.
//
// atomic.Value rejects a nil concrete value being stored after a
// non-nil one of the same type, so the "clear" path stores a typed
// nil io.Writer wrapped in an interface holder. stdoutTarget()
// guards against the nil holder when reading.
func SetStdoutWriter(w io.Writer) {
	stdoutWriter.Store(stdoutWriterHolder{w: w})
}

// stdoutWriterHolder wraps the configured writer so we can store
// "no writer set" by storing a holder whose w is nil — atomic.Value
// requires every Store to carry the same concrete type, which a bare
// io.Writer interface value does not satisfy on the nil-clear path.
type stdoutWriterHolder struct {
	w io.Writer
}

// noopShutdown is the shutdown closure returned when telemetry is
// disabled. It is a function value rather than a nil so callers can
// unconditionally `defer shutdown(ctx)` without nil-checking.
func noopShutdown(_ context.Context) error { return nil }

// Init configures the global tracer provider, the propagator, and the
// SDK exporter from cfg. When cfg.Enabled() is false, Init installs a
// no-op tracer provider and returns a no-op shutdown — the per-span
// cost on the hot paths is then a single nil-method call.
//
// Callers MUST defer the returned shutdown(ctx) before exiting so any
// queued spans are flushed.
func Init(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	// Always install the W3C TraceContext + Baggage propagator. The
	// global propagator is read by every otel.Tracer instance, and the
	// no-op provider safely ignores propagated context, so doing this
	// unconditionally costs nothing when tracing is disabled and means
	// upstream services can pass trace context through us without
	// silently dropping it.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if !cfg.Enabled() {
		// No-op provider. otel.GetTracerProvider() will return this
		// and every span StartSpan creates becomes a noop.Span.
		otel.SetTracerProvider(noop.NewTracerProvider())
		return noopShutdown, nil
	}

	exporter, err := buildExporter(ctx, cfg)
	if err != nil {
		return noopShutdown, fmt.Errorf("telemetry: build exporter: %w", err)
	}

	res, err := buildResource(cfg)
	if err != nil {
		// Don't fail Init for a resource error — fall back to the
		// minimal resource so spans still flow. Logging here would
		// import slog and create a circular dependency surface; we
		// surface it by returning the error to the caller, who
		// decides whether to abort startup.
		return noopShutdown, fmt.Errorf("telemetry: build resource: %w", err)
	}

	sampler, err := parseSampler(cfg.Sampler)
	if err != nil {
		return noopShutdown, fmt.Errorf("telemetry: parse sampler: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	otel.SetTracerProvider(tp)

	configHolder.Store(&cfg)

	shutdown := func(shutdownCtx context.Context) error {
		// Drain any in-flight spans, then drop the provider so a
		// subsequent Init call starts from a clean slate (helps tests
		// that re-init within the same process).
		err := tp.Shutdown(shutdownCtx)
		otel.SetTracerProvider(noop.NewTracerProvider())
		configHolder.Store((*Config)(nil))
		return err
	}
	return shutdown, nil
}

// configHolder caches the active Config so StartSpan can consult flags
// like IncludeActor without threading the Config through every call
// site. Stored as *Config so a nil pointer means "telemetry off /
// defaults".
var configHolder atomic.Value // *Config

// buildExporter constructs the SDK SpanExporter for the configured
// exporter kind. For OTLP gRPC we pass WithDialOption(grpc.WithBlock())
// off — the local collector may not be up at process start and we
// don't want to delay the CLI by waiting on it. Spans queue in the
// batcher and flush on shutdown.
func buildExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	switch cfg.Exporter {
	case ExporterOTLPGRPC:
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.resolveEndpoint()),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		return otlptrace.New(ctx, otlptracegrpc.NewClient(opts...))
	case ExporterOTLPHTTP:
		endpoint := cfg.resolveEndpoint()
		opts := []otlptracehttp.Option{}
		// OTLP HTTP wants the bare host:port; strip the scheme that
		// operators tend to include in the env var.
		host, insecure := stripHTTPScheme(endpoint)
		opts = append(opts, otlptracehttp.WithEndpoint(host))
		if insecure || cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		return otlptrace.New(ctx, otlptracehttp.NewClient(opts...))
	case ExporterStdout:
		return stdouttrace.New(stdouttrace.WithWriter(stdoutTarget()))
	default:
		return nil, fmt.Errorf("unknown exporter %q (want %s, %s, %s, or empty)",
			cfg.Exporter, ExporterOTLPGRPC, ExporterOTLPHTTP, ExporterStdout)
	}
}

// stripHTTPScheme normalises endpoints like "http://collector:4318" to
// "collector:4318" + an insecure hint so otlptracehttp accepts them.
func stripHTTPScheme(endpoint string) (string, bool) {
	if strings.HasPrefix(endpoint, "https://") {
		return strings.TrimPrefix(endpoint, "https://"), false
	}
	if strings.HasPrefix(endpoint, "http://") {
		return strings.TrimPrefix(endpoint, "http://"), true
	}
	return endpoint, false
}

// buildResource constructs the OTel Resource describing this process.
// service.name and service.version come from cfg; statebound.commit
// and statebound.go_version are populated from build info.
//
// We deliberately use NewSchemaless and skip resource.Default() to
// avoid a Schema URL conflict between our pinned semconv version and
// whatever the SDK ships internally. Operators who want richer
// resource attributes can layer them in via OTEL_RESOURCE_ATTRIBUTES,
// which the SDK reads regardless of how we constructed the base.
func buildResource(cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
		attribute.String("statebound.go_version", runtime.Version()),
	}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}
	if commit := buildCommit(); commit != "" {
		attrs = append(attrs, attribute.String("statebound.commit", commit))
	}
	return resource.NewSchemaless(attrs...), nil
}

// buildCommit returns the VCS revision recorded in debug.BuildInfo, or
// empty when the binary was built with -buildvcs=false (which is how
// scripts/go.sh runs). The fallback is acceptable: cli.Commit-style
// ldflags injection happens at the caller in cmd/statebound/main.go.
func buildCommit() string {
	// We deliberately do not import cli.Commit here to avoid an
	// import cycle (cli imports telemetry). The cmd binary passes
	// the commit through Config.ServiceVersion if it wants it on the
	// resource; this helper only adds value when buildinfo is
	// available, which is rarely true under our docker-go shim.
	return ""
}

// parseSampler maps a sampler string onto an sdktrace.Sampler.
//
//	""           parent-based always-on (the recommended default)
//	"always"     always sample
//	"never"      never sample
//	"ratio:0.X"  parent-based trace-id-ratio sampler at 0.X
func parseSampler(s string) (sdktrace.Sampler, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "":
		return sdktrace.ParentBased(sdktrace.AlwaysSample()), nil
	case "always":
		return sdktrace.AlwaysSample(), nil
	case "never":
		return sdktrace.NeverSample(), nil
	}
	if strings.HasPrefix(v, "ratio:") {
		raw := strings.TrimPrefix(v, "ratio:")
		ratio, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("ratio %q: %w", raw, err)
		}
		if ratio < 0 || ratio > 1 {
			return nil, fmt.Errorf("ratio %v: must be in [0,1]", ratio)
		}
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio)), nil
	}
	return nil, fmt.Errorf("unknown sampler %q (want '', always, never, ratio:N)", s)
}

// Tracer returns the package tracer. Always safe to call: when
// telemetry is off, the returned Tracer creates no-op spans and the
// per-call cost is one method dispatch.
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// StartSpan is the convenience wrapper used by every CLI hot path. It
// returns a (ctx, span) pair so the caller can attach further
// attributes, record errors, and End() the span on return. When OTel
// is off, the span is a no-op span — ctx.Done()-style logic continues
// to work because the underlying context is unchanged.
//
// Usage:
//
//	ctx, span := telemetry.StartSpan(ctx, "plan.generate",
//	    telemetry.AttrConnector.String(name),
//	)
//	defer span.End()
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if len(attrs) == 0 {
		return Tracer().Start(ctx, name)
	}
	return Tracer().Start(ctx, name, trace.WithAttributes(attrs...))
}

// stdoutTarget returns the writer the stdouttrace exporter should
// write to. Tests register a writer via SetStdoutWriter; in production
// we fall back to os.Stdout. Spans go to stdout (not stderr) on
// purpose — they are structured data and operators usually pipe them
// into a JSON parser, while stderr carries human progress lines.
func stdoutTarget() io.Writer {
	if h, ok := stdoutWriter.Load().(stdoutWriterHolder); ok && h.w != nil {
		return h.w
	}
	return os.Stdout
}

// IncludeActor reports whether the operator opted in to actor
// attributes via STATEBOUND_OTEL_INCLUDE_ACTOR=true. Call sites that
// would otherwise emit AttrActorKind/AttrActorSubject MUST gate on this
// helper so PII never reaches the collector by default.
func IncludeActor() bool {
	v, _ := configHolder.Load().(*Config)
	if v == nil {
		return false
	}
	return v.IncludeActor
}
