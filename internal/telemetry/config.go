// Package telemetry wires OpenTelemetry tracing into the statebound CLI.
//
// Telemetry is OFF by default: when no STATEBOUND_OTEL_* env var is set,
// Detect returns a zero-value Config and Init installs a no-op tracer
// provider so the cost per span is one nil-function call. Operators
// turn telemetry on via STATEBOUND_OTEL_EXPORTER plus optional endpoint
// and sampling controls; see docs/observability.md.
//
// Wave A (v0.7) ships traces only. Metrics (Prometheus exporter, RED
// counters, host-process metrics) arrive in wave C alongside otel-pgx
// for storage-layer instrumentation.
package telemetry

import (
	"os"
	"strings"
)

// Default values applied when the env var is unset or empty. The
// service name matches the binary name and is overridable so the same
// build can register itself under different names in fleet
// deployments.
const (
	defaultServiceName    = "statebound"
	defaultGRPCEndpoint   = "localhost:4317"
	defaultHTTPEndpoint   = "http://localhost:4318"
	defaultGRPCInsecure   = true
	defaultIncludeActor   = false
)

// Exporter kinds recognised by Detect/Init. Any other value short-circuits
// Init to a no-op provider so a typo never silently disables tracing in
// production — Init returns an error the caller can surface.
const (
	ExporterOff      = ""
	ExporterOTLPGRPC = "otlp-grpc"
	ExporterOTLPHTTP = "otlp-http"
	ExporterStdout   = "stdout"
)

// Environment variables consulted by Detect. Kept as exported constants
// so docs and tests reference one source of truth.
const (
	EnvExporter      = "STATEBOUND_OTEL_EXPORTER"
	EnvEndpoint      = "STATEBOUND_OTEL_ENDPOINT"
	EnvServiceName   = "STATEBOUND_OTEL_SERVICE_NAME"
	EnvInsecure      = "STATEBOUND_OTEL_INSECURE"
	EnvSampler       = "STATEBOUND_OTEL_SAMPLER"
	EnvIncludeActor  = "STATEBOUND_OTEL_INCLUDE_ACTOR"
)

// Config controls telemetry initialisation. Build it from env vars via
// Detect, or construct one directly in tests. A zero Config (Exporter
// == ExporterOff) means "telemetry disabled" and Init will install a
// no-op provider.
type Config struct {
	// Exporter selects the SDK exporter. ExporterOff disables tracing.
	// Recognised values: "otlp-grpc", "otlp-http", "stdout", or "" (off).
	Exporter string

	// Endpoint is the exporter's collector endpoint. Ignored for
	// "stdout"; defaults to "localhost:4317" (gRPC) or
	// "http://localhost:4318" (HTTP) when empty.
	Endpoint string

	// ServiceName is the OTel service.name resource attribute. Defaults
	// to "statebound" when empty.
	ServiceName string

	// ServiceVersion is the OTel service.version resource attribute.
	// Populated by the caller from build metadata (cli.Version).
	ServiceVersion string

	// Insecure, for gRPC, instructs the exporter to skip TLS. Default
	// is true since the local collector pattern is usually plaintext on
	// loopback. Override to false when sending to a TLS-fronted
	// collector. Ignored for HTTP/stdout.
	Insecure bool

	// Sampler picks the trace sampler. Recognised values:
	//   ""           -> parent-based always-on (default)
	//   "always"     -> always sample
	//   "never"      -> never sample
	//   "ratio:0.1"  -> trace ratio sampler at 0.1
	Sampler string

	// IncludeActor opts in to attaching actor identifiers (kind +
	// subject) to span attributes. Off by default — actor subjects can
	// be PII (email addresses, OIDC subs) and should not leak through
	// the OTel collector unless an operator explicitly authorised it.
	IncludeActor bool
}

// Enabled reports whether the config requests an active exporter. A
// false return means Init will install a no-op provider.
func (c Config) Enabled() bool {
	return c.Exporter != ExporterOff
}

// Detect reads STATEBOUND_OTEL_* env vars and returns a Config. When
// no exporter is configured, Detect returns Config{} (Enabled() ==
// false) so callers can skip Init or call Init unconditionally.
func Detect() Config {
	cfg := Config{
		Exporter:     strings.ToLower(strings.TrimSpace(os.Getenv(EnvExporter))),
		Endpoint:     strings.TrimSpace(os.Getenv(EnvEndpoint)),
		ServiceName:  strings.TrimSpace(os.Getenv(EnvServiceName)),
		Sampler:      strings.TrimSpace(os.Getenv(EnvSampler)),
		Insecure:     defaultGRPCInsecure,
		IncludeActor: defaultIncludeActor,
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = defaultServiceName
	}
	if v := strings.TrimSpace(os.Getenv(EnvInsecure)); v != "" {
		cfg.Insecure = parseBool(v, defaultGRPCInsecure)
	}
	if v := strings.TrimSpace(os.Getenv(EnvIncludeActor)); v != "" {
		cfg.IncludeActor = parseBool(v, defaultIncludeActor)
	}
	return cfg
}

// parseBool accepts the common truthy spellings ("1", "true", "yes",
// "on", any case) and returns fallback for anything else. Strict
// parsing here would surprise operators who type "True"; lenient
// parsing matches the standard OTel SDK behaviour.
func parseBool(s string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on", "y", "t":
		return true
	case "0", "false", "no", "off", "n", "f":
		return false
	default:
		return fallback
	}
}

// resolveEndpoint returns the endpoint to use for the configured
// exporter, applying the per-exporter default when the explicit
// endpoint is empty. Returns "" when the exporter does not consume an
// endpoint (stdout, off).
func (c Config) resolveEndpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	switch c.Exporter {
	case ExporterOTLPGRPC:
		return defaultGRPCEndpoint
	case ExporterOTLPHTTP:
		return defaultHTTPEndpoint
	default:
		return ""
	}
}
