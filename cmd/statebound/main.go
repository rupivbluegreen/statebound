// Package main is the entry point for the statebound binary.
//
// It wires up structured logging and OpenTelemetry tracing, then
// delegates to the Cobra-rooted CLI in internal/cli. All argument
// parsing, subcommand routing, and flag handling lives there;
// main() stays intentionally tiny.
//
// Telemetry is OFF by default. Set STATEBOUND_OTEL_EXPORTER to
// "otlp-grpc", "otlp-http", or "stdout" to enable trace export.
// See docs/observability.md for the complete env-var matrix.
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"statebound.dev/statebound/internal/cli"
	"statebound.dev/statebound/internal/telemetry"
)

func main() {
	os.Exit(run())
}

// run is split out from main so we can use deferred cleanup (which
// os.Exit would skip). The exit code is returned to main, which is
// the only function allowed to call os.Exit. Without this split,
// queued OTel spans would never reach the exporter on error paths.
func run() int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Detect telemetry config from env vars and initialise the global
	// tracer provider. When no STATEBOUND_OTEL_* vars are set, this
	// installs a no-op provider so the per-span overhead in the CLI
	// hot paths is one nil-method call. Init failures are logged but
	// do not abort the run — observability should never break the
	// control plane.
	cfg := telemetry.Detect()
	cfg.ServiceVersion = cli.Version
	shutdown, err := telemetry.Init(context.Background(), cfg)
	if err != nil {
		slog.Warn("telemetry init failed; continuing without tracing", "err", err)
	}
	defer func() {
		// Give the exporter a bounded window to flush queued spans.
		// Operators on flaky networks would rather miss the last few
		// spans than wait 30s for an unreachable collector.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(shutdownCtx); err != nil {
			slog.Warn("telemetry shutdown reported error", "err", err)
		}
	}()

	if err := cli.Execute(); err != nil {
		slog.Error("statebound exited with error", "err", err)
		return 1
	}
	return 0
}
