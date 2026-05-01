// Package main is the entry point for the statebound binary.
//
// It wires up structured logging, then delegates to the Cobra-rooted
// CLI in internal/cli. All argument parsing, subcommand routing, and
// flag handling lives there; main() stays intentionally tiny.
package main

import (
	"log/slog"
	"os"

	"statebound.dev/statebound/internal/cli"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := cli.Execute(); err != nil {
		slog.Error("statebound exited with error", "err", err)
		os.Exit(1)
	}
}
