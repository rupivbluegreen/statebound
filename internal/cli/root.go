// Package cli wires the Cobra command tree for the statebound binary.
//
// Each subcommand lives in its own file and registers itself with the
// root via an add<Name>Cmd(parent) function called from init() below.
// This keeps the file boundary clean and avoids a single megafile.
package cli

import (
	"os"

	"github.com/spf13/cobra"
)

const (
	defaultDBDSN = "postgres://statebound:statebound@localhost:5432/statebound?sslmode=disable"
	envDBDSN     = "STATEBOUND_DB_DSN"
)

// Persistent flag values. Cobra writes into these when flags are parsed.
// They are package-private; subcommands read them via the helpers below.
var (
	flagConfig   string
	flagLogLevel string
	flagDBDSN    string
)

var rootCmd = &cobra.Command{
	Use:   "statebound",
	Short: "Authorization governance control plane",
	Long: "Statebound is a terminal-native, open-source desired-state " +
		"authorization governance platform for regulated infrastructure " +
		"and applications. It replaces spreadsheet-based authorization " +
		"matrices with versioned, approvable, reconcilable, " +
		"evidence-producing authorization models.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root Cobra command. main() calls this and reports any
// error via slog before exiting non-zero.
func Execute() error {
	return rootCmd.Execute()
}

// dbDSN returns the configured database DSN, preferring the --db-dsn flag,
// then the STATEBOUND_DB_DSN environment variable, then the built-in default.
func dbDSN() string {
	if flagDBDSN != "" {
		return flagDBDSN
	}
	if v := os.Getenv(envDBDSN); v != "" {
		return v
	}
	return defaultDBDSN
}

func init() {
	defaultDSN := os.Getenv(envDBDSN)
	if defaultDSN == "" {
		defaultDSN = defaultDBDSN
	}

	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "",
		"path to optional YAML config file")
	rootCmd.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info",
		"log level: debug, info, warn, error")
	rootCmd.PersistentFlags().StringVar(&flagDBDSN, "db-dsn", defaultDSN,
		"PostgreSQL DSN; falls back to "+envDBDSN+" env var")

	addVersionCmd(rootCmd)
	addTUICmd(rootCmd)
	addInitCmd(rootCmd)
	addProductCmd(rootCmd)
	addModelCmd(rootCmd)
	addValidateCmd(rootCmd)
	addApprovalCmd(rootCmd)
	addDiffCmd(rootCmd)
	addAuditCmd(rootCmd)
	addPolicyCmd(rootCmd)
	addEvidenceCmd(rootCmd)
	addPlanCmd(rootCmd)
	addDriftCmd(rootCmd)
	addApplyCmd(rootCmd)
	addConnectorCmd(rootCmd)
	addAgentCmd(rootCmd)
	addInferenceCmd(rootCmd)
	addRoleCmd(rootCmd)
	addKeyCmd(rootCmd)
}
