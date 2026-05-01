package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Version metadata. Overridden at build time via:
//
//	-ldflags "-X statebound.dev/statebound/internal/cli.Version=..."
//	-ldflags "-X statebound.dev/statebound/internal/cli.Commit=..."
//	-ldflags "-X statebound.dev/statebound/internal/cli.BuildDate=..."
var (
	Version   = "0.0.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// versionString returns the canonical one-line version banner. Exposed so
// other call sites (e.g. a future --version on root) can reuse it.
func versionString() string {
	return fmt.Sprintf("statebound %s (commit %s, built %s, go %s)",
		Version, Commit, BuildDate, runtime.Version())
}

func addVersionCmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the statebound version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), versionString())
			return err
		},
	}
	parent.AddCommand(cmd)
}
