package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// addInitCmd registers `statebound init`. In Phase 0 this is a no-op
// placeholder; Phase 2 will use it to scaffold migrations and a first
// product after the storage layer is wired through.
func addInitCmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a Statebound deployment (Phase 2+)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.ErrOrStderr(),
				"init is a no-op until Phase 2")
			return err
		},
	}
	parent.AddCommand(cmd)
}
