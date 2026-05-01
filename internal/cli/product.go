package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

const phase0NotImplemented = "not yet implemented in Phase 0 — Phase 1 wires this to storage"

func addProductCmd(parent *cobra.Command) {
	productCmd := &cobra.Command{
		Use:   "product",
		Short: "Manage Products (top-level governed applications/services)",
	}

	createCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new Product",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"%s (would create product %q)\n", phase0NotImplemented, args[0])
			return err
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List Products",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), phase0NotImplemented)
			return err
		},
	}

	productCmd.AddCommand(createCmd, listCmd)
	parent.AddCommand(productCmd)
}
