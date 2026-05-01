package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func addValidateCmd(parent *cobra.Command) {
	var file string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a desired-state YAML model file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"validate is wired in Phase 1 (would validate %q)\n", file)
			return err
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "path to YAML model file")
	_ = cmd.MarkFlagRequired("file")
	parent.AddCommand(cmd)
}
