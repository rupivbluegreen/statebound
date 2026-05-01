package cli

import (
	"github.com/spf13/cobra"
)

func addInferenceCmd(parent *cobra.Command) {
	inferenceCmd := &cobra.Command{
		Use:   "inference",
		Short: "Manage inference backends (provided by statebound-reason add-on)",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List registered inference backends",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printAddonStub(cmd.OutOrStdout())
		},
	}

	registerCmd := &cobra.Command{
		Use:   "register",
		Short: "Register an inference backend from a YAML file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printAddonStub(cmd.OutOrStdout())
		},
	}
	registerCmd.Flags().StringP("file", "f", "", "path to ModelBackend YAML")

	inferenceCmd.AddCommand(listCmd, registerCmd)
	parent.AddCommand(inferenceCmd)
}
