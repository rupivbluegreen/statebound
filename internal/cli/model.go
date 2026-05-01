package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func addModelCmd(parent *cobra.Command) {
	modelCmd := &cobra.Command{
		Use:   "model",
		Short: "Import and export authorization models (YAML)",
	}

	var importFile string
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import a desired-state YAML model file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"%s (would import %q)\n", phase0NotImplemented, importFile)
			return err
		},
	}
	importCmd.Flags().StringVarP(&importFile, "file", "f", "",
		"path to YAML model file")
	_ = importCmd.MarkFlagRequired("file")

	var exportProduct string
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export the desired-state YAML model for a product",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"%s (would export product %q)\n", phase0NotImplemented, exportProduct)
			return err
		},
	}
	exportCmd.Flags().StringVar(&exportProduct, "product", "",
		"product name to export")
	_ = exportCmd.MarkFlagRequired("product")

	modelCmd.AddCommand(importCmd, exportCmd)
	parent.AddCommand(modelCmd)
}
