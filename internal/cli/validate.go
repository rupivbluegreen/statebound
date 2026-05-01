package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"statebound.dev/statebound/internal/model"
)

func addValidateCmd(parent *cobra.Command) {
	var file string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a desired-state YAML model file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read %s: %w", file, err)
			}
			var doc model.ProductAuthorizationModel
			if err := yaml.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("parse %s: %w", file, err)
			}
			findings := model.Validate(&doc)
			if len(findings) == 0 {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "OK: 0 findings")
				return err
			}
			printValidationFindings(cmd.ErrOrStderr(), findings)
			return fmt.Errorf("validation failed: %d findings", len(findings))
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "path to YAML model file")
	_ = cmd.MarkFlagRequired("file")
	parent.AddCommand(cmd)
}
