package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"statebound.dev/statebound/internal/model"
)

func addModelCmd(parent *cobra.Command) {
	modelCmd := &cobra.Command{
		Use:   "model",
		Short: "Import and export authorization models (YAML)",
	}
	modelCmd.AddCommand(newModelImportCmd(), newModelExportCmd())
	parent.AddCommand(modelCmd)
}

func newModelImportCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import a desired-state YAML model file",
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

			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			result, err := model.Import(cmd.Context(), store, &doc, actor)
			if err != nil {
				var vfe *model.ValidationFailedError
				if errors.As(err, &vfe) {
					printValidationFindings(cmd.ErrOrStderr(), vfe.Findings)
					return fmt.Errorf("validation failed: %d findings", len(vfe.Findings))
				}
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"imported product %s: %d assets, %d scopes, %d entitlements, %d service accounts, %d global objects, %d authorizations\n",
				result.Product,
				len(doc.Spec.Assets),
				len(doc.Spec.AssetScopes),
				len(doc.Spec.Entitlements),
				len(doc.Spec.ServiceAccounts),
				len(doc.Spec.GlobalObjects),
				result.AuthorizationsTotal,
			)
			return err
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "path to YAML model file")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func newModelExportCmd() *cobra.Command {
	var (
		productName string
		format      string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the desired-state YAML model for a product",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			doc, err := model.Export(cmd.Context(), store, productName)
			if err != nil {
				return err
			}
			return writeModel(cmd.OutOrStdout(), doc, format)
		},
	}
	cmd.Flags().StringVar(&productName, "product", "", "product name to export")
	cmd.Flags().StringVar(&format, "format", "yaml", "output format: yaml or json")
	_ = cmd.MarkFlagRequired("product")
	return cmd
}

func writeModel(w io.Writer, doc *model.ProductAuthorizationModel, format string) error {
	switch format {
	case "", "yaml":
		b, err := yaml.Marshal(doc)
		if err != nil {
			return fmt.Errorf("marshal yaml: %w", err)
		}
		_, err = w.Write(b)
		return err
	case "json":
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		_, err = io.WriteString(w, "\n")
		return err
	default:
		return fmt.Errorf("unknown format %q (want yaml or json)", format)
	}
}

// printValidationFindings emits one line per ValidationError to the given
// writer in the format "<path>: <message>".
func printValidationFindings(w io.Writer, findings []model.ValidationError) {
	for _, f := range findings {
		_, _ = fmt.Fprintf(w, "%s: %s\n", f.Path, f.Message)
	}
}

