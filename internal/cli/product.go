package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

func addProductCmd(parent *cobra.Command) {
	productCmd := &cobra.Command{
		Use:   "product",
		Short: "Manage Products (top-level governed applications/services)",
	}
	productCmd.AddCommand(newProductCreateCmd(), newProductListCmd())
	parent.AddCommand(productCmd)
}

func newProductCreateCmd() *cobra.Command {
	var (
		owner       string
		description string
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new Product",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			product, err := domain.NewProduct(name, owner, description)
			if err != nil {
				return fmt.Errorf("invalid product: %w", err)
			}

			err = store.WithTx(cmd.Context(), func(tx storage.Storage) error {
				if err := tx.CreateProduct(cmd.Context(), product); err != nil {
					return fmt.Errorf("create product: %w", err)
				}
				evt, err := domain.NewAuditEvent(domain.EventProductCreated, actor, "product", string(product.ID), map[string]any{
					"name":  product.Name,
					"owner": product.Owner,
				})
				if err != nil {
					return fmt.Errorf("build audit event: %w", err)
				}
				if err := tx.AppendAuditEvent(cmd.Context(), evt); err != nil {
					return fmt.Errorf("append audit event: %w", err)
				}
				return nil
			})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "created product %s (id %s)\n", product.Name, product.ID)
			return err
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "", "owner team or person (required)")
	cmd.Flags().StringVar(&description, "description", "", "free-form description")
	_ = cmd.MarkFlagRequired("owner")
	return cmd
}

func newProductListCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Products",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			products, err := store.ListProducts(cmd.Context())
			if err != nil {
				return fmt.Errorf("list products: %w", err)
			}
			return renderProducts(cmd, products, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "output format: table, json, or yaml")
	return cmd
}

// productView is a serializable projection of a Product. Hand-rolled so
// json/yaml output stays stable when the domain type grows.
type productView struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Owner       string `json:"owner" yaml:"owner"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	CreatedAt   string `json:"createdAt" yaml:"createdAt"`
	UpdatedAt   string `json:"updatedAt" yaml:"updatedAt"`
}

func toProductViews(products []*domain.Product) []productView {
	out := make([]productView, 0, len(products))
	for _, p := range products {
		out = append(out, productView{
			ID:          string(p.ID),
			Name:        p.Name,
			Owner:       p.Owner,
			Description: p.Description,
			CreatedAt:   p.CreatedAt.UTC().Format(time.RFC3339),
			UpdatedAt:   p.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	return out
}

func renderProducts(cmd *cobra.Command, products []*domain.Product, format string) error {
	switch format {
	case "", "table":
		return renderProductsTable(cmd, products)
	case "json":
		b, err := json.MarshalIndent(toProductViews(products), "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	case "yaml":
		b, err := yaml.Marshal(toProductViews(products))
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(cmd.OutOrStdout(), string(b))
		return err
	default:
		return fmt.Errorf("unknown format %q (want table, json, or yaml)", format)
	}
}

func renderProductsTable(cmd *cobra.Command, products []*domain.Product) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "NAME\tOWNER\tCREATED"); err != nil {
		return err
	}
	for _, p := range products {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.Owner, p.CreatedAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return w.Flush()
}
