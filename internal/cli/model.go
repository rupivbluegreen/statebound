package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"statebound.dev/statebound/internal/authz"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
	"statebound.dev/statebound/internal/storage"
)

// envAutoApprove is the dev-only gate for `model import --auto-approve`.
// Mirrors the constant in internal/model so the CLI can produce a friendly
// pre-flight error before opening storage.
const envAutoApprove = "STATEBOUND_DEV_AUTO_APPROVE"

func addModelCmd(parent *cobra.Command) {
	modelCmd := &cobra.Command{
		Use:   "model",
		Short: "Import and export authorization models (YAML)",
	}
	modelCmd.AddCommand(newModelImportCmd(), newModelExportCmd())
	parent.AddCommand(modelCmd)
}

func newModelImportCmd() *cobra.Command {
	var (
		file        string
		submit      bool
		autoApprove bool
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import a desired-state YAML model file as a draft change set",
		Long: "Reads a ProductAuthorizationModel YAML file, validates it, and " +
			"records a draft ChangeSet. Use --submit to also transition the " +
			"draft to Submitted in the same run; use --auto-approve to walk " +
			"the change set straight to Approved (dev-only, requires " +
			"STATEBOUND_DEV_AUTO_APPROVE=true).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if submit && autoApprove {
				return fmt.Errorf("--submit and --auto-approve are mutually exclusive")
			}
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
			mode := model.ImportModeChangeSet
			if autoApprove {
				if os.Getenv(envAutoApprove) != "true" {
					return fmt.Errorf("auto-approve requires %s=true; set it for development only", envAutoApprove)
				}
				mode = model.ImportModeAutoApprove
			}

			result, err := model.Import(cmd.Context(), store, &doc, actor, mode)
			if err != nil {
				var vfe *model.ValidationFailedError
				if errors.As(err, &vfe) {
					printValidationFindings(cmd.ErrOrStderr(), vfe.Findings)
					return fmt.Errorf("validation failed: %d findings", len(vfe.Findings))
				}
				return err
			}

			out := cmd.OutOrStdout()
			if result.Diff.IsEmpty() {
				_, err := fmt.Fprintf(out, "no changes; %s already matches the imported model\n", doc.Metadata.Product)
				return err
			}

			summary := result.Diff.Summary()
			if mode == model.ImportModeAutoApprove {
				return printAutoApproveResult(cmd.Context(), store, out, &doc, result, summary)
			}

			csID := *result.ChangeSetID
			if _, err := fmt.Fprintf(out, "change set %s drafted: %s; submit with: statebound approval request --change-set %s\n",
				shortID(csID), summary, csID); err != nil {
				return err
			}

			if submit {
				return submitChangeSet(cmd.Context(), store, out, csID, actor)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "path to YAML model file")
	cmd.Flags().BoolVar(&submit, "submit", false, "after drafting, immediately transition the change set to Submitted")
	cmd.Flags().BoolVar(&autoApprove, "auto-approve", false,
		"dev-only: walk the change set straight through to Approved (requires "+envAutoApprove+"=true)")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

// submitChangeSet drives a Draft -> Submitted transition and emits the
// matching audit event. Used by `model import --submit` to chain a draft into
// the approval queue without a second CLI invocation.
func submitChangeSet(ctx context.Context, store storage.Storage, w io.Writer, csID domain.ID, actor domain.Actor) error {
	if err := store.WithTx(ctx, func(tx storage.Storage) error {
		cs, err := tx.GetChangeSetByID(ctx, csID)
		if err != nil {
			return fmt.Errorf("get change set: %w", err)
		}
		result, err := evaluatePolicyGate(ctx, tx, authz.PhaseSubmit, cs, actor)
		if err != nil {
			return err
		}
		if err := enforcePolicy(result); err != nil {
			return err
		}
		now := time.Now().UTC()
		if err := tx.UpdateChangeSetState(ctx, csID, domain.ChangeSetStateSubmitted, &now, ""); err != nil {
			return fmt.Errorf("transition to submitted: %w", err)
		}
		evt, err := domain.NewAuditEvent(domain.EventChangeSetSubmitted, actor, "change_set", string(csID), map[string]any{
			"change_set_id": string(csID),
		})
		if err != nil {
			return fmt.Errorf("build changeset.submitted audit: %w", err)
		}
		if err := tx.AppendAuditEvent(ctx, evt); err != nil {
			return fmt.Errorf("append changeset.submitted audit: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "submitted change set %s\n", shortID(csID))
	return err
}

// printAutoApproveResult formats the human-friendly summary printed when
// `model import --auto-approve` succeeds. We re-read the freshly-minted
// approved version so we can include its sequence in the output.
func printAutoApproveResult(ctx context.Context, store storage.Storage, w io.Writer, doc *model.ProductAuthorizationModel, result *model.ImportResult, summary string) error {
	if result.ApprovedVersionID == nil {
		// Defensive: should not happen on a clean auto-approve.
		_, err := fmt.Fprintf(w, "auto-approved %s: %s\n", doc.Metadata.Product, summary)
		return err
	}
	av, _, err := store.GetApprovedVersionByID(ctx, *result.ApprovedVersionID)
	if err != nil {
		// Don't fail the command just because we can't render a sequence.
		_, werr := fmt.Fprintf(w, "auto-approved %s: %s; version id %s\n",
			doc.Metadata.Product, summary, *result.ApprovedVersionID)
		return werr
	}
	csShort := ""
	if result.ChangeSetID != nil {
		csShort = shortID(*result.ChangeSetID)
	}
	_, err = fmt.Fprintf(w, "auto-approved change set %s: %s; created version %s:v%d\n",
		csShort, summary, doc.Metadata.Product, av.Sequence)
	return err
}

func newModelExportCmd() *cobra.Command {
	var (
		productName string
		format      string
		version     int64
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the desired-state YAML model for a product's latest approved version",
		Long: "Reconstructs the ProductAuthorizationModel from an immutable " +
			"approved-version snapshot. Without --version this exports the " +
			"latest approved version; pass --version <seq> to export a " +
			"specific version. Errors when the product has no approved " +
			"versions.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			product, err := store.GetProductByName(cmd.Context(), productName)
			if err != nil {
				return fmt.Errorf("lookup product %q: %w", productName, err)
			}

			snap, err := loadApprovedSnapshot(cmd.Context(), store, product.ID, version)
			if err != nil {
				return err
			}
			doc, err := model.FromSnapshot(snap.Content)
			if err != nil {
				return fmt.Errorf("decode snapshot: %w", err)
			}
			return writeModel(cmd.OutOrStdout(), doc, format)
		},
	}
	cmd.Flags().StringVar(&productName, "product", "", "product name to export")
	cmd.Flags().StringVar(&format, "format", "yaml", "output format: yaml or json")
	cmd.Flags().Int64Var(&version, "version", 0, "approved-version sequence to export; default = latest")
	_ = cmd.MarkFlagRequired("product")
	return cmd
}

// loadApprovedSnapshot resolves the snapshot for the requested version (or the
// latest, when version == 0). Returns ErrNotFound translated into a friendly
// "no approved version" message.
func loadApprovedSnapshot(ctx context.Context, store storage.Storage, productID domain.ID, version int64) (*domain.ApprovedVersionSnapshot, error) {
	if version == 0 {
		_, snap, err := store.GetLatestApprovedVersion(ctx, productID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, fmt.Errorf("no approved version for product")
			}
			return nil, fmt.Errorf("get latest approved version: %w", err)
		}
		return snap, nil
	}
	versions, err := store.ListApprovedVersions(ctx, productID, 0)
	if err != nil {
		return nil, fmt.Errorf("list approved versions: %w", err)
	}
	for _, v := range versions {
		if v.Sequence == version {
			_, snap, err := store.GetApprovedVersionByID(ctx, v.ID)
			if err != nil {
				return nil, fmt.Errorf("get approved version v%d: %w", version, err)
			}
			return snap, nil
		}
	}
	return nil, fmt.Errorf("approved version v%d not found", version)
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

// shortID returns the first 8 characters of a domain ID. The Phase 2 CLI
// surfaces short IDs in tables and human messages; the full UUID stays in
// JSON/YAML output and audit events.
func shortID(id domain.ID) string {
	s := string(id)
	if len(s) >= 8 {
		return s[:8]
	}
	return s
}
