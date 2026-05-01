package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
	"statebound.dev/statebound/internal/storage"
)

// addDiffCmd registers `statebound diff`. The command is read-only: it never
// opens a transaction, never mutates state, and never emits audit events. It
// is meant to live in the GitOps loop alongside `model import`.
func addDiffCmd(parent *cobra.Command) {
	var (
		productName string
		file        string
		format      string
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show the diff between a YAML model and a product's latest approved version",
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
			if findings := model.Validate(&doc); len(findings) > 0 {
				printValidationFindings(cmd.ErrOrStderr(), findings)
				return fmt.Errorf("validation failed: %d findings", len(findings))
			}

			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			before, parentSeq, err := loadCurrentApprovedModel(cmd.Context(), store, productName)
			if err != nil {
				return err
			}
			diff, err := model.ComputeDiff(before, &doc)
			if err != nil {
				return fmt.Errorf("compute diff: %w", err)
			}
			return renderDiff(cmd.OutOrStdout(), productName, &doc, diff, parentSeq, format)
		},
	}
	cmd.Flags().StringVar(&productName, "product", "", "product name to compare against (required)")
	cmd.Flags().StringVarP(&file, "file", "f", "", "path to YAML model file (required)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	_ = cmd.MarkFlagRequired("product")
	_ = cmd.MarkFlagRequired("file")
	parent.AddCommand(cmd)
}

// loadCurrentApprovedModel returns (model, sequence, err) for the product's
// latest approved version, or (nil, 0, nil) when there is no prior version
// (which the renderer surfaces as "no prior version").
func loadCurrentApprovedModel(ctx context.Context, store storage.Storage, productName string) (*model.ProductAuthorizationModel, int64, error) {
	product, err := store.GetProductByName(ctx, productName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("lookup product %q: %w", productName, err)
	}
	av, snap, err := store.GetLatestApprovedVersion(ctx, product.ID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("get latest approved version: %w", err)
	}
	m, err := model.FromSnapshot(snap.Content)
	if err != nil {
		return nil, 0, fmt.Errorf("decode snapshot: %w", err)
	}
	return m, av.Sequence, nil
}

// renderDiff prints the diff in either human-readable text or JSON.
func renderDiff(w io.Writer, productName string, after *model.ProductAuthorizationModel, diff *model.Diff, parentSeq int64, format string) error {
	switch format {
	case "", "text":
		return renderDiffText(w, productName, after, diff, parentSeq)
	case "json":
		// Ship a stable struct so the JSON shape doesn't drift if the diff
		// engine adds private fields later.
		view := struct {
			Product       string         `json:"product"`
			ParentVersion int64          `json:"parentVersion"`
			HasParent     bool           `json:"hasParent"`
			Items         []diffItemView `json:"items"`
			Summary       diffSummary    `json:"summary"`
		}{
			Product:       productName,
			ParentVersion: parentSeq,
			HasParent:     parentSeq > 0,
			Items:         toDiffItemViews(diff),
			Summary:       summarize(diff),
		}
		b, err := json.MarshalIndent(view, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	default:
		return fmt.Errorf("unknown format %q (want text or json)", format)
	}
}

type diffItemView struct {
	Kind         string         `json:"kind"`
	Action       string         `json:"action"`
	ResourceName string         `json:"resourceName"`
	Before       map[string]any `json:"before,omitempty"`
	After        map[string]any `json:"after,omitempty"`
}

type diffSummary struct {
	Adds    int `json:"adds"`
	Updates int `json:"updates"`
	Deletes int `json:"deletes"`
}

func toDiffItemViews(d *model.Diff) []diffItemView {
	if d == nil {
		return []diffItemView{}
	}
	out := make([]diffItemView, 0, len(d.Items))
	for _, it := range d.Items {
		out = append(out, diffItemView{
			Kind:         string(it.Kind),
			Action:       string(it.Action),
			ResourceName: it.ResourceName,
			Before:       it.Before,
			After:        it.After,
		})
	}
	return out
}

func summarize(d *model.Diff) diffSummary {
	var s diffSummary
	if d == nil {
		return s
	}
	for _, it := range d.Items {
		switch it.Action {
		case domain.ChangeSetActionAdd:
			s.Adds++
		case domain.ChangeSetActionUpdate:
			s.Updates++
		case domain.ChangeSetActionDelete:
			s.Deletes++
		}
	}
	return s
}

// renderDiffText prints the human-readable diff. We intentionally avoid ANSI
// escape codes when the output is not a terminal — the Phase 2 wave A scope
// keeps colors out so the output stays diffable in CI logs.
func renderDiffText(w io.Writer, productName string, after *model.ProductAuthorizationModel, diff *model.Diff, parentSeq int64) error {
	header := fmt.Sprintf("Diff for %s: %s", productName, after.Metadata.Product)
	if parentSeq > 0 {
		header += fmt.Sprintf(" against version v%d", parentSeq)
	} else {
		header += " (no prior version)"
	}
	if _, err := fmt.Fprintln(w, header); err != nil {
		return err
	}

	if diff == nil || diff.IsEmpty() {
		_, err := fmt.Fprintln(w, "no changes")
		return err
	}

	for _, it := range diff.Items {
		if err := writeDiffItem(w, it); err != nil {
			return err
		}
	}

	s := summarize(diff)
	_, err := fmt.Fprintf(w, "\n%d add(s), %d update(s), %d delete(s)\n", s.Adds, s.Updates, s.Deletes)
	return err
}

// writeDiffItem prints one diff entry. Adds use '+', deletes '-', updates '~'.
// Update payloads are followed by indented YAML for both sides so reviewers
// can see what changed.
func writeDiffItem(w io.Writer, it *model.DiffItem) error {
	var marker string
	switch it.Action {
	case domain.ChangeSetActionAdd:
		marker = "+"
	case domain.ChangeSetActionDelete:
		marker = "-"
	case domain.ChangeSetActionUpdate:
		marker = "~"
	default:
		marker = "?"
	}
	if _, err := fmt.Fprintf(w, "%s %s %s\n", marker, it.Kind, it.ResourceName); err != nil {
		return err
	}
	if it.Action == domain.ChangeSetActionUpdate {
		fmt.Fprintln(w, "    before:")
		if err := writeIndentedYAML(w, it.Before, "      "); err != nil {
			return err
		}
		fmt.Fprintln(w, "    after:")
		if err := writeIndentedYAML(w, it.After, "      "); err != nil {
			return err
		}
	}
	return nil
}
