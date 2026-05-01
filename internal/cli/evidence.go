// Package cli — evidence subcommand. Phase 3 surfaces the deterministic
// evidence engine to operators via three subcommands:
//
//   - export: build a PackContent for a product's approved version, persist
//     the bytes through the EvidencePackStore, emit evidence.created and
//     evidence.exported audit events, and write the bytes to a sink.
//   - list:   list previously exported packs for a product (newest first).
//   - show:   read a pack by id and write its bytes (with optional
//     markdown unwrap) to a sink.
//
// `evidence export --format` chooses the pack content format (json or
// markdown). `evidence list --format` chooses the OUTPUT rendering format
// for the list view (text or json) — they are intentionally separate.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/evidence"
	"statebound.dev/statebound/internal/storage"
)

// addEvidenceCmd registers `statebound evidence` and its subcommands on the
// supplied parent (root command).
func addEvidenceCmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Export, list, and inspect evidence packs",
	}
	cmd.AddCommand(newEvidenceExportCmd(), newEvidenceListCmd(), newEvidenceShowCmd())
	parent.AddCommand(cmd)
}

// ----- export -----

func newEvidenceExportCmd() *cobra.Command {
	var (
		productName string
		versionStr  string
		format      string
		output      string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export an evidence pack for a product's approved version",
		Long: "Builds a deterministic PackContent for the latest (or named) " +
			"approved version of a product, persists it through the " +
			"EvidencePackStore (idempotent on (av,format,content_hash)), " +
			"and emits evidence.created and evidence.exported audit events. " +
			"The bytes are written to --output (- for stdout, default).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			normalizedFormat, err := normalizeEvidenceFormat(format)
			if err != nil {
				return err
			}
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			return runEvidenceExport(cmd.Context(), store, cmd.OutOrStdout(), cmd.ErrOrStderr(), evidenceExportArgs{
				productName: productName,
				versionStr:  versionStr,
				format:      normalizedFormat,
				output:      output,
				actor:       actor,
			})
		},
	}
	cmd.Flags().StringVar(&productName, "product", "", "product name (required)")
	cmd.Flags().StringVar(&versionStr, "version", "latest",
		"approved-version sequence to export, or 'latest' (default)")
	cmd.Flags().StringVar(&format, "format", domain.EvidencePackFormatJSON,
		"pack format: json or markdown")
	cmd.Flags().StringVarP(&output, "output", "o", "-",
		"write bytes to this path; '-' for stdout (default)")
	_ = cmd.MarkFlagRequired("product")
	return cmd
}

// evidenceExportArgs bundles the parsed flags for runEvidenceExport so the
// signature stays narrow as the subcommand grows.
type evidenceExportArgs struct {
	productName string
	versionStr  string
	format      string
	output      string
	actor       domain.Actor
}

// runEvidenceExport is the testable handler body. It resolves the product,
// the requested approved version, builds the pack, persists it inside
// WithTx, emits both audit events, then writes the bytes to the sink.
func runEvidenceExport(ctx context.Context, store storage.Storage, stdout, stderr io.Writer, args evidenceExportArgs) error {
	product, err := store.GetProductByName(ctx, args.productName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("product %q not found", args.productName)
		}
		return fmt.Errorf("lookup product %q: %w", args.productName, err)
	}

	av, err := resolveApprovedVersion(ctx, store, product.ID, args.productName, args.versionStr)
	if err != nil {
		return err
	}

	// Pin the builder clock to the approved version's CreatedAt so two
	// consecutive exports for the same (product, version, format) produce
	// byte-identical bytes. The pack is meant to be a deterministic
	// point-in-time view of the AV; using time.Now would shift the
	// generated_at field on every export and defeat the reproducibility
	// promise verified by `diff -q` in CI.
	avCreatedAt := av.CreatedAt.UTC()
	builder := evidence.NewBuilder(store).WithClock(func() time.Time { return avCreatedAt })
	content, err := builder.BuildByVersionID(ctx, av.ID)
	if err != nil {
		return fmt.Errorf("build evidence pack: %w", err)
	}

	contentBytes, err := encodeEvidenceBytes(content, args.format)
	if err != nil {
		return err
	}

	pack, err := domain.NewEvidencePack(product.ID, av.ID, av.Sequence, args.format, contentBytes, args.actor)
	if err != nil {
		return fmt.Errorf("build evidence pack record: %w", err)
	}

	sink := evidenceSinkLabel(args.output)

	if err := store.WithTx(ctx, func(tx storage.Storage) error {
		if err := tx.AppendEvidencePack(ctx, pack); err != nil {
			return fmt.Errorf("append evidence pack: %w", err)
		}
		createdEvt, err := domain.NewAuditEvent(
			domain.EventEvidenceCreated,
			args.actor,
			"evidence_pack",
			string(pack.ID),
			map[string]any{
				"evidence_pack_id":    string(pack.ID),
				"approved_version_id": string(pack.ApprovedVersionID),
				"format":              pack.Format,
				"content_hash":        pack.ContentHash,
			},
		)
		if err != nil {
			return fmt.Errorf("build evidence.created audit: %w", err)
		}
		if err := tx.AppendAuditEvent(ctx, createdEvt); err != nil {
			return fmt.Errorf("append evidence.created audit: %w", err)
		}
		exportedEvt, err := domain.NewAuditEvent(
			domain.EventEvidenceExported,
			args.actor,
			"evidence_pack",
			string(pack.ID),
			map[string]any{
				"evidence_pack_id": string(pack.ID),
				"format":           pack.Format,
				"sink":             sink,
			},
		)
		if err != nil {
			return fmt.Errorf("build evidence.exported audit: %w", err)
		}
		if err := tx.AppendAuditEvent(ctx, exportedEvt); err != nil {
			return fmt.Errorf("append evidence.exported audit: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	// Bytes go to the sink; the human summary goes to stderr so a stdout
	// redirect captures only the pack bytes.
	if err := writeEvidenceBytes(stdout, args.output, contentBytes); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr,
		"evidence pack %s (%s, sha256:%s) for %s:v%d\n",
		shortID(pack.ID), pack.Format, shortHash(pack.ContentHash),
		product.Name, pack.Sequence,
	)
	return err
}

// resolveApprovedVersion returns the approved-version row for the product
// matching versionStr ('latest' or a positive integer sequence).
func resolveApprovedVersion(ctx context.Context, store storage.Storage, productID domain.ID, productName, versionStr string) (*domain.ApprovedVersion, error) {
	v := strings.TrimSpace(versionStr)
	if v == "" || strings.EqualFold(v, "latest") {
		av, _, err := store.GetLatestApprovedVersion(ctx, productID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, fmt.Errorf("product %s has no approved versions yet", productName)
			}
			return nil, fmt.Errorf("get latest approved version: %w", err)
		}
		return av, nil
	}
	seq, err := parsePositiveInt64(v)
	if err != nil {
		return nil, fmt.Errorf("--version %q: %w", versionStr, err)
	}
	versions, err := store.ListApprovedVersions(ctx, productID, 0)
	if err != nil {
		return nil, fmt.Errorf("list approved versions: %w", err)
	}
	for _, vv := range versions {
		if vv.Sequence == seq {
			return vv, nil
		}
	}
	return nil, fmt.Errorf("product %s has no approved version v%d", productName, seq)
}

// encodeEvidenceBytes dispatches on format and produces the canonical bytes
// the storage layer should hash and persist.
func encodeEvidenceBytes(content *evidence.PackContent, format string) ([]byte, error) {
	switch format {
	case domain.EvidencePackFormatJSON:
		b, err := evidence.EncodeJSON(content)
		if err != nil {
			return nil, fmt.Errorf("encode pack json: %w", err)
		}
		return b, nil
	case domain.EvidencePackFormatMarkdown:
		b, err := evidence.ExportMarkdown(content)
		if err != nil {
			return nil, fmt.Errorf("export pack markdown: %w", err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("unknown format %q (want %s or %s)",
			format, domain.EvidencePackFormatJSON, domain.EvidencePackFormatMarkdown)
	}
}

// normalizeEvidenceFormat lower-cases the input and validates it.
func normalizeEvidenceFormat(s string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case domain.EvidencePackFormatJSON, domain.EvidencePackFormatMarkdown:
		return v, nil
	default:
		return "", fmt.Errorf("unknown format %q (want %s or %s)",
			s, domain.EvidencePackFormatJSON, domain.EvidencePackFormatMarkdown)
	}
}

// parsePositiveInt64 parses a base-10 int64 and rejects non-positive values.
func parsePositiveInt64(s string) (int64, error) {
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("not an integer")
	}
	if n < 1 {
		return 0, fmt.Errorf("must be a positive integer or 'latest'")
	}
	return n, nil
}

// evidenceSinkLabel returns the canonical sink label embedded in the
// evidence.exported audit payload: "stdout" for "-", otherwise "file:<path>".
func evidenceSinkLabel(output string) string {
	if output == "" || output == "-" {
		return "stdout"
	}
	return "file:" + output
}

// writeEvidenceBytes writes b either to stdout (output == "-") or to the
// given file path.
func writeEvidenceBytes(stdout io.Writer, output string, b []byte) error {
	if output == "" || output == "-" {
		if _, err := stdout.Write(b); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(output, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", output, err)
	}
	return nil
}

// ----- list -----

func newEvidenceListCmd() *cobra.Command {
	var (
		productName  string
		limit        int
		outputFormat string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List evidence packs for a product, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			return runEvidenceList(cmd.Context(), store, cmd.OutOrStdout(), productName, limit, outputFormat)
		},
	}
	cmd.Flags().StringVar(&productName, "product", "", "product name (required)")
	cmd.Flags().IntVar(&limit, "limit", 20, "max rows to return")
	cmd.Flags().StringVar(&outputFormat, "format", "text", "output rendering: text or json")
	_ = cmd.MarkFlagRequired("product")
	return cmd
}

// evidencePackView is the trimmed metadata projection used by `evidence list`.
// We deliberately omit Content here — pack bytes can be megabytes and listing
// 20 of them inline destroys terminal usability.
type evidencePackView struct {
	ID                domain.ID `json:"id"`
	ProductID         domain.ID `json:"product_id"`
	ApprovedVersionID domain.ID `json:"approved_version_id"`
	Sequence          int64     `json:"sequence"`
	Format            string    `json:"format"`
	ContentHash       string    `json:"content_hash"`
	GeneratedAt       time.Time `json:"generated_at"`
	GeneratedByKind   string    `json:"generated_by_kind"`
	GeneratedBySubj   string    `json:"generated_by_subject"`
}

func toEvidencePackView(p *domain.EvidencePack) evidencePackView {
	return evidencePackView{
		ID:                p.ID,
		ProductID:         p.ProductID,
		ApprovedVersionID: p.ApprovedVersionID,
		Sequence:          p.Sequence,
		Format:            p.Format,
		ContentHash:       p.ContentHash,
		GeneratedAt:       p.GeneratedAt.UTC(),
		GeneratedByKind:   string(p.GeneratedBy.Kind),
		GeneratedBySubj:   p.GeneratedBy.Subject,
	}
}

func runEvidenceList(ctx context.Context, store storage.Storage, w io.Writer, productName string, limit int, outputFormat string) error {
	product, err := store.GetProductByName(ctx, productName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("product %q not found", productName)
		}
		return fmt.Errorf("lookup product %q: %w", productName, err)
	}
	packs, err := store.ListEvidencePacksByProduct(ctx, product.ID, limit)
	if err != nil {
		return fmt.Errorf("list evidence packs: %w", err)
	}

	switch strings.ToLower(strings.TrimSpace(outputFormat)) {
	case "", "text":
		return renderEvidenceListText(w, packs)
	case "json":
		views := make([]evidencePackView, 0, len(packs))
		for _, p := range packs {
			if p == nil {
				continue
			}
			views = append(views, toEvidencePackView(p))
		}
		b, err := json.MarshalIndent(views, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		_, err = io.WriteString(w, "\n")
		return err
	default:
		return fmt.Errorf("unknown format %q (want text or json)", outputFormat)
	}
}

func renderEvidenceListText(w io.Writer, packs []*domain.EvidencePack) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tFORMAT\tVERSION\tHASH\tGENERATED_AT\tGENERATED_BY"); err != nil {
		return err
	}
	for _, p := range packs {
		if p == nil {
			continue
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\tv%d\t%s\t%s\t%s\n",
			shortID(p.ID),
			p.Format,
			p.Sequence,
			shortHash(p.ContentHash),
			p.GeneratedAt.UTC().Format(time.RFC3339),
			actorString(p.GeneratedBy),
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// ----- show -----

func newEvidenceShowCmd() *cobra.Command {
	var (
		output string
		unwrap bool
	)
	cmd := &cobra.Command{
		Use:   "show <pack-id>",
		Short: "Print the bytes of an evidence pack by id",
		Long: "Loads the EvidencePack row by id and writes its persisted " +
			"content bytes to --output. With --unwrap and a markdown pack, " +
			"the JSON envelope is parsed and the body field is written instead " +
			"so the markdown can be piped to less without jq.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			return runEvidenceShow(cmd.Context(), store, cmd.OutOrStdout(), domain.ID(args[0]), output, unwrap)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "-",
		"write bytes to this path; '-' for stdout (default)")
	cmd.Flags().BoolVar(&unwrap, "unwrap", false,
		"for markdown packs, unwrap the JSON envelope and write only the body")
	return cmd
}

func runEvidenceShow(ctx context.Context, store storage.Storage, stdout io.Writer, packID domain.ID, output string, unwrap bool) error {
	pack, err := store.GetEvidencePackByID(ctx, packID)
	if err != nil {
		if errors.Is(err, storage.ErrEvidencePackNotFound) || errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("evidence pack %s not found", packID)
		}
		return fmt.Errorf("get evidence pack %s: %w", packID, err)
	}
	bytes := []byte(pack.Content)
	if unwrap && pack.Format == domain.EvidencePackFormatMarkdown {
		var env struct {
			Format string `json:"format"`
			Body   string `json:"body"`
		}
		if err := json.Unmarshal(bytes, &env); err != nil {
			return fmt.Errorf("unwrap markdown envelope: %w", err)
		}
		bytes = []byte(env.Body)
	}
	return writeEvidenceBytes(stdout, output, bytes)
}

// ----- helpers -----

// shortHash returns the first 12 hex characters of h, or the original when
// shorter. Used for table rendering and the export summary line.
func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
