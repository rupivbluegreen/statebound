// Package cli — drift subcommand. Phase 4' wires the connector drift path
// into the CLI so operators can scan target systems for mismatches against
// an approved version of a product.
//
// `drift scan` runs the connector's CollectActualState + Compare cycle,
// persists a DriftScan + DriftFindings, emits the audit event triplet
// (drift.scan.started, drift.scan.succeeded|failed, drift.finding.detected),
// and writes the canonical findings JSON to --output. `drift list` and
// `drift show` are the read-only views for browsing prior scans.
//
// Like Phase 4 plans, scans are deterministic: re-running drift scan with
// identical desired state + identical actual state produces an identical
// summary_hash. The summary_hash is the SHA-256 hex of the canonical
// findings list (sorted, JSON-encoded with sorted map keys at every level)
// and is what the CI smoke greps for to assert reproducibility.
//
// Drift never applies; agents never get here. This subcommand is read-only
// against target systems beyond CollectActualState — it does not modify
// any target host, fragment, or grant.
package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/connectors/builtins"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
	"statebound.dev/statebound/internal/storage"
)

// addDriftCmd registers `statebound drift` and its subcommands on the
// supplied parent (root command).
func addDriftCmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "drift",
		Short: "Scan target systems for drift against an approved version",
		Long: "Drift detection compares an approved version of a product " +
			"against actual state collected from a target system through a " +
			"connector. Findings are persisted, audited, and exported as " +
			"canonical JSON. Phase 4' is read-only against the target — apply " +
			"is reserved for Phase 6+.",
	}
	cmd.AddCommand(newDriftScanCmd(), newDriftListCmd(), newDriftShowCmd())
	parent.AddCommand(cmd)
}

// ----- scan -----

func newDriftScanCmd() *cobra.Command {
	var (
		productName   string
		versionStr    string
		connectorName string
		source        string
		output        string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a target system for drift against an approved version",
		Long: "Resolves the named product's approved version, hands it (plus " +
			"the supplied --source) to the named connector's CollectActualState " +
			"and Compare methods, persists the resulting scan + findings, emits " +
			"audit events, and writes canonical findings JSON to --output. The " +
			"summary_hash inside the output is reproducible: identical desired " +
			"state + identical actual state produce byte-identical bytes.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			actor := actorFromCmd(cmd)
			return runDriftScan(cmd.Context(), store, cmd.OutOrStdout(), cmd.ErrOrStderr(), driftScanArgs{
				productName:   productName,
				versionStr:    versionStr,
				connectorName: connectorName,
				source:        source,
				output:        output,
				actor:         actor,
			})
		},
	}
	cmd.Flags().StringVar(&productName, "product", "", "product name (required)")
	cmd.Flags().StringVar(&versionStr, "version", "latest",
		"approved-version sequence to scan against, or 'latest' (default)")
	cmd.Flags().StringVar(&connectorName, "connector", "",
		"connector name; must support collect_actual + compare (required)")
	cmd.Flags().StringVar(&source, "source", "",
		"connector source ref, e.g. /etc/sudoers.d for linux-sudo (required)")
	cmd.Flags().StringVarP(&output, "output", "o", "-",
		"write findings JSON to this path; '-' for stdout (default)")
	_ = cmd.MarkFlagRequired("product")
	_ = cmd.MarkFlagRequired("connector")
	_ = cmd.MarkFlagRequired("source")
	return cmd
}

// driftScanArgs bundles the parsed flags for runDriftScan so the signature
// stays narrow.
type driftScanArgs struct {
	productName   string
	versionStr    string
	connectorName string
	source        string
	output        string
	actor         domain.Actor
}

// driftScanOutput is the canonical wire shape written by `drift scan`. It
// is also what `drift show` writes. Both encoders go through json.Marshal
// of this struct so field order stays deterministic across runs.
type driftScanOutput struct {
	Scan     driftScanOutputScan        `json:"scan"`
	Findings []driftScanOutputFinding   `json:"findings"`
}

// driftScanOutputScan is the metadata header of the canonical export. Field
// order is fixed so two encodes of the same scan produce byte-identical
// bytes.
type driftScanOutputScan struct {
	ID                      domain.ID  `json:"id"`
	Connector               string     `json:"connector"`
	ConnectorVersion        string     `json:"connector_version"`
	SourceRef               string     `json:"source_ref"`
	ApprovedVersionID       domain.ID  `json:"approved_version_id"`
	ApprovedVersionSequence int64      `json:"approved_version_sequence"`
	StartedAt               time.Time  `json:"started_at"`
	FinishedAt              *time.Time `json:"finished_at,omitempty"`
	State                   string     `json:"state"`
	SummaryHash             string     `json:"summary_hash"`
	FindingCount            int        `json:"finding_count"`
	FailureMessage          string     `json:"failure_message,omitempty"`
}

// driftScanOutputFinding mirrors domain.DriftFinding without the persistence
// columns. The JSON tags fix the wire-shape contract used by the CI smoke
// (which greps for .findings[*]) and external auditors.
type driftScanOutputFinding struct {
	Sequence     int             `json:"sequence"`
	Kind         string          `json:"kind"`
	Severity     string          `json:"severity"`
	ResourceKind string          `json:"resource_kind"`
	ResourceRef  string          `json:"resource_ref"`
	Desired      json.RawMessage `json:"desired,omitempty"`
	Actual       json.RawMessage `json:"actual,omitempty"`
	Diff         json.RawMessage `json:"diff"`
	Message      string          `json:"message"`
	DetectedAt   time.Time       `json:"detected_at"`
}

// canonicalFinding is the subset of a finding that feeds the summary_hash.
// We keep it separate from driftScanOutputFinding so a future addition to
// the export wire shape (e.g. a render-only label) does not silently change
// every previously-computed summary_hash. Field ORDER and field SET here
// are part of the public contract: bumping it invalidates every prior hash
// and must be a deliberate decision.
type canonicalFinding struct {
	Sequence     int             `json:"sequence"`
	Kind         string          `json:"kind"`
	Severity     string          `json:"severity"`
	ResourceKind string          `json:"resource_kind"`
	ResourceRef  string          `json:"resource_ref"`
	Desired      json.RawMessage `json:"desired,omitempty"`
	Actual       json.RawMessage `json:"actual,omitempty"`
	Diff         json.RawMessage `json:"diff"`
	Message      string          `json:"message"`
}

// runDriftScan is the testable handler body. The flow is intentionally
// linear and matches the spec in CLAUDE.md / the agent prompt:
//   1. Boot connector registry, resolve connector, validate capabilities.
//   2. Resolve product + approved version, decode snapshot.
//   3. Open scan in 'running' state, emit drift.scan.started.
//   4. CollectActualState + Compare OUTSIDE the tx (network/fs work must
//      not hold a tx open).
//   5. On error, transition scan -> failed and emit drift.scan.failed.
//   6. On success, persist findings + transition scan -> succeeded inside
//      a fresh tx and emit drift.scan.succeeded plus per-finding
//      drift.finding.detected events.
//   7. Write canonical findings JSON to --output, summary line to stderr.
func runDriftScan(ctx context.Context, store storage.Storage, stdout, stderr io.Writer, args driftScanArgs) error {
	// 1. Connector registry + capability check.
	registry := connectors.NewRegistry()
	builtins.Register(registry)

	conn, ok := registry.Get(args.connectorName)
	if !ok {
		names := make([]string, 0)
		for _, c := range registry.List() {
			names = append(names, c.Name())
		}
		return fmt.Errorf("unknown connector %q; available: %s",
			args.connectorName, strings.Join(names, ", "))
	}
	if !connectorSupportsDrift(conn) {
		return fmt.Errorf("connector %s does not support drift detection", conn.Name())
	}

	// 2. Resolve product + approved version + snapshot.
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
	if av == nil {
		return fmt.Errorf("%s has no approved versions yet — drift scan requires approval first", args.productName)
	}
	_, snapshot, err := store.GetApprovedVersionByID(ctx, av.ID)
	if err != nil {
		return fmt.Errorf("load approved version snapshot: %w", err)
	}
	if snapshot == nil {
		return fmt.Errorf("%s v%d has no snapshot content", args.productName, av.Sequence)
	}
	pam, err := model.FromSnapshot(snapshot.Content)
	if err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}

	desired := connectors.ApprovedState{
		Product:           product,
		ApprovedVersionID: av.ID,
		Sequence:          av.Sequence,
		Snapshot:          snapshot.Content,
		Model:             pam,
	}

	// Resolve --source to an absolute path so the source_ref is stable
	// across invocations from different working directories. We only do
	// this for paths that look like file system roots (i.e. don't already
	// carry a scheme); host-based connectors arriving in later phases can
	// pass "host:..." style refs through unchanged.
	absSource := args.source
	if !strings.Contains(absSource, "://") {
		if abs, absErr := filepath.Abs(absSource); absErr == nil {
			absSource = abs
		}
	}
	sourceRef := absSource
	if !strings.Contains(sourceRef, "://") {
		sourceRef = "file://" + sourceRef
	}

	scope := connectors.CollectionScope{Path: absSource}

	// 3. Open scan + emit drift.scan.started in one tx.
	scan, err := domain.NewDriftScan(
		product.ID, av.ID, av.Sequence,
		conn.Name(), conn.Version(),
		sourceRef, args.actor,
	)
	if err != nil {
		return fmt.Errorf("build drift scan: %w", err)
	}

	if err := store.WithTx(ctx, func(tx storage.Storage) error {
		if err := tx.AppendDriftScan(ctx, scan); err != nil {
			return fmt.Errorf("append drift scan: %w", err)
		}
		startedEvt, err := domain.NewAuditEvent(
			domain.EventDriftScanStarted,
			args.actor,
			"drift_scan",
			string(scan.ID),
			map[string]any{
				"scan_id":             string(scan.ID),
				"connector":           scan.ConnectorName,
				"connector_version":   scan.ConnectorVersion,
				"source_ref":          scan.SourceRef,
				"approved_version_id": string(scan.ApprovedVersionID),
			},
		)
		if err != nil {
			return fmt.Errorf("build drift.scan.started audit: %w", err)
		}
		if err := tx.AppendAuditEvent(ctx, startedEvt); err != nil {
			return fmt.Errorf("append drift.scan.started audit: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	// 4. Collect + Compare OUTSIDE any tx. These can do filesystem or
	// network I/O and we don't want a tx open while they run.
	actual, err := conn.CollectActualState(ctx, scope)
	if err != nil {
		return failDriftScan(ctx, store, stderr, scan, args.actor, fmt.Errorf("collect actual state: %w", err))
	}
	connectorFindings, err := conn.Compare(ctx, desired, actual)
	if err != nil {
		return failDriftScan(ctx, store, stderr, scan, args.actor, fmt.Errorf("compare: %w", err))
	}

	// 5. Translate connector findings into domain findings, sorted for
	// determinism. Connectors are expected to return them ordered by
	// (resource_kind, resource_ref) — we re-sort here as defense in depth.
	sort.SliceStable(connectorFindings, func(i, j int) bool {
		if connectorFindings[i].ResourceKind != connectorFindings[j].ResourceKind {
			return connectorFindings[i].ResourceKind < connectorFindings[j].ResourceKind
		}
		return connectorFindings[i].ResourceRef < connectorFindings[j].ResourceRef
	})

	domainFindings := make([]*domain.DriftFinding, 0, len(connectorFindings))
	wireFindings := make([]driftScanOutputFinding, 0, len(connectorFindings))
	canonicalFindings := make([]canonicalFinding, 0, len(connectorFindings))

	for i, cf := range connectorFindings {
		seq := i + 1

		desiredJSON, err := marshalOptionalMap(cf.Desired)
		if err != nil {
			return failDriftScan(ctx, store, stderr, scan, args.actor,
				fmt.Errorf("finding %d: marshal desired: %w", seq, err))
		}
		actualJSON, err := marshalOptionalMap(cf.Actual)
		if err != nil {
			return failDriftScan(ctx, store, stderr, scan, args.actor,
				fmt.Errorf("finding %d: marshal actual: %w", seq, err))
		}
		diffJSON, err := marshalDiffMap(cf.Diff)
		if err != nil {
			return failDriftScan(ctx, store, stderr, scan, args.actor,
				fmt.Errorf("finding %d: marshal diff: %w", seq, err))
		}

		df, err := domain.NewDriftFinding(
			scan.ID, seq,
			domain.DriftKind(cf.Kind),
			domain.DriftSeverity(cf.Severity),
			cf.ResourceKind, cf.ResourceRef,
			desiredJSON, actualJSON, diffJSON,
			cf.Message,
		)
		if err != nil {
			return failDriftScan(ctx, store, stderr, scan, args.actor,
				fmt.Errorf("finding %d: build domain finding: %w", seq, err))
		}
		domainFindings = append(domainFindings, df)
		wireFindings = append(wireFindings, driftScanOutputFinding{
			Sequence:     df.Sequence,
			Kind:         string(df.Kind),
			Severity:     string(df.Severity),
			ResourceKind: df.ResourceKind,
			ResourceRef:  df.ResourceRef,
			Desired:      df.Desired,
			Actual:       df.Actual,
			Diff:         df.Diff,
			Message:      df.Message,
			DetectedAt:   df.DetectedAt.UTC(),
		})
		canonicalFindings = append(canonicalFindings, canonicalFinding{
			Sequence:     df.Sequence,
			Kind:         string(df.Kind),
			Severity:     string(df.Severity),
			ResourceKind: df.ResourceKind,
			ResourceRef:  df.ResourceRef,
			Desired:      df.Desired,
			Actual:       df.Actual,
			Diff:         df.Diff,
			Message:      df.Message,
		})
	}

	// 6. Compute summary_hash deterministically from the canonical
	// findings list. We marshal the slice (json.Marshal walks it in slice
	// order; the json.RawMessage fields are already canonical from
	// connector.Compare or domain.NewDriftFinding's empty-{} default).
	summaryBytes, err := json.Marshal(canonicalFindings)
	if err != nil {
		return failDriftScan(ctx, store, stderr, scan, args.actor,
			fmt.Errorf("marshal canonical findings: %w", err))
	}
	sum := sha256.Sum256(summaryBytes)
	summaryHash := "sha256:" + hex.EncodeToString(sum[:])
	severityDist := severityDistribution(connectorFindings)

	// 7. Persist findings + terminal scan + audit events in one tx.
	if err := scan.Transition(domain.DriftScanStateSucceeded, time.Now().UTC(), summaryHash, len(domainFindings), ""); err != nil {
		return failDriftScan(ctx, store, stderr, scan, args.actor,
			fmt.Errorf("transition scan to succeeded: %w", err))
	}

	if err := store.WithTx(ctx, func(tx storage.Storage) error {
		if len(domainFindings) > 0 {
			if err := tx.AppendDriftFindings(ctx, domainFindings); err != nil {
				return fmt.Errorf("append drift findings: %w", err)
			}
		}
		if err := tx.UpdateDriftScan(ctx, scan); err != nil {
			return fmt.Errorf("update drift scan: %w", err)
		}
		succeededEvt, err := domain.NewAuditEvent(
			domain.EventDriftScanSucceeded,
			args.actor,
			"drift_scan",
			string(scan.ID),
			map[string]any{
				"scan_id":               string(scan.ID),
				"finding_count":         len(domainFindings),
				"summary_hash":          summaryHash,
				"severity_distribution": severityDist,
			},
		)
		if err != nil {
			return fmt.Errorf("build drift.scan.succeeded audit: %w", err)
		}
		if err := tx.AppendAuditEvent(ctx, succeededEvt); err != nil {
			return fmt.Errorf("append drift.scan.succeeded audit: %w", err)
		}
		// Per-finding events. We keep payloads small (sequence + the
		// classification triple) — full bodies live in drift_findings.
		for _, df := range domainFindings {
			detectedEvt, err := domain.NewAuditEvent(
				domain.EventDriftFindingDetected,
				args.actor,
				"drift_finding",
				string(df.ID),
				map[string]any{
					"scan_id":       string(scan.ID),
					"finding_id":    string(df.ID),
					"sequence":      df.Sequence,
					"kind":          string(df.Kind),
					"severity":      string(df.Severity),
					"resource_kind": df.ResourceKind,
					"resource_ref":  df.ResourceRef,
				},
			)
			if err != nil {
				return fmt.Errorf("build drift.finding.detected audit: %w", err)
			}
			if err := tx.AppendAuditEvent(ctx, detectedEvt); err != nil {
				return fmt.Errorf("append drift.finding.detected audit: %w", err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// 8. Write canonical findings JSON to the sink.
	out := driftScanOutput{
		Scan: driftScanOutputScan{
			ID:                      scan.ID,
			Connector:               scan.ConnectorName,
			ConnectorVersion:        scan.ConnectorVersion,
			SourceRef:               scan.SourceRef,
			ApprovedVersionID:       scan.ApprovedVersionID,
			ApprovedVersionSequence: scan.Sequence,
			StartedAt:               scan.StartedAt.UTC(),
			FinishedAt:              finishedAtPtr(scan),
			State:                   string(scan.State),
			SummaryHash:             scan.SummaryHash,
			FindingCount:            scan.FindingCount,
		},
		Findings: wireFindings,
	}
	if err := writeDriftBytes(stdout, args.output, out); err != nil {
		return err
	}

	// 9. Human summary on stderr (so a stdout redirect captures only the
	// JSON wire shape).
	summary := fmt.Sprintf(
		"drift scan %s (%s, source=%s) for %s:v%d: %s; %d findings (%s)",
		shortID(scan.ID), scan.ConnectorName, scan.SourceRef,
		product.Name, scan.Sequence, scan.State, scan.FindingCount,
		formatSeverityDistribution(severityDist),
	)
	_, err = fmt.Fprintln(stderr, summary)
	return err
}

// failDriftScan transitions the scan to Failed in a fresh tx, emits
// drift.scan.failed, and returns the original error to the caller. It is
// the only path that records a failed scan, so any error from collect/
// compare/persist passes through here.
func failDriftScan(
	ctx context.Context,
	store storage.Storage,
	stderr io.Writer,
	scan *domain.DriftScan,
	actor domain.Actor,
	cause error,
) error {
	failureMsg := cause.Error()
	if err := scan.Transition(domain.DriftScanStateFailed, time.Now().UTC(), "", 0, failureMsg); err != nil {
		// State machine refused the transition (e.g. already terminal).
		// Surface both errors so the operator can untangle the chain.
		return fmt.Errorf("%w (additionally: failed to record failure: %v)", cause, err)
	}
	if txErr := store.WithTx(ctx, func(tx storage.Storage) error {
		if err := tx.UpdateDriftScan(ctx, scan); err != nil {
			return fmt.Errorf("update drift scan to failed: %w", err)
		}
		failedEvt, err := domain.NewAuditEvent(
			domain.EventDriftScanFailed,
			actor,
			"drift_scan",
			string(scan.ID),
			map[string]any{
				"scan_id":         string(scan.ID),
				"connector":       scan.ConnectorName,
				"failure_message": failureMsg,
			},
		)
		if err != nil {
			return fmt.Errorf("build drift.scan.failed audit: %w", err)
		}
		if err := tx.AppendAuditEvent(ctx, failedEvt); err != nil {
			return fmt.Errorf("append drift.scan.failed audit: %w", err)
		}
		return nil
	}); txErr != nil {
		// Preserve both: the cause and the failure-recording error.
		return fmt.Errorf("%w (additionally: %v)", cause, txErr)
	}
	_, _ = fmt.Fprintf(stderr,
		"drift scan %s for connector %s failed: %s\n",
		shortID(scan.ID), scan.ConnectorName, failureMsg)
	return cause
}

// connectorSupportsDrift reports whether c advertises both
// CollectActualState and Compare. We deliberately rely on Capabilities()
// rather than calling the methods and checking for ErrCapabilityNotSupported
// so a connector that returns the sentinel from one method but advertises
// the cap (a programmer bug) is treated as supporting drift.
func connectorSupportsDrift(c connectors.Connector) bool {
	hasCollect := false
	hasCompare := false
	for _, cap := range c.Capabilities() {
		switch cap {
		case connectors.CapabilityCollectActual:
			hasCollect = true
		case connectors.CapabilityCompare:
			hasCompare = true
		}
	}
	return hasCollect && hasCompare
}

// marshalOptionalMap produces canonical JSON bytes for the desired/actual
// finding bodies. nil maps become a nil slice (so domain.NewDriftFinding's
// validator skips them and the omitempty tag elides the wire field).
func marshalOptionalMap(m map[string]any) (json.RawMessage, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// marshalDiffMap mirrors marshalOptionalMap for the diff field, which
// domain.NewDriftFinding will default to "{}" if empty. Returning nil here
// hands that responsibility to the domain constructor.
func marshalDiffMap(m map[string]any) (json.RawMessage, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// severityDistribution returns the count of findings at each severity level.
// Keys are the canonical domain.DriftSeverity strings; severities with zero
// findings are still emitted with value 0 so the audit payload has a stable
// shape for downstream tooling.
func severityDistribution(findings []connectors.DriftFinding) map[string]int {
	dist := map[string]int{
		string(domain.DriftSeverityCritical): 0,
		string(domain.DriftSeverityHigh):     0,
		string(domain.DriftSeverityMedium):   0,
		string(domain.DriftSeverityLow):      0,
		string(domain.DriftSeverityInfo):     0,
	}
	for _, f := range findings {
		if _, ok := dist[f.Severity]; !ok {
			dist[f.Severity] = 0
		}
		dist[f.Severity]++
	}
	return dist
}

// formatSeverityDistribution renders the dist map in a stable
// "n_critical critical, n_high high, ..." format for the stderr summary.
// Severity order is fixed (Critical -> Info) so two runs read identically.
func formatSeverityDistribution(dist map[string]int) string {
	order := []string{
		string(domain.DriftSeverityCritical),
		string(domain.DriftSeverityHigh),
		string(domain.DriftSeverityMedium),
		string(domain.DriftSeverityLow),
		string(domain.DriftSeverityInfo),
	}
	parts := make([]string, 0, len(order))
	for _, sev := range order {
		parts = append(parts, fmt.Sprintf("%d %s", dist[sev], sev))
	}
	return strings.Join(parts, ", ")
}

// finishedAtPtr safely projects the FinishedAt field. Nil for scans that
// somehow lack a finished_at (shouldn't happen for a Succeeded scan, but
// the wire shape supports nil for symmetry with running scans rendered by
// `drift list` and `drift show`).
func finishedAtPtr(scan *domain.DriftScan) *time.Time {
	if scan == nil || scan.FinishedAt == nil {
		return nil
	}
	t := scan.FinishedAt.UTC()
	return &t
}

// writeDriftBytes routes the canonical JSON to stdout (output == "-") or
// to a file path. The encoder is json.Marshal of the typed struct so field
// order is fixed; we append a trailing newline so the bytes are
// diff/cat-friendly.
func writeDriftBytes(stdout io.Writer, output string, out driftScanOutput) error {
	b, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal drift scan output: %w", err)
	}
	b = append(b, '\n')
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

func newDriftListCmd() *cobra.Command {
	var (
		productName  string
		limit        int
		outputFormat string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List drift scans for a product, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			return runDriftList(cmd.Context(), store, cmd.OutOrStdout(), productName, limit, outputFormat)
		},
	}
	cmd.Flags().StringVar(&productName, "product", "", "product name (required)")
	cmd.Flags().IntVar(&limit, "limit", 20, "max rows to return")
	cmd.Flags().StringVar(&outputFormat, "format", "text", "output rendering: text or json")
	_ = cmd.MarkFlagRequired("product")
	return cmd
}

// driftScanView is the trimmed metadata projection used by `drift list`.
// We deliberately omit findings here — listing 20 scans with their full
// bodies destroys terminal usability.
type driftScanView struct {
	ID                domain.ID  `json:"id"`
	ProductID         domain.ID  `json:"product_id"`
	ApprovedVersionID domain.ID  `json:"approved_version_id"`
	Sequence          int64      `json:"sequence"`
	Connector         string     `json:"connector"`
	ConnectorVersion  string     `json:"connector_version"`
	SourceRef         string     `json:"source_ref"`
	State             string     `json:"state"`
	FindingCount      int        `json:"finding_count"`
	SummaryHash       string     `json:"summary_hash"`
	StartedAt         time.Time  `json:"started_at"`
	FinishedAt        *time.Time `json:"finished_at,omitempty"`
	InitiatedByKind   string     `json:"initiated_by_kind"`
	InitiatedBySubj   string     `json:"initiated_by_subject"`
}

func toDriftScanView(s *domain.DriftScan) driftScanView {
	return driftScanView{
		ID:                s.ID,
		ProductID:         s.ProductID,
		ApprovedVersionID: s.ApprovedVersionID,
		Sequence:          s.Sequence,
		Connector:         s.ConnectorName,
		ConnectorVersion:  s.ConnectorVersion,
		SourceRef:         s.SourceRef,
		State:             string(s.State),
		FindingCount:      s.FindingCount,
		SummaryHash:       s.SummaryHash,
		StartedAt:         s.StartedAt.UTC(),
		FinishedAt:        finishedAtPtr(s),
		InitiatedByKind:   string(s.InitiatedBy.Kind),
		InitiatedBySubj:   s.InitiatedBy.Subject,
	}
}

func runDriftList(ctx context.Context, store storage.Storage, w io.Writer, productName string, limit int, outputFormat string) error {
	product, err := store.GetProductByName(ctx, productName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("product %q not found", productName)
		}
		return fmt.Errorf("lookup product %q: %w", productName, err)
	}
	scans, err := store.ListDriftScansByProduct(ctx, product.ID, limit)
	if err != nil {
		return fmt.Errorf("list drift scans: %w", err)
	}

	switch strings.ToLower(strings.TrimSpace(outputFormat)) {
	case "", "text":
		return renderDriftListText(w, scans)
	case "json":
		views := make([]driftScanView, 0, len(scans))
		for _, s := range scans {
			if s == nil {
				continue
			}
			views = append(views, toDriftScanView(s))
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

func renderDriftListText(w io.Writer, scans []*domain.DriftScan) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tCONNECTOR\tSTATE\tFINDINGS\tSTARTED_AT\tINITIATED_BY"); err != nil {
		return err
	}
	for _, s := range scans {
		if s == nil {
			continue
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			shortID(s.ID),
			s.ConnectorName,
			s.State,
			s.FindingCount,
			s.StartedAt.UTC().Format(time.RFC3339),
			actorString(s.InitiatedBy),
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// ----- show -----

func newDriftShowCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "show <scan-id>",
		Short: "Print the canonical JSON of a drift scan by id",
		Long: "Loads the DriftScan and its findings by id and writes the same " +
			"canonical JSON shape that `drift scan` produces. Useful for " +
			"re-exporting a previously-run scan without re-collecting actual " +
			"state.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			return runDriftShow(cmd.Context(), store, cmd.OutOrStdout(), domain.ID(args[0]), output)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "-",
		"write bytes to this path; '-' for stdout (default)")
	return cmd
}

func runDriftShow(ctx context.Context, store storage.Storage, stdout io.Writer, scanID domain.ID, output string) error {
	scan, findings, err := store.GetDriftScanByID(ctx, scanID)
	if err != nil {
		if errors.Is(err, storage.ErrDriftScanNotFound) || errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("drift scan %s not found", scanID)
		}
		return fmt.Errorf("get drift scan %s: %w", scanID, err)
	}
	wireFindings := make([]driftScanOutputFinding, 0, len(findings))
	for _, df := range findings {
		if df == nil {
			continue
		}
		wireFindings = append(wireFindings, driftScanOutputFinding{
			Sequence:     df.Sequence,
			Kind:         string(df.Kind),
			Severity:     string(df.Severity),
			ResourceKind: df.ResourceKind,
			ResourceRef:  df.ResourceRef,
			Desired:      df.Desired,
			Actual:       df.Actual,
			Diff:         df.Diff,
			Message:      df.Message,
			DetectedAt:   df.DetectedAt.UTC(),
		})
	}
	out := driftScanOutput{
		Scan: driftScanOutputScan{
			ID:                      scan.ID,
			Connector:               scan.ConnectorName,
			ConnectorVersion:        scan.ConnectorVersion,
			SourceRef:               scan.SourceRef,
			ApprovedVersionID:       scan.ApprovedVersionID,
			ApprovedVersionSequence: scan.Sequence,
			StartedAt:               scan.StartedAt.UTC(),
			FinishedAt:              finishedAtPtr(scan),
			State:                   string(scan.State),
			SummaryHash:             scan.SummaryHash,
			FindingCount:            scan.FindingCount,
			FailureMessage:          scan.FailureMessage,
		},
		Findings: wireFindings,
	}
	return writeDriftBytes(stdout, output, out)
}
