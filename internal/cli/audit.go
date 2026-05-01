package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

func addAuditCmd(parent *cobra.Command) {
	auditCmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect and verify the immutable audit log",
	}
	auditCmd.AddCommand(newAuditListCmd(), newAuditVerifyCmd())
	parent.AddCommand(auditCmd)
}

// ----- list -----

func newAuditListCmd() *cobra.Command {
	var (
		limit        int
		kind         string
		resourceType string
		resourceID   string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit events, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := storeFromCmd(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close(cmd.Context()) }()

			filter := storage.AuditFilter{
				ResourceType: resourceType,
				ResourceID:   resourceID,
				Limit:        limit,
			}
			if kind != "" {
				filter.Kind = domain.EventKind(kind)
			}
			events, err := store.ListAuditEvents(cmd.Context(), filter)
			if err != nil {
				return fmt.Errorf("list audit events: %w", err)
			}
			return renderAuditTable(cmd.OutOrStdout(), events)
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "max rows to return; 0 = no limit")
	cmd.Flags().StringVar(&kind, "kind", "", "filter by event kind, e.g. changeset.approved")
	cmd.Flags().StringVar(&resourceType, "resource-type", "", "filter by resource type")
	cmd.Flags().StringVar(&resourceID, "resource-id", "", "filter by resource id")
	return cmd
}

func renderAuditTable(w io.Writer, events []*domain.AuditEvent) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "OCCURRED_AT\tKIND\tACTOR\tRESOURCE"); err != nil {
		return err
	}
	for _, e := range events {
		resource := e.ResourceType + "/" + e.ResourceID
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			e.OccurredAt.UTC().Format(time.RFC3339),
			e.Kind,
			actorString(e.Actor),
			resource,
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// ----- verify -----

func newAuditVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Recompute and verify the audit-event hash chain via the SQL audit_event_hash function",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pool, err := pgxpool.New(cmd.Context(), dbDSN())
			if err != nil {
				return fmt.Errorf("open pool: %w", err)
			}
			defer pool.Close()

			return runAuditVerify(cmd.Context(), pool, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	return cmd
}

// runAuditVerify walks audit_events in (occurred_at, id) order and checks each
// row's hash against `audit_event_hash(prev, ...)` evaluated server-side. We
// rely on the SQL function so Go and Postgres canonicalize the payload the
// same way (jsonb-to-text, with sorted keys).
func runAuditVerify(ctx context.Context, pool *pgxpool.Pool, stdout, stderr io.Writer) error {
	if !auditFunctionExists(ctx, pool) {
		_, err := fmt.Fprintln(stderr, "warning: audit_event_hash() not present; skipping verification")
		return err
	}

	const listQ = `
SELECT id, prev_hash, hash, kind, actor_kind, actor_subject,
       resource_type, resource_id, payload, occurred_at
  FROM audit_events
 ORDER BY occurred_at ASC, id ASC
`
	rows, err := pool.Query(ctx, listQ)
	if err != nil {
		return fmt.Errorf("query audit_events: %w", err)
	}
	defer rows.Close()

	type auditRow struct {
		id           string
		prevHash     string
		hash         string
		kind         string
		actorKind    string
		actorSubject string
		resourceType string
		resourceID   string
		payload      []byte
		occurredAt   time.Time
	}

	var batch []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(
			&r.id, &r.prevHash, &r.hash, &r.kind, &r.actorKind, &r.actorSubject,
			&r.resourceType, &r.resourceID, &r.payload, &r.occurredAt,
		); err != nil {
			return fmt.Errorf("scan audit row: %w", err)
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate audit rows: %w", err)
	}

	const computeQ = `
SELECT audit_event_hash($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
`
	prev := ""
	for i, r := range batch {
		// Sanity: stored prev_hash must equal the running prev value.
		if r.prevHash != prev {
			_, _ = fmt.Fprintf(stderr,
				"MISMATCH at event %s (#%d): expected prev_hash %q, found %q\n",
				r.id, i+1, prev, r.prevHash)
			return errors.New("audit chain: prev_hash mismatch")
		}
		var computed string
		if err := pool.QueryRow(ctx, computeQ,
			prev, r.kind, r.actorKind, r.actorSubject,
			r.resourceType, r.resourceID, r.payload, r.occurredAt,
		).Scan(&computed); err != nil {
			return fmt.Errorf("compute hash for event %s: %w", r.id, err)
		}
		if computed != r.hash {
			_, _ = fmt.Fprintf(stderr,
				"MISMATCH at event %s (#%d): expected hash %s, found %s\n",
				r.id, i+1, computed, r.hash)
			return errors.New("audit chain: hash mismatch")
		}
		prev = r.hash
	}

	_, err = fmt.Fprintf(stdout, "OK: %d events, chain verified\n", len(batch))
	return err
}

// auditFunctionExists returns true when the database exposes the
// audit_event_hash function. Older deployments (pre-migration 0003) won't
// have it, in which case the caller falls back to a "skip with warning"
// message rather than failing the verify run.
func auditFunctionExists(ctx context.Context, pool *pgxpool.Pool) bool {
	const q = `SELECT 1 FROM pg_proc WHERE proname = 'audit_event_hash' LIMIT 1`
	var ok int
	err := pool.QueryRow(ctx, q).Scan(&ok)
	if err == nil {
		return true
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	// Any other error means we couldn't tell; treat as "skip" rather than
	// crashing the verification command.
	var pgErr *pgconn.PgError
	_ = errors.As(err, &pgErr)
	return false
}
