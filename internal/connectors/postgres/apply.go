// Phase 6 apply: Apply executes a plan against the target Postgres
// inside a single transaction. On any failure the transaction is
// rolled back and remaining items are marked skipped — partial apply
// would leave the target in an inconsistent state and is explicitly
// disallowed.
//
// DryRun mode does NOT open a transaction. It walks the plan items,
// generates the SQL via the helpers in sql.go, and returns Statements
// populated with the literal strings that would have been executed.
// Every item lands as Status="skipped". The auditor reads this output
// to verify the planned change before signing off.
//
// SummaryHash is the SHA-256 of canonical JSON over Items so two apply
// runs that touch the same items in the same order produce the same
// hash — the CLI persists this on PlanApplyRecord.

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"statebound.dev/statebound/internal/connectors"
)

// Apply executes plan against the connector's target system. On
// DryRun the connector does not connect to the target; on a real
// apply it opens one pgx connection, begins a transaction, executes
// every item's SQL, commits on success, rolls back on the first
// failure (and marks remaining items skipped).
func (*Connector) Apply(ctx context.Context, plan *connectors.PlanForApply, opts connectors.ApplyOptions) (*connectors.ApplyResult, error) {
	if plan == nil {
		return nil, fmt.Errorf("postgres apply: nil plan")
	}
	if opts.Target == "" {
		return nil, fmt.Errorf("postgres apply: ApplyOptions.Target (DSN) is required")
	}

	startedAt := time.Now().UTC()
	items := sortedPlanItems(plan.Items)

	if opts.DryRun {
		return dryRunApply(items, opts.Target, startedAt), nil
	}

	conn, err := pgx.Connect(ctx, opts.Target)
	if err != nil {
		return nil, fmt.Errorf("postgres apply: connect: %w", err)
	}
	defer conn.Close(ctx)

	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("postgres apply: begin tx: %w", err)
	}

	result := &connectors.ApplyResult{
		ConnectorName:    connectorName,
		ConnectorVersion: connectorVersion,
		Target:           opts.Target,
		StartedAt:        startedAt,
		DryRun:           false,
		Items:            make([]connectors.ApplyItemResult, 0, len(items)),
	}

	failedIdx := -1
	for i, it := range items {
		stmts := statementsForItem(it)
		applyItem := connectors.ApplyItemResult{
			Sequence:     it.Sequence,
			ResourceKind: it.ResourceKind,
			ResourceRef:  it.ResourceRef,
			Statements:   stmts,
			RowsAffected: -1,
		}
		if len(stmts) == 0 {
			// Nothing to do for this item — count as skipped, not failed.
			applyItem.Status = "skipped"
			result.Items = append(result.Items, applyItem)
			continue
		}

		var rowsTotal int64
		execErr := func() error {
			for _, s := range stmts {
				tag, err := tx.Exec(ctx, s)
				if err != nil {
					return err
				}
				rowsTotal += tag.RowsAffected()
			}
			return nil
		}()
		if execErr != nil {
			applyItem.Status = "failed"
			applyItem.Error = execErr.Error()
			result.Items = append(result.Items, applyItem)
			failedIdx = i
			break
		}
		applyItem.Status = "applied"
		applyItem.RowsAffected = int(rowsTotal)
		result.Items = append(result.Items, applyItem)
	}

	if failedIdx >= 0 {
		// Mark remaining as skipped so the result still has 1:1 alignment
		// with the plan. Then rollback.
		for j := failedIdx + 1; j < len(items); j++ {
			it := items[j]
			result.Items = append(result.Items, connectors.ApplyItemResult{
				Sequence:     it.Sequence,
				ResourceKind: it.ResourceKind,
				ResourceRef:  it.ResourceRef,
				Status:       "skipped",
				Statements:   []string{},
				RowsAffected: -1,
				Error:        "skipped due to earlier failure",
			})
		}
		if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			// Surface rollback failure as part of the failed item's
			// error — the parent item is already failed, but a stuck
			// transaction is worth knowing about.
			result.Items[failedIdx].Error = fmt.Sprintf("%s; rollback: %s", result.Items[failedIdx].Error, rbErr.Error())
		}
	} else {
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("postgres apply: commit: %w", err)
		}
	}

	result.FinishedAt = time.Now().UTC()
	result.SummaryHash = computeSummaryHash(result.Items)
	return result, nil
}

// dryRunApply walks the plan items and produces an ApplyResult with
// every item marked skipped + Statements populated. Does not open a
// connection.
func dryRunApply(items []connectors.PlanItem, target string, startedAt time.Time) *connectors.ApplyResult {
	out := &connectors.ApplyResult{
		ConnectorName:    connectorName,
		ConnectorVersion: connectorVersion,
		Target:           target,
		StartedAt:        startedAt,
		DryRun:           true,
		Items:            make([]connectors.ApplyItemResult, 0, len(items)),
	}
	for _, it := range items {
		stmts := statementsForItem(it)
		if stmts == nil {
			stmts = []string{}
		}
		out.Items = append(out.Items, connectors.ApplyItemResult{
			Sequence:     it.Sequence,
			ResourceKind: it.ResourceKind,
			ResourceRef:  it.ResourceRef,
			Status:       "skipped",
			Statements:   stmts,
			RowsAffected: -1,
		})
	}
	out.FinishedAt = time.Now().UTC()
	out.SummaryHash = computeSummaryHash(out.Items)
	return out
}

// statementsForItem dispatches to the right SQL helper based on
// ResourceKind. Returns nil for kinds this connector does not handle
// (defensive — Plan should never emit such kinds).
func statementsForItem(it connectors.PlanItem) []string {
	switch it.ResourceKind {
	case "postgres.role":
		role, _ := it.Body["role"].(string)
		login, _ := it.Body["login"].(bool)
		inherit, _ := it.Body["inherit"].(bool)
		connLimit := intFromBody(it.Body, "connection_limit", -1)
		return BuildCreateRoleSQL(role, login, inherit, connLimit)
	case "postgres.grant":
		asRole, _ := it.Body["as_role"].(string)
		database, _ := it.Body["database"].(string)
		schema, _ := it.Body["schema"].(string)
		privs := privilegesFromBody(it.Body)
		tables := tablesFromBody(it.Body)
		return BuildGrantSQL(asRole, database, schema, privs, tables)
	default:
		return nil
	}
}

// sortedPlanItems returns a copy of items sorted by Sequence ASC. Apply
// must run roles before grants so grants reference an existing role —
// Plan emits roles first, but we re-sort by Sequence here as defense
// in depth.
func sortedPlanItems(in []connectors.PlanItem) []connectors.PlanItem {
	out := append([]connectors.PlanItem(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out
}

// computeSummaryHash returns the hex SHA-256 of the canonical JSON over
// the apply items. Item structs are marshalled directly; encoding/json
// emits keys in struct-declaration order which is stable for our
// ApplyItemResult definition.
func computeSummaryHash(items []connectors.ApplyItemResult) string {
	raw, err := json.Marshal(items)
	if err != nil {
		// Degenerate case — items contain something un-marshallable.
		// We fall back to hashing a constant so the result is at least
		// deterministic and obviously distinct from a real hash.
		raw = []byte("postgres-apply-summary-marshal-error")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
