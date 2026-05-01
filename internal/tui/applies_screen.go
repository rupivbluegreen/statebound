package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// applyListLimit caps the table size; matches the spec guidance for the
// section view (newest 50). Stays in lock-step with planListLimit and
// driftListLimit so the three top-level browsers behave the same.
const applyListLimit = 50

// applyRecordsLoadedMsg carries the result of fanning
// ListPlanApplyRecordsByPlan out over every plan. The screen flattens
// the per-plan slices into one global, StartedAt-descending list.
type applyRecordsLoadedMsg struct {
	records []*domain.PlanApplyRecord
}

// appliesScreen lists PlanApplyRecord rows across all plans, newest
// first. Read-only — apply itself is a CLI action; this screen is just
// a browser so an operator can see what was applied (and what failed)
// alongside the rest of the audit story.
type appliesScreen struct {
	store storage.Storage

	records []*domain.PlanApplyRecord

	cursor  int
	loading bool
	loadErr error
}

func newAppliesScreen(store storage.Storage) appliesScreen {
	return appliesScreen{
		store:   store,
		loading: store != nil,
	}
}

func (s appliesScreen) Title() string { return "Apply Records" }

func (s appliesScreen) Init() tea.Cmd {
	if s.store == nil {
		return nil
	}
	return loadApplyRecordsCmd(s.store)
}

func (s appliesScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case applyRecordsLoadedMsg:
		s.records = sortApplyRecordsDesc(msg.records)
		s.loading = false
		s.loadErr = nil
		if s.cursor >= len(s.records) {
			s.cursor = 0
		}
		return s, nil
	case errMsg:
		s.loading = false
		s.loadErr = msg.err
		return s, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if s.cursor > 0 {
				s.cursor--
			}
			return s, nil
		case "down", "j":
			if s.cursor < len(s.records)-1 {
				s.cursor++
			}
			return s, nil
		case "home", "g":
			s.cursor = 0
			return s, nil
		case "end", "G":
			if n := len(s.records); n > 0 {
				s.cursor = n - 1
			}
			return s, nil
		case "r":
			if s.store == nil {
				return s, nil
			}
			s.loading = true
			s.loadErr = nil
			return s, loadApplyRecordsCmd(s.store)
		}
	}
	return s, nil
}

func (s appliesScreen) View() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Apply Records"))
	b.WriteString("\n\n")

	if s.store == nil {
		b.WriteString(errorStyle.Render("no database connected"))
		b.WriteString("\n")
		b.WriteString(helpStyle.Render("set --db-dsn or STATEBOUND_DB_DSN, then relaunch"))
		return b.String()
	}
	if s.loading {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	if s.loadErr != nil {
		b.WriteString(errorStyle.Render("error: " + s.loadErr.Error()))
		b.WriteString("\n")
		b.WriteString(helpStyle.Render("press r to retry, q/esc to go back"))
		return b.String()
	}
	if len(s.records) == 0 {
		b.WriteString(dimStyle.Render("No apply records yet. Run `statebound apply <plan-id> --dry-run` to preview an apply."))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render("r to refresh, q/esc to go back"))
		return b.String()
	}

	header := fmt.Sprintf("  %-10s  %-10s  %-9s  %-3s  %-7s  %-9s  %-19s",
		"ID", "PLAN", "STATE", "DRY", "APPLIED", "FAILED", "STARTED_AT")
	b.WriteString(dimStyle.Render(header))
	b.WriteString("\n")

	for i, rec := range s.records {
		marker := "  "
		if i == s.cursor {
			marker = "> "
		}
		dry := "n"
		if rec.DryRun {
			dry = "y"
		}
		row := fmt.Sprintf("%s%-10s  %-10s  %-9s  %-3s  %-7d  %-9d  %-19s",
			marker,
			shortID(rec.ID),
			shortID(rec.PlanID),
			truncate(string(rec.State), 9),
			dry,
			rec.AppliedItems,
			rec.FailedItems,
			rec.StartedAt.UTC().Format("2006-01-02 15:04:05"),
		)
		if i == s.cursor {
			b.WriteString(selectedRowStyle.Render(row))
		} else {
			b.WriteString(rowStyle.Render(row))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("r to refresh; q/esc to go back"))
	return b.String()
}

// loadApplyRecordsCmd fans ListPlanApplyRecordsByPlan over every plan in
// every product. Bigger deployments will want a dedicated
// ListPlanApplyRecordsByProduct query — but for Phase 6 the apply
// volume is bounded by deliberate operator clicks, and this loop runs
// once per screen open.
func loadApplyRecordsCmd(store storage.Storage) tea.Cmd {
	return func() tea.Msg {
		ctx := ensureContext()
		products, err := store.ListProducts(ctx)
		if err != nil {
			return errMsg{err: err}
		}
		var all []*domain.PlanApplyRecord
		for _, p := range products {
			if p == nil {
				continue
			}
			plans, err := store.ListPlansByProduct(ctx, p.ID, 0)
			if err != nil {
				return errMsg{err: err}
			}
			for _, plan := range plans {
				if plan == nil {
					continue
				}
				records, err := store.ListPlanApplyRecordsByPlan(ctx, plan.ID)
				if err != nil {
					return errMsg{err: err}
				}
				all = append(all, records...)
			}
		}
		return applyRecordsLoadedMsg{records: all}
	}
}

// sortApplyRecordsDesc orders apply records by StartedAt descending
// (newest first), with ID as a stable tiebreaker.
func sortApplyRecordsDesc(in []*domain.PlanApplyRecord) []*domain.PlanApplyRecord {
	out := append([]*domain.PlanApplyRecord(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].StartedAt.UTC(), out[j].StartedAt.UTC()
		if !ai.Equal(aj) {
			return ai.After(aj)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > applyListLimit {
		out = out[:applyListLimit]
	}
	return out
}
