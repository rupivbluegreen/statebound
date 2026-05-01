package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// planListLimit caps the table size; matches the spec guidance for the
// section view (newest 50).
const planListLimit = 50

// plansLoadedMsg carries the result of fanning ListPlansByProduct out over
// every product. The screen flattens the per-product slices into one
// global, GeneratedAt-descending list.
type plansLoadedMsg struct {
	plans []*domain.Plan
}

// plansScreen lists plans across all products, newest first. Press Enter
// on a row to open the detail view (summary, refused_reason, item count,
// first ~50 lines of content).
type plansScreen struct {
	store storage.Storage

	plans        []*domain.Plan
	productNames map[domain.ID]string

	cursor  int
	loading bool
	loadErr error
}

func newPlansScreen(store storage.Storage) plansScreen {
	return plansScreen{
		store:        store,
		loading:      store != nil,
		productNames: map[domain.ID]string{},
	}
}

func (s plansScreen) Title() string { return "Plans" }

func (s plansScreen) Init() tea.Cmd {
	if s.store == nil {
		return nil
	}
	return tea.Batch(
		loadPlansCmd(s.store),
		loadProductNamesCmd(s.store),
	)
}

func (s plansScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case plansLoadedMsg:
		s.plans = sortPlansDesc(msg.plans)
		s.loading = false
		s.loadErr = nil
		if s.cursor >= len(s.plans) {
			s.cursor = 0
		}
		return s, nil
	case productNamesLoadedMsg:
		if msg.names != nil {
			s.productNames = msg.names
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
			if s.cursor < len(s.plans)-1 {
				s.cursor++
			}
			return s, nil
		case "home", "g":
			s.cursor = 0
			return s, nil
		case "end", "G":
			if n := len(s.plans); n > 0 {
				s.cursor = n - 1
			}
			return s, nil
		case "r":
			if s.store == nil {
				return s, nil
			}
			s.loading = true
			s.loadErr = nil
			return s, tea.Batch(
				loadPlansCmd(s.store),
				loadProductNamesCmd(s.store),
			)
		case "enter", "right", "l":
			if len(s.plans) == 0 {
				return s, nil
			}
			plan := s.plans[s.cursor]
			next := newPlanDetailScreen(s.store, plan, s.productNames[plan.ProductID])
			return s, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		}
	}
	return s, nil
}

func (s plansScreen) View() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Plans"))
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
	if len(s.plans) == 0 {
		b.WriteString(dimStyle.Render("No plans yet. Run `statebound plan --product <name> --connector <name>` to create one."))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render("r to refresh, q/esc to go back"))
		return b.String()
	}

	header := fmt.Sprintf("  %-10s  %-20s  %-7s  %-14s  %-8s  %-14s  %-19s",
		"ID", "PRODUCT", "VERSION", "CONNECTOR", "STATE", "HASH", "GENERATED_AT")
	b.WriteString(dimStyle.Render(header))
	b.WriteString("\n")

	for i, p := range s.plans {
		marker := "  "
		if i == s.cursor {
			marker = "> "
		}
		productName := s.productNames[p.ProductID]
		if productName == "" {
			productName = shortID(p.ProductID)
		}
		row := fmt.Sprintf("%s%-10s  %-20s  v%-6d  %-14s  %-8s  %-14s  %-19s",
			marker,
			shortID(p.ID),
			truncate(productName, 20),
			p.Sequence,
			truncate(p.ConnectorName, 14),
			truncate(string(p.State), 8),
			truncate(p.ContentHash, 14),
			p.GeneratedAt.UTC().Format("2006-01-02 15:04:05"),
		)
		if i == s.cursor {
			b.WriteString(selectedRowStyle.Render(row))
		} else {
			b.WriteString(rowStyle.Render(row))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("enter to open; r to refresh; q/esc to go back"))
	return b.String()
}

// loadPlansCmd lists every product, then fans ListPlansByProduct over each
// to build a global plan list. We list products first so an empty product
// table yields an empty plan list rather than a misleading error.
func loadPlansCmd(store storage.Storage) tea.Cmd {
	return func() tea.Msg {
		ctx := ensureContext()
		products, err := store.ListProducts(ctx)
		if err != nil {
			return errMsg{err: err}
		}
		var all []*domain.Plan
		for _, p := range products {
			if p == nil {
				continue
			}
			plans, err := store.ListPlansByProduct(ctx, p.ID, planListLimit)
			if err != nil {
				return errMsg{err: err}
			}
			all = append(all, plans...)
		}
		return plansLoadedMsg{plans: all}
	}
}

// sortPlansDesc orders plans by GeneratedAt descending (newest first), then
// by ID for stability when two plans share a timestamp.
func sortPlansDesc(in []*domain.Plan) []*domain.Plan {
	out := append([]*domain.Plan(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].GeneratedAt.UTC(), out[j].GeneratedAt.UTC()
		if !ai.Equal(aj) {
			return ai.After(aj)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > planListLimit {
		out = out[:planListLimit]
	}
	return out
}

// planItemsLoadedMsg carries the items list for a specific Plan.
type planItemsLoadedMsg struct {
	planID domain.ID
	items  []*domain.PlanItem
}

// planDetailScreen renders one plan's metadata, refused_reason, item count,
// and the first detailContentLineLimit lines of the persisted content blob.
// Read-only; there is no state-machine transition surface here yet (Apply
// arrives in Phase 6+).
type planDetailScreen struct {
	store       storage.Storage
	plan        *domain.Plan
	productName string

	items   []*domain.PlanItem
	loading bool
	loadErr error
}

func newPlanDetailScreen(store storage.Storage, plan *domain.Plan, productName string) planDetailScreen {
	return planDetailScreen{
		store:       store,
		plan:        plan,
		productName: productName,
		loading:     plan != nil && store != nil,
	}
}

func (s planDetailScreen) Title() string {
	if s.plan == nil {
		return "Plan"
	}
	return fmt.Sprintf("Plan %s", shortID(s.plan.ID))
}

func (s planDetailScreen) Init() tea.Cmd {
	if s.plan == nil || s.store == nil {
		return nil
	}
	return loadPlanItemsCmd(s.store, s.plan.ID)
}

func (s planDetailScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case planItemsLoadedMsg:
		if s.plan != nil && msg.planID == s.plan.ID {
			s.items = msg.items
			s.loading = false
		}
		return s, nil
	case errMsg:
		s.loading = false
		s.loadErr = msg.err
		return s, nil
	case tea.KeyMsg:
		// No mutating actions; let the model-level esc/q handle navigation.
		return s, nil
	}
	return s, nil
}

func (s planDetailScreen) View() string {
	var b strings.Builder
	if s.plan == nil {
		b.WriteString(errorStyle.Render("missing plan"))
		return b.String()
	}
	productName := s.productName
	if productName == "" {
		productName = shortID(s.plan.ProductID)
	}
	b.WriteString(sectionHeaderStyle.Render(
		fmt.Sprintf("Plan — %s v%d via %s", productName, s.plan.Sequence, s.plan.ConnectorName)))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "  ID:                  %s\n", s.plan.ID)
	fmt.Fprintf(&b, "  State:               %s\n", s.plan.State)
	fmt.Fprintf(&b, "  Connector:           %s (v%s)\n", s.plan.ConnectorName, s.plan.ConnectorVersion)
	fmt.Fprintf(&b, "  Approved version id: %s\n", s.plan.ApprovedVersionID)
	fmt.Fprintf(&b, "  Content hash:        sha256:%s\n", s.plan.ContentHash)
	fmt.Fprintf(&b, "  Summary:             %s\n", s.plan.Summary)
	fmt.Fprintf(&b, "  Generated at:        %s\n", s.plan.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "  Generated by:        %s (%s)\n", s.plan.GeneratedBy.Subject, s.plan.GeneratedBy.Kind)
	if s.plan.RefusedReason != "" {
		fmt.Fprintf(&b, "  Refused reason:      %s\n", s.plan.RefusedReason)
	}
	if s.loading {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  loading items..."))
	} else if s.loadErr != nil {
		b.WriteString("\n")
		b.WriteString(errorStyle.Render("  error: " + s.loadErr.Error()))
	} else {
		fmt.Fprintf(&b, "  Items:               %d\n", len(s.items))
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(fmt.Sprintf("  --- content (first %d lines) ---", detailContentLineLimit)))
	b.WriteString("\n")
	for _, line := range firstNLines(string(s.plan.Content), detailContentLineLimit) {
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("q/esc to go back"))
	return b.String()
}

// loadPlanItemsCmd issues GetPlanByID solely for the items slice — the plan
// header is already rendered from the parent screen's cached row.
func loadPlanItemsCmd(store storage.Storage, planID domain.ID) tea.Cmd {
	return func() tea.Msg {
		_, items, err := store.GetPlanByID(ensureContext(), planID)
		if err != nil {
			return errMsg{err: err}
		}
		return planItemsLoadedMsg{planID: planID, items: items}
	}
}
