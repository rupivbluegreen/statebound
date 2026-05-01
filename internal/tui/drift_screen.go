package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// driftListLimit caps the table size; matches the spec guidance for the
// section view (newest 50). Stays in lock-step with planListLimit so the
// two top-level browsers behave the same.
const driftListLimit = 50

// driftScansLoadedMsg carries the result of fanning ListDriftScansByProduct
// out over every product. The screen flattens the per-product slices into
// one global, StartedAt-descending list.
type driftScansLoadedMsg struct {
	scans []*domain.DriftScan
}

// driftFindingsLoadedMsg carries the findings list for a specific scan.
type driftFindingsLoadedMsg struct {
	scanID   domain.ID
	findings []*domain.DriftFinding
}

// driftScreen lists drift scans across all products, newest first. Press
// Enter on a row to open the detail view (scan metadata + findings table).
type driftScreen struct {
	store storage.Storage

	scans        []*domain.DriftScan
	productNames map[domain.ID]string

	cursor  int
	loading bool
	loadErr error
}

func newDriftScreen(store storage.Storage) driftScreen {
	return driftScreen{
		store:        store,
		loading:      store != nil,
		productNames: map[domain.ID]string{},
	}
}

func (s driftScreen) Title() string { return "Drift Findings" }

func (s driftScreen) Init() tea.Cmd {
	if s.store == nil {
		return nil
	}
	return tea.Batch(
		loadDriftScansCmd(s.store),
		loadProductNamesCmd(s.store),
	)
}

func (s driftScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case driftScansLoadedMsg:
		s.scans = sortDriftScansDesc(msg.scans)
		s.loading = false
		s.loadErr = nil
		if s.cursor >= len(s.scans) {
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
			if s.cursor < len(s.scans)-1 {
				s.cursor++
			}
			return s, nil
		case "home", "g":
			s.cursor = 0
			return s, nil
		case "end", "G":
			if n := len(s.scans); n > 0 {
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
				loadDriftScansCmd(s.store),
				loadProductNamesCmd(s.store),
			)
		case "enter", "right", "l":
			if len(s.scans) == 0 {
				return s, nil
			}
			scan := s.scans[s.cursor]
			next := newDriftDetailScreen(s.store, scan, s.productNames[scan.ProductID])
			return s, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		}
	}
	return s, nil
}

func (s driftScreen) View() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Drift Findings"))
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
	if len(s.scans) == 0 {
		b.WriteString(dimStyle.Render("No drift scans yet. Run `statebound drift scan --product <name> --connector <name> --source <path>` to create one."))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render("r to refresh, q/esc to go back"))
		return b.String()
	}

	header := fmt.Sprintf("  %-10s  %-20s  %-14s  %-10s  %-8s  %-19s",
		"ID", "PRODUCT", "CONNECTOR", "STATE", "FINDINGS", "STARTED_AT")
	b.WriteString(dimStyle.Render(header))
	b.WriteString("\n")

	for i, scan := range s.scans {
		marker := "  "
		if i == s.cursor {
			marker = "> "
		}
		productName := s.productNames[scan.ProductID]
		if productName == "" {
			productName = shortID(scan.ProductID)
		}
		row := fmt.Sprintf("%s%-10s  %-20s  %-14s  %-10s  %-8d  %-19s",
			marker,
			shortID(scan.ID),
			truncate(productName, 20),
			truncate(scan.ConnectorName, 14),
			truncate(string(scan.State), 10),
			scan.FindingCount,
			scan.StartedAt.UTC().Format("2006-01-02 15:04:05"),
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

// loadDriftScansCmd lists every product, then fans ListDriftScansByProduct
// over each to build a global scan list. We list products first so an
// empty product table yields an empty scan list rather than a misleading
// error.
func loadDriftScansCmd(store storage.Storage) tea.Cmd {
	return func() tea.Msg {
		ctx := ensureContext()
		products, err := store.ListProducts(ctx)
		if err != nil {
			return errMsg{err: err}
		}
		var all []*domain.DriftScan
		for _, p := range products {
			if p == nil {
				continue
			}
			scans, err := store.ListDriftScansByProduct(ctx, p.ID, driftListLimit)
			if err != nil {
				return errMsg{err: err}
			}
			all = append(all, scans...)
		}
		return driftScansLoadedMsg{scans: all}
	}
}

// sortDriftScansDesc orders scans by StartedAt descending (newest first),
// then by ID for stability when two scans share a timestamp.
func sortDriftScansDesc(in []*domain.DriftScan) []*domain.DriftScan {
	out := append([]*domain.DriftScan(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].StartedAt.UTC(), out[j].StartedAt.UTC()
		if !ai.Equal(aj) {
			return ai.After(aj)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > driftListLimit {
		out = out[:driftListLimit]
	}
	return out
}

// driftDetailScreen renders one scan's metadata and findings table.
// Read-only; there is no state-machine transition surface here yet (the
// scan is already terminal by the time it reaches this screen).
type driftDetailScreen struct {
	store       storage.Storage
	scan        *domain.DriftScan
	productName string

	findings []*domain.DriftFinding
	loading  bool
	loadErr  error
}

func newDriftDetailScreen(store storage.Storage, scan *domain.DriftScan, productName string) driftDetailScreen {
	return driftDetailScreen{
		store:       store,
		scan:        scan,
		productName: productName,
		loading:     scan != nil && store != nil,
	}
}

func (s driftDetailScreen) Title() string {
	if s.scan == nil {
		return "Drift Scan"
	}
	return fmt.Sprintf("Drift Scan %s", shortID(s.scan.ID))
}

func (s driftDetailScreen) Init() tea.Cmd {
	if s.scan == nil || s.store == nil {
		return nil
	}
	return loadDriftFindingsCmd(s.store, s.scan.ID)
}

func (s driftDetailScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case driftFindingsLoadedMsg:
		if s.scan != nil && msg.scanID == s.scan.ID {
			s.findings = msg.findings
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

func (s driftDetailScreen) View() string {
	var b strings.Builder
	if s.scan == nil {
		b.WriteString(errorStyle.Render("missing scan"))
		return b.String()
	}
	productName := s.productName
	if productName == "" {
		productName = shortID(s.scan.ProductID)
	}
	b.WriteString(sectionHeaderStyle.Render(
		fmt.Sprintf("Drift Scan — %s v%d via %s", productName, s.scan.Sequence, s.scan.ConnectorName)))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "  ID:                  %s\n", s.scan.ID)
	fmt.Fprintf(&b, "  State:               %s\n", s.scan.State)
	fmt.Fprintf(&b, "  Connector:           %s (v%s)\n", s.scan.ConnectorName, s.scan.ConnectorVersion)
	fmt.Fprintf(&b, "  Source ref:          %s\n", s.scan.SourceRef)
	fmt.Fprintf(&b, "  Approved version id: %s\n", s.scan.ApprovedVersionID)
	fmt.Fprintf(&b, "  Started at:          %s\n", s.scan.StartedAt.UTC().Format("2006-01-02T15:04:05Z"))
	if s.scan.FinishedAt != nil {
		fmt.Fprintf(&b, "  Finished at:         %s\n", s.scan.FinishedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	fmt.Fprintf(&b, "  Initiated by:        %s (%s)\n", s.scan.InitiatedBy.Subject, s.scan.InitiatedBy.Kind)
	if s.scan.SummaryHash != "" {
		fmt.Fprintf(&b, "  Summary hash:        %s\n", s.scan.SummaryHash)
	}
	fmt.Fprintf(&b, "  Finding count:       %d\n", s.scan.FindingCount)
	if s.scan.FailureMessage != "" {
		fmt.Fprintf(&b, "  Failure message:     %s\n", s.scan.FailureMessage)
	}
	b.WriteString("\n")

	if s.loading {
		b.WriteString(dimStyle.Render("  loading findings..."))
	} else if s.loadErr != nil {
		b.WriteString(errorStyle.Render("  error: " + s.loadErr.Error()))
	} else if len(s.findings) == 0 {
		b.WriteString(dimStyle.Render("  no findings"))
	} else {
		header := fmt.Sprintf("  %-3s  %-10s  %-9s  %-25s  %-30s  %s",
			"#", "KIND", "SEVERITY", "RESOURCE_KIND", "RESOURCE_REF", "MESSAGE")
		b.WriteString(dimStyle.Render(header))
		b.WriteString("\n")
		for _, f := range s.findings {
			if f == nil {
				continue
			}
			row := fmt.Sprintf("  %-3d  %-10s  %-9s  %-25s  %-30s  %s",
				f.Sequence,
				truncate(string(f.Kind), 10),
				truncate(string(f.Severity), 9),
				truncate(f.ResourceKind, 25),
				truncate(f.ResourceRef, 30),
				truncate(f.Message, 60),
			)
			b.WriteString(rowStyle.Render(row))
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("q/esc to go back"))
	return b.String()
}

// loadDriftFindingsCmd issues GetDriftScanByID solely for the findings
// slice — the scan header is already rendered from the parent screen's
// cached row.
func loadDriftFindingsCmd(store storage.Storage, scanID domain.ID) tea.Cmd {
	return func() tea.Msg {
		_, findings, err := store.GetDriftScanByID(ensureContext(), scanID)
		if err != nil {
			return errMsg{err: err}
		}
		return driftFindingsLoadedMsg{scanID: scanID, findings: findings}
	}
}
