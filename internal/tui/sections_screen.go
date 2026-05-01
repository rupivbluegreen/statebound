package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"statebound.dev/statebound/internal/storage"
)

// sectionEntry is one row in the top-level sections list.
type sectionEntry struct {
	name      string
	phase     string // human-readable phase note shown when a section is not yet implemented
	available bool   // when true, selecting the row navigates; otherwise emits a status message
}

// topLevelSections lists the navigable sections of the TUI in the order
// defined by the project spec section 11. For Phase 1, only Products is
// fully navigable; the rest report which phase will deliver them.
var topLevelSections = []sectionEntry{
	{name: "Products", phase: "Phase 1", available: true},
	{name: "Assets", phase: "Phase 1"},
	{name: "Asset Scopes", phase: "Phase 1"},
	{name: "Entitlements", phase: "Phase 1"},
	{name: "Service Accounts", phase: "Phase 1"},
	{name: "Global Objects", phase: "Phase 1"},
	{name: "Authorizations", phase: "Phase 1"},
	{name: "Change Sets", phase: "Phase 2", available: true},
	{name: "Approvals", phase: "Phase 2", available: true},
	{name: "Plans", phase: "Phase 4", available: true},
	{name: "Drift Findings", phase: "Phase 4'", available: true},
	{name: "Evidence Packs", phase: "Phase 3", available: true},
	{name: "Connectors", phase: "Phase 4"},
	{name: "Audit Log", phase: "Phase 2"},
	{name: "Policy", phase: "Phase 2"},
}

// sectionsScreen is the top-level menu of the TUI. It shows the canonical
// section list with a status hint per row and routes the cursor to a child
// screen when a row is selected.
type sectionsScreen struct {
	store  storage.Storage
	cursor int
}

func newSectionsScreen(store storage.Storage) sectionsScreen {
	return sectionsScreen{store: store}
}

func (s sectionsScreen) Title() string { return "Sections" }

func (s sectionsScreen) Init() tea.Cmd { return nil }

func (s sectionsScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	switch key.String() {
	case "up", "k":
		if s.cursor > 0 {
			s.cursor--
		}
		return s, nil
	case "down", "j":
		if s.cursor < len(topLevelSections)-1 {
			s.cursor++
		}
		return s, nil
	case "home", "g":
		s.cursor = 0
		return s, nil
	case "end", "G":
		s.cursor = len(topLevelSections) - 1
		return s, nil
	case "enter", "right", "l":
		entry := topLevelSections[s.cursor]
		if !entry.available {
			return s, func() tea.Msg {
				return statusMsg{
					text: fmt.Sprintf("Section %q arrives in %s (per the project roadmap)", entry.name, entry.phase),
				}
			}
		}
		// Phase 1 wires Products; Phase 2 wave A adds Change Sets and Approvals.
		switch entry.name {
		case "Products":
			next := newProductsScreen(s.store)
			return s, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		case "Change Sets":
			next := newChangeSetsScreen(s.store)
			return s, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		case "Approvals":
			next := newApprovalsScreen(s.store)
			return s, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		case "Evidence Packs":
			next := newEvidenceScreen(s.store)
			return s, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		case "Plans":
			next := newPlansScreen(s.store)
			return s, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		case "Drift Findings":
			next := newDriftScreen(s.store)
			return s, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		}
		return s, nil
	}
	return s, nil
}

func (s sectionsScreen) View() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Top-level sections"))
	b.WriteString("\n\n")

	for i, entry := range topLevelSections {
		marker := "  "
		if i == s.cursor {
			marker = "> "
		}
		row := fmt.Sprintf("%s%-20s  %s", marker, entry.name, sectionStatus(entry))
		if i == s.cursor {
			b.WriteString(selectedRowStyle.Render(row))
		} else if entry.available {
			b.WriteString(rowStyle.Render(row))
		} else {
			b.WriteString(dimStyle.Render(row))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("up/down or j/k to move; enter to open; q/esc to quit"))
	return b.String()
}

// sectionStatus formats the right-hand status hint per row.
func sectionStatus(e sectionEntry) string {
	if e.available {
		return "ready"
	}
	return fmt.Sprintf("(%s+)", e.phase)
}

// ensureContext returns a background context. Centralising the helper makes
// it easy to swap in a request-scoped one later without touching every screen.
func ensureContext() context.Context {
	return context.Background()
}
