// Package tui hosts the Bubble Tea model for the statebound TUI.
//
// Phase 0 ships only a centered placeholder screen with the planned
// top-level sections. Later phases replace this with paneled views over
// the domain types, but every later phase keeps the same Model type so
// the cmd/cli wiring does not need to change.
package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Model is the Bubble Tea model for the Phase 0 placeholder TUI.
// It tracks only window dimensions and a status string; later phases
// will extend it with panes, focus state, and a Storage handle.
type Model struct {
	width  int
	height int
	status string
}

// NewModel constructs the initial Model. Bubble Tea idiom returns a value,
// not a pointer.
func NewModel() Model {
	return Model{
		status: "ready",
	}
}

// sections lists the planned top-level TUI views from the project spec §11.
// Reasoning-add-on-only sections (Inference Backends, Agents, Agent
// Invocations) are intentionally omitted from the core placeholder.
var sections = []string{
	"Products",
	"Assets",
	"Asset Scopes",
	"Entitlements",
	"Service Accounts",
	"Global Objects",
	"Authorizations",
	"Change Sets",
	"Approvals",
	"Plans",
	"Drift Findings",
	"Evidence Packs",
	"Connectors",
	"Audit Log",
	"Policy",
}

// Init satisfies tea.Model. Phase 0 has no startup commands.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles input messages. Phase 0 only handles quit keys and
// window resizes.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		}
	}
	return m, nil
}

// View renders the placeholder screen.
func (m Model) View() string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("63")).
		Padding(0, 1)

	subtitleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("244")).
		Italic(true).
		Padding(0, 1)

	sectionHeaderStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("69")).
		Padding(1, 0, 0, 0)

	sectionItemStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("252")).
		Padding(0, 2)

	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Italic(true).
		Padding(1, 0, 0, 0)

	var b strings.Builder
	b.WriteString(titleStyle.Render("Statebound"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("Authorization governance control plane"))
	b.WriteString("\n")
	b.WriteString(sectionHeaderStyle.Render("Planned sections:"))
	b.WriteString("\n")
	for _, s := range sections {
		b.WriteString(sectionItemStyle.Render("- " + s))
		b.WriteString("\n")
	}
	b.WriteString(footerStyle.Render("Phase 0 placeholder. Press q or Ctrl+C to quit."))

	body := b.String()

	if m.width <= 0 || m.height <= 0 {
		return body
	}
	return lipgloss.Place(m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		body)
}
