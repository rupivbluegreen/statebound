package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// changeSetsScopeSubmitted tags the submitted-only ListChangeSets result so
// it cannot be confused with the all-states list issued from changeSetsScreen.
const changeSetsScopeSubmitted = "submitted"

// approvalsScreen lists ChangeSets in Submitted state across all products.
// It loads asynchronously on Init and pushes the shared change-set detail
// screen on Enter.
type approvalsScreen struct {
	store storage.Storage

	pending      []*domain.ChangeSet
	productNames map[domain.ID]string

	cursor  int
	loading bool
	loadErr error
}

func newApprovalsScreen(store storage.Storage) approvalsScreen {
	return approvalsScreen{
		store:        store,
		loading:      store != nil,
		productNames: map[domain.ID]string{},
	}
}

func (s approvalsScreen) Title() string { return "Approvals" }

func (s approvalsScreen) Init() tea.Cmd {
	if s.store == nil {
		return nil
	}
	submitted := domain.ChangeSetStateSubmitted
	return tea.Batch(
		loadChangeSetsCmd(s.store, changeSetsScopeSubmitted, storage.ChangeSetFilter{
			State: &submitted,
			Limit: 200,
		}),
		loadProductNamesCmd(s.store),
	)
}

func (s approvalsScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case changeSetsLoadedMsg:
		if msg.scope != changeSetsScopeSubmitted {
			return s, nil
		}
		s.pending = sortChangeSetsDesc(msg.changeSets)
		s.loading = false
		s.loadErr = nil
		if s.cursor >= len(s.pending) {
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
			if s.cursor < len(s.pending)-1 {
				s.cursor++
			}
			return s, nil
		case "home", "g":
			s.cursor = 0
			return s, nil
		case "end", "G":
			if n := len(s.pending); n > 0 {
				s.cursor = n - 1
			}
			return s, nil
		case "r":
			if s.store == nil {
				return s, nil
			}
			s.loading = true
			s.loadErr = nil
			submitted := domain.ChangeSetStateSubmitted
			return s, tea.Batch(
				loadChangeSetsCmd(s.store, changeSetsScopeSubmitted, storage.ChangeSetFilter{
					State: &submitted,
					Limit: 200,
				}),
				loadProductNamesCmd(s.store),
			)
		case "enter", "right", "l":
			if len(s.pending) == 0 {
				return s, nil
			}
			selected := s.pending[s.cursor]
			next := newChangeSetDetailScreen(s.store, selected, s.productNames[selected.ProductID])
			return s, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		}
	}
	return s, nil
}

func (s approvalsScreen) View() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Pending Approvals"))
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
	if len(s.pending) == 0 {
		b.WriteString(dimStyle.Render("No pending approvals."))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render("r to refresh, q/esc to go back"))
		return b.String()
	}

	header := fmt.Sprintf("  %-20s  %-30s  %-20s  %-19s", "PRODUCT", "TITLE", "REQUESTED_BY", "SUBMITTED")
	b.WriteString(dimStyle.Render(header))
	b.WriteString("\n")

	for i, cs := range s.pending {
		marker := "  "
		if i == s.cursor {
			marker = "> "
		}
		productName := s.productNames[cs.ProductID]
		if productName == "" {
			productName = shortID(cs.ProductID)
		}
		submitted := "-"
		if cs.SubmittedAt != nil {
			submitted = cs.SubmittedAt.UTC().Format("2006-01-02 15:04:05")
		}
		row := fmt.Sprintf("%s%-20s  %-30s  %-20s  %-19s",
			marker,
			truncate(productName, 20),
			truncate(cs.Title, 30),
			truncate(cs.RequestedBy.Subject, 20),
			submitted,
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
