package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// changeSetTab indexes the tabs in the change-set detail screen.
type changeSetTab int

const (
	csTabItems changeSetTab = iota
	csTabApprovals
)

var changeSetTabLabels = []string{"Items", "Approvals"}

// changeSetDetailScreen shows a tabbed detail view for a single ChangeSet.
// Items and Approvals are loaded lazily on first view and cached.
type changeSetDetailScreen struct {
	store       storage.Storage
	cs          *domain.ChangeSet
	productName string

	tab changeSetTab

	itemsLoaded bool
	items       []*domain.ChangeSetItem
	itemsErr    error
	itemCursor  int
	expanded    bool

	approvalsLoaded bool
	approvals       []*domain.Approval
	approvalsErr    error
	approvalCursor  int
}

func newChangeSetDetailScreen(store storage.Storage, cs *domain.ChangeSet, productName string) changeSetDetailScreen {
	return changeSetDetailScreen{
		store:       store,
		cs:          cs,
		productName: productName,
		tab:         csTabItems,
	}
}

func (s changeSetDetailScreen) Title() string {
	if s.cs == nil {
		return "Change Set"
	}
	if s.productName != "" {
		return fmt.Sprintf("CS:%s/%s", s.productName, truncate(s.cs.Title, 24))
	}
	return "CS:" + truncate(s.cs.Title, 32)
}

func (s changeSetDetailScreen) Init() tea.Cmd {
	return s.loadCmdForTab(s.tab)
}

func (s changeSetDetailScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case changeSetItemsLoadedMsg:
		if s.cs != nil && msg.changeSetID == s.cs.ID {
			s.items = msg.items
			s.itemsLoaded = true
			s.itemsErr = nil
		}
		return s, nil
	case approvalsLoadedMsg:
		if s.cs != nil && msg.changeSetID == s.cs.ID {
			s.approvals = msg.approvals
			s.approvalsLoaded = true
			s.approvalsErr = nil
		}
		return s, nil
	case errMsg:
		switch s.tab {
		case csTabItems:
			s.itemsErr = msg.err
			s.itemsLoaded = true
		case csTabApprovals:
			s.approvalsErr = msg.err
			s.approvalsLoaded = true
		}
		return s, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "1":
			return s.switchTab(csTabItems)
		case "2":
			return s.switchTab(csTabApprovals)
		case "tab", "right", "l":
			return s.switchTab((s.tab + 1) % changeSetTab(len(changeSetTabLabels)))
		case "shift+tab", "left", "h":
			next := s.tab - 1
			if next < 0 {
				next = changeSetTab(len(changeSetTabLabels)) - 1
			}
			return s.switchTab(next)
		case "up", "k":
			s.cursorUp()
			return s, nil
		case "down", "j":
			s.cursorDown()
			return s, nil
		case "home", "g":
			s.cursorHome()
			return s, nil
		case "end", "G":
			s.cursorEnd()
			return s, nil
		case "enter":
			if s.tab == csTabItems && len(s.items) > 0 {
				s.expanded = !s.expanded
			}
			return s, nil
		}
	}
	return s, nil
}

func (s *changeSetDetailScreen) cursorUp() {
	switch s.tab {
	case csTabItems:
		if s.itemCursor > 0 {
			s.itemCursor--
			s.expanded = false
		}
	case csTabApprovals:
		if s.approvalCursor > 0 {
			s.approvalCursor--
		}
	}
}

func (s *changeSetDetailScreen) cursorDown() {
	switch s.tab {
	case csTabItems:
		if s.itemCursor < len(s.items)-1 {
			s.itemCursor++
			s.expanded = false
		}
	case csTabApprovals:
		if s.approvalCursor < len(s.approvals)-1 {
			s.approvalCursor++
		}
	}
}

func (s *changeSetDetailScreen) cursorHome() {
	switch s.tab {
	case csTabItems:
		s.itemCursor = 0
		s.expanded = false
	case csTabApprovals:
		s.approvalCursor = 0
	}
}

func (s *changeSetDetailScreen) cursorEnd() {
	switch s.tab {
	case csTabItems:
		if n := len(s.items); n > 0 {
			s.itemCursor = n - 1
			s.expanded = false
		}
	case csTabApprovals:
		if n := len(s.approvals); n > 0 {
			s.approvalCursor = n - 1
		}
	}
}

func (s changeSetDetailScreen) switchTab(t changeSetTab) (screen, tea.Cmd) {
	s.tab = t
	s.expanded = false
	return s, s.loadCmdForTab(t)
}

func (s changeSetDetailScreen) loadCmdForTab(t changeSetTab) tea.Cmd {
	if s.store == nil || s.cs == nil {
		return nil
	}
	csID := s.cs.ID
	switch t {
	case csTabItems:
		if s.itemsLoaded {
			return nil
		}
		return func() tea.Msg {
			items, err := s.store.ListChangeSetItems(ensureContext(), csID)
			if err != nil {
				return errMsg{err: err}
			}
			return changeSetItemsLoadedMsg{changeSetID: csID, items: items}
		}
	case csTabApprovals:
		if s.approvalsLoaded {
			return nil
		}
		return func() tea.Msg {
			as, err := s.store.ListApprovalsByChangeSet(ensureContext(), csID)
			if err != nil {
				return errMsg{err: err}
			}
			return approvalsLoadedMsg{changeSetID: csID, approvals: as}
		}
	}
	return nil
}

func (s changeSetDetailScreen) View() string {
	if s.cs == nil {
		return errorStyle.Render("no change set selected")
	}
	var b strings.Builder
	b.WriteString(s.renderHeader())
	b.WriteString("\n")
	b.WriteString(s.renderTabStrip())
	b.WriteString("\n\n")
	if s.store == nil {
		b.WriteString(errorStyle.Render("no database connected"))
		return b.String()
	}
	switch s.tab {
	case csTabItems:
		b.WriteString(s.viewItems())
	case csTabApprovals:
		b.WriteString(s.viewApprovals())
	}
	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("1/2 to switch tabs; tab/shift+tab to cycle; enter expands a diff item; q/esc to go back"))
	return b.String()
}

func (s changeSetDetailScreen) renderHeader() string {
	var b strings.Builder
	badge := renderStateBadge(s.cs.State, len(stateLabel(s.cs.State)))
	productLabel := s.productName
	if productLabel == "" {
		productLabel = shortID(s.cs.ProductID)
	}

	b.WriteString(badge)
	b.WriteString("  ")
	b.WriteString(sectionHeaderStyle.Render(s.cs.Title))
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("Product:        %s\n", productLabel))
	desc := s.cs.Description
	if desc == "" {
		desc = dimStyle.Render("(no description)")
	}
	b.WriteString(fmt.Sprintf("Description:    %s\n", desc))
	b.WriteString(fmt.Sprintf("Requested by:   %s (%s)\n", s.cs.RequestedBy.Subject, s.cs.RequestedBy.Kind))
	parent := "none"
	if s.cs.ParentApprovedVersionID != nil {
		parent = string(*s.cs.ParentApprovedVersionID)
	}
	b.WriteString(fmt.Sprintf("Parent version: %s\n", parent))
	b.WriteString(fmt.Sprintf("Created:        %s\n", s.cs.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC")))
	if s.cs.SubmittedAt != nil {
		b.WriteString(fmt.Sprintf("Submitted:      %s\n", s.cs.SubmittedAt.UTC().Format("2006-01-02 15:04:05 UTC")))
	}
	if s.cs.DecidedAt != nil {
		b.WriteString(fmt.Sprintf("Decided:        %s\n", s.cs.DecidedAt.UTC().Format("2006-01-02 15:04:05 UTC")))
	}
	if s.cs.DecisionReason != "" {
		b.WriteString(fmt.Sprintf("Reason:         %s\n", s.cs.DecisionReason))
	}
	return strings.TrimRight(b.String(), "\n")
}

func (s changeSetDetailScreen) renderTabStrip() string {
	var parts []string
	for i, label := range changeSetTabLabels {
		text := fmt.Sprintf("%d %s", i+1, label)
		if changeSetTab(i) == s.tab {
			parts = append(parts, tabActiveStyle.Render(text))
		} else {
			parts = append(parts, tabInactiveStyle.Render(text))
		}
	}
	return strings.Join(parts, " ")
}

func (s changeSetDetailScreen) viewItems() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Items"))
	b.WriteString("\n\n")
	if s.itemsErr != nil {
		b.WriteString(errorStyle.Render("error: " + s.itemsErr.Error()))
		return b.String()
	}
	if !s.itemsLoaded {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	if len(s.items) == 0 {
		b.WriteString(dimStyle.Render("(no items)"))
		return b.String()
	}

	sorted := sortItemsForDisplay(s.items)
	for i, it := range sorted {
		marker := "  "
		if i == s.itemCursor {
			marker = "> "
		}
		row := fmt.Sprintf("%s%s %-15s %s", marker, actionSign(it.Action), string(it.Kind), it.ResourceName)
		styled := styleForAction(it.Action).Render(row)
		if i == s.itemCursor {
			b.WriteString(selectedRowStyle.Render(row))
		} else {
			b.WriteString(styled)
		}
		b.WriteString("\n")
		if i == s.itemCursor && s.expanded {
			b.WriteString("\n")
			b.WriteString(RenderDiffItems([]*domain.ChangeSetItem{it}, 80))
			b.WriteString("\n\n")
		}
	}
	return b.String()
}

func (s changeSetDetailScreen) viewApprovals() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Approvals"))
	b.WriteString("\n\n")
	if s.approvalsErr != nil {
		b.WriteString(errorStyle.Render("error: " + s.approvalsErr.Error()))
		return b.String()
	}
	if !s.approvalsLoaded {
		b.WriteString(dimStyle.Render("loading..."))
		return b.String()
	}
	if len(s.approvals) == 0 {
		b.WriteString(dimStyle.Render("(no approvals yet)"))
		return b.String()
	}
	for i, a := range s.approvals {
		marker := "  "
		if i == s.approvalCursor {
			marker = "> "
		}
		decisionLabel := strings.ToUpper(string(a.Decision))
		var decision string
		switch a.Decision {
		case domain.ApprovalDecisionApproved:
			decision = approvedStyle.Render(decisionLabel)
		case domain.ApprovalDecisionRejected:
			decision = rejectedStyle.Render(decisionLabel)
		default:
			decision = dimStyle.Render(decisionLabel)
		}
		header := fmt.Sprintf("%s%s  %s (%s)  %s",
			marker,
			decision,
			a.Approver.Subject,
			a.Approver.Kind,
			a.DecidedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		)
		if i == s.approvalCursor {
			b.WriteString(selectedRowStyle.Render(header))
		} else {
			b.WriteString(rowStyle.Render(header))
		}
		b.WriteString("\n")
		if a.Reason != "" {
			b.WriteString(rowStyle.Render("    reason: " + a.Reason))
			b.WriteString("\n")
		}
	}
	return b.String()
}

// sortItemsForDisplay returns items ordered by (Kind, ResourceName) using the
// canonical kind order from the diff renderer.
func sortItemsForDisplay(items []*domain.ChangeSetItem) []*domain.ChangeSetItem {
	rank := make(map[domain.ChangeSetItemKind]int, len(diffKindOrder))
	for i, k := range diffKindOrder {
		rank[k] = i
	}
	out := append([]*domain.ChangeSetItem(nil), items...)
	// stable insertion sort: small lists, deterministic output
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			ra, rb := rank[a.Kind], rank[b.Kind]
			if ra < rb || (ra == rb && a.ResourceName <= b.ResourceName) {
				break
			}
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// actionSign returns the leading symbol for a ChangeSetAction.
func actionSign(a domain.ChangeSetAction) string {
	switch a {
	case domain.ChangeSetActionAdd:
		return "+"
	case domain.ChangeSetActionDelete:
		return "-"
	case domain.ChangeSetActionUpdate:
		return "~"
	}
	return "?"
}

// styleForAction maps a ChangeSetAction to its lipgloss style.
func styleForAction(a domain.ChangeSetAction) lipgloss.Style {
	switch a {
	case domain.ChangeSetActionAdd:
		return addStyle
	case domain.ChangeSetActionDelete:
		return deleteStyle
	case domain.ChangeSetActionUpdate:
		return updateStyle
	}
	return rowStyle
}
