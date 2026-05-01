package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// changeSetsScopeAll is the scope tag carried on changeSetsLoadedMsg from the
// all-states list, distinguishing it from the submitted-only approvals list.
const changeSetsScopeAll = "all"

// changeSetFilterMode cycles through the spec-defined header filters. Order
// matters: F advances by one and wraps. csFilterAll means "no state filter".
type changeSetFilterMode int

const (
	csFilterAll changeSetFilterMode = iota
	csFilterDraft
	csFilterSubmitted
	csFilterApproved
	csFilterRejected
	csFilterConflicted
)

// changeSetFilterModes is the cycle order used by `f`.
var changeSetFilterModes = []changeSetFilterMode{
	csFilterAll,
	csFilterDraft,
	csFilterSubmitted,
	csFilterApproved,
	csFilterRejected,
	csFilterConflicted,
}

// changeSetsScreen lists ChangeSets across all products. It loads the list
// asynchronously on Init, resolves product IDs to names through a cached
// lookup, and supports a state filter cycle via `f`.
type changeSetsScreen struct {
	store storage.Storage

	allChangeSets []*domain.ChangeSet
	productNames  map[domain.ID]string

	cursor  int
	loading bool
	loadErr error

	filter changeSetFilterMode
}

func newChangeSetsScreen(store storage.Storage) changeSetsScreen {
	return changeSetsScreen{
		store:        store,
		loading:      store != nil,
		productNames: map[domain.ID]string{},
	}
}

func (s changeSetsScreen) Title() string { return "Change Sets" }

func (s changeSetsScreen) Init() tea.Cmd {
	if s.store == nil {
		return nil
	}
	return tea.Batch(
		loadChangeSetsCmd(s.store, changeSetsScopeAll, storage.ChangeSetFilter{Limit: 200}),
		loadProductNamesCmd(s.store),
	)
}

func (s changeSetsScreen) Update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case changeSetsLoadedMsg:
		if msg.scope != changeSetsScopeAll {
			return s, nil
		}
		s.allChangeSets = sortChangeSetsDesc(msg.changeSets)
		s.loading = false
		s.loadErr = nil
		if s.cursor >= len(s.visible()) {
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
			if s.cursor < len(s.visible())-1 {
				s.cursor++
			}
			return s, nil
		case "home", "g":
			s.cursor = 0
			return s, nil
		case "end", "G":
			if n := len(s.visible()); n > 0 {
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
				loadChangeSetsCmd(s.store, changeSetsScopeAll, storage.ChangeSetFilter{Limit: 200}),
				loadProductNamesCmd(s.store),
			)
		case "f":
			s.filter = nextFilter(s.filter)
			s.cursor = 0
			return s, nil
		case "enter", "right", "l":
			vis := s.visible()
			if len(vis) == 0 {
				return s, nil
			}
			selected := vis[s.cursor]
			next := newChangeSetDetailScreen(s.store, selected, s.productNames[selected.ProductID])
			return s, tea.Batch(
				func() tea.Msg { return pushScreenMsg{s: next} },
				next.Init(),
			)
		}
	}
	return s, nil
}

// visible returns the change sets matching the current filter, in already-sorted order.
func (s changeSetsScreen) visible() []*domain.ChangeSet {
	state, hasState := filterState(s.filter)
	if !hasState {
		return s.allChangeSets
	}
	out := make([]*domain.ChangeSet, 0, len(s.allChangeSets))
	for _, cs := range s.allChangeSets {
		if cs.State == state {
			out = append(out, cs)
		}
	}
	return out
}

func (s changeSetsScreen) View() string {
	var b strings.Builder
	b.WriteString(sectionHeaderStyle.Render("Change Sets"))
	b.WriteString("  ")
	b.WriteString(dimStyle.Render("filter: " + filterLabel(s.filter)))
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

	vis := s.visible()
	if len(vis) == 0 {
		if s.filter == csFilterAll {
			b.WriteString(dimStyle.Render("No change sets yet. Run `statebound model import -f <file>` to draft one."))
		} else {
			b.WriteString(dimStyle.Render(fmt.Sprintf("No change sets in state %q.", filterLabel(s.filter))))
		}
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render("f to cycle filter, r to refresh, q/esc to go back"))
		return b.String()
	}

	header := fmt.Sprintf("  %-11s  %-20s  %-30s  %-20s  %-19s", "STATE", "PRODUCT", "TITLE", "REQUESTED_BY", "CREATED")
	b.WriteString(dimStyle.Render(header))
	b.WriteString("\n")

	for i, cs := range vis {
		marker := "  "
		if i == s.cursor {
			marker = "> "
		}
		state := renderStateBadge(cs.State, 11)
		productName := s.productNames[cs.ProductID]
		if productName == "" {
			productName = shortID(cs.ProductID)
		}
		row := fmt.Sprintf("%s%s  %-20s  %-30s  %-20s  %-19s",
			marker,
			state,
			truncate(productName, 20),
			truncate(cs.Title, 30),
			truncate(cs.RequestedBy.Subject, 20),
			cs.CreatedAt.UTC().Format("2006-01-02 15:04:05"),
		)
		if i == s.cursor {
			b.WriteString(selectedRowStyle.Render(row))
		} else {
			b.WriteString(rowStyle.Render(row))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("enter to open; f to cycle filter; r to refresh; q/esc to go back"))
	return b.String()
}

// loadChangeSetsCmd issues ListChangeSets and emits a changeSetsLoadedMsg
// (or errMsg) without blocking the render loop.
func loadChangeSetsCmd(store storage.Storage, scope string, filter storage.ChangeSetFilter) tea.Cmd {
	return func() tea.Msg {
		css, err := store.ListChangeSets(ensureContext(), filter)
		if err != nil {
			return errMsg{err: err}
		}
		return changeSetsLoadedMsg{scope: scope, changeSets: css}
	}
}

// loadProductNamesCmd builds a productID -> Name map from ListProducts so
// downstream screens can show readable product labels rather than UUIDs.
func loadProductNamesCmd(store storage.Storage) tea.Cmd {
	return func() tea.Msg {
		ps, err := store.ListProducts(ensureContext())
		if err != nil {
			return errMsg{err: err}
		}
		names := make(map[domain.ID]string, len(ps))
		for _, p := range ps {
			if p == nil {
				continue
			}
			names[p.ID] = p.Name
		}
		return productNamesLoadedMsg{names: names}
	}
}

// sortChangeSetsDesc sorts by CreatedAt descending in place and returns the slice.
func sortChangeSetsDesc(in []*domain.ChangeSet) []*domain.ChangeSet {
	out := append([]*domain.ChangeSet(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// nextFilter advances f one step around the cycle.
func nextFilter(f changeSetFilterMode) changeSetFilterMode {
	for i, m := range changeSetFilterModes {
		if m == f {
			return changeSetFilterModes[(i+1)%len(changeSetFilterModes)]
		}
	}
	return csFilterAll
}

// filterLabel renders the filter mode for the header strip.
func filterLabel(f changeSetFilterMode) string {
	switch f {
	case csFilterAll:
		return "all"
	case csFilterDraft:
		return "draft"
	case csFilterSubmitted:
		return "submitted"
	case csFilterApproved:
		return "approved"
	case csFilterRejected:
		return "rejected"
	case csFilterConflicted:
		return "conflicted"
	}
	return "all"
}

// filterState maps a filter mode to a domain ChangeSetState. The second
// return is false for csFilterAll (no state filter).
func filterState(f changeSetFilterMode) (domain.ChangeSetState, bool) {
	switch f {
	case csFilterDraft:
		return domain.ChangeSetStateDraft, true
	case csFilterSubmitted:
		return domain.ChangeSetStateSubmitted, true
	case csFilterApproved:
		return domain.ChangeSetStateApproved, true
	case csFilterRejected:
		return domain.ChangeSetStateRejected, true
	case csFilterConflicted:
		return domain.ChangeSetStateConflicted, true
	}
	return "", false
}

// renderStateBadge renders a left-padded coloured badge fitting in width
// columns (so subsequent columns line up regardless of style escape codes).
func renderStateBadge(state domain.ChangeSetState, width int) string {
	label := stateLabel(state)
	if len(label) > width {
		label = label[:width]
	}
	padded := label + strings.Repeat(" ", width-len(label))
	switch state {
	case domain.ChangeSetStateDraft:
		return draftStyle.Render(padded)
	case domain.ChangeSetStateSubmitted:
		return submittedStyle.Render(padded)
	case domain.ChangeSetStateApproved:
		return approvedStyle.Render(padded)
	case domain.ChangeSetStateRejected:
		return rejectedStyle.Render(padded)
	case domain.ChangeSetStateConflicted:
		return conflictedStyle.Render(padded)
	}
	return dimStyle.Render(padded)
}

// stateLabel uppercases the state for badge rendering.
func stateLabel(state domain.ChangeSetState) string {
	return strings.ToUpper(string(state))
}

// shortID returns the first 8 characters of an ID, used as a fallback when a
// product name has not yet loaded.
func shortID(id domain.ID) string {
	s := string(id)
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
