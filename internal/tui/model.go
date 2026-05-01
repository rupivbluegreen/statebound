// Package tui hosts the Bubble Tea model for the statebound TUI.
//
// The TUI is a stack-of-screens state machine: the top-level Model holds a
// slice of screens, the tip is the active one, and navigation is expressed
// as push/pop messages. The top bar renders breadcrumbs from the stack, the
// body is the active screen's View, and the bottom bar shows connection
// status and the most recent transient message.
package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"statebound.dev/statebound/internal/storage"
)

// Model is the top-level Bubble Tea model. It owns window dimensions, the
// storage handle (may be nil for disconnected mode), the stack of active
// screens, and a single-line status string.
type Model struct {
	width  int
	height int
	store  storage.Storage

	screens []screen

	status     string
	statusErr  bool
	connected  bool
	connectErr error

	quit bool
}

// NewModel constructs the initial Model with the sections screen on top of
// the stack. Pass nil for store to launch in disconnected demo mode; every
// data-bound screen will surface "no database connected" rather than crash.
func NewModel(store storage.Storage) Model {
	return Model{
		store:   store,
		screens: []screen{newSectionsScreen(store)},
	}
}

// Init dispatches startup commands. We ping the storage backend so the
// bottom bar can show connection status, then forward to the active screen's
// own Init.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{}
	if m.store != nil {
		cmds = append(cmds, pingCmd(m.store))
	}
	if len(m.screens) > 0 {
		if c := m.screens[len(m.screens)-1].Init(); c != nil {
			cmds = append(cmds, c)
		}
	}
	if len(cmds) == 0 {
		return nil
	}
	return tea.Batch(cmds...)
}

// Update handles input and routing. Global keys (q/esc/ctrl+c) are
// intercepted here; everything else is forwarded to the active screen.
// Custom messages from screens (push/pop, status) are handled here too.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.quit = true
			return m, tea.Quit
		case "q", "esc":
			if len(m.screens) > 1 {
				m.screens = m.screens[:len(m.screens)-1]
				m.status = ""
				m.statusErr = false
				return m, nil
			}
			m.quit = true
			return m, tea.Quit
		}
		return m.forwardToActive(msg)

	case pingResultMsg:
		if msg.err != nil {
			m.connected = false
			m.connectErr = msg.err
		} else {
			m.connected = true
			m.connectErr = nil
		}
		return m, nil

	case statusMsg:
		m.status = msg.text
		m.statusErr = msg.isError
		return m, nil

	case pushScreenMsg:
		m.screens = append(m.screens, msg.s)
		m.status = ""
		m.statusErr = false
		return m, nil

	case popScreenMsg:
		if len(m.screens) > 1 {
			m.screens = m.screens[:len(m.screens)-1]
		}
		m.status = ""
		m.statusErr = false
		return m, nil

	case errMsg:
		// An async command bubbled an error up to the top level. Forward to
		// the active screen too (some screens want to record it locally),
		// then surface a one-line summary in the status bar.
		_, cmd := m.forwardToActive(msg)
		m.status = "error: " + msg.Error()
		m.statusErr = true
		return m, cmd
	}

	// Default: forward to the active screen.
	return m.forwardToActive(msg)
}

// forwardToActive delegates the message to the screen at the tip of the
// stack, replacing it with the (possibly mutated) screen returned.
func (m Model) forwardToActive(msg tea.Msg) (tea.Model, tea.Cmd) {
	if len(m.screens) == 0 {
		return m, nil
	}
	idx := len(m.screens) - 1
	next, cmd := m.screens[idx].Update(msg)
	m.screens[idx] = next
	return m, cmd
}

// View renders the chrome (top bar, body, bottom bar) around the active
// screen. lipgloss is used only for styling; layout is plain string concat.
func (m Model) View() string {
	if m.quit {
		return ""
	}
	var b strings.Builder
	b.WriteString(m.renderTopBar())
	b.WriteString("\n")
	b.WriteString(m.renderBody())
	b.WriteString("\n")
	b.WriteString(m.renderBottomBar())
	return b.String()
}

func (m Model) renderTopBar() string {
	var crumbs []string
	for _, s := range m.screens {
		crumbs = append(crumbs, s.Title())
	}
	bc := strings.Join(crumbs, "  >  ")
	return lipgloss.JoinHorizontal(lipgloss.Top,
		titleStyle.Render("Statebound"),
		breadcrumbStyle.Render(bc),
	)
}

func (m Model) renderBody() string {
	if len(m.screens) == 0 {
		return ""
	}
	return m.screens[len(m.screens)-1].View()
}

func (m Model) renderBottomBar() string {
	var conn string
	switch {
	case m.store == nil:
		conn = dimStyle.Render("not connected: no storage handle")
	case m.connectErr != nil:
		conn = statusErrorStyle.Render("not connected: " + m.connectErr.Error())
	case m.connected:
		conn = statusStyle.Render("connected")
	default:
		conn = dimStyle.Render("connecting...")
	}

	var msgPart string
	if m.status != "" {
		if m.statusErr {
			msgPart = statusErrorStyle.Render(m.status)
		} else {
			msgPart = statusStyle.Render(m.status)
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, conn, msgPart)
}

// pingCmd issues a Ping against the storage backend and returns the result
// as a pingResultMsg. We intentionally use a fresh background context so
// the ping does not race against the program shutdown context.
func pingCmd(store storage.Storage) tea.Cmd {
	return func() tea.Msg {
		err := store.Ping(ensureContext())
		return pingResultMsg{err: err}
	}
}
