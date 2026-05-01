package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// screen is the contract every navigable view in the TUI implements.
// The top-level Model holds a stack of screens; the tip is the active one.
//
// Screens are values, not pointers, but Update returns a (possibly mutated)
// screen so a screen can evolve its own state without the caller knowing
// about the concrete type.
type screen interface {
	Title() string
	Init() tea.Cmd
	Update(tea.Msg) (screen, tea.Cmd)
	View() string
}

// errMsg surfaces an async command failure to a screen or the top-level
// Model. Screens that issue tea.Cmd background work should wrap any error
// in this type and return it as the message.
type errMsg struct{ err error }

func (e errMsg) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

// pingResultMsg carries the result of pinging the storage backend. The
// top-level Model handles it to update connection status; screens ignore it.
type pingResultMsg struct{ err error }

// statusMsg is a request from a child screen to the top-level Model to
// surface a transient message in the bottom status bar.
type statusMsg struct {
	text    string
	isError bool
}

// pushScreenMsg asks the top-level Model to push a new screen onto the stack.
type pushScreenMsg struct{ s screen }

// popScreenMsg asks the top-level Model to pop the active screen off the stack.
type popScreenMsg struct{}
