package cli

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/tui"
)

func addTUICmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive terminal UI",
		Long: "Launches the Bubble Tea TUI. Requires a real TTY; do not " +
			"run this through a non-interactive Docker exec.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			program := tea.NewProgram(tui.NewModel())
			if _, err := program.Run(); err != nil {
				return fmt.Errorf("tui: %w", err)
			}
			return nil
		},
	}
	parent.AddCommand(cmd)
}
