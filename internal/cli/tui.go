package cli

import (
	"context"
	"fmt"
	"log/slog"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/storage"
	"statebound.dev/statebound/internal/tui"
)

func addTUICmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive terminal UI",
		Long: "Launches the Bubble Tea TUI. Requires a real TTY; do not " +
			"run this through a non-interactive Docker exec.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Open a storage handle if possible. Storage failures must not
			// fail the command — the TUI launches in disconnected mode and
			// reports the issue in its bottom status bar.
			var store storage.Storage
			s, err := storeFromCmd(cmd)
			if err != nil {
				slog.Warn("tui: storage unavailable, launching in disconnected mode",
					"error", err)
			} else {
				store = s
			}

			program := tea.NewProgram(tui.NewModel(store))
			_, runErr := program.Run()

			if store != nil {
				closeCtx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if cerr := store.Close(closeCtx); cerr != nil {
					slog.Warn("tui: error closing storage", "error", cerr)
				}
			}

			if runErr != nil {
				return fmt.Errorf("tui: %w", runErr)
			}
			return nil
		},
	}
	parent.AddCommand(cmd)
}
