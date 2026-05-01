// Package cli — connector subcommand. Phase 4 surfaces the connector
// registry to operators so they can discover what's installed without
// running a plan. Today there are two built-ins (linux-sudo, linux-ssh);
// Phase 6+ adds postgres and beyond.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/connectors/builtins"
)

// addConnectorCmd registers `statebound connector` on parent (root command).
func addConnectorCmd(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "connector",
		Short: "Inspect installed connectors",
	}
	cmd.AddCommand(newConnectorListCmd())
	parent.AddCommand(cmd)
}

func newConnectorListCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List installed connectors",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runConnectorList(cmd.OutOrStdout(), format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

// connectorView is the JSON shape printed by `connector list --format json`.
// Hand-rolled so the wire shape stays stable as the Connector interface grows.
type connectorView struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

func runConnectorList(w io.Writer, format string) error {
	registry := connectors.NewRegistry()
	builtins.Register(registry)

	all := registry.List()
	views := make([]connectorView, 0, len(all))
	for _, c := range all {
		caps := make([]string, 0, len(c.Capabilities()))
		for _, cap := range c.Capabilities() {
			caps = append(caps, string(cap))
		}
		views = append(views, connectorView{
			Name:         c.Name(),
			Version:      c.Version(),
			Capabilities: caps,
		})
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		return renderConnectorTable(w, views)
	case "json":
		b, err := json.MarshalIndent(views, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		_, err = io.WriteString(w, "\n")
		return err
	default:
		return fmt.Errorf("unknown format %q (want text or json)", format)
	}
}

func renderConnectorTable(w io.Writer, views []connectorView) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAME\tVERSION\tCAPABILITIES"); err != nil {
		return err
	}
	for _, v := range views {
		caps := strings.Join(v.Capabilities, ",")
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", v.Name, v.Version, caps); err != nil {
			return err
		}
	}
	return tw.Flush()
}
