package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// addonNotInstalled is the canonical message printed by every reasoning
// add-on stub subcommand when the add-on is not present. The exact text is
// part of the user-visible contract (see the project spec §10, §11) and must not
// change without coordinated update of the docs and the TUI.
const addonNotInstalled = "reasoning add-on not installed. " +
	"See docs/agent-governance.md to enable optional AI assist."

// printAddonStub writes the canonical not-installed message and returns nil
// (absence of the add-on is not an error).
func printAddonStub(w io.Writer) error {
	_, err := fmt.Fprintln(w, addonNotInstalled)
	return err
}

func addAgentCmd(parent *cobra.Command) {
	agentCmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage reasoning agents (provided by statebound-reason add-on)",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List registered agents",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printAddonStub(cmd.OutOrStdout())
		},
	}

	registerCmd := &cobra.Command{
		Use:   "register",
		Short: "Register an agent from a YAML file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printAddonStub(cmd.OutOrStdout())
		},
	}
	registerCmd.Flags().StringP("file", "f", "", "path to AgentRegistration YAML")

	invokeCmd := &cobra.Command{
		Use:   "invoke <agent-name>",
		Short: "Invoke an agent with a natural-language intent",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printAddonStub(cmd.OutOrStdout())
		},
	}
	invokeCmd.Flags().String("intent", "", "natural-language intent string")
	invokeCmd.Flags().String("input-file", "", "path to additional structured input")

	invocationsCmd := &cobra.Command{
		Use:   "invocations",
		Short: "List recent agent invocations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printAddonStub(cmd.OutOrStdout())
		},
	}
	invocationsCmd.Flags().String("agent", "", "filter by agent name")
	invocationsCmd.Flags().String("since", "", "duration window, e.g. 24h")

	transcriptCmd := &cobra.Command{
		Use:   "transcript <invocation-id>",
		Short: "Print the full transcript of an agent invocation",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printAddonStub(cmd.OutOrStdout())
		},
	}

	agentCmd.AddCommand(listCmd, registerCmd, invokeCmd, invocationsCmd, transcriptCmd)
	parent.AddCommand(agentCmd)
}
