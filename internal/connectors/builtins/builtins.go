// Package builtins wires every connector that ships in core into a
// connectors.Registry. It lives in a sub-package (rather than directly
// under internal/connectors) because the connector subpackages
// (linux_sudo, linux_ssh, ...) import internal/connectors for the
// Connector interface and shared types — placing RegisterBuiltins in
// internal/connectors itself would create an import cycle.
//
// CLI/service bootstrap calls builtins.Register(registry) once at
// process start. New built-in connectors land here so the CLI and TUI
// pick them up without additional wiring.
package builtins

import (
	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/connectors/linux_ssh"
	"statebound.dev/statebound/internal/connectors/linux_sudo"
)

// Register adds every core-shipped connector to r.
func Register(r *connectors.Registry) {
	r.Register(linux_sudo.New())
	r.Register(linux_ssh.New())
}
