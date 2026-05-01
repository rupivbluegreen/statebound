package connectors

// RegisterBuiltins is intentionally NOT defined here.
//
// The original Phase 4 design placed RegisterBuiltins in this file, in
// package connectors. That cannot compile: the connector subpackages
// (linux_sudo, linux_ssh, ...) import internal/connectors for the
// Connector interface, Capability constants, PlanItem, etc., so importing
// the subpackages back from package connectors creates an import cycle.
//
// The wiring lives in internal/connectors/builtins instead. CLI/service
// bootstrap should import that package and call builtins.Register(r):
//
//	r := connectors.NewRegistry()
//	builtins.Register(r)
//
// This file is kept (empty of declarations) so the spec-mandated path
// internal/connectors/registry.go exists and points future readers at the
// real wiring location via this comment.
