// Package connectors defines the Phase 4+ connector interface and registry.
//
// A connector translates between the deterministic core's ApprovedVersion
// snapshot and a real target system (Linux hosts, Postgres, Kubernetes,
// etc.). Connectors live in subpackages (e.g. internal/connectors/linux_sudo)
// and register themselves with a Registry by name.
//
// Phase 4 ships only the Plan path: connectors propose changes but do not
// apply them. Apply, CollectActualState, and Compare arrive in later
// phases; this package defines placeholder types so future connectors do
// not need to invent them.
//
// Connectors do NOT touch the database. The CLI/service layer takes a
// connector's *PlanResult, builds a *domain.Plan (computing the hash,
// minting an id, etc.), and persists it through storage.PlanStore. Keep
// connector packages free of pgx, sqlc, and anything that dials the DB.
package connectors

import (
	"context"
	"fmt"
	"sort"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
)

// Capability is what a connector advertises it can do. Phase 4
// connectors return only CapabilityPlan; CapabilityApply,
// CapabilityCollectActual, and CapabilityCompare arrive in later phases.
type Capability string

const (
	CapabilityPlan          Capability = "plan"
	CapabilityApply         Capability = "apply"
	CapabilityCollectActual Capability = "collect_actual"
	CapabilityCompare       Capability = "compare"
)

// ApprovedState is the snapshot the connector reads from. It mirrors
// the YAML model and is delivered as both the parsed model + the JSON
// snapshot bytes — connectors typically need the parsed shape, but the
// raw snapshot is included for connectors that prefer to walk JSON.
type ApprovedState struct {
	Product           *domain.Product
	ApprovedVersionID domain.ID
	Sequence          int64
	Snapshot          map[string]any
	Model             *model.ProductAuthorizationModel
}

// ValidationFinding is a soft pre-flight check. Hard errors come from
// returning a non-nil error from Plan(). Severity values are
// "info" | "warning" | "error".
type ValidationFinding struct {
	Severity string // "info" | "warning" | "error"
	Path     string // YAML-ish path into the model
	Message  string
}

// CollectionScope is a placeholder for Phase 4'/6 (drift collection
// arrives in core v0.5+). Defined now as an empty struct so the
// Connector interface can compile uniformly.
type CollectionScope struct{}

// ActualState is a placeholder for Phase 4'/6 (drift collection
// arrives in core v0.5+).
type ActualState struct{}

// ApplyResult is a placeholder for Phase 6 (apply lands in core v0.6+).
type ApplyResult struct{}

// DriftFinding is a placeholder for Phase 4' (drift detection lands in
// core v0.5+).
type DriftFinding struct{}

// Connector is the contract every target-system connector implements.
// Phase 4 ships only the read paths (Name, Version, Capabilities,
// ValidateDesiredState, Plan); Apply / CollectActualState / Compare
// arrive in later phases on the same interface.
type Connector interface {
	// Name is the stable, lower-kebab identifier for the connector,
	// e.g. "linux-sudo" or "linux-ssh". Registry uses this as the key.
	Name() string

	// Version is the semver string the connector advertises. Plans
	// record this as Plan.ConnectorVersion, so an audit can answer
	// "which connector version produced this plan".
	Version() string

	// Capabilities lists what the connector can do. Phase 4 connectors
	// typically return only []Capability{CapabilityPlan}.
	Capabilities() []Capability

	// ValidateDesiredState performs soft pre-flight checks against the
	// approved state. Soft findings (info/warning) are returned as
	// ValidationFinding. Hard validation failures should be returned
	// as a non-nil error.
	ValidateDesiredState(ctx context.Context, state ApprovedState) ([]ValidationFinding, error)

	// Plan produces a deterministic proposal of changes from the
	// approved state. Re-running Plan with identical inputs MUST
	// yield byte-identical PlanResult.Content (the storage layer
	// keys on content_hash to make re-plan a no-op). Connectors do
	// not touch the database; they return a PlanResult and let the
	// caller persist it.
	Plan(ctx context.Context, state ApprovedState) (*PlanResult, error)
}

// PlanResult is what Connector.Plan() returns. The caller (CLI/service
// layer) marshals Content to canonical JSON, computes the SHA-256, mints
// a domain.Plan, and persists items + plan in one tx via
// storage.PlanStore.AppendPlan.
type PlanResult struct {
	ConnectorName    string
	ConnectorVersion string
	Summary          string
	Items            []PlanItem
	// Content is canonical-JSON-serializable. The caller is responsible
	// for json.Marshal'ing it deterministically (sorted keys, etc.) before
	// hashing — connectors should construct it with that in mind.
	Content map[string]any
}

// PlanItem is the connector-side shape; the caller copies these into
// domain.PlanItem (filling in PlanID + ID) for persistence.
type PlanItem struct {
	Sequence     int            // 1-based ordinal within the plan
	Action       string         // "create" | "update" | "delete"
	ResourceKind string         // e.g. "linux.local-group-membership"
	ResourceRef  string         // stable identifier inside the target system
	Body         map[string]any // canonical JSON shape; caller marshals
	Risk         string         // "low" | "medium" | "high" | "critical"
	Note         string         // free-form connector note
}

// Registry is the connector lookup map populated by init() blocks in
// each connector package. Phase 4 keeps this minimal; phase 6+ may add
// per-connector configuration objects.
type Registry struct {
	byName map[string]Connector
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Connector)}
}

// Register adds c to the registry. Registering the same name twice is a
// programmer error and panics: connectors are wired at process start, so
// duplication is never legitimate at runtime.
func (r *Registry) Register(c Connector) {
	if c == nil {
		panic("connectors: Register called with nil Connector")
	}
	if _, exists := r.byName[c.Name()]; exists {
		panic(fmt.Sprintf("connectors: duplicate registration for %q", c.Name()))
	}
	r.byName[c.Name()] = c
}

// Get returns the connector registered under name. The second return
// value reports whether a connector with that name is present.
func (r *Registry) Get(name string) (Connector, bool) {
	c, ok := r.byName[name]
	return c, ok
}

// List returns every registered connector ordered by name (ascending),
// so callers (CLI list, TUI) get a deterministic display order.
func (r *Registry) List() []Connector {
	names := make([]string, 0, len(r.byName))
	for n := range r.byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Connector, 0, len(names))
	for _, n := range names {
		out = append(out, r.byName[n])
	}
	return out
}
