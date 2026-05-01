// Package connectors defines the Phase 4+ connector interface and registry.
//
// A connector translates between the deterministic core's ApprovedVersion
// snapshot and a real target system (Linux hosts, Postgres, Kubernetes,
// etc.). Connectors live in subpackages (e.g. internal/connectors/linux_sudo)
// and register themselves with a Registry by name.
//
// Phase 4 shipped only the Plan path. Phase 4' adds CollectActualState
// and Compare so the CLI can scan target systems for drift relative to
// an ApprovedVersion. Apply remains a placeholder for Phase 6.
//
// Connectors do NOT touch the database. The CLI/service layer takes a
// connector's *PlanResult, builds a *domain.Plan (computing the hash,
// minting an id, etc.), and persists it through storage.PlanStore. The
// same is true for drift: the connector returns []DriftFinding and the
// CLI translates those into domain.DriftFinding rows. Keep connector
// packages free of pgx, sqlc, and anything that dials the DB.
package connectors

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/model"
)

// ErrCapabilityNotSupported is returned by connectors that have not
// implemented one of the Phase 4'+ optional capabilities (e.g. drift
// collection on the linux-ssh connector). Callers (CLI/service layer)
// should surface a clean "connector X does not support drift detection"
// message rather than treating this as a generic failure.
var ErrCapabilityNotSupported = errors.New("connectors: capability not supported")

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

// CollectionScope tells a connector where to look for actual state.
// Connectors that read from local files use Path; connectors that talk
// to hosts use Host + Selectors. The Phase 4' Linux sudo connector uses
// Path; later connectors (Postgres, Kubernetes) will use Host or a
// connector-specific Selectors map.
type CollectionScope struct {
	// Path is the file system root the connector should read, e.g.
	// "/etc/sudoers.d". Empty if the connector is host-based.
	Path string
	// Host is the optional host identifier for connectors that need to
	// label collected state with its origin. Empty for file-only
	// collection.
	Host string
	// Selectors are free-form connector-specific filters. The connector
	// documents the keys it understands; unknown keys are ignored.
	Selectors map[string]string
}

// ActualState is what a connector observed in the target system. It
// mirrors the structure of ApprovedState but represents reality.
//
// Items must be sortable + canonicalisable so two collects of the same
// input produce byte-identical bytes (ordered by ResourceKind ASC then
// ResourceRef ASC). Connectors are expected to enforce this ordering
// before returning.
type ActualState struct {
	ConnectorName    string
	ConnectorVersion string
	// SourceRef mirrors DriftScan.SourceRef: a stable string describing
	// where the bytes came from, e.g. "file:///etc/sudoers.d".
	SourceRef   string
	CollectedAt time.Time
	Items       []ActualStateItem
}

// ActualStateItem is one observed resource snapshot.
type ActualStateItem struct {
	// ResourceKind mirrors PlanItem.ResourceKind, e.g.
	// "linux.sudoers-fragment".
	ResourceKind string
	// ResourceRef is the stable identifier within the target system,
	// e.g. "/etc/sudoers.d/payments-prod-readonly".
	ResourceRef string
	// Body is the canonical-JSON-serializable observed body. The
	// connector is responsible for producing a stable shape so two
	// collects of the same input encode to identical bytes.
	Body map[string]any
}

// ApplyResult is a placeholder for Phase 6 (apply lands in core v0.6+).
type ApplyResult struct{}

// DriftFinding is a connector-side finding. The CLI/service layer
// translates these into domain.DriftFinding rows for persistence.
// Fields mirror domain.DriftFinding minus the scan id and persistence
// concerns. Bodies are canonical-JSON-serializable maps; the caller
// marshals them into JSONB on the way to the database.
type DriftFinding struct {
	// Kind is one of "missing", "unexpected", "modified". The CLI maps
	// this to domain.DriftKind on persistence.
	Kind string
	// Severity is one of "info", "low", "medium", "high", "critical".
	// Mapped to domain.DriftSeverity on persistence.
	Severity string
	// ResourceKind / ResourceRef mirror ActualStateItem.
	ResourceKind string
	ResourceRef  string
	// Desired is the desired-state body; nil for "unexpected" kind.
	Desired map[string]any
	// Actual is the observed body; nil for "missing" kind.
	Actual map[string]any
	// Diff is a free-form connector-specific delta, e.g.
	// {"missing_lines": [...]} or {"changed": ["content"]}.
	Diff    map[string]any
	Message string
}

// Connector is the contract every target-system connector implements.
// Phase 4 shipped Name, Version, Capabilities, ValidateDesiredState,
// and Plan. Phase 4' adds CollectActualState and Compare. Connectors
// that have not implemented the drift methods return
// ErrCapabilityNotSupported and omit the matching capabilities from
// Capabilities(); embedding UnsupportedCollectAndCompare is the
// standard way to do this.
type Connector interface {
	// Name is the stable, lower-kebab identifier for the connector,
	// e.g. "linux-sudo" or "linux-ssh". Registry uses this as the key.
	Name() string

	// Version is the semver string the connector advertises. Plans
	// record this as Plan.ConnectorVersion, so an audit can answer
	// "which connector version produced this plan".
	Version() string

	// Capabilities lists what the connector can do. Phase 4 connectors
	// typically return only []Capability{CapabilityPlan}; Phase 4'+
	// connectors that implement drift add CapabilityCollectActual and
	// CapabilityCompare.
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

	// CollectActualState reads the target system through the supplied
	// scope and returns a deterministic snapshot of what actually
	// exists. Two collects of the same target with the same scope MUST
	// produce byte-identical Items (sorted ascending by ResourceKind,
	// ResourceRef). Connectors that do not implement collection return
	// ErrCapabilityNotSupported.
	CollectActualState(ctx context.Context, scope CollectionScope) (*ActualState, error)

	// Compare diffs the supplied desired state against an actual state
	// snapshot and returns one DriftFinding per mismatch. The result
	// must be deterministic: identical inputs produce identical
	// findings in identical order. Connectors that do not implement
	// comparison return ErrCapabilityNotSupported.
	Compare(ctx context.Context, desired ApprovedState, actual *ActualState) ([]DriftFinding, error)
}

// UnsupportedCollectAndCompare is a default implementation of the
// drift methods. Connectors without drift support embed this type to
// keep their struct minimal:
//
//	type Connector struct {
//	    connectors.UnsupportedCollectAndCompare
//	    // ... rest of state
//	}
//
// Both methods return ErrCapabilityNotSupported. Such connectors must
// also leave CapabilityCollectActual / CapabilityCompare out of their
// Capabilities() return value so callers can dispatch on capabilities
// instead of probing for the error.
type UnsupportedCollectAndCompare struct{}

// CollectActualState always returns ErrCapabilityNotSupported.
func (UnsupportedCollectAndCompare) CollectActualState(context.Context, CollectionScope) (*ActualState, error) {
	return nil, ErrCapabilityNotSupported
}

// Compare always returns ErrCapabilityNotSupported.
func (UnsupportedCollectAndCompare) Compare(context.Context, ApprovedState, *ActualState) ([]DriftFinding, error) {
	return nil, ErrCapabilityNotSupported
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
