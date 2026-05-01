package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// DriftScanState enumerates the lifecycle states of a connector-driven
// drift scan. A scan begins in Running and lands in exactly one terminal
// state (Succeeded or Failed); there are no other transitions.
//
// Keep this list in sync with the SQL CHECK constraint in
// migrations/0007_drift.sql.
type DriftScanState string

const (
	// DriftScanStateRunning is the initial state assigned by NewDriftScan;
	// FinishedAt is nil and findings have not yet landed.
	DriftScanStateRunning DriftScanState = "running"
	// DriftScanStateSucceeded is the terminal state once the connector
	// has produced its findings list and persistence has captured them.
	DriftScanStateSucceeded DriftScanState = "succeeded"
	// DriftScanStateFailed is the terminal state when the connector or
	// driver produced an unrecoverable error before findings could be
	// persisted; FailureMessage carries the human-readable cause.
	DriftScanStateFailed DriftScanState = "failed"
)

// DriftKind enumerates the kinds of mismatch a connector can report.
//
// Keep this list in sync with the SQL CHECK constraint in
// migrations/0007_drift.sql.
type DriftKind string

const (
	// DriftKindMissing means the resource exists in the desired state
	// but is absent in the actual state collected from the target.
	DriftKindMissing DriftKind = "missing"
	// DriftKindUnexpected means the resource exists in the actual state
	// but is absent in the desired state.
	DriftKindUnexpected DriftKind = "unexpected"
	// DriftKindModified means the resource exists in both desired and
	// actual states but the bodies disagree.
	DriftKindModified DriftKind = "modified"
)

// DriftSeverity classifies how worrying a finding is. Mirrors the
// connector PlanItem risk taxonomy so CLI/TUI can render colour-coded
// views.
//
// Keep this list in sync with the SQL CHECK constraint in
// migrations/0007_drift.sql.
type DriftSeverity string

const (
	DriftSeverityInfo     DriftSeverity = "info"
	DriftSeverityLow      DriftSeverity = "low"
	DriftSeverityMedium   DriftSeverity = "medium"
	DriftSeverityHigh     DriftSeverity = "high"
	DriftSeverityCritical DriftSeverity = "critical"
)

// Sentinel errors for DriftScan / DriftFinding validation and the
// DriftScan state machine.
var (
	ErrDriftScanNotFound          = errors.New("domain: drift scan not found")
	ErrDriftScanInvalid           = errors.New("domain: drift scan invalid")
	ErrDriftScanInvalidTransition = errors.New("domain: drift scan state transition is not allowed")
	ErrDriftFindingInvalid        = errors.New("domain: drift finding invalid")

	ErrDriftScanProductIDRequired         = errors.New("domain: drift scan product id is required")
	ErrDriftScanApprovedVersionIDRequired = errors.New("domain: drift scan approved version id is required")
	ErrDriftScanSequenceInvalid           = errors.New("domain: drift scan sequence must be >= 1")
	ErrDriftScanConnectorNameRequired     = errors.New("domain: drift scan connector name is required")
	ErrDriftScanConnectorVersionRequired  = errors.New("domain: drift scan connector version is required")
	ErrDriftScanSourceRefRequired         = errors.New("domain: drift scan source ref is required")
	ErrDriftScanStateInvalid              = errors.New("domain: drift scan state is invalid")
	ErrDriftScanFindingCountInvalid       = errors.New("domain: drift scan finding count must be >= 0")
	ErrDriftScanFailureMessageRequired    = errors.New("domain: drift scan failure message is required when transitioning to failed")

	ErrDriftFindingScanIDRequired       = errors.New("domain: drift finding scan id is required")
	ErrDriftFindingSequenceInvalid      = errors.New("domain: drift finding sequence must be >= 1")
	ErrDriftFindingKindInvalid          = errors.New("domain: drift finding kind is invalid")
	ErrDriftFindingSeverityInvalid      = errors.New("domain: drift finding severity is invalid")
	ErrDriftFindingResourceKindRequired = errors.New("domain: drift finding resource kind is required")
	ErrDriftFindingResourceRefRequired  = errors.New("domain: drift finding resource ref is required")
)

// DriftScan is one execution of a connector's CollectActualState +
// Compare cycle. It produces N findings stored in drift_findings.
//
// Plans are immutable once written; DriftScans, by contrast, lifecycle
// from Running to a terminal state via Transition. The terminal write
// records SummaryHash (canonical hash of the findings list) and
// FindingCount alongside the state flip.
type DriftScan struct {
	ID                ID
	ProductID         ID
	ApprovedVersionID ID
	// Sequence mirrors ApprovedVersion.Sequence so an evidence pack can
	// answer "what was the desired state when this scan ran".
	Sequence         int64
	ConnectorName    string
	ConnectorVersion string
	State            DriftScanState
	// SourceRef records where the connector looked: e.g.
	// "file:///etc/sudoers.d" for a file-system collector or
	// "host:pay-linux-01" for a host-based one.
	SourceRef      string
	StartedAt      time.Time
	FinishedAt     *time.Time
	InitiatedBy    Actor
	FailureMessage string
	// SummaryHash is the SHA-256 hex of the canonical findings list,
	// included in the evidence pack so an auditor can verify the scan
	// content has not been retouched after the fact.
	SummaryHash  string
	FindingCount int
}

// DriftFinding is one individual mismatch produced by a DriftScan.
// Findings are persisted in bulk after the scan terminates; the
// (scan_id, sequence) tuple is unique within a scan.
type DriftFinding struct {
	ID           ID
	ScanID       ID
	Sequence     int
	Kind         DriftKind
	Severity     DriftSeverity
	ResourceKind string
	ResourceRef  string
	// Desired is the canonical JSON body of the desired-state resource;
	// nil for DriftKindUnexpected.
	Desired json.RawMessage
	// Actual is the canonical JSON body observed in the target system;
	// nil for DriftKindMissing.
	Actual json.RawMessage
	// Diff is a connector-specific JSON object describing the delta,
	// e.g. {"missing_lines":[...]}. Empty {} is acceptable.
	Diff       json.RawMessage
	Message    string
	DetectedAt time.Time
}

// IsValidDriftScanState reports whether s is one of the DriftScanState constants.
func IsValidDriftScanState(s string) bool {
	switch DriftScanState(s) {
	case DriftScanStateRunning, DriftScanStateSucceeded, DriftScanStateFailed:
		return true
	}
	return false
}

// IsValidDriftKind reports whether s is one of the DriftKind constants.
func IsValidDriftKind(s string) bool {
	switch DriftKind(s) {
	case DriftKindMissing, DriftKindUnexpected, DriftKindModified:
		return true
	}
	return false
}

// IsValidDriftSeverity reports whether s is one of the DriftSeverity constants.
func IsValidDriftSeverity(s string) bool {
	switch DriftSeverity(s) {
	case DriftSeverityInfo,
		DriftSeverityLow,
		DriftSeverityMedium,
		DriftSeverityHigh,
		DriftSeverityCritical:
		return true
	}
	return false
}

// NewDriftScan constructs and validates a DriftScan in the Running state.
// FinishedAt is nil and FindingCount/SummaryHash are zero-valued; the
// caller flips to Succeeded/Failed via Transition once the connector
// returns.
func NewDriftScan(
	productID, approvedVersionID ID,
	sequence int64,
	connectorName, connectorVersion, sourceRef string,
	initiatedBy Actor,
) (*DriftScan, error) {
	if productID == "" {
		return nil, ErrDriftScanProductIDRequired
	}
	if approvedVersionID == "" {
		return nil, ErrDriftScanApprovedVersionIDRequired
	}
	if sequence < 1 {
		return nil, ErrDriftScanSequenceInvalid
	}
	if connectorName == "" {
		return nil, ErrDriftScanConnectorNameRequired
	}
	if connectorVersion == "" {
		return nil, ErrDriftScanConnectorVersionRequired
	}
	if sourceRef == "" {
		return nil, ErrDriftScanSourceRefRequired
	}
	if err := initiatedBy.Validate(); err != nil {
		return nil, err
	}
	return &DriftScan{
		ID:                NewID(),
		ProductID:         productID,
		ApprovedVersionID: approvedVersionID,
		Sequence:          sequence,
		ConnectorName:     connectorName,
		ConnectorVersion:  connectorVersion,
		State:             DriftScanStateRunning,
		SourceRef:         sourceRef,
		StartedAt:         time.Now().UTC(),
		InitiatedBy:       initiatedBy,
	}, nil
}

// CanTransitionTo reports whether moving from the receiver's state to
// target is a legal state-machine edge.
//
// Legal edges:
//   - Running -> Succeeded
//   - Running -> Failed
//
// All other edges (and any edge from a terminal state) are illegal.
func (d *DriftScan) CanTransitionTo(target DriftScanState) bool {
	if d == nil {
		return false
	}
	if d.State != DriftScanStateRunning {
		return false
	}
	return target == DriftScanStateSucceeded || target == DriftScanStateFailed
}

// Transition advances the DriftScan to its terminal state. Passing
// Failed requires a non-empty failureMessage; passing Succeeded ignores
// failureMessage. summaryHash and findingCount are recorded on both
// terminal states (a failed scan can still have produced partial
// findings up to the point of failure, though Phase 4' callers will
// typically pass 0/empty).
func (d *DriftScan) Transition(
	target DriftScanState,
	finishedAt time.Time,
	summaryHash string,
	findingCount int,
	failureMessage string,
) error {
	if d == nil {
		return ErrDriftScanInvalid
	}
	if !IsValidDriftScanState(string(target)) {
		return fmt.Errorf("%w: %q", ErrDriftScanStateInvalid, string(target))
	}
	if !d.CanTransitionTo(target) {
		return fmt.Errorf("%w: %s -> %s", ErrDriftScanInvalidTransition, d.State, target)
	}
	if findingCount < 0 {
		return ErrDriftScanFindingCountInvalid
	}
	if target == DriftScanStateFailed && failureMessage == "" {
		return ErrDriftScanFailureMessageRequired
	}
	d.State = target
	finished := finishedAt
	d.FinishedAt = &finished
	d.SummaryHash = summaryHash
	d.FindingCount = findingCount
	if target == DriftScanStateFailed {
		d.FailureMessage = failureMessage
	}
	return nil
}

// NewDriftFinding builds a DriftFinding bound to a scan id. The
// caller assigns sequence (1-based ordinal within the scan); persistence
// enforces uniqueness via UNIQUE(scan_id, sequence).
//
// desired/actual/diff are accepted as json.RawMessage so connectors can
// pre-canonicalise without an extra encode round-trip. Nil or empty
// desired/actual is allowed (and required) for missing/unexpected
// kinds; diff defaults to the empty JSON object {} when empty so the
// NOT NULL JSONB column always has a value.
func NewDriftFinding(
	scanID ID,
	sequence int,
	kind DriftKind,
	severity DriftSeverity,
	resourceKind, resourceRef string,
	desired, actual, diffPayload json.RawMessage,
	message string,
) (*DriftFinding, error) {
	if scanID == "" {
		return nil, ErrDriftFindingScanIDRequired
	}
	if sequence < 1 {
		return nil, ErrDriftFindingSequenceInvalid
	}
	if !IsValidDriftKind(string(kind)) {
		return nil, fmt.Errorf("%w: %q", ErrDriftFindingKindInvalid, string(kind))
	}
	if !IsValidDriftSeverity(string(severity)) {
		return nil, fmt.Errorf("%w: %q", ErrDriftFindingSeverityInvalid, string(severity))
	}
	if resourceKind == "" {
		return nil, ErrDriftFindingResourceKindRequired
	}
	if resourceRef == "" {
		return nil, ErrDriftFindingResourceRefRequired
	}
	if len(desired) > 0 && !json.Valid(desired) {
		return nil, fmt.Errorf("%w: desired is not valid JSON", ErrDriftFindingInvalid)
	}
	if len(actual) > 0 && !json.Valid(actual) {
		return nil, fmt.Errorf("%w: actual is not valid JSON", ErrDriftFindingInvalid)
	}
	if len(diffPayload) > 0 && !json.Valid(diffPayload) {
		return nil, fmt.Errorf("%w: diff is not valid JSON", ErrDriftFindingInvalid)
	}
	diff := diffPayload
	if len(diff) == 0 {
		diff = json.RawMessage("{}")
	}
	// Defensive copies so the persisted bytes cannot be mutated by the
	// caller after construction.
	var desiredCopy json.RawMessage
	if len(desired) > 0 {
		desiredCopy = append(json.RawMessage(nil), desired...)
	}
	var actualCopy json.RawMessage
	if len(actual) > 0 {
		actualCopy = append(json.RawMessage(nil), actual...)
	}
	diffCopy := append(json.RawMessage(nil), diff...)
	return &DriftFinding{
		ID:           NewID(),
		ScanID:       scanID,
		Sequence:     sequence,
		Kind:         kind,
		Severity:     severity,
		ResourceKind: resourceKind,
		ResourceRef:  resourceRef,
		Desired:      desiredCopy,
		Actual:       actualCopy,
		Diff:         diffCopy,
		Message:      message,
		DetectedAt:   time.Now().UTC(),
	}, nil
}
