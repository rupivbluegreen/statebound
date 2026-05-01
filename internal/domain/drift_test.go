package domain

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func validDriftInitiatedBy() Actor {
	return Actor{Kind: ActorHuman, Subject: "engineer@example.com"}
}

func TestNewDriftScan_Valid(t *testing.T) {
	productID := NewID()
	avID := NewID()
	by := validDriftInitiatedBy()

	scan, err := NewDriftScan(productID, avID, 7, "linux-sudo", "0.4.0",
		"file:///etc/sudoers.d", by)
	if err != nil {
		t.Fatalf("NewDriftScan: %v", err)
	}
	if scan.ID == "" {
		t.Error("ID empty")
	}
	if scan.ProductID != productID {
		t.Errorf("ProductID = %q, want %q", scan.ProductID, productID)
	}
	if scan.ApprovedVersionID != avID {
		t.Errorf("ApprovedVersionID = %q, want %q", scan.ApprovedVersionID, avID)
	}
	if scan.Sequence != 7 {
		t.Errorf("Sequence = %d, want 7", scan.Sequence)
	}
	if scan.ConnectorName != "linux-sudo" {
		t.Errorf("ConnectorName = %q", scan.ConnectorName)
	}
	if scan.ConnectorVersion != "0.4.0" {
		t.Errorf("ConnectorVersion = %q", scan.ConnectorVersion)
	}
	if scan.SourceRef != "file:///etc/sudoers.d" {
		t.Errorf("SourceRef = %q", scan.SourceRef)
	}
	if scan.State != DriftScanStateRunning {
		t.Errorf("State = %q, want running", scan.State)
	}
	if scan.StartedAt.IsZero() {
		t.Error("StartedAt zero")
	}
	if scan.StartedAt.Location() != time.UTC {
		t.Errorf("StartedAt location = %v, want UTC", scan.StartedAt.Location())
	}
	if scan.FinishedAt != nil {
		t.Errorf("FinishedAt = %v, want nil", scan.FinishedAt)
	}
	if scan.FindingCount != 0 {
		t.Errorf("FindingCount = %d, want 0", scan.FindingCount)
	}
	if scan.SummaryHash != "" {
		t.Errorf("SummaryHash = %q, want empty", scan.SummaryHash)
	}
	if scan.FailureMessage != "" {
		t.Errorf("FailureMessage = %q, want empty", scan.FailureMessage)
	}
}

func TestNewDriftScan_Invalid(t *testing.T) {
	productID := NewID()
	avID := NewID()
	by := validDriftInitiatedBy()

	cases := []struct {
		name             string
		productID        ID
		avID             ID
		sequence         int64
		connectorName    string
		connectorVersion string
		sourceRef        string
		initiatedBy      Actor
		wantErr          error
	}{
		{"empty product", "", avID, 1, "linux-sudo", "0.4.0", "file:///x", by, ErrDriftScanProductIDRequired},
		{"empty av", productID, "", 1, "linux-sudo", "0.4.0", "file:///x", by, ErrDriftScanApprovedVersionIDRequired},
		{"sequence zero", productID, avID, 0, "linux-sudo", "0.4.0", "file:///x", by, ErrDriftScanSequenceInvalid},
		{"sequence negative", productID, avID, -1, "linux-sudo", "0.4.0", "file:///x", by, ErrDriftScanSequenceInvalid},
		{"empty connector name", productID, avID, 1, "", "0.4.0", "file:///x", by, ErrDriftScanConnectorNameRequired},
		{"empty connector version", productID, avID, 1, "linux-sudo", "", "file:///x", by, ErrDriftScanConnectorVersionRequired},
		{"empty source ref", productID, avID, 1, "linux-sudo", "0.4.0", "", by, ErrDriftScanSourceRefRequired},
		{"invalid actor", productID, avID, 1, "linux-sudo", "0.4.0", "file:///x", Actor{}, ErrActorKindInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDriftScan(tc.productID, tc.avID, tc.sequence,
				tc.connectorName, tc.connectorVersion, tc.sourceRef, tc.initiatedBy)
			if err == nil {
				t.Fatalf("NewDriftScan succeeded; want error %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.wantErr)
			}
		})
	}
}

func TestDriftScan_StateMachine_RunningToSucceeded(t *testing.T) {
	scan, err := NewDriftScan(NewID(), NewID(), 1, "linux-sudo", "0.4.0",
		"file:///etc/sudoers.d", validDriftInitiatedBy())
	if err != nil {
		t.Fatalf("NewDriftScan: %v", err)
	}
	if !scan.CanTransitionTo(DriftScanStateSucceeded) {
		t.Fatalf("CanTransitionTo(succeeded) returned false from running")
	}
	finished := time.Now().UTC()
	if err := scan.Transition(DriftScanStateSucceeded, finished, "deadbeef", 3, ""); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if scan.State != DriftScanStateSucceeded {
		t.Errorf("State = %q, want succeeded", scan.State)
	}
	if scan.FinishedAt == nil || !scan.FinishedAt.Equal(finished) {
		t.Errorf("FinishedAt = %v, want %v", scan.FinishedAt, finished)
	}
	if scan.SummaryHash != "deadbeef" {
		t.Errorf("SummaryHash = %q", scan.SummaryHash)
	}
	if scan.FindingCount != 3 {
		t.Errorf("FindingCount = %d, want 3", scan.FindingCount)
	}
	if scan.FailureMessage != "" {
		t.Errorf("FailureMessage = %q, want empty on succeeded", scan.FailureMessage)
	}
}

func TestDriftScan_StateMachine_RunningToFailed(t *testing.T) {
	scan, err := NewDriftScan(NewID(), NewID(), 1, "linux-sudo", "0.4.0",
		"file:///etc/sudoers.d", validDriftInitiatedBy())
	if err != nil {
		t.Fatalf("NewDriftScan: %v", err)
	}
	finished := time.Now().UTC()
	if err := scan.Transition(DriftScanStateFailed, finished, "", 0, "connector exploded"); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if scan.State != DriftScanStateFailed {
		t.Errorf("State = %q, want failed", scan.State)
	}
	if scan.FailureMessage != "connector exploded" {
		t.Errorf("FailureMessage = %q", scan.FailureMessage)
	}
	if scan.FinishedAt == nil {
		t.Error("FinishedAt nil after failed transition")
	}
}

func TestDriftScan_StateMachine_FailedRequiresMessage(t *testing.T) {
	scan, err := NewDriftScan(NewID(), NewID(), 1, "linux-sudo", "0.4.0",
		"file:///etc/sudoers.d", validDriftInitiatedBy())
	if err != nil {
		t.Fatalf("NewDriftScan: %v", err)
	}
	err = scan.Transition(DriftScanStateFailed, time.Now().UTC(), "", 0, "")
	if !errors.Is(err, ErrDriftScanFailureMessageRequired) {
		t.Errorf("err = %v, want errors.Is == ErrDriftScanFailureMessageRequired", err)
	}
}

func TestDriftScan_StateMachine_TerminalIsSticky(t *testing.T) {
	mk := func(terminal DriftScanState) *DriftScan {
		s, err := NewDriftScan(NewID(), NewID(), 1, "linux-sudo", "0.4.0",
			"file:///etc/sudoers.d", validDriftInitiatedBy())
		if err != nil {
			t.Fatalf("NewDriftScan: %v", err)
		}
		switch terminal {
		case DriftScanStateSucceeded:
			if err := s.Transition(DriftScanStateSucceeded, time.Now().UTC(), "h", 0, ""); err != nil {
				t.Fatalf("seed succeeded: %v", err)
			}
		case DriftScanStateFailed:
			if err := s.Transition(DriftScanStateFailed, time.Now().UTC(), "", 0, "boom"); err != nil {
				t.Fatalf("seed failed: %v", err)
			}
		}
		return s
	}

	for _, from := range []DriftScanState{DriftScanStateSucceeded, DriftScanStateFailed} {
		for _, to := range []DriftScanState{
			DriftScanStateRunning, DriftScanStateSucceeded, DriftScanStateFailed,
		} {
			t.Run(string(from)+"->"+string(to), func(t *testing.T) {
				s := mk(from)
				if s.CanTransitionTo(to) {
					t.Fatalf("CanTransitionTo(%s) returned true from terminal %s", to, from)
				}
				err := s.Transition(to, time.Now().UTC(), "h", 0, "boom")
				if err == nil {
					t.Fatalf("Transition(%s) succeeded from terminal %s; want error", to, from)
				}
				if !errors.Is(err, ErrDriftScanInvalidTransition) {
					t.Errorf("err = %v, want errors.Is == ErrDriftScanInvalidTransition", err)
				}
			})
		}
	}
}

func TestDriftScan_StateMachine_RunningToRunningForbidden(t *testing.T) {
	scan, err := NewDriftScan(NewID(), NewID(), 1, "linux-sudo", "0.4.0",
		"file:///etc/sudoers.d", validDriftInitiatedBy())
	if err != nil {
		t.Fatalf("NewDriftScan: %v", err)
	}
	if scan.CanTransitionTo(DriftScanStateRunning) {
		t.Errorf("CanTransitionTo(running) returned true from running; only terminal states are legal")
	}
	err = scan.Transition(DriftScanStateRunning, time.Now().UTC(), "", 0, "")
	if !errors.Is(err, ErrDriftScanInvalidTransition) {
		t.Errorf("err = %v, want errors.Is == ErrDriftScanInvalidTransition", err)
	}
}

func TestDriftScan_StateMachine_InvalidTargetState(t *testing.T) {
	scan, err := NewDriftScan(NewID(), NewID(), 1, "linux-sudo", "0.4.0",
		"file:///etc/sudoers.d", validDriftInitiatedBy())
	if err != nil {
		t.Fatalf("NewDriftScan: %v", err)
	}
	err = scan.Transition(DriftScanState("bogus"), time.Now().UTC(), "", 0, "x")
	if !errors.Is(err, ErrDriftScanStateInvalid) {
		t.Errorf("err = %v, want errors.Is == ErrDriftScanStateInvalid", err)
	}
}

func TestNewDriftFinding_Valid(t *testing.T) {
	scanID := NewID()
	desired := json.RawMessage(`{"path":"/etc/sudoers.d/payments","content":"ok"}`)
	actual := json.RawMessage(`{"path":"/etc/sudoers.d/payments","content":"tampered"}`)
	diff := json.RawMessage(`{"changed":["content"]}`)

	f, err := NewDriftFinding(scanID, 1, DriftKindModified, DriftSeverityHigh,
		"linux.sudoers-fragment", "/etc/sudoers.d/payments",
		desired, actual, diff, "content tampered")
	if err != nil {
		t.Fatalf("NewDriftFinding: %v", err)
	}
	if f.ID == "" {
		t.Error("ID empty")
	}
	if f.ScanID != scanID {
		t.Errorf("ScanID = %q, want %q", f.ScanID, scanID)
	}
	if f.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", f.Sequence)
	}
	if f.Kind != DriftKindModified {
		t.Errorf("Kind = %q", f.Kind)
	}
	if f.Severity != DriftSeverityHigh {
		t.Errorf("Severity = %q", f.Severity)
	}
	if f.ResourceKind != "linux.sudoers-fragment" {
		t.Errorf("ResourceKind = %q", f.ResourceKind)
	}
	if f.ResourceRef != "/etc/sudoers.d/payments" {
		t.Errorf("ResourceRef = %q", f.ResourceRef)
	}
	if f.Message != "content tampered" {
		t.Errorf("Message = %q", f.Message)
	}
	if f.DetectedAt.IsZero() {
		t.Error("DetectedAt zero")
	}

	// Mutating the caller's slices must not change the persisted bytes.
	desired[0] = 'X'
	actual[0] = 'X'
	diff[0] = 'X'
	if string(f.Desired[0]) == "X" || string(f.Actual[0]) == "X" || string(f.Diff[0]) == "X" {
		t.Errorf("defensive copy missing: caller mutation reached the finding")
	}
}

func TestNewDriftFinding_DiffDefaultsToEmptyObject(t *testing.T) {
	f, err := NewDriftFinding(NewID(), 1, DriftKindMissing, DriftSeverityMedium,
		"linux.sudoers-fragment", "/etc/sudoers.d/x",
		json.RawMessage(`{"k":1}`), nil, nil, "")
	if err != nil {
		t.Fatalf("NewDriftFinding: %v", err)
	}
	if string(f.Diff) != "{}" {
		t.Errorf("Diff = %q, want %q", string(f.Diff), "{}")
	}
}

func TestNewDriftFinding_MissingActualIsNil(t *testing.T) {
	f, err := NewDriftFinding(NewID(), 1, DriftKindMissing, DriftSeverityLow,
		"linux.sudoers-fragment", "/etc/sudoers.d/x",
		json.RawMessage(`{"k":1}`), nil, json.RawMessage(`{}`), "absent")
	if err != nil {
		t.Fatalf("NewDriftFinding: %v", err)
	}
	if f.Actual != nil {
		t.Errorf("Actual = %v, want nil for missing kind", f.Actual)
	}
}

func TestNewDriftFinding_UnexpectedDesiredIsNil(t *testing.T) {
	f, err := NewDriftFinding(NewID(), 1, DriftKindUnexpected, DriftSeverityLow,
		"linux.sudoers-fragment", "/etc/sudoers.d/x",
		nil, json.RawMessage(`{"k":1}`), json.RawMessage(`{}`), "extra")
	if err != nil {
		t.Fatalf("NewDriftFinding: %v", err)
	}
	if f.Desired != nil {
		t.Errorf("Desired = %v, want nil for unexpected kind", f.Desired)
	}
}

func TestNewDriftFinding_Invalid(t *testing.T) {
	scanID := NewID()
	desired := json.RawMessage(`{"k":1}`)
	actual := json.RawMessage(`{"k":2}`)
	diff := json.RawMessage(`{"x":1}`)

	cases := []struct {
		name         string
		scanID       ID
		sequence     int
		kind         DriftKind
		severity     DriftSeverity
		resourceKind string
		resourceRef  string
		desired      json.RawMessage
		actual       json.RawMessage
		diff         json.RawMessage
		wantErr      error
	}{
		{"empty scan id", "", 1, DriftKindModified, DriftSeverityLow, "rk", "rr", desired, actual, diff, ErrDriftFindingScanIDRequired},
		{"sequence zero", scanID, 0, DriftKindModified, DriftSeverityLow, "rk", "rr", desired, actual, diff, ErrDriftFindingSequenceInvalid},
		{"sequence negative", scanID, -1, DriftKindModified, DriftSeverityLow, "rk", "rr", desired, actual, diff, ErrDriftFindingSequenceInvalid},
		{"bad kind", scanID, 1, DriftKind("bogus"), DriftSeverityLow, "rk", "rr", desired, actual, diff, ErrDriftFindingKindInvalid},
		{"empty kind", scanID, 1, DriftKind(""), DriftSeverityLow, "rk", "rr", desired, actual, diff, ErrDriftFindingKindInvalid},
		{"bad severity", scanID, 1, DriftKindModified, DriftSeverity("bogus"), "rk", "rr", desired, actual, diff, ErrDriftFindingSeverityInvalid},
		{"empty severity", scanID, 1, DriftKindModified, DriftSeverity(""), "rk", "rr", desired, actual, diff, ErrDriftFindingSeverityInvalid},
		{"empty resource kind", scanID, 1, DriftKindModified, DriftSeverityLow, "", "rr", desired, actual, diff, ErrDriftFindingResourceKindRequired},
		{"empty resource ref", scanID, 1, DriftKindModified, DriftSeverityLow, "rk", "", desired, actual, diff, ErrDriftFindingResourceRefRequired},
		{"bad desired json", scanID, 1, DriftKindModified, DriftSeverityLow, "rk", "rr", json.RawMessage(`{not-json`), actual, diff, ErrDriftFindingInvalid},
		{"bad actual json", scanID, 1, DriftKindModified, DriftSeverityLow, "rk", "rr", desired, json.RawMessage(`{not-json`), diff, ErrDriftFindingInvalid},
		{"bad diff json", scanID, 1, DriftKindModified, DriftSeverityLow, "rk", "rr", desired, actual, json.RawMessage(`{not-json`), ErrDriftFindingInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDriftFinding(tc.scanID, tc.sequence, tc.kind, tc.severity,
				tc.resourceKind, tc.resourceRef, tc.desired, tc.actual, tc.diff, "msg")
			if err == nil {
				t.Fatalf("NewDriftFinding succeeded; want error %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.wantErr)
			}
		})
	}
}

func TestIsValidDriftScanState(t *testing.T) {
	for _, s := range []DriftScanState{
		DriftScanStateRunning, DriftScanStateSucceeded, DriftScanStateFailed,
	} {
		if !IsValidDriftScanState(string(s)) {
			t.Errorf("IsValidDriftScanState(%q) = false, want true", s)
		}
	}
	if IsValidDriftScanState("") || IsValidDriftScanState("bogus") {
		t.Error("IsValidDriftScanState accepted invalid input")
	}
}

func TestIsValidDriftKind(t *testing.T) {
	for _, k := range []DriftKind{DriftKindMissing, DriftKindUnexpected, DriftKindModified} {
		if !IsValidDriftKind(string(k)) {
			t.Errorf("IsValidDriftKind(%q) = false, want true", k)
		}
	}
	if IsValidDriftKind("") || IsValidDriftKind("bogus") {
		t.Error("IsValidDriftKind accepted invalid input")
	}
}

func TestIsValidDriftSeverity(t *testing.T) {
	for _, s := range []DriftSeverity{
		DriftSeverityInfo, DriftSeverityLow, DriftSeverityMedium,
		DriftSeverityHigh, DriftSeverityCritical,
	} {
		if !IsValidDriftSeverity(string(s)) {
			t.Errorf("IsValidDriftSeverity(%q) = false, want true", s)
		}
	}
	if IsValidDriftSeverity("") || IsValidDriftSeverity("bogus") {
		t.Error("IsValidDriftSeverity accepted invalid input")
	}
}
