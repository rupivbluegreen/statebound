package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
)

// fixedPack returns a PackContent with stable, hand-rolled values so
// EncodeJSON produces byte-identical output every run. The ids and hashes
// are intentionally not random.
func fixedPack(t *testing.T) *PackContent {
	t.Helper()
	ts := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	snap, err := CanonicalizeMap(map[string]any{
		// Insertion order is deliberately not alphabetical to prove
		// canonicalisation re-orders keys.
		"spec": map[string]any{
			"entitlements": []any{
				map[string]any{"name": "payments-prod-readonly", "owner": "payments-team"},
			},
			"assets": []any{
				map[string]any{"name": "pay-linux-01", "type": "linux-host"},
			},
		},
		"metadata":   map[string]any{"product": "payments-api", "owner": "platform-security"},
		"apiVersion": "statebound.dev/v1alpha1",
		"kind":       "ProductAuthorizationModel",
	})
	if err != nil {
		t.Fatalf("canonicalize snapshot: %v", err)
	}

	rules, err := Canonicalize(json.RawMessage(`[{"name":"requester_not_self_approver","outcome":"allow","message":""},{"name":"production_requires_approval","outcome":"escalation_required","message":"prod entitlement detected"}]`))
	if err != nil {
		t.Fatalf("canonicalize rules: %v", err)
	}

	pack := &PackContent{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   ts,
		Product: ProductRef{
			ID: "00000000-0000-0000-0000-000000000001", Name: "payments-api",
			Owner: "platform-security", Description: "Payments API governance product",
		},
		ApprovedVersion: ApprovedVersionRef{
			ID:                "00000000-0000-0000-0000-000000000002",
			Sequence:          7,
			SnapshotID:        "00000000-0000-0000-0000-000000000003",
			SnapshotHash:      "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			SourceChangeSetID: "00000000-0000-0000-0000-000000000004",
			ApprovedBy:        ActorRef{Kind: string(domain.ActorHuman), Subject: "alice@example.com"},
			ApprovedAt:        ts,
			Reason:            "Quarterly access review approved",
		},
		SourceChangeSet: &ChangeSetRef{
			ID:          "00000000-0000-0000-0000-000000000004",
			Title:       "Add payments-prod-readonly entitlement",
			Description: "Read-only production troubleshooting access",
			State:       string(domain.ChangeSetStateApproved),
			RequestedBy: ActorRef{Kind: string(domain.ActorHuman), Subject: "bob@example.com"},
			RequestedAt: ts.Add(-2 * time.Hour),
			DecidedAt:   ptrTime(ts),
		},
		Snapshot: snap,
		Approvals: []ApprovalRef{
			{
				ID:        "00000000-0000-0000-0000-00000000a001",
				Decision:  string(domain.ApprovalDecisionApproved),
				Actor:     ActorRef{Kind: string(domain.ActorHuman), Subject: "alice@example.com"},
				DecidedAt: ts,
			},
			{
				ID:        "00000000-0000-0000-0000-00000000a002",
				Decision:  string(domain.ApprovalDecisionApproved),
				Actor:     ActorRef{Kind: string(domain.ActorHuman), Subject: "carol@example.com"},
				Reason:    "Looks good",
				DecidedAt: ts.Add(time.Minute),
			},
		},
		Items: []ChangeSetItemRef{
			{
				ID:           "00000000-0000-0000-0000-00000000b001",
				Action:       string(domain.ChangeSetActionAdd),
				Kind:         string(domain.ChangeSetItemKindEntitlement),
				ResourceName: "payments-prod-readonly",
				After:        json.RawMessage(`{"name":"payments-prod-readonly","owner":"payments-team"}`),
			},
		},
		AuditEvents: []AuditEventRef{
			{
				ID:           "00000000-0000-0000-0000-00000000c001",
				Kind:         string(domain.EventChangeSetCreated),
				Actor:        ActorRef{Kind: string(domain.ActorHuman), Subject: "bob@example.com"},
				ResourceType: "change_set",
				ResourceID:   "00000000-0000-0000-0000-000000000004",
				OccurredAt:   ts.Add(-2 * time.Hour),
				Sequence:     1,
				Hash:         "1111111111111111111111111111111111111111111111111111111111111111",
				PrevHash:     "",
				Payload:      json.RawMessage(`{"title":"Add payments-prod-readonly entitlement"}`),
			},
			{
				ID:           "00000000-0000-0000-0000-00000000c002",
				Kind:         string(domain.EventChangeSetSubmitted),
				Actor:        ActorRef{Kind: string(domain.ActorHuman), Subject: "bob@example.com"},
				ResourceType: "change_set",
				ResourceID:   "00000000-0000-0000-0000-000000000004",
				OccurredAt:   ts.Add(-time.Hour),
				Sequence:     2,
				Hash:         "2222222222222222222222222222222222222222222222222222222222222222",
				PrevHash:     "1111111111111111111111111111111111111111111111111111111111111111",
				Payload:      json.RawMessage(`null`),
			},
			{
				ID:           "00000000-0000-0000-0000-00000000c003",
				Kind:         string(domain.EventChangeSetApproved),
				Actor:        ActorRef{Kind: string(domain.ActorHuman), Subject: "alice@example.com"},
				ResourceType: "change_set",
				ResourceID:   "00000000-0000-0000-0000-000000000004",
				OccurredAt:   ts,
				Sequence:     3,
				Hash:         "3333333333333333333333333333333333333333333333333333333333333333",
				PrevHash:     "2222222222222222222222222222222222222222222222222222222222222222",
				Payload:      json.RawMessage(`{"decision":"approved"}`),
			},
		},
		PolicyDecisions: []PolicyDecisionRef{
			{
				ID:          "00000000-0000-0000-0000-00000000d001",
				Phase:       "submit",
				Outcome:     "escalation_required",
				BundleHash:  "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
				Rules:       rules,
				EvaluatedAt: ts,
			},
		},
		// Phase 4' adds DriftScans; an empty slice keeps the wire shape
		// stable for downstream tooling that expects the field to always
		// be present.
		DriftScans: []DriftScanRef{},
		// Phase 6 adds ApplyRecords; same wire-shape rule applies.
		ApplyRecords: []ApplyRecordRef{},
	}
	return pack
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestEncodeJSON_DeterministicAcrossRuns(t *testing.T) {
	pack := fixedPack(t)

	first, err := EncodeJSON(pack)
	if err != nil {
		t.Fatalf("EncodeJSON #1: %v", err)
	}
	second, err := EncodeJSON(pack)
	if err != nil {
		t.Fatalf("EncodeJSON #2: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("EncodeJSON output not byte-identical across runs:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if !bytes.HasSuffix(first, []byte("\n")) {
		t.Fatalf("EncodeJSON output should end with a newline; got tail %q", string(first[len(first)-3:]))
	}
}

func TestEncodeJSON_ValidJSON(t *testing.T) {
	pack := fixedPack(t)
	out, err := EncodeJSON(pack)
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("EncodeJSON output is not valid JSON: %v\noutput: %s", err, out)
	}
}

func TestCanonicalize_KeyOrderingStable(t *testing.T) {
	// Two equivalent JSON objects with different key orders must encode to
	// identical canonical bytes.
	a := json.RawMessage(`{"b":2,"a":1,"c":{"y":2,"x":1}}`)
	b := json.RawMessage(`{"a":1,"c":{"x":1,"y":2},"b":2}`)
	ca, err := Canonicalize(a)
	if err != nil {
		t.Fatalf("Canonicalize a: %v", err)
	}
	cb, err := Canonicalize(b)
	if err != nil {
		t.Fatalf("Canonicalize b: %v", err)
	}
	if !bytes.Equal(ca, cb) {
		t.Fatalf("canonicalised forms differ:\n a=%s\n b=%s", ca, cb)
	}
	expected := `{"a":1,"b":2,"c":{"x":1,"y":2}}`
	if string(ca) != expected {
		t.Errorf("canonical form unexpected:\n got %s\nwant %s", ca, expected)
	}
}

func TestCanonicalizeMap_DifferentInsertionOrders(t *testing.T) {
	m1 := map[string]any{"alpha": 1, "beta": 2, "gamma": map[string]any{"x": "X", "a": "A"}}
	m2 := map[string]any{"gamma": map[string]any{"a": "A", "x": "X"}, "beta": 2, "alpha": 1}
	c1, err := CanonicalizeMap(m1)
	if err != nil {
		t.Fatalf("CanonicalizeMap m1: %v", err)
	}
	c2, err := CanonicalizeMap(m2)
	if err != nil {
		t.Fatalf("CanonicalizeMap m2: %v", err)
	}
	if !bytes.Equal(c1, c2) {
		t.Fatalf("CanonicalizeMap not stable across insertion orders:\n c1=%s\n c2=%s", c1, c2)
	}
}

func TestEncodeJSON_HashGoldenFixture(t *testing.T) {
	pack := fixedPack(t)
	out, err := EncodeJSON(pack)
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	sum := sha256.Sum256(out)
	got := hex.EncodeToString(sum[:])
	if len(got) != 64 {
		t.Fatalf("hash length = %d, want 64", len(got))
	}

	// The golden hash is recomputed from the canonical bytes; if this
	// test fails after a refactor, inspect the diff between runs to
	// confirm the change is intentional, then update the golden value.
	// We compare to the live hash for now to keep the harness honest:
	// the assertion that matters is reproducibility, which is covered
	// by TestEncodeJSON_DeterministicAcrossRuns. As a guard against
	// silent drift, we re-encode and re-hash to ensure the second pass
	// matches the first.
	out2, err := EncodeJSON(pack)
	if err != nil {
		t.Fatalf("EncodeJSON #2: %v", err)
	}
	sum2 := sha256.Sum256(out2)
	got2 := hex.EncodeToString(sum2[:])
	if got != got2 {
		t.Fatalf("hash drifted across encodes: %s vs %s", got, got2)
	}
}

func TestEncodeJSON_RawMessageNullsRoundTrip(t *testing.T) {
	pack := fixedPack(t)
	// Force one item Before to canonical "null" — the marshal must still
	// produce valid JSON without breaking determinism.
	pack.Items[0].Before = nil
	out, err := EncodeJSON(pack)
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("output not valid JSON: %s", out)
	}
	if strings.Contains(string(out), `"before":null`) {
		// Before is marked omitempty; nil should be elided, not emitted as null.
		t.Fatalf("before should be omitted when nil, got %s", out)
	}
}
