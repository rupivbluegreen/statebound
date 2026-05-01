package authz

import (
	"context"
	"encoding/json"
	"fmt"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// PolicyResultRecorder is the narrow storage shape Record needs. The
// production storage.Storage in internal/storage/postgres satisfies it via
// PolicyDecisionStore + AuditStore. Tests can satisfy it with a tiny
// in-memory fake so they don't need a real database.
type PolicyResultRecorder interface {
	storage.PolicyDecisionStore
	storage.AuditStore
}

// Record persists a PolicyResult and fans it out to the audit log. It is
// idempotent per result.DecisionID: if the underlying store enforces a
// primary key on policy_decisions.id (which the schema does) a second call
// with the same DecisionID will surface storage.ErrAlreadyExists and Record
// will return that error unchanged so callers can detect the retry.
//
// Record performs two writes in sequence:
//  1. policy_decisions row (full canonical Rules + Input bytes).
//  2. audit_events row of kind policy.evaluated with a compact summary
//     payload (rule_id+outcome+severity per rule, never the full message —
//     the message can be reconstructed from the policy_decisions row by
//     decision_id and we keep audit payloads small because they hash-chain).
//
// Both writes happen in the caller's context. If callers need atomicity
// they can wrap Record in storage.WithTx.
func Record(ctx context.Context, store PolicyResultRecorder, actor domain.Actor, result *PolicyResult) error {
	if result == nil {
		return fmt.Errorf("authz: Record called with nil result")
	}

	rec, err := toPolicyDecisionRecord(result)
	if err != nil {
		return err
	}
	if err := store.AppendPolicyDecision(ctx, rec); err != nil {
		return fmt.Errorf("authz: append policy decision: %w", err)
	}

	payload, err := buildAuditPayload(result)
	if err != nil {
		return err
	}
	event, err := domain.NewAuditEvent(
		domain.EventPolicyEvaluated,
		actor,
		"change_set",
		string(result.ChangeSetID),
		payload,
	)
	if err != nil {
		return fmt.Errorf("authz: build audit event: %w", err)
	}
	if err := store.AppendAuditEvent(ctx, event); err != nil {
		return fmt.Errorf("authz: append audit event: %w", err)
	}
	return nil
}

// toPolicyDecisionRecord canonicalises a PolicyResult into the persisted
// row shape. Rules are re-marshaled here (rather than reusing the slice
// allocated by Evaluate) because we want the JSONB stored to match the
// sorted order in result.Rules byte-for-byte.
func toPolicyDecisionRecord(result *PolicyResult) (*storage.PolicyDecisionRecord, error) {
	rulesJSON, err := json.Marshal(result.Rules)
	if err != nil {
		return nil, fmt.Errorf("authz: marshal rules: %w", err)
	}
	if len(result.Input) == 0 {
		return nil, fmt.Errorf("authz: PolicyResult has empty Input bytes")
	}
	return &storage.PolicyDecisionRecord{
		ID:          result.DecisionID,
		ChangeSetID: result.ChangeSetID,
		Phase:       string(result.Phase),
		Outcome:     string(result.Outcome),
		Rules:       rulesJSON,
		Input:       append(json.RawMessage(nil), result.Input...),
		BundleHash:  result.BundleHash,
		EvaluatedAt: result.EvaluatedAt,
	}, nil
}

// buildAuditPayload returns the compact audit payload for a single
// policy.evaluated event. We deliberately omit per-rule messages and
// metadata: those live on the policy_decisions row which the audit row
// references by decision_id, and keeping the audit payload small keeps
// the hash chain cheap to walk.
func buildAuditPayload(result *PolicyResult) (map[string]any, error) {
	rules := make([]map[string]any, 0, len(result.Rules))
	for _, r := range result.Rules {
		rules = append(rules, map[string]any{
			"rule_id":  r.RuleID,
			"outcome":  string(r.Outcome),
			"severity": string(r.Severity),
		})
	}
	return map[string]any{
		"decision_id":   string(result.DecisionID),
		"change_set_id": string(result.ChangeSetID),
		"phase":         string(result.Phase),
		"outcome":       string(result.Outcome),
		"bundle_hash":   result.BundleHash,
		"rules_count":   len(result.Rules),
		"rules":         rules,
	}, nil
}
