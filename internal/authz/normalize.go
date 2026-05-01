package authz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode"

	"statebound.dev/statebound/internal/domain"
)

// canonicalInputJSON converts the caller's Input into the JSON document the
// Rego rule library expects. The Rego layer reads input.* via snake_case
// keys (input.change_set, input.requested_by, item.resource_name, etc.),
// but the Go domain types and the YAML model use camelCase. This function
// is the only place that translation lives — keep it deterministic and
// well-tested.
//
// Every map key produced by this function is snake_case. Values that come
// in as nested maps from item.Before/Item.After (camelCase YAML) are
// walked recursively and rewritten.
//
// The result is a stable canonical JSON document: encoding/json sorts map
// keys, so byte-for-byte equivalent inputs produce byte-for-byte equivalent
// output. This is load-bearing: the input bytes are persisted alongside
// the decision and feed into the audit hash chain.
func canonicalInputJSON(in Input) ([]byte, error) {
	doc := map[string]any{
		"phase":      string(in.Phase),
		"product":    productView(in.Product),
		"change_set": changeSetView(in.ChangeSet),
		"items":      itemsView(in.Items),
		"approvals":  approvalsView(in.Approvals),
	}
	if in.Approver != nil {
		doc["approver"] = actorView(*in.Approver)
	}
	if in.BeforeModel != nil {
		doc["before_model"] = snakeKeysAny(in.BeforeModel)
	}
	if in.AfterModel != nil {
		doc["after_model"] = snakeKeysAny(in.AfterModel)
	}

	// We marshal via a buffer so we can pass an explicit encoder if we
	// later want HTML escaping disabled. encoding/json sorts map keys
	// already, which is what gives us determinism here.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encode canonical input: %w", err)
	}
	// json.Encoder.Encode appends a trailing newline; strip it so the
	// canonical bytes match what json.Marshal would have produced.
	out := bytes.TrimRight(buf.Bytes(), "\n")
	return out, nil
}

// productView projects domain.Product into the snake_case shape the Rego
// rules read. We expose name/owner/description/id only; any field added
// later should be considered policy-visible and reviewed.
func productView(p domain.Product) map[string]any {
	return map[string]any{
		"id":          string(p.ID),
		"name":        p.Name,
		"owner":       p.Owner,
		"description": p.Description,
	}
}

// changeSetView projects domain.ChangeSet. parent_approved_version_id is
// emitted only when present so absent-vs-empty is not surfaced ambiguously.
func changeSetView(cs domain.ChangeSet) map[string]any {
	view := map[string]any{
		"id":           string(cs.ID),
		"product_id":   string(cs.ProductID),
		"state":        string(cs.State),
		"title":        cs.Title,
		"description":  cs.Description,
		"requested_by": actorView(cs.RequestedBy),
	}
	if cs.ParentApprovedVersionID != nil {
		view["parent_approved_version_id"] = string(*cs.ParentApprovedVersionID)
	}
	if cs.SubmittedAt != nil {
		view["submitted_at"] = cs.SubmittedAt.UTC().Format("2006-01-02T15:04:05.000000000Z")
	}
	if cs.DecidedAt != nil {
		view["decided_at"] = cs.DecidedAt.UTC().Format("2006-01-02T15:04:05.000000000Z")
	}
	if cs.DecisionReason != "" {
		view["decision_reason"] = cs.DecisionReason
	}
	return view
}

// actorView projects domain.Actor (kind+subject) into the snake_case shape
// the Rego rules read. Empty kinds/subjects are emitted as empty strings;
// callers should validate before evaluation if they want a stricter check.
func actorView(a domain.Actor) map[string]any {
	return map[string]any{
		"kind":    string(a.Kind),
		"subject": a.Subject,
	}
}

// itemsView projects []*domain.ChangeSetItem into the slice shape the Rego
// rules iterate over. Item.Before and Item.After are walked recursively to
// turn camelCase YAML keys into snake_case so rules can reach values like
// item.after.usage_pattern (vs Go's usagePattern).
func itemsView(items []*domain.ChangeSetItem) []any {
	out := make([]any, 0, len(items))
	for _, it := range items {
		if it == nil {
			continue
		}
		entry := map[string]any{
			"id":            string(it.ID),
			"change_set_id": string(it.ChangeSetID),
			"kind":          string(it.Kind),
			"action":        string(it.Action),
			"resource_name": it.ResourceName,
		}
		if it.Before == nil {
			entry["before"] = nil
		} else {
			entry["before"] = snakeKeysAny(it.Before)
		}
		if it.After == nil {
			entry["after"] = nil
		} else {
			entry["after"] = snakeKeysAny(it.After)
		}
		out = append(out, entry)
	}
	return out
}

// approvalsView projects []*domain.Approval into the slice shape the Rego
// rules iterate over.
func approvalsView(approvals []*domain.Approval) []any {
	out := make([]any, 0, len(approvals))
	for _, a := range approvals {
		if a == nil {
			continue
		}
		entry := map[string]any{
			"id":            string(a.ID),
			"change_set_id": string(a.ChangeSetID),
			"actor":         actorView(a.Approver),
			"decision":      string(a.Decision),
			"reason":        a.Reason,
		}
		out = append(out, entry)
	}
	return out
}

// snakeKeysAny recursively rewrites camelCase map keys to snake_case. It
// preserves slice ordering, leaves scalar values untouched, and copies
// values into freshly allocated maps so the input is never mutated.
func snakeKeysAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[camelToSnake(k)] = snakeKeysAny(vv)
		}
		return out
	case map[any]any:
		// gopkg.in/yaml.v3 emits map[any]any when keys are non-string;
		// we coerce to map[string]any to keep the JSON layer happy.
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[camelToSnake(fmt.Sprint(k))] = snakeKeysAny(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = snakeKeysAny(vv)
		}
		return out
	case []string:
		// Optimisation: avoid round-tripping pure-string slices through
		// the []any path. Doing so also guarantees the JSON output stays
		// a homogeneous array of strings (Rego's `commands.allow`).
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	default:
		return v
	}
}

// camelToSnake converts a camelCase or PascalCase identifier to snake_case.
// Already-snake_case strings pass through unchanged. Acronyms run together
// keep their internal boundaries (HTTPServer -> http_server).
func camelToSnake(s string) string {
	if s == "" {
		return s
	}
	// Fast path: nothing to do if there are no upper-case runes.
	if !hasUpper(s) {
		return s
	}

	runes := []rune(s)
	var out []rune
	for i, r := range runes {
		if unicode.IsUpper(r) {
			lower := unicode.ToLower(r)
			if i == 0 {
				out = append(out, lower)
				continue
			}
			prev := runes[i-1]
			// Insert a separator on the lower->upper boundary
			// (camelHere -> camel_here) and on the runup-to-lowercase
			// boundary inside an acronym (HTTPServer -> http_server).
			next := rune(0)
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			if unicode.IsLower(prev) || unicode.IsDigit(prev) {
				out = append(out, '_', lower)
				continue
			}
			if unicode.IsUpper(prev) && unicode.IsLower(next) {
				out = append(out, '_', lower)
				continue
			}
			out = append(out, lower)
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// hasUpper reports whether any rune in s is upper-case ASCII or Unicode.
func hasUpper(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}
