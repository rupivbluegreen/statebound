package authz

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
)

// TestCanonicalInputJSON_AllKeysSnakeCase walks the marshaled canonical
// input recursively and fails on any map key that contains an upper-case
// rune. The Rego rules read input via snake_case selectors, so a single
// camelCase leak would silently break the whole policy library.
func TestCanonicalInputJSON_AllKeysSnakeCase(t *testing.T) {
	in := sampleSubmitInput(t)
	raw, err := canonicalInputJSON(in)
	if err != nil {
		t.Fatalf("canonicalInputJSON: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal canonical: %v", err)
	}
	if err := assertSnakeKeys("$", doc); err != nil {
		t.Fatalf("snake-case check: %v\nraw: %s", err, raw)
	}
}

// TestCanonicalInputJSON_TopLevelShape pins the expected top-level shape
// of the document so a future refactor cannot accidentally drop a field
// the Rego rules depend on.
func TestCanonicalInputJSON_TopLevelShape(t *testing.T) {
	in := sampleSubmitInput(t)
	raw, err := canonicalInputJSON(in)
	if err != nil {
		t.Fatalf("canonicalInputJSON: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, want := range []string{"phase", "product", "change_set", "items", "approvals"} {
		if _, ok := doc[want]; !ok {
			t.Errorf("missing top-level key %q in %v", want, keysOf(doc))
		}
	}
	if got := doc["phase"]; got != "submit" {
		t.Errorf("phase = %v, want submit", got)
	}
	items, ok := doc["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("items missing or wrong type: %T", doc["items"])
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("items[0] is %T, want object", items[0])
	}
	for _, want := range []string{"action", "kind", "resource_name", "after"} {
		if _, ok := first[want]; !ok {
			t.Errorf("items[0] missing key %q in %v", want, keysOf(first))
		}
	}
}

// TestCanonicalInputJSON_NestedSnakeCaseRewrite verifies that camelCase
// keys nested inside item.after (which originated from camelCase YAML)
// are rewritten to snake_case at every depth.
func TestCanonicalInputJSON_NestedSnakeCaseRewrite(t *testing.T) {
	productID := domain.NewID()
	cs := domain.ChangeSet{
		ID:          domain.NewID(),
		ProductID:   productID,
		State:       domain.ChangeSetStateDraft,
		Title:       "test",
		RequestedBy: domain.Actor{Kind: domain.ActorHuman, Subject: "alice"},
	}
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		ChangeSetID:  cs.ID,
		Kind:         domain.ChangeSetItemKindServiceAccount,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "payments-batch",
		After: map[string]any{
			"name":         "payments-batch",
			"owner":        "platform",
			"usagePattern": "system-to-system",
			"purpose":      "settlement",
			"authorizations": []any{
				map[string]any{
					"type":        "linux.local-group",
					"scope":       "prod-linux",
					"asUser":      "root",
					"globalObject": "payments-runtime",
				},
			},
		},
	}
	in := Input{
		Phase:     PhaseSubmit,
		Product:   domain.Product{ID: productID, Name: "p", Owner: "o"},
		ChangeSet: cs,
		Items:     []*domain.ChangeSetItem{item},
	}
	raw, err := canonicalInputJSON(in)
	if err != nil {
		t.Fatalf("canonicalInputJSON: %v", err)
	}
	str := string(raw)
	for _, banned := range []string{"usagePattern", "asUser", "globalObject"} {
		if strings.Contains(str, banned) {
			t.Errorf("found camelCase key %q in canonical JSON: %s", banned, str)
		}
	}
	for _, want := range []string{"usage_pattern", "as_user", "global_object"} {
		if !strings.Contains(str, want) {
			t.Errorf("missing snake_case key %q in canonical JSON: %s", want, str)
		}
	}
}

// TestAggregateOutcome covers the deny > escalate > allow precedence rule.
func TestAggregateOutcome(t *testing.T) {
	cases := []struct {
		name  string
		rules []RuleDecision
		want  DecisionOutcome
	}{
		{"empty allows", nil, DecisionAllow},
		{"only allow", []RuleDecision{{Outcome: DecisionAllow}}, DecisionAllow},
		{"escalate over allow", []RuleDecision{
			{Outcome: DecisionAllow},
			{Outcome: DecisionEscalateRequired},
		}, DecisionEscalateRequired},
		{"deny dominates", []RuleDecision{
			{Outcome: DecisionEscalateRequired},
			{Outcome: DecisionDeny},
			{Outcome: DecisionAllow},
		}, DecisionDeny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aggregateOutcome(tc.rules); got != tc.want {
				t.Errorf("aggregateOutcome = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCamelToSnake covers the specific shapes that show up in the YAML
// model: usagePattern, asUser, globalObject, plus a few edge cases.
func TestCamelToSnake(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"name":          "name",
		"owner":         "owner",
		"usagePattern":  "usage_pattern",
		"asUser":        "as_user",
		"globalObject":  "global_object",
		"already_snake": "already_snake",
		"HTTPServer":    "http_server",
		"HTTP":          "http",
		"ID":            "id",
		"id":            "id",
		"camelCase":     "camel_case",
	}
	for in, want := range cases {
		if got := camelToSnake(in); got != want {
			t.Errorf("camelToSnake(%q) = %q, want %q", in, got, want)
		}
	}
}

// sampleSubmitInput builds a tiny but realistic Input for use in tests.
// The shape mirrors what the importer would produce for one entitlement
// add at submission time.
func sampleSubmitInput(t *testing.T) Input {
	t.Helper()
	productID := domain.NewID()
	cs := domain.ChangeSet{
		ID:          domain.NewID(),
		ProductID:   productID,
		State:       domain.ChangeSetStateSubmitted,
		Title:       "add read-only ent",
		Description: "for prod troubleshooting",
		RequestedBy: domain.Actor{Kind: domain.ActorHuman, Subject: "alice"},
		CreatedAt:   time.Now().UTC(),
	}
	item := &domain.ChangeSetItem{
		ID:           domain.NewID(),
		ChangeSetID:  cs.ID,
		Kind:         domain.ChangeSetItemKindEntitlement,
		Action:       domain.ChangeSetActionAdd,
		ResourceName: "payments-prod-readonly",
		After: map[string]any{
			"name":    "payments-prod-readonly",
			"owner":   "platform",
			"purpose": "ro",
			"authorizations": []any{
				map[string]any{
					"type":  "linux.ssh",
					"scope": "prod-linux",
				},
			},
		},
	}
	return Input{
		Phase:     PhaseSubmit,
		Product:   domain.Product{ID: productID, Name: "payments-api", Owner: "platform"},
		ChangeSet: cs,
		Items:     []*domain.ChangeSetItem{item},
	}
}

// assertSnakeKeys walks v and returns an error if any map key contains an
// uppercase rune. Path is for nice error messages only.
func assertSnakeKeys(path string, v any) error {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			if hasUpper(k) {
				return errBadKey(path + "." + k)
			}
			if err := assertSnakeKeys(path+"."+k, vv); err != nil {
				return err
			}
		}
	case []any:
		for i, vv := range x {
			if err := assertSnakeKeys(arrPath(path, i), vv); err != nil {
				return err
			}
		}
	}
	return nil
}

type badKeyErr struct{ path string }

func (e badKeyErr) Error() string { return "non-snake_case key at " + e.path }

func errBadKey(path string) error { return badKeyErr{path: path} }

func arrPath(path string, i int) string {
	return path + "[" + itoa(i) + "]"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
