package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"statebound.dev/statebound/internal/domain"
)

// aggregateQuery is the Rego query the evaluator runs. The aggregator
// package (policies/builtin/aggregate.rego) unions every rule package's
// `decision` set into one place so we only have to drive a single query.
const aggregateQuery = "data.statebound.aggregate.decisions"

// opaEvaluator is the production Evaluator. It pre-prepares the Rego query
// once at construction time so per-call Evaluate work is just JSON marshal,
// pq.Eval, and result decoding.
type opaEvaluator struct {
	bundleHash string
	pq         rego.PreparedEvalQuery
	now        func() time.Time
}

// NewOPAEvaluator loads the embedded Rego bundle, computes its hash, and
// prepares the aggregate decisions query. It is safe to call this once at
// process start and reuse the returned Evaluator for the lifetime of the
// process; callers needing concurrent evaluation can share the returned
// value across goroutines.
func NewOPAEvaluator(ctx context.Context) (Evaluator, error) {
	mods, err := loadBundleModules(bundleFS)
	if err != nil {
		return nil, err
	}
	hash, err := computeBundleHash(bundleFS)
	if err != nil {
		return nil, err
	}

	opts := []func(*rego.Rego){rego.Query(aggregateQuery)}
	for _, m := range mods {
		opts = append(opts, rego.Module(m.Filename, m.Source))
	}
	r := rego.New(opts...)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("authz: prepare rego query: %w", err)
	}
	return &opaEvaluator{
		bundleHash: hash,
		pq:         pq,
		now:        func() time.Time { return time.Now().UTC() },
	}, nil
}

// BundleHash returns the deterministic SHA-256 of the embedded Rego bundle
// in hex. Persist this with every PolicyResult so a future replay can
// detect a bundle drift before a re-evaluation.
func (e *opaEvaluator) BundleHash() string { return e.bundleHash }

// Evaluate runs the prepared aggregate query against in. The returned
// PolicyResult is populated in canonical form: Rules are sorted, the
// aggregate Outcome is derived from Rules, and Input is the same JSON
// document that was fed to OPA (so a row in policy_decisions plus the
// bundle hash is a complete replay record).
func (e *opaEvaluator) Evaluate(ctx context.Context, in Input) (*PolicyResult, error) {
	canonical, err := canonicalInputJSON(in)
	if err != nil {
		return nil, fmt.Errorf("authz: build canonical input: %w", err)
	}

	var inputDoc any
	if err := json.Unmarshal(canonical, &inputDoc); err != nil {
		return nil, fmt.Errorf("authz: re-decode canonical input: %w", err)
	}

	rs, err := e.pq.Eval(ctx, rego.EvalInput(inputDoc))
	if err != nil {
		return nil, fmt.Errorf("authz: rego eval: %w", err)
	}

	rules, err := decodeRules(rs)
	if err != nil {
		return nil, err
	}
	sortRules(rules)

	return &PolicyResult{
		DecisionID:  domain.NewID(),
		ChangeSetID: in.ChangeSet.ID,
		Phase:       in.Phase,
		Outcome:     aggregateOutcome(rules),
		Rules:       rules,
		Input:       canonical,
		BundleHash:  e.bundleHash,
		EvaluatedAt: e.now(),
	}, nil
}

// decodeRules walks the OPA result set and turns every emitted decision
// object into a RuleDecision. We expect at most one Result entry whose
// first Expression is a slice of decision maps; an empty result set is a
// legitimate "all rules silent" case and produces a nil slice.
func decodeRules(rs rego.ResultSet) ([]RuleDecision, error) {
	if len(rs) == 0 {
		return nil, nil
	}
	if len(rs[0].Expressions) == 0 {
		return nil, nil
	}
	val := rs[0].Expressions[0].Value
	raw, ok := val.([]any)
	if !ok {
		return nil, fmt.Errorf("authz: aggregate decisions expression has unexpected type %T", val)
	}
	rules := make([]RuleDecision, 0, len(raw))
	for i, item := range raw {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("authz: decision[%d] is %T, want object", i, item)
		}
		rd, err := ruleFromMap(obj)
		if err != nil {
			return nil, fmt.Errorf("authz: decision[%d]: %w", i, err)
		}
		rules = append(rules, rd)
	}
	return rules, nil
}

// ruleFromMap converts the Go-native form of a Rego object decision into a
// RuleDecision. Unknown outcome/severity values pass through unchanged so
// callers can still see them in the audit log; they just won't compare
// equal to the documented constants.
func ruleFromMap(obj map[string]any) (RuleDecision, error) {
	rd := RuleDecision{}
	if v, ok := obj["rule_id"].(string); ok {
		rd.RuleID = v
	} else {
		return rd, fmt.Errorf("missing rule_id")
	}
	if v, ok := obj["outcome"].(string); ok {
		rd.Outcome = DecisionOutcome(v)
	} else {
		return rd, fmt.Errorf("missing outcome")
	}
	if v, ok := obj["message"].(string); ok {
		rd.Message = v
	}
	if v, ok := obj["severity"].(string); ok {
		rd.Severity = Severity(v)
	}
	if v, ok := obj["metadata"].(map[string]any); ok {
		rd.Metadata = v
	}
	return rd, nil
}

// sortRules orders rules deterministically: most severe outcome first,
// then RuleID, then Message. This is the order used both for human-facing
// surfaces (TUI, CLI) and for the canonical JSON in audit payloads.
func sortRules(rules []RuleDecision) {
	sort.SliceStable(rules, func(i, j int) bool {
		ri, rj := outcomeRank(rules[i].Outcome), outcomeRank(rules[j].Outcome)
		if ri != rj {
			return ri < rj
		}
		if rules[i].RuleID != rules[j].RuleID {
			return rules[i].RuleID < rules[j].RuleID
		}
		return rules[i].Message < rules[j].Message
	})
}
