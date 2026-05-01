// Phase 6 drift detection: Compare diffs the desired state (re-derived
// by re-running Plan) against the actual state captured by
// CollectActualState. Findings are emitted in deterministic order so
// repeated calls with identical inputs yield identical output.
//
// ResourceRef alignment is the load-bearing part of this design.
// Plan's ResourceRef format is keyed on (scope, database, schema,
// grantee, privileges, tables); CollectActualState's ResourceRef format
// is keyed on (host, database, schema, grantee, table). They do NOT
// match byte-for-byte. Compare therefore re-keys both sides on a
// canonical (database, schema, grantee, table) tuple before walking
// the union — see canonicalGrantKey / canonicalRoleKey.

package postgres

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"statebound.dev/statebound/internal/connectors"
)

// Compare diffs the desired state (re-derived from Plan) against the
// supplied ActualState. Returns one DriftFinding per mismatch.
//
// A nil actual state is a structural error. An empty actual is fine —
// it just means everything desired is missing.
func (c *Connector) Compare(ctx context.Context, desired connectors.ApprovedState, actual *connectors.ActualState) ([]connectors.DriftFinding, error) {
	if actual == nil {
		return nil, fmt.Errorf("postgres compare: nil actual state")
	}

	plan, err := c.Plan(ctx, desired)
	if err != nil {
		return nil, fmt.Errorf("postgres compare: re-running plan: %w", err)
	}

	// Bucket desired items by (kind, canonical key).
	desiredRoles := map[string]connectors.PlanItem{}
	desiredGrants := map[string]connectors.PlanItem{}
	for _, it := range plan.Items {
		switch it.ResourceKind {
		case "postgres.role":
			desiredRoles[canonicalRoleKey(it.Body)] = it
		case "postgres.grant":
			// One desired grant may target many tables. Expand to one
			// (key,item) pair per table so per-table drift can be
			// detected independently.
			for _, key := range expandGrantToKeys(it.Body) {
				desiredGrants[key] = it
			}
		}
	}

	// Bucket actual items by the same key shapes.
	actualRoles := map[string]connectors.ActualStateItem{}
	actualGrants := map[string]connectors.ActualStateItem{}
	for _, it := range actual.Items {
		switch it.ResourceKind {
		case "postgres.role":
			actualRoles[canonicalRoleKey(it.Body)] = it
		case "postgres.grant":
			for _, key := range expandGrantToKeys(it.Body) {
				actualGrants[key] = it
			}
		}
	}

	findings := make([]connectors.DriftFinding, 0)
	findings = append(findings, compareRoles(desiredRoles, actualRoles)...)
	findings = append(findings, compareGrants(desiredGrants, actualGrants)...)

	// Sort: ResourceRef ASC, Kind ASC, Message ASC.
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.ResourceRef != b.ResourceRef {
			return a.ResourceRef < b.ResourceRef
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Message < b.Message
	})
	return findings, nil
}

// canonicalRoleKey produces a stable identity key for a role from its
// Body shape (works for both desired plan-item bodies and actual
// state-item bodies, since both carry "database" and "role" keys).
func canonicalRoleKey(body map[string]any) string {
	db, _ := body["database"].(string)
	role, _ := body["role"].(string)
	return fmt.Sprintf("%s:role:%s", db, role)
}

// expandGrantToKeys produces one (database, schema, as_role, table)
// canonical key per table in the grant body. A grant body with an
// empty tables list expands to a single "*" entry so empty-vs-empty
// comparison still aligns.
func expandGrantToKeys(body map[string]any) []string {
	db, _ := body["database"].(string)
	schema, _ := body["schema"].(string)
	if schema == "" {
		schema = "*"
	}
	asRole, _ := body["as_role"].(string)
	tables := tablesFromBody(body)
	if len(tables) == 0 {
		return []string{fmt.Sprintf("%s:%s:%s:*", db, schema, asRole)}
	}
	out := make([]string, 0, len(tables))
	for _, t := range tables {
		out = append(out, fmt.Sprintf("%s:%s:%s:%s", db, schema, asRole, t))
	}
	return out
}

// tablesFromBody walks body.objects.tables out of a grant body. Returns
// a sorted []string; tolerates both []string and []any.
func tablesFromBody(body map[string]any) []string {
	objs, ok := body["objects"]
	if !ok || objs == nil {
		return []string{}
	}
	var raw any
	switch m := objs.(type) {
	case map[string]any:
		raw = m["tables"]
	case map[any]any:
		raw = m["tables"]
	default:
		return []string{}
	}
	out := stringList(raw)
	sort.Strings(out)
	return out
}

// privilegesFromBody pulls a sorted upper-case []string privileges
// list out of a body. Tolerates both []string and []any.
func privilegesFromBody(body map[string]any) []string {
	raw, ok := body["privileges"]
	if !ok {
		return []string{}
	}
	out := stringList(raw)
	for i := range out {
		out[i] = strings.ToUpper(strings.TrimSpace(out[i]))
	}
	sort.Strings(out)
	return out
}

// compareRoles walks the union of desired/actual role keys and emits
// findings.
func compareRoles(desired map[string]connectors.PlanItem, actual map[string]connectors.ActualStateItem) []connectors.DriftFinding {
	keys := unionKeys(roleKeyset(desired), actualRoleKeyset(actual))

	var out []connectors.DriftFinding
	for _, k := range keys {
		dItem, dOK := desired[k]
		aItem, aOK := actual[k]
		switch {
		case dOK && !aOK:
			out = append(out, missingRoleFinding(dItem))
		case !dOK && aOK:
			// Unexpected role on the target. We do NOT alert on every
			// system role; collectRoles already filtered pg_*. Other
			// roles are real drift.
			out = append(out, unexpectedRoleFinding(aItem))
		default:
			out = append(out, compareRoleBodies(dItem, aItem)...)
		}
	}
	return out
}

// compareGrants walks the union of desired/actual grant keys and emits
// findings.
func compareGrants(desired map[string]connectors.PlanItem, actual map[string]connectors.ActualStateItem) []connectors.DriftFinding {
	keys := unionKeys(grantKeyset(desired), actualGrantKeyset(actual))

	var out []connectors.DriftFinding
	for _, k := range keys {
		dItem, dOK := desired[k]
		aItem, aOK := actual[k]
		switch {
		case dOK && !aOK:
			out = append(out, missingGrantFinding(dItem))
		case !dOK && aOK:
			out = append(out, unexpectedGrantFinding(aItem))
		default:
			out = append(out, compareGrantBodies(dItem, aItem)...)
		}
	}
	return out
}

// roleKeyset / grantKeyset / actual* return the set of keys for one of
// the maps so we can union them for the walk.
func roleKeyset(in map[string]connectors.PlanItem) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}
func actualRoleKeyset(in map[string]connectors.ActualStateItem) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}
func grantKeyset(in map[string]connectors.PlanItem) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}
func actualGrantKeyset(in map[string]connectors.ActualStateItem) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

// unionKeys returns the union of two key sets in lex-sorted order.
func unionKeys(a, b map[string]struct{}) []string {
	merged := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		merged[k] = struct{}{}
	}
	for k := range b {
		merged[k] = struct{}{}
	}
	out := make([]string, 0, len(merged))
	for k := range merged {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// missingRoleFinding flags a desired role that has no actual counterpart.
func missingRoleFinding(d connectors.PlanItem) connectors.DriftFinding {
	severity := "medium"
	if strings.ToLower(d.Risk) == "high" || strings.ToLower(d.Risk) == "critical" {
		severity = "high"
	}
	return connectors.DriftFinding{
		Kind:         "missing",
		Severity:     severity,
		ResourceKind: d.ResourceKind,
		ResourceRef:  d.ResourceRef,
		Desired:      d.Body,
		Actual:       nil,
		Diff: map[string]any{
			"missing_resource": d.ResourceRef,
		},
		Message: fmt.Sprintf("%s missing on target", d.ResourceRef),
	}
}

// unexpectedRoleFinding flags an actual role with no desired counterpart.
func unexpectedRoleFinding(a connectors.ActualStateItem) connectors.DriftFinding {
	return connectors.DriftFinding{
		Kind:         "unexpected",
		Severity:     "medium",
		ResourceKind: a.ResourceKind,
		ResourceRef:  a.ResourceRef,
		Desired:      nil,
		Actual:       a.Body,
		Diff: map[string]any{
			"unexpected_resource": a.ResourceRef,
		},
		Message: fmt.Sprintf("%s exists on target but not in desired state", a.ResourceRef),
	}
}

// compareRoleBodies emits per-field drift findings (login, inherit,
// connection_limit). No diff in any dimension yields no finding.
func compareRoleBodies(d connectors.PlanItem, a connectors.ActualStateItem) []connectors.DriftFinding {
	var out []connectors.DriftFinding

	dLogin, _ := d.Body["login"].(bool)
	aLogin, _ := a.Body["login"].(bool)
	if dLogin != aLogin {
		out = append(out, connectors.DriftFinding{
			Kind:         "modified",
			Severity:     "high",
			ResourceKind: d.ResourceKind,
			ResourceRef:  d.ResourceRef,
			Desired:      d.Body,
			Actual:       a.Body,
			Diff: map[string]any{
				"field":         "login",
				"desired_login": dLogin,
				"actual_login":  aLogin,
			},
			Message: fmt.Sprintf("%s login changed: desired=%t actual=%t", d.ResourceRef, dLogin, aLogin),
		})
	}

	dInherit, _ := d.Body["inherit"].(bool)
	aInherit, _ := a.Body["inherit"].(bool)
	if dInherit != aInherit {
		out = append(out, connectors.DriftFinding{
			Kind:         "modified",
			Severity:     "medium",
			ResourceKind: d.ResourceKind,
			ResourceRef:  d.ResourceRef,
			Desired:      d.Body,
			Actual:       a.Body,
			Diff: map[string]any{
				"field":           "inherit",
				"desired_inherit": dInherit,
				"actual_inherit":  aInherit,
			},
			Message: fmt.Sprintf("%s inherit changed: desired=%t actual=%t", d.ResourceRef, dInherit, aInherit),
		})
	}

	dCL := intFromBody(d.Body, "connection_limit", -1)
	aCL := intFromBody(a.Body, "connection_limit", -1)
	if dCL != aCL {
		out = append(out, connectors.DriftFinding{
			Kind:         "modified",
			Severity:     "medium",
			ResourceKind: d.ResourceKind,
			ResourceRef:  d.ResourceRef,
			Desired:      d.Body,
			Actual:       a.Body,
			Diff: map[string]any{
				"field":                    "connection_limit",
				"desired_connection_limit": dCL,
				"actual_connection_limit":  aCL,
			},
			Message: fmt.Sprintf("%s connection_limit changed: desired=%d actual=%d", d.ResourceRef, dCL, aCL),
		})
	}

	return out
}

// missingGrantFinding flags a desired grant absent from the target.
func missingGrantFinding(d connectors.PlanItem) connectors.DriftFinding {
	severity := privilegeSeverity(privilegesFromBody(d.Body))
	if severity == "low" {
		// Even a pure SELECT grant absent from prod is medium-worthy.
		severity = "medium"
	}
	return connectors.DriftFinding{
		Kind:         "missing",
		Severity:     severity,
		ResourceKind: d.ResourceKind,
		ResourceRef:  d.ResourceRef,
		Desired:      d.Body,
		Actual:       nil,
		Diff: map[string]any{
			"missing_resource": d.ResourceRef,
		},
		Message: fmt.Sprintf("%s missing on target", d.ResourceRef),
	}
}

// unexpectedGrantFinding flags a grant on the target with no desired
// counterpart. Severity reflects what is being granted, since extra
// privileges are the more dangerous direction.
func unexpectedGrantFinding(a connectors.ActualStateItem) connectors.DriftFinding {
	severity := privilegeSeverity(privilegesFromBody(a.Body))
	if severity == "low" {
		severity = "medium"
	}
	return connectors.DriftFinding{
		Kind:         "unexpected",
		Severity:     severity,
		ResourceKind: a.ResourceKind,
		ResourceRef:  a.ResourceRef,
		Desired:      nil,
		Actual:       a.Body,
		Diff: map[string]any{
			"unexpected_resource": a.ResourceRef,
		},
		Message: fmt.Sprintf("%s exists on target but not in desired state", a.ResourceRef),
	}
}

// compareGrantBodies emits a privileges drift finding when the
// privilege set differs between desired and actual.
func compareGrantBodies(d connectors.PlanItem, a connectors.ActualStateItem) []connectors.DriftFinding {
	dPrivs := privilegesFromBody(d.Body)
	aPrivs := privilegesFromBody(a.Body)
	added, removed := diffStringSets(dPrivs, aPrivs)
	if len(added) == 0 && len(removed) == 0 {
		return nil
	}
	severity := grantChangeSeverity(added, removed)
	return []connectors.DriftFinding{{
		Kind:         "modified",
		Severity:     severity,
		ResourceKind: d.ResourceKind,
		ResourceRef:  d.ResourceRef,
		Desired:      d.Body,
		Actual:       a.Body,
		Diff: map[string]any{
			"added_privileges":   added,
			"removed_privileges": removed,
		},
		Message: fmt.Sprintf("%s privileges drifted (+%d, -%d)", d.ResourceRef, len(added), len(removed)),
	}}
}

// grantChangeSeverity classifies a privilege delta. Added DELETE,
// TRUNCATE, or ALL is high severity; everything else is medium.
func grantChangeSeverity(added, removed []string) string {
	for _, p := range added {
		up := strings.ToUpper(strings.TrimSpace(p))
		if up == "ALL" || up == "ALL PRIVILEGES" || up == "DELETE" || up == "TRUNCATE" {
			return "high"
		}
	}
	_ = removed
	return "medium"
}

// diffStringSets returns (added, removed) where added is "in actual,
// not desired" and removed is "in desired, not actual". Inputs need
// not be pre-sorted; both outputs are lex-sorted.
func diffStringSets(desired, actual []string) (added, removed []string) {
	desiredSet := make(map[string]struct{}, len(desired))
	for _, d := range desired {
		desiredSet[d] = struct{}{}
	}
	actualSet := make(map[string]struct{}, len(actual))
	for _, a := range actual {
		actualSet[a] = struct{}{}
	}
	for _, a := range actual {
		if _, ok := desiredSet[a]; !ok {
			added = append(added, a)
		}
	}
	for _, d := range desired {
		if _, ok := actualSet[d]; !ok {
			removed = append(removed, d)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if added == nil {
		added = []string{}
	}
	if removed == nil {
		removed = []string{}
	}
	return added, removed
}

// intFromBody pulls an int field out of a body, with a default if the
// key is absent or unconvertible.
func intFromBody(body map[string]any, key string, def int) int {
	v, ok := body[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return def
}
