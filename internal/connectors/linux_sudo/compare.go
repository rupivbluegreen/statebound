// Phase 4' drift detection: Compare diffs the desired state (re-derived
// by re-running Plan) against the actual state captured by
// CollectActualState. Findings are emitted in deterministic order so
// repeated calls with identical inputs yield identical output.

package linux_sudo

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"statebound.dev/statebound/internal/connectors"
)

// Compare diffs the desired state against the supplied ActualState.
// Compare is implemented as a function of the existing Plan output:
// it re-runs Plan(state) to recover the desired body shape per
// ResourceRef, then walks the union of desired + actual keys.
//
// A nil actual is a structural error. An empty actual is fine — it
// just means every desired item is missing.
func (c *Connector) Compare(ctx context.Context, desired connectors.ApprovedState, actual *connectors.ActualState) ([]connectors.DriftFinding, error) {
	if actual == nil {
		return nil, fmt.Errorf("linux-sudo compare: nil actual state")
	}

	plan, err := c.Plan(ctx, desired)
	if err != nil {
		return nil, fmt.Errorf("linux-sudo compare: re-running plan: %w", err)
	}

	desiredByRef := make(map[string]connectors.PlanItem, len(plan.Items))
	for _, it := range plan.Items {
		desiredByRef[it.ResourceRef] = it
	}
	actualByRef := make(map[string]connectors.ActualStateItem, len(actual.Items))
	for _, it := range actual.Items {
		actualByRef[it.ResourceRef] = it
	}

	keySet := make(map[string]struct{}, len(desiredByRef)+len(actualByRef))
	for k := range desiredByRef {
		keySet[k] = struct{}{}
	}
	for k := range actualByRef {
		keySet[k] = struct{}{}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	findings := make([]connectors.DriftFinding, 0)
	for _, ref := range keys {
		dItem, dOK := desiredByRef[ref]
		aItem, aOK := actualByRef[ref]

		switch {
		case dOK && !aOK:
			findings = append(findings, missingFinding(dItem))
		case !dOK && aOK:
			findings = append(findings, unexpectedFinding(aItem))
		default:
			findings = append(findings, compareBodies(dItem, aItem)...)
		}
	}

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

// missingFinding flags a desired item that has no actual counterpart on
// the host. Severity inherits from the desired body's risk shape:
// wildcard allows → critical, root as_user → high, otherwise low.
func missingFinding(d connectors.PlanItem) connectors.DriftFinding {
	severity := severityFromDesiredBody(d)
	return connectors.DriftFinding{
		Kind:         "missing",
		Severity:     severity,
		ResourceKind: d.ResourceKind,
		ResourceRef:  d.ResourceRef,
		Desired:      d.Body,
		Actual:       nil,
		Diff: map[string]any{
			"missing_resource": d.ResourceRef,
			"expected_kind":    d.ResourceKind,
		},
		Message: fmt.Sprintf("%s missing on host", d.ResourceRef),
	}
}

// unexpectedFinding flags an actual item with no desired counterpart.
// Any extra grant on the host is medium severity for sudoers.
func unexpectedFinding(a connectors.ActualStateItem) connectors.DriftFinding {
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
		Message: fmt.Sprintf("%s exists on host but not in desired state", a.ResourceRef),
	}
}

// compareBodies diffs a desired sudoers fragment (or local-group
// membership) against its observed counterpart. Up to three findings
// per resource: as_user mismatch, allow-list mismatch, deny-list
// mismatch (or member-list mismatch for groups). No diff in either
// dimension yields no finding for that dimension.
func compareBodies(d connectors.PlanItem, a connectors.ActualStateItem) []connectors.DriftFinding {
	switch d.ResourceKind {
	case "linux.sudoers-fragment":
		return compareSudoersBodies(d, a)
	case "linux.local-group-membership":
		return compareGroupBodies(d, a)
	default:
		return nil
	}
}

// compareSudoersBodies emits findings for sudoers fragment drift.
func compareSudoersBodies(d connectors.PlanItem, a connectors.ActualStateItem) []connectors.DriftFinding {
	var out []connectors.DriftFinding

	desiredAsUser, _ := d.Body["as_user"].(string)
	actualAsUser, _ := a.Body["as_user"].(string)
	if desiredAsUser != actualAsUser {
		out = append(out, connectors.DriftFinding{
			Kind:         "modified",
			Severity:     "high",
			ResourceKind: d.ResourceKind,
			ResourceRef:  d.ResourceRef,
			Desired:      d.Body,
			Actual:       a.Body,
			Diff: map[string]any{
				"field":          "as_user",
				"desired_as_user": desiredAsUser,
				"actual_as_user":  actualAsUser,
			},
			Message: fmt.Sprintf("%s as_user changed: desired=%q actual=%q", d.ResourceRef, desiredAsUser, actualAsUser),
		})
	}

	// Allow-list comparison.
	desiredAllows := desiredAllowList(d)
	actualAllows := stringListFromBody(a.Body, "allows")
	added, removed := diffSortedLists(desiredAllows, actualAllows)
	if len(added) > 0 || len(removed) > 0 {
		out = append(out, connectors.DriftFinding{
			Kind:         "modified",
			Severity:     allowChangeSeverity(added, removed),
			ResourceKind: d.ResourceKind,
			ResourceRef:  d.ResourceRef,
			Desired:      d.Body,
			Actual:       a.Body,
			Diff: map[string]any{
				"added_allows":   added,
				"removed_allows": removed,
			},
			Message: fmt.Sprintf("%s allow list drifted (+%d, -%d)", d.ResourceRef, len(added), len(removed)),
		})
	}

	// Deny-list comparison.
	desiredDenies := desiredDenyList(d)
	actualDenies := stringListFromBody(a.Body, "denies")
	addedD, removedD := diffSortedLists(desiredDenies, actualDenies)
	if len(addedD) > 0 || len(removedD) > 0 {
		out = append(out, connectors.DriftFinding{
			Kind:         "modified",
			Severity:     "medium",
			ResourceKind: d.ResourceKind,
			ResourceRef:  d.ResourceRef,
			Desired:      d.Body,
			Actual:       a.Body,
			Diff: map[string]any{
				"added_denies":   addedD,
				"removed_denies": removedD,
			},
			Message: fmt.Sprintf("%s deny list drifted (+%d, -%d)", d.ResourceRef, len(addedD), len(removedD)),
		})
	}

	return out
}

// compareGroupBodies emits a single membership-drift finding when the
// member set differs.
func compareGroupBodies(d connectors.PlanItem, a connectors.ActualStateItem) []connectors.DriftFinding {
	desiredMembers := stringListFromBody(d.Body, "members")
	actualMembers := stringListFromBody(a.Body, "members")
	added, removed := diffSortedLists(desiredMembers, actualMembers)
	if len(added) == 0 && len(removed) == 0 {
		return nil
	}
	return []connectors.DriftFinding{{
		Kind:         "modified",
		Severity:     "medium",
		ResourceKind: d.ResourceKind,
		ResourceRef:  d.ResourceRef,
		Desired:      d.Body,
		Actual:       a.Body,
		Diff: map[string]any{
			"added_members":   added,
			"removed_members": removed,
		},
		Message: fmt.Sprintf("%s membership drifted (+%d, -%d)", d.ResourceRef, len(added), len(removed)),
	}}
}

// severityFromDesiredBody re-derives the risk tier of a desired item
// without round-tripping through classifySudoRisk. We inspect the
// rendered content + as_user fields the plan stuffed into Body.
func severityFromDesiredBody(d connectors.PlanItem) string {
	switch d.ResourceKind {
	case "linux.sudoers-fragment":
		// Allow-list lives in the rendered "content" string, but the
		// plan's PlanItem.Risk already carries the canonical
		// classification. Use it directly so we stay in lockstep with
		// classifySudoRisk.
		switch strings.ToLower(d.Risk) {
		case "critical":
			return "critical"
		case "high":
			return "high"
		case "medium":
			return "medium"
		}
		// Fall back: probe the body for as_user==root.
		if asUser, _ := d.Body["as_user"].(string); asUser == "root" {
			return "high"
		}
		return "low"
	case "linux.local-group-membership":
		if strings.ToLower(d.Risk) == "medium" {
			return "medium"
		}
		return "low"
	default:
		return "low"
	}
}

// allowChangeSeverity classifies an allow-list delta:
//   - critical if any added command is a literal "*" or contains "*";
//   - high    if any added or removed command contains "root" or "*";
//   - medium  otherwise.
func allowChangeSeverity(added, removed []string) string {
	for _, cmd := range added {
		trimmed := strings.TrimSpace(cmd)
		upper := strings.ToUpper(trimmed)
		if upper == "*" || upper == "ALL" || upper == "*:ALL" {
			return "critical"
		}
		if strings.Contains(cmd, "*") {
			return "critical"
		}
	}
	for _, cmd := range append(append([]string{}, added...), removed...) {
		if strings.Contains(cmd, "*") {
			return "high"
		}
		if strings.Contains(cmd, "root") {
			return "high"
		}
	}
	return "medium"
}

// desiredAllowList recovers the desired allow list. The plan body
// stores it inside the rendered "content" string, but for a clean
// comparison we re-parse the content using the same parser the
// collector uses — this guarantees the desired side and actual side
// are normalised identically.
func desiredAllowList(d connectors.PlanItem) []string {
	content, _ := d.Body["content"].(string)
	parsed := parseSudoersFragment([]byte(content))
	return parsed.allows
}

// desiredDenyList mirrors desiredAllowList but for denies.
func desiredDenyList(d connectors.PlanItem) []string {
	content, _ := d.Body["content"].(string)
	parsed := parseSudoersFragment([]byte(content))
	return parsed.denies
}

// stringListFromBody pulls a []string out of a map[string]any body.
// Tolerates both []string and []any (json round-trip artifact).
func stringListFromBody(body map[string]any, key string) []string {
	raw, ok := body[key]
	if !ok || raw == nil {
		return []string{}
	}
	switch v := raw.(type) {
	case []string:
		out := append([]string(nil), v...)
		sort.Strings(out)
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	default:
		return []string{}
	}
}

// diffSortedLists returns (added, removed): items in actual but not in
// desired, and items in desired but not in actual. Both inputs are
// expected to be lex-sorted; the function does not re-sort.
func diffSortedLists(desired, actual []string) (added, removed []string) {
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
	if added == nil {
		added = []string{}
	}
	if removed == nil {
		removed = []string{}
	}
	return added, removed
}
