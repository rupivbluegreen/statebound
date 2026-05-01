// Package linux_sudo implements the Phase 4 plan-only Linux sudo
// connector. It is a pure function of the approved-state model: given a
// ProductAuthorizationModel, it emits sudoers fragments for entitlements
// with linux.sudo authorizations and local-group memberships for service
// accounts with linux.local-group authorizations. It never executes sudo,
// SSH, or any shell command — Phase 4 is plan-only.
package linux_sudo

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/model"
)

// connectorName / connectorVersion are exported via the Connector
// methods. Bump connectorVersion on any change to plan output shape so
// content_hash divergence is observable in audit logs.
const (
	connectorName    = "linux-sudo"
	connectorVersion = "0.4.0"
	schemaVersion    = "linux-sudo.statebound.dev/v0alpha1"
)

// Connector is the linux-sudo plan + drift connector. Phase 4 shipped
// the Plan path; Phase 4' added CollectActualState (read sudoers
// fragments off disk) and Compare (diff observed bytes against the
// approved-state plan). All operations are pure file IO — the
// connector never executes sudo, ssh, or any shell command.
type Connector struct{}

// New returns a fresh Connector. Stateless; safe to share.
func New() *Connector { return &Connector{} }

// Name returns the stable registry key.
func (*Connector) Name() string { return connectorName }

// Version returns the connector semver.
func (*Connector) Version() string { return connectorVersion }

// Capabilities reports Plan, CollectActualState, and Compare. Phase 4'
// adds drift detection on top of the Phase 4 plan path.
func (*Connector) Capabilities() []connectors.Capability {
	return []connectors.Capability{
		connectors.CapabilityPlan,
		connectors.CapabilityCollectActual,
		connectors.CapabilityCompare,
	}
}

// ValidateDesiredState performs soft pre-flight checks against the
// approved state. Findings are returned as ValidationFinding; only
// structurally-invalid input produces a non-nil error.
func (*Connector) ValidateDesiredState(_ context.Context, state connectors.ApprovedState) ([]connectors.ValidationFinding, error) {
	if state.Model == nil {
		return nil, fmt.Errorf("linux-sudo: ValidateDesiredState: nil model")
	}
	scopes := scopeIndex(state.Model)
	var findings []connectors.ValidationFinding

	// Sort entitlements for deterministic finding order.
	ents := append([]model.YAMLEntitlement(nil), state.Model.Spec.Entitlements...)
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })

	for _, ent := range ents {
		for i, auth := range ent.Authorizations {
			if auth.Type != "linux.sudo" {
				continue
			}
			// Missing scope.
			if _, ok := scopes[auth.Scope]; !ok {
				findings = append(findings, connectors.ValidationFinding{
					Severity: "error",
					Path:     fmt.Sprintf("entitlements.%s.authorizations[%d].scope", ent.Name, i),
					Message:  fmt.Sprintf("asset scope %q not defined in model", auth.Scope),
				})
			}
			allows := authorizationAllowList(auth)
			denies := authorizationDenyList(auth)
			// Empty allow + deny is an error: nothing to enforce.
			if len(allows) == 0 && len(denies) == 0 {
				findings = append(findings, connectors.ValidationFinding{
					Severity: "error",
					Path:     fmt.Sprintf("entitlements.%s.authorizations[%d].commands", ent.Name, i),
					Message:  "linux.sudo authorization has empty allow and deny lists",
				})
			}
			// Wildcard allow commands: warn for elevated approval.
			for j, cmd := range allows {
				if strings.Contains(cmd, "*") {
					findings = append(findings, connectors.ValidationFinding{
						Severity: "warning",
						Path:     fmt.Sprintf("entitlements.%s.authorizations[%d].commands.allow[%d]", ent.Name, i, j),
						Message:  "wildcard sudo command flagged for elevated approval",
					})
				}
			}
			// Root-equivalent grant warning.
			if authorizationAsUser(auth) == "root" {
				findings = append(findings, connectors.ValidationFinding{
					Severity: "warning",
					Path:     fmt.Sprintf("entitlements.%s.authorizations[%d].asUser", ent.Name, i),
					Message:  "root-equivalent grant",
				})
			}
		}
	}
	return findings, nil
}

// Plan walks the model in deterministic order and emits PlanItems for
// linux.sudo authorizations and linux.local-group memberships. Re-running
// Plan with identical inputs MUST produce a byte-identical Content map
// (the storage layer keys plans on content_hash).
func (*Connector) Plan(_ context.Context, state connectors.ApprovedState) (*connectors.PlanResult, error) {
	if state.Model == nil {
		return nil, fmt.Errorf("linux-sudo: Plan: nil model")
	}

	items := make([]connectors.PlanItem, 0)
	itemsAsMaps := make([]map[string]any, 0)
	seq := 1

	// 1. Entitlements first, then service accounts. Within each,
	// sort by name for deterministic ordering.
	ents := append([]model.YAMLEntitlement(nil), state.Model.Spec.Entitlements...)
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })

	for _, ent := range ents {
		auths := append([]model.YAMLAuthorization(nil), ent.Authorizations...)
		sort.Slice(auths, func(i, j int) bool {
			ai, aj := auths[i], auths[j]
			if ai.Type != aj.Type {
				return ai.Type < aj.Type
			}
			if ai.Scope != aj.Scope {
				return ai.Scope < aj.Scope
			}
			return authorizationAsUser(ai) < authorizationAsUser(aj)
		})
		for _, auth := range auths {
			if auth.Type != "linux.sudo" {
				continue
			}
			// One PlanItem per scope. Scope here is a single name; the
			// list spec ("for each AssetScope referenced via Scope")
			// degenerates to a single scope per authorization in the
			// current YAML schema. We keep the sort step explicit so a
			// future multi-scope authorization shape lands correctly.
			scopes := []string{auth.Scope}
			sort.Strings(scopes)
			for _, scopeName := range scopes {
				body := buildSudoersBody(ent, auth, scopeName, state.Sequence)
				risk := classifySudoRisk(auth)
				note := fmt.Sprintf("%d commands allowed; %d denied",
					len(authorizationAllowList(auth)),
					len(authorizationDenyList(auth)),
				)
				resourceRef := fmt.Sprintf("%s:/etc/sudoers.d/%s", scopeName, ent.Name)

				item := connectors.PlanItem{
					Sequence:     seq,
					Action:       "create",
					ResourceKind: "linux.sudoers-fragment",
					ResourceRef:  resourceRef,
					Body:         body,
					Risk:         risk,
					Note:         note,
				}
				items = append(items, item)
				itemsAsMaps = append(itemsAsMaps, planItemAsMap(item))
				seq++
			}
		}
	}

	// 2. Service accounts with linux.local-group authorizations.
	sas := append([]model.YAMLServiceAccount(nil), state.Model.Spec.ServiceAccounts...)
	sort.Slice(sas, func(i, j int) bool { return sas[i].Name < sas[j].Name })

	for _, sa := range sas {
		auths := append([]model.YAMLAuthorization(nil), sa.Authorizations...)
		sort.Slice(auths, func(i, j int) bool {
			ai, aj := auths[i], auths[j]
			if ai.Type != aj.Type {
				return ai.Type < aj.Type
			}
			if ai.Scope != aj.Scope {
				return ai.Scope < aj.Scope
			}
			return authorizationGroup(ai) < authorizationGroup(aj)
		})
		for _, auth := range auths {
			if auth.Type != "linux.local-group" {
				continue
			}
			group := authorizationGroup(auth)
			scopeName := auth.Scope
			body := map[string]any{
				"scope":   scopeName,
				"group":   group,
				"members": []string{sa.Name},
			}
			risk := "low"
			if strings.Contains(scopeName, "prod") {
				risk = "medium"
			}
			item := connectors.PlanItem{
				Sequence:     seq,
				Action:       "create",
				ResourceKind: "linux.local-group-membership",
				ResourceRef:  fmt.Sprintf("%s:%s", scopeName, group),
				Body:         body,
				Risk:         risk,
				Note:         "",
			}
			items = append(items, item)
			itemsAsMaps = append(itemsAsMaps, planItemAsMap(item))
			seq++
		}
	}

	summary := fmt.Sprintf("linux-sudo: %d planned change(s)", len(items))
	content := map[string]any{
		"schema_version":            schemaVersion,
		"connector":                 connectorName,
		"version":                   connectorVersion,
		"approved_version_sequence": state.Sequence,
		"items":                     itemsAsMaps,
		"summary":                   summary,
	}

	return &connectors.PlanResult{
		ConnectorName:    connectorName,
		ConnectorVersion: connectorVersion,
		Summary:          summary,
		Items:            items,
		Content:          content,
	}, nil
}

// buildSudoersBody constructs the canonical Body map for a sudoers
// fragment plan item, including the rendered fragment text.
func buildSudoersBody(ent model.YAMLEntitlement, auth model.YAMLAuthorization, scopeName string, sequence int64) map[string]any {
	asUser := authorizationAsUser(auth)
	if asUser == "" {
		asUser = "root"
	}
	content := renderSudoersFragment(ent.Name, scopeName, asUser, auth, sequence)
	return map[string]any{
		"path":        fmt.Sprintf("/etc/sudoers.d/%s", ent.Name),
		"scope":       scopeName,
		"entitlement": ent.Name,
		"as_user":     asUser,
		"content":     content,
	}
}

// renderSudoersFragment formats the sudoers file text. Format is:
//
//   # Generated by statebound — do not edit by hand
//   # Source: entitlement=<name> asset_scope=<scope> approved_version=<sequence>
//   %<entitlement> ALL=(<as_user>) <COMMA_SORTED_ALLOWS>
//   %<entitlement> ALL=(<as_user>) !<DENY_CMD>
//
// Allow line is omitted entirely if no allow commands. Deny lines are one
// per deny command, lex-sorted, omitted if no denies. Trailing newline.
func renderSudoersFragment(entName, scopeName, asUser string, auth model.YAMLAuthorization, sequence int64) string {
	allows := append([]string(nil), authorizationAllowList(auth)...)
	denies := append([]string(nil), authorizationDenyList(auth)...)
	sort.Strings(allows)
	sort.Strings(denies)

	var b strings.Builder
	b.WriteString("# Generated by statebound — do not edit by hand\n")
	b.WriteString(fmt.Sprintf("# Source: entitlement=%s asset_scope=%s approved_version=%d\n",
		entName, scopeName, sequence))
	if len(allows) > 0 {
		b.WriteString(fmt.Sprintf("%%%s ALL=(%s) %s\n",
			entName, asUser, strings.Join(allows, ", ")))
	}
	for _, deny := range denies {
		b.WriteString(fmt.Sprintf("%%%s ALL=(%s) !%s\n", entName, asUser, deny))
	}
	return b.String()
}

// classifySudoRisk computes the risk tier for a linux.sudo plan item:
//   - "critical" if any allow command is "*"/"ALL"/"*:ALL" (case-insensitive
//     after trim) OR contains a "*" wildcard;
//   - "high" if as_user == "root" (case-sensitive);
//   - "low" otherwise.
func classifySudoRisk(auth model.YAMLAuthorization) string {
	for _, cmd := range authorizationAllowList(auth) {
		trimmed := strings.TrimSpace(cmd)
		upper := strings.ToUpper(trimmed)
		if upper == "*" || upper == "ALL" || upper == "*:ALL" {
			return "critical"
		}
		if strings.Contains(cmd, "*") {
			return "critical"
		}
	}
	if authorizationAsUser(auth) == "root" {
		return "high"
	}
	return "low"
}

// scopeIndex builds a name -> presence index for AssetScopes so
// validation can flag dangling scope references.
func scopeIndex(m *model.ProductAuthorizationModel) map[string]struct{} {
	out := make(map[string]struct{}, len(m.Spec.AssetScopes))
	for _, s := range m.Spec.AssetScopes {
		out[s.Name] = struct{}{}
	}
	return out
}

// authorizationAsUser pulls the asUser value out of YAMLAuthorization.Spec.
// Returns "" if absent or wrong type.
func authorizationAsUser(auth model.YAMLAuthorization) string {
	if auth.Spec == nil {
		return ""
	}
	v, ok := auth.Spec["asUser"]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// authorizationGroup pulls the group value out of YAMLAuthorization.Spec.
func authorizationGroup(auth model.YAMLAuthorization) string {
	if auth.Spec == nil {
		return ""
	}
	v, ok := auth.Spec["group"]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// authorizationAllowList extracts commands.allow as a []string. The yaml
// decoder lands the value as []any with string elements; non-strings are
// silently skipped.
func authorizationAllowList(auth model.YAMLAuthorization) []string {
	return authorizationCommandList(auth, "allow")
}

// authorizationDenyList extracts commands.deny as a []string.
func authorizationDenyList(auth model.YAMLAuthorization) []string {
	return authorizationCommandList(auth, "deny")
}

// authorizationCommandList walks Spec["commands"][which] and coerces
// string entries into a slice. Returns nil if the path is absent.
func authorizationCommandList(auth model.YAMLAuthorization, which string) []string {
	if auth.Spec == nil {
		return nil
	}
	cmds, ok := auth.Spec["commands"]
	if !ok || cmds == nil {
		return nil
	}
	cmdsMap, ok := cmds.(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := cmdsMap[which]
	if !ok || raw == nil {
		return nil
	}
	rawList, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(rawList))
	for _, item := range rawList {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// planItemAsMap mirrors a PlanItem into the canonical map shape stored in
// PlanResult.Content["items"]. Keeps Content self-contained so canonical
// JSON exports do not need a back-reference to the connector type.
func planItemAsMap(it connectors.PlanItem) map[string]any {
	return map[string]any{
		"sequence":      it.Sequence,
		"action":        it.Action,
		"resource_kind": it.ResourceKind,
		"resource_ref":  it.ResourceRef,
		"body":          it.Body,
		"risk":          it.Risk,
		"note":          it.Note,
	}
}
