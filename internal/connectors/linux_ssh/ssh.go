// Package linux_ssh implements the Phase 4 plan-only Linux SSH
// connector. Like linux_sudo, this is a pure function of the
// approved-state model: it emits ssh-access-list plan items for
// entitlements and service accounts that declare linux.ssh
// authorizations. Phase 4 does not resolve principals (humans → uids);
// that lands in Phase 6+. Plans are deterministic and never executed.
package linux_ssh

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/model"
)

const (
	connectorName    = "linux-ssh"
	connectorVersion = "0.4.0"
	schemaVersion    = "linux-ssh.statebound.dev/v0alpha1"
)

// Connector is the linux-ssh plan-only connector.
//
// UnsupportedCollectAndCompare is embedded so the type satisfies the
// Phase 4'+ Connector interface (which gained CollectActualState and
// Compare) without yet implementing drift detection. Both methods
// return ErrCapabilityNotSupported.
//
// Phase 6 added Apply to the Connector contract; linux-ssh remains
// plan-only (Postgres is the first connector to implement Apply), so
// UnsupportedApply is embedded alongside.
type Connector struct {
	connectors.UnsupportedCollectAndCompare
	connectors.UnsupportedApply
}

// New returns a fresh Connector. Stateless; safe to share.
func New() *Connector { return &Connector{} }

// Name returns the stable registry key.
func (*Connector) Name() string { return connectorName }

// Version returns the connector semver.
func (*Connector) Version() string { return connectorVersion }

// Capabilities reports that this connector only supports Plan in Phase 4.
func (*Connector) Capabilities() []connectors.Capability {
	return []connectors.Capability{connectors.CapabilityPlan}
}

// ValidateDesiredState performs soft pre-flight checks for SSH
// authorizations: warn on prod-scoped grants, error on dangling scopes.
func (*Connector) ValidateDesiredState(_ context.Context, state connectors.ApprovedState) ([]connectors.ValidationFinding, error) {
	if state.Model == nil {
		return nil, fmt.Errorf("linux-ssh: ValidateDesiredState: nil model")
	}
	scopes := scopeIndex(state.Model)
	var findings []connectors.ValidationFinding

	ents := append([]model.YAMLEntitlement(nil), state.Model.Spec.Entitlements...)
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })
	for _, ent := range ents {
		for i, auth := range ent.Authorizations {
			if auth.Type != "linux.ssh" {
				continue
			}
			if _, ok := scopes[auth.Scope]; !ok {
				findings = append(findings, connectors.ValidationFinding{
					Severity: "error",
					Path:     fmt.Sprintf("entitlements.%s.authorizations[%d].scope", ent.Name, i),
					Message:  fmt.Sprintf("asset scope %q not defined in model", auth.Scope),
				})
				continue
			}
			if strings.Contains(auth.Scope, "prod") {
				findings = append(findings, connectors.ValidationFinding{
					Severity: "warning",
					Path:     fmt.Sprintf("entitlements.%s.authorizations[%d]", ent.Name, i),
					Message:  "prod-scoped SSH access — reviewer should verify principal eligibility",
				})
			}
		}
	}

	sas := append([]model.YAMLServiceAccount(nil), state.Model.Spec.ServiceAccounts...)
	sort.Slice(sas, func(i, j int) bool { return sas[i].Name < sas[j].Name })
	for _, sa := range sas {
		for i, auth := range sa.Authorizations {
			if auth.Type != "linux.ssh" {
				continue
			}
			if _, ok := scopes[auth.Scope]; !ok {
				findings = append(findings, connectors.ValidationFinding{
					Severity: "error",
					Path:     fmt.Sprintf("serviceAccounts.%s.authorizations[%d].scope", sa.Name, i),
					Message:  fmt.Sprintf("asset scope %q not defined in model", auth.Scope),
				})
				continue
			}
			if strings.Contains(auth.Scope, "prod") {
				findings = append(findings, connectors.ValidationFinding{
					Severity: "warning",
					Path:     fmt.Sprintf("serviceAccounts.%s.authorizations[%d]", sa.Name, i),
					Message:  "prod-scoped SSH access — reviewer should verify principal eligibility",
				})
			}
		}
	}
	return findings, nil
}

// Plan walks the model in deterministic order and emits ssh-access-list
// items for each linux.ssh authorization on entitlements and service
// accounts. Re-running Plan with identical inputs yields a byte-identical
// Content map.
func (*Connector) Plan(_ context.Context, state connectors.ApprovedState) (*connectors.PlanResult, error) {
	if state.Model == nil {
		return nil, fmt.Errorf("linux-ssh: Plan: nil model")
	}

	items := make([]connectors.PlanItem, 0)
	itemsAsMaps := make([]map[string]any, 0)
	seq := 1

	// Entitlements first, sorted by name; then service accounts.
	ents := append([]model.YAMLEntitlement(nil), state.Model.Spec.Entitlements...)
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })

	for _, ent := range ents {
		auths := append([]model.YAMLAuthorization(nil), ent.Authorizations...)
		sort.Slice(auths, func(i, j int) bool {
			ai, aj := auths[i], auths[j]
			if ai.Type != aj.Type {
				return ai.Type < aj.Type
			}
			return ai.Scope < aj.Scope
		})
		for _, auth := range auths {
			if auth.Type != "linux.ssh" {
				continue
			}
			scopeName := auth.Scope
			methods := authorizationMethods(auth)
			sort.Strings(methods)
			body := map[string]any{
				"scope":       scopeName,
				"entitlement": ent.Name,
				"methods":     methods,
				"principals":  []string{},
			}
			risk := "low"
			if strings.Contains(scopeName, "prod") {
				risk = "medium"
			}
			item := connectors.PlanItem{
				Sequence:     seq,
				Action:       "create",
				ResourceKind: "linux.ssh-access-list",
				ResourceRef:  fmt.Sprintf("%s:ssh:%s", scopeName, ent.Name),
				Body:         body,
				Risk:         risk,
				Note:         "principals resolved at apply time (Phase 6+)",
			}
			items = append(items, item)
			itemsAsMaps = append(itemsAsMaps, planItemAsMap(item))
			seq++
		}
	}

	sas := append([]model.YAMLServiceAccount(nil), state.Model.Spec.ServiceAccounts...)
	sort.Slice(sas, func(i, j int) bool { return sas[i].Name < sas[j].Name })

	for _, sa := range sas {
		auths := append([]model.YAMLAuthorization(nil), sa.Authorizations...)
		sort.Slice(auths, func(i, j int) bool {
			ai, aj := auths[i], auths[j]
			if ai.Type != aj.Type {
				return ai.Type < aj.Type
			}
			return ai.Scope < aj.Scope
		})
		for _, auth := range auths {
			if auth.Type != "linux.ssh" {
				continue
			}
			scopeName := auth.Scope
			methods := authorizationMethods(auth)
			sort.Strings(methods)
			body := map[string]any{
				"scope":       scopeName,
				"entitlement": sa.Name,
				"methods":     methods,
				"principals":  []string{sa.Name},
			}
			risk := "low"
			if strings.Contains(scopeName, "prod") {
				risk = "medium"
			}
			item := connectors.PlanItem{
				Sequence:     seq,
				Action:       "create",
				ResourceKind: "linux.ssh-access-list",
				ResourceRef:  fmt.Sprintf("%s:ssh:%s", scopeName, sa.Name),
				Body:         body,
				Risk:         risk,
				Note:         "",
			}
			items = append(items, item)
			itemsAsMaps = append(itemsAsMaps, planItemAsMap(item))
			seq++
		}
	}

	summary := fmt.Sprintf("linux-ssh: %d planned change(s)", len(items))
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

// scopeIndex builds a name -> presence index for AssetScopes so
// validation can flag dangling scope references.
func scopeIndex(m *model.ProductAuthorizationModel) map[string]struct{} {
	out := make(map[string]struct{}, len(m.Spec.AssetScopes))
	for _, s := range m.Spec.AssetScopes {
		out[s.Name] = struct{}{}
	}
	return out
}

// authorizationMethods extracts the methods list from a linux.ssh
// authorization's free-form Spec map. Returns an empty slice if absent.
func authorizationMethods(auth model.YAMLAuthorization) []string {
	if auth.Spec == nil {
		return []string{}
	}
	raw, ok := auth.Spec["methods"]
	if !ok || raw == nil {
		return []string{}
	}
	rawList, ok := raw.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(rawList))
	for _, m := range rawList {
		if s, ok := m.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// planItemAsMap mirrors a PlanItem into the canonical map shape stored in
// PlanResult.Content["items"].
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
