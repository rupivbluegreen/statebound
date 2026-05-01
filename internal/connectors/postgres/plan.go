// Phase 6 plan-path implementation. Plan walks the approved-state
// model in deterministic order and emits PlanItems for postgres.role
// authorizations on service accounts and postgres.grant authorizations
// on entitlements (and on service accounts, in case a SA needs an
// explicit grant rather than role-based access).
//
// Determinism rules — required for content_hash stability:
//   - Entitlements / service accounts iterated in name-ascending order.
//   - Within each, authorizations iterated in (Type, Scope, Body) order.
//   - Within each authorization, privilege and table lists are sorted
//     before they enter the PlanItem body.
//   - PlanItem.Sequence is assigned at emission time so reordering
//     authoring inputs reorders sequence numbers but never produces
//     gaps.

package postgres

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"statebound.dev/statebound/internal/connectors"
	"statebound.dev/statebound/internal/model"
)

// authTypeRole / authTypeGrant are the YAMLAuthorization.Type values
// this connector handles. Anything else in the model is silently
// ignored — that is the linux_sudo / linux_ssh convention and lets
// multiple connectors target the same model without coordination.
const (
	authTypeRole  = "postgres.role"
	authTypeGrant = "postgres.grant"
)

// ValidateDesiredState performs soft pre-flight checks. Findings are
// returned as ValidationFinding; only structurally-invalid input
// (nil model) produces a non-nil error. The CLI prints "warning"
// findings without blocking; "error" findings should block apply.
func (*Connector) ValidateDesiredState(_ context.Context, state connectors.ApprovedState) ([]connectors.ValidationFinding, error) {
	if state.Model == nil {
		return nil, fmt.Errorf("postgres: ValidateDesiredState: nil model")
	}
	scopes := scopeIndex(state.Model)
	envByScope := scopeEnvironments(state.Model)
	_ = envByScope // reserved for future env-driven validation

	var findings []connectors.ValidationFinding

	// Iterate in name order so finding output is deterministic.
	ents := append([]model.YAMLEntitlement(nil), state.Model.Spec.Entitlements...)
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })
	for _, ent := range ents {
		for i, auth := range ent.Authorizations {
			if !isPostgresAuth(auth.Type) {
				continue
			}
			path := fmt.Sprintf("entitlements.%s.authorizations[%d]", ent.Name, i)
			findings = append(findings, validateAuth(auth, path, scopes)...)
		}
	}

	sas := append([]model.YAMLServiceAccount(nil), state.Model.Spec.ServiceAccounts...)
	sort.Slice(sas, func(i, j int) bool { return sas[i].Name < sas[j].Name })
	for _, sa := range sas {
		for i, auth := range sa.Authorizations {
			if !isPostgresAuth(auth.Type) {
				continue
			}
			path := fmt.Sprintf("serviceAccounts.%s.authorizations[%d]", sa.Name, i)
			findings = append(findings, validateAuth(auth, path, scopes)...)
		}
	}

	return findings, nil
}

// validateAuth runs all field-level checks for one postgres.* auth.
func validateAuth(auth model.YAMLAuthorization, path string, scopes map[string]struct{}) []connectors.ValidationFinding {
	var out []connectors.ValidationFinding

	// Scope must resolve.
	if _, ok := scopes[auth.Scope]; !ok {
		out = append(out, connectors.ValidationFinding{
			Severity: "error",
			Path:     path + ".scope",
			Message:  fmt.Sprintf("asset scope %q not defined in model", auth.Scope),
		})
	}

	switch auth.Type {
	case authTypeGrant:
		out = append(out, validateGrantAuth(auth, path)...)
	case authTypeRole:
		out = append(out, validateRoleAuth(auth, path)...)
	default:
		out = append(out, connectors.ValidationFinding{
			Severity: "error",
			Path:     path + ".type",
			Message:  fmt.Sprintf("unknown postgres.* authorization type %q", auth.Type),
		})
	}
	return out
}

// validateGrantAuth checks a postgres.grant authorization.
func validateGrantAuth(auth model.YAMLAuthorization, path string) []connectors.ValidationFinding {
	var out []connectors.ValidationFinding
	if specString(auth.Spec, "database") == "" {
		out = append(out, connectors.ValidationFinding{
			Severity: "error",
			Path:     path + ".database",
			Message:  "postgres.grant requires a non-empty database",
		})
	}
	if specString(auth.Spec, "as_role") == "" {
		out = append(out, connectors.ValidationFinding{
			Severity: "error",
			Path:     path + ".as_role",
			Message:  "postgres.grant requires as_role (the role being granted to)",
		})
	}
	privs := canonicalPrivileges(auth.Spec["privileges"])
	if len(privs) == 0 {
		out = append(out, connectors.ValidationFinding{
			Severity: "error",
			Path:     path + ".privileges",
			Message:  "postgres.grant requires a non-empty privileges list",
		})
	}
	for _, p := range privs {
		if p == "ALL" || p == "ALL PRIVILEGES" {
			out = append(out, connectors.ValidationFinding{
				Severity: "warning",
				Path:     path + ".privileges",
				Message:  "ALL/ALL PRIVILEGES is overbroad — list explicit privileges",
			})
			break
		}
	}
	return out
}

// validateRoleAuth checks a postgres.role authorization.
func validateRoleAuth(auth model.YAMLAuthorization, path string) []connectors.ValidationFinding {
	var out []connectors.ValidationFinding
	if specString(auth.Spec, "database") == "" {
		out = append(out, connectors.ValidationFinding{
			Severity: "error",
			Path:     path + ".database",
			Message:  "postgres.role requires a non-empty database",
		})
	}
	if specString(auth.Spec, "role") == "" {
		out = append(out, connectors.ValidationFinding{
			Severity: "error",
			Path:     path + ".role",
			Message:  "postgres.role requires role",
		})
	}
	login, _ := specBool(auth.Spec, "login")
	if login && specString(auth.Spec, "password_ref") == "" {
		out = append(out, connectors.ValidationFinding{
			Severity: "warning",
			Path:     path + ".password_ref",
			Message:  "login=true role has no password_ref — operator should declare credential source",
		})
	}
	return out
}

// Plan walks the model and emits PlanItems for postgres.* authorizations.
// Re-running Plan with identical inputs MUST produce a byte-identical
// Content map (the storage layer keys plans on content_hash).
func (*Connector) Plan(_ context.Context, state connectors.ApprovedState) (*connectors.PlanResult, error) {
	if state.Model == nil {
		return nil, fmt.Errorf("postgres: Plan: nil model")
	}
	envByScope := scopeEnvironments(state.Model)

	items := make([]connectors.PlanItem, 0)
	itemsAsMaps := make([]map[string]any, 0)
	seq := 1

	// 1. Service accounts first — roles must logically pre-exist
	// before grants reference them. Order: SA name ASC, then by
	// (auth.Type, auth.Scope) inside the SA.
	sas := append([]model.YAMLServiceAccount(nil), state.Model.Spec.ServiceAccounts...)
	sort.Slice(sas, func(i, j int) bool { return sas[i].Name < sas[j].Name })

	for _, sa := range sas {
		auths := sortedAuthorizations(sa.Authorizations)
		for _, auth := range auths {
			if auth.Type != authTypeRole {
				continue
			}
			role := specToDesiredRole(auth.Scope, auth.Spec)
			item := buildRolePlanItem(seq, role, envByScope[auth.Scope])
			items = append(items, item)
			itemsAsMaps = append(itemsAsMaps, planItemAsMap(item))
			seq++
		}
	}

	// 2. Entitlements — grants. Order: entitlement name ASC.
	ents := append([]model.YAMLEntitlement(nil), state.Model.Spec.Entitlements...)
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })

	for _, ent := range ents {
		auths := sortedAuthorizations(ent.Authorizations)
		for _, auth := range auths {
			if auth.Type != authTypeGrant {
				continue
			}
			grant := specToDesiredGrant(auth.Scope, auth.Spec)
			item := buildGrantPlanItem(seq, grant, envByScope[auth.Scope])
			items = append(items, item)
			itemsAsMaps = append(itemsAsMaps, planItemAsMap(item))
			seq++
		}
	}

	// 3. Service-account grants (rare but allowed). Same ordering
	// rules as entitlement grants.
	for _, sa := range sas {
		auths := sortedAuthorizations(sa.Authorizations)
		for _, auth := range auths {
			if auth.Type != authTypeGrant {
				continue
			}
			grant := specToDesiredGrant(auth.Scope, auth.Spec)
			item := buildGrantPlanItem(seq, grant, envByScope[auth.Scope])
			items = append(items, item)
			itemsAsMaps = append(itemsAsMaps, planItemAsMap(item))
			seq++
		}
	}

	summary := fmt.Sprintf("postgres: %d planned change(s)", len(items))
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

// buildRolePlanItem constructs a PlanItem for a postgres.role authorization.
func buildRolePlanItem(seq int, r desiredRole, env string) connectors.PlanItem {
	risk := "low"
	if env == "prod" || strings.Contains(strings.ToLower(r.scope), "prod") {
		risk = "high"
	} else if r.login {
		// LOGIN roles in non-prod are still medium risk: they are
		// human-or-service-impersonating credentials.
		risk = "medium"
	}
	return connectors.PlanItem{
		Sequence:     seq,
		Action:       "create",
		ResourceKind: "postgres.role",
		ResourceRef:  fmt.Sprintf("%s:%s:role:%s", r.scope, r.database, r.role),
		Body:         r.body(),
		Risk:         risk,
		Note:         roleNote(r),
	}
}

// roleNote produces a one-line description for a role plan item.
func roleNote(r desiredRole) string {
	loginStr := "NOLOGIN"
	if r.login {
		loginStr = "LOGIN"
	}
	if r.connLimit < 0 {
		return fmt.Sprintf("role %s (%s, INHERIT=%t, conn limit unlimited)",
			r.role, loginStr, r.inherit)
	}
	return fmt.Sprintf("role %s (%s, INHERIT=%t, conn limit %d)",
		r.role, loginStr, r.inherit, r.connLimit)
}

// buildGrantPlanItem constructs a PlanItem for a postgres.grant authorization.
func buildGrantPlanItem(seq int, g desiredGrant, env string) connectors.PlanItem {
	risk := privilegeSeverity(g.privileges)
	// Prod scoping bumps the floor: a SELECT-only grant in prod is
	// at least medium risk.
	if env == "prod" || strings.Contains(strings.ToLower(g.scope), "prod") {
		risk = maxSeverity(risk, "high")
	}
	resourceRef := fmt.Sprintf(
		"%s:%s:%s:grant:%s:%s:%s",
		g.scope, g.database, schemaOrStar(g.schema),
		g.asRole,
		canonicalPrivilegeKey(g.privileges),
		canonicalGrantTargets(g.tables),
	)
	return connectors.PlanItem{
		Sequence:     seq,
		Action:       "create",
		ResourceKind: "postgres.grant",
		ResourceRef:  resourceRef,
		Body:         g.body(),
		Risk:         risk,
		Note:         grantNote(g),
	}
}

// grantNote produces a one-line description for a grant plan item.
func grantNote(g desiredGrant) string {
	target := "all tables"
	if len(g.tables) > 0 {
		target = fmt.Sprintf("%d table(s)", len(g.tables))
	}
	return fmt.Sprintf("GRANT %s ON %s TO %s",
		strings.Join(g.privileges, ","), target, g.asRole)
}

// sortedAuthorizations returns a copy of the authorization slice
// sorted by (Type, Scope, deterministic-body-string). Matches the
// linux_sudo convention so plan ordering is stable across YAML edits
// that preserve set-equality.
func sortedAuthorizations(in []model.YAMLAuthorization) []model.YAMLAuthorization {
	out := append([]model.YAMLAuthorization(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i], out[j]
		if ai.Type != aj.Type {
			return ai.Type < aj.Type
		}
		if ai.Scope != aj.Scope {
			return ai.Scope < aj.Scope
		}
		// Tie-break on key fields likely to differentiate two same-type
		// authorizations on the same scope.
		ar := specString(ai.Spec, "as_role") + specString(ai.Spec, "role")
		br := specString(aj.Spec, "as_role") + specString(aj.Spec, "role")
		if ar != br {
			return ar < br
		}
		return strings.Join(canonicalPrivileges(ai.Spec["privileges"]), ",") <
			strings.Join(canonicalPrivileges(aj.Spec["privileges"]), ",")
	})
	return out
}

// scopeIndex returns a presence index for AssetScope names.
func scopeIndex(m *model.ProductAuthorizationModel) map[string]struct{} {
	out := make(map[string]struct{}, len(m.Spec.AssetScopes))
	for _, s := range m.Spec.AssetScopes {
		out[s.Name] = struct{}{}
	}
	return out
}

// scopeEnvironments maps an AssetScope name to the dominant environment
// of the assets it selects. We treat a scope as "prod" iff its
// selector's environment is "prod" OR every selected asset is in env
// prod. Empty environment string means unknown.
func scopeEnvironments(m *model.ProductAuthorizationModel) map[string]string {
	envByScope := make(map[string]string, len(m.Spec.AssetScopes))
	for _, s := range m.Spec.AssetScopes {
		// 1. Prefer the selector's own environment field.
		if s.Selector.Environment != "" {
			envByScope[s.Name] = s.Selector.Environment
			continue
		}
		// 2. Otherwise infer from explicit asset list.
		if len(s.AssetNames) > 0 {
			envByScope[s.Name] = inferEnvFromAssets(m, s.AssetNames)
			continue
		}
		// 3. Otherwise unknown.
		envByScope[s.Name] = ""
	}
	return envByScope
}

// inferEnvFromAssets returns the common environment across the named
// assets, or "" if mixed.
func inferEnvFromAssets(m *model.ProductAuthorizationModel, names []string) string {
	envSet := make(map[string]struct{})
	byName := make(map[string]model.YAMLAsset, len(m.Spec.Assets))
	for _, a := range m.Spec.Assets {
		byName[a.Name] = a
	}
	for _, n := range names {
		if a, ok := byName[n]; ok && a.Environment != "" {
			envSet[a.Environment] = struct{}{}
		}
	}
	if len(envSet) != 1 {
		return ""
	}
	for k := range envSet {
		return k
	}
	return ""
}

// isPostgresAuth returns true for authorization types this connector
// recognises. Future postgres.* types land here.
func isPostgresAuth(t string) bool {
	return t == authTypeRole || t == authTypeGrant
}

// planItemAsMap mirrors a PlanItem into the canonical map shape stored
// in PlanResult.Content["items"].
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
