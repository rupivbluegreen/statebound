package model

import (
	"fmt"
	"strings"

	"statebound.dev/statebound/internal/domain"
)

// ValidationError is one finding produced by Validate. Multiple findings can
// be reported at once so callers can render every problem in a single pass.
type ValidationError struct {
	Path    string
	Message string
}

// Error implements the error interface for individual findings; useful when a
// single ValidationError is bubbled up.
func (v ValidationError) Error() string {
	if v.Path == "" {
		return v.Message
	}
	return v.Path + ": " + v.Message
}

// ValidationFailedError wraps a non-empty slice of ValidationError so callers
// can distinguish validation problems from generic Go errors. Returned by the
// importer when the model is malformed.
type ValidationFailedError struct {
	Findings []ValidationError
}

// Error renders a one-line summary; CLI callers print the per-finding details
// from the Findings slice.
func (e *ValidationFailedError) Error() string {
	if len(e.Findings) == 1 {
		return "validation failed: " + e.Findings[0].Error()
	}
	return fmt.Sprintf("validation failed: %d findings", len(e.Findings))
}

// Validate checks a parsed ProductAuthorizationModel for structural and
// referential problems. It always returns a slice (possibly empty); it never
// returns Go's error and never panics.
func Validate(m *ProductAuthorizationModel) []ValidationError {
	v := &validator{}
	if m == nil {
		v.addf("", "model is nil")
		return v.findings
	}
	v.checkHeader(m)
	v.checkAssets(m.Spec.Assets)
	v.checkAssetScopes(m.Spec.Assets, m.Spec.AssetScopes)
	v.checkGlobalObjects(m.Spec.GlobalObjects)
	scopeNames := nameSet(scopeNames(m.Spec.AssetScopes))
	globalNames := nameSet(globalObjectNames(m.Spec.GlobalObjects))
	v.checkEntitlements(m.Spec.Entitlements, scopeNames, globalNames)
	v.checkServiceAccounts(m.Spec.ServiceAccounts, scopeNames, globalNames)
	return v.findings
}

// validator accumulates findings while traversing the document.
type validator struct {
	findings []ValidationError
}

func (v *validator) addf(path, format string, args ...any) {
	v.findings = append(v.findings, ValidationError{
		Path:    path,
		Message: fmt.Sprintf(format, args...),
	})
}

func (v *validator) checkHeader(m *ProductAuthorizationModel) {
	if m.APIVersion != APIVersion {
		v.addf("apiVersion", "must equal %q, got %q", APIVersion, m.APIVersion)
	}
	if m.Kind != Kind {
		v.addf("kind", "must equal %q, got %q", Kind, m.Kind)
	}
	if m.Metadata.Product == "" {
		v.addf("metadata.product", "is required")
	} else if !domain.IsValidProductName(m.Metadata.Product) {
		v.addf("metadata.product", "must be a lower-kebab slug, 1..63 chars, [a-z0-9-]")
	}
	if m.Metadata.Owner == "" {
		v.addf("metadata.owner", "is required")
	}
}

func (v *validator) checkAssets(assets []YAMLAsset) {
	seen := make(map[string]int, len(assets))
	for i, a := range assets {
		path := fmt.Sprintf("spec.assets[%d]", i)
		if a.Name == "" {
			v.addf(path+".name", "is required")
		} else if prev, dup := seen[a.Name]; dup {
			v.addf(path+".name", "duplicate asset name %q (also at spec.assets[%d])", a.Name, prev)
		} else {
			seen[a.Name] = i
		}
		if a.Type == "" {
			v.addf(path+".type", "is required")
		} else if !domain.IsValidAssetType(a.Type) {
			v.addf(path+".type", "invalid asset type %q", a.Type)
		}
		if a.Environment == "" {
			v.addf(path+".environment", "is required")
		} else if !isValidEnvName(a.Environment) {
			v.addf(path+".environment", "must be one of dev, staging, prod (got %q)", a.Environment)
		}
		for k, val := range a.Labels {
			if !domain.IsValidLabelKey(k) {
				v.addf(path+".labels", "invalid label key %q", k)
			}
			if !domain.IsValidLabelValue(val) {
				v.addf(path+".labels", "invalid label value for key %q", k)
			}
		}
	}
}

func (v *validator) checkAssetScopes(assets []YAMLAsset, scopes []YAMLAssetScope) {
	assetNames := nameSet(assetYAMLNames(assets))
	seen := make(map[string]int, len(scopes))
	for i, s := range scopes {
		path := fmt.Sprintf("spec.assetScopes[%d]", i)
		if s.Name == "" {
			v.addf(path+".name", "is required")
		} else if prev, dup := seen[s.Name]; dup {
			v.addf(path+".name", "duplicate asset scope name %q (also at spec.assetScopes[%d])", s.Name, prev)
		} else {
			seen[s.Name] = i
		}
		hasSelector := s.Selector.Type != "" ||
			s.Selector.Environment != "" ||
			len(s.Selector.Labels) > 0
		hasNames := len(s.AssetNames) > 0
		if !hasSelector && !hasNames {
			v.addf(path, "selector or assets list is required")
		}
		if s.Selector.Type != "" && !domain.IsValidAssetType(s.Selector.Type) {
			v.addf(path+".selector.type", "invalid asset type %q", s.Selector.Type)
		}
		if s.Selector.Environment != "" && !isValidEnvName(s.Selector.Environment) {
			v.addf(path+".selector.environment", "must be one of dev, staging, prod (got %q)", s.Selector.Environment)
		}
		for k, val := range s.Selector.Labels {
			if !domain.IsValidLabelKey(k) {
				v.addf(path+".selector", "invalid label key %q", k)
			}
			if !domain.IsValidLabelValue(val) {
				v.addf(path+".selector", "invalid label value for key %q", k)
			}
		}
		for j, name := range s.AssetNames {
			ap := fmt.Sprintf("%s.assets[%d]", path, j)
			if name == "" {
				v.addf(ap, "is required")
				continue
			}
			if _, ok := assetNames[name]; !ok {
				v.addf(ap, "asset %q is not declared in spec.assets", name)
			}
		}
	}
}

func (v *validator) checkGlobalObjects(objs []YAMLGlobalObject) {
	seen := make(map[string]int, len(objs))
	for i, g := range objs {
		path := fmt.Sprintf("spec.globalObjects[%d]", i)
		if g.Name == "" {
			v.addf(path+".name", "is required")
		} else if prev, dup := seen[g.Name]; dup {
			v.addf(path+".name", "duplicate global object name %q (also at spec.globalObjects[%d])", g.Name, prev)
		} else {
			seen[g.Name] = i
		}
		if g.Type == "" {
			v.addf(path+".type", "is required")
		} else if !domain.IsValidGlobalObjectType(g.Type) {
			v.addf(path+".type", "invalid global object type %q", g.Type)
		}
		if g.Spec == nil {
			v.addf(path+".spec", "is required")
		}
	}
}

func (v *validator) checkEntitlements(entitlements []YAMLEntitlement, scopes, globals map[string]struct{}) {
	seen := make(map[string]int, len(entitlements))
	for i, e := range entitlements {
		path := fmt.Sprintf("spec.entitlements[%d]", i)
		if e.Name == "" {
			v.addf(path+".name", "is required")
		} else if prev, dup := seen[e.Name]; dup {
			v.addf(path+".name", "duplicate entitlement name %q (also at spec.entitlements[%d])", e.Name, prev)
		} else {
			seen[e.Name] = i
		}
		if e.Owner == "" {
			v.addf(path+".owner", "is required")
		}
		if e.Purpose == "" {
			v.addf(path+".purpose", "is required")
		}
		for j, auth := range e.Authorizations {
			v.checkAuthorization(fmt.Sprintf("%s.authorizations[%d]", path, j), auth, scopes, globals)
		}
	}
}

func (v *validator) checkServiceAccounts(accounts []YAMLServiceAccount, scopes, globals map[string]struct{}) {
	seen := make(map[string]int, len(accounts))
	for i, a := range accounts {
		path := fmt.Sprintf("spec.serviceAccounts[%d]", i)
		if a.Name == "" {
			v.addf(path+".name", "is required")
		} else if prev, dup := seen[a.Name]; dup {
			v.addf(path+".name", "duplicate service account name %q (also at spec.serviceAccounts[%d])", a.Name, prev)
		} else {
			seen[a.Name] = i
		}
		if a.Owner == "" {
			v.addf(path+".owner", "is required")
		}
		if a.Purpose == "" {
			v.addf(path+".purpose", "is required")
		}
		if a.UsagePattern == "" {
			v.addf(path+".usagePattern", "is required")
		} else if !domain.IsValidUsagePattern(a.UsagePattern) {
			v.addf(path+".usagePattern", "invalid usage pattern %q", a.UsagePattern)
		}
		for j, auth := range a.Authorizations {
			v.checkAuthorization(fmt.Sprintf("%s.authorizations[%d]", path, j), auth, scopes, globals)
		}
	}
}

// checkAuthorization runs the per-authorization validation: type, target
// exclusivity, target existence, and the type-specific spec rules. The spec
// rules reuse domain.Authorization.Validate by constructing a transient
// Authorization with synthetic IDs that satisfy the parent/target invariants.
func (v *validator) checkAuthorization(path string, auth YAMLAuthorization, scopes, globals map[string]struct{}) {
	if auth.Type == "" {
		v.addf(path+".type", "is required")
	} else if !domain.IsValidAuthorizationType(auth.Type) {
		v.addf(path+".type", "invalid authorization type %q", auth.Type)
	}

	// Phase 6: light-weight model-side check for postgres.* sub-types
	// before we hand off to the domain validator. Catches the
	// most common authoring mistakes (missing database / role /
	// privileges) with a clearer path than the synthetic-ID round-trip
	// produces. The connector still does the deep validation against
	// the live catalog at plan time.
	if strings.HasPrefix(auth.Type, "postgres.") {
		if findings := validatePostgresAuthorization(path, auth); len(findings) > 0 {
			v.findings = append(v.findings, findings...)
		}
	}

	hasScope := auth.Scope != ""
	hasGlobal := auth.GlobalObject != ""
	switch {
	case hasScope && hasGlobal:
		v.addf(path, "scope and globalObject are mutually exclusive")
	case !hasScope && !hasGlobal:
		v.addf(path, "exactly one of scope or globalObject is required")
	case hasScope:
		if _, ok := scopes[auth.Scope]; !ok {
			v.addf(path+".scope", "asset scope %q is not declared in spec.assetScopes", auth.Scope)
		}
	case hasGlobal:
		if _, ok := globals[auth.GlobalObject]; !ok {
			v.addf(path+".globalObject", "global object %q is not declared in spec.globalObjects", auth.GlobalObject)
		}
	}

	if !domain.IsValidAuthorizationType(auth.Type) {
		// Spec validation needs a known type; skip the per-type check.
		return
	}

	// Build a transient Authorization just to reuse the per-type spec rules.
	// We synthesize plausible scope/global IDs to satisfy the exclusivity
	// invariant in domain validation; the importer will swap these for real
	// IDs at apply time.
	syntheticID := domain.ID("00000000-0000-0000-0000-000000000000")
	var (
		scopeID  *domain.ID
		globalID *domain.ID
	)
	if hasScope {
		scopeID = &syntheticID
	}
	if hasGlobal {
		globalID = &syntheticID
	}
	// Pick an arbitrary parent (entitlement) for the spec check; per-type spec
	// validation does not depend on the parent kind.
	a := &domain.Authorization{
		ID:             syntheticID,
		ParentKind:     domain.AuthParentEntitlement,
		ParentID:       syntheticID,
		Type:           domain.AuthorizationType(auth.Type),
		AssetScopeID:   scopeID,
		GlobalObjectID: globalID,
		Spec:           auth.Spec,
	}
	if err := a.Validate(); err != nil {
		v.addf(path, "%s", err.Error())
	}
}

// nameSet builds a set from a slice of names.
func nameSet(names []string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}

func assetYAMLNames(assets []YAMLAsset) []string {
	out := make([]string, 0, len(assets))
	for _, a := range assets {
		if a.Name != "" {
			out = append(out, a.Name)
		}
	}
	return out
}

func scopeNames(scopes []YAMLAssetScope) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s.Name != "" {
			out = append(out, s.Name)
		}
	}
	return out
}

func globalObjectNames(objs []YAMLGlobalObject) []string {
	out := make([]string, 0, len(objs))
	for _, g := range objs {
		if g.Name != "" {
			out = append(out, g.Name)
		}
	}
	return out
}

// isValidEnvName accepts the three Statebound environment slugs.
func isValidEnvName(s string) bool {
	switch domain.Environment(s) {
	case domain.EnvDev, domain.EnvStaging, domain.EnvProd:
		return true
	}
	return false
}

// validatePostgresAuthorization runs the model-side checks for the
// postgres.* authorization sub-types. Findings target the Body/Spec
// catch-all map of YAMLAuthorization (the unified inline body for
// Phase 6+ connector-specific keys). The connector does the deep
// validation against the live catalog at plan time; this function
// catches the most common authoring mistakes early.
//
// Sub-types handled:
//   - postgres.grant: requires database (string), privileges
//     (non-empty []string), and either schema+objects (any shape) or
//     a top-level objects pattern.
//   - postgres.role: requires database (string) and role (string).
//
// Unknown postgres.* sub-types produce one finding.
func validatePostgresAuthorization(path string, auth YAMLAuthorization) []ValidationError {
	body := auth.Body()
	switch auth.Type {
	case string(domain.AuthTypePostgresGrant):
		var findings []ValidationError
		if !hasNonEmptyString(body, "database") {
			findings = append(findings, ValidationError{
				Path:    path + ".database",
				Message: "is required for postgres.grant",
			})
		}
		if !hasNonEmptyStringSlice(body, "privileges") {
			findings = append(findings, ValidationError{
				Path:    path + ".privileges",
				Message: "must be a non-empty list of strings",
			})
		}
		// Either a top-level objects pattern, or schema + objects (in
		// any shape) covers the grant target.
		_, hasObjects := body["objects"]
		_, hasSchema := body["schema"]
		if !hasObjects && !hasSchema {
			findings = append(findings, ValidationError{
				Path:    path,
				Message: "postgres.grant requires schema+objects or a top-level objects pattern",
			})
		}
		return findings
	case string(domain.AuthTypePostgresRole):
		var findings []ValidationError
		if !hasNonEmptyString(body, "database") {
			findings = append(findings, ValidationError{
				Path:    path + ".database",
				Message: "is required for postgres.role",
			})
		}
		if !hasNonEmptyString(body, "role") {
			findings = append(findings, ValidationError{
				Path:    path + ".role",
				Message: "is required for postgres.role",
			})
		}
		return findings
	default:
		// Caller restricts this dispatch to postgres.* prefixed types.
		// The only way we land here is a postgres.* sub-type that the
		// domain enum does not recognise. checkAuthorization already
		// flags the invalid type itself; emit a more specific message
		// pointing at the postgres.* dispatch so authors know which
		// sub-types are supported.
		return []ValidationError{{
			Path:    path + ".type",
			Message: fmt.Sprintf("unknown postgres authorization sub-type %q (supported: postgres.grant, postgres.role)", auth.Type),
		}}
	}
}

// hasNonEmptyString reports whether body[key] is a non-empty string.
func hasNonEmptyString(body map[string]any, key string) bool {
	if body == nil {
		return false
	}
	raw, ok := body[key]
	if !ok || raw == nil {
		return false
	}
	s, ok := raw.(string)
	return ok && s != ""
}

// hasNonEmptyStringSlice reports whether body[key] is a non-empty
// []string-shaped value (accepts []any of strings or []string).
func hasNonEmptyStringSlice(body map[string]any, key string) bool {
	if body == nil {
		return false
	}
	raw, ok := body[key]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case []string:
		return len(v) > 0
	case []any:
		if len(v) == 0 {
			return false
		}
		for _, item := range v {
			if _, ok := item.(string); !ok {
				return false
			}
		}
		return true
	}
	return false
}
