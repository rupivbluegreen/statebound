// Internal types used by plan/compare/apply. These types are NOT
// part of the connector public API surface — they are an internal
// normalised representation of the raw YAML authorization Spec maps
// so plan.go, compare.go, and apply.go don't each have to re-walk
// map[string]any structures.
//
// Round-tripping rule: every conversion from a YAMLAuthorization.Spec
// into a desired* struct must be deterministic given the same input,
// and the canonical Body() form fed into PlanItem.Body must round-trip
// through json.Marshal without surprises (sorted lists, no nil maps).

package postgres

import (
	"sort"
	"strings"
)

// desiredRole is the normalised shape of a postgres.role authorization.
// It is built from a YAMLAuthorization.Spec via specToDesiredRole;
// callers should treat it as immutable.
type desiredRole struct {
	scope       string
	database    string
	role        string
	login       bool
	inherit     bool
	connLimit   int  // -1 means "unlimited" (Postgres default)
	hasPassword bool // true when password_ref was supplied
	passwordRef string
}

// desiredGrant is the normalised shape of a postgres.grant authorization.
// privileges and tables are lex-sorted (case-preserving) so two specs
// that differ only in list order are considered identical for hashing
// and comparison purposes.
type desiredGrant struct {
	scope      string
	database   string
	schema     string   // empty if grant is schema-scoped only
	asRole     string   // the role being granted to
	privileges []string // sorted, upper-cased for canonicalisation
	tables     []string // sorted; empty means "all tables in schema" (handled by caller)
	objectsRaw map[string]any
}

// privilegeSeverity classifies a privilege list as low/medium/high
// based on which verbs appear. The classification is used both at
// plan time (PlanItem.Risk) and at compare time (DriftFinding.Severity).
//
//   - critical: ALL or ALL PRIVILEGES present
//   - high:     DELETE, TRUNCATE, REFERENCES present
//   - medium:   any other write privilege (INSERT, UPDATE)
//   - low:      everything read-only (SELECT, USAGE, CONNECT)
func privilegeSeverity(privs []string) string {
	highest := "low"
	for _, p := range privs {
		up := strings.ToUpper(strings.TrimSpace(p))
		switch up {
		case "ALL", "ALL PRIVILEGES":
			return "critical"
		case "DELETE", "TRUNCATE", "REFERENCES":
			if rank(highest) < rank("high") {
				highest = "high"
			}
		case "INSERT", "UPDATE":
			if rank(highest) < rank("medium") {
				highest = "medium"
			}
		}
	}
	return highest
}

// rank gives a comparable integer for a severity tier.
func rank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// max returns the higher-ranked of two severities.
func maxSeverity(a, b string) string {
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

// canonicalPrivileges normalises a raw []any (or []string) into a
// sorted, upper-cased []string. Entries that are not strings are
// silently skipped; whitespace is trimmed.
func canonicalPrivileges(raw any) []string {
	out := stringList(raw)
	for i, s := range out {
		out[i] = strings.ToUpper(strings.TrimSpace(s))
	}
	sort.Strings(out)
	return out
}

// stringList coerces a raw value (typically []any from YAML decode or
// []string from a Go-built spec) into a []string. Returns an empty
// slice when raw is nil or of an unsupported type.
func stringList(raw any) []string {
	switch v := raw.(type) {
	case nil:
		return []string{}
	case []string:
		out := append([]string(nil), v...)
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return []string{}
	}
}

// nestedTableList walks objects.tables out of a raw spec map. The
// YAML decoder lands the objects sub-map as map[string]any; we accept
// both that and an already-typed map[string]any in case a caller
// constructs the spec programmatically.
func nestedTableList(spec map[string]any) []string {
	if spec == nil {
		return []string{}
	}
	objs, ok := spec["objects"]
	if !ok || objs == nil {
		return []string{}
	}
	var tables any
	switch m := objs.(type) {
	case map[string]any:
		tables = m["tables"]
	case map[any]any:
		tables = m["tables"]
	default:
		return []string{}
	}
	out := stringList(tables)
	sort.Strings(out)
	return out
}

// specString pulls a string field out of a Spec map. Returns empty
// string when absent or not a string.
func specString(spec map[string]any, key string) string {
	if spec == nil {
		return ""
	}
	v, ok := spec[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// specBool pulls a bool field out of a Spec map, with an explicit
// "present" return so callers can distinguish "not specified" from
// "explicitly false".
func specBool(spec map[string]any, key string) (val, present bool) {
	if spec == nil {
		return false, false
	}
	v, ok := spec[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	if !ok {
		return false, false
	}
	return b, true
}

// specInt pulls an int field out of a Spec map. Accepts int, int64,
// and float64 (the YAML decoder lands integers as int).
func specInt(spec map[string]any, key string, defaultVal int) int {
	if spec == nil {
		return defaultVal
	}
	v, ok := spec[key]
	if !ok {
		return defaultVal
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return defaultVal
	}
}

// specToDesiredRole builds a desiredRole from a YAMLAuthorization.Spec.
// Caller is responsible for confirming auth.Type == "postgres.role".
func specToDesiredRole(scope string, spec map[string]any) desiredRole {
	login, _ := specBool(spec, "login")
	inheritVal, inheritPresent := specBool(spec, "inherit")
	inherit := true // postgres default
	if inheritPresent {
		inherit = inheritVal
	}
	connLimit := specInt(spec, "connection_limit", -1)
	pwRef := specString(spec, "password_ref")
	return desiredRole{
		scope:       scope,
		database:    specString(spec, "database"),
		role:        specString(spec, "role"),
		login:       login,
		inherit:     inherit,
		connLimit:   connLimit,
		hasPassword: pwRef != "",
		passwordRef: pwRef,
	}
}

// specToDesiredGrant builds a desiredGrant from a
// YAMLAuthorization.Spec. Caller is responsible for confirming
// auth.Type == "postgres.grant".
func specToDesiredGrant(scope string, spec map[string]any) desiredGrant {
	g := desiredGrant{
		scope:      scope,
		database:   specString(spec, "database"),
		schema:     specString(spec, "schema"),
		asRole:     specString(spec, "as_role"),
		privileges: canonicalPrivileges(spec["privileges"]),
		tables:     nestedTableList(spec),
	}
	if objs, ok := spec["objects"]; ok {
		switch m := objs.(type) {
		case map[string]any:
			g.objectsRaw = m
		case map[any]any:
			conv := make(map[string]any, len(m))
			for k, v := range m {
				if ks, ok := k.(string); ok {
					conv[ks] = v
				}
			}
			g.objectsRaw = conv
		}
	}
	return g
}

// roleBody renders a desiredRole into the canonical map[string]any
// shape stored on PlanItem.Body. Two desiredRole values with equal
// fields render to deeply-equal maps so json.Marshal produces
// byte-identical output.
func (r desiredRole) body() map[string]any {
	body := map[string]any{
		"scope":            r.scope,
		"database":         r.database,
		"role":             r.role,
		"login":            r.login,
		"inherit":          r.inherit,
		"connection_limit": r.connLimit,
	}
	if r.hasPassword {
		body["password_ref"] = r.passwordRef
	}
	return body
}

// grantBody renders a desiredGrant into the canonical map[string]any
// shape stored on PlanItem.Body. Tables are emitted as a sorted list.
func (g desiredGrant) body() map[string]any {
	objects := map[string]any{
		"tables": append([]string{}, g.tables...),
	}
	body := map[string]any{
		"scope":      g.scope,
		"as_role":    g.asRole,
		"database":   g.database,
		"privileges": append([]string{}, g.privileges...),
		"objects":    objects,
	}
	if g.schema != "" {
		body["schema"] = g.schema
	}
	return body
}

// canonicalGrantTargets produces a stable colon-joined target list
// for use in ResourceRef. Empty target list emits "*".
func canonicalGrantTargets(tables []string) string {
	if len(tables) == 0 {
		return "*"
	}
	cp := append([]string(nil), tables...)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// canonicalPrivilegeKey joins a sorted privilege list into a colon-safe
// stable key. Used inside ResourceRef construction. Empty privileges
// emit "*".
func canonicalPrivilegeKey(privs []string) string {
	if len(privs) == 0 {
		return "*"
	}
	cp := append([]string(nil), privs...)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// schemaOrStar returns the schema name or "*" for "no schema specified".
// Used in ResourceRef construction so two grants without a schema still
// have stable identifiers.
func schemaOrStar(s string) string {
	if s == "" {
		return "*"
	}
	return s
}
