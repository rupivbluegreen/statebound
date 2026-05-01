// Package model implements the Phase 1 YAML schema, validator, importer, and
// exporter for ProductAuthorizationModel documents. All logic is pure: the
// importer/exporter take a storage.Storage handle so the package never opens
// connections itself.
package model

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// APIVersion is the only API version this package accepts.
const APIVersion = "statebound.dev/v1alpha1"

// Kind is the only YAML kind this package accepts.
const Kind = "ProductAuthorizationModel"

// ProductAuthorizationModel is the top-level YAML document — the entire
// desired-state for a single product, captured as one file.
type ProductAuthorizationModel struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   ProductMetadata `yaml:"metadata"`
	Spec       ProductSpec     `yaml:"spec"`
}

// ProductMetadata captures the product header.
type ProductMetadata struct {
	Product     string `yaml:"product"`
	Owner       string `yaml:"owner"`
	Description string `yaml:"description,omitempty"`
}

// ProductSpec is the body of the YAML document.
type ProductSpec struct {
	Assets          []YAMLAsset          `yaml:"assets,omitempty"`
	AssetScopes     []YAMLAssetScope     `yaml:"assetScopes,omitempty"`
	Entitlements    []YAMLEntitlement    `yaml:"entitlements,omitempty"`
	ServiceAccounts []YAMLServiceAccount `yaml:"serviceAccounts,omitempty"`
	GlobalObjects   []YAMLGlobalObject   `yaml:"globalObjects,omitempty"`
}

// YAMLAsset mirrors a domain.Asset entry in YAML form.
type YAMLAsset struct {
	Name        string            `yaml:"name"`
	Type        string            `yaml:"type"`
	Environment string            `yaml:"environment"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Description string            `yaml:"description,omitempty"`
}

// YAMLAssetScope mirrors a domain.AssetScope. Either Selector or AssetNames is
// expected at use sites; the validator enforces "at least one" semantics.
type YAMLAssetScope struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Selector    YAMLAssetSelector `yaml:"selector,omitempty"`
	AssetNames  []string          `yaml:"assets,omitempty"`
}

// YAMLAssetSelector is a flat selector mapping. "type" and "environment" are
// reserved keys; every other key is a label match. Custom UnmarshalYAML splits
// the raw mapping into the three buckets.
type YAMLAssetSelector struct {
	Type        string
	Environment string
	Labels      map[string]string
}

// MarshalYAML re-emits the selector as a flat mapping with type, environment,
// and label entries inline. Keys are emitted in a deterministic order: type,
// environment, then labels sorted alphabetically.
func (s YAMLAssetSelector) MarshalYAML() (any, error) {
	node := &yaml.Node{Kind: yaml.MappingNode}
	if s.Type != "" {
		appendStringPair(node, "type", s.Type)
	}
	if s.Environment != "" {
		appendStringPair(node, "environment", s.Environment)
	}
	for _, k := range sortedKeys(s.Labels) {
		appendStringPair(node, k, s.Labels[k])
	}
	return node, nil
}

// UnmarshalYAML splits a flat mapping into the type, environment, and labels
// buckets. Non-string scalar values for known keys are rejected.
func (s *YAMLAssetSelector) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Kind == 0 {
		return nil
	}
	if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("asset selector must be a mapping, got %s", nodeKindName(value.Kind))
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valNode := value.Content[i+1]
		if keyNode.Kind != yaml.ScalarNode {
			return fmt.Errorf("asset selector keys must be scalars, got %s", nodeKindName(keyNode.Kind))
		}
		key := keyNode.Value
		switch key {
		case "type":
			if err := requireScalarString(valNode, "selector.type"); err != nil {
				return err
			}
			s.Type = valNode.Value
		case "environment":
			if err := requireScalarString(valNode, "selector.environment"); err != nil {
				return err
			}
			s.Environment = valNode.Value
		default:
			if err := requireScalarString(valNode, "selector."+key); err != nil {
				return err
			}
			if s.Labels == nil {
				s.Labels = make(map[string]string)
			}
			s.Labels[key] = valNode.Value
		}
	}
	return nil
}

// YAMLEntitlement mirrors a domain.Entitlement and holds its inline
// authorizations.
type YAMLEntitlement struct {
	Name           string              `yaml:"name"`
	Owner          string              `yaml:"owner"`
	Purpose        string              `yaml:"purpose"`
	Authorizations []YAMLAuthorization `yaml:"authorizations,omitempty"`
}

// YAMLServiceAccount mirrors a domain.ServiceAccount and holds its inline
// authorizations.
type YAMLServiceAccount struct {
	Name           string              `yaml:"name"`
	Owner          string              `yaml:"owner"`
	UsagePattern   string              `yaml:"usagePattern"`
	Purpose        string              `yaml:"purpose"`
	Authorizations []YAMLAuthorization `yaml:"authorizations,omitempty"`
}

// YAMLGlobalObject mirrors a domain.GlobalObject. Spec is a free-form mapping
// validated at use time according to type.
type YAMLGlobalObject struct {
	Name string         `yaml:"name"`
	Type string         `yaml:"type"`
	Spec map[string]any `yaml:"spec"`
}

// YAMLAuthorization is a single permission entry. Type, Scope, and
// GlobalObject are reserved keys; every other key is captured into Spec so
// type-specific fields (methods, asUser, commands, group, ...) can sit inline.
//
// Spec doubles as the inline "body" map for connector-specific keys.
// Phase 6 added Postgres authorization types (postgres.grant,
// postgres.role) whose fields (database, schema, privileges, role,
// login, objects, ...) land here verbatim. The custom UnmarshalYAML
// below absorbs any non-reserved key into Spec, so YAML authors can
// keep type-specific fields at the top level of an authorization
// without nesting them under a separate "body:" key. Connectors and
// the per-type validators read straight from Spec; see
// validatePostgresAuthorization for an example.
type YAMLAuthorization struct {
	Type         string
	Scope        string
	GlobalObject string
	Spec         map[string]any
}

// Body returns the connector-specific catch-all map for this
// authorization, which is the same backing map as Spec. This is a
// readability alias used by the Postgres validators (and any future
// connector validators) that prefer "body" over "spec" terminology.
// Returns nil if the authorization has no inline keys.
func (a YAMLAuthorization) Body() map[string]any {
	return a.Spec
}

// MarshalYAML re-emits the authorization as a flat mapping. Reserved keys
// (type, scope, globalObject) come first in fixed order; the remainder of Spec
// is sorted alphabetically for determinism.
func (a YAMLAuthorization) MarshalYAML() (any, error) {
	node := &yaml.Node{Kind: yaml.MappingNode}
	if a.Type != "" {
		appendStringPair(node, "type", a.Type)
	}
	if a.Scope != "" {
		appendStringPair(node, "scope", a.Scope)
	}
	if a.GlobalObject != "" {
		appendStringPair(node, "globalObject", a.GlobalObject)
	}
	for _, k := range sortedKeys(a.Spec) {
		valNode, err := anyToYAMLNode(a.Spec[k])
		if err != nil {
			return nil, fmt.Errorf("authorization spec key %q: %w", k, err)
		}
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}
		node.Content = append(node.Content, keyNode, valNode)
	}
	return node, nil
}

// UnmarshalYAML pulls type, scope, and globalObject out of the mapping; every
// other key is decoded into the Spec map so we keep type-specific fields
// inline rather than nested under a "spec:" key.
func (a *YAMLAuthorization) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Kind == 0 {
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("authorization must be a mapping, got %s", nodeKindName(value.Kind))
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valNode := value.Content[i+1]
		if keyNode.Kind != yaml.ScalarNode {
			return fmt.Errorf("authorization keys must be scalars, got %s", nodeKindName(keyNode.Kind))
		}
		key := keyNode.Value
		switch key {
		case "type":
			if err := requireScalarString(valNode, "authorization.type"); err != nil {
				return err
			}
			a.Type = valNode.Value
		case "scope":
			if err := requireScalarString(valNode, "authorization.scope"); err != nil {
				return err
			}
			a.Scope = valNode.Value
		case "globalObject":
			if err := requireScalarString(valNode, "authorization.globalObject"); err != nil {
				return err
			}
			a.GlobalObject = valNode.Value
		default:
			var raw any
			if err := valNode.Decode(&raw); err != nil {
				return fmt.Errorf("authorization spec key %q: %w", key, err)
			}
			if a.Spec == nil {
				a.Spec = make(map[string]any)
			}
			a.Spec[key] = raw
		}
	}
	return nil
}

// requireScalarString ensures n is a YAML string scalar and rejects nulls or
// nested structures so callers see a clear path-prefixed error.
func requireScalarString(n *yaml.Node, path string) error {
	if n == nil {
		return fmt.Errorf("%s: missing value", path)
	}
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("%s: must be a string, got %s", path, nodeKindName(n.Kind))
	}
	if n.Tag == "!!null" {
		return fmt.Errorf("%s: must be a string, got null", path)
	}
	return nil
}

// nodeKindName returns a human-friendly label for a yaml.NodeKind.
func nodeKindName(k yaml.Kind) string {
	switch k {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	}
	return "unknown"
}

// appendStringPair appends a string key/value pair to a mapping node.
func appendStringPair(parent *yaml.Node, key, val string) {
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val},
	)
}
