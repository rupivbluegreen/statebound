package model

import (
	"fmt"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// nowUTC is a small wrapper so tests can swap clock behaviour later if needed.
func nowUTC() time.Time { return time.Now().UTC() }

// sortedKeys returns the keys of a string-keyed map in lexicographic order.
// Used to produce deterministic YAML output.
func sortedKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// anyToYAMLNode encodes an arbitrary value to a yaml.Node by round-tripping
// through the yaml encoder. This produces output identical to a direct
// yaml.Marshal of the value, which is what we want for nested authorization
// spec values inside our custom MarshalYAML.
func anyToYAMLNode(v any) (*yaml.Node, error) {
	node := &yaml.Node{}
	if err := node.Encode(v); err != nil {
		return nil, fmt.Errorf("encode yaml node: %w", err)
	}
	return node, nil
}
