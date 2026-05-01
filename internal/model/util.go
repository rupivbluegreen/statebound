package model

import (
	"bytes"
	"encoding/json"
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

// canonicalJSONBytes encodes v as JSON with map keys sorted lexicographically
// at every level. Output is byte-stable across runs and machines, which is
// what diff equality and snapshot hashing rely on.
func canonicalJSONBytes(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		out, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(out)
		return nil
	}
}
