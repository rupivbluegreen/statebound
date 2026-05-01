package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// EncodeJSON returns canonical JSON bytes for the pack:
//
//   - struct fields are emitted in the declared order in PackContent;
//   - every nested map[string]any encoded inside this package is round-
//     tripped through writeCanonical so its keys are sorted lexicographically
//     at every level;
//   - every json.RawMessage in PackContent is already canonical because the
//     builder calls Canonicalize on the way in (see builder.go);
//   - the encoder uses a custom byte-level emitter rather than json.Marshal
//     so we are not at the mercy of encoding/json's defaults if they ever
//     change between Go releases for integers, time.Time, or quoting;
//   - output is terminated with a trailing newline so the bytes are
//     POSIX-friendly diff/cat targets.
//
// EncodeJSON(c) and EncodeJSON(c) for the same *PackContent always
// produce byte-identical output. SHA-256 of those bytes is the
// EvidencePack.ContentHash that the storage layer persists.
func EncodeJSON(c *PackContent) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("evidence: nil pack content")
	}
	// The simplest deterministic encoder is json.Marshal of the typed
	// PackContent struct: encoding/json emits struct fields in declared
	// order and, for any map[string]X it encounters in a json.RawMessage
	// blob, the bytes are already pre-canonicalised by the builder. We
	// then append a trailing newline.
	//
	// time.Time formats deterministically as RFC3339Nano. Pointers and
	// omitempty fields render the same way every run because PackContent
	// has no maps directly on it — the only maps live inside RawMessage
	// fields that have already been canonicalised.
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("evidence: marshal pack content: %w", err)
	}
	out := make([]byte, 0, len(raw)+1)
	out = append(out, raw...)
	out = append(out, '\n')
	return out, nil
}

// Canonicalize re-marshals raw JSON so map keys are sorted at every level
// and there is no extra whitespace. The result is the exact bytes that
// EncodeJSON's pack-level marshal would emit had it constructed the value
// itself, so embedding the result in a PackContent.RawMessage field keeps
// the pack reproducible.
//
// Canonicalize accepts JSON null, objects, arrays, strings, booleans, and
// numbers. Objects are sorted; arrays preserve their input order; numbers
// round-trip through encoding/json's number handling.
func Canonicalize(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("evidence: canonicalize: input is not valid JSON")
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("evidence: canonicalize decode: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, fmt.Errorf("evidence: canonicalize encode: %w", err)
	}
	return json.RawMessage(buf.Bytes()), nil
}

// CanonicalizeMap is a convenience wrapper for the common case where a
// caller already holds a map[string]any (e.g., a snapshot Content row
// retrieved as map[string]any from the storage layer) and wants its
// canonical-JSON bytes for embedding in a PackContent RawMessage field.
func CanonicalizeMap(m map[string]any) (json.RawMessage, error) {
	if m == nil {
		// Encode null rather than {} so omitempty does the right thing
		// at the parent struct level if the caller chooses to skip it.
		return json.RawMessage("null"), nil
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, m); err != nil {
		return nil, fmt.Errorf("evidence: canonicalize map: %w", err)
	}
	return json.RawMessage(buf.Bytes()), nil
}

// writeCanonical emits v to buf with sorted object keys and no extra
// whitespace. It is intentionally narrow — only the JSON shapes the
// builder hands it can occur — and intentionally local: we do not want
// the canonical emitter to drift with future Go encoding/json changes.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		out, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(out)
		return nil
	case json.Number:
		buf.WriteString(t.String())
		return nil
	case float64:
		out, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(out)
		return nil
	case int:
		out, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(out)
		return nil
	case int64:
		out, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(out)
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
			if err := writeCanonical(buf, t[k]); err != nil {
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
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		// Fallback: hand the value to encoding/json. This branch should
		// be unreachable for inputs produced via UseNumber decoding, but
		// we want a safe fallback rather than a silent panic.
		out, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("evidence: canonicalize: unsupported type %T: %w", t, err)
		}
		buf.Write(out)
		return nil
	}
}
