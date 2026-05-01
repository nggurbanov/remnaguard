package jsonpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
)

func DecodeObjectNoDuplicateKeys(r io.Reader, maxBytes int64) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(io.LimitReader(r, maxBytes))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("top-level JSON object required")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := t.(string)
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate JSON key %q", key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		out[key] = bytes.Clone(raw)
	}
	_, err = dec.Token()
	return out, err
}

func ValidateFields(obj map[string]json.RawMessage, allowed []string) error {
	set := map[string]bool{}
	for _, field := range allowed {
		set[field] = true
	}
	for field := range maps.Keys(obj) {
		if !set[field] {
			return fmt.Errorf("unknown JSON field %q", field)
		}
	}
	return nil
}
