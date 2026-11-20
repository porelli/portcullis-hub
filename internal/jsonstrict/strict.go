// Package jsonstrict is the Hub's one strict JSON decoder (moved from
// internal/aigate, which ports core mcp-gate/internal/config/strict.go:
// keep the two in step, the gate refuses what this refuses). The gate
// files, link.json, join codes and the agent API decode through it.
package jsonstrict

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

var (
	unmarshalerType     = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
	nullableType        = reflect.TypeFor[interface{ nullable() reflect.Type }]()
)

func typeOf(v any) reflect.Type { return reflect.TypeOf(v).Elem() }

// checkShape walks the JSON against the Go type: objects of struct types
// have exactly the struct's json keys (case-sensitive; omitempty keys may
// be absent), no object has a duplicate key, and nothing is null.
// encoding/json alone matches keys case-insensitively, keeps the last of
// duplicate keys and silently leaves missing fields at their zero value.
// Errors carry JSON paths, never values.
func checkShape(raw []byte, t reflect.Type, path string) error {
	if reflect.PointerTo(t).Implements(nullableType) {
		// Nullable: null, or the shape of T.
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return checkShape(raw, reflect.New(t).Interface().(interface{ nullable() reflect.Type }).nullable(), path)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s: null", path)
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) || reflect.PointerTo(t).Implements(textUnmarshalerType) {
		return nil // a leaf with its own decoder (time.Time, netip.Addr, netip.Prefix)
	}
	switch t.Kind() {
	case reflect.Struct:
		keys, vals, err := object(raw, path)
		if err != nil {
			return err
		}
		type field struct {
			t         reflect.Type
			omitempty bool
		}
		fields := map[string]field{}
		for i := 0; i < t.NumField(); i++ {
			sf := t.Field(i)
			if !sf.IsExported() {
				continue
			}
			tag := sf.Tag.Get("json")
			name, opts, _ := strings.Cut(tag, ",")
			if name == "-" || name == "" {
				continue
			}
			fields[name] = field{sf.Type, strings.Contains(opts, "omitempty")}
		}
		present := map[string]bool{}
		for i, k := range keys {
			f, ok := fields[k]
			if !ok {
				return fmt.Errorf("%s: unknown field %q", path, k)
			}
			present[k] = true
			if err := checkShape(vals[i], f.t, path+"."+k); err != nil {
				return err
			}
		}
		for name, f := range fields {
			if !present[name] && !f.omitempty {
				return fmt.Errorf("%s: missing field %q", path, name)
			}
		}
	case reflect.Map:
		keys, vals, err := object(raw, path)
		if err != nil {
			return err
		}
		for i := range keys {
			if err := checkShape(vals[i], t.Elem(), path+"["+fmt.Sprintf("%q", keys[i])+"]"); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			// []byte: only a base64 string (encoding/json would also take
			// a list of numbers).
			if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '"' {
				return fmt.Errorf("%s: not a base64 string", path)
			}
			return nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return fmt.Errorf("%s: not a list", path)
		}
		for i, it := range items {
			if err := checkShape(it, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// object splits a JSON object into its keys and raw values, in order,
// refusing duplicate keys.
func object(raw []byte, path string) ([]string, []json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, nil, fmt.Errorf("%s: not an object", path)
	}
	var keys []string
	var vals []json.RawMessage
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, fmt.Errorf("%s: malformed object", path)
		}
		k, _ := tok.(string)
		if seen[k] {
			return nil, nil, fmt.Errorf("%s: duplicate key %q", path, k)
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("%s: malformed object", path)
		}
		keys = append(keys, k)
		vals = append(vals, v)
	}
	return keys, vals, nil
}

// Decode: valid JSON with no trailing data, exactly the struct's keys
// (case-sensitive, no duplicates, none missing unless omitempty, no
// null), then the typed decode. Errors carry JSON paths, never values.
func Decode(b []byte, v any) error {
	if !json.Valid(b) {
		// Never echo the content (the credentials file holds ciphertexts).
		return fmt.Errorf("not valid JSON (or trailing data)")
	}
	if err := checkShape(b, typeOf(v), "$"); err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		if te, ok := err.(*json.UnmarshalTypeError); ok {
			return fmt.Errorf("%s: wrong type", te.Field)
		}
		return fmt.Errorf("does not decode")
	}
	return nil
}

// Nullable is a value that may be JSON null (the HA documents' `null`
// fields, contract §20: `public|null`, `set: null`, `not_ready_since`).
// Decode refuses null everywhere else; a Nullable leaf takes it, and a
// non-null value is checked as T.
type Nullable[T any] struct {
	Valid bool
	V     T
}

// Some is a non-null Nullable.
func Some[T any](v T) Nullable[T] { return Nullable[T]{Valid: true, V: v} }

// UnmarshalJSON: null → !Valid, else V. Strict only through Decode, which
// checks the shape of T first (checkShape).
func (n *Nullable[T]) UnmarshalJSON(b []byte) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		*n = Nullable[T]{}
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil { // the shape was checked by Decode
		return err
	}
	*n = Nullable[T]{Valid: true, V: v}
	return nil
}

// MarshalJSON: null when !Valid, else V.
func (n Nullable[T]) MarshalJSON() ([]byte, error) {
	if !n.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(n.V)
}

func (*Nullable[T]) nullable() reflect.Type { return reflect.TypeFor[T]() }
