// Canonical tool arguments (contract §15.6): a port of the gate's
// mcp-gate/internal/canon (porelli/portcullis, canon.go) rule for rule, so
// the Hub hashes, confirms and runs exactly what the gate would accept —
// the RFC 8785 canonical JSON (gowebpki/jcs), refusing duplicate keys at
// any level, depth over 64, numbers that can't round-trip (outside the
// safe-integer range, precision loss, over 40 bytes or |exponent| > 350)
// and U+2028 / U+2029. TestCanonParity runs core's vectors. Keep both in
// sync.
package mcpsdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

const (
	maxDepth     = 64
	maxNumberLen = 40  // bytes of one number's text
	maxExponent  = 350 // |exponent| of one number
	maxSafeInt   = 1<<53 - 1
)

// ErrArguments: the arguments can't be canonicalised without changing them.
var ErrArguments = errors.New("arguments can't be passed on unchanged")

// CanonicalArguments returns the canonical bytes of tools/call arguments: absent or
// null = {}; otherwise exactly one JSON object.
func CanonicalArguments(raw json.RawMessage) ([]byte, error) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return []byte("{}"), nil
	}
	if t[0] != '{' || !utf8.Valid(t) {
		return nil, ErrArguments
	}
	if err := check(t); err != nil {
		return nil, err
	}
	c, err := jcs.Transform(t)
	if err != nil {
		return nil, ErrArguments
	}
	// JCS writes U+2028 / U+2029 raw; Go's JSON encoder (the SDK client's)
	// re-escapes them, so the forwarded bytes would differ from the
	// hashed ones. Refused: the gate forwards exactly what it hashed.
	if bytes.ContainsRune(c, '\u2028') || bytes.ContainsRune(c, '\u2029') {
		return nil, ErrArguments
	}
	return c, nil
}

// check walks the tokens: one value, no trailing data, no duplicate keys,
// bounded depth, every number exactly representable.
func check(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := value(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrArguments
	}
	return nil
}

func value(dec *json.Decoder, depth int) error {
	if depth > maxDepth {
		return ErrArguments
	}
	tok, err := dec.Token()
	if err != nil {
		return ErrArguments
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return ErrArguments
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return ErrArguments
				}
				seen[key] = true
				if err := value(dec, depth+1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := value(dec, depth+1); err != nil {
					return err
				}
			}
		default:
			return ErrArguments
		}
		if _, err := dec.Token(); err != nil { // the closing delimiter
			return ErrArguments
		}
	case json.Number:
		return number(string(v))
	}
	return nil
}

// number: the canonical text must denote exactly the input's value.
func number(s string) error {
	if len(s) > maxNumberLen {
		return ErrArguments
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(strings.TrimPrefix(s[i+1:], "+"))
		if err != nil || e > maxExponent || e < -maxExponent {
			return ErrArguments
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || math.Abs(f) > maxSafeInt {
		return ErrArguments
	}
	text, err := jcs.NumberToJSON(f)
	if err != nil {
		return ErrArguments
	}
	in, ok1 := new(big.Rat).SetString(s)
	out, ok2 := new(big.Rat).SetString(text)
	if !ok1 || !ok2 || in.Cmp(out) != 0 {
		return ErrArguments
	}
	return nil
}
