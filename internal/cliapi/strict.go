package cliapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Body caps (contract §18.4).
const (
	MaxCertRequest  = 16 << 10
	MaxEnrolRequest = 64 << 10
	MaxSmallRequest = 4 << 10
	MaxBundle       = 4 << 20
	MaxReport       = 256 << 10
)

// ErrTooLarge is wrapped by DecodeStrict when the body exceeds its cap.
var ErrTooLarge = errors.New("body too large")

// DecodeStrict reads at most max bytes from r and decodes exactly one JSON
// value into v: unknown fields, trailing data and anything above max are
// refused. The error never quotes the input.
func DecodeStrict(r io.Reader, max int64, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if int64(len(b)) > max {
		return fmt.Errorf("%w (over %d bytes)", ErrTooLarge, max)
	}
	return UnmarshalStrict(b, v)
}

// UnmarshalStrict is DecodeStrict for a byte slice already in memory (the
// caller has applied its cap).
func UnmarshalStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var se *json.SyntaxError
		var te *json.UnmarshalTypeError
		switch {
		case errors.As(err, &se):
			return fmt.Errorf("invalid JSON at offset %d", se.Offset)
		case errors.As(err, &te):
			return fmt.Errorf("invalid JSON: field %q has the wrong type", te.Field)
		case errors.Is(err, io.EOF):
			return errors.New("empty body")
		}
		return fmt.Errorf("invalid JSON: %s", fieldError(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON: trailing data")
	}
	return nil
}

// fieldError keeps encoding/json's own messages (they name fields, never
// values), e.g. `json: unknown field "x"`.
func fieldError(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
