package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// secretKeys are the JSON fields and query parameters --debug never prints.
var secretKeys = map[string]bool{
	"code": true, "code_verifier": true, "nonce": true, "key_proof": true, "state": true,
	"secret": true, "proof": true, "challenge": true, "access_token": true, "id_token": true,
	"refresh_token": true, "code_challenge": true,
}

// Redact is a body for --debug: JSON with every secret field's value
// replaced by "[redacted]", or "[N bytes]" for anything else.
func Redact(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return fmt.Sprintf("[%d bytes]", len(b))
	}
	out, _ := json.Marshal(redactValue(v))
	s := string(out)
	if len(s) > 2000 {
		s = s[:2000] + "…"
	}
	return s
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if secretKeys[strings.ToLower(k)] {
				t[k] = "[redacted]"
			} else {
				t[k] = redactValue(x)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactValue(t[i])
		}
	}
	return v
}

// redactURL drops secret query values.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "[url]"
	}
	q := u.Query()
	for k := range q {
		if secretKeys[strings.ToLower(k)] {
			q.Set(k, "[redacted]")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// RedactURL is redactURL for other packages (the authorize URL is public,
// but --debug keeps the same rule).
func RedactURL(s string) string { return redactURL(s) }
