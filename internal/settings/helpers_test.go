package settings

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/templates"
	"gopkg.in/yaml.v3"
)

// opt decodes one manifest option written as YAML.
func opt(t *testing.T, src string) *templates.Option {
	t.Helper()
	var o templates.Option
	if err := yaml.Unmarshal([]byte(src), &o); err != nil {
		t.Fatalf("option yaml: %v", err)
	}
	if o.Key == "" {
		o.Key = "k"
	}
	if o.Label == "" {
		o.Label = "K"
	}
	return &o
}

// wantErr fails unless err is non-nil and contains every part.
func wantErr(t *testing.T, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want an error containing %q, got nil", parts)
	}
	for _, p := range parts {
		if !strings.Contains(err.Error(), p) {
			t.Fatalf("error %q does not contain %q", err, p)
		}
	}
}

func mustParse(t *testing.T, o *templates.Option, raw any) Value {
	t.Helper()
	v, err := NewRegistry().Parse(o, raw)
	if err != nil {
		t.Fatalf("Parse(%v): %v", raw, err)
	}
	return v
}

func refused(t *testing.T, o *templates.Option, raw any, parts ...string) {
	t.Helper()
	_, err := NewRegistry().Parse(o, raw)
	wantErr(t, err, parts...)
}
