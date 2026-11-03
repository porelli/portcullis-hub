package settings

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/templates"
)

// H4: JSON renders never HTML-escape & < > (env refuses the backslash
// of &).
func TestJSONRenderNoHTMLEscape(t *testing.T) {
	o := opt(t, "type: list\nitems: {type: string}\n")
	r, err := Render(o, []Value{"https://x/?a=1&b=<2>"}, &templates.Render{Format: templates.RenderJSON})
	if err != nil || r.Text != `["https://x/?a=1&b=<2>"]` {
		t.Errorf("list json = %q, %v", r.Text, err)
	}
	s := opt(t, "type: string\n")
	if r, err := Render(s, "R&D", &templates.Render{Format: templates.RenderJSON}); err != nil || r.Text != `"R&D"` {
		t.Errorf("string json = %q, %v", r.Text, err)
	}
	tb := opt(t, "type: table\ncolumns: [{name: a, label: A, type: string}]\n")
	if r, err := Render(tb, []map[string]Value{{"a": "x&y"}}, nil); err != nil || r.Text != `[{"a":"x&y"}]` {
		t.Errorf("table json = %q, %v", r.Text, err)
	}
	if err := CheckEnvText(`["a\"b"]`, true); err == nil || !strings.Contains(err.Error(), "JSON escapes") {
		t.Errorf("CheckEnvText(JSON with an escape) = %v", err)
	}
}

// H6: requires counts a bool false as not set.
func TestRequiresBoolFalseIsEmpty(t *testing.T) {
	spec := &templates.SettingsSpec{Options: []templates.Option{
		{Key: "enable_smtp", Type: templates.TypeBool, Requires: []string{"smtp_host"}},
		{Key: "smtp_host", Type: templates.TypeString},
	}}
	if err := CheckRequires(spec, map[string]Value{"enable_smtp": false}); err != nil {
		t.Errorf("false with no host: %v", err)
	}
	if err := CheckRequires(spec, map[string]Value{"enable_smtp": true}); err == nil {
		t.Error("true with no host accepted")
	}
}
