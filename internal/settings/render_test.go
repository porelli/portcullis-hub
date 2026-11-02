package settings

import (
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/templates"
	"gopkg.in/yaml.v3"
)

func rd(t *testing.T, src string) *templates.Render {
	t.Helper()
	var r templates.Render
	if err := yaml.Unmarshal([]byte(src), &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

const gib = int64(1) << 30

func TestRender(t *testing.T) {
	size := opt(t, "type: size\nallow_unlimited: true\n")
	cases := []struct {
		name     string
		o        *templates.Option
		v        Value
		render   string
		wantText string
		wantJSON any
	}{
		{"size GiB integer", size, 10 * gib, "{unit: GiB, integer: true}", "10", int64(10)},
		{"size GiB fraction", size, 3 * gib / 2, "{unit: GiB}", "1.5", 1.5},
		{"size MiB", size, 10 * gib, "{unit: MiB, integer: true}", "10240", int64(10240)},
		{"size bytes by default", size, 10 * gib, "{}", "10737418240", int64(10737418240)},
		{"size GB is 10^9", size, int64(5_000_000_000), "{unit: GB, integer: true}", "5", int64(5)},
		{"size GiB in GB", size, 10 * gib, "{unit: GB}", "10.73741824", 10.73741824},
		{"size TB", size, int64(2_000_000_000_000), "{unit: TB, integer: true}", "2", int64(2)},
		{"unlimited -1", size, Unlimited{}, "{unlimited: \"-1\"}", "-1", int64(-1)},
		{"unlimited none", size, Unlimited{}, "{unlimited: none}", "none", "none"},
		{"duration days", opt(t, "type: duration\n"), int64(2592000), "{unit: d, integer: true}", "30", int64(30)},
		{"duration minutes", opt(t, "type: duration\n"), int64(5400), "{unit: m}", "90", int64(90)},
		{"duration h fraction", opt(t, "type: duration\n"), int64(5400), "{unit: h}", "1.5", 1.5},
		{"int", opt(t, "type: int\nunit: days\n"), int64(30), "{unit: days}", "30", int64(30)},
		{"bool true", opt(t, "type: bool\n"), true, "{true: \"yes\", false: \"no\"}", "yes", "yes"},
		{"bool false", opt(t, "type: bool\n"), false, "{true: \"yes\", false: \"no\"}", "no", "no"},
		{"bool plain", opt(t, "type: bool\n"), true, "{}", "true", true},
		{"string", opt(t, "type: string\n"), "a b", "{}", "a b", "a b"},
		{"list join", opt(t, "type: list\nitems: {type: string}\n"), []Value{"eng", "ita"}, "{join: \"+\"}", "eng+ita", "eng+ita"},
		{"list json", opt(t, "type: list\nitems: {type: string}\n"), []Value{"eng", "ita"}, "{format: json}", `["eng","ita"]`, []any{"eng", "ita"}},
		{"list default join", opt(t, "type: list\nitems: {type: int}\n"), []Value{int64(1), int64(2)}, "{}", "1,2", []any{int64(1), int64(2)}},
		{"list csv", opt(t, "type: list\nitems: {type: string}\n"), []Value{"a,b", "c"}, "{format: csv}", `"a,b",c`, `"a,b",c`},
		{"table csv", opt(t, "type: table\ncolumns: [{name: name, label: N, type: string}, {name: port, label: P, type: int}]\n"),
			[]map[string]Value{{"name": "a", "port": int64(80)}, {"name": "b"}}, "{format: csv}",
			"name,port\na,80\nb,\n", "name,port\na,80\nb,\n"},
		{"table json keyed", opt(t, "type: table\nkey_column: name\ncolumns: [{name: name, label: N, type: string}, {name: port, label: P, type: int}]\n"),
			[]map[string]Value{{"name": "a", "port": int64(80)}}, "{format: json}",
			`{"a":{"name":"a","port":80}}`, map[string]any{"a": map[string]any{"name": "a", "port": int64(80)}}},
		{"multi_enum yaml", opt(t, "type: multi_enum\noptions: [{value: a, label: A}, {value: b, label: B}]\n"), []Value{"a", "b"}, "{format: yaml}", "- a\n- b\n", "- a\n- b\n"},
	}
	for _, c := range cases {
		got, err := Render(c.o, c.v, rd(t, c.render))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got.Text != c.wantText || !reflect.DeepEqual(got.JSON, c.wantJSON) {
			t.Errorf("%s: got %q / %#v, want %q / %#v", c.name, got.Text, got.JSON, c.wantText, c.wantJSON)
		}
	}
	// A nil render is the defaults.
	if got, err := Render(opt(t, "type: bool\n"), false, nil); err != nil || got.Text != "false" {
		t.Errorf("nil render = %#v, %v", got, err)
	}

	refusals := []struct {
		name   string
		o      *templates.Option
		v      Value
		render string
		parts  []string
	}{
		{"1.5GiB into integer GiB", size, 3 * gib / 2, "{unit: GiB, integer: true}", []string{"GiB", "whole"}},
		{"GiB into integer GB", size, 10 * gib, "{unit: GB, integer: true}", []string{"GB", "whole"}},
		{"unlimited without sentinel", size, Unlimited{}, "{unit: GiB}", []string{"unlimited"}},
		{"unlimited not allowed", opt(t, "type: size\n"), Unlimited{}, "{unlimited: \"-1\"}", []string{"unlimited"}},
		{"90m into integer h", opt(t, "type: duration\n"), int64(5400), "{unit: h, integer: true}", []string{"h", "whole"}},
		{"join newline", opt(t, "type: list\nitems: {type: string}\n"), []Value{"a", "b"}, "{join: \"\\n\"}", []string{"newline"}},
		{"item holds the separator", opt(t, "type: list\nitems: {type: string}\n"), []Value{"a+b"}, "{join: \"+\"}", []string{"separator"}},
	}
	for _, c := range refusals {
		_, err := Render(c.o, c.v, rd(t, c.render))
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		for _, p := range c.parts {
			if !strings.Contains(err.Error(), p) {
				t.Errorf("%s: %q does not name %q", c.name, err, p)
			}
		}
	}
}

func TestRenderRefusesNewlinesAndOversize(t *testing.T) {
	tbl := opt(t, "type: table\ncolumns: [{name: n, label: N, type: string}]\n")
	two := []map[string]Value{{"n": "a"}, {"n": "b"}}
	csv := &templates.Render{Format: "csv"}
	for _, d := range []templates.Delivery{
		{Env: "ROWS", Render: csv},
		{Header: &templates.HeaderDelivery{Name: "X-Forwarded-Attr-Rows", Render: csv}},
		{Claim: &templates.ClaimDelivery{Client: "c", Name: "rows", Render: csv}},
	} {
		_, err := RenderDelivery(tbl, two, &d)
		wantErr(t, err, "newline", DeliveryName(&d))
	}
	// Files and hooks take structured text.
	for _, d := range []templates.Delivery{
		{File: &templates.FileDelivery{Name: "f", Render: csv}},
		{Hook: "h", Render: csv},
	} {
		if _, err := RenderDelivery(tbl, two, &d); err != nil {
			t.Errorf("%s: %v", DeliveryName(&d), err)
		}
	}

	s := opt(t, "type: string\n")
	h := templates.Delivery{Header: &templates.HeaderDelivery{Name: "X-Forwarded-Attr-Big"}}
	c := templates.Delivery{Claim: &templates.ClaimDelivery{Client: "c", Name: "big"}}
	if _, err := RenderDelivery(s, strings.Repeat("a", 1024), &h); err != nil {
		t.Errorf("1024-byte header: %v", err)
	}
	_, err := RenderDelivery(s, strings.Repeat("a", 1025), &h)
	wantErr(t, err, "header X-Forwarded-Attr-Big", "1024")
	if _, err := RenderDelivery(s, strings.Repeat("a", 4096), &c); err != nil {
		t.Errorf("4096-byte claim: %v", err)
	}
	_, err = RenderDelivery(s, strings.Repeat("a", 4097), &c)
	wantErr(t, err, "claim big", "4096")
	// The delivery's own render is used.
	b := opt(t, "type: bool\n")
	got, err := RenderDelivery(b, true, &templates.Delivery{Claim: &templates.ClaimDelivery{Client: "c", Name: "x", Render: rd(t, "{true: \"1\"}")}})
	if err != nil || got.Text != "1" {
		t.Errorf("claim render = %#v, %v", got, err)
	}
}

func TestCheckOptionRenders(t *testing.T) {
	bad := map[string]string{
		"type: size\ndelivery: [{env: Q, render: {unit: days}}]\n":                        "unit",
		"type: size\nallow_unlimited: true\ndelivery: [{env: Q, render: {unit: GiB}}]\n":  "unlimited",
		"type: size\ndelivery: [{env: Q, render: {unlimited: \"-1\"}}]\n":                 "unlimited",
		"type: int\nunit: days\ndelivery: [{env: Q, render: {unit: GiB}}]\n":              "unit",
		"type: string\ndelivery: [{env: Q, render: {true: \"y\"}}]\n":                     "true",
		"type: string\ndelivery: [{env: Q, render: {join: \"+\"}}]\n":                     "join",
		"type: string\ndelivery: [{env: Q, render: {format: xml}}]\n":                     "format",
		"type: duration\ndelivery: [{env: Q, render: {unit: GiB}}]\n":                     "unit",
		"type: bool\ndelivery: [{env: Q, render: {integer: true}}]\n":                     "integer",
		"type: list\nitems: {type: string}\ndelivery: [{env: Q, render: {join: \"\"}}]\n": "join",
	}
	for s, part := range bad {
		wantErr(t, NewRegistry().CheckOption(opt(t, s)), part)
	}
	ok := []string{
		"type: size\nallow_unlimited: true\ndelivery: [{claim: {client: c, name: q, render: {unit: GiB, unlimited: \"-1\"}}}]\n",
		"type: size\ndelivery: [{hook: h, render: {unit: GB, integer: true}}]\n",
		"type: list\nitems: {type: string}\ndelivery: [{env: L, render: {join: \" \"}}]\n",
		"type: bool\ndelivery: [{env: B, render: {true: \"on\", false: \"off\"}}]\n",
		"type: string\nscope: person_entered\nmax_len: 10\ndelivery: [{env: L, render: {join: \",\"}}]\n",
		"type: table\ncolumns: [{name: a, label: A, type: string}]\ndelivery: [{file: {name: f}}]\n",
	}
	for _, s := range ok {
		if err := NewRegistry().CheckOption(opt(t, s)); err != nil {
			t.Errorf("CheckOption(%q): %v", s, err)
		}
	}
}
