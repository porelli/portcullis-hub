package settings

import (
	"strings"
	"testing"
)

func TestSizeParse(t *testing.T) {
	o := opt(t, "type: size\nstep: 1GiB\nallow_unlimited: true\n")
	for _, raw := range []any{"10GiB", 10737418240, int64(10737418240), float64(10737418240), "10 GiB"} {
		if v := mustParse(t, o, raw); v != int64(10737418240) {
			t.Errorf("Parse(%v) = %#v", raw, v)
		}
	}
	if v := mustParse(t, o, "unlimited"); v != (Unlimited{}) {
		t.Errorf("unlimited = %#v", v)
	}
	if v := mustParse(t, o, Unlimited{}); v != (Unlimited{}) {
		t.Errorf("Unlimited{} = %#v", v)
	}
	refused(t, o, "1.5GiB", "must be a multiple of 1 GiB")
	refused(t, opt(t, "type: size\n"), "unlimited", "unlimited")
	for _, bad := range []any{"500 gigs", "10GB", "10G", "-1", -1, "1e3", "", true, "0.5B", 1.5} {
		refused(t, opt(t, "type: size\n"), bad)
	}
	if got := NewRegistry().Display(o, int64(10737418240)); got != "10 GiB" {
		t.Errorf("Display = %q", got)
	}
	if got := NewRegistry().Display(o, Unlimited{}); got != "unlimited" {
		t.Errorf("Display(unlimited) = %q", got)
	}
	k, _ := NewRegistry().Kind("size")
	if c, ok := k.Compare(o, Unlimited{}, int64(1)); !ok || c <= 0 {
		t.Errorf("unlimited must beat a number: %d %v", c, ok)
	}
	if c, ok := k.Compare(o, int64(1), int64(2)); !ok || c >= 0 {
		t.Errorf("1 < 2: %d %v", c, ok)
	}
}

func TestDurationParse(t *testing.T) {
	o := opt(t, "type: duration\n")
	if v := mustParse(t, o, "30d"); v != int64(2592000) {
		t.Errorf("30d = %#v", v)
	}
	if v := mustParse(t, o, "90m"); v != int64(5400) {
		t.Errorf("90m = %#v", v)
	}
	if v := mustParse(t, o, 60); v != int64(60) {
		t.Errorf("60 = %#v", v)
	}
	b := opt(t, "type: duration\nmin: 1h\nmax: 30d\n")
	mustParse(t, b, "1h")
	mustParse(t, b, "30d")
	refused(t, b, "59m", "at least 1h")
	refused(t, b, "31d", "at most 30d")
	refused(t, o, "-5m")
	refused(t, o, "1500ms", "whole seconds")
	refused(t, o, "soon")
	if got := NewRegistry().Display(o, int64(5400)); got != "1h30m" {
		t.Errorf("Display = %q", got)
	}
}

func TestIntParse(t *testing.T) {
	o := opt(t, "type: int\nmin: 0\nmax: 3650\nstep: 5\nunit: days\n")
	if v := mustParse(t, o, 30); v != int64(30) {
		t.Errorf("30 = %#v", v)
	}
	if v := mustParse(t, o, "3650"); v != int64(3650) {
		t.Errorf("3650 = %#v", v)
	}
	refused(t, o, "3651", "at most 3650")
	refused(t, o, -5, "at least 0")
	refused(t, o, 31, "multiple of 5")
	refused(t, o, 1.5)
	refused(t, o, "x")
	if got := NewRegistry().Display(o, int64(30)); got != "30 days" {
		t.Errorf("Display = %q", got)
	}
	// step counts from min.
	s := opt(t, "type: int\nmin: 1\nstep: 2\n")
	mustParse(t, s, 3)
	refused(t, s, 4, "multiple of 2")
}

func TestBoolParse(t *testing.T) {
	o := opt(t, "type: bool\n")
	if mustParse(t, o, true) != true || mustParse(t, o, false) != false {
		t.Error("bool")
	}
	refused(t, o, "yes")
	refused(t, o, 1)
}

func TestStringFormats(t *testing.T) {
	cases := []struct{ format, good, bad string }{
		{"hostname", "a.example.com", "-a"},
		{"ip", "10.0.0.1", "10.0.0.300"},
		{"cidr", "10.0.0.0/8", "10.0.0.0/33"},
		{"url", "https://x", "x"},
		{"email", "alice@example.com", "alice"},
		{"iana_tz", "Europe/Rome", "Mars/Base"},
		{"locale", "it-IT", "it-!!"},
		{"cron", "*/5 * * * *", "61 * * * *"},
		{"semver", "1.2.3", "1.2"},
		{"hex", "deadBEEF", "xyz"},
	}
	for _, c := range cases {
		o := opt(t, "type: string\nformat: "+c.format+"\n")
		if err := NewRegistry().CheckOption(o); err != nil {
			t.Fatalf("%s: CheckOption: %v", c.format, err)
		}
		if _, err := NewRegistry().Parse(o, c.good); err != nil {
			t.Errorf("%s: %q refused: %v", c.format, c.good, err)
		}
		refused(t, o, c.bad, c.format)
	}
	wantErr(t, NewRegistry().CheckOption(opt(t, "type: string\nformat: phone\n")), "format")

	p := opt(t, "type: string\npattern: '^[a-z]+$'\nmin_len: 2\nmax_len: 4\n")
	mustParse(t, p, "abc")
	refused(t, p, "a", "at least 2")
	refused(t, p, "abcde", "at most 4")
	refused(t, p, "ab1", "pattern")
	// The pattern applies to the whole value even with alternation.
	alt := opt(t, "type: string\npattern: '^a|b$'\n")
	refused(t, alt, "axx", "pattern")
	for _, s := range []string{"a\nb", "a\tb", "a\x7fb", "a\rb"} {
		refused(t, opt(t, "type: string\n"), s, "control characters")
	}
	refused(t, opt(t, "type: string\n"), 5, "string")
	refused(t, opt(t, "type: string\n"), "\xff", "UTF-8")
	if got := NewRegistry().Display(opt(t, "type: string\n"), "x"); got != "x" {
		t.Errorf("Display = %q", got)
	}
}

func TestEnumRankAndCompare(t *testing.T) {
	o := opt(t, "type: enum\noptions: [{value: viewer, label: Viewer}, {value: editor, label: Editor}, {value: admin, label: Admin}]\n")
	if err := NewRegistry().CheckOption(o); err != nil {
		t.Fatal(err)
	}
	if v := mustParse(t, o, "editor"); v != "editor" {
		t.Errorf("editor = %#v", v)
	}
	refused(t, o, "owner", "owner")
	k, _ := NewRegistry().Kind("enum")
	if c, ok := k.Compare(o, "viewer", "admin"); !ok || c >= 0 {
		t.Errorf("viewer < admin: %d %v", c, ok)
	}
	if c, ok := k.Compare(o, "admin", "editor"); !ok || c <= 0 {
		t.Errorf("admin > editor: %d %v", c, ok)
	}
	if c, ok := k.Compare(o, "editor", "editor"); !ok || c != 0 {
		t.Errorf("editor = editor: %d %v", c, ok)
	}
	if got := NewRegistry().Display(o, "admin"); got != "Admin" {
		t.Errorf("Display = %q", got)
	}
	for _, bad := range []string{
		"type: enum\n",
		"type: enum\noptions: [{value: a, label: A}, {value: a, label: B}]\n",
		"type: enum\noptions: [{value: '', label: A}]\n",
		"type: enum\noptions: [{value: a, label: ''}]\n",
		"type: enum\noptions: [{value: \"a\\nb\", label: A}]\n",
		"type: enum\noptions: [{value: a, label: A}]\nmin: 1\n",
	} {
		if NewRegistry().CheckOption(opt(t, bad)) == nil {
			t.Errorf("CheckOption accepted %q", bad)
		}
	}
	if !strings.Contains(NewRegistry().CheckOption(opt(t, "type: enum\noptions: [{value: a, label: A}]\nmin: 1\n")).Error(), "min") {
		t.Error("irrelevant field must be named")
	}
}

func TestScalarCheckOption(t *testing.T) {
	good := []string{
		"type: int\nmin: 0\nmax: 10\nstep: 2\nunit: days\ndefault: 4\n",
		"type: size\nstep: 1GiB\nmin: 0\nmax: 1TiB\ndefault: 500GiB\nallow_unlimited: true\ndelivery: [{env: Q, render: {unlimited: \"-1\"}}]\n",
		"type: duration\nmin: 1h\nmax: 30d\ndefault: 7d\n",
		"type: bool\ndefault: false\n",
		"type: string\ndefault: abc\nmax_len: 5\n",
	}
	for _, s := range good {
		if err := NewRegistry().CheckOption(opt(t, s)); err != nil {
			t.Errorf("CheckOption(%q): %v", s, err)
		}
	}
	bad := map[string]string{
		"type: int\nmin: 5\nmax: 1\n":                                 "min",
		"type: int\nstep: 0\n":                                        "step",
		"type: int\nstep: -2\n":                                       "step",
		"type: int\nmin: x\n":                                         "min",
		"type: int\nmax: 10\ndefault: 11\n":                           "default",
		"type: int\nallow_unlimited: true\n":                          "allow_unlimited",
		"type: size\nstep: 1GB\n":                                     "step",
		"type: size\nstep: 0\n":                                       "step",
		"type: size\nstep: 1GiB\ndefault: 1.5GiB\n":                   "default",
		"type: size\ndefault: 500 gigs\n":                             "default",
		"type: size\ndefault: unlimited\n":                            "default",
		"type: size\nunit: GiB\n":                                     "unit",
		"type: duration\nmin: 2d\nmax: 1d\n":                          "min",
		"type: duration\nstep: 1d\n":                                  "step",
		"type: bool\ndefault: yes\n":                                  "default",
		"type: string\npattern: '[a-z]+'\n":                           "anchored",
		"type: string\npattern: '^[a-z+$'\n":                          "pattern",
		"type: string\nmin_len: 5\nmax_len: 2\n":                      "min_len",
		"type: string\nmax_len: 70000\n":                              "max_len",
		"type: string\nmax_len: 2\ndefault: abc\n":                    "default",
		"type: string\nformat: hex\ndefault: xyz\n":                   "default",
		"type: string\npattern: '" + strings.Repeat("a", 501) + "'\n": "pattern",
	}
	for s, part := range bad {
		wantErr(t, NewRegistry().CheckOption(opt(t, s)), part)
	}
}
