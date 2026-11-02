package settings

import (
	"reflect"
	"testing"
)

func TestMultiEnumAndList(t *testing.T) {
	me := opt(t, "type: multi_enum\noptions: [{value: eng, label: English}, {value: ita, label: Italian}, {value: fra, label: French}]\n")
	if err := NewRegistry().CheckOption(me); err != nil {
		t.Fatal(err)
	}
	// Set semantics: option order, duplicates collapse.
	if v := mustParse(t, me, []any{"fra", "eng", "fra"}); !reflect.DeepEqual(v, []Value{"eng", "fra"}) {
		t.Errorf("multi_enum = %#v", v)
	}
	if v := mustParse(t, me, []string{"ita"}); !reflect.DeepEqual(v, []Value{"ita"}) {
		t.Errorf("[]string = %#v", v)
	}
	refused(t, me, []any{"deu"}, "deu")
	refused(t, me, "eng", "list")
	if got := NewRegistry().Display(me, []Value{"eng", "ita"}); got != "English, Italian" {
		t.Errorf("Display = %q", got)
	}

	l := opt(t, "type: list\nitems: {type: string, pattern: '^/dev/.+$'}\nunique: true\nmax_items: 8\n")
	if err := NewRegistry().CheckOption(l); err != nil {
		t.Fatal(err)
	}
	if v := mustParse(t, l, []any{"/dev/sdb", "/dev/sda"}); !reflect.DeepEqual(v, []Value{"/dev/sdb", "/dev/sda"}) {
		t.Errorf("list keeps order: %#v", v)
	}
	refused(t, l, []any{"/dev/sda", "/dev/sda"}, "duplicate")
	refused(t, l, []any{"/etc/passwd"}, "item 1", "pattern")
	nine := []any{}
	for _, c := range "abcdefghi" {
		nine = append(nine, "/dev/sd"+string(c))
	}
	refused(t, l, nine, "at most 8")
	// Without unique, duplicates stay.
	d := opt(t, "type: list\nitems: {type: int, min: 1}\nmin_items: 1\n")
	if v := mustParse(t, d, []any{2, 2}); !reflect.DeepEqual(v, []Value{int64(2), int64(2)}) {
		t.Errorf("int list = %#v", v)
	}
	refused(t, d, []any{}, "at least 1")
	refused(t, d, []any{0}, "item 1")
	for _, bad := range []string{
		"type: list\n",
		"type: list\nitems: {type: size}\n",
		"type: list\nitems: {type: enum}\n",
		"type: list\nitems: {type: string, pattern: '[x'}\n",
		"type: list\nitems: {type: string}\nmax_items: 1001\n",
		"type: list\nitems: {type: string}\nmin_items: 3\nmax_items: 2\n",
		"type: multi_enum\n",
	} {
		if NewRegistry().CheckOption(opt(t, bad)) == nil {
			t.Errorf("CheckOption accepted %q", bad)
		}
	}
}

func TestTableParse(t *testing.T) {
	o := opt(t, `type: table
key_column: name
columns:
  - {name: name, label: Name, type: string, required: true, max_len: 16}
  - {name: port, label: Port, type: int, min: 1, max: 65535}
  - {name: tls, label: TLS, type: bool}
  - {name: mode, label: Mode, type: enum, options: [{value: ro, label: RO}, {value: rw, label: RW}]}
`)
	if err := NewRegistry().CheckOption(o); err != nil {
		t.Fatal(err)
	}
	v := mustParse(t, o, []any{
		map[string]any{"name": "a", "port": 80, "tls": true, "mode": "ro"},
		map[string]any{"name": "b"},
	})
	want := []map[string]Value{{"name": "a", "port": int64(80), "tls": true, "mode": "ro"}, {"name": "b"}}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("table = %#v", v)
	}
	refused(t, o, []any{map[string]any{"port": 80}}, "row 1", "name", "required")
	refused(t, o, []any{map[string]any{"name": "a"}, map[string]any{"name": "a"}}, "duplicate", "name")
	refused(t, o, []any{map[string]any{"name": "a", "port": 0}}, "row 1", "port")
	refused(t, o, []any{map[string]any{"name": "a", "extra": 1}}, "extra")
	refused(t, o, []any{"a"}, "row 1")
	if got := NewRegistry().Display(o, want); got != "2 rows" {
		t.Errorf("Display = %q", got)
	}
	for _, bad := range []string{
		"type: table\n",
		"type: table\ncolumns: [{name: Bad, label: B, type: string}]\n",
		"type: table\ncolumns: [{name: a, label: A, type: string}, {name: a, label: A, type: int}]\n",
		"type: table\ncolumns: [{name: a, label: A, type: list}]\n",
		"type: table\ncolumns: [{name: a, label: A, type: string}]\nkey_column: b\n",
		"type: table\ncolumns: [{name: a, label: A, type: enum}]\n",
		"type: table\ncolumns: [{name: a, label: '', type: string}]\n",
	} {
		if NewRegistry().CheckOption(opt(t, bad)) == nil {
			t.Errorf("CheckOption accepted %q", bad)
		}
	}
}

func TestUserGroupNames(t *testing.T) {
	u := opt(t, "type: user\n")
	if v := mustParse(t, u, "Alice"); v != "alice" {
		t.Errorf("user folds to lowercase: %#v", v)
	}
	refused(t, u, "alice@example.com", "username", "not an email")
	refused(t, u, "-alice", "username")
	refused(t, u, "", "username")
	us := opt(t, "type: users\n")
	if v := mustParse(t, us, []any{"bob", "alice", "Bob"}); !reflect.DeepEqual(v, []Value{"alice", "bob"}) {
		t.Errorf("users = %#v", v)
	}
	refused(t, us, []any{"a@b.c"}, "not an email")

	g := opt(t, "type: group\n")
	if v := mustParse(t, g, "office_milan"); v != "office_milan" {
		t.Errorf("group = %#v", v)
	}
	refused(t, g, "office milan", "group name")
	refused(t, g, "_x", "group name")
	gs := opt(t, "type: groups\n")
	if v := mustParse(t, gs, []any{"b", "a", "b"}); !reflect.DeepEqual(v, []Value{"a", "b"}) {
		t.Errorf("groups = %#v", v)
	}
	if got := NewRegistry().Display(gs, []Value{"a", "b"}); got != "a, b" {
		t.Errorf("Display = %q", got)
	}
}

// Fix round 1: a username is ASCII before it is lowercased (the Kelvin
// sign K lowercases to k).
func TestUserASCIIBeforeFold(t *testing.T) {
	u := opt(t, "type: user\n")
	for _, s := range []string{"Kelvin", "alİce", "bobſ"} {
		refused(t, u, s, "username")
	}
	refused(t, opt(t, "type: users\n"), []any{"Kelvin"}, "username")
}
