package settings

import (
	"errors"
	"sort"
	"testing"

	"github.com/portcullis/hub/internal/templates"
)

type stubKind struct{ name string }

func (s stubKind) Name() string                                      { return s.name }
func (stubKind) CheckOption(*templates.Option) error                 { return nil }
func (stubKind) Parse(_ *templates.Option, raw any) (Value, error)   { return raw, nil }
func (stubKind) Display(*templates.Option, Value) string             { return "stub" }
func (stubKind) Compare(*templates.Option, Value, Value) (int, bool) { return 0, false }

func TestRegistryReserved(t *testing.T) {
	r := NewRegistry()
	for typ, feature := range map[string]string{
		"person_id":     "file sharing (project 3)",
		"person_secret": "file sharing (project 3)",
		"folder":        "shared folders (project 2)",
	} {
		_, err := r.Kind(typ)
		var ni *ErrNotImplemented
		if !errors.As(err, &ni) || ni.Feature != feature || ni.Type != typ {
			t.Errorf("Kind(%s) = %v, want ErrNotImplemented{%s}", typ, err, feature)
		}
		if r.Known(typ) {
			t.Errorf("Known(%s) before Register", typ)
		}
	}
	if _, err := r.Kind("text"); err == nil {
		t.Error("Kind(text) must fail")
	}
	r.Register(stubKind{"person_id"})
	if !r.Known("person_id") {
		t.Error("Known(person_id) after Register")
	}
	if k, err := r.Kind("person_id"); err != nil || k.Name() != "person_id" {
		t.Errorf("Kind after Register = %v, %v", k, err)
	}
	// Register replaces a kind of the same name.
	r.Register(stubKind{"string"})
	if got := r.Display(&templates.Option{Type: "string"}, "x"); got != "stub" {
		t.Errorf("replaced kind not used: %q", got)
	}
	// A reserved type's option is refused through CheckOption too.
	var ni *ErrNotImplemented
	if err := NewRegistry().CheckOption(&templates.Option{Key: "k", Type: "folder"}); !errors.As(err, &ni) {
		t.Errorf("CheckOption(folder) = %v", err)
	}
}

// TestBuiltinTypesParity: the registry's kinds are exactly
// templates.BuiltinTypes (T-3), so Discover with nil and with the
// registry know the same types.
func TestBuiltinTypesParity(t *testing.T) {
	var got, want []string
	for _, n := range NewRegistry().Names() {
		got = append(got, n)
	}
	for n := range templates.BuiltinTypes {
		want = append(want, n)
	}
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("registry %v, BuiltinTypes %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("registry %v, BuiltinTypes %v", got, want)
		}
	}
}

func TestParseDefault(t *testing.T) {
	if err := ParseDefault(opt(t, "type: size\ndefault: 500GiB\n")); err != nil {
		t.Error(err)
	}
	wantErr(t, ParseDefault(opt(t, "type: size\ndefault: 500 gigs\n")), "default")
	if err := ParseDefault(opt(t, "type: size\n")); err != nil {
		t.Error(err)
	}
}

func TestCheckOptionGroupValues(t *testing.T) {
	o := opt(t, "type: enum\noptions: [{value: user, label: User}, {value: admin, label: Admin}]\ndefault: user\ngroup_values: {'{{ADMIN_GROUP}}': owner}\n")
	wantErr(t, NewRegistry().CheckOption(o), "group_values", "owner")
}

func TestResolveOwner(t *testing.T) {
	o := opt(t, pathOpt+"writes_as: {uid: 1000, gid: pgid}\n")
	uid, gid, err := ResolveOwner(o, map[string]Value{"pgid": int64(100)})
	if err != nil || uid != 1000 || gid != 100 {
		t.Errorf("ResolveOwner = %d, %d, %v", uid, gid, err)
	}
	// A string option holding a number works too.
	if _, gid, err := ResolveOwner(o, map[string]Value{"pgid": "100"}); err != nil || gid != 100 {
		t.Errorf("string pgid = %d, %v", gid, err)
	}
	for _, inst := range []map[string]Value{nil, {"pgid": "abc"}, {"pgid": int64(-1)}, {"pgid": true}} {
		if _, _, err := ResolveOwner(o, inst); err == nil {
			t.Errorf("ResolveOwner(%v) accepted", inst)
		}
	}
	if _, _, err := ResolveOwner(opt(t, pathOpt), nil); err == nil {
		t.Error("no writes_as must be an error")
	}
}
