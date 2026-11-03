// Package settings holds the setting kinds of template contract v3
// (integration contracts §13.2, §13.5): parsing input into canonical
// values, display, ordering and rendering per delivery. The manifest
// model and its structural validation live in internal/templates; this
// package adds the type-specific checks (Registry.CheckOption, wired into
// templates.ValidateSettingsSpec through templates.Kinds).
package settings

import (
	"context"
	"fmt"
	"sort"

	"github.com/portcullis/hub/internal/templates"
)

// Value is a canonical setting value: string | int64 | bool | []Value |
// []map[string]Value | Unlimited. Sizes are bytes, durations seconds.
type Value = any

// Unlimited is a size's "unlimited" value (allow_unlimited). It is stored
// as the string UnlimitedText; -1 / 0 / "none" are only what a delivery
// renders it as (render.unlimited).
type Unlimited struct{}

// UnlimitedText is how Unlimited is written as input and in storage.
const UnlimitedText = "unlimited"

// Kind is one setting type.
type Kind interface {
	Name() string
	// CheckOption checks the manifest-time constraints of this type
	// (bounds, patterns, choices, columns, …). Defaults, group_values
	// and renders are checked by Registry.CheckOption.
	CheckOption(o *templates.Option) error
	// Parse turns input (JSON-decoded or YAML-decoded) into the canonical
	// value, enforcing o's constraints. A canonical value parses to itself.
	Parse(o *templates.Option, raw any) (Value, error)
	// Display is the value as the panel shows it ("10 GiB", "Administrator").
	Display(o *templates.Option, v Value) string
	// Compare orders a and b (-1, 0, 1); false = the type isn't ordered.
	Compare(o *templates.Option, a, b Value) (int, bool)
}

// Mounter is a kind whose value is a host directory (path; folder in
// project 2).
type Mounter interface {
	HostPath(o *templates.Option, v Value) (string, error)
}

// Person is one person of an option's population: the lowercase username
// and their groups (name → LLDAP group id).
type Person struct {
	User   string
	Groups map[string]int
}

// PerPersonKind is a kind whose per-person value the Hub computes rather
// than resolves (project 3).
type PerPersonKind interface {
	PersonValues(ctx context.Context, instance string, o *templates.Option, people []Person) (map[string]Value, error)
}

// ErrNotImplemented is a reserved type this Hub doesn't implement.
type ErrNotImplemented struct{ Type, Feature string }

func (e *ErrNotImplemented) Error() string {
	return fmt.Sprintf("type %s needs %s, which this Hub doesn't implement", e.Type, e.Feature)
}

// Registry is the Hub's set of kinds by type name. It implements
// templates.Kinds.
type Registry struct{ kinds map[string]Kind }

// NewRegistry returns a registry with every built-in kind
// (templates.BuiltinTypes).
func NewRegistry() *Registry {
	r := &Registry{kinds: map[string]Kind{}}
	for _, k := range []Kind{
		stringKind{}, intKind{}, sizeKind{}, durationKind{}, boolKind{}, enumKind{},
		multiEnumKind{}, listKind{}, tableKind{},
		nameKind{name: templates.TypeGroup}, nameKind{name: templates.TypeGroups, set: true},
		nameKind{name: templates.TypeUser, user: true}, nameKind{name: templates.TypeUsers, user: true, set: true},
		pathKind{}, secretKind{},
	} {
		r.Register(k)
	}
	return r
}

// Register adds k, replacing a kind of the same name.
func (r *Registry) Register(k Kind) { r.kinds[k.Name()] = k }

// Names are the registered type names, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.kinds))
	for n := range r.kinds {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Kind returns typ's kind. A reserved type that isn't registered is an
// *ErrNotImplemented naming its feature (templates.ReservedFeature).
func (r *Registry) Kind(typ string) (Kind, error) {
	if k, ok := r.kinds[typ]; ok {
		return k, nil
	}
	if f := templates.ReservedFeature(&templates.Option{Type: typ}); f != "" {
		return nil, &ErrNotImplemented{Type: typ, Feature: f}
	}
	return nil, fmt.Errorf("unknown type %q", typ)
}

// Known reports whether typ has a registered kind.
func (r *Registry) Known(typ string) bool {
	_, ok := r.kinds[typ]
	return ok
}

// Parse parses raw as a value of o.
func (r *Registry) Parse(o *templates.Option, raw any) (Value, error) {
	k, err := r.Kind(o.Type)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("no value")
	}
	return k.Parse(o, raw)
}

// Display shows v as the panel does ("" for a type without a kind).
func (r *Registry) Display(o *templates.Option, v Value) string {
	k, err := r.Kind(o.Type)
	if err != nil {
		return ""
	}
	return k.Display(o, v)
}

// CheckOption is every type-specific manifest check of o: the kind's own
// constraints, each delivery's render, the default and the group_values
// (both must parse as values of o).
func (r *Registry) CheckOption(o *templates.Option) error {
	k, err := r.Kind(o.Type)
	if err != nil {
		return err
	}
	if err := k.CheckOption(o); err != nil {
		return err
	}
	if err := checkRenders(o); err != nil {
		return err
	}
	// The default and each group_values value parse, and render through
	// every delivery (the implicit env included, with the env quote rule).
	if o.Default != nil {
		v, err := r.Parse(o, o.Default)
		if err == nil {
			err = checkValueDeliveries(o, v)
		}
		if err != nil {
			return fmt.Errorf("default %v: %w", o.Default, err)
		}
	}
	for _, g := range sortedKeys(o.GroupValues) {
		v, err := r.Parse(o, o.GroupValues[g])
		if err == nil {
			err = checkValueDeliveries(o, v)
		}
		if err != nil {
			return fmt.Errorf("group_values[%s] %v: %w", g, o.GroupValues[g], err)
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// onlyFields refuses o's type-specific fields that type doesn't take
// (a misplaced constraint must not pass silently).
func onlyFields(o *templates.Option, allowed ...string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	set := []struct {
		name string
		on   bool
	}{
		{"pattern", o.Pattern != ""},
		{"format", o.Format != ""},
		{"min_len", o.MinLen != nil},
		{"max_len", o.MaxLen != nil},
		{"min_items", o.MinItems != nil},
		{"max_items", o.MaxItems != nil},
		{"min", o.Min != nil},
		{"max", o.Max != nil},
		{"step", o.Step != nil},
		{"unit", o.Unit != ""},
		{"allow_unlimited", o.AllowUnlimited},
		{"options", o.Choices != nil},
		{"items", o.Items != nil},
		{"columns", o.Columns != nil},
		{"key_column", o.KeyColumn != ""},
		{"target", o.Target != nil},
		{"mode", o.Mode != ""},
		{"needs", o.Needs != ""},
	}
	for _, f := range set {
		if f.on && !ok[f.name] {
			return fmt.Errorf("%s is not a constraint of type %s", f.name, o.Type)
		}
	}
	return nil
}

// maxID bounds a writes_as uid / gid.
const maxID = 1<<31 - 1

// ResolveOwner resolves a path option's writes_as against the instance's
// values: numbers as written, option references through their value (an
// int, or a string holding a decimal number).
func ResolveOwner(o *templates.Option, instance map[string]Value) (uid, gid int, err error) {
	if o.WritesAs == nil {
		return 0, 0, fmt.Errorf("setting %s has no writes_as", o.Key)
	}
	one := func(what string, ref templates.OwnerRef) (int, error) {
		if ref.Num != nil {
			if *ref.Num < 0 || *ref.Num > maxID {
				return 0, fmt.Errorf("writes_as.%s = %d is not a valid id (0-%d)", what, *ref.Num, maxID)
			}
			return *ref.Num, nil
		}
		v, ok := instance[ref.Key]
		if !ok || v == nil {
			return 0, fmt.Errorf("writes_as.%s: %s has no value", what, ref.Key)
		}
		var n int64
		switch x := v.(type) {
		case string:
			if n, err = parseDecimal(x); err != nil {
				return 0, fmt.Errorf("writes_as.%s: %s = %q is not a number", what, ref.Key, x)
			}
		default:
			if n, err = toInt(v); err != nil {
				return 0, fmt.Errorf("writes_as.%s: %s is not a number", what, ref.Key)
			}
		}
		if n < 0 || n > maxID {
			return 0, fmt.Errorf("writes_as.%s: %s = %d is not a valid id", what, ref.Key, n)
		}
		return int(n), nil
	}
	if uid, err = one("uid", o.WritesAs.UID); err != nil {
		return 0, 0, err
	}
	if gid, err = one("gid", o.WritesAs.GID); err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}
