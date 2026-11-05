package settings

import (
	"fmt"
	"strings"

	"github.com/portcullis/hub/internal/templates"
)

// CheckRequires checks that every instance option's requires and
// requires_any are satisfied:
// when an option has a non-empty value, every option it requires must also
// have a non-empty value. Returns an error naming both options.
func CheckRequires(spec *templates.SettingsSpec, values map[string]Value) error {
	return CheckRequiresTouched(spec, values, nil)
}

// CheckRequiresTouched is CheckRequires for a save of the touched keys
// (nil: every key): requires_any is judged only for an option the save
// touches or one whose requires_any names a touched key (B-M1: a slot a
// group purge left without readers or writers doesn't block an
// unrelated save; the doctor's served_to_nobody reports it). requires
// is judged for every option, as before.
func CheckRequiresTouched(spec *templates.SettingsSpec, values map[string]Value, touched map[string]bool) error {
	judged := func(o *templates.Option) bool {
		if touched == nil || touched[o.Key] {
			return true
		}
		for _, k := range o.RequiresAny {
			if touched[k] {
				return true
			}
		}
		return false
	}
	for i := range spec.Options {
		o := &spec.Options[i]
		if o.EffectiveScope() != templates.ScopeInstance {
			continue
		}
		if len(o.Requires) == 0 && len(o.RequiresAny) == 0 {
			continue
		}

		v, ok := values[o.Key]
		if !ok || isEmpty(v) {
			continue
		}

		// requires_any (§13.9): at least one of the listed options set.
		if len(o.RequiresAny) > 0 && judged(o) {
			found := false
			for _, req := range o.RequiresAny {
				if rv, ok := values[req]; ok && !isEmpty(rv) {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("setting %s needs at least one of %s to be set", o.Key, strings.Join(o.RequiresAny, ", "))
			}
		}

		// o has a value: check its requirements
		for _, req := range o.Requires {
			rv, ok := values[req]
			if !ok || isEmpty(rv) {
				return fmt.Errorf("option %s requires %s to be set", o.Key, req)
			}
		}
	}
	return nil
}

// isEmpty reports whether v is an empty value (nil, empty string, false,
// empty list, empty table).
func isEmpty(v Value) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case bool:
		return !x
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case []map[string]any:
		return len(x) == 0
	default:
		return false
	}
}

// UnmetRequiresAny lists, in option order, the instance options of spec
// that have a value while none of their requires_any options is set —
// what a save refuses, judged on stored values (the doctor's
// served_to_nobody, plan 3 Task 11: a share slot whose folder is set but
// has neither readers nor writers).
func UnmetRequiresAny(spec *templates.SettingsSpec, values map[string]Value) []string {
	if spec == nil {
		return nil
	}
	var out []string
	for _, o := range spec.Options {
		if o.EffectiveScope() != templates.ScopeInstance || len(o.RequiresAny) == 0 {
			continue
		}
		if v, ok := values[o.Key]; !ok || isEmpty(v) {
			continue
		}
		set := false
		for _, req := range o.RequiresAny {
			if rv, ok := values[req]; ok && !isEmpty(rv) {
				set = true
			}
		}
		if !set {
			out = append(out, o.Key)
		}
	}
	return out
}
