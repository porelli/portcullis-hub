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
	for _, o := range spec.Options {
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
		if len(o.RequiresAny) > 0 {
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
