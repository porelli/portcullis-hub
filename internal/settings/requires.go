package settings

import (
	"fmt"

	"github.com/portcullis/hub/internal/templates"
)

// CheckRequires checks that every instance option's requires are satisfied:
// when an option has a non-empty value, every option it requires must also
// have a non-empty value. Returns an error naming both options.
func CheckRequires(spec *templates.SettingsSpec, values map[string]Value) error {
	for _, o := range spec.Options {
		if o.EffectiveScope() != templates.ScopeInstance {
			continue
		}
		if len(o.Requires) == 0 {
			continue
		}

		v, ok := values[o.Key]
		if !ok || isEmpty(v) {
			continue
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
