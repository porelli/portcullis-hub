package settings

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/templates"
)

// TestCheckRequiresAny (contract §13.9, F2): a non-empty option with
// requires_any needs one of the listed options non-empty (else an error
// naming it); an empty one needs nothing.
func TestCheckRequiresAny(t *testing.T) {
	spec := &templates.SettingsSpec{Options: []templates.Option{
		{Key: "share1_folder", Type: templates.TypePath, RequiresAny: []string{"share1_readers", "share1_writers"}},
		{Key: "share1_readers", Type: templates.TypeGroups},
		{Key: "share1_writers", Type: templates.TypeGroups},
	}}
	for _, c := range []struct {
		name   string
		values map[string]Value
		ok     bool
	}{
		{"empty folder", map[string]Value{}, true},
		{"folder alone", map[string]Value{"share1_folder": "/srv/x"}, false},
		{"empty lists", map[string]Value{"share1_folder": "/srv/x", "share1_readers": []Value{}, "share1_writers": []Value{}}, false},
		{"readers", map[string]Value{"share1_folder": "/srv/x", "share1_readers": []Value{"office"}}, true},
		{"writers", map[string]Value{"share1_folder": "/srv/x", "share1_writers": []Value{"office"}}, true},
	} {
		err := CheckRequires(spec, c.values)
		if c.ok != (err == nil) {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "share1_folder") {
			t.Errorf("%s: %v doesn't name the option", c.name, err)
		}
	}
}
