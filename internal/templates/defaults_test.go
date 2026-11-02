package templates_test

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// Every internal test fixture also runs through the real settings
// registry: a nil Kinds means settings.NewRegistry() in this binary.
func init() { templates.SetNilKinds(settings.NewRegistry()) }

func manifestWith(option string) []byte {
	return []byte(templates.HdrHead + "settings:\n  options:\n    - " + option + "\n")
}

// TestDefaultsCanonical: a template's defaults must be canonical values of
// their type (wired through Kinds.CheckOption into ValidateSettingsSpec).
func TestDefaultsCanonical(t *testing.T) {
	reg := settings.NewRegistry()
	build := func(option string) error {
		_, err := templates.BuildForTest("app", "src", "", manifestWith(option), []byte(templates.HdrCompose), "example.org", reg)
		return err
	}
	if err := build("{key: quota, label: Q, type: size, default: 500GiB, delivery: [{env: THEME}]}"); err != nil {
		t.Errorf("500GiB refused: %v", err)
	}
	cases := map[string]string{
		"{key: quota, label: Q, type: size, default: 500 gigs, delivery: [{env: THEME}]}":                        "default",
		"{key: quota, label: Q, type: size, step: 1GiB, default: 1.5GiB, delivery: [{env: THEME}]}":              "multiple of 1 GiB",
		"{key: quota, label: Q, type: size, allow_unlimited: true, delivery: [{env: THEME}]}":                    "render.unlimited",
		"{key: days, label: D, type: int, min: 0, max: 10, default: 11, delivery: [{env: TRASH_DAYS}]}":          "at most 10",
		"{key: days, label: D, type: int, step: 0, delivery: [{env: TRASH_DAYS}]}":                               "step",
		"{key: tz, label: T, type: string, format: iana_tz, default: Mars/Base, delivery: [{env: THEME}]}":       "iana_tz",
		"{key: th, label: T, type: string, pattern: '[a-z]+', delivery: [{env: THEME}]}":                         "anchored",
		"{key: th, label: T, type: enum, options: [{value: a, label: A}], default: b, delivery: [{env: THEME}]}": "default",
		"{key: th, label: T, type: string, min: 1, delivery: [{env: THEME}]}":                                    "min",
		"{key: th, label: T, type: bool, delivery: [{env: THEME, render: {join: '+'}}]}":                         "join",
	}
	for option, want := range cases {
		err := build(option)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "setting ") {
			t.Errorf("%s: %v, want a setting error naming %q", option, err, want)
		}
	}
	// A type the registry reserves is refused through Discover's path too.
	if err := build("{key: f, label: F, type: folder}"); err == nil || !strings.Contains(err.Error(), "shared folders (project 2)") {
		t.Errorf("folder: %v", err)
	}
}
