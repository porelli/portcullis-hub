//go:build !e2etest

package e2etest

import (
	"strings"
	"testing"
)

// TestDefaultBuildHasNoHooks: a default build is not an e2etest build,
// carries no marker, and refuses either hook's variable.
func TestDefaultBuildHasNoHooks(t *testing.T) {
	if Enabled || Marker() != "" {
		t.Fatal("a default build has the e2etest hooks")
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := ClockOffset(env(map[string]string{EnvClockOffset: "/tmp/offset"})); err == nil || !strings.Contains(err.Error(), "needs an e2etest build") {
		t.Errorf("clock: %v", err)
	}
	if _, err := OversizeInfo(env(map[string]string{EnvOversizeInfo: "1"})); err == nil || !strings.Contains(err.Error(), "needs an e2etest build") {
		t.Errorf("info: %v", err)
	}
	if f, err := ClockOffset(env(nil)); err != nil || f != nil {
		t.Errorf("unset: %v", err)
	}
}
