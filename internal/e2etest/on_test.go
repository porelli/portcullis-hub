//go:build e2etest

package e2etest

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestE2ETestBuildHooks: the offset file is read (cached a second:
// a change shows after it), missing / empty / unparsable = 0.
func TestE2ETestBuildHooks(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if !Enabled || Marker() == "" {
		t.Fatal("not an e2etest build")
	}
	p := filepath.Join(t.TempDir(), "offset")
	clock := time.Now()
	now := func() time.Time { return clock }
	r := OffsetReader(p, now)
	if r() != 0 {
		t.Error("missing file")
	}
	os.WriteFile(p, []byte("16m\n"), 0o600)
	if r() != 0 {
		t.Error("re-read within the second")
	}
	clock = clock.Add(1100 * time.Millisecond)
	if r() != 16*time.Minute {
		t.Errorf("after a second: %v", r())
	}
	os.WriteFile(p, []byte("soon"), 0o600)
	clock = clock.Add(2 * time.Second)
	if r() != 0 {
		t.Error("unparsable")
	}
	os.WriteFile(p, nil, 0o600)
	clock = clock.Add(2 * time.Second)
	if r() != 0 {
		t.Error("empty")
	}
	if f, err := ClockOffset(env(map[string]string{EnvClockOffset: p})); err != nil || f == nil {
		t.Errorf("%v", err)
	}
	if on, err := OversizeInfo(env(map[string]string{EnvOversizeInfo: "1"})); err != nil || !on {
		t.Errorf("%v %v", on, err)
	}
}
