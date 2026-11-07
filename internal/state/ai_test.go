package state

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestAISettingsLoad: a state file without ai (or with part of it) keeps
// a new install's values for what it lacks; values outside the bounds
// refuse to start.
func TestAISettingsLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.yaml")
	os.WriteFile(p, []byte("enabled: []\n"), 0600)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.AI, DefaultAISettings()) {
		t.Errorf("no ai = %+v, want the defaults", s.AI)
	}
	if !reflect.DeepEqual(New().AI, DefaultAISettings()) {
		t.Error("New lacks the AI defaults")
	}
	os.WriteFile(p, []byte("ai:\n  enabled: true\n  clients:\n    claude: {offered: false}\n"), 0600)
	if s, err = Load(p); err != nil {
		t.Fatal(err)
	}
	if !s.AI.Enabled || s.AI.Clients.Claude.Offered || !s.AI.Clients.Generic.Offered || s.AI.OfflineMaxDays != 30 || s.AI.Limits.Fanout != 4 {
		t.Errorf("partial ai = %+v", s.AI)
	}
	for _, bad := range []string{"ai: {offline_idle_days: 0}\n", "ai: {offline_max_days: 91}\n", "ai: {limits: {fanout: 9}}\n"} {
		os.WriteFile(p, []byte(bad), 0600)
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "ai:") {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}
