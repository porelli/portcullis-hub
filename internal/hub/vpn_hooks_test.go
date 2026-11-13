package hub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// vpn hooks (when: [vpn], contract §3.3) are never the settings engine's:
// sortedHooks drops them as it drops ai hooks.
func TestVPNHooksNeverDelivered(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "templates", "testdata", "vpn_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct{ Name, Manifest, Compose string }
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	var m, c string
	for _, v := range vs {
		if v.Name == "headscale-shaped ok" {
			m, c = v.Manifest, v.Compose
		}
	}
	m = strings.Replace(m, "hooks:\n", "hooks:\n  - {name: apply, service: glue, command: [/apply], when: [start]}\n", 1)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "mesh", "manifest.yaml"), m)
	writeFile(t, filepath.Join(dir, "mesh", "compose.yml"), c)
	tp, err := templates.Load(dir, "mesh", "src", "example.org", settings.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if len(tp.Manifest.Hooks) != 3 {
		t.Fatalf("hooks %v", tp.Manifest.Hooks)
	}
	var names []string
	for _, hk := range sortedHooks(&tp) {
		names = append(names, hk.Name)
	}
	if strings.Join(names, ",") != "apply" {
		t.Fatalf("settings-engine hooks %v, want [apply]", names)
	}
}
