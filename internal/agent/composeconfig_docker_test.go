//go:build docker

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/compose"
)

// TestComposeConfigRealCLI: the real `docker compose config --format
// json` output loads with the agent's loader and holds what compose will
// run: the env file interpolated (privileged from ${P}), relative binds
// absolute under the project directory, $$ kept literal.
func TestComposeConfigRealCLI(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker CLI")
	}
	dir := t.TempDir()
	files := filepath.Join(dir, "files")
	os.MkdirAll(files, 0o755)
	c := filepath.Join(dir, "compose.yml")
	os.WriteFile(c, []byte("services:\n  web:\n    image: x\n    privileged: ${P:-false}\n    volumes: [\"./templates/a:/a:ro\"]\n    environment: {H: \"$$HOME\"}\n    profiles: [extra]\n"), 0o644)
	env := filepath.Join(dir, "env")
	os.WriteFile(env, []byte("P=true\n"), 0o600)
	args := compose.Args(compose.Project{Name: "portcullis-app", Files: []string{c}, ProjectDir: files, EnvFile: env}, "--profile", "*", "config", "--format", "json")
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		t.Fatalf("compose config: %v", err)
	}
	f := filepath.Join(dir, "resolved.json")
	os.WriteFile(f, out, 0o600)
	m, err := loadResolved("app", f, files)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := m.Services["web"]
	if !ok {
		s, ok = m.DisabledServices["web"]
	}
	if !ok || !s.Privileged {
		t.Errorf("privileged not interpolated from the env file: %+v", s)
	}
	if len(s.Volumes) != 1 || s.Volumes[0].Source != filepath.Join(files, "templates/a") {
		t.Errorf("bind %+v", s.Volumes)
	}
	if h := s.Environment["H"]; h == nil || !strings.Contains(*h, "HOME") {
		t.Errorf("$$ escape: %v", s.Environment["H"])
	}
}
