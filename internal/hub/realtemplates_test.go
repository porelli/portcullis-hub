package hub

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// TestRealTemplatesInstances renders the default instance and a second
// instance of every template in the sibling templates checkout (contract
// v2), and — when the docker compose CLI is available — has compose merge
// them (`config`, no daemon needed): the second instance keeps none of the
// template's Traefik names (labels: !override), routes its own hostnames
// and gets its own volume names; the default instance keeps today's.
func TestRealTemplatesInstances(t *testing.T) {
	dir := os.Getenv("PORTCULLIS_TEMPLATES_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "portcullis-templates")
	}
	dir, _ = filepath.Abs(dir)
	if _, err := os.Stat(filepath.Join(dir, "grafana", "manifest.yaml")); err != nil {
		t.Skipf("no templates checkout at %s", dir)
	}
	dir = aiPendingTemplatesDir(t, dir)
	root := t.TempDir()
	project, data := filepath.Join(root, "project"), filepath.Join(root, "data")
	// Every variable a template reads from the core env, with a value.
	refs := map[string]bool{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "compose.yml"))
		if err == nil {
			for r := range templates.EnvRefs(string(b)) {
				refs[r] = true
			}
		}
	}
	var core []string
	for r := range refs {
		if !strings.HasPrefix(r, "PORTCULLIS_") && templates.EnvKeyRe.MatchString(r) {
			core = append(core, r+"=x")
		}
	}
	sort.Strings(core)
	writeFile(t, filepath.Join(project, ".env"), strings.Join(core, "\n")+"\n")
	st := state.New()
	st.Sources = []state.Source{{Name: "portcullis", Path: dir}}
	os.MkdirAll(data, 0755)
	if err := st.Save(filepath.Join(data, "state.yaml")); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{ProjectDir: project, ProjectHostDir: project, DataDir: data, Domain: "example.org"}, newFakeRunner(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Discover()
	// Every template must load: say why one doesn't (until the templates
	// are converted to contract v3 settings, the v2 ones are refused).
	loaded := map[string]bool{}
	for _, c := range h.Templates() {
		loaded[c.ID] = true
	}
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "manifest.yaml")); err != nil || loaded[e.Name()] {
			continue
		}
		_, err := templates.Load(dir, e.Name(), "portcullis", "example.org", settings.NewRegistry())
		t.Errorf("%s: not in the catalog: %v", e.Name(), err)
	}
	_, lookErr := exec.LookPath("docker")
	haveCompose := lookErr == nil && exec.Command("docker", "compose", "version").Run() == nil
	if !haveCompose {
		t.Log("docker compose not available: rendering only")
	}
	n := 0
	for _, cat := range h.Templates() {
		ids := []string{cat.ID}
		if cat.Manifest.Multi() {
			id := cat.ID + "-t"
			if len(id) > 31 {
				id = id[:31]
			}
			if err := h.CreateInstance(cat.ID, id, nil); err != nil {
				t.Errorf("%s: create: %v", cat.ID, err)
				continue
			}
			ids = append(ids, id)
		}
		for _, id := range ids {
			h.mu.Lock()
			v := h.findLocked(id)
			err := h.generateAppEnvLocked(v, nil)
			if err == nil {
				err = h.generateOverrideLocked(v, state.InstanceSettings{})
			}
			c := *v
			h.mu.Unlock()
			if err != nil {
				t.Errorf("%s: %v", id, err)
				continue
			}
			n++
			// The pre-up check's loader (compose-go, F15) must read every
			// real template with its Hub override as compose does.
			if _, err := loadRendered(t.Context(), h.project(&c), h.cfg.ProjectDir); err != nil {
				t.Errorf("%s: compose-go loader: %v", id, err)
			}
			if haveCompose {
				checkComposeConfig(t, h, &c)
			}
		}
	}
	t.Logf("%d instances rendered", n)
}

func checkComposeConfig(t *testing.T, h *Hub, v *templates.Template) {
	t.Helper()
	p := h.project(v)
	args := []string{"compose", "-p", p.Name}
	for _, f := range p.Files {
		args = append(args, "-f", f)
	}
	args = append(args, "--project-directory", p.ProjectDir, "--env-file", p.EnvFile, "config", "--format", "json")
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Errorf("%s: compose config: %v\n%s", v.ID, err, out)
		return
	}
	var doc struct {
		Services map[string]struct {
			Labels map[string]string `json:"labels"`
		} `json:"services"`
		Volumes map[string]struct {
			Name string `json:"name"`
		} `json:"volumes"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("%s: %v", v.ID, err)
	}
	names := v.NamesFor(v.ID)
	for k, vol := range doc.Volumes {
		if want, ok := names.Volumes[k]; ok && vol.Name != want {
			t.Errorf("%s: volume %s named %s, want %s", v.ID, k, vol.Name, want)
		}
	}
	hosts := map[string]bool{}
	for _, host := range v.Hosts {
		hosts[host] = true
	}
	for svc, s := range doc.Services {
		for k, val := range s.Labels {
			if !strings.HasPrefix(k, "traefik.") {
				continue
			}
			parts := strings.SplitN(k, ".", 5)
			if len(parts) < 5 || (parts[2] != "routers" && parts[2] != "services" && parts[2] != "middlewares") {
				continue
			}
			name := parts[3]
			if !v.IsDefault() && !strings.HasPrefix(name, v.ID+"_") && !strings.HasPrefix(name, "portcullis-") {
				t.Errorf("%s: service %s keeps the template's Traefik name in %s", v.ID, svc, k)
			}
			if strings.HasSuffix(k, ".rule") && parts[1] == "http" {
				rh, _ := templates.RuntimeHosts(val)
				for _, host := range rh {
					if !hosts[host] {
						t.Errorf("%s: %s routes %s, not one of %v", v.ID, k, host, v.Hosts)
					}
				}
			}
		}
	}
}
