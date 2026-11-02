package hub

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/state"
)

// The golden fixture: grafana and disks exactly as the base commit
// 10c7211 (before instances) knew them. testdata/golden/ holds what that
// commit generated for them (env secrets masked), produced by running this
// fixture there in a temporary worktree.
const goldenGrafanaManifest = "name: Grafana\ncategory: monitoring\nauth:\n  method: header-auth\n  group_access: true\n  access_group: users_grafana\n  admin_group: admin_grafana\n  admin_paths: [/admin/]\nenv:\n  - key: GF_SECRET\n    generate: random\nsettings:\n  - key: GF_THEME\n    type: select\n    options: [dark, light]\nports:\n  - key: GRAFANA_PORT\n    container: 3000\n    default: 3300\n    service: grafana\n"

const goldenGrafanaCompose = "services:\n  grafana:\n    image: grafana\n    environment:\n      GF_SERVER_ROOT_URL: https://grafana.${PORTCULLIS_DOMAIN:-portcullis.local}\n      CORE: ${CORE_VAR}\n    volumes:\n      - grafana-data:/var/lib/grafana\n    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers.grafana.rule: Host(`grafana.${PORTCULLIS_DOMAIN:-portcullis.local}`)\n      traefik.http.routers.grafana.middlewares: portcullis-auth@docker,portcullis-groups@docker,security-headers@file\n      traefik.http.routers.grafana-api.rule: Host(`grafana.${PORTCULLIS_DOMAIN:-portcullis.local}`) && PathPrefix(`/api`)\n      traefik.http.services.grafana.loadbalancer.server.port: \"3000\"\nvolumes:\n  grafana-data:\n    name: portcullis_grafana-data\n"

const goldenDisksManifest = "name: Disks\ncategory: monitoring\nauth:\n  method: forward-auth\nports:\n  - key: DISKS_PORT\n    container: 8080\n    default: 8090\n    service: disks\n"

const goldenDisksCompose = "services:\n  disks:\n    image: x\n    volumes:\n      - data:/data\n    labels:\n      traefik.http.routers.disks.rule: Host(`disks.${PORTCULLIS_DOMAIN:-portcullis.local}`)\n      traefik.http.routers.disks.middlewares: portcullis-auth@docker,portcullis-groups@docker\nvolumes:\n  data: {}\n"

// goldenGrafanaV2 is the same grafana converted to contract v2 (multi,
// hostname variable, no volume name), as the real template is.
var (
	goldenGrafanaV2Manifest = "instances: multi\n" + goldenGrafanaManifest
	goldenGrafanaV2Compose  = strings.NewReplacer(
		"grafana.${PORTCULLIS_DOMAIN:-portcullis.local}", "${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}",
		"  grafana-data:\n    name: portcullis_grafana-data\n", "  grafana-data: {}\n",
	).Replace(goldenGrafanaCompose)
)

// goldenRun enables grafana (legacy or v2) and disks from an existing
// state.yaml and returns each one's override and env (secrets masked)
// and the policy file.
func goldenRun(t *testing.T, v2 bool) (*fixture, map[string]string) {
	t.Helper()
	root := t.TempDir()
	f := &fixture{runner: newFakeRunner(), engine: &fakeEngine{logs: map[string]string{}}, idp: &fakeIdP{},
		project: filepath.Join(root, "project"), data: filepath.Join(root, "data"), src: filepath.Join(root, "src")}
	writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\n")
	gm, gc := goldenGrafanaManifest, goldenGrafanaCompose
	if v2 {
		gm, gc = goldenGrafanaV2Manifest, goldenGrafanaV2Compose
	}
	writeFile(t, filepath.Join(f.src, "grafana", "manifest.yaml"), gm)
	writeFile(t, filepath.Join(f.src, "grafana", "compose.yml"), gc)
	writeFile(t, filepath.Join(f.src, "disks", "manifest.yaml"), goldenDisksManifest)
	writeFile(t, filepath.Join(f.src, "disks", "compose.yml"), goldenDisksCompose)
	st := state.New()
	st.Sources = []state.Source{{Name: "local", Path: f.src}}
	st.Enabled = []string{"grafana", "disks"}
	st.Settings["grafana"] = map[string]string{"GRAFANA_PORT": "3301", "GF_THEME": "dark"}
	os.MkdirAll(f.data, 0755)
	if err := st.Save(filepath.Join(f.data, "state.yaml")); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{ProjectDir: f.project, ProjectHostDir: "/host/project", DataDir: f.data, Domain: "example.org"}, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	h.lockPoll = 5 * time.Millisecond
	h.Init()
	t.Cleanup(h.Wait)
	f.h = h
	out := map[string]string{}
	for _, id := range []string{"grafana", "disks"} {
		if err := h.Disable(id); err != nil {
			t.Fatal(err)
		}
		if err := h.Enable(id); err != nil {
			t.Fatal(err)
		}
		ov, _ := os.ReadFile(filepath.Join(f.data, "overrides", id+".override.yml"))
		env, _ := os.ReadFile(filepath.Join(f.data, "env", id+".env"))
		env = regexp.MustCompile(`=[0-9a-f]{32}\n`).ReplaceAll(env, []byte("=<random>\n"))
		out[id+".override.yml"], out[id+".env"] = string(ov), string(env)
	}
	pol, _ := os.ReadFile(filepath.Join(f.data, "group-gate-policy.json"))
	out["policy.json"] = string(pol)
	return f, out
}

func golden(t *testing.T, name string) string {
	t.Helper()
	return readFile(t, filepath.Join("testdata", "golden", name))
}

// instanceVarLineRe matches the instance variables (contract §2/§3.1) the
// Hub now adds to every env, the default instance's included.
var instanceVarLineRe = regexp.MustCompile(`(?m)^PORTCULLIS_(INSTANCE|HOST_[A-Z0-9_]+|OIDC_CLIENT_ID(_[A-Z0-9_]+)?|ACCESS_GROUP|ADMIN_GROUP)=.*\n`)
