package agentapi

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"

	"github.com/portcullis/hub/internal/templates"
)

// loadBundleModel loads compose as the agent loads a bundle: project
// portcullis-<instance>, working directory dir, every profile, paths
// unresolved (the Hub's loadRendered options).
func loadBundleModel(t *testing.T, dir, instance, compose string, env []string) (*types.Project, error) {
	t.Helper()
	f := filepath.Join(dir, "compose.yml")
	if err := os.WriteFile(f, []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	po, err := cli.NewProjectOptions([]string{f}, cli.WithName("portcullis-"+instance), cli.WithWorkingDirectory(dir),
		cli.WithEnv(env), cli.WithProfiles([]string{"*"}), cli.WithConsistency(false), cli.WithResolvedPaths(false), cli.WithoutEnvironmentResolution)
	if err != nil {
		return nil, err
	}
	return po.LoadProject(context.Background())
}

const cleanBundle = `services:
  web:
    image: ghcr.io/example/app:1
    cap_add: [CHOWN, SETUID, SETGID]
    security_opt: [no-new-privileges:true]
    devices: ["/dev/null:/dev/portcullis-unused-1"]
    networks: [portcullis-proxy, default]
    volumes:
      - data:/data
      - ./templates/app/app.conf:/etc/app.conf:ro
      - ./certs/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro
      - /srv/photos:/photos
      - type: tmpfs
        target: /tmp
    extra_hosts: ["db.internal:192.0.2.10"]
    ports: ["8080:80"]
    labels:
      traefik.http.routers.app.rule: Host(` + "`app.example.org`" + `)
  init:
    image: busybox
    network_mode: none
    volumes_from: [web]
  sidecar:
    image: busybox
    network_mode: service:web
    ipc: service:web
    profiles: [extra]
networks:
  portcullis-proxy:
    external: true
volumes:
  data: {}
`

func TestValidateBundleRefusesEscapes(t *testing.T) {
	roots := []string{"/srv", "/mnt", "/media"}
	dir := t.TempDir()
	m, err := loadBundleModel(t, dir, "app", cleanBundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundle(m, "app", roots, dir); err != nil {
		t.Fatalf("clean bundle: %v", err)
	}
	svc := func(extra string) string {
		return "services:\n  web:\n    image: x\n" + extra
	}
	cases := map[string]struct{ compose, want string }{
		"privileged":             {svc("    privileged: true\n"), "privileged"},
		"device":                 {svc("    devices: [\"/dev/sda:/dev/sda\"]\n"), "host device /dev/sda"},
		"etc bind":               {svc("    volumes: [\"/etc:/host-etc:ro\"]\n"), "bind /etc is outside"},
		"dot-dot bind":           {svc("    volumes: [\"../outside:/x\"]\n"), `".." segments`},
		"root dot-dot bind":      {svc("    volumes: [\"/srv/../etc:/x\"]\n"), `".." segments`},
		"relative escape":        {svc("    volumes: [\"./templates/../../x:/x\"]\n"), `".." segments`},
		"home bind":              {svc("    volumes: [\"~/x:/x\"]\n"), "~"},
		"host root bind":         {svc("    volumes: [\"/:/host\"]\n"), "root directory"},
		"socket under a root":    {svc("    volumes: [\"/srv/docker.sock:/var/run/docker.sock\"]\n"), "sockets"},
		"engine socket":          {svc("    volumes: [\"/var/run/docker.sock:/s\"]\n"), "sockets"},
		"root sibling":           {svc("    volumes: [\"/srvx:/x\"]\n"), "outside"},
		"shared propagation":     {svc("    volumes:\n      - type: bind\n        source: /srv/x\n        target: /x\n        bind: {propagation: rshared}\n"), "propagation"},
		"network_mode host":      {svc("    network_mode: host\n"), "network_mode \"host\""},
		"network_mode bridge":    {svc("    network_mode: bridge\n"), "network_mode"},
		"network_mode other":     {svc("    network_mode: container:abc\n"), "network_mode"},
		"pid host":               {svc("    pid: host\n"), "pid \"host\""},
		"ipc host":               {svc("    ipc: host\n"), "ipc \"host\""},
		"userns host":            {svc("    userns_mode: host\n"), "userns_mode"},
		"uts host":               {svc("    uts: host\n"), "uts"},
		"cgroup host":            {svc("    cgroup: host\n"), "cgroup"},
		"cap SYS_ADMIN":          {svc("    cap_add: [SYS_ADMIN]\n"), "cap_add SYS_ADMIN"},
		"cap NET_ADMIN":          {svc("    cap_add: [CAP_NET_ADMIN]\n"), "cap_add NET_ADMIN"},
		"cap ALL":                {svc("    cap_add: [ALL]\n"), "cap_add ALL"},
		"seccomp unconfined":     {svc("    security_opt: [seccomp:unconfined]\n"), "security_opt"},
		"label disable":          {svc("    security_opt: [\"label=disable\"]\n"), "security_opt"},
		"sysctls":                {svc("    sysctls: {net.core.somaxconn: 1024}\n"), "sysctls"},
		"host-gateway":           {svc("    extra_hosts: [\"auth.example.org:host-gateway\"]\n"), "host-gateway"},
		"build":                  {"services:\n  web:\n    build: .\n", "build"},
		"device cgroup rules":    {svc("    device_cgroup_rules: [\"c 1:3 mr\"]\n"), "device_cgroup_rules"},
		"cgroup parent":          {svc("    cgroup_parent: /x\n"), "cgroup_parent"},
		"runtime":                {svc("    runtime: runc\n"), "runtime"},
		"volumes_from container": {svc("    volumes_from: [\"container:abc\"]\n"), "volumes_from"},
		"external links":         {svc("    external_links: [db]\n"), "external_links"},
		"compose label":          {svc("    labels: {com.docker.compose.project: portcullis-other}\n"), "compose's own"},
		"core service name":      {"services:\n  traefik:\n    image: x\n", "reserved"},
		"worker agent alias":     {svc("    networks:\n      default:\n        aliases: [agent]\n"), "reserved"},
		"container name core":    {svc("    container_name: portcullis-hub-1\n"), "reserved"},
		"external network":       {svc("    networks: [portcullis]\nnetworks:\n  portcullis:\n    external: true\n"), "only portcullis-proxy"},
		"named network":          {svc("    networks: [n]\nnetworks:\n  n:\n    name: portcullis-link\n"), "not the project's own"},
		"external volume":        {svc("    volumes: [\"v:/v\"]\nvolumes:\n  v:\n    external: true\n    name: portcullis-other_data\n"), "external volumes"},
		"other instance volume":  {svc("    volumes: [\"v:/v\"]\nvolumes:\n  v:\n    name: portcullis-other_data\n"), "outside the instance's names"},
		"core volume key":        {svc("    volumes: [\"hub_data:/v\"]\nvolumes:\n  hub_data: {}\n"), "core's"},
		"core volume name":       {svc("    volumes: [\"v:/v\"]\nvolumes:\n  v:\n    name: portcullis_vault_data\n"), "core's volume"},
		"driver_opts bind":       {svc("    volumes: [\"v:/v\"]\nvolumes:\n  v:\n    driver_opts: {type: none, o: bind, device: /etc}\n"), "driver_opts"},
		"undeclared volume":      {svc("    volumes:\n      - type: volume\n        source: ghost\n        target: /g\n"), "not declared"},
		"secrets volume":         {svc("    volumes: [\"portcullis-hub-secrets:/s\"]\nvolumes:\n  portcullis-hub-secrets: {}\n"), "core's"},
		"configs":                {svc("    configs: [c]\nconfigs:\n  c:\n    file: /etc/passwd\n"), "configs"},
		"env_file":               {svc("    env_file: [/etc/environment]\n"), "env_file"},
		"profile hides escape":   {svc("  hidden:\n    image: x\n    privileged: true\n    profiles: [never]\n"), "privileged"},
	}
	for name, c := range cases {
		m, err := loadBundleModel(t, dir, "app", c.compose, nil)
		if err != nil {
			continue // compose itself refuses it: never runs
		}
		err = ValidateBundle(m, "app", roots, dir)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	// The bundle's identity and paths.
	m, _ = loadBundleModel(t, dir, "app", cleanBundle, nil)
	if err := ValidateBundle(m, "other", roots, dir); err == nil {
		t.Error("another instance's id accepted")
	}
	for _, bad := range [][]string{{"/"}, {"srv"}, {"/srv/../etc"}} {
		if err := ValidateBundle(m, "app", bad, dir); err == nil {
			t.Errorf("roots %v accepted", bad)
		}
	}
	if err := ValidateBundle(m, "app", roots, "relative/dir"); err == nil {
		t.Error("a relative bundle dir accepted")
	}
	if err := ValidateBundle(nil, "app", roots, dir); err == nil {
		t.Error("nil model accepted")
	}
	// A bind outside the roots is refused when the roots don't cover it.
	if err := ValidateBundle(m, "app", []string{"/mnt"}, dir); err == nil || !strings.Contains(err.Error(), "/srv/photos") {
		t.Errorf("/srv bind with roots /mnt: %v", err)
	}
}

func TestProjectLabelOK(t *testing.T) {
	bundled := map[string]bool{"immich": true, "photos-2": true}
	for _, c := range []struct {
		labels map[string]string
		id     string
		ok     bool
	}{
		{map[string]string{ProjectLabel: "portcullis-immich"}, "immich", true},
		{map[string]string{ProjectLabel: "portcullis-photos-2"}, "photos-2", true},
		{map[string]string{ProjectLabel: "portcullis-paperless"}, "", false},
		{map[string]string{ProjectLabel: "portcullis"}, "", false},
		{map[string]string{ProjectLabel: "portcullis-"}, "", false},
		{map[string]string{ProjectLabel: "immich"}, "", false},
		{map[string]string{ProjectLabel: "Portcullis-immich"}, "", false},
		{map[string]string{ProjectLabel: "portcullis-immich "}, "", false},
		{map[string]string{"com.docker.compose.service": "web"}, "", false},
		{nil, "", false},
	} {
		id, ok := ProjectLabelOK(c.labels, bundled)
		if id != c.id || ok != c.ok {
			t.Errorf("%v: %q %v", c.labels, id, ok)
		}
	}
	if _, ok := ProjectLabelOK(map[string]string{ProjectLabel: "portcullis-immich"}, nil); ok {
		t.Error("nothing bundled, still in scope")
	}
}

// TestValidateBundleRealTemplates: every worker-placeable real template
// (templates.Placement) loads as a bundle that ValidateBundle accepts,
// except the ones that need host devices or capabilities beyond the
// default set, which are refused (and listed).
var requiredVarRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):?\?`)

func TestValidateBundleRealTemplates(t *testing.T) {
	dir := os.Getenv("PORTCULLIS_TEMPLATES_DIR")
	if dir == "" {
		t.Skip("PORTCULLIS_TEMPLATES_DIR not set")
	}
	roots := []string{"/srv", "/mnt", "/media"}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ok, refused []string
	for _, e := range entries {
		id := e.Name()
		tp, err := templates.Load(dir, id, "portcullis", "example.org", nil)
		if err != nil {
			continue
		}
		c := tp.ReadCompose()
		if po, _ := templates.Placement(c, tp.Manifest, nil, roots); po {
			continue
		}
		bundle := t.TempDir()
		// The Hub's .env sets every required variable: stand-ins here.
		env := []string{"PORTCULLIS_DOMAIN=example.org"}
		for _, g := range requiredVarRe.FindAllStringSubmatch(string(c), -1) {
			env = append(env, g[1]+"=x")
		}
		m, err := loadBundleModel(t, bundle, id, string(c), env)
		if err != nil {
			t.Logf("%s: compose doesn't load without its env: %v", id, err)
			continue
		}
		if err := ValidateBundle(m, id, roots, bundle); err != nil {
			refused = append(refused, id+": "+err.Error())
			continue
		}
		ok = append(ok, id)
	}
	t.Logf("bundles accepted: %s", strings.Join(ok, " "))
	for _, r := range refused {
		t.Errorf("refused: %s", r)
	}
	if len(ok) < 10 {
		t.Errorf("only %d real templates pass as bundles", len(ok))
	}
}
