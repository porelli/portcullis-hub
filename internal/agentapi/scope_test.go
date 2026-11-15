package agentapi

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
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

// manifestFor is the Hub's manifest of instance (of template) with
// its volume names.
func manifestFor(instance, template string, vols map[string]string) BundleManifest {
	return BundleManifest{Instance: instance, Template: template, Volumes: vols}
}

func validate(m *types.Project, mf BundleManifest, roots []string, dir string) error {
	return ValidateBundle(m, mf, nil, roots, dir)
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
	app := manifestFor("app", "app", map[string]string{"data": "portcullis-app_data"})
	if err := validate(m, app, roots, dir); err != nil {
		t.Fatalf("clean bundle: %v", err)
	}
	svc := func(extra string) string {
		return "services:\n  web:\n    image: x\n" + extra
	}
	cases := map[string]struct{ compose, want string }{
		"privileged":             {svc("    privileged: true\n"), "compose key privileged"},
		"post_start privileged":  {svc("    post_start:\n      - command: [sh, -c, x]\n        privileged: true\n"), "compose key post_start"},
		"pre_stop hook":          {svc("    pre_stop:\n      - command: [sh]\n"), "compose key pre_stop"},
		"use_api_socket":         {svc("    use_api_socket: true\n"), "compose key use_api_socket"},
		"provider":               {"services:\n  web:\n    provider:\n      type: model\n      options: {model: x}\n", "compose key provider"},
		"service models":         {svc("    models: [m]\nmodels:\n  m:\n    model: ai/x\n"), "models"},
		"develop":                {svc("    develop:\n      watch:\n        - path: ./src\n          action: sync\n          target: /src\n"), "compose key develop"},
		"deploy":                 {svc("    deploy:\n      resources:\n        reservations:\n          devices:\n            - capabilities: [gpu]\n"), "compose key deploy"},
		"annotations":            {svc("    annotations: {a: b}\n"), "compose key annotations"},
		"service extension":      {svc("    x-podman: {x: 1}\n"), "x-* extension"},
		"logging syslog":         {svc("    logging:\n      driver: syslog\n"), "logging driver"},
		"pull_policy build":      {svc("    pull_policy: build\n"), "pull_policy build"},
		"fixed proxy address":    {svc("    networks:\n      portcullis-proxy:\n        ipv4_address: 172.31.254.2\nnetworks:\n  portcullis-proxy:\n    external: true\n"), "fixed address"},
		"macvlan network":        {svc("    networks: [n]\nnetworks:\n  n:\n    driver: macvlan\n"), "driver \"macvlan\""},
		"network driver_opts":    {svc("    networks: [n]\nnetworks:\n  n:\n    driver_opts: {parent: eth0}\n"), "compose key driver_opts"},
		"network ipam":           {svc("    networks: [n]\nnetworks:\n  n:\n    ipam:\n      config:\n        - subnet: 192.168.1.0/24\n"), "compose key ipam"},
		"jobs":                   {"services:\n  web:\n    image: x\njobs:\n  j:\n    image: x\n", "jobs"},
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
		"build":                  {"services:\n  web:\n    build: .\n", "compose key build"},
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
		"other instance volume":  {svc("    volumes: [\"v:/v\"]\nvolumes:\n  v:\n    name: portcullis-other_data\n"), "the manifest says"},
		"key not in manifest":    {svc("    volumes: [\"extra:/v\"]\nvolumes:\n  extra: {}\n"), "not in the bundle manifest"},
		"core volume key":        {svc("    volumes: [\"hub_data:/v\"]\nvolumes:\n  hub_data: {}\n"), "core's"},
		"core volume name":       {svc("    volumes: [\"v:/v\"]\nvolumes:\n  v:\n    name: portcullis_vault_data\n"), "core's volume"},
		"driver_opts bind":       {svc("    volumes: [\"v:/v\"]\nvolumes:\n  v:\n    driver_opts: {type: none, o: bind, device: /etc}\n"), "driver_opts"},
		"undeclared volume":      {svc("    volumes:\n      - type: volume\n        source: ghost\n        target: /g\n"), "not declared"},
		"secrets volume":         {svc("    volumes: [\"portcullis-hub-secrets:/s\"]\nvolumes:\n  portcullis-hub-secrets: {}\n"), "core's"},
		"configs":                {svc("    configs: [c]\nconfigs:\n  c:\n    file: /etc/passwd\n"), "configs"},
		"env_file":               {svc("    env_file: [/etc/environment]\n"), "env_file"},
		"profile hides escape":   {svc("  hidden:\n    image: x\n    privileged: true\n    profiles: [never]\n"), "privileged"},
		"links outside":          {svc("    links: [db]\n"), "links db"},
	}
	for name, c := range cases {
		m, err := loadBundleModel(t, dir, "app", c.compose, nil)
		if err != nil {
			t.Logf("%s: compose-go refuses it itself: %v", name, err)
			continue // never runs
		}
		mf := app
		if name == "other instance volume" {
			mf = manifestFor("app", "app", map[string]string{"v": "portcullis-app_v"})
		}
		err = validate(m, mf, roots, dir)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
	// The bundle's identity and paths.
	m, _ = loadBundleModel(t, dir, "app", cleanBundle, nil)
	if err := validate(m, manifestFor("other", "app", nil), roots, dir); err == nil {
		t.Error("another instance's id accepted")
	}
	for _, bad := range [][]string{{"/"}, {"srv"}, {"/srv/../etc"}} {
		if err := validate(m, app, bad, dir); err == nil {
			t.Errorf("roots %v accepted", bad)
		}
	}
	if err := validate(m, app, roots, "relative/dir"); err == nil {
		t.Error("a relative bundle dir accepted")
	}
	if err := validate(nil, app, roots, dir); err == nil {
		t.Error("nil model accepted")
	}
	// A bind outside the roots is refused when the roots don't cover it.
	if err := validate(m, app, []string{"/mnt"}, dir); err == nil || !strings.Contains(err.Error(), "/srv/photos") {
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

// nonZero is a non-zero value of type t (for the allowlist sweep).
func nonZero(t reflect.Type) reflect.Value {
	v := reflect.New(t).Elem()
	switch t.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(t.Elem()))
		if t.Elem().Kind() != reflect.Struct {
			v.Elem().Set(nonZero(t.Elem()))
		}
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(t, 1, 1))
	case reflect.Map:
		v.Set(reflect.MakeMap(t))
		v.SetMapIndex(nonZero(t.Key()), reflect.New(t.Elem()).Elem())
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).IsExported() {
				if f := nonZero(t.Field(i).Type); f.IsValid() && !f.IsZero() {
					v.Field(i).Set(f)
					return v
				}
			}
		}
	}
	return v
}

// fieldsOf lists struct t's yaml keys (inline structs flattened) with
// their index paths.
func fieldsOf(t reflect.Type, prefix []int) map[string][]int {
	out := map[string][]int{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		idx := append(append([]int{}, prefix...), i)
		if name == "" && strings.Contains(opts, "inline") && f.Type.Kind() == reflect.Struct {
			for k, v := range fieldsOf(f.Type, idx) {
				out[k] = v
			}
			continue
		}
		if name != "-" && name != "" {
			out[name] = idx
		}
	}
	return out
}

const sweepCompose = "services:\n  web:\n    image: x\n    networks: [n]\n    volumes:\n      - type: volume\n        source: v\n        target: /v\nnetworks:\n  n: {}\nvolumes:\n  v: {}\n"

// TestBundleAllowlistRefusesUnknownKeys: every compose key of a service,
// a network, a volume, a mount and a service network that isn't
// allowlisted is refused when set, so a field compose-go adds later is
// refused by default.
func TestBundleAllowlistRefusesUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	mf := manifestFor("app", "app", map[string]string{"v": "portcullis-app_v"})
	base, err := loadBundleModel(t, dir, "app", sweepCompose, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(base, mf, nil, dir); err != nil {
		t.Fatalf("base: %v", err)
	}
	type target struct {
		what    string
		typ     reflect.Type
		allowed map[string]bool
		set     func(m *types.Project, idx []int, val reflect.Value)
	}
	targets := []target{
		{"service", reflect.TypeFor[types.ServiceConfig](), serviceKeys, func(m *types.Project, idx []int, val reflect.Value) {
			s := m.Services["web"]
			reflect.ValueOf(&s).Elem().FieldByIndex(idx).Set(val)
			m.Services["web"] = s
		}},
		{"network", reflect.TypeFor[types.NetworkConfig](), networkKeys, func(m *types.Project, idx []int, val reflect.Value) {
			n := m.Networks["n"]
			reflect.ValueOf(&n).Elem().FieldByIndex(idx).Set(val)
			m.Networks["n"] = n
		}},
		{"volume", reflect.TypeFor[types.VolumeConfig](), volumeKeys, func(m *types.Project, idx []int, val reflect.Value) {
			v := m.Volumes["v"]
			reflect.ValueOf(&v).Elem().FieldByIndex(idx).Set(val)
			m.Volumes["v"] = v
		}},
		{"mount", reflect.TypeFor[types.ServiceVolumeConfig](), mountKeys, func(m *types.Project, idx []int, val reflect.Value) {
			s := m.Services["web"]
			s.Volumes = slices.Clone(s.Volumes)
			reflect.ValueOf(&s.Volumes[0]).Elem().FieldByIndex(idx).Set(val)
			m.Services["web"] = s
		}},
		{"service network", reflect.TypeFor[types.ServiceNetworkConfig](), serviceNetworkKeys, func(m *types.Project, idx []int, val reflect.Value) {
			s := m.Services["web"]
			cfg := types.ServiceNetworkConfig{}
			reflect.ValueOf(&cfg).Elem().FieldByIndex(idx).Set(val)
			s.Networks = map[string]*types.ServiceNetworkConfig{"n": &cfg}
			m.Services["web"] = s
		}},
	}
	swept := 0
	for _, tg := range targets {
		for key, idx := range fieldsOf(tg.typ, nil) {
			if tg.allowed[key] {
				continue
			}
			m, err := loadBundleModel(t, dir, "app", sweepCompose, nil)
			if err != nil {
				t.Fatal(err)
			}
			val := nonZero(tg.typ.FieldByIndex(idx).Type)
			if val.IsZero() {
				t.Errorf("%s %s: no non-zero test value", tg.what, key)
				continue
			}
			tg.set(m, idx, val)
			err = validate(m, mf, nil, dir)
			want := "compose key " + key
			switch {
			case key == "#extensions":
				want = "x-* extension"
			case tg.what == "volume" && key == "external":
				want = "external volumes" // refused before the key check
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s key %s: err %v, want %q", tg.what, key, err, want)
			}
			swept++
		}
	}
	// Project-level jobs (compose-go's schema needs triggers; set directly).
	m, _ := loadBundleModel(t, dir, "app", sweepCompose, nil)
	m.Jobs = types.Jobs{"j": {}}
	if err := validate(m, mf, nil, dir); err == nil || !strings.Contains(err.Error(), "jobs") {
		t.Errorf("jobs: %v", err)
	}
	m.Jobs, m.DisabledJobs = nil, types.Jobs{"j": {}}
	if err := validate(m, mf, nil, dir); err == nil || !strings.Contains(err.Error(), "jobs") {
		t.Errorf("disabled jobs: %v", err)
	}
	if swept < 50 {
		t.Errorf("only %d keys swept", swept)
	}
	t.Logf("%d non-allowlisted keys refused", swept)
}

// TestBundleVolumeNamesCrossInstance: names come from the Hub's manifest
// and never reach another bundled instance's volumes.
func TestBundleVolumeNamesCrossInstance(t *testing.T) {
	dir := t.TempDir()
	var loadKey func(instance, key, name string) *types.Project
	load := func(instance, name string) *types.Project { return loadKey(instance, "data", name) }
	loadKey = func(instance, key, name string) *types.Project {
		c := "services:\n  web:\n    image: x\n    volumes: [\"" + key + ":/d\"]\nvolumes:\n  " + key + ": {}\n"
		if name != "" {
			c = "services:\n  web:\n    image: x\n    volumes: [\"" + key + ":/d\"]\nvolumes:\n  " + key + ":\n    name: " + name + "\n"
		}
		m, err := loadBundleModel(t, dir, instance, c, nil)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	photos := manifestFor("photos", "immich", map[string]string{"data": "portcullis_photos-data"})
	photos2 := manifestFor("photos-2", "immich", map[string]string{"data": "portcullis_photos-2-data"})
	immich := manifestFor("immich", "immich", map[string]string{"data": "portcullis_data"})
	for _, c := range []struct {
		name   string
		model  *types.Project
		m      BundleManifest
		others []BundleManifest
		want   string
	}{
		{"own multi name", load("photos", "portcullis_photos-data"), photos, []BundleManifest{immich, photos2}, ""},
		{"longer own prefix", load("photos-2", "portcullis_photos-2-data"), photos2, []BundleManifest{photos, immich}, ""},
		{"default instance's portcullis_<key>", load("immich", "portcullis_data"), immich, []BundleManifest{photos}, ""},
		{"compose default", load("photos", ""), manifestFor("photos", "immich", map[string]string{"data": "portcullis-photos_data"}), nil, ""},
		{"non-default can't take portcullis_<key>", load("photos", "portcullis_data"),
			manifestFor("photos", "immich", map[string]string{"data": "portcullis_data"}), nil, "not one of the instance's volume names"},
		{"another instance's name", loadKey("photos", "2-data", "portcullis_photos-2-data"),
			manifestFor("photos", "immich", map[string]string{"2-data": "portcullis_photos-2-data"}), []BundleManifest{photos2}, "is instance photos-2's"},
		{"under a longer other prefix", loadKey("photos", "2-x", "portcullis_photos-2-x"),
			manifestFor("photos", "immich", map[string]string{"2-x": "portcullis_photos-2-x"}), []BundleManifest{photos2}, "falls under instance photos-2's"},
		{"default key under another instance", loadKey("immich", "photos-data2", "portcullis_photos-data2"),
			manifestFor("immich", "immich", map[string]string{"photos-data2": "portcullis_photos-data2"}), []BundleManifest{photos}, "falls under instance photos's"},
		{"default key equal to another's name", loadKey("immich", "photos-data", "portcullis_photos-data"),
			manifestFor("immich", "immich", map[string]string{"photos-data": "portcullis_photos-data"}), []BundleManifest{photos}, "is instance photos's"},
		{"non-default name of the wrong form", load("photos", "portcullis_photos-2-data"),
			manifestFor("photos", "immich", map[string]string{"data": "portcullis_photos-2-data"}), nil, "not one of the instance's volume names"},
		{"model name differs from the manifest", load("photos", "portcullis_photos-2-data"), photos, []BundleManifest{photos2}, "the manifest says"},
		{"key missing from the manifest", load("photos", ""), manifestFor("photos", "immich", nil), nil, "not in the bundle manifest"},
		{"core name in the manifest", load("immich", "portcullis_hub_data"),
			manifestFor("immich", "immich", map[string]string{"data": "portcullis_hub_data"}), nil, "not one of the instance's volume names"},
		{"another project in the manifest", load("photos", "portcullis-paperless_data"),
			manifestFor("photos", "immich", map[string]string{"data": "portcullis-paperless_data"}), nil, "not one of the instance's volume names"},
	} {
		err := ValidateBundle(c.model, c.m, c.others, nil, dir)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
	}
}
