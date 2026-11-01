package hub

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserOverrideValidation(t *testing.T) {
	f := newFixture(t)
	svc := func(body string) string { return "services:\n  grafana:\n" + body }
	bad := map[string]string{
		"yaml":                      "services: [unclosed",
		"not a mapping":             "- a\n- b\n",
		"top-level key":             "x-thing: 1\nservices: {}\n",
		"unknown service":           "services:\n  nope:\n    image: x\n",
		"privileged":                svc("    privileged: true\n"),
		"host network":              svc("    network_mode: host\n"),
		"pid":                       svc("    pid: host\n"),
		"ipc":                       svc("    ipc: host\n"),
		"cap_add":                   svc("    cap_add: [SYS_ADMIN]\n"),
		"devices":                   svc("    devices: [/dev/sda]\n"),
		"security_opt":              svc("    security_opt: [seccomp=unconfined]\n"),
		"networks":                  svc("    networks: [portcullis-proxy]\n"),
		"extends":                   svc("    extends: {file: /etc/x.yml, service: y}\n"),
		"env_file":                  svc("    env_file: ./.env\n"),
		"unlisted key":              svc("    sysctls: {net.ipv4.ip_forward: 1}\n"),
		"traefik label":             svc("    labels:\n      traefik.http.routers.grafana.middlewares: \"\"\n"),
		"traefik list":              svc("    labels:\n      - traefik.http.routers.x.rule=Host(`evil.example.com`)\n"),
		"traefik case":              svc("    labels:\n      Traefik.enable: \"false\"\n"),
		"compose label":             svc("    labels:\n      com.docker.compose.project: other\n"),
		"reset tag":                 svc("    labels: !reset {}\n"),
		"override tag":              svc("    networks: !override [default]\n"),
		"docker socket":             svc("    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"),
		"run socket":                svc("    volumes:\n      - /run/docker.sock:/s\n"),
		"root":                      svc("    volumes:\n      - /:/host\n"),
		"root //":                   svc("    volumes:\n      - //:/host\n"),
		"root /./":                  svc("    volumes:\n      - /./:/host\n"),
		"etc ..":                    svc("    volumes:\n      - /etc/..:/host\n"),
		"var (contains the socket)": svc("    volumes:\n      - /var:/host\n"),
		"etc":                       svc("    volumes:\n      - /etc:/host-etc:ro\n"),
		"proc":                      svc("    volumes:\n      - /proc/1:/x\n"),
		"docker state":              svc("    volumes:\n      - /var/lib/docker/volumes:/x\n"),
		"core checkout":             svc("    volumes:\n      - /host/project:/x\n"),
		"core secrets":              svc("    volumes:\n      - /host/project/secrets:/x\n"),
		"core parent":               svc("    volumes:\n      - /host:/x\n"),
		"relative":                  svc("    volumes:\n      - ./.env:/x\n"),
		"relative escape":           svc("    volumes:\n      - ./templates/grafana/../../.env:/x\n"),
		"other template":            svc("    volumes:\n      - ./templates/other:/x\n"),
		"variable":                  svc("    volumes:\n      - ${HOME}:/x\n"),
		"long socket":               svc("    volumes:\n      - type: bind\n        source: /var/run/docker.sock\n        target: /s\n"),
		"npipe":                     svc("    volumes:\n      - type: npipe\n        source: x\n        target: /s\n"),
		"propagation":               svc("    volumes:\n      - type: bind\n        source: /srv/a\n        target: /a\n        bind: {propagation: rshared}\n"),
		"port variable":             svc("    ports: [\"${P}:80\"]\n"),
		"port range":                svc("    ports: [\"70000:80\"]\n"),
		"port bad ip":               svc("    ports: [\"nope:80:80\"]\n"),
		"volume driver":             "volumes:\n  data:\n    driver_opts: {type: none, o: bind, device: /var/run}\n",
		"volume name":               "volumes:\n  data:\n    name: portcullis-keycloak_data\n",
		"network unknown":           "networks:\n  portcullis-proxy:\n    external: false\n",
		"depends unknown":           svc("    depends_on: [db]\n"),
	}
	for name, c := range bad {
		if _, _, err := f.h.SaveUserOverride("grafana", c); statusOf(err) != 400 {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if _, err := os.Stat(f.h.userOverridePath("grafana")); err == nil {
		t.Fatal("a refused override was written")
	}

	good := svc(`    image: grafana/grafana:11.0.0
    environment:
      GF_LOG_LEVEL: debug
      PRICE: "costs $$5"
    labels:
      com.example.backup: "true"
    volumes:
      - /srv/grafana/plugins:/var/lib/grafana/plugins
      - ./templates/grafana/extra.ini:/etc/grafana/extra.ini:ro
      - /srv:/srv-all:ro
      - plugins:/plugins
      - type: bind
        source: /mnt/media
        target: /media
        read_only: true
    ports:
      - "127.0.0.1:9100:9100"
      - target: 9200
        published: "9200"
        protocol: udp
      - "9300"
    mem_limit: 512m
    cap_drop: [ALL]
volumes:
  plugins: {}
`)
	restart, detail, err := f.h.SaveUserOverride("grafana", good)
	if err != nil {
		t.Fatal(err)
	}
	if restart || !strings.HasPrefix(detail, "saved (") || strings.Contains(detail, "debug") {
		t.Errorf("restart=%v detail=%q", restart, detail)
	}
	if fi, err := os.Stat(f.h.userOverridePath("grafana")); err != nil || fi.Mode().Perm() != 0600 {
		t.Errorf("override file: %v %v", fi, err)
	}
	v, err := f.h.ComposeFiles("grafana")
	if err != nil || v.UserOverride != good || !strings.Contains(v.Compose, "grafana.${PORTCULLIS_DOMAIN") ||
		!strings.Contains(v.HubOverride, "3300:3000") || len(v.Rules) == 0 {
		t.Errorf("view = %+v %v", v, err)
	}

	// compose runs with the three layers, the custom one last.
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	ps := f.runner.Projects()
	files := ps[len(ps)-1].Files
	if len(files) != 3 || !strings.HasSuffix(files[0], "grafana/compose.yml") ||
		files[1] != f.h.overridePath("grafana") || files[2] != f.h.userOverridePath("grafana") {
		t.Errorf("files = %v", files)
	}
	if restart, _, err := f.h.SaveUserOverride("grafana", good); err != nil || !restart {
		t.Errorf("enabled app: restart=%v err=%v", restart, err)
	}

	// Empty (or comment-only) = no file.
	for _, empty := range []string{"", "  \n", "# nothing yet\n"} {
		f.h.SaveUserOverride("grafana", good)
		if _, detail, err := f.h.SaveUserOverride("grafana", empty); err != nil || detail != "removed" {
			t.Errorf("%q: %q %v", empty, detail, err)
		}
		if _, err := os.Stat(f.h.userOverridePath("grafana")); !os.IsNotExist(err) {
			t.Errorf("%q: override file kept", empty)
		}
	}
}

func TestUserOverrideNetworks(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.src, "net", "manifest.yaml"), "name: Net\nauth:\n  method: forward-auth\n")
	writeFile(t, filepath.Join(f.src, "net", "compose.yml"), "services:\n  a:\n    image: x\n    networks: [backend, portcullis-proxy]\n    labels:\n      traefik.http.routers.n.rule: Host(`net.${PORTCULLIS_DOMAIN}`)\nnetworks:\n  backend: {}\n  portcullis-proxy:\n    external: true\n")
	f.h.Discover()
	if _, _, err := f.h.SaveUserOverride("net", "networks:\n  backend:\n    driver_opts: {com.docker.network.driver.mtu: \"1400\"}\n"); err != nil {
		t.Errorf("driver_opts on the template's own network refused: %v", err)
	}
	for _, c := range []string{
		"networks:\n  portcullis-proxy:\n    labels: {a: b}\n",
		"networks:\n  backend:\n    external: true\n",
		"networks:\n  backend:\n    name: portcullis-proxy\n",
		"services:\n  a:\n    stop_timeout: 3\n",
	} {
		if _, _, err := f.h.SaveUserOverride("net", c); statusOf(err) != 400 {
			t.Errorf("%q accepted: %v", c, err)
		}
	}
}

// The custom override's host ports count in the pre-flight checks, both
// ways, and against the app's own Settings ports.
func TestUserOverridePorts(t *testing.T) {
	f := newFixture(t)
	if err := f.h.Enable("grafana"); err != nil { // 3300
		t.Fatal(err)
	}
	if _, _, err := f.h.SaveUserOverride("grafana", "services:\n  grafana:\n    ports: [\"3300:3000\"]\n"); statusOf(err) != 409 {
		t.Errorf("duplicate of its own Settings port accepted: %v", err)
	}
	if _, _, err := f.h.SaveUserOverride("other", "services:\n  web:\n    ports: [\"9000:80\"]\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SaveSettings("other", SettingsUpdate{Values: map[string]string{"OTHER_PORT": "3301"}, Inherit: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("other"); err != nil {
		t.Fatal(err)
	}
	_, _, err := f.h.SaveUserOverride("grafana", "services:\n  grafana:\n    ports: [\"9000:3000\"]\n")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "enabled app other — change its custom override") {
		t.Errorf("collision with another app's custom port: %v", err)
	}
	// Binding a specific address doesn't help against 0.0.0.0.
	if _, _, err := f.h.SaveUserOverride("grafana", "services:\n  grafana:\n    ports: [\"127.0.0.1:9000:3000\"]\n"); statusOf(err) != 409 {
		t.Errorf("overlapping bind accepted: %v", err)
	}
	if _, _, err := f.h.SaveUserOverride("grafana", "services:\n  grafana:\n    ports: [\"9000:3000/udp\"]\n"); err != nil {
		t.Errorf("other protocol refused: %v", err)
	}
}

// A template update that drops a service the custom override names makes
// compose up fail closed, before compose runs.
func TestUserOverrideRevalidatedOnUp(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.h.SaveUserOverride("other", "services:\n  worker:\n    environment: {A: b}\n"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.src, "other", "compose.yml"), "services:\n  web:\n    image: x\n    labels:\n      traefik.http.routers.other.rule: Host(`other.${PORTCULLIS_DOMAIN}`)\n")
	f.h.Discover()
	n := len(f.runner.Calls())
	err := f.h.Enable("other")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "not valid for this template any more") || !strings.Contains(err.Error(), "worker") {
		t.Errorf("err = %v", err)
	}
	if c := f.runner.Calls()[n:]; len(c) != 0 {
		t.Errorf("compose ran: %v", c)
	}
	if f.h.IsEnabled("other") {
		t.Error("enabled")
	}
	// A restart refuses before stopping the running app.
	f.h.mu.Lock()
	f.h.st.SetEnabled("other", true)
	f.h.findLocked("other").Enabled = true
	f.h.mu.Unlock()
	n = len(f.runner.Calls())
	if err := f.h.RestartApp("other"); statusOf(err) != 409 {
		t.Errorf("restart = %v", err)
	}
	if c := f.runner.Calls()[n:]; len(c) != 0 {
		t.Errorf("restart ran compose: %v", c)
	}
	// The override itself is kept: it survives template syncs.
	if _, err := os.Stat(f.h.userOverridePath("other")); err != nil {
		t.Error(err)
	}
}

func TestParseBindRoots(t *testing.T) {
	if r, err := ParseBindRoots("", "/opt/portcullis"); err != nil || strings.Join(r, ":") != "/srv:/mnt:/media" {
		t.Errorf("default = %v %v", r, err)
	}
	if r, err := ParseBindRoots("/data/media/:/srv", "/opt/portcullis"); err != nil || strings.Join(r, ":") != "/data/media:/srv" {
		t.Errorf("custom = %v %v", r, err)
	}
	for _, bad := range []string{"/", "//", "/./", "relative", "/etc", "/etc/x", "/var", "/var/lib/docker", "/usr/local", "/srv/../etc", "/opt", "/opt/portcullis/secrets", "/run", "$HOME", "/srv:"} {
		if _, err := ParseBindRoots(bad, "/opt/portcullis"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := New(Config{DataDir: t.TempDir(), OverrideBindRoots: "/"}, nil, nil, nil); err == nil {
		t.Error("New accepted / as a bind root")
	}
}
