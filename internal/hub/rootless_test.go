package hub

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// dnsManifest is pihole-like: host port 53 over TCP and UDP.
const dnsManifest = `name: DNS
description: x
version: "1.0"
category: x
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: custom
ports:
  - key: DNS_TCP
    container: 53
    protocol: tcp
    default: 53
    service: dns
  - key: DNS_UDP
    container: 53
    protocol: udp
    default: 53
    service: dns
`

const dnsCompose = "services:\n  dns:\n    image: x\n    ports:\n      - \"${DNS_TCP:-53}:53/tcp\"\n      - \"${DNS_UDP:-53}:53/udp\"\n"

// espManifest has a device slot set through a setting.
const espManifest = `name: ESP
description: x
version: "1.0"
category: x
ai: {unsupported: "test fixture"}
auth:
  method: custom
settings:
  options:
    - key: serial
      label: Serial device
      type: string
      default: ""
      applies: restart
      delivery: [{env: ESP_DEVICE}]
`

const espCompose = "services:\n  esp:\n    image: x\n    devices:\n      - ${ESP_DEVICE:-/dev/null}:/dev/ttyUSB0\n"

func podmanAt(t *testing.T, f *fixture, portStart string) {
	t.Helper()
	f.h.cfg.Runtime = docker.RuntimePodman
	writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\nPORTCULLIS_UNPRIVILEGED_PORT_START="+portStart+"\n")
}

func TestCreateRefusedUnderPodman(t *testing.T) {
	extra := map[string][2]string{"dns": {dnsManifest, dnsCompose}}
	f := newInstanceFixtureExtra(t, nil, nil, extra)
	if f.h.Template("dns") == nil {
		t.Fatal("dns fixture not loaded (see the log)")
	}
	podmanAt(t, f, "80")
	_, err := f.h.CreateInstanceAs(CreateRequest{Template: "dns", ID: "dns-b", Label: "B"}, directory.Human("alice"))
	want := "dns-b can't run under rootless Podman: host port 53/tcp is below net.ipv4.ip_unprivileged_port_start (80): lower it to 53 on the host to allow it (any local user can then bind ports from 53); " +
		"host port 53/udp is below net.ipv4.ip_unprivileged_port_start (80): lower it to 53 on the host to allow it (any local user can then bind ports from 53)"
	if statusOf(err) != 409 || err.Error() != want {
		t.Fatalf("create = %v (%d)\nwant %s", err, statusOf(err), want)
	}
	f.h.mu.RLock()
	_, made := f.h.st.Instances["dns-b"]
	f.h.mu.RUnlock()
	if made {
		t.Error("a refused create stored the instance")
	}
	// Lowered to 53: degraded (UDP), created.
	podmanAt(t, f, "53")
	if err := f.h.CreateInstance("dns", "dns-c", nil); err != nil {
		t.Fatalf("at 53: %v", err)
	}
	// Under Docker nothing is judged.
	f2 := newInstanceFixtureExtra(t, nil, nil, extra)
	f2.h.cfg.Runtime = docker.RuntimeDocker
	if err := f2.h.CreateInstance("dns", "dns-b", nil); err != nil {
		t.Fatalf("docker: %v", err)
	}
}

func TestEnableRefusedUnderPodman(t *testing.T) {
	seed := func(st *state.AppState) {
		st.Settings = map[string]state.InstanceSettings{"esp": {Values: map[string]any{"serial": "/dev/ttyUSB0"}, Types: map[string]string{"serial": "string"}}}
	}
	f := newInstanceFixtureExtra(t, seed, nil, map[string][2]string{"esp": {espManifest, espCompose}})
	if f.h.Template("esp") == nil {
		t.Fatal("esp fixture not loaded (see the log)")
	}
	podmanAt(t, f, "80")
	simulateCompose(f, 0)
	err := f.h.Enable("esp")
	want := "esp can't run under rootless Podman: service esp passes the host device /dev/ttyUSB0: device access needs host root"
	if statusOf(err) != 409 || !strings.Contains(err.Error(), want) {
		t.Fatalf("enable = %v (%d)", err, statusOf(err))
	}
	for _, c := range f.runner.Calls() {
		if strings.HasPrefix(c, "up:") || strings.HasPrefix(c, "create:") {
			t.Errorf("compose ran: %v", f.runner.Calls())
		}
	}
	// The slot unset: degraded, enabled.
	f.h.mu.Lock()
	s := f.h.st.Settings["esp"]
	s.Values = map[string]any{"serial": ""}
	f.h.st.Settings["esp"] = s
	f.h.mu.Unlock()
	if err := f.h.Enable("esp"); err != nil {
		t.Fatalf("slot unset: %v", err)
	}
	if v := f.h.Instances(); !hasRootless(v, "esp", templates.CompatDegraded) {
		t.Errorf("instance view: %+v", v)
	}
}

func hasRootless(vs []InstanceView, id, status string) bool {
	for _, v := range vs {
		if v.ID == id {
			return v.Rootless != nil && v.Rootless.Status == status
		}
	}
	return false
}

// P13: restore into a new id creates through createEntry: refused too.
func TestRestoreAsRefusedUnderPodman(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	podmanAt(t, f, "5000") // grafana publishes 3300
	_, err = f.h.RestoreInstanceAs(entry.Archive, "grafana-c", directory.Human("root"))
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "grafana-c can't run under rootless Podman: host port 3300/tcp is below") {
		t.Fatalf("restore as = %v (%d)", err, statusOf(err))
	}
	f.h.mu.RLock()
	_, made := f.h.st.Instances["grafana-c"]
	f.h.mu.RUnlock()
	if made {
		t.Error("a refused restore stored the instance")
	}
}

func TestTemplateViewRootless(t *testing.T) {
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"dns": {dnsManifest, dnsCompose}})
	for _, tv := range f.h.Templates() {
		if tv.Rootless != nil {
			t.Fatalf("%s: rootless under docker", tv.ID)
		}
	}
	for _, v := range f.h.Instances() {
		if v.Rootless != nil {
			t.Fatalf("%s: rootless under docker", v.ID)
		}
	}
	podmanAt(t, f, "80")
	seen := false
	for _, tv := range f.h.Templates() {
		if tv.Rootless == nil {
			t.Errorf("%s: no rootless under podman", tv.ID)
		}
		if tv.ID == "dns" {
			seen = tv.Rootless.Status == templates.CompatRefused
		}
	}
	if !seen {
		t.Error("dns not refused at 80")
	}
}

// TestRealTemplatesRootlessClassification: every real template's verdict
// at port start 80 equals the templates repo's committed classification
// (tests/rootless.txt: <id>\t<status>\t<reasons joined "; ">, sorted).
func TestRealTemplatesRootlessClassification(t *testing.T) {
	dir := os.Getenv("PORTCULLIS_TEMPLATES_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "portcullis-templates")
	}
	dir, _ = filepath.Abs(dir)
	want, err := os.ReadFile(filepath.Join(dir, "tests", "rootless.txt"))
	if err != nil {
		t.Skipf("no templates checkout with tests/rootless.txt at %s", dir)
	}
	entries, _ := os.ReadDir(dir)
	var lines []string
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "manifest.yaml")); err != nil {
			continue
		}
		tp, err := templates.Load(dir, e.Name(), "portcullis", "example.org", settings.NewRegistry())
		if err != nil {
			t.Errorf("%s: %v", e.Name(), err)
			continue
		}
		c := templates.RootlessCompat(tp.ReadCompose(), tp.Manifest, nil, 80)
		lines = append(lines, e.Name()+"\t"+c.Status+"\t"+strings.Join(c.Reasons, "; "))
	}
	sort.Strings(lines)
	got := strings.Join(lines, "\n") + "\n"
	if got != string(want) {
		t.Errorf("classification differs from %s/tests/rootless.txt:\n--- hub\n%s--- templates\n%s", dir, got, want)
	}
}
