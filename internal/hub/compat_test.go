package hub

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/kube"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/directory"
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
	f.h.cfg.Runtime = runtime.KindPodman
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
	f2.h.cfg.Runtime = runtime.KindDocker
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
			return v.Compat != nil && v.Compat.Status == status && v.Compat.Runtime == runtime.KindPodman
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
		if tv.Compat != nil {
			t.Fatalf("%s: compat under docker", tv.ID)
		}
	}
	for _, v := range f.h.Instances() {
		if v.Compat != nil {
			t.Fatalf("%s: compat under docker", v.ID)
		}
	}
	podmanAt(t, f, "80")
	seen := false
	for _, tv := range f.h.Templates() {
		if tv.Compat == nil || tv.Compat.Runtime != runtime.KindPodman {
			t.Errorf("%s: no podman compat under podman", tv.ID)
			continue
		}
		if tv.ID == "dns" {
			seen = tv.Compat.Status == templates.CompatRefused
		}
	}
	if !seen {
		t.Error("dns not refused at 80")
	}
}

// TestRealTemplatesRuntimeClassification: every real template's verdict
// equals the templates repo's committed classification: tests/runtime.txt
// (<id>\t<runtime>\t<status>\t<reasons joined "; ">, podman at port
// start 80 and kubernetes, sorted) or, before the templates switch,
// tests/rootless.txt (<id>\t<status>\t<reasons>, podman only).
func TestRealTemplatesRuntimeClassification(t *testing.T) {
	dir := os.Getenv("PORTCULLIS_TEMPLATES_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "portcullis-templates")
	}
	dir, _ = filepath.Abs(dir)
	file, both := "runtime.txt", true
	want, err := os.ReadFile(filepath.Join(dir, "tests", file))
	if err != nil {
		file, both = "rootless.txt", false
		if want, err = os.ReadFile(filepath.Join(dir, "tests", file)); err != nil {
			t.Skipf("no templates checkout with tests/runtime.txt or rootless.txt at %s", dir)
		}
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
		if !both {
			c := templates.RuntimeCompat(runtime.KindPodman, tp.ReadCompose(), tp.Manifest, nil, 80)
			lines = append(lines, e.Name()+"\t"+c.Status+"\t"+strings.Join(c.Reasons, "; "))
			continue
		}
		for _, rt := range []runtime.Kind{runtime.KindKubernetes, runtime.KindPodman} {
			c := templates.RuntimeCompat(rt, tp.ReadCompose(), tp.Manifest, nil, 80)
			lines = append(lines, e.Name()+"\t"+string(rt)+"\t"+c.Status+"\t"+strings.Join(c.Reasons, "; "))
			if rt == runtime.KindKubernetes && c.Status != templates.CompatRefused {
				kubePriorityWithinCap(t, e.Name(), &tp)
			}
		}
	}
	sort.Strings(lines)
	got := strings.Join(lines, "\n") + "\n"
	if got != string(want) {
		t.Errorf("classification differs from %s/tests/%s:\n--- hub\n%s--- templates\n%s", dir, file, got, want)
	}
}

// kubePriorityWithinCap: a template that isn't refused on Kubernetes
// never gets a route above kube.MaxAppPriority — its own routers'
// bounds, and the Hub's public (+1) and extra-domain sign-in (+2)
// routers above them (no MCP routers on Kubernetes). IngressObjects
// refuses anything higher, so a template over the cap must be classified
// refused instead.
func kubePriorityWithinCap(t *testing.T, id string, tp *templates.Template) {
	t.Helper()
	routes, err := templates.ParseRoutes(tp.ReadCompose())
	if err != nil {
		t.Errorf("%s: %v", id, err)
		return
	}
	if top := routes.MaxPriorityBound() + 2; top > kube.MaxAppPriority {
		t.Errorf("%s: classified usable on Kubernetes but its routes reach priority %d (> %d)", id, top, kube.MaxAppPriority)
	}
}

const restartCompose = "services:\n  web:\n    image: x\n    restart: unless-stopped\n    depends_on:\n      init:\n        condition: service_completed_successfully\n      job2:\n        condition: service_completed_successfully\n  job2:\n    image: x\n    restart: unless-stopped\n  init:\n    image: x\n    restart: \"no\"\n  worker:\n    image: y\n  retry:\n    image: z\n    restart: on-failure\n  already:\n    image: w\n    restart: always\n"

// Under podman the override sets `restart: always` on the services the
// template runs `unless-stopped` (podman-restart.service starts only
// `always` containers at boot); one-shot jobs, no policy, on-failure and
// always stay as written. Docker: unchanged.
func TestOverridePodmanRestartAlways(t *testing.T) {
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"rs": {gateManifest, restartCompose}})
	if f.h.Template("rs") == nil {
		t.Fatal("rs fixture not loaded (see the log)")
	}
	render := func(rt runtime.Kind) map[string]map[string]any {
		f.h.cfg.Runtime = rt
		f.h.mu.Lock()
		out, err := f.h.renderOverrideLocked(f.h.findLocked("rs"), state.InstanceSettings{})
		f.h.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Services map[string]map[string]any `yaml:"services"`
		}
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return doc.Services
	}
	for svc, s := range render(runtime.KindDocker) {
		if _, ok := s["restart"]; ok {
			t.Errorf("docker: %s gets restart %v", svc, s["restart"])
		}
	}
	got := render(runtime.KindPodman)
	if got["web"]["restart"] != "always" {
		t.Errorf("podman: web restart = %v", got["web"]["restart"])
	}
	for _, svc := range []string{"init", "job2", "worker", "retry", "already"} {
		if r, ok := got[svc]["restart"]; ok {
			t.Errorf("podman: %s gets restart %v", svc, r)
		}
	}
}

// Under Kubernetes: a template with a refused feature is never created
// (409 "on Kubernetes"), the views carry compat with runtime kubernetes,
// and a dns-like app on port 53 is fine (no unprivileged port limit).
func TestCreateRefusedOnKubernetes(t *testing.T) {
	hostCompose := "services:\n  relay:\n    image: x\n    network_mode: host\n"
	relayManifest := "name: Relay\ndescription: x\nversion: \"1.0\"\ncategory: x\nai: {unsupported: \"test fixture\"}\nauth:\n  method: custom\n"
	extra := map[string][2]string{"dns": {dnsManifest, dnsCompose}, "esp": {espManifest, espCompose}, "relay": {relayManifest, hostCompose}}
	f := newInstanceFixtureExtra(t, nil, nil, extra)
	f.h.cfg.Runtime = runtime.KindKubernetes
	_, err := f.h.CreateInstanceAs(CreateRequest{Template: "relay", ID: "relay-b", Label: "B"}, directory.Human("alice"))
	if want := "relay-b can't run on Kubernetes: service relay uses network_mode: host (not on Kubernetes)"; statusOf(err) != 409 || err.Error() != want {
		t.Fatalf("create = %v (%d), want %q", err, statusOf(err), want)
	}
	if _, err := f.h.CreateInstanceAs(CreateRequest{Template: "dns", ID: "dns-b", Label: "B"}, directory.Human("alice")); err != nil {
		t.Fatalf("dns on kubernetes: %v", err)
	}
	for _, tv := range f.h.Templates() {
		if tv.Compat == nil || tv.Compat.Runtime != runtime.KindKubernetes {
			t.Fatalf("%s: compat %+v under kubernetes", tv.ID, tv.Compat)
		}
		switch tv.ID {
		case "esp":
			if tv.Compat.Status != templates.CompatDegraded || tv.Compat.Reasons[0] != "service esp has device slots: host devices can't be passed on Kubernetes" {
				t.Errorf("esp: %+v", tv.Compat)
			}
		case "relay":
			if tv.Compat.Status != templates.CompatRefused {
				t.Errorf("relay: %+v", tv.Compat)
			}
		}
	}
	// The instance's own value: a real device refuses it.
	s := f.h.st.Settings["esp"]
	if s.Values == nil {
		s.Values = map[string]any{}
	}
	writeFile(t, f.h.envPath("esp"), "ESP_DEVICE=/dev/ttyUSB0\n")
	if c := f.h.instanceCompat(f.h.Template("esp"), s); c.Status != templates.CompatRefused || c.Reasons[0] != "service esp passes host devices (not on Kubernetes)" {
		t.Errorf("esp instance: %+v", c)
	}
}
