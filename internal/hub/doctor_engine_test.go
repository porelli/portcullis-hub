package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/state"
)

const gateManifest = `name: Gate
description: x
version: "1.0"
category: x
ai: {unsupported: "test fixture"}
auth:
  method: custom
`

const gateCompose = "services:\n  app:\n    image: x\n    volumes:\n      - ./templates/x/gate.sh:/gate.sh:ro\n      - ./templates/x/conf:/conf\n      - ./templates/x/labelled:/l:ro,z\n      - /srv/media:/media\n      - data:/data\n      - type: bind\n        source: ./templates/x/long.py\n        target: /long.py\n        read_only: true\n  side:\n    image: y\n    volumes:\n      - ./certs/ca-bundle.crt:/ca.crt:ro\nvolumes:\n  data: {}\n"

func TestSELinuxRelabels(t *testing.T) {
	got := selinuxRelabels([]byte(gateCompose))
	if len(got) != 1 || len(got["app"]) != 3 {
		t.Fatalf("relabels = %#v", got)
	}
	var vols []map[string]any
	for _, e := range got["app"] {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(strings.ReplaceAll(e, "\n        ", "\n")), &m); err != nil {
			t.Fatalf("%q: %v", e, err)
		}
		vols = append(vols, m)
	}
	want := map[string]bool{"/gate.sh": true, "/conf": false, "/long.py": true}
	for _, m := range vols {
		ro, ok := want[m["target"].(string)]
		if !ok || m["type"] != "bind" || m["read_only"] != ro || !strings.HasPrefix(m["source"].(string), "./templates/x/") {
			t.Errorf("entry %v", m)
		}
		if b, _ := m["bind"].(map[string]any); b["selinux"] != "z" {
			t.Errorf("entry %v: no selinux z", m)
		}
	}
	// A shared folder, a named volume, core's certs, an already labelled
	// bind, a long bind with other keys (M6): never.
	if got := selinuxRelabels([]byte("services:\n  a:\n    image: x\n    volumes:\n      - /srv/media:/media\n      - ${MEDIA:-./templates/x}:/m\n      - ./templates/../secrets:/s\n      - type: bind\n        source: ./templates/x/p\n        target: /p\n        bind:\n          propagation: rslave\n")); len(got) != 0 {
		t.Errorf("relabelled %#v", got)
	}
}

// TestOverrideSELinuxRelabel: under podman on SELinux the override
// re-declares the template's own binds with bind.selinux z; under Docker
// on SELinux, or podman without it, the override is byte-identical.
func TestOverrideSELinuxRelabel(t *testing.T) {
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"gate": {gateManifest, gateCompose}})
	if f.h.Template("gate") == nil {
		t.Fatal("gate fixture not loaded (see the log)")
	}
	render := func(rt docker.Runtime, selinux bool) string {
		f.h.cfg.Runtime = rt
		f.h.selinuxMu.Lock()
		f.h.selinuxKnown, f.h.selinuxOn = true, selinux
		f.h.selinuxMu.Unlock()
		f.h.mu.Lock()
		defer f.h.mu.Unlock()
		out, err := f.h.renderOverrideLocked(f.h.findLocked("gate"), state.InstanceSettings{})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	plain := render(docker.RuntimeDocker, false)
	if got := render(docker.RuntimeDocker, true); got != plain {
		t.Errorf("docker on SELinux changed the override:\n%s", got)
	}
	if got := render(docker.RuntimePodman, false); got != plain {
		t.Errorf("podman without SELinux changed the override:\n%s", got)
	}
	got := render(docker.RuntimePodman, true)
	for _, want := range []string{`source: "./templates/x/gate.sh"`, `target: "/gate.sh"`, "selinux: z"} {
		if !strings.Contains(got, want) {
			t.Errorf("relabelled override lacks %q:\n%s", want, got)
		}
	}
	for _, never := range []string{"/srv/media", "ca-bundle", "/l\""} {
		if strings.Contains(got, never) {
			t.Errorf("relabelled %s:\n%s", never, got)
		}
	}
	if strings.Contains(plain, "selinux") {
		t.Errorf("plain override relabels:\n%s", plain)
	}
}

// The engine's SELinux flag is read once the guard verified the engine,
// then cached; never before.
func TestEngineSELinuxCached(t *testing.T) {
	f := newFixture(t)
	f.h.cfg.Runtime = docker.RuntimePodman
	g := docker.NewGuard(docker.RuntimePodman)
	f.h.cfg.Guard = g
	f.engine.fx().secOpts = []string{"name=rootless", "name=selinux"}
	if f.h.engineSELinux(context.Background()) || f.h.selinuxCached() {
		t.Fatal("read before verification")
	}
	if err := g.Verify(context.Background(), fakeVersions{{Name: "Podman Engine"}}); err != nil {
		t.Fatal(err)
	}
	if !f.h.engineSELinux(context.Background()) || !f.h.relabelBinds() {
		t.Fatal("not read after verification")
	}
	f.engine.fx().secOpts = nil
	if !f.h.engineSELinux(context.Background()) {
		t.Error("not cached")
	}
	in := f.h.doctorEngineIn(context.Background())
	if in == nil || in.Runtime != "podman" || !in.SELinux || in.Mismatch != "" {
		t.Errorf("engine input = %+v", in)
	}
	f.h.cfg.Guard = nil
	if f.h.doctorEngineIn(context.Background()) != nil {
		t.Error("engine input without a guard")
	}
}

func TestServiceLimits(t *testing.T) {
	got := serviceLimits([]byte("x-l: &l\n  mem_limit: 256m\nservices:\n  a:\n    <<: *l\n    image: x\n    pids_limit: 100\n  b:\n    image: y\n    pids_limit: -1\n"))
	if got["a"] != [2]bool{true, true} || got["b"] != [2]bool{false, false} {
		t.Errorf("limits = %v", got)
	}
}

// I4: the docs template's ./docs bind is labelled too (core's overlay
// covers only core's services); ./docs-other, ./secrets and the
// checkout root never are.
func TestSELinuxRelabelsDocs(t *testing.T) {
	got := selinuxRelabels([]byte("services:\n  docs:\n    image: x\n    volumes:\n      - ./docs:/docs/docs:ro\n      - ./templates/docs/mkdocs.yml:/docs/mkdocs.yml:ro\n      - ./docs-other:/o:ro\n      - ./secrets:/s:ro\n      - .:/project:ro\n"))
	if len(got["docs"]) != 2 {
		t.Fatalf("relabels = %#v", got)
	}
	joined := strings.Join(got["docs"], "\n")
	for _, want := range []string{`source: "./docs"`, `target: "/docs/docs"`, `source: "./templates/docs/mkdocs.yml"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("lacks %s:\n%s", want, joined)
		}
	}
	for _, never := range []string{"docs-other", "secrets", `source: "."`} {
		if strings.Contains(joined, never) {
			t.Errorf("relabelled %s:\n%s", never, joined)
		}
	}
}

// M14: collectRuntime records each container's inspected limits next to
// what its compose sets (limits_not_enforced's inputs).
func TestCollectRuntimeLimits(t *testing.T) {
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"lim": {gateManifest,
		"services:\n  app:\n    image: x\n    mem_limit: 256m\n    pids_limit: 100\n  side:\n    image: y\n"}})
	if f.h.Template("lim") == nil {
		t.Fatal("lim fixture not loaded (see the log)")
	}
	app, side := container("c-app", "portcullis-lim", "app", "running"), container("c-side", "portcullis-lim", "side", "running")
	f.engine.mu.Lock()
	f.engine.containers = append(f.engine.containers, app, side)
	f.engine.mu.Unlock()
	f.engine.fx().inspect = map[string]docker.ContainerInfo{
		"c-app":  {ID: "c-app", Memory: 0, PidsLimit: 100},
		"c-side": {ID: "c-side", Memory: 64 << 20},
	}
	got := map[string]runtimeEntry{}
	for _, e := range f.h.collectRuntime(context.Background(), []string{"lim"}) {
		got[e.Service] = e
	}
	if a := got["app"]; !a.WantMemory || !a.WantPids || a.Memory != 0 || a.PidsLimit != 100 {
		t.Errorf("app = %+v", a)
	}
	if s := got["side"]; s.WantMemory || s.WantPids || s.Memory != 64<<20 {
		t.Errorf("side = %+v", s)
	}
}

// M5: under podman an up whose SELinux flag can't be read is refused
// (503), never rendered without the relabels.
func TestPrepareUpRefusesUnreadableSELinux(t *testing.T) {
	f := newFixture(t)
	f.h.cfg.Runtime, f.h.cfg.Guard = docker.RuntimePodman, verifiedGuard(t, docker.RuntimePodman)
	f.engine.fx().secErr = errors.New("info denied")
	if err := f.h.Enable("grafana"); statusOf(err) != 503 || !strings.Contains(err.Error(), "security options") {
		t.Fatalf("enable = %v (%d)", err, statusOf(err))
	}
	f.engine.fx().secErr = nil
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatalf("readable: %v", err)
	}
}
