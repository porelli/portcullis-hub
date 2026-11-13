package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/idmap"
	"github.com/portcullis/hub/internal/templates"
)

type fakeVersions []docker.Component

func (f fakeVersions) Components(context.Context) ([]docker.Component, error) { return f, nil }

// verifiedGuard is a guard for rt verified against a fake engine of rt.
func verifiedGuard(t *testing.T, rt docker.Runtime) *docker.Guard {
	t.Helper()
	g := docker.NewGuard(rt)
	name, ver := "Engine", "29.0.0"
	if rt == docker.RuntimePodman {
		name, ver = "Podman Engine", "5.4.2"
	}
	if err := g.Verify(context.Background(), fakeVersions{{Name: name, Version: ver}}); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestRuntimeView(t *testing.T) {
	// Docker: maps and port null, security options read once verified.
	f := newFixture(t)
	f.h.cfg.Runtime, f.h.cfg.Guard = docker.RuntimeDocker, verifiedGuard(t, docker.RuntimeDocker)
	f.engine.fx().secOpts = []string{"name=seccomp,profile=builtin", "name=selinux"}
	f.h.readIDMaps = func() (idmap.Map, idmap.Map, error) { t.Fatal("id maps read under docker"); return nil, nil, nil }
	v := f.h.Runtime(context.Background())
	b, _ := json.Marshal(v)
	if want := `{"runtime":"docker","verified":true,"engine":"Engine","engine_version":"29.0.0","mismatch":"","rootless":false,"uid_map":null,"gid_map":null,"unprivileged_port_start":null,"selinux":true}`; string(b) != want {
		t.Errorf("docker view:\n got %s\nwant %s", b, want)
	}

	// Podman: the Hub's maps and core's port start.
	f = newFixture(t)
	f.h.cfg.Runtime, f.h.cfg.Guard = docker.RuntimePodman, verifiedGuard(t, docker.RuntimePodman)
	f.engine.fx().secOpts = []string{"name=rootless", "name=seccomp"}
	writeFile(t, filepath.Join(f.project, ".env"), "PORTCULLIS_UNPRIVILEGED_PORT_START=80\n")
	um, _ := idmap.Parse("0 1001 1\n1 100000 65536")
	gm, _ := idmap.Parse("0 1001 1\n1 200000 65536")
	f.h.readIDMaps = func() (idmap.Map, idmap.Map, error) { return um, gm, nil }
	b, _ = json.Marshal(f.h.Runtime(context.Background()))
	if want := `{"runtime":"podman","verified":true,"engine":"Podman Engine","engine_version":"5.4.2","mismatch":"","rootless":true,"uid_map":[{"container":0,"host":1001,"size":1},{"container":1,"host":100000,"size":65536}],"gid_map":[{"container":0,"host":1001,"size":1},{"container":1,"host":200000,"size":65536}],"unprivileged_port_start":80,"selinux":false}`; string(b) != want {
		t.Errorf("podman view:\n got %s\nwant %s", b, want)
	}
	// Unreadable or out-of-range port start = 1024.
	for _, raw := range []string{"abc", "", "65536", "-1", "+80", "8 0"} {
		writeFile(t, filepath.Join(f.project, ".env"), "PORTCULLIS_UNPRIVILEGED_PORT_START="+raw+"\n")
		if p := f.h.Runtime(context.Background()).UnprivilegedPortStart; p == nil || *p != 1024 {
			t.Errorf("%q: port start %v", raw, p)
		}
	}
	// 0 is a deliberate host setting: every port is unprivileged.
	writeFile(t, filepath.Join(f.project, ".env"), "PORTCULLIS_UNPRIVILEGED_PORT_START=0\n")
	if p := f.h.Runtime(context.Background()).UnprivilegedPortStart; p == nil || *p != 0 {
		t.Errorf("0: port start %v", p)
	}
	if c := f.h.templateCompat(&templates.Template{Manifest: templates.Manifest{Ports: []templates.Port{{Key: "DNS", Default: 53, Protocol: "tcp"}}}}); c.Status != templates.CompatOK {
		t.Errorf("port 53 at port start 0 = %+v", c)
	}
	os.Remove(filepath.Join(f.project, ".env"))
	if p := f.h.Runtime(context.Background()).UnprivilegedPortStart; p == nil || *p != 1024 {
		t.Errorf("no core env: port start %v", p)
	}

	// Unverified (or no guard): verified false, no Info call.
	f = newFixture(t)
	f.h.cfg.Runtime, f.h.cfg.Guard = docker.RuntimePodman, docker.NewGuard(docker.RuntimePodman)
	f.engine.fx().secErr = errors.New("must not be called")
	f.h.readIDMaps = func() (idmap.Map, idmap.Map, error) { return nil, nil, errors.New("no proc") }
	v = f.h.Runtime(context.Background())
	if v.Verified || v.Rootless || v.UIDMap != nil || v.GIDMap != nil || v.UnprivilegedPortStart == nil {
		t.Errorf("unverified view = %+v", v)
	}
	f.h.cfg.Guard = nil
	if v := f.h.Runtime(context.Background()); v.Verified {
		t.Errorf("nil guard verified: %+v", v)
	}
}

// Core's port start is never a template variable (contract §2): a
// compose referencing it doesn't get core's value.
func TestUnprivilegedPortStartNotPassed(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\nPORTCULLIS_UNPRIVILEGED_PORT_START=80\n")
	writeFile(t, filepath.Join(f.src, "grafana", "compose.yml"), strings.Replace(grafanaCompose, "X: ${CORE_VAR}", "X: ${CORE_VAR}\n      P: ${PORTCULLIS_UNPRIVILEGED_PORT_START:-1}", 1))
	f.h.Discover()
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	env := readEnvFile(filepath.Join(f.data, "env", "grafana.env"))
	if env["CORE_VAR"] != "core-value" {
		t.Fatalf("env = %v", env)
	}
	if v, ok := env[VarUnprivilegedPortStart]; ok {
		t.Errorf("core's port start passed to the template: %q", v)
	}
}

// eventEngine streams a fixed list of events, then blocks.
type eventEngine struct {
	*fakeEngine
	events []docker.Event
}

func (e *eventEngine) Events(ctx context.Context, f docker.Filters, fn func(docker.Event)) error {
	for _, ev := range e.events {
		fn(ev)
	}
	<-ctx.Done()
	return ctx.Err()
}

func podmanEvent(action string) docker.Event {
	ev := docker.Event{Type: "container", Action: action}
	ev.Actor.Attributes = map[string]string{docker.LabelProject: "portcullis-grafana"}
	return ev
}

// Podman's extra actions (init, cleanup, health_status without a suffix)
// trigger nothing; a start still does.
func TestWatchEventsIgnoresPodmanActions(t *testing.T) {
	f := newFixture(t)
	drain := func() {
		select {
		case <-f.h.kick:
		default:
		}
	}
	run := func(evs ...docker.Event) bool {
		drain()
		f.h.engine = &eventEngine{fakeEngine: f.engine, events: evs}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		f.h.watchEvents(ctx)
		select {
		case <-f.h.kick:
			return true
		default:
			return false
		}
	}
	if run(podmanEvent("init"), podmanEvent("cleanup"), podmanEvent("health_status"), podmanEvent("exec_died"), podmanEvent("mount")) {
		t.Error("podman's extra actions triggered a reconcile")
	}
	if !run(podmanEvent("start")) {
		t.Error("start didn't trigger a reconcile")
	}
}

// P5: start-time engine work waits for the guard; an unverified engine
// never stops Init, and the helper sweep runs once it is verified — only
// on helpers created before the start.
func TestInitWaitsForGuard(t *testing.T) {
	f := newFixture(t)
	g := docker.NewGuard(docker.RuntimeDocker)
	f.h.cfg.Guard = g
	old := docker.Container{ID: "old", Labels: map[string]string{docker.LabelHelper: "1"}, Created: time.Now().Add(-time.Hour).Unix()}
	fresh := docker.Container{ID: "fresh", Labels: map[string]string{docker.LabelHelper: "1"}, Created: time.Now().Add(time.Hour).Unix()}
	f.engine.mu.Lock()
	f.engine.containers = append(f.engine.containers, old, fresh)
	f.engine.mu.Unlock()
	removed := func() []string {
		v := f.engine.vol()
		v.vmu.Lock()
		defer v.vmu.Unlock()
		return append([]string(nil), v.removed...)
	}
	f.h.SweepBackupLeftovers()
	if len(removed()) != 0 {
		t.Fatalf("swept before verification: %v", removed())
	}
	if err := g.Verify(context.Background(), fakeVersions{{Name: "Engine"}}); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if got := removed(); len(got) != 1 || got[0] != "old" {
		t.Errorf("removed %v, want [old]", got)
	}
}
