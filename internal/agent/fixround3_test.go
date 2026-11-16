package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
)

func waitCall(t *testing.T, f *apiFixture, call string) {
	t.Helper()
	for i := 0; i < 3000; i++ {
		for _, c := range f.rt.Calls() {
			if c == call {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no %q in %v", call, f.rt.Calls())
}

func countCalls(f *apiFixture, call string) int {
	n := 0
	for _, c := range f.rt.Calls() {
		if c == call {
			n++
		}
	}
	return n
}

// backstopFixture: instance app bundled with a bind under the root, its
// container c-app running.
func backstopFixture(t *testing.T) *apiFixture {
	t.Helper()
	f := newAPI(t)
	os.MkdirAll(filepath.Join(f.root, "real"), 0o755)
	if c, b := f.putFor(t, "app", map[string]string{BundleCompose: bindCompose(f.root + "/real/sub:/x")}); c != 204 {
		t.Fatalf("bundle: %d %s", c, b)
	}
	f.rt.Lock()
	f.rt.Units = []runtime.Unit{{ID: "c-app", Project: "portcullis-app", Instance: "app", State: "running"}}
	f.rt.Infos["c-app"] = runtime.UnitInfo{ID: "c-app", Labels: map[string]string{docker.LabelProject: "portcullis-app"},
		Mounts: []runtime.Mount{{Type: "bind", Source: f.root + "/real/sub", Destination: "/x", RW: true}}}
	f.rt.Unlock()
	return f
}

// TestStartBackstopSweeps (review A2-H1): a container that started while
// nobody listened (agent start, a reconnect) is caught by the sweep: at
// start, after a subscribe, periodically.
func TestStartBackstopSweeps(t *testing.T) {
	f := backstopFixture(t)
	os.Symlink(t.TempDir(), filepath.Join(f.root, "real", "sub"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.api.WatchStarts(ctx) // no event at all
	waitCall(t, f, "down-by-name portcullis-app")
	if q := f.api.Quarantined(); !strings.Contains(q["app"], "symlink") {
		t.Errorf("quarantine %v", q)
	}
	// A clean running container is left alone.
	g := backstopFixture(t)
	g.api.Sweep(context.Background())
	if g.api.Quarantined() != nil || countCalls(g, "signal c-app KILL") != 0 {
		t.Errorf("a clean sweep acted: %v", g.rt.Calls())
	}
}

// TestStartBackstopFailClosed (review A2-M1): an unknown project is
// stopped; an event without the label is checked through inspection; a
// mount the bundle doesn't have is a violation; a failed down is
// retried; the quarantine is persisted.
func TestStartBackstopFailClosed(t *testing.T) {
	t.Run("unknown project", func(t *testing.T) {
		f := newAPI(t)
		f.api.CheckStarted(context.Background(), "c-x", "portcullis-ghost")
		waitCall(t, f, "down-by-name portcullis-ghost")
		if countCalls(f, "signal c-x KILL") != 1 || f.api.Quarantined()["ghost"] == "" {
			t.Errorf("calls %v q %v", f.rt.Calls(), f.api.Quarantined())
		}
	})
	t.Run("no label in the event", func(t *testing.T) {
		f := backstopFixture(t)
		os.Symlink(t.TempDir(), filepath.Join(f.root, "real", "sub"))
		f.api.CheckStarted(context.Background(), "c-app", "")
		waitCall(t, f, "down-by-name portcullis-app")
		if !strings.Contains(strings.Join(f.rt.Calls(), "\n"), "inspect c-app") {
			t.Errorf("not inspected: %v", f.rt.Calls())
		}
	})
	t.Run("a foreign mount", func(t *testing.T) {
		f := backstopFixture(t)
		f.rt.Lock()
		i := f.rt.Infos["c-app"]
		i.Mounts = append(i.Mounts, runtime.Mount{Type: "bind", Source: "/", Destination: "/host", RW: true})
		f.rt.Infos["c-app"] = i
		f.rt.Unlock()
		f.api.CheckStarted(context.Background(), "c-app", "portcullis-app")
		if q := f.api.Quarantined(); !strings.Contains(q["app"], "which its bundle doesn't") {
			t.Errorf("quarantine %v", q)
		}
	})
	t.Run("down retried, quarantine persisted", func(t *testing.T) {
		f := backstopFixture(t)
		f.rt.downFails.Store(2)
		os.Symlink(t.TempDir(), filepath.Join(f.root, "real", "sub"))
		f.api.CheckStarted(context.Background(), "c-app", "portcullis-app")
		for i := 0; i < 8000 && countCalls(f, "down-by-name portcullis-app") < 3; i++ {
			time.Sleep(time.Millisecond)
		}
		if n := countCalls(f, "down-by-name portcullis-app"); n < 3 {
			t.Errorf("downs %d", n)
		}
		api2 := NewAPI(APIConfig{DataDir: f.data, BindRoots: []string{f.root}, Runtime: f.rt, Net: f.net})
		if api2.Quarantined()["app"] == "" {
			t.Error("the quarantine didn't survive a restart")
		}
	})
	t.Run("own containers (by id) and helpers ignored", func(t *testing.T) {
		f := newAPI(t)
		f.api.cfg.OwnContainers = []string{"c-agent"}
		f.api.CheckStarted(context.Background(), "c-agent", "portcullis-worker")
		f.rt.Lock()
		f.rt.Infos["c-h"] = runtime.UnitInfo{ID: "c-h", Labels: map[string]string{docker.LabelHelper: "volume_io", docker.LabelProject: "portcullis-app"}}
		f.rt.Unlock()
		f.api.CheckStarted(context.Background(), "c-h", "portcullis-app")
		if f.api.Quarantined() != nil {
			t.Errorf("quarantined %v", f.api.Quarantined())
		}
	})
}

// TestNestedBindsConcurrentPUT (review A2-M2): two PUTs that nest, at
// once: exactly one is accepted.
func TestNestedBindsConcurrentPUT(t *testing.T) {
	f := newAPI(t)
	os.MkdirAll(filepath.Join(f.root, "a", "b"), 0o755)
	var barrier sync.WaitGroup
	barrier.Add(2)
	cfg := f.api.cfg.Config
	f.api.cfg.Config = func(ctx context.Context, p compose.Project) ([]byte, error) {
		barrier.Done()
		done := make(chan struct{})
		go func() { barrier.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(300 * time.Millisecond): // the global lock serialises them
		}
		return cfg(ctx, p)
	}
	codes := make(chan int, 2)
	for id, src := range map[string]string{"one": f.root + "/a:/x", "two": f.root + "/a/b:/y:ro"} {
		go func() {
			c, _ := f.putFor(t, id, map[string]string{BundleCompose: bindCompose(src)})
			codes <- c
		}()
	}
	got := map[int]int{}
	for i := 0; i < 2; i++ {
		got[<-codes]++
	}
	if got[204] != 1 || got[400] != 1 {
		t.Errorf("codes %v", got)
	}
}

// TestNestedBindsEdges (review B2-L7): segment boundaries, unclean
// sources, disabled services.
func TestNestedBindsEdges(t *testing.T) {
	f := newAPI(t)
	for _, d := range []string{"a/b", "ab"} {
		os.MkdirAll(filepath.Join(f.root, d), 0o755)
	}
	if c, b := f.putFor(t, "one", map[string]string{BundleCompose: bindCompose(f.root + "/a:/x")}); c != 204 {
		t.Fatalf("%d %s", c, b)
	}
	if c, b := f.putFor(t, "two", map[string]string{BundleCompose: bindCompose(f.root + "/ab:/x")}); c != 204 {
		t.Errorf("/ab beside /a: %d %s", c, b)
	}
	for name, compose := range map[string]string{
		"unclean":  bindCompose(f.root + "/a/./b/:/x"),
		"disabled": "services:\n  off:\n    image: x\n    profiles: [never]\n    volumes: [\"" + f.root + "/a/b:/x\"]\n",
	} {
		if c, b := f.putFor(t, "three", map[string]string{BundleCompose: compose}); c != 400 || !strings.Contains(b, "may not nest") {
			t.Errorf("%s: %d %s", name, c, b)
		}
	}
}

// TestProtectedAncestorAtBindTime (review A2-M3): a bind source whose
// ancestor is the same directory as a protected one (an alias the text
// compare can't see) is refused.
func TestProtectedAncestorAtBindTime(t *testing.T) {
	f := newAPI(t)
	prot := filepath.Join(f.root, "..", "protected-install")
	prot, _ = filepath.Abs(prot)
	os.MkdirAll(filepath.Join(prot, "x"), 0o755)
	f.api.cfg.Protected = append(f.api.cfg.Protected, prot)
	// The alias: a hard-to-see second path to it (a symlink stands in
	// for a bind mount, which needs root).
	alias := filepath.Join(f.root, "alias")
	os.Symlink(prot, alias)
	if err := f.api.protectedAncestor(alias + "/x"); err == nil {
		t.Error("an alias of a protected dir passed")
	}
	if err := f.api.protectedAncestor(f.root + "/photos"); err != nil {
		t.Errorf("a plain source: %v", err)
	}
}

// TestBackstopKillsBeforeDown (review B2-L8): the kill is synchronous,
// the down in the background: two violating starts are both killed at once.
func TestBackstopKillsBeforeDown(t *testing.T) {
	f := newAPI(t)
	f.rt.downFails.Store(1000) // the downs keep failing
	start := time.Now()
	f.api.CheckStarted(context.Background(), "c-1", "portcullis-x1")
	f.api.CheckStarted(context.Background(), "c-2", "portcullis-x2")
	if time.Since(start) > time.Second || countCalls(f, "signal c-1 KILL") != 1 || countCalls(f, "signal c-2 KILL") != 1 {
		t.Errorf("%s %v", time.Since(start), f.rt.Calls())
	}
}

// TestCheckVisible (review A2-M3): the install dir and the engine's data
// root must be visible to the agent; a missing or empty one refuses.
func TestCheckVisible(t *testing.T) {
	d := t.TempDir()
	if err := CheckVisible(d, d); err != nil {
		t.Errorf("visible: %v", err)
	}
	for _, bad := range []string{"", filepath.Join(d, "absent")} {
		if err := CheckVisible(d, bad); err == nil || !strings.Contains(err.Error(), "isn't visible to the agent") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// TestOwnContainersByID (fix round 3 review): the backstop exempts the
// agent's own containers by id only — an instance whose project is the
// agent's own name gets no pass — and a bundle of that id is refused.
func TestOwnContainersByID(t *testing.T) {
	f := newAPI(t)
	f.api.cfg.OwnProject = "portcullis-worker"
	f.api.cfg.OwnContainers = []string{"c-agent"}
	f.api.CheckStarted(context.Background(), "c-agent", "portcullis-worker")
	if f.api.Quarantined() != nil {
		t.Fatalf("the agent's own container was acted on: %v", f.rt.Calls())
	}
	// Another container in that project (no bundle): stopped.
	f.api.CheckStarted(context.Background(), "c-intruder", "portcullis-worker")
	waitCall(t, f, "down-by-name portcullis-worker")
	if countCalls(f, "signal c-intruder KILL") != 1 {
		t.Errorf("calls %v", f.rt.Calls())
	}
	c, b := f.putFor(t, "worker", map[string]string{BundleCompose: "services:\n  web:\n    image: x\n"})
	if c != 400 || !strings.Contains(b, "reserved") {
		t.Errorf("bundle of the reserved id: %d %s", c, b)
	}
}
