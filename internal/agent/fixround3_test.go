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
		f.addInfo("c-x", "portcullis-ghost")
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
	f.addInfo("c-1", "portcullis-x1")
	f.addInfo("c-2", "portcullis-x2")
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

// TestOwnContainersByID (fix rounds 3–4, R3-M1): the backstop never acts
// on the agent's own compose project — a recreated sidecar or a compose
// run there is left alone, nothing is quarantined, nothing taken down —
// and a bundle whose id maps there is refused. A portcullis-x container
// with no bundle is still taken down.
func TestOwnContainersByID(t *testing.T) {
	f := newAPI(t)
	f.api.cfg.OwnProject = "portcullis-worker"
	f.api.cfg.OwnContainers = []string{"c-agent"}
	f.addInfo("c-agent", "portcullis-worker")
	f.addInfo("c-sidecar-recreated", "portcullis-worker")
	f.api.CheckStarted(context.Background(), "c-agent", "portcullis-worker")
	f.api.CheckStarted(context.Background(), "c-sidecar-recreated", "portcullis-worker")
	f.api.CheckStarted(context.Background(), "c-compose-run", "")
	f.rt.Lock()
	f.rt.Infos["c-compose-run"] = runtime.UnitInfo{ID: "c-compose-run", Labels: map[string]string{docker.LabelProject: "portcullis-worker"}}
	f.rt.Unlock()
	f.api.CheckStarted(context.Background(), "c-compose-run", "")
	time.Sleep(50 * time.Millisecond)
	if f.api.Quarantined() != nil || countCalls(f, "down-by-name portcullis-worker") != 0 || countCalls(f, "signal c-sidecar-recreated KILL") != 0 {
		t.Fatalf("the agent's own project was acted on: %v %v", f.rt.Calls(), f.api.Quarantined())
	}
	f.addInfo("c-x", "portcullis-x")
	f.api.CheckStarted(context.Background(), "c-x", "portcullis-x")
	waitCall(t, f, "down-by-name portcullis-x")
	c, b := f.putFor(t, "worker", map[string]string{BundleCompose: "services:\n  web:\n    image: x\n"})
	if c != 400 || !strings.Contains(b, "reserved") {
		t.Errorf("bundle of the reserved id: %d %s", c, b)
	}
}

// TestLiftWithoutBundle (R3-M2): a quarantine with no bundle held is
// lifted (nothing runs); the Hub's next push must be accepted, or the
// instance is quarantined again.
func TestLiftWithoutBundle(t *testing.T) {
	f := newAPI(t)
	f.api.quarantine("ghost", "a container of an instance the agent holds no valid bundle for")
	if c := f.code(t, "DELETE", "/v1/projects/ghost/quarantine", nil); c != 204 {
		t.Fatalf("lift: %d", c)
	}
	if f.api.Quarantined() != nil {
		t.Fatal("still quarantined")
	}
	// The push after the lift is refused (a nested bind? here: include).
	if c, _ := f.putFor(t, "ghost", map[string]string{BundleCompose: "include: [/x.yml]\nservices:\n  web:\n    image: x\n"}); c != 400 {
		t.Fatalf("push: %d", c)
	}
	if f.api.Quarantined()["ghost"] == "" {
		t.Error("a refused push after the lift didn't quarantine again")
	}
	// Lifted again, an accepted push completes it.
	f.code(t, "DELETE", "/v1/projects/ghost/quarantine", nil)
	if c, b := f.putFor(t, "ghost", map[string]string{BundleCompose: "services:\n  web:\n    image: x\n"}); c != 204 {
		t.Fatalf("good push: %d %s", c, b)
	}
	if f.api.Quarantined() != nil {
		t.Errorf("quarantined after a good push: %v", f.api.Quarantined())
	}
}

// TestQuarantineFailsClosed (R3-L2): an unreadable quarantine.json makes
// every instance quarantined (starts refused, running units killed)
// until repaired; a failed save is reported.
func TestQuarantineFailsClosed(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app")
	os.WriteFile(filepath.Join(f.data, "quarantine.json"), []byte("{not json"), 0o600)
	api2 := NewAPI(APIConfig{DataDir: f.data, BindRoots: []string{f.root}, Runtime: f.rt, Net: f.net, Config: f.api.cfg.Config})
	if q := api2.Quarantined(); q[QuarantineAllKey] == "" {
		t.Fatalf("quarantine %v", q)
	}
	if api2.quarantineOf("app") == "" {
		t.Error("app not quarantined")
	}
	f.rt.Lock()
	f.rt.Infos["c-app"] = runtime.UnitInfo{ID: "c-app", Labels: map[string]string{docker.LabelProject: "portcullis-app"}}
	f.rt.Unlock()
	api2.CheckStarted(context.Background(), "c-app", "portcullis-app")
	waitCall(t, f, "signal c-app KILL")
	// Repaired: the next sweep reads it again.
	os.WriteFile(filepath.Join(f.data, "quarantine.json"), []byte("{}"), 0o600)
	api2.Sweep(context.Background())
	if q := api2.Quarantined(); q[QuarantineAllKey] != "" {
		t.Errorf("still all quarantined: %v", q)
	}
	// A failed save is reported.
	os.Remove(filepath.Join(f.data, "quarantine.json"))
	os.Mkdir(filepath.Join(f.data, "quarantine.json"), 0o700) // a directory: the rename fails
	api2.quarantine("app", "x")
	if api2.QuarantineError() == "" || api2.quarantineOf("app") == "" {
		t.Errorf("save error %q", api2.QuarantineError())
	}
}

// TestOneDownWorkerPerID (R3-L3): repeated violations of one id start a
// single down worker.
func TestOneDownWorkerPerID(t *testing.T) {
	f := newAPI(t)
	f.rt.downFails.Store(1000)
	f.addInfo("c-g", "portcullis-ghost")
	for i := 0; i < 5; i++ {
		f.api.CheckStarted(context.Background(), "c-g", "portcullis-ghost")
	}
	time.Sleep(1500 * time.Millisecond)
	if n := countCalls(f, "down-by-name portcullis-ghost"); n > 2 {
		t.Errorf("%d downs: the workers piled up", n)
	}
}

// TestSelfIdentity (R4-L1): the agent's own container comes from its id
// (env or the kernel's view), never a hostname; the container found must
// be that id with the agent's service label; its names are reserved.
func TestSelfIdentity(t *testing.T) {
	id := strings.Repeat("ab", 32)
	mi := "123 45 0:1 /var/lib/docker/containers/" + id + "/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n"
	if got, err := containerIDFrom(strings.NewReader(mi)); err != nil || got != id {
		t.Errorf("mountinfo: %q %v", got, err)
	}
	other := strings.Repeat("cd", 32)
	if _, err := containerIDFrom(strings.NewReader(mi + "1 2 0:1 /var/lib/docker/containers/" + other + "/hosts /etc/hosts rw\n")); err == nil {
		t.Error("two ids accepted")
	}
	if got, _ := SelfContainerID(func(k string) string {
		if k == "AGENT_CONTAINER_ID" {
			return id
		}
		return ""
	}, "/nonexistent"); got != id {
		t.Errorf("env: %q", got)
	}
	f := newAPI(t)
	f.rt.Lock()
	f.rt.Infos[id] = runtime.UnitInfo{ID: id, Image: "sha256:agent", Labels: map[string]string{"com.docker.compose.service": "agent", "com.docker.compose.project": "portcullis-worker", SelfImageLabel: "1"}}
	f.rt.Infos["spoof"] = runtime.UnitInfo{ID: other, Labels: map[string]string{"com.docker.compose.service": "web"}}
	noImg := strings.Repeat("ef", 32)
	f.rt.Infos[noImg] = runtime.UnitInfo{ID: noImg, Labels: map[string]string{"com.docker.compose.service": "agent"}}
	f.rt.Unlock()
	if _, err := VerifySelf(context.Background(), f.rt, id, "agent", ""); err != nil {
		t.Errorf("verify: %v", err)
	}
	if _, err := VerifySelf(context.Background(), f.rt, id, "agent", "sha256:agent"); err != nil {
		t.Errorf("verify with AGENT_SELF_IMAGE_ID: %v", err)
	}
	for name, c := range map[string]struct{ id, service, image string }{
		"wrong service":       {id, "web", ""},
		"wrong image":         {id, "agent", "sha256:other"},
		"not the agent image": {noImg, "agent", ""},
		"unknown id":          {strings.Repeat("01", 32), "agent", ""},
	} {
		if _, err := VerifySelf(context.Background(), f.rt, c.id, c.service, c.image); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// cgroup v1 form; none found → an error, never a guess.
	if got, err := containerIDFrom(strings.NewReader("12:pids:/docker/" + id + "\n")); err != nil || got != id {
		t.Errorf("cgroup: %q %v", got, err)
	}
	if _, err := containerIDFrom(strings.NewReader("0::/\n")); err == nil {
		t.Error("no id accepted")
	}
	// The hostname resolves to another container: refused.
	if _, err := VerifySelf(context.Background(), f.rt, "spoof", "agent", ""); err == nil {
		t.Error("a container with another id accepted")
	}
	// Its names are reserved for bundles.
	f.api.cfg.ReservedNames = []string{"portcullis-worker-agent-1", id[:12]}
	c, b := f.putFor(t, "app", map[string]string{BundleCompose: "services:\n  web:\n    image: x\n    container_name: " + id[:12] + "\n"})
	if c != 400 || !strings.Contains(b, "the agent's own") {
		t.Errorf("container_name of the agent: %d %s", c, b)
	}
}

// TestInspectNotFoundIgnored (R4-L2, commit review): a container gone
// between the list and the inspect (typed not-found, twice) is ignored
// only for an instance with a valid, unquarantined bundle; with no bundle
// or a quarantine its project goes down (and is or stays quarantined).
func TestInspectNotFoundIgnored(t *testing.T) {
	f := backstopFixture(t)
	f.rt.Lock()
	delete(f.rt.Infos, "c-app")
	f.rt.Unlock()
	f.api.CheckStarted(context.Background(), "c-app", "portcullis-app")
	time.Sleep(20 * time.Millisecond)
	if f.api.Quarantined() != nil || countCalls(f, "down-by-name portcullis-app") != 0 {
		t.Errorf("acted on a gone container: %v %v", f.api.Quarantined(), f.rt.Calls())
	}
	// No bundle for its project: fail closed (its siblings may run).
	f.api.CheckStarted(context.Background(), "c-ghost", "portcullis-ghost")
	waitCall(t, f, "down-by-name portcullis-ghost")
	if f.api.Quarantined()["ghost"] == "" {
		t.Errorf("no bundle: not quarantined %v", f.api.Quarantined())
	}
	// Quarantined: it stays so and goes down again.
	f.api.quarantine("app", "an earlier violation")
	f.api.CheckStarted(context.Background(), "c-app", "portcullis-app")
	waitCall(t, f, "down-by-name portcullis-app")
	if f.api.Quarantined()["app"] != "an earlier violation" {
		t.Errorf("quarantined: %v", f.api.Quarantined())
	}
	if countCalls(f, "signal c-app KILL")+countCalls(f, "signal c-ghost KILL") != 0 {
		t.Errorf("killed a gone container: %v", f.rt.Calls())
	}
}

// TestLiftRacesRequarantine (R3-L1, R4-L6): a re-quarantine with the same
// text during the lift's walk survives the lift.
func TestLiftRacesRequarantine(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app")
	const why = "a container of an instance the agent holds no valid bundle for"
	f.api.quarantine("app", why)
	f.api.testWalkHook = func(id string) { f.api.quarantine(id, why) }
	if c := f.code(t, "DELETE", "/v1/projects/app/quarantine", nil); c != 204 {
		t.Fatalf("lift: %d", c)
	}
	if f.api.Quarantined()["app"] == "" {
		t.Error("the quarantine set during the lift was erased")
	}
}

// addInfo makes container c (of project) exist in the fake engine.
func (f *apiFixture) addInfo(c, project string) {
	f.rt.Lock()
	f.rt.Infos[c] = runtime.UnitInfo{ID: c, Labels: map[string]string{docker.LabelProject: project}}
	f.rt.Unlock()
}
