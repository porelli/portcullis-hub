package hub

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
)

const webImage = "grafana/grafana:12@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// progressCompose: web (pinned), db (its image from the env's default),
// an init one-shot on web's image (pulled once), a pull_policy never service
// (left to compose).
const progressCompose = "services:\n" +
	"  web:\n    image: " + webImage + "\n    environment:\n      GF_THEME: ${GF_THEME:-dark}\n    labels:\n      traefik.http.routers.grafana.rule: Host(`grafana.${PORTCULLIS_DOMAIN:-x}`)\n      traefik.http.routers.grafana.entrypoints: websecure\n" +
	"  db:\n    image: ${DB_IMAGE:-postgres:17}\n" +
	"  init:\n    image: " + webImage + "\n    restart: \"no\"\n" +
	"  tools:\n    image: busybox:1\n    pull_policy: never\n"

func startSteps() []Step {
	return []Step{
		{Key: StepImages, Label: "Downloading images"},
		{Key: StepCreate, Label: "Creating"},
		{Key: StepStart, Label: "Starting services"},
		{Key: StepHealthy, Label: "Waiting until healthy"},
	}
}

// progressFixture: grafana on progressCompose; compose's create makes
// the three containers, its up starts them (init runs and exits 0); web
// reports health "starting" twice, then healthy. The progress clock
// moves a second per reading, so no percent is held back.
func progressFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	writeFile(t, filepath.Join(f.src, "grafana", "compose.yml"), progressCompose)
	f.h.Discover()
	if f.h.Template("grafana") == nil {
		t.Fatal("grafana not discovered")
	}
	clk := &testClock{t: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)}
	f.h.progressNow = func() time.Time { clk.add(time.Second); return clk.now() }
	withReadyWait(t, 5*time.Second, 5*time.Millisecond)
	proj := projectName("grafana")
	f.runner.createHook = func(string) {
		f.engine.mu.Lock()
		f.engine.containers = []docker.Container{
			container("w1", proj, "web", "created"), container("d1", proj, "db", "created"), container("i1", proj, "init", "created"),
		}
		f.engine.mu.Unlock()
	}
	f.runner.upHook = func(string) {
		f.engine.mu.Lock()
		for i := range f.engine.containers {
			c := &f.engine.containers[i]
			c.State = "running"
			if c.Service() == "init" {
				c.State = "exited"
			}
		}
		f.engine.mu.Unlock()
	}
	var mu sync.Mutex
	starting := 2
	f.engine.stateHook = func(id string, st docker.State) docker.State {
		mu.Lock()
		defer mu.Unlock()
		if id == "w1" && st.Running {
			st.Health = "healthy"
			if starting > 0 {
				starting--
				st.Health = "starting"
			}
		}
		return st
	}
	return f
}

// acceptedProgress is a reporter for op on id, accepted (written).
func acceptedProgress(f *fixture, id string) (*Progress, context.Context) {
	p := f.h.newProgress(id, OpEnable, startSteps())
	p.begin("op1", "admin", nil)
	return p, withProgress(context.Background(), p)
}

// TestStartUpReportsSteps: with a reporter, startUp downloads every image
// compose would pull before create (percent = bytes over all images,
// one detail entry per image), then reports create, start and healthy
// in that order, each ending done at 100 %.
func TestStartUpReportsSteps(t *testing.T) {
	f := progressFixture(t)
	var mid []Step
	f.engine.pullFn = func(ctx context.Context, ref string, onBytes func(done, total int64)) error {
		if ref != webImage {
			return nil // postgres:17 is present
		}
		onBytes(0, 690_000_000)
		onBytes(312_000_000, 690_000_000)
		if r := f.h.LastOp("grafana"); r != nil {
			mid = append(mid, stepOf(*r, StepImages))
		}
		onBytes(690_000_000, 690_000_000)
		return nil
	}
	_, ctx := acceptedProgress(f, "grafana")
	if err := f.h.composeUp(ctx, f.h.Template("grafana")); err != nil {
		t.Fatal(err)
	}
	pulls := f.engine.Pulls()
	slices.Sort(pulls)
	if !slices.Equal(pulls, []string{webImage, "postgres:17"}) {
		t.Fatalf("pulls = %v (busybox is pull_policy never: left to compose)", pulls)
	}
	if len(f.runner.Creates()) != 1 {
		t.Fatalf("creates = %v", f.runner.Creates())
	}
	if len(mid) != 1 || mid[0].State != StepRunning || mid[0].Percent == nil || *mid[0].Percent != 45 ||
		!strings.Contains(mid[0].Detail, "grafana/grafana:12 — 312 of 690 MB") || strings.Contains(mid[0].Detail, "sha256") {
		t.Fatalf("images while downloading: %+v", mid)
	}
	r := opFile(t, f.h, "grafana")
	var prev *time.Time
	for _, key := range []string{StepImages, StepCreate, StepStart, StepHealthy} {
		s := stepOf(r, key)
		if s.State != StepDone || s.StartedAt == nil || s.EndedAt == nil {
			t.Fatalf("%s: %+v", key, s)
		}
		if prev != nil && s.StartedAt.Before(*prev) {
			t.Fatalf("%s started before the step ahead of it ended: %+v", key, r.Steps)
		}
		prev = s.EndedAt
		if key != StepCreate && (s.Percent == nil || *s.Percent != 100) {
			t.Fatalf("%s percent: %+v", key, s)
		}
	}
	if s := stepOf(r, StepImages); s.Detail != "grafana/grafana:12 — done; postgres:17 — done" {
		t.Fatalf("images detail %q", s.Detail)
	}
	if s := stepOf(r, StepStart); s.Detail != "Starting services (3 of 3)" {
		t.Fatalf("start detail %q", s.Detail)
	}
	if s := stepOf(r, StepHealthy); s.Detail != "Waiting until healthy (3 of 3)" {
		t.Fatalf("healthy detail %q", s.Detail)
	}
}

// Without a reporter startUp is as before: no pull of its own, no wait.
func TestStartUpNoReporterUnchanged(t *testing.T) {
	f := progressFixture(t)
	if err := f.h.composeUp(context.Background(), f.h.Template("grafana")); err != nil {
		t.Fatal(err)
	}
	if p := f.engine.Pulls(); len(p) != 0 {
		t.Fatalf("pulled %v without a reporter", p)
	}
	if len(f.runner.Creates()) != 1 || !slices.Contains(f.runner.Calls(), "up:"+projectName("grafana")) {
		t.Fatalf("creates %v calls %v", f.runner.Creates(), f.runner.Calls())
	}
}

// A failed download is left to compose's create (logged, never an
// error); health that never comes fails only the healthy step.
func TestStartUpPullFailsAndUnhealthy(t *testing.T) {
	f := progressFixture(t)
	withReadyWait(t, 20*time.Millisecond, 5*time.Millisecond)
	f.engine.pullFn = func(ctx context.Context, ref string, onBytes func(done, total int64)) error {
		if ref == webImage {
			return fmt.Errorf("pull %s: unauthorized", ref)
		}
		return nil
	}
	f.engine.stateHook = func(id string, st docker.State) docker.State {
		if id == "d1" && st.Running {
			st.Health = "unhealthy"
		}
		return st
	}
	_, ctx := acceptedProgress(f, "grafana")
	if err := f.h.composeUp(ctx, f.h.Template("grafana")); err != nil {
		t.Fatal(err)
	}
	r := opFile(t, f.h, "grafana")
	if s := stepOf(r, StepImages); s.State != StepDone || s.Detail != "grafana/grafana:12 — left to compose; postgres:17 — done" {
		t.Fatalf("images: %+v", s)
	}
	if s := stepOf(r, StepHealthy); s.State != StepFailed || !strings.Contains(s.Detail, "2 of 3 services healthy") || !strings.Contains(s.Detail, "db unhealthy") {
		t.Fatalf("healthy: %+v", s)
	}
	if len(f.runner.Creates()) != 1 || !slices.Contains(f.runner.Calls(), "up:"+projectName("grafana")) {
		t.Fatalf("creates %v calls %v", f.runner.Creates(), f.runner.Calls())
	}
}

// TestPullCancelled: a Stop during the download stops the pull, the
// images step ends stopped, nothing is created, and the operation ends
// stopped (startUp's error is a stop error).
func TestPullCancelled(t *testing.T) {
	f := progressFixture(t)
	pulling := make(chan struct{})
	pullErr := make(chan error, 1)
	f.engine.pullFn = func(ctx context.Context, ref string, onBytes func(done, total int64)) error {
		if ref != webImage {
			return nil
		}
		onBytes(1_000_000, 690_000_000)
		close(pulling)
		<-ctx.Done() // a download that only a Stop ends
		err := fmt.Errorf("pull %s: %w", ref, ctx.Err())
		pullErr <- err
		return err
	}
	var upErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, upErr = f.h.runOpSync("grafana", OpEnable, directory.Human("admin"), startSteps(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
			ready()
			return nil, nil, f.h.composeUp(ctx, f.h.Template("grafana"))
		})
	}()
	select {
	case <-pulling:
	case <-time.After(5 * time.Second):
		t.Fatal("the pull never started")
	}
	if err := f.h.cancelOp("grafana", directory.Human("admin")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startUp did not return after the Stop")
	}
	if err := <-pullErr; !isStopErr(err) {
		t.Fatalf("pull ended with %v", err)
	}
	if !isStopErr(upErr) {
		t.Fatalf("startUp = %v, want a stop error", upErr)
	}
	if c := f.runner.Creates(); len(c) != 0 {
		t.Fatalf("created after a Stop: %v", c)
	}
	r := opFile(t, f.h, "grafana")
	if s := stepOf(r, StepImages); s.State != StepStopped {
		t.Fatalf("images: %+v", s)
	}
	if s := stepOf(r, StepCreate); s.State != StepWaiting {
		t.Fatalf("create: %+v", s)
	}
	if r.Running || r.OK || r.Error != "" || r.StoppedBy != "admin" {
		t.Fatalf("record: %+v", r)
	}
}
