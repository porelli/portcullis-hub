package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"testing"
	"testing/fstest"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
	"github.com/portcullis/hub/internal/workertest"
)

// The worker conformance suite (final review structural guard): one
// table of cases, each the real agent's answer, run against the real
// backend + agent (realWorker) and against the method-level fake
// (workerFake) the folder tests still use — a fake behaviour the agent
// doesn't share fails CI.

// conformTarget is the Hub-facing worker under test and its engine.
type conformTarget interface {
	runtime.Instances
	PushBundle(ctx context.Context, id string, files fs.FS, m agentapi.BundleManifest) error
	RemoveProject(ctx context.Context, id string) error
	engine() *runtimetest.Fake
}

func (w *realWorker) engine() *runtimetest.Fake { return w.eng }
func (w *workerFake) engine() *runtimetest.Fake { return w.Fake }

const conformCompose = "services:\n  web:\n    image: x:1@sha256:1111111111111111111111111111111111111111111111111111111111111111\n"

func conformBundle(id, tmpl string, withCompose bool) (fs.FS, agentapi.BundleManifest) {
	files := fstest.MapFS{}
	if withCompose {
		files["compose.yml"] = &fstest.MapFile{Data: []byte(conformCompose), Mode: 0o644}
	} else {
		files["env"] = &fstest.MapFile{Data: []byte("A=1\n"), Mode: 0o600}
	}
	m := agentapi.BundleManifest{Instance: id, Template: tmpl, Files: map[string]agentapi.FileEntry{}}
	for n, f := range files {
		s := sha256.Sum256(f.Data)
		m.Files[n] = agentapi.FileEntry{SHA256: hex.EncodeToString(s[:]), Mode: uint32(f.Mode), Size: int64(len(f.Data))}
	}
	return files, m
}

func status(err error) int {
	var ae *agentrt.Error
	if errors.As(err, &ae) {
		return ae.Status
	}
	if err == nil {
		return 0
	}
	return -1
}

var conformCases = []struct {
	name string
	run  func(t *testing.T, w conformTarget)
}{
	{"bundle refusals (no template id, no compose.yml)", func(t *testing.T, w conformTarget) {
		f, m := conformBundle("app", "", true)
		if err := w.PushBundle(context.Background(), "app", f, m); err == nil {
			t.Error("a bundle without a template id taken")
		}
		f, m = conformBundle("app", "app", false)
		if err := w.PushBundle(context.Background(), "app", f, m); err == nil {
			t.Error("a bundle without compose.yml taken")
		}
	}},
	{"remove a project twice: the second is 404", func(t *testing.T, w conformTarget) {
		f, m := conformBundle("app", "app", true)
		if err := w.PushBundle(context.Background(), "app", f, m); err != nil {
			t.Fatal(err)
		}
		if err := w.RemoveProject(context.Background(), "app"); err != nil {
			t.Fatal(err)
		}
		if err := w.RemoveProject(context.Background(), "app"); status(err) != http.StatusNotFound || !docker.IsNotFound(err) {
			t.Errorf("second removal: %v", err)
		}
	}},
	{"remove with containers left: 409", func(t *testing.T, w conformTarget) {
		f, m := conformBundle("app", "app", true)
		if err := w.PushBundle(context.Background(), "app", f, m); err != nil {
			t.Fatal(err)
		}
		e := w.engine()
		e.Lock()
		e.Units = append(e.Units, runtime.Unit{ID: "c1", Project: "portcullis-app", Instance: "app", Service: "web", State: "exited",
			Labels: map[string]string{docker.LabelProject: "portcullis-app", docker.LabelService: "web"}})
		e.Unlock()
		if err := w.RemoveProject(context.Background(), "app"); status(err) != http.StatusConflict {
			t.Errorf("removal with a container: %v", err)
		}
	}},
	{"down / down-by-name / create / list of a never-held id: 404", func(t *testing.T, w conformTarget) {
		p := runtime.Project{Name: "portcullis-ghost", Instance: "ghost"}
		if err := w.Down(context.Background(), p); status(err) != http.StatusNotFound {
			t.Errorf("down: %v", err)
		}
		if err := w.DownByName(context.Background(), "portcullis-ghost"); status(err) != http.StatusNotFound {
			t.Errorf("down-by-name: %v", err)
		}
		if err := w.Create(context.Background(), p); status(err) != http.StatusNotFound {
			t.Errorf("create: %v", err)
		}
		if _, err := w.List(context.Background(), runtime.Filter{Instance: "ghost"}); status(err) != http.StatusNotFound {
			t.Errorf("list: %v", err)
		}
	}},
	{"a down after the removal (tombstone): done", func(t *testing.T, w conformTarget) {
		f, m := conformBundle("app", "app", true)
		if err := w.PushBundle(context.Background(), "app", f, m); err != nil {
			t.Fatal(err)
		}
		if err := w.RemoveProject(context.Background(), "app"); err != nil {
			t.Fatal(err)
		}
		if err := w.Down(context.Background(), runtime.Project{Name: "portcullis-app", Instance: "app"}); err != nil {
			t.Errorf("down of a tombstoned id: %v", err)
		}
	}},
	{"an exec this agent didn't start: not found", func(t *testing.T, w conformTarget) {
		if _, err := w.ExecRunning(context.Background(), "never-started"); !docker.IsNotFound(err) {
			t.Errorf("%v", err)
		}
	}},
}

func TestWorkerConformanceReal(t *testing.T) {
	for _, c := range conformCases {
		t.Run(c.name, func(t *testing.T) { c.run(t, newRealWorker(t, workertest.Opts{})) })
	}
}

func TestWorkerConformanceFake(t *testing.T) {
	for _, c := range conformCases {
		t.Run(c.name, func(t *testing.T) {
			c.run(t, &workerFake{Fake: &runtimetest.Fake{Infos: map[string]runtime.UnitInfo{}, Volumes: map[string]runtime.Volume{}, States: map[string]runtime.State{}}})
		})
	}
}
