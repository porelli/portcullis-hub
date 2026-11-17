package hub

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"regexp"
	"sync"
	"testing"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
	"github.com/portcullis/hub/internal/workertest"
)

// realWorker is a worker as the Hub's placement, move and server tests
// see it (final review structural guard): the real Hub-side backend
// (internal/runtime/agent) pinned to a real portcullis-agent in process
// (internal/workertest) with an in-memory engine. The knobs the tests set
// are faults injected at the HTTP layer (the agent's real error shape) or
// at the engine — never a different answer than the agent's.
type realWorker struct {
	*agentrt.Backend
	wt  *workertest.Worker
	eng *runtimetest.Fake

	mu sync.Mutex
	// info: the engine facts the agent's Info returns (the agent fills
	// its own fields: version, runtime, bind roots, quarantine, clock).
	info    agentapi.Info
	infoErr error
	// pullErr fails the engine's next pulls; pushErr makes the agent
	// refuse the next bundle (400 with its text); removeErrs / downErrs
	// fail the next project removals / downs (409); pushHook runs at
	// each push.
	pullErr    error
	pushErr    error
	removeErrs int
	downErrs   int
	pushHook   func()
	bundles    []map[string]string
}

// newRealWorker starts the worker (o's zero values: the defaults).
func newRealWorker(t testing.TB, o workertest.Opts) *realWorker {
	t.Helper()
	w := &realWorker{info: agentapi.Info{Arch: "amd64", DockerRootDir: "/var/lib/docker", UnprivilegedPortStart: 1024, CPUs: 4, MemBytes: 8 << 30,
		DiskTotal: 1 << 40, DiskFree: 1 << 39, EngineVersion: "29.0", EngineAPI: "1.45"}}
	o.Info = func(context.Context) (agentapi.Info, error) {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.info, w.infoErr
	}
	w.wt = workertest.NewWorker(t, o)
	w.eng = w.wt.Engine
	w.Backend, _ = w.wt.Backend(nil)
	return w
}

// Calls are the engine's calls, plus the agent-level events the tests
// order on ("signal bundle <id>", "signal remove-project <id>",
// "signal unquarantine <id>").
func (w *realWorker) Calls() []string { return w.eng.Calls() }
func (w *realWorker) Lock()           { w.eng.Lock() }
func (w *realWorker) Unlock()         { w.eng.Unlock() }

// holds: the agent holds a bundle of id.
func (w *realWorker) holds(id string) bool { return w.wt.API.HoldsForTest(id) }

// quarantine / quarantineAll set the agent's own quarantine.
func (w *realWorker) quarantine(id, why string) { w.wt.API.QuarantineForTest(id, why) }
func (w *realWorker) quarantineAll(why string)  { w.wt.API.QuarantineAllForTest(why) }

// take returns a counter knob's next failure (and counts it down).
func take(n *int) bool {
	if *n > 0 {
		*n--
		return true
	}
	return false
}

func (w *realWorker) PushBundle(ctx context.Context, id string, files fs.FS, m agentapi.BundleManifest) error {
	w.mu.Lock()
	hook, perr := w.pushHook, w.pushErr
	w.mu.Unlock()
	if hook != nil {
		hook()
	}
	if perr != nil {
		w.wt.Fail(`^PUT /v1/projects/`+regexp.QuoteMeta(id)+`/bundle$`, 1, http.StatusBadRequest, perr.Error())
	}
	if err := w.Backend.PushBundle(ctx, id, files, m); err != nil {
		return err
	}
	got := map[string]string{}
	for n := range m.Files {
		f, err := files.Open(n)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(f)
		f.Close()
		got[n] = string(b)
	}
	w.mu.Lock()
	w.bundles = append(w.bundles, got)
	w.mu.Unlock()
	w.eng.Signal(context.Background(), "bundle", id) // recorded in order
	return nil
}

func (w *realWorker) RemoveProject(ctx context.Context, id string) error {
	w.mu.Lock()
	fail := take(&w.removeErrs)
	w.mu.Unlock()
	if fail {
		w.wt.Fail(`^DELETE /v1/projects/`+regexp.QuoteMeta(id)+`$`, 1, http.StatusConflict, "the worker refused the removal")
	}
	if err := w.Backend.RemoveProject(ctx, id); err != nil {
		return err
	}
	w.eng.Signal(context.Background(), "remove-project", id)
	return nil
}

func (w *realWorker) Down(ctx context.Context, p runtime.Project) error {
	w.mu.Lock()
	fail := take(&w.downErrs)
	w.mu.Unlock()
	if fail {
		w.wt.Fail(`^POST /v1/projects/`+regexp.QuoteMeta(p.Instance)+`/down$`, 1, http.StatusConflict, "the worker's down failed")
	}
	return w.Backend.Down(ctx, p)
}

func (w *realWorker) Unquarantine(ctx context.Context, id string) error {
	if err := w.Backend.Unquarantine(ctx, id); err != nil {
		return err
	}
	w.eng.Signal(context.Background(), "unquarantine", id)
	return nil
}

// pull applies pullErr at the engine for ref's next pull.
func (w *realWorker) pull(ref string) func() {
	w.mu.Lock()
	perr := w.pullErr
	w.mu.Unlock()
	if perr == nil {
		return func() {}
	}
	w.eng.Lock()
	if w.eng.ErrOn == nil {
		w.eng.ErrOn = map[string]error{}
	}
	w.eng.ErrOn["pull "+ref] = perr
	w.eng.Unlock()
	return func() {
		w.eng.Lock()
		delete(w.eng.ErrOn, "pull "+ref)
		w.eng.Unlock()
	}
}

func (w *realWorker) Pull(ctx context.Context, ref string, fn func(int64, int64, bool)) error {
	defer w.pull(ref)()
	return w.Backend.Pull(ctx, ref, fn)
}

func (w *realWorker) PreflightPull(ctx context.Context, ref string) error {
	defer w.pull(ref)()
	return w.Backend.PreflightPull(ctx, ref)
}

func (w *realWorker) lastBundle() map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.bundles) == 0 {
		return nil
	}
	return w.bundles[len(w.bundles)-1]
}

// agentErr: err is an agent error with status.
func agentErr(err error, status int) bool {
	var ae *agentrt.Error
	return errors.As(err, &ae) && ae.Status == status
}
