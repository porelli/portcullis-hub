// Package runtimetest is an in-memory runtime.Instances for tests: canned
// units, volumes and exec answers, and every call recorded in order.
package runtimetest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

// ErrNotFound is what the fake answers for an unknown unit or volume:
// typed like the engine's (errdefs.IsNotFound holds).
var ErrNotFound error = notFoundErr{}

type notFoundErr struct{}

func (notFoundErr) Error() string { return "not found" }
func (notFoundErr) NotFound()     {}

// Fake is an in-memory runtime. The zero value is a docker runtime with
// nothing in it; set the exported fields before use (or under Lock).
type Fake struct {
	mu sync.Mutex

	K        runtime.Kind
	Environ  []string
	InfoVal  runtime.Info
	InfoErr  error
	Units    []runtime.Unit
	Infos    map[string]runtime.UnitInfo
	States   map[string]runtime.State
	LogsVal  map[string][]byte
	Volumes  map[string]runtime.Volume
	Contents map[string][]byte // volume name → its tar (VolumeOut/In)
	// ExecFn answers Exec (nil: exit 0, no output); Err, if set, fails
	// every method but Kind/Env.
	ExecFn func(id string, in runtime.ExecInput) (*runtime.ExecResult, error)
	Err    error
	// Usage: Stats answers StatsVal (StatsErr first); with StatsBlock
	// set, Stats waits until it is closed (or ctx is done). LayerSizes /
	// ImageSizes answer LayerSize / ImageSize (missing: a
	// NotMeasuredError). StatsDelay delays each Stats call.
	StatsVal   map[string]runtime.UnitStats
	StatsErr   map[string]error
	StatsBlock chan struct{}
	StatsDelay time.Duration
	LayerSizes map[string]int64
	ImageSizes map[string]int64
	// FixerFn answers RunFixer (nil: exit 0, no output).
	FixerFn func(s runtime.FixerSpec) (*runtime.RunResult, error)
	// ErrOn fails a call whose record starts with a key ("pull ghcr.io/x",
	// "down portcullis-app"): fault injection at the engine.
	ErrOn map[string]error
	// DownRemovesUnits: Down / DownByName drop the project's Units (as a
	// compose down does; the real-agent harness sets it).
	DownRemovesUnits bool

	calls []string
}

var _ runtime.Instances = (*Fake)(nil)

func (f *Fake) rec(format string, a ...any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := fmt.Sprintf(format, a...)
	f.calls = append(f.calls, call)
	for k, err := range f.ErrOn {
		if strings.HasPrefix(call, k) {
			return err
		}
	}
	return f.Err
}

// dropUnits removes project's units (DownRemovesUnits).
func (f *Fake) dropUnits(project string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.DownRemovesUnits {
		return
	}
	var keep []runtime.Unit
	for _, u := range f.Units {
		if u.Project != project {
			keep = append(keep, u)
		}
	}
	f.Units = keep
}

// Calls are the calls made so far, in order ("up portcullis-x", …).
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *Fake) Kind() runtime.Kind {
	if f.K == "" {
		return runtime.KindDocker
	}
	return f.K
}

func (f *Fake) Env() []string { return f.Environ }

// SetInfo changes Info's answer (safe while the fake is in use).
func (f *Fake) SetInfo(i runtime.Info) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.InfoVal = i
}

func (f *Fake) Info(context.Context) (runtime.Info, error) {
	if err := f.rec("info"); err != nil {
		return runtime.Info{}, err
	}
	f.mu.Lock()
	i := f.InfoVal
	f.mu.Unlock()
	i.Kind = f.Kind()
	return i, f.InfoErr
}

func (f *Fake) Create(_ context.Context, p runtime.Project) error { return f.rec("create %s", p.Name) }

func (f *Fake) Up(_ context.Context, p runtime.Project, _ func(string, int64, int64, bool)) error {
	return f.rec("up %s", p.Name)
}

func (f *Fake) Down(_ context.Context, p runtime.Project) error {
	if err := f.rec("down %s", p.Name); err != nil {
		return err
	}
	f.dropUnits(p.Name)
	return nil
}

func (f *Fake) DownByName(_ context.Context, name string) error {
	if err := f.rec("down-by-name %s", name); err != nil {
		return err
	}
	f.dropUnits(name)
	return nil
}

func (f *Fake) Pull(_ context.Context, ref string, _ func(int64, int64, bool)) error {
	return f.rec("pull %s", ref)
}

func match(u runtime.Unit, flt runtime.Filter) bool {
	switch {
	case flt.Helper:
		_, ok := u.Labels["portcullis.io/helper"]
		return ok
	case flt.Instance != "":
		return u.Instance == flt.Instance && (flt.Service == "" || u.Service == flt.Service)
	case flt.All:
		return u.Project != ""
	}
	return true
}

func (f *Fake) List(_ context.Context, flt runtime.Filter) ([]runtime.Unit, error) {
	if err := f.rec("list %+v", flt); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []runtime.Unit
	for _, u := range f.Units {
		if match(u, flt) {
			out = append(out, u)
		}
	}
	return out, nil
}

func (f *Fake) Inspect(_ context.Context, id string) (runtime.UnitInfo, error) {
	if err := f.rec("inspect %s", id); err != nil {
		return runtime.UnitInfo{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if i, ok := f.Infos[id]; ok {
		return i, nil
	}
	return runtime.UnitInfo{}, ErrNotFound
}

func (f *Fake) Logs(_ context.Context, id string, _ int, _ bool) ([]byte, error) {
	if err := f.rec("logs %s", id); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.LogsVal[id], nil
}

func (f *Fake) Exec(_ context.Context, id string, in runtime.ExecInput) (*runtime.ExecResult, error) {
	if err := f.rec("exec %s %v", id, in.Cmd); err != nil {
		return nil, err
	}
	if f.ExecFn != nil {
		return f.ExecFn(id, in)
	}
	return &runtime.ExecResult{}, nil
}

func (f *Fake) ExecSplit(_ context.Context, id string, in runtime.ExecInput) (*runtime.ExecSplitResult, error) {
	if err := f.rec("exec-split %s %v", id, in.Cmd); err != nil {
		return nil, err
	}
	return &runtime.ExecSplitResult{}, nil
}

func (f *Fake) ExecRunning(_ context.Context, execID string) (bool, error) {
	return false, f.rec("exec-running %s", execID)
}

func (f *Fake) Signal(_ context.Context, id, sig string) error { return f.rec("signal %s %s", id, sig) }

func (f *Fake) RestartService(_ context.Context, project, service string, timeout time.Duration) error {
	return f.rec("restart-service %s %s %s", project, service, timeout)
}

func (f *Fake) State(_ context.Context, id string) (runtime.State, error) {
	if err := f.rec("state %s", id); err != nil {
		return runtime.State{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.States[id]; ok {
		return s, nil
	}
	for _, u := range f.Units {
		if u.ID == id {
			return runtime.State{Running: u.State == "running", Status: u.State}, nil
		}
	}
	return runtime.State{}, ErrNotFound
}

func (f *Fake) Events(ctx context.Context, flt runtime.Filter, _ func(runtime.Event)) error {
	if err := f.rec("events %+v", flt); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *Fake) ListVolumes(_ context.Context, flt runtime.Filter) ([]runtime.Volume, error) {
	if err := f.rec("volumes %+v", flt); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []runtime.Volume
	for _, v := range f.Volumes {
		if flt.Instance == "" || v.Labels["com.docker.compose.project"] == runtime.ProjectName(flt.Instance) || v.Labels["portcullis.io/instance"] == flt.Instance {
			out = append(out, v)
		}
	}
	return out, nil
}

func (f *Fake) InspectVolume(_ context.Context, name string) (runtime.Volume, error) {
	if err := f.rec("inspect-volume %s", name); err != nil {
		return runtime.Volume{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.Volumes[name]; ok {
		return v, nil
	}
	return runtime.Volume{}, ErrNotFound
}

func (f *Fake) CreateVolume(_ context.Context, v runtime.Volume) error {
	if err := f.rec("create-volume %s", v.Name); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Volumes == nil {
		f.Volumes = map[string]runtime.Volume{}
	}
	f.Volumes[v.Name] = v
	return nil
}

func (f *Fake) RemoveVolume(_ context.Context, name string) error {
	if err := f.rec("remove-volume %s", name); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.Volumes, name)
	delete(f.Contents, name)
	return nil
}

func (f *Fake) VolumeOut(_ context.Context, instance, volume, path string) (io.ReadCloser, error) {
	if err := f.rec("volume-out %s %s %s", instance, volume, path); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return io.NopCloser(bytes.NewReader(f.Contents[volume])), nil
}

func (f *Fake) VolumeIn(_ context.Context, instance, volume, path string, r io.Reader) error {
	if err := f.rec("volume-in %s %s %s", instance, volume, path); err != nil {
		return err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Contents == nil {
		f.Contents = map[string][]byte{}
	}
	f.Contents[volume] = b
	return nil
}

func (f *Fake) RemoveHelper(_ context.Context, id string) error { return f.rec("remove-helper %s", id) }

func (f *Fake) RunFixer(_ context.Context, s runtime.FixerSpec, _ func(io.Reader) error) (*runtime.RunResult, error) {
	if err := f.rec("fixer %v", s.Cmd); err != nil {
		return nil, err
	}
	f.mu.Lock()
	fn := f.FixerFn
	f.mu.Unlock()
	if fn != nil {
		return fn(s)
	}
	return &runtime.RunResult{}, nil
}

func (f *Fake) Stats(ctx context.Context, id string) (runtime.UnitStats, error) {
	if err := f.rec("stats %s", id); err != nil {
		return runtime.UnitStats{}, err
	}
	f.mu.Lock()
	block, delay := f.StatsBlock, f.StatsDelay
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return runtime.UnitStats{}, ctx.Err()
		}
	}
	if delay > 0 {
		t := time.NewTimer(delay)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return runtime.UnitStats{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.StatsErr[id]; err != nil {
		return runtime.UnitStats{}, err
	}
	if s, ok := f.StatsVal[id]; ok {
		return s, nil
	}
	return runtime.UnitStats{}, ErrNotFound
}

func (f *Fake) LayerSize(_ context.Context, id string) (int64, error) {
	if err := f.rec("layer-size %s", id); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if n, ok := f.LayerSizes[id]; ok {
		return n, nil
	}
	return 0, &runtime.NotMeasuredError{Why: "the engine didn't report a size"}
}

func (f *Fake) ImageSize(_ context.Context, ref string) (int64, error) {
	if err := f.rec("image-size %s", ref); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if n, ok := f.ImageSizes[ref]; ok {
		return n, nil
	}
	return 0, &runtime.NotMeasuredError{Why: "the engine didn't report a size"}
}

// SetStats changes one unit's stats answer (safe while the fake is in
// use).
func (f *Fake) SetStats(id string, s runtime.UnitStats) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.StatsVal == nil {
		f.StatsVal = map[string]runtime.UnitStats{}
	}
	f.StatsVal[id] = s
}

func (f *Fake) EnsureImage(_ context.Context, ref string) error { return f.rec("ensure-image %s", ref) }

// Lock / Unlock guard the exported fields while a test changes them
// under running calls.
func (f *Fake) Lock()   { f.mu.Lock() }
func (f *Fake) Unlock() { f.mu.Unlock() }
