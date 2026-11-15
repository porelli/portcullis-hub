// Package runtimetest is an in-memory runtime.Instances for tests: canned
// units, volumes and exec answers, and every call recorded in order.
package runtimetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/portcullis/hub/internal/runtime"
)

// ErrNotFound is what the fake answers for an unknown unit or volume.
var ErrNotFound = errors.New("not found")

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

	calls []string
}

var _ runtime.Instances = (*Fake)(nil)

func (f *Fake) rec(format string, a ...any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf(format, a...))
	return f.Err
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

func (f *Fake) Down(_ context.Context, p runtime.Project) error { return f.rec("down %s", p.Name) }

func (f *Fake) DownByName(_ context.Context, name string) error {
	return f.rec("down-by-name %s", name)
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
	return &runtime.RunResult{}, nil
}

func (f *Fake) EnsureImage(_ context.Context, ref string) error { return f.rec("ensure-image %s", ref) }
