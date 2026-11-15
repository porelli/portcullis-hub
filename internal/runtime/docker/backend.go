// Package docker is the docker backend of runtime.Instances: Docker and
// Podman through the compose CLI (up/down only: compose has no API) and
// the Engine API (internal/docker) for everything else. It moves code,
// not behaviour: every call reaches the engine and compose exactly as the
// Hub's own code did before the runtime interface.
package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/portcullis/hub/internal/compose"
	engine "github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/archive"
)

// Engine is the part of the Docker Engine API the backend uses
// (*docker.Client; fakes in tests).
type Engine interface {
	ListContainers(ctx context.Context, f engine.Filters) ([]engine.Container, error)
	Logs(ctx context.Context, id string, tail int, timestamps bool) ([]byte, error)
	Exec(ctx context.Context, id string, cmd []string, timeout time.Duration) (*engine.ExecResult, error)
	Events(ctx context.Context, f engine.Filters, fn func(engine.Event)) error
	// Volumes and volume I/O (instance backups, guarded delete, the
	// volume collision check; docker/volumes.go).
	ListVolumes(ctx context.Context, f engine.Filters) ([]engine.Volume, error)
	InspectVolume(ctx context.Context, name string) (engine.Volume, error)
	CreateVolume(ctx context.Context, v engine.Volume) error
	RemoveVolume(ctx context.Context, name string) error
	EnsureImage(ctx context.Context, ref string) error
	// PullWithProgress downloads ref unless present (docker/pull.go).
	PullWithProgress(ctx context.Context, ref string, onBytes func(done, total int64, sized bool)) error
	CreateHelper(ctx context.Context, s engine.HelperSpec) (string, error)
	RemoveContainer(ctx context.Context, id string) error
	CopyFromContainer(ctx context.Context, id, path string) (io.ReadCloser, error)
	CopyToContainer(ctx context.Context, id, path string, content io.Reader) error
	// ContainerKill signals a container (a settings reload, §13.8);
	// ContainerState is its run state and health.
	ContainerKill(ctx context.Context, id, signal string) error
	ContainerState(ctx context.Context, id string) (engine.State, error)
	// ExecStdin runs a settings hook (§13.8): argv, stdin written then
	// closed, no TTY; ExecRunning: a timed-out exec still runs.
	ExecStdin(ctx context.Context, id string, in engine.ExecInput) (*engine.ExecResult, error)
	// ExecStdinSplit runs an AI hook (§15.5, G6): stdout and stderr apart.
	ExecStdinSplit(ctx context.Context, id string, in engine.ExecInput) (*engine.ExecSplitResult, error)
	ExecRunning(ctx context.Context, execID string) (bool, error)
	// RunHelper runs the shared-folder fixer, a STARTED helper (contract
	// §6); InspectContainer inspects a container; SecurityOptions is the
	// daemon's Info (userns / rootless refusal).
	RunHelper(ctx context.Context, s engine.RunSpec, out func(tar io.Reader) error) (*engine.RunResult, error)
	InspectContainer(ctx context.Context, id string) (engine.ContainerInfo, error)
	SecurityOptions(ctx context.Context) ([]string, error)
	// DockerRootDir is the daemon's data root (no shared folder at,
	// above or under it).
	DockerRootDir(ctx context.Context) (string, error)
	// APIVersion is the daemon's highest Engine API version.
	APIVersion(ctx context.Context) (string, error)
	// ListNetworks lists the engine's networks with their subnets.
	ListNetworks(ctx context.Context) ([]engine.Network, error)
}

// Options configure a Backend.
type Options struct {
	// Kind is docker or podman (HUB_CONTAINER_RUNTIME).
	Kind runtime.Kind
	// Guard is the engine runtime guard (nil: unit tests, always
	// verified); the engine client and the compose CLI hold it too.
	Guard *engine.Guard
	// HelperImage is the volume I/O helpers' image (pinned).
	HelperImage string
}

// Backend serves runtime.Instances from a compose runner and an engine.
type Backend struct {
	opt     Options
	compose compose.Runner
	engine  Engine
}

var _ runtime.Instances = (*Backend)(nil)

// New returns the docker backend (eng nil: unit tests, EngineAbsent).
func New(runner compose.Runner, eng Engine, opt Options) *Backend {
	if opt.Kind == "" {
		opt.Kind = runtime.KindDocker
	}
	return &Backend{opt: opt, compose: runner, engine: eng}
}

// EngineAbsent: the backend has a compose runner and no engine (unit
// tests only; the Hub then skips everything that reads the engine).
func (b *Backend) EngineAbsent() bool { return b.engine == nil }

func (b *Backend) Kind() runtime.Kind { return b.opt.Kind }

func (b *Backend) Env() []string { return b.compose.Env() }

// Info folds the daemon's security options, data root, API version and
// networks together with the guard's state. Any read failing is the
// error (naming what failed).
func (b *Backend) Info(ctx context.Context) (runtime.Info, error) {
	i := runtime.Info{Kind: b.opt.Kind, Verified: true}
	if g := b.opt.Guard; g != nil {
		if err := g.Err(); err != nil {
			i.Verified, i.Why = false, err.Error()
		}
	}
	opts, err := b.engine.SecurityOptions(ctx)
	if err != nil {
		return i, err
	}
	i.SecurityOptions = opts
	i.SELinux = runtime.SecurityOption(opts, "selinux")
	i.Remapped = engine.RemappedIDs(opts)
	i.IDMapped = i.Remapped != ""
	root, err := b.engine.DockerRootDir(ctx)
	if err != nil {
		return i, fmt.Errorf("the data root: %w", err)
	}
	i.ForbiddenRoots = []string{root}
	if i.APIVersion, err = b.engine.APIVersion(ctx); err != nil {
		return i, fmt.Errorf("the API version: %w", err)
	}
	if i.Networks, err = b.engine.ListNetworks(ctx); err != nil {
		return i, fmt.Errorf("the networks: %w", err)
	}
	return i, nil
}

func (b *Backend) Create(ctx context.Context, p runtime.Project) error {
	return b.compose.Create(ctx, p.Files)
}

// Up runs compose up; onPull is never called (Pull already downloaded
// every image, compose runs with --pull never).
func (b *Backend) Up(ctx context.Context, p runtime.Project, _ func(string, int64, int64, bool)) error {
	return b.compose.Up(ctx, p.Files)
}

func (b *Backend) Down(ctx context.Context, p runtime.Project) error {
	return b.compose.Down(ctx, p.Files)
}

func (b *Backend) DownByName(ctx context.Context, name string) error {
	return b.compose.DownByName(ctx, name)
}

func (b *Backend) Pull(ctx context.Context, ref string, onBytes func(done, total int64, sized bool)) error {
	return b.engine.PullWithProgress(ctx, ref, onBytes)
}

// filters is f as Engine API filters: zero = none (every container), All
// = every compose project's, Instance its project's (+ Service), Helper
// the helpers'.
func filters(f runtime.Filter) engine.Filters {
	var labels []string
	switch {
	case f.Helper:
		labels = append(labels, engine.LabelHelper)
	case f.Instance != "":
		labels = append(labels, engine.LabelProject+"="+runtime.ProjectName(f.Instance))
		if f.Service != "" {
			labels = append(labels, engine.LabelService+"="+f.Service)
		}
	case f.All:
		labels = append(labels, engine.LabelProject)
	}
	if labels == nil {
		return nil
	}
	return engine.Filters{"label": labels}
}

// unit converts a listed container.
func unit(c engine.Container) runtime.Unit {
	u := runtime.Unit{ID: c.ID, Name: c.Name(), Project: c.Project(), Service: c.Service(), Image: c.Image,
		State: c.State, Status: c.Status, Labels: c.Labels, Created: c.Created, Networks: c.Networks}
	if len(u.Project) > len(runtime.ProjectPrefix) && u.Project[:len(runtime.ProjectPrefix)] == runtime.ProjectPrefix {
		u.Instance = u.Project[len(runtime.ProjectPrefix):]
	}
	return u
}

func (b *Backend) List(ctx context.Context, f runtime.Filter) ([]runtime.Unit, error) {
	cs, err := b.engine.ListContainers(ctx, filters(f))
	if err != nil {
		return nil, err
	}
	var out []runtime.Unit
	for _, c := range cs {
		out = append(out, unit(c))
	}
	return out, nil
}

func (b *Backend) Inspect(ctx context.Context, id string) (runtime.UnitInfo, error) {
	return b.engine.InspectContainer(ctx, id)
}

func (b *Backend) Logs(ctx context.Context, id string, tail int, ts bool) ([]byte, error) {
	return b.engine.Logs(ctx, id, tail, ts)
}

// Exec runs in: with NoStdin the Engine's plain exec (no stdin, the
// container's user), else stdin attached (written, then closed).
func (b *Backend) Exec(ctx context.Context, id string, in runtime.ExecInput) (*runtime.ExecResult, error) {
	if in.NoStdin {
		if in.User != "" || in.Stdin != nil {
			return nil, errors.New("exec: NoStdin takes no user and no stdin")
		}
		return b.engine.Exec(ctx, id, in.Cmd, in.Timeout)
	}
	return b.engine.ExecStdin(ctx, id, in)
}

func (b *Backend) ExecSplit(ctx context.Context, id string, in runtime.ExecInput) (*runtime.ExecSplitResult, error) {
	return b.engine.ExecStdinSplit(ctx, id, in)
}

func (b *Backend) ExecRunning(ctx context.Context, execID string) (bool, error) {
	return b.engine.ExecRunning(ctx, execID)
}

func (b *Backend) Signal(ctx context.Context, id, sig string) error {
	return b.engine.ContainerKill(ctx, id, sig)
}

func (b *Backend) State(ctx context.Context, id string) (runtime.State, error) {
	return b.engine.ContainerState(ctx, id)
}

// Events streams container events matching f.
func (b *Backend) Events(ctx context.Context, f runtime.Filter, fn func(runtime.Event)) error {
	ef := filters(f)
	if ef == nil {
		ef = engine.Filters{}
	}
	ef["type"] = []string{"container"}
	return b.engine.Events(ctx, ef, fn)
}

func (b *Backend) ListVolumes(ctx context.Context, f runtime.Filter) ([]runtime.Volume, error) {
	return b.engine.ListVolumes(ctx, filters(f))
}

func (b *Backend) InspectVolume(ctx context.Context, name string) (runtime.Volume, error) {
	return b.engine.InspectVolume(ctx, name)
}

func (b *Backend) CreateVolume(ctx context.Context, v runtime.Volume) error {
	return b.engine.CreateVolume(ctx, v)
}

func (b *Backend) RemoveVolume(ctx context.Context, name string) error {
	return b.engine.RemoveVolume(ctx, name)
}

// createHelper creates a never-started helper container mounting volume
// at path (read-only for reads).
func (b *Backend) createHelper(ctx context.Context, instance, volume, path string, readOnly bool) (string, error) {
	hid, err := b.engine.CreateHelper(ctx, engine.HelperSpec{Image: b.opt.HelperImage, Volumes: map[string]string{volume: path}, ReadOnly: readOnly, Instance: instance})
	if err != nil {
		return "", fmt.Errorf("helper container: %w", err)
	}
	return hid, nil
}

func (b *Backend) removeHelper(ctx context.Context, instance, hid string) {
	if rerr := b.engine.RemoveContainer(context.WithoutCancel(ctx), hid); rerr != nil {
		log.Printf("instance %s: removing helper container %s: %v", instance, hid, rerr)
	}
}

// helperReader is an archive read from a helper; Close removes the
// helper.
type helperReader struct {
	io.ReadCloser
	done func()
}

func (r *helperReader) Close() error {
	err := r.ReadCloser.Close()
	r.done()
	return err
}

// VolumeOut streams volume through a read-only helper (the engine's
// archive of path, in the engine's own form: archive.Normalize reads
// every form); closing the stream removes the helper.
func (b *Backend) VolumeOut(ctx context.Context, instance, volume, path string) (io.ReadCloser, error) {
	hid, err := b.createHelper(ctx, instance, volume, path, true)
	if err != nil {
		return nil, err
	}
	rc, err := b.engine.CopyFromContainer(ctx, hid, path)
	if err != nil {
		b.removeHelper(ctx, instance, hid)
		return nil, err
	}
	return &helperReader{ReadCloser: rc, done: func() { b.removeHelper(ctx, instance, hid) }}, nil
}

// VolumeIn extracts r (canonical "<base of path>/…" entries) into volume
// through a writable helper. Docker extracts at "/" (only an upload to "/"
// applies the volume root's own owner and mode); Podman resolves an
// extract target to a volume only inside its mount, so there the entries
// go relative to the mount, extracted at it (archive.Relative).
func (b *Backend) VolumeIn(ctx context.Context, instance, volume, path string, r io.Reader) error {
	hid, err := b.createHelper(ctx, instance, volume, path, false)
	if err != nil {
		return err
	}
	defer b.removeHelper(ctx, instance, hid)
	if b.opt.Kind == runtime.KindPodman {
		pr, pw := io.Pipe()
		defer pr.Close()
		go func() { pw.CloseWithError(archive.Relative(r, pw, path)) }()
		if err := b.engine.CopyToContainer(ctx, hid, path, pr); err != nil {
			return fmt.Errorf("restoring volume %s: %w", volume, err)
		}
		return nil
	}
	if err := b.engine.CopyToContainer(ctx, hid, "/", r); err != nil {
		return fmt.Errorf("restoring volume %s: %w", volume, err)
	}
	return nil
}

func (b *Backend) RemoveHelper(ctx context.Context, id string) error {
	return b.engine.RemoveContainer(ctx, id)
}

func (b *Backend) RunFixer(ctx context.Context, s runtime.FixerSpec, out func(tar io.Reader) error) (*runtime.RunResult, error) {
	return b.engine.RunHelper(ctx, s, out)
}

func (b *Backend) EnsureImage(ctx context.Context, ref string) error {
	return b.engine.EnsureImage(ctx, ref)
}
