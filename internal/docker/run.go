package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// BindMount is one host directory bound into a started helper (always the
// long form, Type bind; never Docker's CreateMountpoint, which would
// create a missing host path following host symlinks — ruling 23).
type BindMount struct {
	Source   string // host path, absolute and clean
	Target   string // container path
	ReadOnly bool
}

// RunSpec is a started helper container: the shared-folder fixer (contract
// §6). Every isolation field the daemon would otherwise take from the
// image or its defaults is set here.
type RunSpec struct {
	// Image: an image ID (sha256:…) or a reference pinned by digest
	// (…@sha256:…); never a tag alone.
	Image string
	// Cmd is the full argv, set as the Entrypoint (absolute path, no
	// shell); the container's Cmd stays empty.
	Cmd  []string
	User string // "0:0"
	// Env is added to the image's environment.
	Env []string
	// Binds are the only host paths the helper sees.
	Binds []BindMount
	// Scratch are anonymous volume targets ("/out", "/in"), removed with
	// the container.
	Scratch []string
	// CapAdd is added after CapDrop ALL (helperCaps names the allowed ones).
	CapAdd  []string
	Label   string // LabelHelper value, e.g. "folder:photos"
	Pids    int64
	Memory  int64 // also the memory+swap limit: no swap
	Timeout time.Duration
	// InPath / In: a tar stream extracted at InPath before the start
	// ("" = none). OutPath: copied out as a tar after a 0 exit ("" = none).
	InPath  string
	In      io.Reader
	OutPath string
}

// RunResult is a finished helper: its exit code and demultiplexed output,
// stdout's last MaxRunStdout bytes and stderr's first MaxRunStderr.
type RunResult struct {
	ExitCode      int
	Stdout        []byte
	Stderr        []byte
	StdoutClipped bool
	StderrClipped bool
}

// Output caps of a started helper (contract §6: the report is the last
// stdout line, ≤ 256 KiB; stderr is for crashes only).
const (
	MaxRunStdout = 256 << 10
	MaxRunStderr = 16 << 10
)

// helperCaps are the only capabilities a started helper may be given: the
// fixer's (contract §6). Anything else is a programming error.
var helperCaps = []string{"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID"}

var (
	imageIDRe     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	imageDigestRe = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)
)

// PinnedImage reports whether ref names exactly one image: an image ID
// (sha256:…) or a reference pinned by digest.
func PinnedImage(ref string) bool {
	return imageIDRe.MatchString(ref) || imageDigestRe.MatchString(ref)
}

func cleanAbsPath(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func (s RunSpec) check() error {
	switch {
	case !PinnedImage(s.Image):
		return fmt.Errorf("helper image %q is not pinned (image ID or @sha256 digest)", s.Image)
	case len(s.Cmd) == 0 || !cleanAbsPath(s.Cmd[0]):
		return errors.New("helper argv must start with an absolute path")
	case s.User == "" || s.Label == "":
		return errors.New("helper needs a user and a label")
	case s.Pids <= 0 || s.Memory <= 0 || s.Timeout <= 0:
		return errors.New("helper needs pids, memory and timeout limits")
	case (s.In != nil) != (s.InPath != ""):
		return errors.New("helper input needs both a path and a stream")
	}
	targets := map[string]bool{}
	for _, b := range s.Binds {
		if !cleanAbsPath(b.Source) || !cleanAbsPath(b.Target) || b.Target == "/" || targets[b.Target] {
			return fmt.Errorf("helper bind %q → %q: want absolute, clean, distinct paths", b.Source, b.Target)
		}
		targets[b.Target] = true
	}
	for _, t := range s.Scratch {
		if !cleanAbsPath(t) || t == "/" || targets[t] {
			return fmt.Errorf("helper scratch volume %q: want an absolute, clean, distinct path", t)
		}
		targets[t] = true
	}
	for _, c := range s.CapAdd {
		if !slices.Contains(helperCaps, c) {
			return fmt.Errorf("helper capability %q is not allowed", c)
		}
	}
	return nil
}

// RunHelper runs a started helper (see RunSpec): create → copy In → start
// → wait for not-running (after the start: a created container already is
// "not running"; Timeout or ctx done → SIGKILL and an error) → logs → copy
// OutPath to out (exit 0 only) → remove, always, also on failure or
// cancellation. A non-zero exit is not an error here: the caller reads
// ExitCode.
func (c *Client) RunHelper(ctx context.Context, s RunSpec, out func(tar io.Reader) error) (*RunResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	mounts := make([]mount.Mount, 0, len(s.Binds)+len(s.Scratch))
	for _, b := range s.Binds {
		mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: b.Source, Target: b.Target, ReadOnly: b.ReadOnly})
	}
	for _, t := range s.Scratch {
		mounts = append(mounts, mount.Mount{Type: mount.TypeVolume, Target: t, VolumeOptions: &mount.VolumeOptions{NoCopy: true}})
	}
	pids := s.Pids
	cctx, cancel := context.WithTimeout(ctx, requestTimeout)
	created, err := c.api.ContainerCreate(cctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image:      s.Image,
			Entrypoint: slices.Clone(s.Cmd),
			// The image's USER, HEALTHCHECK and ENTRYPOINT are replaced
			// (ruling 19); no TTY, no stdin.
			User:            s.User,
			Env:             slices.Clone(s.Env),
			Healthcheck:     &container.HealthConfig{Test: []string{"NONE"}},
			NetworkDisabled: true,
			Labels:          map[string]string{LabelHelper: s.Label},
		},
		HostConfig: &container.HostConfig{
			NetworkMode:    "none",
			IpcMode:        container.IPCModePrivate,
			CgroupnsMode:   container.CgroupnsModePrivate,
			ReadonlyRootfs: true,
			CapDrop:        []string{"ALL"},
			CapAdd:         slices.Clone(s.CapAdd),
			SecurityOpt:    []string{"no-new-privileges:true"},
			Mounts:         mounts,
			// The report is read from the logs: a daemon default driver
			// that can't be read back would lose it.
			LogConfig: container.LogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
			Resources: container.Resources{PidsLimit: &pids, Memory: s.Memory, MemorySwap: s.Memory},
		},
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("create helper: %w", err)
	}
	id := created.ID
	// Removed whatever happens, also when ctx is already done.
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
		defer cancel()
		if _, err := c.api.ContainerRemove(rctx, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil && !IsNotFound(err) {
			// The Hub's start-up sweep (LabelHelper) removes it later.
			log.Printf("docker: removing helper %s (%s): %v", shortID(id), s.Label, err)
		}
	}()
	if s.InPath != "" {
		if _, err := c.api.CopyToContainer(ctx, id, client.CopyToContainerOptions{DestinationPath: s.InPath, Content: s.In}); err != nil {
			return nil, fmt.Errorf("copy into helper: %w", err)
		}
	}
	sctx, cancel := context.WithTimeout(ctx, requestTimeout)
	_, err = c.api.ContainerStart(sctx, id, client.ContainerStartOptions{})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("start helper: %w", err)
	}
	code, err := c.waitHelper(ctx, id, s.Timeout)
	if err != nil {
		return nil, err
	}
	res := &RunResult{ExitCode: code}
	if err := c.helperLogs(ctx, id, res); err != nil {
		return res, fmt.Errorf("helper logs: %w", err)
	}
	if s.OutPath != "" && code == 0 && out != nil {
		rc, err := c.CopyFromContainer(ctx, id, s.OutPath)
		if err != nil {
			return res, fmt.Errorf("copy out of helper: %w", err)
		}
		defer rc.Close()
		if err := out(rc); err != nil {
			return res, err
		}
	}
	return res, nil
}

// waitHelper waits for the started helper to stop. Past timeout, or when
// ctx is done, it is killed and the run fails.
func (c *Client) waitHelper(ctx context.Context, id string, timeout time.Duration) (int, error) {
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	w := c.api.ContainerWait(wctx, id, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	var werr error
	select {
	case r := <-w.Result:
		if r.Error != nil && r.Error.Message != "" {
			return 0, fmt.Errorf("helper wait: %s", r.Error.Message)
		}
		return int(r.StatusCode), nil
	case werr = <-w.Error:
	case <-wctx.Done():
		werr = wctx.Err()
	}
	if wctx.Err() == nil {
		return 0, fmt.Errorf("helper wait: %w", werr)
	}
	kctx, kcancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
	defer kcancel()
	if _, err := c.api.ContainerKill(kctx, id, client.ContainerKillOptions{Signal: "KILL"}); err != nil && !IsNotFound(err) {
		log.Printf("docker: killing helper %s: %v", shortID(id), err)
	}
	if ctx.Err() != nil {
		return 0, fmt.Errorf("helper cancelled: %w", ctx.Err())
	}
	return 0, fmt.Errorf("helper timed out after %s (killed)", timeout)
}

// helperLogs reads the stopped helper's whole output, demultiplexed.
func (c *Client) helperLogs(ctx context.Context, id string, res *RunResult) error {
	lctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	rc, err := c.api.ContainerLogs(lctx, id, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return err
	}
	defer rc.Close()
	stdout := &tailBuffer{max: MaxRunStdout}
	stderr := &limitedBuffer{max: MaxRunStderr}
	if _, err := stdcopy.StdCopy(stdout, stderr, rc); err != nil {
		return err
	}
	res.Stdout, res.StdoutClipped = stdout.bytes(), stdout.clipped
	res.Stderr, res.StderrClipped = stderr.buf, stderr.truncated
	return nil
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	buf     []byte
	max     int
	clipped bool
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) >= b.max {
		b.clipped = b.clipped || len(p) > b.max || len(b.buf) > 0
		b.buf = append(b.buf[:0], p[len(p)-b.max:]...)
		return n, nil
	}
	if over := len(b.buf) + len(p) - b.max; over > 0 {
		b.buf = append(b.buf[:0], b.buf[over:]...)
		b.clipped = true
	}
	b.buf = append(b.buf, p...)
	return n, nil
}

func (b *tailBuffer) bytes() []byte { return b.buf }

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// ContainerInfo is the part of a container inspect the Hub uses.
type ContainerInfo struct {
	ID     string
	Image  string // the image ID (sha256:…) the container runs
	Labels map[string]string
	// PidMode is HostConfig.PidMode ("host": the container sees the
	// host's processes; the doctor's gid check never reads it).
	PidMode string
	// Memory / PidsLimit: HostConfig's memory limit (bytes) and pids
	// limit (0 = none; -1 or unset read as 0): limits_not_enforced.
	Memory    int64
	PidsLimit int64
	// Privileged, CapAdd and Devices: HostConfig's (the doctor's
	// vpn_gateway_privileged).
	Privileged bool
	CapAdd     []string
	Devices    []string
}

// InspectContainer inspects one container (IsNotFound when missing).
func (c *Client) InspectContainer(ctx context.Context, id string) (ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return ContainerInfo{}, err
	}
	ci := ContainerInfo{ID: res.Container.ID, Image: res.Container.Image}
	if res.Container.Config != nil {
		ci.Labels = res.Container.Config.Labels
	}
	if res.Container.HostConfig != nil {
		ci.PidMode = string(res.Container.HostConfig.PidMode)
		ci.Memory = res.Container.HostConfig.Memory
		if p := res.Container.HostConfig.PidsLimit; p != nil && *p > 0 {
			ci.PidsLimit = *p
		}
		ci.Privileged = res.Container.HostConfig.Privileged
		ci.CapAdd = append([]string(nil), res.Container.HostConfig.CapAdd...)
		for _, d := range res.Container.HostConfig.Devices {
			ci.Devices = append(ci.Devices, d.PathOnHost)
		}
	}
	return ci, nil
}

// SecurityOptions is the daemon's Info SecurityOptions ("name=seccomp,…",
// "name=userns", "name=rootless", …).
func (c *Client) SecurityOptions(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.Info(ctx, client.InfoOptions{})
	if err != nil {
		return nil, err
	}
	return res.Info.SecurityOptions, nil
}

// DockerRootDir is the daemon's data root (Info DockerRootDir, a host
// path): image layers, containers and volumes live under it.
func (c *Client) DockerRootDir(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.Info(ctx, client.InfoOptions{})
	if err != nil {
		return "", err
	}
	return res.Info.DockerRootDir, nil
}

// RemappedIDs names the SecurityOptions entry ("userns" or "rootless")
// under which ids inside a container are translated, or "".
func RemappedIDs(opts []string) string {
	for _, o := range opts {
		for _, kv := range strings.Split(o, ",") {
			if k, v, _ := strings.Cut(kv, "="); k == "name" && (v == "userns" || v == "rootless") {
				return v
			}
		}
	}
	return ""
}

// APIVersion is the daemon's highest Engine API version (GET /version,
// e.g. "1.47").
func (c *Client) APIVersion(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		return "", err
	}
	return res.APIVersion, nil
}
