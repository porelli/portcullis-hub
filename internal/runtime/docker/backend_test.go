package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/compose"
	engine "github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/archive"
)

// recorder is a fake engine + compose runner recording every call (name
// and the arguments that matter) in order.
type recorder struct {
	mu     sync.Mutex
	calls  []string
	nets   []engine.Network
	tarOut []byte // CopyFromContainer's answer
	tarIn  map[string][]byte
}

func (r *recorder) rec(format string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf(format, a...))
}

func (r *recorder) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// compose.Runner
func (r *recorder) Create(_ context.Context, p compose.Project) error {
	r.rec("compose create %s %v", p.Name, p.Files)
	return nil
}
func (r *recorder) Up(_ context.Context, p compose.Project) error {
	r.rec("compose up %s %v", p.Name, p.Files)
	return nil
}
func (r *recorder) Down(_ context.Context, p compose.Project) error {
	r.rec("compose down %s %v", p.Name, p.Files)
	return nil
}
func (r *recorder) DownByName(_ context.Context, name string) error {
	r.rec("compose down-by-name %s", name)
	return nil
}
func (r *recorder) Env() []string { return []string{"HOME=/h"} }

// Engine
func (r *recorder) ListContainers(_ context.Context, f engine.Filters) ([]engine.Container, error) {
	r.rec("list %v", f)
	return []engine.Container{{ID: "c1", Names: []string{"/portcullis-app-web-1"}, State: "running", Labels: map[string]string{engine.LabelProject: "portcullis-app", engine.LabelService: "web"}}}, nil
}
func (r *recorder) Logs(_ context.Context, id string, tail int, ts bool) ([]byte, error) {
	r.rec("logs %s %d %v", id, tail, ts)
	return nil, nil
}
func (r *recorder) Exec(_ context.Context, id string, cmd []string, timeout time.Duration) (*engine.ExecResult, error) {
	r.rec("exec %s %v %s", id, cmd, timeout)
	return &engine.ExecResult{}, nil
}
func (r *recorder) Events(_ context.Context, f engine.Filters, fn func(engine.Event)) error {
	r.rec("events %v", f)
	return nil
}
func (r *recorder) ListVolumes(_ context.Context, f engine.Filters) ([]engine.Volume, error) {
	r.rec("volumes %v", f)
	return nil, nil
}
func (r *recorder) InspectVolume(_ context.Context, name string) (engine.Volume, error) {
	r.rec("inspect-volume %s", name)
	return engine.Volume{Name: name}, nil
}
func (r *recorder) CreateVolume(_ context.Context, v engine.Volume) error {
	r.rec("create-volume %s", v.Name)
	return nil
}
func (r *recorder) RemoveVolume(_ context.Context, name string) error {
	r.rec("remove-volume %s", name)
	return nil
}
func (r *recorder) EnsureImage(_ context.Context, ref string) error {
	r.rec("ensure-image %s", ref)
	return nil
}
func (r *recorder) PullWithProgress(_ context.Context, ref string, _ func(int64, int64, bool)) error {
	r.rec("pull %s", ref)
	return nil
}
func (r *recorder) CreateHelper(_ context.Context, s engine.HelperSpec) (string, error) {
	r.rec("create-helper %s %v ro=%v %s", s.Image, s.Volumes, s.ReadOnly, s.Instance)
	return "h1", nil
}
func (r *recorder) RemoveContainer(_ context.Context, id string) error {
	r.rec("remove %s", id)
	return nil
}
func (r *recorder) CopyFromContainer(_ context.Context, id, path string) (io.ReadCloser, error) {
	r.rec("copy-from %s %s", id, path)
	return io.NopCloser(bytes.NewReader(r.tarOut)), nil
}
func (r *recorder) CopyToContainer(_ context.Context, id, path string, content io.Reader) error {
	b, err := io.ReadAll(content)
	r.rec("copy-to %s %s", id, path)
	r.mu.Lock()
	if r.tarIn == nil {
		r.tarIn = map[string][]byte{}
	}
	r.tarIn[path] = b
	r.mu.Unlock()
	return err
}
func (r *recorder) ContainerKill(_ context.Context, id, sig string) error {
	r.rec("kill %s %s", id, sig)
	return nil
}
func (r *recorder) ContainerState(_ context.Context, id string) (engine.State, error) {
	r.rec("state %s", id)
	return engine.State{}, nil
}
func (r *recorder) ExecStdin(_ context.Context, id string, in engine.ExecInput) (*engine.ExecResult, error) {
	r.rec("exec-stdin %s %v %q", id, in.Cmd, in.User)
	return &engine.ExecResult{}, nil
}
func (r *recorder) ExecStdinSplit(_ context.Context, id string, in engine.ExecInput) (*engine.ExecSplitResult, error) {
	r.rec("exec-split %s %v", id, in.Cmd)
	return &engine.ExecSplitResult{}, nil
}
func (r *recorder) ExecRunning(_ context.Context, execID string) (bool, error) {
	r.rec("exec-running %s", execID)
	return false, nil
}
func (r *recorder) RunHelper(_ context.Context, s engine.RunSpec, _ func(io.Reader) error) (*engine.RunResult, error) {
	r.rec("run-helper %s %v %s", s.Image, s.Cmd, s.Label)
	return &engine.RunResult{}, nil
}
func (r *recorder) InspectContainer(_ context.Context, id string) (engine.ContainerInfo, error) {
	r.rec("inspect %s", id)
	return engine.ContainerInfo{ID: id}, nil
}
func (r *recorder) SecurityOptions(context.Context) ([]string, error) {
	r.rec("security-options")
	return []string{"name=seccomp,profile=builtin", "name=selinux", "name=rootless"}, nil
}
func (r *recorder) DockerRootDir(context.Context) (string, error) {
	r.rec("docker-root")
	return "/var/lib/docker", nil
}
func (r *recorder) APIVersion(context.Context) (string, error) {
	r.rec("api-version")
	return "1.47", nil
}
func (r *recorder) ListNetworks(context.Context) ([]engine.Network, error) {
	r.rec("networks")
	return r.nets, nil
}

const testHelper = "docker.io/library/alpine:3@sha256:0000000000000000000000000000000000000000000000000000000000000000"

// mkTar builds a tar of (name, typeflag, body) entries.
func mkTar(t *testing.T, entries ...[3]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e[0], Typeflag: e[1][0], Mode: 0o755, Size: int64(len(e[2]))}
		if hdr.Typeflag == tar.TypeDir {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeDir {
			tw.Write([]byte(e[2]))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func names(t *testing.T, b []byte) []string {
	t.Helper()
	var out []string
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, h.Name)
	}
}

// TestDockerBackendMatchesEngine: each runtime operation reaches the
// compose runner and the engine with exactly the calls (and in the order)
// the Hub made itself before the runtime interface: create/up/down,
// backup (volume out), restore (volume in), the fixer and the reads.
func TestDockerBackendMatchesEngine(t *testing.T) {
	ctx := context.Background()
	r := &recorder{tarOut: mkTar(t, [3]string{"data/", "5", ""}, [3]string{"data/x", "0", "x"})}
	b := New(r, r, Options{Kind: runtime.KindDocker, HelperImage: testHelper})
	files := compose.Project{Name: "portcullis-app", Files: []string{"/t/compose.yml", "/d/o.yml"}, ProjectDir: "/host", EnvFile: "/d/app.env"}
	p := runtime.Project{Name: "portcullis-app", Instance: "app", Files: files}
	step := func(name string, want []string, fn func() error) {
		t.Helper()
		r.mu.Lock()
		r.calls = nil
		r.mu.Unlock()
		if err := fn(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := r.Calls(); !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", name, got, want)
		}
	}
	fl := "[/t/compose.yml /d/o.yml]"
	step("create", []string{"pull docker.io/x@sha256:1", "compose create portcullis-app " + fl}, func() error {
		if err := b.Pull(ctx, "docker.io/x@sha256:1", nil); err != nil {
			return err
		}
		return b.Create(ctx, p)
	})
	step("up", []string{"compose up portcullis-app " + fl}, func() error { return b.Up(ctx, p, nil) })
	step("down", []string{"compose down portcullis-app " + fl, "compose down-by-name portcullis-app"}, func() error {
		if err := b.Down(ctx, p); err != nil {
			return err
		}
		return b.DownByName(ctx, "portcullis-app")
	})
	step("backup", []string{
		"volumes map[label:[com.docker.compose.project=portcullis-app]]",
		"ensure-image " + testHelper,
		"create-helper " + testHelper + " map[portcullis-app_data:/data] ro=true app",
		"copy-from h1 /data",
		"remove h1",
	}, func() error {
		if _, err := b.ListVolumes(ctx, runtime.Filter{Instance: "app"}); err != nil {
			return err
		}
		if err := b.EnsureImage(ctx, testHelper); err != nil {
			return err
		}
		rc, err := b.VolumeOut(ctx, "app", "portcullis-app_data", "/data")
		if err != nil {
			return err
		}
		got, _ := io.ReadAll(rc)
		if !bytes.Equal(got, r.tarOut) {
			t.Error("the volume stream isn't the engine's archive")
		}
		return rc.Close()
	})
	step("restore", []string{
		"remove-volume portcullis-app_data",
		"create-volume portcullis-app_data",
		"inspect-volume portcullis-app_data",
		"create-helper " + testHelper + " map[portcullis-app_data:/data] ro=false app",
		"copy-to h1 /",
		"remove h1",
	}, func() error {
		if err := b.RemoveVolume(ctx, "portcullis-app_data"); err != nil {
			return err
		}
		if err := b.CreateVolume(ctx, runtime.Volume{Name: "portcullis-app_data"}); err != nil {
			return err
		}
		if _, err := b.InspectVolume(ctx, "portcullis-app_data"); err != nil {
			return err
		}
		return b.VolumeIn(ctx, "app", "portcullis-app_data", "/data", bytes.NewReader(r.tarOut))
	})
	if !bytes.Equal(r.tarIn["/"], r.tarOut) {
		t.Error("docker: the restore didn't send the canonical archive to /")
	}
	step("fixer", []string{"security-options", "docker-root", "api-version", "networks", "run-helper sha256:abc [/usr/local/bin/hub folderfix check] folder:x"}, func() error {
		if _, err := b.Info(ctx); err != nil {
			return err
		}
		_, err := b.RunFixer(ctx, runtime.FixerSpec{Image: "sha256:abc", Cmd: []string{"/usr/local/bin/hub", "folderfix", "check"}, Label: "folder:x"}, nil)
		return err
	})
	step("reads", []string{
		"list map[label:[com.docker.compose.project=portcullis-app com.docker.compose.service=web]]",
		"list map[label:[com.docker.compose.project]]",
		"list map[]",
		"list map[label:[io.portcullis.hub.helper]]",
		"remove h9",
		"inspect c1",
		"logs c1 50 true",
		"exec c1 [/bin/sh -c id] 30s",
		"exec-stdin c1 [/hook] \"10001\"",
		"exec-split c1 [/ai]",
		"exec-running e1",
		"kill c1 HUP",
		"state c1",
		"events map[label:[com.docker.compose.project] type:[container]]",
	}, func() error {
		us, err := b.List(ctx, runtime.Filter{Instance: "app", Service: "web"})
		if err != nil {
			return err
		}
		if len(us) != 1 || us[0].Name != "portcullis-app-web-1" || us[0].Instance != "app" || us[0].Service != "web" || us[0].State != "running" {
			t.Errorf("unit = %+v", us)
		}
		b.List(ctx, runtime.Filter{All: true})
		b.List(ctx, runtime.Filter{})
		b.List(ctx, runtime.Filter{Helper: true})
		b.RemoveHelper(ctx, "h9")
		b.Inspect(ctx, "c1")
		b.Logs(ctx, "c1", 50, true)
		b.Exec(ctx, "c1", runtime.ExecInput{Cmd: []string{"/bin/sh", "-c", "id"}, Timeout: 30 * time.Second, NoStdin: true})
		b.Exec(ctx, "c1", runtime.ExecInput{Cmd: []string{"/hook"}, User: "10001"})
		b.ExecSplit(ctx, "c1", runtime.ExecInput{Cmd: []string{"/ai"}})
		b.ExecRunning(ctx, "e1")
		b.Signal(ctx, "c1", "HUP")
		b.State(ctx, "c1")
		return b.Events(ctx, runtime.Filter{All: true}, func(runtime.Event) {})
	})
	if _, err := b.Exec(ctx, "c1", runtime.ExecInput{Cmd: []string{"x"}, User: "0", NoStdin: true}); err == nil {
		t.Error("a NoStdin exec with a user was run")
	}
	if got := b.Env(); !reflect.DeepEqual(got, []string{"HOME=/h"}) {
		t.Errorf("Env = %v", got)
	}
}

// TestDockerBackendPodmanQuirks: Podman's networks carry no IPRange in
// inspect (the subnets alone are the answer), its archives name the root
// "/" (the canonical form reads it), and a restore extracts at the mount
// with relative names (never at "/", which would be the helper's own root
// filesystem under Podman).
func TestDockerBackendPodmanQuirks(t *testing.T) {
	ctx := context.Background()
	podmanTar := mkTar(t, [3]string{"/", "5", ""}, [3]string{"/x", "0", "x"}, [3]string{"/sub/", "5", ""}, [3]string{"/sub/y", "0", "y"})
	r := &recorder{tarOut: podmanTar, nets: []engine.Network{{Name: "portcullis-vpn", Subnets: []netip.Prefix{netip.MustParsePrefix("172.31.254.0/26")}}, {Name: "none"}}}
	b := New(r, r, Options{Kind: runtime.KindPodman, HelperImage: testHelper})
	info, err := b.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Networks) != 2 || info.Networks[0].Subnets[0].String() != "172.31.254.0/26" || len(info.Networks[1].Subnets) != 0 {
		t.Errorf("networks = %+v", info.Networks)
	}
	if !info.SELinux || !info.IDMapped || info.Remapped != "rootless" || info.Kind != runtime.KindPodman || info.ForbiddenRoots[0] != "/var/lib/docker" || info.APIVersion != "1.47" {
		t.Errorf("info = %+v", info)
	}
	rc, err := b.VolumeOut(ctx, "app", "v", "/data")
	if err != nil {
		t.Fatal(err)
	}
	var canon bytes.Buffer
	if err := archive.Normalize(rc, &canon, "/data", nil); err != nil {
		t.Fatalf("a podman archive (root /): %v", err)
	}
	rc.Close()
	if got := strings.Join(names(t, canon.Bytes()), " "); got != "data/ data/x data/sub/ data/sub/y" {
		t.Errorf("canonical = %s", got)
	}
	if err := b.VolumeIn(ctx, "app", "v", "/data", bytes.NewReader(canon.Bytes())); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.tarIn["/"]; ok {
		t.Error("podman: extracted at /")
	}
	if got := strings.Join(names(t, r.tarIn["/data"]), " "); got != "./ ./x ./sub/ ./sub/y" {
		t.Errorf("podman extract at the mount = %s", got)
	}
	if b.Kind() != runtime.KindPodman {
		t.Error("kind")
	}
}
