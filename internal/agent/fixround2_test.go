package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
)

// putFor PUTs a bundle of instance id made of files (compose files only).
func (f *apiFixture) putFor(t *testing.T, id string, files map[string]string) (int, string) {
	t.Helper()
	var list []bundleFile
	for n, d := range files {
		mode := int64(0o644)
		if n == BundleEnv {
			mode = 0o600
		}
		list = append(list, bundleFile{name: n, data: d, mode: mode})
	}
	resp, b := f.req(t, "PUT", "/v1/projects/"+id+"/bundle", bytes.NewReader(bundleTar(t, id, nil, list)))
	return resp.StatusCode, string(b)
}

func bindCompose(binds ...string) string {
	return "services:\n  web:\n    image: x\n    volumes: [\"" + strings.Join(binds, "\", \"") + "\"]\n"
}

// TestNestedBindsRefused (review A-H2a): a bind source may not nest with
// another instance's (either way, either order), and an instance's own
// writable bind may not contain another of its bind sources.
func TestNestedBindsRefused(t *testing.T) {
	for _, order := range [][2]string{{"a", "b"}, {"b", "a"}} {
		f := newAPI(t)
		os.MkdirAll(filepath.Join(f.root, "a", "b"), 0o755)
		srcs := map[string]string{"a": f.root + "/a:/x", "b": f.root + "/a/b:/y:ro"}
		if c, b := f.putFor(t, "one", map[string]string{BundleCompose: bindCompose(srcs[order[0]])}); c != 204 {
			t.Fatalf("%v first: %d %s", order, c, b)
		}
		c, b := f.putFor(t, "two", map[string]string{BundleCompose: bindCompose(srcs[order[1]])})
		if c != 400 || !strings.Contains(b, "may not nest") {
			t.Errorf("%v second: %d %s", order, c, b)
		}
	}
	f := newAPI(t)
	os.MkdirAll(filepath.Join(f.root, "a", "b"), 0o755)
	// One instance: a writable bind containing another of its sources.
	c, b := f.putFor(t, "one", map[string]string{BundleCompose: bindCompose(f.root+"/a:/x", f.root+"/a/b:/y:ro")})
	if c != 400 || !strings.Contains(b, "nested binds are refused") {
		t.Errorf("own nested rw: %d %s", c, b)
	}
	// Read-only parent, the same source twice, and siblings are fine.
	if c, b := f.putFor(t, "one", map[string]string{BundleCompose: bindCompose(f.root+"/a:/x:ro", f.root+"/a/b:/y:ro")}); c != 204 {
		t.Errorf("own nested ro: %d %s", c, b)
	}
	os.MkdirAll(filepath.Join(f.root, "c"), 0o755)
	if c, b := f.putFor(t, "two", map[string]string{BundleCompose: bindCompose(f.root + "/c:/c")}); c != 204 {
		t.Errorf("a sibling: %d %s", c, b)
	}
}

// TestStartBackstop (review A-H2b): a container start (the engine's own,
// never through the agent) re-walks the instance's bind sources; a
// planted symlink kills the container, takes the project down and
// quarantines the instance (reported in /v1/info, refused until a new
// bundle).
func TestStartBackstop(t *testing.T) {
	f := newAPI(t)
	os.MkdirAll(filepath.Join(f.root, "real"), 0o755)
	files := map[string]string{BundleCompose: bindCompose(f.root + "/real/sub:/x")}
	if c, b := f.putFor(t, "app", files); c != 204 {
		t.Fatalf("bundle: %d %s", c, b)
	}
	ev := runtime.Event{Type: "container", Action: "start"}
	ev.Actor.ID = "c-app"
	ev.Actor.Attributes = map[string]string{docker.LabelProject: "portcullis-app"}
	f.rt.evs = []runtime.Event{ev}
	// Clean: nothing happens.
	f.api.CheckStarted(context.Background(), "c-app", "portcullis-app")
	if q := f.api.Quarantined(); q != nil {
		t.Fatalf("quarantined a clean start: %v", q)
	}
	os.Symlink(t.TempDir(), filepath.Join(f.root, "real", "sub"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.api.WatchStarts(ctx); close(done) }()
	for i := 0; i < 1000 && f.api.Quarantined() == nil; i++ {
		os.ReadDir(f.root) // a yield
	}
	cancel()
	<-done
	q := f.api.Quarantined()
	if !strings.Contains(q["app"], "symlink") {
		t.Fatalf("quarantine %v", q)
	}
	waitCall(t, f, "down-by-name portcullis-app")
	if calls := strings.Join(f.rt.Calls(), "\n"); !strings.Contains(calls, "signal c-app KILL") {
		t.Errorf("calls %s", calls)
	}
	if c := f.code(t, "POST", "/v1/projects/app/up", nil); c != 409 {
		t.Errorf("up while quarantined: %d", c)
	}
	// A bundle never lifts it (review A2-M1); the Hub's explicit lift
	// does, after the walk passes again.
	if c := f.code(t, "DELETE", "/v1/projects/app/quarantine", nil); c != 409 {
		t.Errorf("lift while still failing: %d", c)
	}
	os.Remove(filepath.Join(f.root, "real", "sub"))
	if c, b := f.putFor(t, "app", files); c != 204 {
		t.Fatalf("re-bundle: %d %s", c, b)
	}
	if q := f.api.Quarantined(); q == nil {
		t.Error("a bundle lifted the quarantine")
	}
	if c := f.code(t, "DELETE", "/v1/projects/app/quarantine", nil); c != 204 {
		t.Errorf("lift: %d", c)
	}
	if q := f.api.Quarantined(); q != nil {
		t.Errorf("still quarantined: %v", q)
	}
}

// TestRootNotVisibleRefused (review A-H3): a folder root the agent can't
// see is refused, never passed; the start refuses missing roots.
func TestRootNotVisibleRefused(t *testing.T) {
	f := newAPI(t)
	missing := filepath.Join(f.root, "absent-root")
	f.api.cfg.BindRoots = []string{missing}
	c, b := f.putFor(t, "app", map[string]string{BundleCompose: bindCompose(missing + "/x:/x")})
	if c != 400 || !strings.Contains(b, "isn't visible to the agent") {
		t.Errorf("bundle: %d %s", c, b)
	}
	if err := walkNoSymlink(nil, []string{missing}, missing+"/x"); !errors.Is(err, ErrRootNotVisible) {
		t.Errorf("walk: %v", err)
	}
	if err := CheckRootsVisible([]string{f.root, missing}); err == nil || !strings.Contains(err.Error(), "folder root "+missing+" isn't visible to the agent") {
		t.Errorf("start: %v", err)
	}
	if err := CheckRootsVisible([]string{f.root}); err != nil {
		t.Errorf("a real root: %v", err)
	}
	// The instance's own dirs may be absent (made at commit).
	if err := walkNoSymlink([]string{filepath.Join(f.data, "files", "app")}, nil, filepath.Join(f.data, "files", "app", "templates/x")); err != nil {
		t.Errorf("own dir: %v", err)
	}
}

// TestEnvFileLabelFileRefused (review A-M1): env_file and label_file are
// refused on the raw YAML, before compose config could read them; only
// the instance's own bundle env file is allowed.
func TestEnvFileLabelFileRefused(t *testing.T) {
	f := newAPI(t)
	var calls atomic.Int32
	cfg := f.api.cfg.Config
	f.api.cfg.Config = func(ctx context.Context, p compose.Project) ([]byte, error) {
		calls.Add(1)
		return cfg(ctx, p)
	}
	key := filepath.Join(f.data, "identity", "tls.key")
	for name, svc := range map[string]string{
		"a key":           "    env_file: " + key + "\n",
		"long form":       "    env_file: [{path: " + key + ", required: false}]\n",
		"another's env":   "    env_file: " + filepath.Join(f.data, "projects", "other", BundleEnv) + "\n",
		"label_file":      "    label_file: " + key + "\n",
		"two, one is own": "    env_file: [" + filepath.Join(f.data, "projects", "app", BundleEnv) + ", " + key + "]\n",
	} {
		for _, file := range []string{BundleCompose, BundleOverride} {
			files := map[string]string{BundleCompose: "services:\n  web:\n    image: x\n"}
			files[file] += "services:\n  web:\n" + svc
			if file == BundleCompose {
				files[file] = "services:\n  web:\n    image: x\n" + svc
			}
			c, b := f.putFor(t, "app", files)
			if c != 400 || !strings.Contains(b, "is not allowed") {
				t.Errorf("%s in %s: %d %s", name, file, c, b)
			}
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("compose config ran %d times", n)
	}
	if !envFileIsOwn(filepath.Join(f.data, "projects", "app", BundleEnv), []string{filepath.Join(f.data, "projects", "app", BundleEnv)}) {
		t.Error("the own env file refused")
	}
}

// TestProtectedOutsideRoots (review A-M2): the start refuses a protected
// path inside a folder root, by path and through an alias of the same
// directory (os.SameFile).
func TestProtectedOutsideRoots(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(base, "srv")
	os.MkdirAll(filepath.Join(root, "p", "worker-data"), 0o755)
	if err := CheckProtectedOutsideRoots([]string{root + "/p/worker-data"}, []string{root}); err == nil || !strings.Contains(err.Error(), "inside the folder root") {
		t.Errorf("by path: %v", err)
	}
	alias := filepath.Join(base, "alias")
	os.Symlink(root, alias)
	if err := CheckProtectedOutsideRoots([]string{alias + "/p/worker-data"}, []string{root}); err == nil || !strings.Contains(err.Error(), "the same directory") {
		t.Errorf("an alias: %v", err)
	}
	other := filepath.Join(base, "install", "worker-data")
	os.MkdirAll(other, 0o755)
	if err := CheckProtectedOutsideRoots([]string{other, filepath.Dir(other)}, []string{root}); err != nil {
		t.Errorf("outside: %v", err)
	}
}

// TestInstallDirProtected (review A-H1): the agent's install dir (its
// compose working dir) is protected: its files can't be bound.
func TestInstallDirProtected(t *testing.T) {
	f := newAPI(t)
	install := filepath.Join(f.root, "portcullis-install")
	os.MkdirAll(install, 0o755)
	f.api.cfg.Protected = append(f.api.cfg.Protected, install)
	for _, b := range []string{install + "/portcullis:/x", install + "/docker-compose.worker.yml:/y:ro"} {
		c, body := f.putFor(t, "app", map[string]string{BundleCompose: bindCompose(b)})
		if c != 400 || !strings.Contains(body, "protected") {
			t.Errorf("%s: %d %s", b, c, body)
		}
	}
}

// TestVolumeInSecurityBits (review A-L2): setuid / setgid bits and file
// capabilities never reach the engine; an archive over the free space is
// 507; an unreadable free space refuses the restore.
func TestVolumeInSecurityBits(t *testing.T) {
	var in, out bytes.Buffer
	tw := tar.NewWriter(&in)
	tw.WriteHeader(&tar.Header{Name: "data/", Typeflag: tar.TypeDir, Mode: 0o2755})
	tw.WriteHeader(&tar.Header{Name: "data/su", Typeflag: tar.TypeReg, Mode: 0o4755, Size: 1, Format: tar.FormatPAX,
		PAXRecords: map[string]string{"SCHILY.xattr.security.capability": "x", "SCHILY.xattr.security.selinux": "s", "SCHILY.xattr.user.k": "v"}})
	tw.Write([]byte("x"))
	tw.Close()
	if err := checkedVolumeTar(bytes.NewReader(in.Bytes()), &out, "data", 0); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&out)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Mode&0o6000 != 0 {
			t.Errorf("%s: mode %o", h.Name, h.Mode)
		}
		if _, ok := h.PAXRecords["SCHILY.xattr.security.capability"]; ok {
			t.Errorf("%s: a file capability kept", h.Name)
		}
		if h.Name == "data/su" && (h.PAXRecords["SCHILY.xattr.security.selinux"] != "s" || h.PAXRecords["SCHILY.xattr.user.k"] != "v") {
			t.Errorf("%s: xattrs %v", h.Name, h.PAXRecords)
		}
	}
	var ve *volumeTarError
	if err := checkedVolumeTar(bytes.NewReader(in.Bytes()), &bytes.Buffer{}, "data", 0); err != nil {
		t.Fatal(err)
	}
	if err := checkedVolumeTar(bytes.NewReader(in.Bytes()), &bytes.Buffer{}, "data", 0); errors.As(err, &ve) {
		t.Fatal(err)
	}
	big := bytes.Buffer{}
	tw = tar.NewWriter(&big)
	tw.WriteHeader(&tar.Header{Name: "data/f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 100})
	tw.Write(bytes.Repeat([]byte("x"), 100))
	tw.Close()
	if err := checkedVolumeTar(bytes.NewReader(big.Bytes()), &bytes.Buffer{}, "data", 10); !errors.As(err, &ve) || ve.status != 507 {
		t.Errorf("over the free space: %v", err)
	}
	// Through the route: free space unreadable → 507.
	f := newAPI(t)
	f.bundle(t, "app")
	f.api.cfg.DiskFree = func(context.Context) (int64, bool) { return 0, false }
	f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-app"}}
	_, b := f.req(t, "POST", "/v1/helpers", bytes.NewReader(mustJSON(agentapi.HelperSpec{Kind: agentapi.HelperVolumeIO, Instance: "app", Volume: "portcullis-app_data", Path: "/data", Write: true})))
	var hc agentapi.HelperCreated
	json.Unmarshal(b, &hc)
	if c := f.code(t, "PUT", "/v1/helpers/"+hc.ID+"/archive", in.Bytes()); c != 507 {
		t.Errorf("unreadable free space: %d", c)
	}
}

// TestInstallDirLabel: the install dir comes from the agent's own compose
// label; none (or "/") refuses the start.
func TestInstallDirLabel(t *testing.T) {
	if _, err := InstallDirOf(map[string]string{}); err == nil {
		t.Error("no label accepted")
	}
	if _, err := InstallDirOf(map[string]string{"com.docker.compose.project.working_dir": "/"}); err == nil {
		t.Error("/ accepted")
	}
	if d, err := InstallDirOf(map[string]string{"com.docker.compose.project.working_dir": "/srv/portcullis"}); err != nil || d != "/srv/portcullis" {
		t.Errorf("%q %v", d, err)
	}
}
