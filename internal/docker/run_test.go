package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRun is a Docker API fake for one started helper "f1".
type fakeRun struct {
	t        *testing.T
	mu       sync.Mutex
	calls    []string
	create   []byte
	putPath  string
	putBody  string
	getPath  string
	startErr bool
	block    bool // wait blocks until the request is cancelled
	exit     int
	stdout   string
	stderr   string
}

func (f *fakeRun) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *fakeRun) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeRun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/_ping" {
		return
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/containers/create":
		f.record("create")
		f.create, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"Id":"f1","Warnings":[]}`))
	case r.Method == "PUT" && r.URL.Path == "/containers/f1/archive":
		f.record("archive PUT")
		b, _ := io.ReadAll(r.Body)
		f.putPath, f.putBody = r.URL.Query().Get("path"), string(b)
	case r.Method == "POST" && r.URL.Path == "/containers/f1/start":
		f.record("start")
		if f.startErr {
			http.Error(w, `{"message":"cannot start"}`, 500)
			return
		}
		w.WriteHeader(204)
	case r.Method == "POST" && r.URL.Path == "/containers/f1/wait":
		f.record("wait " + r.URL.Query().Get("condition"))
		if f.block {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"StatusCode": f.exit})
	case r.Method == "POST" && r.URL.Path == "/containers/f1/kill":
		f.record("kill " + r.URL.Query().Get("signal"))
		w.WriteHeader(204)
	case r.Method == "GET" && r.URL.Path == "/containers/f1/logs":
		f.record("logs")
		q := r.URL.Query()
		if q.Get("stdout") != "1" || q.Get("stderr") != "1" || q.Get("follow") == "1" {
			f.t.Errorf("logs query = %s", r.URL.RawQuery)
		}
		var b bytes.Buffer
		for s := f.stdout; len(s) > 0; {
			n := min(len(s), 32<<10)
			b.Write(frame(1, s[:n]))
			s = s[n:]
		}
		if f.stderr != "" {
			b.Write(frame(2, f.stderr))
		}
		w.Write(b.Bytes())
	case r.Method == "GET" && r.URL.Path == "/containers/f1/archive":
		f.record("archive GET")
		f.getPath = r.URL.Query().Get("path")
		w.Header().Set("X-Docker-Container-Path-Stat", "eyJuYW1lIjoib3V0In0=") // {"name":"out"}
		w.Write([]byte("OUTTAR"))
	case r.Method == "DELETE" && r.URL.Path == "/containers/f1":
		f.record("delete")
		if r.URL.Query().Get("force") != "1" || r.URL.Query().Get("v") != "1" {
			f.t.Errorf("remove = %s, want force and volumes", r.URL.RawQuery)
		}
		w.WriteHeader(204)
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(404)
	}
}

func fixerSpec() RunSpec {
	return RunSpec{
		Image:   "sha256:" + strings.Repeat("a", 64),
		Cmd:     []string{"/usr/local/bin/hub", "folderfix", "restore", "--root=/folder"},
		User:    "0:0",
		Env:     []string{"GOMAXPROCS=2"},
		Binds:   []BindMount{{Source: "/srv/photos", Target: "/folder", ReadOnly: false}},
		Scratch: []string{"/in", "/out"},
		CapAdd:  []string{"CHOWN", "FOWNER"},
		Label:   "folder:photos",
		Pids:    16,
		Memory:  256 << 20,
		Timeout: time.Minute,
		InPath:  "/in",
		In:      strings.NewReader("INTAR"),
		OutPath: "/out",
	}
}

// The create body pins every isolation field (contract §6, rulings 19/23).
func TestRunHelperSpec(t *testing.T) {
	f := &fakeRun{t: t, stdout: "{\"mode\":\"restore\"}\n", stderr: "warn\n"}
	c := newTestClient(t, f)
	var got []byte
	res, err := c.RunHelper(context.Background(), fixerSpec(), func(r io.Reader) error {
		got, _ = io.ReadAll(r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != "{\"mode\":\"restore\"}\n" || string(res.Stderr) != "warn\n" {
		t.Errorf("result = %+v", res)
	}
	if string(got) != "OUTTAR" || f.getPath != "/out" || f.putPath != "/in" || f.putBody != "INTAR" {
		t.Errorf("archive: out %q get %q put %q %q", got, f.getPath, f.putPath, f.putBody)
	}
	want := []string{"create", "archive PUT", "start", "wait not-running", "logs", "archive GET", "delete"}
	if c := f.Calls(); !slices.Equal(c, want) {
		t.Errorf("calls = %v, want %v", c, want)
	}

	var cfg struct {
		Image, User, WorkingDir string
		Entrypoint, Cmd, Env    []string
		Tty, OpenStdin          bool
		AttachStdin             bool
		NetworkDisabled         bool
		Labels                  map[string]string
		Healthcheck             struct{ Test []string }
		Volumes                 map[string]any
		ExposedPorts            map[string]any
	}
	var hc struct {
		NetworkMode, IpcMode, PidMode, UTSMode, UsernsMode, CgroupnsMode string
		ReadonlyRootfs, Privileged, AutoRemove, PublishAllPorts          bool
		CapDrop, CapAdd, SecurityOpt, Binds, VolumesFrom, GroupAdd       []string
		PidsLimit, Memory, MemorySwap                                    int64
		Devices                                                          []any
		DeviceRequests                                                   []any
		PortBindings                                                     map[string]any
		LogConfig                                                        struct {
			Type   string
			Config map[string]string
		}
		Mounts []struct {
			Type, Source, Target string
			ReadOnly             bool
			BindOptions          map[string]any
			VolumeOptions        *struct{ NoCopy bool }
		}
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(f.create, &top); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(f.create, &cfg)
	if err := json.Unmarshal(top["HostConfig"], &hc); err != nil {
		t.Fatal(err)
	}
	if cfg.Image != fixerSpec().Image || cfg.User != "0:0" || !slices.Equal(cfg.Entrypoint, fixerSpec().Cmd) || len(cfg.Cmd) != 0 ||
		cfg.Tty || cfg.OpenStdin || cfg.AttachStdin || !cfg.NetworkDisabled || len(cfg.ExposedPorts) != 0 ||
		!slices.Equal(cfg.Healthcheck.Test, []string{"NONE"}) || !slices.Equal(cfg.Env, []string{"GOMAXPROCS=2"}) {
		t.Errorf("config = %+v", cfg)
	}
	if len(cfg.Labels) != 1 || cfg.Labels[LabelHelper] != "folder:photos" {
		t.Errorf("labels = %v", cfg.Labels)
	}
	if hc.NetworkMode != "none" || !hc.ReadonlyRootfs || hc.Privileged || hc.AutoRemove || hc.PublishAllPorts ||
		!slices.Equal(hc.CapDrop, []string{"ALL"}) || !slices.Equal(hc.CapAdd, []string{"CAP_CHOWN", "CAP_FOWNER"}) ||
		!slices.Equal(hc.SecurityOpt, []string{"no-new-privileges:true"}) || len(hc.Binds) != 0 || len(hc.VolumesFrom) != 0 ||
		len(hc.GroupAdd) != 0 || len(hc.Devices) != 0 || len(hc.DeviceRequests) != 0 || len(hc.PortBindings) != 0 ||
		hc.PidsLimit != 16 || hc.Memory != 268435456 || hc.MemorySwap != 268435456 {
		t.Errorf("host config = %+v", hc)
	}
	// No host namespace of any kind.
	if hc.IpcMode != "private" || hc.PidMode != "" || hc.UTSMode != "" || hc.UsernsMode != "" || hc.CgroupnsMode != "private" {
		t.Errorf("namespaces: ipc %q pid %q uts %q userns %q cgroupns %q", hc.IpcMode, hc.PidMode, hc.UTSMode, hc.UsernsMode, hc.CgroupnsMode)
	}
	if hc.LogConfig.Type != "json-file" {
		t.Errorf("log config = %+v", hc.LogConfig)
	}
	if len(hc.Mounts) != 3 {
		t.Fatalf("mounts = %+v", hc.Mounts)
	}
	b := hc.Mounts[0]
	if b.Type != "bind" || b.Source != "/srv/photos" || b.Target != "/folder" || b.ReadOnly || b.BindOptions["CreateMountpoint"] != nil {
		t.Errorf("bind = %+v", b)
	}
	for i, tg := range []string{"/in", "/out"} {
		m := hc.Mounts[i+1]
		if m.Type != "volume" || m.Source != "" || m.Target != tg || m.ReadOnly || m.VolumeOptions == nil || !m.VolumeOptions.NoCopy {
			t.Errorf("scratch %s = %+v", tg, m)
		}
	}

	// Read-only bind, no scratch, no copy.
	f2 := &fakeRun{t: t, stdout: "{}\n"}
	s := fixerSpec()
	s.Binds[0].ReadOnly, s.Scratch, s.In, s.InPath, s.OutPath = true, nil, nil, "", ""
	if _, err := newTestClient(t, f2).RunHelper(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
	if want := []string{"create", "start", "wait not-running", "logs", "delete"}; !slices.Equal(f2.Calls(), want) {
		t.Errorf("calls = %v", f2.Calls())
	}
	json.Unmarshal(f2.create, &top)
	hc.Mounts = nil
	json.Unmarshal(top["HostConfig"], &hc)
	if len(hc.Mounts) != 1 || !hc.Mounts[0].ReadOnly {
		t.Errorf("mounts = %+v", hc.Mounts)
	}
}

// The spec is checked before anything is created.
func TestRunHelperRefusesBadSpec(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_ping" {
			t.Errorf("called %s %s", r.Method, r.URL.Path)
		}
	}))
	for name, mut := range map[string]func(*RunSpec){
		"no image":      func(s *RunSpec) { s.Image = "" },
		"tag image":     func(s *RunSpec) { s.Image = "ghcr.io/porelli/portcullis-hub:edge" },
		"relative argv": func(s *RunSpec) { s.Cmd[0] = "hub" },
		"no user":       func(s *RunSpec) { s.User = "" },
		"no label":      func(s *RunSpec) { s.Label = "" },
		"no pids":       func(s *RunSpec) { s.Pids = 0 },
		"no memory":     func(s *RunSpec) { s.Memory = 0 },
		"no timeout":    func(s *RunSpec) { s.Timeout = 0 },
		"in no path":    func(s *RunSpec) { s.InPath = "" },
		"relative bind": func(s *RunSpec) { s.Binds[0].Source = "srv" },
		"unclean bind":  func(s *RunSpec) { s.Binds[0].Source = "/srv/../etc" },
		"bad target":    func(s *RunSpec) { s.Binds[0].Target = "/" },
		"scratch dup":   func(s *RunSpec) { s.Scratch = []string{"/folder"} },
		"cap all":       func(s *RunSpec) { s.CapAdd = []string{"ALL"} },
		"cap admin":     func(s *RunSpec) { s.CapAdd = []string{"SYS_ADMIN"} },
		"cap lower":     func(s *RunSpec) { s.CapAdd = []string{"chown"} },
	} {
		s := fixerSpec()
		s.Cmd = slices.Clone(s.Cmd)
		s.Binds = slices.Clone(s.Binds)
		mut(&s)
		if _, err := c.RunHelper(context.Background(), s, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Start fails → the container is still removed; the wait exceeds the
// timeout → killed, then removed, and the run is an error.
func TestRunHelperRemovesOnFailure(t *testing.T) {
	f := &fakeRun{t: t, startErr: true}
	s := fixerSpec()
	s.In, s.InPath = nil, ""
	if _, err := newTestClient(t, f).RunHelper(context.Background(), s, nil); err == nil {
		t.Error("start failure: no error")
	}
	if want := []string{"create", "start", "delete"}; !slices.Equal(f.Calls(), want) {
		t.Errorf("calls = %v, want %v", f.Calls(), want)
	}

	f = &fakeRun{t: t, block: true}
	s.Timeout = 50 * time.Millisecond
	_, err := newTestClient(t, f).RunHelper(context.Background(), s, nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("timeout: err = %v", err)
	}
	if want := []string{"create", "start", "wait not-running", "kill KILL", "delete"}; !slices.Equal(f.Calls(), want) {
		t.Errorf("calls = %v, want %v", f.Calls(), want)
	}

	// The caller cancels: killed and removed too, though ctx is done.
	f = &fakeRun{t: t, block: true}
	s.Timeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := newTestClient(t, f).RunHelper(ctx, s, nil); err == nil {
		t.Error("cancel: no error")
	}
	if want := []string{"create", "start", "wait not-running", "kill KILL", "delete"}; !slices.Equal(f.Calls(), want) {
		t.Errorf("calls = %v, want %v", f.Calls(), want)
	}

	// A failing out callback is the run's error, after the removal.
	f = &fakeRun{t: t, stdout: "{}\n"}
	s = fixerSpec()
	s.In, s.InPath = nil, ""
	if _, err := newTestClient(t, f).RunHelper(context.Background(), s, func(io.Reader) error { return io.ErrUnexpectedEOF }); err == nil {
		t.Error("out error: no error")
	}
	if c := f.Calls(); c[len(c)-1] != "delete" {
		t.Errorf("calls = %v", c)
	}

	// A non-zero exit is no Docker error, and nothing is copied out.
	f = &fakeRun{t: t, exit: 2, stdout: "{}\n"}
	res, err := newTestClient(t, f).RunHelper(context.Background(), s, func(io.Reader) error { t.Error("copied out"); return nil })
	if err != nil || res.ExitCode != 2 {
		t.Errorf("exit 2: %+v, %v", res, err)
	}
	if want := []string{"create", "start", "wait not-running", "logs", "delete"}; !slices.Equal(f.Calls(), want) {
		t.Errorf("calls = %v, want %v", f.Calls(), want)
	}
}

// stdout keeps its last 256 KiB (the report is the last line), stderr its
// first 16 KiB (a crash's message comes first).
func TestRunHelperClipsLogs(t *testing.T) {
	big := strings.Repeat("x", 1<<20-len("REPORT\n")) + "REPORT\n"
	f := &fakeRun{t: t, stdout: big, stderr: "PANIC" + strings.Repeat("y", 64<<10)}
	s := fixerSpec()
	s.In, s.InPath, s.OutPath = nil, "", ""
	res, err := newTestClient(t, f).RunHelper(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != 256<<10 || !strings.HasSuffix(string(res.Stdout), "REPORT\n") || !res.StdoutClipped {
		t.Errorf("stdout: %d bytes, clipped %v", len(res.Stdout), res.StdoutClipped)
	}
	if len(res.Stderr) != 16<<10 || !strings.HasPrefix(string(res.Stderr), "PANIC") || !res.StderrClipped {
		t.Errorf("stderr: %d bytes, clipped %v", len(res.Stderr), res.StderrClipped)
	}
}

func TestInspectContainerAndSecurity(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/_ping":
		case "/containers/abc123/json":
			w.Write([]byte(`{"Id":"abc123full","Image":"sha256:` + strings.Repeat("b", 64) + `","Config":{"Image":"ghcr.io/x:edge","Labels":{"a":"b"}},"HostConfig":{"Memory":536870912,"PidsLimit":256}}`))
		case "/containers/nolimits/json":
			w.Write([]byte(`{"Id":"nolimits","Image":"sha256:x","HostConfig":{"Memory":0,"PidsLimit":-1}}`))
		case "/info":
			w.Write([]byte(`{"SecurityOptions":["name=seccomp,profile=builtin","name=userns"],"DockerRootDir":"/mnt/ssd/docker"}`))
		default:
			http.Error(w, `{"message":"no such container"}`, 404)
		}
	}))
	ci, err := c.InspectContainer(context.Background(), "abc123")
	if err != nil || ci.ID != "abc123full" || ci.Image != "sha256:"+strings.Repeat("b", 64) || ci.Labels["a"] != "b" {
		t.Errorf("inspect = %+v, %v", ci, err)
	}
	if ci.Memory != 512<<20 || ci.PidsLimit != 256 {
		t.Errorf("limits = %d, %d", ci.Memory, ci.PidsLimit)
	}
	if ci, err := c.InspectContainer(context.Background(), "nolimits"); err != nil || ci.Memory != 0 || ci.PidsLimit != 0 {
		t.Errorf("no limits = %+v, %v", ci, err)
	}
	if _, err := c.InspectContainer(context.Background(), "nope"); !IsNotFound(err) {
		t.Errorf("missing: %v", err)
	}
	opts, err := c.SecurityOptions(context.Background())
	if err != nil || !slices.Equal(opts, []string{"name=seccomp,profile=builtin", "name=userns"}) {
		t.Errorf("security options = %v, %v", opts, err)
	}
	if root, err := c.DockerRootDir(context.Background()); err != nil || root != "/mnt/ssd/docker" {
		t.Errorf("docker root = %q, %v", root, err)
	}
}

func TestRemappedIDs(t *testing.T) {
	for _, c := range []struct {
		opts []string
		want string
	}{
		{nil, ""},
		{[]string{"name=seccomp,profile=builtin", "name=apparmor", "name=cgroupns"}, ""},
		{[]string{"name=userns"}, "userns"},
		{[]string{"name=seccomp,profile=builtin", "name=rootless"}, "rootless"},
		{[]string{"name=usernsx"}, ""},
	} {
		if got := RemappedIDs(c.opts); got != c.want {
			t.Errorf("RemappedIDs(%v) = %q, want %q", c.opts, got, c.want)
		}
	}
}
