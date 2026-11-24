package fixerspec

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
)

const agentBinary = "/usr/local/bin/portcullis-agent"

func runs() map[string]Run {
	gid := 1000
	id := folderfix.Options{ExpectDev: 64768, ExpectIno: 2, ExpectMountRoot: "/srv"}
	apply := id
	apply.Target.GID, apply.Target.Files = gid, "rw"
	apply.ExpectDigest = strings.Repeat("a", 64)
	snap := id
	snap.Target.GID, snap.Target.Files = gid, "rw"
	return map[string]Run{
		"scan":          {Mode: "scan", Folder: "photos", Source: "/srv/photos", Opts: id},
		"path scan":     {Mode: "scan", Source: "/srv/x"},
		"learning scan": {Mode: "scan", Folder: "photos", Source: "/srv/photos", Opts: folderfix.Options{ExpectDev: 1, ExpectIno: 2}, Unchecked: true},
		"probe":         {Mode: "probe", Source: "/srv", Extra: folderfix.ArgsExtra{Rel: "photos"}},
		"probe create":  {Mode: "probe", Source: "/srv", Extra: folderfix.ArgsExtra{Rel: "photos/new", Create: true}},
		"snapshot":      {Mode: "snapshot", Folder: "photos", Source: "/srv/photos", Opts: snap, Out: func(r io.Reader) error { return nil }},
		"apply":         {Mode: "apply", Folder: "photos", Source: "/srv/photos", Opts: apply},
		"restore":       {Mode: "restore", Folder: "photos", Source: "/srv/photos", Opts: snap, In: strings.NewReader("")},
		"timeout":       {Mode: "scan", Source: "/srv/x", Timeout: 3 * time.Minute},
	}
}

// TestRebuildSameSpec: every spec the Hub builds is rebuilt byte for byte
// by the agent's own builder (the agent's binary, its own image).
func TestRebuildSameSpec(t *testing.T) {
	for name, r := range runs() {
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sent := agentapi.FixerSpecOf(r.Spec("", agentBinary))
		if _, err := Rebuild(sent, agentBinary, []string{"/srv"}, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestRebuildRefusesAnythingElse: a spec that differs from the builder's
// in any field, or binds outside the folder roots, is "not a fixed helper".
func TestRebuildRefusesAnythingElse(t *testing.T) {
	base := runs()["apply"]
	good := agentapi.FixerSpecOf(base.Spec("", agentBinary))
	mut := map[string]func(s *agentapi.FixerSpec){
		"another binary":      func(s *agentapi.FixerSpec) { s.Cmd[0] = "/bin/sh" },
		"a shell command":     func(s *agentapi.FixerSpec) { s.Cmd = []string{"/bin/sh", "-c", "id"} },
		"an extra flag":       func(s *agentapi.FixerSpec) { s.Cmd = append(s.Cmd, "--evil") },
		"an extra capability": func(s *agentapi.FixerSpec) { s.CapAdd = append(s.CapAdd, "SYS_ADMIN") },
		"another user":        func(s *agentapi.FixerSpec) { s.User = "1000:1000" },
		"a second bind": func(s *agentapi.FixerSpec) {
			s.Binds = append(s.Binds, agentapi.BindMount{Source: "/etc", Target: "/etc"})
		},
		"a bind outside roots": func(s *agentapi.FixerSpec) { s.Binds[0].Source = "/etc"; s.Cmd = fixRoot(s.Cmd) },
		"a writable probe":     func(s *agentapi.FixerSpec) {},
		"more memory":          func(s *agentapi.FixerSpec) { s.Memory *= 4 },
		"more pids":            func(s *agentapi.FixerSpec) { s.Pids = 1024 },
		"another label":        func(s *agentapi.FixerSpec) { s.Label = "evil" },
		"extra env":            func(s *agentapi.FixerSpec) { s.Env = append(s.Env, "LD_PRELOAD=/x") },
		"a scratch volume":     func(s *agentapi.FixerSpec) { s.Scratch = append(s.Scratch, "/tmp") },
		"an in path":           func(s *agentapi.FixerSpec) { s.InPath = "/in" },
		"no folderfix":         func(s *agentapi.FixerSpec) { s.Cmd = s.Cmd[:1] },
		"empty":                func(s *agentapi.FixerSpec) { *s = agentapi.FixerSpec{} },
	}
	delete(mut, "a writable probe")
	for name, f := range mut {
		s := clone(good)
		f(&s)
		if _, err := Rebuild(s, agentBinary, []string{"/srv"}, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "not a fixed helper") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A writable bind on a read-only mode.
	probe := agentapi.FixerSpecOf(runs()["probe"].Spec("", agentBinary))
	probe.Binds[0].ReadOnly = false
	if _, err := Rebuild(probe, agentBinary, []string{"/srv"}, nil); err == nil {
		t.Error("a writable probe accepted")
	}
	// A folder that is, holds or is inside a protected path is refused.
	for _, prot := range []string{"/srv/photos", "/srv/photos/sub", "/srv"} {
		if _, err := Rebuild(good, agentBinary, []string{"/srv"}, nil, prot); err == nil {
			t.Errorf("protected %s: accepted", prot)
		}
	}
	if _, err := Rebuild(good, agentBinary, []string{"/srv"}, nil, "/srv/other"); err != nil {
		t.Errorf("an unrelated protected path: %v", err)
	}
	// The roots decide.
	if _, err := Rebuild(good, agentBinary, []string{"/mnt"}, nil); err == nil {
		t.Error("a folder outside the worker's roots accepted")
	}
}

func clone(s agentapi.FixerSpec) agentapi.FixerSpec {
	s.Cmd = append([]string{}, s.Cmd...)
	s.Binds = append([]agentapi.BindMount{}, s.Binds...)
	s.CapAdd = append([]string{}, s.CapAdd...)
	s.Env = append([]string{}, s.Env...)
	s.Scratch = append([]string{}, s.Scratch...)
	if s.Volumes != nil {
		s.Volumes = append([]agentapi.VolumeMount{}, s.Volumes...)
	}
	return s
}

func fixRoot(cmd []string) []string { return cmd }

// TestRebuildUsage (contract §17.4, ux3): the usage mode on a worker is
// admitted with label usage:<target>, for a bundled project's volume (the
// agent's volumeInScope) or a bind under the worker's roots; a usage:
// label with another mode, or a usage run with another label, is refused.
func TestRebuildUsage(t *testing.T) {
	caps := folderfix.Options{MaxEntries: 2_000_000, MaxTime: 2 * time.Minute}
	inScope := func(name string) bool { return name == "portcullis-paperless_data" }
	vol := agentapi.FixerSpecOf(Run{Mode: "usage", Volume: runtime.VolumeMount{Name: "portcullis-paperless_data", Instance: "paperless"}, Opts: caps}.Spec("", agentBinary))
	r, err := Rebuild(vol, agentBinary, []string{"/srv"}, inScope)
	if err != nil {
		t.Fatalf("a bundled project's volume: %v", err)
	}
	if r.Mode != "usage" || r.Volume.Name != "portcullis-paperless_data" || r.Volume.Instance != "paperless" || r.Source != "" {
		t.Errorf("rebuilt %+v", r)
	}
	bind := agentapi.FixerSpecOf(Run{Mode: "usage", Source: "/srv/paperless/media", Opts: caps}.Spec("", agentBinary))
	if _, err := Rebuild(bind, agentBinary, []string{"/srv"}, inScope); err != nil {
		t.Errorf("a bind under the roots: %v", err)
	}
	refused := func(name string, s agentapi.FixerSpec, want string, scope func(string) bool) {
		t.Helper()
		_, err := Rebuild(s, agentBinary, []string{"/srv"}, scope)
		if err == nil || !strings.Contains(err.Error(), "not a fixed helper") || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	out := agentapi.FixerSpecOf(Run{Mode: "usage", Source: "/etc", Opts: caps}.Spec("", agentBinary))
	refused("a bind outside the roots", out, "outside", inScope)
	other := agentapi.FixerSpecOf(Run{Mode: "usage", Volume: runtime.VolumeMount{Name: "portcullis-other_data", Instance: "other"}, Opts: caps}.Spec("", agentBinary))
	refused("another project's volume", other, "volume portcullis-other_data is not a bundled project's", inScope)
	refused("no volume scope", vol, "is not a bundled project's", nil)
	// The usage: label with the scan mode.
	scan := agentapi.FixerSpecOf(Run{Mode: "scan", Source: "/srv/x"}.Spec("", agentBinary))
	scan.Label = "usage:/srv/x"
	refused("label usage: with mode scan", scan, "usage", inScope)
	// The usage mode with another label.
	relabel := clone(bind)
	relabel.Label = "path-check"
	refused("mode usage with label path-check", relabel, "usage", inScope)
	// Both a volume and a bind, or neither.
	both := clone(vol)
	both.Binds = []agentapi.BindMount{{Source: "/srv/x", Target: UsageRoot, ReadOnly: true}}
	refused("a volume and a bind", both, "exactly one", inScope)
	none := clone(vol)
	none.Volumes = nil
	refused("no mount", none, "exactly one", inScope)
	// A writable bind, a second volume, more caps: not the builder's.
	rw := clone(bind)
	rw.Binds[0].ReadOnly = false
	refused("a writable bind", rw, "differs", inScope)
	extra := clone(vol)
	extra.CapAdd = append(extra.CapAdd, "DAC_OVERRIDE")
	refused("an extra capability", extra, "differs", inScope)
	retarget := clone(vol)
	retarget.Volumes[0].Target = "/etc"
	refused("a volume elsewhere", retarget, "differs", inScope)
	// A volume on a mode that isn't usage.
	vs := clone(scan)
	vs.Label = "path-check"
	vs.Volumes = []agentapi.VolumeMount{{Name: "portcullis-paperless_data", Target: UsageRoot}}
	refused("a volume on a scan", vs, "volume", inScope)
}

// TestUsageCaps (Task 9 review nit 3): a usage run asks for at most the
// primary's caps; the worker's agent refuses more.
func TestUsageCaps(t *testing.T) {
	base := Run{Mode: "usage", Source: "/srv/x", Opts: folderfix.Options{MaxEntries: UsageMaxEntries, MaxTime: UsageMaxTime}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	more := base
	more.Opts.MaxEntries++
	long := base
	long.Opts.MaxTime = UsageMaxTime + time.Second
	slow := base
	slow.Timeout = UsageMaxTime + time.Minute
	for name, r := range map[string]Run{"more entries": more, "a longer walk": long, "a longer timeout": slow} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		spec := agentapi.FixerSpecOf(r.Spec("", agentBinary))
		if _, err := Rebuild(spec, agentBinary, []string{"/srv"}, nil); err == nil {
			t.Errorf("%s: rebuilt", name)
		}
	}
	// A volume name is checked before the scope hook ever sees it.
	asked := 0
	scope := func(string) bool { asked++; return true }
	bad := agentapi.FixerSpecOf(Run{Mode: "usage", Volume: runtime.VolumeMount{Name: "ok"}, Opts: base.Opts}.Spec("", agentBinary))
	bad.Volumes[0].Name = "a/../b"
	if _, err := Rebuild(bad, agentBinary, []string{"/srv"}, scope); err == nil || asked != 0 {
		t.Errorf("a bad volume name: %v, hook asked %d times", err, asked)
	}
}
