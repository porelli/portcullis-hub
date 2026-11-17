package fixerspec

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/folderfix"
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
		if _, err := Rebuild(sent, agentBinary, []string{"/srv"}); err != nil {
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
		if _, err := Rebuild(s, agentBinary, []string{"/srv"}); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "not a fixed helper") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A writable bind on a read-only mode.
	probe := agentapi.FixerSpecOf(runs()["probe"].Spec("", agentBinary))
	probe.Binds[0].ReadOnly = false
	if _, err := Rebuild(probe, agentBinary, []string{"/srv"}); err == nil {
		t.Error("a writable probe accepted")
	}
	// A folder that is, holds or is inside a protected path is refused.
	for _, prot := range []string{"/srv/photos", "/srv/photos/sub", "/srv"} {
		if _, err := Rebuild(good, agentBinary, []string{"/srv"}, prot); err == nil {
			t.Errorf("protected %s: accepted", prot)
		}
	}
	if _, err := Rebuild(good, agentBinary, []string{"/srv"}, "/srv/other"); err != nil {
		t.Errorf("an unrelated protected path: %v", err)
	}
	// The roots decide.
	if _, err := Rebuild(good, agentBinary, []string{"/mnt"}); err == nil {
		t.Error("a folder outside the worker's roots accepted")
	}
}

func clone(s agentapi.FixerSpec) agentapi.FixerSpec {
	s.Cmd = append([]string{}, s.Cmd...)
	s.Binds = append([]agentapi.BindMount{}, s.Binds...)
	s.CapAdd = append([]string{}, s.CapAdd...)
	s.Env = append([]string{}, s.Env...)
	s.Scratch = append([]string{}, s.Scratch...)
	return s
}

func fixRoot(cmd []string) []string { return cmd }
