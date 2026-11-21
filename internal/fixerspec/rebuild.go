package fixerspec

import (
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
)

// ErrNotFixed prefixes every Rebuild refusal (the agent answers 403).
var ErrNotFixed = errors.New("not a fixed helper")

// Rebuild is the worker agent's check of a folder_fix spec it is sent
// (contract §17.4): it recovers the run from the spec's argv (binary
// folderfix <mode> <flags>), its one bind, label and transfers, refuses a
// folder outside roots, validates the run, rebuilds the spec with Spec and
// accepts it only when the two encodings are byte for byte the same.
//
// protected are paths the folder may not equal, contain or be inside
// (the agent's data dir, the engine's roots; "/" always).
//
// The usage mode (ux3) goes with label usage:<target> only, and measures
// exactly one read-only mount: a bind under roots (the protected paths
// apply), or a named volume volumeInScope accepts (a bundled project's;
// nil: none is).
func Rebuild(s agentapi.FixerSpec, binary string, roots []string, volumeInScope func(name string) bool, protected ...string) (Run, error) {
	refuse := func(format string, args ...any) (Run, error) {
		return Run{}, fmt.Errorf("%w: "+format, append([]any{ErrNotFixed}, args...)...)
	}
	if len(s.Cmd) < 3 || s.Cmd[0] != binary || s.Cmd[1] != "folderfix" {
		return refuse("the command must be %s folderfix <mode> …", binary)
	}
	mode, o, x, err := folderfix.ParseArgs(s.Cmd[2:])
	if err != nil {
		return refuse("%v", err)
	}
	usageLabel := strings.HasPrefix(s.Label, "usage:")
	if (mode == "usage") != usageLabel {
		return refuse("the usage mode goes with a usage: label only (mode %s, label %q)", mode, s.Label)
	}
	if mode != "usage" && len(s.Volumes) > 0 {
		return refuse("a named volume is for the usage mode only")
	}
	if mode == "usage" {
		if len(s.Binds)+len(s.Volumes) != 1 {
			return refuse("usage measures exactly one volume or one bind")
		}
		if len(s.Volumes) == 1 {
			v := s.Volumes[0]
			if volumeInScope == nil || !volumeInScope(v.Name) {
				return refuse("volume %s is not a bundled project's", clipName(v.Name))
			}
			r := Run{Mode: mode, Volume: runtime.VolumeMount{Name: v.Name, Target: v.Target, Instance: v.Instance}, Opts: o, Extra: x,
				Timeout: time.Duration(s.TimeoutMS) * time.Millisecond}
			return rebuilt(s, r, binary, refuse)
		}
	}
	if len(s.Binds) != 1 {
		return refuse("exactly one bind")
	}
	src := s.Binds[0].Source
	if !underAny(src, roots) {
		return refuse("the folder is outside the server's folder roots")
	}
	for _, f := range append(protected, "/") {
		f = path.Clean(f)
		if src == f || (f != "/" && (strings.HasPrefix(src, f+"/") || strings.HasPrefix(f, src+"/"))) {
			return refuse("the folder touches a protected path (%s)", f)
		}
	}
	r := Run{Mode: mode, Source: src, Opts: o, Extra: x, Timeout: time.Duration(s.TimeoutMS) * time.Millisecond}
	switch {
	case mode == "usage":
		return rebuilt(s, r, binary, refuse)
	case s.Label == "path-check":
	case strings.HasPrefix(s.Label, "folder:"):
		r.Folder = strings.TrimPrefix(s.Label, "folder:")
	default:
		return refuse("label %q", s.Label)
	}
	if s.InPath != "" {
		r.In = strings.NewReader("")
	}
	if s.OutPath != "" {
		r.Out = func(io.Reader) error { return nil }
	}
	if mode == "scan" && r.Folder != "" && o.ExpectMountRoot == "" {
		r.Unchecked = true
	}
	return rebuilt(s, r, binary, refuse)
}

// rebuilt validates r and accepts s only when it is byte for byte r's
// own spec.
func rebuilt(s agentapi.FixerSpec, r Run, binary string, refuse func(string, ...any) (Run, error)) (Run, error) {
	if err := r.Validate(); err != nil {
		return refuse("%v", err)
	}
	if !agentapi.SameFixer(s, agentapi.FixerSpecOf(r.Spec("", binary))) {
		return refuse("the spec differs from the fixer's own")
	}
	return r, nil
}

// clipName is a volume name for a refusal: printable, at most 120 runes.
func clipName(n string) string {
	n = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return '?'
		}
		return c
	}, n)
	if rs := []rune(n); len(rs) > 120 {
		n = string(rs[:120]) + "…"
	}
	return n
}

func underAny(p string, roots []string) bool {
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return false
	}
	for _, r := range roots {
		if r != "/" && (p == r || strings.HasPrefix(p, r+"/")) {
			return true
		}
	}
	return false
}
