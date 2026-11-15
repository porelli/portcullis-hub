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
)

// ErrNotFixed prefixes every Rebuild refusal (the agent answers 403).
var ErrNotFixed = errors.New("not a fixed helper")

// Rebuild is the worker agent's check of a folder_fix spec it is sent
// (contract §17.4): it recovers the run from the spec's argv (binary
// folderfix <mode> <flags>), its one bind, label and transfers, refuses a
// folder outside roots, validates the run, rebuilds the spec with Spec and
// accepts it only when the two encodings are byte for byte the same.
func Rebuild(s agentapi.FixerSpec, binary string, roots []string) (Run, error) {
	refuse := func(format string, args ...any) (Run, error) {
		return Run{}, fmt.Errorf("%w: "+format, append([]any{ErrNotFixed}, args...)...)
	}
	if len(s.Cmd) < 3 || s.Cmd[0] != binary || s.Cmd[1] != "folderfix" {
		return refuse("the command must be %s folderfix <mode> …", binary)
	}
	if len(s.Binds) != 1 {
		return refuse("exactly one bind")
	}
	mode, o, x, err := folderfix.ParseArgs(s.Cmd[2:])
	if err != nil {
		return refuse("%v", err)
	}
	src := s.Binds[0].Source
	if !underAny(src, roots) {
		return refuse("the folder is outside the server's folder roots")
	}
	r := Run{Mode: mode, Source: src, Opts: o, Extra: x, Timeout: time.Duration(s.TimeoutMS) * time.Millisecond}
	switch {
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
	if err := r.Validate(); err != nil {
		return refuse("%v", err)
	}
	if !agentapi.SameFixer(s, agentapi.FixerSpecOf(r.Spec("", binary))) {
		return refuse("the spec differs from the fixer's own")
	}
	return r, nil
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
