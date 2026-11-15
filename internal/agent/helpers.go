package agent

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/fixerspec"
	"github.com/portcullis/hub/internal/runtime"
)

const syscallNoFollow = syscall.O_NOFOLLOW

// MaxFixerTransfer bounds a fixer snapshot (in or out; the Hub's
// maxSnapshotBytes).
const MaxFixerTransfer = 2 << 30

// createHelper is POST /v1/helpers: a volume_io helper on a volume of a
// bundled instance (by its compose labels), or a folder_fix run whose
// spec the agent rebuilds byte for byte (fixerspec.Rebuild, its own
// binary and image, binds under the worker's folder roots).
func (a *API) createHelper(w http.ResponseWriter, r *http.Request) {
	var req agentapi.HelperSpec
	if !decodeBody(w, r, &req) {
		return
	}
	h := &helper{spec: req}
	switch req.Kind {
	case agentapi.HelperVolumeIO:
		if req.Spec != nil || a.project(req.Instance) == nil {
			writeError(w, http.StatusForbidden, "not a fixed helper: a volume helper of a bundled instance")
			return
		}
		if !path.IsAbs(req.Path) || path.Clean(req.Path) != req.Path || req.Path == "/" {
			writeError(w, http.StatusBadRequest, "path must be an absolute clean mount point")
			return
		}
		v, owner, ok := a.scopedVolume(w, r, req.Volume)
		if !ok {
			return
		}
		if owner != req.Instance {
			writeError(w, http.StatusForbidden, "volume "+v.Name+" is another instance's")
			return
		}
	case agentapi.HelperFolderFix:
		if req.Spec == nil || req.Instance != "" || req.Volume != "" || req.Path != "" || req.Write {
			writeError(w, http.StatusForbidden, "not a fixed helper: folder_fix takes its spec only")
			return
		}
		if _, err := fixerspec.Rebuild(*req.Spec, AgentBinary, a.cfg.BindRoots, a.protected()...); err != nil {
			writeError(w, http.StatusForbidden, clipMsg(err.Error()))
			return
		}
		if err := walkNoSymlink(nil, a.cfg.BindRoots, req.Spec.Binds[0].Source); err != nil {
			writeError(w, http.StatusForbidden, "not a fixed helper: "+clipMsg(err.Error()))
			return
		}
		if a.cfg.SelfImage == "" {
			writeError(w, http.StatusServiceUnavailable, "the agent's own image is unknown: the fixer can't run")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "kind must be volume_io or folder_fix")
		return
	}
	id := randomID()
	a.mu.Lock()
	a.helpers[id] = h
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, agentapi.HelperCreated{ID: id})
}

// helperArchiveOut: GET /v1/helpers/{h}/archive — a volume_io read, or a
// finished folder_fix run's out tar.
func (a *API) helperArchiveOut(w http.ResponseWriter, r *http.Request) {
	_, h, ok := a.helper(w, r)
	if !ok {
		return
	}
	switch {
	case h.spec.Kind == agentapi.HelperVolumeIO && !h.spec.Write:
		rc, err := a.cfg.Runtime.VolumeOut(r.Context(), h.spec.Instance, h.spec.Volume, h.spec.Path)
		if err != nil {
			engineError(w, err)
			return
		}
		defer rc.Close()
		w.Header().Set("Content-Type", "application/x-tar")
		io.Copy(w, rc)
	case h.spec.Kind == agentapi.HelperFolderFix && h.ran && h.out != "":
		f, err := os.Open(h.out)
		if err != nil {
			writeError(w, http.StatusNotFound, "no output")
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/x-tar")
		io.Copy(w, f)
	default:
		writeError(w, http.StatusConflict, "this helper has nothing to read")
	}
}

// helperArchiveIn: PUT /v1/helpers/{h}/archive — a volume_io write, or a
// folder_fix run's input (its InPath), staged before the run.
func (a *API) helperArchiveIn(w http.ResponseWriter, r *http.Request) {
	id, h, ok := a.helper(w, r)
	if !ok {
		return
	}
	switch {
	case h.spec.Kind == agentapi.HelperVolumeIO && h.spec.Write:
		// Every entry checked (review M1) and re-encoded: the engine only
		// ever sees the checked stream.
		pr, pw := io.Pipe()
		limit, ok := a.freeForRestore(r.Context())
		if !ok {
			writeError(w, http.StatusInsufficientStorage, "the engine's free space can't be read: a restore needs it")
			return
		}
		go func() { pw.CloseWithError(checkedVolumeTar(r.Body, pw, path.Base(h.spec.Path), limit)) }()
		err := a.cfg.Runtime.VolumeIn(r.Context(), h.spec.Instance, h.spec.Volume, h.spec.Path, pr)
		pr.CloseWithError(err)
		if err != nil {
			var ve *volumeTarError
			if errors.As(err, &ve) {
				code := http.StatusBadRequest
				if ve.status != 0 {
					code = ve.status
				}
				writeError(w, code, clipMsg(ve.Error()))
				return
			}
			engineError(w, err)
			return
		}
	case h.spec.Kind == agentapi.HelperFolderFix && h.spec.Spec.InPath != "" && !h.ran:
		if err := os.MkdirAll(a.helpersDir(), 0o700); err != nil {
			writeError(w, http.StatusInternalServerError, "can't stage the input")
			return
		}
		p := filepath.Join(a.helpersDir(), id+".in")
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscallNoFollow, 0o600)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "can't stage the input")
			return
		}
		n, err := io.Copy(f, io.LimitReader(r.Body, MaxFixerTransfer+1))
		f.Close()
		if err != nil || n > MaxFixerTransfer {
			os.Remove(p)
			writeError(w, http.StatusRequestEntityTooLarge, "the input is over its cap")
			return
		}
		a.mu.Lock()
		h.in = p
		a.mu.Unlock()
	default:
		writeError(w, http.StatusConflict, "this helper takes no input")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// helperRun: POST /v1/helpers/{h}/run — the folder_fix run on the agent's
// own image; its out tar is kept for GET archive.
func (a *API) helperRun(w http.ResponseWriter, r *http.Request) {
	id, h, ok := a.helper(w, r)
	if !ok {
		return
	}
	if h.spec.Kind != agentapi.HelperFolderFix || h.ran {
		writeError(w, http.StatusConflict, "only a folder_fix helper runs, once")
		return
	}
	if h.spec.Spec.InPath != "" && h.in == "" {
		writeError(w, http.StatusConflict, "put the input first")
		return
	}
	var in io.Reader
	if h.in != "" {
		f, err := os.Open(h.in)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "the staged input is gone")
			return
		}
		defer f.Close()
		in = f
	}
	// The folder again, right before the run (C4).
	if err := walkNoSymlink(nil, a.cfg.BindRoots, h.spec.Spec.Binds[0].Source); err != nil {
		writeError(w, http.StatusConflict, clipMsg(err.Error()))
		return
	}
	spec := h.spec.Spec.Runtime(a.cfg.SelfImage, in)
	outPath := ""
	out := func(t io.Reader) error {
		if err := os.MkdirAll(a.helpersDir(), 0o700); err != nil {
			return err
		}
		outPath = filepath.Join(a.helpersDir(), id+".out")
		f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscallNoFollow, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		n, err := io.Copy(f, io.LimitReader(t, MaxFixerTransfer+1))
		if err == nil && n > MaxFixerTransfer {
			err = errors.New("the fixer's output is over its cap")
		}
		return err
	}
	res, err := a.cfg.Runtime.RunFixer(r.Context(), spec, out)
	if err != nil {
		engineError(w, err)
		return
	}
	a.mu.Lock()
	h.ran, h.result, h.out = true, res, outPath
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, agentapi.RunResult{ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr, StdoutClipped: res.StdoutClipped, StderrClipped: res.StderrClipped})
}

// removeHelper: DELETE /v1/helpers/{h} — a registered helper (its staged
// files removed), or a leftover helper container of a bundled instance.
func (a *API) removeHelper(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("h")
	a.mu.Lock()
	h := a.helpers[id]
	delete(a.helpers, id)
	a.mu.Unlock()
	if h != nil {
		if h.in != "" {
			os.Remove(h.in)
		}
		if h.out != "" {
			os.Remove(h.out)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	units, err := a.cfg.Runtime.List(r.Context(), runtime.Filter{Helper: true})
	if err != nil {
		engineError(w, err)
		return
	}
	for _, u := range units {
		if u.ID == id {
			if _, ok := a.inScope(u.Labels); !ok {
				break
			}
			if err := a.cfg.Runtime.RemoveHelper(r.Context(), id); err != nil {
				engineError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	writeError(w, http.StatusNotFound, "no such helper")
}

// ── data files ───────────────────────────────────────────────────────────

type appFile struct {
	name string
	data []byte
	mode os.FileMode
}

// readAppFileTar: exactly <name>.json or <name>.tsv (the data file's
// formats) and optionally <name>.secrets.json,
// regular files, ≤ MaxJSON each.
func readAppFileTar(r io.Reader, name string) ([]appFile, error) {
	tr := tar.NewReader(io.LimitReader(r, 4*agentapi.MaxJSON))
	modes := map[string]os.FileMode{name + ".json": 0o640, name + ".tsv": 0o640, name + ".secrets.json": 0o600}
	var out []appFile
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("not a tar")
		}
		mode, ok := modes[hdr.Name]
		if !ok || hdr.Typeflag != tar.TypeReg || seen[hdr.Name] || hdr.Size > agentapi.MaxJSON {
			return nil, fmt.Errorf("only %s.json and %s.secrets.json, once each, as regular files", name, name)
		}
		seen[hdr.Name] = true
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		out = append(out, appFile{name: hdr.Name, data: b, mode: mode})
	}
	if seen[name+".json"] == seen[name+".tsv"] {
		return nil, fmt.Errorf("exactly one of %s.json or %s.tsv is required", name, name)
	}
	return out, nil
}

// Volume archive caps (review M1).
const (
	MaxVolumeArchive = 256 << 30
	MaxVolumeEntries = 5_000_000
)

type volumeTarError struct {
	msg    string
	status int // 0: 400
}

func (e *volumeTarError) Error() string { return "volume archive: " + e.msg }

// checkedVolumeTar copies the tar r to w entry by entry: only regular
// files and directories (no symlink, hard link, device or FIFO), every
// name "<base>" or "<base>/…" clean (no absolute name, no ".."), at most
// MaxVolumeEntries entries and MaxVolumeArchive bytes.
func checkedVolumeTar(r io.Reader, w io.Writer, base string, limit int64) error {
	if limit <= 0 || limit > MaxVolumeArchive {
		limit = MaxVolumeArchive
	}
	tr := tar.NewReader(r)
	tw := tar.NewWriter(w)
	var total int64
	n := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return tw.Close()
		}
		if err != nil {
			return &volumeTarError{msg: "not a tar: " + clipMsg(err.Error())}
		}
		n++
		if n > MaxVolumeEntries {
			return &volumeTarError{msg: "too many entries"}
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		switch {
		case hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir:
			return &volumeTarError{msg: fmt.Sprintf("%q: only regular files and directories", clipMsg(hdr.Name))}
		case strings.HasPrefix(name, "/") || path.Clean(name) != name || name != base && !strings.HasPrefix(name, base+"/"):
			return &volumeTarError{msg: fmt.Sprintf("%q: not a clean name below %s", clipMsg(hdr.Name), base)}
		}
		for _, seg := range strings.Split(name, "/") {
			if seg == ".." || seg == "." || seg == "" {
				return &volumeTarError{msg: fmt.Sprintf("%q: not a clean name", clipMsg(hdr.Name))}
			}
		}
		total += hdr.Size
		if total > limit {
			if limit < MaxVolumeArchive {
				return &volumeTarError{msg: "larger than the free space on the worker", status: http.StatusInsufficientStorage}
			}
			return &volumeTarError{msg: "over its size cap"}
		}
		// No setuid / setgid bits and no file capabilities from an
		// archive a worker restores (review A-L2).
		out := &tar.Header{Name: hdr.Name, Typeflag: hdr.Typeflag, Mode: hdr.Mode & 0o1777, Uid: hdr.Uid, Gid: hdr.Gid, Size: hdr.Size,
			ModTime: hdr.ModTime, Format: tar.FormatPAX, PAXRecords: xattrsOnly(hdr.PAXRecords)}
		if err := tw.WriteHeader(out); err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := io.CopyN(tw, tr, hdr.Size); err != nil {
				return err
			}
		}
	}
}

// xattrsOnly keeps the ACL / xattr records a restore carries, but no
// security.* one other than security.selinux (no file capabilities).
func xattrsOnly(r map[string]string) map[string]string {
	var out map[string]string
	for k, v := range r {
		if strings.HasPrefix(k, "SCHILY.xattr.") && (!strings.HasPrefix(k, "SCHILY.xattr.security.") || k == "SCHILY.xattr.security.selinux") {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
	}
	return out
}

// freeForRestore is the engine's free space a volume restore may fill
// (APIConfig.DiskFree; none configured: only the size cap; unreadable:
// false, the restore is refused).
func (a *API) freeForRestore(ctx context.Context) (int64, bool) {
	if a.cfg.DiskFree == nil {
		return 0, true
	}
	return a.cfg.DiskFree(ctx)
}
