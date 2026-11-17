package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/runtime"
)

// Backend is runtime.Instances over one worker's agent API, plus
// DeliverFile, PushBundle and AgentInfo.
type Backend struct{ c *client }

var _ runtime.Instances = (*Backend)(nil)

// New is the backend of cfg's worker.
func New(cfg Config) *Backend { return &Backend{c: newClient(cfg)} }

// R is the route of method m (its i-th step).
func R(m string, i int) agentapi.Route { return agentapi.Routes[m][i] }

func (b *Backend) Kind() runtime.Kind { return b.c.cfg.Kind }
func (b *Backend) Env() []string      { return b.c.cfg.Env }

// AgentInfo is GET /v1/info (≤ MaxInfo; a longer answer is an error,
// never a partial decode).
func (b *Backend) AgentInfo(ctx context.Context) (agentapi.Info, error) {
	var i agentapi.Info
	if err := b.c.json(ctx, "GET", R("Info", 0).Path, nil, nil, &i, agentapi.MaxInfo); err != nil {
		return i, err
	}
	b.c.setAgentVersion(i.AgentVersion)
	return i, nil
}

// Info is the agent's info as runtime.Info (Kind docker|podman, SELinux,
// IDMapped, ForbiddenRoots = [DockerRootDir], …).
func (b *Backend) Info(ctx context.Context) (runtime.Info, error) {
	i, err := b.AgentInfo(ctx)
	if err != nil {
		return runtime.Info{}, err
	}
	ri, err := i.RuntimeInfo()
	if err != nil {
		return runtime.Info{}, &Error{Status: http.StatusBadGateway, Msg: err.Error()}
	}
	return ri, nil
}

func (b *Backend) project(ctx context.Context, m string, p runtime.Project) error {
	return b.c.json(ctx, "POST", path(R(m, 0), "id", p.Instance), nil, nil, nil, 0)
}

func (b *Backend) Create(ctx context.Context, p runtime.Project) error {
	return b.project(ctx, "Create", p)
}
// Down takes the project down. The agent's 404 "no such project" (it holds
// no bundle of it: never created there, or removed) is a down — nothing of
// it runs there; every caller (a move's rollback, a recovery, a drain)
// would otherwise stay stuck on it.
func (b *Backend) Down(ctx context.Context, p runtime.Project) error {
	err := b.project(ctx, "Down", p)
	var ae *Error
	if errors.As(err, &ae) && ae.AgentStatus == http.StatusNotFound {
		return nil
	}
	return err
}

// DownByName takes portcullis-<id> down (name must be one).
func (b *Backend) DownByName(ctx context.Context, name string) error {
	id, ok := strings.CutPrefix(name, runtime.ProjectPrefix)
	if !ok || agentapi.ValidInstance(id) != nil {
		return &Error{Status: http.StatusBadRequest, Msg: "not an instance's project: " + clip(name)}
	}
	return b.c.json(ctx, "POST", path(R("DownByName", 0), "id", id), nil, nil, nil, 0)
}

// progress streams a long call's ndjson; the last line (End) carries its
// outcome; a stream that ends without it failed.
func (b *Backend) progress(ctx context.Context, p string, body any, fn func(agentapi.ProgressLine)) error {
	var rd io.Reader
	ct := ""
	if body != nil {
		j, _ := json.Marshal(body)
		rd, ct = bytes.NewReader(j), "application/json"
	}
	resp, err := b.c.do(ctx, "POST", p, nil, rd, ct, opHeader(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var end *agentapi.ProgressLine
	err = ndjson(resp.Body, func(line []byte) error {
		var pl agentapi.ProgressLine
		if agentapi.Decode(bytes.NewReader(line), agentapi.MaxLine, &pl) != nil {
			return nil // a line that doesn't decode is dropped
		}
		if pl.End {
			end = &pl
			return nil
		}
		if fn != nil {
			fn(pl)
		}
		return nil
	})
	if err != nil {
		return transportErr(err)
	}
	switch {
	case end == nil:
		return &Error{Status: http.StatusBadGateway, Msg: "the agent's progress stream ended early"}
	case end.Error != "":
		return b.c.agentError(end.Status, end.Error)
	}
	return nil
}

func (b *Backend) Up(ctx context.Context, p runtime.Project, onPull func(svc string, done, total int64, sized bool)) error {
	return b.progress(ctx, path(R("Up", 0), "id", p.Instance), nil, func(pl agentapi.ProgressLine) {
		if onPull != nil {
			onPull(pl.Service, pl.Done, pl.Total, pl.Sized)
		}
	})
}

func (b *Backend) Pull(ctx context.Context, ref string, onBytes func(done, total int64, sized bool)) error {
	return b.progress(ctx, R("Pull", 0).Path, agentapi.RefRequest{Ref: ref}, func(pl agentapi.ProgressLine) {
		if onBytes != nil {
			onBytes(pl.Done, pl.Total, pl.Sized)
		}
	})
}

// PreflightPull is the placement pre-pull (contract §17.4): ref, pinned
// by digest, pulled before any bundle of the instance exists.
func (b *Backend) PreflightPull(ctx context.Context, ref string) error {
	return b.progress(ctx, R("Pull", 0).Path, agentapi.RefRequest{Ref: ref, Preflight: true}, func(agentapi.ProgressLine) {})
}

func (b *Backend) EnsureImage(ctx context.Context, ref string) error {
	return b.c.json(ctx, "POST", R("EnsureImage", 0).Path, nil, agentapi.RefRequest{Ref: ref}, nil, 0)
}

func filterQuery(f runtime.Filter) url.Values {
	q := url.Values{}
	for k, v := range agentapi.FilterQuery(f) {
		q.Set(k, v)
	}
	return q
}

func (b *Backend) List(ctx context.Context, f runtime.Filter) ([]runtime.Unit, error) {
	var us []agentapi.Unit
	if err := b.c.json(ctx, "GET", R("List", 0).Path, filterQuery(f), nil, &us, agentapi.MaxJSON); err != nil {
		return nil, err
	}
	out := make([]runtime.Unit, 0, len(us))
	for _, u := range us {
		out = append(out, u.Runtime())
	}
	return out, nil
}

func (b *Backend) Inspect(ctx context.Context, id string) (runtime.UnitInfo, error) {
	var u agentapi.UnitInfo
	err := b.c.json(ctx, "GET", path(R("Inspect", 0), "cid", id), nil, nil, &u, agentapi.MaxJSON)
	return u.Runtime(), err
}

func (b *Backend) State(ctx context.Context, id string) (runtime.State, error) {
	var s agentapi.State
	err := b.c.json(ctx, "GET", path(R("State", 0), "cid", id), nil, nil, &s, agentapi.MaxJSON)
	return s.Runtime(), err
}

func (b *Backend) Logs(ctx context.Context, id string, tail int, ts bool) ([]byte, error) {
	q := url.Values{agentapi.QueryTail: {itoa(tail)}}
	if ts {
		q.Set(agentapi.QueryTS, "1")
	}
	resp, err := b.c.do(ctx, "GET", path(R("Logs", 0), "cid", id), q, nil, "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := agentapi.ReadCapped(resp.Body, agentapi.MaxLogs)
	if err != nil {
		return nil, &Error{Status: http.StatusBadGateway, Msg: "the agent's logs are over the cap"}
	}
	return out, nil
}

func (b *Backend) Exec(ctx context.Context, id string, in runtime.ExecInput) (*runtime.ExecResult, error) {
	var r agentapi.ExecResult
	if err := b.c.json(ctx, "POST", path(R("Exec", 0), "cid", id), nil, agentapi.ExecRequestOf(in), &r, agentapi.MaxJSON); err != nil {
		return nil, err
	}
	return &runtime.ExecResult{Output: r.Output, ExitCode: r.ExitCode, TimedOut: r.TimedOut, Truncated: r.Truncated, ExecID: r.ExecID}, nil
}

func (b *Backend) ExecSplit(ctx context.Context, id string, in runtime.ExecInput) (*runtime.ExecSplitResult, error) {
	var r agentapi.ExecSplitResult
	if err := b.c.json(ctx, "POST", path(R("ExecSplit", 0), "cid", id), nil, agentapi.ExecRequestOf(in), &r, agentapi.MaxJSON); err != nil {
		return nil, err
	}
	return &runtime.ExecSplitResult{Stdout: r.Stdout, Stderr: r.Stderr, StdoutTruncated: r.StdoutTruncated, StderrTruncated: r.StderrTruncated,
		ExitCode: r.ExitCode, TimedOut: r.TimedOut, ExecID: r.ExecID}, nil
}

func (b *Backend) ExecRunning(ctx context.Context, execID string) (bool, error) {
	var r agentapi.ExecRunning
	err := b.c.json(ctx, "GET", path(R("ExecRunning", 0), "exec", execID), nil, nil, &r, agentapi.MaxJSON)
	return r.Running, err
}

func (b *Backend) Signal(ctx context.Context, id, sig string) error {
	return b.c.json(ctx, "POST", path(R("Signal", 0), "cid", id), nil, agentapi.SignalRequest{Signal: sig}, nil, 0)
}

// Events streams until ctx ends or the agent closes the stream.
func (b *Backend) Events(ctx context.Context, f runtime.Filter, fn func(runtime.Event)) error {
	resp, err := b.c.do(ctx, "GET", R("Events", 0).Path, filterQuery(f), nil, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	err = ndjson(resp.Body, func(line []byte) error {
		var e agentapi.Event
		if agentapi.Decode(bytes.NewReader(line), agentapi.MaxLine, &e) == nil {
			fn(e.Runtime())
		}
		return nil
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return transportErr(err)
	}
	return &Error{Status: http.StatusBadGateway, Msg: "the agent closed the event stream"}
}

func (b *Backend) ListVolumes(ctx context.Context, f runtime.Filter) ([]runtime.Volume, error) {
	var vs []agentapi.Volume
	if err := b.c.json(ctx, "GET", R("ListVolumes", 0).Path, filterQuery(f), nil, &vs, agentapi.MaxJSON); err != nil {
		return nil, err
	}
	out := make([]runtime.Volume, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Runtime())
	}
	return out, nil
}

func (b *Backend) InspectVolume(ctx context.Context, name string) (runtime.Volume, error) {
	var v agentapi.Volume
	err := b.c.json(ctx, "GET", path(R("InspectVolume", 0), "name", name), nil, nil, &v, agentapi.MaxJSON)
	return v.Runtime(), err
}

func (b *Backend) CreateVolume(ctx context.Context, v runtime.Volume) error {
	return b.c.json(ctx, "POST", R("CreateVolume", 0).Path, nil, agentapi.VolumeOf(v), nil, 0)
}

func (b *Backend) RemoveVolume(ctx context.Context, name string) error {
	return b.c.json(ctx, "DELETE", path(R("RemoveVolume", 0), "name", name), nil, nil, nil, 0)
}

func (b *Backend) createHelper(ctx context.Context, s agentapi.HelperSpec) (string, error) {
	var hc agentapi.HelperCreated
	if err := b.c.json(ctx, "POST", R("VolumeOut", 0).Path, nil, s, &hc, agentapi.MaxJSON); err != nil {
		return "", err
	}
	if hc.ID == "" || len(hc.ID) > 128 || strings.ContainsAny(hc.ID, "/?#% ") {
		return "", &Error{Status: http.StatusBadGateway, Msg: "the agent answered an invalid helper id"}
	}
	return hc.ID, nil
}

// HelperCleanupTimeout bounds a helper's removal (a backup's Close).
var HelperCleanupTimeout = 15 * time.Second

func (b *Backend) deleteHelper(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), HelperCleanupTimeout)
	defer cancel()
	b.c.json(ctx, "DELETE", path(R("RemoveHelper", 0), "h", id), nil, nil, nil, 0)
}

type helperReader struct {
	io.ReadCloser
	done func()
}

func (h *helperReader) Close() error {
	err := h.ReadCloser.Close()
	h.done()
	return err
}

// VolumeOut streams the volume's tar (the caller checks every entry with
// the Hub's archive rules before writing anything; closing removes the
// agent's helper).
func (b *Backend) VolumeOut(ctx context.Context, instance, volume, p string) (io.ReadCloser, error) {
	id, err := b.createHelper(ctx, agentapi.HelperSpec{Kind: agentapi.HelperVolumeIO, Instance: instance, Volume: volume, Path: p})
	if err != nil {
		return nil, err
	}
	resp, err := b.c.do(ctx, "GET", path(R("VolumeOut", 1), "h", id), nil, nil, "", nil)
	if err != nil {
		b.deleteHelper(id)
		return nil, err
	}
	return &helperReader{ReadCloser: resp.Body, done: func() { b.deleteHelper(id) }}, nil
}

func (b *Backend) VolumeIn(ctx context.Context, instance, volume, p string, r io.Reader) error {
	id, err := b.createHelper(ctx, agentapi.HelperSpec{Kind: agentapi.HelperVolumeIO, Instance: instance, Volume: volume, Path: p, Write: true})
	if err != nil {
		return err
	}
	defer b.deleteHelper(id)
	resp, err := b.c.do(ctx, "PUT", path(R("VolumeIn", 1), "h", id), nil, r, "application/x-tar", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (b *Backend) RemoveHelper(ctx context.Context, id string) error {
	return b.c.json(ctx, "DELETE", path(R("RemoveHelper", 0), "h", id), nil, nil, nil, 0)
}

// RunFixer sends the spec (the agent rebuilds it and runs it on its own
// image), its input, runs it and hands out its output tar.
func (b *Backend) RunFixer(ctx context.Context, s runtime.FixerSpec, out func(tar io.Reader) error) (*runtime.RunResult, error) {
	spec := agentapi.FixerSpecOf(s)
	id, err := b.createHelper(ctx, agentapi.HelperSpec{Kind: agentapi.HelperFolderFix, Spec: &spec})
	if err != nil {
		return nil, err
	}
	defer b.deleteHelper(id)
	if s.InPath != "" && s.In != nil {
		resp, err := b.c.do(ctx, "PUT", path(R("RunFixer", 1), "h", id), nil, s.In, "application/x-tar", nil)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
	}
	var rr agentapi.RunResult
	if err := b.c.json(ctx, "POST", path(R("RunFixer", 2), "h", id), nil, nil, &rr, agentapi.MaxJSON); err != nil {
		return nil, err
	}
	res := &runtime.RunResult{ExitCode: rr.ExitCode, Stdout: rr.Stdout, Stderr: rr.Stderr, StdoutClipped: rr.StdoutClipped, StderrClipped: rr.StderrClipped}
	if s.OutPath != "" && rr.ExitCode == 0 && out != nil {
		resp, err := b.c.do(ctx, "GET", path(R("RunFixer", 3), "h", id), nil, nil, "", nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if err := out(resp.Body); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// DeliverFile is PUT /v1/projects/{id}/appfiles/{name}: a tar of the data
// file and, when it carries secrets, <name>.secrets.json.
func (b *Backend) DeliverFile(ctx context.Context, instance string, f runtime.FileDelivery) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, data []byte, mode int64) {
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(data))})
		tw.Write(data)
	}
	name := f.FileName
	if name == "" {
		name = f.Name + ".json"
	}
	add(name, f.Data, 0o640)
	if f.Secrets != nil {
		add(f.Name+".secrets.json", f.Secrets, 0o600)
	}
	if err := tw.Close(); err != nil {
		return err
	}
	resp, err := b.c.do(ctx, "PUT", path(agentapi.ExtraRoutes["AppFile"], "id", instance, "name", f.Name), nil, &buf, "application/x-tar", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// PushBundle sends instance id's bundle: MANIFEST.json then every file
// m lists, read from files (paths relative to the bundle root), with the
// manifest's modes; the tar is streamed.
func (b *Backend) PushBundle(ctx context.Context, id string, files fs.FS, m agentapi.BundleManifest) error {
	if m.Instance != id {
		return errors.New("the manifest names another instance")
	}
	if err := agentapi.ValidateManifest(m, agentapi.MaxBundle); err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		err := agentapi.WriteManifest(tw, m)
		names := make([]string, 0, len(m.Files))
		for n := range m.Files {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if err != nil {
				break
			}
			e := m.Files[n]
			err = tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: int64(e.Mode), Size: e.Size, Format: tar.FormatPAX})
			if err != nil {
				break
			}
			var f fs.File
			if f, err = files.Open(n); err != nil {
				break
			}
			_, err = io.CopyN(tw, f, e.Size)
			f.Close()
		}
		if err == nil {
			err = tw.Close()
		}
		pw.CloseWithError(err)
	}()
	resp, err := b.c.do(ctx, "PUT", path(agentapi.ExtraRoutes["Bundle"], "id", id), nil, pr, "application/x-tar", nil)
	pr.Close()
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// RestartCoreService is refused: core (mail included) runs on the
// primary only, never on a worker.
func (b *Backend) RestartCoreService(context.Context, string, time.Duration) error {
	return runtime.ErrUnsupported
}
