package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/compose-spec/compose-go/v2/types"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
)

// The bundle's compose files at its root (contract §17.4: laid out as
// under the primary's project directory; the Hub renders them for the
// worker), and the appfiles prefix moved to <data>/appfiles/<id>/.
const (
	BundleCompose      = "compose.yml"
	BundleOverride     = "override.yml"
	BundleUserOverride = "user.yml"
	BundleEnv          = "env"
	BundleAppfiles     = "appfiles/"
	// ProxyNetwork is the worker's portcullis-proxy (the agent holds the
	// Traefik address on it, pre-flight P35).
	ProxyNetwork = "portcullis-proxy"
	// AgentBinary is the agent inside its image (the fixer's command).
	AgentBinary = "/usr/local/bin/portcullis-agent"
)

// signals the Hub may send (contract §17.4).
var signals = map[string]bool{"HUP": true, "USR1": true, "USR2": true}

// Net is the engine's network side the agent needs (internal/docker).
type Net interface {
	EnsureNetwork(ctx context.Context, name string, subnet, ipRange netip.Prefix, internal bool, labels map[string]string) error
	ConnectNetwork(ctx context.Context, net, container string, ip netip.Addr) error
	ContainerAddr(ctx context.Context, id, net string) (netip.Addr, map[string]string, error)
	PortBinds(ctx context.Context) ([]docker.PortBind, error)
}

// APIConfig is the projects API's configuration.
type APIConfig struct {
	DataDir   string
	BindRoots []string
	Runtime   runtime.Instances
	Net       Net
	// SelfImage is the agent's own image ID (the fixer runs on it, P7);
	// HelperImage the pinned volume helper image.
	SelfImage, HelperImage string
	// ComposeEnv is the environment compose interpolates with.
	ComposeEnv []string
	// Protected are paths no bind may equal, contain or be inside (the
	// engine's roots and sockets, system directories; the data dir is
	// always added).
	Protected []string
	// Config runs `docker compose config` (compose.CLI.Config): the model
	// the agent validates and runs is its output, never the bundle's files.
	Config func(ctx context.Context, p compose.Project) ([]byte, error)
	// OwnProject is the agent's own compose project (its container's
	// label): no instance may take its name (a bundle of that id is
	// refused). OwnContainers are its containers' ids, read at start: the
	// only ones the start backstop leaves alone by identity (never by
	// project name).
	OwnProject    string
	OwnContainers []string
	// DiskFree is the engine's free space a restore may fill (ok false:
	// unreadable, restores refused; nil: no check, tests).
	DiskFree func(ctx context.Context) (free int64, ok bool)
}

// project is one bundled instance as the agent holds it.
type project struct {
	manifest agentapi.BundleManifest
	model    *types.Project
	images   map[string]bool
	// routes: service → the ports its traefik.http.services.*.loadbalancer.server.port labels name.
	routes map[string]map[int]bool
}

type helper struct {
	spec    agentapi.HelperSpec
	in, out string // folder_fix staging files
	ran     bool
	result  *runtime.RunResult
}

// API is the ready-state agent API (Config.Routes): every route of
// contract §17.4 with the scope its row names.
type API struct {
	cfg APIConfig
	mux *http.ServeMux

	mu       sync.Mutex
	projects map[string]*project
	// quarantined: instance → why its bind sources failed the check at a
	// container start the engine made (A-H2b): refused until the Hub lifts
	// it. quarantineAll: why every instance counts as quarantined (an
	// unreadable quarantine.json, R3-L2; "" = none); saveErr: the last
	// failed save (reported in /v1/info). lifted: ids lifted without a
	// bundle, awaiting the Hub's push. downs: ids a down worker runs for.
	quarantined   map[string]string
	quarantineAll string
	saveErr       string
	lifted        map[string]bool
	downs         map[string]bool
	bundleMu      sync.Mutex
	execs         map[string]bool
	helpers       map[string]*helper
	ops           map[string]context.CancelFunc
}

// NewAPI loads the bundles already on disk (each re-validated; an invalid
// one is dropped from scope and logged).
func NewAPI(cfg APIConfig) *API {
	a := &API{cfg: cfg, projects: map[string]*project{}, quarantined: map[string]string{}, lifted: map[string]bool{}, downs: map[string]bool{}, execs: map[string]bool{}, helpers: map[string]*helper{}, ops: map[string]context.CancelFunc{}}
	a.mux = http.NewServeMux()
	a.routes()
	a.loadQuarantine()
	entries, _ := os.ReadDir(a.projectsDir())
	for _, e := range entries {
		if !e.IsDir() || agentapi.ValidInstance(e.Name()) != nil {
			continue
		}
		if p, err := a.loadStored(e.Name()); err != nil {
			log.Printf("bundle %s: %v (out of scope until the Hub sends it again)", e.Name(), err)
		} else {
			a.projects[e.Name()] = p
		}
	}
	return a
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

func (a *API) projectsDir() string         { return filepath.Join(a.cfg.DataDir, "projects") }
func (a *API) projectDir(id string) string { return filepath.Join(a.projectsDir(), id) }
func (a *API) appfilesDir(id string) string {
	return filepath.Join(a.cfg.DataDir, "appfiles", id)
}
func (a *API) helpersDir() string { return filepath.Join(a.cfg.DataDir, "helpers") }

func (a *API) routes() {
	h := func(r agentapi.Route, f http.HandlerFunc) { a.mux.HandleFunc(r.Pattern(), f) }
	R := agentapi.Routes
	X := agentapi.ExtraRoutes
	h(X["Bundle"], a.withProjectID(false, a.putBundle))
	h(X["RemoveProject"], a.withProjectID(true, a.removeProject))
	h(X["Unquarantine"], a.withProjectID(false, a.unquarantine))
	h(X["AppFile"], a.withProjectID(true, a.putAppFile))
	h(X["StopOp"], a.stopOp)
	h(R["Create"][0], a.withProjectID(true, a.lifecycle("create")))
	h(R["Up"][0], a.withProjectID(true, a.lifecycle("up")))
	h(R["Down"][0], a.withProjectID(true, a.lifecycle("down")))
	h(R["DownByName"][0], a.withProjectID(true, a.lifecycle("down-by-name")))
	h(R["Pull"][0], a.pull)
	h(R["EnsureImage"][0], a.ensureImage)
	h(R["List"][0], a.list)
	h(R["Inspect"][0], a.withContainer(a.inspect))
	h(R["State"][0], a.withContainer(a.state))
	h(R["Logs"][0], a.withContainer(a.logs))
	h(R["Exec"][0], a.withContainer(a.exec(false)))
	h(R["ExecSplit"][0], a.withContainer(a.exec(true)))
	h(R["ExecRunning"][0], a.execRunning)
	h(R["Signal"][0], a.withContainer(a.signal))
	h(R["Events"][0], a.events)
	h(R["ListVolumes"][0], a.listVolumes)
	h(R["InspectVolume"][0], a.inspectVolume)
	h(R["CreateVolume"][0], a.createVolume)
	h(R["RemoveVolume"][0], a.removeVolume)
	h(R["VolumeOut"][0], a.createHelper) // POST /v1/helpers (shared)
	h(R["VolumeOut"][1], a.helperArchiveOut)
	h(R["VolumeIn"][1], a.helperArchiveIn)
	h(R["RunFixer"][2], a.helperRun)
	h(R["RemoveHelper"][0], a.removeHelper)
	a.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { writeError(w, http.StatusNotFound, "not found") })
}

// ── scope helpers ────────────────────────────────────────────────────────

func (a *API) bundled() map[string]bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]bool, len(a.projects))
	for id := range a.projects {
		out[id] = true
	}
	return out
}

func (a *API) project(id string) *project {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.projects[id]
}

// withProjectID: {id} an instance id, and (needBundle) bundled; else 404.
func (a *API) withProjectID(needBundle bool, f func(w http.ResponseWriter, r *http.Request, id string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if agentapi.ValidInstance(id) != nil || (needBundle && a.project(id) == nil) {
			writeError(w, http.StatusNotFound, "no such project")
			return
		}
		f(w, r, id)
	}
}

// inScope: a unit's labels name a bundled project, or it is one of the
// Hub's helpers for a bundled instance.
func (a *API) inScope(labels map[string]string) (string, bool) {
	b := a.bundled()
	if id, ok := agentapi.ProjectLabelOK(labels, b); ok {
		return id, true
	}
	if v, ok := labels[docker.LabelHelper]; ok {
		switch {
		case b[v]:
			return v, true // a volume helper for a bundled instance
		case strings.HasPrefix(v, "folder:") || v == "path-check":
			return "", true // the agent's own fixer runs
		}
	}
	return "", false
}

// withContainer: {cid} a container of a bundled project (else 403).
func (a *API) withContainer(f func(w http.ResponseWriter, r *http.Request, cid string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cid := r.PathValue("cid")
		info, err := a.cfg.Runtime.Inspect(r.Context(), cid)
		if err != nil {
			writeError(w, http.StatusNotFound, "no such container")
			return
		}
		if _, ok := agentapi.ProjectLabelOK(info.Labels, a.bundled()); !ok {
			writeError(w, http.StatusForbidden, "the container is not a bundled project's")
			return
		}
		f(w, r, info.ID)
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := agentapi.Decode(r.Body, agentapi.MaxJSON, v); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func engineError(w http.ResponseWriter, err error) {
	var se interface{ HTTPStatus() int }
	code := http.StatusBadGateway
	if errors.As(err, &se) {
		code = se.HTTPStatus()
	}
	writeError(w, code, clipMsg(err.Error()))
}

// ── bundles ──────────────────────────────────────────────────────────────

var appFileNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// putAppFile is DeliverFile: a tar of exactly <name>.json (0640) and,
// optionally, <name>.secrets.json (0600), each written atomically into
// <data>/appfiles/<id>/<name>/ (the directory is bind-mounted, so the new
// inode shows at once).
func (a *API) putAppFile(w http.ResponseWriter, r *http.Request, id string) {
	name := r.PathValue("name")
	if !appFileNameRe.MatchString(name) {
		writeError(w, http.StatusBadRequest, "not a data file name")
		return
	}
	files, err := readAppFileTar(r.Body, name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	root, err := a.appfilesRoot(id)
	if err != nil {
		writeError(w, http.StatusConflict, "the data file directory: "+clipMsg(err.Error()))
		return
	}
	defer root.Close()
	for _, f := range files {
		if err := checkRooted(root, name+"/"+f.name); err != nil {
			writeError(w, http.StatusConflict, "the data file: "+clipMsg(err.Error()))
			return
		}
	}
	for _, f := range files {
		if err := writeRooted(root, name+"/"+f.name, strings.NewReader(string(f.data)), f.mode); err != nil {
			writeError(w, http.StatusConflict, "the data file: "+clipMsg(err.Error()))
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── lifecycle ────────────────────────────────────────────────────────────

// checkVolumes: every manifest volume that already exists carries this
// instance's compose labels; one that doesn't is refused, never adopted.
func (a *API) checkVolumes(ctx context.Context, id string) error {
	p := a.project(id)
	for _, key := range sortedKeys(p.manifest.Volumes) {
		name := p.manifest.Volumes[key]
		v, err := a.cfg.Runtime.InspectVolume(ctx, name)
		if err != nil {
			continue // absent: compose creates it with the labels
		}
		if v.Labels[docker.LabelProject] != runtime.ProjectName(id) {
			return fmt.Errorf("volume %s exists without this instance's compose labels: it is never adopted", name)
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// opContext is the request's context, cancellable by DELETE /v1/ops/{op}
// when the request names an op (OpHeader).
func (a *API) opContext(r *http.Request) (context.Context, func()) {
	ctx, cancel := context.WithCancel(r.Context())
	op := r.Header.Get(agentapi.OpHeader)
	if !opIDRe.MatchString(op) {
		return ctx, cancel
	}
	a.mu.Lock()
	a.ops[op] = cancel
	a.mu.Unlock()
	return ctx, func() {
		a.mu.Lock()
		delete(a.ops, op)
		a.mu.Unlock()
		cancel()
	}
}

var opIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

func (a *API) stopOp(w http.ResponseWriter, r *http.Request) {
	op := r.PathValue("op")
	a.mu.Lock()
	cancel, ok := a.ops[op]
	a.mu.Unlock()
	if !opIDRe.MatchString(op) || !ok {
		writeError(w, http.StatusNotFound, "no such operation")
		return
	}
	cancel()
	w.WriteHeader(http.StatusNoContent)
}

// ndjson writes progress lines and flushes each one.
type ndjson struct {
	w  http.ResponseWriter
	mu sync.Mutex
}

func (n *ndjson) line(v any) {
	b, err := json.Marshal(v)
	if err != nil || len(b) > agentapi.MaxLine {
		return // a line over the cap is dropped
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.w.Write(append(b, '\n'))
	if f, ok := n.w.(http.Flusher); ok {
		f.Flush()
	}
}

func statusOfErr(err error) int {
	var se interface{ HTTPStatus() int }
	if errors.As(err, &se) {
		return se.HTTPStatus()
	}
	return http.StatusBadGateway
}

func (a *API) lifecycle(verb string) func(w http.ResponseWriter, r *http.Request, id string) {
	return func(w http.ResponseWriter, r *http.Request, id string) {
		ctx, done := a.opContext(r)
		defer done()
		p := a.runtimeProject(id)
		if why := a.quarantineOf(id); why != "" && (verb == "create" || verb == "up") {
			writeError(w, http.StatusConflict, clipMsg("the instance is quarantined: "+why+" (an admin must lift it)"))
			return
		}
		if verb == "create" || verb == "up" {
			// The bind sources again, right before the engine sees them
			// (C4; the residual race until the engine mounts is ledgered).
			if err := a.checkBindPaths(id, p.Model); err != nil {
				writeError(w, http.StatusConflict, clipMsg(err.Error()))
				return
			}
		}
		switch verb {
		case "create":
			if err := a.checkVolumes(ctx, id); err != nil {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			if err := a.cfg.Runtime.Create(ctx, p); err != nil {
				engineError(w, err)
				return
			}
		case "down":
			if err := a.cfg.Runtime.Down(ctx, p); err != nil {
				engineError(w, err)
				return
			}
		case "down-by-name":
			if err := a.cfg.Runtime.DownByName(ctx, p.Name); err != nil {
				engineError(w, err)
				return
			}
		case "up":
			if err := a.checkVolumes(ctx, id); err != nil {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.WriteHeader(http.StatusOK)
			flush(w)
			out := &ndjson{w: w}
			err := a.cfg.Runtime.Up(ctx, p, func(svc string, done, total int64, sized bool) {
				out.line(agentapi.ProgressLine{Step: "images", Service: svc, Done: done, Total: total, Sized: sized})
			})
			end := agentapi.ProgressLine{End: true}
			if err != nil {
				end.Error, end.Status = clipMsg(err.Error()), statusOfErr(err)
			}
			out.line(end)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// imageOK: ref is in a bundle's model, or the pinned helper image.
func (a *API) imageOK(ref string) bool {
	if ref != "" && ref == a.cfg.HelperImage {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.projects {
		if p.images[ref] {
			return true
		}
	}
	return false
}

func (a *API) pull(w http.ResponseWriter, r *http.Request) {
	var req agentapi.RefRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !a.imageOK(req.Ref) {
		writeError(w, http.StatusForbidden, "the image is in no bundle")
		return
	}
	ctx, done := a.opContext(r)
	defer done()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flush(w)
	out := &ndjson{w: w}
	err := a.cfg.Runtime.Pull(ctx, req.Ref, func(d, t int64, sized bool) {
		out.line(agentapi.ProgressLine{Done: d, Total: t, Sized: sized})
	})
	end := agentapi.ProgressLine{End: true}
	if err != nil {
		end.Error, end.Status = clipMsg(err.Error()), statusOfErr(err)
	}
	out.line(end)
}

func (a *API) ensureImage(w http.ResponseWriter, r *http.Request) {
	var req agentapi.RefRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !a.imageOK(req.Ref) {
		writeError(w, http.StatusForbidden, "the image is in no bundle")
		return
	}
	if err := a.cfg.Runtime.EnsureImage(r.Context(), req.Ref); err != nil {
		engineError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── containers ───────────────────────────────────────────────────────────

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	f, err := agentapi.ParseFilter(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if f.Instance != "" && a.project(f.Instance) == nil {
		writeError(w, http.StatusNotFound, "no such project")
		return
	}
	units, err := a.cfg.Runtime.List(r.Context(), f)
	if err != nil {
		engineError(w, err)
		return
	}
	out := []agentapi.Unit{}
	for _, u := range units {
		if _, ok := a.inScope(u.Labels); ok {
			out = append(out, agentapi.UnitOf(u))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) inspect(w http.ResponseWriter, r *http.Request, cid string) {
	info, err := a.cfg.Runtime.Inspect(r.Context(), cid)
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agentapi.UnitInfoOf(info))
}

func (a *API) state(w http.ResponseWriter, r *http.Request, cid string) {
	st, err := a.cfg.Runtime.State(r.Context(), cid)
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agentapi.StateOf(st))
}

// TruncatedHeader marks logs cut to MaxLogs (the last bytes kept).
const TruncatedHeader = "Portcullis-Truncated"

func (a *API) logs(w http.ResponseWriter, r *http.Request, cid string) {
	tail, ts := 0, false
	for k, vs := range r.URL.Query() {
		if len(vs) != 1 {
			writeError(w, http.StatusBadRequest, "query parameters once each")
			return
		}
		switch k {
		case agentapi.QueryTail:
			n, err := strconv.Atoi(vs[0])
			if err != nil || n < 0 || n > 100000 {
				writeError(w, http.StatusBadRequest, "tail must be 0–100000")
				return
			}
			tail = n
		case agentapi.QueryTS:
			if vs[0] != "1" {
				writeError(w, http.StatusBadRequest, "ts: only 1")
				return
			}
			ts = true
		default:
			writeError(w, http.StatusBadRequest, "unknown query parameter")
			return
		}
	}
	b, err := a.cfg.Runtime.Logs(r.Context(), cid, tail, ts)
	if err != nil {
		engineError(w, err)
		return
	}
	if len(b) > agentapi.MaxLogs {
		b = b[len(b)-agentapi.MaxLogs:]
		w.Header().Set(TruncatedHeader, "1")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(b)
}

func (a *API) exec(split bool) func(w http.ResponseWriter, r *http.Request, cid string) {
	return func(w http.ResponseWriter, r *http.Request, cid string) {
		var req agentapi.ExecRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if len(req.Cmd) == 0 {
			writeError(w, http.StatusBadRequest, "cmd is required")
			return
		}
		in := req.Runtime()
		if split {
			res, err := a.cfg.Runtime.ExecSplit(r.Context(), cid, in)
			if err != nil {
				engineError(w, err)
				return
			}
			a.rememberExec(res.ExecID)
			writeJSON(w, http.StatusOK, agentapi.ExecSplitResult{Stdout: res.Stdout, Stderr: res.Stderr, StdoutTruncated: res.StdoutTruncated,
				StderrTruncated: res.StderrTruncated, ExitCode: res.ExitCode, TimedOut: res.TimedOut, ExecID: res.ExecID})
			return
		}
		res, err := a.cfg.Runtime.Exec(r.Context(), cid, in)
		if err != nil {
			engineError(w, err)
			return
		}
		a.rememberExec(res.ExecID)
		writeJSON(w, http.StatusOK, agentapi.ExecResult{Output: res.Output, ExitCode: res.ExitCode, TimedOut: res.TimedOut, Truncated: res.Truncated, ExecID: res.ExecID})
	}
}

func (a *API) rememberExec(id string) {
	if id == "" {
		return
	}
	a.mu.Lock()
	a.execs[id] = true
	a.mu.Unlock()
}

func (a *API) execRunning(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("exec")
	a.mu.Lock()
	ok := a.execs[id]
	a.mu.Unlock()
	if !ok {
		writeError(w, http.StatusForbidden, "not an exec the agent started")
		return
	}
	running, err := a.cfg.Runtime.ExecRunning(r.Context(), id)
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agentapi.ExecRunning{Running: running})
}

func (a *API) signal(w http.ResponseWriter, r *http.Request, cid string) {
	var req agentapi.SignalRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !signals[req.Signal] {
		writeError(w, http.StatusBadRequest, "signal must be HUP, USR1 or USR2")
		return
	}
	if err := a.cfg.Runtime.Signal(r.Context(), cid, req.Signal); err != nil {
		engineError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// events streams the engine's events of bundled projects, one ndjson line
// each (a line over MaxLine is dropped).
func (a *API) events(w http.ResponseWriter, r *http.Request) {
	f, err := agentapi.ParseFilter(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if f.Instance != "" && a.project(f.Instance) == nil {
		writeError(w, http.StatusNotFound, "no such project")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	out := &ndjson{w: w}
	err = a.cfg.Runtime.Events(r.Context(), f, func(e runtime.Event) {
		if _, ok := a.inScope(e.Actor.Attributes); ok {
			out.line(agentapi.EventOf(e))
		}
	})
	if err != nil && r.Context().Err() == nil {
		out.line(map[string]string{"error": clipMsg(err.Error())})
	}
}

// ── volumes ──────────────────────────────────────────────────────────────

// volumeOwner: the bundled instance whose compose labels v carries (a
// volume is in scope by its labels only, never by its name alone).
func (a *API) volumeOwner(v runtime.Volume) (string, bool) {
	return agentapi.ProjectLabelOK(v.Labels, a.bundled())
}

func (a *API) listVolumes(w http.ResponseWriter, r *http.Request) {
	f, err := agentapi.ParseFilter(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	vols, err := a.cfg.Runtime.ListVolumes(r.Context(), f)
	if err != nil {
		engineError(w, err)
		return
	}
	out := []agentapi.Volume{}
	for _, v := range vols {
		if _, ok := a.volumeOwner(v); ok {
			out = append(out, agentapi.VolumeOf(v))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) scopedVolume(w http.ResponseWriter, r *http.Request, name string) (runtime.Volume, string, bool) {
	v, err := a.cfg.Runtime.InspectVolume(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such volume")
		return v, "", false
	}
	id, ok := a.volumeOwner(v)
	if !ok {
		writeError(w, http.StatusForbidden, "the volume is not a bundled project's")
		return v, "", false
	}
	return v, id, true
}

func (a *API) inspectVolume(w http.ResponseWriter, r *http.Request) {
	if v, _, ok := a.scopedVolume(w, r, r.PathValue("name")); ok {
		writeJSON(w, http.StatusOK, agentapi.VolumeOf(v))
	}
}

func (a *API) removeVolume(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, _, ok := a.scopedVolume(w, r, name); !ok {
		return
	}
	if err := a.cfg.Runtime.RemoveVolume(r.Context(), name); err != nil {
		engineError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// createVolume: only a name a bundled manifest lists, labelled as that
// instance's compose volume.
func (a *API) createVolume(w http.ResponseWriter, r *http.Request) {
	var req agentapi.Volume
	if !decodeBody(w, r, &req) {
		return
	}
	v := req.Runtime()
	owner := ""
	a.mu.Lock()
	for id, p := range a.projects {
		for _, n := range p.manifest.Volumes {
			if n == v.Name {
				owner = id
			}
		}
	}
	a.mu.Unlock()
	if owner == "" {
		writeError(w, http.StatusForbidden, "the volume is in no bundle's manifest")
		return
	}
	if v.Labels[docker.LabelProject] != runtime.ProjectName(owner) || (v.Driver != "" && v.Driver != "local") || len(v.Options) > 0 {
		writeError(w, http.StatusForbidden, "the volume must carry its instance's compose labels, the local driver and no options")
		return
	}
	if err := a.cfg.Runtime.CreateVolume(r.Context(), v); err != nil {
		engineError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ──────────────────────────────────────────────────────────────

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *API) helper(w http.ResponseWriter, r *http.Request) (string, *helper, bool) {
	id := r.PathValue("h")
	a.mu.Lock()
	h := a.helpers[id]
	a.mu.Unlock()
	if h == nil {
		writeError(w, http.StatusNotFound, "no such helper")
		return id, nil, false
	}
	return id, h, true
}

// quarantineOf is why instance id is quarantined ("" = it isn't).
func (a *API) quarantineOf(id string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.quarantineAll != "" {
		return a.quarantineAll
	}
	return a.quarantined[id]
}

// QuarantineAllKey is the /v1/info key standing for every instance.
const QuarantineAllKey = "*"

// Quarantined are the quarantined instances and why (GET /v1/info); key
// "*" means every instance (an unreadable quarantine.json).
func (a *API) Quarantined() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.quarantined) == 0 && a.quarantineAll == "" {
		return nil
	}
	out := maps.Clone(a.quarantined)
	if out == nil {
		out = map[string]string{}
	}
	if a.quarantineAll != "" {
		out[QuarantineAllKey] = a.quarantineAll
	}
	return out
}

// QuarantineError is the last failed save of the quarantine ("" = none).
func (a *API) QuarantineError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.saveErr
}

func (a *API) quarantinePath() string { return filepath.Join(a.cfg.DataDir, "quarantine.json") }

// loadQuarantine reads the persisted quarantine (review A2-M1). Fail
// closed (R3-L2): a file that exists but can't be read or parsed makes
// every instance quarantined until it is repaired (re-read every sweep).
func (a *API) loadQuarantine() {
	b, err := os.ReadFile(a.quarantinePath())
	if errors.Is(err, fs.ErrNotExist) {
		a.mu.Lock()
		a.quarantineAll = ""
		a.mu.Unlock()
		return
	}
	var q map[string]string
	if err == nil {
		err = json.Unmarshal(b, &q)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		if a.quarantineAll == "" {
			log.Printf("bind check: %s is unreadable (%v): every instance counts as quarantined until it is repaired", a.quarantinePath(), err)
		}
		a.quarantineAll = "the agent's quarantine.json is unreadable: repair or remove it on the worker"
		return
	}
	a.quarantineAll = ""
	for id, why := range q {
		if agentapi.ValidInstance(id) == nil {
			a.quarantined[id] = why
		}
	}
}

// saveQuarantineLocked persists the quarantine; a failure is kept for
// /v1/info (the quarantine holds in memory: kill and refuse anyway).
// Caller holds a.mu.
func (a *API) saveQuarantineLocked() {
	b, _ := json.Marshal(a.quarantined)
	if err := writeFileAtomic(a.quarantinePath(), b); err != nil {
		a.saveErr = "saving the quarantine failed: " + err.Error()
		log.Printf("bind check: %s", a.saveErr)
		return
	}
	a.saveErr = ""
}

// quarantine marks instance id quarantined (persisted).
func (a *API) quarantine(id, why string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.quarantined[id] = why
	delete(a.lifted, id)
	a.saveQuarantineLocked()
}

// unquarantine is DELETE /v1/projects/{id}/quarantine: the Hub's explicit
// admin action (never a bundle PUT), under the bundle lock (R3-L1).
// Without a bundle (nothing of it can run) it simply clears, and the
// Hub's next push must be accepted or the quarantine comes back (R3-M2);
// with one, its bind sources are walked again first. Only the reason read
// at the start is cleared: a new one meanwhile stays.
func (a *API) unquarantine(w http.ResponseWriter, r *http.Request, id string) {
	defer a.lockID(id)()
	a.mu.Lock()
	all, why := a.quarantineAll, a.quarantined[id]
	a.mu.Unlock()
	if all != "" {
		writeError(w, http.StatusConflict, clipMsg(all))
		return
	}
	if why == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p := a.project(id)
	if p != nil {
		if err := a.checkBindPaths(id, p.model); err != nil {
			writeError(w, http.StatusConflict, clipMsg("still failing the bind check: "+err.Error()))
			return
		}
	}
	a.mu.Lock()
	if a.quarantined[id] == why {
		delete(a.quarantined, id)
		if p == nil {
			a.lifted[id] = true
		}
		a.saveQuarantineLocked()
	}
	a.mu.Unlock()
	log.Printf("bind check: %s: the quarantine was lifted by the Hub", id)
	w.WriteHeader(http.StatusNoContent)
}

// SweepEvery is how often the backstop re-checks every running container
// of the agent's projects, whatever the event stream saw.
var SweepEvery = 30 * time.Second

// WatchStarts is the backstop of A-H2: every container start of an
// instance project — the engine's own too (a restart policy, a daemon
// restart, a reboot), which never goes through the agent — is checked.
// Starts the stream can't have seen (before the agent ran, while the
// stream reconnects) are caught by a sweep of every running container:
// once at start, right after every (re)subscribe, and every SweepEvery
// (review A2-H1). Runs until ctx ends.
func (a *API) WatchStarts(ctx context.Context) {
	a.Sweep(ctx)
	go func() {
		t := time.NewTicker(SweepEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.Sweep(ctx)
			}
		}
	}()
	backoff := time.Second
	for ctx.Err() == nil {
		subscribed := make(chan struct{})
		go func() {
			// Once the subscription has had a moment to be established:
			// what started before it is swept.
			select {
			case <-ctx.Done():
			case <-subscribed:
			case <-time.After(time.Second):
				a.Sweep(ctx)
			}
		}()
		err := a.cfg.Runtime.Events(ctx, runtime.Filter{All: true}, func(ev runtime.Event) {
			if ev.Action != "start" {
				return
			}
			a.CheckStarted(ctx, ev.Actor.ID, ev.Actor.Attributes[docker.LabelProject])
		})
		close(subscribed)
		if ctx.Err() != nil {
			return
		}
		log.Printf("bind check: the engine's event stream ended (%v); retrying in %s", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
		a.Sweep(ctx)
	}
}

// Sweep checks every running container of an instance project (and
// re-reads an unreadable quarantine.json: repaired, it applies again).
func (a *API) Sweep(ctx context.Context) {
	if a.quarantineOf("\x00") != "" {
		a.loadQuarantine()
	}
	units, err := a.cfg.Runtime.List(ctx, runtime.Filter{All: true})
	if err != nil {
		log.Printf("bind check: listing the containers: %v", err)
		return
	}
	for _, u := range units {
		if u.State != "running" && u.State != "restarting" {
			continue
		}
		a.CheckStarted(ctx, u.ID, u.Project)
	}
}

// CheckStarted runs the backstop for one started container (project:
// its label as the event carried it, "" = read by inspection, review
// A2-M1). A violation:
//   - an instance project the agent holds no bundle for (unknown, or
//     dropped at load): stopped;
//   - a bind mount the bundle doesn't have, or one failing the walk;
//
// kills the container now and takes the project down in the background,
// retried with backoff until it succeeds; the instance is quarantined
// (persisted) until the Hub lifts it.
func (a *API) CheckStarted(ctx context.Context, container, project string) {
	var info runtime.UnitInfo
	inspected := false
	if container != "" {
		if i, err := a.cfg.Runtime.Inspect(ctx, container); err == nil {
			info, inspected = i, true
			if project == "" {
				project = i.Labels[docker.LabelProject]
			}
		} else if project == "" {
			log.Printf("bind check: can't inspect %s: %v", clipMsg(container), err)
			return
		}
	}
	if inspected && info.Labels[docker.LabelHelper] != "" {
		return // the agent's own helper (its spec checked when created)
	}
	// The agent's own compose project is never acted on (R3-M1): no
	// instance can map there (reserved ids), and a recreated sidecar or a
	// compose run of the worker stack is the operator's.
	if project == "" || slices.Contains(a.cfg.OwnContainers, container) || (a.cfg.OwnProject != "" && project == a.cfg.OwnProject) {
		return
	}
	id, ok := strings.CutPrefix(project, runtime.ProjectPrefix)
	if !ok || agentapi.ValidInstance(id) != nil {
		return
	}
	var why string
	p := a.project(id)
	switch {
	case a.quarantineOf(id) != "":
		why = a.quarantineOf(id) // quarantined (or all are): it must not run
	case p == nil:
		why = "a container of an instance the agent holds no valid bundle for"
	case !inspected:
		why = "the started container can't be inspected (its mounts unchecked)"
	default:
		if err := a.checkBindPaths(id, p.model); err != nil {
			why = err.Error()
		} else {
			why = a.checkMounts(id, p, info.Mounts)
		}
	}
	if why == "" {
		return
	}
	why = clipMsg(why)
	log.Printf("bind check: %s: a started container fails the bind check (%s): killed, taken down, quarantined", id, why)
	if a.quarantineOf(id) == "" {
		a.quarantine(id, why)
	}
	if container != "" {
		if err := a.cfg.Runtime.Signal(ctx, container, "KILL"); err != nil {
			log.Printf("bind check: %s: kill %s: %v", id, clipMsg(container), err)
		}
	}
	// One down worker per id (R3-L3: sweeps don't pile them up).
	a.mu.Lock()
	running := a.downs[id]
	a.downs[id] = true
	a.mu.Unlock()
	if !running {
		go func() {
			a.downUntilDone(ctx, id)
			a.mu.Lock()
			delete(a.downs, id)
			a.mu.Unlock()
		}()
	}
}

// checkMounts compares a container's actual bind mounts with its bundle:
// each must be one of the bundle's bind sources and pass the walk.
func (a *API) checkMounts(id string, p *project, mounts []runtime.Mount) string {
	want := bindsOf(p.model)
	own := []string{a.filesDir(id), a.appfilesDir(id)}
	for _, m := range mounts {
		if m.Type != "bind" {
			continue
		}
		src := filepath.Clean(m.Source)
		if _, ok := want[src]; !ok {
			return "the container has the bind mount " + src + ", which its bundle doesn't"
		}
		if err := walkNoSymlink(own, a.cfg.BindRoots, src); err != nil {
			return err.Error()
		}
	}
	return ""
}

// downUntilDone takes instance id's project down, retried with backoff
// (1 s … 1 min) until it succeeds or ctx ends; the quarantine stays.
func (a *API) downUntilDone(ctx context.Context, id string) {
	backoff := time.Second
	for {
		err := a.cfg.Runtime.DownByName(ctx, runtime.ProjectName(id))
		if err == nil {
			return
		}
		log.Printf("bind check: %s: down: %v (retried in %s)", id, err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

// flush sends what is buffered (a stream's header at once).
func flush(w http.ResponseWriter) {
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
}
