package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/compose-spec/compose-go/v2/cli"
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
	execs    map[string]bool
	helpers  map[string]*helper
	ops      map[string]context.CancelFunc
}

// NewAPI loads the bundles already on disk (each re-validated; an invalid
// one is dropped from scope and logged).
func NewAPI(cfg APIConfig) *API {
	a := &API{cfg: cfg, projects: map[string]*project{}, execs: map[string]bool{}, helpers: map[string]*helper{}, ops: map[string]context.CancelFunc{}}
	a.mux = http.NewServeMux()
	a.routes()
	entries, _ := os.ReadDir(a.projectsDir())
	for _, e := range entries {
		if !e.IsDir() || agentapi.ValidInstance(e.Name()) != nil {
			continue
		}
		if p, err := a.loadProject(e.Name(), a.projectDir(e.Name())); err != nil {
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

// composeFiles are the bundle's compose files, in order, that exist.
func composeFiles(dir string) []string {
	var out []string
	for _, f := range []string{BundleCompose, BundleOverride, BundleUserOverride} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			out = append(out, filepath.Join(dir, f))
		}
	}
	return out
}

// loadModel loads the bundle in dir (compose-go, every profile, paths
// unresolved: the Hub's loadRendered options).
func (a *API) loadModel(id, dir string) (*types.Project, error) {
	files := composeFiles(dir)
	if len(files) == 0 || filepath.Base(files[0]) != BundleCompose {
		return nil, errors.New("the bundle has no compose.yml")
	}
	opts := []cli.ProjectOptionsFn{cli.WithName(runtime.ProjectName(id)), cli.WithWorkingDirectory(dir), cli.WithEnv(a.cfg.ComposeEnv),
		cli.WithProfiles([]string{"*"}), cli.WithConsistency(false), cli.WithResolvedPaths(false), cli.WithoutEnvironmentResolution}
	if _, err := os.Stat(filepath.Join(dir, BundleEnv)); err == nil {
		opts = append(opts, cli.WithEnvFiles(filepath.Join(dir, BundleEnv)), cli.WithDotEnv)
	}
	po, err := cli.NewProjectOptions(files, opts...)
	if err != nil {
		return nil, err
	}
	return po.LoadProject(context.Background())
}

func (a *API) readManifest(dir string) (agentapi.BundleManifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, agentapi.ManifestName))
	if err != nil {
		return agentapi.BundleManifest{}, err
	}
	var m agentapi.BundleManifest
	err = agentapi.Decode(strings.NewReader(string(b)), agentapi.MaxJSON, &m)
	return m, err
}

// loadProject validates the bundle in dir as instance id's, to live at
// the project directory (relative binds resolve there).
func (a *API) loadProject(id, dir string) (*project, error) {
	m, err := a.readManifest(dir)
	if err != nil {
		return nil, err
	}
	if m.Instance != id {
		return nil, errors.New("the manifest names another instance")
	}
	model, err := a.loadModel(id, dir)
	if err != nil {
		return nil, err
	}
	var others []agentapi.BundleManifest
	a.mu.Lock()
	for oid, p := range a.projects {
		if oid != id {
			others = append(others, p.manifest)
		}
	}
	a.mu.Unlock()
	roots := append(append([]string{}, a.cfg.BindRoots...), a.appfilesDir(id))
	if err := agentapi.ValidateBundle(model, m, others, roots, a.projectDir(id)); err != nil {
		return nil, err
	}
	p := &project{manifest: m, model: model, images: map[string]bool{}, routes: map[string]map[int]bool{}}
	all := map[string]types.ServiceConfig{}
	for n, s := range model.DisabledServices {
		all[n] = s
	}
	for n, s := range model.Services {
		all[n] = s
	}
	for n, s := range all {
		if s.Image != "" {
			p.images[s.Image] = true
		}
		for k, v := range s.Labels {
			if routePortRe.MatchString(strings.ToLower(k)) {
				if port, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && port > 0 && port < 65536 {
					if p.routes[n] == nil {
						p.routes[n] = map[int]bool{}
					}
					p.routes[n][port] = true
				}
			}
		}
	}
	return p, nil
}

var routePortRe = regexp.MustCompile(`^traefik\.http\.services\.[^.]+\.loadbalancer\.server\.port$`)

// putBundle writes the bundle into <data>/projects/<id>.new/, re-validates
// it and only then renames it over <data>/projects/<id>/; the bundle's
// appfiles/ go to <data>/appfiles/<id>/ (kept across bundles).
func (a *API) putBundle(w http.ResponseWriter, r *http.Request, id string) {
	staging := a.projectDir(id) + ".new"
	os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0o750); err != nil {
		writeError(w, http.StatusInternalServerError, "can't stage the bundle")
		return
	}
	defer os.RemoveAll(staging)
	m, err := agentapi.ReadBundle(r.Body, id, agentapi.MaxBundle, func(name string, mode fs.FileMode, data io.Reader) error {
		return writeStaged(staging, name, mode, data)
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, clipMsg(err.Error()))
		return
	}
	// The manifest is kept with the bundle (restarts re-validate from it).
	mb, _ := json.Marshal(m)
	if err := writeStaged(staging, agentapi.ManifestName, 0o600, strings.NewReader(string(mb))); err != nil {
		writeError(w, http.StatusInternalServerError, "can't stage the manifest")
		return
	}
	p, err := a.loadProject(id, staging)
	if err != nil {
		writeError(w, http.StatusBadRequest, clipMsg(err.Error()))
		return
	}
	if err := a.commitBundle(id, staging); err != nil {
		writeError(w, http.StatusInternalServerError, clipMsg(err.Error()))
		return
	}
	a.mu.Lock()
	a.projects[id] = p
	a.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// writeStaged writes one bundle file under dir (name is clean and
// relative: agentapi.ReadBundle), never following a symlink.
func writeStaged(dir, name string, mode fs.FileMode, data io.Reader) error {
	p := filepath.Join(dir, filepath.FromSlash(name))
	if rel, err := filepath.Rel(dir, p); err != nil || strings.HasPrefix(rel, "..") {
		return errors.New("bundle: a path escapes the bundle")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscallNoFollow, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, data); err != nil {
		f.Close()
		os.Remove(p)
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (a *API) commitBundle(id, staging string) error {
	// appfiles/ → <data>/appfiles/<id>/ (each file renamed into place).
	src := filepath.Join(staging, strings.TrimSuffix(BundleAppfiles, "/"))
	if _, err := os.Stat(src); err == nil {
		dst := a.appfilesDir(id)
		err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(src, p)
			if d.IsDir() {
				return os.MkdirAll(filepath.Join(dst, rel), 0o750)
			}
			return os.Rename(p, filepath.Join(dst, rel))
		})
		if err != nil {
			return fmt.Errorf("appfiles: %v", err)
		}
		os.RemoveAll(src)
	}
	final, old := a.projectDir(id), a.projectDir(id)+".old"
	os.RemoveAll(old)
	if _, err := os.Stat(final); err == nil {
		if err := os.Rename(final, old); err != nil {
			return err
		}
	}
	if err := os.Rename(staging, final); err != nil {
		os.Rename(old, final)
		return err
	}
	return os.RemoveAll(old)
}

func (a *API) removeProject(w http.ResponseWriter, r *http.Request, id string) {
	units, err := a.cfg.Runtime.List(r.Context(), runtime.Filter{Instance: id})
	if err != nil {
		engineError(w, err)
		return
	}
	if len(units) > 0 {
		writeError(w, http.StatusConflict, "the project still has containers: take it down first")
		return
	}
	a.mu.Lock()
	delete(a.projects, id)
	a.mu.Unlock()
	os.RemoveAll(a.projectDir(id))
	os.RemoveAll(a.appfilesDir(id))
	w.WriteHeader(http.StatusNoContent)
}

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
	dir := filepath.Join(a.appfilesDir(id), name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		writeError(w, http.StatusInternalServerError, "can't create the data file directory")
		return
	}
	for _, f := range files {
		if err := writeAtomic(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			writeError(w, http.StatusInternalServerError, "can't write the data file")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── lifecycle ────────────────────────────────────────────────────────────

func (a *API) runtimeProject(id string) runtime.Project {
	p := a.project(id)
	dir := a.projectDir(id)
	cf := compose.Project{Name: runtime.ProjectName(id), Files: composeFiles(dir), ProjectDir: dir}
	if _, err := os.Stat(filepath.Join(dir, BundleEnv)); err == nil {
		cf.EnvFile = filepath.Join(dir, BundleEnv)
	}
	return runtime.Project{Name: cf.Name, Instance: id, Files: cf, Model: p.model}
}

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
