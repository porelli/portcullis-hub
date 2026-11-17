package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/runtime"
)

// The bundle on a worker (contract §17.4; review fix round 1, C1/C2):
//   - <data>/projects/<id>/: MANIFEST.json and the compose files
//     (compose.yml, override.yml, user.yml, env) — never bindable, never
//     run: only `docker compose config` reads them;
//   - <data>/files/<id>/: templates/… and certs/ca-bundle.crt, the
//     compose project directory (relative binds resolve there; binds must
//     be read-only);
//   - <data>/resolved/<id>.json: compose config's output, validated, the
//     only file up / down ever run, with <data>/resolved/<id>.env (only
//     the bundle's COMPOSE_PROFILES) as the env file;
//   - <data>/appfiles/<id>/: the data files (read-only binds).

// bundleRoots are the only names a bundle's files may start with.
var bundleRootFiles = map[string]bool{BundleCompose: true, BundleOverride: true, BundleUserOverride: true, BundleEnv: true}

const certsBundle = "certs/ca-bundle.crt"

// bundlePathOK: a bundle file is one of the compose files, a template
// file, an appfile or the CA bundle; anything else (.env included) is
// refused.
func bundlePathOK(p string) bool {
	switch {
	case bundleRootFiles[p], p == certsBundle:
		return true
	case strings.HasPrefix(p, "templates/") && len(p) > len("templates/"):
		return true
	case strings.HasPrefix(p, BundleAppfiles) && len(p) > len(BundleAppfiles):
		// Never a settings secrets file (errSecretsFile): primary-only.
		return !strings.HasSuffix(p, ".secrets.json")
	}
	return false
}

func (a *API) filesDir(id string) string     { return filepath.Join(a.cfg.DataDir, "files", id) }
func (a *API) resolvedDir() string           { return filepath.Join(a.cfg.DataDir, "resolved") }
func (a *API) resolvedFile(id string) string { return filepath.Join(a.resolvedDir(), id+".json") }
func (a *API) resolvedEnv(id string) string  { return filepath.Join(a.resolvedDir(), id+".env") }

// protected is every path no bind may touch: the configured ones, the
// agent's data dir and "/".
func (a *API) protected() []string {
	out := append([]string{}, a.cfg.Protected...)
	return append(out, a.cfg.DataDir, "/")
}

func (a *API) scope(id string) agentapi.BundleScope {
	return agentapi.BundleScope{BindRoots: a.cfg.BindRoots, ReadOnlyDirs: []string{a.filesDir(id), a.appfilesDir(id)},
		Protected: a.protected(), ProjectDir: a.projectsDir()}
}

// refuseIncludeExtends decodes a compose file as YAML: a top-level
// include or a service extends is refused (§3's rule again on the
// worker: compose would read files the agent never validated).
func refuseIncludeExtends(name string, b []byte, ownEnv []string) error {
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	if _, ok := doc["include"]; ok {
		return fmt.Errorf("%s: include is not allowed", name)
	}
	svcs, _ := doc["services"].(map[string]any)
	for n, sv := range svcs {
		if m, ok := sv.(map[string]any); ok {
			if _, ok := m["extends"]; ok {
				return fmt.Errorf("%s: service %s: extends is not allowed", name, n)
			}
			// A-M1: compose config would read (and inline) the files, as
			// the agent, before anything is validated.
			for _, k := range []string{"env_file", "label_file"} {
				if v, ok := m[k]; ok && !(k == "env_file" && envFileIsOwn(v, ownEnv)) {
					return fmt.Errorf("%s: service %s: %s is not allowed", name, n, k)
				}
			}
		}
	}
	return nil
}

// envFileIsOwn: an env_file naming exactly the instance's own bundle env
// file (one entry, a plain string or {path} without required: false).
func envFileIsOwn(v any, own []string) bool {
	one := func(x any) string {
		switch t := x.(type) {
		case string:
			return t
		case map[string]any:
			if len(t) == 1 {
				if p, ok := t["path"].(string); ok {
					return p
				}
			}
		}
		return ""
	}
	var p string
	switch t := v.(type) {
	case []any:
		if len(t) != 1 {
			return false
		}
		p = one(t[0])
	default:
		p = one(t)
	}
	return p != "" && slices.Contains(own, p)
}

var profilesRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.,*-]*$`)

// profilesOf is the bundle env's COMPOSE_PROFILES (the setup choices'
// profiles, §13.18), the only variable the run-time env file carries.
func profilesOf(env []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(env))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	out := ""
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.TrimSpace(k) != "COMPOSE_PROFILES" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if v != "" && !profilesRe.MatchString(v) {
			return "", errors.New("COMPOSE_PROFILES: only profile names")
		}
		out = v
	}
	return out, sc.Err()
}

// loadResolved loads compose config's output (absolute paths, already
// interpolated: no env, every profile).
func loadResolved(id, file, workdir string) (*types.Project, error) {
	po, err := cli.NewProjectOptions([]string{file}, cli.WithName(runtime.ProjectName(id)), cli.WithWorkingDirectory(workdir),
		cli.WithEnv([]string{}), cli.WithProfiles([]string{"*"}), cli.WithConsistency(false), cli.WithResolvedPaths(false),
		cli.WithoutEnvironmentResolution)
	if err != nil {
		return nil, err
	}
	return po.LoadProject(context.Background())
}

// validateResolved validates the resolved model of instance id, the
// bind sources walked from their roots (no symlink anywhere, C4), and
// builds the project's scope facts.
func (a *API) validateResolved(id string, m agentapi.BundleManifest, model *types.Project) (*project, error) {
	var others []agentapi.BundleManifest
	otherBinds := map[string]map[string]bool{}
	a.mu.Lock()
	for oid, p := range a.projects {
		if oid != id {
			others = append(others, p.manifest)
			otherBinds[oid] = bindsOf(p.model)
		}
	}
	a.mu.Unlock()
	if err := agentapi.ValidateBundle(model, m, others, a.scope(id)); err != nil {
		return nil, err
	}
	if err := checkNestedBinds(id, bindsOf(model), otherBinds); err != nil {
		return nil, err
	}
	// The agent's own containers' names are reserved (R4-L1).
	for _, ss := range []types.Services{model.Services, model.DisabledServices} {
		for n, sv := range ss {
			for _, name := range []string{sv.ContainerName, sv.Hostname} {
				for _, r := range a.cfg.ReservedNames {
					if name != "" && strings.EqualFold(strings.TrimPrefix(name, "/"), strings.TrimPrefix(r, "/")) {
						return nil, fmt.Errorf("service %s: the name %q is the agent's own", n, name)
					}
				}
			}
		}
	}
	if err := a.checkBindPaths(id, model); err != nil {
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

// bindSources are a model's bind sources (services and disabled ones).
func bindSources(model *types.Project) []string {
	var out []string
	for _, ss := range []types.Services{model.Services, model.DisabledServices} {
		for _, s := range ss {
			for _, v := range s.Volumes {
				if v.Type == types.VolumeTypeBind && v.Source != "" {
					out = append(out, v.Source)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// checkBindPaths walks every bind source from the directory that allows
// it (a folder root or the instance's files / appfiles dir), component by
// component with os.Root.Lstat: a symlink anywhere is refused (C4). The
// directory itself must be a real directory with no symlink in its path;
// a folder root the agent can't see is refused (A-H3: never "passed").
// A missing component ends the walk (the engine creates it below).
func (a *API) checkBindPaths(id string, model *types.Project) error {
	own := []string{a.filesDir(id), a.appfilesDir(id)}
	for _, src := range bindSources(model) {
		if err := walkNoSymlink(own, a.cfg.BindRoots, src); err != nil {
			return fmt.Errorf("%w (bind %s)", err, clipMsg(src))
		}
		// The instance's own files and appfiles dirs live in the data
		// dir by design (read-only binds, ValidateBundle); every other
		// source is a folder root's.
		if underAny(filepath.Clean(src), own) {
			continue
		}
		if err := a.protectedAncestor(src); err != nil {
			return fmt.Errorf("%w (bind %s)", err, clipMsg(src))
		}
	}
	return nil
}

// protectedAncestor (review A2-M3): no existing ancestor of src (src
// included) may be the same directory (device and inode) as a protected
// one the agent can see — an alias the text compare can't tell, a bind
// mount of it under a folder root. "/" is protected by equality only.
func (a *API) protectedAncestor(src string) error {
	var prot []os.FileInfo
	var names []string
	for _, p := range a.protected() {
		if p == "/" {
			continue
		}
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			prot, names = append(prot, fi), append(names, p)
		}
	}
	for cur := filepath.Clean(src); ; cur = filepath.Dir(cur) {
		if fi, err := os.Stat(cur); err == nil {
			for i, p := range prot {
				if os.SameFile(fi, p) {
					return fmt.Errorf("the same directory as the protected %s: refused", names[i])
				}
			}
		}
		if cur == "/" || cur == "." {
			return nil
		}
	}
}

// ErrRootNotVisible: a folder root isn't a directory inside the agent.
var ErrRootNotVisible = errors.New("isn't visible to the agent")

// CheckRootsVisible: every folder root is a directory the agent sees, at
// the same path, with no symlink in it (the agent's start refuses
// otherwise: its walks would mean nothing).
func CheckRootsVisible(roots []string) error {
	for _, r := range roots {
		real, err := filepath.EvalSymlinks(r)
		if err != nil {
			return fmt.Errorf("folder root %s %w", r, ErrRootNotVisible)
		}
		if real != r {
			return fmt.Errorf("folder root %s has a symlink in its path: %w", r, ErrNotPlain)
		}
		if fi, err := os.Stat(r); err != nil || !fi.IsDir() {
			return fmt.Errorf("folder root %s %w", r, ErrRootNotVisible)
		}
	}
	return nil
}

// walkNoSymlink checks src below the longest base containing it: one of
// own (the instance's own dirs: may not exist yet) or roots (the folder
// roots: must exist, A-H3).
func walkNoSymlink(own, roots []string, src string) error {
	src = filepath.Clean(src)
	base, isRoot := "", false
	for _, b := range own {
		if (src == b || strings.HasPrefix(src, b+"/")) && len(b) > len(base) {
			base, isRoot = b, false
		}
	}
	for _, b := range roots {
		if (src == b || strings.HasPrefix(src, b+"/")) && len(b) > len(base) {
			base, isRoot = b, true
		}
	}
	if base == "" {
		return errors.New("not under a folder root")
	}
	real, err := filepath.EvalSymlinks(base)
	switch {
	case err != nil && errors.Is(err, fs.ErrNotExist) && !isRoot:
		return nil // the instance's own dir, not made yet: nothing below can be a link
	case err != nil && isRoot:
		return fmt.Errorf("folder root %s %w", base, ErrRootNotVisible)
	case err != nil:
		return fmt.Errorf("%s: %w", base, err)
	case real != base:
		return fmt.Errorf("a symlink in a folder root's path (%s): %w", base, ErrNotPlain)
	}
	if fi, err := os.Stat(base); err != nil || !fi.IsDir() {
		if isRoot {
			return fmt.Errorf("folder root %s %w", base, ErrRootNotVisible)
		}
		return fmt.Errorf("%s isn't a directory: %w", base, ErrNotPlain)
	}
	if src == base {
		return nil
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return err
	}
	defer root.Close()
	rel, _ := filepath.Rel(base, src)
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		fi, err := root.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("a symlink in a bind source (%s): %w", path.Join(base, p), ErrNotPlain)
		}
	}
	return nil
}

// bindsOf are a model's bind sources with whether each is writable.
func bindsOf(model *types.Project) map[string]bool {
	out := map[string]bool{}
	for _, ss := range []types.Services{model.Services, model.DisabledServices} {
		for _, s := range ss {
			for _, v := range s.Volumes {
				if v.Type == types.VolumeTypeBind && v.Source != "" {
					src := filepath.Clean(v.Source)
					out[src] = out[src] || !v.ReadOnly
				}
			}
		}
	}
	return out
}

func strictlyUnder(p, dir string) bool {
	return dir == "/" && p != "/" || strings.HasPrefix(p, dir+"/")
}

// checkNestedBinds (A-H2a): no bind source of instance id may be an
// ancestor of, or inside, a bind source of another instance on this
// worker, and none of its own writable binds may contain another of its
// bind sources — so no container can rewrite a directory above another
// container's bind source.
func checkNestedBinds(id string, mine map[string]bool, others map[string]map[string]bool) error {
	srcs := make([]string, 0, len(mine))
	for s := range mine {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	for _, s := range srcs {
		for _, o := range srcs {
			if o != s && mine[s] && strictlyUnder(o, s) {
				return fmt.Errorf("nested binds are refused: the writable bind %s contains %s", clipMsg(s), clipMsg(o))
			}
		}
		oids := make([]string, 0, len(others))
		for oid := range others {
			oids = append(oids, oid)
		}
		sort.Strings(oids)
		for _, oid := range oids {
			if oid == id {
				continue
			}
			for o := range others[oid] {
				if strictlyUnder(o, s) || strictlyUnder(s, o) {
					return fmt.Errorf("binds across instances may not nest (instance %s): %s and %s", oid, clipMsg(s), clipMsg(o))
				}
			}
		}
	}
	return nil
}

// lockID takes the agent-wide bundle lock (review A2-M2; per API, I5):
// every bundle PUT, project removal and quarantine lift run under it, so
// the cross-instance checks and the commit can't interleave.
func (a *API) lockID(string) func() {
	a.bundleMu.Lock()
	return a.bundleMu.Unlock
}

// putBundle: the tar into <data>/projects/<id>.new (only the bundle's
// allowed names), include/extends refused, templates and certs moved to
// <data>/files/<id>.new, then `docker compose config` with the bundle's
// env file and the files dir as project directory; that output is
// validated (ValidateBundle, symlink walk) and becomes the only file the
// agent runs. Only then is everything swapped into place.
func (a *API) putBundle(w http.ResponseWriter, r *http.Request, id string) {
	defer a.lockID(id)()
	sw := &statusWriter{ResponseWriter: w}
	a.putBundleLocked(sw, r, id)
	// The bundle the Hub sends right after a lift (fix round 4, R3-M2):
	// refused, the instance is quarantined again; accepted, the lift is
	// complete.
	a.mu.Lock()
	lifted := a.lifted[id]
	delete(a.lifted, id)
	a.mu.Unlock()
	if lifted && sw.code >= 400 {
		a.quarantine(id, "the bundle sent after the quarantine was lifted was refused")
	}
}

// statusWriter records the status a handler wrote.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(c int) {
	if s.code == 0 {
		s.code = c
	}
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (a *API) putBundleLocked(w http.ResponseWriter, r *http.Request, id string) {
	// An instance whose project would be the agent's own (fix round 3).
	if a.cfg.OwnProject != "" && runtime.ProjectName(id) == a.cfg.OwnProject {
		writeError(w, http.StatusBadRequest, "the instance id "+id+" is reserved on this worker: its project would be the agent's own")
		return
	}
	if a.cfg.Config == nil {
		writeError(w, http.StatusServiceUnavailable, "the agent can't run compose config")
		return
	}
	staging, filesStaging := a.projectDir(id)+".new", a.filesDir(id)+".new"
	os.RemoveAll(staging)
	os.RemoveAll(filesStaging)
	defer os.RemoveAll(staging)
	defer os.RemoveAll(filesStaging)
	if err := os.MkdirAll(staging, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "can't stage the bundle")
		return
	}
	m, err := agentapi.ReadBundle(r.Body, id, agentapi.MaxBundle, func(name string, mode fs.FileMode, data io.Reader) error {
		if !bundlePathOK(name) {
			return fmt.Errorf("bundle: %s: only compose.yml, override.yml, user.yml, env, templates/…, appfiles/… and certs/ca-bundle.crt", clipMsg(name))
		}
		return writeStaged(staging, name, mode, data)
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, clipMsg(err.Error()))
		return
	}
	if _, ok := m.Files[BundleCompose]; !ok {
		writeError(w, http.StatusBadRequest, "the bundle has no compose.yml")
		return
	}
	var files []string
	for _, f := range []string{BundleCompose, BundleOverride, BundleUserOverride} {
		b, err := os.ReadFile(filepath.Join(staging, f))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil {
			err = refuseIncludeExtends(f, b, []string{filepath.Join(a.projectDir(id), BundleEnv)})
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, clipMsg(err.Error()))
			return
		}
		files = append(files, filepath.Join(staging, f))
	}
	envFile := filepath.Join(staging, BundleEnv)
	envBytes, err := os.ReadFile(envFile)
	if errors.Is(err, fs.ErrNotExist) {
		envFile = filepath.Join(staging, ".empty.env")
		envBytes = nil
		err = os.WriteFile(envFile, nil, 0o600)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "can't read the env file")
		return
	}
	profiles, err := profilesOf(envBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// templates/ and certs/ → the files dir (the project directory).
	if err := os.MkdirAll(filesStaging, 0o750); err != nil {
		writeError(w, http.StatusInternalServerError, "can't stage the files")
		return
	}
	for _, d := range []string{"templates", "certs"} {
		if _, err := os.Lstat(filepath.Join(staging, d)); err == nil {
			if err := os.Rename(filepath.Join(staging, d), filepath.Join(filesStaging, d)); err != nil {
				writeError(w, http.StatusInternalServerError, "can't stage the files")
				return
			}
		}
	}
	// The app's own user reads its template files (bind sources) as on
	// the primary (templates/ there is 0755): every directory of the files
	// tree 0755; the files keep the primary's modes.
	// Nothing secret is ever in that world-readable tree: only template
	// files and the CA bundle (the env, overrides and manifest stay in the
	// 0700 project dir, appfiles — data and secrets files — in appfiles/).
	if err := filesTreeOnly(filesStaging); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := openDirs(filesStaging); err != nil {
		writeError(w, http.StatusInternalServerError, "can't stage the files")
		return
	}
	out, err := a.cfg.Config(r.Context(), compose.Project{Name: runtime.ProjectName(id), Files: files, ProjectDir: a.filesDir(id), EnvFile: envFile})
	if err != nil {
		writeError(w, http.StatusBadRequest, "compose config: "+clipMsg(err.Error()))
		return
	}
	resolvedStaging := filepath.Join(staging, ".resolved.json")
	if err := os.WriteFile(resolvedStaging, out, 0o600); err != nil {
		writeError(w, http.StatusInternalServerError, "can't stage the resolved model")
		return
	}
	model, err := loadResolved(id, resolvedStaging, a.filesDir(id))
	if err != nil {
		writeError(w, http.StatusBadRequest, "the resolved model: "+clipMsg(err.Error()))
		return
	}
	p, err := a.validateResolved(id, m, model)
	if err != nil {
		writeError(w, http.StatusBadRequest, clipMsg(err.Error()))
		return
	}
	if err := a.commitBundle(id, staging, filesStaging, out, profiles, m); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, ErrNotPlain) {
			code = http.StatusConflict
		}
		writeError(w, code, clipMsg(err.Error()))
		return
	}
	a.mu.Lock()
	a.projects[id] = p // a quarantine stays: only the Hub's explicit lift ends it
	a.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// loadStored re-validates a bundle on disk at start (from its resolved
// model: the bundle's own files are never run).
func (a *API) loadStored(id string) (*project, error) {
	b, err := os.ReadFile(filepath.Join(a.projectDir(id), agentapi.ManifestName))
	if err != nil {
		return nil, err
	}
	var m agentapi.BundleManifest
	if err := agentapi.Decode(bytes.NewReader(b), agentapi.MaxJSON, &m); err != nil {
		return nil, err
	}
	if m.Instance != id {
		return nil, errors.New("the manifest names another instance")
	}
	model, err := loadResolved(id, a.resolvedFile(id), a.filesDir(id))
	if err != nil {
		return nil, err
	}
	return a.validateResolved(id, m, model)
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

// commitBundle: the appfiles checked and written (rooted, no symlink),
// the manifest kept, then the project and files dirs swapped and the
// resolved model and its env file written (agent-only, 0600 in 0700).
func (a *API) commitBundle(id, staging, filesStaging string, resolved []byte, profiles string, m agentapi.BundleManifest) error {
	src := filepath.Join(staging, strings.TrimSuffix(BundleAppfiles, "/"))
	var rels []string
	if _, err := os.Lstat(src); err == nil {
		err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type().IsRegular() {
				rel, _ := filepath.Rel(src, p)
				rels = append(rels, filepath.ToSlash(rel))
			} else if !d.IsDir() {
				return ErrNotPlain
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("appfiles: %w", err)
		}
	}
	if len(rels) > 0 {
		root, err := a.appfilesRoot(id)
		if err != nil {
			return fmt.Errorf("appfiles: %w", err)
		}
		defer root.Close()
		for _, rel := range rels {
			if err := checkRooted(root, rel); err != nil {
				return fmt.Errorf("appfiles: %w", err)
			}
		}
		for _, rel := range rels {
			p := filepath.Join(src, filepath.FromSlash(rel))
			fi, err := os.Lstat(p)
			if err != nil {
				return err
			}
			f, err := os.OpenFile(p, os.O_RDONLY|syscallNoFollow, 0)
			if err != nil {
				return err
			}
			err = writeRooted(root, rel, f, fi.Mode().Perm(), a.appfilesGID())
			f.Close()
			if err != nil {
				return fmt.Errorf("appfiles: %w", err)
			}
		}
	}
	os.RemoveAll(src)
	os.Remove(filepath.Join(staging, ".resolved.json"))
	os.Remove(filepath.Join(staging, ".empty.env"))
	mb, _ := jsonMarshal(m)
	if err := writeStaged(staging, agentapi.ManifestName, 0o600, bytes.NewReader(mb)); err != nil {
		return err
	}
	for _, sw := range [][2]string{{staging, a.projectDir(id)}, {filesStaging, a.filesDir(id)}} {
		if err := swapDir(sw[0], sw[1]); err != nil {
			return err
		}
	}
	// files/ itself: traversable, never listable (no instance sees which
	// others there are).
	if err := os.Chmod(filepath.Dir(a.filesDir(id)), 0o711); err != nil {
		return err
	}
	if err := os.MkdirAll(a.resolvedDir(), 0o700); err != nil {
		return err
	}
	os.Chmod(a.resolvedDir(), 0o700)
	if err := writeFileAtomic(a.resolvedEnv(id), []byte("COMPOSE_PROFILES="+profiles+"\n")); err != nil {
		return err
	}
	return writeFileAtomic(a.resolvedFile(id), resolved)
}

// filesTreeOnly: root holds only templates/** and certs/ca-bundle.crt
// (regular files and directories).
func filesTreeOnly(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		switch {
		case rel == "." || rel == "templates" || rel == "certs":
			return nil
		case d.IsDir() && strings.HasPrefix(rel, "templates/"):
			return nil
		case d.Type().IsRegular() && (strings.HasPrefix(rel, "templates/") || rel == certsBundle):
			return nil
		}
		return fmt.Errorf("bundle: %s doesn't belong in the files tree", rel)
	})
}

// openDirs makes every directory under root (root included) 0755; links
// are never followed (WalkDir doesn't).
func openDirs(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0o755)
		}
		return nil
	})
}

// swapDir renames from over to (the old one removed; links not followed).
func swapDir(from, to string) error {
	old := to + ".old"
	os.RemoveAll(old)
	if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
		return err
	}
	if _, err := os.Lstat(to); err == nil {
		if err := os.Rename(to, old); err != nil {
			return err
		}
	}
	if err := os.Rename(from, to); err != nil {
		os.Rename(old, to)
		return err
	}
	return os.RemoveAll(old)
}

func (a *API) removeProject(w http.ResponseWriter, r *http.Request, id string) {
	defer a.lockID(id)()
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
	if _, ok := a.quarantined[id]; ok {
		delete(a.quarantined, id) // the project is gone with its bundle
		a.saveQuarantineLocked()
	}
	a.mu.Unlock()
	for _, p := range []string{a.projectDir(id), a.filesDir(id), a.appfilesDir(id), a.resolvedFile(id), a.resolvedEnv(id)} {
		os.RemoveAll(p)
	}
	w.WriteHeader(http.StatusNoContent)
}

// runtimeProject is what compose runs: the resolved model only, the
// files dir as project directory, the agent's env file (profiles only).
func (a *API) runtimeProject(id string) runtime.Project {
	p := a.project(id)
	cf := compose.Project{Name: runtime.ProjectName(id), Files: []string{a.resolvedFile(id)}, ProjectDir: a.filesDir(id), EnvFile: a.resolvedEnv(id)}
	return runtime.Project{Name: cf.Name, Instance: id, Files: cf, Model: p.model}
}

// CheckProtectedOutsideRoots (A-M2): no protected path may be inside (or
// equal to) a folder root — compared as text and, for every ancestor the
// agent can see, by device and inode (os.SameFile), so an alias of the
// same directory is caught where the kernel shows it. FUSE union views
// (Unraid's /mnt/user vs /mnt/cache) can't be told apart: documented.
func CheckProtectedOutsideRoots(protected, roots []string) error {
	type id struct {
		root string
		fi   os.FileInfo
	}
	var rs []id
	for _, r := range roots {
		if fi, err := os.Stat(r); err == nil {
			rs = append(rs, id{r, fi})
		}
	}
	for _, p := range protected {
		p = filepath.Clean(p)
		for _, r := range roots {
			if p == r || strings.HasPrefix(p, r+"/") {
				return fmt.Errorf("the protected path %s is inside the folder root %s: move it outside the folder roots, or narrow PORTCULLIS_WORKER_BIND_ROOTS", p, r)
			}
		}
		for a := p; ; a = filepath.Dir(a) {
			if fi, err := os.Stat(a); err == nil {
				for _, r := range rs {
					if os.SameFile(fi, r.fi) {
						return fmt.Errorf("the protected path %s is inside the folder root %s (the same directory as %s): move it outside the folder roots, or narrow PORTCULLIS_WORKER_BIND_ROOTS", p, r.root, a)
					}
				}
			}
			if a == "/" || a == "." {
				break
			}
		}
	}
	return nil
}

// InstallDirOf is the agent's compose working dir (its own container's
// com.docker.compose.project.working_dir label): the worker's install
// (./portcullis, .env, docker-compose.worker.yml), protected like the
// data dir (review A-H1). Missing or "/": no start.
func InstallDirOf(labels map[string]string) (string, error) {
	d := labels["com.docker.compose.project.working_dir"]
	if d == "" || !filepath.IsAbs(d) || filepath.Clean(d) != d || d == "/" {
		return "", errors.New("the agent's container has no usable com.docker.compose.project.working_dir label: start it with ./portcullis worker …")
	}
	return d, nil
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// CheckVisible: each path is a directory the agent sees (review A2-M3).
func CheckVisible(paths ...string) error {
	for _, p := range paths {
		if fi, err := os.Stat(p); p == "" || err != nil || !fi.IsDir() {
			return fmt.Errorf("%q isn't visible to the agent: mount it read-only at the same path (the install dir and the engine's data root are compared by device and inode)", p)
		}
	}
	return nil
}
