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
	"sort"
	"strconv"
	"strings"
	"sync"

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
		return true
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
func refuseIncludeExtends(name string, b []byte) error {
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
		}
	}
	return nil
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
	a.mu.Lock()
	for oid, p := range a.projects {
		if oid != id {
			others = append(others, p.manifest)
		}
	}
	a.mu.Unlock()
	if err := agentapi.ValidateBundle(model, m, others, a.scope(id)); err != nil {
		return nil, err
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
// directory itself must be a real directory with no symlink in its path.
// A missing component ends the walk (the engine creates it below).
func (a *API) checkBindPaths(id string, model *types.Project) error {
	bases := append([]string{a.filesDir(id), a.appfilesDir(id)}, a.cfg.BindRoots...)
	for _, src := range bindSources(model) {
		if err := walkNoSymlink(bases, src); err != nil {
			return fmt.Errorf("%w (bind %s)", err, clipMsg(src))
		}
	}
	return nil
}

// walkNoSymlink checks src below the longest base containing it.
func walkNoSymlink(bases []string, src string) error {
	src = filepath.Clean(src)
	base := ""
	for _, b := range bases {
		if (src == b || strings.HasPrefix(src, b+"/")) && len(b) > len(base) {
			base = b
		}
	}
	if base == "" {
		return errors.New("not under a folder root")
	}
	if real, err := filepath.EvalSymlinks(base); err != nil {
		if errors.Is(err, fs.ErrNotExist) && src != base {
			return nil // the engine creates it (and nothing below can be a link yet)
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%s: %w", base, err)
	} else if real != base {
		return fmt.Errorf("a symlink in a folder root's path (%s): %w", base, ErrNotPlain)
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

// bundleLocks serialises one id's bundle PUTs (review L5).
var bundleLocks sync.Map

func lockID(id string) func() {
	v, _ := bundleLocks.LoadOrStore(id, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// putBundle: the tar into <data>/projects/<id>.new (only the bundle's
// allowed names), include/extends refused, templates and certs moved to
// <data>/files/<id>.new, then `docker compose config` with the bundle's
// env file and the files dir as project directory; that output is
// validated (ValidateBundle, symlink walk) and becomes the only file the
// agent runs. Only then is everything swapped into place.
func (a *API) putBundle(w http.ResponseWriter, r *http.Request, id string) {
	defer lockID(id)()
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
			err = refuseIncludeExtends(f, b)
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
	a.projects[id] = p
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
			err = writeRooted(root, rel, f, fi.Mode().Perm())
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
	if err := os.MkdirAll(a.resolvedDir(), 0o700); err != nil {
		return err
	}
	os.Chmod(a.resolvedDir(), 0o700)
	if err := writeFileAtomic(a.resolvedEnv(id), []byte("COMPOSE_PROFILES="+profiles+"\n")); err != nil {
		return err
	}
	return writeFileAtomic(a.resolvedFile(id), resolved)
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
	defer lockID(id)()
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
