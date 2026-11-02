package hub

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
)

// fakeRunner records compose calls and checks that no two operations on the
// same project ever overlap.
type fakeRunner struct {
	mu         sync.Mutex
	calls      []string
	projects   []compose.Project
	active     map[string]int
	overlap    []string
	upErr      error
	downErr    error
	byNameErr  error
	creates    []string
	createHook func(project string)
	upHook     func(project string) // runs inside Up (after begin)
	// gate, if set, blocks Up until closed; entered receives the project
	// name when Up starts.
	gate    chan struct{}
	entered chan string
	delay   time.Duration
	// onDown runs on a successful Down/DownByName (e.g. the fake engine
	// forgets the project's containers).
	onDown func(project string)
}

func newFakeRunner() *fakeRunner { return &fakeRunner{active: map[string]int{}} }

func (f *fakeRunner) begin(op, name string, p compose.Project) {
	f.mu.Lock()
	f.calls = append(f.calls, op+":"+name)
	f.projects = append(f.projects, p)
	f.active[name]++
	if f.active[name] > 1 {
		f.overlap = append(f.overlap, op+":"+name)
	}
	f.mu.Unlock()
}

func (f *fakeRunner) end(name string) {
	f.mu.Lock()
	f.active[name]--
	f.mu.Unlock()
}

// Create (`up --no-start`) is recorded apart from calls (most tests check
// the up/down sequence); createHook can change the fake engine's
// containers as compose would.
func (f *fakeRunner) Create(ctx context.Context, p compose.Project) error {
	f.mu.Lock()
	f.creates = append(f.creates, p.Name)
	hook := f.createHook
	f.mu.Unlock()
	if hook != nil {
		hook(p.Name)
	}
	return nil
}

func (f *fakeRunner) Creates() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.creates...)
}

func (f *fakeRunner) Up(ctx context.Context, p compose.Project) error {
	f.begin("up", p.Name, p)
	defer f.end(p.Name)
	if f.upHook != nil {
		f.upHook(p.Name)
	}
	if f.entered != nil {
		f.entered <- p.Name
	}
	if f.gate != nil {
		<-f.gate
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return f.upErr
}

func (f *fakeRunner) Down(ctx context.Context, p compose.Project) error {
	f.begin("down", p.Name, p)
	defer f.end(p.Name)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.downErr == nil && f.onDown != nil {
		f.onDown(p.Name)
	}
	return f.downErr
}

func (f *fakeRunner) DownByName(ctx context.Context, name string) error {
	f.begin("downbyname", name, compose.Project{Name: name})
	defer f.end(name)
	if f.byNameErr == nil && f.onDown != nil {
		f.onDown(name)
	}
	return f.byNameErr
}

func (f *fakeRunner) Projects() []compose.Project {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]compose.Project(nil), f.projects...)
}

func (f *fakeRunner) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeRunner) Overlaps() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.overlap...)
}

// fakeEngine serves canned containers/logs/exec results.
type fakeEngine struct {
	mu         sync.Mutex
	containers []docker.Container
	listErr    error
	logs       map[string]string
	execCmd    []string
	execID     string
	execRes    *docker.ExecResult
	ve         *volumeEngine
}

func (e *fakeEngine) ListContainers(ctx context.Context, f docker.Filters) ([]docker.Container, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.listErr != nil {
		return nil, e.listErr
	}
	var out []docker.Container
	for _, c := range e.containers {
		ok := true
		for _, l := range f["label"] {
			k, v, hasV := cut(l)
			got, present := c.Labels[k]
			if !present || (hasV && got != v) {
				ok = false
			}
		}
		if ok {
			out = append(out, c)
		}
	}
	return out, nil
}

func cut(s string) (string, string, bool) {
	for i := range s {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func (e *fakeEngine) Logs(ctx context.Context, id string, tail int, ts bool) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, ok := e.logs[id]
	if !ok {
		return nil, errors.New("no such container")
	}
	return []byte(l), nil
}

func (e *fakeEngine) Exec(ctx context.Context, id string, cmd []string, timeout time.Duration) (*docker.ExecResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.execID, e.execCmd = id, cmd
	if e.execRes == nil {
		return &docker.ExecResult{Output: []byte("ok\n")}, nil
	}
	return e.execRes, nil
}

func (e *fakeEngine) Events(ctx context.Context, f docker.Filters, fn func(docker.Event)) error {
	<-ctx.Done()
	return ctx.Err()
}

func container(id, project, service, st string) docker.Container {
	return docker.Container{
		ID: id, Names: []string{"/" + project + "-" + service + "-1"}, State: st, Status: st,
		Labels: map[string]string{docker.LabelProject: project, docker.LabelService: service, docker.LabelNumber: "1"},
	}
}

// fakeIdP records client registrations.
type fakeIdP struct {
	registerErr error
	mu          sync.Mutex
	registered  []string
	updated     []string
	specs       []keycloak.ClientSpec
	hostUpdates []string // "<client>:<old uris> -> <new uris>"
	callbacks   []string // "+add -remove"
	// onCallbacks, if set, runs (once) at the start of the next
	// UpdateForwardAuthCallbacks, without f.mu.
	onCallbacks func()
	callbackErr error    // UpdateForwardAuthCallbacks fails with it (recorded nothing)
	access      []string // "+<client>:<owner>:<group>" / "-<client>:<owner>"
	accessErr   error
	deleted     []string // "<client>:<owner>"
	deleteErr   error
}

func (f *fakeIdP) DeleteClient(ctx context.Context, clientID, owner string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, clientID+":"+owner)
	return nil
}

func (f *fakeIdP) EnsureClientAccess(ctx context.Context, s keycloak.AccessSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.access = append(f.access, "+"+s.ClientID+":"+s.TemplateID+":"+s.Group)
	return f.accessErr
}

func (f *fakeIdP) RemoveClientAccess(ctx context.Context, clientID, owner string, allowedHosts []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.access = append(f.access, "-"+clientID+":"+owner)
	return nil
}

func (f *fakeIdP) accessCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.access...)
}

func (f *fakeIdP) RegisterClient(ctx context.Context, s keycloak.ClientSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.registerErr != nil {
		return f.registerErr
	}
	f.specs = append(f.specs, s)
	f.registered = append(f.registered, fmt.Sprintf("%s:%s:%s:%s:%s", s.ClientID, s.TemplateID, s.ACR, s.Secret, strings.Join(s.AllowedHosts, ",")))
	return nil
}

func (f *fakeIdP) UpdateClientACR(ctx context.Context, s keycloak.ClientSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updated = append(f.updated, s.ClientID+":"+s.ACR)
	return nil
}

func (f *fakeIdP) UpdateClientHosts(ctx context.Context, s keycloak.ClientSpec, oldURIs []string, hostMap map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hostUpdates = append(f.hostUpdates, s.ClientID+":"+strings.Join(oldURIs, ",")+" -> "+strings.Join(s.RedirectURIs, ","))
	return nil
}

func (f *fakeIdP) UpdateForwardAuthCallbacks(ctx context.Context, add, remove []string) error {
	f.mu.Lock()
	hook := f.onCallbacks
	f.onCallbacks = nil
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.callbackErr != nil {
		return f.callbackErr
	}
	if len(add)+len(remove) > 0 {
		f.callbacks = append(f.callbacks, "+"+strings.Join(add, ",")+" -"+strings.Join(remove, ","))
	}
	return nil
}

// ── fixture ──────────────────────────────────────────────

const grafanaManifest = `name: Grafana
category: monitoring
auth:
  method: header-auth
  group_access: true
  access_group: users_grafana
  admin_group: admin_grafana
  admin_paths: [/admin/, /api/admin]
env:
  - key: GF_SECRET
    generate: random
settings:
  options:
    - key: gf_theme
      label: Theme
      type: enum
      options: [{value: dark, label: Dark}, {value: light, label: Light}]
      delivery: [{env: GF_THEME}]
    - key: media
      label: Media
      type: path
      target: {service: web, mount: /media}
ports:
  - key: GRAFANA_PORT
    container: 3000
    default: 3300
    service: web
`

const grafanaCompose = "services:\n  web:\n    image: grafana\n    environment:\n      X: ${CORE_VAR}\n      GF_THEME: ${GF_THEME:-dark}\n    labels:\n      traefik.http.routers.grafana.rule: Host(`grafana.${PORTCULLIS_DOMAIN:-x}`)\n      traefik.http.routers.grafana.entrypoints: websecure\n"

const otherManifest = `name: Other
category: misc
auth:
  method: native-oidc
  sso: true
  group_access: true
  access_group: users_other
keycloak_clients:
  - client_id: other
    secret_env: OTHER_SECRET
    redirect_uri: https://other.{{DOMAIN}}/cb
    email_verified_claim: false
env:
  - key: OTHER_SECRET
    generate: random
ports:
  - key: OTHER_PORT
    container: 80
    default: 3300
    service: web
`

const otherCompose = "services:\n  web:\n    image: x\n    labels:\n      traefik.http.routers.other.rule: Host(`other.${PORTCULLIS_DOMAIN}`)\n  worker:\n    image: y\n"

type fixture struct {
	h       *Hub
	runner  *fakeRunner
	engine  *fakeEngine
	idp     *fakeIdP
	project string
	data    string
	src     string
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{
		runner:  newFakeRunner(),
		engine:  &fakeEngine{logs: map[string]string{}},
		idp:     &fakeIdP{},
		project: filepath.Join(root, "project"),
		data:    filepath.Join(root, "data"),
		src:     filepath.Join(root, "src"),
	}
	writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\nUNUSED=x\n")
	writeFile(t, filepath.Join(f.src, "grafana", "manifest.yaml"), grafanaManifest)
	writeFile(t, filepath.Join(f.src, "grafana", "compose.yml"), grafanaCompose)
	writeFile(t, filepath.Join(f.src, "grafana", "conf", "grafana.ini"), "[x]\n")
	writeFile(t, filepath.Join(f.src, "other", "manifest.yaml"), otherManifest)
	writeFile(t, filepath.Join(f.src, "other", "compose.yml"), otherCompose)

	st := state.New()
	st.Sources = []state.Source{{Name: "local", Path: f.src}}
	os.MkdirAll(f.data, 0755)
	if err := st.Save(filepath.Join(f.data, "state.yaml")); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{ProjectDir: f.project, ProjectHostDir: "/host/project", DataDir: f.data, Domain: "example.org"}, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	h.lockPoll = 5 * time.Millisecond
	h.Init()
	// Runs before t.TempDir's cleanup (LIFO): no background restart may
	// still be writing into the temp dirs.
	t.Cleanup(h.Wait)
	f.h = h
	return f
}

// ── fake volumes ─────────────────────────────────────────

// fakeFile is one entry of a fake volume ("" = the volume root).
type fakeFile struct {
	Name     string
	Dir      bool
	Mode     int64
	UID, GID int
	Body     string
}

type fakeVolume struct {
	docker.Volume
	files map[string]fakeFile
}

// volumeEngine adds volumes and never-started helper containers to
// fakeEngine (the archive endpoints as the daemon serves them).
type volumeEngine struct {
	vmu          sync.Mutex
	volumes      map[string]*fakeVolume
	helpers      map[string]docker.HelperSpec
	helperLog    []docker.HelperSpec
	removed      []string // helper ids removed
	volRemoved   []string
	images       []string
	nextID       int
	copyToErr    func(volume string) error
	copyFromErr  func(volume string) error
	removeVolErr func(name string) error
	imageErr     error
}

func (e *fakeEngine) vol() *volumeEngine {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ve == nil {
		e.ve = &volumeEngine{volumes: map[string]*fakeVolume{}, helpers: map[string]docker.HelperSpec{}}
	}
	return e.ve
}

// addVolume creates a volume of project with files (root owned by uid).
func (e *fakeEngine) addVolume(name, project, key string, uid int, files ...fakeFile) {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	fv := &fakeVolume{Volume: docker.Volume{Name: name, Driver: "local", Labels: map[string]string{}}, files: map[string]fakeFile{}}
	if project != "" {
		fv.Labels[docker.LabelProject] = project
		fv.Labels[docker.LabelVolume] = key
	}
	fv.files[""] = fakeFile{Dir: true, Mode: 0755, UID: uid, GID: uid}
	for _, f := range files {
		fv.files[f.Name] = f
	}
	v.volumes[name] = fv
}

func (e *fakeEngine) volumeFiles(name string) map[string]fakeFile {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	fv := v.volumes[name]
	if fv == nil {
		return nil
	}
	out := map[string]fakeFile{}
	for k, f := range fv.files {
		out[k] = f
	}
	return out
}

func (e *fakeEngine) volumeNames() []string {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	var out []string
	for n := range v.volumes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

var errNoSuchVolume = cerrdefs.ErrNotFound.WithMessage("no such volume")

func (e *fakeEngine) ListVolumes(ctx context.Context, f docker.Filters) ([]docker.Volume, error) {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	var out []docker.Volume
	for _, fv := range v.volumes {
		ok := true
		for _, l := range f["label"] {
			k, val, hasV := cut(l)
			got, present := fv.Labels[k]
			if !present || (hasV && got != val) {
				ok = false
			}
		}
		if ok {
			out = append(out, fv.Volume)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (e *fakeEngine) InspectVolume(ctx context.Context, name string) (docker.Volume, error) {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	if fv := v.volumes[name]; fv != nil {
		return fv.Volume, nil
	}
	return docker.Volume{}, errNoSuchVolume
}

func (e *fakeEngine) CreateVolume(ctx context.Context, vol docker.Volume) error {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	if v.volumes[vol.Name] != nil {
		return nil // Docker: creating an existing volume is a no-op
	}
	if vol.Labels == nil {
		vol.Labels = map[string]string{}
	}
	if vol.Driver == "" {
		vol.Driver = "local"
	}
	v.volumes[vol.Name] = &fakeVolume{Volume: vol, files: map[string]fakeFile{"": {Dir: true, Mode: 0755}}}
	return nil
}

func (e *fakeEngine) RemoveVolume(ctx context.Context, name string) error {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	if v.removeVolErr != nil {
		if err := v.removeVolErr(name); err != nil {
			return err
		}
	}
	if v.volumes[name] == nil {
		return errNoSuchVolume
	}
	for _, h := range v.helpers {
		if _, used := h.Volumes[name]; used {
			return errors.New("volume is in use")
		}
	}
	delete(v.volumes, name)
	v.volRemoved = append(v.volRemoved, name)
	return nil
}

func (e *fakeEngine) EnsureImage(ctx context.Context, ref string) error {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	v.images = append(v.images, ref)
	return v.imageErr
}

func (e *fakeEngine) CreateHelper(ctx context.Context, s docker.HelperSpec) (string, error) {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	for name := range s.Volumes {
		if v.volumes[name] == nil {
			// Docker would create it: the Hub must never rely on that.
			return "", fmt.Errorf("helper mounts missing volume %s", name)
		}
	}
	v.nextID++
	id := fmt.Sprintf("helper-%d", v.nextID)
	v.helpers[id] = s
	v.helperLog = append(v.helperLog, s)
	e.mu.Lock()
	e.containers = append(e.containers, docker.Container{ID: id, Names: []string{"/" + id}, State: "created", Labels: map[string]string{docker.LabelHelper: s.Instance}})
	e.mu.Unlock()
	return id, nil
}

func (e *fakeEngine) RemoveContainer(ctx context.Context, id string) error {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	delete(v.helpers, id)
	v.removed = append(v.removed, id)
	e.mu.Lock()
	var keep []docker.Container
	for _, c := range e.containers {
		if c.ID != id {
			keep = append(keep, c)
		}
	}
	e.containers = keep
	e.mu.Unlock()
	return nil
}

// mountAt returns the volume helper id mounts at target.
func (v *volumeEngine) mountAt(id, target string) (*fakeVolume, docker.HelperSpec, error) {
	h, ok := v.helpers[id]
	if !ok {
		return nil, h, errors.New("no such container")
	}
	for name, tg := range h.Volumes {
		if tg == target {
			return v.volumes[name], h, nil
		}
	}
	return nil, h, fmt.Errorf("nothing mounted at %s", target)
}

func (e *fakeEngine) CopyFromContainer(ctx context.Context, id, path string) (io.ReadCloser, error) {
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	fv, _, err := v.mountAt(id, path)
	if err != nil {
		return nil, err
	}
	if v.copyFromErr != nil {
		if err := v.copyFromErr(fv.Name); err != nil {
			return nil, err
		}
	}
	base := strings.TrimPrefix(path, "/")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(fv.files))
	for n := range fv.files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := fv.files[n]
		name := base
		if n != "" {
			name = base + "/" + n
		}
		hdr := &tar.Header{Name: name, Mode: f.Mode, Uid: f.UID, Gid: f.GID, ModTime: time.Unix(1700000000, 0)}
		if f.Dir {
			hdr.Typeflag, hdr.Name = tar.TypeDir, name+"/"
		} else {
			hdr.Typeflag, hdr.Size = tar.TypeReg, int64(len(f.Body))
		}
		tw.WriteHeader(hdr)
		tw.Write([]byte(f.Body))
	}
	tw.Close()
	return io.NopCloser(&buf), nil
}

func (e *fakeEngine) CopyToContainer(ctx context.Context, id, path string, content io.Reader) error {
	data, err := io.ReadAll(content)
	if err != nil {
		return err
	}
	v := e.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	h, ok := v.helpers[id]
	if !ok {
		return errors.New("no such container")
	}
	if path != "/" {
		return fmt.Errorf("fake: extract at %s", path)
	}
	if h.ReadOnly {
		return errors.New("container rootfs is marked read-only")
	}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.Trim(hdr.Name, "/")
		top, rest, _ := strings.Cut(name, "/")
		var fv *fakeVolume
		for vn, tg := range h.Volumes {
			if tg == "/"+top {
				fv = v.volumes[vn]
			}
		}
		if fv == nil {
			return fmt.Errorf("fake: %s is outside the mounted volumes", hdr.Name)
		}
		if v.copyToErr != nil {
			if err := v.copyToErr(fv.Name); err != nil {
				return err
			}
		}
		body, _ := io.ReadAll(tr)
		fv.files[rest] = fakeFile{Name: rest, Dir: hdr.Typeflag == tar.TypeDir, Mode: hdr.Mode, UID: hdr.Uid, GID: hdr.Gid, Body: string(body)}
	}
}

// fakeGroups records instance group operations.
type fakeGroups struct {
	mu       sync.Mutex
	calls    []string // "+name:actor" / "-name:actor"
	delErr   error
	actorErr error
	// createErr, if set, fails creating the named group.
	createErr func(name string) error
	// createWarn, if set, creates the group with a warning (purged
	// leftovers).
	createWarn func(name string) string
	// existing: groups LLDAP has (MissingInstanceGroups; created ones
	// are added); missingErr fails the check.
	existing   map[string]bool
	missingErr error
}

func (g *fakeGroups) MissingInstanceGroups(ctx context.Context, names []string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.missingErr != nil {
		return nil, g.missingErr
	}
	var out []string
	for _, n := range names {
		if !g.existing[n] {
			out = append(out, n)
		}
	}
	return out, nil
}

func (g *fakeGroups) ResolveActor(ctx context.Context, actor string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.actorErr
}

func (g *fakeGroups) CreateInstanceGroup(ctx context.Context, actor, name string) (bool, []string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.createErr != nil {
		if err := g.createErr(name); err != nil {
			return false, nil, err
		}
	}
	g.calls = append(g.calls, "+"+name+":"+actor)
	if g.existing == nil {
		g.existing = map[string]bool{}
	}
	g.existing[name] = true
	if g.createWarn != nil {
		if w := g.createWarn(name); w != "" {
			return true, []string{w}, nil
		}
	}
	return true, nil, nil
}

func (g *fakeGroups) DeleteInstanceGroup(ctx context.Context, actor, name string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.delErr != nil {
		return nil, g.delErr
	}
	g.calls = append(g.calls, "-"+name+":"+actor)
	return nil, nil
}

func (g *fakeGroups) Calls() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.calls...)
}
