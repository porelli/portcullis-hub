package httpapi

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/lldap/lldaptest"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/web"
)

// ── fake Docker engine (volumes + never-started helpers) ──

type fakeVol struct {
	docker.Volume
	files map[string]*tar.Header // "" = volume root
	body  map[string][]byte
}

// fakeEngine is the Engine API as far as instances, backups and restore
// use it: no containers but helpers, volumes with files, the archive
// endpoints.
type fakeEngine struct {
	mu      sync.Mutex
	vols    map[string]*fakeVol
	helpers map[string]docker.HelperSpec
	next    int
	// Shared-folder fixer runs (started helpers): every spec in fixerRuns;
	// fixerReports scripts a mode's answer (else a minimal report, exit 0).
	fixerRuns    []docker.RunSpec
	fixerReports map[string]fakeFixer
	// fixerGates: a mode's runs block until gate[0] closes, signalling
	// gate[1] (non-blocking) once each started (gateFixer).
	fixerGates map[string][2]chan struct{}
	secOpts    []string
}

// fakeFixer is one scripted fixer answer: exit code, the report line and,
// for snapshot, the snapshot file copied out of /out.
type fakeFixer struct {
	Exit     int
	Report   string
	Snapshot []byte
}

// fakeSelfImage is the image ID every inspected container runs.
var fakeSelfImage = "sha256:" + strings.Repeat("f", 64)

func (e *fakeEngine) InspectContainer(_ context.Context, id string) (docker.ContainerInfo, error) {
	return docker.ContainerInfo{ID: id, Image: fakeSelfImage}, nil
}

func (e *fakeEngine) DockerRootDir(context.Context) (string, error) { return "/var/lib/docker", nil }
func (e *fakeEngine) APIVersion(context.Context) (string, error)    { return "1.47", nil }

func (e *fakeEngine) SecurityOptions(context.Context) ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.secOpts, nil
}

// scriptFixer sets the answer of every later run of mode.
func (e *fakeEngine) scriptFixer(mode string, f fakeFixer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fixerReports == nil {
		e.fixerReports = map[string]fakeFixer{}
	}
	e.fixerReports[mode] = f
}

func (e *fakeEngine) RunHelper(_ context.Context, s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error) {
	if s.In != nil {
		io.Copy(io.Discard, s.In)
	}
	mode := ""
	if len(s.Cmd) > 2 {
		mode = s.Cmd[2]
	}
	e.mu.Lock()
	e.fixerRuns = append(e.fixerRuns, s)
	f, ok := e.fixerReports[mode]
	gate, gated := e.fixerGates[mode]
	e.mu.Unlock()
	if gated {
		select {
		case gate[1] <- struct{}{}:
		default:
		}
		<-gate[0]
	}
	if !ok {
		f = fakeFixer{Report: fmt.Sprintf(`{"version":1,"mode":%q}`, mode), Snapshot: []byte("fake-snapshot")}
	}
	if f.Exit == 0 && s.OutPath != "" && out != nil {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		tw.WriteHeader(&tar.Header{Name: "out/", Typeflag: tar.TypeDir, Mode: 0o755})
		tw.WriteHeader(&tar.Header{Name: "out/snapshot.ndjson.gz", Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(f.Snapshot))})
		tw.Write(f.Snapshot)
		tw.Close()
		if err := out(&b); err != nil {
			return &docker.RunResult{}, err
		}
	}
	return &docker.RunResult{ExitCode: f.Exit, Stdout: []byte(f.Report + "\n")}, nil
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{vols: map[string]*fakeVol{}, helpers: map[string]docker.HelperSpec{}}
}

func (e *fakeEngine) ContainerKill(context.Context, string, string) error { return nil }
func (e *fakeEngine) ExecStdin(context.Context, string, docker.ExecInput) (*docker.ExecResult, error) {
	return nil, cerrdefs.ErrNotFound.WithMessage("no such container")
}
func (e *fakeEngine) ExecStdinSplit(context.Context, string, docker.ExecInput) (*docker.ExecSplitResult, error) {
	return nil, cerrdefs.ErrNotFound.WithMessage("no such container")
}
func (e *fakeEngine) ExecRunning(context.Context, string) (bool, error) { return false, nil }
func (e *fakeEngine) ContainerState(context.Context, string) (docker.State, error) {
	return docker.State{}, cerrdefs.ErrNotFound.WithMessage("no such container")
}

var errNoVolume = cerrdefs.ErrNotFound.WithMessage("no such volume")

func (e *fakeEngine) addVolume(name, project, key string, files map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v := &fakeVol{Volume: docker.Volume{Name: name, Driver: "local", Labels: map[string]string{docker.LabelProject: project, docker.LabelVolume: key}},
		files: map[string]*tar.Header{"": {Typeflag: tar.TypeDir, Mode: 0755, Uid: 472, Gid: 472}}, body: map[string][]byte{}}
	for n, b := range files {
		v.files[n] = &tar.Header{Typeflag: tar.TypeReg, Mode: 0644, Uid: 472, Gid: 472, Size: int64(len(b))}
		v.body[n] = []byte(b)
	}
	e.vols[name] = v
}

func (e *fakeEngine) ListContainers(ctx context.Context, f docker.Filters) ([]docker.Container, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []docker.Container
	for id, h := range e.helpers {
		c := docker.Container{ID: id, Names: []string{"/" + id}, State: "created", Labels: map[string]string{docker.LabelHelper: h.Instance}}
		if matchLabels(c.Labels, f) {
			out = append(out, c)
		}
	}
	return out, nil
}

func matchLabels(have map[string]string, f docker.Filters) bool {
	for _, l := range f["label"] {
		k, v, hasV := strings.Cut(l, "=")
		got, ok := have[k]
		if !ok || (hasV && got != v) {
			return false
		}
	}
	return true
}

func (e *fakeEngine) Logs(context.Context, string, int, bool) ([]byte, error) {
	return []byte("fake log line\n"), nil
}
func (e *fakeEngine) Exec(context.Context, string, []string, time.Duration) (*docker.ExecResult, error) {
	return &docker.ExecResult{Output: []byte("ok\n")}, nil
}
func (e *fakeEngine) Events(ctx context.Context, _ docker.Filters, _ func(docker.Event)) error {
	<-ctx.Done()
	return ctx.Err()
}

func (e *fakeEngine) ListVolumes(ctx context.Context, f docker.Filters) ([]docker.Volume, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []docker.Volume{}
	for _, v := range e.vols {
		if matchLabels(v.Labels, f) {
			out = append(out, v.Volume)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (e *fakeEngine) InspectVolume(ctx context.Context, name string) (docker.Volume, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if v := e.vols[name]; v != nil {
		return v.Volume, nil
	}
	return docker.Volume{}, errNoVolume
}

func (e *fakeEngine) CreateVolume(ctx context.Context, vol docker.Volume) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.vols[vol.Name] == nil {
		if vol.Driver == "" {
			vol.Driver = "local"
		}
		e.vols[vol.Name] = &fakeVol{Volume: vol, files: map[string]*tar.Header{"": {Typeflag: tar.TypeDir, Mode: 0755}}, body: map[string][]byte{}}
	}
	return nil
}

func (e *fakeEngine) RemoveVolume(ctx context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.vols[name] == nil {
		return errNoVolume
	}
	delete(e.vols, name)
	return nil
}

func (e *fakeEngine) EnsureImage(context.Context, string) error { return nil }

func (e *fakeEngine) PullWithProgress(context.Context, string, func(int64, int64, bool)) error {
	return nil
}

func (e *fakeEngine) CreateHelper(ctx context.Context, s docker.HelperSpec) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for n := range s.Volumes {
		if e.vols[n] == nil {
			return "", fmt.Errorf("helper mounts missing volume %s", n)
		}
	}
	e.next++
	id := fmt.Sprintf("helper-%d", e.next)
	e.helpers[id] = s
	return id, nil
}

func (e *fakeEngine) RemoveContainer(ctx context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.helpers, id)
	return nil
}

func (e *fakeEngine) CopyFromContainer(ctx context.Context, id, path string) (io.ReadCloser, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h, ok := e.helpers[id]
	if !ok {
		return nil, errors.New("no such container")
	}
	var v *fakeVol
	for n, tg := range h.Volumes {
		if tg == path {
			v = e.vols[n]
		}
	}
	if v == nil {
		return nil, fmt.Errorf("nothing mounted at %s", path)
	}
	base := strings.TrimPrefix(path, "/")
	names := make([]string, 0, len(v.files))
	for n := range v.files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		hdr := *v.files[n]
		hdr.Name, hdr.ModTime = base, time.Unix(1700000000, 0)
		if n != "" {
			hdr.Name = base + "/" + n
		}
		if hdr.Typeflag == tar.TypeDir {
			hdr.Name += "/"
		}
		tw.WriteHeader(&hdr)
		tw.Write(v.body[n])
	}
	tw.Close()
	return io.NopCloser(&buf), nil
}

func (e *fakeEngine) CopyToContainer(ctx context.Context, id, path string, content io.Reader) error {
	data, err := io.ReadAll(content)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	h, ok := e.helpers[id]
	if !ok || path != "/" || h.ReadOnly {
		return errors.New("fake: bad upload")
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
		top, rest, _ := strings.Cut(strings.Trim(hdr.Name, "/"), "/")
		var v *fakeVol
		for n, tg := range h.Volumes {
			if tg == "/"+top {
				v = e.vols[n]
			}
		}
		if v == nil {
			return fmt.Errorf("fake: %s outside the mounts", hdr.Name)
		}
		b, _ := io.ReadAll(tr)
		hc := *hdr
		v.files[rest], v.body[rest] = &hc, b
	}
}

// ── fixture ──────────────────────────────────────────────

// Contract v2 multi templates: grafana (one host router), home
// (synapse-like: host "home" immutable).
const instGrafanaManifest = `name: Grafana
category: monitoring
icon: "📊"
description: Dashboards
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: header-auth
  group_access: true
  access_group: users_grafana
  admin_group: admin_grafana
urls:
  - label: Dashboards
    url: "https://{{HOST_GRAFANA}}"
`

const instGrafanaCompose = "services:\n  web:\n    image: grafana\n    volumes:\n      - grafana-data:/var/lib/grafana\n    labels:\n" +
	"      traefik.http.routers.grafana.rule: Host(`${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}`)\n" +
	"volumes:\n  grafana-data: {}\n"

const instHomeManifest = `name: Home
category: chat
icon: "💬"
description: Synapse-like homeserver (its server name is fixed)
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_home
hosts:
  immutable: [home]
`

const instHomeCompose = "services:\n  web:\n    image: x\n    labels:\n" +
	"      traefik.http.routers.home.rule: Host(`${PORTCULLIS_HOST_HOME:-matrix.portcullis.local}`)\n" +
	"      traefik.http.routers.media.rule: Host(`${PORTCULLIS_HOST_MEDIA:-media.portcullis.local}`)\n"

type instEnv struct {
	s        *Server
	hub, ppl *httptest.Server
	engine   *fakeEngine
	ll       *lldaptest.Server
	audit    string
}

// readyDomains is a fixed DomainSource.
type readyDomains []hub.Domain

func (d readyDomains) Domains() []hub.Domain { return d }

func newInstEnv(t *testing.T) *instEnv {
	return newInstEnvAt(t, t.TempDir())
}

func newInstEnvAt(t *testing.T, root string) *instEnv {
	t.Helper()
	return newInstEnvWith(t, root, nil, nil)
}

// newInstEnvWith is newInstEnvAt with extra templates (id → manifest,
// compose) in the source, and engine wrapping the fake engine (nil: the
// fake engine itself).
func newInstEnvWith(t *testing.T, root string, extra map[string][2]string, engine func(*fakeEngine) hub.Engine) *instEnv {
	t.Helper()
	return newInstEnvOpts(t, root, instEnvOpts{extra: extra, engine: engine})
}

// instEnvOpts: extra templates and the engine wrapper (newInstEnvWith),
// cfg changes the Hub's Config, seed the state before the Hub loads it.
type instEnvOpts struct {
	extra  map[string][2]string
	engine func(*fakeEngine) hub.Engine
	cfg    func(*hub.Config)
	seed   func(*state.AppState)
	runner compose.Runner // nil: nopRunner
	// data writes files into the data directory before the Hub loads it.
	data func(dir string)
}

func newInstEnvOpts(t *testing.T, root string, o instEnvOpts) *instEnv {
	t.Helper()
	extra, engine := o.extra, o.engine
	src := filepath.Join(root, "src")
	tmpls := map[string][2]string{"grafana": {instGrafanaManifest, instGrafanaCompose}, "home": {instHomeManifest, instHomeCompose}}
	for id, files := range extra {
		tmpls[id] = files
	}
	for id, files := range tmpls {
		os.MkdirAll(filepath.Join(src, id), 0755)
		os.WriteFile(filepath.Join(src, id, "manifest.yaml"), []byte(files[0]), 0644)
		os.WriteFile(filepath.Join(src, id, "compose.yml"), []byte(files[1]), 0644)
	}
	data := filepath.Join(root, "data")
	os.MkdirAll(data, 0755)
	st := state.New()
	st.Sources = []state.Source{{Name: "local", Path: src}}
	if o.seed != nil {
		o.seed(st)
	}
	if o.data != nil {
		o.data(data)
	}
	st.Save(filepath.Join(data, "state.yaml"))
	eng := newFakeEngine()
	var he hub.Engine = eng
	if engine != nil {
		he = engine(eng)
	}
	cfg := hub.Config{ProjectDir: filepath.Join(root, "project"), ProjectHostDir: "/host/project", DataDir: data, Domain: "example.org", ClientCertTTL: 720 * time.Hour}
	if o.cfg != nil {
		o.cfg(&cfg)
	}
	var runner compose.Runner = nopRunner{}
	if o.runner != nil {
		runner = o.runner
	}
	h, err := hub.New(cfg, runner, he, nil)
	if err != nil {
		t.Fatal(err)
	}
	// No test resolves a real name (the doctor looks up the main domain).
	h.SetLookupIP(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	})
	h.Init()
	t.Cleanup(h.Wait)
	h.SetDomainSource(readyDomains{{Name: "team-b.example.net", State: hub.DomainReady}, {Name: "pending.example.net", State: "pending"}})

	ll := lldaptest.New(t, "portcullis-hub", "svc-password-0123456789")
	ll.AddUser("root", "root@example.org", "Root", "root-password-1", "lldap_admin")
	ll.AddUser("dana", "dana@example.org", "Dana", "")
	ll.AddGroup("helpers", "dana")
	cred := filepath.Join(root, "lldap")
	os.MkdirAll(cred, 0700)
	os.WriteFile(filepath.Join(cred, "username"), []byte("portcullis-hub"), 0600)
	os.WriteFile(filepath.Join(cred, "password"), []byte("svc-password-0123456789"), 0600)
	kc := kctest.New(t)
	kc.Importable = ll.HasUser
	kc.LDAPUUID = ll.UUIDOf
	secret := filepath.Join(root, "invite-secret")
	os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0600)
	dir := &directory.Service{
		LLDAP:   lldap.New(ll.HTTP.URL, ll.LDAPURL(), ll.BaseDN, cred),
		KC:      keycloak.New(kc.HTTP.URL, "admin", "admin"),
		Invites: invite.New("http://127.0.0.1:1", secret),
		Audit:   &directory.AuditLog{Path: filepath.Join(data, "audit.jsonl")},
		Apps:    h.DirectoryApps,
		Store:   &directory.Store{Path: filepath.Join(data, "directory.yaml")},
	}
	h.SetAudit(dir.Audit)
	h.SetGroups(dir)
	s := &Server{Hub: h, Secret: testSecret, Web: web.FS, Directory: dir, Audit: dir.Audit}
	hh, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ph, err := s.PeopleHandler()
	if err != nil {
		t.Fatal(err)
	}
	e := &instEnv{s: s, hub: httptest.NewServer(hh), ppl: httptest.NewServer(ph), engine: eng, ll: ll, audit: dir.Audit.Path}
	t.Cleanup(e.hub.Close)
	t.Cleanup(e.ppl.Close)
	return e
}

func (e *instEnv) do(t *testing.T, user, method, path, body string) (int, string) {
	t.Helper()
	r, b := doAs(t, e.hub, user, method, path, body)
	return r.StatusCode, b
}

func (e *instEnv) auditActions(t *testing.T, prefix string) []string {
	t.Helper()
	var out []string
	for _, a := range readAudit(t, e.audit) {
		if strings.HasPrefix(a.Action, prefix) {
			out = append(out, a.Action+":"+a.Result+":"+a.Actor+":"+a.Target)
		}
	}
	return out
}

// ── tests ────────────────────────────────────────────────

func TestInstanceRoutesAdminOnly(t *testing.T) {
	e := newInstEnv(t)
	// dana is a delegate (may invite), not an admin.
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/invite", `{"group":"helpers"}`, 200)
	routes := []struct{ method, path, body string }{
		{"GET", "/api/instances", ""},
		{"POST", "/api/instances", `{"template":"grafana","id":"grafana-x","label":"Test"}`},
		{"GET", "/api/instances/defaults?template=grafana&id=grafana-x", ""},
		{"PUT", "/api/instances/grafana/hosts", `{"hosts":{"grafana":"g2.example.org"}}`},
		{"PUT", "/api/instances/grafana/label", `{"label":"Home"}`},
		{"DELETE", "/api/instances/grafana", `{"confirm":"grafana"}`},
		{"GET", "/api/backups", ""},
		{"GET", "/api/instances/grafana/backups", ""},
		{"POST", "/api/instances/grafana/backups", ""},
		{"POST", "/api/instances/grafana/restore", `{"archive":"grafana/20261102T153000Z.tar"}`},
		{"POST", "/api/instances/restore", `{"archive":"grafana/20261102T153000Z.tar","id":"grafana-c"}`},
		{"GET", "/api/instances/grafana/op", ""},
		{"POST", "/api/instances/grafana/op/stop", "{}"},
	}
	for _, user := range []string{"dana", "nobody", ""} {
		for _, r := range routes {
			if code, b := e.do(t, user, r.method, r.path, r.body); code != 403 {
				t.Errorf("%q %s %s = %d %s, want 403", user, r.method, r.path, code, b)
			}
		}
	}
	// Never on the people listener.
	for _, r := range routes {
		if resp, _ := doAs(t, e.ppl, "root", r.method, r.path, r.body); resp.StatusCode != 404 && resp.StatusCode != 405 {
			t.Errorf("people %s %s = %d, want 404", r.method, r.path, resp.StatusCode)
		}
	}
	if got := e.s.Hub.Instances(); len(got) != 0 {
		t.Fatalf("a refused request created something: %+v", got)
	}
	if a := e.auditActions(t, "instance."); len(a) != 0 {
		t.Fatalf("refused requests reached the Hub: %v", a)
	}
	// CSRF: a form post is refused before the handler.
	req, _ := http.NewRequest("POST", e.hub.URL+"/api/instances", strings.NewReader(`template=grafana&id=grafana-x`))
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("form post = %d", resp.StatusCode)
	}
}

func TestCreateInstanceRoute(t *testing.T) {
	e := newInstEnv(t)
	// Defaults: pre-filled hostnames per domain, the domain picker's list.
	code, b := e.do(t, "root", "GET", "/api/instances/defaults?template=home&id=home-team-a&domain=team-b.example.net", "")
	var d struct {
		Hosts   map[string]string `json:"hosts"`
		Routers []hub.HostRouter  `json:"routers"`
		Domains []hub.InstanceDomain
		Multi   bool
	}
	json.Unmarshal([]byte(b), &d)
	if code != 200 || d.Hosts["home"] != "matrix-team-a.team-b.example.net" || d.Hosts["media"] != "media-team-a.team-b.example.net" || !d.Multi {
		t.Fatalf("defaults = %d %s", code, b)
	}
	if len(d.Routers) != 2 || d.Routers[0].Router != "home" || !d.Routers[0].Immutable || d.Routers[1].Immutable {
		t.Errorf("routers = %+v", d.Routers)
	}
	if len(d.Domains) != 3 || !d.Domains[0].Main || d.Domains[0].Name != "example.org" ||
		d.Domains[1].Name != "pending.example.net" || d.Domains[1].Assignable || !d.Domains[2].Assignable {
		t.Errorf("domains = %+v", d.Domains)
	}
	if code, _ := e.do(t, "root", "GET", "/api/instances/defaults?template=home&id=home-a&domain=other.example", ""); code != 400 {
		t.Errorf("unknown domain = %d", code)
	}

	// Create with explicit hosts on the enrolled domain.
	// In the background (202, op create, §11.7): the result names it.
	rec := e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-team-a","label":"Test","hosts":{"grafana":"grafana.team-b.example.net"}}`)
	if !rec.OK || rec.Op != "create" || rec.Result["instance"] != "grafana-team-a" {
		t.Fatalf("create = %+v", rec)
	}
	v, _ := e.s.Hub.InstanceView("grafana-team-a")
	if v.ID != "grafana-team-a" || v.State != "created" || v.Hosts["grafana"] != "grafana.team-b.example.net" || v.AccessGroup != "users_grafana-team-a" {
		t.Errorf("created = %+v", v)
	}
	// Its groups exist in LLDAP (created as root, through the guardrails).
	for _, g := range []string{"users_grafana-team-a", "admin_grafana-team-a"} {
		if !e.ll.HasGroup(g) {
			t.Errorf("group %s not created", g)
		}
	}
	// Hosts omitted = the defaults on the main domain.
	e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-lab","label":"Test"}`)
	if v, _ := e.s.Hub.InstanceView("grafana-lab"); v.Hosts["grafana"] != "grafana-lab.example.org" {
		t.Fatalf("default hosts = %+v", v)
	}
	// Refusals: bad id, duplicate, deeper name, not-ready domain, unknown field.
	for _, c := range []struct {
		body string
		code int
		msg  string
	}{
		{`{"template":"grafana","id":"Bad_ID"}`, 400, "must match"},
		{`{"template":"grafana","id":"grafana-lab","label":"L"}`, 409, "instance grafana-lab already exists\n"},
		{`{"template":"grafana","id":"grafana-x","label":"X","hosts":{"grafana":"a.b.example.org"}}`, 400, "deeper names need an added domain"},
		{`{"template":"grafana","id":"grafana-x","label":"X","hosts":{"grafana":"a.b.team-b.example.net"}}`, 400, "covers one label"},
		{`{"template":"grafana","id":"grafana-x","label":"X","hosts":{"grafana":"g.pending.example.net"}}`, 409, "not assignable"},
		{`{"template":"grafana","id":"grafana-x","extra":1}`, 400, "body must be"},
		{`{"template":"grafana","id":"grafana-x"}`, 400, "a label is required"},
		{`{"template":"grafana","id":"grafana-x","label":"x\u200b"}`, 400, "visible text"},
		{`{"template":"grafana","id":"grafana-x","label":"X","groups":{}}`, 400, "mode must be"},
		{`{"template":"grafana","id":"grafana-x","label":"X","groups":{"mode":"existing","users":"lldap_admin","admins":"lldap_admin"}}`, 400, "the users group can't be a built-in or administrator group"},
		{`{"template":"grafana","id":"grafana-x","label":"X","groups":{"mode":"existing","users":"nope","admins":"lldap_admin"}}`, 400, "unknown group nope"},
	} {
		if code, b := e.do(t, "root", "POST", "/api/instances", c.body); code != c.code || !strings.Contains(b, c.msg) || (strings.HasSuffix(c.msg, "\n") && b != c.msg) {
			t.Errorf("%s = %d %s, want %d %q", c.body, code, b, c.code, c.msg)
		}
	}
	// List.
	code, b = e.do(t, "root", "GET", "/api/instances", "")
	var list []hub.InstanceView
	json.Unmarshal([]byte(b), &list)
	if code != 200 || len(list) != 2 || list[0].ID != "grafana-lab" || list[1].ID != "grafana-team-a" {
		t.Fatalf("list = %d %s", code, b)
	}
	got := strings.Join(e.auditActions(t, "instance.create"), ",")
	if !strings.HasPrefix(got, "instance.create:ok:root:grafana-team-a,instance.create:ok:root:grafana-lab,instance.create:refused:root:Bad_ID") {
		t.Errorf("audit = %s", got)
	}
}

func TestUpdateHostsRoute(t *testing.T) {
	e := newInstEnv(t)
	e.runOp(t, "POST", "/api/instances", `{"template":"home","id":"home-b","label":"Test","hosts":{"home":"matrix-b.example.org","media":"media-b.example.org"}}`)
	// A mutable host moves; the answer is the instance.
	code, b := e.do(t, "root", "PUT", "/api/instances/home-b/hosts", `{"hosts":{"home":"matrix-b.example.org","media":"media.team-b.example.net"}}`)
	if code != 200 || !strings.Contains(b, `"media":"media.team-b.example.net"`) {
		t.Fatalf("update = %d %s", code, b)
	}
	// The immutable one can't.
	code, b = e.do(t, "root", "PUT", "/api/instances/home-b/hosts", `{"hosts":{"home":"chat-b.example.org","media":"media.team-b.example.net"}}`)
	if code != 409 || !strings.Contains(b, "can't change") {
		t.Fatalf("immutable = %d %s", code, b)
	}
	if code, _ := e.do(t, "root", "PUT", "/api/instances/nope/hosts", `{"hosts":{"home":"x.example.org"}}`); code != 404 {
		t.Errorf("unknown = %d", code)
	}
	// The default instance (never enabled, not listed before): the answer
	// is its view, never a zero value.
	code, b = e.do(t, "root", "PUT", "/api/instances/grafana/hosts", `{"hosts":{"grafana":"dash.example.org"}}`)
	var v hub.InstanceView
	json.Unmarshal([]byte(b), &v)
	if code != 200 || v.ID != "grafana" || !v.Default || v.Template != "grafana" || v.Hosts["grafana"] != "dash.example.org" || v.Project != "portcullis-grafana" {
		t.Fatalf("default instance = %d %s", code, b)
	}
	got := strings.Join(e.auditActions(t, "instance.update"), ",")
	if got != "instance.update:ok:root:home-b,instance.update:refused:root:home-b,instance.update:refused:root:nope,instance.update:ok:root:grafana" {
		t.Errorf("audit = %s", got)
	}
}

func TestDeleteNeedsTypedID(t *testing.T) {
	e := newInstEnv(t)
	e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-team-a","label":"Test"}`)
	e.engine.addVolume("portcullis_grafana-team-a-grafana-data", "portcullis-grafana-team-a", "grafana-data", map[string]string{"grafana.db": "rows"})
	for _, body := range []string{`{}`, `{"confirm":""}`, `{"confirm":"grafana"}`, `{"confirm":"GRAFANA-TEAM-A"}`, `{"confirm":" grafana-team-a "}`, `{"confirm":"grafana-team-a\n"}`} {
		if code, b := e.do(t, "root", "DELETE", "/api/instances/grafana-team-a", body); code != 400 || !strings.Contains(b, "type the instance id") {
			t.Errorf("%s = %d %s, want 400", body, code, b)
		}
	}
	if code, _ := e.do(t, "root", "DELETE", "/api/instances/grafana-team-a", ``); code != 400 {
		t.Errorf("no body = %d", code)
	}
	// Nothing happened: no backup, the instance and its volume are there.
	if list, _ := e.s.Hub.ListBackups(""); len(list) != 0 {
		t.Fatalf("a refused delete took a backup: %v", list)
	}
	if _, ok := e.s.Hub.InstanceView("grafana-team-a"); !ok {
		t.Fatal("instance gone")
	}
	// Typed: backup first, then everything goes; warnings reported.
	// Accepted (202), runs in the background; the op record has the outcome.
	rec := e.runOp(t, "DELETE", "/api/instances/grafana-team-a", `{"confirm":"grafana-team-a"}`)
	if !rec.OK || rec.Op != "delete" || !strings.HasPrefix(rec.Result["backup"], "grafana-team-a/") {
		t.Fatalf("delete op = %+v", rec)
	}
	if !strings.Contains(strings.Join(rec.Warnings, "\n"), "IdP") && !strings.Contains(strings.Join(rec.Warnings, "\n"), "Keycloak") {
		t.Errorf("warnings = %v", rec.Warnings)
	}
	if _, ok := e.s.Hub.InstanceView("grafana-team-a"); ok {
		t.Error("instance still listed")
	}
	if _, err := e.engine.InspectVolume(context.Background(), "portcullis_grafana-team-a-grafana-data"); err == nil {
		t.Error("volume kept")
	}
	if e.ll.HasGroup("users_grafana-team-a") {
		t.Error("group kept")
	}
	// The backup stays listed (instance gone).
	code, b := e.do(t, "root", "GET", "/api/backups", "")
	if code != 200 || !strings.Contains(b, `"instance_exists":false`) || !strings.Contains(b, `"reason":"delete"`) {
		t.Fatalf("backups = %d %s", code, b)
	}
	got := strings.Join(e.auditActions(t, "instance.delete"), ",")
	if !strings.HasPrefix(got, "instance.delete:refused:root:grafana-team-a") || !strings.HasSuffix(got, "instance.delete:ok:root:grafana-team-a") {
		t.Errorf("audit = %s", got)
	}
}

func TestBackupRestoreRoutes(t *testing.T) {
	e := newInstEnv(t)
	e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-team-a","label":"Test"}`)
	vol := "portcullis_grafana-team-a-grafana-data"
	e.engine.addVolume(vol, "portcullis-grafana-team-a", "grafana-data", map[string]string{"grafana.db": "v1"})
	rec := e.runOp(t, "POST", "/api/instances/grafana-team-a/backups", "")
	list, _ := e.s.Hub.ListBackups("grafana-team-a")
	var entry hub.BackupEntry
	for _, x := range list {
		if x.Archive == rec.Result["archive"] {
			entry = x
		}
	}
	if !rec.OK || rec.Op != "backup" || entry.Reason != "manual" || entry.Instance != "grafana-team-a" || !entry.InstanceExists {
		t.Fatalf("backup = %+v %+v", rec, list)
	}
	// Listed, per instance and overall.
	for _, p := range []string{"/api/backups", "/api/instances/grafana-team-a/backups"} {
		if code, b := e.do(t, "root", "GET", p, ""); code != 200 || !strings.Contains(b, entry.Archive) {
			t.Errorf("%s = %d %s", p, code, b)
		}
	}
	if code, b := e.do(t, "root", "GET", "/api/instances/grafana-lab/backups", ""); code != 200 || b != "[]\n" {
		t.Errorf("none = %d %q", code, b)
	}
	// Same instance: the data comes back, a pre-restore backup is taken.
	e.engine.mu.Lock()
	e.engine.vols[vol].body["grafana.db"] = []byte("v2")
	e.engine.mu.Unlock()
	time.Sleep(1100 * time.Millisecond) // archives are named by the second
	rec = e.runOp(t, "POST", "/api/instances/grafana-team-a/restore", `{"archive":"`+entry.Archive+`"}`)
	if !rec.OK || rec.Op != "restore" || !strings.HasPrefix(rec.Result["pre_restore_backup"], "grafana-team-a/") {
		t.Fatalf("restore = %+v", rec)
	}
	e.engine.mu.Lock()
	if got := string(e.engine.vols[vol].body["grafana.db"]); got != "v1" {
		t.Errorf("restored data = %q", got)
	}
	e.engine.mu.Unlock()
	// Bad archive names: 400; another instance's archive: 400; missing: 404.
	for _, c := range []struct {
		path, body string
		code       int
		msg        string
	}{
		{"/api/instances/grafana-team-a/restore", `{"archive":"../x.tar"}`, 400, ""},
		{"/api/instances/grafana-team-a/restore", `{"archive":"grafana-lab/20261102T153000Z.tar"}`, 400, ""},
		{"/api/instances/grafana-team-a/restore", `{"archive":"grafana-team-a/20201102T153000Z.tar"}`, 404, ""},
		{"/api/instances/restore", `{"archive":"grafana-team-a/20201102T153000Z.tar","id":"grafana-c"}`, 404, ""},
		{"/api/instances/restore", `{"archive":"` + entry.Archive + `","id":"grafana-team-a"}`, 409, "instance grafana-team-a already exists\n"},
	} {
		if code, b := e.do(t, "root", "POST", c.path, c.body); code != c.code || (c.msg != "" && b != c.msg) {
			t.Errorf("%s %s = %d %s, want %d", c.path, c.body, code, b, c.code)
		}
	}
	// Into a new id: created, default hosts, data copied, groups made.
	rec = e.runOp(t, "POST", "/api/instances/restore", `{"archive":"`+entry.Archive+`","id":"grafana-team-c"}`)
	if !rec.OK || rec.Result["instance"] != "grafana-team-c" {
		t.Fatalf("restore as = %+v", rec)
	}
	v, ok := e.s.Hub.InstanceView("grafana-team-c")
	if !ok || v.State != "created" || v.Hosts["grafana"] != "grafana-team-c.example.org" {
		t.Fatalf("new instance = %+v", v)
	}
	e.engine.mu.Lock()
	if nv := e.engine.vols["portcullis_grafana-team-c-grafana-data"]; nv == nil || string(nv.body["grafana.db"]) != "v1" {
		t.Errorf("new volume = %+v", nv)
	}
	e.engine.mu.Unlock()
	if !e.ll.HasGroup("users_grafana-team-c") {
		t.Error("group not created")
	}
	got := e.auditActions(t, "instance.")
	want := []string{"instance.create:ok:root:grafana-team-a", "instance.backup:ok:root:grafana-team-a", "instance.restore:ok:root:grafana-team-a"}
	if len(got) < 3 || strings.Join(got[:3], ",") != strings.Join(want, ",") || got[len(got)-1] != "instance.restore:ok:root:grafana-team-c" {
		t.Errorf("audit = %v", got)
	}
}

// runOp sends a long-operation request, expects 202 with an op id, and
// polls the instance's op record until that operation finished.
func (e *instEnv) runOp(t *testing.T, method, path, body string) hub.OpRecord {
	t.Helper()
	code, b := e.do(t, "root", method, path, body)
	var acc struct{ OpID, Op, Instance, Poll string }
	json.Unmarshal([]byte(b), &struct {
		OpID     *string `json:"op_id"`
		Op       *string `json:"op"`
		Instance *string `json:"instance"`
		Poll     *string `json:"poll"`
	}{&acc.OpID, &acc.Op, &acc.Instance, &acc.Poll})
	if code != 202 || acc.OpID == "" || acc.Poll != "/api/instances/"+acc.Instance+"/op?op_id="+acc.OpID {
		t.Fatalf("%s %s = %d %s, want 202 + op id", method, path, code, b)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		code, b := e.do(t, "root", "GET", acc.Poll, "")
		var rec hub.OpRecord
		if code == 200 && json.Unmarshal([]byte(b), &rec) == nil && rec.OpID == acc.OpID && !rec.Running {
			return rec
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s %s: op %s did not finish", method, path, acc.OpID)
	return hub.OpRecord{}
}

// TestInstanceLabelRoute (apps, §11.9): PUT /api/instances/{id}/label
// answers the instance; a create bound to existing groups uses them.
func TestInstanceLabelRoute(t *testing.T) {
	e := newInstEnv(t)
	e.ll.AddGroup("team", "alice")
	rec := e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-t","label":"Team","groups":{"mode":"existing","users":"team","admins":"lldap_admin"}}`)
	if !rec.OK {
		t.Fatalf("create = %+v", rec)
	}
	if e.ll.HasGroup("users_grafana-t") || e.ll.HasGroup("admin_grafana-t") {
		t.Error("a bound create created groups")
	}
	code, b := e.do(t, "root", "PUT", "/api/instances/grafana-t/label", `{"label":"Team B"}`)
	var v hub.InstanceView
	if code != 200 || json.Unmarshal([]byte(b), &v) != nil || v.Label != "Team B" || v.Name != "Grafana · Team B" ||
		v.GroupsMode != "existing" || v.AccessGroup != "team" || v.AdminGroup != "lldap_admin" {
		t.Fatalf("label = %d %s", code, b)
	}
	for _, c := range []struct {
		path, body string
		code       int
	}{
		{"/api/instances/grafana-t/label", `{"label":""}`, 400},
		{"/api/instances/grafana-t/label", `{"label":"x","more":1}`, 400},
		{"/api/instances/nope-x/label", `{"label":"X"}`, 404},
	} {
		if code, b := e.do(t, "root", "PUT", c.path, c.body); code != c.code {
			t.Errorf("%s %s = %d %s, want %d", c.path, c.body, code, b, c.code)
		}
	}
}
