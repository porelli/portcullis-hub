package hub

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
)

// fakeRunner records compose calls and checks that no two operations on the
// same project ever overlap.
type fakeRunner struct {
	mu        sync.Mutex
	calls     []string
	projects  []compose.Project
	active    map[string]int
	overlap   []string
	upErr     error
	downErr   error
	byNameErr error
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

func (f *fakeRunner) Up(ctx context.Context, p compose.Project) error {
	f.begin("up", p.Name, p)
	defer f.end(p.Name)
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
  - key: GF_THEME
    type: select
    options: [dark, light]
  - key: MEDIA
    type: path
    target: {service: grafana, mount: /media}
ports:
  - key: GRAFANA_PORT
    container: 3000
    default: 3300
    service: grafana
`

const grafanaCompose = "services:\n  grafana:\n    image: grafana\n    environment:\n      X: ${CORE_VAR}\n    labels:\n      traefik.http.routers.grafana.rule: Host(`grafana.${PORTCULLIS_DOMAIN:-x}`)\n      traefik.http.routers.grafana.entrypoints: websecure\n"

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
