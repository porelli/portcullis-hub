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
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/policy"
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
	// A Stop kills a running compose: cancelled, it does nothing.
	if err := ctx.Err(); err != nil {
		return err
	}
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
	if err := ctx.Err(); err != nil {
		return err
	}
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
	// kills: "<container>:<signal>" per ContainerKill; killHook runs in
	// it; states overrides a container's ContainerState (default: its
	// listed state, no healthcheck).
	kills    []string
	killHook func(id, signal string)
	states   map[string]docker.State
	// ExecStdin (hooks): every call, in order; execStdin (if set) answers
	// it (called without mu: it may block); execRunning: ExecRunning's
	// answer per exec id; execInflight / execMaxInflight: overlap.
	execCalls       []execCall
	execStdin       func(id string, in docker.ExecInput) (*docker.ExecResult, error)
	execRunning     map[string]bool
	execInspects    int
	execInflight    int
	execMaxInflight int
	// fixer: started helper runs (fixer_test.go).
	fixer *fixerFake
	// execFn, if set, answers Exec (under mu: it must not call the engine).
	execFn func(id string, cmd []string) (*docker.ExecResult, error)
	// apiVersion: APIVersion's answer ("" = 1.47).
	apiVersion string
	// ExecStdinSplit (AI hooks, G6): every call in splitCalls; execSplit
	// (if set, called without mu) answers it, else exit 0, no output.
	splitCalls []execCall
	execSplit  func(id string, in docker.ExecInput) (*docker.ExecSplitResult, error)
	// PullWithProgress (startUp's images step): every ref in pulls;
	// pullFn (if set, called without mu) serves the pull stream through
	// onBytes, else the image is already present. stateHook (if set,
	// called without mu) changes what ContainerState answers.
	pulls     []string
	pullFn    func(ctx context.Context, ref string, onBytes func(done, total int64, sized bool)) error
	stateHook func(id string, st docker.State) docker.State
}

func (e *fakeEngine) PullWithProgress(ctx context.Context, ref string, onBytes func(done, total int64, sized bool)) error {
	e.mu.Lock()
	e.pulls = append(e.pulls, ref)
	fn := e.pullFn
	e.mu.Unlock()
	if fn != nil {
		return fn(ctx, ref, onBytes)
	}
	return nil
}

func (e *fakeEngine) Pulls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.pulls...)
}

func (e *fakeEngine) ExecStdinSplit(ctx context.Context, id string, in docker.ExecInput) (*docker.ExecSplitResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.splitCalls = append(e.splitCalls, execCall{container: id, in: in})
	fn := e.execSplit
	e.mu.Unlock()
	if fn != nil {
		return fn(id, in)
	}
	return &docker.ExecSplitResult{ExecID: "x"}, nil
}

func (e *fakeEngine) SplitCalls() []execCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]execCall(nil), e.splitCalls...)
}

func (e *fakeEngine) setExecSplit(fn func(id string, in docker.ExecInput) (*docker.ExecSplitResult, error)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.execSplit = fn
}

type execCall struct {
	container string
	in        docker.ExecInput
}

func (e *fakeEngine) ExecStdin(ctx context.Context, id string, in docker.ExecInput) (*docker.ExecResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err // like the SDK: a cancelled context fails the exec
	}
	e.mu.Lock()
	e.execCalls = append(e.execCalls, execCall{container: id, in: in})
	fn := e.execStdin
	e.execInflight++
	if e.execInflight > e.execMaxInflight {
		e.execMaxInflight = e.execInflight
	}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.execInflight--
		e.mu.Unlock()
	}()
	if fn != nil {
		return fn(id, in)
	}
	return &docker.ExecResult{Output: []byte("applied\n"), ExecID: "x"}, nil
}

func (e *fakeEngine) ExecRunning(ctx context.Context, execID string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.execInspects++
	return e.execRunning[execID], nil
}

func (e *fakeEngine) setExec(fn func(id string, in docker.ExecInput) (*docker.ExecResult, error)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.execStdin = fn
}

func (e *fakeEngine) setExecRunning(execID string, running bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.execRunning == nil {
		e.execRunning = map[string]bool{}
	}
	e.execRunning[execID] = running
}

func (e *fakeEngine) ExecCalls() []execCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]execCall(nil), e.execCalls...)
}

func (e *fakeEngine) ContainerKill(ctx context.Context, id, signal string) error {
	e.mu.Lock()
	e.kills = append(e.kills, id+":"+signal)
	hook := e.killHook
	e.mu.Unlock()
	if hook != nil {
		hook(id, signal)
	}
	return nil
}

func (e *fakeEngine) ContainerState(ctx context.Context, id string) (docker.State, error) {
	st, err := e.containerState(id)
	e.mu.Lock()
	hook := e.stateHook
	e.mu.Unlock()
	if err == nil && hook != nil {
		st = hook(id, st)
	}
	return st, err
}

func (e *fakeEngine) containerState(id string) (docker.State, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if st, ok := e.states[id]; ok {
		return st, nil
	}
	for _, c := range e.containers {
		if c.ID == id {
			return docker.State{Running: c.State == "running", Status: c.State}, nil
		}
	}
	return docker.State{}, errors.New("no such container")
}

func (e *fakeEngine) Kills() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.kills...)
}

func (e *fakeEngine) setState(id string, st docker.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.states == nil {
		e.states = map[string]docker.State{}
	}
	e.states[id] = st
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
	if fn := e.execFn; fn != nil {
		return fn(id, cmd)
	}
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
	// Setting claims (EnsureSettingClaims / RemoveSettingClaims): the
	// current claim set per client, the removals ("<client>:<owner>:<attr,…>"),
	// claimOwners (client → owner tag; unset = the owner asked for) and
	// claimErr (both fail with it).
	claims      map[string][]keycloak.SettingClaim
	claimRemove []string
	claimOwners map[string]string
	claimErr    error
	// claimGate, if set, blocks every EnsureSettingClaims until closed.
	claimGate chan struct{}
	// claimAll: every EnsureSettingClaims call ("<client>:<n claims>");
	// claimFail: per client, EnsureSettingClaims fails with it.
	claimAll  []string
	claimFail map[string]error
	// clients: the clients Keycloak has (RegisterClient adds, DeleteClient
	// removes); RegisterClient reports created for one not listed.
	clients map[string]bool
}

func (f *fakeIdP) claimAllCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.claimAll...)
}

func (f *fakeIdP) EnsureSettingClaims(ctx context.Context, clientID, owner string, claims []keycloak.SettingClaim) error {
	f.mu.Lock()
	gate := f.claimGate
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimAll = append(f.claimAll, fmt.Sprintf("%s:%d", clientID, len(claims)))
	if err := f.claimFail[clientID]; err != nil {
		return err
	}
	if f.claimErr != nil {
		return f.claimErr
	}
	if o, ok := f.claimOwners[clientID]; ok && o != owner {
		return &keycloak.ConflictError{ClientID: clientID, TemplateID: owner, Owner: o}
	}
	if f.claims == nil {
		f.claims = map[string][]keycloak.SettingClaim{}
	}
	f.claims[clientID] = append([]keycloak.SettingClaim(nil), claims...)
	return nil
}

func (f *fakeIdP) RemoveSettingClaims(ctx context.Context, clientID, owner string, attrs []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimErr != nil {
		return f.claimErr
	}
	f.claimRemove = append(f.claimRemove, clientID+":"+owner+":"+strings.Join(attrs, ","))
	if o, ok := f.claimOwners[clientID]; ok && o != owner {
		return &keycloak.ConflictError{ClientID: clientID, TemplateID: owner, Owner: o}
	}
	drop := map[string]bool{}
	for _, a := range attrs {
		drop[a] = true
	}
	var kept []keycloak.SettingClaim
	for _, c := range f.claims[clientID] {
		if !drop[c.Attr] {
			kept = append(kept, c)
		}
	}
	if f.claims != nil {
		f.claims[clientID] = kept
	}
	return nil
}

// settingClaims is client's current claim set.
func (f *fakeIdP) settingClaims(client string) []keycloak.SettingClaim {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]keycloak.SettingClaim(nil), f.claims[client]...)
}

func (f *fakeIdP) claimRemovals() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.claimRemove...)
}

// fakeAttrStore is LLDAP's user attribute schema and values (AttrStore).
type fakeAttrStore struct {
	mu      sync.Mutex
	schema  map[string]lldap.Attribute
	values  map[string]map[string][]string // user → attr → values
	sets    []string                       // SetUserAttributes calls: "<user> +a=v -b"
	deleted []string
	// failUser: SetUserAttributes for that user fails; err: every call.
	failUser string
	err      error
	lists    int  // ListUsers calls
	failAdd  bool // AddHiddenUserAttribute fails
	// failSchema: UserAttributes fails (LLDAP GraphQL down).
	failSchema bool
}

func newFakeAttrStore() *fakeAttrStore {
	return &fakeAttrStore{schema: map[string]lldap.Attribute{}, values: map[string]map[string][]string{}}
}

func (s *fakeAttrStore) UserAttributes(ctx context.Context) ([]lldap.Attribute, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if s.failSchema {
		return nil, fmt.Errorf("lldap graphql down")
	}
	var out []lldap.Attribute
	for _, a := range s.schema {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *fakeAttrStore) ListUsers(ctx context.Context) ([]lldap.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists++
	if s.err != nil {
		return nil, s.err
	}
	var out []lldap.User
	for u, vs := range s.values {
		a := map[string][]string{}
		for k, v := range vs {
			a[k] = append([]string(nil), v...)
		}
		out = append(out, lldap.User{ID: u, Attributes: a})
	}
	return out, nil
}

func (s *fakeAttrStore) AddHiddenUserAttribute(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.failAdd {
		return fmt.Errorf("lldap down")
	}
	if _, ok := s.schema[name]; ok {
		return fmt.Errorf("attribute %s already exists", name)
	}
	s.schema[name] = lldap.Attribute{Name: name}
	return nil
}

func (s *fakeAttrStore) DeleteUserAttribute(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if _, ok := s.schema[name]; !ok {
		return fmt.Errorf("no attribute %s", name)
	}
	delete(s.schema, name)
	for _, vs := range s.values {
		delete(vs, name)
	}
	s.deleted = append(s.deleted, name)
	return nil
}

func (s *fakeAttrStore) SetUserAttributes(ctx context.Context, user string, set map[string][]string, remove []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if user == s.failUser {
		return fmt.Errorf("no such user %s", user)
	}
	call := user
	for _, a := range remove {
		if _, ok := s.schema[a]; !ok {
			return fmt.Errorf("attribute %s must be declared first", a)
		}
		delete(s.values[user], a)
		call += " -" + a
	}
	keys := make([]string, 0, len(set))
	for a := range set {
		keys = append(keys, a)
	}
	sort.Strings(keys)
	for _, a := range keys {
		if _, ok := s.schema[a]; !ok {
			return fmt.Errorf("attribute %s must be declared first", a)
		}
		if s.values[user] == nil {
			s.values[user] = map[string][]string{}
		}
		s.values[user][a] = append([]string(nil), set[a]...)
		call += " +" + a + "=" + strings.Join(set[a], ",")
	}
	s.sets = append(s.sets, call)
	return nil
}

// value is user's value of attr ("" and false: none).
func (s *fakeAttrStore) value(user, attr string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[user][attr]
	return strings.Join(v, ","), ok
}

func (s *fakeAttrStore) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sets...)
}

func (s *fakeAttrStore) has(attr string) (lldap.Attribute, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.schema[attr]
	return a, ok
}

func (f *fakeIdP) DeleteClient(ctx context.Context, clientID, owner string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, clientID+":"+owner)
	delete(f.clients, clientID)
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

func (f *fakeIdP) RegisterClient(ctx context.Context, s keycloak.ClientSpec) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.registerErr != nil {
		return false, f.registerErr
	}
	f.specs = append(f.specs, s)
	f.registered = append(f.registered, fmt.Sprintf("%s:%s:%s:%s:%s", s.ClientID, s.TemplateID, s.ACR, s.Secret, strings.Join(s.AllowedHosts, ",")))
	if f.clients == nil {
		f.clients = map[string]bool{}
	}
	created := !f.clients[s.ClientID]
	f.clients[s.ClientID] = true
	return created, nil
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
ai: {unsupported: "test fixture"}
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
ai: {unsupported: "test fixture"}
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
	clk     *fakeClock // set by fixtures that install a fake clock
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
var errNoSuchContainer = cerrdefs.ErrNotFound.WithMessage("no such container")

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
	// people, if set, gets the groups created and deleted here.
	people *fakePeople
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

func (g *fakeGroups) ResolveActor(ctx context.Context, actor directory.Actor) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.actorErr
}

func (g *fakeGroups) CreateInstanceGroup(ctx context.Context, actor directory.Actor, name string) (bool, []string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.createErr != nil {
		if err := g.createErr(name); err != nil {
			return false, nil, err
		}
	}
	g.calls = append(g.calls, "+"+name+":"+actor.User)
	if g.existing == nil {
		g.existing = map[string]bool{}
	}
	g.existing[name] = true
	if g.people != nil {
		g.people.addGroup(name)
	}
	if g.createWarn != nil {
		if w := g.createWarn(name); w != "" {
			return true, []string{w}, nil
		}
	}
	return true, nil, nil
}

func (g *fakeGroups) DeleteInstanceGroup(ctx context.Context, actor directory.Actor, name string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.delErr != nil {
		return nil, g.delErr
	}
	g.calls = append(g.calls, "-"+name+":"+actor.User)
	if g.people != nil {
		g.people.deleteGroup(name)
	}
	return nil, nil
}

func (g *fakeGroups) set(fn func(g *fakeGroups)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fn(g)
}

func (g *fakeGroups) Calls() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.calls...)
}

// fakePeople is the directory as the Hub's settings see it (People) and
// the LLDAP side of the sweep check (LDAPUsers): users, groups with ids
// (a re-created group gets a new id), expired memberships and groups
// that can't hold privileged values.
type fakePeople struct {
	mu        sync.Mutex
	users     map[string]bool
	groups    map[string]int
	members   map[string]map[string]bool
	expired   map[string]map[string]bool
	privilege map[string]string
	// uuids: LLDAP account uuids (default "uuid-<user>"; recreate gives
	// a new one).
	uuids map[string]string
	// emails / pending: Membership.Emails and Membership.Pending (the gate
	// file's people and expiring, plan 4 T11).
	emails  map[string]string
	pending map[string]map[string]time.Time
	err     error
	nextID  int
	calls   int
	// onMembership, if set, runs once after the next snapshot is taken
	// (without p.mu): something changing between snapshot and use.
	onMembership func()
}

func newFakePeople(users ...string) *fakePeople {
	p := &fakePeople{users: map[string]bool{"admin": true, "portcullis-hub": true}, groups: map[string]int{}, members: map[string]map[string]bool{},
		expired: map[string]map[string]bool{}, privilege: map[string]string{}, nextID: 100}
	for _, u := range users {
		p.users[u] = true
	}
	return p
}

func (p *fakePeople) addGroup(name string, members ...string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.groups[name]; !ok {
		p.nextID++
		p.groups[name] = p.nextID
		p.members[name] = map[string]bool{}
	}
	for _, m := range members {
		p.users[m] = true
		p.members[name][m] = true
	}
	return p.groups[name]
}

func (p *fakePeople) deleteGroup(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.groups, name)
	delete(p.members, name)
}

// uuidLocked is user's account uuid. Caller holds p.mu.
func (p *fakePeople) uuidLocked(user string) string {
	if u, ok := p.uuids[user]; ok {
		return u
	}
	return "uuid-" + user
}

// uuidOf is user's account uuid.
func (p *fakePeople) uuidOf(user string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.uuidLocked(user)
}

// recreate deletes user and creates the name again (a new uuid, no
// groups).
func (p *fakePeople) recreate(user string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.uuids == nil {
		p.uuids = map[string]string{}
	}
	p.nextID++
	p.uuids[user] = fmt.Sprintf("uuid-%s-%d", user, p.nextID)
	for _, ms := range p.members {
		delete(ms, user)
	}
}

// removeMember takes user out of group.
func (p *fakePeople) removeMember(group, user string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.members[group], user)
}

func (p *fakePeople) id(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.groups[name]
}

func (p *fakePeople) set(fn func(p *fakePeople)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(p)
}

func (p *fakePeople) Membership(ctx context.Context, now time.Time) (*directory.Membership, error) {
	p.mu.Lock()
	hook := p.onMembership
	p.onMembership = nil
	if hook != nil {
		defer hook()
	}
	defer p.mu.Unlock()
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	m := &directory.Membership{Users: map[string]map[string]int{}, Groups: map[string]directory.MemberGroup{}, Expired: map[string]map[string]bool{}, Privilege: map[string]string{}, UUIDs: map[string]string{}}
	for u := range p.users {
		if u != "portcullis-hub" {
			m.Users[u] = map[string]int{}
			m.UUIDs[u] = p.uuidLocked(u)
		}
	}
	for g, id := range p.groups {
		mg := directory.MemberGroup{ID: id, Members: []string{}}
		for u := range p.members[g] {
			mg.Members = append(mg.Members, u)
			m.Users[u][g] = id
		}
		sort.Strings(mg.Members)
		m.Groups[g] = mg
		if why := p.privilege[g]; why != "" {
			m.Privilege[g] = why
		}
	}
	m.Emails, m.Pending = map[string]string{}, map[string]map[string]time.Time{}
	for u, e := range p.emails {
		if _, ok := m.Users[u]; ok {
			m.Emails[u] = e
		}
	}
	for u, gs := range p.pending {
		m.Pending[u] = map[string]time.Time{}
		for g, at := range gs {
			m.Pending[u][g] = at
		}
	}
	for u, gs := range p.expired {
		m.Expired[u] = map[string]bool{}
		for g, v := range gs {
			m.Expired[u][g] = v
		}
	}
	return m, nil
}

func (p *fakePeople) PrivilegeProblem(ctx context.Context, group string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return "", p.err
	}
	if _, ok := p.groups[group]; !ok {
		return "", &directory.Error{Status: 404, Msg: "no such group " + group}
	}
	return p.privilege[group], nil
}

func (p *fakePeople) ListUsers(ctx context.Context) ([]lldap.User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	var out []lldap.User
	for u := range p.users {
		out = append(out, lldap.User{ID: u})
	}
	return out, nil
}

func (p *fakePeople) ServiceUser() string { return "portcullis-hub" }

// ── fake fixer runs (started helpers, contract §6) ───────

// fixerFake scripts started helper runs: every spec is recorded; run (if
// set) answers, else reports[mode] (exit 0 + that stdout line), else a
// minimal report of the mode. inspect answers InspectContainer by id;
// secOpts is the daemon's SecurityOptions.
type fixerFake struct {
	fmu        sync.Mutex
	specs      []docker.RunSpec
	inputs     [][]byte // the drained In stream of each run (nil = none)
	run        func(s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error)
	reports    map[string]string
	inspect    map[string]docker.ContainerInfo
	inspectErr error
	inspected  []string
	secOpts    []string
	secErr     error
	// dockerRoot / rootErr answer DockerRootDir ("" = /var/lib/docker).
	dockerRoot string
	rootErr    error
}

func (e *fakeEngine) fx() *fixerFake {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fixer == nil {
		e.fixer = &fixerFake{}
	}
	return e.fixer
}

// fixerMode is the mode of a fixer argv (/usr/local/bin/hub folderfix <mode> …).
func fixerMode(cmd []string) string {
	if len(cmd) < 3 {
		return ""
	}
	return cmd[2]
}

func (e *fakeEngine) RunHelper(ctx context.Context, s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error) {
	f := e.fx()
	var in []byte
	if s.In != nil {
		in, _ = io.ReadAll(s.In)
	}
	f.fmu.Lock()
	f.specs = append(f.specs, s)
	f.inputs = append(f.inputs, in)
	run, rep := f.run, f.reports[fixerMode(s.Cmd)]
	f.fmu.Unlock()
	if run != nil {
		return run(s, out)
	}
	if rep == "" {
		rep = fmt.Sprintf(`{"version":1,"mode":%q}`, fixerMode(s.Cmd))
	}
	return &docker.RunResult{Stdout: []byte(rep + "\n")}, nil
}

func (e *fakeEngine) InspectContainer(ctx context.Context, id string) (docker.ContainerInfo, error) {
	f := e.fx()
	f.fmu.Lock()
	defer f.fmu.Unlock()
	f.inspected = append(f.inspected, id)
	if f.inspectErr != nil {
		return docker.ContainerInfo{}, f.inspectErr
	}
	ci, ok := f.inspect[id]
	if !ok {
		return docker.ContainerInfo{}, errNoSuchContainer
	}
	return ci, nil
}

func (e *fakeEngine) SecurityOptions(ctx context.Context) ([]string, error) {
	f := e.fx()
	f.fmu.Lock()
	defer f.fmu.Unlock()
	return f.secOpts, f.secErr
}

func (e *fakeEngine) DockerRootDir(ctx context.Context) (string, error) {
	f := e.fx()
	f.fmu.Lock()
	defer f.fmu.Unlock()
	if f.dockerRoot == "" && f.rootErr == nil {
		return "/var/lib/docker", nil
	}
	return f.dockerRoot, f.rootErr
}

func (e *fakeEngine) APIVersion(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.apiVersion == "" {
		return "1.47", nil
	}
	return e.apiVersion, nil
}

func (f *fixerFake) Specs() []docker.RunSpec {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	return append([]docker.RunSpec(nil), f.specs...)
}

// dirStateOf adapts a test's (expiring, attributes) function to
// DirectoryState: no membership (the gate file then keeps the last
// file's populations, like a failing directory).
func dirStateOf(f func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error)) DirectoryState {
	return func(ctx context.Context) (DirectorySnapshot, error) {
		exp, attrs, err := f(ctx)
		return DirectorySnapshot{Expiring: exp, Attrs: attrs}, err
	}
}
