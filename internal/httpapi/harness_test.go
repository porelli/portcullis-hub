//go:build harness

package httpapi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

// TestHarness serves the Hub UI against the in-memory fakes (LLDAP,
// Keycloak, Docker engine, compose runner, domains) for a browser check:
//
//	go test -tags harness -run TestHarness -timeout 0 ./internal/httpapi
//
// It listens on HUB_HARNESS_ADDR (default 127.0.0.1:18888), signs every
// request in as "root" (an LLDAP admin) with the proxy secret, serves the
// people listener on HUB_HARNESS_PEOPLE_ADDR (default 127.0.0.1:18889)
// signed in as HUB_HARNESS_PEOPLE_USER (default alice; a request's
// X-Harness-User overrides it), and runs until HUB_HARNESS_FOR (a
// duration, default 30m) has passed.
//
// Settings panel fixtures (the Hub's internal/hub/testdata/settings
// templates, each a default instance):
//
//   - tmfixture (Time Machine): per-person size_limit (unlimited allowed,
//     resolve_choices max / min / priority added here,
//     data file restarting on membership changes) with rows for
//     office_milan and it_staff, a file-delivered string and a set secret;
//     users_tmfixture holds 60 people (the "who gets what" pages).
//   - privapp (enabled once and disabled, so role carries its seeded
//     admin_privapp row): privileged person enum role — office_milan is
//     refused with a reason (harnessPeople) —, the person enum tier, the
//     group-scope
//     list libraries (file + env) with a record for office_milan.
//   - secretapp: secrets (one generated), api_url requiring api_key.
//   - hookapp: ENABLED, per-person seats office_milan 3, it_staff 5 (My
//     apps: alice 3, bob 5); its hook apply fails ("exited 1") until
//     POST /harness/hook/fix (POST /harness/hook/break fails it again),
//     so the deliveries strip shows the reason and Retry clears it.
//   - claimapp, headerapp, nativeapp: claims, headers, native sign-in.
//   - entryapp: ENABLED (method custom, access group entryapp: alice, bob
//     and dave), person-entered ext_id (32 lowercase hex, unique,
//     admin_override, file ids restarting) and nick (hook apply, no
//     admin_override); carol entered an ext_id and then left entryapp
//     (the panel's "Stored, not delivered: no access").
//
// The directory: root (admin), dana, alice, bob, carol, dave, erin and
// user01-user55; groups office_milan (alice, bob, erin), it_staff (bob,
// user07), helpers, and the fixtures' access and admin groups.
func TestHarness(t *testing.T) {
	addr := os.Getenv("HUB_HARNESS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18888"
	}
	// It signs everyone in as an admin: loopback only.
	host, _, err := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		t.Fatalf("HUB_HARNESS_ADDR %q: the harness signs every request in as an admin and only listens on a loopback IP address (e.g. 127.0.0.1:18888)", addr)
	}
	extra := map[string][2]string{}
	for _, id := range harnessFixtures {
		dir := filepath.Join("..", "hub", "testdata", "settings", id)
		m, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		c, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
		if err != nil {
			t.Fatal(err)
		}
		manifest := string(m)
		if id == "tmfixture" {
			// The resolve selector: largest wins, or the admin's order.
			manifest = strings.Replace(manifest, "      resolve: max\n", "      resolve: max\n      resolve_choices: [max, min, priority]\n", 1)
		}
		extra[id] = [2]string{manifest, string(c)}
	}
	// Shared folders and the doctor (plan 2, Task 14): photos (a
	// declared read option, an undeclared one, a lan_only port) and samba
	// (a declared write option).
	extra["photos"] = [2]string{folderAppManifest, folderAppCompose}
	extra["samba"] = [2]string{harnessSambaManifest, harnessSambaCompose}
	var eng *harnessEngine
	disk := newHarnessDisk()
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{
		extra: extra,
		engine: func(f *fakeEngine) hub.Engine {
			eng = &harnessEngine{fakeEngine: f, disk: disk,
				running: map[string][]string{"hookapp": {"app"}, "entryapp": {"app"}, "photos": {"server"}, "samba": {"samba"}}}
			return eng
		},
		cfg: func(c *hub.Config) { c.FixerImage = testFixerImage },
		seed: func(st *state.AppState) {
			// A Problem: secretapp's folder changed on disk at its last
			// start (explain-only).
			st.FolderChanged = map[string][]state.FolderChange{"secretapp": {{Instance: "secretapp", Key: "files", Folder: "media",
				At: time.Now().UTC(), Detail: "/srv/media/inbox is a symlink"}}}
		},
	})
	h := e.s.Hub
	for _, id := range append(slices.Clone(harnessFixtures), "photos", "samba") {
		if h.Template(id) == nil {
			t.Fatalf("fixture %s not loaded (see the log)", id)
		}
	}
	seedDirectory(e)
	h.SetPeople(harnessPeople{e.s.Directory})

	// Seed: two extra instances, one enabled, with data; backups, one of
	// a deleted instance.
	for _, c := range []struct{ tmpl, id string }{{"grafana", "grafana-team-a"}, {"home", "home-b"}, {"grafana", "grafana-old"}} {
		if _, err := h.CreateInstanceAs(c.tmpl, c.id, nil, "root"); err != nil {
			t.Fatal(err)
		}
	}
	e.engine.addVolume("portcullis_grafana-team-a-grafana-data", "portcullis-grafana-team-a", "grafana-data", map[string]string{"grafana.db": "rows"})
	e.engine.addVolume("portcullis_grafana-old-grafana-data", "portcullis-grafana-old", "grafana-data", map[string]string{"grafana.db": "old rows"})
	if err := h.Enable("grafana-team-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BackupInstance("grafana-team-a", "root"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := h.DeleteInstance("grafana-old", "grafana-old", "root"); err != nil {
		t.Fatal(err)
	}
	seedSettings(t, h, eng)
	seedEntries(t, e)
	seedFolders(t, h, disk)

	d, err := time.ParseDuration(os.Getenv("HUB_HARNESS_FOR"))
	if err != nil {
		d = 30 * time.Minute
	}
	handler := e.hub.Config.Handler
	mux := http.NewServeMux()
	mux.HandleFunc("POST /harness/hook/fix", func(w http.ResponseWriter, r *http.Request) {
		eng.hookOK.Store(true)
		fmt.Fprintln(w, "hook apply now exits 0")
	})
	mux.HandleFunc("POST /harness/hook/break", func(w http.ResponseWriter, r *http.Request) {
		eng.hookOK.Store(false)
		fmt.Fprintln(w, "hook apply now exits 1")
	})
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(ProxySecretHeader, testSecret)
		r.Header.Set("X-Forwarded-User", "root")
		handler.ServeHTTP(w, r)
	}))
	srv := &http.Server{Addr: addr, Handler: mux}
	// The people listener (My apps): signed in as HUB_HARNESS_PEOPLE_USER
	// (default alice), or the request's X-Harness-User.
	paddr := os.Getenv("HUB_HARNESS_PEOPLE_ADDR")
	if paddr == "" {
		paddr = "127.0.0.1:18889"
	}
	if host, _, err := net.SplitHostPort(paddr); err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatalf("HUB_HARNESS_PEOPLE_ADDR %q: loopback IP addresses only", paddr)
	}
	puser := os.Getenv("HUB_HARNESS_PEOPLE_USER")
	if puser == "" {
		puser = "alice"
	}
	people := e.ppl.Config.Handler
	psrv := &http.Server{Addr: paddr, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.Header.Get("X-Harness-User")
		if u == "" {
			u = puser
		}
		r.Header.Set(ProxySecretHeader, testSecret)
		r.Header.Set("X-Forwarded-User", u)
		people.ServeHTTP(w, r)
	})}
	go func() {
		if err := psrv.ListenAndServe(); err != http.ErrServerClosed {
			t.Errorf("people listener: %v", err)
		}
	}()
	go func() {
		time.Sleep(d)
		psrv.Close()
		srv.Close()
	}()
	t.Logf("harness on http://%s, people listener on http://%s as %s, for %s (hookapp's hook fails until POST /harness/hook/fix)", addr, paddr, puser, d)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		t.Fatal(err)
	}
}

// harnessFixtures are the Hub's settings test templates the harness
// serves (internal/hub/testdata/settings).
var harnessFixtures = []string{"tmfixture", "privapp", "secretapp", "hookapp", "claimapp", "headerapp", "nativeapp", "entryapp"}

// seedDirectory adds the settings fixtures' people and groups to the
// fake LLDAP.
func seedDirectory(e *instEnv) {
	for _, u := range []string{"alice", "bob", "carol", "dave", "erin"} {
		e.ll.AddUser(u, u+"@example.org", strings.ToUpper(u[:1])+u[1:], "")
	}
	many := []string{"alice", "bob", "carol"}
	for i := 1; i <= 55; i++ {
		u := fmt.Sprintf("user%02d", i)
		e.ll.AddUser(u, u+"@example.org", fmt.Sprintf("User %02d", i), "")
		many = append(many, u)
	}
	e.ll.AddGroup("office_milan", "alice", "bob", "erin")
	e.ll.AddGroup("it_staff", "bob", "user07")
	e.ll.AddGroup("users_tmfixture", many...)
	e.ll.AddGroup("admin_tmfixture", "root")
	for _, id := range []string{"privapp", "secretapp", "hookapp", "nativeapp"} {
		e.ll.AddGroup("users_"+id, "root", "alice", "bob", "carol")
		e.ll.AddGroup("admin_"+id, "root", "dave")
	}
	e.ll.AddGroup("users_dash", "alice", "bob")
	e.ll.AddGroup("admin_dash", "root")
	e.ll.AddGroup("users_immich", "alice", "bob", "carol")
	e.ll.AddGroup("admin_immich", "root")
	e.ll.AddGroup("entryapp", "alice", "bob", "carol", "dave")
	for _, id := range []string{"photos", "samba"} {
		e.ll.AddGroup("users_"+id, "root", "alice", "bob")
		e.ll.AddGroup("admin_"+id, "root")
	}
}

// harnessCarolExt is the ext_id carol entered before leaving entryapp.
const harnessCarolExt = "c0ffeec0ffeec0ffeec0ffeec0ffee00"

// seedEntries enables entryapp, has carol enter an ext_id, then takes
// her out of its access group (stored, not delivered: no access).
func seedEntries(t *testing.T, e *instEnv) {
	t.Helper()
	h := e.s.Hub
	if err := h.Enable("entryapp"); err != nil {
		t.Fatalf("enabling entryapp: %v", err)
	}
	if _, err := h.SetPersonValue(context.Background(), "entryapp", "ext_id", "carol", json.RawMessage(`"`+harnessCarolExt+`"`), "carol"); err != nil {
		t.Fatalf("seeding carol's ext_id: %v", err)
	}
	e.ll.RemoveMember("entryapp", "carol")
	h.Wait()
}

// seedSettings stores the fixtures' panel content and makes hookapp's
// last delivery fail.
func seedSettings(t *testing.T, h *hub.Hub, eng *harnessEngine) {
	t.Helper()
	raw := func(v any) json.RawMessage {
		b, _ := json.Marshal(v)
		return b
	}
	tok := "harness-api-token-value"
	if _, err := h.SaveSettings("tmfixture", hub.SettingsUpdate{
		Person: map[string]hub.PersonChange{"size_limit": {Default: raw("500GiB"), Rows: []hub.GroupValueInput{
			{Group: "office_milan", Value: raw("10GiB")}, {Group: "it_staff", Value: raw("2TiB")},
		}}},
		Values:  map[string]json.RawMessage{"greeting": raw("Welcome back")},
		Secrets: map[string]hub.SecretChange{"api_token": {Value: &tok}},
	}, "root"); err != nil {
		t.Fatalf("seeding tmfixture: %v", err)
	}
	if _, err := h.SaveSettings("privapp", hub.SettingsUpdate{
		Groups: map[string][]hub.GroupValueInput{"libraries": {{Group: "office_milan", Value: raw([]string{"photos", "projects"})}}},
		Values: map[string]json.RawMessage{"motd": raw("Maintenance on Sunday")},
	}, "root"); err != nil {
		t.Fatalf("seeding privapp: %v", err)
	}
	// Enabled once, so its person options are seeded (the {{ADMIN_GROUP}}
	// row of role), then disabled again.
	if _, err := h.EnableAs("privapp", "root"); err != nil {
		t.Fatalf("enabling privapp: %v", err)
	}
	if err := h.Disable("privapp"); err != nil {
		t.Fatalf("disabling privapp: %v", err)
	}
	// My apps on the people listener: alice gets 3 seats from
	// office_milan, bob 5 from it_staff (office_milan losing).
	if _, err := h.SaveSettings("hookapp", hub.SettingsUpdate{
		Person: map[string]hub.PersonChange{"seats": {Default: raw(1), Rows: []hub.GroupValueInput{
			{Group: "office_milan", Value: raw(3)}, {Group: "it_staff", Value: raw(5)},
		}}},
	}, "root"); err != nil {
		t.Fatalf("seeding hookapp: %v", err)
	}
	eng.hookOK.Store(true)
	if err := h.Enable("hookapp"); err != nil {
		t.Fatalf("enabling hookapp: %v", err)
	}
	h.Wait()
	eng.hookOK.Store(false)
	if _, err := h.RetryDeliveries(context.Background(), "hookapp", "root"); err != nil {
		t.Logf("hookapp delivery (expected to fail): %v", err)
	}
}

// harnessEngine is the fake engine plus running containers for the
// listed instances (project portcullis-<id>, one per service) and a
// hook apply that exits 1 until hookOK.
type harnessEngine struct {
	*fakeEngine
	running map[string][]string // instance id → services
	hookOK  atomic.Bool
	disk    *harnessDisk
}

// RunHelper answers the shared-folder fixer's runs from the fake disk.
func (e *harnessEngine) RunHelper(_ context.Context, s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error) {
	return e.disk.run(s, out)
}

func (e *harnessEngine) ListContainers(ctx context.Context, f docker.Filters) ([]docker.Container, error) {
	out, err := e.fakeEngine.ListContainers(ctx, f)
	if err != nil {
		return nil, err
	}
	for id, services := range e.running {
		project := hub.ProjectPrefix + id
		for _, svc := range services {
			c := docker.Container{
				ID: project + "-" + svc, Names: []string{"/" + project + "-" + svc + "-1"}, State: "running", Status: "Up 2 hours",
				Labels: map[string]string{docker.LabelProject: project, docker.LabelService: svc, docker.LabelNumber: "1"},
			}
			if matchLabels(c.Labels, f) {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func (e *harnessEngine) ContainerState(ctx context.Context, id string) (docker.State, error) {
	for inst, services := range e.running {
		for _, svc := range services {
			if id == hub.ProjectPrefix+inst+"-"+svc {
				return docker.State{Running: true}, nil
			}
		}
	}
	return e.fakeEngine.ContainerState(ctx, id)
}

func (e *harnessEngine) ExecStdin(_ context.Context, _ string, in docker.ExecInput) (*docker.ExecResult, error) {
	if len(in.Cmd) > 0 && in.Cmd[0] == "/apply" && !e.hookOK.Load() {
		return &docker.ExecResult{ExitCode: 1, Output: []byte("quota backend unreachable: connection refused\n")}, nil
	}
	return &docker.ExecResult{Output: []byte("ok\n")}, nil
}

// harnessPeople is the directory with office_milan refused for
// privileged values (as a rule group whose rule uses a field delegates
// can edit would be).
type harnessPeople struct{ *directory.Service }

const harnessPrivilegeReason = "its rule uses fields delegates can edit: office_location"

func (p harnessPeople) Membership(ctx context.Context, now time.Time) (*directory.Membership, error) {
	m, err := p.Service.Membership(ctx, now)
	if err != nil {
		return nil, err
	}
	m.Privilege["office_milan"] = harnessPrivilegeReason
	return m, nil
}

func (p harnessPeople) PrivilegeProblem(ctx context.Context, group string) (string, error) {
	why, err := p.Service.PrivilegeProblem(ctx, group)
	if err == nil && group == "office_milan" {
		why = harnessPrivilegeReason
	}
	return why, err
}

// ── shared folders and the doctor (plan 2, Task 14) ─────────────────

// harnessSamba is a writer of shared folders (a declared write option).
const harnessSambaManifest = `name: Samba
category: files
instances: multi
auth:
  method: header-auth
  group_access: true
  access_group: users_samba
  admin_group: admin_samba
urls:
  - label: Web
    url: "https://{{HOST_SAMBA}}"
settings:
  options:
    - key: share
      label: Shared folder
      type: path
      target: {service: samba, mount: /share}
      folder: {access: write, runs_as: {uid: 2000, gid: 2000}}
      applies: restart
`

const harnessSambaCompose = "services:\n  samba:\n    image: samba\n    user: \"2000:2000\"\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.samba.rule: Host(`${PORTCULLIS_HOST_SAMBA:-samba.portcullis.local}`)\n" +
	"      traefik.http.routers.samba.entrypoints: websecure\n" +
	"      traefik.http.routers.samba.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"      traefik.http.services.samba.loadbalancer.server.port: \"8080\"\n"

// seedFolders enables photos and samba and defines two shared folders,
// each applied once (a snapshot, so "Undo last fix…"): media (Family
// media, used by photos' undeclared extra: an Info) and scans (its name
// carries markup, used by samba), which then drifts (a Warning with
// "Apply again" and "Undo last fix"). The Doctor also has photos' SMB
// port on 0.0.0.0 (lan_only: Rebind…) and secretapp's changed folder (a
// Problem, explain-only). /srv/photos and /srv/projects exist on the
// fake disk, unused; /srv/new-share is missing ("Create it");
// samba-office (disabled) is a second writer nobody assigned yet.
func seedFolders(t *testing.T, h *hub.Hub, disk *harnessDisk) {
	t.Helper()
	for _, id := range []string{"photos", "samba"} {
		if err := h.Enable(id); err != nil {
			t.Fatalf("enabling %s: %v", id, err)
		}
	}
	// samba-office: a second (disabled) writer, free for the browser's
	// assignment.
	if _, err := h.CreateInstanceAs("samba", "samba-office", nil, "root"); err != nil {
		t.Fatalf("creating samba-office: %v", err)
	}
	for _, p := range []string{"/srv/media", "/srv/scans", "/srv/photos", "/srv/projects"} {
		disk.add(p)
	}
	ctx := context.Background()
	for _, f := range []struct {
		id, name, path, desc string
		uses                 []hub.FolderUse
	}{
		{"media", "Family media", "/srv/media", "Photos and videos of the family.", []hub.FolderUse{{Instance: "photos", Key: "extra"}}},
		{"scans", "Old <b>scans</b>", "/srv/scans", "Scanned <i>letters</i>.", []hub.FolderUse{{Instance: "samba", Key: "share", Subpath: "letters"}}},
	} {
		if _, _, err := h.CreateFolder(ctx, hub.FolderInput{ID: f.id, Name: f.name, Path: f.path, Description: f.desc}, "root"); err != nil {
			t.Fatalf("creating folder %s: %v", f.id, err)
		}
		req := hub.AssignRequest{Uses: f.uses}
		plan, err := h.PreviewAssign(ctx, f.id, req)
		if err != nil {
			t.Fatalf("previewing %s: %v", f.id, err)
		}
		op, err := h.StartAssign(f.id, req, plan.Hash, "root")
		if err != nil {
			t.Fatalf("assigning %s: %v", f.id, err)
		}
		if rec := waitHubOp(t, h, "_folder."+f.id, op.OpID); !rec.OK {
			t.Fatalf("assigning %s failed: %+v", f.id, rec)
		}
	}
	disk.drift("/srv/scans", 37)
	op, err := h.StartDoctorScan("root")
	if err != nil {
		t.Fatalf("doctor scan: %v", err)
	}
	if rec := waitHubOp(t, h, "_doctor", op.OpID); !rec.OK {
		t.Fatalf("doctor scan failed: %+v", rec)
	}
}

// waitHubOp waits for op id under key to finish.
func waitHubOp(t *testing.T, h *hub.Hub, key, id string) hub.OpRecord {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if r := h.LastOp(key); r != nil && r.OpID == id && !r.Running {
			return *r
		}
		if time.Now().After(deadline) {
			t.Fatalf("op %s of %s never finished: %+v", id, key, h.LastOp(key))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// harnessDir is one directory of the fake host disk.
type harnessDir struct {
	dev, ino    uint64
	files, dirs int64
	applied     bool  // the folder's ownership was applied
	drift       int64 // entries that drifted since
	last        int64 // entries the last apply changed (what an undo restores)
}

// harnessDisk answers the fixer's probe, scan, snapshot, apply and
// restore runs (host path → directory). An apply reports 2 hard links
// and 1 race (warnings), a restore 1 entry changed since the fix.
type harnessDisk struct {
	mu   sync.Mutex
	dirs map[string]*harnessDir
	next uint64
}

func newHarnessDisk() *harnessDisk { return &harnessDisk{dirs: map[string]*harnessDir{}} }

func (d *harnessDisk) add(p string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addLocked(p)
}

func (d *harnessDisk) addLocked(p string) *harnessDir {
	d.next++
	e := &harnessDir{dev: 2049, ino: 500 + d.next, files: 12410, dirs: 312}
	d.dirs[p] = e
	return e
}

func (d *harnessDisk) drift(p string, n int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dirs[p].drift = n
}

// pending is what an apply would change.
func (e *harnessDir) pending() int64 {
	if !e.applied {
		return e.files + e.dirs + 1
	}
	return e.drift
}

func (e *harnessDir) plan() *folderfix.PlanCounts {
	n := e.pending()
	if n == 0 {
		return &folderfix.PlanCounts{Digest: strings.Repeat("cd", 32), KeepGroup: map[int]int64{}, KeepUser: map[int]int64{}}
	}
	dirs := int64(0)
	if !e.applied {
		dirs = e.dirs + 1
	}
	return &folderfix.PlanCounts{Changes: n, Digest: strings.Repeat("ab", 32), ChangeGroup: folderfix.Count{N: n},
		AddSetgid: folderfix.Count{N: dirs}, AddDefaultACL: folderfix.Count{N: dirs},
		KeepGroup: map[int]int64{1000: n}, KeepUser: map[int]int64{}}
}

func harnessReply(rep any, exit int) (*docker.RunResult, error) {
	b, _ := json.Marshal(rep)
	return &docker.RunResult{ExitCode: exit, Stdout: append(b, '\n')}, nil
}

func harnessArg(cmd []string, flag string) (string, bool) {
	for _, a := range cmd {
		if a == "--"+flag {
			return "", true
		}
		if v, ok := strings.CutPrefix(a, "--"+flag+"="); ok {
			return v, true
		}
	}
	return "", false
}

func (d *harnessDisk) run(s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error) {
	if s.In != nil {
		io.Copy(io.Discard, s.In)
	}
	mode := ""
	if len(s.Cmd) > 2 {
		mode = s.Cmd[2]
	}
	if len(s.Binds) == 0 {
		return nil, fmt.Errorf("fixer %s without a bind mount", mode)
	}
	src := s.Binds[0].Source
	d.mu.Lock()
	defer d.mu.Unlock()
	if mode == "probe" {
		rel, _ := harnessArg(s.Cmd, "rel")
		_, create := harnessArg(s.Cmd, "create")
		p := folderfix.ProbeReport{Version: 1, Mode: "probe", Root: "/broot", Rel: rel, MountRoot: "/"}
		e := d.dirs[path.Join(src, rel)]
		if e == nil && create {
			e = d.addLocked(path.Join(src, rel))
			e.files, e.dirs = 0, 0
			p.Created = true
		}
		if e != nil {
			p.Exists, p.Dev, p.Ino, p.FSType = true, e.dev, e.ino, "ext4"
			for _, a := range s.Cmd {
				if sub, ok := strings.CutPrefix(a, "--sub="); ok {
					sp := folderfix.SubProbe{Rel: sub}
					if se := d.dirs[path.Join(src, rel, sub)]; se != nil {
						sp.Exists, sp.Dev, sp.Ino = true, se.dev, se.ino
					}
					p.Subs = append(p.Subs, sp)
				}
			}
		}
		return harnessReply(p, 0)
	}
	e := d.dirs[src]
	if e == nil {
		return harnessReply(folderfix.Report{Version: 1, Mode: mode, Errors: []string{"no such directory"}}, 2)
	}
	n := e.files + e.dirs + 1
	switch mode {
	case "scan":
		rep := folderfix.Report{Version: 1, Mode: "scan", Root: "/folder", Dev: e.dev, Ino: e.ino, MountRoot: src, FSType: "ext4",
			ACL: true, Xattr: true, Entries: n, Files: e.files, Dirs: e.dirs, Owners: []folderfix.OwnerCount{{UID: 1000, GID: 1000, N: n}},
			FreeBytes: 1 << 40, TotalBytes: 4 << 40}
		if _, ok := harnessArg(s.Cmd, "gid"); ok {
			rep.Plan = e.plan()
			c := folderfix.Count{N: e.pending()}
			if e.applied && e.drift > 0 {
				c.Sample = []string{"1998/letter-01.pdf", "1998/letter-02.pdf"}
			}
			rep.Expected = &folderfix.Conformance{Group: c}
		}
		return harnessReply(rep, 0)
	case "snapshot":
		kind, _ := harnessArg(s.Cmd, "kind")
		if kind == "" {
			kind = "apply"
		}
		gid, _ := harnessArg(s.Cmd, "gid")
		files, _ := harnessArg(s.Cmd, "files")
		owner := "null"
		if o, ok := harnessArg(s.Cmd, "owner"); ok {
			owner = o
		}
		if gid == "" {
			gid = "0"
		}
		plan := e.plan()
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		fmt.Fprintf(zw, `{"version":1,"kind":%q,"rules":1,"root_dev":%d,"root_ino":%d,"gid":%s,"files":%q,"owner_uid":%s,"created_at":"x","entries":%d}`+"\n",
			kind, e.dev, e.ino, gid, files, owner, plan.Changes)
		zw.Close()
		var tb bytes.Buffer
		tw := tar.NewWriter(&tb)
		tw.WriteHeader(&tar.Header{Name: "out/", Typeflag: tar.TypeDir, Mode: 0o700})
		tw.WriteHeader(&tar.Header{Name: "out/" + folderfix.SnapshotName, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(gz.Len())})
		tw.Write(gz.Bytes())
		tw.Close()
		if out != nil {
			if err := out(&tb); err != nil {
				return nil, err
			}
		}
		return harnessReply(folderfix.Report{Version: 1, Mode: "snapshot", Dev: e.dev, Ino: e.ino, Plan: plan, Entries: plan.Changes}, 0)
	case "apply":
		for _, a := range s.Cmd {
			if m, ok := strings.CutPrefix(a, "--mkdir="); ok {
				if d.dirs[path.Join(src, m)] == nil {
					c := d.addLocked(path.Join(src, m))
					c.files, c.dirs = 0, 0
				}
			}
		}
		plan := e.plan()
		e.last, e.applied, e.drift = e.pending(), true, 0
		return harnessReply(folderfix.Report{Version: 1, Mode: "apply", Dev: e.dev, Ino: e.ino, Changed: e.last, Plan: plan,
			HardLinks: folderfix.Count{N: 2, Sample: []string{"album/cover.jpg"}},
			Races:     folderfix.Count{N: 1, Sample: []string{"inbox/upload.part"}}}, 0)
	case "restore":
		rep := folderfix.Report{Version: 1, Mode: "restore", Dev: e.dev, Ino: e.ino}
		if _, dry := harnessArg(s.Cmd, "dry-run"); dry {
			if e.applied {
				rep.ToRestore, rep.ChangedSince = e.last, folderfix.Count{N: 1, Sample: []string{"inbox/new.jpg"}}
			}
			return harnessReply(rep, 0)
		}
		rep.Changed, rep.ChangedSince = e.last, folderfix.Count{N: 1, Sample: []string{"inbox/new.jpg"}}
		e.applied, e.drift = false, 0
		return harnessReply(rep, 0)
	}
	return nil, fmt.Errorf("unexpected fixer mode %q", mode)
}

// Exec answers the doctor's group check (ls /proc, cat of the status
// files): one process with gid 1000 and no supplementary groups.
func (e *harnessEngine) Exec(ctx context.Context, id string, cmd []string, d time.Duration) (*docker.ExecResult, error) {
	switch {
	case len(cmd) > 0 && cmd[0] == "ls":
		return &docker.ExecResult{Output: []byte("1\nself\n")}, nil
	case len(cmd) > 0 && cmd[0] == "cat":
		return &docker.ExecResult{Output: []byte("Name:\tapp\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t\n")}, nil
	}
	return e.fakeEngine.Exec(ctx, id, cmd, d)
}
