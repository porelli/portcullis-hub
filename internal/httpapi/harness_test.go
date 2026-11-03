//go:build harness

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/hub"
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
	var eng *harnessEngine
	e := newInstEnvWith(t, t.TempDir(), extra, func(f *fakeEngine) hub.Engine {
		eng = &harnessEngine{fakeEngine: f, running: map[string][]string{"hookapp": {"app"}, "entryapp": {"app"}}}
		return eng
	})
	h := e.s.Hub
	for _, id := range harnessFixtures {
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
