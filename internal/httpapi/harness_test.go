//go:build harness

package httpapi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/portcullis/hub/internal/confirm"
	"html"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/credentials"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"

	"filippo.io/age"
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
// X-Harness-User overrides it; on the Hub listener a harness_user=admin
// cookie signs in as the bootstrap admin), and runs until HUB_HARNESS_FOR (a
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
//   - smbfixture (file sharing, plan 3 Task 14): ENABLED, router-less,
//     access group users_smbfixture (alice, bob, carol, smbuser — a
//     reserved name: "unavailable" — and harnessXSSUser), SMB lan_only
//     on 0.0.0.0 (the doctor's Rebind…), connect_address nas.home.arpa,
//     an extra info line carrying markup; alice's password starts voided
//     by a restore, bob's is active; its sync hook reports folders
//     (alice, a former member's 182 GiB, one of unknown size). Fresh
//     auth is harnessFreshAuth: the authorize URL is the people
//     listener's /harness/authorize (a fake sign-in page that sends a
//     code back to the redirect URI, people.html), and Verify checks the
//     code, its PKCE S256 challenge and nonce. GET /harness/evil?state=…
//     on the Hub listener (another origin) posts a forged callback
//     message to its parent. A people-listener request's harness_user
//     cookie picks the user (after X-Harness-User).
//
// AI support (plan 4 Task 21; My apps' "Connect your AI" card): the
// master switch on with a gate recipient, all three AI clients offered
// and healthy (Claude with the admin flag), the people MCP off (so a
// person without an AI app sees no card; Settings → AI turns it on);
// aiapp (Tokens: app_token read and write, Headers: identity_headers
// read only; users_aiapp: alice, bob) and homeauto ("Home Assistant",
// app_oauth; users_homeauto: alice) are enabled with every companion on.
// The AI Keycloak is a fake holding alice's Claude and Claude Code
// connections and bob's Claude one (Disconnect removes them); the
// access log has alice's recent requests (one tool name carrying
// markup) and one of bob's.
//
// Admin AI UI (plan 4 Task 22): the MCP listener is on (gate_present);
// ai-chat (the templates package's AI page fixture: openai_compatible and
// anthropic) selects two model providers, "ollama" (no key: optional)
// and "claude" (a label carrying markup, its key set); users_ai-chat:
// alice, bob, carol. The AI tab's four states: plain (the templates
// package's unsupported fixture, with an alternative not vetted by
// Portcullis), aiapp-off (an enabled aiapp instance, companions off),
// aiapp (on) and aiapp-mtls (policy mTLS: refused, LoA 3). Two audit
// entries via AI (Claude Code): aiapp-off's mode change and the
// refused switch-on of aiapp-mtls.
//
// The progress panel (operation progress Task 8): gitea, gitea-warn,
// grafana-scratch and nativeapp's interrupted enable, with POST
// /harness/op/break-undo and /harness/op/fix-undo
// (harness_progress_test.go).
//
// The directory: root (admin), dana, alice, bob, carol, dave, erin and
// user01-user55; groups office_milan (alice, bob, erin), it_staff (bob,
// user07), helpers, and the fixtures' access and admin groups. The group
// pages (seedGroupPages): office_milan rule-based with every row state,
// it_staff with an end date and the remove permission (bob a delegate);
// POST /harness/lldap/flaky fails the next change's apply. The person
// pages (seedPersonPages): carol in a group of each state; turin_desk and
// all_offices are rule groups.
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
	extra["smbfixture"] = harnessSMBFixture(t)
	// AI support (plan 4 Task 21): aiapp and homeauto (an app_oauth app).
	extra["aiapp"], extra["homeauto"] = harnessAIFixtures(t)
	extra["ai-chat"], extra["plain"] = harnessAIPageFixtures(t)
	// The progress panel (operation progress Task 8).
	extra["gitea"] = [2]string{harnessGiteaManifest, harnessGiteaCompose}
	// Apps and the instance page (apps Task 6): a one-off setup job.
	extra["guacamole"] = [2]string{harnessGuacManifest, harnessGuacCompose}
	// The setup form (apps Task 7): a database choice.
	extra["nextcloud"] = [2]string{harnessNextcloudManifest, harnessNextcloudCompose}
	hrun := &harnessRunner{}
	aiDir := t.TempDir()
	aiRecipient, aiGateData := harnessAIFiles(t, aiDir)
	paddr := os.Getenv("HUB_HARNESS_PEOPLE_ADDR")
	if paddr == "" {
		paddr = "127.0.0.1:18889"
	}
	secrets := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	var eng *harnessEngine
	disk := newHarnessDisk()
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{
		extra:  extra,
		runner: hrun,
		data:   func(dir string) { seedInterruptedOp(t, dir) },
		engine: func(f *fakeEngine) hub.Engine {
			eng = &harnessEngine{fakeEngine: f, disk: disk, prog: newHarnessProgress(), jobs: map[string]map[string]int{},
				running: map[string][]string{"hookapp": {"app"}, "entryapp": {"app"}, "photos": {"server"}, "samba": {"samba"}, "smbfixture": {"smb"},
					// aiapp's hooks run in its app service (the tok-mcp
					// companion isn't running: the doctor's AI finding).
					"aiapp": {"app"}}}
			return eng
		},
		cfg: func(c *hub.Config) {
			c.FixerImage = testFixerImage
			c.SecretsDir = secrets
			c.MCPGateRecipientFile = aiRecipient
			c.MCPGateDataDir = aiGateData
			c.MCPListener = true
		},
		seed: func(st *state.AppState) {
			seedAIState(st)
			// alice's file-share password was voided by a restore.
			voided := time.Now().UTC().Add(-26 * time.Hour)
			st.Credentials = map[string]map[string]map[string]state.Credential{"smbfixture": {"share_password": {"alice": {
				ID: "0011223344556677", Version: 1, UUID: "harness", CreatedAt: voided.Add(-30 * 24 * time.Hour), CreatedBy: "alice",
				RevokedAt: &voided, RevokedBy: "hub", Reason: state.CredentialReasonRestore}}}}
			// A Problem: secretapp's folder changed on disk at its last
			// start (explain-only).
			st.FolderChanged = map[string][]state.FolderChange{"secretapp": {{Instance: "secretapp", Key: "files", Folder: "media",
				At: time.Now().UTC(), Detail: "/srv/media/inbox is a symlink"}}}
		},
	})
	hrun.eng = eng
	// The Hub page's people links (Users & Groups, group names, the old
	// #users… deep links) go to this people listener.
	e.s.PeopleURL = "http://" + paddr + "/"
	// The shared navigation's Hub link goes to this Hub listener.
	e.s.HubURL = "http://" + addr + "/"
	h := e.s.Hub
	for _, id := range append(slices.Clone(harnessFixtures), "photos", "samba", "smbfixture", "aiapp", "homeauto", "ai-chat", "plain", "gitea", "guacamole", "nextcloud") {
		if h.Template(id) == nil {
			t.Fatalf("fixture %s not loaded (see the log)", id)
		}
	}
	seedDirectory(e)
	h.SetPeople(harnessPeople{e.s.Directory})
	seedAI(h)

	// Seed: two extra instances, one enabled, with data; backups, one of
	// a deleted instance.
	for _, c := range []struct{ tmpl, id string }{{"grafana", "grafana-team-a"}, {"home", "home-b"}, {"grafana", "grafana-old"}} {
		if _, err := h.CreateInstanceAs(hub.CreateRequest{Template: c.tmpl, ID: c.id, Label: "Test"}, directory.Human("root")); err != nil {
			t.Fatal(err)
		}
	}
	e.engine.addVolume("portcullis_grafana-team-a-grafana-data", "portcullis-grafana-team-a", "grafana-data", map[string]string{"grafana.db": "rows"})
	e.engine.addVolume("portcullis_grafana-old-grafana-data", "portcullis-grafana-old", "grafana-data", map[string]string{"grafana.db": "old rows"})
	if err := h.Enable("grafana-team-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BackupInstance("grafana-team-a", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := h.DeleteInstance("grafana-old", "grafana-old", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	seedAIAdmin(t, h)
	seedSettings(t, h, eng)
	seedEntries(t, e)
	seedFolders(t, h, disk)
	fa := seedFileSharing(t, h, paddr)
	hfa := seedConfirmations(t, h, addr, paddr)
	flaky := seedGroupPages(t, e)
	seedApps(t, e, eng)

	d, err := time.ParseDuration(os.Getenv("HUB_HARNESS_FOR"))
	if err != nil {
		d = 30 * time.Minute
	}
	handler := flaky.wrap(harnessDelayed(e.hub.Config.Handler))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /harness/lldap/flaky", func(w http.ResponseWriter, r *http.Request) {
		flaky.next.Store(true)
		fmt.Fprintln(w, "LLDAP is down while the next directory change is applied")
	})
	mux.HandleFunc("POST /harness/hook/fix", func(w http.ResponseWriter, r *http.Request) {
		eng.hookOK.Store(true)
		fmt.Fprintln(w, "hook apply now exits 0")
	})
	mux.HandleFunc("POST /harness/hook/break", func(w http.ResponseWriter, r *http.Request) {
		eng.hookOK.Store(false)
		fmt.Fprintln(w, "hook apply now exits 1")
	})
	mux.HandleFunc("GET /harness/evil", harnessEvilPage)
	seedProgress(t, e, mux)
	mux.HandleFunc("GET /harness/authorize", hfa.authorizePage)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(ProxySecretHeader, testSecret)
		// A harness_user=admin cookie signs the Hub page in as the
		// bootstrap admin (its "can't use apps" hint); anything else root.
		u := "root"
		if c, err := r.Cookie("harness_user"); err == nil && c.Value == "admin" {
			u = "admin"
		}
		r.Header.Set("X-Forwarded-User", u)
		handler.ServeHTTP(w, r)
	}))
	srv := &http.Server{Addr: addr, Handler: mux}
	// The people listener (My apps): signed in as HUB_HARNESS_PEOPLE_USER
	// (default alice), or the request's X-Harness-User.
	if host, _, err := net.SplitHostPort(paddr); err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatalf("HUB_HARNESS_PEOPLE_ADDR %q: loopback IP addresses only", paddr)
	}
	puser := os.Getenv("HUB_HARNESS_PEOPLE_USER")
	if puser == "" {
		puser = "alice"
	}
	people := flaky.wrap(e.ppl.Config.Handler)
	psrv := &http.Server{Addr: paddr, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/harness/authorize" {
			fa.authorizePage(w, r)
			return
		}
		u := r.Header.Get("X-Harness-User")
		if c, err := r.Cookie("harness_user"); u == "" && err == nil && c.Value != "" {
			u = c.Value
		}
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
	e.ll.AddGroup("users_aiapp", "alice", "bob")
	e.ll.AddGroup("admin_aiapp", "root")
	e.ll.AddGroup("users_homeauto", "alice")
	e.ll.AddGroup("users_ai-chat", "alice", "bob", "carol")
	e.ll.AddGroup("users_aiapp-off", "alice", "carol")
	e.ll.AddGroup("users_aiapp-mtls", "bob")
	e.ll.AddGroup("admin_homeauto", "root")
	e.ll.AddGroup("users_dash", "alice", "bob")
	e.ll.AddGroup("admin_dash", "root")
	e.ll.AddGroup("users_immich", "alice", "bob", "carol")
	e.ll.AddGroup("admin_immich", "root")
	e.ll.AddGroup("entryapp", "alice", "bob", "carol", "dave")
	e.ll.AddUser("smbuser", "smbuser@example.org", "Reserved Name", "")
	e.ll.AddUser(harnessXSSUser, "xss@example.org", "<b>Mallory</b>", "")
	e.ll.AddGroup("users_smbfixture", "alice", "bob", "carol", "smbuser", harnessXSSUser)
	e.ll.AddGroup("admin_smbfixture", "root")
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
	if _, err := h.SetPersonValue(context.Background(), "entryapp", "ext_id", "carol", json.RawMessage(`"`+harnessCarolExt+`"`), directory.Human("carol")); err != nil {
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
	}, directory.Human("root")); err != nil {
		t.Fatalf("seeding tmfixture: %v", err)
	}
	if _, err := h.SaveSettings("privapp", hub.SettingsUpdate{
		Groups: map[string][]hub.GroupValueInput{"libraries": {{Group: "office_milan", Value: raw([]string{"photos", "projects"})}}},
		Values: map[string]json.RawMessage{"motd": raw("Maintenance on Sunday")},
	}, directory.Human("root")); err != nil {
		t.Fatalf("seeding privapp: %v", err)
	}
	// Enabled once, so its person options are seeded (the {{ADMIN_GROUP}}
	// row of role), then disabled again.
	if _, err := h.EnableAs("privapp", directory.Human("root")); err != nil {
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
	}, directory.Human("root")); err != nil {
		t.Fatalf("seeding hookapp: %v", err)
	}
	eng.hookOK.Store(true)
	if err := h.Enable("hookapp"); err != nil {
		t.Fatalf("enabling hookapp: %v", err)
	}
	h.Wait()
	eng.hookOK.Store(false)
	if _, err := h.RetryDeliveries(context.Background(), "hookapp", directory.Human("root")); err != nil {
		t.Logf("hookapp delivery (expected to fail): %v", err)
	}
}

// harnessEngine is the fake engine plus running containers for the
// listed instances (project portcullis-<id>, one per service) and a
// hook apply that exits 1 until hookOK.
type harnessEngine struct {
	*fakeEngine
	runMu   sync.Mutex
	running map[string][]string // instance id → services (runMu)
	// jobs: a running instance's one-off jobs, exited with their code
	// (harness_apps_test.go; runMu).
	jobs   map[string]map[string]int
	hookOK atomic.Bool
	disk   *harnessDisk
	// The progress panel's fixtures (harness_progress_test.go): image
	// pulls and volume removals that take a while, and instances whose
	// containers never get healthy.
	prog harnessProgress
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
	e.runMu.Lock()
	defer e.runMu.Unlock()
	for id, services := range e.running {
		project := hub.ProjectPrefix + id
		for _, svc := range services {
			status := "Up 2 hours"
			if e.prog.unhealthy[id] {
				status = "Up 1 minute (health: starting)"
			}
			c := docker.Container{
				ID: project + "-" + svc, Names: []string{"/" + project + "-" + svc + "-1"}, State: "running", Status: status,
				Labels: map[string]string{docker.LabelProject: project, docker.LabelService: svc, docker.LabelNumber: "1"},
			}
			if matchLabels(c.Labels, f) {
				out = append(out, c)
			}
		}
		for svc, exit := range e.jobContainers(id) {
			c := docker.Container{
				ID: project + "-" + svc, Names: []string{"/" + project + "-" + svc + "-1"}, State: "exited", Status: fmt.Sprintf("Exited (%d) 2 hours ago", exit),
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
	e.runMu.Lock()
	defer e.runMu.Unlock()
	for inst, services := range e.running {
		for _, svc := range services {
			if id == hub.ProjectPrefix+inst+"-"+svc {
				if e.prog.unhealthy[inst] {
					return docker.State{Running: true, Status: "running", Health: "starting"}, nil
				}
				return docker.State{Running: true}, nil
			}
		}
		for svc, exit := range e.jobContainers(inst) {
			if id == hub.ProjectPrefix+inst+"-"+svc {
				return docker.State{Status: "exited", ExitCode: exit}, nil
			}
		}
	}
	return e.fakeEngine.ContainerState(ctx, id)
}

func (e *harnessEngine) ExecStdin(_ context.Context, _ string, in docker.ExecInput) (*docker.ExecResult, error) {
	if len(in.Cmd) > 0 && in.Cmd[0] == "/apply" && !e.hookOK.Load() {
		return &docker.ExecResult{ExitCode: 1, Output: []byte("quota backend unreachable: connection refused\n")}, nil
	}
	if len(in.Cmd) > 0 && in.Cmd[0] == "/portcullis/portcullis-sync" {
		return &docker.ExecResult{Output: []byte("synced\nPORTCULLIS-REPORT " + harnessSMBReport + "\n")}, nil
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
ai: {unsupported: "test fixture"}
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
	if _, err := h.CreateInstanceAs(hub.CreateRequest{Template: "samba", ID: "samba-office", Label: "Test"}, directory.Human("root")); err != nil {
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
		if _, _, err := h.CreateFolder(ctx, hub.FolderInput{ID: f.id, Name: f.name, Path: f.path, Description: f.desc}, directory.Human("root")); err != nil {
			t.Fatalf("creating folder %s: %v", f.id, err)
		}
		req := hub.AssignRequest{Uses: f.uses}
		plan, err := h.PreviewAssign(ctx, f.id, req)
		if err != nil {
			t.Fatalf("previewing %s: %v", f.id, err)
		}
		op, err := h.StartAssign(f.id, req, plan.Hash, directory.Human("root"))
		if err != nil {
			t.Fatalf("assigning %s: %v", f.id, err)
		}
		if rec := waitHubOp(t, h, "_folder."+f.id, op.OpID); !rec.OK {
			t.Fatalf("assigning %s failed: %+v", f.id, rec)
		}
	}
	disk.drift("/srv/scans", 37)
	op, err := h.StartDoctorScan(directory.Human("root"))
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

// ── file sharing (plan 3 Task 14) ─────────────────────────────────────

// harnessXSSUser is a member of users_smbfixture whose name is markup:
// the File sharing tab must show it as text.
const harnessXSSUser = `<img src=x onerror=alert('xss-user')>`

// harnessSMBReport is smbfixture's sync hook report: alice's home, a
// former member's (uid 20003, 182 GiB) and one whose size the hook
// couldn't read.
const harnessSMBReport = `{"version":1,"folders":[` +
	`{"option":"homes","name":"alice","uid":20000,"former":false,"bytes":10737418240},` +
	`{"option":"homes","name":"carol","uid":20003,"former":true,"bytes":195421011968},` +
	`{"option":"homes","name":"dave","uid":20004,"former":true,"bytes":null}]}`

// harnessSMBFixture is the Hub's smbfixture template with an info line
// carrying markup (My apps must show it as text).
func harnessSMBFixture(t *testing.T) [2]string {
	t.Helper()
	dir := filepath.Join("..", "hub", "testdata", "settings", "smbfixture")
	m, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	const line = `        - {label: Username, value: "{user}"}` + "\n"
	manifest := string(m)
	if !strings.Contains(manifest, line) {
		t.Fatal("smbfixture's info lines changed: update harnessSMBFixture")
	}
	manifest = strings.Replace(manifest, line, line+`        - {label: "<b>Note</b>", value: "<img src=x onerror=alert('xss-info')> for {user}"}`+"\n", 1)
	return [2]string{manifest, string(c)}
}

// seedFileSharing wires the fake fresh auth, adds smbfixture's people,
// sets its connect address, enables it and creates bob's password.
func seedFileSharing(t *testing.T, h *hub.Hub, paddr string) *harnessFreshAuth {
	t.Helper()
	fa := &harnessFreshAuth{base: "http://" + paddr, codes: map[string]harnessCode{}}
	h.SetFreshAuth(hub.ListenerPeople, fa)
	h.SetFreshAuthReadyForTest(true)
	raw, _ := json.Marshal("nas.home.arpa")
	if _, err := h.SaveSettings("smbfixture", hub.SettingsUpdate{Values: map[string]json.RawMessage{"connect_address": raw}}, directory.Human("root")); err != nil {
		t.Fatalf("seeding smbfixture: %v", err)
	}
	if err := h.Enable("smbfixture"); err != nil {
		t.Fatalf("enabling smbfixture: %v", err)
	}
	h.Wait()
	// bob's password (the fake verifier accepts this one code).
	fa.mu.Lock()
	fa.codes["seed"] = harnessCode{challenge: s256B64("seed-verifier-0123456789012345678901234567890"), nonce: "seed-nonce", user: "bob"}
	fa.mu.Unlock()
	cc, err := h.CreateCredential(context.Background(), "smbfixture", "share_password", "bob",
		freshauth.Proof{Code: "seed", CodeVerifier: "seed-verifier-0123456789012345678901234567890", Nonce: "seed-nonce"})
	if err != nil {
		t.Fatalf("creating bob's password: %v", err)
	}
	credentials.Zero(cc.Password)
	h.Wait()
	return fa
}

// seedConfirmations (plan 4 Task 14) wires the Hub listener's fake fresh
// auth (its own /harness/authorize, signing in root) and seeds four
// pending confirmations: two companion-style ones for the people user
// (an argument carrying markup; typed check "AI App") and two admin ones
// for root on the Hub listener (typed check "grafana-team-a"). Their
// local URLs are logged.
func seedConfirmations(t *testing.T, h *hub.Hub, addr, paddr string) *harnessFreshAuth {
	t.Helper()
	hfa := &harnessFreshAuth{base: "http://" + addr, as: "root", codes: map[string]harnessCode{}}
	h.SetFreshAuth(hub.ListenerHub, hfa)
	puser := os.Getenv("HUB_HARNESS_PEOPLE_USER")
	if puser == "" {
		puser = "alice"
	}
	digest := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	for i, c := range []struct {
		user, listener, tool, args, typed, label, base string
		cons                                           []string
	}{
		{puser, hub.ListenerPeople, "delete_repo", `{"name":"<script>alert('xss-confirm')</script>","owner":"alice"}`, "AI App", "Tokens on AI App (aiapp.example.org)", paddr,
			[]string{"Runs delete_repo once on AI App (aiapp.example.org) as you, with exactly the arguments below.", "AI App asks you to confirm every call of delete_repo."}},
		{puser, hub.ListenerPeople, "delete_branch", `{"branch":"feature/x","repo":"site"}`, "AI App", "Tokens on AI App (aiapp.example.org)", paddr,
			[]string{"Runs delete_branch once on AI App (aiapp.example.org) as you, with exactly the arguments below."}},
		{"root", hub.ListenerHub, "delete_instance", `{"id":"grafana-team-a"}`, "grafana-team-a", "instance grafana-team-a", addr,
			[]string{"Takes a backup, then permanently removes its containers, volumes, Keycloak client and groups users_grafana-team-a, admin_grafana-team-a"}},
		{"root", hub.ListenerHub, "restore_instance", `{"backup":"2026-11-06T10:00:00Z","id":"grafana-team-a"}`, "grafana-team-a", "instance grafana-team-a", addr,
			[]string{"Stops grafana-team-a and replaces its data with the backup's."}},
	} {
		res := "https://people.example.org/mcp"
		if c.listener == hub.ListenerHub {
			res = "https://hub.example.org/mcp"
		}
		if c.listener == hub.ListenerPeople {
			res = "https://aiapp.example.org/mcp"
		}
		cf, err := h.CreateConfirmation(directory.Actor{User: c.user, Via: directory.ViaAI, Client: "portcullis-ai-claude"}, confirm.Request{
			User: c.user, Client: "portcullis-ai-claude", Resource: res, Tool: c.tool, ArgsSHA256: digest(c.args), ArgsPreview: c.args,
			Listener: c.listener, Typed: c.typed, Label: c.label, Consequences: c.cons})
		if err != nil {
			t.Fatalf("seeding confirmation %d: %v", i, err)
		}
		t.Logf("confirmation %d (%s, %s): http://%s/confirm/%s", i, c.user, c.tool, c.base, cf.ID)
	}
	return hfa
}

// harnessCode is one code the fake sign-in page handed out.
type harnessCode struct{ challenge, nonce, user string }

// harnessFreshAuth is the fresh-auth verifier for the browser check: its
// authorize URL is the people listener's fake sign-in page, and Verify
// accepts a code that page issued, once, when the posted verifier's S256
// is the code's challenge and the nonce is the one the page was given.
type harnessFreshAuth struct {
	base string // the listener, http://host:port
	// as: the user the fake page signs in (""= the people listener's:
	// the harness_user cookie, HUB_HARNESS_PEOPLE_USER, else alice).
	as    string
	mu    sync.Mutex
	codes map[string]harnessCode
	n     int
}

func s256B64(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *harnessFreshAuth) Info() freshauth.AuthorizeInfo {
	return freshauth.AuthorizeInfo{AuthorizeURL: f.base + "/harness/authorize", ClientID: freshauth.ClientID, RedirectURI: f.base + "/"}
}

func (f *harnessFreshAuth) Verify(_ context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.codes[p.Code]
	delete(f.codes, p.Code) // single use
	switch {
	case !ok:
		return nil, &freshauth.Error{Reason: "unknown or used code"}
	case s256B64(p.CodeVerifier) != c.challenge:
		return nil, &freshauth.Error{Reason: "PKCE verifier mismatch"}
	case p.Nonce != c.nonce:
		return nil, &freshauth.Error{Reason: "nonce mismatch"}
	case c.user != user:
		return nil, &freshauth.Error{Reason: "username mismatch"}
	}
	return &freshauth.Result{User: user, AuthTime: time.Now(), AMR: []string{"hwk"}}, nil
}

// authorizePage is the fake Keycloak authorize endpoint: every parameter
// the contract requires must be there (400 naming the missing or wrong
// ones), then a page "touches the passkey" and redirects to the redirect
// URI with a fresh code and the state (also a link, and ?error= with
// Cancel).
func (f *harnessFreshAuth) authorizePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	info := f.Info()
	want := map[string]string{"response_type": "code", "client_id": info.ClientID, "redirect_uri": info.RedirectURI, "scope": "openid",
		"prompt": "login", "max_age": "0", "acr_values": "hwk", "code_challenge_method": "S256"}
	var bad []string
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if q.Get(k) != want[k] {
			bad = append(bad, fmt.Sprintf("%s=%q (want %q)", k, q.Get(k), want[k]))
		}
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if q.Get(k) == "" {
			bad = append(bad, k+" missing")
		}
	}
	if len(q.Get("code_challenge")) != 43 {
		bad = append(bad, "code_challenge is not a base64url SHA-256")
	}
	if len(bad) > 0 {
		http.Error(w, "fake authorize: "+strings.Join(bad, "; "), http.StatusBadRequest)
		return
	}
	user := "alice"
	if c, err := r.Cookie("harness_user"); err == nil && c.Value != "" {
		user = c.Value
	}
	if u := os.Getenv("HUB_HARNESS_PEOPLE_USER"); u != "" && user == "alice" {
		user = u
	}
	if f.as != "" {
		user = f.as
	}
	f.mu.Lock()
	f.n++
	code := fmt.Sprintf("harness-code-%d-%d", f.n, time.Now().UnixNano())
	f.codes[code] = harnessCode{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), user: user}
	f.mu.Unlock()
	back := info.RedirectURI + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
	// harness_hold=1 (cookie): no automatic redirect, for the forged-message checks.
	refresh := `<meta http-equiv="refresh" content="2;url=` + html.EscapeString(back) + `">`
	if c, err := r.Cookie("harness_hold"); err == nil && c.Value == "1" {
		refresh = ""
	}
	cancel := info.RedirectURI + "?" + url.Values{"error": {"access_denied"}, "state": {q.Get("state")}}.Encode()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Fake sign-in</title>
%s</head>
<body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem">
<h1>Fake Keycloak (harness)</h1><p>prompt=login · max_age=0 · acr_values=hwk · PKCE S256 · signing in as <b>%s</b></p>
<p><a id="approve" style="color:#60a5fa" href="%s">Touch your passkey (fake)</a> · <a id="deny" style="color:#94a3b8" href="%s">Cancel</a></p>
<p>Continuing by itself in 2 seconds (unless the harness_hold cookie is 1).</p></body></html>`,
		refresh, html.EscapeString(user), html.EscapeString(back), html.EscapeString(cancel))
}

// harnessEvilPage (Hub listener: another origin than people.<domain>)
// posts a forged fresh-auth message, with the state it is given, to its
// parent and its opener. myapps.js must ignore it.
func harnessEvilPage(w http.ResponseWriter, r *http.Request) {
	state, _ := json.Marshal(r.URL.Query().Get("state"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><body>evil<script>
var m = {type: 'portcullis-fresh-auth', code: 'evil-code', state: %s, error: ''};
if (window.parent !== window) window.parent.postMessage(m, '*');
if (window.opener) window.opener.postMessage(m, '*');
document.body.append(' posted');
</script></body></html>`, state)
}

// harnessAIFixtures are the AI apps: the Hub's aiapp test template and
// the templates package's app_oauth fixture as "Home Assistant" with an
// access group.
func harnessAIFixtures(t *testing.T) (aiapp, homeauto [2]string) {
	t.Helper()
	read := func(dir string) [2]string {
		m, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		c, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
		if err != nil {
			t.Fatal(err)
		}
		return [2]string{string(m), string(c)}
	}
	aiapp = read(filepath.Join("..", "hub", "testdata", "ai", "aiapp"))
	homeauto = read(filepath.Join("..", "templates", "testdata", "ai", "oauth"))
	m := strings.Replace(homeauto[0], "name: OAuth App\n", "name: Home Assistant\n", 1)
	m = strings.Replace(m, "      label: OAuth App\n", "      label: Home Assistant\n", 1)
	m = strings.Replace(m, "  group_access: true\n", "  group_access: true\n  access_group: users_homeauto\n", 1)
	m = strings.Replace(m, "      path: /mcp\n", "      path: /api/mcp\n", 1)
	homeauto[0] = m
	return aiapp, homeauto
}

// harnessAIFiles writes the gate's age recipient and its data directory
// with the access log (alice's lines, newest last, and one of bob's).
func harnessAIFiles(t *testing.T, dir string) (recipient, data string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipient = filepath.Join(dir, "age.pub")
	if err := os.WriteFile(recipient, []byte(id.Recipient().String()+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	data = filepath.Join(dir, "mcp-gate-data")
	if err := os.MkdirAll(data, 0o750); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var b strings.Builder
	for i, l := range []struct{ user, via, instance, companion, resource, tool, decision string }{
		{"alice", "aggregate", "aiapp", "tok", "https://aiapp.example.org/mcp", "list_issues", "allow"},
		{"alice", "aggregate", "aiapp", "tok", "https://aiapp.example.org/mcp", "search_repos", "allow"},
		{"bob", "direct", "aiapp", "tok", "https://aiapp.example.org/mcp", "tool_of_bob", "allow"},
		{"alice", "direct", "aiapp", "hdr", "https://aiapp.example.org/hdr/mcp", "<img src=x onerror=alert('xss-activity')>", "deny:read_only"},
		{"alice", "aggregate", "aiapp", "tok", "https://aiapp.example.org/mcp", "delete_repository", "confirm:ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"},
		{"alice", "direct", "", "", "https://people.example.org/mcp", "my_apps", "allow"},
	} {
		line, _ := json.Marshal(map[string]any{"time": now.Add(time.Duration(i-6) * time.Minute).Format(time.RFC3339), "user": l.user,
			"client": "portcullis-ai-claude", "resource": l.resource, "instance": l.instance, "companion": l.companion, "via": l.via,
			"method": "tools/call", "tool": l.tool, "args_sha256": strings.Repeat("ab", 32), "decision": l.decision, "upstream_status": 200, "duration_ms": 42})
		b.Write(append(line, '\n'))
	}
	if err := os.WriteFile(filepath.Join(data, hub.AccessLogName), []byte(b.String()), 0o640); err != nil {
		t.Fatal(err)
	}
	return recipient, data
}

// seedAIState switches AI support on (state): the master switch, Claude
// with the admin flag, the people MCP off, aiapp and homeauto enabled
// with every companion on.
func seedAIState(st *state.AppState) {
	st.AI.Enabled = true
	st.AI.Clients.Claude.Admin = true
	st.AI.PortcullisPeople = false
	st.Enabled = append(st.Enabled, "aiapp", "homeauto")
	st.AIInstances = map[string]state.AIInstance{
		"aiapp":    {Companions: map[string]state.AICompanion{"tok": {Enabled: true, Mode: "read_write"}, "hdr": {Enabled: true, Mode: "read_only"}}},
		"homeauto": {Companions: map[string]state.AICompanion{"oauth": {Enabled: true, Mode: "read_write"}}},
		// The AI page's provider selection (Task 23 writes it through the
		// API; seedAIAdmin adds the providers).
		"ai-chat": {Providers: []string{"ollama", "claude"}},
	}
}

// harnessAIPageFixtures: the templates package's AI page (ai-chat, with
// an access group) and its unsupported fixture (plain).
func harnessAIPageFixtures(t *testing.T) (chat, plain [2]string) {
	t.Helper()
	read := func(dir string) [2]string {
		m, err := os.ReadFile(filepath.Join("..", "templates", "testdata", "ai", dir, "manifest.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		c, err := os.ReadFile(filepath.Join("..", "templates", "testdata", "ai", dir, "compose.yml"))
		if err != nil {
			t.Fatal(err)
		}
		return [2]string{string(m), string(c)}
	}
	chat, plain = read("chat"), read("unsupported")
	chat[0] = strings.Replace(chat[0], "access_group: users_chat", "access_group: users_ai-chat", 1)
	return chat, plain
}

// seedAIAdmin seeds the admin AI UI (Task 22): two model providers (the
// claude one with its key set) selected by ai-chat, the instances
// aiapp-off (enabled, companions off) and aiapp-mtls (policy mTLS), and
// two audit entries made via AI.
func seedAIAdmin(t *testing.T, h *hub.Hub) {
	t.Helper()
	root := directory.Human("root")
	for _, p := range []state.ModelProvider{
		{Name: "ollama", Label: "Ollama on the GPU box", Kind: "openai_compatible", BaseURL: "http://gpu.lan:11434/v1",
			Models: state.ProviderModels{Fetch: true, List: []string{"llama3.3:70b", "qwen3:32b"}}, Credentials: "admin"},
		{Name: "claude", Label: "Anthropic <b>Claude</b>", Kind: "anthropic",
			Models: state.ProviderModels{List: []string{"claude-opus-4-5"}}, Credentials: "admin"},
	} {
		if _, err := h.AddModelProvider(p, root); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := h.SetProviderSecret("claude", "key", []byte("sk-ant-HARNESS-NEVER-SHOWN"), root); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"aiapp-off", "aiapp-mtls"} {
		if _, err := h.CreateInstanceAs(hub.CreateRequest{Template: "aiapp", ID: id, Label: "Test"}, root); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Enable("aiapp-off"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SaveSettings("aiapp-mtls", hub.SettingsUpdate{Policy: &policy.AuthPolicy{Factors: []string{"mtls"}, Op: "any"}}, root); err != nil {
		t.Fatal(err)
	}
	viaAI := directory.Actor{User: "root", Via: directory.ViaAI, Client: keycloak.AIClientIDs.ClaudeCode}
	ctx := context.Background()
	if _, err := h.UpdateInstanceAI(ctx, "aiapp-off", hub.InstanceAIUpdate{Companions: map[string]hub.CompanionUpdate{"tok": {Mode: ptrTo("read_only")}}}, viaAI); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UpdateInstanceAI(ctx, "aiapp-mtls", hub.InstanceAIUpdate{Companions: map[string]hub.CompanionUpdate{"tok": {Enabled: ptrTo(true)}}}, viaAI); err == nil {
		t.Fatal("aiapp-mtls: switching AI on was not refused")
	}
}

func ptrTo[T any](v T) *T { return &v }

// seedAI wires the AI Keycloak fake (alice's and bob's connections) and
// marks the three AI clients healthy.
func seedAI(h *hub.Hub) {
	now := time.Now().UTC()
	at := func(d time.Duration) *time.Time { x := now.Add(d).Truncate(time.Second); return &x }
	h.SetAIKeycloak(&peopleConnKC{conns: map[string][]keycloak.AIConnection{
		"alice": {
			{Client: keycloak.AIClientIDs.Claude, Consented: at(-72 * time.Hour), LastUsed: at(-2 * time.Minute), Expires: at(27 * 24 * time.Hour)},
			{Client: keycloak.AIClientIDs.ClaudeCode, Consented: at(-26 * time.Hour), LastUsed: at(-5 * time.Hour), Expires: at(6 * 24 * time.Hour)},
		},
		"bob": {{Client: keycloak.AIClientIDs.Claude, Consented: at(-time.Hour), LastUsed: at(-time.Hour), Expires: at(29 * 24 * time.Hour)}},
	}})
	h.SetAIClientHealth(map[string]bool{keycloak.AIClientIDs.Claude: true, keycloak.AIClientIDs.ClaudeCode: true, keycloak.AIClientIDs.Generic: true})
}

// seedGroupPages sets up the group pages (people & groups Task 5):
//
//   - office_milan becomes rule-based (office = "Milan", office a list
//     field): alice matches; bob matches and is added by hand too ("also
//     matches the rule"); dave is added by hand with an end; carol
//     matches and is kept out; erin, put back by hand in LLDAP after the
//     rule ran, is "not explained by the rule"; user03's added-by-hand
//     and gina's kept-out entries ended a moment after they were made.
//   - it_staff (manual) has user07 with an end, and holds the "remove"
//     permission (bob is a delegate: the read-only view).
//
// The background evaluator doesn't run here: the rule group is evaluated
// once after its conversion. POST /harness/lldap/flaky makes LLDAP
// unreachable while the next directory change is applied (its answer:
// applied false), and back right after.
func seedGroupPages(t *testing.T, e *instEnv) *harnessFlaky {
	t.Helper()
	p := e.ppl
	mustDo(t, p, "root", "POST", "/api/directory/fields", `{"name":"office","label":"Office","kind":"list","values":["Milan","Turin"]}`, 200)
	e.ll.AddUser("gina", "gina@example.org", "Gina", "")
	for u, office := range map[string]string{"alice": "Milan", "bob": "Milan", "carol": "Milan", "dave": "Turin", "erin": "Turin", "gina": "Milan"} {
		mustDo(t, p, "root", "PUT", "/api/directory/users/"+u+"/details", `{"attrs":{"office":["`+office+`"]}}`, 200)
	}
	convertToRule(t, e, "office_milan", `office = "Milan"`)
	if _, err := e.s.Directory.Evaluate(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("evaluating the rule groups: %v", err)
	}
	until := time.Now().UTC().Add(21 * 24 * time.Hour).Format(time.RFC3339)
	mustDo(t, p, "root", "POST", "/api/directory/groups/office_milan/members", `{"username":"bob","reason":"moving to Turin in December"}`, 200)
	mustDo(t, p, "root", "POST", "/api/directory/groups/office_milan/members", `{"username":"dave","reason":"contractor on the Milan project","until":"`+until+`"}`, 200)
	mustDo(t, p, "root", "POST", "/api/directory/groups/office_milan/exceptions", `{"user":"carol","include":false,"reason":"on leave"}`, 200)
	end := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	mustDo(t, p, "root", "PUT", "/api/directory/groups/it_staff/members/user07/expiry", `{"until":"`+end+`"}`, 200)
	mustDo(t, p, "root", "PUT", "/api/directory/permissions/remove", `{"group":"it_staff"}`, 200)
	seedPersonPages(t, e)
	// Two entries that end in a moment (an end must be in the future):
	// user03 added by hand (then "not explained by the rule") and gina
	// kept out (then "matches the rule", joining at the next sync).
	soon := time.Now().UTC().Add(3 * time.Second).Format(time.RFC3339)
	mustDo(t, p, "root", "POST", "/api/directory/groups/office_milan/members", `{"username":"user03","reason":"covering in October","until":"`+soon+`"}`, 200)
	mustDo(t, p, "root", "POST", "/api/directory/groups/office_milan/exceptions", `{"user":"gina","include":false,"reason":"sabbatical","until":"`+soon+`"}`, 200)
	time.Sleep(4 * time.Second)
	// Last: no later change may evaluate erin (or the two above) out again.
	e.ll.AddMember("office_milan", "erin")
	return &harnessFlaky{cred: filepath.Join(e.s.Directory.LLDAP.(*lldap.Client).CredentialsDir, "password"), s: e.s}
}

// convertToRule makes the manual group rule-based (nobody kept).
func convertToRule(t *testing.T, e *instEnv, group, rule string) {
	t.Helper()
	p := e.ppl
	b := mustDo(t, p, "root", "POST", "/api/directory/groups/"+group+"/convert-preview", `{"rule":`+strconvQuote(rule)+`}`, 200)
	var prev directory.ConvertPreview
	if err := json.Unmarshal([]byte(b), &prev); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"rule": rule, "keep": []string{}, "preview": prev})
	mustDo(t, p, "root", "POST", "/api/directory/groups/"+group+"/convert", string(body), 200)
}

// seedPersonPages sets up carol's page (people & groups Task 6) with a
// group in each state: kept out of office_milan (seedGroupPages), added
// by hand to turin_desk (office = "Turin") until 30 days from now,
// matching all_offices, a member of the fixtures' users_* groups, and of
// book_club (manual) until 45 days from now. turin_desk and all_offices
// are also the rule groups the invite form offers.
func seedPersonPages(t *testing.T, e *instEnv) {
	t.Helper()
	p := e.ppl
	for _, g := range []struct{ name, rule string }{{"turin_desk", `office = "Turin"`}, {"all_offices", `office in ("Milan", "Turin")`}, {"book_club", ""}} {
		mustDo(t, p, "root", "POST", "/api/directory/groups", `{"name":"`+g.name+`"}`, 200)
		if g.rule != "" {
			convertToRule(t, e, g.name, g.rule)
		}
	}
	if _, err := e.s.Directory.Evaluate(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("evaluating the rule groups: %v", err)
	}
	in30 := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	in45 := time.Now().UTC().Add(45 * 24 * time.Hour).Format(time.RFC3339)
	mustDo(t, p, "root", "POST", "/api/directory/groups/turin_desk/members", `{"username":"carol","reason":"covering the Turin desk","until":"`+in30+`"}`, 200)
	mustDo(t, p, "root", "POST", "/api/directory/groups/book_club/members", `{"username":"carol","until":"`+in45+`"}`, 200)
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// harnessFlaky takes LLDAP away (its service password file renamed)
// while the next directory change settles, and gives it back once that
// request is answered.
type harnessFlaky struct {
	cred string
	s    *Server
	next atomic.Bool // the next Settle runs with LLDAP down
	down atomic.Bool
	once sync.Once
}

func (f *harnessFlaky) wrap(h http.Handler) http.Handler {
	f.once.Do(func() {
		f.s.callHook = func(method string, _ ...any) {
			if method == "Settle" && f.next.CompareAndSwap(true, false) {
				if err := os.Rename(f.cred, f.cred+".off"); err == nil {
					f.down.Store(true)
				}
			}
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		if f.down.CompareAndSwap(true, false) {
			_ = os.Rename(f.cred+".off", f.cred)
		}
	})
}
