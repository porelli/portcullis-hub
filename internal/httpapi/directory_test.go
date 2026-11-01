package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/lldap/lldaptest"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/web"
)

var _ compose.Runner = nopRunner{}

func newDirServer(t *testing.T) (*httptest.Server, *lldaptest.Server, *kctest.Server) {
	t.Helper()
	return newDirServerWith(t, nil)
}

// newDirServerWith lets the caller adjust the directory service first.
func newDirServerWith(t *testing.T, adjust func(*directory.Service)) (*httptest.Server, *lldaptest.Server, *kctest.Server) {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "src", "demo")
	os.MkdirAll(src, 0755)
	os.WriteFile(filepath.Join(src, "manifest.yaml"), []byte("name: Demo\ncategory: test\nicon: x\nurls:\n  - label: Demo\n    url: https://demo.{{DOMAIN}}\nauth:\n  method: forward-auth\n  group_access: true\n  access_group: users_demo\n  admin_group: admin_demo\n"), 0644)
	os.WriteFile(filepath.Join(src, "compose.yml"), []byte("services:\n  web:\n    image: x\n    labels:\n      traefik.http.routers.demo.rule: Host(`demo.${PORTCULLIS_DOMAIN}`)\n"), 0644)
	data := filepath.Join(root, "data")
	os.MkdirAll(data, 0755)
	st := state.New()
	st.Sources = []state.Source{{Name: "local", Path: filepath.Dir(src)}}
	st.Save(filepath.Join(data, "state.yaml"))
	h, err := hub.New(hub.Config{ProjectDir: filepath.Join(root, "project"), DataDir: data, Domain: "example.org"}, nopRunner{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Init()
	t.Cleanup(h.Wait)

	ll := lldaptest.New(t, "portcullis-hub", "svc-password-0123456789")
	ll.AddUser("root", "root@example.org", "Root", "root-password-1", "lldap_admin")
	cred := filepath.Join(root, "lldap")
	os.MkdirAll(cred, 0700)
	os.WriteFile(filepath.Join(cred, "username"), []byte("portcullis-hub"), 0600)
	os.WriteFile(filepath.Join(cred, "password"), []byte("svc-password-0123456789"), 0600)
	kc := kctest.New(t)
	kc.Importable = ll.HasUser
	inv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Username string }
		json.NewDecoder(r.Body).Decode(&req)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{"url": "https://enroll.example.org/invite/" + req.Username, "expires_at": time.Now().Add(time.Hour)})
	}))
	t.Cleanup(inv.Close)
	secret := filepath.Join(root, "invite-secret")
	os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0600)

	s := &Server{Hub: h, Secret: testSecret, Web: web.FS, Directory: &directory.Service{
		LLDAP:   lldap.New(ll.HTTP.URL, ll.LDAPURL(), ll.BaseDN, cred),
		KC:      keycloak.New(kc.HTTP.URL, "admin", "admin"),
		Invites: invite.New(inv.URL, secret),
		Audit:   &directory.AuditLog{Path: filepath.Join(data, "audit.jsonl")},
		Apps:    h.DirectoryApps,
	}}
	if adjust != nil {
		adjust(s.Directory)
	}
	handler, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, ll, kc
}

func doAs(t *testing.T, srv *httptest.Server, user, method, path, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ProxySecretHeader, testSecret)
	if user != "" {
		req.Header.Set("X-Forwarded-User", user)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestDirectoryAPI(t *testing.T) {
	srv, ll, kc := newDirServer(t)

	r, b := doAs(t, srv, "root", "GET", "/api/directory", "")
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("overview = %d %s", r.StatusCode, b)
	}
	var ov directory.Overview
	json.Unmarshal([]byte(b), &ov)
	// The test catalog's apps aren't enabled, so nothing is suggested.
	if !ov.Available || ov.Me != "root" || len(ov.Suggestions) != 0 {
		t.Errorf("overview = %+v", ov)
	}

	ll.AddUser("ops", "ops@example.org", "", "ops-password-123", "lldap_admin")
	kc.Import("ghost") // a stale federated copy: LLDAP has no ghost
	kc.Import("ops")
	cases := []struct {
		user, method, path, body string
		want                     int
	}{
		{"root", "POST", "/api/directory/groups", `{"name":"users_demo"}`, 200},
		{"root", "POST", "/api/directory/users", `{"username":"kim","email":"kim@example.org","groups":["users_demo"]}`, 200},
		{"", "POST", "/api/directory/users", `{"username":"lee","email":"lee@example.org"}`, 403},
		{"root", "POST", "/api/directory/users", `{"username":"Lee!","email":"lee@example.org"}`, 400},
		{"root", "PUT", "/api/directory/users/kim", `{"display_name":"Kim K"}`, 200},
		{"root", "POST", "/api/directory/users/kim/invite", `{}`, 200},
		{"root", "POST", "/api/directory/users/kim/require-passkey", `{}`, 200},
		{"root", "POST", "/api/directory/users/kim/clear-actions", `{}`, 200},
		{"root", "POST", "/api/directory/users/kim/remove-passkeys", `{"confirm":"kim","invite":true}`, 200},
		{"root", "POST", "/api/directory/users/kim/password", `{"password":"short"}`, 400},
		{"root", "POST", "/api/directory/users/portcullis-hub/password", `{"generate":true}`, 409},
		{"root", "DELETE", "/api/directory/groups/lldap_admin/members/root", `{}`, 409},
		{"root", "DELETE", "/api/directory/users/root", `{"confirm":"root"}`, 409},
		{"root", "POST", "/api/directory/groups/users_demo/members", `{"username":"root"}`, 200},
		{"root", "DELETE", "/api/directory/groups/users_demo/members/root", `{}`, 200},
		{"root", "DELETE", "/api/directory/users/kim", `{"confirm":"kim"}`, 200},
		{"root", "DELETE", "/api/directory/groups/users_demo", `{"confirm":"users_demo"}`, 200},
		{"root", "GET", "/api/directory/audit", "", 200},
		{"root", "POST", "/api/directory/users/admin/invite", `{"confirm":"admin"}`, 409},
		{"root", "POST", "/api/directory/users/ops/invite", `{}`, 409}, // administrators: server-side only
		{"root", "POST", "/api/directory/users/ops/remove-passkeys", `{"confirm":"ops","invite":true}`, 409},
		{"root", "POST", "/api/directory/users/ops/password", `{"generate":true}`, 400},
		{"root", "POST", "/api/directory/users/ops/password", `{"generate":true,"confirm":"ops"}`, 200},
		{"root", "DELETE", "/api/directory/keycloak-stale/ops", `{"confirm":"ops"}`, 409}, // in LLDAP
		{"root", "DELETE", "/api/directory/keycloak-stale/ghost", `{"confirm":"x"}`, 400},
		{"root", "DELETE", "/api/directory/keycloak-stale/ghost", `{"confirm":"ghost"}`, 200},
	}
	for _, c := range cases {
		if r, b := doAs(t, srv, c.user, c.method, c.path, c.body); r.StatusCode != c.want {
			t.Errorf("%s %s = %d (%s), want %d", c.method, c.path, r.StatusCode, strings.TrimSpace(b), c.want)
		}
	}
	if ll.HasUser("kim") || ll.HasGroup("users_demo") || kc.Get("kim") != nil || kc.Get("ghost") != nil || kc.Get("ops") == nil {
		t.Error("cleanup did not reach LLDAP / Keycloak")
	}

	if _, b := doAs(t, srv, "root", "POST", "/api/directory/users/ops/invite", `{}`); !strings.Contains(b, "administrators are recovered from the server: ./portcullis invite ops") {
		t.Errorf("admin invite message = %q", b)
	}

	// Password reset response: generated once, not cached.
	ll.AddUser("max", "max@example.org", "", "")
	r, b = doAs(t, srv, "root", "POST", "/api/directory/users/max/password", `{"generate":true}`)
	var res directory.Result
	json.Unmarshal([]byte(b), &res)
	if r.StatusCode != 200 || res.Password == "" || ll.Password("max") != res.Password || r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("reset = %d %s", r.StatusCode, b)
	}

	// Mutations need the CSRF guards like every other route.
	req, _ := http.NewRequest("POST", srv.URL+"/api/directory/groups", strings.NewReader(`{"name":"g"}`))
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set("Content-Type", "text/plain")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain mutation = %d", resp.StatusCode)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Body = io.NopCloser(strings.NewReader(`{"name":"g"}`))
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site mutation = %d", resp.StatusCode)
	}
	if r, _ := do(t, srv, "GET", "/api/directory", "", false); r.StatusCode != 401 {
		t.Errorf("no proxy secret = %d", r.StatusCode)
	}
	if ll.HasGroup("g") {
		t.Error("guarded request reached LLDAP")
	}

	var audit []directory.AuditEntry
	_, b = doAs(t, srv, "root", "GET", "/api/directory/audit", "")
	json.Unmarshal([]byte(b), &audit)
	if len(audit) < 15 || audit[0].Action != "user.password" || strings.Contains(b, res.Password) {
		t.Errorf("audit = %d entries", len(audit))
	}
}

// TestDirectoryDelegates: the Caller is built per request from
// X-Forwarded-User; delegates get their permissions and nothing more.
func TestDirectoryDelegates(t *testing.T) {
	srv, ll, _ := newDirServerWith(t, func(d *directory.Service) {
		d.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
		cfg, _ := d.Store.Load()
		cfg.Permissions = map[string]string{directory.PermEditDetails: "hr", directory.PermInvite: "hr"}
		if err := d.Store.Save(cfg); err != nil {
			t.Fatal(err)
		}
	})
	ll.AddGroup("hr")
	ll.AddGroup("users_demo")
	ll.AddUser("hilda", "hilda@example.org", "Hilda", "", "hr")
	ll.AddUser("bob", "bob@example.org", "Bob", "")
	cases := []struct {
		user, method, path, body string
		want                     int
	}{
		{"hilda", "PUT", "/api/directory/users/bob", `{"display_name":"Robert"}`, 200},
		{"hilda", "PUT", "/api/directory/users/hilda", `{"display_name":"Boss"}`, 403},
		{"hilda", "PUT", "/api/directory/users/root", `{"display_name":"X"}`, 403},
		{"hilda", "POST", "/api/directory/users", `{"username":"nina","email":"nina@example.org"}`, 200},
		{"hilda", "POST", "/api/directory/users", `{"username":"otto","email":"otto@example.org","groups":["users_demo"]}`, 400},
		{"hilda", "POST", "/api/directory/users", `{"username":"otto","email":"otto@example.org","onboarding":"password","generate_password":true}`, 403},
		{"hilda", "POST", "/api/directory/users/bob/invite", `{}`, 403},  // not created by a delegate
		{"hilda", "POST", "/api/directory/users/nina/invite", `{}`, 200}, // hilda created nina; no credentials yet
		{"hilda", "DELETE", "/api/directory/users/bob", `{"confirm":"bob"}`, 403},
		{"hilda", "POST", "/api/directory/users/bob/password", `{"generate":true}`, 403},
		{"hilda", "POST", "/api/directory/groups/users_demo/members", `{"username":"bob"}`, 403},
		{"hilda", "POST", "/api/directory/groups/hr/members", `{"username":"bob"}`, 403},
		{"hilda", "POST", "/api/directory/groups", `{"name":"mine"}`, 403},
		{"bob", "PUT", "/api/directory/users/nina", `{"display_name":"X"}`, 403},
		{"stranger", "POST", "/api/directory/users", `{"username":"zed","email":"zed@example.org"}`, 403},
		{"", "PUT", "/api/directory/users/bob", `{"display_name":"X"}`, 403},
		{"root", "DELETE", "/api/directory/users/nina", `{"confirm":"nina"}`, 200},
	}
	for _, c := range cases {
		if r, b := doAs(t, srv, c.user, c.method, c.path, c.body); r.StatusCode != c.want {
			t.Errorf("%s %s %s = %d (%s), want %d", c.user, c.method, c.path, r.StatusCode, strings.TrimSpace(b), c.want)
		}
	}
	if m := ll.GroupMembers("users_demo"); len(m) != 0 {
		t.Errorf("users_demo = %v", m)
	}
	if m := ll.GroupMembers("hr"); len(m) != 1 {
		t.Errorf("hr = %v", m)
	}
}

func TestPortalApps(t *testing.T) {
	srv, _, _ := newDirServer(t)
	if r, b := doAs(t, srv, "root", "POST", "/api/templates/enable", `{"id":"demo"}`); r.StatusCode != 200 {
		t.Fatalf("enable = %d %s", r.StatusCode, b)
	}
	r, b := doAs(t, srv, "", "GET", "/api/portal/apps", "")
	var doc hub.PortalDocument
	if err := json.Unmarshal([]byte(b), &doc); err != nil || r.StatusCode != 200 {
		t.Fatalf("portal = %d %s", r.StatusCode, b)
	}
	if doc.Version != 1 || len(doc.Apps) != 1 || doc.Apps[0].AccessGroup != "users_demo" || doc.Apps[0].URLs[0].URL != "https://demo.example.org" {
		t.Errorf("portal = %+v", doc)
	}
}
