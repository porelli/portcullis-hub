package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
	"github.com/portcullis/hub/internal/lldap/lldaptest"
	"github.com/portcullis/hub/internal/signin"
)

// helpEnv: the directory routes on both listeners with the Hub's
// sign-in side wired as main wires it; sign_in_help → hr (bob), invite →
// inviters (carol, dana); alice ordinary with a passkey and two
// certificates; ann an administrator.
type helpEnv struct {
	s           *Server
	hub, people *httptest.Server
	ll          *lldaptest.Server
	kc          *kctest.Server
	ca          *signInCertActions
	audit       string
}

func newHelpEnv(t *testing.T) *helpEnv {
	t.Helper()
	s, ll, kc := newDirFixture(t, func(d *directory.Service) {
		d.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	})
	hh, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ph, err := s.PeopleHandler()
	if err != nil {
		t.Fatal(err)
	}
	e := &helpEnv{s: s, hub: httptest.NewServer(hh), people: httptest.NewServer(ph), ll: ll, kc: kc, ca: &signInCertActions{}, audit: s.Directory.Audit.Path}
	t.Cleanup(e.hub.Close)
	t.Cleanup(e.people.Close)
	ll.AddUser("alice", "alice@example.org", "Alice", "")
	ll.AddUser("ann", "ann@example.org", "Ann", "", "lldap_admin")
	ll.AddGroup("hr")
	ll.AddGroup("inviters")
	ll.AddUser("bob", "bob@example.org", "Bob", "", "hr")
	ll.AddUser("carol", "carol@example.org", "Carol", "", "inviters")
	ll.AddUser("dana", "dana@example.org", "Dana", "", "inviters")
	for _, u := range []string{"alice", "ann", "dana", "root"} {
		kc.Import(u, kctest.Credential{ID: "w-" + u, Type: "webauthn-passwordless"})
	}
	h := s.Hub
	h.SetAudit(s.Directory.Audit)
	h.SetPeople(s.Directory)
	h.SetSignInHelp(s.Directory)
	h.SetHistorySources(hub.HistorySources{Audit: s.Directory.RecentMatching})
	later := time.Now().Add(60 * 24 * time.Hour)
	h.SetSignInSources(hub.SignInSources{
		Passkeys: func(context.Context) (map[string][]keycloak.PasskeyCredential, error) {
			return map[string][]keycloak.PasskeyCredential{"alice": {{ID: "k", Type: string(signin.SecurityKey), Label: "YubiKey 5C"}}}, nil
		},
		Certificates: func(context.Context) ([]invite.CertRecord, error) {
			return []invite.CertRecord{
				{User: "alice", Serial: "0a:02", Kind: invite.KindBrowser, NotBefore: time.Now().Add(-time.Hour), NotAfter: later},
				{User: "alice", Serial: "0a:01", Kind: invite.KindYubiKey, NotBefore: time.Now().Add(-time.Hour), NotAfter: later},
				{User: "ann", Serial: "0c:01", Kind: invite.KindBrowser, NotAfter: later},
			}, nil
		},
	})
	if _, err := h.SetMethod(context.Background(), signin.YubiKeyCert, true, directory.Human("root")); err != nil && !strings.Contains(err.Error(), "already") {
		t.Logf("yubikey_cert on: %v", err)
	}
	h.SetFreshAuth(hub.ListenerPeople, &fakeFreshAuth{})
	h.SetFreshAuth(hub.ListenerHub, &fakeFreshAuth{})
	h.SetFreshAuthReadyForTest(true)
	h.SetCertActions(e.ca)
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/sign_in_help", `{"group":"hr"}`, 200)
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/invite", `{"group":"inviters"}`, 200)
	return e
}

// TestHelpScope (D32): bob (sign_in_help) sends alice a setup link,
// removes her passkeys and revokes a certificate (audited "as
// sign_in_help"); never a password or a new certificate; never on
// himself, an administrator or a permission-group member; out of hr
// he's refused at once; carol (invite only) never removes passkeys.
func TestHelpScope(t *testing.T) {
	e := newHelpEnv(t)
	p := e.people
	if b := mustDo(t, p, "bob", "POST", "/api/directory/users/alice/invite", `{}`, 200); !strings.Contains(b, `"invite"`) {
		t.Errorf("invite answer = %s", b)
	}
	mustDo(t, p, "bob", "POST", "/api/directory/users/alice/remove-passkeys", `{"confirm":"alice"}`, 200)
	mustDo(t, p, "bob", "DELETE", "/api/directory/users/alice/certificates/0a:02", ``, 204)
	if !slices.Equal(e.ca.revokes, []string{"alice/0a:02"}) {
		t.Errorf("revokes = %v", e.ca.revokes)
	}
	got := map[string]string{}
	for _, a := range readAudit(t, e.audit) {
		if a.Actor == "bob" && a.Result == "ok" {
			got[a.Action] = a.Detail
		}
	}
	if got["user.invite"] != "as sign_in_help" || got["user.remove_passkeys"] != "new_invite=false; as sign_in_help" || got["cert.revoke"] != "browser 0a:02; as sign_in_help" {
		t.Errorf("audit = %v", got)
	}
	// The help entries are in alice's history.
	var page hub.HistoryPage
	json.Unmarshal([]byte(mustDo(t, p, "root", "GET", "/api/directory/users/alice/signin/history", ``, 200)), &page)
	help := 0
	for _, en := range page.Entries {
		if en.Kind == "help" && en.By == "bob" {
			help++
		}
	}
	if help != 3 {
		t.Errorf("help entries = %d: %+v", help, page.Entries)
	}
	for _, c := range []struct{ user, method, path, body string }{
		{"bob", "POST", "/api/directory/users/alice/password", `{"generate":true,"confirm":"alice"}`},
		{"bob", "POST", "/api/directory/users/alice/certificates", `{"csr":"CSR","code":"c","code_verifier":"v","nonce":"n"}`},
		{"bob", "POST", "/api/directory/users/bob/invite", `{}`},
		{"bob", "DELETE", "/api/directory/users/bob/certificates/0a:02", ``},
		{"bob", "POST", "/api/directory/users/root/remove-passkeys", `{"confirm":"root"}`},
		{"bob", "POST", "/api/directory/users/ann/invite", `{}`},
		{"bob", "DELETE", "/api/directory/users/ann/certificates/0c:01", ``},
		{"bob", "POST", "/api/directory/users/dana/remove-passkeys", `{"confirm":"dana"}`},
		{"bob", "GET", "/api/directory/users/dana/signin", ``},
		{"carol", "POST", "/api/directory/users/alice/remove-passkeys", `{"confirm":"alice"}`},
		{"carol", "DELETE", "/api/directory/users/alice/certificates/0a:01", ``},
		{"carol", "GET", "/api/directory/users/alice/signin", ``},
	} {
		if r, b := doAs(t, p, c.user, c.method, c.path, c.body); r.StatusCode != 403 {
			t.Errorf("%s %s %s = %d %s, want 403", c.user, c.method, c.path, r.StatusCode, b)
		}
	}
	if len(e.ca.issues) != 0 || len(e.ca.revokes) != 1 {
		t.Errorf("enroll called: issues %v revokes %v", e.ca.issues, e.ca.revokes)
	}
	// Out of hr: the next call is refused (fresh snapshot).
	e.ll.RemoveMember("hr", "bob")
	if r, b := doAs(t, p, "bob", "POST", "/api/directory/users/alice/invite", `{}`); r.StatusCode != 403 {
		t.Errorf("removed holder invite = %d %s", r.StatusCode, b)
	}
	if r, b := doAs(t, p, "bob", "DELETE", "/api/directory/users/alice/certificates/0a:01", ``); r.StatusCode != 403 {
		t.Errorf("removed holder revoke = %d %s", r.StatusCode, b)
	}
}

// TestSignInHelpIsGrantable: the existing permission route grants
// sign_in_help; its group becomes a permission group (its members can't
// be targeted by other delegates), and holders see it in their perms.
func TestSignInHelpIsGrantable(t *testing.T) {
	e := newHelpEnv(t)
	b := mustDo(t, e.people, "bob", "GET", "/api/directory/me", ``, 200)
	if !strings.Contains(b, `"perms":["sign_in_help"]`) {
		t.Errorf("bob me = %s", b)
	}
	// carol (invite) can't target bob: hr holds a delegated permission.
	if r, b := doAs(t, e.people, "carol", "POST", "/api/directory/users/bob/invite", `{}`); r.StatusCode != 403 || !strings.Contains(b, "holds a delegated permission") {
		t.Errorf("carol → bob = %d %s", r.StatusCode, b)
	}
	if r, _ := doAs(t, e.hub, "root", "PUT", "/api/directory/permissions/sign_in_helper", `{"group":"hr"}`); r.StatusCode != 400 {
		t.Errorf("unknown permission = %d", r.StatusCode)
	}
}

// TestAdminCertificateTargetsRoutes: the routes answer the Hub's 409s
// (another administrator, the protected names) on both listeners; on
// alice an admin revokes (no "as sign_in_help").
func TestAdminCertificateTargetsRoutes(t *testing.T) {
	e := newHelpEnv(t)
	const adminText = "administrators' certificates are managed from the server: ./portcullis cert revoke <serial>"
	const protText = "this account's certificates are managed from the server: ./portcullis cert revoke <serial>"
	for _, srv := range []*httptest.Server{e.hub, e.people} {
		for u, want := range map[string]string{"ann": adminText, "admin": protText, "portcullis-hub": protText, "portcullis-breakglass": protText} {
			if r, b := doAs(t, srv, "root", "DELETE", "/api/directory/users/"+u+"/certificates/0c:01", ``); r.StatusCode != 409 || strings.TrimSpace(b) != want {
				t.Errorf("revoke %s = %d %s", u, r.StatusCode, b)
			}
			if r, b := doAs(t, srv, "root", "POST", "/api/directory/users/"+u+"/certificates", `{"csr":"CSR","code":"c","code_verifier":"v","nonce":"n"}`); r.StatusCode != 409 || strings.TrimSpace(b) != want {
				t.Errorf("issue %s = %d %s", u, r.StatusCode, b)
			}
		}
	}
	mustDo(t, e.hub, "root", "DELETE", "/api/directory/users/alice/certificates/0a:01", ``, 204)
	if r, _ := doAs(t, e.hub, "root", "DELETE", "/api/directory/users/alice/certificates/0c:01", ``); r.StatusCode != 404 {
		t.Errorf("ann's serial on alice = %d", r.StatusCode)
	}
	b := mustDo(t, e.people, "root", "POST", "/api/directory/users/alice/certificates", `{"csr":"CSR","code":"c","code_verifier":"v","nonce":"n"}`, 200)
	if !strings.Contains(b, `"serial":"99:aa"`) || !slices.Equal(e.ca.issues, []string{"alice"}) {
		t.Errorf("issue = %s (%v)", b, e.ca.issues)
	}
	for _, a := range readAudit(t, e.audit) {
		if a.Actor == "root" && strings.HasPrefix(a.Action, "cert.") && strings.Contains(a.Detail, "sign_in_help") {
			t.Errorf("admin entry %+v", a)
		}
	}
	// enroll's CSR text is passed through (400).
	e.ca.issueErr = &invite.APIError{Status: 400, Message: "the CSR's signature doesn't verify"}
	if r, b := doAs(t, e.people, "root", "POST", "/api/directory/users/alice/certificates", `{"csr":"CSR","code":"c","code_verifier":"v","nonce":"n"}`); r.StatusCode != 400 || strings.TrimSpace(b) != "the CSR's signature doesn't verify" {
		t.Errorf("enroll 400 = %d %s", r.StatusCode, b)
	}
}

// TestAdminTakeoverUnchangedRoutes: another admin's passkeys and
// password still need the typed name, then work.
func TestAdminTakeoverUnchangedRoutes(t *testing.T) {
	e := newHelpEnv(t)
	if r, _ := doAs(t, e.hub, "root", "POST", "/api/directory/users/ann/remove-passkeys", `{"confirm":""}`); r.StatusCode != 400 {
		t.Errorf("untyped = %d", r.StatusCode)
	}
	mustDo(t, e.hub, "root", "POST", "/api/directory/users/ann/remove-passkeys", `{"confirm":"ann"}`, 200)
	if r, _ := doAs(t, e.hub, "root", "POST", "/api/directory/users/ann/password", `{"generate":true}`); r.StatusCode != 400 {
		t.Errorf("password untyped = %d", r.StatusCode)
	}
	mustDo(t, e.hub, "root", "POST", "/api/directory/users/ann/password", `{"generate":true,"confirm":"ann"}`, 200)
}

// TestPersonSignInRoutes: the view (fresh_auth: the listener's own),
// can, and the history route under the same rule; the cursor passes
// through unchanged.
func TestPersonSignInRoutes(t *testing.T) {
	e := newHelpEnv(t)
	var v struct {
		User         string           `json:"user"`
		Certificates []hub.CertRow    `json:"certificates"`
		FreshAuth    *map[string]any  `json:"fresh_auth"`
		Can          map[string]bool  `json:"can"`
		Methods      []map[string]any `json:"methods"`
	}
	json.Unmarshal([]byte(mustDo(t, e.people, "root", "GET", "/api/directory/users/alice/signin", ``, 200)), &v)
	if v.User != "alice" || len(v.Certificates) != 2 || len(v.Methods) != 6 || v.FreshAuth == nil ||
		!v.Can["setup_link"] || !v.Can["remove_passkeys"] || !v.Can["revoke"] || !v.Can["issue"] || !v.Can["password"] {
		t.Errorf("admin view = %+v", v)
	}
	v.Can = nil
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/directory/users/ann/signin", ``, 200)), &v)
	if v.Can["setup_link"] || v.Can["issue"] || v.Can["revoke"] || !v.Can["remove_passkeys"] || !v.Can["password"] {
		t.Errorf("admin on ann can = %v", v.Can)
	}
	v.Can = nil
	json.Unmarshal([]byte(mustDo(t, e.people, "bob", "GET", "/api/directory/users/alice/signin", ``, 200)), &v)
	if !v.Can["setup_link"] || !v.Can["remove_passkeys"] || !v.Can["revoke"] || v.Can["issue"] || v.Can["password"] {
		t.Errorf("holder can = %v", v.Can)
	}
	for _, c := range []struct {
		user, path string
		want       int
	}{
		{"carol", "/api/directory/users/alice/signin", 403}, {"carol", "/api/directory/users/alice/signin/history", 403},
		{"bob", "/api/directory/users/ann/signin/history", 403}, {"root", "/api/directory/users/nobody/signin", 404},
		{"root", "/api/directory/users/alice/signin/history?limit=0", 400}, {"root", "/api/directory/users/alice/signin/history?before=x&before=y", 400},
		{"", "/api/directory/users/alice/signin", 401},
	} {
		if r, b := doAs(t, e.people, c.user, "GET", c.path, ``); r.StatusCode != c.want {
			t.Errorf("%s %s = %d %s, want %d", c.user, c.path, r.StatusCode, b, c.want)
		}
	}
	mustDo(t, e.people, "bob", "GET", "/api/directory/users/alice/signin/history?limit=5", ``, 200)
	// The cursor is the Hub's own: what the Hub answers for alice is what
	// the route answers.
	want, err := e.s.Hub.SignInHistory(context.Background(), "alice", "", 5)
	if err != nil {
		t.Fatal(err)
	}
	var got hub.HistoryPage
	json.Unmarshal([]byte(mustDo(t, e.people, "root", "GET", "/api/directory/users/alice/signin/history?limit=5", ``, 200)), &got)
	if got.Next != want.Next {
		t.Errorf("next = %q, want %q", got.Next, want.Next)
	}
}

// TestHelpToolClasses (D33): the classes and twins; set_permission
// takes sign_in_help; the people tools are listed only to holders (and
// admins) and refused for a target the holder may not help, before any
// confirmation.
func TestHelpToolClasses(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	byScope := map[string]map[string]Tool{ScopeAdmin: {}, ScopePeople: {}}
	for _, sc := range []string{ScopeAdmin, ScopePeople} {
		for _, tl := range e.s.tools(sc) {
			byScope[sc][tl.Name] = tl
		}
	}
	for _, c := range []struct {
		scope, name string
		class       ToolClass
		twin, perm  string
	}{
		{ScopeAdmin, "person_sign_in", ClassRead, "GET /api/directory/users/{username}/signin", ""},
		{ScopeAdmin, "revoke_person_certificate", ClassDestructive, "DELETE /api/directory/users/{username}/certificates/{serial}", ""},
		{ScopeAdmin, "issue_yubikey_certificate", ClassRead, "POST /api/directory/users/{username}/certificates", ""},
		{ScopeAdmin, "remove_passkeys", ClassDestructive, "POST /api/directory/users/{username}/remove-passkeys", ""},
		{ScopeAdmin, "set_permission", ClassDestructive, "PUT /api/directory/permissions/{perm}", ""},
		{ScopePeople, "person_sign_in", ClassRead, "GET /api/directory/users/{username}/signin", directory.PermSignInHelp},
		{ScopePeople, "revoke_person_certificate", ClassDestructive, "DELETE /api/directory/users/{username}/certificates/{serial}", directory.PermSignInHelp},
		{ScopePeople, "remove_passkeys", ClassDestructive, "POST /api/directory/users/{username}/remove-passkeys", directory.PermSignInHelp},
	} {
		tl, ok := byScope[c.scope][c.name]
		if !ok || tl.Class != c.class || tl.Twin != c.twin || tl.Perm != c.perm {
			t.Errorf("%s %s = %v %q %q %q", c.scope, c.name, ok, tl.Class, tl.Twin, tl.Perm)
		}
	}
	if !strings.Contains(byScope[ScopeAdmin]["set_permission"].Description, "sign_in_help") {
		t.Error("set_permission's description doesn't name sign_in_help")
	}
	e.ll.AddGroup("hr")
	e.ll.AddUser("hal", "hal@example.org", "Hal", "", "hr")
	if txt, isErr, _ := e.tool(t, "set_permission", map[string]any{"perm": "sign_in_help", "group": "hr"}); isErr {
		t.Fatalf("set_permission sign_in_help = %s", txt)
	}
	if got := e.list(t, "/mcp/people", "hal", "2025-11-25"); !slices.Contains(got, "revoke_person_certificate") || !slices.Contains(got, "person_sign_in") || !slices.Contains(got, "remove_passkeys") {
		t.Errorf("hal's people tools = %v", got)
	}
	if got := e.list(t, "/mcp/people", "alice", "2025-11-25"); slices.Contains(got, "revoke_person_certificate") {
		t.Errorf("alice's people tools = %v", got)
	}
	// A target hal may not help (root, an administrator): 403 at once.
	if txt, isErr := e.people(t, "hal", "revoke_person_certificate", map[string]any{"username": "root", "serial": "01"}); !isErr || !strings.HasPrefix(txt, "403: ") || strings.Contains(txt, "/confirm/") {
		t.Errorf("hal → root = %s", txt)
	}
	if txt, isErr := e.people(t, "alice", "revoke_person_certificate", map[string]any{"username": "bob", "serial": "01"}); !isErr || !strings.HasPrefix(txt, "403: not allowed: needs sign_in_help") {
		t.Errorf("alice → bob = %s", txt)
	}
	// The handoff names the person's page, never a certificate.
	if txt, isErr, _ := e.tool(t, "issue_yubikey_certificate", map[string]any{"username": "alice"}); isErr || !strings.Contains(txt, "https://people.example.org/#people/alice") || strings.Contains(txt, "BEGIN") {
		t.Errorf("issue handoff = %s", txt)
	}
}
