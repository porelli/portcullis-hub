package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// vault: header-auth, an instance int (env, restart), an env secret and a
// per-person size (data file). plex: an app with its own login.
const setVaultManifest = `name: Vault
category: tools
ai: {unsupported: "test fixture"}
auth:
  method: header-auth
  group_access: true
  access_group: users_vault
  admin_group: admin_vault
files:
  - {name: quota, service: app, mount: /portcullis}
settings:
  options:
    - key: trash_days
      label: Trash days
      type: int
      min: 1
      default: 30
      applies: restart
      delivery: [{env: VAULT_TRASH_DAYS}]
    - key: api_key
      label: API key
      type: secret
      applies: restart
      delivery: [{env: VAULT_API_KEY}]
    - key: storage_quota
      label: Storage quota
      type: size
      scope: person
      default: 10GiB
      resolve: max
      applies: next_sign_in
      delivery: [{file: {name: quota}}]
`

const setVaultCompose = "services:\n  app:\n    image: vault\n    environment:\n      TRASH: ${VAULT_TRASH_DAYS}\n      KEY: ${VAULT_API_KEY}\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.vault.rule: Host(`vault.${PORTCULLIS_DOMAIN}`)\n" +
	"      traefik.http.routers.vault.middlewares: portcullis-auth@docker,portcullis-groups@docker\n"

const setPlexManifest = "name: Plex\nai: {unsupported: test fixture}\nauth:\n  method: custom\n  sso: false\n  native_login: {supported: true, allow_without_gateway: true}\n"

const setPlexCompose = "services:\n  web:\n    image: x\n    labels:\n      traefik.http.routers.plex.rule: Host(`plex.${PORTCULLIS_DOMAIN}`)\n"

// secretValue must never leave the Hub.
const secretValue = "Sup3r-s3cret-API-key-value"

type setEnv struct {
	s     *Server
	hub   *httptest.Server
	ppl   *httptest.Server
	ll    *lldaptest.Server
	audit string
	noDir *httptest.Server // the same Hub without Users & Groups
}

func newSetEnv(t *testing.T) *setEnv {
	t.Helper()
	return newSetEnvWith(t, nil)
}

// newSetEnvWith is newSetEnv with extra templates (id → manifest,
// compose).
func newSetEnvWith(t *testing.T, extra map[string][2]string) *setEnv {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "src")
	tmpls := map[string][2]string{"vault": {setVaultManifest, setVaultCompose}, "plex": {setPlexManifest, setPlexCompose}}
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
	st.Save(filepath.Join(data, "state.yaml"))
	h, err := hub.New(hub.Config{ProjectDir: filepath.Join(root, "project"), ProjectHostDir: "/host/project", DataDir: data, Domain: "example.org"}, nopRunner{}, newFakeEngine(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Init()
	t.Cleanup(h.Wait)
	if h.Template("vault") == nil || h.Template("plex") == nil {
		t.Fatal("fixture templates not loaded (see the log)")
	}
	ll := lldaptest.New(t, "portcullis-hub", "svc-password-0123456789")
	ll.AddUser("root", "root@example.org", "Root", "root-password-1", "lldap_admin")
	ll.AddUser("dana", "dana@example.org", "Dana", "")
	ll.AddUser("bob", "bob@example.org", "Bob", "")
	ll.AddGroup("helpers", "dana")
	ll.AddGroup("users_vault", "root", "bob")
	ll.AddGroup("admin_vault", "root")
	ll.AddGroup("office_milan", "bob")
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
	h.SetPeople(dir)
	s := &Server{Hub: h, Secret: testSecret, Web: web.FS, Directory: dir, Audit: dir.Audit}
	hh, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ph, err := s.PeopleHandler()
	if err != nil {
		t.Fatal(err)
	}
	nd := &Server{Hub: h, Secret: testSecret, Web: web.FS}
	nh, err := nd.Handler()
	if err != nil {
		t.Fatal(err)
	}
	e := &setEnv{s: s, hub: httptest.NewServer(hh), ppl: httptest.NewServer(ph), noDir: httptest.NewServer(nh), ll: ll, audit: dir.Audit.Path}
	t.Cleanup(e.hub.Close)
	t.Cleanup(e.ppl.Close)
	t.Cleanup(e.noDir.Close)
	return e
}

func (e *setEnv) do(t *testing.T, user, method, path, body string) (int, string) {
	t.Helper()
	r, b := doAs(t, e.hub, user, method, path, body)
	return r.StatusCode, b
}

var settingsRoutes = []struct{ method, path, body string }{
	{"GET", "/api/instances/vault/settings", ""},
	{"PUT", "/api/instances/vault/settings", `{"values":{"trash_days":7}}`},
	{"POST", "/api/instances/vault/settings/preview", `{"values":{"trash_days":7}}`},
	{"POST", "/api/instances/vault/settings/retry", `{}`},
}

func TestSettingsRoutesAdminOnly(t *testing.T) {
	e := newSetEnv(t)
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/"+directory.PermEditDetails, `{"group":"helpers"}`, 200)
	for _, user := range []string{"dana", "bob", "nobody"} {
		for _, r := range settingsRoutes {
			if code, b := e.do(t, user, r.method, r.path, r.body); code != 403 {
				t.Errorf("%q %s %s = %d %s, want 403", user, r.method, r.path, code, b)
			}
		}
	}
	for _, r := range settingsRoutes {
		if code, b := e.do(t, "", r.method, r.path, r.body); code != 401 {
			t.Errorf("no user %s %s = %d %s, want 401", r.method, r.path, code, b)
		}
		// Settings need Users & Groups: without it nobody can be checked.
		if resp, b := doAs(t, e.noDir, "root", r.method, r.path, r.body); resp.StatusCode != 503 {
			t.Errorf("no directory %s %s = %d %s, want 503", r.method, r.path, resp.StatusCode, b)
		}
		// Never on the people listener.
		if resp, _ := doAs(t, e.ppl, "root", r.method, r.path, r.body); resp.StatusCode != 404 && resp.StatusCode != 405 {
			t.Errorf("people %s %s = %d, want 404", r.method, r.path, resp.StatusCode)
		}
	}
	for _, a := range readAudit(t, e.audit) {
		if strings.HasPrefix(a.Action, "settings.") {
			t.Errorf("a refused request reached the Hub: %+v", a)
		}
	}
	if code, b := e.do(t, "root", "GET", "/api/instances/vault/settings", ""); code != 200 {
		t.Errorf("admin GET = %d %s", code, b)
	}
	if code, _ := e.do(t, "root", "GET", "/api/instances/missing/settings", ""); code != 404 {
		t.Errorf("unknown instance = %d", code)
	}
}

func TestOldSettingsRouteGone(t *testing.T) {
	e := newSetEnv(t)
	for _, m := range []string{"GET", "PUT"} {
		for _, id := range []string{"x", "vault"} {
			if code, b := e.do(t, "root", m, "/api/templates/settings/"+id, `{}`); code != 404 {
				t.Errorf("%s /api/templates/settings/%s = %d %s, want 404", m, id, code, b)
			}
		}
	}
}

func TestPanelNeverReturnsSecrets(t *testing.T) {
	e := newSetEnv(t)
	code, b := e.do(t, "root", "PUT", "/api/instances/vault/settings", `{"secrets":{"api_key":{"value":"`+secretValue+`"}}}`)
	if code != 200 || strings.Contains(b, secretValue) {
		t.Fatalf("save = %d %s", code, b)
	}
	code, b = e.do(t, "root", "GET", "/api/instances/vault/settings", "")
	if code != 200 || strings.Contains(b, secretValue) {
		t.Fatalf("panel = %d, carries the secret: %v", code, strings.Contains(b, secretValue))
	}
	var p struct {
		Secrets map[string]map[string]any `json:"secrets"`
		Options []map[string]any          `json:"options"`
	}
	if err := json.Unmarshal([]byte(b), &p); err != nil {
		t.Fatal(err)
	}
	if p.Secrets["api_key"]["set"] != true || p.Secrets["api_key"]["updated_at"] == nil || len(p.Options) != 3 {
		t.Errorf("panel = %s", b)
	}
	// A body that doesn't decode never echoes the secret.
	for _, bad := range []string{
		`{"secrets":{"api_key":{"value":"` + secretValue + `","extra":1}}}`,
		`{"secrets":{"api_key":{"value":` + secretValue + `}}}`,
		`{"secrets":{"api_key":{"value":"` + secretValue + `"}}} trailing`,
		`{"secrets":{"api_key":"` + secretValue + `"}}`,
	} {
		for _, path := range []string{"/api/instances/vault/settings", "/api/instances/vault/settings/preview"} {
			method := "PUT"
			if strings.HasSuffix(path, "preview") {
				method = "POST"
			}
			if code, b := e.do(t, "root", method, path, bad); code != 400 || strings.Contains(b, secretValue) || strings.Contains(b, "Sup3r") {
				t.Errorf("%s %s = %d %q", method, path, code, b)
			}
		}
	}
	// A refused secret value names the option, never the value.
	if code, b := e.do(t, "root", "PUT", "/api/instances/vault/settings", `{"secrets":{"api_key":{"value":"it's-`+secretValue+`"}}}`); code != 400 || strings.Contains(b, secretValue) || !strings.Contains(b, "api_key") {
		t.Errorf("refused secret = %d %q", code, b)
	}
	for _, a := range readAudit(t, e.audit) {
		if strings.Contains(a.Detail+a.Error, secretValue) {
			t.Errorf("audit carries the secret: %+v", a)
		}
	}
}

func TestPreviewRoute(t *testing.T) {
	e := newSetEnv(t)
	code, b := e.do(t, "root", "POST", "/api/instances/vault/settings/preview", `{"person":{"storage_quota":{"default":"10GiB","rows":[{"group":"office_milan","value":"2TiB"}]}}}`)
	if code != 200 {
		t.Fatalf("preview = %d %s", code, b)
	}
	var p hub.Preview
	if err := json.Unmarshal([]byte(b), &p); err != nil {
		t.Fatal(err)
	}
	op := p.Options["storage_quota"]
	if p.Effect != "none" || op.Changes != 1 || len(op.People) != 2 {
		t.Errorf("preview = %s", b)
	}
	code, b = e.do(t, "root", "GET", "/api/instances/vault/settings", "")
	var panel hub.SettingsPanel
	if err := json.Unmarshal([]byte(b), &panel); code != 200 || err != nil {
		t.Fatalf("panel = %d %v", code, err)
	}
	for _, r := range panel.Person["storage_quota"].Rows {
		if r.Group == "office_milan" {
			t.Errorf("the preview stored the row: %+v", panel.Person)
		}
	}
	if p.Population.Count != 2 {
		t.Errorf("preview population = %+v", p.Population)
	}
}

func TestPutAnswersSaveResult(t *testing.T) {
	e := newSetEnv(t)
	opOK(t, e.hub, "POST", "/api/templates/enable", `{"id":"vault"}`)
	code, b := e.do(t, "root", "PUT", "/api/instances/vault/settings", `{"values":{"trash_days":7},"ports":{}}`)
	if code != 200 {
		t.Fatalf("save = %d %s", code, b)
	}
	var res map[string]json.RawMessage
	if err := json.Unmarshal([]byte(b), &res); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"effect", "changed", "deliveries"} {
		if _, ok := res[k]; !ok {
			t.Errorf("answer %s lacks %q", b, k)
		}
	}
	if string(res["effect"]) != `"restart"` || string(res["changed"]) != `["trash_days"]` {
		t.Errorf("answer = %s", b)
	}
	// The answer's warnings key, when there are warnings.
	code, b = e.do(t, "root", "PUT", "/api/instances/vault/settings", `{"person":{"storage_quota":{"default":"10GiB","rows":[{"group":"office_milan","value":"1TiB"}]}}}`)
	if code != 200 {
		t.Fatalf("person save = %d %s", code, b)
	}
	// A 400 names the option.
	if code, b := e.do(t, "root", "PUT", "/api/instances/vault/settings", `{"values":{"trash_days":0}}`); code != 400 || !strings.Contains(b, "trash_days") {
		t.Errorf("bad value = %d %s", code, b)
	}
	// Unknown body fields (also the old flat form) are refused.
	for _, bad := range []string{`{"trash_days":7}`, `{"values":{},"bogus":1}`, `{"person":{"storage_quota":{"default":"1GiB","rule":"max"}}}`} {
		if code, b := e.do(t, "root", "PUT", "/api/instances/vault/settings", bad); code != 400 {
			t.Errorf("%s = %d %s", bad, code, b)
		}
	}
	big := `{"values":{"trash_days":7},"ports":{"X":"` + strings.Repeat("1", 256<<10) + `"}}`
	if code, _ := e.do(t, "root", "PUT", "/api/instances/vault/settings", big); code != 400 {
		t.Errorf("oversized body = %d", code)
	}
	if code, _ := e.do(t, "root", "PUT", "/api/instances/vault/settings", `{"public_access":1}`); code != 400 {
		t.Errorf("public_access 1 = %d", code)
	}

	// P27: a sign-in mode change is audited as app.sign_in, refusals too.
	put := func(body string) int {
		code, _ := e.do(t, "root", "PUT", "/api/instances/plex/settings", body)
		return code
	}
	if c := put(`{"sign_in":"native"}`); c != 200 {
		t.Fatalf("native = %d", c)
	}
	if c := put(`{"sign_in":"native"}`); c != 200 { // unchanged: not audited
		t.Fatalf("native again = %d", c)
	}
	if c := put(`{"sign_in":"gateway","auth_policy":{"factors":["password"]}}`); c != 400 {
		t.Fatalf("refused = %d", c)
	}
	var signIn []directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "app.sign_in" {
			signIn = append(signIn, a)
		}
	}
	if len(signIn) != 2 || signIn[0].Actor != "root" || signIn[0].Target != "plex" || signIn[0].Result != "ok" ||
		!strings.Contains(signIn[0].Detail, "gateway -> native") || signIn[1].Result != "refused" {
		t.Errorf("app.sign_in audit = %+v", signIn)
	}
}

func TestRetryAudited(t *testing.T) {
	e := newSetEnv(t)
	code, b := e.do(t, "root", "POST", "/api/instances/vault/settings/retry", ``)
	if code != 200 || !strings.Contains(b, `"instance":"vault"`) {
		t.Fatalf("retry = %d %s", code, b)
	}
	var got []directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "settings.retry" {
			got = append(got, a)
		}
	}
	if len(got) != 1 || got[0].Actor != "root" || got[0].Target != "vault" {
		t.Errorf("audit = %+v", got)
	}
}

// Expert Save Env: posting every variable back is fine; a changed
// option-owned value is still a 400.
func TestExpertEnvPostsEverything(t *testing.T) {
	e := newSetEnv(t)
	if code, b := e.do(t, "root", "PUT", "/api/instances/vault/settings", `{"values":{"trash_days":9},"secrets":{"api_key":{"value":"`+secretValue+`"}}}`); code != 200 {
		t.Fatalf("save = %d %s", code, b)
	}
	code, b := e.do(t, "root", "GET", "/api/templates/env/vault", "")
	if code != 200 || strings.Contains(b, secretValue) {
		t.Fatalf("env = %d %s", code, b)
	}
	var env struct {
		Variables map[string]string `json:"variables"`
	}
	json.Unmarshal([]byte(b), &env)
	env.Variables["MY_VAR"] = "1"
	body, _ := json.Marshal(env.Variables)
	if code, b := e.do(t, "root", "PUT", "/api/templates/env/vault", string(body)); code != 200 {
		t.Fatalf("post everything back = %d %s", code, b)
	}
	env.Variables["VAULT_TRASH_DAYS"] = "3"
	body, _ = json.Marshal(env.Variables)
	if code, b := e.do(t, "root", "PUT", "/api/templates/env/vault", string(body)); code != 400 || !strings.Contains(b, "trash_days") {
		t.Errorf("changed owned variable = %d %s", code, b)
	}
}
