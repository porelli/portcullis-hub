package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/domains"
)

const dnsToken = "dns-SECRET-0123456789abcdefghij"

// fakeDomainsService is core's domains API over HTTP (§12.2). A token
// "reject-…" makes it answer 400 quoting the token (a careless service):
// the Hub must still never echo it.
type fakeDomainsService struct {
	mu     sync.Mutex
	list   map[string]map[string]any
	bodies []string
}

func newFakeDomainsService(t *testing.T, secret string) (*fakeDomainsService, *httptest.Server) {
	f := &fakeDomainsService{list: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /domains", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []map[string]any{}
		for _, d := range f.list {
			out = append(out, d)
		}
		json.NewEncoder(w).Encode(out)
	})
	creds := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		var b struct {
			Provider    string            `json:"provider"`
			Credentials map[string]string `json:"credentials"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		raw, _ := json.Marshal(b)
		f.mu.Lock()
		f.bodies = append(f.bodies, string(raw))
		f.mu.Unlock()
		if tok := b.Credentials["api_token"]; strings.HasPrefix(tok, "reject-") {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "token " + tok + " rejected"})
			return "", false
		}
		return b.Provider, true
	}
	mux.HandleFunc("PUT /domains/{name}", func(w http.ResponseWriter, r *http.Request) {
		p, ok := creds(w, r)
		if !ok {
			return
		}
		d := map[string]any{"name": r.PathValue("name"), "provider": p, "records_ok": false, "cert_not_after": nil, "last_error": "", "state": "pending"}
		f.mu.Lock()
		f.list[r.PathValue("name")] = d
		f.mu.Unlock()
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("POST /domains/{name}/token", func(w http.ResponseWriter, r *http.Request) {
		p, ok := creds(w, r)
		if !ok {
			return
		}
		f.mu.Lock()
		d := f.list[r.PathValue("name")]
		d["provider"] = p
		f.mu.Unlock()
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("DELETE /domains/{name}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		delete(f.list, r.PathValue("name"))
		f.mu.Unlock()
		w.WriteHeader(204)
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

type domainsEnv struct {
	s        *Server
	hub, ppl *httptest.Server
	fake     *fakeDomainsService
	audit    string
	bodies   []string // every Hub answer
}

func newDomainsEnv(t *testing.T) *domainsEnv {
	t.Helper()
	s, ll, _ := newDirFixture(t, func(d *directory.Service) {
		d.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	})
	secret := strings.Repeat("d", 40)
	fake, fsrv := newFakeDomainsService(t, secret)
	sf := filepath.Join(t.TempDir(), "api-secret")
	os.WriteFile(sf, []byte(secret+"\n"), 0600)
	s.Hub.SetDomainsAPI(domains.New(fsrv.URL, sf))
	s.Hub.SetAudit(s.Directory.Audit)
	ll.AddUser("bob", "bob@example.org", "Bob", "")
	ll.AddUser("dana", "dana@example.org", "Dana", "")
	ll.AddGroup("helpers", "dana")
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.PeopleHandler()
	if err != nil {
		t.Fatal(err)
	}
	e := &domainsEnv{s: s, hub: httptest.NewServer(h), ppl: httptest.NewServer(p), fake: fake, audit: s.Directory.Audit.Path}
	t.Cleanup(e.hub.Close)
	t.Cleanup(e.ppl.Close)
	// dana is a delegate (may invite), not an admin.
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/invite", `{"group":"helpers"}`, 200)
	return e
}

func (e *domainsEnv) do(t *testing.T, srv *httptest.Server, user, method, path, body string) (int, string) {
	t.Helper()
	r, b := doAs(t, srv, user, method, path, body)
	e.bodies = append(e.bodies, b)
	return r.StatusCode, b
}

func enrollBody(name, tok string) string {
	return `{"name":"` + name + `","provider":"cloudflare","credentials":{"api_token":"` + tok + `"}}`
}

func TestDomainRoutesAdminOnly(t *testing.T) {
	e := newDomainsEnv(t)
	routes := []struct{ method, path, body string }{
		{"GET", "/api/domains", ""},
		{"POST", "/api/domains", enrollBody("team-b.example.net", dnsToken)},
		{"POST", "/api/domains/team-b.example.net/token", `{"provider":"cloudflare","credentials":{"api_token":"` + dnsToken + `"}}`},
		{"DELETE", "/api/domains/team-b.example.net", ""},
	}
	for _, user := range []string{"bob", "dana", ""} {
		for _, r := range routes {
			if code, b := e.do(t, e.hub, user, r.method, r.path, r.body); code != 403 {
				t.Errorf("%q %s %s = %d %s, want 403", user, r.method, r.path, code, b)
			}
		}
	}
	// Never on the people listener.
	for _, r := range routes {
		if code, _ := e.do(t, e.ppl, "root", r.method, r.path, r.body); code != 404 && code != 405 {
			t.Errorf("people %s %s = %d, want 404", r.method, r.path, code)
		}
	}
	if len(e.fake.bodies) != 0 {
		t.Fatalf("refused requests reached the service: %v", e.fake.bodies)
	}
	// The admin can; each step is audited.
	if code, b := e.do(t, e.hub, "root", "POST", "/api/domains", enrollBody("team-b.example.net", dnsToken)); code != 202 || !strings.Contains(b, `"state":"pending"`) {
		t.Fatalf("enroll = %d %s", code, b)
	}
	code, b := e.do(t, e.hub, "root", "GET", "/api/domains", "")
	var list []domains.Domain
	json.Unmarshal([]byte(b), &list)
	if code != 200 || len(list) != 1 || list[0].Name != "team-b.example.net" {
		t.Fatalf("list = %d %s", code, b)
	}
	if code, b := e.do(t, e.hub, "root", "POST", "/api/domains/team-b.example.net/token", `{"provider":"cloudflare","credentials":{"api_token":"`+dnsToken+`x"}}`); code != 202 {
		t.Fatalf("token = %d %s", code, b)
	}
	if code, b := e.do(t, e.hub, "root", "DELETE", "/api/domains/team-b.example.net", ""); code != 204 {
		t.Fatalf("delete = %d %s", code, b)
	}
	entries := readAudit(t, e.audit)
	var actions []string
	for _, a := range entries {
		if strings.HasPrefix(a.Action, "domain.") {
			actions = append(actions, a.Action+":"+a.Result+":"+a.Actor)
		}
	}
	if strings.Join(actions, ",") != "domain.enroll:ok:root,domain.token:ok:root,domain.delete:ok:root" {
		t.Fatalf("audit %v", actions)
	}
}

func TestTokenNotEchoed(t *testing.T) {
	// Task 17b: over every admin tool's result, too.
	t.Run("admin tools", testToolsNotEchoed)
	e := newDomainsEnv(t)
	// Accepted: the answer carries no credentials.
	code, b := e.do(t, e.hub, "root", "POST", "/api/domains", enrollBody("team-b.example.net", dnsToken))
	if code != 202 {
		t.Fatalf("enroll = %d %s", code, b)
	}
	// Rejected by the service with the token in its message.
	code, b = e.do(t, e.hub, "root", "POST", "/api/domains", enrollBody("team-c.example.net", "reject-"+dnsToken))
	if code != 400 || !strings.Contains(b, "[redacted]") {
		t.Fatalf("rejected enroll = %d %s", code, b)
	}
	// Malformed bodies: fixed messages, never the decoder's (which could quote values).
	for _, body := range []string{`{"name":"x.example.net","provider":"cloudflare","credentials":{"api_token":1}}`,
		`{"name":"x.example.net","provider":"cloudflare","credentials":{"api_token":"` + dnsToken + `"},"extra":"` + dnsToken + `"}`,
		`{"name":"x.example.net","credentials":"` + dnsToken + `"}`} {
		if code, _ := e.do(t, e.hub, "root", "POST", "/api/domains", body); code != 400 {
			t.Fatalf("malformed = %d", code)
		}
	}
	e.do(t, e.hub, "root", "POST", "/api/domains/team-b.example.net/token", `{"provider":"cloudflare","credentials":{"api_token":"reject-`+dnsToken+`"}}`)
	e.do(t, e.hub, "root", "GET", "/api/domains", "")
	for _, b := range e.bodies {
		if strings.Contains(b, dnsToken) {
			t.Errorf("an answer echoes the token: %s", b)
		}
	}
	raw, _ := os.ReadFile(e.audit)
	if strings.Contains(string(raw), dnsToken) {
		t.Error("the token is in the audit log")
	}
	filepath.Walk(filepath.Dir(e.audit), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), dnsToken) {
				t.Errorf("the token is in %s", p)
			}
		}
		return nil
	})
	// It did reach the service, once per request.
	if len(e.fake.bodies) < 3 || !strings.Contains(e.fake.bodies[0], dnsToken) {
		t.Fatalf("service bodies %v", e.fake.bodies)
	}
}

func TestDomainsDisabledSaysWhy(t *testing.T) {
	s, _, _ := newDirFixture(t, nil)
	s.Hub.SetDomainsAPI(domains.New("http://127.0.0.1:1", filepath.Join(t.TempDir(), "missing")))
	h, _ := s.Handler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	r, b := doAs(t, srv, "root", "GET", "/api/domains", "")
	if r.StatusCode != 503 || !strings.Contains(b, "domains disabled") || !strings.Contains(b, `"disabled":true`) {
		t.Fatalf("disabled = %d %s", r.StatusCode, b)
	}
	// Unreachable (secret present, nothing listening): 503 with the known list.
	sf := filepath.Join(t.TempDir(), "s")
	os.WriteFile(sf, []byte(strings.Repeat("x", 40)), 0600)
	s.Hub.SetDomainsAPI(&domains.Client{APIURL: "http://127.0.0.1:1", SecretFile: sf, HTTP: &http.Client{Timeout: time.Second}})
	r, b = doAs(t, srv, "root", "GET", "/api/domains", "")
	if r.StatusCode != 503 || !strings.Contains(b, "unreachable") || !strings.Contains(b, `"domains":[]`) {
		t.Fatalf("unreachable = %d %s", r.StatusCode, b)
	}
}

func readAudit(t *testing.T, path string) []directory.AuditEntry {
	t.Helper()
	raw, _ := os.ReadFile(path)
	var out []directory.AuditEntry
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e directory.AuditEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}
