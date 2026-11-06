package httpapi

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// forgedAIHeaders are what a browser (or anything reaching the Hub or
// people listener) could send to pose as the AI.
var forgedAIHeaders = map[string]string{
	"X-Portcullis-AI-Client":   "portcullis-ai-claude-code",
	"X-Portcullis-AI-Resource": "https://hub.example.org/mcp",
	"X-Portcullis-AI-Via":      "ai",
	"X-Portcullis-Via":         "ai",
}

func auditFileLines(t *testing.T, s *Server) []string {
	t.Helper()
	b, err := os.ReadFile(s.Directory.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func forged(t *testing.T, srv *httptest.Server, method, path, body string) int {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "root")
	for k, v := range forgedAIHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestForgedAIHeadersIgnored (ruling G41, contract §9.5 / §15.7): the hub
// and people listeners never take "via AI" from a request, so a browser
// can't forge it — neither on directory mutations nor on the Hub's own
// audit lines.
func TestForgedAIHeadersIgnored(t *testing.T) {
	s, _, _ := newDirFixture(t, nil)
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.PeopleHandler()
	if err != nil {
		t.Fatal(err)
	}
	hubSrv, peopleSrv := httptest.NewServer(h), httptest.NewServer(p)
	t.Cleanup(hubSrv.Close)
	t.Cleanup(peopleSrv.Close)

	if c := forged(t, hubSrv, "POST", "/api/directory/groups", `{"name":"g1"}`); c != 200 {
		t.Fatalf("hub create group = %d", c)
	}
	if c := forged(t, peopleSrv, "POST", "/api/directory/groups", `{"name":"g2"}`); c != 200 {
		t.Fatalf("people create group = %d", c)
	}
	if c := forged(t, hubSrv, "PUT", "/api/templates/compose/demo", `{"user_override":""}`); c != 200 {
		t.Fatalf("compose override = %d", c)
	}
	// A refused directory mutation (protected account).
	forged(t, hubSrv, "DELETE", "/api/directory/users/admin", `{"confirm":"admin"}`)
	lines := auditFileLines(t, s)
	if len(lines) < 4 {
		t.Fatalf("audit lines = %d: %v", len(lines), lines)
	}
	for _, l := range lines {
		if strings.Contains(l, `"via"`) || strings.Contains(l, `"client"`) || strings.Contains(l, "portcullis-ai") {
			t.Errorf("forged AI attribution in %s", l)
		}
	}
}

// mcpAIHeaderFiles are the only non-test Go files (relative to the repo
// root) allowed to name X-Portcullis-AI-*: the MCP listener (Task 13),
// which takes them from the gate behind the MCP secret and turns them into
// an mcpIdentity.
var mcpAIHeaderFiles = map[string]bool{"internal/httpapi/mcplistener.go": true}

// TestNoAIHeaderReads (G41): no Hub code outside the MCP listener's
// identity seam names an X-Portcullis-AI-* header. Task 13's listener
// file(s) are the only allowed readers (mcpAIHeaderFiles).
func TestNoAIHeaderReads(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if mcpAIHeaderFiles[filepath.ToSlash(rel)] {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(string(b)), "x-portcullis-ai-") {
			t.Errorf("%s names an X-Portcullis-AI-* header: only the MCP listener (mcpAIHeaderFiles) may", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestMCPIdentity: the constructor Task 13's listener uses.
func TestMCPIdentity(t *testing.T) {
	a, err := mcpIdentity(" Root ", " portcullis-ai-claude-code ")
	if err != nil || a != (directory.Actor{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude-code"}) {
		t.Errorf("mcpIdentity = %+v, %v", a, err)
	}
	for _, c := range [][2]string{{"", "c"}, {"root", ""}, {" ", " "}} {
		if _, err := mcpIdentity(c[0], c[1]); err == nil {
			t.Errorf("mcpIdentity(%q, %q) accepted", c[0], c[1])
		}
	}
	// No identity: the person from X-Forwarded-User, never via AI.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-User", "alice")
	for k, v := range forgedAIHeaders {
		r.Header.Set(k, v)
	}
	if got := requestActor(r); got != directory.Human("alice") {
		t.Errorf("requestActor = %+v", got)
	}
	// With the identity: it wins over X-Forwarded-User.
	r = withMCPIdentity(r, a)
	if got := requestActor(r); got != a || actor(r) != "root" {
		t.Errorf("requestActor = %+v, actor = %q", got, actor(r))
	}
}

// TestMCPIdentityAttributes: a request carrying the MCP identity (Task 13
// attaches it on :8890) reaches the same handlers, resolves its Caller
// with the attribution and every audit line — directory and Hub — says
// via ai and the client.
func TestMCPIdentityAttributes(t *testing.T) {
	s, _, _ := newDirFixture(t, nil)
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	a, err := mcpIdentity("root", "portcullis-ai-claude")
	if err != nil {
		t.Fatal(err)
	}
	send := func(method, path, body string) int {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(ProxySecretHeader, testSecret)
		r.Header.Set("X-Forwarded-User", "mallory") // ignored: the identity wins
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withMCPIdentity(r, a))
		return w.Code
	}
	if c := send("POST", "/api/directory/groups", `{"name":"g1"}`); c != 200 {
		t.Fatalf("create group = %d", c)
	}
	if c := send("PUT", "/api/templates/compose/demo", `{"user_override":""}`); c != 200 {
		t.Fatalf("compose override = %d", c)
	}
	lines := auditFileLines(t, s)
	if len(lines) != 2 {
		t.Fatalf("audit = %v", lines)
	}
	for _, l := range lines {
		if !strings.Contains(l, `"actor":"root"`) || !strings.Contains(l, `"via":"ai","client":"portcullis-ai-claude"`) {
			t.Errorf("entry = %s", l)
		}
	}
}

// TestAuditAs: auditAs fills actor, via, client and the result.
func TestAuditAs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	s := &Server{Audit: &directory.AuditLog{Path: p}}
	ai := directory.Actor{User: "root", Via: directory.ViaAI, Client: "c"}
	s.auditAs(ai, directory.AuditEntry{Action: "instance.enable", Target: "x"}, nil)
	s.auditAs(ai, directory.AuditEntry{Action: "instance.enable", Target: "x"}, &hub.StatusError{Status: 409, Err: errors.New("busy")})
	s.auditAs(directory.Human("root"), directory.AuditEntry{Action: "instance.enable", Target: "x"}, errors.New("boom"))
	got, err := s.Audit.Recent(10)
	if err != nil || len(got) != 3 {
		t.Fatalf("Recent = %+v, %v", got, err)
	}
	if got[2].Actor != "root" || got[2].Via != "ai" || got[2].Client != "c" || got[2].Result != "ok" {
		t.Errorf("ok = %+v", got[2])
	}
	if got[1].Result != "refused" || got[1].Via != "ai" || got[1].Error != "busy" {
		t.Errorf("refused = %+v", got[1])
	}
	if got[0].Result != "error" || got[0].Via != "" || got[0].Client != "" {
		t.Errorf("error = %+v", got[0])
	}
}
