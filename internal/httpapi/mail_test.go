package httpapi

import (
	"context"
	"encoding/json"
	"slices"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/mailctl/mailctltest"
)

// mailHelpEnv: newHelpEnv (bob holds sign_in_help, ann and root are
// administrators) with alice and bob in mail_users, core mail on and the
// fake mailctl wired; alice has one mail password.
func mailHelpEnv(t *testing.T) (*helpEnv, *mailctltest.Server, string) {
	t.Helper()
	e := newHelpEnv(t)
	e.ll.AddGroup("mail_users", "alice", "bob")
	mc := mailctltest.New(t)
	h := e.s.Hub
	h.SetMailAPI(mc.Client())
	h.SetMailCoreForTest(true, "mail.example.org")
	h.SyncMailForTest(context.Background())
	r, b := doAs(t, e.people, "alice", "POST", "/api/me/mail/passwords", `{"label":"phone","expiry":"none","code":"c","code_verifier":"v","nonce":"n"}`)
	if r.StatusCode != 201 {
		t.Fatalf("create %d %s", r.StatusCode, b)
	}
	_, after, _ := strings.Cut(b, `"id":"`)
	id, _, _ := strings.Cut(after, `"`)
	return e, mc, id
}

// TestMailRoutesAdminOnly: the admin mail routes are 403 for everyone
// but administrators and 404 on the people listener; a sign_in_help
// holder may read a person's mail (aliases []) and revoke a password,
// never set aliases; someone else gets 403.
func TestMailRoutesAdminOnly(t *testing.T) {
	e, mc, id := mailHelpEnv(t)
	admin := [][3]string{
		{"GET", "/api/mail/settings", ""}, {"PUT", "/api/mail/settings", `{}`}, {"GET", "/api/mail/status", ""}, {"GET", "/api/mail/checks", ""},
		{"PUT", "/api/mail/domains/example.org", `{"enabled":true,"groups":[]}`}, {"PUT", "/api/directory/groups/hr/mail-list", `{"enabled":false,"domain":"","posting":""}`},
		{"POST", "/api/mail/actions/dkim-rotate", `{"domain":"example.org"}`},
	}
	for _, rt := range admin {
		if r, _ := doAs(t, e.hub, "bob", rt[0], rt[1], rt[2]); r.StatusCode != 403 {
			t.Errorf("holder %s %s = %d", rt[0], rt[1], r.StatusCode)
		}
		if r, _ := doAs(t, e.people, "root", rt[0], rt[1], rt[2]); r.StatusCode != 404 {
			t.Errorf("people listener %s %s = %d", rt[0], rt[1], r.StatusCode)
		}
	}
	if r, b := doAs(t, e.hub, "ann", "GET", "/api/mail/settings", ""); r.StatusCode != 200 || !strings.Contains(b, `"mail":"on"`) {
		t.Fatalf("admin settings %d %s", r.StatusCode, b)
	}
	if r, b := doAs(t, e.hub, "ann", "PUT", "/api/directory/users/alice/mail", `{"aliases":["sales@example.org"]}`); r.StatusCode != 200 || !strings.Contains(b, "sales@example.org") {
		t.Fatalf("admin aliases %d %s", r.StatusCode, b)
	}
	// The holder: GET (aliases []) and DELETE on both listeners; never PUT.
	r, b := doAs(t, e.people, "bob", "GET", "/api/directory/users/alice/mail", "")
	if r.StatusCode != 200 || !strings.Contains(b, `"aliases":[]`) || !strings.Contains(b, `"label":"phone"`) || strings.Contains(b, "mailpw-") {
		t.Fatalf("holder read %d %s", r.StatusCode, b)
	}
	if r, _ := doAs(t, e.people, "bob", "PUT", "/api/directory/users/alice/mail", `{"aliases":[]}`); r.StatusCode != 403 {
		t.Fatalf("holder PUT %d", r.StatusCode)
	}
	if r, _ := doAs(t, e.people, "carol", "GET", "/api/directory/users/alice/mail", ""); r.StatusCode != 403 {
		t.Fatalf("someone else %d", r.StatusCode)
	}
	if r, b := doAs(t, e.people, "bob", "DELETE", "/api/directory/users/alice/mail/passwords/"+id, ""); r.StatusCode != 204 {
		t.Fatalf("holder revoke %d %s", r.StatusCode, b)
	}
	e.s.Hub.Wait()
	if len(mc.Creds("alice")) != 0 {
		t.Fatal("not revoked")
	}
	// Status: never a credential.
	if r, b := doAs(t, e.hub, "ann", "GET", "/api/mail/status", ""); r.StatusCode != 200 || !strings.Contains(b, `"reachable":true`) || strings.Contains(b, "mailpw-") {
		t.Fatalf("status %d %s", r.StatusCode, b)
	}
}

// TestHostMailDrain: POST /host/mail/drain → 202, every mail domain
// draining (audited, actor host); GET /host/mail/domains; neither on a
// TCP listener.
func TestHostMailDrain(t *testing.T) {
	e, _, _ := mailHelpEnv(t)
	for _, srv := range []string{"hub", "people"} {
		s := e.hub
		if srv == "people" {
			s = e.people
		}
		for _, rt := range [][2]string{{"POST", "/host/mail/drain"}, {"GET", "/host/mail/domains"}} {
			if r, _ := doAs(t, s, "root", rt[0], rt[1], ""); r.StatusCode != 404 {
				t.Errorf("%s %s %s = %d", srv, rt[0], rt[1], r.StatusCode)
			}
		}
	}
	dir, _ := os.MkdirTemp("", "hm")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "h.sock")
	l, err := ListenHost(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: HostHandler(e.s.Hub)}
	go srv.Serve(l)
	defer srv.Close()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	get := func() string {
		resp, err := c.Get("http://hub/host/mail/domains")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(b))
	}
	if got := get(); got != `[{"name":"example.org","state":"on"}]` {
		t.Fatalf("domains %s", got)
	}
	resp, err := c.Post("http://hub/host/mail/drain", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 202 || !strings.Contains(string(b), `{"domains":[{"name":"example.org","state":"draining"}]}`) {
		t.Fatalf("drain %d %s", resp.StatusCode, b)
	}
	if got := get(); got != `[{"name":"example.org","state":"draining"}]` {
		t.Fatalf("after %s", got)
	}
	found := false
	for _, a := range readAudit(t, e.audit) {
		found = found || (a.Action == "mail.domain" && a.Actor == "host")
	}
	if !found {
		t.Fatal("no mail.domain audit by host")
	}
}

// TestMailStatusToolTwin: mail_status is the one mail tool: class R,
// admin scope, twin GET /api/mail/status, no arguments; it answers the
// route's JSON (never a credential).
func TestMailStatusToolTwin(t *testing.T) {
	e, _, _ := mailHelpEnv(t)
	e.s.registerMCPTools()
	var found []Tool
	for _, scope := range []string{ScopeAdmin, ScopePeople} {
		for _, tl := range e.s.tools(scope) {
			if strings.Contains(tl.Name, "mail") {
				found = append(found, tl)
			}
		}
	}
	if len(found) != 1 || found[0].Name != "mail_status" || found[0].Class != ClassRead || found[0].Scope != ScopeAdmin || found[0].Twin != "GET /api/mail/status" {
		t.Fatalf("mail tools %+v", found)
	}
	out, err := found[0].Run(context.Background(), nil, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	_, route := doAs(t, e.hub, "ann", "GET", "/api/mail/status", "")
	if strings.TrimSpace(string(b)) != strings.TrimSpace(route) || strings.Contains(string(b), "mailpw-") {
		t.Fatalf("tool %s\nroute %s", b, route)
	}
}

// TestNoMailCredentialTool: no tool on any scope has a mail-password
// route as twin, and every such route is listed with "credentials: never
// through MCP".
func TestNoMailCredentialTool(t *testing.T) {
	e, _, _ := mailHelpEnv(t)
	e.s.registerMCPTools()
	creds := []string{"GET /api/me/mail", "POST /api/me/mail/passwords", "DELETE /api/me/mail/passwords/{id}",
		"GET /api/directory/users/{username}/mail", "DELETE /api/directory/users/{username}/mail/passwords/{id}"}
	for _, scope := range []string{ScopeAdmin, ScopePeople} {
		for _, tl := range e.s.tools(scope) {
			for _, r := range append([]string{tl.Twin}, tl.AlsoTwins...) {
				if slices.Contains(creds, r) {
					t.Errorf("tool %s mirrors %s", tl.Name, r)
				}
			}
		}
	}
	for _, r := range creds {
		why := mailNoToolRoutes[r]
		if why == "" {
			why = signInNoToolRoutes[r]
		}
		if why != "credentials: never through MCP" {
			t.Errorf("%s: reason %q", r, why)
		}
	}
}
