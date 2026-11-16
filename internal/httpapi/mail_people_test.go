package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/mailctl/mailctltest"
)

// mailEnv: signInEnv with alice and bob in mail_users, core mail on, the
// fake mailctl wired and the first document accepted.
func mailEnv(t *testing.T) (*toolEnv, *mailctltest.Server) {
	t.Helper()
	e, _ := signInEnv(t)
	e.ll.AddGroup("mail_users", "alice", "bob")
	mc := mailctltest.New(t)
	h := e.s.Hub
	h.SetMailAPI(mc.Client())
	h.SetMailCoreForTest(true, "mail.example.org")
	h.SyncMailForTest(context.Background())
	if mc.Puts() != 1 {
		t.Fatalf("no first document: %v", mc.Requests)
	}
	return e, mc
}

// TestNoStoreHeader: the create answer is 201 no-store / no-cache with
// {id, password, mobileconfig_b64}, the buffer zeroed after the write,
// nothing of it in the audit.
func TestNoStoreHeader(t *testing.T) {
	e, mc := mailEnv(t)
	var zeroed [][]byte
	orig := zeroPassword
	zeroPassword = func(b []byte) { orig(b); zeroed = append(zeroed, b) }
	t.Cleanup(func() { zeroPassword = orig })
	r, b := doAs(t, e.ppl, "Alice", "POST", "/api/me/mail/passwords", `{"label":"iPhone","expiry":"90d","code":"c","code_verifier":"v","nonce":"n"}`)
	if r.StatusCode != 201 || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("create = %d %v %s", r.StatusCode, r.Header, b)
	}
	var v struct {
		ID, Password    string
		MobileconfigB64 string `json:"mobileconfig_b64"`
	}
	dec := json.NewDecoder(strings.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	prof, _ := base64.StdEncoding.DecodeString(v.MobileconfigB64)
	if v.ID == "" || len(mc.Created) != 1 || v.Password != mc.Created[0] || !strings.Contains(string(prof), v.Password) || !strings.Contains(string(prof), "com.apple.mail.managed") {
		t.Fatalf("answer %+v", v)
	}
	if len(zeroed) < 2 {
		t.Fatal("the answer buffers weren't zeroed")
	}
	for _, z := range zeroed {
		if strings.Trim(string(z), "\x00") != "" {
			t.Fatal("a buffer wasn't zeroed")
		}
	}
	for _, a := range readAudit(t, e.audit) {
		if strings.Contains(a.Detail+a.Error, v.Password) {
			t.Errorf("audit holds the password: %+v", a)
		}
	}
	// The view lists it, never a secret.
	r, b = doAs(t, e.ppl, "alice", "GET", "/api/me/mail", "")
	if r.StatusCode != 200 || strings.Contains(b, v.Password) || !strings.Contains(b, `"label":"iPhone"`) || !strings.Contains(b, `"username":"alice@example.org"`) {
		t.Fatalf("view = %d %s", r.StatusCode, b)
	}
	// Revoke: 204, then gone.
	if r, b := doAs(t, e.ppl, "alice", "DELETE", "/api/me/mail/passwords/"+v.ID, ""); r.StatusCode != 204 {
		t.Fatalf("revoke = %d %s", r.StatusCode, b)
	}
	e.s.Hub.Wait()
	if len(mc.Creds("alice")) != 0 {
		t.Fatal("not revoked in mailctl")
	}
	// Strict body and the flat proof only.
	for _, body := range []string{`{"label":"x","expiry":"none","proof":{"code":"c"}}`, `{"label":"x","expiry":"none","user":"bob"}`, `{"label":"` + strings.Repeat("a", 9<<10) + `"}`} {
		if r, _ := doAs(t, e.ppl, "alice", "POST", "/api/me/mail/passwords", body); r.StatusCode != 400 && r.StatusCode != 413 {
			t.Errorf("%.40s… = %d", body, r.StatusCode)
		}
	}
}

// TestMailPeopleRoutes: caller only (401 without one), people listener
// only (404 on the Hub listener), the shared 404 for non-members.
func TestMailPeopleRoutes(t *testing.T) {
	e, _ := mailEnv(t)
	routes := [][3]string{{"GET", "/api/me/mail", ""}, {"POST", "/api/me/mail/passwords", `{}`}, {"DELETE", "/api/me/mail/passwords/x", ""}}
	for _, rt := range routes {
		if r, _ := doAs(t, e.ppl, "", rt[0], rt[1], rt[2]); r.StatusCode != 401 {
			t.Errorf("no caller %s %s = %d", rt[0], rt[1], r.StatusCode)
		}
		if r, _ := doAs(t, e.hub, "root", rt[0], rt[1], rt[2]); r.StatusCode != 404 {
			t.Errorf("hub listener %s %s = %d", rt[0], rt[1], r.StatusCode)
		}
	}
	r1, b1 := doAs(t, e.ppl, "root", "GET", "/api/me/mail", "")
	r2, b2 := doAs(t, e.ppl, "nobody", "GET", "/api/me/mail", "")
	if r1.StatusCode != 404 || r2.StatusCode != 404 || b1 != b2 {
		t.Errorf("non-members: %d %q / %d %q", r1.StatusCode, b1, r2.StatusCode, b2)
	}
}

// TestNoAdminCreateRoute: no route on either listener creates a mail
// password for someone else.
func TestNoAdminCreateRoute(t *testing.T) {
	e, _ := mailEnv(t)
	for _, mux := range [][]string{e.s.hubMux().patterns, e.s.peopleMux().patterns} {
		for _, p := range mux {
			method, path, _ := strings.Cut(p, " ")
			if method == "POST" && strings.Contains(path, "mail") && path != "/api/me/mail/passwords" && !strings.HasPrefix(path, "/api/mail/actions/") && path != "/api/mail/confirm-removal" {
				t.Errorf("a POST route creates mail credentials: %s", p)
			}
			if strings.Contains(path, "/mail/passwords") && method == "POST" && strings.Contains(path, "{") {
				t.Errorf("a create route takes a parameter: %s", p)
			}
		}
	}
}
