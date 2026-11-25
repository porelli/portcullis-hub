package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Verified emails (contract §9.8): the admin route and the self-service
// code routes.

// emailVerified answers user's email_verified in root's people view.
func emailVerified(t *testing.T, e *peopleEnv, user string) bool {
	t.Helper()
	_, b := doAs(t, e.people, "root", "GET", "/api/directory", "")
	var ov struct {
		Users []struct {
			Username      string `json:"username"`
			EmailVerified *bool  `json:"email_verified"`
		} `json:"users"`
	}
	if err := json.Unmarshal([]byte(b), &ov); err != nil {
		t.Fatal(err)
	}
	for _, u := range ov.Users {
		if u.Username == user {
			if u.EmailVerified == nil {
				t.Fatalf("%s has no email_verified: %s", user, b)
			}
			return *u.EmailVerified
		}
	}
	t.Fatalf("%s not listed", user)
	return false
}

func TestMarkEmailVerifiedRoute(t *testing.T) {
	e := newPeopleEnv(t)
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	e.ll.AddUser("carl", "carl@example.org", "Carl", "")
	e.ll.AddUser("nomail", "", "No Mail", "")
	if emailVerified(t, e, "bob") {
		t.Fatal("bob verified before")
	}
	for _, srv := range []string{"people", "hub"} {
		s := e.people
		if srv == "hub" {
			s = e.hub
		}
		r, b := doAs(t, s, "root", "POST", "/api/directory/users/bob/email/verified", "")
		if r.StatusCode != 204 || b != "" {
			t.Fatalf("%s: mark = %d %q", srv, r.StatusCode, b)
		}
	}
	if !emailVerified(t, e, "bob") {
		t.Error("bob not verified")
	}
	audit, _ := os.ReadFile(e.s.Directory.Audit.Path)
	if !strings.Contains(string(audit), `"action":"user.email_verified","target":"bob"`) {
		t.Errorf("audit:\n%s", audit)
	}
	// Without edit_details: 403.
	if r, _ := doAs(t, e.people, "bob", "POST", "/api/directory/users/carl/email/verified", ""); r.StatusCode != 403 {
		t.Errorf("bob on carl = %d", r.StatusCode)
	}
	// Your own: by code only.
	if r, _ := doAs(t, e.people, "root", "POST", "/api/directory/users/root/email/verified", ""); r.StatusCode != 403 {
		t.Errorf("root on root = %d", r.StatusCode)
	}
	// No email: 400, the contract's text.
	if r, b := doAs(t, e.people, "root", "POST", "/api/directory/users/nomail/email/verified", ""); r.StatusCode != 400 || strings.TrimSpace(b) != "this person has no email" {
		t.Errorf("no email = %d %q", r.StatusCode, b)
	}
	if r, _ := doAs(t, e.people, "root", "POST", "/api/directory/users/ghost/email/verified", ""); r.StatusCode != 404 {
		t.Errorf("unknown = %d", r.StatusCode)
	}
	// An admin's PUT that changes the email verifies it; one that keeps
	// it doesn't (ruling C9).
	mustDo(t, e.people, "root", "PUT", "/api/directory/users/carl", `{"email":"carl@example.org","display_name":"Carl C"}`, 200)
	if emailVerified(t, e, "carl") {
		t.Error("an unchanged email was verified by a save")
	}
	mustDo(t, e.people, "root", "PUT", "/api/directory/users/carl", `{"email":"carl.new@example.org"}`, 200)
	if !emailVerified(t, e, "carl") {
		t.Error("an admin-set email isn't verified")
	}
}

var mailCodeRe = regexp.MustCompile(`Your code is ([0-9]{8})\.`)

// codeEnv: the people env with the code flow wired and its mail caught.
type codeEnv struct {
	*peopleEnv
	mu   sync.Mutex
	sent []string // bodies
}

func newCodeEnv(t *testing.T) *codeEnv {
	t.Helper()
	e := &codeEnv{peopleEnv: newPeopleEnv(t)}
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	e.s.Hub.SetEmailVerifier(e.s.Directory)
	e.s.Hub.SetAudit(e.s.Directory.Audit)
	e.s.Hub.SetHubMailSenderForTest(func(_ context.Context, to, _, body string) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.sent = append(e.sent, to+"\n"+body)
		return nil
	})
	return e
}

func (e *codeEnv) code(t *testing.T) string {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.sent) == 0 {
		t.Fatal("no mail")
	}
	m := mailCodeRe.FindStringSubmatch(e.sent[len(e.sent)-1])
	if m == nil {
		t.Fatalf("mail %q", e.sent[len(e.sent)-1])
	}
	return m[1]
}

func TestEmailVerifyRoutes(t *testing.T) {
	e := newCodeEnv(t)
	r, b := doAs(t, e.people, "bob", "POST", "/api/me/email/verify", "")
	var started struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if r.StatusCode != 202 || json.Unmarshal([]byte(b), &started) != nil || time.Until(started.ExpiresAt) < 14*time.Minute {
		t.Fatalf("start = %d %s", r.StatusCode, b)
	}
	if !strings.HasPrefix(e.sent[0], "bob@example.org\n") {
		t.Errorf("sent to %q", e.sent[0])
	}
	code := e.code(t)
	bad := "00000000"
	if code == bad {
		bad = "11111111"
	}
	r, b = doAs(t, e.people, "bob", "POST", "/api/me/email/verify/confirm", `{"code":"`+bad+`"}`)
	if r.StatusCode != 400 || strings.TrimSpace(b) != `{"attempts_left":4}` {
		t.Errorf("wrong = %d %s", r.StatusCode, b)
	}
	if strings.Contains(b, code) {
		t.Error("the code in an answer")
	}
	// Only the signed-in person's own code: root can't use bob's.
	if r, _ := doAs(t, e.people, "root", "POST", "/api/me/email/verify/confirm", `{"code":"`+code+`"}`); r.StatusCode != 410 {
		t.Errorf("root with bob's code = %d", r.StatusCode)
	}
	r, b = doAs(t, e.people, "bob", "POST", "/api/me/email/verify/confirm", `{"code":"`+code+`"}`)
	if r.StatusCode != 200 || strings.TrimSpace(b) != `{"verified":true}` {
		t.Fatalf("right = %d %s", r.StatusCode, b)
	}
	if !emailVerified(t, e.peopleEnv, "bob") {
		t.Error("bob not verified")
	}
	if emailVerified(t, e.peopleEnv, "root") {
		t.Error("root verified")
	}
	r, b = doAs(t, e.people, "bob", "POST", "/api/me/email/verify/confirm", `{"code":"`+code+`"}`)
	if r.StatusCode != 410 || strings.TrimSpace(b) != "this code has expired: ask for a new one" {
		t.Errorf("reuse = %d %q", r.StatusCode, b)
	}
	// Bad bodies.
	if r, _ := doAs(t, e.people, "bob", "POST", "/api/me/email/verify/confirm", `{"code":1}`); r.StatusCode != 400 {
		t.Errorf("bad body = %d", r.StatusCode)
	}
	if r, _ := doAs(t, e.people, "", "POST", "/api/me/email/verify", ""); r.StatusCode != 401 {
		t.Errorf("nobody = %d", r.StatusCode)
	}
	// People listener only.
	if r, _ := doAs(t, e.hub, "root", "POST", "/api/me/email/verify", ""); r.StatusCode != 404 {
		t.Errorf("hub listener = %d", r.StatusCode)
	}
	// The audit names the sends and the verification, never the code.
	audit, _ := os.ReadFile(e.s.Directory.Audit.Path)
	if !strings.Contains(string(audit), `"action":"email.code_sent"`) || !strings.Contains(string(audit), `"action":"email.verified"`) || strings.Contains(string(audit), code) {
		t.Errorf("audit:\n%s", audit)
	}
	// Three sends an hour, then 429.
	for i := 0; i < 2; i++ {
		mustDo(t, e.people, "bob", "POST", "/api/me/email/verify", "", 202)
	}
	if r, b := doAs(t, e.people, "bob", "POST", "/api/me/email/verify", ""); r.StatusCode != 429 || strings.TrimSpace(b) != "too many codes: try again later" {
		t.Errorf("4th = %d %q", r.StatusCode, b)
	}
}

func TestVerifyRefusedImpersonating(t *testing.T) {
	e := newCodeEnv(t)
	for _, path := range []string{"/api/me/email/verify", "/api/me/email/verify/confirm", "/api/directory/users/bob/email/verified"} {
		req := newReq(t, e.people.URL+path, `{"code":"12345678"}`)
		req.Header.Set(ImpersonationHeader, "root")
		r, b := sendReq(t, req)
		if r.StatusCode != 403 || strings.TrimSpace(b) != errWhileImpersonated {
			t.Errorf("%s while impersonating = %d %q", path, r.StatusCode, b)
		}
	}
	if len(e.sent) != 0 {
		t.Error("a code was sent while impersonating")
	}
}

func TestVerifyNoSender(t *testing.T) {
	e := newCodeEnv(t)
	e.s.Hub.SetHubMailSenderForTest(nil) // the real sender: no mail here
	r, b := doAs(t, e.people, "bob", "POST", "/api/me/email/verify", "")
	if r.StatusCode != 409 || strings.TrimSpace(b) != "mail isn't set up on this server" {
		t.Errorf("no sender = %d %q", r.StatusCode, b)
	}
	// Admins can still mark it verified.
	mustDo(t, e.people, "root", "POST", "/api/directory/users/bob/email/verified", "", 204)
}

// newReq is a POST as bob on the people listener (doAs's headers).
func newReq(t *testing.T, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "bob")
	return req
}

func sendReq(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}
