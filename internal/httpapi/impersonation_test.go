package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/signin"
)

// fakeImpKC is the Keycloak side of the impersonation rules: everyone
// enabled, required actions per user.
type fakeImpKC struct {
	mu       sync.Mutex
	disabled map[string]bool
	actions  map[string][]string
	notices  []string
}

func (f *fakeImpKC) UserEnabled(_ context.Context, u string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.disabled[u], nil
}

func (f *fakeImpKC) RequiredActions(_ context.Context, u string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.actions[u]...), nil
}

func (f *fakeImpKC) RequireImpersonationNotice(_ context.Context, u string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notices = append(f.notices, u)
	return nil
}

// impEnv is helpEnv with the impersonation side wired (security keys
// on, a fake Keycloak).
type impEnv struct {
	*helpEnv
	kc *fakeImpKC
}

func newImpEnv(t *testing.T) *impEnv {
	t.Helper()
	e := newHelpEnv(t)
	if _, err := e.s.Hub.SetMethod(context.Background(), signin.SecurityKey, true, directory.Human("root")); err != nil && !strings.Contains(err.Error(), "already") {
		t.Logf("security_key on: %v", err)
	}
	kc := &fakeImpKC{disabled: map[string]bool{}, actions: map[string][]string{}}
	e.s.Hub.SetImpersonationKeycloak(kc)
	return &impEnv{helpEnv: e, kc: kc}
}

// testJWT is an unsigned token whose payload is claims.
func testJWT(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(claims)) + ".c2ln"
}

// doH is doAs with extra headers.
func doH(t *testing.T, srv *httptest.Server, user, method, path, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ProxySecretHeader, testSecret)
	if user != "" {
		req.Header.Set("X-Forwarded-User", user)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

const startBody = `{"reason":"checking quota","code":"c","code_verifier":"v","nonce":"n"}`

// start starts admin's impersonation of target on srv (want 200) and
// answers the id.
func (e *impEnv) start(t *testing.T, srv *httptest.Server, admin, target string) hub.StartedImpersonation {
	t.Helper()
	r, b := doH(t, srv, admin, "POST", "/api/directory/users/"+target+"/impersonation", startBody,
		map[string]string{"X-Forwarded-Access-Token": testJWT(`{"sid":"sid-` + admin + `"}`)})
	if r.StatusCode != 200 {
		t.Fatalf("start %s as %s = %d %s", admin, target, r.StatusCode, b)
	}
	var out hub.StartedImpersonation
	if err := json.Unmarshal([]byte(b), &out); err != nil || len(out.ID) != 32 {
		t.Fatalf("start = %s", b)
	}
	return out
}

// TestImpersonationRoutesAdminsOnly: anyone but an administrator gets
// 403 on the start, Stop, the list and the switch; the people listener
// has no list or switch.
func TestImpersonationRoutesAdminsOnly(t *testing.T) {
	e := newImpEnv(t)
	tok := map[string]string{"X-Forwarded-Access-Token": testJWT(`{"sid":"s-bob"}`)}
	for _, srv := range []*httptest.Server{e.hub, e.people} {
		for _, who := range []string{"bob", "alice"} {
			if r, b := doH(t, srv, who, "POST", "/api/directory/users/dana/impersonation", startBody, tok); r.StatusCode != 403 {
				t.Errorf("%s start = %d %s, want 403", who, r.StatusCode, b)
			}
			if r, b := doAs(t, srv, who, "POST", "/api/directory/users/dana/impersonation/stop", ``); r.StatusCode != 403 {
				t.Errorf("%s stop = %d %s, want 403", who, r.StatusCode, b)
			}
		}
	}
	for _, who := range []string{"bob", "alice"} {
		if r, _ := doAs(t, e.hub, who, "GET", "/api/impersonations", ""); r.StatusCode != 403 {
			t.Errorf("%s list = %d, want 403", who, r.StatusCode)
		}
		if r, _ := doAs(t, e.hub, who, "PUT", "/api/signin/impersonation", `{"allowed":false}`); r.StatusCode != 403 {
			t.Errorf("%s switch = %d, want 403", who, r.StatusCode)
		}
	}
	if r, _ := doAs(t, e.hub, "", "GET", "/api/impersonations", ""); r.StatusCode != 401 {
		t.Errorf("no user list = %d, want 401", r.StatusCode)
	}
	if r, _ := doAs(t, e.hub, "", "POST", "/api/directory/users/alice/impersonation", startBody); r.StatusCode != 401 {
		t.Errorf("no user start = %d, want 401", r.StatusCode)
	}
	for _, rt := range [][3]string{{"GET", "/api/impersonations", ""}, {"PUT", "/api/signin/impersonation", `{"allowed":false}`}} {
		if r, _ := doAs(t, e.people, "root", rt[0], rt[1], rt[2]); r.StatusCode != 404 {
			t.Errorf("people %s %s = %d, want 404", rt[0], rt[1], r.StatusCode)
		}
	}
	// The administrator: the list, the switch (allowed required), Stop
	// of nobody 404.
	b := mustDo(t, e.hub, "root", "GET", "/api/impersonations", "", 200)
	var v hub.ImpersonationsView
	if json.Unmarshal([]byte(b), &v) != nil || !v.Allowed || v.MaxMinutes != 30 || v.Running == nil || v.Recent == nil {
		t.Errorf("list = %s", b)
	}
	mustDo(t, e.hub, "root", "PUT", "/api/signin/impersonation", `{}`, 400)
	mustDo(t, e.hub, "root", "PUT", "/api/signin/impersonation", `{"allowed":false,"x":1}`, 400)
	b = mustDo(t, e.hub, "root", "PUT", "/api/signin/impersonation", `{"allowed":false}`, 200)
	if json.Unmarshal([]byte(b), &v) != nil || v.Allowed {
		t.Errorf("switch off = %s", b)
	}
	if r, b := doH(t, e.people, "root", "POST", "/api/directory/users/alice/impersonation", startBody, tok); r.StatusCode != 409 || !strings.Contains(b, "switched off (Settings → Sign-in)") {
		t.Errorf("start while off = %d %s", r.StatusCode, b)
	}
	mustDo(t, e.hub, "root", "PUT", "/api/signin/impersonation", `{"allowed":true}`, 200)
	mustDo(t, e.people, "root", "POST", "/api/directory/users/alice/impersonation/stop", ``, 404)
	// Not a username: 400 (Task 6 review M3), on both listeners.
	mustDo(t, e.people, "root", "POST", "/api/directory/users/al%20ice/impersonation/stop", ``, 400)
	mustDo(t, e.hub, "root", "POST", "/api/directory/users/"+strings.Repeat("a", 65)+"/impersonation/stop", ``, 400)
}

// TestStartRouteShape: ≤ 8 KiB (413), unknown fields 400, the sid read
// from the access token (none: 403 "sign in again", F40), then 200 {id,
// next, until} with the record bound to that sid; Stop ends it (204).
func TestStartRouteShape(t *testing.T) {
	e := newImpEnv(t)
	tok := map[string]string{"X-Forwarded-Access-Token": testJWT(`{"sid":"sid-root"}`)}
	big := `{"reason":"` + strings.Repeat("a", 9<<10) + `","code":"c","code_verifier":"v","nonce":"n"}`
	if r, _ := doH(t, e.people, "root", "POST", "/api/directory/users/alice/impersonation", big, tok); r.StatusCode != 413 {
		t.Errorf("9 KiB = %d, want 413", r.StatusCode)
	}
	if r, _ := doH(t, e.people, "root", "POST", "/api/directory/users/alice/impersonation", `{"reason":"checking quota","admin_sid":"x"}`, tok); r.StatusCode != 400 {
		t.Errorf("unknown field = %d, want 400", r.StatusCode)
	}
	// No token (group-gate withheld it), or one without a sid.
	for _, h := range []map[string]string{nil, {"X-Forwarded-Access-Token": testJWT(`{"sub":"x"}`)}} {
		if r, b := doH(t, e.people, "root", "POST", "/api/directory/users/alice/impersonation", startBody, h); r.StatusCode != 403 || strings.TrimSpace(b) != "your sign-in can't be read: sign in again" {
			t.Errorf("no sid %v = %d %q", h, r.StatusCode, b)
		}
	}
	// The Hub listener's route works too (API only, F36).
	out := e.start(t, e.hub, "root", "alice")
	if out.Next != "https://auth.example.org/realms/portcullis/portcullis-impersonate/start?id="+out.ID || out.Until.IsZero() {
		t.Errorf("start = %+v", out)
	}
	running := e.s.Hub.Impersonations().Running
	if len(running) != 1 || running[0].ID != out.ID || running[0].Person != "alice" || running[0].Admin != "root" {
		t.Fatalf("running = %+v", running)
	}
	// One at a time.
	if r, b := doH(t, e.people, "root", "POST", "/api/directory/users/dana/impersonation", startBody, tok); r.StatusCode != 409 || !strings.Contains(b, "you are signed in as alice until") {
		t.Errorf("second start = %d %s", r.StatusCode, b)
	}
	if r, _ := doAs(t, e.people, "ann", "POST", "/api/directory/users/alice/impersonation/stop", ``); r.StatusCode != 204 {
		t.Errorf("stop by ann = %d", r.StatusCode)
	}
	if v := e.s.Hub.Impersonations(); len(v.Running) != 0 || len(v.Recent) != 1 || v.Recent[0].How != hub.ImpStopped {
		t.Errorf("after stop = %+v", v)
	}
	// The sid is the access token's: the proof's sign-in ran in session
	// sid-root, so a token naming another session is refused.
	e.s.Hub.SetFreshAuth(hub.ListenerPeople, &sidFreshAuth{sid: "sid-root"})
	other := map[string]string{"X-Forwarded-Access-Token": testJWT(`{"sid":"sid-other"}`)}
	if r, b := doH(t, e.people, "root", "POST", "/api/directory/users/alice/impersonation", startBody, other); r.StatusCode != 403 || strings.TrimSpace(b) != "a fresh sign-in is required" {
		t.Errorf("another session's token = %d %q", r.StatusCode, b)
	}
	if r, b := doH(t, e.people, "root", "POST", "/api/directory/users/alice/impersonation", startBody, tok); r.StatusCode != 200 {
		t.Errorf("the proof's session = %d %s", r.StatusCode, b)
	}
}

// sidFreshAuth verifies every proof as a security-key touch whose ID
// token's sid is sid.
type sidFreshAuth struct {
	fakeFreshAuth
	sid string
}

func (f *sidFreshAuth) Verify(ctx context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	r, err := f.fakeFreshAuth.Verify(ctx, p, user)
	if r != nil {
		r.SID = f.sid
	}
	return r, err
}

// TestMeImpersonation: only the running id the header names, whose
// person is the caller, is active; another id, another person or an
// ended one answers null. The Hub listener has no such route.
func TestMeImpersonation(t *testing.T) {
	e := newImpEnv(t)
	out := e.start(t, e.people, "root", "alice")
	get := func(user, id string) map[string]any {
		t.Helper()
		h := map[string]string{}
		if id != "" {
			h[ImpersonationHeader] = id
		}
		r, b := doH(t, e.people, user, "GET", "/api/me/impersonation", "", h)
		if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("me = %d %s", r.StatusCode, b)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(b), &v); err != nil {
			t.Fatal(err)
		}
		if _, ok := v["active"]; !ok {
			t.Fatalf("no active key: %s", b)
		}
		return v
	}
	v := get("alice", out.ID)
	a, _ := v["active"].(map[string]any)
	if a == nil || a["person"] != "alice" || a["admin"] != "root" || a["reason"] != "checking quota" ||
		a["stop_url"] != "https://people.example.org/impersonation/stop" || a["until"] != out.Until.UTC().Format("2006-01-02T15:04:05Z") {
		t.Errorf("active = %v", v)
	}
	for _, c := range [][2]string{{"alice", ""}, {"alice", strings.Repeat("0", 32)}, {"dana", out.ID}, {"root", out.ID}} {
		if v := get(c[0], c[1]); v["active"] != nil {
			t.Errorf("%s with %q = %v, want null", c[0], c[1], v)
		}
	}
	mustDo(t, e.hub, "root", "POST", "/api/directory/users/alice/impersonation/stop", ``, 204)
	if v := get("alice", out.ID); v["active"] != nil {
		t.Errorf("ended = %v, want null", v)
	}
	if r, _ := doH(t, e.hub, "alice", "GET", "/api/me/impersonation", "", map[string]string{ImpersonationHeader: out.ID}); r.StatusCode != 404 {
		t.Errorf("hub listener = %d, want 404", r.StatusCode)
	}
}

// TestStopOwnRoute: Stop in the impersonating browser → 200 sign_out,
// no-store, audited with the administrator as actor; then the banner
// read is null and a second Stop 404.
func TestStopOwnRoute(t *testing.T) {
	e := newImpEnv(t)
	out := e.start(t, e.people, "root", "alice")
	h := map[string]string{ImpersonationHeader: out.ID}
	if r, _ := doH(t, e.people, "dana", "POST", "/api/me/impersonation/stop", `{}`, h); r.StatusCode != 404 {
		t.Errorf("another person's stop = %d, want 404", r.StatusCode)
	}
	r, b := doH(t, e.people, "alice", "POST", "/api/me/impersonation/stop", `{}`, h)
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("stop = %d %s %v", r.StatusCode, b, r.Header)
	}
	var so map[string]string
	if json.Unmarshal([]byte(b), &so) != nil || so["sign_out"] != "https://auth.example.org/oauth2/sign_out?rd=https%3A%2F%2Fexample.org%2F" {
		t.Errorf("stop = %s", b)
	}
	if _, b := doH(t, e.people, "alice", "GET", "/api/me/impersonation", "", h); !strings.Contains(b, `"active":null`) {
		t.Errorf("after stop = %s", b)
	}
	if r, _ := doH(t, e.people, "alice", "POST", "/api/me/impersonation/stop", `{}`, h); r.StatusCode != 404 {
		t.Errorf("second stop = %d, want 404", r.StatusCode)
	}
	// CSRF still applies to the one route the read-only rule lets through.
	req, _ := http.NewRequest("POST", e.people.URL+"/api/me/impersonation/stop", strings.NewReader(``))
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set(ImpersonationHeader, out.ID)
	req.Header.Set("Content-Type", "text/plain")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain stop = %v %v", resp, err)
	}
	var ends []directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "impersonation.end" {
			ends = append(ends, a)
		}
	}
	if len(ends) != 1 || ends[0].Actor != "root" || ends[0].Target != "alice" || !strings.HasPrefix(ends[0].Detail, out.ID+" · stopped") {
		t.Errorf("end audit = %+v", ends)
	}
}

// TestPersonSignInCanImpersonate: can.impersonate, impersonate_refusal
// and impersonation (contract §9.7) — an administrator on alice true;
// on an administrator false with the start's text; switched off false
// with D36.1's text; a running one shown to administrators only; a
// sign_in_help holder never can, never sees the record.
func TestPersonSignInCanImpersonate(t *testing.T) {
	e := newImpEnv(t)
	type view struct {
		Can struct {
			Impersonate bool `json:"impersonate"`
		} `json:"can"`
		Impersonation      *hub.ImpersonationView `json:"impersonation"`
		ImpersonateRefusal *string                `json:"impersonate_refusal"`
	}
	get := func(srv *httptest.Server, caller, u string) view {
		t.Helper()
		var v view
		b := mustDo(t, srv, caller, "GET", "/api/directory/users/"+u+"/signin", "", 200)
		if err := json.Unmarshal([]byte(b), &v); err != nil || v.ImpersonateRefusal == nil || !strings.Contains(b, `"impersonation":`) {
			t.Fatalf("view = %s", b)
		}
		return v
	}
	if v := get(e.people, "root", "alice"); !v.Can.Impersonate || *v.ImpersonateRefusal != "" || v.Impersonation != nil {
		t.Errorf("root on alice = %+v", v)
	}
	if v := get(e.people, "root", "ann"); v.Can.Impersonate || *v.ImpersonateRefusal != "administrators can't be signed in as" {
		t.Errorf("root on ann = %+v %q", v, *v.ImpersonateRefusal)
	}
	e.kc.actions["alice"] = []string{"webauthn-register-passwordless"}
	if v := get(e.hub, "root", "alice"); v.Can.Impersonate || *v.ImpersonateRefusal != "alice has an unfinished sign-in step (a setup link?): finish or cancel it first" {
		t.Errorf("unfinished = %q", *v.ImpersonateRefusal)
	}
	e.kc.actions["alice"] = []string{"portcullis-impersonation-notice"}
	mustDo(t, e.hub, "root", "PUT", "/api/signin/impersonation", `{"allowed":false}`, 200)
	if v := get(e.people, "root", "alice"); v.Can.Impersonate || *v.ImpersonateRefusal != "signing in as someone else is switched off (Settings → Sign-in)" {
		t.Errorf("off = %q", *v.ImpersonateRefusal)
	}
	mustDo(t, e.hub, "root", "PUT", "/api/signin/impersonation", `{"allowed":true}`, 200)
	out := e.start(t, e.people, "root", "alice")
	v := get(e.people, "ann", "alice")
	if v.Can.Impersonate || *v.ImpersonateRefusal != "root is signed in as alice right now" || v.Impersonation == nil || v.Impersonation.ID != out.ID || v.Impersonation.Reason != "checking quota" {
		t.Errorf("ann on alice while root runs = %+v %q", v, *v.ImpersonateRefusal)
	}
	if v := get(e.people, "root", "dana"); v.Can.Impersonate || !strings.HasPrefix(*v.ImpersonateRefusal, "you are signed in as alice until ") {
		t.Errorf("root on dana while running = %q", *v.ImpersonateRefusal)
	}
	// The holder: never can, never sees the record or a refusal.
	if v := get(e.people, "bob", "alice"); v.Can.Impersonate || *v.ImpersonateRefusal != "" || v.Impersonation != nil {
		t.Errorf("bob on alice = %+v", v)
	}
}

// TestStopPageReachable: GET /impersonation/stop on the people listener
// is the Stop page (HTML); the Hub listener has none.
func TestStopPageReachable(t *testing.T) {
	e := newImpEnv(t)
	r, b := doAs(t, e.people, "alice", "GET", "/impersonation/stop", "")
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") || !strings.Contains(b, `id="imp-stop"`) || r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("people stop page = %d %q %s", r.StatusCode, r.Header.Get("Content-Type"), b)
	}
	// Impersonated, it is still a read.
	if r, _ := doH(t, e.people, "alice", "GET", "/impersonation/stop", "", map[string]string{ImpersonationHeader: strings.Repeat("a", 32)}); r.StatusCode != 200 {
		t.Errorf("impersonated stop page = %d", r.StatusCode)
	}
	for _, rt := range [][3]string{{"GET", "/impersonation/stop", ""}, {"GET", "/api/me/impersonation", ""}, {"POST", "/api/me/impersonation/stop", `{}`}} {
		if r, _ := doAs(t, e.hub, "alice", rt[0], rt[1], rt[2]); r.StatusCode != 404 {
			t.Errorf("hub %s %s = %d, want 404", rt[0], rt[1], r.StatusCode)
		}
	}
}

// TestCallerSID (F20): the sid of the access token's payload, decoded
// without a signature check; "" for anything else.
func TestCallerSID(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	for _, c := range []struct {
		name string
		hdr  []string
		want string
	}{
		{"sid", []string{testJWT(`{"sid":"s1","sub":"x"}`)}, "s1"},
		{"padded", []string{enc([]byte("{}")) + "." + base64.URLEncoding.EncodeToString([]byte(`{"sid":"s-2"}`)) + ".x"}, "s-2"},
		{"no header", nil, ""},
		{"two headers", []string{testJWT(`{"sid":"a"}`), testJWT(`{"sid":"b"}`)}, ""},
		{"two segments", []string{enc([]byte("{}")) + "." + enc([]byte(`{"sid":"s1"}`))}, ""},
		{"four segments", []string{testJWT(`{"sid":"s1"}`) + ".x"}, ""},
		{"bad base64", []string{"e30.*!*.x"}, ""},
		{"std base64", []string{"e30." + base64.StdEncoding.EncodeToString([]byte(`{"sid":"???>>>"}`)) + ".x"}, ""},
		{"not json", []string{"e30." + enc([]byte(`sid=s1`)) + ".x"}, ""},
		{"sid a number", []string{testJWT(`{"sid":12}`)}, ""},
		{"sid null", []string{testJWT(`{"sid":null}`)}, ""},
		{"no sid", []string{testJWT(`{"sub":"x"}`)}, ""},
		{"array", []string{testJWT(`["sid"]`)}, ""},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		for _, h := range c.hdr {
			r.Header.Add("X-Forwarded-Access-Token", h)
		}
		if got := callerSID(r); got != c.want {
			t.Errorf("%s: callerSID = %q, want %q", c.name, got, c.want)
		}
	}
}
