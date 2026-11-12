package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSecret = "0123456789abcdef0123456789abcdef-test"

func TestCheckSecret(t *testing.T) {
	if CheckSecret("") == nil || CheckSecret(strings.Repeat("x", MinSecretLen-1)) == nil {
		t.Error("weak secret accepted")
	}
	if err := CheckSecret(strings.Repeat("x", MinSecretLen)); err != nil {
		t.Error(err)
	}
}

func TestProxySecret(t *testing.T) {
	var sawHeader string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get(ProxySecretHeader)
		w.WriteHeader(204)
	})
	h := ProxySecret(testSecret, inner)
	cases := []struct {
		name    string
		method  string
		path    string
		headers []string
		want    int
	}{
		{"healthz without secret", "GET", "/healthz", nil, 204},
		{"healthz HEAD", "HEAD", "/healthz", nil, 204},
		{"healthz POST needs secret", "POST", "/healthz", nil, 401},
		{"healthz lookalike", "GET", "/healthz/", nil, 401},
		{"healthz lookalike 2", "GET", "/healthzx", nil, 401},
		{"missing", "GET", "/api/templates", nil, 401},
		{"empty", "GET", "/api/templates", []string{""}, 403},
		{"wrong", "GET", "/api/templates", []string{"nope"}, 403},
		{"prefix of secret", "GET", "/", []string{testSecret[:20]}, 403},
		{"secret plus suffix", "GET", "/", []string{testSecret + "x"}, 403},
		{"duplicated header", "GET", "/", []string{testSecret, testSecret}, 403},
		{"wrong then right", "GET", "/", []string{"x", testSecret}, 403},
		{"correct", "GET", "/api/templates", []string{testSecret}, 204},
		{"correct POST", "POST", "/api/templates/enable", []string{testSecret}, 204},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		for _, v := range c.headers {
			req.Header.Add(ProxySecretHeader, v)
		}
		rec := httptest.NewRecorder()
		sawHeader = ""
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
		if rec.Code == 204 && sawHeader != "" {
			t.Errorf("%s: secret header passed to handler", c.name)
		}
		if rec.Code >= 400 && strings.Contains(rec.Body.String(), testSecret) {
			t.Errorf("%s: secret echoed", c.name)
		}
	}
}

func TestCSRF(t *testing.T) {
	h := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	cases := []struct {
		name, method, ctype, fetchSite, origin string
		want                                   int
	}{
		{"get", "GET", "", "cross-site", "", 204},
		{"json same-origin", "POST", "application/json", "same-origin", "", 204},
		{"json charset", "PUT", "application/json; charset=utf-8", "same-origin", "", 204},
		{"json no fetch metadata", "POST", "application/json", "", "", 204},
		{"form post", "POST", "application/x-www-form-urlencoded", "same-origin", "", 415},
		{"text/plain post", "POST", "text/plain", "same-origin", "", 415},
		{"no content type", "DELETE", "", "same-origin", "", 415},
		{"cross-site json", "POST", "application/json", "cross-site", "", 403},
		{"same-site sibling app", "POST", "application/json", "same-site", "", 403},
		{"foreign origin", "PUT", "application/json", "", "https://evil.example.org", 403},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "https://hub.example.org/api/x", strings.NewReader("{}"))
		if c.ctype != "" {
			req.Header.Set("Content-Type", c.ctype)
		}
		if c.fetchSite != "" {
			req.Header.Set("Sec-Fetch-Site", c.fetchSite)
		}
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
	}
}

// TestRefuseWhileImpersonated (D42, contract §5.1, Review Focus 4):
// with X-Forwarded-Impersonation every request but GET / HEAD is 403
// with the fixed text on both listeners, the own Stop excepted; reads
// work; without the header nothing changes.
func TestRefuseWhileImpersonated(t *testing.T) {
	e := newImpEnv(t)
	const want = "not while you are signed in as someone else: Stop first"
	id := strings.Repeat("ab", 16)
	imp := map[string]string{ImpersonationHeader: id}
	writes := []struct {
		srv          *httptest.Server
		method, path string
		body         string
	}{
		{e.people, "PUT", "/api/me/signin/password", `{"password":"x","code":"c","code_verifier":"v","nonce":"n"}`},
		{e.people, "POST", "/api/me/signin/browser-certificates", `{}`},
		{e.people, "DELETE", "/api/me/signin/certificates/0a:02", ``},
		{e.people, "DELETE", "/api/me/ai/connections/x", ``},
		{e.people, "PUT", "/api/me/apps/i/values/k", `{"value":"v"}`},
		{e.people, "POST", "/api/me/apps/i/credentials/k", `{}`},
		{e.people, "POST", "/api/me/confirmations/ABC", `{"approve":true}`},
		{e.people, "POST", "/api/directory/users/bob/invite", `{}`},
		{e.people, "POST", "/api/directory/users/alice/impersonation", startBody},
		{e.people, "POST", "/api/directory/users/alice/impersonation/stop", ``},
		{e.people, "OPTIONS", "/api/me/apps", ``},
		// Not the exact Stop path: refused too.
		{e.people, "POST", "/api/me/impersonation/stop/", `{}`},
		{e.people, "POST", "/api/me/impersonation%2Fstop", `{}`},
		{e.people, "PUT", "/api/me/impersonation/stop", `{}`},
		{e.hub, "PUT", "/api/signin/impersonation", `{"allowed":false}`},
		{e.hub, "POST", "/api/directory/users/bob/invite", `{}`},
		{e.hub, "POST", "/api/templates/enable", `{"id":"demo"}`},
	}
	for _, w := range writes {
		for _, hv := range []string{id, ""} {
			r, b := doH(t, w.srv, "alice", w.method, w.path, w.body, map[string]string{ImpersonationHeader: hv})
			if r.StatusCode != 403 || strings.TrimSpace(b) != want {
				t.Errorf("impersonated (%q) %s %s = %d %q", hv, w.method, w.path, r.StatusCode, b)
			}
		}
		// Without the header the route answers as always (never this text).
		if r, b := doAs(t, w.srv, "alice", w.method, w.path, w.body); strings.TrimSpace(b) == want {
			t.Errorf("not impersonated %s %s = %d %q", w.method, w.path, r.StatusCode, b)
		}
	}
	// Reads work.
	for _, rd := range []struct {
		srv          *httptest.Server
		method, path string
	}{{e.people, "GET", "/api/me/apps"}, {e.people, "GET", "/api/me/signin"}, {e.people, "HEAD", "/api/me/apps"}, {e.hub, "GET", "/api/impersonations"}} {
		user := "alice"
		if rd.srv == e.hub {
			user = "root"
		}
		if r, b := doH(t, rd.srv, user, rd.method, rd.path, "", imp); r.StatusCode != 200 {
			t.Errorf("impersonated %s %s = %d %s", rd.method, rd.path, r.StatusCode, b)
		}
	}
	// The own Stop passes (404 here: nothing runs under that id).
	if r, b := doH(t, e.people, "alice", "POST", "/api/me/impersonation/stop", `{}`, imp); r.StatusCode != 404 || strings.TrimSpace(b) == want {
		t.Errorf("own stop = %d %q", r.StatusCode, b)
	}
	// The proxy secret still comes first.
	req, _ := http.NewRequest("POST", e.people.URL+"/api/me/impersonation/stop", strings.NewReader(`{}`))
	req.Header.Set(ImpersonationHeader, id)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 401 {
		t.Errorf("no proxy secret = %v %v", resp, err)
	}
	// The middleware alone.
	h := RefuseWhileImpersonated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }))
	for _, c := range []struct {
		method, path string
		set          bool
		code         int
	}{
		{"POST", "/x", false, 299}, {"DELETE", "/x", false, 299}, {"GET", "/x", true, 299}, {"HEAD", "/x", true, 299},
		{"POST", "/x", true, 403}, {"PATCH", "/x", true, 403}, {"OPTIONS", "/x", true, 403},
		{"POST", "/api/me/impersonation/stop", true, 299}, {"DELETE", "/api/me/impersonation/stop", true, 403},
	} {
		r := httptest.NewRequest(c.method, c.path, nil)
		if c.set {
			r.Header.Set(ImpersonationHeader, id)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != c.code {
			t.Errorf("%s %s set=%v = %d, want %d", c.method, c.path, c.set, rec.Code, c.code)
		}
	}
}
