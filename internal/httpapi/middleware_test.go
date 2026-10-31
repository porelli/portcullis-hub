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
