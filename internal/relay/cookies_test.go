package relay

import (
	"net/http"
	"strings"
	"testing"
)

// TestCookieFilterDomainVariants (Review Focus 3, contract §5): every
// Set-Cookie leaves host-only (its Domain stripped, whatever its
// spelling), every Portcullis cookie is dropped, several headers each
// judged alone.
func TestCookieFilterDomainVariants(t *testing.T) {
	h := http.Header{}
	for _, c := range []string{
		"a=1; Domain=.app.example.org; Path=/",
		"b=2; Domain=APP.example.org",
		"c=3; Domain=example.org; Secure; HttpOnly",
		"d=4; Domain=app.example.org.",
		"e=5; domain=evil.example; SameSite=Lax",
		"f=6",
		"__Host-g=7; Path=/; Secure",
		"__Secure-h=8; Domain=example.org; Secure",
		"_oauth2_proxy=stolen; Domain=.example.org",
		"_oauth2_proxy_0=x",
		"_oauth2_proxy_csrf_abc=x",
		"__Host-portcullis_ext=x; Path=/; Secure",
		"__Host-portcullis_ext-2=x; Path=/; Secure",
		"my_csrf_token=x",
		"_OAUTH2_PROXY=upper",
		"not a cookie",
		"=empty-name",
	} {
		h.Add("Set-Cookie", c)
	}
	FilterResponseCookies(h, "app.example.org")
	got := h.Values("Set-Cookie")
	byName := map[string]string{}
	for _, c := range got {
		name, _, _ := strings.Cut(c, "=")
		byName[name] = c
		if strings.Contains(strings.ToLower(c), "domain") {
			t.Errorf("a Domain survived: %q", c)
		}
	}
	for _, keep := range []string{"a", "b", "c", "d", "e", "f", "__Host-g", "__Secure-h"} {
		if _, ok := byName[keep]; !ok {
			t.Errorf("%s dropped: %v", keep, got)
		}
	}
	for _, drop := range []string{"_oauth2_proxy", "_oauth2_proxy_0", "_oauth2_proxy_csrf_abc", "__Host-portcullis_ext", "__Host-portcullis_ext-2", "my_csrf_token", "_OAUTH2_PROXY", "not a cookie", ""} {
		if c, ok := byName[drop]; ok {
			t.Errorf("%q kept: %q", drop, c)
		}
	}
	if len(got) != 8 {
		t.Errorf("%d cookies kept: %v", len(got), got)
	}
	if !strings.Contains(byName["c"], "Secure") || !strings.Contains(byName["c"], "HttpOnly") || !strings.Contains(byName["e"], "SameSite=Lax") || !strings.Contains(byName["a"], "Path=/") {
		t.Errorf("attributes lost: %v", got)
	}
	// No Set-Cookie at all stays none.
	empty := http.Header{}
	FilterResponseCookies(empty, "app.example.org")
	if _, ok := empty["Set-Cookie"]; ok {
		t.Error("an empty Set-Cookie list appeared")
	}
}

// TestRequestCookiesStripped: every Portcullis cookie leaves the request
// (one or several Cookie headers), the app's own stay.
func TestRequestCookiesStripped(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", "_oauth2_proxy_0=s; app=1; _oauth2_proxy_csrf_x=c")
	h.Add("Cookie", "__Host-portcullis_ext-2=e; theme=dark")
	h.Add("Cookie", "_oauth2_proxy=s2; __Host-portcullis_ext=e2; x_csrf_y=1")
	FilterRequestCookies(h)
	got := h.Values("Cookie")
	if len(got) != 1 || got[0] != "app=1; theme=dark" {
		t.Errorf("cookies %q", got)
	}
	only := http.Header{"Cookie": {"_oauth2_proxy_1=x"}}
	FilterRequestCookies(only)
	if _, ok := only["Cookie"]; ok {
		t.Errorf("an empty Cookie header kept: %q", only["Cookie"])
	}
	for _, n := range []string{"_oauth2_proxy", "_oauth2_proxy_9", "_oauth2_proxy_csrf_a", "__Host-portcullis_ext", "__Host-portcullis_ext-3", "a_csrf", "__host-PORTCULLIS_EXT"} {
		if !Reserved(n) {
			t.Errorf("%s not reserved", n)
		}
	}
	for _, n := range []string{"app", "session", "__Host-app", "oauth2", "csrf"} {
		if Reserved(n) && n != "csrf" {
			t.Errorf("%s reserved", n)
		}
	}
}
