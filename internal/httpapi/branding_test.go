package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStaticContentTypes: both listeners serve the logo and favicon set
// with its content type and nosniff; the people listener still serves
// nothing beyond its allowlist; the two CSP pages allow the manifest.
func TestStaticContentTypes(t *testing.T) {
	e := newPeopleEnv(t)
	types := map[string]string{
		"favicon.svg":          "image/svg+xml",
		"mark.svg":             "image/svg+xml",
		"favicon.ico":          "image/x-icon",
		"apple-touch-icon.png": "image/png",
		"icon-192.png":         "image/png",
		"icon-512.png":         "image/png",
		"maskable-512.png":     "image/png",
		"site.webmanifest":     "application/manifest+json",
	}
	for name, ct := range types {
		for _, l := range []struct {
			name, user string
			srv        *httptest.Server
		}{{"hub", "root", e.hub}, {"people", "bob", e.people}} {
			r, _ := doAs(t, l.srv, l.user, "GET", "/static/"+name, "")
			if r.StatusCode != 200 || r.Header.Get("Content-Type") != ct || r.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("%s /static/%s = %d %q nosniff %q, want 200 %q", l.name, name, r.StatusCode, r.Header.Get("Content-Type"), r.Header.Get("X-Content-Type-Options"), ct)
			}
		}
	}
	if r, _ := doAs(t, e.people, "bob", "GET", "/static/settings.js", ""); r.StatusCode != 404 {
		t.Errorf("people settings.js = %d, want 404", r.StatusCode)
	}
	for name, csp := range map[string]string{"confirmCSP": confirmCSP, "impStopCSP": impStopCSP} {
		if !strings.Contains(csp, "manifest-src 'self'") {
			t.Errorf("%s lacks manifest-src 'self': %s", name, csp)
		}
	}
}
