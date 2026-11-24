package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSettingsControlsStyled is the computed-style regression guard of
// the Settings sections and the SSH access subtabs (ux3 item 5): a real
// Hub handler (newDirFixture) with a few GETs answered from
// testdata/uismoke (mail on with a wired provider, domains, two servers, a
// VPN provider, SSH on) is opened in headless Chromium, and no visible
// input, textarea, select or button there may keep a light (browser
// default) background, nor a link a dark colour.
//
// It needs node with Playwright resolvable (NODE_PATH, e.g. a
// node_modules holding playwright) and a Chromium (Playwright's own, or
// PLAYWRIGHT_CHROMIUM); without them it skips, unless
// PORTCULLIS_UI_SMOKE=require.
func TestSettingsControlsStyled(t *testing.T) {
	skip := func(why string) {
		if os.Getenv("PORTCULLIS_UI_SMOKE") == "require" {
			t.Fatal(why)
		}
		t.Skip(why)
	}
	node, err := exec.LookPath("node")
	if err != nil {
		skip("node not installed")
	}
	if out, err := exec.Command(node, "-e", "require.resolve('playwright')").CombinedOutput(); err != nil {
		skip("playwright not resolvable from node (set NODE_PATH): " + strings.TrimSpace(string(out)))
	}
	s, _, _ := newDirFixture(t, nil)
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	mocks, err := filepath.Abs(filepath.Join("testdata", "uismoke"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if b, err := os.ReadFile(filepath.Join(mocks, strings.ReplaceAll(r.URL.Path, "/", "_")+".json")); err == nil {
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
				return
			}
		}
		r.Header.Set(ProxySecretHeader, testSecret)
		r.Header.Set("X-Forwarded-User", "root")
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	out, err := exec.Command(node, filepath.Join(mocks, "check.js"), srv.URL).Output()
	if err != nil {
		t.Fatalf("node: %v: %s", err, out)
	}
	var bad []string
	if err := json.Unmarshal(out, &bad); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, b := range bad {
		if strings.HasPrefix(b, "check failed: ") && strings.Contains(b, "Executable doesn't exist") {
			skip(b)
		}
	}
	for _, b := range bad {
		t.Error(b)
	}
}
