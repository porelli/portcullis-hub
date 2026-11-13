package httpapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHostSocketOnly (contract §16): the /host/ routes exist only on the
// control socket (404 on the Hub, people and MCP listeners); the socket
// is 0600 and answers its routes.
func TestHostSocketOnly(t *testing.T) {
	e := newPeopleEnv(t)
	for _, srv := range []string{"hub", "people"} {
		s := e.hub
		if srv == "people" {
			s = e.people
		}
		for _, r := range []struct{ m, p string }{{"POST", "/host/vpn/devices"}, {"GET", "/host/vpn/devices"}, {"DELETE", "/host/vpn/devices/x"}, {"GET", "/host/vpn/info"}} {
			if resp, _ := doAs(t, s, "root", r.m, r.p, `{}`); resp.StatusCode != 404 {
				t.Errorf("%s %s %s = %d", srv, r.m, r.p, resp.StatusCode)
			}
		}
	}
	e.s.MCPSecret = strings.Repeat("m", 40)
	mh, err := e.s.MCPHandler()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/host/vpn/info", "/host/vpn/devices"} {
		req, _ := http.NewRequest("GET", p, nil)
		rec := &recorder{header: http.Header{}}
		mh.ServeHTTP(rec, req)
		if rec.code != 404 && rec.code != 401 && rec.code != 403 {
			t.Errorf("MCP listener %s = %d", p, rec.code)
		}
	}
	dir, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "h.sock")
	os.WriteFile(sock, []byte("x"), 0o644)
	if _, err := ListenHost(sock); err == nil {
		t.Fatal("a regular file at the socket path was replaced")
	}
	os.Remove(sock)
	l, err := ListenHost(sock)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(sock)
	if fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode %v", fi.Mode())
	}
	srv := &http.Server{Handler: HostHandler(e.s.Hub)}
	go srv.Serve(l)
	defer srv.Close()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	resp, err := c.Get("http://hub/host/vpn/info")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"admin_device_seen":false`) {
		t.Fatalf("info %d %s", resp.StatusCode, b)
	}
	// The builtin is off here (no wg): adding a device is refused, the
	// body is strict.
	resp, _ = c.Post("http://hub/host/vpn/devices", "application/json", strings.NewReader(`{"user":"root","name":"x","public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`))
	if resp.StatusCode != 409 {
		t.Fatalf("add with the builtin off = %d", resp.StatusCode)
	}
	resp, _ = c.Post("http://hub/host/vpn/devices", "application/json", strings.NewReader(`{"user":"root","private_key":"x"}`))
	if resp.StatusCode != 400 {
		t.Fatalf("unknown field = %d", resp.StatusCode)
	}
}

type recorder struct {
	header http.Header
	code   int
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *recorder) WriteHeader(c int)           { r.code = c }

// TestVPNAssetsAllowlist (V18): /vpn/assets/ serves only the page's own
// files (its copies of the fresh-auth scripts included), nothing else.
func TestVPNAssetsAllowlist(t *testing.T) {
	e := newPeopleEnv(t)
	for f := range vpnAssets {
		if resp, _ := doAs(t, e.people, "alice", "GET", "/vpn/assets/"+f, ""); resp.StatusCode != 200 {
			t.Errorf("%s = %d", f, resp.StatusCode)
		}
	}
	for _, f := range []string{"index.html", "settings.js", "directory.js", "myapps.js", "vendor%2Fqrcode.js", "..%2Findex.html", "vpn.html"} {
		if resp, _ := doAs(t, e.people, "alice", "GET", "/vpn/assets/"+f, ""); resp.StatusCode != 404 {
			t.Errorf("%s = %d", f, resp.StatusCode)
		}
	}
	if !vpnAssets["freshauth.js"] || !vpnAssets["freshauth-callback.js"] {
		t.Error("the fresh-auth scripts must be in vpnAssets")
	}
	// The page and its API are the people listener's only.
	resp, body := doAs(t, e.people, "alice", "GET", "/vpn/", "")
	if resp.StatusCode != 200 || !strings.Contains(body, "/vpn/assets/vpn.js") || strings.Contains(body, "/static/") {
		t.Fatalf("page %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Error("no CSP")
	}
	if resp, _ := doAs(t, e.hub, "root", "GET", "/vpn/api/devices", ""); resp.StatusCode == 200 {
		t.Error("the Hub listener answers /vpn/api/devices")
	}
	resp, body = doAs(t, e.people, "alice", "GET", "/vpn/api/devices", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"devices":[]`) {
		t.Fatalf("devices %d %s", resp.StatusCode, body)
	}
}
