package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

var testCLISecret = strings.Repeat("c", 40)

func newCLIServer(t *testing.T) (*httptest.Server, *hub.Hub) {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	os.MkdirAll(data, 0o755)
	state.New().Save(filepath.Join(data, "state.yaml"))
	h, err := newTestHub(hub.Config{ProjectDir: filepath.Join(root, "project"), DataDir: data, Domain: "example.org"}, nopRunner{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Init()
	t.Cleanup(h.Wait)
	s := &Server{Hub: h, Secret: testSecret, CLI: CLIOptions{Secret: testCLISecret, Issuer: "https://auth.example.org/realms/portcullis",
		AuthorizeURL: "https://auth.example.org/realms/portcullis/protocol/openid-connect/auth", MinCLI: "1.2.0"}}
	handler, err := s.CLIHandler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, h
}

func cliDo(t *testing.T, srv *httptest.Server, method, path, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set(ProxySecretHeader, testCLISecret)
	req.Header.Set(cliapi.HeaderCLI, cliapi.CLIHeaderValue("1.2.3"))
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestCLIListenerOnlyCLIRoutes(t *testing.T) {
	srv, _ := newCLIServer(t)
	for _, p := range []string{"/", "/healthz", "/api/templates", "/api/directory/users", "/api/me/apps", "/mcp", "/api/cli/v1/", "/api/cli/v1/nope", "/static/index.html"} {
		if r, _ := cliDo(t, srv, "GET", p, "", nil); r.StatusCode != 404 {
			t.Errorf("GET %s = %d, want 404", p, r.StatusCode)
		}
	}
	if r, _ := cliDo(t, srv, "POST", "/api/cli/v1/config", "{}", nil); r.StatusCode != 404 && r.StatusCode != 405 {
		t.Errorf("POST config = %d", r.StatusCode)
	}
	if r, _ := cliDo(t, srv, "GET", "/api/cli/v1/ssh/certificates", "", nil); r.StatusCode != 404 && r.StatusCode != 405 {
		t.Errorf("GET certificates = %d", r.StatusCode)
	}
}

func TestCLIListenerIgnoresIdentityHeaders(t *testing.T) {
	srv, h := newCLIServer(t)
	h.SetCLIClientReadyForTest(true)
	enableSSH(t, h)
	// No verifier: the proof fails closed whoever the headers name.
	r, b := cliDo(t, srv, "POST", "/api/cli/v1/ssh/certificates", `{"code":"c","code_verifier":"v","nonce":"n","redirect_uri":"http://127.0.0.1:38917/callback","public_key":"x","key_proof":"y","host_groups":[]}`,
		map[string]string{"X-Forwarded-User": "root", "X-Auth-Request-Preferred-Username": "root", "X-Forwarded-Preferred-Username": "root", "Authorization": "Bearer x"})
	if r.StatusCode == 200 || strings.Contains(b, "certificates") {
		t.Errorf("identity headers changed something: %d %s", r.StatusCode, b)
	}
}

func enableSSH(t *testing.T, h *hub.Hub) {
	t.Helper()
	if err := h.SetSSHEnabledForTest(true); err != nil {
		t.Fatal(err)
	}
}

func TestCLIListenerProxySecret(t *testing.T) {
	srv, _ := newCLIServer(t)
	for name, v := range map[string]string{"missing": "", "main secret": testSecret, "wrong": strings.Repeat("x", 40)} {
		r, _ := cliDo(t, srv, "GET", "/api/cli/v1/config", "", map[string]string{ProxySecretHeader: v})
		if r.StatusCode != 401 {
			t.Errorf("%s: %d, want 401", name, r.StatusCode)
		}
	}
	// Two values never pass.
	req, _ := http.NewRequest("GET", srv.URL+"/api/cli/v1/config", nil)
	req.Header.Add(ProxySecretHeader, testCLISecret)
	req.Header.Add(ProxySecretHeader, testCLISecret)
	req.Header.Set(cliapi.HeaderCLI, cliapi.CLIHeaderValue("1.2.3"))
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Errorf("two secrets: %d", resp.StatusCode)
	}
	// The other listeners never accept the CLI secret.
	main := newServer(t)
	if r, _ := do(t, main, "GET", "/api/templates", "", false); r.StatusCode == 200 {
		t.Fatal("no secret passed")
	}
	req, _ = http.NewRequest("GET", main.URL+"/api/templates", nil)
	req.Header.Set(ProxySecretHeader, testCLISecret)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode == 200 {
		t.Error("the Hub listener accepted the CLI secret")
	}
	// The same secret for both is refused at start.
	s := &Server{Secret: testCLISecret, CLI: CLIOptions{Secret: testCLISecret}}
	if _, err := s.CLIHandler(); err == nil {
		t.Error("CLI secret equal to the Hub's accepted")
	}
	if err := CheckCLISecret("short"); err == nil || strings.Contains(err.Error(), "short") {
		t.Errorf("short secret: %v", err)
	}
}

func TestCLI426(t *testing.T) {
	srv, _ := newCLIServer(t)
	for _, v := range []string{"0.0.1; api=0", "1.2.3; api=2", "garbage", "1.1.9; api=1"} {
		r, b := cliDo(t, srv, "GET", "/api/cli/v1/config", "", map[string]string{cliapi.HeaderCLI: v})
		if r.StatusCode != 426 || !strings.Contains(b, "update the Portcullis CLI to 1.2.0") {
			t.Errorf("%q: %d %s", v, r.StatusCode, b)
		}
	}
	if r, _ := cliDo(t, srv, "GET", "/api/cli/v1/config", "", map[string]string{cliapi.HeaderCLI: ""}); r.StatusCode != 426 {
		t.Errorf("no header: %d", r.StatusCode)
	}
	for _, v := range []string{"1.2.0; api=1", "v1.3.0; api=1", "dev; api=1"} {
		if r, _ := cliDo(t, srv, "GET", "/api/cli/v1/config", "", map[string]string{cliapi.HeaderCLI: v}); r.StatusCode != 200 {
			t.Errorf("%q: %d", v, r.StatusCode)
		}
	}
}

func TestConfigShape(t *testing.T) {
	srv, _ := newCLIServer(t)
	r, b := cliDo(t, srv, "GET", "/api/cli/v1/config", "", nil)
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", r.StatusCode, r.Header)
	}
	var m map[string]any
	json.Unmarshal([]byte(b), &m)
	want := []string{"api", "authorize_url", "client_id", "device", "domain", "issuer", "min_cli", "redirect_ports"}
	if len(m) != len(want) {
		t.Errorf("keys %v", m)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if m["api"] != 1.0 || m["client_id"] != "portcullis-cli" || m["device"] != false || m["domain"] != "example.org" {
		t.Errorf("config %v", m)
	}
	if p, _ := m["redirect_ports"].([]any); len(p) != 3 || p[0] != 38917.0 || p[2] != 38919.0 {
		t.Errorf("ports %v", m["redirect_ports"])
	}
}

func TestCLIStrictBodies(t *testing.T) {
	srv, h := newCLIServer(t)
	enableSSH(t, h)
	if r, _ := cliDo(t, srv, "POST", "/api/cli/v1/ssh/certificates", `{"code":"x","zz":1}`, nil); r.StatusCode != 400 {
		t.Errorf("unknown field: %d", r.StatusCode)
	}
	big := `{"code":"` + strings.Repeat("a", cliapi.MaxCertRequest) + `"}`
	if r, _ := cliDo(t, srv, "POST", "/api/cli/v1/ssh/certificates", big, nil); r.StatusCode != 413 {
		t.Errorf("oversized: %d", r.StatusCode)
	}
}

func TestSignOff409(t *testing.T) {
	srv, _ := newCLIServer(t)
	r, b := cliDo(t, srv, "POST", "/api/cli/v1/ssh/certificates", `{"code":"c","code_verifier":"v","nonce":"n","redirect_uri":"x","public_key":"k","key_proof":"p","host_groups":[]}`, nil)
	if r.StatusCode != 409 || !strings.Contains(b, "SSH access is off on this server") {
		t.Errorf("%d %s", r.StatusCode, b)
	}
	// config still answers while off.
	if r, _ := cliDo(t, srv, "GET", "/api/cli/v1/config", "", nil); r.StatusCode != 200 {
		t.Errorf("config while off: %d", r.StatusCode)
	}
}

func TestRevokedKeysPublicText(t *testing.T) {
	srv, h := newCLIServer(t)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXf2yZXNFwHqiadxQBruvDLwOZYX4l4+MUIDqyknOMZ"
	if _, err := h.RevokeKeys("root", "test", []string{key + " a comment"}, "alice"); err != nil {
		t.Fatal(err)
	}
	r, b := cliDo(t, srv, "GET", "/api/cli/v1/ssh/revoked-keys", "", nil)
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") || b != key+"\n" {
		t.Errorf("%d %q %q", r.StatusCode, r.Header.Get("Content-Type"), b)
	}
	_ = time.Second
}
