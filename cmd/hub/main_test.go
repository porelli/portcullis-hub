package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/fidomds"
	"github.com/portcullis/hub/internal/hub"
)

// The spec: a corrupt directory.yaml refuses to start; a missing one is
// an empty directory.
func TestOpenDirectoryStore(t *testing.T) {
	dir := t.TempDir()
	if st, err := openDirectoryStore(dir); err != nil || st.Path != filepath.Join(dir, "directory.yaml") {
		t.Fatalf("missing file: %v %v", st, err)
	}
	for name, body := range map[string]string{
		"corrupt":         "version: 1\nfields: [\n",
		"unknown version": "version: 99\n",
		"unknown key":     "version: 1\nbogus: true\n",
		"bad rule":        "version: 1\ngroups:\n  g:\n    rule: 'city ='\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, "directory.yaml"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := openDirectoryStore(dir); err == nil || !strings.Contains(err.Error(), "directory.yaml") {
			t.Errorf("%s: err = %v, want a refusal naming directory.yaml", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "directory.yaml"), []byte("version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openDirectoryStore(dir); err != nil {
		t.Errorf("valid file: %v", err)
	}
}

// TestFolderfixDispatch runs the test binary as `hub folderfix …` with no
// Hub environment: the fixer answers, not the Hub's start-up checks.
func TestFolderfixDispatch(t *testing.T) {
	if args := os.Getenv("HUB_TEST_MAIN_ARGS"); args != "" {
		os.Args = append([]string{"hub"}, strings.Split(args, "\x1f")...)
		main()
		return
	}
	run := func(args ...string) (int, string, string) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFolderfixDispatch$")
		cmd.Env = []string{"HUB_TEST_MAIN_ARGS=" + strings.Join(args, "\x1f"), "PATH=" + os.Getenv("PATH")}
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			t.Fatal(err)
		}
		return cmd.ProcessState.ExitCode(), out.String(), errb.String()
	}
	code, _, errOut := run("folderfix", "bogus")
	if code != 1 || strings.Contains(errOut, "HUB_PROXY_SECRET") || !strings.Contains(errOut, "folderfix:") {
		t.Fatalf("bad mode: exit %d stderr %q", code, errOut)
	}
	code, out, errOut := run("folderfix", "scan", "--root="+t.TempDir())
	line := strings.SplitN(out, "\n", 2)[0]
	var r struct{ Mode string }
	if code != 0 || json.Unmarshal([]byte(line), &r) != nil || r.Mode != "scan" {
		t.Fatalf("scan: exit %d out %q stderr %q", code, out, errOut)
	}
}

// HUB_FIXER_IMAGE is honoured only with HUB_DEV=1 (ruling 37): an
// env-selected root-capable image is otherwise refused at start.
func TestFixerImageFromEnv(t *testing.T) {
	pinned := "ghcr.io/porelli/portcullis-hub:dev@sha256:" + strings.Repeat("a", 64)
	for _, c := range []struct {
		img, dev string
		want     string
		ok       bool
	}{
		{"", "", "", true},
		{"", "1", "", true},
		{pinned, "1", pinned, true},
		{pinned, "", "", false},
		{pinned, "true", "", false},
		{pinned, "0", "", false},
	} {
		got, err := fixerImageFromEnv(func(k string) string {
			return map[string]string{"HUB_FIXER_IMAGE": c.img, "HUB_DEV": c.dev}[k]
		})
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("image %q dev %q: %q, %v", c.img, c.dev, got, err)
		}
	}
}

// TestExtraAuthenticatorsNeedDev: HUB_SIGNIN_EXTRA_AUTHENTICATORS without
// HUB_DEV=1 refuses the start; HUB_FIDO_MDS_URL defaults to FIDO's MDS3.
func TestExtraAuthenticatorsNeedDev(t *testing.T) {
	for _, c := range []struct {
		url, extra, dev string
		wantURL         string
		ok              bool
	}{
		{"", "", "", fidomds.DefaultURL, true},
		{"", "/x/extra.json", "1", fidomds.DefaultURL, true},
		{"", "/x/extra.json", "", "", false},
		{"", "/x/extra.json", "true", "", false},
		{"", "/x/extra.json", "0", "", false},
		{"http://mds.test:8080/blob", "", "", "http://mds.test:8080/blob", true},
		{"ftp://mds.test/", "", "", "", false},
		{"not a url", "", "", "", false},
		{"off", "", "", "", true},
	} {
		u, extra, err := signInMDSFromEnv(func(k string) string {
			return map[string]string{"HUB_FIDO_MDS_URL": c.url, "HUB_SIGNIN_EXTRA_AUTHENTICATORS": c.extra, "HUB_DEV": c.dev}[k]
		})
		if (err == nil) != c.ok || u != c.wantURL || (c.ok && extra != c.extra) {
			t.Errorf("url %q extra %q dev %q: %q %q %v", c.url, c.extra, c.dev, u, extra, err)
		}
	}
}

func TestFreshAuthFromEnv(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	fa, err := freshAuthFromEnv(get(nil), "example.org", "http://keycloak:8080")
	if err != nil {
		t.Fatal(err)
	}
	want := freshAuthSetup{
		Issuer:       "https://auth.example.org/realms/portcullis",
		TokenURL:     "http://keycloak:8080/realms/portcullis/protocol/openid-connect/token",
		JWKSURL:      "http://keycloak:8080/realms/portcullis/protocol/openid-connect/certs",
		AuthorizeURL: "https://auth.example.org/realms/portcullis/protocol/openid-connect/auth",
		AccountURL:   "https://auth.example.org/realms/portcullis/account/account-security/signing-in",
		RedirectURI:  "https://people.example.org/signin",
		WebOrigin:    "https://people.example.org",
		// The Hub listener's confirmation page (G11): its own verifier.
		HubRedirectURI: "https://hub.example.org/",
		HubWebOrigin:   "https://hub.example.org",
		// The VPN page (contract §8 per-host model, V8).
		VPNRedirectURI: "https://people.example.org/vpn/",
	}
	if fa != want {
		t.Errorf("default = %+v\nwant %+v", fa, want)
	}
	fa, err = freshAuthFromEnv(get(map[string]string{"HUB_KEYCLOAK_PUBLIC_URL": "https://login.example.net/"}), "example.org", "http://keycloak:8080/")
	if err != nil || fa.Issuer != "https://login.example.net/realms/portcullis" || fa.TokenURL != want.TokenURL {
		t.Errorf("set = %+v, %v", fa, err)
	}
	for _, bad := range []string{"http://auth.example.org", "https://auth.example.org/sub", "https://u:p@auth.example.org", "https://auth.example.org?x=1", "auth.example.org", "https://"} {
		if _, err := freshAuthFromEnv(get(map[string]string{"HUB_KEYCLOAK_PUBLIC_URL": bad}), "example.org", "http://keycloak:8080"); err == nil {
			t.Errorf("HUB_KEYCLOAK_PUBLIC_URL=%q accepted", bad)
		}
	}
}

// TestPeopleVerifierRedirect (sign-in part 2, D24): the people
// listener's verifier redirects to the Sign-in page, the Hub listener's
// to the Hub's "/"; EnsureFreshAuthClient gets the same two.
func TestPeopleVerifierRedirect(t *testing.T) {
	fa, err := freshAuthFromEnv(func(string) string { return "" }, "example.org", "http://keycloak:8080")
	if err != nil {
		t.Fatal(err)
	}
	cfgs := fa.verifierConfigs(http.DefaultClient, func() []string { return nil })
	if len(cfgs) != 3 || cfgs[hub.ListenerPeople].RedirectURI != "https://people.example.org/signin" || cfgs[hub.ListenerHub].RedirectURI != "https://hub.example.org/" ||
		cfgs[hub.ListenerPeopleVPN].RedirectURI != "https://people.example.org/vpn/" {
		t.Errorf("verifier configs = %+v", cfgs)
	}
	// The client: three redirect URIs, one web origin per host.
	if r, o := fa.redirectURIs(), fa.webOrigins(); strings.Join(r, " ") != "https://people.example.org/signin https://people.example.org/vpn/ https://hub.example.org/" ||
		strings.Join(o, " ") != "https://people.example.org https://hub.example.org" {
		t.Errorf("client URIs %v origins %v", r, o)
	}
	if fa.RedirectURI != "https://people.example.org/signin" || fa.HubRedirectURI != "https://hub.example.org/" {
		t.Errorf("client redirect URIs = %q, %q", fa.RedirectURI, fa.HubRedirectURI)
	}
}

type fakeDirHub struct{ syncs, checks, stale, vpn int }

func (f *fakeDirHub) TriggerVPNPublish() { f.vpn++ }

func (f *fakeDirHub) TriggerDirectorySync()   { f.syncs++ }
func (f *fakeDirHub) TriggerCredentialCheck() { f.checks++ }
func (f *fakeDirHub) MarkInventoryStale()     { f.stale++ }

// Plan 3 Task 9: OnChange triggers the directory sync and the holder
// check; OnEvaluated (every evaluator run) the holder check only.
func TestWireDirectoryHooks(t *testing.T) {
	dir := &directory.Service{}
	h := &fakeDirHub{}
	wireDirectoryHooks(dir, h)
	if dir.OnChange == nil || dir.OnEvaluated == nil {
		t.Fatal("hooks not set")
	}
	dir.OnChange()
	if h.syncs != 1 || h.checks != 1 || h.stale != 1 || h.vpn != 1 {
		t.Errorf("OnChange: syncs %d checks %d stale %d vpn %d", h.syncs, h.checks, h.stale, h.vpn)
	}
	dir.OnEvaluated()
	if h.syncs != 1 || h.checks != 2 || h.stale != 1 {
		t.Errorf("OnEvaluated: syncs %d checks %d", h.syncs, h.checks)
	}
}

// TestMCPListenerFromEnv (contract §15.7): defaults :8890 and core's
// mount; a missing secret file = no listener (no error); under 32
// characters refuses the start without quoting the value.
func TestMCPListenerFromEnv(t *testing.T) {
	dir := t.TempDir()
	envOf := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	l, err := mcpListenerFromEnv(envOf(map[string]string{"HUB_MCP_GATE_SECRET_FILE": filepath.Join(dir, "missing")}))
	if err != nil || l.on || l.secret != "" || l.addr != ":8890" {
		t.Errorf("missing = %+v %v", l, err)
	}
	if l, _ := mcpListenerFromEnv(envOf(nil)); l.file != "/run/portcullis/mcp-gate/hub-secret" {
		t.Errorf("default file = %q", l.file)
	}
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte(strings.Repeat("q", 31)+"\n"), 0o600)
	if _, err := mcpListenerFromEnv(envOf(map[string]string{"HUB_MCP_GATE_SECRET_FILE": short})); err == nil || strings.Contains(err.Error(), "qqqq") {
		t.Errorf("short = %v", err)
	}
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte(strings.Repeat("q", 48)+"\n"), 0o600)
	l, err = mcpListenerFromEnv(envOf(map[string]string{"HUB_MCP_GATE_SECRET_FILE": good, "HUB_MCP_ADDR": ":9999"}))
	if err != nil || !l.on || l.secret != strings.Repeat("q", 48) || l.addr != ":9999" {
		t.Errorf("good = %v %v %q", l.on, err, l.addr)
	}
}

// TestHubRefusesBadClientCertTTL (contract §8.1 "Limits"): the ceiling of
// browser certificate lifetimes is HUB_CLIENT_CERT_TTL in whole days, in
// core's grammar (a bare number is seconds); unset, unparsable or under a
// day refuses the start.
func TestHubRefusesBadClientCertTTL(t *testing.T) {
	for _, v := range []string{"", "abc", "3600", "23h", "1439m", "0d", "1.5d", "-1d", "30 d", "720H", "99999999999999999999d"} {
		if _, err := clientCertTTLFromEnv(func(k string) string {
			if k == "HUB_CLIENT_CERT_TTL" {
				return v
			}
			return ""
		}); err == nil {
			t.Errorf("HUB_CLIENT_CERT_TTL %q accepted", v)
		}
	}
	for v, days := range map[string]int{"2592000": 30, "720h": 30, "30d": 30, "86400s": 1, "1d": 1, "2160h": 90, "43201m": 30} {
		d, err := clientCertTTLFromEnv(func(k string) string {
			if k == "HUB_CLIENT_CERT_TTL" {
				return v
			}
			return ""
		})
		if err != nil || int(d/(24*time.Hour)) != days {
			t.Errorf("HUB_CLIENT_CERT_TTL %q = %v, %v; want %d days", v, d, err, days)
		}
	}
}

// TestMaxMinutes (D36): unset is 30, "2" is 2; "0", "31", "x", "-1",
// " 5" and "05x" refuse the start.
func TestMaxMinutes(t *testing.T) {
	for v, want := range map[string]int{"": 30, "2": 2, "30": 30, "1": 1} {
		got, err := impersonationMaxMinutesFromEnv(func(k string) string {
			if k == "HUB_IMPERSONATION_MAX_MINUTES" {
				return v
			}
			return ""
		})
		if err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", v, got, err, want)
		}
	}
	for _, v := range []string{"0", "31", "x", "-1", " 5", "05x", "999999999999999999999"} {
		if _, err := impersonationMaxMinutesFromEnv(func(string) string { return v }); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

// TestRuntimeFromEnv: HUB_CONTAINER_RUNTIME is required, docker or podman
// (contract §6, P0: no default).
func TestRuntimeFromEnv(t *testing.T) {
	for v, want := range map[string]docker.Runtime{"docker": docker.RuntimeDocker, "podman": docker.RuntimePodman} {
		got, err := runtimeFromEnv(func(k string) string { return map[string]string{"HUB_CONTAINER_RUNTIME": v}[k] })
		if err != nil || got != want {
			t.Errorf("%q: %q, %v", v, got, err)
		}
	}
	for _, v := range []string{"", "rkt", "Docker", "podman "} {
		if _, err := runtimeFromEnv(func(k string) string { return map[string]string{"HUB_CONTAINER_RUNTIME": v}[k] }); err == nil || !strings.Contains(err.Error(), "HUB_CONTAINER_RUNTIME") {
			t.Errorf("%q accepted or unnamed: %v", v, err)
		}
	}
}

// HUB_VPN_DOC_GID: default 10007; never the Hub's own 10001, never junk.
func TestVPNDocGIDFromEnv(t *testing.T) {
	envOf := func(v string) func(string) string { return func(string) string { return v } }
	if g, err := vpnDocGIDFromEnv(envOf("")); err != nil || g != 10007 {
		t.Fatalf("default %d %v", g, err)
	}
	if g, err := vpnDocGIDFromEnv(envOf("10020")); err != nil || g != 10020 {
		t.Fatalf("10020: %d %v", g, err)
	}
	for _, bad := range []string{"10001", "0", "-1", "65536", "x", "010007", " 10007"} {
		if _, err := vpnDocGIDFromEnv(envOf(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestHubVPNSubcommand (contract §16): the public key comes on stdin and
// goes in the POST body (never argv), the config JSON goes to stdout; a
// missing socket exits 1 with "the Hub isn't running".
func TestHubVPNSubcommand(t *testing.T) {
	dir, err := os.MkdirTemp("", "hv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	var stdout, stderr bytes.Buffer
	if code := vpnMain([]string{"host-info"}, strings.NewReader(""), &stdout, &stderr, sock); code != 1 || !strings.Contains(stderr.String(), "the Hub isn't running") {
		t.Fatalf("no socket: %d %q", code, stderr.String())
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	var body string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.RequestURI())
		body = string(b)
		switch {
		case r.Method == "POST":
			w.WriteHeader(201)
			io.WriteString(w, `{"address":"10.213.0.2"}`)
		case strings.HasPrefix(r.URL.Path, "/host/vpn/devices/nope"):
			http.Error(w, "no such device", 404)
		default:
			io.WriteString(w, `[]`)
		}
	})}
	go srv.Serve(l)
	defer srv.Close()
	stdout.Reset()
	key := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	if code := vpnMain([]string{"add-device", "--user", "alice", "--name", "laptop"}, strings.NewReader(key+"\n"), &stdout, &stderr, sock); code != 0 || stdout.String() != `{"address":"10.213.0.2"}` {
		t.Fatalf("add-device: %d %q %q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(body, `"public_key":"`+key+`"`) || !strings.Contains(body, `"user":"alice"`) {
		t.Fatalf("body %s", body)
	}
	stderr.Reset()
	if code := vpnMain([]string{"revoke", "nope"}, nil, &stdout, &stderr, sock); code != 1 || !strings.Contains(stderr.String(), "no such device") {
		t.Fatalf("revoke: %d %q", code, stderr.String())
	}
	vpnMain([]string{"devices", "--user", "bob"}, nil, &stdout, &stderr, sock)
	vpnMain([]string{"host-info"}, nil, &stdout, &stderr, sock)
	if strings.Join(got, "|") != "POST /host/vpn/devices|DELETE /host/vpn/devices/nope|GET /host/vpn/devices?user=bob|GET /host/vpn/info" {
		t.Fatalf("requests %v", got)
	}
	for _, bad := range [][]string{{}, {"add-device", "--user", "a"}, {"revoke"}, {"frob"}} {
		if code := vpnMain(bad, nil, &stdout, &stderr, sock); code != 2 {
			t.Errorf("%v: exit %d", bad, code)
		}
	}
}
