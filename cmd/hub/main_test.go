package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
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
		RedirectURI:  "https://people.example.org/",
		WebOrigin:    "https://people.example.org",
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

type fakeDirHub struct{ syncs, checks int }

func (f *fakeDirHub) TriggerDirectorySync()   { f.syncs++ }
func (f *fakeDirHub) TriggerCredentialCheck() { f.checks++ }

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
	if h.syncs != 1 || h.checks != 1 {
		t.Errorf("OnChange: syncs %d checks %d", h.syncs, h.checks)
	}
	dir.OnEvaluated()
	if h.syncs != 1 || h.checks != 2 {
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
