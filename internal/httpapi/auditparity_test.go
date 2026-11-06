package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/hub"
)

// runningEngine is the fake engine with grafana's web container running
// (exec needs one).
type runningEngine struct{ *fakeEngine }

// Exec exits 3 for a command containing "exit3".
func (e runningEngine) Exec(ctx context.Context, id string, cmd []string, d time.Duration) (*docker.ExecResult, error) {
	if strings.Contains(strings.Join(cmd, " "), "exit3") {
		return &docker.ExecResult{Output: []byte("ok\n"), ExitCode: 3}, nil
	}
	return e.fakeEngine.Exec(ctx, id, cmd, d)
}

func (e runningEngine) ListContainers(ctx context.Context, f docker.Filters) ([]docker.Container, error) {
	out, err := e.fakeEngine.ListContainers(ctx, f)
	c := docker.Container{ID: "c-grafana-web", Names: []string{"/portcullis-grafana-web-1"}, State: "running",
		Labels: map[string]string{docker.LabelProject: "portcullis-grafana", docker.LabelService: "web", docker.LabelNumber: "1"}}
	if matchLabels(c.Labels, f) {
		out = append(out, c)
	}
	return out, err
}

// localTemplateRepo makes a git repository with one commit and maps
// https://git.example.invalid/tmpl.git to it for every git the Hub runs.
func localTemplateRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := filepath.Join(t.TempDir(), "tmpl")
	os.MkdirAll(repo, 0755)
	os.WriteFile(filepath.Join(repo, "README.md"), []byte("templates\n"), 0644)
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"add", "."},
		{"-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	const url = "https://git.example.invalid/tmpl.git"
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "url."+repo+".insteadOf")
	t.Setenv("GIT_CONFIG_VALUE_0", url)
	t.Setenv("GIT_CONFIG_KEY_1", "protocol.file.allow")
	t.Setenv("GIT_CONFIG_VALUE_1", "always")
	return url
}

// TestUnauditedMutationsNowAudited (Task 7c, ruling G57): enable,
// disable, restart, exec, env save, drift resolve, source add / remove /
// sync and the default policy write one audit entry each — the action,
// the target, the result the answer stands for (2xx ok, 4xx refused,
// 5xx error) and the actor with via / client. The exec detail is the
// service name only (never the command or its output), env saves name
// the variables (never values), a source URL's credentials never reach
// the log.
func TestUnauditedMutationsNowAudited(t *testing.T) {
	url := localTemplateRepo(t)
	e := newInstEnvWith(t, t.TempDir(), nil, func(f *fakeEngine) hub.Engine { return runningEngine{f} })
	handler, err := e.s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ai := directory.Actor{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude-code"}
	call := func(a directory.Actor, method, path, body string) int {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(ProxySecretHeader, testSecret)
		req.Header.Set("X-Forwarded-User", a.User)
		if a.Via != "" {
			req = withMCPIdentity(req, a)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	resultOf := func(code int) string {
		switch {
		case code < 300:
			return "ok"
		case code < 500:
			return "refused"
		}
		return "error"
	}

	const secretCmd = "echo cmd-SECRET-42"
	const secretVal = "env-SECRET-value-42"
	const urlToken = "ghp_URLTOKEN42"
	steps := []struct {
		name                 string
		actor                directory.Actor
		method, path, body   string
		code                 int // expected HTTP status
		action, target, want string
	}{
		{"enable", ai, "POST", "/api/templates/enable", `{"id":"grafana"}`, 200, "instance.enable", "grafana", ""},
		{"enable unknown (human)", directory.Human("root"), "POST", "/api/templates/enable", `{"id":"missing"}`, 400, "instance.enable", "missing", ""},
		{"restart", ai, "POST", "/api/templates/restart/grafana", `{}`, 200, "instance.restart", "grafana", ""},
		{"restart unknown", ai, "POST", "/api/templates/restart/nosuch", `{}`, 404, "instance.restart", "nosuch", ""},
		{"exec", ai, "POST", "/api/templates/exec/grafana", `{"service":"web","command":"` + secretCmd + `"}`, 200, "instance.exec", "grafana", "service=web exit=0"},
		{"exec non-zero exit", ai, "POST", "/api/templates/exec/grafana", `{"service":"web","command":"` + secretCmd + ` exit3"}`, 200, "instance.exec", "grafana", "service=web exit=3"},
		{"exec bad service", ai, "POST", "/api/templates/exec/grafana", `{"service":"db","command":"` + secretCmd + `"}`, 400, "instance.exec", "grafana", "service=db"},
		{"env save", ai, "PUT", "/api/templates/env/grafana", `{"MY_VAR":"` + secretVal + `"}`, 200, "app.env", "grafana", "MY_VAR"},
		{"env save Hub-set", ai, "PUT", "/api/templates/env/grafana", `{"PORTCULLIS_DOMAIN":"` + secretVal + `"}`, 400, "app.env", "grafana", ""},
		{"drift resolve", ai, "POST", "/api/drift/resolve", `{"id":"grafana","action":"apply"}`, 200, "drift.resolve", "grafana", "apply"},
		{"drift resolve bogus", ai, "POST", "/api/drift/resolve", `{"id":"grafana","action":"bogus"}`, 400, "drift.resolve", "grafana", "bogus"},
		{"disable", ai, "POST", "/api/templates/disable", `{"id":"grafana"}`, 200, "instance.disable", "grafana", ""},
		{"disable again", ai, "POST", "/api/templates/disable", `{"id":"grafana"}`, 400, "instance.disable", "grafana", ""},
		{"source add", ai, "POST", "/api/sources/add", `{"name":"extra","url":"` + url + `"}`, 200, "source.add", "extra", url},
		{"source add bad url", ai, "POST", "/api/sources/add", `{"name":"other","url":"file:///etc"}`, 400, "source.add", "other", ""},
		{"source add with credentials", ai, "POST", "/api/sources/add", `{"name":"tok","url":"https://` + urlToken + `@git.example.invalid/x.git"}`, 400, "source.add", "tok", "https://git.example.invalid/x.git"},
		{"source sync", ai, "POST", "/api/sources/sync", ``, 200, "source.sync", "sources", ""},
		{"source remove", ai, "POST", "/api/sources/remove", `{"name":"extra"}`, 200, "source.remove", "extra", ""},
		{"source remove unknown", ai, "POST", "/api/sources/remove", `{"name":"extra"}`, 400, "source.remove", "extra", ""},
		{"default policy", ai, "PUT", "/api/settings", `{"default_auth_policy":{"factors":["webauthn"]}}`, 200, "settings.default_policy", "default", ""},
		{"default policy refused", ai, "PUT", "/api/settings", `{"default_auth_policy":{"factors":["password","mtls"]}}`, 400, "settings.default_policy", "default", ""},
	}
	for _, s := range steps {
		before := len(readAudit(t, e.audit))
		code := call(s.actor, s.method, s.path, s.body)
		if code != s.code {
			t.Errorf("%s: HTTP %d, want %d", s.name, code, s.code)
		}
		var mine []directory.AuditEntry
		for _, a := range readAudit(t, e.audit)[before:] {
			if a.Action == s.action {
				mine = append(mine, a)
			}
		}
		if len(mine) != 1 {
			t.Errorf("%s: %s entries = %+v, want exactly one", s.name, s.action, mine)
			continue
		}
		a := mine[0]
		if a.Target != s.target || a.Result != resultOf(code) {
			t.Errorf("%s: entry target=%q result=%q, want %q %q (%+v)", s.name, a.Target, a.Result, s.target, resultOf(code), a)
		}
		if a.Actor != s.actor.User || a.Via != s.actor.Via || a.Client != s.actor.Client {
			t.Errorf("%s: actor=%q via=%q client=%q, want %+v", s.name, a.Actor, a.Via, a.Client, s.actor)
		}
		if s.want != "" && a.Detail != s.want {
			t.Errorf("%s: detail = %q, want %q", s.name, a.Detail, s.want)
		}
		if a.Result != "ok" && a.Error == "" {
			t.Errorf("%s: a %s entry without its error", s.name, a.Result)
		}
	}
	raw, _ := os.ReadFile(e.audit)
	for _, secret := range []string{secretCmd, "cmd-SECRET", secretVal, urlToken, "ok\\n"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the audit log holds %q:\n%s", secret, raw)
		}
	}
}

// The default policy saved unchanged changes nothing and writes no entry.
func TestDefaultPolicyUnchangedNotAudited(t *testing.T) {
	e := newInstEnv(t)
	body := `{"default_auth_policy":{"factors":["webauthn"]}}`
	mustDo(t, e.hub, "root", http.MethodPut, "/api/settings", body, 200)
	n := len(e.auditActions(t, "settings.default_policy"))
	mustDo(t, e.hub, "root", http.MethodPut, "/api/settings", body, 200)
	if got := e.auditActions(t, "settings.default_policy"); len(got) != n {
		t.Errorf("unchanged save audited: %q", got)
	}
}

const cloudManifest = `name: Cloud
category: productivity
auth:
  method: forward-auth
  group_access: true
  access_group: users_cloud
  public_access:
    enabled_by_default: true
    description: Public share links
    token_pattern: '^[A-Za-z0-9-]{1,32}$'
    paths:
      - prefix: "/s/{token}"
        description: Share page
`

const cloudCompose = "services:\n  cloud:\n    image: nc\n    labels:\n" +
	"      traefik.http.routers.cloud.rule: Host(`${PORTCULLIS_HOST_CLOUD:-cloud.portcullis.local}`)\n" +
	"      traefik.http.services.cloud.loadbalancer.server.port: \"80\"\n"

// TestRefusedPublicTokenNotInAuditFile (security review): a settings
// save refused over its public tokens answers the admin the Hub's
// message, but audit.jsonl holds no form of any token — raw, quoted or a
// share URL's segment.
func TestRefusedPublicTokenNotInAuditFile(t *testing.T) {
	e := newInstEnvWith(t, t.TempDir(), map[string][2]string{"cloud": {cloudManifest, cloudCompose}}, nil)
	if e.s.Hub.Template("cloud") == nil {
		t.Fatal("cloud template not loaded")
	}
	for _, in := range []string{`raw tok!SECRET1`, `tok"SECRET2`, "https://cloud.example.org/s/seg!SECRET3", "https://other.example.org/x/SECRET4"} {
		body, _ := json.Marshal(map[string]any{"public_mode": "listed", "public_tokens": []string{in}})
		code, b := e.do(t, "root", "PUT", "/api/instances/cloud/settings", string(body))
		if code != 400 {
			t.Fatalf("%q: %d %s, want 400", in, code, b)
		}
	}
	raw, _ := os.ReadFile(e.audit)
	if strings.Contains(string(raw), "SECRET") {
		t.Errorf("a token form in audit.jsonl:\n%s", raw)
	}
	if !strings.Contains(string(raw), "public token refused (400)") {
		t.Errorf("no fixed refusal in audit.jsonl:\n%s", raw)
	}
}
