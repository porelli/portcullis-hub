package kube

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/templates"
)

// translatorOnly are the translator's refusals RuntimeCompat can't judge
// from a template: they depend on deploy-time inputs (the Hub's state,
// core.env, file contents) or on the Hub's own rendering. Every other
// refusal must be one kubeCompat gives too.
var translatorOnly = map[string]string{
	"%s needs internet egress, and core.env has no node addresses (PORTCULLIS_KUBE_NODE_ADDRESSES): not deployed": "core.env",
	"API address %s is not an IPv4 address":                       "core.env",
	"node address %s is not an IPv4 address":                      "core.env",
	"VPN slot %d is outside 0–46":                                 "the Hub's VPN state",
	"%s %s exceeds 1 MiB":                                         "file contents",
	"data file %s exceeds 1 MiB":                                  "file contents",
	"secret %s exceeds 1 MiB":                                     "file contents",
	"template files for %s exceed 1 MiB":                          "file contents",
	"service %s binds a template file that doesn't exist":         "files on disk",
	"%s and %s give the same object name %s":                      "names from the manifest and the Hub's inputs (data files, options)",
	"%s: no compose model":                                        "internal",
	"service %s: its image is not resolved to a digest":           "registry",
	"companion %s: port %d":                                       "the Hub's companion inputs",
	"companion %s: service %s is not a compose service":           "the Hub's companion inputs",
	"companion alias %q isn't portcullis-mcp-%s--<companion>":     "the Hub's companion inputs",
	"service %s mounts the per-person secrets at %q, not its own": "the Hub's override",
	"service %s publishes port %d for the local networks only, and no (IPv4) Local networks are set": "the Hub's Local networks setting",
	"the services' depends_on form a cycle":                                                          "compose refuses the file first",
}

var verbRe = regexp.MustCompile(`%[sdqv]`)

// literals are the string literals of the Go files, by name (first
// argument of calls to name, or every literal when name is "").
func literals(t *testing.T, files []string, name string) map[string]string {
	t.Helper()
	out := map[string]string{}
	fs := token.NewFileSet()
	for _, f := range files {
		af, err := parser.ParseFile(fs, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if name == "" {
				if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					if s, err := strconv.Unquote(bl.Value); err == nil {
						out[s] = filepath.Base(f)
					}
				}
				return true
			}
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != name {
				return true
			}
			if bl, ok := call.Args[0].(*ast.BasicLit); ok && bl.Kind == token.STRING {
				if s, err := strconv.Unquote(bl.Value); err == nil {
					out[s] = filepath.Base(f)
				}
			}
			return true
		})
	}
	return out
}

// TestEveryTranslatorRefusalInCompat: each refusal the translator can
// give is one kubeCompat gives as well (same text, verbs aside), or it's
// judged through KubeLabelCheck (ingress.go: the very code), or it's on
// translatorOnly with its reason. The vectors (TestTranslatorRefusesWhat
// CompatRefuses) then prove the two agree case by case.
func TestEveryTranslatorRefusalInCompat(t *testing.T) {
	if templates.KubeLabelCheck == nil {
		t.Fatal("templates.KubeLabelCheck isn't installed")
	}
	var mine []string
	ents, _ := os.ReadDir(".")
	for _, e := range ents {
		if n := e.Name(); strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") && n != "ingress.go" {
			mine = append(mine, n)
		}
	}
	compat := map[string]bool{}
	for s := range literals(t, []string{"../../templates/kubecompat.go", "../../templates/runtimecompat.go"}, "") {
		compat[verbRe.ReplaceAllString(s, "%")] = true
	}
	seen := map[string]bool{}
	for f, file := range literals(t, mine, "refused") {
		seen[f] = true
		if _, ok := translatorOnly[f]; ok || compat[verbRe.ReplaceAllString(f, "%")] {
			continue
		}
		t.Errorf("%s: the translator refuses %q, kubeCompat never does (add it there, or to translatorOnly with why)", file, f)
	}
	for f := range translatorOnly {
		if !seen[f] {
			t.Errorf("translatorOnly %q: no such refusal any more", f)
		}
	}
}

// TestCompatJudgesLabelsLikeTheDeploy: a template's Traefik labels the
// deploy would refuse are refused by RuntimeCompat, with the same text.
func TestCompatJudgesLabelsLikeTheDeploy(t *testing.T) {
	for labels, why := range map[string]string{
		"      traefik.http.routers.web.rule: Host(`a.example.org`)\n      traefik.http.services.web.loadbalancer.server.port: \"80\"\n      traefik.http.services.web.loadbalancer.server.scheme: https\n": "service web: loadbalancer.server.scheme is not on Kubernetes",
		"      traefik.tcp.routers.db.rule: HostSNI(`*`)\n": "web: tcp routers are not on Kubernetes",
		"      traefik.http.routers.web.rule: Host(`a.example.org`)\n      traefik.http.routers.web.priority: \"5000\"\n      traefik.http.services.web.loadbalancer.server.port: \"80\"\n": "router web: priority 5000 is above 1000 (not on Kubernetes)",
		"      traefik.http.routers.web.rule: Host(`a.example.org`)\n      traefik.http.services.web.loadbalancer.server.port: \"80\"\n":                                                    "",
	} {
		compose := "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: \"101:101\"\n    labels:\n      traefik.enable: \"true\"\n" + labels
		c := templates.RuntimeCompat("kubernetes", []byte(compose), templates.Manifest{}, nil, 80)
		got := strings.Join(c.Reasons, "; ")
		if got != why {
			t.Errorf("%q: compat %q, want %q", labels, got, why)
		}
		_, err := Translate(inputOf(t, compose, "lc"))
		if refusedErr(err) != why {
			t.Errorf("%q: translator %v", labels, err)
		}
	}
}

// TestRefusalsNeverEchoInstanceValues: values the instance's env puts
// into a template (a secret, an admin's path) never appear in a refusal,
// from RuntimeCompat or from the translator.
func TestRefusalsNeverEchoInstanceValues(t *testing.T) {
	const secret = "s3cr3t-Hunter2-value"
	env := map[string]string{"APP_USER": secret, "APP_GROUP": secret, "APP_CAP": secret, "APP_PATH": "/" + secret, "APP_IP": secret,
		"APP_EXPOSE": secret, "PORTCULLIS_HOST_WEB": secret + ".example.org", "APP_PRIO": secret, "APP_TIER": secret, "APP_SVC": secret}
	composes := []string{
		"services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: ${APP_USER}\n",
		"services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: \"101:101\"\n    group_add: [\"${APP_GROUP}\"]\n",
		"services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: \"101:101\"\n    cap_add: [\"${APP_CAP}\"]\n",
		"services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: \"101:101\"\n    volumes: [\"${APP_PATH}:/data\"]\n",
		"services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: \"101:101\"\n    ports: [\"${APP_IP}:8080:80\"]\n",
		"services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: \"101:101\"\n    expose: [\"${APP_EXPOSE}\"]\n",
		"services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: \"101:101\"\n    labels:\n      traefik.enable: \"true\"\n" +
			"      traefik.http.routers.web.rule: Host(`${PORTCULLIS_HOST_WEB:-web.portcullis.local}`) && Headers(`X`, `${APP_SVC}`)\n      traefik.http.services.web.loadbalancer.server.port: \"80\"\n",
		"services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: \"101:101\"\n    labels:\n      traefik.enable: \"true\"\n" +
			"      traefik.http.routers.web.rule: Host(`a.example.org`)\n      traefik.http.routers.web.priority: ${APP_PRIO}\n      traefik.http.routers.web.tls.options: ${APP_TIER}\n      traefik.http.routers.web.service: ${APP_SVC}\n",
	}
	for _, compose := range composes {
		c := templates.RuntimeCompat("kubernetes", []byte(compose), templates.Manifest{}, env, 80)
		if r := strings.Join(c.Reasons, "; "); strings.Contains(strings.ToLower(r), strings.ToLower(secret)) {
			t.Errorf("compat echoes the value: %s", r)
		}
		dir := t.TempDir()
		var lines []string
		for k, v := range env {
			lines = append(lines, k+"="+v)
		}
		os.WriteFile(filepath.Join(dir, "env"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(compose), 0o644)
		m, err := loadModelErr(dir, "sec")
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(secret)) {
				t.Logf("compose itself names the value (not a Hub refusal): %v", err)
			}
			continue
		}
		in := Input{Instance: "sec", Template: "x", Namespace: ns, Model: m, Digests: digests(m), HubImage: hubImage, BindRoots: []string{"/srv"},
			Settings: Settings{PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16", NodeAddresses: []string{"192.0.2.10"}}}
		if _, err := Translate(in); err != nil && strings.Contains(strings.ToLower(err.Error()), strings.ToLower(secret)) {
			t.Errorf("translator echoes the value: %v", err)
		}
	}
}

// TestRefusalsQuoteOnlyKnownNames: a router's service or middleware is
// quoted only when it is core's documented name or the template's own;
// any other value (it may come from the instance's settings) isn't.
func TestRefusalsQuoteOnlyKnownNames(t *testing.T) {
	const secret = "s3cr3t-pass.word@x"
	base := map[string]string{"traefik.http.routers.r.rule": "Host(`a.example.org`)", "traefik.http.services.web.loadbalancer.server.port": "80",
		"traefik.http.middlewares.mw.headers.customrequestheaders.A": "b"}
	for _, c := range []struct{ key, value, want string }{
		{"traefik.http.routers.r.service", secret, "router r: its service isn't on Kubernetes"},
		{"traefik.http.routers.r.middlewares", secret, "a middleware is not on Kubernetes (not the instance's own, not a core name apps may use)"},
		{"traefik.http.routers.r.service", "hub@docker", "router r: service hub@docker is not on Kubernetes"},
		{"traefik.http.routers.r.service", "web@" + secret, "router r: its service isn't on Kubernetes"},
		{"traefik.http.routers.r.service", "Web@" + secret, "router r: its service isn't on Kubernetes"},
		{"traefik.http.routers.r.service", "web@kubernetescrd", "router r: its service isn't on Kubernetes"},
		{"traefik.http.routers.r.service", "Web@file", "router r: service web@file is not on Kubernetes"},
		{"traefik.http.routers.r.middlewares", "mw@" + secret, "a middleware is not on Kubernetes (not the instance's own, not a core name apps may use)"},
		{"traefik.http.routers.r.middlewares", "mw@file", "middleware mw@file is not on Kubernetes (not the instance's own, not a core name apps may use)"},
		{"traefik.http.routers.r.middlewares", "hub-proxy-secret@docker", "middleware hub-proxy-secret@docker is not on Kubernetes (not the instance's own, not a core name apps may use)"},
	} {
		l := maps.Clone(base)
		l[c.key] = c.value
		_, err := IngressObjects("app", EdgeNamespace, ns, map[string]map[string]string{"web": l})
		if got := refusedErr(err); got != c.want {
			t.Errorf("%s=%s: %q, want %q", c.key, c.value, got, c.want)
		}
		if strings.Contains(fmt.Sprint(err), secret) {
			t.Errorf("echoed: %v", err)
		}
	}
	// Through RuntimeCompat with the value in the instance env.
	compose := "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: \"101:101\"\n    labels:\n      traefik.enable: \"true\"\n" +
		"      traefik.http.routers.r.rule: Host(`a.example.org`)\n      traefik.http.routers.r.service: ${SVC:-web}\n      traefik.http.services.web.loadbalancer.server.port: \"80\"\n"
	c := templates.RuntimeCompat("kubernetes", []byte(compose), templates.Manifest{}, map[string]string{"SVC": secret}, 80)
	if strings.Contains(strings.Join(c.Reasons, " "), secret) {
		t.Errorf("compat echoed: %v", c.Reasons)
	}
}

// TestEdgeNamesStayOneLabel: a router or middleware whose name would
// give an edge object name with "--" (or a trailing -) after <instance>--
// once sanitized is refused, by RuntimeCompat and the translator alike
// (core's admission: one DNS label without "--").
func TestEdgeNamesStayOneLabel(t *testing.T) {
	for labels, why := range map[string]string{
		"      traefik.http.routers.web.rule: Host(`a.example.org`)\n      traefik.http.routers.web.middlewares: a__b\n      traefik.http.middlewares.a__b.headers.customrequestheaders.X: y\n      traefik.http.services.web.loadbalancer.server.port: \"80\"\n": "middleware a__b: its name isn't one DNS label once _ and . become - (no --, no trailing -; not on Kubernetes)",
		"      traefik.http.routers.web_.rule: Host(`a.example.org`)\n      traefik.http.services.web.loadbalancer.server.port: \"80\"\n":                                                                                                                         "router web_: its name isn't one DNS label once _ and . become - (no --, no trailing -; not on Kubernetes)",
		"      traefik.http.routers.web_1.rule: Host(`a.example.org`)\n      traefik.http.services.web.loadbalancer.server.port: \"80\"\n":                                                                                                                        "",
	} {
		compose := "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    user: \"101:101\"\n    labels:\n      traefik.enable: \"true\"\n" + labels
		c := templates.RuntimeCompat("kubernetes", []byte(compose), templates.Manifest{}, nil, 80)
		if got := strings.Join(c.Reasons, "; "); got != why {
			t.Errorf("compat %q, want %q", got, why)
		}
		if _, err := Translate(inputOf(t, compose, "en")); refusedErr(err) != why {
			t.Errorf("translator %v, want %q", err, why)
		}
	}
}

// TestEdgeNameJudgesTemplatePartOnly: the Hub's companion router
// portcullis-mcp-<instance>--<companion> passes (its "--" is the Hub's);
// a template name with "__" is still refused, also after that prefix,
// and another instance's prefix isn't the Hub's.
func TestEdgeNameJudgesTemplatePartOnly(t *testing.T) {
	route := func(r string) map[string]map[string]string {
		return map[string]map[string]string{"web": {"traefik.http.routers." + r + ".rule": "Host(`a.example.org`) && (Path(`/mcp`) || Path(`/.well-known/oauth-protected-resource/mcp`))",
			"traefik.http.routers." + r + ".service": "mcp-gate@docker", "traefik.http.services.web.loadbalancer.server.port": "80"}}
	}
	if _, err := IngressObjects("echo-k", EdgeNamespace, ns, route("portcullis-mcp-echo-k--echo")); err != nil {
		t.Errorf("the companion router: %v", err)
	}
	for _, r := range []string{"portcullis-mcp-echo-k--a__b", "a__b", "portcullis-mcp-other--echo"} {
		if _, err := IngressObjects("echo-k", EdgeNamespace, ns, route(r)); !strings.Contains(refusedErr(err), "isn't one DNS label") {
			t.Errorf("%s: %v", r, err)
		}
	}
}
