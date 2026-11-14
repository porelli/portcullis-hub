package kube

import (
	"go/ast"
	"go/parser"
	"go/token"
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
	"API address %q is not an IPv4 address":                       "core.env",
	"node address %q is not an IPv4 address":                      "core.env",
	"VPN slot %d is outside 0–46":                                 "the Hub's VPN state",
	"%s %s exceeds 1 MiB":                                         "file contents",
	"data file %s exceeds 1 MiB":                                  "file contents",
	"secret %s exceeds 1 MiB":                                     "file contents",
	"template files for %s exceed 1 MiB":                          "file contents",
	"service %s binds template file %s, which doesn't exist":      "files on disk",
	"%s and %s give the same object name %s":                      "names from the manifest and the Hub's inputs (data files, options)",
	"%s: no compose model":                                        "internal",
	"service %s: image %s is not resolved to a digest":            "registry",
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
