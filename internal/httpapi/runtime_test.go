package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/runtime/kube"

	"github.com/portcullis/hub/internal/runtime/runtimetest"

	"github.com/portcullis/hub/internal/runtime"
	dockerrt "github.com/portcullis/hub/internal/runtime/docker"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/hub"
)

type fakeVersions []docker.Component

func (f fakeVersions) Components(context.Context) ([]docker.Component, error) { return f, nil }

// refusingEngine answers every container listing with the guard's
// refusal, decorated the way the SDK decorates a transport error.
type refusingEngine struct {
	*fakeEngine
	g *docker.Guard
}

func (e refusingEngine) ListContainers(ctx context.Context, f docker.Filters) ([]docker.Container, error) {
	if err := e.g.Err(); err != nil {
		return nil, fmt.Errorf("error during connect: Get \"http://socket-proxy-hub:2375/v1.47/containers/json\": %w", err)
	}
	return e.fakeEngine.ListContainers(ctx, f)
}

func TestRuntimeRoute(t *testing.T) {
	g := docker.NewGuard(runtime.KindDocker)
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{
		cfg:    func(c *hub.Config) { c.Runtime, c.Guard = runtime.KindDocker, g },
		engine: func(f *fakeEngine) dockerrt.Engine { return refusingEngine{fakeEngine: f, g: g} },
	})
	code, body := e.do(t, "root", "GET", "/api/runtime", "")
	if code != 200 {
		t.Fatalf("GET /api/runtime = %d %s", code, body)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"runtime", "verified", "engine", "engine_version", "mismatch", "rootless", "uid_map", "gid_map", "unprivileged_port_start", "selinux"} {
		if _, ok := v[k]; !ok {
			t.Errorf("no %q in %s", k, body)
		}
	}
	if v["runtime"] != "docker" || v["verified"] != false || v["uid_map"] != nil || v["unprivileged_port_start"] != nil {
		t.Errorf("view = %s", body)
	}
	// Another route reaching the refused engine: 503 with the guard's
	// own message.
	code, body = e.do(t, "root", "GET", "/api/templates/logs/grafana", "")
	if code != 503 || !strings.Contains(body, "the container engine is not verified: not checked yet") || strings.Contains(body, "error during connect") {
		t.Errorf("refused engine: %d %q", code, body)
	}
	// Admins only; the people listener has no such route.
	if code, _ := e.do(t, "dana", "GET", "/api/runtime", ""); code != 403 {
		t.Errorf("non-admin: %d", code)
	}
	if r, _ := doAs(t, e.ppl, "root", "GET", "/api/runtime", ""); r.StatusCode == 200 {
		t.Errorf("people listener answers /api/runtime")
	}
	// Verified: 200 and the engine named.
	if err := g.Verify(context.Background(), fakeVersions{{Name: "Engine", Version: "29.0.0"}}); err != nil {
		t.Fatal(err)
	}
	_, body = e.do(t, "root", "GET", "/api/runtime", "")
	if !strings.Contains(body, `"verified":true`) || !strings.Contains(body, `"engine":"Engine"`) {
		t.Errorf("verified view = %s", body)
	}
}

// TestRuntimeRouteKubernetes: under Kubernetes the view comes from the
// cluster guard (Info) plus core.env's kube context, and adds context,
// admission and netpol; the maps and the port start are null.
func TestRuntimeRouteKubernetes(t *testing.T) {
	rt := &runtimetest.Fake{K: runtime.KindKubernetes, InfoVal: runtime.Info{Verified: true, EngineVersion: "v1.37.2+k3s1", Admission: "ok", Netpol: "proven"}}
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{
		cfg: func(c *hub.Config) {
			c.Runtime = runtime.KindKubernetes
			os.MkdirAll(c.ProjectDir, 0o755)
			os.WriteFile(filepath.Join(c.ProjectDir, ".env"), []byte("PORTCULLIS_KUBE_CONTEXT=default\n"), 0o644)
		},
		rt: rt,
	})
	code, body := e.do(t, "root", "GET", "/api/runtime", "")
	if code != 200 {
		t.Fatalf("GET /api/runtime = %d %s", code, body)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"runtime": "kubernetes", "verified": true, "engine": "Kubernetes", "engine_version": "v1.37.2+k3s1", "mismatch": "",
		"rootless": false, "uid_map": nil, "gid_map": nil, "unprivileged_port_start": nil, "selinux": false, "context": "default", "admission": "ok", "netpol": "proven"}
	for k, w := range want {
		if got, ok := v[k]; !ok || got != w {
			t.Errorf("%s = %v (present %v), want %v", k, got, ok, w)
		}
	}
	// Not verified: the guard's why is the mismatch; the self-test and
	// the probe say so.
	rt.SetInfo(runtime.Info{Verified: false, Why: "admission self-test: guard missing", Admission: "missing", Netpol: "unproven"})
	_, body = e.do(t, "root", "GET", "/api/runtime", "")
	json.Unmarshal([]byte(body), &v)
	if v["verified"] != false || v["mismatch"] != "admission self-test: guard missing" || v["admission"] != "missing" || v["netpol"] != "unproven" {
		t.Errorf("unverified view = %s", body)
	}
}

// Under Docker and Podman context, admission and netpol are absent.
func TestRuntimeRouteNoKubeFields(t *testing.T) {
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{})
	_, body := e.do(t, "root", "GET", "/api/runtime", "")
	for _, k := range []string{`"context"`, `"admission"`, `"netpol"`} {
		if strings.Contains(body, k) {
			t.Errorf("docker view has %s: %s", k, body)
		}
	}
}

// The cluster guard's refusal is a 503 with its why, like the engine
// guard's.
func TestClusterUnverifiedIs503(t *testing.T) {
	err := fmt.Errorf("listing: %w", &kube.UnverifiedError{Why: "admission self-test: the guard is missing"})
	if got := errStatus(err, 500); got != 503 {
		t.Errorf("status %d", got)
	}
}
