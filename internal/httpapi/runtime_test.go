package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

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
	g := docker.NewGuard(docker.RuntimeDocker)
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{
		cfg:    func(c *hub.Config) { c.Runtime, c.Guard = docker.RuntimeDocker, g },
		engine: func(f *fakeEngine) hub.Engine { return refusingEngine{fakeEngine: f, g: g} },
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
