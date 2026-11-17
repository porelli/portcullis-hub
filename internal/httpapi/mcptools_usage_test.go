package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	dockerrt "github.com/portcullis/hub/internal/runtime/docker"
	"github.com/portcullis/hub/internal/state"
)

// usageWrapEngine answers the usage calls of the docker backend with one
// running container of instance grafana-a.
type usageWrapEngine struct{ dockerrt.Engine }

func (usageWrapEngine) ListContainers(_ context.Context, f docker.Filters) ([]docker.Container, error) {
	for _, l := range f["label"] {
		if l == docker.LabelHelper {
			return nil, nil // no helpers: the start-up sweep removes nothing
		}
	}
	return []docker.Container{{ID: "web1", Names: []string{"/portcullis-grafana-a-web-1"}, State: "running",
		Labels: map[string]string{docker.LabelProject: "portcullis-grafana-a", docker.LabelService: "web", docker.LabelNumber: "1"}}}, nil
}

func (usageWrapEngine) ContainerStats(context.Context, string) (runtime.UnitStats, error) {
	m := uint64(32 << 20)
	return runtime.UnitStats{Read: time.Now(), MemUsage: &m}, nil
}

func (usageWrapEngine) InspectContainer(_ context.Context, id string) (docker.ContainerInfo, error) {
	return docker.ContainerInfo{ID: id, Memory: 64 << 20}, nil
}

func (usageWrapEngine) HostResources(context.Context) (int, int64, error) { return 2, 4 << 30, nil }

const usageRedactLiteral = "redact-me-0123456789"

func usageToolEnv(t *testing.T) *toolEnv {
	t.Helper()
	e := newToolEnvWith(t, mcpEnvOpts{
		wrap: func(en dockerrt.Engine) dockerrt.Engine { return usageWrapEngine{en} },
		seed: func(st *state.AppState) {
			if st.Instances == nil {
				st.Instances = map[string]state.Instance{}
			}
			st.Instances["grafana-a"] = state.Instance{ID: "grafana-a", Template: "grafana", State: state.InstanceCreated,
				Hosts: map[string]string{"grafana": "grafana-a.example.org"}, Label: "Team " + usageRedactLiteral}
		},
	})
	e.s.Hub.SweepUsage(context.Background())
	return e
}

// canonJSON re-encodes a JSON text (key order, spacing).
func canonJSON(t *testing.T, s string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("not JSON: %v: %s", err, s)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestUsageToolsParity(t *testing.T) {
	e := usageToolEnv(t)
	byName := map[string]Tool{}
	for _, tl := range e.s.tools(ScopeAdmin) {
		byName[tl.Name] = tl
	}
	for name, twin := range map[string]string{"usage_overview": "GET /api/usage", "usage_instance": "GET /api/usage/instances/{id}"} {
		if tl, ok := byName[name]; !ok || tl.Class != ClassRead || tl.Twin != twin {
			t.Errorf("%s = %+v", name, tl)
		}
	}
	for _, c := range []struct {
		tool string
		args any
		path string
	}{
		{"usage_overview", map[string]any{}, "/api/usage"},
		{"usage_instance", map[string]any{"id": "grafana-a"}, "/api/usage/instances/grafana-a"},
	} {
		txt, isErr, _ := e.tool(t, c.tool, c.args)
		if isErr {
			t.Fatalf("%s: %s", c.tool, txt)
		}
		route := mustDo(t, e.hub, "root", "GET", c.path, "", 200)
		if !strings.Contains(route, usageRedactLiteral) {
			t.Fatalf("%s: the label isn't in the route's answer: %s", c.tool, route)
		}
		// metrics_scraped / sampled_at are equal: both answers read one cache.
		if canonJSON(t, txt) != canonJSON(t, route) {
			t.Errorf("%s differs from %s:\n tool  %s\n route %s", c.tool, c.path, txt, route)
		}
	}
	// A redact literal planted in a label is masked in the tools' answers.
	e.s.RedactLiterals = []string{usageRedactLiteral}
	for _, c := range []struct {
		tool string
		args any
	}{{"usage_overview", map[string]any{}}, {"usage_instance", map[string]any{"id": "grafana-a"}}} {
		txt, isErr, _ := e.tool(t, c.tool, c.args)
		if isErr || strings.Contains(txt, usageRedactLiteral) {
			t.Errorf("%s: redaction: %v %s", c.tool, isErr, txt)
		}
	}
	if txt, isErr, _ := e.tool(t, "usage_instance", map[string]any{"id": "../x"}); !isErr || !strings.Contains(txt, "404") || !strings.Contains(txt, "app instance not found") {
		t.Errorf("bad id = %v %s", isErr, txt)
	}
}
