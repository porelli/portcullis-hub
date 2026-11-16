package agent

import (
	"context"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/runtime"
)

// gather is the agent registry's metrics by name.
func gather(t *testing.T, a *Agent) map[string][]*dto.Metric {
	t.Helper()
	mfs, err := a.registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]*dto.Metric{}
	for _, mf := range mfs {
		out[mf.GetName()] = mf.Metric
	}
	return out
}

// TestAgentDiskAndHealthMetrics (core T17's alerts; link re-labels them
// with server=<id>): the engine root's free and total bytes, the data
// dir's total next to its free bytes, and one unhealthy gauge per
// bundled instance service.
func TestAgentDiskAndHealthMetrics(t *testing.T) {
	root, data := t.TempDir(), t.TempDir()
	a := &Agent{cfg: Config{DataDir: data, Runtime: "docker",
		Info: func(context.Context) (agentapi.Info, error) { return agentapi.Info{DockerRootDir: root}, nil },
		Unhealthy: func(context.Context) []UnitHealth {
			return []UnitHealth{{Instance: "notes", Service: "web"}}
		}}}
	m := gather(t, a)
	for _, n := range []string{"portcullis_agent_disk_free_bytes", "portcullis_agent_disk_total_bytes", "portcullis_agent_data_total_bytes", "portcullis_agent_data_free_bytes"} {
		if len(m[n]) != 1 || m[n][0].GetGauge().GetValue() <= 0 {
			t.Errorf("%s = %v", n, m[n])
		}
	}
	u := m["portcullis_agent_container_unhealthy"]
	if len(u) != 1 || u[0].GetGauge().GetValue() != 1 {
		t.Fatalf("unhealthy %v", u)
	}
	labels := map[string]string{}
	for _, l := range u[0].Label {
		labels[l.GetName()] = l.GetValue()
	}
	if labels["app"] != "notes" || labels["service"] != "web" || len(labels) != 2 {
		t.Errorf("labels %v", labels)
	}
	// No engine root known: the gauges are 0, never an error.
	b := &Agent{cfg: Config{DataDir: data, Runtime: "docker"}}
	if m := gather(t, b); m["portcullis_agent_disk_total_bytes"][0].GetGauge().GetValue() != 0 || len(m["portcullis_agent_container_unhealthy"]) != 0 {
		t.Errorf("no root / no health source: %v", m)
	}
}

// TestUnhealthyListsBundledOnly: an unhealthy container of a bundled
// instance counts (once per service); healthy ones, unbundled projects
// and the agent's own don't.
func TestUnhealthyListsBundledOnly(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app")
	f.rt.Lock()
	f.rt.Units = []runtime.Unit{
		{ID: "1", Project: "portcullis-app", Service: "web", State: "running", Status: "Up 3 minutes (unhealthy)"},
		{ID: "2", Project: "portcullis-app", Service: "web", State: "running", Status: "Up 3 minutes (unhealthy)"},
		{ID: "3", Project: "portcullis-app", Service: "db", State: "running", Status: "Up 3 minutes (healthy)"},
		{ID: "4", Project: "portcullis-ghost", Service: "web", State: "running", Status: "Up (unhealthy)"},
		{ID: "5", Project: "portcullis-worker", Service: "agent", State: "running", Status: "Up (unhealthy)"},
	}
	f.rt.Unlock()
	got := f.api.Unhealthy(context.Background())
	if len(got) != 1 || got[0] != (UnitHealth{Instance: "app", Service: "web"}) {
		t.Errorf("%v", got)
	}
}
