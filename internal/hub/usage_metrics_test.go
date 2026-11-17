package hub

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"

	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
)

func TestUsageCollectorSeries(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"), uunit("a2", "portcullis-a", "db", 1, "running"))
	e.rt.Infos = map[string]runtime.UnitInfo{"a1": {ID: "a1", Memory: 64 << 20}, "a2": {ID: "a2"}}
	e.rt.SetStats("a1", runtime.UnitStats{Read: e.clock.Now(), CPUUsageNS: pu(3e9), MemUsage: pu(1 << 20), Pids: pu(4), NetRx: pu(10), NetTx: pu(20)})
	// db: no memory figure (absent, never 0), no counters.
	e.rt.SetStats("a2", runtime.UnitStats{Read: e.clock.Now(), Pids: pu(2)})
	e.sweep()
	want := `
# HELP portcullis_container_cpu_seconds_total CPU time the container used (seconds).
# TYPE portcullis_container_cpu_seconds_total counter
portcullis_container_cpu_seconds_total{instance="a",number="1",service="web"} 3
# HELP portcullis_container_memory_working_set_bytes The container's working set (usage minus inactive file pages).
# TYPE portcullis_container_memory_working_set_bytes gauge
portcullis_container_memory_working_set_bytes{instance="a",number="1",service="web"} 1.048576e+06
# HELP portcullis_container_memory_limit_bytes The container's memory limit (left out when it has none).
# TYPE portcullis_container_memory_limit_bytes gauge
portcullis_container_memory_limit_bytes{instance="a",number="1",service="web"} 6.7108864e+07
# HELP portcullis_container_pids Processes and threads in the container.
# TYPE portcullis_container_pids gauge
portcullis_container_pids{instance="a",number="1",service="db"} 2
portcullis_container_pids{instance="a",number="1",service="web"} 4
# HELP portcullis_container_network_receive_bytes_total Bytes the container received.
# TYPE portcullis_container_network_receive_bytes_total counter
portcullis_container_network_receive_bytes_total{instance="a",number="1",service="web"} 10
`
	c := e.h.UsageCollector()
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"portcullis_container_cpu_seconds_total", "portcullis_container_memory_working_set_bytes", "portcullis_container_memory_limit_bytes",
		"portcullis_container_pids", "portcullis_container_network_receive_bytes_total"); err != nil {
		t.Error(err)
	}
	if n := testutil.CollectAndCount(c, "portcullis_usage_sampler_last_success_timestamp_seconds"); n != 1 {
		t.Errorf("last success series = %d", n)
	}
	// Kubernetes: CPU is a gauge, so no counter (U9).
	k := newUsageEnv(t, "a")
	k.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"))
	cores := 0.25
	k.rt.SetStats("a1", runtime.UnitStats{Read: k.clock.Now(), CPUCores: &cores, MemWorkingSet: pu(64 << 20)})
	k.sweep()
	if n := testutil.CollectAndCount(k.h.UsageCollector(), "portcullis_container_cpu_seconds_total"); n != 0 {
		t.Errorf("a gauge-only runtime exports %d CPU counters", n)
	}
}

func TestUsageCollectorNoHostPath(t *testing.T) {
	e := newStorageEnv(t)
	e.h.usage.fixer = func(_ context.Context, r fixerRun) (*folderfix.Report, error) {
		return &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 10, Dev: 3, TotalBytes: 100, FreeBytes: 50}, nil
	}
	e.rt.Lock()
	e.rt.Infos["a1"] = runtime.UnitInfo{ID: "a1", Mounts: []runtime.UnitMount{{Type: "bind", Source: "/srv/media-x/x", Destination: "/x"}}}
	e.rt.Unlock()
	e.h.usage.mu.Lock()
	e.h.usage.conts["a1"].Inspect = time.Time{}
	e.h.usage.mu.Unlock()
	e.sweep()
	if _, _, err := e.measure(t, ""); err != nil {
		t.Fatal(err)
	}
	out, err := testutil.CollectAndFormat(e.h.UsageCollector(), expfmt.TypeTextPlain, "portcullis_storage_alloc_bytes", "portcullis_storage_measured_timestamp_seconds", "portcullis_filesystem_free_bytes")
	if err != nil {
		t.Fatal(err)
	}
	txt := string(out)
	if strings.Contains(txt, "/srv") || !strings.Contains(txt, `target="bind:1"`) || !strings.Contains(txt, `portcullis_filesystem_free_bytes{dev="3"} 50`) {
		t.Errorf("metrics:\n%s", txt)
	}
}

func TestUsageCollectorCardinality(t *testing.T) {
	e := newUsageEnv(t, "a")
	var us []runtime.Unit
	for i := range 256 {
		u := uunit(fmt.Sprintf("c%03d", i), "portcullis-a", "web", i+1, "running")
		us = append(us, u)
		e.rt.SetStats(u.ID, runtime.UnitStats{Read: e.clock.Now(), CPUUsageNS: pu(1), MemUsage: pu(1), Pids: pu(1), NetRx: pu(1), NetTx: pu(1), BlkRead: pu(1), BlkWrite: pu(1)})
	}
	e.setUnits(us...)
	e.rt.Infos = map[string]runtime.UnitInfo{}
	for _, u := range us {
		e.rt.Infos[u.ID] = runtime.UnitInfo{ID: u.ID, Memory: 1 << 20}
	}
	e.sweep()
	reg := prometheus.NewRegistry()
	reg.MustRegister(e.h.UsageCollector())
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, mf := range mfs {
		n += len(mf.GetMetric())
	}
	if n > 2600 || n < 2000 {
		t.Errorf("%d series", n)
	}
}

func TestMetricsScrapedRecently(t *testing.T) {
	e := newUsageEnv(t)
	if e.h.MetricsScrapedRecently() {
		t.Error("scraped before any scrape")
	}
	e.h.NoteMetricsScrape()
	if !e.h.MetricsScrapedRecently() || !e.h.UsageOverview().MetricsScraped || !e.h.UsageStorage().MetricsScraped {
		t.Error("not scraped after a scrape")
	}
	e.clock.Add(6 * time.Minute)
	if e.h.MetricsScrapedRecently() {
		t.Error("still scraped 6 min later")
	}
}
