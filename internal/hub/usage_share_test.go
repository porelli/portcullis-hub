package hub

import (
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/usage"
)

// fakeHost is a readHost hook: each call's counters advance by 15 s of
// 3000 ticks, 1500 idle, and 15 × 4096 bytes read.
func (e *usageEnv) fakeHost() *atomic.Int32 {
	var n atomic.Int32
	e.h.usage.readHost = func() (usage.HostCounters, error) {
		i := uint64(n.Add(1))
		return usage.HostCounters{At: e.clock.Now(), CPUTotal: 10000 + 3000*i, CPUIdle: 5000 + 1500*i,
			MemTotal: 16 << 30, MemAvailable: 10 << 30, DiskRead: 15 * 4096 * i, DiskWrite: 1 << 20}, nil
	}
	return &n
}

func TestUsageHostsPrimary(t *testing.T) {
	e := newUsageEnv(t, "a")
	reads := e.fakeHost()
	e.rt.InfoVal.CPUs = 2
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"), uunit("hub", "portcullis", "hub", 1, "running"))
	e.stats("a1", 1e9, 1<<20)
	e.stats("hub", 1e9, 1<<20)
	e.sweep()
	v := e.h.UsageOverview("last")
	h, ok := v.Hosts["primary"]
	if !ok || h.Name != "Primary" || h.CPUs == nil || *h.CPUs != 2 || h.MemoryBytes == nil {
		t.Fatalf("hosts = %+v", v.Hosts)
	}
	// The first read has no rate yet; memory is there at once.
	if h.CPUUsedCores != nil || h.BlkReadBps != nil || h.MemUsedBytes == nil || *h.MemUsedBytes != 6<<30 {
		t.Errorf("first = %+v", h)
	}
	e.clock.Add(usage.Interval)
	e.sweep()
	v = e.h.UsageOverview("last")
	h = v.Hosts["primary"]
	if h.CPUUsedCores == nil || *h.CPUUsedCores != 1.0 || h.MemUsedBytes == nil || *h.MemUsedBytes != 6<<30 {
		t.Errorf("cpu / mem = %v %v", h.CPUUsedCores, h.MemUsedBytes)
	}
	if h.BlkReadBps == nil || *h.BlkReadBps != 4096 || h.BlkWriteBps == nil || *h.BlkWriteBps != 0 || h.Why != "" {
		t.Errorf("blk = %v %v %q", h.BlkReadBps, h.BlkWriteBps, h.Why)
	}
	if reads.Load() != 2 {
		t.Errorf("host read %d times in 2 sweeps", reads.Load())
	}
	if len(v.Apps) != 1 || v.Apps[0].Server != "primary" || v.Core.Server != "primary" {
		t.Errorf("servers = %+v / %q", v.Apps, v.Core.Server)
	}
	if g, err := e.h.UsageInstance("a"); err != nil || g.Server != "primary" {
		t.Errorf("instance = %+v %v", g, err)
	}
	if n := e.h.usage.hostRing.Len(); n != 2 {
		t.Errorf("host ring = %d points", n)
	}

	b, _ := json.Marshal(v)
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["host"]; ok {
		t.Error("the old host field is still there")
	}
	hp := raw["hosts"].(map[string]any)["primary"].(map[string]any)
	for _, k := range []string{"name", "cpus", "memory_bytes", "cpu_used_cores", "mem_used_bytes", "blk_read_bps", "blk_write_bps"} {
		if _, ok := hp[k]; !ok {
			t.Errorf("hosts.primary has no %q", k)
		}
	}
	if _, ok := hp["why"]; ok {
		t.Error("why without a reason")
	}
	if raw["apps"].([]any)[0].(map[string]any)["server"] != "primary" {
		t.Error("apps[0].server")
	}
}

// A failed read: no figure (never 0) and the error logged once, not
// every sweep; the counters before it still give the next rate.
func TestUsageHostsReadFails(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.rt.InfoVal.CPUs = 2
	var fail atomic.Bool
	n := 0
	e.h.usage.readHost = func() (usage.HostCounters, error) {
		if fail.Load() {
			return usage.HostCounters{}, errors.New("open /proc/stat: no such file")
		}
		n++
		return usage.HostCounters{At: e.clock.Now(), CPUTotal: uint64(3000 * n), CPUIdle: uint64(1500 * n), MemTotal: 4 << 30, MemAvailable: 1 << 30}, nil
	}
	logs := captureLog(t)
	e.sweep()
	fail.Store(true)
	for range 3 {
		e.clock.Add(usage.Interval)
		e.sweep()
	}
	h := e.h.UsageOverview("last").Hosts["primary"]
	if h.CPUUsedCores != nil || h.MemUsedBytes != nil || h.BlkReadBps != nil {
		t.Errorf("failed read = %+v", h)
	}
	if c := strings.Count(logs.String(), "usage: the host's counters"); c != 1 {
		t.Errorf("logged %d times:\n%s", c, logs.String())
	}
	fail.Store(false)
	e.clock.Add(usage.Interval)
	e.sweep()
	h = e.h.UsageOverview("last").Hosts["primary"]
	// 60 s over 3000 ticks, 1500 idle on 2 CPUs.
	if h.CPUUsedCores == nil || *h.CPUUsedCores != 1.0 || h.MemUsedBytes == nil || *h.MemUsedBytes != 3<<30 {
		t.Errorf("after = %+v", h)
	}
}

func TestUsageHostsKubernetes(t *testing.T) {
	e := newUsageEnv(t, "a")
	reads := e.fakeHost()
	e.rt.K = runtime.KindKubernetes
	e.setUnits(uunit("a--web-x/web", "portcullis-a", "web", 1, "running"))
	e.stats("a--web-x/web", 1e9, 1<<20)
	e.sweep()
	e.clock.Add(usage.Interval)
	e.sweep()
	v := e.h.UsageOverview("last")
	h, ok := v.Hosts["primary"]
	if !ok || h.Name != "Primary" || h.Why != "not measured on Kubernetes" {
		t.Fatalf("hosts = %+v", v.Hosts)
	}
	if h.CPUs != nil || h.MemoryBytes != nil || h.CPUUsedCores != nil || h.MemUsedBytes != nil || h.BlkReadBps != nil || h.BlkWriteBps != nil {
		t.Errorf("a figure on Kubernetes: %+v", h)
	}
	if reads.Load() != 0 {
		t.Errorf("the pod's procfs read %d times on Kubernetes", reads.Load())
	}
	if len(v.Apps) != 1 || v.Apps[0].Server != "primary" {
		t.Errorf("apps = %+v", v.Apps)
	}
}

// TestUsageWindow1h: in window 1h each container's sample is the mean of
// its hour (nulls skipped, the group partial then), the totals sum those
// means, and hosts.primary is the host's mean; window last is unchanged.
func TestUsageWindow1h(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.fakeHost()
	e.rt.InfoVal.CPUs = 2
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"), uunit("a2", "portcullis-a", "db", 1, "running"))
	cpu := []uint64{0, 15e9, 45e9, 90e9} // nil, 1, 2, 3 cores
	for i := range 4 {
		if i > 0 {
			e.clock.Add(usage.Interval)
		}
		e.stats("a1", cpu[i], uint64(100*(i+1)))
		e.stats("a2", 0, 100)
		e.sweep()
	}
	v := e.h.UsageOverview("1h")
	if v.Window != "1h" || len(v.Apps) != 1 {
		t.Fatalf("window %q apps %+v", v.Window, v.Apps)
	}
	g := v.Apps[0]
	byService := map[string]UsageContainer{}
	for _, c := range g.Containers {
		byService[c.Service] = c
	}
	web, db := byService["web"].Sample, byService["db"].Sample
	if web.CPUCores == nil || *web.CPUCores != 2 || web.MemBytes == nil || *web.MemBytes != 250 {
		t.Errorf("web = %v %v", web.CPUCores, web.MemBytes)
	}
	if db.CPUCores == nil || *db.CPUCores != 0 || db.MemBytes == nil || *db.MemBytes != 100 {
		t.Errorf("db = %v %v", db.CPUCores, db.MemBytes)
	}
	if web.MemLimitBytes == nil || *web.MemLimitBytes != 0 {
		t.Errorf("web limit = %v", web.MemLimitBytes)
	}
	if g.Totals.CPUCores == nil || *g.Totals.CPUCores != 2 || g.Totals.MemBytes == nil || *g.Totals.MemBytes != 350 || !g.Partial {
		t.Errorf("totals = %v %v partial %v", g.Totals.CPUCores, g.Totals.MemBytes, g.Partial)
	}
	h := v.Hosts["primary"]
	if h.CPUUsedCores == nil || *h.CPUUsedCores != 1.0 || h.MemUsedBytes == nil || *h.MemUsedBytes != 6<<30 || h.BlkReadBps == nil || *h.BlkReadBps != 4096 {
		t.Errorf("host mean = %+v", h)
	}

	last := e.h.UsageOverview("last")
	if last.Window != "last" {
		t.Errorf("window = %q", last.Window)
	}
	for _, c := range last.Apps[0].Containers {
		if c.Service == "web" && (c.Sample.CPUCores == nil || *c.Sample.CPUCores != 3 || *c.Sample.MemBytes != 400) {
			t.Errorf("last web = %v %v", c.Sample.CPUCores, c.Sample.MemBytes)
		}
	}
	// The points of more than an hour ago are out of the window.
	e.clock.Add(time.Hour + usage.Interval)
	e.stats("a1", 90e9+15e9*240, 1000)
	e.stats("a2", 0, 100)
	e.sweep()
	for _, c := range e.h.UsageOverview("1h").Apps[0].Containers {
		if c.Service == "web" && (c.Sample.MemBytes == nil || *c.Sample.MemBytes != 1000) {
			t.Errorf("an hour later web mem = %v", c.Sample.MemBytes)
		}
	}
}
