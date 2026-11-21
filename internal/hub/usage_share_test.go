package hub

import (
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

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
	v := e.h.UsageOverview()
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
	v = e.h.UsageOverview()
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
	h := e.h.UsageOverview().Hosts["primary"]
	if h.CPUUsedCores != nil || h.MemUsedBytes != nil || h.BlkReadBps != nil {
		t.Errorf("failed read = %+v", h)
	}
	if c := strings.Count(logs.String(), "usage: the host's counters"); c != 1 {
		t.Errorf("logged %d times:\n%s", c, logs.String())
	}
	fail.Store(false)
	e.clock.Add(usage.Interval)
	e.sweep()
	h = e.h.UsageOverview().Hosts["primary"]
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
	v := e.h.UsageOverview()
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
