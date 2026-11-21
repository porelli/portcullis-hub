package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
	"github.com/portcullis/hub/internal/usage"
)

// fakeWorkerRT is a worker's agent backend in the sampler's tests: the
// fake engine plus HostUsage; block makes List hang until ctx ends (or,
// with ignoreCtx, until release closes: a worker that never answers).
type fakeWorkerRT struct {
	*runtimetest.Fake
	mu        sync.Mutex
	hostN     uint64
	hostErr   error
	clock     *usageClock
	block     bool
	ignoreCtx bool
	release   chan struct{}
}

func (f *fakeWorkerRT) HostUsage(context.Context) (usage.HostCounters, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hostErr != nil {
		return usage.HostCounters{}, f.hostErr
	}
	f.hostN++
	return usage.HostCounters{At: f.clock.Now(), CPUTotal: 1000 * f.hostN, CPUIdle: 250 * f.hostN, MemTotal: 8 << 30, MemAvailable: 6 << 30}, nil
}

func (f *fakeWorkerRT) List(ctx context.Context, flt runtime.Filter) ([]runtime.Unit, error) {
	f.mu.Lock()
	block, ignore, rel := f.block, f.ignoreCtx, f.release
	f.mu.Unlock()
	if block {
		if ignore {
			<-rel
		} else {
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	return f.Fake.List(ctx, flt)
}

// addWorker registers a ready worker id named name with instances ids
// placed on it, returning its fake backend.
func (e *usageEnv) addWorker(t *testing.T, id, name string) *fakeWorkerRT {
	t.Helper()
	w := &fakeWorkerRT{Fake: &runtimetest.Fake{InfoVal: runtime.Info{Verified: true, CPUs: 4, MemoryBytes: 8 << 30}, Infos: map[string]runtime.UnitInfo{},
		Volumes: map[string]runtime.Volume{}}, clock: e.clock, release: make(chan struct{})}
	t.Cleanup(func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		select {
		case <-w.release:
		default:
			close(w.release)
		}
	})
	if !e.h.setServer(id, &serverRT{Name: name, State: ServerReady, RT: w}) {
		t.Fatal("setServer")
	}
	return w
}

// placed sets the env's instances: id → server ("" primary).
func (e *usageEnv) placed(m map[string]string) {
	e.h.usage.instances = func() []usageInst {
		var out []usageInst
		for _, id := range slices.Sorted(func(yield func(string) bool) {
			for k := range m {
				if !yield(k) {
					return
				}
			}
		}) {
			out = append(out, usageInst{ID: id, Template: "tmpl", Name: "App " + id, Server: m[id]})
		}
		return out
	}
}

func wstats(w *fakeWorkerRT, clock *usageClock, id string, cpuNS, mem uint64) {
	w.SetStats(id, runtime.UnitStats{Read: clock.Now(), CPUUsageNS: pu(cpuNS), MemUsage: pu(mem)})
}

func groupOf(v UsageView, id string) *UsageGroup {
	for i := range v.Apps {
		if v.Apps[i].Instance == id {
			return &v.Apps[i]
		}
	}
	return nil
}

func TestWorkerSweepTotals(t *testing.T) {
	e := newUsageEnv(t)
	e.placed(map[string]string{"p": "", "a": "w1", "b": "w1"})
	w := e.addWorker(t, "w1", "nas")
	e.setUnits(uunit("p1", "portcullis-p", "web", 1, "running"))
	e.stats("p1", 1e9, 1<<20)
	w.Lock()
	w.Units = []runtime.Unit{uunit("a1", "portcullis-a", "web", 1, "running"), uunit("a2", "portcullis-a", "db", 1, "running"),
		uunit("b1", "portcullis-b", "web", 1, "running"),
		// The agent's own fixer helper: never a group.
		{ID: "h1", State: "running", Labels: map[string]string{docker.LabelHelper: "usage:x"}}}
	w.Unlock()
	for i, id := range []string{"a1", "a2", "b1"} {
		wstats(w, e.clock, id, 0, uint64(100*(i+1)))
	}
	e.sweep()
	e.clock.Add(usage.Interval)
	wstats(w, e.clock, "a1", 15e9, 100)
	wstats(w, e.clock, "a2", 15e9, 200)
	wstats(w, e.clock, "b1", 30e9, 300)
	e.stats("p1", 1e9, 1<<20)
	e.sweep()
	v := e.h.UsageOverview("last")
	h, ok := v.Hosts["w1"]
	if !ok || h.Name != "nas" || h.CPUs == nil || *h.CPUs != 4 || h.MemoryBytes == nil || *h.MemoryBytes != 8<<30 || h.Why != "" {
		t.Fatalf("hosts = %+v", v.Hosts)
	}
	// 1000 ticks, 250 idle, on 4 CPUs: 3 cores.
	if h.CPUUsedCores == nil || *h.CPUUsedCores != 3 || h.MemUsedBytes == nil || *h.MemUsedBytes != 2<<30 {
		t.Errorf("w1 host figures = %v %v", h.CPUUsedCores, h.MemUsedBytes)
	}
	a, b, p := groupOf(v, "a"), groupOf(v, "b"), groupOf(v, "p")
	if a == nil || b == nil || p == nil {
		t.Fatalf("apps = %+v", v.Apps)
	}
	if a.Server != "w1" || b.Server != "w1" || p.Server != "primary" {
		t.Errorf("servers = %q %q %q", a.Server, b.Server, p.Server)
	}
	if a.Totals.CPUCores == nil || *a.Totals.CPUCores != 2 || a.Totals.MemBytes == nil || *a.Totals.MemBytes != 300 || len(a.Containers) != 2 || a.Status != "running" {
		t.Errorf("a = %+v", a)
	}
	if b.Totals.CPUCores == nil || *b.Totals.CPUCores != 2 || *b.Totals.MemBytes != 300 {
		t.Errorf("b = %+v", b.Totals)
	}
	if len(v.Core.Containers) != 0 || len(v.UnknownProjects) != 0 {
		t.Errorf("a worker's helper in core or unknown: %+v %+v", v.Core, v.UnknownProjects)
	}
	// The worker's own figures went through its backend, never the primary's.
	if usageCalls(e.rt.Calls(), "stats a") > 0 || usageCalls(w.Calls(), "stats p1") > 0 {
		t.Errorf("crossed calls: primary %v worker %v", e.rt.Calls(), w.Calls())
	}
	// The instance route and its history on the worker.
	g, err := e.h.UsageInstance("a")
	if err != nil || g.Server != "w1" || len(g.Containers) != 2 || len(g.History.T) != 2 {
		t.Errorf("instance a = %+v %v", g, err)
	}
	// Window 1h on a worker: its host's mean.
	if h := e.h.UsageOverview("1h").Hosts["w1"]; h.CPUUsedCores == nil || *h.CPUUsedCores != 3 {
		t.Errorf("1h w1 = %+v", h)
	}
	b2, _ := json.Marshal(v)
	if !strings.Contains(string(b2), `"w1":{"name":"nas"`) {
		t.Errorf("JSON: %s", b2)
	}
}

func TestWorkerSweepOldAgent(t *testing.T) {
	e := newUsageEnv(t)
	e.placed(map[string]string{"p": "", "a": "w1"})
	w := e.addWorker(t, "w1", "nas")
	e.setUnits(uunit("p1", "portcullis-p", "web", 1, "running"))
	e.stats("p1", 1e9, 1<<20)
	w.Lock()
	w.Units = []runtime.Unit{uunit("a1", "portcullis-a", "web", 1, "running")}
	w.StatsErr = map[string]error{"a1": agentrt.ErrOlderAgent}
	w.Unlock()
	w.hostErr = agentrt.ErrOlderAgent
	e.sweep()
	v := e.h.UsageOverview("last")
	const why = "not measured: nas's agent is older than the Hub"
	a := groupOf(v, "a")
	if a == nil || a.Status != "not_measured" || a.Why != why || a.Server != "w1" || a.Totals.CPUCores != nil || a.Totals.MemBytes != nil {
		t.Errorf("a = %+v", a)
	}
	h := v.Hosts["w1"]
	if h.Why != why || h.CPUUsedCores != nil || h.MemUsedBytes != nil || h.CPUs != nil || h.MemoryBytes != nil {
		t.Errorf("w1 host = %+v", h)
	}
	if p := groupOf(v, "p"); p == nil || p.Status != "running" || p.Why != "" || p.Server != "primary" {
		t.Errorf("p = %+v", p)
	}
	if hp := v.Hosts["primary"]; hp.Why != "" || hp.CPUs == nil {
		t.Errorf("primary host = %+v", hp)
	}
	// Only the host route old: the apps are still measured.
	w.Lock()
	w.StatsErr = nil
	w.Unlock()
	wstats(w, e.clock, "a1", 1, 1)
	e.clock.Add(usage.Interval)
	e.sweep()
	v = e.h.UsageOverview("last")
	if a := groupOf(v, "a"); a == nil || a.Status != "running" {
		t.Errorf("a after = %+v", a)
	}
	if h := v.Hosts["w1"]; h.Why != why || h.CPUUsedCores != nil {
		t.Errorf("w1 host after = %+v", h)
	}
}

func TestWorkerSweepUnreachable(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		t.Run(fmt.Sprintf("ignoreCtx=%v", ignore), func(t *testing.T) {
			e := newUsageEnv(t)
			e.h.usage.budget = 300 * time.Millisecond
			e.placed(map[string]string{"p": "", "a": "w1"})
			w := e.addWorker(t, "w1", "nas")
			e.setUnits(uunit("p1", "portcullis-p", "web", 1, "running"))
			e.stats("p1", 1e9, 1<<20)
			w.Lock()
			w.Units = []runtime.Unit{uunit("a1", "portcullis-a", "web", 1, "running")}
			w.Unlock()
			wstats(w, e.clock, "a1", 1, 1)
			e.sweep() // measured once
			w.mu.Lock()
			w.block, w.ignoreCtx = true, ignore
			w.mu.Unlock()
			e.clock.Add(usage.Interval)
			start := time.Now()
			e.sweep()
			if d := time.Since(start); d > e.h.usage.budget+time.Second {
				t.Errorf("the sweep took %v", d)
			}
			v := e.h.UsageOverview("last")
			const why = "not measured: nas is unreachable"
			if a := groupOf(v, "a"); a == nil || a.Status != "not_measured" || a.Why != why || a.Totals.CPUCores != nil || len(a.Containers) != 0 {
				t.Errorf("a = %+v", a)
			}
			if h := v.Hosts["w1"]; h.Why != why || h.CPUUsedCores != nil || h.CPUs != nil {
				t.Errorf("w1 host = %+v", h)
			}
			if p := groupOf(v, "p"); p == nil || p.Status != "running" {
				t.Errorf("the primary held up: %+v", p)
			}
			if v.Stale || v.SampledAt == nil {
				t.Errorf("the primary's sweep is stale: %v %v", v.Stale, v.SampledAt)
			}
		})
	}
}

func TestWorkerSweepMaxContainers(t *testing.T) {
	e := newUsageEnv(t)
	e.placed(map[string]string{"p": "", "a": "w1"})
	w := e.addWorker(t, "w1", "nas")
	var pu, wu []runtime.Unit
	for i := range 200 {
		pu = append(pu, uunit(fmt.Sprintf("p%03d", i), "portcullis-p", "web", i+1, "running"))
		wu = append(wu, uunit(fmt.Sprintf("a%03d", i), "portcullis-a", "web", i+1, "running"))
	}
	e.setUnits(pu...)
	w.Lock()
	w.Units = wu
	w.Unlock()
	e.sweep()
	v := e.h.UsageOverview("last")
	if v.OverLimit != 400-usage.MaxContainers {
		t.Errorf("over_limit = %d", v.OverLimit)
	}
	n := 0
	for _, g := range v.Apps {
		n += len(g.Containers)
	}
	if n != usage.MaxContainers {
		t.Errorf("%d containers sampled, want %d", n, usage.MaxContainers)
	}
	if got := usageCalls(w.Calls(), "stats ") + usageCalls(w.Calls(), "inspect "); got == 0 || usageCalls(w.Calls(), "stats ") > usage.MaxContainers-200 {
		t.Errorf("worker calls: %d stats", usageCalls(w.Calls(), "stats "))
	}
}

func TestWorkerMeasureVolumes(t *testing.T) {
	e := newUsageEnv(t)
	e.h.bindRoots = []string{"/srv"}
	e.placed(map[string]string{"p": "", "a": "w1"})
	w := e.addWorker(t, "w1", "nas")
	e.rt.Volumes = map[string]runtime.Volume{"portcullis-p_data": vol("portcullis-p_data", "portcullis-p")}
	w.Lock()
	w.Volumes["portcullis-a_data"] = vol("portcullis-a_data", "portcullis-a")
	w.Units = []runtime.Unit{uunit("a1", "portcullis-a", "web", 1, "running")}
	w.Infos["a1"] = runtime.UnitInfo{ID: "a1", Mounts: []runtime.Mount{{Type: "volume", Name: "portcullis-a_data", Destination: "/data"}}}
	w.LayerSizes = map[string]int64{"a1": 4096}
	rep, _ := json.Marshal(folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 5000, ApparentBytes: 4000, Dev: 42, FreeBytes: 10, TotalBytes: 100})
	w.FixerFn = func(s runtime.FixerSpec) (*runtime.RunResult, error) {
		return &runtime.RunResult{Stdout: append(rep, '\n')}, nil
	}
	w.Unlock()
	e.rt.FixerFn = func(s runtime.FixerSpec) (*runtime.RunResult, error) {
		return &runtime.RunResult{Stdout: append(rep, '\n')}, nil
	}
	wstats(w, e.clock, "a1", 1, 1)
	e.sweep()
	e.h.usage.fixer = nil // the real fixer path: the worker's backend
	if _, _, err := e.h.measureStorage(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	var wf, pf []string
	for _, c := range w.Calls() {
		if strings.HasPrefix(c, "fixer ") {
			wf = append(wf, c)
		}
	}
	for _, c := range e.rt.Calls() {
		if strings.HasPrefix(c, "fixer ") {
			pf = append(pf, c)
		}
	}
	if len(wf) != 1 || !strings.Contains(wf[0], "folderfix usage") {
		t.Errorf("worker fixer runs = %v", wf)
	}
	for _, c := range pf {
		if strings.Contains(c, "portcullis-a") {
			t.Errorf("the primary measured a worker's volume: %s", c)
		}
	}
	if usageCalls(e.rt.Calls(), "inspect-volume portcullis-a_data") > 0 || usageCalls(e.rt.Calls(), "layer-size a1") > 0 {
		t.Errorf("the primary reached a worker's target: %v", e.rt.Calls())
	}
	items := storageItems(e.h, "a")
	it := items["volume:portcullis-a_data"]
	if it.AllocBytes == nil || *it.AllocBytes != 5000 || it.Dev == nil || *it.Dev != 42 || !slices.Equal(it.Services, []string{"web.1"}) {
		t.Errorf("worker volume item = %+v", it)
	}
	if l := items["layer:web.1"]; l.AllocBytes == nil || *l.AllocBytes != 4096 {
		t.Errorf("worker layer = %+v", l)
	}
	v := e.h.UsageStorage()
	found := false
	for _, d := range v.Disks {
		if d.Server == "w1" && d.Dev == 42 && slices.Contains(d.Owners, "a") {
			found = true
		}
		if d.Server == "primary" && slices.Contains(d.Owners, "a") {
			t.Errorf("a worker's volume on a primary disk: %+v", d)
		}
	}
	if !found {
		t.Errorf("disks = %+v", v.Disks)
	}
}
