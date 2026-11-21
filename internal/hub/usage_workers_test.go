package hub

import (
	"context"
	"encoding/json"
	"errors"
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
	// statsIgnore: Stats waits for release whatever its context;
	// hangVolumes / hangFixer: ListVolumes or (through the fixer seam)
	// a fixer run hangs until its context ends.
	statsIgnore, hangVolumes, hangFixer bool
	// slowInfo / slowHost: Info and HostUsage block until their
	// context ends; listDelay: List answers after it.
	slowInfo, slowHost bool
	listDelay          time.Duration
	listsVolumes       int
	// slowStats: these containers' Stats wait until their context ends.
	slowStats map[string]bool
}

func (f *fakeWorkerRT) HostUsage(ctx context.Context) (usage.HostCounters, error) {
	f.mu.Lock()
	slow := f.slowHost
	f.mu.Unlock()
	if slow {
		<-ctx.Done()
		return usage.HostCounters{}, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hostErr != nil {
		return usage.HostCounters{}, f.hostErr
	}
	f.hostN++
	return usage.HostCounters{At: f.clock.Now(), CPUTotal: 1000 * f.hostN, CPUIdle: 250 * f.hostN, MemTotal: 8 << 30, MemAvailable: 6 << 30}, nil
}

// Info with slowInfo: blocks until its context ends (a slow worker,
// within its per-call timeout).
func (f *fakeWorkerRT) Info(ctx context.Context) (runtime.Info, error) {
	f.mu.Lock()
	slow := f.slowInfo
	f.mu.Unlock()
	if slow {
		<-ctx.Done()
		return runtime.Info{}, ctx.Err()
	}
	return f.Fake.Info(ctx)
}

func (f *fakeWorkerRT) List(ctx context.Context, flt runtime.Filter) ([]runtime.Unit, error) {
	f.mu.Lock()
	block, ignore, rel, delay := f.block, f.ignoreCtx, f.release, f.listDelay
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
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
	e.fakeHost()
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
			e.stats("p1", 1e9+15e9, 1<<20) // 1 core over the interval
			before := usageCalls(e.rt.Calls(), "stats p1")
			start := time.Now()
			e.sweep()
			// I1: the primary sampled at once, never held up by the worker.
			if usageCalls(e.rt.Calls(), "stats p1") != before+1 {
				t.Errorf("the primary's stats weren't taken during the slow sweep")
			}
			if c := groupOf(e.h.UsageOverview("last"), "p").Containers[0]; c.Sample.CPUCores == nil || *c.Sample.CPUCores != 1 {
				t.Errorf("the primary's sample didn't change: %v", c.Sample.CPUCores)
			}
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
	// The primary's 200 first; w1's one app of 200 doesn't fit the 56
	// left: cut whole, not measured with the reason (never a subset).
	if v.OverLimit != 200 {
		t.Errorf("over_limit = %d", v.OverLimit)
	}
	if p := groupOf(v, "p"); p == nil || len(p.Containers) != 200 {
		t.Errorf("p = %+v", p)
	}
	if a := groupOf(v, "a"); a == nil || a.Status != "not_measured" || a.Why != "not measured: too many containers" || a.Totals.CPUCores != nil {
		t.Errorf("a = %+v", a)
	}
	if n := usageCalls(w.Calls(), "stats "); n != 0 {
		t.Errorf("worker stats calls: %d", n)
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
	// The storage view names the app's server itself (ux3 final review M2).
	for _, g := range v.Apps {
		if g.Instance == "a" && g.Server != "w1" {
			t.Errorf("storage group a's server = %q, want w1", g.Server)
		}
	}
}

// fakeWorkerRT.Stats with statsIgnore: a stats call that never honours its
// context (until release): the sample phase is late.
func (f *fakeWorkerRT) Stats(ctx context.Context, id string) (runtime.UnitStats, error) {
	f.mu.Lock()
	ignore, rel := f.statsIgnore, f.release
	f.mu.Unlock()
	if ignore {
		<-rel
	}
	f.mu.Lock()
	slow := f.slowStats[id]
	f.mu.Unlock()
	if slow {
		<-ctx.Done()
		return runtime.UnitStats{}, ctx.Err()
	}
	return f.Fake.Stats(ctx, id)
}

// TestWorkerSweepFairCap (I2): the room after the primary is shared
// fairly: a worker that floods can't hide another's apps; its app that
// doesn't fit is not measured with the reason, never dropped.
func TestWorkerSweepFairCap(t *testing.T) {
	e := newUsageEnv(t)
	e.placed(map[string]string{"a": "w1", "flood": "w1", "c": "w2"})
	w1 := e.addWorker(t, "w1", "big")
	w2 := e.addWorker(t, "w2", "small")
	var us []runtime.Unit
	for i := range 5 {
		us = append(us, uunit(fmt.Sprintf("a%d", i), "portcullis-a", "web", i+1, "running"))
	}
	for i := range 300 {
		us = append(us, uunit(fmt.Sprintf("f%03d", i), "portcullis-flood", "web", i+1, "running"))
	}
	w1.Lock()
	w1.Units = us
	w1.Unlock()
	w2.Lock()
	w2.Units = []runtime.Unit{uunit("c1", "portcullis-c", "web", 1, "running"), uunit("c2", "portcullis-c", "db", 1, "running")}
	w2.Unlock()
	e.sweep()
	v := e.h.UsageOverview("last")
	if c := groupOf(v, "c"); c == nil || len(c.Containers) != 2 || c.Status == "not_measured" {
		t.Errorf("w2's app hidden by w1: %+v", c)
	}
	if a := groupOf(v, "a"); a == nil || len(a.Containers) != 5 {
		t.Errorf("w1's small app: %+v", a)
	}
	if f := groupOf(v, "flood"); f == nil || f.Status != "not_measured" || f.Why != "not measured: too many containers" || len(f.Containers) != 0 {
		t.Errorf("flood = %+v", f)
	}
	if v.OverLimit != 300 {
		t.Errorf("over_limit = %d", v.OverLimit)
	}
	if fairShare(10, map[string]int{"x": 7, "y": 7, "z": 7})["z"] != 4 || fairShare(10, map[string]int{"x": 1, "y": 20})["y"] != 9 {
		t.Error("fairShare")
	}
}

// TestWorkerSweepLateSample (nits 1, 2): a worker lists in time but its
// stats never answer: its apps are unreachable at the deadline, its host
// figures (read in time) kept; the next sweep skips it while its last
// goroutine still runs (no second goroutine, no second list).
func TestWorkerSweepLateSample(t *testing.T) {
	e := newUsageEnv(t)
	e.h.usage.budget = 300 * time.Millisecond
	e.placed(map[string]string{"a": "w1"})
	w := e.addWorker(t, "w1", "nas")
	w.Lock()
	w.Units = []runtime.Unit{uunit("a1", "portcullis-a", "web", 1, "running")}
	w.Unlock()
	wstats(w, e.clock, "a1", 1, 1)
	w.mu.Lock()
	w.statsIgnore = true
	w.mu.Unlock()
	e.sweep()
	v := e.h.UsageOverview("last")
	if a := groupOf(v, "a"); a == nil || a.Why != "not measured: nas is unreachable" {
		t.Errorf("a = %+v", a)
	}
	if h := v.Hosts["w1"]; h.MemUsedBytes == nil || *h.MemUsedBytes != 2<<30 || h.CPUs == nil || h.Why != "" {
		t.Errorf("w1 host = %+v", h)
	}
	lists := usageCalls(w.Calls(), "list ")
	e.clock.Add(usage.Interval)
	e.sweep()
	if usageCalls(w.Calls(), "list ") != lists {
		t.Error("a second sweep started while the last one still runs")
	}
	if a := groupOf(e.h.UsageOverview("last"), "a"); a == nil || a.Why != "not measured: nas is unreachable" {
		t.Errorf("a while busy = %+v", a)
	}
}

// TestWorkerNotReady (ruling 2): an app on a server that isn't ready is
// listed not measured, with the reason.
func TestWorkerNotReady(t *testing.T) {
	e := newUsageEnv(t)
	e.placed(map[string]string{"a": "w1", "b": "w2"})
	e.h.setServer("w1", &serverRT{Name: "nas", State: ServerOffline})
	e.h.setServer("w2", &serverRT{Name: "pi", State: ServerEnrolling})
	e.sweep()
	v := e.h.UsageOverview("last")
	if a := groupOf(v, "a"); a == nil || a.Status != "not_measured" || a.Why != "not measured: nas is offline" || a.Server != "w1" {
		t.Errorf("a = %+v", a)
	}
	if b := groupOf(v, "b"); b == nil || b.Why != "not measured: pi isn't ready yet" {
		t.Errorf("b = %+v", b)
	}
	if _, ok := v.Hosts["w1"]; ok {
		t.Error("a host entry for a server that isn't ready")
	}
}

// TestWorkerFiguresBounded (M1): a worker's derived CPU rate is at most
// its CPUs; a host with an impossible CPU count has none.
func TestWorkerFiguresBounded(t *testing.T) {
	e := newUsageEnv(t)
	e.placed(map[string]string{"a": "w1"})
	w := e.addWorker(t, "w1", "nas")
	w.Lock()
	w.Units = []runtime.Unit{uunit("a1", "portcullis-a", "web", 1, "running")}
	w.Unlock()
	wstats(w, e.clock, "a1", 0, 1)
	e.sweep()
	e.clock.Add(usage.Interval)
	wstats(w, e.clock, "a1", 1e18, 1) // 6.7e7 cores claimed
	e.sweep()
	a := groupOf(e.h.UsageOverview("last"), "a")
	if a == nil || a.Containers[0].Sample.CPUCores == nil || *a.Containers[0].Sample.CPUCores != 4 || *a.Totals.CPUCores != 4 {
		t.Errorf("a = %+v", a)
	}
}

// TestWorkerStorageHang (I3): a worker whose storage calls hang never
// stalls the measurer (each call has a Hub-side deadline) nor holds
// diskMu; the primary's targets are measured first.
func TestWorkerStorageHang(t *testing.T) {
	oldCall, oldFixer := storageWorkerCall, storageWorkerFixer
	storageWorkerCall, storageWorkerFixer = 100*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { storageWorkerCall, storageWorkerFixer = oldCall, oldFixer })
	for _, hang := range []string{"list", "fixer"} {
		t.Run(hang, func(t *testing.T) {
			e := newUsageEnv(t)
			e.placed(map[string]string{"p": "", "a": "w1"})
			w := e.addWorker(t, "w1", "nas")
			e.rt.Volumes = map[string]runtime.Volume{"portcullis-p_data": vol("portcullis-p_data", "portcullis-p")}
			w.Lock()
			w.Volumes["portcullis-a_data"] = vol("portcullis-a_data", "portcullis-a")
			w.Unlock()
			w.mu.Lock()
			w.hangVolumes, w.hangFixer = hang == "list", hang == "fixer"
			w.mu.Unlock()
			var order []string
			var mu sync.Mutex
			heldDuringWorker := false
			e.h.usage.fixer = func(ctx context.Context, r fixerRun) (*folderfix.Report, error) {
				mu.Lock()
				order = append(order, r.Server+":"+r.Volume.Name)
				mu.Unlock()
				if r.Server == "" {
					return &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 1, Dev: 1, TotalBytes: 2, FreeBytes: 1}, nil
				}
				if e.h.usage.diskMu.TryLock() {
					e.h.usage.diskMu.Unlock()
				} else {
					heldDuringWorker = true
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			done := make(chan error, 1)
			go func() { _, _, err := e.h.measureStorage(context.Background(), ""); done <- err }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("a hung worker stalled the measurer")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(order) == 0 || order[0] != ":portcullis-p_data" {
				t.Errorf("run order = %v", order)
			}
			if heldDuringWorker {
				t.Error("diskMu held across a worker's run")
			}
			if it := storageItems(e.h, "p")["volume:portcullis-p_data"]; it.AllocBytes == nil {
				t.Errorf("the primary's volume = %+v", it)
			}
		})
	}
}

func (f *fakeWorkerRT) ListVolumes(ctx context.Context, flt runtime.Filter) ([]runtime.Volume, error) {
	f.mu.Lock()
	hang := f.hangVolumes
	f.listsVolumes++
	f.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.Fake.ListVolumes(ctx, flt)
}

// TestWorkerSweepSlowWorkerFair (Task 10 re-review New I1): a worker slow
// within its per-call timeouts never decides another worker's share:
// w2 is sampled fresh, nothing is "too many", over_limit stays 0.
func TestWorkerSweepSlowWorkerFair(t *testing.T) {
	for _, mode := range []string{"slow list phase", "list blocks"} {
		t.Run(mode, func(t *testing.T) {
			e := newUsageEnv(t)
			// As the real 12 s and 5 s: 3 × timeout > budget. "list
			// blocks": a list that ends only with the budget (a 5 s
			// timeout, a 300 ms budget).
			e.h.usage.budget, e.h.usage.statsTimeout = time.Second, 400*time.Millisecond
			if mode == "list blocks" {
				e.h.usage.budget, e.h.usage.statsTimeout = 300*time.Millisecond, 5*time.Second
			}
			e.placed(map[string]string{"a": "w1", "c": "w2"})
			w1 := e.addWorker(t, "w1", "slow")
			w2 := e.addWorker(t, "w2", "fast")
			w1.Lock()
			w1.Units = []runtime.Unit{uunit("a1", "portcullis-a", "web", 1, "running")}
			w1.Unlock()
			w2.Lock()
			w2.Units = []runtime.Unit{uunit("c1", "portcullis-c", "web", 1, "running")}
			w2.Unlock()
			wstats(w1, e.clock, "a1", 0, 1)
			wstats(w2, e.clock, "c1", 0, 1)
			e.sweep()
			e.clock.Add(usage.Interval)
			wstats(w2, e.clock, "c1", 15e9, 1)
			w1.mu.Lock()
			if mode == "slow list phase" {
				// Info and host each a whole timeout, the list just inside
				// its own: the list phase ends after the budget.
				w1.slowInfo, w1.slowHost, w1.listDelay = true, true, 350*time.Millisecond
				e.h.usage.workers["w1"].infoAt = time.Time{}
			} else {
				w1.block = true
			}
			w1.mu.Unlock()
			before := usageCalls(w2.Calls(), "stats c1")
			e.sweep()
			if usageCalls(w2.Calls(), "stats c1") != before+1 {
				t.Error("w2's stats weren't taken")
			}
			v := e.h.UsageOverview("last")
			if c := groupOf(v, "c"); c == nil || c.Status != "running" || c.Containers[0].Sample.CPUCores == nil || *c.Containers[0].Sample.CPUCores != 1 {
				t.Errorf("c = %+v", c)
			}
			if v.OverLimit != 0 {
				t.Errorf("over_limit = %d", v.OverLimit)
			}
			if a := groupOf(v, "a"); a == nil || a.Why == usageTooMany {
				t.Errorf("the slow worker's app = %+v", a)
			}
			if mode == "list blocks" {
				if a := groupOf(v, "a"); a.Why != "not measured: slow is unreachable" {
					t.Errorf("a = %+v", a)
				}
			}
		})
	}
}

// TestWorkerSweepSampleOutOfBudget (New I1): a worker whose stats outlast
// the sweep's budget is unreachable, never its stale sample shown as
// current.
func TestWorkerSweepSampleOutOfBudget(t *testing.T) {
	e := newUsageEnv(t)
	e.h.usage.budget = 300 * time.Millisecond
	e.placed(map[string]string{"a": "w1"})
	w := e.addWorker(t, "w1", "nas")
	w.Lock()
	w.Units = []runtime.Unit{uunit("a1", "portcullis-a", "web", 1, "running"), uunit("a2", "portcullis-a", "db", 1, "running")}
	w.Unlock()
	wstats(w, e.clock, "a1", 0, 1)
	wstats(w, e.clock, "a2", 0, 1)
	e.sweep()
	if a := groupOf(e.h.UsageOverview("last"), "a"); a == nil || a.Status != "running" {
		t.Fatalf("a = %+v", a)
	}
	w.Lock()
	w.StatsDelay = time.Second
	w.Unlock()
	e.clock.Add(usage.Interval)
	e.sweep()
	// Every container cut by the budget: not measured with the reason,
	// never the previous sample.
	a := groupOf(e.h.UsageOverview("last"), "a")
	if a == nil || a.Status != "not_measured" || a.Why != "not measured: nas is unreachable" || len(a.Containers) != 2 {
		t.Fatalf("a = %+v", a)
	}
	for _, c := range a.Containers {
		if c.Why != "not measured: nas is unreachable" || c.Sample.MemBytes != nil {
			t.Errorf("container %s = %+v", c.Service, c)
		}
	}
}

// TestWorkerSweepSkippedKeepsOthers (re-review 2 ruling): a job the
// budget cuts leaves only that container not measured; the worker's
// other fresh samples are kept.
func TestWorkerSweepSkippedKeepsOthers(t *testing.T) {
	e := newUsageEnv(t)
	e.h.usage.budget = 400 * time.Millisecond
	e.placed(map[string]string{"a": "w1"})
	w := e.addWorker(t, "w1", "nas")
	w.Lock()
	w.Units = []runtime.Unit{uunit("a1", "portcullis-a", "web", 1, "running"), uunit("a2", "portcullis-a", "db", 1, "running")}
	w.Unlock()
	wstats(w, e.clock, "a1", 0, 100)
	wstats(w, e.clock, "a2", 0, 200)
	e.sweep()
	e.clock.Add(usage.Interval)
	wstats(w, e.clock, "a1", 0, 111)
	w.mu.Lock()
	w.slowStats = map[string]bool{"a2": true}
	w.mu.Unlock()
	e.sweep()
	a := groupOf(e.h.UsageOverview("last"), "a")
	if a == nil || a.Status == "not_measured" || !a.Partial {
		t.Fatalf("a = %+v", a)
	}
	for _, c := range a.Containers {
		switch c.Service {
		case "web":
			if c.Why != "" || c.Sample.MemBytes == nil || *c.Sample.MemBytes != 111 {
				t.Errorf("the fresh sample = %+v", c)
			}
		case "db":
			if c.Why != "not measured: nas is unreachable" || c.Sample.MemBytes != nil {
				t.Errorf("the cut one = %+v", c)
			}
		}
	}
}

// TestWorkerSweepGoneDoesntHold (re-review 2 New I1): a worker whose list
// fails at once, or that is busy, takes no share: w2 decides at once and
// is sampled fresh within the budget, never at the early point.
func TestWorkerSweepGoneDoesntHold(t *testing.T) {
	for _, mode := range []string{"list fails", "busy"} {
		t.Run(mode, func(t *testing.T) {
			e := newUsageEnv(t)
			// The reviewer's scale: early point 0.75 s, stats 0.8 s.
			e.h.usage.budget, e.h.usage.statsTimeout = 1500*time.Millisecond, time.Second
			e.placed(map[string]string{"a": "w1", "c": "w2"})
			w1 := e.addWorker(t, "w1", "gone")
			w2 := e.addWorker(t, "w2", "fast")
			w2.Lock()
			w2.Units = []runtime.Unit{uunit("c1", "portcullis-c", "web", 1, "running")}
			w2.Unlock()
			wstats(w2, e.clock, "c1", 0, 1)
			e.sweep()
			e.clock.Add(usage.Interval)
			wstats(w2, e.clock, "c1", 15e9, 1)
			w2.Lock()
			w2.StatsDelay = 800 * time.Millisecond
			w2.Unlock()
			if mode == "list fails" {
				w1.Lock()
				w1.Err = errors.New("refused")
				w1.Unlock()
			} else {
				e.h.usage.busyMu.Lock()
				e.h.usage.busy["w1"] = true
				e.h.usage.busyMu.Unlock()
				t.Cleanup(func() {
					e.h.usage.busyMu.Lock()
					delete(e.h.usage.busy, "w1")
					e.h.usage.busyMu.Unlock()
				})
			}
			e.sweep()
			v := e.h.UsageOverview("last")
			c := groupOf(v, "c")
			if c == nil || c.Status != "running" || c.Containers[0].Sample.CPUCores == nil || *c.Containers[0].Sample.CPUCores != 1 {
				t.Errorf("c = %+v", c)
			}
			if a := groupOf(v, "a"); a == nil || a.Why != "not measured: gone is unreachable" {
				t.Errorf("a = %+v", a)
			}
		})
	}
}

// TestUsageCapPaths (re-review 2 New M1): the cap alone.
func TestUsageCapPaths(t *testing.T) {
	ws := func(ids ...string) []*usageWorkerSweep {
		var out []*usageWorkerSweep
		for _, id := range ids {
			out = append(out, &usageWorkerSweep{server: id})
		}
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// (a) the primary and every worker reported: shares at once.
	c := newUsageCap()
	c.start(ctx, ws("w1", "w2"), 0, 5*time.Second)
	c.primary(56)
	got := make(chan int, 2)
	start := time.Now()
	go func() { n, _ := c.worker(ctx, "w1", 10); got <- n }()
	n2, ok := c.worker(ctx, "w2", 500)
	n1 := <-got
	if !ok || n1 != 10 || n2 != 190 || time.Since(start) > time.Second {
		t.Errorf("(a) shares %d %d ok %v after %v", n1, n2, ok, time.Since(start))
	}
	// A worker that's gone counts as reported: no wait.
	c = newUsageCap()
	c.start(ctx, ws("w1", "w2"), 0, 5*time.Second)
	c.primary(0)
	c.gone("w1")
	start = time.Now()
	if n, ok := c.worker(ctx, "w2", 300); !ok || n != 256 || time.Since(start) > time.Second {
		t.Errorf("gone: %d %v after %v", n, ok, time.Since(start))
	}
	// (b) a late reporter gets min(n, equal); the reserved room isn't
	// handed to the early ones.
	c = newUsageCap()
	c.start(ctx, ws("w1", "w2"), 0, 50*time.Millisecond)
	c.primary(0)
	n1, _ = c.worker(ctx, "w1", 300) // decided at the early point
	time.Sleep(10 * time.Millisecond)
	n2, _ = c.worker(ctx, "w2", 300)
	if n1 != 128 || n2 != 128 {
		t.Errorf("(b) %d %d", n1, n2)
	}
	if n, _ := c.worker(ctx, "w2", 5); n > 128 {
		t.Errorf("(b) small late = %d", n)
	}
	// (c) two floods reported, one worker unreported: within
	// 256 − primary − equal.
	c = newUsageCap()
	c.start(ctx, ws("w1", "w2", "w3"), 0, 50*time.Millisecond)
	c.primary(16)
	go func() { n, _ := c.worker(ctx, "w1", 1000); got <- n }()
	n2, _ = c.worker(ctx, "w2", 1000)
	n1 = <-got
	if equal := (256 - 16) / 3; n1+n2 > 256-16-equal || n1 != 80 || n2 != 80 {
		t.Errorf("(c) %d %d", n1, n2)
	}
	// nit 1: a late share is at most the room not yet handed out. The
	// primary reports after the early point with more than last sweep's
	// (200 for 100): w1 had 78 (half of 156); w2, late, gets the 56 − 78
	// left: none.
	c = newUsageCap()
	c.start(ctx, ws("w1", "w2"), 100, 30*time.Millisecond)
	n1, _ = c.worker(ctx, "w1", 1000)
	c.primary(200)
	n2, _ = c.worker(ctx, "w2", 1000)
	if n1 != 78 || n2 != 0 {
		t.Errorf("nit 1: %d %d", n1, n2)
	}
	// Late shares together never exceed the room left.
	c = newUsageCap()
	c.start(ctx, ws("w1", "w2", "w3"), 0, 10*time.Millisecond)
	c.primary(250)
	time.Sleep(30 * time.Millisecond)
	a, _ := c.worker(ctx, "w1", 10)
	b, _ := c.worker(ctx, "w2", 10)
	d, _ := c.worker(ctx, "w3", 10)
	if a+b+d > 6 {
		t.Errorf("late shares %d %d %d over the room 6", a, b, d)
	}
}

// TestWorkerHostWhy (New M2 b): null host figures always say why.
func TestWorkerHostWhy(t *testing.T) {
	e := newUsageEnv(t)
	if h := e.h.UsageOverview("last").Hosts["primary"]; h.Why != "not measured yet" {
		t.Errorf("before any sweep: %+v", h)
	}
	e.h.usage.readHost = func() (usage.HostCounters, error) { return usage.HostCounters{}, errors.New("no /proc") }
	e.placed(map[string]string{"a": "w1"})
	w := e.addWorker(t, "w1", "nas")
	w.mu.Lock()
	w.hostErr = errors.New("boom")
	w.mu.Unlock()
	e.sweep()
	v := e.h.UsageOverview("last")
	if h := v.Hosts["primary"]; h.Why != "not measured: the host's counters can't be read" {
		t.Errorf("primary = %+v", h)
	}
	if h := v.Hosts["w1"]; h.Why != "not measured: nas's host counters can't be read" || h.MemUsedBytes != nil {
		t.Errorf("w1 = %+v", h)
	}
}

// TestWorkerRevokedAndUnknown (New M2 d).
func TestWorkerRevokedAndUnknown(t *testing.T) {
	e := newUsageEnv(t)
	e.placed(map[string]string{"a": "w1", "b": "ghost"})
	e.h.setServer("w1", &serverRT{Name: "nas", State: ServerRevoked})
	e.sweep()
	v := e.h.UsageOverview("last")
	if a := groupOf(v, "a"); a == nil || a.Why != "not measured: nas is revoked" {
		t.Errorf("a = %+v", a)
	}
	if b := groupOf(v, "b"); b == nil || b.Status != "not_measured" || b.Why != "not measured: server ghost is unknown" {
		t.Errorf("b = %+v", b)
	}
}

// TestWorkerStorageClipAndOneListing (New M1, New M2 c): a worker's
// partial reason is clipped; a worker whose listing failed is not listed
// again for its other instances in the same run.
func TestWorkerStorageClipAndOneListing(t *testing.T) {
	old := storageWorkerCall
	storageWorkerCall = 100 * time.Millisecond
	t.Cleanup(func() { storageWorkerCall = old })
	e := newUsageEnv(t)
	e.placed(map[string]string{"a": "w1", "b": "w1", "c": "w1", "d": "w2"})
	w1 := e.addWorker(t, "w1", "nas")
	w1.mu.Lock()
	w1.hangVolumes = true
	w1.mu.Unlock()
	w2 := e.addWorker(t, "w2", "pi")
	w2.Lock()
	w2.Volumes["portcullis-d_data"] = vol("portcullis-d_data", "portcullis-d")
	w2.Unlock()
	long := strings.Repeat("é", 500)
	e.h.usage.fixer = func(_ context.Context, r fixerRun) (*folderfix.Report, error) {
		return &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 1, Partial: true, PartialReason: long, Dev: 1, TotalBytes: 2, FreeBytes: 1}, nil
	}
	start := time.Now()
	if _, _, err := e.h.measureStorage(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*storageWorkerCall+time.Second {
		t.Errorf("the run took %v", d)
	}
	if n := usageCalls(w1.Calls(), "volumes "); n > 1 {
		// (fakeWorkerRT.ListVolumes records nothing when it hangs: count
		// through the Fake below.)
		t.Errorf("w1 listed %d times", n)
	}
	if n := w1.volumeLists(); n != 1 {
		t.Errorf("w1's volumes listed %d times in one run", n)
	}
	it := storageItems(e.h, "d")["volume:portcullis-d_data"]
	if r := []rune(it.PartialReason); len(r) > 200 || len(r) == 0 {
		t.Errorf("partial reason %d runes", len(r))
	}
}

func (f *fakeWorkerRT) volumeLists() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listsVolumes
}
