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
	// statsIgnore: Stats waits for release whatever its context;
	// hangVolumes / hangFixer: ListVolumes or (through the fixer seam)
	// a fixer run hangs until its context ends.
	statsIgnore, hangVolumes, hangFixer bool
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
	f.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.Fake.ListVolumes(ctx, flt)
}
