package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
	"github.com/portcullis/hub/internal/usage"
)

// usageClock is the sampler's fake clock.
type usageClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *usageClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *usageClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var usageT0 = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

type usageEnv struct {
	h     *Hub
	rt    *runtimetest.Fake
	clock *usageClock
}

// newUsageEnv is a Hub on a fake runtime whose instances are ids (named
// "App <id>", template "tmpl").
func newUsageEnv(t *testing.T, ids ...string) *usageEnv {
	t.Helper()
	f := newFixture(t)
	rt := &runtimetest.Fake{InfoVal: runtime.Info{Verified: true, CPUs: 8, MemoryBytes: 16 << 30}}
	f.h.rt = rt
	c := &usageClock{t: usageT0}
	f.h.usage.now = c.Now
	if ids != nil {
		f.h.usage.instances = func() []usageInst {
			var out []usageInst
			for _, id := range ids {
				out = append(out, usageInst{ID: id, Template: "tmpl", Name: "App " + id})
			}
			return out
		}
	}
	return &usageEnv{h: f.h, rt: rt, clock: c}
}

func uunit(id, project, service string, n int, state string) runtime.Unit {
	return runtime.Unit{ID: id, Project: project, Service: service, State: state,
		Instance: strings.TrimPrefix(project, "portcullis-"),
		Labels:   map[string]string{docker.LabelProject: project, docker.LabelService: service, docker.LabelNumber: fmt.Sprint(n)}}
}

func pu(v uint64) *uint64 { return &v }

// stats is a sample read at the env's clock time with cpu ns and memory.
func (e *usageEnv) stats(id string, cpuNS, mem uint64) {
	e.rt.SetStats(id, runtime.UnitStats{Read: e.clock.Now(), CPUUsageNS: pu(cpuNS), MemUsage: pu(mem), Pids: pu(3), NetRx: pu(cpuNS / 1000), NetTx: pu(1)})
}

func (e *usageEnv) sweep() { e.h.usageSweep(context.Background()) }

func (e *usageEnv) setUnits(us ...runtime.Unit) {
	e.rt.Lock()
	e.rt.Units = us
	e.rt.Unlock()
}

func usageCalls(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func TestUsageGroupsAppsCoreUnknownOther(t *testing.T) {
	e := newUsageEnv(t, "a")
	us := []runtime.Unit{
		uunit("a1", "portcullis-a", "web", 1, "running"), uunit("a2", "portcullis-a", "db", 1, "running"),
		uunit("hub", "portcullis", "hub", 1, "running"), uunit("tr", "portcullis", "traefik", 1, "running"),
		uunit("g1", "portcullis-gone", "web", 1, "running"),
		{ID: "o1", State: "running"}, {ID: "o2", State: "running"}, {ID: "o3", State: "exited"},
	}
	e.setUnits(us...)
	for _, u := range us {
		e.stats(u.ID, 1e9, 1<<20)
	}
	e.sweep()
	v := e.h.UsageOverview()
	if len(v.Apps) != 1 || v.Apps[0].Instance != "a" || len(v.Apps[0].Containers) != 2 || v.Apps[0].Name != "App a" {
		t.Errorf("apps = %+v", v.Apps)
	}
	if len(v.Core.Containers) != 2 || v.Core.Instance != "core" {
		t.Errorf("core = %+v", v.Core)
	}
	if len(v.UnknownProjects) != 1 || v.UnknownProjects[0].Name != "portcullis-gone" {
		t.Errorf("unknown = %+v", v.UnknownProjects)
	}
	if v.NotShown != 3 {
		t.Errorf("not_shown = %d", v.NotShown)
	}
	for _, c := range e.rt.Calls() {
		if strings.HasSuffix(c, " o1") || strings.HasSuffix(c, " o2") || strings.HasSuffix(c, " o3") {
			t.Errorf("another container reached: %s", c)
		}
	}
	if v.Host.CPUs == nil || *v.Host.CPUs != 8 || v.Engine.Runtime != "docker" || !v.Engine.Verified || v.SampledAt == nil {
		t.Errorf("header = %+v %+v %v", v.Host, v.Engine, v.SampledAt)
	}

	// Running helpers are one row of the core group.
	e.setUnits(append(us, runtime.Unit{ID: "h1", State: "running", Labels: map[string]string{docker.LabelHelper: "usage:x"}})...)
	e.sweep()
	v = e.h.UsageOverview()
	last := v.Core.Containers[len(v.Core.Containers)-1]
	if !last.Helper || last.Service != "Hub helpers (transient)" || last.Number != 1 {
		t.Errorf("helpers row = %+v", last)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "usage:x") {
		t.Error("a helper's label is shown")
	}
}

func TestUsageAggregatesAndPartial(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"), uunit("a2", "portcullis-a", "db", 1, "running"))
	e.stats("a1", 1e9, 100)
	e.rt.StatsErr = map[string]error{"a2": errors.New("boom SECRET=hunter2")}
	e.sweep()
	g := e.h.UsageOverview().Apps[0]
	if g.Totals.MemBytes == nil || *g.Totals.MemBytes != 100 || !g.Partial {
		t.Errorf("totals = %v partial %v", g.Totals.MemBytes, g.Partial)
	}
	var failed *UsageContainer
	for i := range g.Containers {
		if g.Containers[i].ID12 == "a2" {
			failed = &g.Containers[i]
		}
	}
	if failed == nil || failed.Error != "stats unavailable" || failed.Sample.MemBytes != nil || failed.Sample.CPUCores != nil {
		t.Errorf("failed = %+v", failed)
	}
	b, _ := json.Marshal(e.h.UsageOverview())
	if strings.Contains(string(b), "hunter2") {
		t.Error("the engine error reached the view")
	}
}

func TestUsageCPUOnSecondSweep(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"))
	e.stats("a1", 10e9, 100)
	e.sweep()
	if c := e.h.UsageOverview().Apps[0].Containers[0]; c.Sample.CPUCores != nil {
		t.Errorf("first sweep cpu = %v", *c.Sample.CPUCores)
	}
	e.clock.Add(15 * time.Second)
	e.stats("a1", 13e9, 100)
	e.sweep()
	c := e.h.UsageOverview().Apps[0].Containers[0]
	if c.Sample.CPUCores == nil || *c.Sample.CPUCores < 0.1999 || *c.Sample.CPUCores > 0.2001 {
		t.Errorf("second sweep cpu = %v", c.Sample.CPUCores)
	}
}

func TestUsageCapAt256(t *testing.T) {
	e := newUsageEnv(t, "a")
	var us []runtime.Unit
	for i := range 300 {
		u := uunit(fmt.Sprintf("c%03d", i), "portcullis-a", "web", i+1, "running")
		us = append(us, u)
		e.stats(u.ID, 1, 1)
	}
	e.setUnits(us...)
	e.sweep()
	v := e.h.UsageOverview()
	if n := usageCalls(e.rt.Calls(), "stats "); n != 256 {
		t.Errorf("sampled %d", n)
	}
	if v.OverLimit != 44 || len(v.Apps[0].Containers) != 256 {
		t.Errorf("over_limit %d, containers %d", v.OverLimit, len(v.Apps[0].Containers))
	}
}

func TestUsageInspectEvery5Min(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"))
	e.rt.Infos = map[string]runtime.UnitInfo{"a1": {ID: "a1", Memory: 64 << 20, PidsLimit: 32}}
	e.stats("a1", 1, 1)
	e.sweep()
	e.clock.Add(15 * time.Second)
	e.sweep()
	if n := usageCalls(e.rt.Calls(), "inspect a1"); n != 1 {
		t.Errorf("inspects after 15 s = %d", n)
	}
	e.clock.Add(5 * time.Minute)
	e.sweep()
	if n := usageCalls(e.rt.Calls(), "inspect a1"); n != 2 {
		t.Errorf("inspects after 5 min = %d", n)
	}
	if l := e.h.UsageOverview().Apps[0].Containers[0].Limits; l.MemBytes != 64<<20 || l.Pids != 32 {
		t.Errorf("limits = %+v", l)
	}
}

func TestUsageNeverKeepsEnv(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	e := newUsageEnv(t, "a")
	u := uunit("a1", "portcullis-a", "web", 1, "running")
	u.Labels["io.example.secret"] = "SECRET_TOKEN=abc"
	e.setUnits(u)
	e.rt.Infos = map[string]runtime.UnitInfo{"a1": {ID: "a1", Labels: map[string]string{"x": "SECRET_TOKEN=abc"}, Image: "SECRET_TOKEN=abc"}}
	e.rt.StatsErr = map[string]error{"a1": errors.New("engine said SECRET_TOKEN=abc")}
	e.sweep()
	e.rt.StatsErr = nil
	e.stats("a1", 1, 1)
	e.clock.Add(15 * time.Second)
	e.sweep()
	g, err := e.h.UsageInstance("a")
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"overview": e.h.UsageOverview(), "instance": g, "snapshot": e.h.usageSnapshot()} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "abc") {
			t.Errorf("%s keeps the secret: %s", name, b)
		}
		if strings.Contains(fmt.Sprintf("%+v", v), "abc") {
			t.Errorf("%s keeps the secret", name)
		}
	}
	if strings.Contains(logs.String(), "abc") {
		t.Errorf("the log keeps the secret: %s", logs.String())
	}
}

func TestUsageSweepReleasesMuDuringEngineCalls(t *testing.T) {
	e := newUsageEnv(t)
	e.h.usage.instances = nil // the real instance list, under mu
	e.setUnits(uunit("c1", "portcullis", "hub", 1, "running"))
	e.stats("c1", 1, 1)
	block := make(chan struct{})
	e.rt.Lock()
	e.rt.StatsBlock = block
	e.rt.Unlock()
	done := make(chan struct{})
	go func() { e.sweep(); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for usageCalls(e.rt.Calls(), "stats c1") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the sweep never reached Stats")
		}
		time.Sleep(5 * time.Millisecond)
	}
	locked := make(chan struct{})
	go func() { e.h.mu.Lock(); e.h.mu.Unlock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("Hub.mu is held across the engine call")
	}
	close(block)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep didn't finish")
	}
}

func TestUsageRefusedEngine(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"))
	e.stats("a1", 1, 4096)
	e.sweep()
	refusal := &docker.RefusedError{Why: "not checked yet"}
	e.rt.Lock()
	e.rt.Err = refusal
	e.rt.Unlock()
	e.clock.Add(15 * time.Second)
	e.sweep()
	v := e.h.UsageOverview()
	if v.Engine.Verified || v.Engine.Why != refusal.Message() {
		t.Errorf("engine = %+v", v.Engine)
	}
	if len(v.Apps) != 1 || v.Apps[0].Totals.MemBytes == nil || *v.Apps[0].Totals.MemBytes != 4096 {
		t.Errorf("last good numbers lost: %+v", v.Apps)
	}
	if v.Stale {
		t.Error("stale after one interval")
	}
	e.clock.Add(15 * time.Second)
	e.sweep()
	if !e.h.UsageOverview().Stale {
		t.Error("not stale after two intervals")
	}
}

// Review Focus 1: a container recreated on every sweep keeps one key ring
// and no ghost containers, and web.1's history holds both ids' points.
func TestUsageRingsFollowRecreatedContainers(t *testing.T) {
	e := newUsageEnv(t, "a")
	for i := range 300 {
		id := fmt.Sprintf("web%03d", i)
		e.setUnits(uunit(id, "portcullis-a", "web", 1, "running"))
		e.stats(id, 1, 1)
		e.sweep()
		e.clock.Add(15 * time.Second)
	}
	s := e.h.usage
	s.mu.RLock()
	conts, rings := len(s.conts), len(s.rings)
	ids := map[string]bool{}
	for _, p := range s.rings["a\x00web.1"].Points() {
		ids[p.ID] = true
	}
	s.mu.RUnlock()
	if conts != 1 || rings != 1 {
		t.Errorf("containers %d, rings %d", conts, rings)
	}
	if len(ids) < 2 {
		t.Errorf("web.1 holds points of %d containers", len(ids))
	}
	g, _ := e.h.UsageInstance("a")
	if n := len(g.History.MemBytes["web.1"]); n != usage.RingSize || len(g.History.T) != usage.RingSize {
		t.Errorf("history = %d points, %d times", n, len(g.History.T))
	}
}

func TestUsageStoppedAppShowsStopped(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "exited"), uunit("a2", "portcullis-a", "db", 1, "exited"))
	e.sweep()
	g := e.h.UsageOverview().Apps[0]
	if g.Status != "stopped" || g.Totals.MemBytes != nil || g.Totals.CPUCores != nil || g.Partial {
		t.Errorf("stopped = %+v", g)
	}
	if n := usageCalls(e.rt.Calls(), "stats "); n != 0 {
		t.Errorf("stopped containers sampled %d times", n)
	}
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"), uunit("a2", "portcullis-a", "db", 1, "exited"))
	e.stats("a1", 1, 1)
	e.sweep()
	if g := e.h.UsageOverview().Apps[0]; g.Status != "partly running" || g.Partial {
		t.Errorf("partly = %+v", g)
	}
}

func TestUsageSweepBudget(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	e := newUsageEnv(t, "a")
	var us []runtime.Unit
	for i := range 40 {
		u := uunit(fmt.Sprintf("c%02d", i), "portcullis-a", "web", i+1, "running")
		us = append(us, u)
		e.stats(u.ID, 1, 7)
	}
	e.setUnits(us...)
	e.sweep() // every container has a sample
	e.h.usage.budget = 300 * time.Millisecond
	e.rt.Lock()
	e.rt.StatsDelay = 100 * time.Millisecond
	e.rt.Unlock()
	for _, u := range us {
		e.stats(u.ID, 2, 9)
	}
	e.clock.Add(15 * time.Second)
	logs.Reset()
	start := time.Now()
	e.sweep()
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the sweep took %s", d)
	}
	kept, fresh := 0, 0
	for _, c := range e.h.UsageOverview().Apps[0].Containers {
		switch {
		case c.Sample.MemBytes != nil && *c.Sample.MemBytes == 7:
			kept++
		case c.Sample.MemBytes != nil && *c.Sample.MemBytes == 9:
			fresh++
		}
	}
	if kept == 0 || fresh == 0 || kept+fresh != 40 {
		t.Errorf("kept %d, fresh %d", kept, fresh)
	}
	if n := strings.Count(logs.String(), "budget_skipped"); n != 1 {
		t.Errorf("budget log lines = %d: %s", n, logs.String())
	}
}

func TestUsageHistoryKeyedByServiceNumber(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"), uunit("a2", "portcullis-a", "db", 1, "running"))
	for i := range 3 {
		e.stats("a1", uint64(i+1)*1e9, 100)
		e.stats("a2", uint64(i+1)*1e9, 200)
		e.sweep()
		e.clock.Add(15 * time.Second)
	}
	g, err := e.h.UsageInstance("a")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.History.T) != 3 || len(g.History.MemBytes["web.1"]) != 3 || len(g.History.CPUCores["db.1"]) != 3 {
		t.Errorf("history = %+v", g.History)
	}
	if p := g.History.MemBytes["db.1"][2]; p == nil || *p != 200 {
		t.Errorf("db.1 = %v", p)
	}
	if _, err := e.h.UsageInstance("../x"); err == nil || !strings.Contains(err.Error(), "app instance not found") {
		t.Errorf("bad id: %v", err)
	}
}

// On Kubernetes the core group is not measured (the Hub's Role has
// nothing in the core namespace), nothing is counted as not shown, and a
// runtime-wide NotMeasuredError reaches the doctor.
func TestUsageKubeCoreNotMeasured(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.rt.K = runtime.KindKubernetes
	e.setUnits(uunit("a--web-x/web", "portcullis-a", "web", 1, "running"), runtime.Unit{ID: "x/y", State: "running"})
	e.rt.StatsErr = map[string]error{"a--web-x/web": &runtime.NotMeasuredError{Why: "the cluster has no metrics API (metrics-server)"}}
	e.sweep()
	v := e.h.UsageOverview()
	if v.Core.Status != "not_measured" || v.Core.Why != "not measured on Kubernetes yet" || v.NotShown != 0 {
		t.Errorf("core %q %q, not shown %d", v.Core.Status, v.Core.Why, v.NotShown)
	}
	if g := v.Apps[0]; g.Status != "not_measured" || g.Why != "the cluster has no metrics API (metrics-server)" {
		t.Errorf("app = %q %q", g.Status, g.Why)
	}
	if in := e.h.usageDoctorIn(); in == nil || in.NotMeasured != "the cluster has no metrics API (metrics-server)" {
		t.Errorf("doctor in = %+v", in)
	}
}

// M4: a restart right after the working set neared the limit is an OOM
// kill even when the engine has cleared OOMKilled again: the CPU counter
// going down triggers an inspect at once, the restart count is fresh and
// the point is marked.
func TestUsageOOMRestartLoopSeen(t *testing.T) {
	for name, c := range map[string]struct {
		mem  uint64
		want bool
	}{"near the limit": {95 << 20, true}, "far from it": {40 << 20, false}} {
		t.Run(name, func(t *testing.T) {
			e := newUsageEnv(t, "a")
			e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"))
			t0 := usageT0.Add(-time.Hour)
			e.rt.Infos = map[string]runtime.UnitInfo{"a1": {ID: "a1", Memory: 100 << 20, StartedAt: t0}}
			e.stats("a1", 10e9, c.mem)
			e.sweep()
			e.clock.Add(15 * time.Second)
			// Killed and started again between two sweeps: OOMKilled is
			// already false.
			e.rt.Lock()
			e.rt.Infos["a1"] = runtime.UnitInfo{ID: "a1", Memory: 100 << 20, StartedAt: t0.Add(time.Hour), RestartCount: 1}
			e.rt.Unlock()
			e.stats("a1", 1e8, 10<<20)
			e.sweep()
			if n := usageCalls(e.rt.Calls(), "inspect a1"); n != 2 {
				t.Errorf("inspects = %d, want one at once after the restart", n)
			}
			in := e.h.usageDoctorIn()
			if in == nil || len(in.Containers) != 1 {
				t.Fatalf("in = %+v", in)
			}
			if got := in.Containers[0]; got.Restarts != 1 || got.OOMSeenHour != c.want {
				t.Errorf("restarts %d, OOM seen %v (want %v)", got.Restarts, got.OOMSeenHour, c.want)
			}
		})
	}
}

// M4: a container seen not running and then running again is inspected
// at once (its restart count is fresh), not after 5 minutes.
func TestUsageInspectAfterRestartState(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.rt.Infos = map[string]runtime.UnitInfo{"a1": {ID: "a1", Memory: 64 << 20}}
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"))
	e.stats("a1", 1e9, 1)
	e.sweep()
	e.clock.Add(15 * time.Second)
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "restarting"))
	e.sweep()
	n := usageCalls(e.rt.Calls(), "inspect a1")
	e.clock.Add(15 * time.Second)
	e.rt.Lock()
	e.rt.Infos["a1"] = runtime.UnitInfo{ID: "a1", Memory: 64 << 20, RestartCount: 1}
	e.rt.Unlock()
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"))
	e.sweep()
	if usageCalls(e.rt.Calls(), "inspect a1") != n+1 {
		t.Error("not inspected when it ran again")
	}
	if c := e.h.UsageOverview().Apps[0].Containers[0]; c.Restarts != 1 {
		t.Errorf("restarts = %d", c.Restarts)
	}
}

// M5: a member whose stats call failed keeps its known limits, so the
// group's memory limit stays the sum (never "partly unlimited").
func TestUsageFailedStatsKeepsGroupLimit(t *testing.T) {
	e := newUsageEnv(t, "a")
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"), uunit("a2", "portcullis-a", "db", 1, "running"))
	e.rt.Infos = map[string]runtime.UnitInfo{"a1": {ID: "a1", Memory: 64 << 20, PidsLimit: 10}, "a2": {ID: "a2", Memory: 32 << 20, PidsLimit: 5}}
	e.stats("a1", 1e9, 100)
	e.rt.StatsErr = map[string]error{"a2": errors.New("timeout")}
	e.sweep()
	g := e.h.UsageOverview().Apps[0]
	if g.Totals.MemLimitBytes == nil || *g.Totals.MemLimitBytes != 96<<20 {
		t.Errorf("group memory limit = %v, want 96 MiB", g.Totals.MemLimitBytes)
	}
	if g.Totals.PidsLimit == nil || *g.Totals.PidsLimit != 15 {
		t.Errorf("group pids limit = %v", g.Totals.PidsLimit)
	}
	if g.Totals.MemBytes == nil || !g.Partial {
		t.Errorf("figures %v partial %v", g.Totals.MemBytes, g.Partial)
	}
}
