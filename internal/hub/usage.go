package hub

// The usage sampler (contract §11.11): every 15 s it lists the engine's
// containers, takes one stats sample of each running in-scope container
// (usage.Parallel at once, usage.StatsTimeout each, usage.SweepBudget per
// sweep) and inspects each on first sight and every usage.InspectEvery.
// Everything is kept in the sampler's own cache, guarded by its own
// RWMutex: page views, the CSV export, MCP tools, the doctor and the
// metrics listener read only that cache, never the engine.
//
// Rules: Hub.mu is held only to copy the instance list, never across an
// engine call; an inspect is copied field by field (runtime.UnitInfo:
// never Config.Env), and no engine body is ever logged, stored or
// returned ("stats unavailable").

import (
	"context"
	"errors"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/kube"
	"github.com/portcullis/hub/internal/usage"
	"github.com/prometheus/procfs"
	"github.com/prometheus/procfs/blockdevice"
)

// usageStatsUnavailable is the fixed text of a failed stats sample.
const usageStatsUnavailable = "stats unavailable"

// usageCoreProject is core's compose project.
const usageCoreProject = "portcullis"

// usageInst is an instance as the sampler names it.
type usageInst struct {
	ID, Template, Name string
	// Jobs are the template's one-shot job services; Skip the services
	// expected to have no container (statusSkips: an inactive profile, a
	// companion scaled to 0). Both feed unitHealth's group status.
	Jobs, Skip map[string]bool
}

// usageCont is one container the sampler knows (by container ID).
type usageCont struct {
	ID       string
	Group    string // instance id, "core", or the unknown project's name
	Kind     string // usageApp | usageCore | usageUnknown | usageHelper
	Service  string
	Number   int
	State    string
	Running  bool
	Sampled  bool // a stats sample this start (Sample is from it)
	Limits   usage.Limits
	Inspect  time.Time // the last inspect (zero: never)
	Prev     *runtime.UnitStats
	PrevAt   time.Time // Prev's StartedAt
	Sample   usage.Sample
	Err      string // usageStatsUnavailable, or ""
	NotMeas  string // a NotMeasuredError's Why
	LastSeen time.Time
	// Image (the list's image reference) and Mounts (from the inspect):
	// the storage measurer's layers, images and bind targets.
	Image  string
	Mounts []runtime.Mount
	// LastMem is the last measured working set, kept across a stop (M4:
	// a restart right after it neared the limit is an OOM suspect).
	LastMem *int64
	// Job / Skip: from the instance (usageInst); Health its unitHealth
	// and JobKey the list state the job's health was read for.
	Job, Skip      bool
	Health, JobKey string
}

const (
	usageApp     = "app"
	usageCore    = "core"
	usageUnknown = "unknown"
	usageHelper  = "helper"
)

// usageState is the sampler's cache.
type usageState struct {
	mu sync.RWMutex
	// now is the clock (tests); budget / statsTimeout the sweep's
	// limits (usage.SweepBudget / usage.StatsTimeout; tests).
	now          func() time.Time
	budget       time.Duration
	statsTimeout time.Duration
	// instances overrides the instance list (tests; nil: Hub.Instances).
	instances func() []usageInst

	conts map[string]*usageCont
	// rings: "<group>\x00<service>.<number>" → that key's points (a
	// recreated container continues its key); times: group → the sweep
	// times of the group (the history's time axis).
	rings map[string]*usage.Ring
	times map[string]*usage.Ring
	insts map[string]usageInst

	startedAt   time.Time // the first sweep attempt
	sweptAt     time.Time // the last sweep attempt
	lastSuccess time.Time // the last sweep whose list succeeded
	verified    bool
	why         string
	kind        string
	cpus        int
	mem         int64
	infoAt      time.Time
	notShown    int
	overLimit   int
	// notMeasured: every sampled container answered the same
	// NotMeasuredError (Kubernetes): its Why.
	notMeasured string
	// sweeping: one sweep at a time.
	sweeping sync.Mutex

	// The host's figures (contract §6 "Host figures"): readHost reads
	// the counters once per sweep (tests inject one; nil: not read),
	// host is the last good read (the next rate's base), hostRing the
	// derived figures of the last hour, hostErr the last read's failure
	// (logged once, not every sweep).
	readHost func() (usage.HostCounters, error)
	host     *usage.HostCounters
	hostRing *usage.HostRing
	hostErr  bool

	// The storage measurer (usage_storage.go): diskMu is held around each
	// fixer run, by the doctor's scans too (U12: never two walks at
	// once); measureMu = one run at a time (try-lock, 409); storeMu
	// guards store, the storage cache (nil = not loaded); fixer replaces
	// the usage fixer run (tests).
	diskMu    sync.Mutex
	measureMu sync.Mutex
	storeMu   sync.Mutex
	store     *storageFile
	fixer     func(ctx context.Context, r fixerRun) (*folderfix.Report, error)
	// scrapedAt: the metrics listener's last scrape (Unix ns; 0 = never).
	scrapedAt atomic.Int64
}

func newUsageState() *usageState {
	return &usageState{now: func() time.Time { return time.Now().UTC() }, budget: usage.SweepBudget, statsTimeout: usage.StatsTimeout,
		conts: map[string]*usageCont{}, rings: map[string]*usage.Ring{}, times: map[string]*usage.Ring{}, insts: map[string]usageInst{},
		readHost: readProcHost, hostRing: usage.NewHostRing(usage.RingSize)}
}

// readProcHost reads the host's counters from the Hub's own /proc.
func readProcHost() (usage.HostCounters, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return usage.HostCounters{}, err
	}
	bfs, err := blockdevice.NewFS("/proc", "/sys")
	if err != nil {
		return usage.HostCounters{}, err
	}
	return usage.ReadHost(fs, bfs)
}

// sweepHost reads the host's counters and adds the derived figures at
// now (cpus: the engine's NCPU, 0: the cached one). Never on Kubernetes
// (kind): the Hub's pod is no reliable view of a node, so procfs isn't
// read at all. The error's text is procfs's (a path), never an engine
// body.
func (s *usageState) sweepHost(now time.Time, kind string, cpus int) {
	if s.readHost == nil || kind == string(runtime.KindKubernetes) {
		return
	}
	c, err := s.readHost()
	s.mu.Lock()
	defer s.mu.Unlock()
	if cpus <= 0 {
		cpus = s.cpus
	}
	if err != nil {
		if !s.hostErr {
			log.Printf("usage: the host's counters: %v", err)
		}
		s.hostErr = true
		s.hostRing.Add(usage.HostPoint{T: now})
		return
	}
	if s.hostErr {
		log.Printf("usage: the host's counters are read again")
	}
	s.hostErr = false
	smp := usage.DeriveHost(s.host, c, cpus)
	s.host = &c
	s.hostRing.Add(usage.HostPoint{T: now, S: smp})
}

// RunUsageSampler sweeps every interval until ctx ends (main: usage.Interval).
func (h *Hub) RunUsageSampler(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = usage.Interval
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if !h.noEngine() {
			h.usageSweep(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func usageRefused(err error) bool {
	return errors.Is(err, docker.ErrEngineRefused) || errors.Is(err, kube.ErrClusterUnverified)
}

// usageRefusal is the refusal's message to show (the guard's own text).
func usageRefusal(err error) string {
	var re *docker.RefusedError
	if errors.As(err, &re) {
		return re.Message()
	}
	return err.Error()
}

// usageInstances is the instance list, copied under mu and released.
func (h *Hub) usageInstances() map[string]usageInst {
	out := map[string]usageInst{}
	if f := h.usage.instances; f != nil {
		for _, i := range f() {
			out[i.ID] = i
		}
		return out
	}
	// The jobs and skipped services in one pass under mu (no template
	// copied per instance: usageInstances also serves single lookups).
	h.mu.RLock()
	jobs := make(map[string]map[string]bool, len(h.instances))
	skips := make(map[string]map[string]bool, len(h.instances))
	for i := range h.instances {
		t := &h.instances[i]
		inactive, scaledOff := h.statusSkipsLocked(t)
		skip := make(map[string]bool, len(inactive)+len(scaledOff))
		for svc := range inactive {
			skip[svc] = true
		}
		for svc := range scaledOff {
			skip[svc] = true
		}
		jobs[t.ID], skips[t.ID] = maps.Clone(t.Jobs), skip
	}
	h.mu.RUnlock()
	for _, v := range h.Instances() {
		out[v.ID] = usageInst{ID: v.ID, Template: v.Template, Name: v.Name, Jobs: jobs[v.ID], Skip: skips[v.ID]}
	}
	return out
}

// usageResult is one container's sweep outcome.
type usageResult struct {
	inspected bool
	info      runtime.UnitInfo
	stats     *runtime.UnitStats
	err       error
	skipped   bool // the sweep's budget ran out first
}

// usageSweep is one sweep (RunUsageSampler; tests call it directly).
func (h *Hub) usageSweep(ctx context.Context) {
	s := h.usage
	if !s.sweeping.TryLock() {
		return
	}
	defer s.sweeping.Unlock()
	now := s.now()
	s.mu.Lock()
	if s.startedAt.IsZero() {
		s.startedAt = now
	}
	s.mu.Unlock()
	insts := h.usageInstances()
	kind := string(h.rt.Kind())

	s.mu.RLock()
	needInfo := s.infoAt.IsZero() || now.Sub(s.infoAt) >= usage.InfoEvery
	s.mu.RUnlock()
	var info *runtime.Info
	if needInfo {
		if i, err := h.rt.Info(ctx); err == nil || i.CPUs > 0 {
			info = &i
		} else if !usageRefused(err) {
			log.Printf("usage: the engine's info: %v", err)
		}
	}

	hostCPUs := 0
	if info != nil {
		hostCPUs = info.CPUs
	}
	s.sweepHost(now, kind, hostCPUs)

	units, err := h.rt.List(ctx, runtime.Filter{})
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.sweptAt, s.kind = now, kind
		if info != nil {
			s.cpus, s.mem, s.infoAt = info.CPUs, info.MemoryBytes, now
		}
		if usageRefused(err) {
			s.verified, s.why = false, usageRefusal(err)
			return
		}
		log.Printf("usage: listing containers: %v", err)
		return
	}
	in, notShown := usageScope(units, insts)
	if kind == string(runtime.KindKubernetes) {
		// The Hub sees only its apps namespace: nothing else to count.
		notShown = 0
	}
	over := 0
	if len(in) > usage.MaxContainers {
		over = len(in) - usage.MaxContainers
		in = in[:usage.MaxContainers]
	}

	// A stopped job container's health needs its exit code (the list
	// has none): read once per list state (jobKey), not every sweep.
	jobHealth := map[string]string{}
	s.mu.RLock()
	var jobUnits []usageUnit
	for _, u := range in {
		if u.Kind != usageApp || !insts[u.Group].Jobs[u.Service] {
			continue
		}
		if c := s.conts[u.ID]; c != nil && c.Job && c.JobKey == jobKey(u.Unit) && c.Health != "" {
			jobHealth[u.ID] = c.Health
			continue
		}
		jobUnits = append(jobUnits, u)
	}
	statsTimeout0 := s.statsTimeout
	s.mu.RUnlock()
	for _, u := range jobUnits {
		health := listedJobState(u.State, u.Status)
		if u.State != "running" && u.State != "restarting" && u.State != "created" {
			sctx, scancel := context.WithTimeout(ctx, statsTimeout0)
			if st, err := h.rt.State(sctx, u.ID); err == nil {
				health = unitHealth(true, st)
			}
			scancel()
		}
		jobHealth[u.ID] = health
	}

	// What each container needs, read under the sampler's lock only.
	// A container that started again since the last sweep (its state
	// went back to running, or its CPU counter went down) is inspected at
	// once: its restart count and OOM state are fresh (M4).
	type job struct {
		u       usageUnit
		inspect bool
		prevCPU *uint64
	}
	var jobs []job
	s.mu.RLock()
	for _, u := range in {
		c := s.conts[u.ID]
		due := c == nil || c.Inspect.IsZero() || now.Sub(c.Inspect) >= usage.InspectEvery ||
			(u.State == "running" && c.State != "running")
		if u.State != "running" && !due {
			continue
		}
		j := job{u: u, inspect: due}
		if c != nil && c.Prev != nil {
			j.prevCPU = c.Prev.CPUUsageNS
		}
		jobs = append(jobs, j)
	}
	budget, statsTimeout := s.budget, s.statsTimeout
	s.mu.RUnlock()

	results := make([]usageResult, len(jobs))
	bctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var refused error
	var refusedMu sync.Mutex
	work := make(chan int)
	var wg sync.WaitGroup
	for range usage.Parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				r := &results[i]
				if bctx.Err() != nil {
					r.skipped = true
					continue
				}
				j := jobs[i]
				if j.inspect {
					ictx, icancel := context.WithTimeout(bctx, statsTimeout)
					ui, err := h.rt.Inspect(ictx, j.u.ID)
					icancel()
					if err == nil {
						r.inspected, r.info = true, ui
					} else if usageRefused(err) {
						refusedMu.Lock()
						refused = err
						refusedMu.Unlock()
						cancel()
						r.skipped = true
						continue
					}
				}
				if j.u.State != "running" {
					continue
				}
				sctx, scancel := context.WithTimeout(bctx, statsTimeout)
				st, err := h.rt.Stats(sctx, j.u.ID)
				scancel()
				switch {
				case err == nil:
					r.stats = &st
					if !j.inspect && j.prevCPU != nil && st.CPUUsageNS != nil && *st.CPUUsageNS < *j.prevCPU {
						ictx, icancel := context.WithTimeout(bctx, statsTimeout)
						if ui, err := h.rt.Inspect(ictx, j.u.ID); err == nil {
							r.inspected, r.info = true, ui
						}
						icancel()
					}
				case usageRefused(err):
					refusedMu.Lock()
					refused = err
					refusedMu.Unlock()
					cancel()
					r.skipped = true
				case bctx.Err() != nil && ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded):
					r.skipped = true
				default:
					r.err = err
				}
			}
		}()
	}
	for i := range jobs {
		work <- i
	}
	close(work)
	wg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweptAt, s.kind, s.insts = now, kind, insts
	if info != nil {
		s.cpus, s.mem, s.infoAt = info.CPUs, info.MemoryBytes, now
	}
	if refused != nil {
		s.verified, s.why = false, usageRefusal(refused)
		return
	}
	s.verified, s.why = true, ""
	s.lastSuccess = now
	s.notShown, s.overLimit = notShown, over
	live := map[string]bool{}
	for _, u := range in {
		live[u.ID] = true
		c := s.conts[u.ID]
		if c == nil {
			c = &usageCont{ID: u.ID}
			s.conts[u.ID] = c
		}
		c.Group, c.Kind, c.Service, c.Number, c.State, c.LastSeen, c.Image = u.Group, u.Kind, u.Service, u.Number, u.State, now, u.Image
		c.Running = u.State == "running"
		inst := insts[u.Group]
		c.Job = u.Kind == usageApp && inst.Jobs[u.Service]
		c.Skip = u.Kind == usageApp && inst.Skip[u.Service]
		if c.Job {
			c.Health, c.JobKey = jobHealth[u.ID], jobKey(u.Unit)
		} else {
			c.Health, c.JobKey = unitHealth(false, docker.State{Running: c.Running, Status: u.State}), ""
		}
		if !c.Running {
			c.Sampled, c.Prev, c.Sample, c.Err, c.NotMeas = false, nil, usage.Sample{}, "", ""
		}
	}
	for id := range s.conts {
		if !live[id] {
			delete(s.conts, id)
		}
	}
	skipped, notMeas, sampled := 0, map[string]int{}, 0
	for i, j := range jobs {
		r := results[i]
		c := s.conts[j.u.ID]
		if r.skipped {
			skipped++
			continue
		}
		// A restart: the counter went down, or a later inspect has more
		// restarts or another start. Just after the working set was at
		// 90 % of the limit, it is an OOM suspect even when the engine
		// has already cleared OOMKilled (M4).
		old, hadInspect := c.Limits, !c.Inspect.IsZero()
		restarted := r.stats != nil && c.Prev != nil && c.Prev.CPUUsageNS != nil && r.stats.CPUUsageNS != nil && *r.stats.CPUUsageNS < *c.Prev.CPUUsageNS
		if r.inspected {
			c.Limits, c.Inspect = usage.LimitsOf(r.info), now
			c.Mounts = slices.Clone(r.info.Mounts)
			if hadInspect && (c.Limits.Restarts > old.Restarts || !c.Limits.StartedAt.Equal(old.StartedAt)) {
				restarted = true
			}
		}
		oomSuspect := restarted && c.LastMem != nil && old.MemBytes > 0 && *c.LastMem >= old.MemBytes/10*9
		if restarted {
			c.LastMem = nil
		}
		if !c.Running {
			continue
		}
		sampled++
		switch {
		case r.stats != nil:
			c.Sample = usage.Derive(c.Prev, c.PrevAt, *r.stats, c.Limits)
			st := *r.stats
			c.Prev, c.PrevAt, c.Sampled, c.Err, c.NotMeas = &st, c.Limits.StartedAt, true, "", ""
		default:
			var nm *runtime.NotMeasuredError
			if errors.As(r.err, &nm) {
				c.NotMeas, c.Err = nm.Why, ""
				notMeas[nm.Why]++
			} else {
				c.Err = usageStatsUnavailable
				// Never the error's text: only its class (no engine body).
				log.Printf("usage: stats of %s: %s", shortContainerID(c.ID), usageErrClass(r.err))
			}
			// M5: the limits stay known (from the inspect): one failed
			// call never makes a group's limit "partly unlimited".
			c.Sample, c.Sampled, c.Prev = usage.Sample{}, false, nil
			if !c.Inspect.IsZero() {
				c.Sample = usage.LimitsSample(c.Limits)
			}
		}
		if c.Sample.MemBytes != nil {
			m := *c.Sample.MemBytes
			c.LastMem = &m
		}
		if c.Kind == usageApp || c.Kind == usageCore {
			key := c.Group + "\x00" + usageKey(c.Service, c.Number)
			rg := s.rings[key]
			if rg == nil {
				rg = usage.NewRing(usage.RingSize)
				s.rings[key] = rg
			}
			rg.Add(usage.Point{T: now, S: c.Sample, Restarts: c.Limits.Restarts, OOMKilled: c.Limits.OOMKilled || oomSuspect, ID: c.ID})
		}
	}
	s.notMeasured = ""
	if len(notMeas) == 1 && sampled > 0 {
		for why, n := range notMeas {
			if n == sampled {
				s.notMeasured = why
			}
		}
	}
	// The groups' time axes, and rings of keys that are gone for an hour
	// or whose instance is gone.
	groups := map[string]bool{}
	for _, c := range s.conts {
		if c.Running && (c.Kind == usageApp || c.Kind == usageCore) {
			groups[c.Group] = true
		}
	}
	for g := range groups {
		tr := s.times[g]
		if tr == nil {
			tr = usage.NewRing(usage.RingSize)
			s.times[g] = tr
		}
		tr.Add(usage.Point{T: now})
	}
	keep := func(group string) bool {
		_, ok := insts[group]
		return ok || group == usageCoreProject
	}
	for k, rg := range s.rings {
		g, _, _ := strings.Cut(k, "\x00")
		last, _ := rg.Last()
		if !keep(g) || now.Sub(last.T) > time.Duration(usage.RingSize)*usage.Interval {
			delete(s.rings, k)
		}
	}
	for g, tr := range s.times {
		last, _ := tr.Last()
		if !keep(g) || now.Sub(last.T) > time.Duration(usage.RingSize)*usage.Interval {
			delete(s.times, g)
		}
	}
	if skipped > 0 {
		log.Printf("usage: the sweep's %s budget is spent: budget_skipped %d containers kept their previous sample", budget, skipped)
	}
}

func usageKey(service string, number int) string { return service + "." + strconv.Itoa(number) }

func shortContainerID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// usageErrClass names an engine failure without its text.
func usageErrClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case docker.IsNotFound(err):
		return "not found"
	}
	return usageStatsUnavailable
}

// SweepUsage runs one sweep now (tests; RunUsageSampler sweeps on its
// own schedule).
func (h *Hub) SweepUsage(ctx context.Context) {
	if !h.noEngine() {
		h.usageSweep(ctx)
	}
}

// jobKey is the list state a job container's health was read for: its
// state and, when exited, the "Exited (n)" prefix of its status text (a
// rerun with another exit code is read again).
func jobKey(u runtime.Unit) string {
	if u.State == "exited" {
		if i := strings.IndexByte(u.Status, ')'); i >= 0 {
			return u.State + "\x00" + u.Status[:i+1]
		}
	}
	return u.State
}
