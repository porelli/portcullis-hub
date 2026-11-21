package hub

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/usage"
)

// UsageView is GET /api/usage (contract §11.11): from the sampler's
// cache only. Hosts: server id → its host ("primary" always).
type UsageView struct {
	SampledAt       *time.Time           `json:"sampled_at"`
	IntervalS       int                  `json:"interval_s"`
	Stale           bool                 `json:"stale"`
	Engine          UsageEngine          `json:"engine"`
	Hosts           map[string]UsageHost `json:"hosts"`
	Apps            []UsageGroup         `json:"apps"`
	Core            UsageGroup           `json:"core"`
	UnknownProjects []UsageGroup         `json:"unknown_projects"`
	NotShown        int                  `json:"not_shown"`
	OverLimit       int                  `json:"over_limit"`
	MetricsScraped  bool                 `json:"metrics_scraped"`
	// Window echoes the request's window: "last" or "1h".
	Window string `json:"window"`
}

// UsageEngine is the runtime and the guard's state.
type UsageEngine struct {
	Runtime  string `json:"runtime"`
	Verified bool   `json:"verified"`
	Why      string `json:"why,omitempty"`
}

// UsageHost is one server's host (contract §11.11): its CPUs and memory
// (the engine's /info) and its host-wide figures from procfs (§6 "Host
// figures"); every figure nil when not measured, Why the reason.
type UsageHost struct {
	Name         string   `json:"name"`
	CPUs         *int     `json:"cpus"`
	MemoryBytes  *int64   `json:"memory_bytes"`
	CPUUsedCores *float64 `json:"cpu_used_cores"`
	MemUsedBytes *int64   `json:"mem_used_bytes"`
	BlkReadBps   *float64 `json:"blk_read_bps"`
	BlkWriteBps  *float64 `json:"blk_write_bps"`
	Why          string   `json:"why,omitempty"`
}

// UsageGroup is one app instance, core, or an unknown project.
type UsageGroup struct {
	Instance string `json:"instance"`
	Template string `json:"template"`
	Name     string `json:"name"`
	Status   string `json:"status"` // running | stopped | restarting | partly running | job_failed | not_measured
	Why      string `json:"why,omitempty"`
	// Server is the id of the server it runs on ("primary"; its host is
	// UsageView.Hosts[Server]).
	Server string `json:"server"`
	// JobsDone / JobsFailed: its one-shot setup jobs that finished (exit
	// 0) or failed (unitHealth), reported apart from its services ("running
	// · 3 setup jobs done"; a failed one makes the status job_failed).
	JobsDone   int              `json:"jobs_done"`
	JobsFailed int              `json:"jobs_failed"`
	Totals     usage.Sample     `json:"totals"`
	Partial    bool             `json:"partial"`
	Containers []UsageContainer `json:"containers"`
	History    *UsageHistory    `json:"history,omitempty"` // UsageInstance only
	Storage    *StorageGroup    `json:"storage,omitempty"` // UsageInstance only
}

// UsageContainer is one container of a group (Helper: the core group's
// "Hub helpers (transient)" row, Number its count).
type UsageContainer struct {
	ID12      string       `json:"id12"`
	Service   string       `json:"service"`
	Number    int          `json:"number"`
	State     string       `json:"state"`
	Sample    usage.Sample `json:"sample"`
	Limits    UsageLimits  `json:"limits"`
	OOMKilled bool         `json:"oom_killed"`
	Restarts  int          `json:"restarts"`
	Helper    bool         `json:"helper,omitempty"`
	Error     string       `json:"error,omitempty"`
	// NotMeasured: each null sample field with a known reason → its
	// fixed text (usage.Sample.NotMeasured; contract §11.11).
	NotMeasured map[string]string `json:"not_measured,omitempty"`
	// Job / JobState: a one-shot setup job and its state (done | failed |
	// running | pending, the app page's job_state).
	Job      bool   `json:"job,omitempty"`
	JobState string `json:"job_state,omitempty"`
}

// UsageLimits are a container's limits (MemBytes / Pids 0 = none,
// CPUCores nil = none).
type UsageLimits struct {
	MemBytes int64    `json:"mem_bytes"`
	CPUCores *float64 `json:"cpu_cores"`
	Pids     int64    `json:"pids"`
}

// UsageHistory is a group's last hour, keyed "<service>.<number>".
type UsageHistory struct {
	T        []time.Time           `json:"t"`
	CPUCores map[string][]*float64 `json:"cpu_cores"`
	MemBytes map[string][]*int64   `json:"mem_bytes"`
}

// usageHelpersName names the core group's helpers row.
const usageHelpersName = "Hub helpers (transient)"

// usageNotMeasuredKube: the core group on Kubernetes.
const usageNotMeasuredKube = "not measured on Kubernetes yet"

// usageHostNotMeasuredKube: the primary's host on Kubernetes.
const usageHostNotMeasuredKube = "not measured on Kubernetes"

// The windows of GET /api/usage (contract §11.11).
const (
	UsageWindowLast = "last"
	UsageWindow1h   = "1h"
)

// UsageOverview is the whole view in window ("last": the newest sample;
// "1h": the means of the last hour's points; anything else is "last").
func (h *Hub) UsageOverview(window string) UsageView {
	if window != UsageWindow1h {
		window = UsageWindowLast
	}
	s := h.usage
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := UsageView{IntervalS: int(usage.Interval / time.Second), Apps: []UsageGroup{}, UnknownProjects: []UsageGroup{},
		NotShown: s.notShown, OverLimit: s.overLimit, MetricsScraped: h.MetricsScrapedRecently(), Window: window}
	var since time.Time // zero: the newest sample
	if window == UsageWindow1h {
		since = s.now().Add(-time.Hour)
	}
	v.Engine = UsageEngine{Runtime: s.kind, Verified: s.verified, Why: s.why}
	if v.Engine.Runtime == "" && h.rt != nil {
		v.Engine.Runtime = string(h.rt.Kind())
	}
	if !s.lastSuccess.IsZero() {
		t := s.lastSuccess
		v.SampledAt = &t
	}
	v.Stale = s.lastSuccess.IsZero() || s.now().Sub(s.lastSuccess) >= 2*usage.Interval
	v.Hosts = map[string]UsageHost{servers.PrimaryID: s.primaryHostLocked(v.Engine.Runtime, since)}
	for id, w := range s.workers {
		v.Hosts[id] = w.hostLocked(since)
	}
	// byGroup: "<server>\x00<group>\x00<kind>" (the primary's server "").
	byGroup := map[string][]*usageCont{}
	for _, c := range s.conts {
		k := c.Server + "\x00" + c.Group + "\x00" + c.Kind
		byGroup[k] = append(byGroup[k], c)
	}
	for id, inst := range s.insts {
		if g, ok := s.appGroupLocked(inst, byGroup[inst.Server+"\x00"+id+"\x00"+usageApp], since); ok {
			v.Apps = append(v.Apps, g)
		}
	}
	sort.Slice(v.Apps, func(i, j int) bool { return v.Apps[i].Instance < v.Apps[j].Instance })
	v.Core = s.groupLocked("", "core", "", "Core", byGroup["\x00"+usageCoreProject+"\x00"+usageCore], byGroup["\x00"+usageCoreProject+"\x00"+usageHelper], since)
	if v.Engine.Runtime == "kubernetes" {
		v.Core.Status, v.Core.Why = "not_measured", usageNotMeasuredKube
	}
	var unknown []string
	for k := range byGroup {
		if server, rest, _ := strings.Cut(k, "\x00"); server == "" {
			if g, kind, _ := strings.Cut(rest, "\x00"); kind == usageUnknown {
				unknown = append(unknown, g)
			}
		}
	}
	sort.Strings(unknown)
	for _, p := range unknown {
		v.UnknownProjects = append(v.UnknownProjects, s.groupLocked("", "", "", p, byGroup["\x00"+p+"\x00"+usageUnknown], nil, since))
	}
	return v
}

// usageServerID is a server's id in the views ("" = the primary's).
func usageServerID(server string) string {
	if server == "" {
		return servers.PrimaryID
	}
	return server
}

// appGroupLocked is inst's group from its containers cs on its server.
// On a worker that isn't measured (an older agent, unreachable) it is
// not_measured with the worker's reason, every figure nil (never stale
// numbers); a worker no longer ready shows none (ok false), nor does an
// app with no container. Caller holds s.mu (read).
func (s *usageState) appGroupLocked(inst usageInst, cs []*usageCont, since time.Time) (UsageGroup, bool) {
	if inst.Server != "" {
		w := s.workers[inst.Server]
		if w == nil {
			return UsageGroup{}, false
		}
		if w.appsWhy != "" {
			return UsageGroup{Instance: inst.ID, Template: inst.Template, Name: inst.Name, Server: inst.Server, Status: "not_measured", Why: w.appsWhy,
				Containers: []UsageContainer{}}, true
		}
	}
	if len(cs) == 0 {
		return UsageGroup{}, false
	}
	return s.groupLocked(inst.Server, inst.ID, inst.Template, inst.Name, cs, nil, since), true
}

// hostLocked is a worker's UsageHost: its engine's CPUs and memory (its
// /v1/info) and the newest host point (since: the mean of the points at
// or after it); every figure nil with the reason when not measured.
// Caller holds s.mu (read).
func (w *usageWorker) hostLocked(since time.Time) UsageHost {
	h := UsageHost{Name: w.name}
	if w.hostWhy != "" {
		h.Why = w.hostWhy
		return h
	}
	if w.cpus > 0 {
		n := w.cpus
		h.CPUs = &n
	}
	if w.mem > 0 {
		m := w.mem
		h.MemoryBytes = &m
	}
	var hs usage.HostSample
	if since.IsZero() {
		p, _ := w.hostRing.Last()
		hs = p.S
	} else {
		hs, _ = usage.MeanHost(w.hostRing.Since(since))
	}
	h.CPUUsedCores, h.MemUsedBytes, h.BlkReadBps, h.BlkWriteBps = hs.CPUUsedCores, hs.MemUsedBytes, hs.BlkReadBps, hs.BlkWriteBps
	return h
}

// primaryHostLocked is the primary's UsageHost: the engine's CPUs and
// memory and the newest host point (since non-zero: the mean of the
// points at or after it, nil points skipped). On Kubernetes every figure
// is nil. Caller holds s.mu (read).
func (s *usageState) primaryHostLocked(runtimeKind string, since time.Time) UsageHost {
	h := UsageHost{Name: primaryServerName}
	if runtimeKind == string(runtime.KindKubernetes) {
		h.Why = usageHostNotMeasuredKube
		return h
	}
	if s.cpus > 0 {
		n := s.cpus
		h.CPUs = &n
	}
	if s.mem > 0 {
		m := s.mem
		h.MemoryBytes = &m
	}
	if s.hostRing != nil {
		var hs usage.HostSample
		if since.IsZero() {
			p, _ := s.hostRing.Last()
			hs = p.S
		} else {
			hs, _ = usage.MeanHost(s.hostRing.Since(since))
		}
		h.CPUUsedCores, h.MemUsedBytes, h.BlkReadBps, h.BlkWriteBps = hs.CPUUsedCores, hs.MemUsedBytes, hs.BlkReadBps, hs.BlkWriteBps
	}
	return h
}

// groupLocked builds one group. since non-zero (window 1h): each running
// app or core container's sample is the mean of its key's points at or
// after since (usage.Mean; a skipped nil point makes the group partial),
// and the totals sum those means; helpers and unknown projects have no
// ring and keep their newest sample. Caller holds s.mu (read).
func (s *usageState) groupLocked(server, instance, template, name string, cs, helpers []*usageCont, since time.Time) UsageGroup {
	g := UsageGroup{Instance: instance, Template: template, Name: name, Server: usageServerID(server), Containers: []UsageContainer{}}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Service != cs[j].Service {
			return cs[i].Service < cs[j].Service
		}
		if cs[i].Number != cs[j].Number {
			return cs[i].Number < cs[j].Number
		}
		return cs[i].ID < cs[j].ID
	})
	var samples []usage.Sample
	// unitHealth (shared with Status and reconcile): a done one-shot job
	// is as it should be, and a stopped leftover of a service expected to
	// have no container (an inactive profile, a scaled-off companion)
	// isn't counted (a running or restarting one is, like reconcile's
	// inactiveRunning); a failed job makes it job_failed (never partly
	// running); anything else not up makes the group partly running.
	running, restarting, counted, up, notMeas, measured := 0, 0, 0, 0, map[string]bool{}, 0
	meanPartial := false
	for _, c := range cs {
		sample := c.Sample
		if !since.IsZero() && c.Running && (c.Kind == usageApp || c.Kind == usageCore) {
			if rg := s.rings[ringKey(server, c.Group, c.Service, c.Number)]; rg != nil {
				if ps := rg.Since(since); len(ps) > 0 {
					var p bool
					sample, p = usage.Mean(ps)
					meanPartial = meanPartial || p
				}
			}
		}
		g.Containers = append(g.Containers, UsageContainer{
			ID12: shortContainerID(c.ID), Service: c.Service, Number: c.Number, State: c.State,
			Sample: sample, NotMeasured: runningNotMeasured(c, sample), Limits: UsageLimits{MemBytes: c.Limits.MemBytes, CPUCores: c.Limits.CPUCores, Pids: c.Limits.Pids},
			OOMKilled: c.Limits.OOMKilled, Restarts: c.Limits.Restarts, Error: c.Err,
		})
		health := c.Health
		if health == "" {
			health = unitHealth(false, docker.State{Running: c.Running, Status: c.State})
		}
		if c.Job {
			g.Containers[len(g.Containers)-1].Job, g.Containers[len(g.Containers)-1].JobState = true, health
		}
		if !c.Skip || c.Running || c.State == "restarting" {
			counted++
			if healthUp(health) {
				up++
			}
			if c.Job && health == jobDone {
				g.JobsDone++
			}
			if c.Job && health == jobFailed {
				g.JobsFailed++
			}
		}
		switch {
		case c.Running:
			running++
			samples = append(samples, sample)
			if c.NotMeas != "" {
				notMeas[c.NotMeas] = true
			} else {
				measured++
			}
		case c.State == "restarting":
			restarting++
		}
	}
	if len(helpers) > 0 {
		var hs []usage.Sample
		for _, c := range helpers {
			hs = append(hs, c.Sample)
		}
		tot, _ := usage.Total(hs)
		g.Containers = append(g.Containers, UsageContainer{Service: usageHelpersName, Number: len(helpers), State: "running", Sample: tot, Helper: true})
		samples = append(samples, hs...)
	}
	switch {
	case len(cs) == 0 && len(helpers) == 0:
		g.Status = "stopped"
	case running > 0 && g.JobsFailed > 0:
		// The app page's "setup job failed", never "partly running".
		g.Status = "job_failed"
	case up == counted && (running > 0 || len(cs) == 0):
		// Everything up (helpers only: core's transient row).
		g.Status = "running"
	case running == 0 && restarting > 0:
		g.Status = "restarting"
	case running == 0:
		g.Status = "stopped"
	default:
		g.Status = "partly running"
	}
	if running > 0 && measured == 0 && len(notMeas) == 1 && g.Status != "job_failed" {
		for why := range notMeas {
			g.Status, g.Why = "not_measured", why
		}
	}
	if len(samples) > 0 {
		if since.IsZero() {
			g.Totals, g.Partial = usage.Total(samples)
		} else {
			// Window 1h: only a real gap is partial.
			g.Totals, g.Partial = usage.TotalExcused(samples)
		}
	}
	g.Partial = g.Partial || meanPartial
	return g
}

// runningNotMeasured is a running container's not_measured (a stopped
// one has no sample to explain).
func runningNotMeasured(c *usageCont, s usage.Sample) map[string]string {
	if !c.Running {
		return nil
	}
	return s.NotMeasured()
}

// UsageInstance is one instance's group with its last hour (and, from
// the storage cache, its storage).
func (h *Hub) UsageInstance(id string) (*UsageGroup, error) {
	inst, ok := h.usageInstances()[id]
	if !ok {
		return nil, statusErr(http.StatusNotFound, "app instance not found: %s", id)
	}
	s := h.usage
	s.mu.RLock()
	var cs []*usageCont
	for _, c := range s.conts {
		if c.Kind == usageApp && c.Group == id && c.Server == inst.Server {
			cs = append(cs, c)
		}
	}
	g, ok := s.appGroupLocked(inst, cs, time.Time{})
	if !ok {
		g = s.groupLocked(inst.Server, inst.ID, inst.Template, inst.Name, nil, nil, time.Time{})
		g.Status = "stopped"
	}
	g.History = s.historyLocked(groupKey(inst.Server, id))
	s.mu.RUnlock()
	g.Storage = h.usageStorageGroup(id)
	return &g, nil
}

// historyLocked is a group's last hour on its own time axis (group: its
// groupKey). Caller holds s.mu (read).
func (s *usageState) historyLocked(group string) *UsageHistory {
	hist := &UsageHistory{T: []time.Time{}, CPUCores: map[string][]*float64{}, MemBytes: map[string][]*int64{}}
	tr := s.times[group]
	if tr == nil {
		return hist
	}
	for _, p := range tr.Points() {
		hist.T = append(hist.T, p.T)
	}
	idx := make(map[time.Time]int, len(hist.T))
	for i, t := range hist.T {
		idx[t] = i
	}
	prefix := group + "\x00"
	for k, rg := range s.rings {
		key, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue
		}
		cpu := make([]*float64, len(hist.T))
		mem := make([]*int64, len(hist.T))
		for _, p := range rg.Points() {
			if i, ok := idx[p.T]; ok {
				cpu[i], mem[i] = p.S.CPUCores, p.S.MemBytes
			}
		}
		hist.CPUCores[key], hist.MemBytes[key] = cpu, mem
	}
	return hist
}

// usageSnap is a deep copy of the sampler's cache for the doctor and the
// metrics listener.
type usageSnap struct {
	Runtime     string
	Verified    bool
	Why         string
	Now         time.Time
	LastSuccess time.Time
	Since       time.Time // the first sweep attempt (zero: none yet)
	NotMeasured string
	Containers  []usageSnapCont
}

// usageSnapCont is one app or core container (Instance "" = core).
type usageSnapCont struct {
	Instance, Service string
	Number            int
	ID                string
	Running, Sampled  bool
	Limits            usage.Limits
	Sample            usage.Sample
	// Raw is the last stats sample (the metrics' counters), nil before
	// one.
	Raw *usageRaw
	// Points: the key's last hour, oldest first.
	Points []usage.Point
}

// usageRaw are the counters of the last sample.
type usageRaw struct {
	CPUUsageNS, NetRx, NetTx, BlkRead, BlkWrite *uint64
}

func copyU64(p *uint64) *uint64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func (h *Hub) usageSnapshot() usageSnap {
	s := h.usage
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := usageSnap{Runtime: s.kind, Verified: s.verified, Why: s.why, Now: s.now(), LastSuccess: s.lastSuccess, Since: s.startedAt, NotMeasured: s.notMeasured}
	for _, c := range s.conts {
		// The doctor and the metrics listener: the primary's containers
		// only (a worker's are on its own page and its agent's metrics).
		if (c.Kind != usageApp && c.Kind != usageCore) || c.Server != "" {
			continue
		}
		sc := usageSnapCont{Service: c.Service, Number: c.Number, ID: c.ID, Running: c.Running, Sampled: c.Sampled, Limits: c.Limits, Sample: c.Sample}
		if c.Limits.CPUCores != nil {
			v := *c.Limits.CPUCores
			sc.Limits.CPUCores = &v
		}
		if c.Kind == usageApp {
			sc.Instance = c.Group
		}
		if c.Prev != nil && c.Sampled {
			sc.Raw = &usageRaw{CPUUsageNS: copyU64(c.Prev.CPUUsageNS), NetRx: copyU64(c.Prev.NetRx), NetTx: copyU64(c.Prev.NetTx),
				BlkRead: copyU64(c.Prev.BlkRead), BlkWrite: copyU64(c.Prev.BlkWrite)}
		}
		if rg := s.rings[c.Group+"\x00"+usageKey(c.Service, c.Number)]; rg != nil {
			sc.Points = rg.Points()
		}
		snap.Containers = append(snap.Containers, sc)
	}
	sort.Slice(snap.Containers, func(i, j int) bool {
		a, b := snap.Containers[i], snap.Containers[j]
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return a.Number < b.Number
	})
	return snap
}

// StorageGroup is one instance's storage (contract §11.11; the storage
// measurer fills it).
type StorageGroup struct {
	Instance   string        `json:"instance"`
	Name       string        `json:"name"`
	Items      []StorageItem `json:"items"`
	TotalAlloc *int64        `json:"total_alloc_bytes"`
	Partial    bool          `json:"partial"`
}

// StorageItem is one measured (or listed) target.
type StorageItem struct {
	Target        string   `json:"target"`
	Kind          string   `json:"kind"` // volume | bind | folder | layer | image | hub_files
	Owner         string   `json:"owner"`
	AllocBytes    *int64   `json:"alloc_bytes"`
	ApparentBytes *int64   `json:"apparent_bytes"`
	Partial       bool     `json:"partial"`
	PartialReason string   `json:"partial_reason"`
	InTotal       bool     `json:"in_total"`
	Shared        []string `json:"shared_with,omitempty"`
	// Dev: the filesystem its measurement's report named (nil: unknown,
	// never measured); Services: the containers that mount it (volume
	// and bind items only, sorted "<service>.<number>", the owner's).
	Dev        *uint64    `json:"dev,omitempty"`
	Services   []string   `json:"services,omitempty"`
	Path       string     `json:"-"`
	MeasuredAt *time.Time `json:"measured_at"`
	DurationMS int64      `json:"duration_ms"`
	Error      string     `json:"error,omitempty"`
}
