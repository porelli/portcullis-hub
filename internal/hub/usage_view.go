package hub

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/usage"
)

// UsageView is GET /api/usage (contract §11.11): from the sampler's
// cache only.
type UsageView struct {
	SampledAt       *time.Time   `json:"sampled_at"`
	IntervalS       int          `json:"interval_s"`
	Stale           bool         `json:"stale"`
	Engine          UsageEngine  `json:"engine"`
	Host            UsageHost    `json:"host"`
	Apps            []UsageGroup `json:"apps"`
	Core            UsageGroup   `json:"core"`
	UnknownProjects []UsageGroup `json:"unknown_projects"`
	NotShown        int          `json:"not_shown"`
	OverLimit       int          `json:"over_limit"`
	MetricsScraped  bool         `json:"metrics_scraped"`
}

// UsageEngine is the runtime and the guard's state.
type UsageEngine struct {
	Runtime  string `json:"runtime"`
	Verified bool   `json:"verified"`
	Why      string `json:"why,omitempty"`
}

// UsageHost is the host's CPUs and memory (nil: unknown).
type UsageHost struct {
	CPUs        *int   `json:"cpus"`
	MemoryBytes *int64 `json:"memory_bytes"`
}

// UsageGroup is one app instance, core, or an unknown project.
type UsageGroup struct {
	Instance   string           `json:"instance"`
	Template   string           `json:"template"`
	Name       string           `json:"name"`
	Status     string           `json:"status"` // running | stopped | restarting | partly running | not_measured
	Why        string           `json:"why,omitempty"`
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

// UsageOverview is the whole view.
func (h *Hub) UsageOverview() UsageView {
	s := h.usage
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := UsageView{IntervalS: int(usage.Interval / time.Second), Apps: []UsageGroup{}, UnknownProjects: []UsageGroup{},
		NotShown: s.notShown, OverLimit: s.overLimit, MetricsScraped: h.MetricsScrapedRecently()}
	v.Engine = UsageEngine{Runtime: s.kind, Verified: s.verified, Why: s.why}
	if v.Engine.Runtime == "" && h.rt != nil {
		v.Engine.Runtime = string(h.rt.Kind())
	}
	if !s.lastSuccess.IsZero() {
		t := s.lastSuccess
		v.SampledAt = &t
	}
	v.Stale = s.lastSuccess.IsZero() || s.now().Sub(s.lastSuccess) >= 2*usage.Interval
	if s.cpus > 0 {
		n := s.cpus
		v.Host.CPUs = &n
	}
	if s.mem > 0 {
		m := s.mem
		v.Host.MemoryBytes = &m
	}
	byGroup := map[string][]*usageCont{}
	for _, c := range s.conts {
		byGroup[c.Group+"\x00"+c.Kind] = append(byGroup[c.Group+"\x00"+c.Kind], c)
	}
	for id, inst := range s.insts {
		if cs := byGroup[id+"\x00"+usageApp]; len(cs) > 0 {
			v.Apps = append(v.Apps, s.groupLocked(inst.ID, inst.Template, inst.Name, cs, nil))
		}
	}
	sort.Slice(v.Apps, func(i, j int) bool { return v.Apps[i].Instance < v.Apps[j].Instance })
	v.Core = s.groupLocked("core", "", "Core", byGroup[usageCoreProject+"\x00"+usageCore], byGroup[usageCoreProject+"\x00"+usageHelper])
	if v.Engine.Runtime == "kubernetes" {
		v.Core.Status, v.Core.Why = "not_measured", usageNotMeasuredKube
	}
	var unknown []string
	for k := range byGroup {
		if g, kind, _ := strings.Cut(k, "\x00"); kind == usageUnknown {
			unknown = append(unknown, g)
		}
	}
	sort.Strings(unknown)
	for _, p := range unknown {
		v.UnknownProjects = append(v.UnknownProjects, s.groupLocked("", "", p, byGroup[p+"\x00"+usageUnknown], nil))
	}
	return v
}

// groupLocked builds one group. Caller holds s.mu (read).
func (s *usageState) groupLocked(instance, template, name string, cs, helpers []*usageCont) UsageGroup {
	g := UsageGroup{Instance: instance, Template: template, Name: name, Containers: []UsageContainer{}}
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
	// isn't counted; anything else not up makes the group partly running.
	running, restarting, counted, up, notMeas, measured := 0, 0, 0, 0, map[string]bool{}, 0
	for _, c := range cs {
		g.Containers = append(g.Containers, UsageContainer{
			ID12: shortContainerID(c.ID), Service: c.Service, Number: c.Number, State: c.State,
			Sample: c.Sample, Limits: UsageLimits{MemBytes: c.Limits.MemBytes, CPUCores: c.Limits.CPUCores, Pids: c.Limits.Pids},
			OOMKilled: c.Limits.OOMKilled, Restarts: c.Limits.Restarts, Error: c.Err,
		})
		health := c.Health
		if health == "" {
			health = unitHealth(false, docker.State{Running: c.Running, Status: c.State})
		}
		if !c.Skip || c.Running {
			counted++
			if healthUp(health) {
				up++
			}
		}
		switch {
		case c.Running:
			running++
			samples = append(samples, c.Sample)
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
	if running > 0 && measured == 0 && len(notMeas) == 1 {
		for why := range notMeas {
			g.Status, g.Why = "not_measured", why
		}
	}
	if len(samples) > 0 {
		g.Totals, g.Partial = usage.Total(samples)
	}
	return g
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
		if c.Kind == usageApp && c.Group == id {
			cs = append(cs, c)
		}
	}
	g := s.groupLocked(inst.ID, inst.Template, inst.Name, cs, nil)
	if len(cs) == 0 {
		g.Status = "stopped"
	}
	g.History = s.historyLocked(id)
	s.mu.RUnlock()
	g.Storage = h.usageStorageGroup(id)
	return &g, nil
}

// historyLocked is a group's last hour on its own time axis. Caller holds
// s.mu (read).
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
		if c.Kind != usageApp && c.Kind != usageCore {
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
	Target        string     `json:"target"`
	Kind          string     `json:"kind"` // volume | bind | folder | layer | image | hub_files
	Owner         string     `json:"owner"`
	AllocBytes    *int64     `json:"alloc_bytes"`
	ApparentBytes *int64     `json:"apparent_bytes"`
	Partial       bool       `json:"partial"`
	PartialReason string     `json:"partial_reason"`
	InTotal       bool       `json:"in_total"`
	Shared        []string   `json:"shared_with,omitempty"`
	Dev           uint64     `json:"-"`
	Path          string     `json:"-"`
	MeasuredAt    *time.Time `json:"measured_at"`
	DurationMS    int64      `json:"duration_ms"`
	Error         string     `json:"error,omitempty"`
}
