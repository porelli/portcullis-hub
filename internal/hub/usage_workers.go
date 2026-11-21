package hub

// Workers in the usage sampler (contract §11.11 "Workers", §17.4): every
// ready worker is swept in the same sweep through its agent — list,
// stats, host/usage — one goroutine per server, end to end, each under
// the same usage.Parallel limit and usage.StatsTimeout per call, all
// within the sweep's budget. The primary never waits for a worker: the
// workers join after the primary's sample is recorded, when they answer,
// and at the latest at the deadline (the budget plus usageWorkerGrace),
// after which a missing worker is "not measured: <name> is unreachable"
// (a late answer is dropped). A worker's answers are untrusted: the agent
// backend decodes and checks them; the Hub bounds what it derives (CPU
// rates, sums) and shares the container cap fairly, so one worker can
// neither hide another's apps nor make a figure wrong.

import (
	"context"
	"errors"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/usage"
)

// usageWorkerGrace: how long after the sweep's budget a worker's answer
// is still awaited (a backend that ignores its context).
const usageWorkerGrace = 500 * time.Millisecond

// The reasons of a worker's null figures (contract §11.11).
func workerOlder(name string) string {
	return "not measured: " + name + "'s agent is older than the Hub"
}

func workerUnreachable(name string) string {
	return "not measured: " + name + " is unreachable"
}

func workerHostUnread(name string) string {
	return "not measured: " + name + "'s host counters can't be read"
}

// usageTooMany: an app cut by the container cap (never silently dropped).
const usageTooMany = "not measured: too many containers"

// usageNoHostYet: the host figures before the first read.
const usageNoHostYet = "not measured yet"

// usageWorker is one worker's sampler state (usageState.workers).
type usageWorker struct {
	name   string
	cpus   int
	mem    int64
	infoAt time.Time
	// host: the last good host counters (the next rate's base); hostRing
	// the derived points; hostErr: a read failure was logged.
	host     *usage.HostCounters
	hostRing *usage.HostRing
	hostErr  bool
	// appsWhy / hostWhy: "" = measured; else the "not measured: …" text
	// of its apps and of its host figures. capped: its apps the cap cut.
	appsWhy, hostWhy string
	capped           map[string]bool
}

// usageWorkerSweep is one worker's part of a sweep (built by its own
// goroutine, then handed over; never shared).
type usageWorkerSweep struct {
	server, name string
	rt           runtime.Instances
	info         *runtime.Info
	in           []usageUnit
	host         *usage.HostCounters
	hostWhy      string
	appsWhy      string
	jobHealth    map[string]string
	jobs         []usageJob
	results      []usageResult
	// capped: its apps the cap cut; excess: their containers (over_limit).
	capped map[string]bool
	excess int
	// applied: the results are complete (the sample phase finished).
	applied bool
}

// usageWorkerBatch is the sweep's worker goroutines: each sends what it
// listed (interim: its info and host, for a sample phase that is late)
// and its final result.
type usageWorkerBatch struct {
	interim, final chan *usageWorkerSweep
	expected       []*usageWorkerSweep
	deadline       time.Time
}

// wait collects every final answer until the deadline. A server without
// one is unreachable, keeping the info and host it listed in time (its
// apps aren't recorded). Sorted by server id.
func (b *usageWorkerBatch) wait() []*usageWorkerSweep {
	got, interim := map[string]*usageWorkerSweep{}, map[string]*usageWorkerSweep{}
	timer := time.NewTimer(time.Until(b.deadline))
	defer timer.Stop()
collect:
	for len(got) < len(b.expected) {
		select {
		case sw := <-b.final:
			got[sw.server] = sw
		case sw := <-b.interim:
			interim[sw.server] = sw
		case <-timer.C:
			break collect
		}
	}
	for {
		select {
		case sw := <-b.interim:
			interim[sw.server] = sw
			continue
		default:
		}
		break
	}
	out := make([]*usageWorkerSweep, 0, len(b.expected))
	for _, e := range b.expected {
		if sw := got[e.server]; sw != nil {
			out = append(out, sw)
			continue
		}
		late := &usageWorkerSweep{server: e.server, name: e.name, rt: e.rt}
		late.appsWhy, late.hostWhy = workerUnreachable(e.name), workerUnreachable(e.name)
		if it := interim[e.server]; it != nil {
			late.info, late.host, late.hostWhy = it.info, it.host, it.hostWhy
			if late.host == nil && late.hostWhy == "" {
				late.hostWhy = workerHostUnread(e.name)
			}
		}
		log.Printf("usage: server %s didn't answer within the sweep's budget", e.server)
		out = append(out, late)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].server < out[j].server })
	return out
}

// usageWorkerRTs are the ready workers (id → name, backend).
func (h *Hub) usageWorkerRTs() []*usageWorkerSweep {
	r := h.reg()
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*usageWorkerSweep
	for id, s := range r.servers {
		if s.State == ServerReady && s.RT != nil {
			out = append(out, &usageWorkerSweep{server: id, name: nameOr(s.Name, id), rt: unwrapRT(s.RT)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].server < out[j].server })
	return out
}

// usageNotReady: every registered server that isn't ready → the reason
// its apps are not measured (ruling: they are listed, never hidden).
func (h *Hub) usageNotReady() map[string]string {
	r := h.reg()
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]string{}
	for id, s := range r.servers {
		name := nameOr(s.Name, id)
		switch {
		case s.State == ServerReady && s.RT != nil:
		case s.State == ServerRevoked:
			out[id] = "not measured: " + name + " is revoked"
		case s.State == ServerEnrolling:
			out[id] = "not measured: " + name + " isn't ready yet"
		default:
			out[id] = "not measured: " + name + " is offline"
		}
	}
	return out
}

// usageHostReader is a worker backend's host route (agentrt.Backend).
type usageHostReader interface {
	HostUsage(ctx context.Context) (usage.HostCounters, error)
}

// usageCap is the sweep's container cap: the primary takes its count
// first (at most usage.MaxContainers); every ready worker then has an
// equal share of the rest, at once, whatever another worker does. The
// room a worker doesn't need is handed out only at a fixed early point
// (one stats timeout after the sweep's start, at most half the budget),
// and only to the workers
// that reported by then (fairShare); a worker that reports later gets
// its equal share at once, and keeps it. No worker's share ever waits
// for another worker's answer.
type usageCap struct {
	mu          sync.Mutex
	primaryN    int // -1: not reported (its last sweep's count stands in)
	lastPrimary int
	n           int
	counts      map[string]int
	shares      map[string]chan int
	decided     bool
	early       time.Time
}

func newUsageCap() *usageCap {
	return &usageCap{primaryN: -1, counts: map[string]int{}, shares: map[string]chan int{}}
}

// start readies the cap for the workers in ws and arms the early point.
func (c *usageCap) start(bctx context.Context, ws []*usageWorkerSweep, lastPrimary int, timeout time.Duration) {
	c.mu.Lock()
	c.n, c.lastPrimary = len(ws), lastPrimary
	for _, w := range ws {
		c.shares[w.server] = make(chan int, 1)
	}
	// One stats timeout after the start, and never past half the budget
	// (a worker that reported must still have time to sample).
	c.early = time.Now().Add(timeout)
	if dl, ok := bctx.Deadline(); ok {
		if half := time.Now().Add(time.Until(dl) / 2); half.Before(c.early) {
			c.early = half
		}
	}
	c.mu.Unlock()
	go func() {
		t := time.NewTimer(time.Until(c.early))
		defer t.Stop()
		select {
		case <-t.C:
		case <-bctx.Done():
		}
		c.mu.Lock()
		c.decideLocked()
		c.mu.Unlock()
	}()
}

// roomLocked is what the workers share; equalLocked one worker's equal
// share. Caller holds c.mu.
func (c *usageCap) roomLocked() int {
	p := c.primaryN
	if p < 0 {
		p = c.lastPrimary
	}
	return max(usage.MaxContainers-min(p, usage.MaxContainers), 0)
}

func (c *usageCap) equalLocked() int {
	if c.n == 0 {
		return 0
	}
	return c.roomLocked() / c.n
}

// decideLocked hands the reported workers their shares: the room less
// an equal share kept for each worker that hasn't reported, shared
// fairly among them. Caller holds c.mu.
func (c *usageCap) decideLocked() {
	if c.decided {
		return
	}
	c.decided = true
	reserved := c.equalLocked() * (c.n - len(c.counts))
	shares := fairShare(c.roomLocked()-reserved, c.counts)
	for server := range c.counts {
		c.shares[server] <- shares[server]
	}
}

// primary reports the primary's sampled count.
func (c *usageCap) primary(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.primaryN < 0 {
		c.primaryN = n
	}
	if !c.decided && len(c.counts) == c.n {
		c.decideLocked()
	}
}

// worker reports server's count and returns its share; ok false when
// the sweep's budget ended first (timing, never the cap: the worker is
// then unreachable).
func (c *usageCap) worker(bctx context.Context, server string, n int) (int, bool) {
	c.mu.Lock()
	ch := c.shares[server]
	switch {
	case c.decided:
		// After the early point: the equal share at once.
		c.mu.Unlock()
		return min(n, c.equalOrRoom()), true
	default:
		c.counts[server] = n
		if c.primaryN >= 0 && len(c.counts) == c.n {
			c.decideLocked()
		}
		c.mu.Unlock()
	}
	select {
	case s := <-ch:
		return s, true
	case <-bctx.Done():
		return 0, false
	}
}

func (c *usageCap) equalOrRoom() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.equalLocked()
}

// fairShare splits room among counts (water-filling): every server gets
// an equal share, the room a server doesn't need goes to the others.
func fairShare(room int, counts map[string]int) map[string]int {
	out := map[string]int{}
	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if counts[ids[i]] != counts[ids[j]] {
			return counts[ids[i]] < counts[ids[j]]
		}
		return ids[i] < ids[j]
	})
	room = max(room, 0)
	for i, id := range ids {
		give := min(max(counts[id], 0), room/(len(ids)-i))
		out[id] = give
		room -= give
	}
	return out
}

// capGroups keeps in's whole apps in order while they fit share; an app
// that doesn't fit is cut whole (its containers in excess), never a
// subset with a wrong total.
func capGroups(in []usageUnit, share int) (kept []usageUnit, capped map[string]bool, excess int) {
	var order []string
	byGroup := map[string][]usageUnit{}
	for _, u := range in {
		if _, ok := byGroup[u.Group]; !ok {
			order = append(order, u.Group)
		}
		byGroup[u.Group] = append(byGroup[u.Group], u)
	}
	for _, g := range order {
		us := byGroup[g]
		if len(us) <= share {
			kept = append(kept, us...)
			share -= len(us)
			continue
		}
		if capped == nil {
			capped = map[string]bool{}
		}
		capped[g] = true
		excess += len(us)
	}
	return kept, capped, excess
}

// startWorkers runs every ready worker's sweep, one goroutine each:
// info (hourly), list (its apps only: never a helper or another
// project), host counters, its share of the cap, then its job states,
// inspects and stats; each call under timeout, within bctx. A worker
// whose previous goroutine still runs (a backend that ignored its
// deadline) is skipped: unreachable.
func (h *Hub) startWorkers(bctx context.Context, now time.Time, insts map[string]usageInst, timeout time.Duration, caps *usageCap) *usageWorkerBatch {
	s := h.usage
	ws := h.usageWorkerRTs()
	dl, _ := bctx.Deadline()
	b := &usageWorkerBatch{interim: make(chan *usageWorkerSweep, len(ws)), final: make(chan *usageWorkerSweep, len(ws)), expected: ws, deadline: dl.Add(usageWorkerGrace)}
	s.mu.RLock()
	lastPrimary := s.primaryN
	s.mu.RUnlock()
	caps.start(bctx, ws, lastPrimary, timeout)
	for _, e := range ws {
		s.busyMu.Lock()
		busy := s.busy[e.server]
		if !busy {
			s.busy[e.server] = true
		}
		s.busyMu.Unlock()
		if busy {
			sw := *e
			sw.appsWhy, sw.hostWhy = workerUnreachable(e.name), workerUnreachable(e.name)
			b.final <- &sw
			continue
		}
		go func(sw usageWorkerSweep) {
			out := &sw
			defer func() {
				s.busyMu.Lock()
				delete(s.busy, sw.server)
				s.busyMu.Unlock()
			}()
			defer func() { b.final <- out }()
			if !h.workerList(bctx, now, out, insts, timeout) {
				return
			}
			b.interim <- &usageWorkerSweep{server: sw.server, info: out.info, host: out.host, hostWhy: out.hostWhy}
			share, ok := caps.worker(bctx, sw.server, len(out.in))
			if !ok {
				// The budget ended before a share: timing, never the cap.
				out.appsWhy = workerUnreachable(sw.name)
				return
			}
			out.in, out.capped, out.excess = capGroups(out.in, share)
			out.jobHealth = h.usageJobHealth(bctx, sw.rt, sw.server, out.in, insts, timeout)
			out.jobs = s.usagePlan(sw.server, out.in, now)
			out.results, _ = usageSample(bctx, sw.rt, out.jobs, timeout)
			for _, r := range out.results {
				if errors.Is(r.err, agentrt.ErrOlderAgent) {
					// Not measured, nothing recorded (the view shows the
					// reason only).
					out.appsWhy = workerOlder(sw.name)
					return
				}
				if r.skipped {
					// The budget ran out mid-sample: unreachable, never
					// the previous sample shown as current.
					out.appsWhy = workerUnreachable(sw.name)
					out.capped, out.excess = nil, 0
					return
				}
			}
			out.applied = true
		}(*e)
	}
	return b
}

// workerList is a worker's list phase (false: it failed, the reasons set).
func (h *Hub) workerList(bctx context.Context, now time.Time, sw *usageWorkerSweep, insts map[string]usageInst, timeout time.Duration) bool {
	s := h.usage
	s.mu.RLock()
	w := s.workers[sw.server]
	needInfo := w == nil || w.infoAt.IsZero() || now.Sub(w.infoAt) >= usage.InfoEvery
	s.mu.RUnlock()
	if needInfo {
		ictx, cancel := context.WithTimeout(bctx, timeout)
		if i, err := sw.rt.Info(ictx); err == nil {
			sw.info = &i
		}
		cancel()
	}
	lctx, cancel := context.WithTimeout(bctx, timeout)
	units, err := sw.rt.List(lctx, runtime.Filter{})
	cancel()
	if err != nil {
		why := workerUnreachable(sw.name)
		if errors.Is(err, agentrt.ErrOlderAgent) {
			why = workerOlder(sw.name)
		}
		sw.appsWhy, sw.hostWhy = why, why
		return false
	}
	mine := map[string]usageInst{}
	for id, in := range insts {
		if in.Server == sw.server {
			mine[id] = in
		}
	}
	in, _ := usageScope(units, mine)
	for _, u := range in {
		if u.Kind == usageApp {
			sw.in = append(sw.in, u)
		}
	}
	hr, ok := sw.rt.(usageHostReader)
	if !ok {
		sw.hostWhy = workerOlder(sw.name)
		return true
	}
	hctx, cancel := context.WithTimeout(bctx, timeout)
	c, err := hr.HostUsage(hctx)
	cancel()
	switch {
	case errors.Is(err, agentrt.ErrOlderAgent):
		sw.hostWhy = workerOlder(sw.name)
	case err != nil:
		sw.hostWhy = workerHostUnread(sw.name)
	default:
		// The Hub's clock, never the worker's, times the rate.
		c.At = now
		sw.host = &c
	}
	return true
}

// joinWorkers waits for the workers (at most until their deadline) and
// records them: their containers, reasons, hosts, the apps of servers
// that aren't ready, and over_limit (primaryOver plus every worker's
// cut).
func (h *Hub) joinWorkers(b *usageWorkerBatch, now time.Time, insts map[string]usageInst, notReady map[string]string, primaryOver int) {
	done := b.wait()
	s := h.usage
	s.mu.Lock()
	defer s.mu.Unlock()
	over, workerOver := primaryOver, 0
	for _, w := range done {
		if w.applied {
			cpus := 0
			if w.info != nil {
				cpus = w.info.CPUs
			} else if cur := s.workers[w.server]; cur != nil {
				cpus = cur.cpus
			}
			s.applyLocked(w.server, now, w.in, w.jobs, w.results, insts, w.jobHealth, cpus)
		}
		if w.applied {
			workerOver += w.excess
		}
	}
	over += workerOver
	s.workerOver = workerOver
	s.noteWorkersLocked(done, now)
	s.notReady = notReady
	if s.verified {
		s.overLimit = over
	}
	s.axesLocked(now, insts)
}

// noteWorkersLocked records each worker's info, host point and reasons,
// and forgets the servers that are no longer ready (their containers,
// rings and host). Caller holds s.mu.
func (s *usageState) noteWorkersLocked(done []*usageWorkerSweep, now time.Time) {
	seen := map[string]bool{}
	for _, sw := range done {
		seen[sw.server] = true
		w := s.workers[sw.server]
		if w == nil {
			w = &usageWorker{hostRing: usage.NewHostRing(usage.RingSize)}
			s.workers[sw.server] = w
		}
		w.name = sw.name
		if sw.info != nil && sw.info.CPUs > 0 {
			w.cpus, w.mem, w.infoAt = sw.info.CPUs, sw.info.MemoryBytes, now
		}
		w.appsWhy, w.hostWhy, w.capped = sw.appsWhy, sw.hostWhy, sw.capped
		if sw.host == nil {
			if sw.hostWhy == workerHostUnread(sw.name) && !w.hostErr {
				log.Printf("usage: server %s: its host counters can't be read", sw.server)
				w.hostErr = true
			}
			w.hostRing.Add(usage.HostPoint{T: now})
			continue
		}
		w.hostErr = false
		smp := usage.DeriveHost(w.host, *sw.host, w.cpus)
		w.host = sw.host
		w.hostRing.Add(usage.HostPoint{T: now, S: smp})
	}
	for id := range s.workers {
		if !seen[id] {
			delete(s.workers, id)
		}
	}
	for k, c := range s.conts {
		if c.Server != "" && !seen[c.Server] {
			delete(s.conts, k)
		}
	}
}
