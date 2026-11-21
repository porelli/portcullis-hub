package hub

// Workers in the usage sampler (contract §11.11 "Workers", §17.4): every
// ready worker is swept in the same sweep through its agent — list,
// stats, host/usage — one goroutine per server, each under the same
// usage.Parallel limit and usage.StatsTimeout per call, all within the
// sweep's budget. A worker's answers are untrusted (the agent backend
// decodes them strictly and checks them); a worker that doesn't answer
// in time, or whose agent is older than the Hub, makes its apps and host
// "not measured" with the reason, never a guess, and never holds up the
// primary: the sweep waits for a worker at most until its deadline
// (the budget plus usageWorkerGrace) and drops a late answer.

import (
	"context"
	"errors"
	"log"
	"sort"
	"time"

	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/usage"
)

// usageWorkerGrace: how long after the sweep's budget a worker's answer
// is still awaited (a backend that ignores its context).
const usageWorkerGrace = 500 * time.Millisecond

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
	// of its apps and of its host figures.
	appsWhy, hostWhy string
}

// usageWorkerSweep is one worker's part of a sweep (never shared between
// goroutines: each is built by one, then handed over).
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
	// applied: the results are complete (the sample phase finished).
	applied bool
}

func workerOlder(name string) string {
	return "not measured: " + name + "'s agent is older than the Hub"
}
func workerUnreachable(name string) string {
	return "not measured: " + name + " is unreachable"
}

// usageWorkerBatch is one phase's goroutines: their answers arrive on ch;
// expected lists every server (so a missing answer is known by name).
type usageWorkerBatch struct {
	ch       chan *usageWorkerSweep
	expected []*usageWorkerSweep
	deadline time.Time
}

// wait collects every answer until the deadline; a server whose answer
// hasn't come is unreachable. The result is sorted by server id.
func (b *usageWorkerBatch) wait() []*usageWorkerSweep {
	got := map[string]*usageWorkerSweep{}
	timer := time.NewTimer(time.Until(b.deadline))
	defer timer.Stop()
collect:
	for len(got) < len(b.expected) {
		select {
		case sw := <-b.ch:
			got[sw.server] = sw
		case <-timer.C:
			break collect
		}
	}
	out := make([]*usageWorkerSweep, 0, len(b.expected))
	for _, e := range b.expected {
		if sw := got[e.server]; sw != nil {
			out = append(out, sw)
			continue
		}
		late := &usageWorkerSweep{server: e.server, name: e.name, rt: e.rt}
		late.appsWhy, late.hostWhy = workerUnreachable(e.name), workerUnreachable(e.name)
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

// usageHostReader is a worker backend's host route (agentrt.Backend).
type usageHostReader interface {
	HostUsage(ctx context.Context) (usage.HostCounters, error)
}

// startWorkerLists lists every ready worker's containers in scope (its
// apps' only: never another project, never a helper) and reads its info
// (hourly) and host counters, each call under timeout, within bctx.
func (h *Hub) startWorkerLists(bctx context.Context, now time.Time, insts map[string]usageInst, timeout time.Duration) *usageWorkerBatch {
	s := h.usage
	ws := h.usageWorkerRTs()
	dl, _ := bctx.Deadline()
	b := &usageWorkerBatch{ch: make(chan *usageWorkerSweep, len(ws)), expected: ws, deadline: dl.Add(usageWorkerGrace)}
	for _, e := range ws {
		go func(e usageWorkerSweep) {
			sw := &e
			defer func() { b.ch <- sw }()
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
				return
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
				return
			}
			hctx, cancel := context.WithTimeout(bctx, timeout)
			c, err := hr.HostUsage(hctx)
			cancel()
			switch {
			case errors.Is(err, agentrt.ErrOlderAgent):
				sw.hostWhy = workerOlder(sw.name)
			case err != nil:
				// Not measured this sweep (the rate's base is kept).
			default:
				// The Hub's clock, never the worker's, times the rate.
				c.At = now
				sw.host = &c
			}
		}(*e)
	}
	return b
}

// startWorkerSamples samples every listed worker's containers (its job
// states, inspects and stats), one goroutine per server, within bctx;
// a worker whose stats answer ErrOlderAgent is "older than the Hub". A
// worker that already failed its listing passes through.
func (h *Hub) startWorkerSamples(bctx context.Context, now time.Time, listed []*usageWorkerSweep, insts map[string]usageInst, timeout time.Duration, deadline time.Time) *usageWorkerBatch {
	s := h.usage
	b := &usageWorkerBatch{ch: make(chan *usageWorkerSweep, len(listed)), expected: listed, deadline: deadline}
	for _, sw := range listed {
		if sw.appsWhy != "" {
			b.ch <- sw
			continue
		}
		go func(sw usageWorkerSweep) {
			out := &sw
			defer func() { b.ch <- out }()
			out.jobHealth = h.usageJobHealth(bctx, sw.rt, sw.server, sw.in, insts, timeout)
			out.jobs = s.usagePlan(sw.server, sw.in, now)
			out.results, _ = usageSample(bctx, sw.rt, out.jobs, timeout)
			for _, r := range out.results {
				if errors.Is(r.err, agentrt.ErrOlderAgent) {
					// Not measured, nothing recorded (its containers keep
					// their state; the view shows the reason only).
					out.appsWhy = workerOlder(sw.name)
					return
				}
			}
			out.applied = true
		}(*sw)
	}
	return b
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
		w.appsWhy, w.hostWhy = sw.appsWhy, sw.hostWhy
		if sw.host == nil {
			if sw.hostWhy == "" && !w.hostErr {
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
