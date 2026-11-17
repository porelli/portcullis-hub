package hub

import (
	"context"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The servers loop (contract §17.3): every tick it renews the control
// certificate, advances revocations, polls GET /v1/info of every ready or
// offline server (offline after 3 misses or a handshake older than 3
// min; on return a reconcile and the doctor), and renews worker
// certificates at ⅓ remaining life.

// workerKickEvery: the shortest interval between reconciles one worker's
// events trigger.
var workerKickEvery = 10 * time.Second

// newKicker calls fn at most once per every; a call inside the interval
// arms one trailing call at its end (none is lost), until ctx ends.
func newKicker(ctx context.Context, every time.Duration, fn func()) func() {
	var (
		mu      sync.Mutex
		last    time.Time
		pending bool
	)
	return func() {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()
		if now.Sub(last) >= every {
			last = now
			fn()
			return
		}
		if pending {
			return
		}
		pending = true
		time.AfterFunc(last.Add(every).Sub(now), func() {
			mu.Lock()
			pending, last = false, time.Now()
			mu.Unlock()
			if ctx.Err() == nil {
				fn()
			}
		})
	}
}

// pollState is one server's poll memory.
type pollState struct {
	misses int
	reason string         // why it is offline ("" = none known)
	info   *agentapi.Info // the last /v1/info
	// renewing: a renewal is switching the worker's certificate (an
	// identity mismatch meanwhile isn't one).
	renewing bool
	stop     context.CancelFunc // the event stream
	watched  runtime.Instances  // the runtime it reads
}

func (h *Hub) pollOf(id string) *pollState {
	if h.polls == nil {
		h.polls = map[string]*pollState{}
	}
	ps := h.polls[id]
	if ps == nil {
		ps = &pollState{}
		h.polls[id] = ps
	}
	return ps
}

// notePoll records a good poll (info) or a reason.
func (h *Hub) notePoll(id string, info *agentapi.Info, reason string) {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	ps := h.pollOf(id)
	if info != nil {
		i := *info
		i = sanitizeInfo(i)
		ps.info, ps.misses = &i, 0
	}
	ps.reason = untrusted(reason, 300) // the agent's words may be in it (L4)
}

// RunServers runs the servers loop every `every` (30 s) until ctx ends.
// At start it rewrites link.json from state (it isn't backed up) and
// settles enrolments a Hub restart interrupted.
func (h *Hub) RunServers(ctx context.Context, every time.Duration) {
	if h.kubeOn() || h.cfg.LinkDocDir == "" {
		// Moves a restart interrupted settle all the same (between the
		// primary's own instances, none: nothing to do).
		if h.waitEngine() {
			h.RecoverMoves()
		}
		return
	}
	h.startServers(ctx)
	// Review Focus 2: with the servers' backends in place, after the
	// engine guard.
	if h.waitEngine() {
		h.RecoverMoves()
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		h.serversTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// startServers: link.json rewritten; an enrolment without its secret (a
// Hub restart) ends as a Stop at its step would — before the handshake
// the server goes, from it on it is revoked; every pinned server gets
// its backend.
func (h *Hub) startServers(ctx context.Context) {
	var revoke []string
	h.mu.Lock()
	for id, s := range h.st.Servers {
		if s.State != ServerEnrolling || h.enrolOf(id) != nil {
			continue
		}
		if s.Enrol == nil || (!s.Enrol.Used && (s.Enrol.Step == "" || s.Enrol.Step == StepJoin)) {
			delete(h.st.Servers, id)
			h.setServer(id, nil)
			log.Printf("servers: the enrolment of %s was interrupted by a Hub stop before the worker joined: removed", id)
			continue
		}
		h.beginRevokeLocked(id, false)
		revoke = append(revoke, id)
		log.Printf("servers: the enrolment of %s was interrupted by a Hub stop: revoked", id)
	}
	if err := h.publishLinkLocked(); err != nil {
		log.Printf("servers: link.json at start: %v", err)
	}
	h.saveLocked()
	all := map[string]state.Server{}
	for id, s := range h.st.Servers {
		all[id] = s
	}
	h.mu.Unlock()
	for _, id := range revoke {
		h.auditOp(directory.Actor{}, "server.enrol_refused", id, "", statusErr(409, "the Hub restarted during the enrolment"))
		h.advanceRevoke(ctx, id)
	}
	for id, s := range all {
		switch s.State {
		case ServerReady, ServerOffline:
			b, err := h.serverBackend(ctx, id, s, "")
			if err != nil {
				log.Printf("servers: %s has no backend yet: %v", id, err)
				h.setServer(id, &serverRT{Name: s.Name, State: ServerOffline})
				continue
			}
			if h.setLive(id, b, s.State) && s.State == ServerReady {
				h.watchServer(id, b)
			}
		case ServerRevoked:
			h.setServer(id, &serverRT{Name: s.Name, State: ServerRevoked})
		}
	}
}

// serversTick is one pass of the loop.
func (h *Hub) serversTick(ctx context.Context) {
	if cert, _, err := h.controlCert(ctx); err == nil && cert.Leaf != nil {
		serial := cert.Leaf.SerialNumber.String()
		h.srvMu.Lock()
		changed := h.ctlSerial != "" && h.ctlSerial != serial
		h.ctlSerial = serial
		h.srvMu.Unlock()
		if changed {
			h.rebuildBackends(ctx)
		}
	} else if err != nil && h.nodeSigner() != nil {
		log.Printf("servers: the control certificate: %v", err)
	}
	// Serials owed (signed and never pinned, or of revoked servers),
	// whether or not their server still exists.
	h.drainOwed(ctx, "")
	h.mu.RLock()
	var ids []string
	revoking := map[string]bool{}
	for id, s := range h.st.Servers {
		ids = append(ids, id)
		revoking[id] = s.Revoke != nil
	}
	h.mu.RUnlock()
	sort.Strings(ids)
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		if revoking[id] {
			h.advanceRevoke(ctx, id)
			continue
		}
		h.pollServer(ctx, id)
	}
	// Worker bundles still owed a removal (R3-L10).
	h.drainOwedBundles(ctx)
	// Stuck moves (a rollback that couldn't take the target down) are
	// retried each tick (review B2-M2).
	h.mu.RLock()
	stuck := len(h.stuckMovesLocked()) > 0
	h.mu.RUnlock()
	if stuck {
		h.RecoverMoves()
	}
}

// rebuildBackends gives every pinned server a backend with the current
// control certificate.
func (h *Hub) rebuildBackends(ctx context.Context) {
	h.mu.RLock()
	all := map[string]state.Server{}
	for id, s := range h.st.Servers {
		if s.State == ServerReady || s.State == ServerOffline {
			all[id] = s
		}
	}
	h.mu.RUnlock()
	for id, s := range all {
		h.srvMu.Lock()
		kind := runtime.Kind("")
		if ps := h.polls[id]; ps != nil && ps.info != nil {
			kind = runtime.Kind(ps.info.Runtime)
		}
		h.srvMu.Unlock()
		if b, err := h.serverBackend(ctx, id, s, kind); err == nil {
			if h.setLive(id, b, s.State) && s.State == ServerReady {
				h.watchServer(id, b)
			}
		}
	}
}

// pollServer polls one ready or offline server.
func (h *Hub) pollServer(ctx context.Context, id string) {
	h.mu.RLock()
	s, ok := h.st.Servers[id]
	h.mu.RUnlock()
	if !ok || (s.State != ServerReady && s.State != ServerOffline) {
		return
	}
	b, ok := h.backendOf(id)
	if !ok {
		nb, err := h.serverBackend(ctx, id, s, "")
		if err != nil {
			h.pollMiss(id, "no backend: "+err.Error())
			return
		}
		b = nb
		if !h.setLive(id, b, s.State) {
			return
		}
	}
	c, cancel := context.WithTimeout(ctx, orDur(h.srvT.callWait, 15*time.Second))
	info, err := b.AgentInfo(c)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		h.pollMiss(id, clipRunes(err.Error(), 200))
		return
	}
	// The kind may have changed (the first poll after a start).
	if b.Kind() != runtime.Kind(info.Runtime) && (info.Runtime == string(runtime.KindDocker) || info.Runtime == string(runtime.KindPodman)) {
		if nb, err := h.serverBackend(ctx, id, s, runtime.Kind(info.Runtime)); err == nil {
			b = nb
		}
	}
	// Fail closed (review B-L7): an unreadable link status is offline
	// too — no routing to a worker whose tunnel nobody can vouch for.
	why := ""
	if hs := h.linkHandshakes(); hs == nil {
		why = "link's status is unreadable"
	} else if at, ok := hs[id]; !ok || h.now().Sub(at) > handshakeMaxAge {
		why = "no handshake for 3 minutes"
	}
	if why != "" {
		h.notePoll(id, &info, why)
		h.setOffline(id, why)
		return
	}
	h.notePoll(id, &info, "")
	h.mu.Lock()
	s, ok = h.st.Servers[id]
	if !ok || s.Revoke != nil {
		h.mu.Unlock()
		return
	}
	back := s.State == ServerOffline
	s.State, s.LastContact, s.AgentVersion = ServerReady, h.now().UTC(), info.AgentVersion
	h.st.Servers[id] = s
	h.saveLocked()
	h.mu.Unlock()
	if !h.setLive(id, b, ServerReady) {
		return
	}
	h.watchServer(id, b)
	if back {
		log.Printf("servers: %s is back", id)
		h.TriggerReconcile()
		go func() {
			dctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if _, err := h.Doctor(dctx); err != nil {
				log.Printf("servers: the doctor after %s's return: %v", id, err)
			}
		}()
	}
	if s.CertNotAfter.Sub(h.now()) < nodeCertLife/3 {
		if err := h.renewServer(ctx, id, b); err != nil {
			log.Printf("servers: renewing %s's certificate: %v (retried at the next tick)", id, err)
		}
	}
}

// pollMiss counts a missed poll: the third makes the server offline.
func (h *Hub) pollMiss(id, why string) {
	h.srvMu.Lock()
	ps := h.pollOf(id)
	ps.misses++
	n := ps.misses
	h.srvMu.Unlock()
	if n >= pollMisses {
		h.setOffline(id, why)
	}
}

// setOffline marks a ready server offline (why kept for the view).
func (h *Hub) setOffline(id, why string) {
	h.srvMu.Lock()
	h.pollOf(id).reason = why
	h.srvMu.Unlock()
	h.mu.Lock()
	s, ok := h.st.Servers[id]
	if !ok || s.State != ServerReady {
		h.mu.Unlock()
		return
	}
	s.State = ServerOffline
	h.st.Servers[id] = s
	h.saveLocked()
	h.mu.Unlock()
	r := h.reg()
	r.mu.Lock()
	if rs := r.servers[id]; rs != nil && rs.State == ServerReady {
		rs.State = ServerOffline
	}
	r.mu.Unlock()
	h.stopWatch(id)
	log.Printf("servers: %s is offline: %s", id, why)
}

// identityMismatch: the worker presented another certificate than the
// pinned one (server_identity_mismatch): offline at once.
func (h *Hub) identityMismatch(id string) {
	h.srvMu.Lock()
	renewing := h.polls[id] != nil && h.polls[id].renewing
	h.srvMu.Unlock()
	if renewing {
		return
	}
	go h.setOffline(id, "server_identity_mismatch: the worker presented another certificate than the one pinned")
}

// renewServer renews a worker's certificate: POST /v1/identity/csr (a
// new key) → enroll signs → PUT /v1/identity/cert → the new SPKI and
// serial pinned (server.renewed).
func (h *Hub) renewServer(ctx context.Context, id string, b *agentrt.Backend) error {
	c, cancel := context.WithTimeout(ctx, orDur(h.srvT.callWait, 15*time.Second))
	csr, err := b.IdentityCSR(c)
	cancel()
	if err != nil {
		return err
	}
	leaf, nc, err := h.signWorker(ctx, id, csr.CSR, liveOK)
	if err != nil {
		return err
	}
	defer h.endInflight(nc.Serial)
	h.srvMu.Lock()
	h.pollOf(id).renewing = true
	h.srvMu.Unlock()
	defer func() {
		h.srvMu.Lock()
		h.pollOf(id).renewing = false
		h.srvMu.Unlock()
	}()
	c, cancel = context.WithTimeout(ctx, orDur(h.srvT.callWait, 15*time.Second))
	err = b.PutIdentityCert(c, agentapi.IdentityCert{Certificate: nc.Certificate, CA: nc.CA})
	cancel()
	if err != nil {
		return err
	}
	if err := h.pinServer(ctx, id, leaf, nc.Serial, liveOK); err != nil {
		return err
	}
	h.mu.RLock()
	s := h.st.Servers[id]
	h.mu.RUnlock()
	nb, err := h.serverBackend(ctx, id, s, b.Kind())
	if err != nil {
		return err
	}
	if !h.setLive(id, nb, s.State) {
		return statusErr(409, "server %s was revoked during the renewal", id)
	}
	if s.State == ServerReady {
		h.watchServer(id, nb)
	}
	h.auditOp(directory.Actor{}, "server.renewed", id, "until "+leaf.NotAfter.UTC().Format(time.RFC3339), nil)
	return nil
}

// watchServer (re)starts a ready server's engine event stream: an
// instance container's event triggers a reconcile, as the primary's.
func (h *Hub) watchServer(id string, rt runtime.Instances) {
	// Only for a server still ready in the registry (review A2-L1: a
	// revocation between its registration and here wins).
	r := h.reg()
	r.mu.RLock()
	cur := r.servers[id]
	r.mu.RUnlock()
	if cur == nil || cur.State != ServerReady {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.srvMu.Lock()
	ps := h.pollOf(id)
	if ps.stop != nil && ps.watched == rt {
		h.srvMu.Unlock()
		cancel()
		return
	}
	if ps.stop != nil {
		ps.stop()
	}
	ps.stop, ps.watched = cancel, rt
	h.srvMu.Unlock()
	go func() {
		backoff := time.Second
		// A worker's events kick a reconcile at most every 10 s (review
		// B-L6: a worker can't keep the reconciler busy); a throttled one
		// arms a single trailing kick (review A2-L4: none is lost).
		kick := newKicker(ctx, workerKickEvery, h.TriggerReconcile)

		for ctx.Err() == nil {
			err := rt.Events(ctx, runtime.Filter{All: true}, func(ev runtime.Event) {
				if strings.HasPrefix(ev.Actor.Attributes[docker.LabelProject], ProjectPrefix) {
					switch ev.Action {
					case "start", "die", "stop", "kill", "destroy", "create", "pause", "unpause", "restart", "oom":
						kick()
					}
				}
			})
			if ctx.Err() != nil {
				return
			}
			log.Printf("servers: %s's event stream ended (%v); retrying in %s", id, err, backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			if backoff < time.Minute {
				backoff *= 2
			}
		}
	}()
}

// stopWatch ends a server's event stream.
func (h *Hub) stopWatch(id string) {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	if ps := h.polls[id]; ps != nil && ps.stop != nil {
		ps.stop()
		ps.stop, ps.watched = nil, nil
	}
}

// sanitizeInfo makes a worker's /v1/info text fields safe to show, log
// and hand an AI client (final review L4): its arch, versions, data dir,
// quarantine reasons and error text one clipped line each, with no
// control or bidi characters. Bind roots aren't rewritten (they are
// paths the checks compare): one carrying a control character is dropped.
func sanitizeInfo(i agentapi.Info) agentapi.Info {
	i.Arch, i.AgentVersion, i.EngineVersion = untrusted(i.Arch, 20), untrusted(i.AgentVersion, 40), untrusted(i.EngineVersion, 40)
	i.QuarantineError, i.OwnProject = untrusted(i.QuarantineError, 300), untrusted(i.OwnProject, 80)
	if len(i.Quarantined) > 0 {
		q := make(map[string]string, len(i.Quarantined))
		for k, v := range i.Quarantined {
			q[untrusted(k, 64)] = untrusted(v, 300)
		}
		i.Quarantined = q
	}
	roots := i.BindRoots[:0:0]
	for _, r := range i.BindRoots {
		if !templates.HasControlChars(r) {
			roots = append(roots, r)
		}
	}
	i.BindRoots = roots
	return i
}
