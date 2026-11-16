package hub

import (
	"context"
	"maps"

	"errors"
	"fmt"
	"github.com/portcullis/hub/internal/doctor"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
)

// Revocation and removal (contract §17.6). The server is revoked from
// step 1 on; each step is retried at the next tick until it succeeds, in
// this order:
//  1. the peer and its relays out of link.json (link drops the tunnel);
//  2. the certificate serial revoked through enroll;
//  3. unpinned;
//  4. the instances' relays down (on the primary);
//  5. what the worker held rotated: each placed instance's Keycloak
//     client secrets and its relay token.
//
// Steps 2–5 run only once step 1 has: nothing else happens while link
// still carries the peer.

// RevokeServer revokes server id now (works on an offline server).
func (h *Hub) RevokeServer(ctx context.Context, actor directory.Actor, id string) (err error) {
	defer func() { h.auditOp(actor, "server.revoked", id, "", err) }()
	if actor.User == "" {
		return statusErr(401, "no acting user")
	}
	if servers.ValidID(id) != nil {
		return statusErr(400, "invalid server id")
	}
	h.mu.Lock()
	s, ok := h.st.Servers[id]
	switch {
	case !ok:
		h.mu.Unlock()
		return statusErr(404, "server %s not found", id)
	case s.State == ServerRevoked:
		h.mu.Unlock()
		return statusErr(409, "server %s is already revoked", id)
	}
	h.beginRevokeLocked(id, false)
	h.mu.Unlock()
	h.stopEnrol(id)
	h.advanceRevoke(ctx, id)
	return nil
}

// RemoveServer removes server id (409 while instances remain): POST
// /v1/leave (best effort: a worker that can't be reached is revoked all
// the same), then the revocation; the entry goes once every step is done.
func (h *Hub) RemoveServer(ctx context.Context, actor directory.Actor, id string) (err error) {
	defer func() { h.auditOp(actor, "server.removed", id, "", err) }()
	if actor.User == "" {
		return statusErr(401, "no acting user")
	}
	if servers.ValidID(id) != nil {
		return statusErr(400, "invalid server id")
	}
	// Marked removing under mu with the check (B-L2): no placement lands
	// on it from here on; checked again before the revocation.
	h.mu.Lock()
	s, ok := h.st.Servers[id]
	placed := h.placedLocked(id)
	if ok && len(placed) == 0 {
		if h.removing == nil {
			h.removing = map[string]bool{}
		}
		h.removing[id] = true
	}
	h.mu.Unlock()
	if !ok {
		return statusErr(404, "server %s not found", id)
	}
	if len(placed) > 0 {
		return statusErr(409, "server %s still has %d instance(s): move, restore or forget them first", s.Name, len(placed))
	}
	defer func() {
		h.mu.Lock()
		delete(h.removing, id)
		h.mu.Unlock()
	}()
	if s.State == ServerReady || s.State == ServerOffline {
		if b, ok := h.backendOf(id); ok {
			c, cancel := context.WithTimeout(ctx, orDur(h.srvT.callWait, 15*time.Second))
			if lerr := b.Leave(c); lerr != nil {
				log.Printf("servers: %s didn't take the leave (%v): revoking it all the same", id, lerr)
			}
			cancel()
		}
	}
	h.mu.Lock()
	if placed := h.placedLocked(id); len(placed) > 0 {
		h.mu.Unlock()
		return statusErr(409, "server %s still has %d instance(s): move, restore or forget them first", s.Name, len(placed))
	}
	h.beginRevokeLocked(id, true)
	h.mu.Unlock()
	h.stopEnrol(id)
	h.advanceRevoke(ctx, id)
	return nil
}

// backendOf is a server's agent backend (any state).
func (h *Hub) backendOf(id string) (*agentrt.Backend, bool) {
	r := h.reg()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s := r.servers[id]; s != nil {
		b, ok := s.RT.(*agentrt.Backend)
		return b, ok && b != nil
	}
	return nil, false
}

// beginRevokeLocked marks server id revoked (its instances orphaned, its
// address quarantined) and records the steps to do. remove: the entry
// goes once they are. Caller holds mu (write).
func (h *Hub) beginRevokeLocked(id string, remove bool) {
	s, ok := h.st.Servers[id]
	if !ok {
		return
	}
	now := h.now().UTC()
	if s.Revoke == nil {
		s.Revoke = &state.RevokeSteps{At: now}
	}
	if s.CertSerial != "" {
		h.oweSerialLocked(id, s.CertSerial)
	}
	s.Revoke.Remove = s.Revoke.Remove || remove
	s.State, s.Enrol = ServerRevoked, nil
	if s.QuarantinedUntil.IsZero() {
		s.QuarantinedUntil = now.Add(servers.Quarantine)
	}
	h.st.Servers[id] = s
	for _, iid := range h.placedLocked(id) {
		in := h.st.Instances[iid]
		in.State = state.InstanceOrphaned
		h.st.Instances[iid] = in
	}
	// Step 1 at once, under the same lock (B-L1): the peer is out of
	// link.json before anything waits (advanceRevoke retries a failure).
	if err := h.publishLinkLocked(); err != nil {
		log.Printf("servers: revoking %s: link.json: %v (retried)", id, err)
	}
	h.saveLocked()
	h.setServer(id, &serverRT{Name: s.Name, State: ServerRevoked})
	h.stopWatch(id)
}

// placeableLocked: server can take a new instance (not revoked, not being
// revoked or removed). Caller holds mu.
func (h *Hub) placeableLocked(server string) error {
	s, ok := h.st.Servers[server]
	switch {
	case !ok:
		return statusErr(409, "server %s is unknown", server)
	case s.Revoke != nil || s.State == ServerRevoked:
		return statusErr(409, "server %s is revoked", nameOr(s.Name, server))
	case h.removing[server]:
		return statusErr(409, "server %s is being removed", nameOr(s.Name, server))
	}
	return nil
}

func nameOr(name, id string) string {
	if name == "" {
		return id
	}
	return name
}

// advanceRevoke runs the revocation steps still owed (none = nothing),
// one pass per server at a time.
func (h *Hub) advanceRevoke(ctx context.Context, id string) {
	m, _ := h.revokeLocks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	h.mu.Lock()
	s, ok := h.st.Servers[id]
	if !ok || s.Revoke == nil {
		h.mu.Unlock()
		return
	}
	// 1. link.json (the peer is left out from Revoke on).
	if err := h.publishLinkLocked(); err != nil {
		h.mu.Unlock()
		log.Printf("servers: revoking %s: link.json: %v (retried at the next tick)", id, err)
		return
	}
	rv := *s.Revoke
	placed := h.placedLocked(id)
	// 3. unpin (the serials stay listed for step 2).
	s.CertSerial, s.SPKI = "", ""
	h.st.Servers[id] = s
	h.mu.Unlock()

	// 2. every serial owed for it (the tick drains the rest too).
	h.drainOwed(ctx, id)
	// 4. the relays (their primary projects).
	if !rv.RelaysDone && h.rt != nil {
		var errs []error
		for _, iid := range placed {
			if err := h.rt.DownByName(ctx, projectName(iid)); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", iid, err))
			}
		}
		if err := errors.Join(errs...); err != nil {
			log.Printf("servers: revoking %s: relays down: %v (retried at the next tick)", id, err)
		} else {
			rv.RelaysDone = true
		}
	} else if h.rt == nil {
		rv.RelaysDone = true
	}
	// 5. rotation.
	if !rv.Rotated {
		var errs []error
		for _, iid := range placed {
			if err := h.rotateInstanceSecrets(ctx, iid); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", iid, err))
			}
		}
		if err := errors.Join(errs...); err != nil {
			log.Printf("servers: revoking %s: rotation: %v (retried at the next tick)", id, err)
			h.noteRotation(id, clipRunes(err.Error(), 300))
		} else {
			rv.Rotated = true
			h.noteRotation(id, "")
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok = h.st.Servers[id]
	if !ok || s.Revoke == nil {
		return
	}
	cur := *s.Revoke
	cur.RelaysDone, cur.Rotated = cur.RelaysDone || rv.RelaysDone, cur.Rotated || rv.Rotated
	s.Revoke = &cur
	h.st.Servers[id] = s
	// The entry may go with serials still owed: OwedSerials outlives it.
	if cur.Remove && cur.RelaysDone && cur.Rotated && len(h.placedLocked(id)) == 0 {
		if h.st.Quarantined == nil {
			h.st.Quarantined = map[string]time.Time{}
		}
		h.st.Quarantined[s.TunnelIP] = s.QuarantinedUntil
		delete(h.st.Servers, id)
		h.setServer(id, nil)
		h.srvMu.Lock()
		delete(h.polls, id)
		h.srvMu.Unlock()
	}
	for ip, until := range h.st.Quarantined {
		if h.now().After(until) {
			delete(h.st.Quarantined, ip)
		}
	}
	h.saveLocked()
}

// revokeSerial revokes one node certificate serial through enroll.
func (h *Hub) revokeSerial(ctx context.Context, serial string) error {
	signer := h.nodeSigner()
	if signer == nil {
		return errors.New("enroll isn't configured")
	}
	return signer.RevokeNode(ctx, serial)
}

// oweSerialLocked records serial (of server id) as owed and saves
// state; the error is the save's. Caller holds mu (write).
func (h *Hub) oweSerialLocked(id, serial string) error {
	for _, o := range h.st.OwedSerials {
		if o.Serial == serial {
			return nil
		}
	}
	h.st.OwedSerials = append(h.st.OwedSerials, state.OwedSerial{Server: id, Serial: serial, Since: h.now().UTC()})
	if h.srvT.oweSaveErr != nil {
		if err := h.srvT.oweSaveErr(serial); err != nil {
			return err
		}
	}
	return h.st.Save(h.statePath())
}

// settleSerialLocked drops serial from the owed list (pinned, or
// revoked on pki_node). Caller holds mu (write).
func (h *Hub) settleSerialLocked(serial string) {
	n := len(h.st.OwedSerials)
	h.st.OwedSerials = slices.DeleteFunc(h.st.OwedSerials, func(o state.OwedSerial) bool { return o.Serial == serial })
	if len(h.st.OwedSerials) != n {
		h.saveLocked()
	}
}

// drainOwed revokes the owed serials (only server's; "" = all, whether
// or not their server still exists). Each one revoked leaves the list; a
// failure keeps it for the next tick. Core's revoke is idempotent.
func (h *Hub) drainOwed(ctx context.Context, server string) {
	h.mu.RLock()
	var owed []state.OwedSerial
	for _, o := range h.st.OwedSerials {
		// One whose sign → send → pin op still runs is that op's.
		if (server == "" || o.Server == server) && !h.inflight[o.Serial] {
			owed = append(owed, o)
		}
	}
	h.mu.RUnlock()
	for _, o := range owed {
		if err := h.revokeSerial(ctx, o.Serial); err != nil {
			log.Printf("servers: revoking a certificate of %s: %v (retried at the next tick)", o.Server, err)
			continue
		}
		h.mu.Lock()
		h.settleSerialLocked(o.Serial)
		h.mu.Unlock()
	}
}

// discardSerial: a certificate signed for server id that must never be
// used (the server was revoked, removed or left the state it was signed
// for) is revoked at once; it was owed since it was signed, so a failure
// leaves it to the next tick.
func (h *Hub) discardSerial(ctx context.Context, id, serial string) {
	// Even when the op that signed it was cancelled (a revocation).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := h.revokeSerial(ctx, serial); err != nil {
		log.Printf("servers: revoking %s's unused certificate: %v (retried at the next tick)", id, err)
		h.mu.Lock()
		h.oweSerialLocked(id, serial)
		h.mu.Unlock()
		return
	}
	h.mu.Lock()
	h.settleSerialLocked(serial)
	h.mu.Unlock()
}

// clientLister lists the clients tagged with an owner (keycloak.Client).
type clientLister interface {
	ClientIDsOwnedBy(ctx context.Context, owner string) ([]string, error)
}

// rotateWithoutTemplate (review B-M3): an instance whose template no
// longer resolves can't have its clients re-registered, so they are
// deleted — the ids recorded on the instance, else every client tagged
// with its id — and its relay token is replaced. A restore elsewhere
// registers them again.
func (h *Hub) rotateWithoutTemplate(ctx context.Context, id string, recorded []string) error {
	if h.idp == nil {
		return errors.New("Keycloak isn't configured")
	}
	ids := recorded
	if len(ids) == 0 {
		l, ok := h.idp.(clientLister)
		if !ok {
			return fmt.Errorf("instance %s: its template doesn't resolve and its Keycloak clients aren't recorded", id)
		}
		var err error
		if ids, err = l.ClientIDsOwnedBy(ctx, id); err != nil {
			return fmt.Errorf("listing %s's Keycloak clients: %w", id, err)
		}
	}
	for _, cid := range ids {
		if err := h.idp.DeleteClient(ctx, cid, id); err != nil {
			return fmt.Errorf("Keycloak: deleting client %s of %s: %w", cid, id, err)
		}
	}
	return h.newRelayToken(id)
}

// rotateInstanceSecrets gives instance id new Keycloak client secrets (a
// new random value in its .env, registered with Keycloak) and a new relay
// token: nothing the revoked worker held stays valid. An ai_client is
// deleted (every session of it, offline ones included, goes with it) and
// created again with its new secret. Any failure: retried next tick.
func (h *Hub) rotateInstanceSecrets(ctx context.Context, id string) error {
	h.mu.Lock()
	v := h.findLocked(id)
	if v == nil {
		recorded := append([]string{}, h.st.Instances[id].KeycloakClients...)
		h.mu.Unlock()
		return h.rotateWithoutTemplate(ctx, id, recorded)
	}
	tmpl := *v
	env := readEnvRaw(h.envPath(id))
	var specs []keycloak.ClientSpec
	var aiClients []string
	for _, c := range tmpl.Manifest.Clients {
		if c.SecretEnv == "" {
			continue
		}
		sec, err := randomSecret()
		if err != nil {
			h.mu.Unlock()
			return err
		}
		env[c.SecretEnv] = sec
	}
	if err := writeEnvMap(h.envPath(id), env); err != nil {
		h.mu.Unlock()
		return err
	}
	for _, c := range tmpl.Manifest.Clients {
		switch {
		case c.AIClient:
			aiClients = append(aiClients, c.ClientID)
		case c.SecretEnv != "":
			specs = append(specs, h.clientSpec(&tmpl, c))
		}
	}
	h.mu.Unlock()
	if h.idp != nil {
		for _, sp := range specs {
			if _, err := h.idp.RegisterClient(ctx, sp); err != nil {
				return err
			}
		}
	} else if len(specs) > 0 {
		return errors.New("Keycloak isn't configured")
	}
	if len(aiClients) > 0 {
		kc := h.aiKeycloak()
		if kc == nil {
			return errors.New("Keycloak: the AI client calls are not configured")
		}
		for _, cid := range aiClients {
			h.aiKCMu.Lock()
			err := kc.DeleteAIClient(ctx, cid, tmpl.ID)
			h.aiKCMu.Unlock()
			if err != nil {
				return fmt.Errorf("Keycloak: deleting AI client %s: %w", cid, err)
			}
		}
		if _, err := h.ensureInstanceAIClient(ctx, &tmpl); err != nil {
			return err
		}
	}
	return h.newRelayToken(id)
}

// noteRotation records why server id's step 5 failed ("" = it didn't):
// the doctor's server_secrets_not_rotated.
func (h *Hub) noteRotation(id, why string) {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	if why == "" {
		delete(h.rotateFail, id)
		return
	}
	if h.rotateFail == nil {
		h.rotateFail = map[string]string{}
	}
	h.rotateFail[id] = why
}

// serversDoctorIn is the doctor's servers input.
func (h *Hub) serversDoctorIn() *doctor.ServersIn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.serversDoctorInLocked()
}

// serversDoctorInLocked is serversDoctorIn; caller holds mu (read):
// doctorInputs does, and a second RLock could deadlock with a writer.
func (h *Hub) serversDoctorInLocked() *doctor.ServersIn {
	stuck := map[string]string{}
	for id, to := range h.stuckMovesLocked() {
		stuck[id] = serverLabel(to)
	}
	placed := map[string]string{}
	for id, in := range h.st.Instances {
		if in.Server != "" {
			placed[id] = in.Server
		}
	}
	h.srvMu.Lock()
	in := &doctor.ServersIn{NotRotated: maps.Clone(h.rotateFail), PlacementInvalid: maps.Clone(h.placementInvalid), Stuck: stuck,
		Quarantined: map[string]string{}}
	for id, server := range placed {
		if ps := h.polls[server]; ps != nil && ps.info != nil {
			if why := ps.info.Quarantined[id]; why != "" {
				in.Quarantined[id] = server + ": " + why
			}
		}
	}
	h.srvMu.Unlock()
	if len(in.NotRotated)+len(in.PlacementInvalid)+len(in.Stuck)+len(in.Quarantined) == 0 {
		return nil
	}
	return in
}
