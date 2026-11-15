package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
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
	h.dropEnrol(id)
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
	h.mu.RLock()
	s, ok := h.st.Servers[id]
	placed := h.placedLocked(id)
	h.mu.RUnlock()
	if !ok {
		return statusErr(404, "server %s not found", id)
	}
	if len(placed) > 0 {
		return statusErr(409, "server %s still has %d instance(s): move, restore or forget them first", s.Name, len(placed))
	}
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
	h.beginRevokeLocked(id, true)
	h.mu.Unlock()
	h.dropEnrol(id)
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
		s.Revoke = &state.RevokeSteps{At: now, Serial: s.CertSerial}
	} else if s.CertSerial != "" && s.Revoke.Serial == "" {
		s.Revoke.Serial = s.CertSerial
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
	h.saveLocked()
	h.setServer(id, &serverRT{Name: s.Name, State: ServerRevoked})
	h.stopWatch(id)
}

// advanceRevoke runs the revocation steps still owed (none = nothing).
func (h *Hub) advanceRevoke(ctx context.Context, id string) {
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
	h.mu.Unlock()

	// 2. the certificate.
	if !rv.CertDone {
		if rv.Serial == "" {
			rv.CertDone = true
		} else if signer := h.nodeSigner(); signer == nil {
			log.Printf("servers: revoking %s: enroll isn't configured (retried at the next tick)", id)
		} else if err := signer.RevokeNode(ctx, rv.Serial); err != nil {
			log.Printf("servers: revoking %s's certificate: %v (retried at the next tick)", id, err)
		} else {
			rv.CertDone = true
		}
	}
	// 3. unpin (Revoke keeps the serial for step 2).
	h.mu.Lock()
	if s, ok := h.st.Servers[id]; ok {
		s.CertSerial, s.SPKI = "", ""
		h.st.Servers[id] = s
	}
	h.mu.Unlock()
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
		} else {
			rv.Rotated = true
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok = h.st.Servers[id]
	if !ok || s.Revoke == nil {
		return
	}
	rv.Remove = rv.Remove || s.Revoke.Remove
	s.Revoke = &rv
	h.st.Servers[id] = s
	if rv.Remove && rv.CertDone && rv.RelaysDone && rv.Rotated && len(h.placedLocked(id)) == 0 {
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

// rotateInstanceSecrets gives instance id new Keycloak client secrets (a
// new random value in its .env, registered with Keycloak) and a new relay
// token: nothing the revoked worker held stays valid.
func (h *Hub) rotateInstanceSecrets(ctx context.Context, id string) error {
	h.mu.Lock()
	v := h.findLocked(id)
	if v == nil {
		h.mu.Unlock()
		return fmt.Errorf("instance %s does not resolve", id)
	}
	tmpl := *v
	env := readEnvRaw(h.envPath(id))
	changed := false
	for _, c := range tmpl.Manifest.Clients {
		if c.SecretEnv == "" || c.AIClient {
			continue
		}
		sec, err := randomSecret()
		if err != nil {
			h.mu.Unlock()
			return err
		}
		env[c.SecretEnv], changed = sec, true
	}
	if changed {
		if err := writeEnvMap(h.envPath(id), env); err != nil {
			h.mu.Unlock()
			return err
		}
	}
	var specs []keycloak.ClientSpec
	for _, c := range tmpl.Manifest.Clients {
		if c.SecretEnv != "" && !c.AIClient {
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
	}
	return h.newRelayToken(id)
}
