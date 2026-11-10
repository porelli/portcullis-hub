package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"time"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Keycloak AI clients and the master switch (contract §8 "AI clients",
// §15.11 "Master switch"; plan 4 Task 12b).
//
// While the master switch is on, every pass (the directory sync loop's,
// next to the fresh-auth client, and one right after each Settings → AI
// save) ensures every mcp:* scope, then re-asserts each offered client of
// the Hub's three with EnsureAIClient — its exact mcp:* set
// (wantedAIScopes, limited to the scopes in place) and Settings → AI's
// connection length — and records which succeeded (SetAIClientHealth: a
// failed or conflicting client is never listed in mcp-gate.json). An
// unticked client is deleted when it is tagged portcullis-ai; an untagged
// or foreign one is a conflict, left alone, logged and unhealthy. The
// master switch off keeps the clients and scopes (the gate file says
// enabled: false). Every enabled AI page's ai_client (Task 23) is
// re-asserted in the same pass (EnsureAIClient, its instance's owner tag,
// mcp:all only) and its health merged. Never under mu.

// aiClientPass is one pass: syncAIClients, then the gate file rewritten
// when health changed. Errors are logged once per distinct text (inside)
// and returned for the loop's retry.
func (h *Hub) aiClientPass(ctx context.Context) (changed bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, attrSyncTimeout)
	defer cancel()
	changed, err = h.syncAIClients(ctx)
	if changed {
		h.writePolicyLogged()
	}
	return changed, err
}

// syncAIClients makes Keycloak's AI clients follow Settings → AI and
// records their health; changed = the health of a Hub client changed.
func (h *Hub) syncAIClients(ctx context.Context) (changed bool, err error) {
	h.aiKCMu.Lock()
	defer h.aiKCMu.Unlock()
	kc := h.aiKeycloak()
	h.mu.RLock()
	a := h.st.AI
	plan := h.aiScopePlanLocked()
	pages := h.instanceAIClientWantsLocked()
	h.mu.RUnlock()

	if kc == nil {
		// Not wired (main always wires it): health stays as it is —
		// unknown at start, so nothing is listed.
		return false, nil
	}
	health := map[string]bool{}
	var errs []error
	if a.Enabled {
		errs = ensureAIScopes(ctx, kc, plan.ensure)
	}
	// Scope deletes that failed or never ran (Task 15), any master state.
	errs = append(errs, h.retryOwedDropsLocked(ctx, kc, plan.ensure)...)
	wants := plan.clients
	for _, w := range wants {
		var cerr error
		switch {
		case !w.offered:
			// Unticked: deleted only when tagged portcullis-ai (a missing
			// one is nil); a conflict is left alone. Never listed.
			health[w.id] = false
			if cerr = kc.DeleteAIClient(ctx, w.id, keycloak.AIOwner); cerr != nil {
				cerr = fmt.Errorf("Keycloak: deleting AI client %s: %w", w.id, cerr)
			}
		case a.Enabled:
			// The exact set (ruling): EnsureAIClient refuses a scope that
			// doesn't exist — unhealthy, left as it was —; one whose ensure
			// failed but that exists stays attached.
			spec := keycloak.AIClientSpec{
				ClientID: w.id, Public: true, RedirectURIs: keycloak.AIRedirectURIs(w.id),
				OptionalScopes: slices.Clone(w.scopes),
				OfflineIdle:    time.Duration(a.OfflineIdleDays) * 24 * time.Hour,
				OfflineMax:     time.Duration(a.OfflineMaxDays) * 24 * time.Hour,
				Owner:          keycloak.AIOwner,
			}
			_, cerr = kc.EnsureAIClient(ctx, spec)
			health[w.id] = cerr == nil
			if cerr != nil {
				cerr = fmt.Errorf("Keycloak: AI client %s: %w", w.id, cerr)
			}
		default:
			// Master off: the client is kept as it is, but its health is
			// unknown-bad until a pass with the master on re-asserts it
			// (a switch-on never publishes stale health).
			health[w.id] = false
		}
		h.logAIClientErr(w.id, cerr)
		if cerr != nil {
			errs = append(errs, cerr)
		}
	}
	// Every enabled AI page's ai_client (Task 23, G10): re-asserted like
	// the Hub's three while the master switch is on (mcp:all is among the
	// scopes ensured above); off, kept as it is and unhealthy (not
	// listed). Health merged per id, never replacing the map.
	for _, w := range pages {
		id := w.c.ClientID
		if !a.Enabled {
			health[id] = false
			continue
		}
		_, cerr := kc.EnsureAIClient(ctx, h.instanceAIClientSpec(&w.t, w.c, a))
		health[id] = cerr == nil
		if cerr != nil {
			cerr = fmt.Errorf("Keycloak: AI client %s of %s: %w", id, w.t.ID, cerr)
		}
		h.logAIClientErr(id, cerr)
		if cerr != nil {
			errs = append(errs, cerr)
		}
	}
	return h.mergeAIClientHealth(health), errors.Join(errs...)
}

// aiScopePlan is what a pass over the AI clients applies, from state:
// every mcp:* scope to ensure (companion and fixed) and each Hub client's
// exact wanted set (wantedAIScopes).
type aiScopePlan struct {
	ensure  map[string]keycloak.MCPScope
	clients []aiClientWant
}

type aiClientWant struct {
	id      string
	offered bool
	scopes  []string
}

// aiScopePlanLocked builds the plan. Caller holds mu (read).
func (h *Hub) aiScopePlanLocked() aiScopePlan {
	p := aiScopePlan{ensure: h.companionScopesLocked()}
	for k, v := range h.fixedScopesLocked() {
		p.ensure[k] = v
	}
	for _, c := range hubAIClients(h.st.AI) {
		p.clients = append(p.clients, aiClientWant{c.id, c.c.Offered, h.wantedAIScopesLocked(c.id)})
	}
	return p
}

// ensureAIScopes ensures every scope (sorted; each failure collected, the
// others still ensured). Never under mu.
func ensureAIScopes(ctx context.Context, kc AIKeycloak, ensure map[string]keycloak.MCPScope) []error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(ensure)) {
		if err := kc.EnsureMCPScope(ctx, ensure[name]); err != nil {
			errs = append(errs, fmt.Errorf("Keycloak: client scope %s: %w", name, err))
		}
	}
	return errs
}

// logAIClientErr logs a client's error once per distinct text (a
// conflict says so). Caller holds aiKCMu.
func (h *Hub) logAIClientErr(id string, err error) {
	if h.aiClientErrs == nil {
		h.aiClientErrs = map[string]string{}
	}
	if err == nil {
		delete(h.aiClientErrs, id)
		return
	}
	msg := err.Error()
	if h.aiClientErrs[id] == msg {
		return
	}
	h.aiClientErrs[id] = msg
	var conflict *keycloak.ConflictError
	if errors.As(err, &conflict) {
		log.Printf("ai: AI client %s is not the Hub's (left alone, not listed in mcp-gate.json): %v", id, err)
		return
	}
	log.Printf("ai: AI client %s not in place (not listed in mcp-gate.json; retried): %v", id, err)
}

// mergeAIClientHealth sets the given ids' health, keeping every other
// entry (an ai_client's, Task 23's); changed = any entry changed (unknown
// → known included).
func (h *Hub) mergeAIClientHealth(upd map[string]bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	changed := false
	if h.aiHealth == nil {
		h.aiHealth = map[string]bool{}
		changed = len(upd) > 0
	}
	for id, ok := range upd {
		if old, had := h.aiHealth[id]; !had || old != ok {
			changed = true
		}
		h.aiHealth[id] = ok
	}
	return changed
}

// aiOnLocked: AI support may be on in t's app: the master switch is on
// and t's sign-in template has a way in without a client certificate (a
// restore, a template or sign-in change can make it certificate-only with
// a companion on). Caller holds mu.
func (h *Hub) aiOnLocked(t *templates.Template) bool {
	return h.st.AI.Enabled && !h.certOnlyLocked(t)
}

// masterToggleLocked is the master switch's app side, in the Settings →
// AI commit (caller holds mu, saves, and undoes on a failed save): every
// switched-on app_oauth companion (the gate isn't in its path) owes its
// on_change (OnChangePending) — enabled false with the master off; on, a
// revoke_all first (RevokePending, G34) —; per-companion Enabled / Mode
// are untouched. Returns the enabled instances with a switched-on
// companion (re-rendered and restarted after the commit) and the
// previous ai_instances to put back.
func (h *Hub) masterToggleLocked(on bool) (restart []string, prev map[string]state.AIInstance) {
	h.aiMasterGen++
	prev = maps.Clone(h.st.AIInstances)
	for i := range h.instances {
		t := &h.instances[i]
		if !t.HasAIMCP() {
			continue
		}
		ai, ok := h.st.AIInstances[t.ID]
		if !ok {
			continue
		}
		next := maps.Clone(ai.Companions)
		anyOn := false
		for name, s := range ai.Companions {
			if !s.Enabled {
				continue
			}
			anyOn = true
			c := companionOf(t, name)
			if c == nil || c.Identity.Mode != templates.IdentityAppOAuth {
				continue
			}
			if t.Manifest.AI.OnChange != "" {
				s.OnChangePending = true
			}
			if on && c.Identity.Revoke != "" {
				s.RevokePending = true
			}
			next[name] = s
		}
		ai.Companions = next
		h.st.AIInstances[t.ID] = ai
		if anyOn && t.Enabled {
			restart = append(restart, t.ID)
		}
	}
	slices.Sort(restart)
	return restart, prev
}

// oweMasterRestarts records the restart each instance owes after a
// master toggle (delivered.json: a Hub restart repeats it), right after
// the commit and before any Keycloak call.
func (h *Hub) oweMasterRestarts(ids []string) {
	for _, id := range ids {
		h.setOwed(id, settings.EffectRestart)
	}
}

// restartForMaster re-renders and restarts each instance after a master
// toggle (oweMasterRestarts first): a background Restart, which waits for
// a busy lockApp (a backup) up to restartWait; its start runs the owed
// on_change / revoke_all under lockApp → aiLock (pendingAIAfterStart).
func (h *Hub) restartForMaster(ids []string) {
	for _, id := range ids {
		t := h.Template(id)
		if t == nil {
			continue
		}
		tc := *t
		h.goBackground(func() { h.Restart(tc) })
	}
}
