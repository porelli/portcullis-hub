package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Per-instance AI support across the instance lifecycle (contract §8
// "Follows the resource", §11.3–§11.6, §15.11; plan 4 Task 15):
//
//   - hostname change: the companion scopes' audience and consent text
//     move in SetHosts' Keycloak step (hosts.go, moveAIScopes);
//   - backups: config/ai.json, the instance's AIInstances entry as
//     switches, modes and provider selection only (aiArchive) — never a
//     credential, a caller secret, an oauth-seen record or an internal
//     flag;
//   - same-instance restore: the instance's credential entries go before
//     the volumes are replaced, the archive's AI state comes back through
//     the switch-on refusals (restoredAILocked), every switched-on
//     companion with a revoke hook owes revoke_all (13b's
//     oweAIRevokeLocked) and is listed only after it succeeded; one
//     whose revoke_all failed is switched off (restoreAIAfterStart);
//   - restore into a new id: every companion off, modes and providers
//     kept, no scope;
//   - delete: step 3 removes entries (audited), oauth-seen records,
//     orphans and AIInstances[id]; step 4 deletes the mcp:<id>.* scopes.

// aiArchive is config/ai.json (§11.5).
type aiArchive struct {
	Companions map[string]aiArchiveCompanion `json:"companions"`
	Providers  []string                      `json:"providers"`
}

type aiArchiveCompanion struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
}

// hasAIBlock: t's template has ai.mcp companions or ai.chat (the
// templates whose archives carry config/ai.json).
func hasAIBlock(t *templates.Template) bool {
	a := t.Manifest.AI
	return a != nil && (len(a.MCP) > 0 || a.Chat != nil)
}

// aiArchiveLocked is tg's config/ai.json (nil: none — a template without
// ai.mcp / ai.chat and no AI state). Caller holds mu (read).
func (h *Hub) aiArchiveLocked(tg *target) []byte {
	cur, has := h.st.AIInstances[tg.id]
	if !has && (tg.view == nil || !hasAIBlock(tg.view)) {
		return nil
	}
	a := aiArchive{Companions: map[string]aiArchiveCompanion{}, Providers: slices.Clone(cur.Providers)}
	if a.Providers == nil {
		a.Providers = []string{}
	}
	for name, c := range cur.Companions {
		a.Companions[name] = aiArchiveCompanion{Enabled: c.Enabled, Mode: c.Mode}
	}
	b, _ := json.Marshal(a)
	return append(b, '\n')
}

// aiArchiveMax caps config/ai.json's companions and providers (more =
// the member is refused: AI restored off with one warning).
const aiArchiveMax = 64

// parseAIArchive decodes config/ai.json strictly (one document, known
// keys only).
func parseAIArchive(b []byte) (*aiArchive, error) {
	var a aiArchive
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	if len(a.Companions) > aiArchiveMax || len(a.Providers) > aiArchiveMax {
		return nil, fmt.Errorf("more than %d companions or providers", aiArchiveMax)
	}
	return &a, nil
}

// restoredAILocked is the AI state a restore gives instance t (the view
// after the archive's configuration was applied, so its policy is the
// restored one) from the archive's config/ai.json (a; aErr: it didn't
// decode). copy: a restore into a new id — every companion off. Else
// each switched-on companion passes UpdateInstanceAI's switch-on
// refusals (master switch, ai.unsupported, LoA 3, the companion gone, a
// mode outside its modes, an owed template-update revocation, the alias
// too long); one that fails is restored off with a warning — AI never
// refuses a restore. cur is the instance's AI state before (its Pruned
// companions are kept: their revocation is still owed). has false = no
// entry. Caller holds mu.
func (h *Hub) restoredAILocked(t *templates.Template, a *aiArchive, aErr error, copy bool, cur state.AIInstance) (next state.AIInstance, has bool, warnings []string) {
	next = state.AIInstance{Companions: map[string]state.AICompanion{}}
	for name, c := range cur.Companions {
		if c.Pruned && !copy {
			c.Enabled = false
			next.Companions[name] = c
		}
	}
	switch {
	case aErr != nil:
		warnings = append(warnings, fmt.Sprintf("%s couldn't be read (%v): AI support of %s was restored off", aiMember, aErr, t.ID))
		a = nil
	case a == nil && slices.ContainsFunc(slices.Collect(maps.Values(cur.Companions)), func(c state.AICompanion) bool { return c.Enabled }):
		warnings = append(warnings, fmt.Sprintf("the archive has no AI state (%s): AI support of %s is off", aiMember, t.ID))
	}
	if a != nil {
		for _, name := range slices.Sorted(maps.Keys(a.Companions)) {
			ac := a.Companions[name]
			var c *templates.Companion
			if t.Manifest.AI != nil {
				c = companionOf(t, name)
			}
			if c == nil {
				warnings = append(warnings, fmt.Sprintf("companion %s of the archive is not declared by template %s: its AI state was dropped", clipQuoted(name), t.TemplateID))
				continue
			}
			s := next.Companions[name] // a Pruned one's flags, else zero
			s.Mode, s.Enabled = ac.Mode, ac.Enabled && !copy && !s.Pruned
			if !slices.Contains(c.Modes, s.Mode) {
				warnings = append(warnings, fmt.Sprintf("companion %s: the archive's mode %s is not one of %s: restored off with mode %s", name, clipQuoted(ac.Mode), strings.Join(c.Modes, ", "), defaultMode(c)))
				s.Mode, s.Enabled = defaultMode(c), false
			}
			if ac.Enabled && !copy && s.Pruned {
				warnings = append(warnings, fmt.Sprintf("companion %s restored switched off: a template update's revocation is still owed (see the doctor)", name))
			}
			if s.Enabled {
				if why := h.aiRestoreRefusalLocked(t, c); why != "" {
					warnings = append(warnings, fmt.Sprintf("companion %s restored switched off: %s", name, why))
					s.Enabled = false
				}
			}
			if s.Enabled {
				// As a switch-on commit stamps them (pruneAI's inputs).
				s.IdentityMode, s.RevokeHook = c.Identity.Mode, c.Identity.Revoke
			}
			next.Companions[name] = s
		}
		// The selection passes SetAIProviders' checks one provider at a
		// time (Task 23): unknown, an undeclared kind, a second of a "one"
		// kind — each dropped with a warning, never a refused restore.
		for _, p := range slices.Sorted(slices.Values(a.Providers)) {
			if slices.Contains(next.Providers, p) {
				continue
			}
			if chatOf(t) == nil || h.providerIndexLocked(p) < 0 {
				warnings = append(warnings, fmt.Sprintf("model provider %s of the archive doesn't exist here (or %s is no AI page): dropped from the selection", clipQuoted(p), t.TemplateID))
				continue
			}
			if _, err := h.checkSelectionLocked(t, append(slices.Clone(next.Providers), p)); err != nil {
				warnings = append(warnings, fmt.Sprintf("model provider %s of the archive dropped from the selection: %v", p, err))
				continue
			}
			next.Providers = append(next.Providers, p)
		}
		// A copy is a new place people's chats go out from (fix round 1):
		// say where, with the labels people read.
		if copy && len(next.Providers) > 0 {
			var to []string
			for _, p := range next.Providers {
				to = append(to, h.st.AI.Providers[h.providerIndexLocked(p)].Label+" ("+p+")")
			}
			warnings = append(warnings, fmt.Sprintf("the AI page %s sends what people send on it, and what their apps return to it, to %s (the archive's selection): change it on its AI tab", t.ID, strings.Join(to, ", ")))
		}
	}
	return next, a != nil || len(next.Companions) > 0, warnings
}

// aiRestoreRefusalLocked is why companion c of t can't be on after a
// restore ("" = it can): planAILocked's switch-on refusals but the
// instance's own pending state (it is restoring) and the runtime alias
// check (the start renders it). Caller holds mu.
func (h *Hub) aiRestoreRefusalLocked(t *templates.Template, c *templates.Companion) string {
	if !h.st.AI.Enabled {
		return "AI support is off on this Portcullis"
	}
	if why := h.aiTemplateRefusalLocked(t); why != "" {
		return why
	}
	if c.Identity.Mode != templates.IdentityAppOAuth {
		if err := checkAliasFits(t.ID, c.Name); err != nil {
			return err.Error()
		}
	}
	return ""
}

// setRestoredAILocked writes the restored AI state of id (no entry =
// deleted). Caller holds mu (write) and saves.
func (h *Hub) setRestoredAILocked(id string, next state.AIInstance, has bool) {
	if !has {
		delete(h.st.AIInstances, id)
		return
	}
	if h.st.AIInstances == nil {
		h.st.AIInstances = map[string]state.AIInstance{}
	}
	h.st.AIInstances[id] = next
}

// scopedCompanionsLocked are id's companions that have a scope now
// (switched on, no revoke_all owed, not app_oauth). Caller holds mu.
func (h *Hub) scopedCompanionsLocked(id string) map[string]*templates.Companion {
	out := map[string]*templates.Companion{}
	t := h.findLocked(id)
	if t == nil || !t.HasAIMCP() {
		return out
	}
	sw := h.st.AIInstances[id].Companions
	for i := range t.Manifest.AI.MCP {
		c := &t.Manifest.AI.MCP[i]
		if sw[c.Name].Enabled && !sw[c.Name].RevokePending && c.Identity.Mode != templates.IdentityAppOAuth {
			out[c.Name] = c
		}
	}
	return out
}

// dropRestoredScopes deletes the scopes of companions that had one
// before the restore (had) and are off now (12a's applyAIScopes with
// synthetic switch-offs; one still on keeps it). Logged, never fails the
// restore.
func (h *Hub) dropRestoredScopes(id string, had map[string]*templates.Companion) {
	h.mu.RLock()
	sw := h.st.AIInstances[id].Companions
	var changes []aiChange
	for _, name := range slices.Sorted(maps.Keys(had)) {
		// Off, or owing a revoke_all (its scope is ensured again once that
		// succeeded: syncAIScopes).
		if s := sw[name]; !s.Enabled || s.RevokePending {
			s.Enabled = false
			changes = append(changes, aiChange{c: had[name], before: state.AICompanion{Enabled: true}, after: s, scope: aigate.CompanionScope(id, name)})
		}
	}
	h.mu.RUnlock()
	if len(changes) == 0 {
		return
	}
	if err := h.applyAIScopes(context.Background(), changes); err != nil {
		// A delete that didn't run (no Keycloak, an earlier error) is owed
		// like one that failed; every client pass retries it.
		h.aiKCMu.Lock()
		for _, ch := range changes {
			h.oweScopeDropLocked(ch.scope)
		}
		h.aiKCMu.Unlock()
		log.Printf("ai: %s: the scopes of companions a restore switched off: %v (owed: every AI client pass retries the delete)", id, err)
	}
}

// oweScopeDropLocked records an mcp:* scope whose delete is owed.
// Caller holds aiKCMu.
func (h *Hub) oweScopeDropLocked(name string) {
	if h.aiOwedDrops == nil {
		h.aiOwedDrops = map[string]bool{}
	}
	h.aiOwedDrops[name] = true
}

// retryOwedDropsLocked deletes every owed scope that is still unwanted
// (one wanted again is forgotten). Caller holds aiKCMu.
func (h *Hub) retryOwedDropsLocked(ctx context.Context, kc AIKeycloak, ensure map[string]keycloak.MCPScope) []error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(h.aiOwedDrops)) {
		if _, wanted := ensure[name]; wanted {
			delete(h.aiOwedDrops, name)
			continue
		}
		if err := kc.DeleteMCPScope(ctx, name); err != nil {
			errs = append(errs, fmt.Errorf("Keycloak: deleting client scope %s (owed): %w", name, err))
			continue
		}
		delete(h.aiOwedDrops, name)
	}
	return errs
}

// restoreAIAfterStart switches off every companion of id whose owed
// revoke_all failed in the restore's own start (§11.6: it stays out of
// the gate file, switched off, until a switch-on succeeds — which runs
// revoke_all first, G34). RevokePending stays set, so a later start
// retries the revoke too. Returns the warnings and the error for the op
// record (nil = nothing failed). Caller holds lockApp and aiLock; the
// instance was started.
func (h *Hub) restoreAIAfterStart(id string, actor directory.Actor) ([]string, error) {
	h.mu.Lock()
	a, ok := h.st.AIInstances[id]
	var failed []string
	if ok {
		next := maps.Clone(a.Companions)
		for _, name := range slices.Sorted(maps.Keys(a.Companions)) {
			if s := a.Companions[name]; s.Enabled && s.RevokePending {
				s.Enabled = false
				next[name] = s
				failed = append(failed, name)
			}
		}
		if len(failed) > 0 {
			a.Companions = next
			h.st.AIInstances[id] = a
		}
	}
	var saveErr error
	if len(failed) > 0 {
		if saveErr = h.saveStateLocked(); saveErr != nil {
			// Still not listed (RevokePending): the next start retries.
			log.Printf("ai: %s: saving the switch-off after a failed revoke_all: %v", id, saveErr)
		}
	}
	h.mu.Unlock()
	if len(failed) == 0 {
		return nil, nil
	}
	var warnings []string
	var errs []error
	for _, name := range failed {
		why := h.aiError(id, name)
		if why == "" {
			why = "the owed revoke_all didn't run"
		}
		warnings = append(warnings, fmt.Sprintf("companion %s was switched off: its revoke_all in the restored app failed (%s); switch it on again once the app works", name, why))
		errs = append(errs, fmt.Errorf("companion %s switched off after the restore: %s", name, why))
		h.auditOp(actor, "ai.disable", id+"/"+name, "restore: revoke_all failed", nil)
	}
	h.writePolicyLogged()
	return warnings, errors.Join(append(errs, saveErr)...)
}

// forgetInstanceAI is delete step 3's AI part (§11.4, G56): with the
// project down, every AI credential entry of id is removed (each audited
// ai.credential.revoke reason deleted, actor the deleting admin; no hook
// runs: the app's tokens go with its volumes), then its oauth-seen
// records and orphans, then AIInstances[id]. Idempotent. The caller
// rewrites the gate file.
func (h *Hub) forgetInstanceAI(id string, actor directory.Actor) error {
	for _, e := range h.creds().Entries() {
		if e.Instance != id {
			continue
		}
		if err := h.creds().Remove(e.Instance, e.Companion, e.User); err != nil {
			return fmt.Errorf("removing the AI credential of %s/%s/%s: %w", e.Instance, e.Companion, e.User, err)
		}
		h.auditAI(actor, "ai.credential.revoke", e.Instance+"/"+e.Companion+"/"+e.User, "id "+e.ID+" reason deleted", nil)
	}
	prefix := id + "/"
	if err := h.oauthSeenUpdate(func(seen map[string][]string) bool {
		changed := false
		for ref := range seen {
			if strings.HasPrefix(ref, prefix) {
				delete(seen, ref)
				changed = true
			}
		}
		return changed
	}); err != nil {
		return fmt.Errorf("removing its app_oauth records from %s failed (%w): an administrator must fix or remove that file, then delete again", filepath.Join(h.cfg.DataDir, "ai", oauthSeenName), err)
	}
	if _, err := h.orphansUpdate(func(l []aiOrphanID) ([]aiOrphanID, bool) {
		n := len(l)
		l = slices.DeleteFunc(l, func(o aiOrphanID) bool { return o.Instance == id })
		return l, len(l) != n
	}); err != nil {
		return fmt.Errorf("removing its unstored-credential records from %s failed (%w): an administrator must fix or remove that file, then delete again", filepath.Join(h.cfg.DataDir, "ai", orphansName), err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.st.AIInstances[id]; !ok {
		return nil
	}
	prev := h.st.AIInstances[id]
	delete(h.st.AIInstances, id)
	if err := h.saveStateLocked(); err != nil {
		h.st.AIInstances[id] = prev
		return err
	}
	h.aiErrMu.Lock()
	delete(h.aiReapply, id)
	h.aiErrMu.Unlock()
	return nil
}

// deleteAIScopes is delete step 4's AI part: every mcp:<id>.<companion>
// scope of the template's companions and of the names AI state recorded
// (names), detached from every client first (DeleteMCPScope; missing =
// nothing).
func (h *Hub) deleteAIScopes(ctx context.Context, id string, names []string) error {
	kc := h.aiKeycloak()
	if kc == nil {
		return errors.New("Keycloak: the AI scope calls are not configured")
	}
	h.aiKCMu.Lock()
	defer h.aiKCMu.Unlock()
	// Plus every realm scope named mcp:<id>.* (a retry whose template and
	// AI state are gone; ids and companion names hold no dot, so the
	// prefix is exact).
	listed, err := kc.MCPScopeNames(ctx)
	if err != nil {
		return fmt.Errorf("listing the mcp:* client scopes: %w", err)
	}
	set := map[string]bool{}
	for _, name := range names {
		set[aigate.CompanionScope(id, name)] = true
	}
	prefix := "mcp:" + id + "."
	for _, s := range listed {
		if strings.HasPrefix(s, prefix) {
			set[s] = true
		}
	}
	var errs []error
	for _, scope := range slices.Sorted(maps.Keys(set)) {
		if err := kc.DeleteMCPScope(ctx, scope); err != nil {
			errs = append(errs, fmt.Errorf("deleting client scope %s: %w", scope, err))
		} else {
			delete(h.aiOwedDrops, scope)
		}
	}
	return errors.Join(errs...)
}

// aiScopeNamesLocked are the companion names whose scopes a delete of tg
// removes: the template's companions (any identity mode but app_oauth)
// and every name in its AI state. Caller holds mu.
func (h *Hub) aiScopeNamesLocked(tg *target) []string {
	set := map[string]bool{}
	if tg.view != nil && tg.view.Manifest.AI != nil {
		for _, c := range tg.view.Manifest.AI.MCP {
			if c.Identity.Mode != templates.IdentityAppOAuth {
				set[c.Name] = true
			}
		}
	}
	for name, s := range h.st.AIInstances[tg.id].Companions {
		if s.IdentityMode != templates.IdentityAppOAuth {
			set[name] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// withProviderVars is names plus every PORTCULLIS_AI_PROVIDER_* variable
// of env (G30(b): a backup blanks them by name; restore writes them from
// the provider store for the instance's own selection — Task 23).
func withProviderVars(names map[string]bool, env []byte) map[string]bool {
	out := maps.Clone(names)
	if out == nil {
		out = map[string]bool{}
	}
	for k := range parseEnv(env) {
		if strings.HasPrefix(k, ProviderVarPrefix) {
			out[k] = true
		}
	}
	return out
}
