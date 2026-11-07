package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Per-instance AI support (contract §3.2 "What the Hub renders", §5 MCP
// routes, §8 mcp:* scopes, §15.5 hook I/O, §15.11; plan 4 Task 12a).
//
// A switch-on runs revoke_all → state saved → scopes ensured and
// attached → gate files → override + compose up (enabled instance) →
// on_change; a switch-off reverses it (state → scopes → gate files →
// override + up → revoke_all → entries removed → on_change false); a mode
// change runs revoke_all before anything else. A failure before the
// state save changes nothing (a revoke_all failure is a 502); a failure
// after it is an OpError (op ai), and the same request re-applies every
// step after the save. On a disabled instance only state (and the
// state-derived scopes and gate file) changes: no hook, no compose.
//
// Locks: lockApp (the lifecycle try-lock) → aiLock (a waiting per-instance
// mutex). Every lifecycle operation that changes what AI may use —
// switching AI (UpdateInstanceAI), restore, restore-as, the restore
// recovery, delete and disable — takes aiLock right after lockApp and
// holds it to the end (lifecycleAILock; G35, §15.5); mint and revoke take
// only aiLock (Task 13). Nothing holding aiLock ever waits for lockApp
// (a restart they need is backgrounded), and a start inside such an
// operation runs the owed AI hooks under the operation's hold
// (pendingAIAfterStart, aiHeld). Never Hub.mu across a Keycloak, docker,
// hook or gate call.

// AIKeycloak is the Keycloak side of the mcp:* scopes and the Hub's AI
// clients (keycloak.Client; ai_clients.go).
type AIKeycloak interface {
	EnsureMCPScope(ctx context.Context, s keycloak.MCPScope) error
	DeleteMCPScope(ctx context.Context, name string) error
	SetOptionalScopes(ctx context.Context, clientID string, scopes []string) error
	EnsureAIClient(ctx context.Context, s keycloak.AIClientSpec) error
	DeleteAIClient(ctx context.Context, clientID, owner string) error
	// MCPScopeNames lists the realm's mcp:* scopes (a delete's
	// prefix sweep, Task 15).
	MCPScopeNames(ctx context.Context) ([]string, error)
}

// SetAIKeycloak wires the scope calls (nil: a switch that changes a scope
// fails as an OpError after the state save).
func (h *Hub) SetAIKeycloak(k AIKeycloak) {
	h.mu.Lock()
	h.aiKC = k
	h.mu.Unlock()
}

func (h *Hub) aiKeycloak() AIKeycloak {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.aiKC
}

// aiLock takes instance id's AI lock (waiting) and returns its release.
func (h *Hub) aiLock(id string) func() {
	m, _ := h.aiLocks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// lifecycleAILock is aiLock for a lifecycle operation: the caller holds
// lockApp(id). While it is held, aiHeld marks it, so the operation's own
// start (pendingAIAfterStart, which runs under the same lockApp) doesn't
// wait for the lock it already holds.
func (h *Hub) lifecycleAILock(id string) func() {
	unlock := h.aiLock(id)
	h.aiHeld.Store(id, struct{}{})
	return func() {
		h.aiHeld.Delete(id)
		unlock()
	}
}

// aiTryLock takes instance id's AI lock, waiting at most d (polling every
// lockPoll); ok false = still held after d.
func (h *Hub) aiTryLock(id string, d time.Duration) (unlock func(), ok bool) {
	m, _ := h.aiLocks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	deadline := time.Now().Add(d)
	for {
		if mu.TryLock() {
			return mu.Unlock, true
		}
		if time.Now().After(deadline) {
			return nil, false
		}
		time.Sleep(h.lockPoll)
	}
}

// mtlsRefusal is the switch-on refusal of an instance whose effective
// policy reaches LoA 3 (contract §15.11).
const mtlsRefusal = "needs a client certificate on every request; AI clients can't present one"

// aiPolicyOffDetail is the ai.disable detail of a policy save's switch-off.
const aiPolicyOffDetail = "policy needs mTLS"

// aiProxyNetwork is the network the companion aliases live on.
const aiProxyNetwork = "portcullis-proxy"

// CompanionUpdate is one companion's part of PUT /api/instances/{id}/ai
// (nil = unchanged).
type CompanionUpdate struct {
	Enabled *bool   `json:"enabled"`
	Mode    *string `json:"mode"`
}

// InstanceAIUpdate is PUT /api/instances/{id}/ai: companions (ai.mcp
// templates) or, for an AI page (ai.chat), its model provider selection
// (Task 23; nil = unchanged).
type InstanceAIUpdate struct {
	Companions map[string]CompanionUpdate `json:"companions"`
	Providers  *[]string                  `json:"providers"`
}

// InstanceAIView is the instance's AI tab (GET /api/instances/{id}/ai).
type InstanceAIView struct {
	Unsupported string                 `json:"unsupported"`
	Alternative *templates.Alternative `json:"alternative"`
	MasterOff   bool                   `json:"master_off"`
	// Refused: why a switch-on would be refused now ("" = it wouldn't).
	Refused    string          `json:"refused"`
	Companions []CompanionView `json:"companions"`
	// Providers: an ai.chat instance's provider selection (Task 23).
	Providers []string `json:"providers"`
	// ProviderKinds: an AI page's provider_kinds (kind → one|many; the
	// tab's selection; null for any other template).
	ProviderKinds map[string]string `json:"provider_kinds,omitempty"`
}

// CompanionView is one companion on the AI tab.
type CompanionView struct {
	Name         string   `json:"name"`
	Label        string   `json:"label"`
	URL          string   `json:"url"`
	Kind         string   `json:"kind"`
	IdentityMode string   `json:"identity_mode"`
	Upstream     string   `json:"upstream"`
	Source       string   `json:"source"`
	Modes        []string `json:"modes"`
	Mode         string   `json:"mode"`
	Enabled      bool     `json:"enabled"`
	// Status: off, revoking (off, its revoke_all owed to the next start),
	// on, failed (LastError set), revoke_pending (on, but
	// its owed revoke_all hasn't run yet: kept off) or unavailable (on, but
	// the master switch is off or the instance refuses AI now).
	Status      string `json:"status"`
	LastError   string `json:"last_error"`
	Population  int    `json:"population"`
	Credentials int    `json:"credentials"`
	Revoking    int    `json:"revoking"`
	// Connections: Task 13 (always 0 here).
	Connections int      `json:"connections"`
	Confirm     []string `json:"confirm"`
	Never       []string `json:"never"`
	OwnRules    bool     `json:"own_rules"`
	// Unmatched (app_oauth, T27): people who left before their app
	// account could be matched; their non-AI tokens remain until an
	// administrator deals with them in the app and dismisses them.
	Unmatched []string `json:"unmatched,omitempty"`
}

// InstanceAIResult is PUT's answer: the tab plus whether the app was
// recreated (G49) and warnings.
type InstanceAIResult struct {
	*InstanceAIView
	Restarts bool     `json:"restarts"`
	Warnings []string `json:"warnings"`
}

// aiChange is one companion's planned change.
type aiChange struct {
	c          *templates.Companion
	before     state.AICompanion
	after      state.AICompanion
	hadEntry   bool
	reapply    bool // unchanged, re-applied after a failed ai op
	owed       bool // unchanged, re-applied: it owes hooks (pending flags)
	modeOnly   bool // off → off, only the stored mode changes
	detail     string
	alias      string
	needsAlias bool
	scope      string // the companion's mcp:* scope name
}

func (ch aiChange) switchingOn() bool  { return !ch.before.Enabled && ch.after.Enabled }
func (ch aiChange) switchingOff() bool { return ch.before.Enabled && !ch.after.Enabled }
func (ch aiChange) modeChanged() bool {
	return ch.before.Enabled && ch.after.Enabled && ch.before.Mode != ch.after.Mode
}

// action is the audit action of the change.
func (ch aiChange) action() string {
	switch {
	case ch.switchingOn():
		return "ai.enable"
	case ch.switchingOff():
		return "ai.disable"
	case ch.modeChanged() || ch.modeOnly:
		return "ai.mode"
	case ch.after.Enabled:
		return "ai.enable"
	}
	return "ai.disable"
}

func (ch aiChange) auditDetail() string {
	switch ch.action() {
	case "ai.mode":
		return ch.before.Mode + " -> " + ch.after.Mode
	case "ai.enable":
		return "mode " + ch.after.Mode
	}
	return ch.detail
}

// SetAISupport switches one companion on or off (its mode kept, or the
// default one).
func (h *Hub) SetAISupport(ctx context.Context, id, companion string, on bool, actor directory.Actor) error {
	_, err := h.UpdateInstanceAI(ctx, id, InstanceAIUpdate{Companions: map[string]CompanionUpdate{companion: {Enabled: &on}}}, actor)
	return err
}

// SetAIMode changes one companion's mode.
func (h *Hub) SetAIMode(ctx context.Context, id, companion, mode string, actor directory.Actor) error {
	_, err := h.UpdateInstanceAI(ctx, id, InstanceAIUpdate{Companions: map[string]CompanionUpdate{companion: {Mode: &mode}}}, actor)
	return err
}

// UpdateInstanceAI applies u to instance id (PUT /api/instances/{id}/ai).
// Every change is audited (ai.enable, ai.disable, ai.mode "a -> b").
func (h *Hub) UpdateInstanceAI(ctx context.Context, id string, u InstanceAIUpdate, actor directory.Actor) (*InstanceAIResult, error) {
	return h.updateInstanceAI(ctx, id, u, actor, "")
}

func (h *Hub) updateInstanceAI(ctx context.Context, id string, u InstanceAIUpdate, actor directory.Actor, offDetail string) (res *InstanceAIResult, retErr error) {
	if u.Providers != nil {
		// An AI page has no companions (ai.chat only with ai.unsupported):
		// one part per request.
		if len(u.Companions) > 0 {
			return nil, statusErr(http.StatusBadRequest, "give companions or providers, not both")
		}
		restarts, err := h.setAIProviders(ctx, id, *u.Providers, actor)
		if err != nil {
			return nil, err
		}
		v, err := h.InstanceAI(id)
		if err != nil {
			return nil, err
		}
		return &InstanceAIResult{InstanceAIView: v, Restarts: restarts, Warnings: []string{}}, nil
	}
	var changes []aiChange
	audited := false
	auditAll := func(err error) {
		if audited {
			return
		}
		audited = true
		if len(changes) == 0 {
			// A refusal before the plan: one entry per requested companion.
			for _, name := range slices.Sorted(maps.Keys(u.Companions)) {
				action := "ai.enable"
				if cu := u.Companions[name]; cu.Enabled != nil && !*cu.Enabled {
					action = "ai.disable"
				} else if cu.Enabled == nil && cu.Mode != nil {
					action = "ai.mode"
				}
				h.auditOp(actor, action, id+"/"+clip(name, 32), "", err)
			}
			return
		}
		for _, ch := range changes {
			h.auditOp(actor, ch.action(), id+"/"+ch.c.Name, ch.auditDetail(), err)
		}
	}
	defer func() { auditAll(retErr) }()
	if err := checkAIActor(actor); err != nil {
		return nil, err
	}
	if len(u.Companions) == 0 {
		return nil, statusErr(http.StatusBadRequest, "nothing to change: give companions (or providers, for an AI page)")
	}
	if h.Template(id) == nil {
		return nil, ErrNotFound
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	defer h.aiLock(id)()
	live := h.Template(id)
	if live == nil {
		return nil, ErrNotFound
	}
	t := live
	retry := h.aiReapplyOf(id)

	// The plan and the refusals, under the read lock.
	h.mu.RLock()
	changes, err = h.planAILocked(t, u, retry, offDetail)
	masterGen := h.aiMasterGen
	h.mu.RUnlock()
	if err != nil {
		changes = nil
		return nil, err
	}
	// Docker: another container answering a switched-on alias.
	for _, ch := range changes {
		if ch.needsAlias {
			if err := h.checkAliasFree(ctx, t, ch); err != nil {
				return nil, err
			}
		}
	}
	// On a running instance a companion still owing hooks (RevokePending /
	// OnChangePending) is re-applied by the same request: runPendingAI
	// runs what it owes.
	if t.Enabled {
		for i := range changes {
			ch := &changes[i]
			if ch.before == ch.after && ch.hadEntry && (ch.before.RevokePending || ch.before.OnChangePending) {
				ch.owed = true
			}
		}
	}
	work := slices.DeleteFunc(slices.Clone(changes), func(ch aiChange) bool { return !ch.reapply && !ch.owed && ch.before == ch.after })
	if len(work) == 0 {
		changes = nil
		audited = true
		v, err := h.InstanceAI(id)
		return &InstanceAIResult{InstanceAIView: v, Warnings: []string{}}, err
	}
	changes = work
	running := t.Enabled
	// startUp leaves the owed revoke_alls of this instance to us.
	h.aiApplying.Store(id, true)
	defer h.aiApplying.Delete(id)

	// revoke_all before every switch-on and every mode change (G34): a
	// failure is a 502 and nothing changes. On a stopped instance no hook
	// can run: the companion's Hub-side entries are dropped at once and
	// revoke_all (and on_change) is owed — RevokePending / OnChangePending,
	// run by the next start, before the companion is rendered or listed.
	for i := range changes {
		ch := &changes[i]
		switched := ch.switchingOn() || ch.switchingOff() || ch.modeChanged()
		if !switched {
			continue
		}
		switch {
		case !running:
			if ch.c.Identity.Revoke != "" {
				if err := h.dropAIEntries(id, ch.c.Name); err != nil {
					return nil, err
				}
				ch.after.RevokePending = true
			}
			if t.Manifest.AI.OnChange != "" {
				ch.after.OnChangePending = true
			}
		case ch.c.Identity.Revoke != "" && (ch.switchingOn() || ch.modeChanged()):
			if err := h.revokeAll(ctx, t, ch.c); err != nil {
				h.setAIError(id, ch.c.Name, err.Error())
				return nil, h.finishOp(id, OpAI, err, false)
			}
			ch.after.RevokePending = false
		}
	}
	// On a running instance what runs after the up is owed in the same
	// commit (a crash before it leaves the flags; the success paths
	// clear them): revoke_all of a companion switched (or re-applied) off,
	// on_change of every change but a stored mode.
	if running {
		for i := range changes {
			ch := &changes[i]
			if ch.owed || ch.modeOnly {
				continue
			}
			if ch.c.Identity.Revoke != "" && !ch.after.Enabled && (ch.switchingOff() || ch.reapply) {
				ch.after.RevokePending = true
			}
			ch.after.OnChangePending = t.Manifest.AI.OnChange != ""
		}
	}

	// State. The refusals again under the write lock (a policy save or
	// the master switch may have changed meanwhile, G43): nothing is saved
	// on a refusal (an already-run revoke_all needs no undo).
	if h.testHookAIBeforeSave != nil {
		h.testHookAIBeforeSave()
	}
	h.mu.Lock()
	if h.aiMasterGen != masterGen {
		// The master switch changed since the plan: its commit set owed
		// hooks this plan doesn't know about (12b).
		h.mu.Unlock()
		return nil, statusErr(http.StatusConflict, "AI support was switched on or off meanwhile: try again")
	}
	// A template update (pruneAI takes only mu) may have landed since the
	// plan: the companion gone, its identity changed, or its entry
	// pruned. Committing the plan would clobber that (final review I1).
	if err := h.aiPlanStaleLocked(id, changes); err != nil {
		h.mu.Unlock()
		return nil, err
	}
	if lt := h.findLocked(id); lt != nil && slices.ContainsFunc(changes, func(ch aiChange) bool { return ch.after.Enabled }) {
		var refuse error
		if !h.st.AI.Enabled {
			refuse = statusErr(http.StatusConflict, "AI support is off on this Portcullis: switch it on in Settings → AI first")
		} else if code, why := h.aiRefusalLocked(lt); why != "" {
			refuse = statusErr(code, "%s", why)
		}
		if refuse != nil {
			h.mu.Unlock()
			return nil, refuse
		}
	}
	prev, had := h.st.AIInstances[id]
	next := state.AIInstance{Companions: map[string]state.AICompanion{}, Providers: slices.Clone(prev.Providers)}
	for k, v := range prev.Companions {
		next.Companions[k] = v
	}
	for _, ch := range changes {
		a := ch.after
		if a.Enabled {
			// What a template update is compared with (pruneAI, G33).
			a.IdentityMode, a.RevokeHook = ch.c.Identity.Mode, ch.c.Identity.Revoke
		}
		next.Companions[ch.c.Name] = a
	}
	if h.st.AIInstances == nil {
		h.st.AIInstances = map[string]state.AIInstance{}
	}
	h.st.AIInstances[id] = next
	if err := h.saveStateLocked(); err != nil {
		if had {
			h.st.AIInstances[id] = prev
		} else {
			delete(h.st.AIInstances, id)
		}
		h.mu.Unlock()
		return nil, err
	}
	h.mu.Unlock()
	for _, ch := range changes {
		if ch.switchingOff() {
			// A mint's (or a revoke's) last error belongs to the companion
			// being on (13a carry).
			h.clearMintError(id, ch.c)
		}
	}
	// app_oauth leavers, revocations a switch leaves behind (Task 13b).
	defer h.TriggerAIReconcile()
	if h.testHookAIAfterSave != nil {
		h.testHookAIAfterSave()
	}

	// After the save: every step runs, the first error is the OpError; a
	// companion a step failed for is re-applied by the same request
	// (aiReapply), the others aren't.
	var errs []error
	failed := map[string]bool{}
	all := func() {
		for _, ch := range changes {
			failed[ch.c.Name] = true
		}
	}
	if err := h.applyAIScopes(ctx, changes); err != nil {
		errs = append(errs, err)
		all()
	}
	if err := h.WritePolicy(); err != nil && !errors.Is(err, errGateDirectory) {
		errs = append(errs, fmt.Errorf("gate files: %w", err))
		all()
	}
	restarts := false
	// Only a stored mode of a switched-off companion changed: nothing runs.
	if running && slices.ContainsFunc(changes, func(ch aiChange) bool { return !ch.modeOnly }) {
		if t2 := h.Template(id); t2 != nil {
			t = t2
		}
		upErr := h.composeUp(t)
		if composeFailed(upErr) {
			upErr = statusErr500Wrap("compose up failed", upErr)
		}
		if upErr != nil {
			errs = append(errs, upErr)
			all()
		} else {
			restarts = true
		}
		for _, ch := range changes {
			if ch.owed {
				continue // runPendingAI below
			}
			var cerrs []error
			if ch.c.Identity.Revoke != "" && (ch.switchingOff() || (ch.reapply && !ch.after.Enabled)) {
				if err := h.revokeAll(ctx, t, ch.c); err != nil {
					cerrs = append(cerrs, err)
					if serr := h.setAIPending(id, ch.c.Name, pendRevoke, true); serr != nil {
						cerrs = append(cerrs, serr)
					}
				} else if serr := h.setAIPending(id, ch.c.Name, pendRevoke, false); serr != nil {
					cerrs = append(cerrs, serr)
				}
			}
			if !ch.modeOnly {
				err := h.onChange(ctx, t, ch.c, ch.after)
				if err != nil {
					cerrs = append(cerrs, err)
				}
				// Owed to the next start while it fails.
				if serr := h.setAIPending(id, ch.c.Name, pendOnChange, err != nil); serr != nil {
					cerrs = append(cerrs, serr)
				}
			}
			if len(cerrs) > 0 {
				e := errors.Join(cerrs...)
				h.setAIError(id, ch.c.Name, e.Error())
				errs = append(errs, e)
				failed[ch.c.Name] = true
			} else if !failed[ch.c.Name] {
				h.setAIError(id, ch.c.Name, "")
			}
		}
	}
	if running && restarts {
		// Companions still owing a revoke_all / on_change (switched while
		// stopped, a failed one earlier): run now, render them after.
		done := map[string]bool{} // just run above: never twice in one request
		for _, ch := range changes {
			done[ch.c.Name] = !ch.owed
		}
		if again, perr := h.runPendingAI(ctx, t, done); perr != nil {
			errs = append(errs, perr)
		} else if again {
			if err := h.syncAIScopes(ctx); err != nil {
				errs = append(errs, err)
				all()
			}
			if upErr := h.composeUp(t); upErr != nil {
				errs = append(errs, statusErr500Wrap("compose up failed", upErr))
				all()
			}
			if err := h.WritePolicy(); err != nil && !errors.Is(err, errGateDirectory) {
				errs = append(errs, fmt.Errorf("gate files: %w", err))
				all()
			}
		}
	}
	h.setAIReapply(id, changes, failed)
	err = errors.Join(errs...)
	if running || err != nil {
		err = h.finishOp(id, OpAI, err, false)
	}
	if running {
		h.TriggerReconcile()
	}
	auditAll(err)
	v, verr := h.InstanceAI(id)
	if verr != nil && err == nil {
		err = verr
	}
	if err != nil {
		return nil, err
	}
	return &InstanceAIResult{InstanceAIView: v, Restarts: restarts, Warnings: []string{}}, nil
}

// defaultMode is a companion's mode before the admin chose one.
func defaultMode(c *templates.Companion) string {
	if c.DefaultMode != "" {
		return c.DefaultMode
	}
	if len(c.Modes) > 0 {
		return c.Modes[0]
	}
	return ""
}

// aiRefusalLocked is why t can't get AI support switched on now ("" =
// it can): deleting / restoring / a folder apply (pendingLocked),
// ai.unsupported, or an effective policy at LoA 3. Caller holds mu.
func (h *Hub) aiRefusalLocked(t *templates.Template) (int, string) {
	if err := h.pendingLocked(t.ID); err != nil {
		return http.StatusConflict, err.Error()
	}
	if why := h.aiTemplateRefusalLocked(t); why != "" {
		return http.StatusConflict, why
	}
	return 0, ""
}

// aiTemplateRefusalLocked is the refusal switching on and restoring
// share ("" = none): ai.unsupported, or an effective policy at LoA 3.
// Caller holds mu.
func (h *Hub) aiTemplateRefusalLocked(t *templates.Template) string {
	if !t.HasAIMCP() {
		unsupported := ""
		if t.Manifest.AI != nil {
			unsupported = t.Manifest.AI.Unsupported
		}
		return fmt.Sprintf("%s has no AI support: %s", t.ID, unsupported)
	}
	if policy.LoA(h.effectivePolicyLocked(t)) == 3 {
		return fmt.Sprintf("%s's sign-in policy %s", t.ID, mtlsRefusal)
	}
	return ""
}

// checkAliasFits refuses an alias longer than one DNS label (409).
func checkAliasFits(id, companion string) error {
	if !templates.AliasFits(id, companion) {
		return statusErr(http.StatusConflict, "the alias %s is longer than one DNS label (%d characters, at most %d): use a shorter instance id",
			templates.MCPAlias(id, companion), len(templates.MCPAlias(id, companion)), templates.MaxAliasLen)
	}
	return nil
}

// aiPlanStaleLocked: 409 when a change no longer matches the live view —
// the template gone, the companion gone, its identity mode or revoke hook
// changed, or its stored entry no longer the one planned from (pruned,
// flags changed). Caller holds mu.
func (h *Hub) aiPlanStaleLocked(id string, changes []aiChange) error {
	stale := statusErr(http.StatusConflict, "the template changed meanwhile: try again")
	lt := h.findLocked(id)
	if lt == nil {
		return stale
	}
	cur := h.st.AIInstances[id].Companions
	for _, ch := range changes {
		c := companionOf(lt, ch.c.Name)
		if c == nil || c.Identity.Mode != ch.c.Identity.Mode || c.Identity.Revoke != ch.c.Identity.Revoke {
			return stale
		}
		s, had := cur[ch.c.Name]
		if s.Mode == "" {
			s.Mode = defaultMode(ch.c)
		}
		if had != ch.hadEntry || s != ch.before {
			return stale
		}
	}
	return nil
}

// planAILocked turns u into changes, with every refusal (contract
// §15.11): 404 unknown companion, 400 a mode outside modes, 409 master
// off / pending / unsupported / LoA 3 / the alias too long. Caller holds
// mu (read).
func (h *Hub) planAILocked(t *templates.Template, u InstanceAIUpdate, retry map[string]bool, offDetail string) ([]aiChange, error) {
	if !t.HasAIMCP() {
		return nil, statusErr(http.StatusConflict, "%s has no AI support: %s", t.ID, t.Manifest.AI.Unsupported)
	}
	cur := h.st.AIInstances[t.ID].Companions
	var out []aiChange
	for _, name := range slices.Sorted(maps.Keys(u.Companions)) {
		cu := u.Companions[name]
		c := companionOf(t, name)
		if c == nil {
			return nil, &StatusError{Status: http.StatusNotFound, Err: fmt.Errorf("%s has no companion %s", t.ID, clipQuoted(name))}
		}
		before, had := cur[name]
		if before.Mode == "" {
			before.Mode = defaultMode(c)
		}
		after := before
		if cu.Enabled != nil {
			after.Enabled = *cu.Enabled
		}
		if cu.Mode != nil {
			after.Mode = *cu.Mode
		}
		if !slices.Contains(c.Modes, after.Mode) {
			return nil, statusErr(http.StatusBadRequest, "companion %s: mode %s is not one of %s", name, clipQuoted(after.Mode), strings.Join(c.Modes, ", "))
		}
		ch := aiChange{c: c, before: before, after: after, hadEntry: had, detail: offDetail, scope: aigate.CompanionScope(t.ID, c.Name)}
		if before == after && had {
			ch.reapply = retry[name]
		}
		ch.modeOnly = !before.Enabled && !after.Enabled && before.Mode != after.Mode
		if after.Enabled && before.Pruned {
			// A template update switched it off and its revocation hasn't
			// succeeded yet (revokePruned; fix round 1).
			return nil, statusErr(http.StatusConflict, "companion %s: a template update's revocation is still owed: see the doctor", name)
		}
		if after.Enabled {
			if !h.st.AI.Enabled {
				return nil, statusErr(http.StatusConflict, "AI support is off on this Portcullis: switch it on in Settings → AI first")
			}
			if code, why := h.aiRefusalLocked(t); why != "" {
				return nil, statusErr(code, "%s", why)
			}
			if c.Identity.Mode != templates.IdentityAppOAuth {
				if err := checkAliasFits(t.ID, c.Name); err != nil {
					return nil, err
				}
				ch.alias, ch.needsAlias = templates.MCPAlias(t.ID, c.Name), true
			}
		}
		out = append(out, ch)
	}
	return out, nil
}

// checkAliasFree: no container but the companion's own (this project,
// its service) answers ch's alias on portcullis-proxy (409). Docker
// unreachable is a 503 (fail closed).
func (h *Hub) checkAliasFree(ctx context.Context, t *templates.Template, ch aiChange) error {
	if h.engine == nil {
		return nil
	}
	cs, err := h.engine.ListContainers(ctx, nil)
	if err != nil {
		return statusErr(http.StatusServiceUnavailable, "can't check whether another container answers %s: %v", ch.alias, err)
	}
	for _, c := range cs {
		if c.Project() == projectName(t.ID) && c.Service() == ch.c.Service {
			continue
		}
		taken := strings.EqualFold(c.Name(), ch.alias)
		for _, n := range c.Networks[aiProxyNetwork] {
			taken = taken || strings.EqualFold(n, ch.alias)
		}
		if taken {
			return statusErr(http.StatusConflict, "container %s on %s already answers to %s: AI support can't be switched on", c.Name(), aiProxyNetwork, ch.alias)
		}
	}
	return nil
}

// ── scopes (contract §8) ─────────────────────────────

// companionScopesLocked are the mcp:* scopes of every switched-on
// app_token / identity_headers companion of every instance, by name.
// Caller holds mu (read).
func (h *Hub) companionScopesLocked() map[string]keycloak.MCPScope {
	out := map[string]keycloak.MCPScope{}
	for i := range h.instances {
		h.instanceScopesLocked(&h.instances[i], out)
	}
	return out
}

// instanceScopesLocked adds the mcp:* scopes of t's switched-on
// app_token / identity_headers companions to out, from t's hostnames (a
// hostname change passes the old and the new view; Task 15). Caller
// holds mu (read).
func (h *Hub) instanceScopesLocked(t *templates.Template, out map[string]keycloak.MCPScope) {
	if !t.HasAIMCP() {
		return
	}
	sw := h.st.AIInstances[t.ID].Companions
	for j := range t.Manifest.AI.MCP {
		c := &t.Manifest.AI.MCP[j]
		// A companion owing a revoke_all is off for its scope too.
		if !sw[c.Name].Enabled || sw[c.Name].RevokePending || c.Identity.Mode == templates.IdentityAppOAuth {
			continue
		}
		if s, ok := companionScope(t, c); ok {
			out[s.Name] = s
		}
	}
}

// companionScope is c's scope (ok false: its router has no hostname).
func companionScope(t *templates.Template, c *templates.Companion) (keycloak.MCPScope, bool) {
	host := NormalizeHost(t.Hosts[c.Router])
	if host == "" || !templates.ValidHostname(host) {
		return keycloak.MCPScope{}, false
	}
	return keycloak.MCPScope{
		Name:        aigate.CompanionScope(t.ID, c.Name),
		Audience:    aigate.CompanionURL(host, c.EffectivePublicPath()),
		ConsentText: "Use " + instanceName(t) + " (" + host + ") as you",
	}, true
}

// fixedScopesLocked are the three Portcullis-wide scopes. Caller holds mu.
func (h *Hub) fixedScopesLocked() map[string]keycloak.MCPScope {
	d := NormalizeHost(h.cfg.Domain)
	return map[string]keycloak.MCPScope{
		aigate.ScopeAll:    {Name: aigate.ScopeAll, Audience: aigate.AggregateURL(d), ConsentText: "Use all your Portcullis apps as you"},
		aigate.ScopeAdmin:  {Name: aigate.ScopeAdmin, Audience: aigate.AdminURL(d), ConsentText: "Manage Portcullis as you — administrator"},
		aigate.ScopePeople: {Name: aigate.ScopePeople, Audience: aigate.PeopleURL(d), ConsentText: "Use your Portcullis account as you"},
	}
}

// hubAIClients are the Hub's three AI clients with their settings.
func hubAIClients(a state.AISettings) []struct {
	id string
	c  state.AIClient
} {
	return []struct {
		id string
		c  state.AIClient
	}{{keycloak.AIClientIDs.Claude, a.Clients.Claude}, {keycloak.AIClientIDs.ClaudeCode, a.Clients.ClaudeCode}, {keycloak.AIClientIDs.Generic, a.Clients.Generic}}
}

// wantedAIScopes is the exact mcp:* optional scope set of AI client
// clientID, from state (contract §8): one of the Hub's three gets every
// switched-on companion scope, mcp:all, mcp:portcullis.people while
// PortcullisPeople is on and mcp:portcullis.admin only while it is
// offered with its admin flag and PortcullisAdmin is on; any other id (an
// ai_client) gets mcp:all only. Sorted. Takes mu (read).
func (h *Hub) wantedAIScopes(clientID string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.wantedAIScopesLocked(clientID)
}

func (h *Hub) wantedAIScopesLocked(clientID string) []string {
	out := []string{aigate.ScopeAll}
	var hubClient *state.AIClient
	for _, c := range hubAIClients(h.st.AI) {
		if c.id == clientID {
			cc := c.c
			hubClient = &cc
		}
	}
	if hubClient == nil {
		return out
	}
	for name := range h.companionScopesLocked() {
		out = append(out, name)
	}
	if h.st.AI.PortcullisPeople {
		out = append(out, aigate.ScopePeople)
	}
	if h.st.AI.PortcullisAdmin && hubClient.Offered && hubClient.Admin {
		out = append(out, aigate.ScopeAdmin)
	}
	sort.Strings(out)
	return out
}

// applyAIScopes makes Keycloak follow state after changes: every wanted
// scope ensured (companion and fixed, each before any client names it),
// the offered Hub clients' exact sets applied (a client that doesn't
// exist yet or isn't the Hub's is left to the sync loop, logged), then
// the scopes of switched-off companions deleted. Never under mu.
func (h *Hub) applyAIScopes(ctx context.Context, changes []aiChange) error {
	return h.applyAIScopesFor(ctx, changes, false)
}

// syncAIScopes makes Keycloak follow state with no change to drop (a
// companion whose owed revoke_all just succeeded gets its scope).
func (h *Hub) syncAIScopes(ctx context.Context) error { return h.applyAIScopesFor(ctx, nil, true) }

func (h *Hub) applyAIScopesFor(ctx context.Context, changes []aiChange, force bool) error {
	var drop []string
	touches := force
	for _, ch := range changes {
		if ch.c.Identity.Mode != templates.IdentityAppOAuth && !ch.modeOnly && !ch.modeChanged() {
			touches = true
		}
	}
	if !touches {
		return nil
	}
	kc := h.aiKeycloak()
	if kc == nil {
		return errors.New("Keycloak: the AI scope calls are not configured")
	}
	// One pass at a time over the clients and scopes (ai_clients.go),
	// each reading state after taking the lock.
	h.aiKCMu.Lock()
	defer h.aiKCMu.Unlock()
	h.mu.RLock()
	plan := h.aiScopePlanLocked()
	for _, ch := range changes {
		if !ch.after.Enabled && ch.c.Identity.Mode != templates.IdentityAppOAuth {
			if _, still := plan.ensure[ch.scope]; !still {
				drop = append(drop, ch.scope)
			}
		}
	}
	h.mu.RUnlock()
	errs := ensureAIScopes(ctx, kc, plan.ensure)
	for _, w := range plan.clients {
		if !w.offered {
			continue
		}
		// The exact set (12b ruling): Keycloak refuses a scope that doesn't
		// exist (the client is left as it was, the error returned); one
		// whose ensure failed but that exists stays attached.
		err := kc.SetOptionalScopes(ctx, w.id, w.scopes)
		var conflict *keycloak.ConflictError
		switch {
		case err == nil:
		case errors.Is(err, keycloak.ErrClientNotFound), errors.Is(err, keycloak.ErrNotAIClient), errors.As(err, &conflict):
			log.Printf("ai: client %s not attached (%v): the directory sync applies its scopes", w.id, err)
		default:
			errs = append(errs, fmt.Errorf("Keycloak: client %s scopes: %w", w.id, err))
		}
	}
	for _, name := range drop {
		if err := kc.DeleteMCPScope(ctx, name); err != nil {
			errs = append(errs, fmt.Errorf("Keycloak: deleting client scope %s: %w", name, err))
			h.oweScopeDropLocked(name)
		} else {
			delete(h.aiOwedDrops, name)
		}
	}
	return errors.Join(errs...)
}

// ── hooks (contract §15.5) ───────────────────────────

type aiRevokeAllIn struct {
	Action string `json:"action"`
	Prefix string `json:"prefix"`
}

type aiOnChangeIn struct {
	Action    string `json:"action"`
	Enabled   bool   `json:"enabled"`
	Mode      string `json:"mode"`
	Companion string `json:"companion"`
}

// revokeAll runs c's revoke hook with revoke_all (none: nothing to do —
// identity_headers holds no credential): the companion's entries marked
// revoking first, removed only after success. A failure is a 502 with
// the redacted stderr.
func (h *Hub) revokeAll(ctx context.Context, t *templates.Template, c *templates.Companion) error {
	if c.Identity.Revoke == "" {
		return nil
	}
	// app_oauth: everyone's AI clients' tokens are revoked; oauth-seen.json
	// is kept (T27: recorded people who leave still get their own revoke).
	return h.revokeAllWith(ctx, t, c.Name, c.Identity.Revoke)
}

// dropAIEntries removes every Hub-side credential entry of a companion
// (the gate stops using them at its next reload).
func (h *Hub) dropAIEntries(id, companion string) error {
	for _, e := range h.creds().Entries() {
		if e.Instance == id && e.Companion == companion {
			if err := h.creds().Remove(e.Instance, e.Companion, e.User); err != nil {
				return statusErr(http.StatusInternalServerError, "companion %s: dropping its credentials: %v", companion, err)
			}
		}
	}
	return nil
}

// AI pending flags (state.AICompanion).
const (
	pendRevoke   = "revoke"
	pendOnChange = "on_change"
)

// setAIPending sets or clears a companion's RevokePending (pendRevoke) or
// OnChangePending (pendOnChange); saved, undone on a failed save.
func (h *Hub) setAIPending(id, companion, which string, pending bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	a, ok := h.st.AIInstances[id]
	if !ok {
		return nil
	}
	c, ok := a.Companions[companion]
	if !ok {
		return nil
	}
	before := c
	if which == pendRevoke {
		c.RevokePending = pending
	} else {
		c.OnChangePending = pending
	}
	if c == before {
		return nil
	}
	a.Companions = maps.Clone(a.Companions)
	a.Companions[companion] = c
	h.st.AIInstances[id] = a
	if err := h.saveStateLocked(); err != nil {
		a.Companions[companion] = before
		h.st.AIInstances[id] = a
		return err
	}
	return nil
}

// aiReapplyOf: the companions of id whose last change failed after its
// state save (the same request re-applies them; memory only).
func (h *Hub) aiReapplyOf(id string) map[string]bool {
	h.aiErrMu.Lock()
	defer h.aiErrMu.Unlock()
	return maps.Clone(h.aiReapply[id])
}

// setAIReapply records which of changes failed after the save.
func (h *Hub) setAIReapply(id string, changes []aiChange, failed map[string]bool) {
	h.aiErrMu.Lock()
	defer h.aiErrMu.Unlock()
	if h.aiReapply == nil {
		h.aiReapply = map[string]map[string]bool{}
	}
	m := h.aiReapply[id]
	if m == nil {
		m = map[string]bool{}
	}
	for _, ch := range changes {
		if failed[ch.c.Name] {
			m[ch.c.Name] = true
		} else {
			delete(m, ch.c.Name)
		}
	}
	h.aiReapply[id] = m
}

// runPendingAI runs what t's companions owe (caller holds lockApp and
// aiLock; the containers are up, a companion owing a revoke_all is not
// rendered): revoke_all for RevokePending — success clears it, a failure
// keeps it (and skips the companion's on_change), sets LastError and is
// returned —, then on_change for OnChangePending with the current state
// (success clears it). again: a switched-on companion became renderable
// (or its env changes) — compose up and the gate file again.
func (h *Hub) runPendingAI(ctx context.Context, t *templates.Template, skip map[string]bool) (again bool, err error) {
	h.mu.RLock()
	var pending []*templates.Companion
	states := map[string]state.AICompanion{}
	for name, c := range h.st.AIInstances[t.ID].Companions {
		if (!c.RevokePending && !c.OnChangePending) || skip[name] {
			continue
		}
		if comp := companionOf(t, name); comp != nil {
			pending = append(pending, comp)
			states[name] = c
		}
	}
	h.mu.RUnlock()
	sort.Slice(pending, func(i, j int) bool { return pending[i].Name < pending[j].Name })
	var errs []error
	for _, c := range pending {
		s := states[c.Name]
		if s.RevokePending {
			if rerr := h.revokeAll(ctx, t, c); rerr != nil {
				log.Printf("ai: %s/%s: the owed revoke_all failed (the companion stays off): %v", t.ID, c.Name, rerr)
				h.setAIError(t.ID, c.Name, rerr.Error())
				errs = append(errs, rerr)
				continue
			}
			if serr := h.setAIPending(t.ID, c.Name, pendRevoke, false); serr != nil {
				errs = append(errs, serr)
				continue
			}
			if c.Identity.Mode == templates.IdentityAppOAuth {
				// A restore brought the app's data back: the revoked
				// leavers' tokens too (T27). The reconcile replays them.
				if rerr := h.oauthSeenSetReplay(t.ID + "/" + c.Name); rerr != nil {
					log.Printf("ai: %s/%s: marking the revoked leavers owed again failed: %v", t.ID, c.Name, rerr)
				}
				h.TriggerAIReconcile()
			}
			s.RevokePending = false
			again = again || s.Enabled
		}
		h.setAIError(t.ID, c.Name, "")
		if s.OnChangePending {
			if oerr := h.onChange(ctx, t, c, s); oerr != nil {
				h.setAIError(t.ID, c.Name, oerr.Error())
				errs = append(errs, oerr)
				continue
			}
			if serr := h.setAIPending(t.ID, c.Name, pendOnChange, false); serr != nil {
				errs = append(errs, serr)
			}
		}
	}
	return again, errors.Join(errs...)
}

// aiPendingWait bounds how long a start waits for the instance's AI lock
// (a mint or revoke holding it) before the owed hooks are left for the
// next start (recorded, never silent).
var aiPendingWait = 30 * time.Second

// pendingAIAfterStart is startUp's step (after the up and the start
// hooks, under lockApp): the owed revoke_alls and on_changes. While
// UpdateInstanceAI applies this instance (aiApplying: it holds the AI
// lock and runs them itself after its up) nothing; else it waits up to
// aiPendingWait for the AI lock — a timeout is logged, set as each owed
// companion's LastError and recorded as a failed op ai (unless the
// start's own op records over it); the flags stay, the next start runs
// them. A companion they made
// renderable is applied by a queued restart.
func (h *Hub) pendingAIAfterStart(t *templates.Template) {
	h.mu.RLock()
	var owed []string
	for name, c := range h.st.AIInstances[t.ID].Companions {
		if c.RevokePending || c.OnChangePending {
			owed = append(owed, name)
		}
	}
	h.mu.RUnlock()
	if len(owed) == 0 {
		return
	}
	if _, applying := h.aiApplying.Load(t.ID); applying {
		return
	}
	var unlock func()
	ok := true
	if _, held := h.aiHeld.Load(t.ID); held {
		// The lifecycle operation this start belongs to (it holds
		// lockApp, so nobody else can have set aiHeld) holds the AI lock.
		unlock = func() {}
	} else {
		unlock, ok = h.aiTryLock(t.ID, aiPendingWait)
	}
	if !ok {
		err := fmt.Errorf("the owed AI hooks (revoke_all / on_change) didn't run: the AI lock was busy for %s; they run at the next start (the companions stay off until then)", aiPendingWait)
		log.Printf("ai: %s: %v", t.ID, err)
		for _, name := range owed {
			h.setAIError(t.ID, name, err.Error())
		}
		h.finishOpGuarded(t.ID, OpAI, err, false, true)
		return
	}
	again, err := h.runPendingAI(context.Background(), t, nil)
	unlock()
	if err != nil {
		h.finishOpGuarded(t.ID, OpAI, err, false, true)
	}
	if again {
		if err := h.syncAIScopes(context.Background()); err != nil {
			log.Printf("ai: %s: scopes after the owed revoke_all: %v", t.ID, err)
			h.finishOpGuarded(t.ID, OpAI, err, false, true)
		}
		h.writePolicyLogged()
		tc := *t
		h.goBackground(func() { h.Restart(tc) })
	}
}

// onChange runs the template's ai.on_change hook (none: nothing).
func (h *Hub) onChange(ctx context.Context, t *templates.Template, c *templates.Companion, s state.AICompanion) error {
	if t.Manifest.AI.OnChange == "" {
		return nil
	}
	// What the app is told is what it may do now: switched on (and not
	// owing a revoke_all) in the current state, with the master switch on
	// and the policy below LoA 3 (12b); the per-companion state is kept.
	h.mu.RLock()
	live := h.st.AIInstances[t.ID].Companions[c.Name]
	lt := h.findLocked(t.ID)
	if lt == nil {
		lt = t
	}
	enabled := s.Enabled && live.Enabled && !live.RevokePending && h.aiOnLocked(lt)
	h.mu.RUnlock()
	stdin, _ := json.Marshal(aiOnChangeIn{Action: "on_change", Enabled: enabled, Mode: s.Mode, Companion: c.Name})
	out, u := h.runAIHook(ctx, t, t.Manifest.AI.OnChange, stdin)
	clear(out)
	if !u.OK {
		return &StatusError{Status: http.StatusBadGateway, Err: fmt.Errorf("companion %s: on_change failed: %s", c.Name, u.Error)}
	}
	return nil
}

// runAIHook runs ai hook name of t once, outside the settings delivery
// engine (G5, G6): argv verbatim in a running container of its service,
// the hook's user and timeout, stdin as given, stdout and stderr apart
// (Engine.ExecStdinSplit). On success stdout goes back to the caller only
// — never logged, stored or put in the UnitResult; the caller parses and
// zeroes it. On failure stdout is zeroed and the unit's error holds the
// exit code and stderr only, redacted (the instance's secrets and every
// piece of stdout) and then clipped. Never parsed for PORTCULLIS-REPORT.
func (h *Hub) runAIHook(ctx context.Context, t *templates.Template, name string, stdin []byte) (stdout []byte, res UnitResult) {
	stdout, _, res = h.runAIHookExit(ctx, t, name, stdin)
	return stdout, res
}

// runAIHookExit is runAIHook with the hook's exit code (-1: it didn't
// run to an exit — not found, no container, an Engine error or a
// timeout).
func (h *Hub) runAIHookExit(ctx context.Context, t *templates.Template, name string, stdin []byte) (stdout []byte, exit int, res UnitResult) {
	exit = -1
	res = UnitResult{Unit: "ai:" + name, At: time.Now().UTC()}
	var hk *templates.Hook
	for i := range t.Manifest.Hooks {
		if t.Manifest.Hooks[i].Name == name && t.Manifest.Hooks[i].IsAI() {
			hk = &t.Manifest.Hooks[i]
		}
	}
	if hk == nil {
		res.Error = fmt.Sprintf("hook %s: not an ai hook of the template", clip(name, 64))
		return nil, exit, res
	}
	if h.engine == nil {
		res.Error = fmt.Sprintf("hook %s: no Docker engine", name)
		return nil, exit, res
	}
	cs, _, err := h.appContainers(ctx, t)
	if err != nil {
		res.Error = clipRunes(h.secretRedactor(t.ID)(fmt.Sprintf("hook %s: listing the %s containers: %v", name, hk.Service, err)), unitErrorMax)
		return nil, exit, res
	}
	c := runningContainer(cs, hk.Service)
	if c == nil {
		res.Error = fmt.Sprintf("hook %s: no running container of service %s", name, hk.Service)
		return nil, exit, res
	}
	r, err := h.engine.ExecStdinSplit(ctx, c.ID, docker.ExecInput{Cmd: slices.Clone(hk.Command), User: hk.User, Stdin: append(slices.Clone(stdin), '\n'), Timeout: hk.EffectiveTimeout()})
	var why string
	switch {
	case err != nil:
		why = "failed: " + err.Error()
	case r == nil:
		why = "failed: no result"
	case r.TimedOut:
		why = fmt.Sprintf("timed out after %s (the process may still run)", hk.EffectiveTimeout())
	case r.ExitCode != 0:
		exit = r.ExitCode
		why = fmt.Sprintf("exited %d", r.ExitCode)
	default:
		res.OK, res.Message = true, "exit 0"
		return r.Stdout, 0, res
	}
	var out, errText []byte
	if r != nil {
		out, errText = r.Stdout, r.Stderr
	}
	redact := h.secretRedactor(t.ID, stdoutPieces(out))
	clear(out)
	msg := "hook " + name + ": " + why
	if s := strings.TrimSpace(string(errText)); s != "" {
		msg += ": stderr: " + s
	}
	res.Error = clipRunes(redact(msg), unitErrorMax)
	return nil, exit, res
}

// stdoutPieces are the redaction values of a hook's stdout: the whole of
// it, each line and each token (split on space, quotes and JSON
// punctuation) of 4 bytes or more.
func stdoutPieces(out []byte) []string {
	if len(out) == 0 {
		return nil
	}
	s := string(out)
	vals := []string{s, strings.TrimSpace(s)}
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			vals = append(vals, l)
		}
	}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(`"'{}[],:;`, r) }) {
		if len(f) >= 4 {
			vals = append(vals, f)
		}
	}
	return vals
}

// setAIError records (msg non-empty) or clears a companion's last error
// (memory only: already redacted and clipped).
func (h *Hub) setAIError(id, companion, msg string) {
	h.aiErrMu.Lock()
	defer h.aiErrMu.Unlock()
	k := id + "/" + companion
	if msg == "" {
		delete(h.aiErrs, k)
		return
	}
	if h.aiErrs == nil {
		h.aiErrs = map[string]string{}
	}
	h.aiErrs[k] = clipRunes(msg, unitErrorMax)
}

func (h *Hub) aiError(id, companion string) string {
	h.aiErrMu.Lock()
	defer h.aiErrMu.Unlock()
	return h.aiErrs[id+"/"+companion]
}

// ── the AI tab ───────────────────────────────────────

// InstanceAI is instance id's AI tab. The population is read outside mu
// (a directory that can't be read counts 0).
func (h *Hub) InstanceAI(id string) (*InstanceAIView, error) {
	if h.Template(id) == nil {
		return nil, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), directoryStateTimeout)
	m, merr := h.membership(ctx)
	cancel()
	if merr != nil {
		m = nil
	}
	creds := h.creds().Entries()
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.findLocked(id)
	if t == nil {
		return nil, ErrNotFound
	}
	a := t.Manifest.AI
	v := &InstanceAIView{Unsupported: a.Unsupported, Alternative: a.Alternative, MasterOff: !h.st.AI.Enabled,
		Companions: []CompanionView{}, Providers: slices.Clone(h.st.AIInstances[id].Providers)}
	if v.Providers == nil {
		v.Providers = []string{}
	}
	slices.Sort(v.Providers)
	if ch := chatOf(t); ch != nil {
		v.ProviderKinds = maps.Clone(ch.ProviderKinds)
	}
	if a.Unsupported == "" {
		_, v.Refused = h.aiRefusalLocked(t)
	}
	pop := 0
	if m != nil && h.populationWhyLocked(t) == "" {
		pop = len(h.populationLocked(t, m).People)
	}
	sw := h.st.AIInstances[id].Companions
	seen, _ := h.oauthSeenRead()
	for i := range a.MCP {
		c := &a.MCP[i]
		s := sw[c.Name]
		if s.Mode == "" {
			s.Mode = defaultMode(c)
		}
		cv := CompanionView{Name: c.Name, Label: c.Label, Kind: c.Kind, IdentityMode: c.Identity.Mode, Upstream: c.Upstream,
			Source: c.Source, Modes: slices.Clone(c.Modes), Mode: s.Mode, Enabled: s.Enabled, LastError: h.aiError(id, c.Name),
			Population: pop, Confirm: append([]string{}, c.Tools.Confirm...), Never: append([]string{}, c.Tools.Never...),
			OwnRules: c.Identity.Mode == templates.IdentityAppOAuth}
		if cv.OwnRules {
			cv.Unmatched = slices.Clone(seen.Unmatched[id+"/"+c.Name])
		}
		if host := NormalizeHost(t.Hosts[c.Router]); host != "" {
			cv.URL = aigate.CompanionURL(host, c.EffectivePublicPath())
		}
		for _, e := range creds {
			if e.Instance == id && e.Companion == c.Name {
				if e.State == aigate.StateRevoking {
					cv.Revoking++
				} else {
					cv.Credentials++
				}
			}
		}
		switch {
		case s.Pruned:
			// Switched off by a template update; its revoke_all is owed
			// (AIRevokeProblems), whatever else the state says.
			cv.Status = "revoking"
		case cv.LastError != "":
			cv.Status = "failed"
		case !s.Enabled && s.RevokePending:
			// Off; its app-side credentials are revoked at the next start.
			cv.Status = "revoking"
		case !s.Enabled:
			cv.Status = "off"
		case s.RevokePending:
			// Off until the next start's revoke_all succeeds.
			cv.Status = "revoke_pending"
		case v.MasterOff || v.Refused != "":
			cv.Status = "unavailable"
		default:
			cv.Status = "on"
		}
		v.Companions = append(v.Companions, cv)
	}
	return v, nil
}

// ── policy saves (G43) ───────────────────────────────

// enabledCompanionsLocked are t's switched-on companions, sorted.
func (h *Hub) enabledCompanionsLocked(id string) []string {
	var out []string
	for name, c := range h.st.AIInstances[id].Companions {
		if c.Enabled {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// loaWithLocked is t's effective LoA were it configured with p (and,
// signIn non-nil, that sign-in mode). Caller holds mu.
func (h *Hub) loaWithLocked(t *templates.Template, p policy.AuthPolicy, signIn *string) int {
	capab := h.accessLocked(t).Capability
	if auth := &t.Manifest.Auth; signIn != nil && auth.HasNativeLogin() {
		method := "forward-auth"
		if *signIn == SignInNative && auth.NativeLogin.AllowWithoutGateway {
			method = auth.Method
		}
		capab = policy.CapabilityFor(method)
	}
	return policy.LoA(policy.Resolve(policy.Normalize(p), capab).Policy)
}

// aiOffForSaveLocked: the companions a settings save u switches off
// first (its policy reaches LoA 3). Caller holds mu.
func (h *Hub) aiOffForSaveLocked(t *templates.Template, u SettingsUpdate) []string {
	if u.Policy == nil && !u.Inherit && u.SignIn == nil {
		return nil
	}
	on := h.enabledCompanionsLocked(t.ID)
	if len(on) == 0 {
		return nil
	}
	p := h.accessLocked(t).Configured
	switch {
	case u.Inherit:
		p = h.st.Default()
	case u.Policy != nil:
		p = *u.Policy
	}
	if h.loaWithLocked(t, p, u.SignIn) != 3 {
		return nil
	}
	return on
}

// aiOffWarning is the preview / save warning for companions switched off
// by a policy needing mTLS.
func aiOffWarning(id string, companions []string) string {
	return fmt.Sprintf("%s: AI support for %s is switched off first: the policy %s", id, strings.Join(companions, ", "), mtlsRefusal)
}

// switchAIOff switches companions of id off (audited ai.disable with
// detail). Used by policy saves before they commit.
func (h *Hub) switchAIOff(ctx context.Context, id string, companions []string, actor directory.Actor, detail string) error {
	u := InstanceAIUpdate{Companions: map[string]CompanionUpdate{}}
	off := false
	for _, c := range companions {
		u.Companions[c] = CompanionUpdate{Enabled: &off}
	}
	_, err := h.updateInstanceAI(ctx, id, u, actor, detail)
	return err
}

// defaultPolicyAIOffLocked: instance id → its switched-on companions that
// a new Hub default p would put at LoA 3 (inheriting instances only).
// Caller holds mu.
func (h *Hub) defaultPolicyAIOffLocked(p policy.AuthPolicy) map[string][]string {
	out := map[string][]string{}
	for i := range h.instances {
		t := &h.instances[i]
		if _, own := h.st.AuthPolicies[t.ID]; own {
			continue
		}
		on := h.enabledCompanionsLocked(t.ID)
		if len(on) > 0 && h.loaWithLocked(t, p, nil) == 3 {
			out[t.ID] = on
		}
	}
	return out
}

// DefaultPolicyAIWarnings lists what saving p as the Hub default would
// switch off first (the preview, G43).
func (h *Hub) DefaultPolicyAIWarnings(p policy.AuthPolicy) []string {
	h.mu.RLock()
	off := h.defaultPolicyAIOffLocked(p)
	h.mu.RUnlock()
	var out []string
	for _, id := range slices.Sorted(maps.Keys(off)) {
		out = append(out, aiOffWarning(id, off[id]))
	}
	return out
}

// SetDefaultPolicyAs is SetDefaultPolicy for an actor: every inheriting
// instance the new default puts at LoA 3 gets AI support switched off
// first (audited ai.disable "policy needs mTLS"); a switch-off that fails
// refuses the save (nothing saved). Returns the warnings.
func (h *Hub) SetDefaultPolicyAs(p policy.AuthPolicy, actor directory.Actor) (bool, []string, error) {
	if msg := policy.CapabilityFor("forward-auth").Check(p); msg != "" {
		return false, nil, statusErr(400, "default policy: %s", msg)
	}
	h.mu.RLock()
	off := h.defaultPolicyAIOffLocked(policy.Normalize(p))
	h.mu.RUnlock()
	warnings := []string{}
	for _, id := range slices.Sorted(maps.Keys(off)) {
		if err := h.switchAIOff(context.Background(), id, off[id], actor, aiPolicyOffDetail); err != nil {
			var oe *OpError
			if !errors.As(err, &oe) {
				return false, warnings, fmt.Errorf("the default policy was not saved: switching AI support off on %s first failed: %w", id, err)
			}
			// Off in state and in the gate already; the rest is recorded.
			warnings = append(warnings, fmt.Sprintf("%s: switching AI support off: %s", id, err.Error()))
		}
		warnings = append(warnings, aiOffWarning(id, off[id]))
	}
	changed, err := h.SetDefaultPolicy(p)
	return changed, warnings, err
}
