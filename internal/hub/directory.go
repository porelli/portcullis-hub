package hub

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"sort"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/policy"
)

// DirectorySnapshot is what the policy writer publishes from ONE
// directory read: the pending membership expiries (contract §4
// expiring), the user-attributes.json document (§4.1; nil: no file) and
// the Membership the gate file is built from (§15.4; nil: none), so the
// policy file and mcp-gate.json never disagree.
type DirectorySnapshot struct {
	Expiring   []policy.Expiring
	Attrs      *policy.UserAttributesDocument
	Membership *directory.Membership
}

// DirectoryState reads a DirectorySnapshot. An error makes the writer
// keep the last published expiries, the existing attributes file and the
// last gate file's populations (fail closed).
type DirectoryState func(ctx context.Context) (DirectorySnapshot, error)

// directoryStateTimeout bounds one DirectoryState call.
const directoryStateTimeout = 10 * time.Second

// SetDirectory wires the directory into the Hub: state feeds WritePolicy,
// attrSync (Keycloak attribute mappers, may be nil) runs after each
// directory-triggered policy write. Call before Init and RunDirectorySync.
func (h *Hub) SetDirectory(state DirectoryState, attrSync func(ctx context.Context) error) {
	h.policyWriteMu.Lock()
	defer h.policyWriteMu.Unlock()
	h.dirState, h.attrSync = state, attrSync
}

// dirRead is one directory read for WritePolicy.
type dirRead struct {
	expiring  []policy.Expiring
	attrs     *policy.UserAttributesDocument
	keepAttrs bool // leave user-attributes.json as it is
	// m is the gate file's membership (nil with mErr: unavailable; nil
	// without: not needed).
	m    *directory.Membership
	mErr error
}

// directoryState runs the hook for WritePolicy (caller holds
// policyWriteMu; never under mu). Without a hook (tests, no directory)
// the gate's membership comes from People, only when the gate needs it.
func (h *Hub) directoryState() dirRead {
	if h.dirState == nil {
		m, err := h.gateMembership()
		return dirRead{expiring: []policy.Expiring{}, m: m, mErr: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), directoryStateTimeout)
	defer cancel()
	snap, err := h.dirState(ctx)
	if err != nil {
		log.Printf("auth-policy: directory unavailable, keeping the last published membership expiries and user attributes: %v", err)
		r := dirRead{expiring: h.publishedExpiring(), keepAttrs: true}
		if h.gateWanted() {
			r.mErr = err // the gate keeps the last populations and retries
		}
		return r
	}
	r := dirRead{expiring: normalizeExpiring(snap.Expiring), attrs: snap.Attrs, m: snap.Membership}
	if r.m == nil && h.gateWanted() {
		r.mErr = errors.New("the directory gave no membership")
	}
	return r
}

// publishedExpiring is the expiring list last written: in memory, else
// from the policy file on disk (after a restart), else empty.
func (h *Hub) publishedExpiring() []policy.Expiring {
	if h.lastExpiring != nil {
		return h.lastExpiring
	}
	var doc struct {
		Expiring []policy.Expiring `json:"expiring"`
	}
	b, err := os.ReadFile(h.policyPath())
	switch {
	case errors.Is(err, os.ErrNotExist):
		return []policy.Expiring{}
	case err != nil:
		log.Printf("auth-policy: ERROR: cannot read the previous policy file to keep its membership expiries (%v) — publishing NONE until the directory is readable again", err)
		return []policy.Expiring{}
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		log.Printf("auth-policy: ERROR: the previous policy file is corrupt (%v) — its membership expiries are lost; publishing NONE until the directory is readable again", err)
		return []policy.Expiring{}
	}
	if doc.Expiring == nil {
		return []policy.Expiring{}
	}
	return normalizeExpiring(doc.Expiring)
}

// epoch replaces an unparseable expiry time: already past, so group-gate
// denies the membership (fail closed).
var epoch = time.Unix(0, 0).UTC()

// normalizeExpiring keeps one entry per (user, group): the earliest. An
// unparseable at is logged and published as the Unix epoch (denies).
// Sorted by (at, group, user); never nil.
func normalizeExpiring(in []policy.Expiring) []policy.Expiring {
	type key struct{ user, group string }
	earliest := map[key]policy.Expiring{}
	at := map[key]time.Time{}
	for _, e := range in {
		t, err := time.Parse(time.RFC3339, e.At)
		if err != nil {
			log.Printf("auth-policy: WARNING: expiry of %s in %s has an invalid time %q — publishing it as already expired", e.User, e.Group, e.At)
			t = epoch
			e.At = epoch.Format(time.RFC3339)
		}
		k := key{e.User, e.Group}
		if old, ok := at[k]; !ok || t.Before(old) {
			at[k], earliest[k] = t, e
		}
	}
	out := make([]policy.Expiring, 0, len(earliest))
	for _, e := range earliest {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ta, tb := at[key{a.User, a.Group}], at[key{b.User, b.Group}]
		if !ta.Equal(tb) {
			return ta.Before(tb)
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		return a.User < b.User
	})
	return out
}

// DirectoryStateOf adapts the directory service to DirectoryState (one
// Publish call: expiries, attributes and the membership of one read).
func DirectoryStateOf(d *directory.Service) DirectoryState {
	return func(ctx context.Context) (DirectorySnapshot, error) {
		pub, err := d.Publish(ctx, time.Now().UTC())
		if err != nil {
			return DirectorySnapshot{}, err
		}
		exp := make([]policy.Expiring, 0, len(pub.Expiring))
		for _, e := range pub.Expiring {
			exp = append(exp, policy.Expiring{User: e.User, Group: e.Group, At: e.At.UTC().Format(time.RFC3339)})
		}
		fields := make([]policy.AttrField, 0, len(pub.Fields))
		for _, f := range pub.Fields {
			fields = append(fields, policy.AttrField{Name: f.Name, Multi: f.Multi})
		}
		// The hosts section (header deliveries) is merged in WritePolicy.
		doc := policy.BuildUserAttributes(fields, pub.Users, nil)
		return DirectorySnapshot{Expiring: exp, Attrs: &doc, Membership: pub.Membership}, nil
	}
}

// TriggerDirectorySync asks RunDirectorySync for a policy write and an
// attribute-mapper sync soon. Non-blocking and coalesced: safe to call
// from directory.Service.OnChange.
func (h *Hub) TriggerDirectorySync() {
	select {
	case h.dirKick <- struct{}{}:
	default:
	}
}

const (
	directorySyncDebounce = time.Second
	directorySyncRetry    = time.Minute
	attrSyncTimeout       = 2 * time.Minute
	accessSyncInterval    = 10 * time.Minute
)

// RunDirectorySync writes the policy once at start and after each
// TriggerDirectorySync (debounced), until ctx is done; each write queues
// the membership deliveries (TriggerMembershipDelivery) and is
// followed by an attribute-mapper sync in a separate loop, so a slow
// Keycloak never delays a policy write. A failed mapper sync is logged
// and retried after a minute.
func (h *Hub) RunDirectorySync(ctx context.Context) {
	attrKick := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.runAttrSync(ctx, attrKick)
	}()
	defer func() { <-done }()
	for {
		h.writePolicyLogged()
		// Membership may have changed: per-person, per-group and
		// person-entered deliveries follow (debounced per instance).
		h.TriggerMembershipDelivery()
		select {
		case attrKick <- struct{}{}:
		default:
		}
		// A gate file kept because the directory failed (§15.4): retried.
		var retry <-chan time.Time
		if h.gateStale.Load() {
			retry = time.After(directorySyncRetry)
		}
		select {
		case <-ctx.Done():
			return
		case <-retry:
		case <-h.dirKick:
			select {
			case <-ctx.Done():
				return
			case <-time.After(directorySyncDebounce):
			}
			select {
			case <-h.dirKick:
			default:
			}
		}
	}
}

// runAttrSync runs attrSync and then SyncClientAccess on each kick
// (coalesced), on retry and every accessSyncInterval (the realm's browser
// flow may change under the access flows; groups may be created in LLDAP
// directly).
func (h *Hub) runAttrSync(ctx context.Context, kick <-chan struct{}) {
	var retry <-chan time.Time
	lastFreshErr := "" // logged once per distinct error
	tick := time.NewTicker(accessSyncInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
		case <-retry:
		case <-tick.C:
		}
		retry = nil
		h.policyWriteMu.Lock()
		sync, ensureFresh := h.attrSync, h.freshAuthEnsure
		h.policyWriteMu.Unlock()
		sctx, cancel := context.WithTimeout(ctx, attrSyncTimeout)
		var err error
		if sync != nil {
			if err = sync(sctx); err != nil && ctx.Err() == nil {
				log.Printf("keycloak: attribute mapper sync failed (retrying in %s): %v", directorySyncRetry, err)
			}
		}
		// The fresh-auth client (contract §8): created and re-asserted on
		// every sync. freshAuthReady follows the last ensure: while it
		// fails (a conflicting client, Keycloak down) checkFreshAuth
		// refuses every proof.
		var ferr error
		if ensureFresh != nil {
			ferr = ensureFresh(sctx)
			h.freshAuthReady.Store(ferr == nil)
			if ferr != nil && ctx.Err() == nil {
				if msg := ferr.Error(); msg != lastFreshErr {
					log.Printf("keycloak: fresh-auth client not in place (retrying every %s): %v", directorySyncRetry, ferr)
					lastFreshErr = msg
				}
			} else if ferr == nil {
				lastFreshErr = ""
			}
		}
		// The AI clients (contract §8), like the fresh-auth client: while
		// the master switch is on each offered one is re-asserted, its
		// health recorded and the gate file rewritten when it changed
		// (errors logged once per distinct text inside).
		_, cerr := h.aiClientPass(sctx)
		aerr := h.SyncClientAccess(sctx)
		cancel()
		if aerr != nil && ctx.Err() == nil {
			log.Printf("keycloak: access role sync incomplete (retrying in %s): %v", directorySyncRetry, aerr)
		}
		if (err != nil || aerr != nil || ferr != nil || cerr != nil) && ctx.Err() == nil {
			retry = time.After(directorySyncRetry)
		}
	}
}

// DirectoryApps lists every instance's groups for the Users page
// (group suggestions and "used by") and the guarding rules: each
// instance's privileged groups are the groups named in rows of its
// privileged options (state only, no network: the directory calls this
// under its own lock, order s.mu → Hub.mu).
func (h *Hub) DirectoryApps() []directory.App {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]directory.App, 0, len(h.instances))
	for i := range h.instances {
		t := &h.instances[i]
		out = append(out, directory.App{ID: t.ID, Name: instanceName(t), Enabled: t.Enabled,
			AccessGroup: t.Manifest.Auth.AccessGroup, AdminGroup: t.Manifest.Auth.AdminGroup,
			PrivilegedGroups: h.privilegedGroupsLocked(t)})
	}
	return out
}
