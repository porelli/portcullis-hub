package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Revoke on leave (plan 3 Task 9; contract §13.16 "Who is revoked" and
// "When", §13.9 "Removals are immediate"; F27, F28, F30, F31, F56).
//
// One holder check (CheckCredentialHolders) serves every trigger: the
// directory's OnChange (Hub-made changes: member removal, user or group
// deletion), the rule evaluator's OnEvaluated (its 60 s tick and every
// kick, so edits made straight in LLDAP are caught) and a create's
// re-check (F30). TriggerCredentialCheck coalesces them, never
// debounces; RunCredentialChecks runs them one at a time. Each check:
//
//  1. reads the directory outside mu; unavailable: nothing changes;
//  2. judges every active credential with credentialRevocations (the pure
//     function the doctor's canary shares) and revokes those through the
//     shared path (revokeCredentialsN → applyRevocation: hook ≤ 8 s, else
//     kill + background restart; audited credential.revoke_leave);
//  3. compares, per enabled person_secret instance, the population and
//     the expanded members of each group / groups option with what the
//     last delivered data file was built from (deliveredDoc.Members): a
//     removal delivers at once (the template's hook ends the sessions,
//     §13.17), an addition keeps the 60 s debounce.

// credentialCheckTimeout bounds one holder check (the directory read and
// the revocations' live applies run on their own bounds as well).
const credentialCheckTimeout = 2 * time.Minute

// membersPopulation is deliveredDoc.Members' key for the population (an
// option key never starts with "@").
const membersPopulation = "@population"

// Revocation is one active credential the holder check revokes (F56).
type Revocation struct {
	Instance string
	Key      string
	User     string
	// ID is the credential judged: one created since is left alone.
	ID string
	// Reason: state.CredentialReasonLeave or CredentialReasonDeleted.
	Reason string
}

// credentialRevocations is the holder check (§13.16, F31, F56), pure:
// with the directory snapshot m, every active credential in creds
// (instance → person_secret key → user) of an instance in tmpls is
// revoked when its holder is
//
//   - absent from LLDAP: deleted;
//   - present with a non-empty uuid other than the recorded one (the
//     account was deleted and created again): deleted;
//   - outside the instance's population: leave. An access group LLDAP
//     doesn't have makes the population empty: everyone (fail closed).
//
// An empty current uuid revokes nothing on that ground
// (unverifiableCredentials lists it for the doctor). Keys that aren't
// person_secret options of the template are not judged. Sorted by
// instance, key, user.
//
// An instance in creds without a view in tmpls (its template is missing)
// has every active credential revoked (leave): fail closed.
//
// person_secret templates are router-less with group access (F1), so
// their population doesn't depend on the sign-in mode.
func credentialRevocations(m *directory.Membership, creds map[string]map[string]map[string]state.Credential, tmpls map[string]*templates.Template) []Revocation {
	var out []Revocation
	for _, id := range slices.Sorted(maps.Keys(creds)) {
		t := tmpls[id]
		if t == nil {
			// No view (the template is missing): nothing can say who may
			// hold one — everyone goes (fail closed).
			for _, key := range slices.Sorted(maps.Keys(creds[id])) {
				for _, u := range slices.Sorted(maps.Keys(creds[id][key])) {
					if c := creds[id][key][u]; c.Active() {
						out = append(out, Revocation{Instance: id, Key: key, User: u, ID: c.ID, Reason: state.CredentialReasonLeave})
					}
				}
			}
			continue
		}
		opts := personSecretOptions(t)
		if len(opts) == 0 {
			continue
		}
		in := populationSet(t, m)
		keys := make([]string, 0, len(opts))
		for _, o := range opts {
			keys = append(keys, o.Key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			users := creds[id][key]
			for _, u := range slices.Sorted(maps.Keys(users)) {
				c := users[u]
				if !c.Active() {
					continue
				}
				reason := ""
				_, present := m.Users[u]
				cur := m.UUIDs[u]
				switch {
				case !present:
					reason = state.CredentialReasonDeleted
				case cur != "" && cur != c.UUID:
					reason = state.CredentialReasonDeleted
				case !in[u]:
					reason = state.CredentialReasonLeave
				}
				if reason != "" {
					out = append(out, Revocation{Instance: id, Key: key, User: u, ID: c.ID, Reason: reason})
				}
			}
		}
	}
	return out
}

// unverifiableCredentials are the active credentials (of person_secret
// options in tmpls) whose holder LLDAP lists with an empty uuid: the
// doctor's unverifiable_account input (F31). Sorted.
func unverifiableCredentials(m *directory.Membership, creds map[string]map[string]map[string]state.Credential, tmpls map[string]*templates.Template) []doctor.UnverifiableIn {
	var out []doctor.UnverifiableIn
	for _, id := range slices.Sorted(maps.Keys(tmpls)) {
		t := tmpls[id]
		if t == nil {
			continue
		}
		for _, key := range slices.Sorted(maps.Keys(creds[id])) {
			if personSecretOption(t, key) == nil {
				continue
			}
			for _, u := range slices.Sorted(maps.Keys(creds[id][key])) {
				if _, present := m.Users[u]; present && creds[id][key][u].Active() && m.UUIDs[u] == "" {
					out = append(out, doctor.UnverifiableIn{Instance: id, Key: key, User: u})
				}
			}
		}
	}
	return out
}

// populationSet is t's population in m as a set.
func populationSet(t *templates.Template, m *directory.Membership) map[string]bool {
	in := map[string]bool{}
	for _, p := range populationIn(t, m, false).People {
		in[p.User] = true
	}
	return in
}

// credentialTemplatesLocked are the instances holding credential
// metadata, by id (pointers into h.instances: use under mu only).
// Caller holds mu (read).
func (h *Hub) credentialTemplatesLocked() map[string]*templates.Template {
	out := map[string]*templates.Template{}
	for id := range h.st.Credentials {
		if t := h.findLocked(id); t != nil {
			out[id] = t
		}
	}
	return out
}

// TriggerCredentialCheck asks RunCredentialChecks for a holder check:
// non-blocking and coalesced (one more check after the running one),
// never debounced. Safe from directory.Service.OnChange / OnEvaluated
// and under any Hub lock.
func (h *Hub) TriggerCredentialCheck() {
	select {
	case h.credKick <- struct{}{}:
	default:
	}
}

// RunCredentialChecks runs a holder check on each TriggerCredentialCheck
// until ctx is done. It has no ticker of its own: the evaluator's tick
// (OnEvaluated) drives the periodic check (spec call 23).
func (h *Hub) RunCredentialChecks(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.credKick:
		}
		cctx, cancel := context.WithTimeout(ctx, credentialCheckTimeout)
		n, err := h.CheckCredentialHolders(cctx)
		cancel()
		switch {
		case err != nil && ctx.Err() == nil:
			if msg := err.Error(); msg != h.credCheckErr {
				log.Printf("credentials: holder check not done (nothing revoked; the next one retries): %v", err)
				h.credCheckErr = msg
			}
		case err == nil:
			h.credCheckErr = ""
		}
		if n > 0 {
			log.Printf("credentials: holder check revoked %d file-sharing password(s)", n)
		}
	}
}

// CheckCredentialHolders is one holder check (see the top of this
// file): how many credentials it revoked. The directory unavailable: its
// error, nothing changed. A revocation whose save failed is still
// applied live; the errors are returned joined.
func (h *Hub) CheckCredentialHolders(ctx context.Context) (int, error) {
	m, err := h.membership(ctx)
	if err != nil {
		return 0, err
	}
	h.mu.RLock()
	tmpls := h.credentialTemplatesLocked()
	revs := credentialRevocations(m, h.st.Credentials, tmpls)
	byInst := map[string][]revocation{}
	for _, r := range revs {
		byInst[r.Instance] = append(byInst[r.Instance], revocation{key: r.Key, user: r.User, by: purgeActor, reason: r.Reason, id: r.ID})
	}
	for id, rs := range byInst {
		t := tmpls[id]
		if t == nil {
			log.Printf("ERROR: credentials: %s: holds %d active file-sharing password(s) but its template is missing: revoking them all and stopping its project (fail closed; people must create new ones)", id, len(rs))
			continue
		}
		if populationIn(t, m, false).Why == WhyNoAccess {
			// F31: LLDAP answers without the access group — everyone goes
			// (fail closed, irreversible: each person creates again).
			log.Printf("ERROR: credentials: %s: Users & Groups answers but has no access group %s: revoking all %d active file-sharing password(s) of the instance (fail closed; people must create new ones)", id, accessGroupOf(t), len(rs))
		}
	}
	current := map[string]map[string][]string{}
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil && len(personSecretOptions(t)) > 0 {
			current[id] = h.expandedMembersLocked(t, m)
		}
	}
	h.mu.RUnlock()
	if h.testHookHolderJudged != nil {
		h.testHookHolderJudged()
	}

	// The revocations, one instance per goroutine (each live apply may
	// take its lock wait and hook timeout).
	var (
		wg    sync.WaitGroup
		resMu sync.Mutex
		total int
		errs  []error
	)
	for _, id := range slices.Sorted(maps.Keys(byInst)) {
		rs := byInst[id]
		wg.Go(func() {
			n, err := h.revokeCredentialsN(ctx, id, rs)
			resMu.Lock()
			defer resMu.Unlock()
			total += n
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", id, err))
			}
		})
	}
	wg.Wait()

	// F28: share readers / writers and the population against the last
	// delivered file. An instance just revoked has its credential
	// delivery queued already (files and hooks).
	for _, id := range slices.Sorted(maps.Keys(current)) {
		if byInst[id] != nil {
			continue
		}
		prev := h.loadDelivered(id).Members
		if prev == nil {
			// Never recorded: unknown counts as changed (the debounced run
			// records it; an armed timer is kept).
			h.queueDelivery(id, TriggerMembership, settings.EffectNone, settingsDebounce)
			continue
		}
		removed, added := membersDiff(prev, current[id])
		switch {
		case removed:
			h.queueDelivery(id, TriggerMembership, settings.EffectNone, 0)
		case added:
			h.queueDelivery(id, TriggerMembership, settings.EffectNone, settingsDebounce)
		}
	}
	return total, errors.Join(errs...)
}

// expandedMembersLocked is what t's data files are built from that
// grants file access (F28): the population (membersPopulation) and, per
// instance group / groups option, the members of the groups it names
// within the population (expired memberships dropped). Sorted, never
// nil lists. Caller holds mu (read).
//
// Task 10 binds group values by id and delivers these lists in the data
// file (render.expand_members); this comparison then matches the file
// exactly. Until then it follows the names the values hold.
func (h *Hub) expandedMembersLocked(t *templates.Template, m *directory.Membership) map[string][]string {
	pop := populationIn(t, m, false)
	in := map[string]bool{}
	people := make([]string, 0, len(pop.People))
	for _, p := range pop.People {
		in[p.User] = true
		people = append(people, p.User)
	}
	out := map[string][]string{membersPopulation: people}
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.EffectiveScope() != templates.ScopeInstance || (o.Type != templates.TypeGroup && o.Type != templates.TypeGroups) {
			continue
		}
		set := map[string]bool{}
		if v, ok := h.effectiveValue(t, o, h.st.Settings[t.ID]); ok {
			for _, n := range groupNames(v) {
				g := placeholderGroup(t, n)
				for _, u := range m.Groups[g].Members {
					if in[u] && !m.Expired[u][g] {
						set[u] = true
					}
				}
			}
		}
		out[o.Key] = slices.Sorted(maps.Keys(set))
		if out[o.Key] == nil {
			out[o.Key] = []string{}
		}
	}
	return out
}

// groupNames are the group names a group (string) or groups ([]Value)
// value holds.
func groupNames(v any) []string {
	switch x := v.(type) {
	case string:
		if x != "" {
			return []string{x}
		}
	case []settings.Value:
		var out []string
		for _, it := range x {
			if s, ok := it.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	}
	return nil
}

// membersDiff compares the members a file was delivered with (prev) and
// the current ones: removed — someone in prev is gone from their list
// (or the list is gone); added — someone new.
func membersDiff(prev, cur map[string][]string) (removed, added bool) {
	for k, us := range prev {
		c, ok := cur[k]
		for _, u := range us {
			if !ok || !slices.Contains(c, u) {
				removed = true
			}
		}
	}
	for k, us := range cur {
		p := prev[k]
		for _, u := range us {
			if !slices.Contains(p, u) {
				added = true
			}
		}
	}
	return removed, added
}

// membersRecordable: a run's units let it record the members its files
// were built from — every data file and hook unit it reports is OK
// (written or unchanged). A failed hook keeps the old record, so the
// next check delivers again.
func membersRecordable(units []UnitResult) bool {
	for _, u := range units {
		if (strings.HasPrefix(u.Unit, "file:") || strings.HasPrefix(u.Unit, "hook:")) && !u.OK {
			return false
		}
	}
	return true
}
