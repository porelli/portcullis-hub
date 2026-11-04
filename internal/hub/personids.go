package hub

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Person ids (contract §13.16, plan 3 Task 5): Hub-wide pools of stable
// per-person numbers (pool posix_uid: the uid a file server runs each
// person's files as). An id is keyed by (lowercase username, LLDAP
// uuid): a re-created account (another uuid) retires the old id and gets
// a new one, so it never owns a former account's files. Ids only
// increase and are never reused; a pool never rewinds (F8).

// PoolRewindStep is how far every pool's next advances when the secrets
// epoch says core was restored (F8, contract §13.16).
const PoolRewindStep = 1000

// ensurePersonIDs allocates the ids instance's person_id options need for
// people (F9): one short write-locked section, before the delivery's
// render and before a start's data files, saving state.yaml once if
// anything was allocated. A person without a uuid gets no id (logged)
// and is left out; the others proceed. An error (an exhausted pool, a
// failed save) changes nothing.
func (h *Hub) ensurePersonIDs(instance string, people []settings.Person, uuids map[string]string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.findLocked(instance)
	if t == nil {
		return nil
	}
	pools := map[string]bool{}
	for _, o := range t.Manifest.Options() {
		if o.Type == templates.TypePersonID {
			pools[o.Pool] = true
		}
	}
	if len(pools) == 0 {
		return nil
	}
	names := make([]string, 0, len(pools))
	for p := range pools {
		names = append(names, p)
	}
	sort.Strings(names)
	before := h.snapshotPoolsLocked()
	changed := false
	for _, pool := range names {
		_, c, err := h.allocPersonIDsLocked(pool, people, uuids, instance)
		if err != nil {
			h.st.PersonIDs = before
			return err
		}
		changed = changed || c
	}
	return h.commitPoolsLocked(changed, before)
}

// allocPersonIDs gives every person with a uuid their id in pool (under
// mu, saved once if anything was allocated) and answers user → id.
func (h *Hub) allocPersonIDs(pool string, people []settings.Person, uuids map[string]string) (map[string]int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	before := h.snapshotPoolsLocked()
	ids, changed, err := h.allocPersonIDsLocked(pool, people, uuids, "")
	if err != nil {
		h.st.PersonIDs = before
		return nil, err
	}
	if err := h.commitPoolsLocked(changed, before); err != nil {
		return nil, err
	}
	return ids, nil
}

// PersonID is user's id in pool (false: none yet).
func (h *Hub) PersonID(pool, user string) (int, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.personIDLocked(pool, user)
}

// personIDLocked is PersonID for a caller holding mu (the renderers).
func (h *Hub) personIDLocked(pool, user string) (int, bool) {
	for _, e := range h.st.PersonIDs[pool].Entries {
		if e.User == user && e.RetiredAt == nil {
			return e.ID, true
		}
	}
	return 0, false
}

// NoteSeenOwners records ids a hook report or a per-person tree scan
// listed as file owners (F8): allocation skips them, so a rewound
// state.yaml never hands out an id that already owns files. Kept in the
// pool in state.yaml (sorted, deduplicated, ids inside the pool's range
// only, at most state.MaxSeenOwners — the oldest go first), saved when
// anything new was seen; a failed save changes nothing. Never call it
// with a docker call in flight under mu (it takes mu).
func (h *Hub) NoteSeenOwners(pool string, ids []int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.idRanges[pool]
	if !ok {
		return statusErr(http.StatusInternalServerError, "unknown person id pool %s", pool)
	}
	before := h.snapshotPoolsLocked()
	p := h.st.PersonIDs[pool].Clone()
	if p.Next == 0 {
		p.Next = r[0]
	}
	known := map[int]bool{}
	for _, o := range p.Seen {
		known[o.ID] = true
	}
	now := time.Now().UTC()
	added := 0
	for _, id := range ids {
		if id < r[0] || id > r[1] || known[id] {
			continue
		}
		known[id] = true
		p.Seen = append(p.Seen, state.SeenOwner{ID: id, At: now})
		added++
	}
	if added == 0 {
		return nil
	}
	if over := len(p.Seen) - state.MaxSeenOwners; over > 0 {
		// The oldest out (ties: the lower id).
		sort.SliceStable(p.Seen, func(i, j int) bool {
			if !p.Seen[i].At.Equal(p.Seen[j].At) {
				return p.Seen[i].At.Before(p.Seen[j].At)
			}
			return p.Seen[i].ID < p.Seen[j].ID
		})
		p.Seen = p.Seen[over:]
	}
	sort.Slice(p.Seen, func(i, j int) bool { return p.Seen[i].ID < p.Seen[j].ID })
	h.st.PersonIDs[pool] = p
	return h.commitPoolsLocked(true, before)
}

// maxPoolAdvance bounds AdvancePools' step.
const maxPoolAdvance = 10 * PoolRewindStep

// AdvancePools moves every pool's next forward by `by` (the boot-time
// secrets check found .epoch missing or different: core was restored and
// state.yaml may have rewound, F8), at most to the range end + 1
// (exhausted). Pools state.yaml doesn't have yet are advanced from their
// range's start. Once per process: a second call does nothing. Saved; a
// failed save changes nothing (and doesn't count). Call it before any
// allocation.
func (h *Hub) AdvancePools(by int) error {
	if by <= 0 || by > maxPoolAdvance {
		return statusErr(http.StatusInternalServerError, "pool advance %d is outside 1-%d", by, maxPoolAdvance)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.poolsAdvanced {
		return nil
	}
	before := h.snapshotPoolsLocked()
	h.advancePoolsLocked(by)
	if err := h.commitPoolsLocked(true, before); err != nil {
		return err
	}
	h.poolsAdvanced = true
	return nil
}

// advancePoolsLocked is AdvancePools' change without the save or the
// once-only flag (caller holds mu, checked by, and saves).
func (h *Hub) advancePoolsLocked(by int) {
	names := make([]string, 0, len(h.idRanges))
	for name := range h.idRanges {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		r := h.idRanges[name]
		p := h.st.PersonIDs[name].Clone()
		from := max(p.Next, r[0])
		p.Next = min(from+by, r[1]+1)
		h.st.PersonIDs[name] = p
		log.Printf("person-ids: core restore detected (secrets epoch): pool %s next %d -> %d (a pool never rewinds)", name, from, p.Next)
	}
}

// allocPersonIDsLocked allocates without saving (caller holds mu, saves
// on changed and puts the snapshot back on an error). instance only
// names the log lines.
func (h *Hub) allocPersonIDsLocked(pool string, people []settings.Person, uuids map[string]string, instance string) (map[string]int, bool, error) {
	r, ok := h.idRanges[pool]
	if !ok {
		return nil, false, statusErr(http.StatusInternalServerError, "unknown person id pool %s", pool)
	}
	p := h.st.PersonIDs[pool].Clone()
	used, seen := map[int]bool{}, map[int]bool{}
	for _, e := range p.Entries {
		used[e.ID] = true
	}
	for _, o := range p.Seen {
		seen[o.ID] = true
	}
	where := ""
	if instance != "" {
		where = " (" + instance + ")"
	}
	ids := map[string]int{}
	changed := false
	now := time.Now().UTC()
	for _, person := range people {
		user := strings.ToLower(person.User)
		uuid := uuids[person.User]
		if uuid == "" {
			uuid = uuids[user]
		}
		switch {
		case user == "" || templates.HasControlChars(user):
			log.Printf("person-ids: a username %q isn't usable%s: no %s id", user, where, pool)
			continue
		case uuid == "":
			log.Printf("person-ids: %s has no LLDAP uuid%s: no %s id, left out", user, where, pool)
			continue
		case templates.HasControlChars(uuid):
			log.Printf("person-ids: %s's LLDAP uuid has control characters%s: no %s id, left out", user, where, pool)
			continue
		}
		if _, done := ids[user]; done {
			continue
		}
		cur, own := -1, -1
		for i, e := range p.Entries {
			if e.User == user && e.RetiredAt == nil {
				cur = i
			}
			if e.UUID == uuid {
				own = i
			}
		}
		if own >= 0 {
			e := &p.Entries[own]
			switch {
			case e.User != user:
				// Same LLDAP account under another name: never a second entry.
				log.Printf("person-ids: %s's LLDAP uuid already has %s id %d as %s%s: left out", user, pool, e.ID, e.User, where)
				continue
			case own == cur:
				ids[user] = e.ID
				continue
			}
			// The same account again (e.g. LLDAP restored): its own id back.
			if cur >= 0 {
				at := now
				p.Entries[cur].RetiredAt = &at
				log.Printf("person-ids: %s's LLDAP account changed back%s: %s id %d retired", user, where, pool, p.Entries[cur].ID)
			}
			e.RetiredAt = nil
			ids[user] = e.ID
			changed = true
			log.Printf("person-ids: %s gets their own %s id %d back%s", user, pool, e.ID, where)
			continue
		}
		id := max(p.Next, r[0])
		for id <= r[1] && (state.ReservedPersonID(id) || used[id] || seen[id]) {
			id++
		}
		if id > r[1] {
			return nil, false, statusErr(http.StatusConflict, "uid pool %s is exhausted", pool)
		}
		if cur >= 0 {
			at := now
			p.Entries[cur].RetiredAt = &at
			log.Printf("person-ids: %s's LLDAP account changed%s: %s id %d retired", user, where, pool, p.Entries[cur].ID)
		}
		p.Entries = append(p.Entries, state.PersonIDEntry{User: user, UUID: uuid, ID: id})
		p.Next = id + 1
		used[id] = true
		ids[user] = id
		changed = true
		log.Printf("person-ids: %s gets %s id %d%s", user, pool, id, where)
	}
	if changed {
		h.st.PersonIDs[pool] = p
	}
	return ids, changed, nil
}

// snapshotPoolsLocked is a deep copy of every pool (the undo of a failed
// allocation or save).
func (h *Hub) snapshotPoolsLocked() map[string]state.PersonIDPool {
	out := make(map[string]state.PersonIDPool, len(h.st.PersonIDs))
	for k, p := range h.st.PersonIDs {
		out[k] = p.Clone()
	}
	return out
}

// commitPoolsLocked saves state.yaml when changed; a failed save puts
// before back.
func (h *Hub) commitPoolsLocked(changed bool, before map[string]state.PersonIDPool) error {
	if !changed {
		return nil
	}
	if err := h.saveStateLocked(); err != nil {
		h.st.PersonIDs = before
		return fmt.Errorf("person ids not saved: %w", err)
	}
	return nil
}
