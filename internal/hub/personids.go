package hub

import (
	"fmt"
	"log"
	"net/http"
	"sort"
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
// state.yaml never hands out an id that already owns files. In memory:
// the reports and scans feed it again after a restart, and the boot-time
// epoch check advances the pools (AdvancePools).
func (h *Hub) NoteSeenOwners(pool string, ids []int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.noteSeenOwnersLocked(pool, ids)
}

func (h *Hub) noteSeenOwnersLocked(pool string, ids []int) {
	if len(ids) == 0 {
		return
	}
	set := h.seenOwners[pool]
	if set == nil {
		set = map[int]bool{}
		h.seenOwners[pool] = set
	}
	for _, id := range ids {
		set[id] = true
	}
}

// AdvancePools moves every pool's next forward by `by` (the boot-time
// secrets check found .epoch missing or different: core was restored and
// state.yaml may have rewound, F8). Pools state.yaml doesn't have yet are
// advanced from their range's start. Saved; a failed save changes
// nothing. Call it before any allocation.
func (h *Hub) AdvancePools(by int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	before := h.snapshotPoolsLocked()
	h.advancePoolsLocked(by)
	return h.commitPoolsLocked(true, before)
}

// advancePoolsLocked is AdvancePools without the save (caller holds mu
// and saves).
func (h *Hub) advancePoolsLocked(by int) {
	if by <= 0 {
		return
	}
	names := make([]string, 0, len(h.idRanges))
	for name := range h.idRanges {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := h.st.PersonIDs[name].Clone()
		from := max(p.Next, h.idRanges[name][0])
		p.Next = from + by
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
	used := map[int]bool{}
	for _, e := range p.Entries {
		used[e.ID] = true
	}
	where := ""
	if instance != "" {
		where = " (" + instance + ")"
	}
	ids := map[string]int{}
	changed := false
	now := time.Now().UTC()
	for _, person := range people {
		user := person.User
		uuid := uuids[user]
		if uuid == "" {
			log.Printf("person-ids: %s has no LLDAP uuid%s: no %s id, left out", user, where, pool)
			continue
		}
		if _, done := ids[user]; done {
			continue
		}
		cur := -1
		for i, e := range p.Entries {
			if e.User == user && e.RetiredAt == nil {
				cur = i
				break
			}
		}
		if cur >= 0 && p.Entries[cur].UUID == uuid {
			ids[user] = p.Entries[cur].ID
			continue
		}
		id := max(p.Next, r[0])
		for id <= r[1] && (state.ReservedPersonID(id) || used[id] || h.seenOwners[pool][id]) {
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
