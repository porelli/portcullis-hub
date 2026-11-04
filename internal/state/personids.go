package state

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/templates"
)

// PersonIDEntry is one id a person_id pool handed out (contract §13.16):
// keyed by the lowercase username and the LLDAP account uuid. A retired
// entry (the account was deleted and created again) keeps its id: it is
// never handed out again.
type PersonIDEntry struct {
	User      string     `json:"user" yaml:"user"`
	UUID      string     `json:"uuid" yaml:"uuid"`
	ID        int        `json:"id" yaml:"id"`
	RetiredAt *time.Time `json:"retired_at,omitempty" yaml:"retired_at,omitempty"`
}

// PersonIDPool is one Hub-wide pool: the next id to try (ids only
// increase; at most the range end + 1, which means exhausted), every id
// handed out, and the ids a hook report or a per-person tree scan listed
// as file owners (F8: never allocated; sorted by id, deduplicated, inside
// the range, at most MaxSeenOwners — the oldest go first).
type PersonIDPool struct {
	Next    int             `json:"next" yaml:"next"`
	Entries []PersonIDEntry `json:"entries" yaml:"entries"`
	Seen    []SeenOwner     `json:"seen_owners,omitempty" yaml:"seen_owners,omitempty"`
}

// SeenOwner is one id seen owning files, and when it was first seen.
type SeenOwner struct {
	ID int       `json:"id" yaml:"id"`
	At time.Time `json:"at" yaml:"at"`
}

// MaxSeenOwners bounds a pool's seen owners.
const MaxSeenOwners = 4096

// Clone is a deep copy.
func (p PersonIDPool) Clone() PersonIDPool {
	out := PersonIDPool{Next: p.Next, Entries: make([]PersonIDEntry, len(p.Entries))}
	for i, e := range p.Entries {
		if e.RetiredAt != nil {
			at := *e.RetiredAt
			e.RetiredAt = &at
		}
		out.Entries[i] = e
	}
	if p.Seen != nil {
		out.Seen = append([]SeenOwner(nil), p.Seen...)
	}
	return out
}

// ReservedPersonID reports whether a person id is never allocated,
// whatever a pool's range (F7): system ids 0–999, 1000 (the first
// user on most hosts), 10000–10099 (core's container uids: the Hub's
// 10001, enroll's 10002, …), 65534 (nobody) and 60000–60999 (the
// shared-folder gids, §14.1).
func ReservedPersonID(id int) bool {
	switch {
	case id <= 1000, id >= 10000 && id <= 10099, id == 65534,
		id >= FolderGIDMin && id <= FolderGIDMax:
		return true
	}
	return false
}

// checkPersonIDs refuses a corrupt person_ids pool: the Hub doesn't start
// on it (like checkFolders). next = range end + 1 is an exhausted pool,
// not corrupt.
func (s *AppState) checkPersonIDs() error {
	pools := make([]string, 0, len(s.PersonIDs))
	for name := range s.PersonIDs {
		pools = append(pools, name)
	}
	sort.Strings(pools)
	for _, name := range pools {
		r, ok := templates.PersonIDPools[name]
		if !ok {
			return fmt.Errorf("person_ids: %q is not a pool", name)
		}
		p := s.PersonIDs[name]
		bad := func(format string, args ...any) error {
			return fmt.Errorf("person_ids: %s: %s", name, fmt.Sprintf(format, args...))
		}
		if p.Next < r[0] || p.Next > r[1]+1 {
			return bad("next %d is outside %d-%d", p.Next, r[0], r[1]+1)
		}
		if len(p.Seen) > MaxSeenOwners {
			return bad("more than %d seen owners", MaxSeenOwners)
		}
		for i, o := range p.Seen {
			switch {
			case o.ID < r[0] || o.ID > r[1]:
				return bad("seen owner %d is outside %d-%d", o.ID, r[0], r[1])
			case i > 0 && o.ID <= p.Seen[i-1].ID:
				return bad("seen owners not strictly ascending at %d", o.ID)
			case o.At.IsZero():
				return bad("seen owner %d has no time", o.ID)
			}
		}
		ids := map[int]bool{}
		uuids := map[string]bool{}
		active := map[string]bool{}
		for _, e := range p.Entries {
			switch {
			case e.User == "" || e.User != strings.ToLower(e.User) || templates.HasControlChars(e.User):
				return bad("user %q", e.User)
			case e.UUID == "" || templates.HasControlChars(e.UUID):
				return bad("%s: no uuid", e.User)
			case e.ID < r[0] || e.ID > r[1]:
				return bad("%s: id %d is outside %d-%d", e.User, e.ID, r[0], r[1])
			case ReservedPersonID(e.ID):
				return bad("%s: id %d is reserved", e.User, e.ID)
			case e.ID >= p.Next:
				return bad("%s: id %d is not below next %d", e.User, e.ID, p.Next)
			case ids[e.ID]:
				return bad("id %d is handed out twice", e.ID)
			case uuids[e.UUID]:
				return bad("uuid %s has two entries", e.UUID)
			case e.RetiredAt == nil && active[e.User]:
				return bad("%s has two ids in use", e.User)
			}
			ids[e.ID], uuids[e.UUID] = true, true
			if e.RetiredAt == nil {
				active[e.User] = true
			}
		}
	}
	return nil
}
