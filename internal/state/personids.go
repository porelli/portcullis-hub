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
// increase) and every id handed out.
type PersonIDPool struct {
	Next    int             `json:"next" yaml:"next"`
	Entries []PersonIDEntry `json:"entries" yaml:"entries"`
}

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
// on it (like checkFolders). A next past the range is an exhausted (or
// advanced, F8) pool, not corrupt.
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
		if p.Next < r[0] {
			return bad("next %d is below %d", p.Next, r[0])
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
