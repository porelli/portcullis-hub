package agent

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Tombstones: the instance ids the agent held a bundle of and removed
// (<data>/tombstones.json, 0600). An unbundled Down (unbundledDown) is
// served only for those and quarantined ids: no caller can fish for, or
// stop, an unrelated portcullis-* project.
const maxTombstones = 1000

func (a *API) tombstonesPath() string { return filepath.Join(a.cfg.DataDir, "tombstones.json") }

func (a *API) loadTombstones() {
	a.tombs = map[string]time.Time{}
	b, err := os.ReadFile(a.tombstonesPath())
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		err = json.Unmarshal(b, &a.tombs)
	}
	if err != nil {
		log.Printf("tombstones: %s is unreadable (%v): unbundled downs refused until a bundle is removed again", a.tombstonesPath(), err)
		a.tombs = map[string]time.Time{}
	}
}

// tombstoneLocked records id (caller holds mu), keeping the newest maxTombstones.
func (a *API) tombstoneLocked(id string) {
	a.tombs[id] = time.Now().UTC()
	if len(a.tombs) > maxTombstones {
		ids := make([]string, 0, len(a.tombs))
		for k := range a.tombs {
			ids = append(ids, k)
		}
		sort.Slice(ids, func(i, j int) bool { return a.tombs[ids[i]].Before(a.tombs[ids[j]]) })
		for _, k := range ids[:len(ids)-maxTombstones] {
			delete(a.tombs, k)
		}
	}
	b, err := json.Marshal(a.tombs)
	if err == nil {
		err = writeFileAtomic(a.tombstonesPath(), b)
	}
	if err != nil {
		log.Printf("tombstones: recording %s: %v", id, err)
	}
}
