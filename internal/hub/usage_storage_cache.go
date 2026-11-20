package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
)

// The storage measurer's cache (contract §11.11): <data>/usage/storage.json,
// 0600, at most 4 MiB and 2,048 entries, written atomically. A file that is
// too large, holds too many entries, has another version or isn't valid
// JSON is dropped (logged once) and means "never measured".
const (
	storageCacheVersion    = 1
	storageCacheMaxBytes   = 4 << 20
	storageCacheMaxEntries = 2048
)

// storageFile is storage.json.
type storageFile struct {
	Version int                     `json:"version"`
	LastRun *time.Time              `json:"last_run"`
	Entries map[string]storageEntry `json:"entries"`
}

// storageEntry is one measured (or listed) target, keyed "<kind>:<target>".
type storageEntry struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	// Owners: the instances (or "core") whose data it is.
	Owners        []string  `json:"owners"`
	AllocBytes    *int64    `json:"alloc_bytes"`
	ApparentBytes *int64    `json:"apparent_bytes"`
	Partial       bool      `json:"partial"`
	PartialReason string    `json:"partial_reason,omitempty"`
	MeasuredAt    time.Time `json:"measured_at"`
	DurationMS    int64     `json:"duration_ms"`
	Error         string    `json:"error,omitempty"`
	// Dev / Free / Total: the filesystem underneath (from the report).
	Dev   uint64 `json:"dev,omitempty"`
	Free  uint64 `json:"free_bytes,omitempty"`
	Total uint64 `json:"total_bytes,omitempty"`
}

func (h *Hub) storagePath() string { return filepath.Join(h.cfg.DataDir, "usage", "storage.json") }

// storageLoadLocked reads the cache once (caller holds storeMu).
func (h *Hub) storageLoadLocked() *storageFile {
	s := h.usage
	if s.store != nil {
		return s.store
	}
	s.store = &storageFile{Version: storageCacheVersion, Entries: map[string]storageEntry{}}
	f, err := os.Open(h.storagePath())
	if errors.Is(err, os.ErrNotExist) {
		return s.store
	}
	if err != nil {
		log.Printf("usage: the storage cache can't be read (%v): never measured", errors.Unwrap(err))
		return s.store
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, storageCacheMaxBytes+1))
	var sf storageFile
	switch {
	case err != nil:
		log.Printf("usage: the storage cache can't be read: dropped")
	case len(b) > storageCacheMaxBytes:
		log.Printf("usage: the storage cache is over %d bytes: dropped", storageCacheMaxBytes)
	case json.Unmarshal(b, &sf) != nil:
		log.Printf("usage: the storage cache isn't valid JSON: dropped")
	case sf.Version != storageCacheVersion:
		log.Printf("usage: the storage cache has version %d, want %d: dropped", sf.Version, storageCacheVersion)
	case len(sf.Entries) > storageCacheMaxEntries:
		log.Printf("usage: the storage cache has %d entries (at most %d): dropped", len(sf.Entries), storageCacheMaxEntries)
	default:
		if sf.Entries == nil {
			sf.Entries = map[string]storageEntry{}
		}
		s.store = &sf
	}
	return s.store
}

// storageSaveLocked writes sf atomically (0600). A failure keeps the
// previous file; the caller reports it.
func (h *Hub) storageSaveLocked(sf *storageFile) error {
	if len(sf.Entries) > storageCacheMaxEntries {
		return fmt.Errorf("%d entries (at most %d)", len(sf.Entries), storageCacheMaxEntries)
	}
	b, err := json.Marshal(sf)
	if err != nil {
		return err
	}
	if len(b) > storageCacheMaxBytes {
		return fmt.Errorf("%d bytes (at most %d)", len(b), storageCacheMaxBytes)
	}
	if err := fsutil.MkdirAll(filepath.Dir(h.storagePath()), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(h.storagePath(), b, 0o600)
}

// storageSnapshot is a copy of the cache.
func (h *Hub) storageSnapshot() storageFile {
	s := h.usage
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	sf := h.storageLoadLocked()
	out := storageFile{Version: sf.Version, LastRun: sf.LastRun, Entries: make(map[string]storageEntry, len(sf.Entries))}
	for k, e := range sf.Entries {
		out.Entries[k] = e
	}
	return out
}
