package hub

// The revoked-keys list (contract §18.10, plan C21): hub_data/ssh/
// revoked.json (0600, atomic). Public keys only; the public list and the
// bundles carry the keys, the Hub's views the fingerprints.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/fsutil"
)

// RevokedKey is one entry. Until zero = until an administrator removes it
// (a bring-your-own key).
type RevokedKey struct {
	Key    string    `json:"key"`
	FP     string    `json:"fp"`
	Reason string    `json:"reason"`
	Actor  string    `json:"actor"`
	Added  time.Time `json:"added"`
	Until  time.Time `json:"until"`
}

// revokedStore guards the file.
type revokedStore struct {
	mu sync.Mutex
}

func (h *Hub) sshDir() string { return filepath.Join(h.cfg.DataDir, "ssh") }

func (h *Hub) revokedPath() string { return filepath.Join(h.sshDir(), "revoked.json") }

// loadRevokedLocked reads the list; a missing file is empty, an
// unreadable one an error (callers fail closed: no signing without it).
func (h *Hub) loadRevokedLocked() ([]RevokedKey, error) {
	raw, err := os.ReadFile(h.revokedPath())
	if errors.Is(err, os.ErrNotExist) {
		return []RevokedKey{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("revoked keys: %w", err)
	}
	var out []RevokedKey
	if err := cliapi.UnmarshalStrict(raw, &out); err != nil {
		return nil, fmt.Errorf("revoked keys: %s is corrupt", h.revokedPath())
	}
	return out, nil
}

func (h *Hub) saveRevokedLocked(list []RevokedKey) error {
	sort.Slice(list, func(i, j int) bool { return list[i].FP < list[j].FP })
	raw, err := json.MarshalIndent(list, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h.sshDir(), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(h.revokedPath(), append(raw, '\n'), 0o600)
}

// sshRevokedList is the list (nil, err when unreadable).
func (h *Hub) sshRevokedList() ([]RevokedKey, error) {
	h.sshrev.mu.Lock()
	defer h.sshrev.mu.Unlock()
	return h.loadRevokedLocked()
}

// RevokedKeys are the revoked public keys, sorted (the public list, the
// bundles). An unreadable file logs and answers nil.
func (h *Hub) RevokedKeys() []string {
	l, err := h.sshRevokedList()
	if err != nil {
		log.Printf("ssh: %v", err)
		return nil
	}
	out := make([]string, 0, len(l))
	for _, e := range l {
		out = append(out, e.Key)
	}
	sort.Strings(out)
	return out
}
