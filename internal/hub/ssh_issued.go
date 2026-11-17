package hub

// The issued index (contract §18.13): hub_data/ssh/issued.jsonl, 0600,
// one line per certificate, kept 90 days. Fingerprints, never keys.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
)

// issuedKeep is how long the index keeps a line.
const issuedKeep = 90 * 24 * time.Hour

// IssuedRecord is one issued certificate.
type IssuedRecord struct {
	Time        time.Time `json:"time"`
	User        string    `json:"user"`
	HostGroup   string    `json:"host_group"`
	Serial      string    `json:"serial"`
	KeyFP       string    `json:"key_fp"`
	Principals  []string  `json:"principals"`
	ValidBefore time.Time `json:"valid_before"`
	Flow        string    `json:"flow"`
	Addr        string    `json:"addr"`
	// Own: the person's own key (login --key): its revocation never ends.
	Own bool `json:"own,omitempty"`
}

type issuedIndex struct {
	mu     sync.Mutex
	pruned time.Time
}

func (h *Hub) issuedPath() string { return filepath.Join(h.sshDir(), "issued.jsonl") }

// keysPath is fingerprint → public key of every key the Hub signed in the
// last 90 days (0600): only read to put a key on the revoked list
// (revocation on leave, an admin's Revoke). Never in a log, the audit,
// the history or an answer.
func (h *Hub) keysPath() string { return filepath.Join(h.sshDir(), "keys.json") }

type keyEntry struct {
	Key  string    `json:"key"`
	Seen time.Time `json:"seen"`
}

func (h *Hub) loadKeysLocked() (map[string]keyEntry, error) {
	raw, err := os.ReadFile(h.keysPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]keyEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]keyEntry{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s is corrupt", h.keysPath())
	}
	return out, nil
}

// rememberKey records fp → key (the signing path). Entries older than 90
// days go unless the fingerprint is still on the revoked list (Ruling
// C21-b: a listed key keeps its key).
func (h *Hub) rememberKey(fp, key string, now time.Time) error {
	listed := map[string]bool{}
	if l, err := h.sshRevokedList(); err == nil {
		for _, e := range l {
			listed[e.FP] = true
		}
	} else {
		listed = nil // unreadable: prune nothing
	}
	h.sshiss.mu.Lock()
	defer h.sshiss.mu.Unlock()
	m, err := h.loadKeysLocked()
	if err != nil {
		return err
	}
	m[fp] = keyEntry{Key: key, Seen: now.UTC()}
	for k, e := range m {
		if listed != nil && !listed[k] && now.Sub(e.Seen) > issuedKeep {
			delete(m, k)
		}
	}
	raw, _ := json.Marshal(m)
	if err := os.MkdirAll(h.sshDir(), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(h.keysPath(), raw, 0o600)
}

// issuedKey is the public key of fingerprint fp ("" when unknown).
func (h *Hub) issuedKey(fp string) string {
	h.sshiss.mu.Lock()
	defer h.sshiss.mu.Unlock()
	m, err := h.loadKeysLocked()
	if err != nil {
		return ""
	}
	return m[fp].Key
}

// appendIssued adds records (and prunes old lines at most daily).
func (h *Hub) appendIssued(recs []IssuedRecord, now time.Time) error {
	h.sshiss.mu.Lock()
	defer h.sshiss.mu.Unlock()
	if err := os.MkdirAll(h.sshDir(), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(h.issuedPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			f.Close()
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	_, werr := f.Write(buf.Bytes())
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if now.Sub(h.sshiss.pruned) > 24*time.Hour {
		h.sshiss.pruned = now
		return h.pruneIssuedLocked(now)
	}
	return nil
}

func (h *Hub) readIssuedLocked() ([]IssuedRecord, error) {
	raw, err := os.ReadFile(h.issuedPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []IssuedRecord
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var r IssuedRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.User != "" {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

func (h *Hub) pruneIssuedLocked(now time.Time) error {
	all, err := h.readIssuedLocked()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, r := range all {
		if now.Sub(r.Time) > issuedKeep {
			continue
		}
		b, _ := json.Marshal(r)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return fsutil.WriteFileAtomic(h.issuedPath(), buf.Bytes(), 0o600)
}

// IssuedFor is user's records, oldest first ("" = everyone's).
func (h *Hub) IssuedFor(user string) []IssuedRecord {
	h.sshiss.mu.Lock()
	defer h.sshiss.mu.Unlock()
	all, err := h.readIssuedLocked()
	if err != nil {
		return nil
	}
	out := []IssuedRecord{}
	for _, r := range all {
		if user == "" || r.User == user {
			out = append(out, r)
		}
	}
	return out
}

// issuedByFP is every record of key fp.
func (h *Hub) issuedByFP(fp string) []IssuedRecord {
	var out []IssuedRecord
	for _, r := range h.IssuedFor("") {
		if r.KeyFP == fp {
			out = append(out, r)
		}
	}
	return out
}

func (r IssuedRecord) String() string {
	return fmt.Sprintf("%s %s %s serial %s", r.User, r.HostGroup, r.KeyFP, r.Serial)
}

// pruneKeys drops keys.json entries older than 90 days whose fingerprint
// isn't on the revoked list (daily, after pruneRevoked).
func (h *Hub) pruneKeys(now time.Time) {
	l, err := h.sshRevokedList()
	if err != nil {
		return
	}
	listed := map[string]bool{}
	for _, e := range l {
		listed[e.FP] = true
	}
	h.sshiss.mu.Lock()
	defer h.sshiss.mu.Unlock()
	m, err := h.loadKeysLocked()
	if err != nil {
		return
	}
	n := len(m)
	for k, e := range m {
		if !listed[k] && now.Sub(e.Seen) > issuedKeep {
			delete(m, k)
		}
	}
	if len(m) != n {
		raw, _ := json.Marshal(m)
		_ = fsutil.WriteFileAtomic(h.keysPath(), raw, 0o600)
	}
}

func writeFile0600(p string, b []byte) error { return fsutil.WriteFileAtomic(p, b, 0o600) }
