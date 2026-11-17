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
