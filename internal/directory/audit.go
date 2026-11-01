package directory

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// AuditEntry is one line of the audit log. It never contains a password.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail,omitempty"`
	Result string    `json:"result"` // "ok", "refused" or "error"
	Error  string    `json:"error,omitempty"`
}

// AuditLog appends JSON lines to a file (mode 0600).
type AuditLog struct {
	Path string
	mu   sync.Mutex
}

// Append writes e (Time defaults to now).
func (l *AuditLog) Append(e AuditEntry) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// auditTail is how much of the file Recent reads.
const auditTail = 256 << 10

// Recent returns up to n entries, newest first.
func (l *AuditLog) Recent(n int) ([]AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.Path)
	if os.IsNotExist(err) {
		return []AuditEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := st.Size() - auditTail
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(data, []byte("\n"))
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // partial first line
	}
	out := []AuditEntry{}
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		if len(bytes.TrimSpace(lines[i])) == 0 {
			continue
		}
		var e AuditEntry
		if json.Unmarshal(lines[i], &e) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}
