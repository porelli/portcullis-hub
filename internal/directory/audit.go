package directory

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
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
	// Via is "ai" (ViaAI) on entries made through the Portcullis MCP, else
	// absent; Client is then the AI client (the token's azp). Set only from
	// the identity the gate sent on the MCP listener (contract §9.5, §15.7).
	Via    string `json:"via,omitempty"`
	Client string `json:"client,omitempty"`
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

// AuditScan is how much of the file a filtered view reads at most (the
// last 8 MiB, contract §9.7).
const AuditScan = 8 << 20

// auditChunk is how much RecentMatching reads at a time.
const auditChunk = 256 << 10

// Recent returns up to n entries, newest first.
func (l *AuditLog) Recent(n int) ([]AuditEntry, error) {
	return l.RecentMatching(n, auditTail, nil)
}

// RecentMatching returns up to n entries for which keep says true (nil:
// every entry), newest first, reading at most the last maxScan bytes of
// the file — backwards, a chunk at a time, so it stops as soon as it has
// n. A line cut by the scan limit, or one that doesn't parse, is skipped.
func (l *AuditLog) RecentMatching(n int, maxScan int64, keep func(AuditEntry) bool) ([]AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []AuditEntry{}
	f, err := os.Open(l.Path)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := max(st.Size()-maxScan, 0)
	end := st.Size()
	var carry []byte // the start of the line the last chunk began inside
	for end > start && len(out) < n {
		off := max(end-auditChunk, start)
		buf := make([]byte, end-off, end-off+int64(len(carry)))
		if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
			return nil, err
		}
		data := append(buf, carry...)
		carry = nil
		if off > 0 {
			nl := bytes.IndexByte(data, '\n')
			if nl < 0 {
				carry = data // one line longer than the chunk
				end = off
				continue
			}
			if off > start {
				carry = data[:nl]
			} // else: cut by the scan limit (partial first line)
			data = data[nl+1:]
		}
		out = appendEntries(out, data, n, keep)
		end = off
	}
	return out, nil
}

// appendEntries appends data's lines, last first, to out while it holds
// fewer than n (keep nil: every entry).
func appendEntries(out []AuditEntry, data []byte, n int, keep func(AuditEntry) bool) []AuditEntry {
	lines := bytes.Split(data, []byte("\n"))
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		if len(bytes.TrimSpace(lines[i])) == 0 {
			continue
		}
		var e AuditEntry
		if json.Unmarshal(lines[i], &e) == nil && (keep == nil || keep(e)) {
			out = append(out, e)
		}
	}
	return out
}

// ForGroup keeps the entries for group g (contract §9.7 ?group=): target
// exactly g, or starting with "g:" (group.sync's "<g>:<id>", a member's
// "<g>:<u>"). Exact, case-sensitive; never a substring.
func ForGroup(g string) func(AuditEntry) bool {
	return func(e AuditEntry) bool {
		return e.Target == g || strings.HasPrefix(e.Target, g+":")
	}
}

// ForUser keeps the entries for user u (contract §9.7 ?user=), compared
// lowercased: target exactly u, or "<group>:<u>" (the part after the
// last ':'; group.sync's targets carry the LLDAP user id, the username),
// or a detail holding the token user=<u> followed by a space or the end;
// group.add_member / group.remove_member on a manual group (target the
// group, detail the bare username first) also when the detail's first
// field is u.
func ForUser(u string) func(AuditEntry) bool {
	u = strings.ToLower(u)
	return func(e AuditEntry) bool {
		t := strings.ToLower(e.Target)
		if t == u || t[strings.LastIndex(t, ":")+1:] == u {
			return true
		}
		d := strings.ToLower(e.Detail)
		if (e.Action == "group.add_member" || e.Action == "group.remove_member") && firstField(d) == u {
			return true
		}
		return hasUserToken(d, u)
	}
}

// firstField is d's first space-separated field, without the ';' an
// appended confirmation ("<detail>; confirmation …") leaves on it.
func firstField(d string) string {
	if f := strings.Fields(d); len(f) > 0 {
		return strings.TrimSuffix(f[0], ";")
	}
	return ""
}

// hasUserToken: d (lowercase) holds "user=<u>" starting the text or after
// a space, and followed by a space or the end.
func hasUserToken(d, u string) bool {
	tok := "user=" + u
	for i := 0; ; {
		j := strings.Index(d[i:], tok)
		if j < 0 {
			return false
		}
		j += i
		if (j == 0 || d[j-1] == ' ') && (j+len(tok) == len(d) || d[j+len(tok)] == ' ') {
			return true
		}
		i = j + 1
	}
}
