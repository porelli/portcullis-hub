package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRecentMatching: entries newest first across many chunks (lines
// cut by a chunk boundary are joined), at most n, keep applied, nothing
// older than maxScan bytes, the line cut by the scan limit skipped; Recent
// is RecentMatching over its 256 KiB tail.
func TestRecentMatching(t *testing.T) {
	l := &AuditLog{Path: filepath.Join(t.TempDir(), "audit.jsonl")}
	if got, err := l.RecentMatching(10, AuditScan, nil); err != nil || len(got) != 0 || got == nil {
		t.Fatalf("missing file = %v %v", got, err)
	}
	const total = 6000 // ~1 MiB: four chunks
	pad := strings.Repeat("x", 120)
	for i := range total {
		g := "even"
		if i%2 == 1 {
			g = "odd"
		}
		if err := l.Append(AuditEntry{Actor: "root", Action: "group.rule", Target: fmt.Sprintf("%s:%d", g, i), Detail: pad, Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := l.RecentMatching(total+10, AuditScan, nil)
	if err != nil || len(all) != total {
		t.Fatalf("all = %d %v", len(all), err)
	}
	for i, e := range all {
		if want := total - 1 - i; !strings.HasSuffix(e.Target, fmt.Sprintf(":%d", want)) {
			t.Fatalf("entry %d = %s, want #%d", i, e.Target, want)
		}
	}
	odd, _ := l.RecentMatching(3, AuditScan, ForGroup("odd"))
	if len(odd) != 3 || odd[0].Target != fmt.Sprintf("odd:%d", total-1) || odd[2].Target != fmt.Sprintf("odd:%d", total-5) {
		t.Errorf("odd = %+v", odd)
	}
	// Beyond Recent's 256 KiB: the oldest entry, about 1 MiB back.
	if first, _ := l.RecentMatching(1, AuditScan, func(e AuditEntry) bool { return e.Target == "even:0" }); len(first) != 1 {
		t.Errorf("even:0 not found within %d bytes", AuditScan)
	}
	// The scan limit: only whole lines of the last maxScan bytes.
	st, _ := os.Stat(l.Path)
	line := st.Size() / total
	limited, _ := l.RecentMatching(total, 10*line+line/2, nil)
	if len(limited) != 10 {
		t.Errorf("limited = %d entries, want 10", len(limited))
	}
	recent, _ := l.Recent(total)
	if want := int(auditTail / line); len(recent) < want-10 || len(recent) > want {
		t.Errorf("Recent = %d entries, want about %d", len(recent), want)
	}
}

// TestAuditFilters: ForGroup is exact or "g:" prefixed; ForUser matches
// the target, the part after the last ':' or a user=<u> token, lowercased.
func TestAuditFilters(t *testing.T) {
	g := ForGroup("eng")
	for target, want := range map[string]bool{"eng": true, "eng:dave": true, "engineering": false, "Eng": false, "x:eng": false} {
		if g(AuditEntry{Target: target}) != want {
			t.Errorf("ForGroup(eng) %q = %v", target, !want)
		}
	}
	u := ForUser("Dave")
	for _, c := range []struct {
		target, detail string
		want           bool
	}{
		{"dave", "", true}, {"DAVE", "", true}, {"eng:dave", "", true}, {"a:b:dave", "", true},
		{"davey", "", false}, {"eng:davey", "", false},
		{"eng", "user=dave", true}, {"eng", "add user=Dave include=true", true}, {"eng", "user=davey", false},
		{"eng", "xuser=dave", false}, {"eng", "user=dave,x", false}, {"eng", "user=davey user=dave", true},
	} {
		if u(AuditEntry{Target: c.target, Detail: c.detail}) != c.want {
			t.Errorf("ForUser(Dave) %q %q = %v", c.target, c.detail, !c.want)
		}
	}
}
