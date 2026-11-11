package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/signinhistory"
	"github.com/portcullis/hub/internal/state"
)

var histNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// historyFixture: a Hub whose opened log is <root>/gg, its clock
// histNow, history_days 365, with Keycloak events kcEvents and audit
// entries auditEntries (newest first).
type historyFixture struct {
	f      *fixture
	dir    string
	mu     sync.Mutex
	events []keycloak.Event
	kcErr  error
	audit  []directory.AuditEntry
}

func newHistoryFixture(t *testing.T) *historyFixture {
	t.Helper()
	hf := &historyFixture{}
	hf.f = newInstanceFixtureCfg(t, nil, nil, nil, func(root string, c *Config) {
		hf.dir = filepath.Join(root, "gg")
		c.GroupGateDataDir = hf.dir
	})
	if err := os.MkdirAll(filepath.Join(hf.dir, signinhistory.OpenedDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	hf.f.h.SetAudit(&fakeAudit{})
	ableAdmin(hf.f.h)
	hf.f.h.history.mu.Lock()
	hf.f.h.history.now = func() time.Time { return histNow }
	hf.f.h.history.mu.Unlock()
	hf.f.h.SetHistorySources(HistorySources{
		Events: func(_ context.Context, user string, from, to time.Time, first, max int) ([]keycloak.Event, error) {
			hf.mu.Lock()
			defer hf.mu.Unlock()
			if hf.kcErr != nil {
				return nil, hf.kcErr
			}
			return hf.events[min(first, len(hf.events)):min(first+max, len(hf.events))], nil
		},
		Audit: func(n int, _ int64, keep func(directory.AuditEntry) bool) ([]directory.AuditEntry, error) {
			hf.mu.Lock()
			defer hf.mu.Unlock()
			var out []directory.AuditEntry
			for _, e := range hf.audit {
				if len(out) < n && keep(e) {
					out = append(out, e)
				}
			}
			return out, nil
		},
	})
	return hf
}

func (hf *historyFixture) opened(t *testing.T, at time.Time, user, session, host string) {
	t.Helper()
	p := filepath.Join(hf.dir, signinhistory.OpenedDirName, at.UTC().Format("2006-01-02")+".jsonl")
	b, _ := json.Marshal(map[string]any{"time": at.UTC().Format(time.RFC3339), "user": user, "session": session, "host": host,
		"app": "Files", "methods": []string{"passkey_synced"}, "ip": "198.51.100.4", "ua": "", "act": ""})
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(append(b, '\n'))
	f.Close()
}

func kcLogin(at time.Time, methods string) keycloak.Event {
	return keycloak.Event{Time: at, Type: "LOGIN", ClientID: "portcullis-forward-auth",
		Details: map[string]string{"pc_kind": "sign_in", "pc_methods": methods}}
}

func kinds(es []signinhistory.Entry) []signinhistory.Kind {
	out := []signinhistory.Kind{}
	for _, e := range es {
		out = append(out, e.Kind)
	}
	return out
}

func TestSignInHistoryMerged(t *testing.T) {
	hf := newHistoryFixture(t)
	hf.events = []keycloak.Event{kcLogin(histNow.Add(-time.Minute), "password"), kcLogin(histNow.Add(-3*time.Hour), "")}
	hf.opened(t, histNow.Add(-time.Hour), "alice", "s1", "files.example.com")
	hf.opened(t, histNow.Add(-50*time.Minute), "bob", "s2", "files.example.com")
	hf.audit = []directory.AuditEntry{{Time: histNow.Add(-2 * time.Hour), Actor: "root", Action: "user.invite", Target: "alice", Result: "ok"}}
	p, err := hf.f.h.SignInHistory(context.Background(), "Alice", time.Time{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if want := []signinhistory.Kind{"sign_in", "opened", "help", "sign_in"}; !reflect.DeepEqual(kinds(p.Entries), want) {
		t.Errorf("kinds = %v, want %v", kinds(p.Entries), want)
	}
	if p.Entries[3].Detail != signinhistory.SetupLinkDetail {
		t.Errorf("setup link = %+v", p.Entries[3])
	}
	if p.Next != "" || p.Unknown == nil || len(p.Unknown) != 0 {
		t.Errorf("next %q unknown %v", p.Next, p.Unknown)
	}
	b, _ := json.Marshal(p)
	if !strings.Contains(string(b), `"unknown":[]`) || !strings.Contains(string(b), `"next":""`) {
		t.Errorf("json = %s", b)
	}
	for _, bad := range []int{0, 101} {
		if _, err := hf.f.h.SignInHistory(context.Background(), "alice", time.Time{}, bad); statusOf(err) != 400 {
			t.Errorf("limit %d: %v", bad, err)
		}
	}
}

func TestSignInHistoryPaging(t *testing.T) {
	hf := newHistoryFixture(t)
	for i := range 5 {
		hf.events = append(hf.events, kcLogin(histNow.Add(-time.Duration(i+1)*time.Minute), "password"))
	}
	// Two opened entries at the same second straddle the page cut.
	hf.opened(t, histNow.Add(-10*time.Minute), "alice", "s1", "a.example.com")
	hf.opened(t, histNow.Add(-10*time.Minute), "alice", "s1", "b.example.com")
	ctx := context.Background()
	p, err := hf.f.h.SignInHistory(ctx, "alice", time.Time{}, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 5 || p.Next != p.Entries[4].Time.Format(time.RFC3339Nano) {
		t.Fatalf("page 1 = %d entries, next %q", len(p.Entries), p.Next)
	}
	before, _ := time.Parse(time.RFC3339Nano, p.Next)
	p2, err := hf.f.h.SignInHistory(ctx, "alice", before, 6)
	if err != nil || len(p2.Entries) != 2 || p2.Next != "" || p2.Entries[0].Kind != "opened" {
		t.Errorf("page 2 = %+v, %v", p2, err)
	}
	// Exactly limit: no next.
	p3, _ := hf.f.h.SignInHistory(ctx, "alice", time.Time{}, 7)
	if len(p3.Entries) != 7 || p3.Next != "" {
		t.Errorf("limit 7 = %d, next %q", len(p3.Entries), p3.Next)
	}
}

// staticSource answers its entries whatever the window (the Hub must
// filter), or err.
type staticSource struct {
	es  []signinhistory.Entry
	err error
}

func (s staticSource) Entries(context.Context, string, time.Time, time.Time, int) ([]signinhistory.Entry, error) {
	return s.es, s.err
}

func TestHistoryRetention(t *testing.T) {
	hf := newHistoryFixture(t)
	old := histNow.AddDate(0, 0, -366)
	hf.events = []keycloak.Event{kcLogin(histNow.Add(-time.Hour), "password"), kcLogin(old, "password")}
	hf.opened(t, old, "alice", "s", "files.example.com")
	hf.audit = []directory.AuditEntry{{Time: old, Actor: "root", Action: "user.invite", Target: "alice", Result: "ok"}}
	hf.f.h.AddHistorySource("part3", staticSource{es: []signinhistory.Entry{
		{Time: old, Kind: signinhistory.KindImpersonation},
		{Time: histNow.Add(time.Hour), Kind: signinhistory.KindImpersonation}, // the future: after before
	}})
	p, err := hf.f.h.SignInHistory(context.Background(), "alice", time.Time{}, 50)
	if err != nil || len(p.Entries) != 1 || p.Entries[0].Kind != "sign_in" {
		t.Errorf("entries = %+v, %v", p, err)
	}
	// 30 days: a 31-day-old entry is gone too.
	if _, err := hf.f.h.SetSignInLimits(context.Background(), state.SignInLimits{BrowserCertDays: 30, BrowserCertMaxActive: 3, HistoryDays: 30}, siAdmin); err != nil {
		t.Fatal(err)
	}
	hf.mu.Lock()
	hf.events = []keycloak.Event{kcLogin(histNow.AddDate(0, 0, -31), "password")}
	hf.mu.Unlock()
	if p, _ := hf.f.h.SignInHistory(context.Background(), "alice", time.Time{}, 50); len(p.Entries) != 0 {
		t.Errorf("31 days old with 30 kept: %+v", p.Entries)
	}
}

func TestHistoryUnknownSource(t *testing.T) {
	hf := newHistoryFixture(t)
	hf.kcErr = &keycloak.HTTPError{Op: "read the login events", Status: 500}
	hf.opened(t, histNow.Add(-time.Hour), "alice", "s1", "files.example.com")
	hf.audit = []directory.AuditEntry{{Time: histNow.Add(-2 * time.Hour), Actor: "root", Action: "cert.revoke", Target: "alice", Result: "ok"}}
	p, err := hf.f.h.SignInHistory(context.Background(), "alice", time.Time{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Unknown, []string{"keycloak"}) || !reflect.DeepEqual(kinds(p.Entries), []signinhistory.Kind{"opened", "help"}) {
		t.Errorf("page = %+v", p)
	}
	// The opened log's mount gone: named too.
	os.RemoveAll(hf.dir)
	p, _ = hf.f.h.SignInHistory(context.Background(), "alice", time.Time{}, 50)
	if !reflect.DeepEqual(p.Unknown, []string{"keycloak", "opened"}) || len(p.Entries) != 1 {
		t.Errorf("no mount = %+v", p)
	}
	// Nothing wired at all: every built-in unknown, no failure.
	hf.f.h.SetHistorySources(HistorySources{})
	p, err = hf.f.h.SignInHistory(context.Background(), "alice", time.Time{}, 50)
	if err != nil || !reflect.DeepEqual(p.Unknown, []string{"keycloak", "opened", "audit"}) || len(p.Entries) != 0 {
		t.Errorf("unwired = %+v, %v", p, err)
	}
}

// panicSource panics on every read.
type panicSource struct{}

func (panicSource) Entries(context.Context, string, time.Time, time.Time, int) ([]signinhistory.Entry, error) {
	panic("boom")
}

func TestAddHistorySource(t *testing.T) {
	hf := newHistoryFixture(t)
	hf.f.h.AddHistorySource("part3", staticSource{es: []signinhistory.Entry{{Time: histNow.Add(-time.Minute), Kind: signinhistory.KindImpersonation, By: "root", Reason: "support"}}})
	hf.f.h.AddHistorySource("broken", staticSource{err: errors.New("down")})
	hf.f.h.AddHistorySource("panics", panicSource{})
	hf.f.h.AddHistorySource("keycloak", staticSource{}) // a built-in name: refused
	p, err := hf.f.h.SignInHistory(context.Background(), "alice", time.Time{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 1 || p.Entries[0].Kind != signinhistory.KindImpersonation || p.Entries[0].By != "root" {
		t.Errorf("entries = %+v", p.Entries)
	}
	if !reflect.DeepEqual(p.Unknown, []string{"broken", "panics"}) {
		t.Errorf("unknown = %v", p.Unknown)
	}
	// Added again: replaced.
	hf.f.h.AddHistorySource("broken", staticSource{})
	if p, _ := hf.f.h.SignInHistory(context.Background(), "alice", time.Time{}, 50); !reflect.DeepEqual(p.Unknown, []string{"panics"}) {
		t.Errorf("after replacing = %v", p.Unknown)
	}
}

// TestLimitsChangePrunes (carried, Task 3): a new history_days prunes the
// opened log with it; an unchanged one doesn't.
func TestLimitsChangePrunes(t *testing.T) {
	hf := newHistoryFixture(t)
	h := hf.f.h
	var mu sync.Mutex
	var calls []int
	h.history.mu.Lock()
	h.history.prune = func(days int) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, days)
		return 0, nil
	}
	h.history.mu.Unlock()
	ctx := context.Background()
	if _, err := h.SetSignInLimits(ctx, state.SignInLimits{BrowserCertDays: 30, BrowserCertMaxActive: 3, HistoryDays: 365}, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SetSignInLimits(ctx, state.SignInLimits{BrowserCertDays: 10, BrowserCertMaxActive: 3, HistoryDays: 365}, siAdmin); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(calls) != 0 {
		t.Errorf("unchanged history pruned: %v", calls)
	}
	mu.Unlock()
	if _, err := h.SetSignInLimits(ctx, state.SignInLimits{BrowserCertDays: 10, BrowserCertMaxActive: 3, HistoryDays: 30}, siAdmin); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(calls, []int{30}) {
		t.Errorf("prune calls = %v, want [30]", calls)
	}
}

// TestRunHistoryPrune: the loop prunes the real opened log at once with
// history_days, never today's file.
func TestRunHistoryPrune(t *testing.T) {
	hf := newHistoryFixture(t)
	hf.opened(t, histNow.AddDate(0, 0, -400), "alice", "s", "h")
	hf.opened(t, histNow, "alice", "s", "h")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { hf.f.h.RunHistoryPrune(ctx, time.Hour); close(done) }()
	old := filepath.Join(hf.dir, signinhistory.OpenedDirName, histNow.AddDate(0, 0, -400).Format("2006-01-02")+".jsonl")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(old); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the old day file was not pruned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if _, err := os.Stat(filepath.Join(hf.dir, signinhistory.OpenedDirName, histNow.Format("2006-01-02")+".jsonl")); err != nil {
		t.Errorf("today's file: %v", err)
	}
}
