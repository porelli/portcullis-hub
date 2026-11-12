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

// impEventsKC is a fake of the Keycloak reads the apps function makes.
type impEventsKC struct {
	mu         sync.Mutex
	logins     []keycloak.Event // newest first
	imps       []keycloak.Event
	loginErr   error
	impErr     error
	cfgOff     bool  // the events config doesn't store IMPERSONATE
	cfgErr     error // the events config can't be read
	impCalls   int
	loginReads int
	afterCall  func(n int) // after the n-th impersonate read
}

func (k *impEventsKC) UserClientLoginEvents(_ context.Context, user, client string, from, to time.Time, first, max int) ([]keycloak.Event, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.loginReads++
	if k.loginErr != nil {
		return nil, k.loginErr
	}
	var in []keycloak.Event
	for _, e := range k.logins {
		if e.UserID == user && e.ClientID == client && e.Type == "LOGIN" && !e.Time.Before(from) && e.Time.Before(to) {
			in = append(in, e)
		}
	}
	return in[min(first, len(in)):min(first+max, len(in))], nil
}

func (k *impEventsKC) UserImpersonateEvents(_ context.Context, user string, from, to time.Time) ([]keycloak.Event, error) {
	k.mu.Lock()
	k.impCalls++
	n, err, after := k.impCalls, k.impErr, k.afterCall
	var out []keycloak.Event
	for _, e := range k.imps {
		if e.UserID == user && !e.Time.Before(from) && e.Time.Before(to) {
			out = append(out, e)
		}
	}
	k.mu.Unlock()
	if after != nil {
		defer after(n)
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (k *impEventsKC) ImpersonateEventsStored(context.Context) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return !k.cfgOff, k.cfgErr
}

func writeSignInClients(t *testing.T, h *Hub, clients map[string]string) {
	t.Helper()
	doc := map[string]any{"clients": map[string]any{}}
	for id, name := range clients {
		doc["clients"].(map[string]any)[id] = map[string]string{"template": "default", "name": name}
	}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(h.signInKeycloakPath(), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (hf *historyFixture) openedAct(t *testing.T, at time.Time, user, host, app, act string) {
	t.Helper()
	p := filepath.Join(hf.dir, signinhistory.OpenedDirName, at.UTC().Format("2006-01-02")+".jsonl")
	b, _ := json.Marshal(map[string]any{"time": at.UTC().Format(time.RFC3339), "user": user, "session": "s-" + act, "host": host,
		"app": app, "methods": []string{}, "ip": "", "ua": "", "act": act})
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(append(b, '\n'))
	f.Close()
}

const appsImpID = "0f3c0f3c0f3c0f3c0f3c0f3c0f3c0f3c"

// TestImpersonationApps (D44, contract §8.2 "Apps opened"): gateway apps
// from the opened log's act lines, native apps from LOGINs with pc_act
// for listed clients other than portcullis-forward-auth, deduped,
// gateway first; used from IMPERSONATE with pc_imp = the id, and used
// whenever unsure.
func TestImpersonationApps(t *testing.T) {
	hf := newHistoryFixture(t)
	h := hf.f.h
	started := histNow.Add(-40 * time.Minute)
	ended := started.Add(12 * time.Minute)
	now := histNow
	h.imp.now = func() time.Time { return now }
	writeSignInClients(t, h, map[string]string{signinhistory.ForwardAuthClient: "Gateway", "nextcloud": "Nextcloud", "office": "Office"})
	hf.openedAct(t, started.Add(-time.Minute), "alice", "old.example.org", "Old", "root") // before the start
	hf.openedAct(t, started.Add(time.Minute), "alice", "gitea.example.org", "Gitea", "root")
	hf.openedAct(t, started.Add(2*time.Minute), "alice", "files.example.org", "Files", "root")
	hf.openedAct(t, started.Add(3*time.Minute), "alice", "gitea.example.org", "Gitea", "root")
	hf.openedAct(t, started.Add(4*time.Minute), "alice", "wiki.example.org", "Wiki", "bob") // another admin
	hf.openedAct(t, started.Add(5*time.Minute), "alice", "plain.example.org", "Plain", "")  // alice herself
	hf.openedAct(t, ended.Add(time.Minute), "alice", "late.example.org", "Late", "root")    // after the end
	login := func(at time.Time, client, act string) keycloak.Event {
		d := map[string]string{"pc_kind": "sso"}
		if act != "" {
			d["pc_act"] = act
		}
		return keycloak.Event{Time: at, Type: "LOGIN", ClientID: client, UserID: "alice", Details: d}
	}
	kc := &impEventsKC{
		logins: []keycloak.Event{ // newest first
			login(ended.Add(time.Minute), "office", "root"), // after the end
			login(started.Add(6*time.Minute), "nextcloud", "root"),
			login(started.Add(5*time.Minute), "nextcloud", "root"),
			login(started.Add(5*time.Minute), "unlisted", "root"),
			login(started.Add(4*time.Minute), "office", "bob"),
			login(started.Add(3*time.Minute), signinhistory.ForwardAuthClient, "root"), // the gateway's own client
			login(started.Add(2*time.Minute), "office", ""),
		},
		imps: []keycloak.Event{{Time: started.Add(2 * time.Second), Type: "IMPERSONATE", UserID: "alice",
			Details: map[string]string{"pc_imp": appsImpID, "pc_act": "root"}}},
	}
	slept := 0
	a := &impApps{h: h, kc: kc, sleep: func(context.Context, time.Duration) bool { slept++; return true }}
	rec := state.Impersonation{ID: appsImpID, Admin: "root", Target: "alice", Started: started, Until: started.Add(30 * time.Minute),
		Ended: ended, How: ImpStopped}
	apps, used := a.run(context.Background(), rec)
	want := []signinhistory.OpenedApp{{Name: "Gitea"}, {Name: "Files"}, {Name: "Nextcloud", OwnSession: true}}
	if !reflect.DeepEqual(apps, want) || !used {
		t.Errorf("apps = %+v, used %v; want %+v, used", apps, used, want)
	}
	if slept != 0 {
		t.Errorf("slept %d times long after the end", slept)
	}

	// Apps opened without any IMPERSONATE event of this id (a lost event
	// write): used all the same (review I1).
	other := rec
	other.ID = otherImpID(appsImpID)
	if apps, used := a.run(context.Background(), other); !used || !reflect.DeepEqual(apps, want) {
		t.Errorf("apps without the event: %+v, used %v", apps, used)
	}
	// Another id's event, no app in the window: not used (long after the
	// end: no second ask).
	quiet := other
	quiet.Started, quiet.Ended = started.Add(-10*time.Hour), started.Add(-10*time.Hour+12*time.Minute)
	if apps, used := a.run(context.Background(), quiet); used || len(apps) != 0 {
		t.Errorf("another id's IMPERSONATE counted: %+v, %v", apps, used)
	}
	// The events config drifted (IMPERSONATE not stored) or can't be
	// read: no event proves nothing, so used (final review M2).
	kc.cfgOff = true
	if _, used := a.run(context.Background(), quiet); !used {
		t.Error("IMPERSONATE not stored, read as not used")
	}
	kc.cfgOff, kc.cfgErr = false, errors.New("keycloak down")
	if _, used := a.run(context.Background(), quiet); !used {
		t.Error("an unreadable events config read as not used")
	}
	kc.cfgErr = nil
	// Events unreadable: used; logins unreadable: no native apps, still
	// the gateway's.
	kc.impErr, kc.loginErr = errors.New("keycloak down"), errors.New("keycloak down")
	apps, used = a.run(context.Background(), other)
	if !used || !reflect.DeepEqual(apps, append(want[:2:2], signinhistory.OpenedApp{Name: signinhistory.MoreApps})) {
		t.Errorf("unreadable: apps %+v, used %v", apps, used)
	}
	kc.impErr, kc.loginErr = nil, nil
	// Known used, or no Keycloak: used.
	other.Used = true
	if _, used := a.run(context.Background(), other); !used {
		t.Error("a record known used read as not used")
	}
	other.Used = false
	if _, used := (&impApps{h: h, sleep: a.sleep}).run(context.Background(), quiet); !used {
		t.Error("no Keycloak read as not used")
	}
	// signin-keycloak.json unreadable: which clients are native isn't
	// known → the marker (review I4).
	os.WriteFile(h.signInKeycloakPath(), []byte("{not json"), 0o644)
	if apps, _ := a.run(context.Background(), rec); !reflect.DeepEqual(apps, append(want[:2:2], signinhistory.OpenedApp{Name: signinhistory.MoreApps})) {
		t.Errorf("clients unreadable: apps %+v", apps)
	}
	writeSignInClients(t, h, map[string]string{signinhistory.ForwardAuthClient: "Gateway", "nextcloud": "Nextcloud", "office": "Office"})

	// A native client's page budget spent without a match: what was read,
	// then the marker (security review: never silently incomplete).
	var flood []keycloak.Event
	for i := range impLoginPages * impLoginPage {
		flood = append(flood, login(ended.Add(-time.Duration(i)*time.Millisecond), "office", "bob"))
	}
	kc.mu.Lock()
	saved := kc.logins
	kc.logins = append(flood, saved...)
	kc.loginReads = 0
	kc.mu.Unlock()
	apps, _ = a.run(context.Background(), rec)
	if !reflect.DeepEqual(apps, append(want[:3:3], signinhistory.OpenedApp{Name: signinhistory.MoreApps})) {
		t.Errorf("budget spent: apps %+v", apps)
	}
	kc.mu.Lock()
	if kc.loginReads != impLoginPages+1 { // office's 10 pages, nextcloud's 1
		t.Errorf("%d login reads", kc.loginReads)
	}
	kc.logins = saved
	kc.mu.Unlock()
	// The opened log unreadable (its mount gone): the marker too.
	os.Rename(hf.dir, hf.dir+".away")
	apps, _ = a.run(context.Background(), rec)
	os.Rename(hf.dir+".away", hf.dir)
	if !reflect.DeepEqual(apps, []signinhistory.OpenedApp{{Name: "Nextcloud", OwnSession: true}, {Name: signinhistory.MoreApps}}) {
		t.Errorf("opened log gone: apps %+v", apps)
	}

	// Just stopped (the event may not be readable yet): asked again
	// after the settle time; the event then found → used.
	fresh := other
	fresh.Started, fresh.Ended = now.Add(-30*time.Second), now
	kc.mu.Lock()
	kc.impCalls = 0
	kc.afterCall = func(n int) {
		if n == 1 {
			kc.mu.Lock()
			kc.imps = append(kc.imps, keycloak.Event{Time: now.Add(-time.Second), Type: "IMPERSONATE", UserID: "alice",
				Details: map[string]string{"pc_imp": fresh.ID}})
			kc.mu.Unlock()
		}
	}
	kc.mu.Unlock()
	var waited time.Duration
	a.sleep = func(_ context.Context, d time.Duration) bool { waited = d; return true }
	if _, used := a.run(context.Background(), fresh); !used || waited != impEventSettle {
		t.Errorf("just stopped: used %v, waited %v", used, waited)
	}
	// Still none after the settle time: not used.
	fresh.ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	kc.mu.Lock()
	kc.afterCall = nil
	kc.mu.Unlock()
	if _, used := a.run(context.Background(), fresh); used {
		t.Error("never used read as used after the settle time")
	}
	// The wait cut short (ctx ended): used.
	a.sleep = func(context.Context, time.Duration) bool { return false }
	if _, used := a.run(context.Background(), fresh); !used {
		t.Error("an interrupted wait read as not used")
	}
	// The not-used check at created + 120 s (still running): the window
	// closes at created + 120 s.
	pending := fresh
	pending.Started, pending.Ended = now.Add(-impPendingFor), time.Time{}
	waited = 0
	a.sleep = func(_ context.Context, d time.Duration) bool { waited = d; return true }
	if _, used := a.run(context.Background(), pending); used || waited != impEventSettle {
		t.Errorf("pending check: used %v, waited %v", used, waited)
	}
}

// TestImpersonationAppsSameNameAndSecond: a name from both sources keeps
// its own session (review I2); a line in the start's own second counts
// (group-gate writes whole seconds, review I3).
func TestImpersonationAppsSameNameAndSecond(t *testing.T) {
	hf := newHistoryFixture(t)
	h := hf.f.h
	started := histNow.Add(-40*time.Minute + 700*time.Millisecond)
	now := histNow
	h.imp.now = func() time.Time { return now }
	writeSignInClients(t, h, map[string]string{"nextcloud": "Nextcloud"})
	hf.openedAct(t, started.Truncate(time.Second), "alice", "files.example.org", "Files", "root") // same second, written truncated
	hf.openedAct(t, started.Add(time.Minute), "alice", "cloud.example.org", "Nextcloud", "root")
	kc := &impEventsKC{logins: []keycloak.Event{{Time: started.Add(2 * time.Minute), Type: "LOGIN", ClientID: "nextcloud", UserID: "alice",
		Details: map[string]string{"pc_kind": "sso", "pc_act": "root"}}}}
	a := &impApps{h: h, kc: kc, sleep: func(context.Context, time.Duration) bool { return true }}
	rec := state.Impersonation{ID: appsImpID, Admin: "root", Target: "alice", Started: started, Until: started.Add(30 * time.Minute),
		Ended: started.Add(5 * time.Minute), How: ImpStopped}
	apps, used := a.run(context.Background(), rec)
	want := []signinhistory.OpenedApp{{Name: "Files"}, {Name: "Nextcloud", OwnSession: true}}
	if !reflect.DeepEqual(apps, want) || !used {
		t.Errorf("apps = %+v, used %v; want %+v", apps, used, want)
	}
}

// stampAudit is a fake audit that stamps each entry with the clock and
// reads newest first (directory.Service.RecentMatching).
type stampAudit struct {
	mu      sync.Mutex
	now     func() time.Time
	entries []directory.AuditEntry
	fail    error
	scan    int
}

func (a *stampAudit) Append(e directory.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	e.Time = a.now()
	a.entries = append(a.entries, e)
	return nil
}

// RecentMatchingScan reads newest first; scan bounds how many entries
// it decodes (0: all), the rest is then unread (whole false).
func (a *stampAudit) RecentMatchingScan(n int, _ int64, keep func(directory.AuditEntry) bool) ([]directory.AuditEntry, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return nil, false, a.fail
	}
	out := []directory.AuditEntry{}
	decoded := 0
	for i := len(a.entries) - 1; i >= 0 && len(out) < n; i-- {
		if a.scan > 0 && decoded == a.scan {
			return out, false, nil
		}
		decoded++
		if keep == nil || keep(a.entries[i]) {
			out = append(out, a.entries[i])
		}
	}
	return out, true, nil
}

// TestImpersonationHistoryFromHub (F22): the source main adds reads the
// audit and the kept record's apps, never the live apps function; a
// failure is named unknown.
func TestImpersonationHistoryFromHub(t *testing.T) {
	x := newImpFixture(t)
	au := &stampAudit{now: x.clock}
	x.h.SetAudit(au)
	x.h.history.mu.Lock()
	x.h.history.now = x.clock
	x.h.history.mu.Unlock()
	var calls int
	var mu sync.Mutex
	x.h.SetImpersonationApps(func(context.Context, state.Impersonation) ([]signinhistory.OpenedApp, bool) {
		mu.Lock()
		calls++
		mu.Unlock()
		return []signinhistory.OpenedApp{{Name: "Gitea"}, {Name: "Nextcloud", OwnSession: true}}, true
	})
	x.h.AddHistorySource(HistoryImpersonation, x.h.ImpersonationHistorySource(au.RecentMatchingScan))
	s := x.mustStart(t, "root", "alice")
	x.advance(time.Second)

	page, err := x.h.SignInHistory(x.ctx, "alice", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Detail != "running · ends 14:32 UTC" || page.Entries[0].By != "root" ||
		page.Entries[0].Reason != "checking quota" || page.Entries[0].Kind != signinhistory.KindImpersonation {
		t.Fatalf("running = %+v", page.Entries)
	}
	x.advance(11*time.Minute + 29*time.Second)
	if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	before := calls
	mu.Unlock()
	page, _ = x.h.SignInHistory(x.ctx, "alice", "", 50)
	want := "12 min · stopped by root · apps opened: Gitea, Nextcloud · Nextcloud keeps its own session and may have stayed signed in longer"
	if len(page.Entries) != 1 || page.Entries[0].Detail != want || !page.Entries[0].Time.Equal(impT0) {
		t.Errorf("ended = %+v", page.Entries)
	}
	mu.Lock()
	if calls != before {
		t.Errorf("the history ran the live apps function (%d → %d)", before, calls)
	}
	mu.Unlock()
	if strings.Contains(strings.Join(page.Unknown, ","), HistoryImpersonation) {
		t.Errorf("unknown = %v", page.Unknown)
	}
	// An audit flood (the scan no longer reaches the start): the kept
	// record still gives the entry, and the source is named unknown (a
	// start whose record is gone might be missing; review I5).
	for range 50 {
		x.advance(time.Second)
		au.Append(directory.AuditEntry{Actor: "root", Action: "group.rule", Target: "x", Result: "ok"})
	}
	au.mu.Lock()
	au.scan = 20
	au.mu.Unlock()
	page, _ = x.h.SignInHistory(x.ctx, "alice", "", 50)
	if len(page.Entries) != 1 || page.Entries[0].Detail != want || !strings.Contains(strings.Join(page.Unknown, ","), HistoryImpersonation) {
		t.Errorf("flooded = %+v", page)
	}
	au.mu.Lock()
	au.scan = 0
	au.mu.Unlock()
	// The record gone: the end detail's names, own_session false.
	x.h.mu.Lock()
	x.h.st.Impersonations = nil
	x.h.mu.Unlock()
	page, _ = x.h.SignInHistory(x.ctx, "alice", "", 50)
	if len(page.Entries) != 1 || page.Entries[0].Detail != "12 min · stopped by root · apps opened: Gitea, Nextcloud" {
		t.Errorf("record gone = %+v", page.Entries)
	}
	// bob's history has none of it.
	if page, _ := x.h.SignInHistory(x.ctx, "bob", "", 50); len(page.Entries) != 0 {
		t.Errorf("bob = %+v", page.Entries)
	}
	_ = s
	// The audit unreadable: the source is unknown.
	au.mu.Lock()
	au.fail = errors.New("audit unreadable")
	au.mu.Unlock()
	page, err = x.h.SignInHistory(x.ctx, "alice", "", 50)
	if err != nil || !strings.Contains(strings.Join(page.Unknown, ","), HistoryImpersonation) || len(page.Entries) != 0 {
		t.Errorf("failed = %+v, %v", page, err)
	}
}
