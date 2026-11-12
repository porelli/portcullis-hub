package signinhistory

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

const (
	impA = "0f3c0f3c0f3c0f3c0f3c0f3c0f3c0f3c"
	impB = "9a1d9a1d9a1d9a1d9a1d9a1d9a1d9a1d"
	impC = "c0ffeec0ffeec0ffeec0ffeec0ffee00"
	impD = "d00dd00dd00dd00dd00dd00dd00dd00d"
)

func auditImpStart(at time.Time, admin, target, id, reason, result string) directory.AuditEntry {
	return directory.AuditEntry{Time: at, Actor: admin, Action: "impersonation.start", Target: target,
		Detail: id + " · security_key · " + reason, Result: result}
}

func auditImpEnd(at time.Time, actor, target, detail string) directory.AuditEntry {
	return directory.AuditEntry{Time: at, Actor: actor, Action: "impersonation.end", Target: target, Detail: detail, Result: "ok"}
}

// newestFirst is the audit reader's order.
func newestFirst(es ...directory.AuditEntry) []directory.AuditEntry {
	out := append([]directory.AuditEntry(nil), es...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// TestImpersonationHistoryEntry (contract §8.2 Source 4, D44): one entry
// per ok start, joined with its end.
func TestImpersonationHistoryEntry(t *testing.T) {
	start := t0
	now := t0.Add(2 * time.Hour)
	stored := map[string][]OpenedApp{impA: {{Name: "Gitea"}, {Name: "Nextcloud", OwnSession: true}}}
	audit := newestFirst(
		auditImpStart(start, "root", "alice", impA, "checking quota · and the calendar", "ok"),
		auditImpStart(start.Add(time.Minute), "root", "alice", impB, "refused one", "refused"),
		auditImpEnd(start.Add(11*time.Minute+30*time.Second), "root", "alice", impA+" · stopped · 12 min · apps opened: Gitea, Nextcloud"),
	)
	src := ImpersonationSource{
		Audit: func(ctx context.Context, user string, since time.Time) ([]directory.AuditEntry, error) {
			return audit, nil
		},
		Stored: func(id string) ([]OpenedApp, bool) { a, ok := stored[id]; return a, ok },
		Now:    func() time.Time { return now },
	}
	got, err := src.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), now, 50)
	if err != nil {
		t.Fatal(err)
	}
	want := Entry{Time: start, Kind: KindImpersonation, By: "root", Reason: "checking quota · and the calendar",
		Detail: "12 min · stopped by root · apps opened: Gitea, Nextcloud · Nextcloud keeps its own session and may have stayed signed in longer"}
	want = withScore(want)
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("entries = %+v\nwant %+v", got, want)
	}

	// Running: "running · ends hh:mm UTC".
	until := time.Date(2026, 11, 10, 14, 32, 58, 0, time.UTC)
	src.Audit = func(context.Context, string, time.Time) ([]directory.AuditEntry, error) {
		return []directory.AuditEntry{auditImpStart(start, "root", "alice", impC, "looking", "ok")}, nil
	}
	src.Until = func(id string) (time.Time, bool) { return until, id == impC }
	got, _ = src.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), now, 50)
	if len(got) != 1 || got[0].Detail != "running · ends 14:32 UTC" || got[0].Reason != "looking" {
		t.Errorf("running = %+v", got)
	}

	// Not used; expired; switched off; the record gone: the end detail's
	// names, own_session false; apps none.
	src.Until = nil
	cases := []struct {
		end, actor, want string
	}{
		{impD + " · not_used · 0 min · not used", "portcullis", "not used"},
		{impD + " · expired · 30 min · apps opened: none", "portcullis", "30 min · expired · apps opened: none"},
		{impD + " · switched_off · 4 min · apps opened: Gitea, Nextcloud", "portcullis", "4 min · switched off · apps opened: Gitea, Nextcloud"},
		{impD + " · stopped · 1 min · apps opened: Wiki", "bob", "1 min · stopped by bob · apps opened: Wiki"},
	}
	for _, c := range cases {
		src.Audit = func(context.Context, string, time.Time) ([]directory.AuditEntry, error) {
			return newestFirst(auditImpStart(start, "root", "alice", impD, "r1x", "ok"), auditImpEnd(start.Add(time.Minute), c.actor, "alice", c.end)), nil
		}
		got, _ = src.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), now, 50)
		if len(got) != 1 || got[0].Detail != c.want {
			t.Errorf("%q: entries = %+v, want detail %q", c.end, got, c.want)
		}
	}

	// Another person's entries (by target) are not alice's; a malformed id
	// is dropped.
	src.Audit = func(context.Context, string, time.Time) ([]directory.AuditEntry, error) {
		return []directory.AuditEntry{
			auditImpStart(start, "root", "bob", impA, "alice asked", "ok"),
			auditImpStart(start, "root", "alice", "not-an-id", "x y z", "ok"),
		}, nil
	}
	if got, _ := src.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), now, 50); len(got) != 0 {
		t.Errorf("foreign / malformed kept: %+v", got)
	}
}

func TestImpersonationDetail(t *testing.T) {
	apps := []OpenedApp{{Name: "Gitea"}, {Name: "Nextcloud", OwnSession: true}, {Name: "Office", OwnSession: true}}
	if got, want := ImpersonationDetail(12, "stopped", "root", apps, true),
		"12 min · stopped by root · apps opened: Gitea, Nextcloud, Office · Nextcloud keeps its own session and may have stayed signed in longer · Office keeps its own session and may have stayed signed in longer"; got != want {
		t.Errorf("detail = %q\nwant %q", got, want)
	}
	if got := ImpersonationDetail(12, "expired", "", nil, false); got != "not used" {
		t.Errorf("unused = %q", got)
	}
	if got := ImpersonationDetail(0, "not_used", "", nil, true); got != "not used" {
		t.Errorf("not_used = %q", got)
	}
	if got := ImpersonationDetail(3, "switched_off", "portcullis", nil, true); got != "3 min · switched off · apps opened: none" {
		t.Errorf("switched off = %q", got)
	}
}

// TestImpersonationSourceWindowAndLimit (F22): starts in [since, before)
// only, an end after before still joins, newest first and stable,
// limit; a failure is the source's.
func TestImpersonationSourceWindowAndLimit(t *testing.T) {
	since, before, now := t0.Add(-time.Hour), t0, t0.Add(3*time.Hour)
	var askedSince time.Time
	storedCalls := 0
	audit := newestFirst(
		auditImpStart(since.Add(-time.Minute), "root", "alice", impA, "before since", "ok"),
		auditImpStart(since.Add(10*time.Minute), "root", "alice", impB, "equal one", "ok"),
		auditImpStart(since.Add(10*time.Minute), "bob", "alice", impC, "equal two", "ok"),
		auditImpStart(before.Add(-time.Minute), "root", "alice", impD, "inside, ends after before", "ok"),
		auditImpEnd(before.Add(20*time.Minute), "root", "alice", impD+" · stopped · 21 min · apps opened: Gitea"),
		auditImpStart(before, "root", "alice", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "at before", "ok"),
	)
	src := ImpersonationSource{
		Audit: func(ctx context.Context, user string, s time.Time) ([]directory.AuditEntry, error) {
			askedSince = s
			return audit, nil
		},
		Stored: func(string) ([]OpenedApp, bool) { storedCalls++; return nil, false },
		Now:    func() time.Time { return now },
	}
	got, err := src.Entries(context.Background(), "alice", since, before, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !askedSince.Equal(since) {
		t.Errorf("audit read from %v, want since", askedSince)
	}
	var reasons []string
	for _, e := range got {
		reasons = append(reasons, e.Reason)
	}
	// Equal times keep the audit's (newest first) order.
	if want := []string{"inside, ends after before", "equal two", "equal one"}; !reflect.DeepEqual(reasons, want) {
		t.Fatalf("reasons = %q, want %q", reasons, want)
	}
	if got[0].Detail != "21 min · stopped by root · apps opened: Gitea" {
		t.Errorf("joined end = %q", got[0].Detail)
	}
	if storedCalls == 0 {
		t.Error("Stored never asked")
	}
	if got, _ := src.Entries(context.Background(), "alice", since, before, 2); len(got) != 2 || got[1].Reason != "equal two" {
		t.Errorf("limit 2 = %+v", got)
	}
	if got, _ := src.Entries(context.Background(), "alice", since, before, 0); len(got) != 0 {
		t.Errorf("limit 0 = %+v", got)
	}
	src.Audit = func(context.Context, string, time.Time) ([]directory.AuditEntry, error) {
		return nil, errors.New("audit unreadable")
	}
	if _, err := src.Entries(context.Background(), "alice", since, before, 50); err == nil {
		t.Error("a failed audit read answered entries")
	}
	// No Stored wired: the end's names.
	src.Audit = func(context.Context, string, time.Time) ([]directory.AuditEntry, error) { return audit, nil }
	src.Stored = nil
	if got, _ := src.Entries(context.Background(), "alice", since, before, 1); len(got) != 1 || !strings.Contains(got[0].Detail, "Gitea") {
		t.Errorf("no Stored = %+v", got)
	}
}

// TestFromAuditStillDropsImpersonation (F29, a guard test): part 2's
// audit source never emits impersonation.*.
func TestFromAuditStillDropsImpersonation(t *testing.T) {
	for _, a := range []directory.AuditEntry{
		auditImpStart(t0, "root", "alice", impA, "checking quota", "ok"),
		auditImpEnd(t0, "root", "alice", impA+" · stopped · 12 min · apps opened: Gitea"),
		{Time: t0, Actor: "root", Action: "signin.impersonation", Target: "alice", Detail: "off", Result: "ok"},
	} {
		if e, ok := FromAudit(a, "alice"); ok {
			t.Errorf("%s kept: %+v", a.Action, e)
		}
	}
}

// TestOpenedAndEventsByActor (D44): an opened line with act, and an SSO
// LOGIN with pc_act, are the administrator's (By).
func TestOpenedAndEventsByActor(t *testing.T) {
	dir := t.TempDir()
	day := t0.Truncate(24 * time.Hour)
	writeDay(t, dir, day,
		strings.Replace(line(t0.Add(-time.Hour), "alice", "s1", "files.example.com"), `"act":""`, `"act":"root"`, 1),
		line(t0.Add(-30*time.Minute), "alice", "s2", "wiki.example.com"),
	)
	got, err := OpenedLog{Dir: dir}.Entries(context.Background(), "alice", t0.AddDate(0, 0, -1), t0, 50)
	if err != nil || len(got) != 2 {
		t.Fatalf("entries = %+v, %v", got, err)
	}
	if got[0].By != "" || got[1].By != "root" {
		t.Errorf("by = %q, %q", got[0].By, got[1].By)
	}
	names := map[string]string{"nextcloud": "Nextcloud"}
	e, ok := FromEvent(login("nextcloud", map[string]string{"pc_kind": "sso", "pc_session": "security_key", "pc_act": "root"}), names)
	if !ok || e.Kind != KindOpened || e.By != "root" {
		t.Errorf("sso with pc_act = %+v (%v)", e, ok)
	}
	if e, _ := FromEvent(login("nextcloud", map[string]string{"pc_kind": "sso"}), names); e.By != "" {
		t.Errorf("sso without pc_act: by %q", e.By)
	}
}

// TestOpenedActApps: the apps of the lines with act in [from, to], once
// each, in time order.
func TestOpenedActApps(t *testing.T) {
	dir := t.TempDir()
	day := t0.Truncate(24 * time.Hour)
	act := func(at time.Time, user, session, host, app, a string) string {
		return `{"time":"` + at.Format(time.RFC3339) + `","user":"` + user + `","session":"` + session + `","host":"` + host +
			`","app":"` + app + `","methods":[],"ip":"","ua":"","act":"` + a + `"}`
	}
	from, to := t0.Add(-time.Hour), t0
	writeDay(t, dir, day,
		act(from.Add(-time.Second), "alice", "s1", "old.example.com", "Old", "root"), // before from
		act(from, "alice", "s1", "gitea.example.com", "Gitea", "root"),
		act(from.Add(time.Minute), "alice", "s1", "files.example.com", "", "root"), // no app: the host
		act(from.Add(2*time.Minute), "alice", "s1", "gitea.example.com", "Gitea", "root"),
		act(from.Add(3*time.Minute), "alice", "s1", "wiki.example.com", "Wiki", "bob"), // another admin
		act(from.Add(4*time.Minute), "alice", "s1", "plain.example.com", "Plain", ""),  // not impersonated
		act(from.Add(5*time.Minute), "bob", "s7", "chat.example.com", "Chat", "root"),  // another person
		act(to, "alice", "s1", "photos.example.com", "Photos", "root"),                 // at to: inside
		act(to.Add(time.Second), "alice", "s1", "late.example.com", "Late", "root"),    // after to
	)
	got, err := OpenedLog{Dir: dir}.ActApps("alice", "root", from, to)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Gitea", "files.example.com", "Photos"}; !reflect.DeepEqual(got, want) {
		t.Errorf("apps = %q, want %q", got, want)
	}
	// Across midnight: both days read.
	dir2 := t.TempDir()
	mid := day.Add(24 * time.Hour)
	writeDay(t, dir2, day, act(mid.Add(-time.Minute), "alice", "s1", "a.example.com", "A", "root"))
	writeDay(t, dir2, mid, act(mid.Add(time.Minute), "alice", "s1", "b.example.com", "B", "root"))
	if got, err := (OpenedLog{Dir: dir2}).ActApps("alice", "root", mid.Add(-10*time.Minute), mid.Add(10*time.Minute)); err != nil ||
		!reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Errorf("across midnight = %q, %v", got, err)
	}
	if _, err := (OpenedLog{Dir: "/nonexistent-mount"}).ActApps("alice", "root", from, to); err == nil {
		t.Error("a missing mount read as no apps")
	}
}

// TestOpenedActAppsPartial: a day file longer than the read limit (older
// lines unread) answers *Partial with what it read.
func TestOpenedActAppsPartial(t *testing.T) {
	dir := t.TempDir()
	day := t0.Truncate(24 * time.Hour)
	pad := `{"time":"` + t0.Add(-2*time.Hour).Format(time.RFC3339) + `","user":"bob","session":"x","host":"h","app":"` + strings.Repeat("p", 1000) + `","act":""}`
	lines := make([]string, 0, OpenedScan/len(pad)+2)
	for range OpenedScan/len(pad) + 1 {
		lines = append(lines, pad)
	}
	lines = append(lines, `{"time":"`+t0.Add(-time.Minute).Format(time.RFC3339)+`","user":"alice","session":"s","host":"g","app":"Gitea","act":"root"}`)
	writeDay(t, dir, day, lines...)
	got, err := OpenedLog{Dir: dir}.ActApps("alice", "root", t0.Add(-time.Hour), t0)
	var p *Partial
	if !errors.As(err, &p) || !reflect.DeepEqual(got, []string{"Gitea"}) {
		t.Errorf("long day file = %q, %v", got, err)
	}
	if got := ImpersonationDetail(5, "stopped", "root", []OpenedApp{{Name: "Gitea"}, {Name: MoreApps}}, true); got != "5 min · stopped by root · apps opened: Gitea, possibly other apps" {
		t.Errorf("marker detail = %q", got)
	}
}
