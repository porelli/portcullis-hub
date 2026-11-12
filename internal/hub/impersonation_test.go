package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/signinhistory"
	"github.com/portcullis/hub/internal/state"
)

// impKC is the Keycloak side of the impersonation rules: disabled
// people, required actions, the notices added (with the file as it was
// when each was added).
type impKC struct {
	mu        sync.Mutex
	disabled  map[string]bool
	actions   map[string][]string
	notices   []string
	err       error
	fileAtAdd []string
	path      string
	noticeErr error
}

func (k *impKC) UserEnabled(_ context.Context, u string) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return false, k.err
	}
	if u == "ghost" {
		return false, keycloak.ErrUserNotFound
	}
	return !k.disabled[u], nil
}

func (k *impKC) RequiredActions(_ context.Context, u string) ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.actions[u]), k.err
}

func (k *impKC) RequireImpersonationNotice(_ context.Context, u string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.noticeErr != nil {
		return k.noticeErr
	}
	k.notices = append(k.notices, u)
	b, _ := os.ReadFile(k.path)
	k.fileAtAdd = append(k.fileAtAdd, string(b))
	return nil
}

func (k *impKC) noticed() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.notices)
}

// touchFA is a verifier answering pc_fresh method for user (or as).
type touchFA struct {
	fakeFreshAuth
	mu     sync.Mutex
	method string
	as     string
	sid    string
}

func (f *touchFA) Verify(_ context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	u := user
	if f.as != "" {
		u = f.as
	}
	return &freshauth.Result{User: u, AuthTime: impT0.Add(-7 * time.Second), Method: f.method, SID: f.sid}, nil
}

func (f *touchFA) set(method, as string, err error) {
	f.mu.Lock()
	f.method, f.as, f.err = method, as, err
	f.mu.Unlock()
}

var impT0 = time.Date(2026, 11, 12, 14, 2, 58, 0, time.UTC)

type impFixture struct {
	f     *fixture
	h     *Hub
	audit *fakeAudit
	kc    *impKC
	fa    *touchFA
	ctx   context.Context
	mu    sync.Mutex
	now   time.Time
}

func (x *impFixture) clock() time.Time {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.now
}

func (x *impFixture) advance(d time.Duration) {
	x.mu.Lock()
	x.now = x.now.Add(d)
	x.mu.Unlock()
}

func newImpFixture(t *testing.T) *impFixture {
	t.Helper()
	f, audit := signInFixture(t)
	x := &impFixture{f: f, h: f.h, audit: audit, ctx: context.Background(), now: impT0}
	// The clock first: every file write (setSignIn's too) on the fake
	// clock, never the real one (CI 43261328739: a real-clock written
	// after impT0 kept the file from being due).
	f.h.imp.now = x.clock
	p := newFakePeople("alice", "bob", "carol", "portcullis-x")
	p.addGroup(lldap.AdminGroup, "root", "sam", "ann")
	f.h.SetPeople(adminPeople{p})
	setSignIn(f, func(si *state.SignIn) {
		for m := range allOn() {
			si.Methods[string(m)] = true
		}
		si.Methods[string(signin.BrowserCert)] = true
	})
	x.kc = &impKC{disabled: map[string]bool{}, actions: map[string][]string{}, path: filepath.Join(f.data, ImpersonationFileName)}
	x.fa = &touchFA{method: "security_key"}
	f.h.SetImpersonationKeycloak(x.kc)
	f.h.SetFreshAuth(ListenerPeople, x.fa)
	f.h.SetFreshAuth(ListenerHub, x.fa)
	f.h.freshAuthReady.Store(true)
	return x
}

var impProof = freshauth.Proof{Code: "SECRETCODE", CodeVerifier: "SECRETVERIFIER", Nonce: "SECRETNONCE"}

func (x *impFixture) start(admin, target, reason string) (*StartedImpersonation, error) {
	return x.h.StartImpersonation(x.ctx, StartImpersonation{Target: target, Reason: reason, AdminSID: "f7c1e2d4-1b2a-4c3d-9e8f-001122334455",
		Listener: ListenerPeople, Proof: impProof}, directory.Human(admin))
}

func (x *impFixture) mustStart(t *testing.T, admin, target string) *StartedImpersonation {
	t.Helper()
	s, err := x.start(admin, target, "checking quota")
	if err != nil {
		t.Fatalf("start %s → %s: %v", admin, target, err)
	}
	return s
}

func (x *impFixture) rec(id string) state.Impersonation {
	x.h.mu.RLock()
	defer x.h.mu.RUnlock()
	for _, r := range x.h.st.Impersonations {
		if r.ID == id {
			return r.Clone()
		}
	}
	return state.Impersonation{}
}

// file reads impersonation.json, checked against the readers' rules.
func (x *impFixture) file(t *testing.T) impFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(x.f.data, ImpersonationFileName))
	if err != nil {
		t.Fatal(err)
	}
	return checkImpFileStrict(t, b, x.clock())
}

// TestImpersonationOnByZeroValue (D36.1): an empty state allows it; the
// switch off refuses every start with D36.1's text.
func TestImpersonationOnByZeroValue(t *testing.T) {
	x := newImpFixture(t)
	if v := x.h.Impersonations(); !v.Allowed || v.MaxMinutes != 30 || len(v.Running) != 0 || len(v.Recent) != 0 {
		t.Errorf("view = %+v", v)
	}
	setSignIn(x.f, func(si *state.SignIn) { si.ImpersonationOff = true })
	_, err := x.start("root", "alice", "checking quota")
	if statusOf(err) != 409 || err.Error() != "signing in as someone else is switched off (Settings → Sign-in)" {
		t.Errorf("off: %v", err)
	}
	if e := x.audit.lastOf("impersonation.start"); e.Result != "refused" || e.Actor != "root" || e.Target != "alice" {
		t.Errorf("audit = %+v", e)
	}
}

// TestStartImpersonationRules (D36): the order, each status and text.
func TestStartImpersonationRules(t *testing.T) {
	x := newImpFixture(t)
	x.kc.disabled["carol"] = true
	// Every call in a new refusal window (the limit is TestStartImpersonationFreshTouch's).
	var limMu sync.Mutex
	lim := impT0
	x.h.entryNow = func() time.Time {
		limMu.Lock()
		defer limMu.Unlock()
		lim = lim.Add(2 * time.Minute)
		return lim
	}
	for _, c := range []struct {
		admin, target, reason string
		status                int
		text                  string
	}{
		{"alice", "bob", "checking quota", 403, "not allowed: admins only"},
		{"root", "nobody", "checking quota", 404, "no such person: nobody"},
		{"root", "ghost", "checking quota", 404, "no such person: ghost"},
		{"root", "root", "checking quota", 409, "you can't sign in as yourself"},
		{"root", "admin", "checking quota", 409, "this account can't be signed in as"},
		{"root", "portcullis-hub", "checking quota", 409, "this account can't be signed in as"},
		{"root", "portcullis-x", "checking quota", 409, "this account can't be signed in as"},
		{"root", "sam", "checking quota", 409, "administrators can't be signed in as"},
		{"root", "carol", "checking quota", 409, "this account is disabled"},
		{"root", "alice", "", 400, "type a reason (3–200 characters, one line)"},
		{"root", "alice", "ab", 400, "type a reason (3–200 characters, one line)"},
		{"root", "alice", strings.Repeat("é", 201), 400, "type a reason (3–200 characters, one line)"},
		{"root", "alice", "a\nb c", 400, "type a reason (3–200 characters, one line)"},
		{"root", "alice", "check‮quota", 400, "type a reason (3–200 characters, one line)"},
	} {
		_, err := x.start(c.admin, c.target, c.reason)
		if statusOf(err) != c.status || err.Error() != c.text {
			t.Errorf("%s → %s %q: %v, want %d %q", c.admin, c.target, c.reason, err, c.status, c.text)
		}
		if e := x.audit.last(); e.Action != "impersonation.start" || e.Result != "refused" {
			t.Errorf("%s → %s: audit %+v", c.admin, c.target, e)
		}
	}
	// The reason only on an administrator's own refusals.
	_, _ = x.start("alice", "bob", "typed by alice")
	if e := x.audit.last(); strings.Contains(e.Detail, "typed by alice") {
		t.Errorf("a non-admin's reason was audited: %+v", e)
	}
	_, _ = x.start("root", "carol", "typed by root")
	if e := x.audit.last(); !strings.Contains(e.Detail, "typed by root") {
		t.Errorf("an admin's refusal lacks the reason: %+v", e)
	}
	if n := x.fa.calls.Load(); n != 0 {
		t.Errorf("the verifier ran %d times before rule 9", n)
	}
	// 5. One at a time.
	s := x.mustStart(t, "root", "alice")
	_, err := x.start("root", "bob", "checking quota")
	if want := "you are signed in as alice until " + x.rec(s.ID).Until.Format("15:04") + ": Stop it first"; statusOf(err) != 409 || err.Error() != want {
		t.Errorf("caller runs one: %v, want %q", err, want)
	}
	if _, err := x.start("sam", "alice", "checking quota"); statusOf(err) != 409 || err.Error() != "root is signed in as alice right now" {
		t.Errorf("target taken: %v", err)
	}
	// 6. Unfinished steps (the notice action alone is fine).
	x.kc.actions["bob"] = []string{keycloak.PasskeyAction}
	if _, err := x.start("sam", "bob", "checking quota"); statusOf(err) != 409 || err.Error() != "bob has an unfinished sign-in step (a setup link?): finish or cancel it first" {
		t.Errorf("unfinished: %v", err)
	}
	x.kc.actions["bob"] = []string{keycloak.ImpersonationNoticeAction}
	// 8. No sid.
	if _, err := x.h.StartImpersonation(x.ctx, StartImpersonation{Target: "bob", Reason: "checking quota", Listener: ListenerPeople, Proof: impProof},
		directory.Human("sam")); statusOf(err) != 403 || err.Error() != "your sign-in can't be read: sign in again" {
		t.Errorf("no sid: %v", err)
	}
	// 7. No touch method: before the proof is exchanged.
	setSignIn(x.f, func(si *state.SignIn) { si.Methods["security_key"], si.Methods["yubikey_cert"] = false, false })
	if _, err := x.start("sam", "bob", "checking quota"); statusOf(err) != 409 || err.Error() != "signing in as someone needs security keys or YubiKey certificates switched on" {
		t.Errorf("no touch method: %v", err)
	}
	if n := x.fa.calls.Load(); n != 1 {
		t.Errorf("verifier calls = %d, want 1 (the one start)", n)
	}
	// Keycloak unavailable: 503.
	x.kc.err = errors.New("down")
	setSignIn(x.f, func(si *state.SignIn) { si.Methods["security_key"] = true })
	if _, err := x.start("sam", "bob", "checking quota"); statusOf(err) != 503 {
		t.Errorf("keycloak down: %v", err)
	}
}

// TestStartImpersonationFreshTouch (D36.9, F11).
func TestStartImpersonationFreshTouch(t *testing.T) {
	x := newImpFixture(t)
	// No governing template applies: the people page on password only.
	setSignIn(x.f, func(si *state.SignIn) {
		si.Templates["pw"] = state.SignInTemplate{Name: "PW", Rule: passwordOnly, Enabled: true}
		si.Core["people"] = "pw"
	})
	for _, m := range []string{"security_key", "yubikey_cert"} {
		x.fa.set(m, "", nil)
		s := x.mustStart(t, "root", "alice")
		if r := x.rec(s.ID); r.Fresh != m {
			t.Errorf("fresh = %q", r.Fresh)
		}
		if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("root")); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(label string) {
		t.Helper()
		_, err := x.start("root", "alice", "checking quota")
		if statusOf(err) != 403 || err.Error() != freshauth.Message {
			t.Errorf("%s: %v", label, err)
		}
	}
	for _, m := range []string{"passkey_synced", "passkey_device", "password", "browser_cert"} {
		x.fa.set(m, "", nil)
		refused(m)
	}
	x.fa.set("security_key", "sam", nil)
	refused("another person's proof")
	x.fa.set("security_key", "", nil)
	setSignIn(x.f, func(si *state.SignIn) { si.Methods["security_key"] = false })
	refused("security_key off")
	setSignIn(x.f, func(si *state.SignIn) { si.Methods["security_key"] = true })
	x.fa.set("security_key", "", &freshauth.Error{Reason: "nonce mismatch"})
	refused("a refused proof")
	x.fa.set("security_key", "", &freshauth.Error{Reason: freshauth.ReasonUnreachable})
	if _, err := x.start("root", "alice", "checking quota"); statusOf(err) != 503 {
		t.Errorf("unreachable: %v", err)
	}
	x.fa.set("security_key", "", nil)
	x.h.freshAuthReady.Store(false)
	if _, err := x.start("root", "alice", "checking quota"); statusOf(err) != 503 {
		t.Errorf("not ready: %v", err)
	}
	x.h.freshAuthReady.Store(true)
	// Every refusal audited, no proof value anywhere.
	x.audit.mu.Lock()
	n := 0
	for _, e := range x.audit.entries {
		if e.Action != "impersonation.start" {
			continue
		}
		if e.Result == "refused" {
			n++
		}
		if b, _ := json.Marshal(e); strings.Contains(string(b), "SECRET") {
			t.Errorf("a proof value was audited: %s", b)
		}
	}
	x.audit.mu.Unlock()
	if n != 7 {
		t.Errorf("%d refusals audited, want 7", n)
	}
	// Refusals count toward the limit: 7 refused, 3 more → limited.
	x.fa.set("password", "", nil)
	for range 3 {
		refused("toward the limit")
	}
	x.fa.set("security_key", "", nil)
	if _, err := x.start("root", "alice", "checking quota"); statusOf(err) != 429 {
		t.Errorf("after 10 refusals: %v, want 429", err)
	}
}

// TestStartImpersonationRecord (D38, F2, F3).
func TestStartImpersonationRecord(t *testing.T) {
	x := newImpFixture(t)
	s := x.mustStart(t, "root", "alice")
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(s.ID) {
		t.Errorf("id %q", s.ID)
	}
	if s.Next != "https://auth.example.org/realms/portcullis/portcullis-impersonate/start?id="+s.ID || !s.Until.Equal(impT0.Add(30*time.Minute)) {
		t.Errorf("answer = %+v", s)
	}
	st, err := state.Load(filepath.Join(x.f.data, "state.yaml"))
	if err != nil || len(st.Impersonations) != 1 || st.Impersonations[0].ID != s.ID || st.Impersonations[0].AdminSID == "" {
		t.Fatalf("saved = %+v, %v", st.Impersonations, err)
	}
	doc := x.file(t)
	if len(doc.Pending) != 1 || len(doc.Sessions) != 1 {
		t.Fatalf("file = %+v", doc)
	}
	p, ss := doc.Pending[0], doc.Sessions[0]
	if p.ID != s.ID || p.Admin != "root" || p.Target != "alice" || p.AdminSID != "f7c1e2d4-1b2a-4c3d-9e8f-001122334455" || p.Fresh != "security_key" ||
		p.Reason != "checking quota" || p.Created != "2026-11-12T14:02:58Z" || p.Until != "2026-11-12T14:32:58Z" || p.FreshAt != "2026-11-12T14:02:51Z" {
		t.Errorf("pending = %+v", p)
	}
	if ss.ID != s.ID || ss.Started != p.Created || ss.Ended != nil || ss.Until != p.Until {
		t.Errorf("session = %+v", ss)
	}
	if e := x.audit.lastOf("impersonation.start"); e.Result != "ok" || e.Actor != "root" || e.Target != "alice" || e.Detail != s.ID+" · security_key · checking quota" {
		t.Errorf("audit = %+v", e)
	}
	if v := x.h.ImpersonationOf("alice", s.ID); v == nil || v.Admin != "root" || v.Ended != nil {
		t.Errorf("ImpersonationOf = %+v", v)
	}
	if x.h.ImpersonationOf("bob", s.ID) != nil || x.h.ImpersonationOf("alice", otherImpID(s.ID)) != nil {
		t.Error("ImpersonationOf matched another person or id")
	}
	if v := x.h.Impersonations(); len(v.Running) != 1 || v.Running[0].ID != s.ID {
		t.Errorf("view = %+v", v)
	}
	// Pending drops out at 120 s; the session stays.
	x.advance(121 * time.Second)
	x.h.mu.RLock()
	_ = x.h.writeImpersonationFileLocked()
	x.h.mu.RUnlock()
	if doc := x.file(t); len(doc.Pending) != 0 || len(doc.Sessions) != 1 {
		t.Errorf("after 120 s = %+v", doc)
	}
}

// TestImpersonationRecordsKept (F1): used, ended records stay until
// history_days with their apps; the not-used ones an hour.
func TestImpersonationRecordsKept(t *testing.T) {
	x := newImpFixture(t)
	x.h.SetImpersonationApps(func(_ context.Context, r state.Impersonation) ([]signinhistory.OpenedApp, bool) {
		if r.Target == "bob" {
			return nil, false
		}
		return []signinhistory.OpenedApp{{Name: "Gitea"}}, true
	})
	a := x.mustStart(t, "root", "alice")
	b := x.mustStart(t, "sam", "bob")
	x.advance(time.Minute)
	if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if err := x.h.StopImpersonation(x.ctx, "bob", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if r := x.rec(a.ID); !r.Used || len(r.Apps) != 1 || r.Apps[0].Name != "Gitea" {
		t.Errorf("alice's record = %+v", r)
	}
	if r := x.rec(b.ID); r.Used || r.How != ImpNotUsed {
		t.Errorf("bob's record = %+v", r)
	}
	x.advance(61 * time.Minute)
	x.h.impersonationTick(x.ctx)
	if x.rec(b.ID).ID != "" || x.rec(a.ID).ID == "" {
		t.Errorf("after an hour: %+v", x.h.Impersonations())
	}
	doc := x.file(t)
	if len(doc.Sessions) != 0 || len(doc.Notices["alice"]) != 1 || doc.Notices["alice"][0].Apps[0].Name != "Gitea" {
		t.Errorf("file = %+v", doc)
	}
	x.advance(365 * 24 * time.Hour)
	x.h.impersonationTick(x.ctx)
	if x.rec(a.ID).ID != "" {
		t.Error("kept past history_days")
	}
	if doc := x.file(t); len(doc.Notices) != 0 {
		t.Errorf("notices = %+v", doc.Notices)
	}
}

// TestImpersonationOutsideSignIn (F3): a start, stop or the switch
// between the sign-in writer's two plans never makes it 409, and its
// commit keeps the switch written meanwhile.
func TestImpersonationOutsideSignIn(t *testing.T) {
	x2 := newImpFixture(t)
	between := func() {
		s := x2.mustStart(t, "root", "alice")
		if err := x2.h.StopImpersonation(x2.ctx, "alice", directory.Human("root")); err != nil {
			t.Fatal(err)
		}
		_ = s
		x2.h.impersonationTick(x2.ctx)
		if _, err := x2.h.SetImpersonationAllowed(x2.ctx, false, siAdmin); err != nil {
			t.Fatal(err)
		}
	}
	x2.h.signInBetweenPlans = between
	if err := x2.h.SetAddStronger(!x2.h.st.SignIn.AddStronger, siAdmin); err != nil {
		t.Fatalf("a sign-in change with impersonation writers in between: %v", err)
	}
	x2.h.mu.RLock()
	off := x2.h.st.SignIn.ImpersonationOff
	x2.h.mu.RUnlock()
	if !off {
		t.Error("the sign-in commit lost the switch written meanwhile")
	}
	st, _ := state.Load(filepath.Join(x2.f.data, "state.yaml"))
	if !st.SignIn.ImpersonationOff || len(st.Impersonations) != 1 {
		t.Errorf("saved: off %v, %d records", st.SignIn.ImpersonationOff, len(st.Impersonations))
	}
}

// TestExpiryEnds (D41, F2).
func TestExpiryEnds(t *testing.T) {
	x := newImpFixture(t)
	used := true
	var mu sync.Mutex
	x.h.SetImpersonationApps(func(context.Context, state.Impersonation) ([]signinhistory.OpenedApp, bool) {
		mu.Lock()
		defer mu.Unlock()
		return nil, used
	})
	// Used (or the events unreadable: counted as used): runs until until.
	s := x.mustStart(t, "root", "alice")
	x.advance(125 * time.Second)
	x.h.impersonationTick(x.ctx)
	if r := x.rec(s.ID); !r.Running() || !r.Used {
		t.Fatalf("used at 120 s: %+v", r)
	}
	x.advance(28 * time.Minute)
	x.h.impersonationTick(x.ctx)
	if r := x.rec(s.ID); r.How != ImpExpired || r.EndedBy != "portcullis" || r.Running() {
		t.Fatalf("at until: %+v", r)
	}
	e := x.audit.lastOf("impersonation.end")
	if e.Actor != "portcullis" || e.Target != "alice" || e.Detail != s.ID+" · expired · 30 min · apps opened: none" {
		t.Errorf("audit = %+v", e)
	}
	if doc := x.file(t); len(doc.Sessions) != 1 || doc.Sessions[0].Ended == nil {
		t.Errorf("file = %+v", doc)
	}
	if n := x.kc.noticed(); !slices.Equal(n, []string{"alice"}) {
		t.Errorf("notices = %v", n)
	}
	// Not used at created + 120 s: not_used, no notice, may start again.
	mu.Lock()
	used = false
	mu.Unlock()
	s = x.mustStart(t, "root", "bob")
	x.advance(119 * time.Second)
	x.h.impersonationTick(x.ctx)
	if !x.rec(s.ID).Running() {
		t.Fatal("ended before 120 s")
	}
	x.advance(time.Second)
	x.h.impersonationTick(x.ctx)
	if r := x.rec(s.ID); r.How != ImpNotUsed || r.Running() || r.Used {
		t.Fatalf("not used: %+v", r)
	}
	if e := x.audit.lastOf("impersonation.end"); e.Detail != s.ID+" · not_used · 0 min · not used" || e.Actor != "portcullis" {
		t.Errorf("audit = %+v", e)
	}
	if n := x.kc.noticed(); len(n) != 1 {
		t.Errorf("a not-used end added a notice: %v", n)
	}
	x.mustStart(t, "root", "bob")
}

// TestStopEnds (D41).
func TestStopEnds(t *testing.T) {
	x := newImpFixture(t)
	s := x.mustStart(t, "root", "alice")
	if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("alice")); statusOf(err) != 403 {
		t.Errorf("non-admin stop: %v", err)
	}
	if err := x.h.StopImpersonation(x.ctx, "bob", directory.Human("sam")); statusOf(err) != 404 {
		t.Errorf("none running: %v", err)
	}
	// Not a username: 400 first, even for a non-admin (Task 6 review M3).
	for _, u := range []string{"", "al/ice", "-x", strings.Repeat("a", 65)} {
		if err := x.h.StopImpersonation(x.ctx, u, directory.Human("alice")); statusOf(err) != 400 {
			t.Errorf("stop %q: %v", u, err)
		}
	}
	x.advance(90 * time.Second)
	if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("sam")); err != nil {
		t.Fatal(err)
	}
	if r := x.rec(s.ID); r.How != ImpStopped || r.EndedBy != "sam" {
		t.Errorf("record = %+v", r)
	}
	if e := x.audit.lastOf("impersonation.end"); e.Actor != "sam" || e.Detail != s.ID+" · stopped · 2 min · apps opened: none" {
		t.Errorf("audit = %+v", e)
	}
	// Stop from the impersonating browser.
	s = x.mustStart(t, "root", "alice")
	for _, c := range [][2]string{{otherImpID(s.ID), "alice"}, {s.ID, "bob"}, {"", "alice"}} {
		if _, err := x.h.StopOwnImpersonation(x.ctx, c[0], c[1]); statusOf(err) != 404 {
			t.Errorf("%v: %v", c, err)
		}
	}
	out, err := x.h.StopOwnImpersonation(x.ctx, s.ID, "alice")
	if err != nil || out != "https://auth.example.org/oauth2/sign_out?rd=https%3A%2F%2Fexample.org%2F" {
		t.Errorf("sign_out = %q, %v", out, err)
	}
	if r := x.rec(s.ID); r.How != ImpStopped || r.EndedBy != "root" {
		t.Errorf("record = %+v", r)
	}
	if e := x.audit.lastOf("impersonation.end"); e.Actor != "root" {
		t.Errorf("own stop audited as %q", e.Actor)
	}
	if x.h.ImpersonationOf("alice", s.ID) != nil {
		t.Error("still live after Stop")
	}
	if _, err := x.h.StopOwnImpersonation(x.ctx, s.ID, "alice"); statusOf(err) != 404 {
		t.Errorf("twice: %v", err)
	}
	if v := x.h.Impersonations(); len(v.Recent) != 2 || v.Recent[0].ID != s.ID || v.Recent[0].Ended == nil || v.Recent[0].How != ImpStopped {
		t.Errorf("recent = %+v", v.Recent)
	}
}

// TestSwitchOffEndsAll (D41).
func TestSwitchOffEndsAll(t *testing.T) {
	x := newImpFixture(t)
	a := x.mustStart(t, "root", "alice")
	b := x.mustStart(t, "sam", "bob")
	v, err := x.h.SetImpersonationAllowed(x.ctx, false, siAdmin)
	if err != nil || v.Allowed || len(v.Running) != 0 || len(v.Recent) != 2 {
		t.Fatalf("off = %+v, %v", v, err)
	}
	for _, id := range []string{a.ID, b.ID} {
		if r := x.rec(id); r.How != ImpSwitchedOff || r.EndedBy != "portcullis" {
			t.Errorf("record = %+v", r)
		}
	}
	if _, err := x.start("root", "alice", "checking quota"); statusOf(err) != 409 {
		t.Errorf("start while off: %v", err)
	}
	if e := x.audit.lastOf("signin.impersonation"); e.Detail != "off" || e.Actor != "root" || e.Result != "ok" {
		t.Errorf("audit = %+v", e)
	}
	if doc := x.file(t); doc.Allowed {
		t.Error("file allowed while off")
	}
	if v, err := x.h.SetImpersonationAllowed(x.ctx, true, siAdmin); err != nil || !v.Allowed {
		t.Errorf("on = %+v, %v", v, err)
	}
	if e := x.audit.lastOf("signin.impersonation"); e.Detail != "on" {
		t.Errorf("audit = %+v", e)
	}
	st, _ := state.Load(filepath.Join(x.f.data, "state.yaml"))
	if st.SignIn.ImpersonationOff {
		t.Error("saved off")
	}
}

// TestNoticeOnlyWhenUsed (D45, the Task 4 review): a used end adds the
// notice, after the file holds the notice; a not-used one never.
func TestNoticeOnlyWhenUsed(t *testing.T) {
	x := newImpFixture(t)
	used := true
	x.h.SetImpersonationApps(func(context.Context, state.Impersonation) ([]signinhistory.OpenedApp, bool) { return nil, used })
	s := x.mustStart(t, "root", "alice")
	if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if n := x.kc.noticed(); !slices.Equal(n, []string{"alice"}) {
		t.Fatalf("notices = %v", n)
	}
	// The file was written, with the notice, before the action was added.
	x.kc.mu.Lock()
	at := x.kc.fileAtAdd[0]
	x.kc.mu.Unlock()
	doc := checkImpFileStrict(t, []byte(at), x.clock())
	if len(doc.Notices["alice"]) != 1 || doc.Notices["alice"][0].ID != s.ID {
		t.Errorf("the file when the notice was added: %+v", doc)
	}
	used = false
	x.mustStart(t, "root", "bob")
	if err := x.h.StopImpersonation(x.ctx, "bob", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if n := x.kc.noticed(); len(n) != 1 {
		t.Errorf("a not-used end added a notice: %v", n)
	}
}

// TestEndDetailApps (contract §8.1 audit actions): the apps' names, the
// minutes rounded up.
func TestEndDetailApps(t *testing.T) {
	x := newImpFixture(t)
	x.h.SetImpersonationApps(func(context.Context, state.Impersonation) ([]signinhistory.OpenedApp, bool) {
		return []signinhistory.OpenedApp{{Name: "Gitea"}, {Name: "Nextcloud", OwnSession: true}}, true
	})
	s := x.mustStart(t, "root", "alice")
	x.advance(11*time.Minute + 30*time.Second)
	if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if e := x.audit.lastOf("impersonation.end"); e.Detail != s.ID+" · stopped · 12 min · apps opened: Gitea, Nextcloud" {
		t.Errorf("detail = %q", e.Detail)
	}
	if r := x.rec(s.ID); len(r.Apps) != 2 || !r.Apps[1].OwnSession {
		t.Errorf("apps = %+v", r.Apps)
	}
	for d, want := range map[time.Duration]int{0: 1, time.Second: 1, time.Minute: 1, time.Minute + time.Second: 2, 30 * time.Minute: 30} {
		if n := impMinutes(state.Impersonation{Started: impT0, Ended: impT0.Add(d)}); n != want {
			t.Errorf("%v = %d min, want %d", d, n, want)
		}
	}
}

// TestFileRewrittenEveryMinute (D37): written refreshes with no change.
func TestFileRewrittenEveryMinute(t *testing.T) {
	x := newImpFixture(t)
	x.h.impersonationTick(x.ctx)
	if doc := x.file(t); doc.Written != "2026-11-12T14:02:58Z" {
		t.Fatalf("written = %q", doc.Written)
	}
	x.advance(30 * time.Second)
	x.h.impersonationTick(x.ctx)
	if doc := x.file(t); doc.Written != "2026-11-12T14:02:58Z" {
		t.Errorf("rewritten after 30 s: %q", doc.Written)
	}
	x.advance(30 * time.Second)
	x.h.impersonationTick(x.ctx)
	if doc := x.file(t); doc.Written != "2026-11-12T14:03:58Z" {
		t.Errorf("not rewritten after a minute: %q", doc.Written)
	}
	// RunImpersonationExpiry ticks until ctx ends.
	ctx, cancel := context.WithCancel(x.ctx)
	done := make(chan struct{})
	go func() { x.h.RunImpersonationExpiry(ctx, time.Millisecond); close(done) }()
	x.advance(time.Minute)
	deadline := time.Now().Add(5 * time.Second)
	for x.file(t).Written != "2026-11-12T14:04:58Z" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if w := x.file(t).Written; w != "2026-11-12T14:04:58Z" {
		t.Errorf("the loop didn't rewrite it: %q", w)
	}
}

const impSID = "f7c1e2d4-1b2a-4c3d-9e8f-001122334455"

// breakState makes state.yaml unsaveable (a non-empty directory in its
// place); the returned func puts it back.
func (x *impFixture) breakState(t *testing.T) func() {
	t.Helper()
	p := filepath.Join(x.f.data, "state.yaml")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(p, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
	}
}

func (x *impFixture) saved(t *testing.T) *state.AppState {
	t.Helper()
	st, err := state.Load(filepath.Join(x.f.data, "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// TestSwitchOffNeverRolledBack (review I1): a failed save never keeps
// impersonations running: off in memory, every running one ended and
// the file written, the error reported; the loop saves it.
func TestSwitchOffNeverRolledBack(t *testing.T) {
	x := newImpFixture(t)
	a := x.mustStart(t, "root", "alice")
	b := x.mustStart(t, "sam", "bob")
	fix := x.breakState(t)
	if _, err := x.h.SetImpersonationAllowed(x.ctx, false, siAdmin); statusOf(err) != 500 {
		t.Fatalf("off with a failed save: %v", err)
	}
	for _, id := range []string{a.ID, b.ID} {
		if r := x.rec(id); r.Running() || r.How != ImpSwitchedOff {
			t.Errorf("record = %+v", r)
		}
	}
	doc := x.file(t)
	if doc.Allowed {
		t.Error("the file still allows it")
	}
	for _, s := range doc.Sessions {
		if s.Ended == nil {
			t.Errorf("session %s not ended in the file", s.ID)
		}
	}
	if x.h.Impersonations().Allowed {
		t.Error("the switch was rolled back")
	}
	if e := x.audit.lastOf("signin.impersonation"); e.Result != "error" || e.Detail != "off" {
		t.Errorf("audit = %+v", e)
	}
	fix()
	x.h.impersonationTick(x.ctx)
	if st := x.saved(t); !st.SignIn.ImpersonationOff || len(st.Impersonations) != 2 || st.Impersonations[0].Running() {
		t.Errorf("saved: off %v, %+v", st.SignIn.ImpersonationOff, st.Impersonations)
	}
	// Switching on with a failed save is taken back.
	fix = x.breakState(t)
	if _, err := x.h.SetImpersonationAllowed(x.ctx, true, siAdmin); statusOf(err) != 500 {
		t.Errorf("on with a failed save: %v", err)
	}
	if x.h.Impersonations().Allowed {
		t.Error("switched on although the save failed")
	}
	fix()
}

// TestEndSavedBeforeRestart (review M4): an end whose save fails is in
// the file at once, and the loop saves it, so a restart can't bring it
// back.
func TestEndSavedBeforeRestart(t *testing.T) {
	x := newImpFixture(t)
	s := x.mustStart(t, "root", "alice")
	fix := x.breakState(t)
	if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if doc := x.file(t); len(doc.Sessions) != 1 || doc.Sessions[0].Ended == nil {
		t.Errorf("file = %+v", doc)
	}
	fix()
	x.h.impersonationTick(x.ctx)
	st := x.saved(t)
	if len(st.Impersonations) != 1 || st.Impersonations[0].ID != s.ID || st.Impersonations[0].Running() || !st.Impersonations[0].Finished {
		t.Errorf("saved = %+v", st.Impersonations)
	}
}

// TestEndFinishedAfterCrash (review I2): an end whose second half never
// ran (a crash) or whose notice Keycloak refused is finished by the
// loop: apps, audit, notice — the notice retried until accepted.
func TestEndFinishedAfterCrash(t *testing.T) {
	x := newImpFixture(t)
	x.h.SetImpersonationApps(func(context.Context, state.Impersonation) ([]signinhistory.OpenedApp, bool) {
		return []signinhistory.OpenedApp{{Name: "Gitea"}}, true
	})
	s := x.mustStart(t, "root", "alice")
	// The end's first half only, as if the Hub stopped right after it.
	x.h.mu.Lock()
	x.h.endRunningLocked(func(state.Impersonation) bool { return true }, ImpStopped, "sam")
	x.h.mu.Unlock()
	if r := x.rec(s.ID); r.Finished || len(r.Apps) != 0 {
		t.Fatalf("record = %+v", r)
	}
	x.kc.mu.Lock()
	x.kc.noticeErr = errors.New("keycloak down")
	x.kc.mu.Unlock()
	x.h.impersonationTick(x.ctx)
	r := x.rec(s.ID)
	if !r.Finished || !r.NoticeOwed || !r.Used || len(r.Apps) != 1 {
		t.Fatalf("after the tick: %+v", r)
	}
	if e := x.audit.lastOf("impersonation.end"); e.Actor != "sam" || e.Detail != s.ID+" · stopped · 1 min · apps opened: Gitea" {
		t.Errorf("audit = %+v", e)
	}
	if st := x.saved(t); !st.Impersonations[0].NoticeOwed {
		t.Error("the owed notice isn't saved")
	}
	ends := 0
	x.h.impersonationTick(x.ctx)
	x.kc.mu.Lock()
	x.kc.noticeErr = nil
	x.kc.mu.Unlock()
	x.h.impersonationTick(x.ctx)
	if r := x.rec(s.ID); r.NoticeOwed {
		t.Errorf("still owed: %+v", r)
	}
	if n := x.kc.noticed(); !slices.Equal(n, []string{"alice"}) {
		t.Errorf("notices = %v", n)
	}
	x.audit.mu.Lock()
	for _, e := range x.audit.entries {
		if e.Action == "impersonation.end" {
			ends++
		}
	}
	x.audit.mu.Unlock()
	if ends != 1 {
		t.Errorf("%d end audits, want 1", ends)
	}
	x.h.impersonationTick(x.ctx)
	if n := x.kc.noticed(); len(n) != 1 {
		t.Errorf("notice added again: %v", n)
	}
}

// TestUsedNeverNotUsed (review M3): the not-used check's answer is the
// end's (asked once); a used end is never how not_used.
func TestUsedNeverNotUsed(t *testing.T) {
	x := newImpFixture(t)
	var mu sync.Mutex
	calls := 0
	x.h.SetImpersonationApps(func(context.Context, state.Impersonation) ([]signinhistory.OpenedApp, bool) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return nil, calls > 1 // not used at first, "used" if asked again
	})
	s := x.mustStart(t, "root", "alice")
	x.advance(impPendingFor)
	x.h.impersonationTick(x.ctx)
	if r := x.rec(s.ID); r.How != ImpNotUsed || r.Used || !r.Finished {
		t.Errorf("record = %+v", r)
	}
	if calls != 1 {
		t.Errorf("asked %d times", calls)
	}
	if n := x.kc.noticed(); len(n) != 0 {
		t.Errorf("notice for a not-used end: %v", n)
	}
	// A used answer on a not_used record: never left not_used.
	x2 := newImpFixture(t)
	s = x2.mustStart(t, "root", "alice")
	x2.h.mu.Lock()
	x2.h.endRunningLocked(func(state.Impersonation) bool { return true }, ImpNotUsed, impSystem)
	x2.h.mu.Unlock()
	x2.h.imp.endMu.Lock()
	x2.h.finishEnd(x2.ctx, s.ID, directory.Human(impSystem), &impAnswer{used: true})
	x2.h.imp.endMu.Unlock()
	if r := x2.rec(s.ID); r.How == ImpNotUsed || !r.Used {
		t.Errorf("used but %+v", r)
	}
}

// TestDroppedRecordEnded (review M5): a running record the file's writer
// must leave out is ended in state (expired) and audited.
func TestDroppedRecordEnded(t *testing.T) {
	x := newImpFixture(t)
	bad := state.Impersonation{ID: strings.Repeat("ab", 16), Admin: "root", Target: "alice", AdminSID: impSID, Reason: "x\x07y",
		Fresh: "security_key", FreshAt: impT0, Started: impT0, Until: impT0.Add(30 * time.Minute)}
	x.h.mu.Lock()
	x.h.st.Impersonations = []state.Impersonation{bad}
	x.h.mu.Unlock()
	if x.h.ImpersonationOf("alice", bad.ID) == nil {
		t.Fatal("setup: not running")
	}
	x.h.impersonationTick(x.ctx)
	if r := x.rec(bad.ID); r.Running() || r.How != ImpExpired {
		t.Errorf("record = %+v", r)
	}
	if x.h.ImpersonationOf("alice", bad.ID) != nil {
		t.Error("still running in the Hub's view")
	}
	if e := x.audit.lastOf("impersonation.end"); e.Target != "alice" || !strings.HasPrefix(e.Detail, bad.ID) {
		t.Errorf("audit = %+v", e)
	}
}

// TestStartBindsProofSID (review M6): a sid in the proof's ID token must
// be the caller's session (AdminSID).
func TestStartBindsProofSID(t *testing.T) {
	x := newImpFixture(t)
	x.fa.mu.Lock()
	x.fa.sid = "another-session"
	x.fa.mu.Unlock()
	if _, err := x.start("root", "alice", "checking quota"); statusOf(err) != 403 || err.Error() != freshauth.Message {
		t.Errorf("another session: %v", err)
	}
	if e := x.audit.lastOf("impersonation.start"); e.Result != "refused" || !strings.Contains(e.Detail, "another session") {
		t.Errorf("audit = %+v", e)
	}
	x.fa.mu.Lock()
	x.fa.sid = impSID
	x.fa.mu.Unlock()
	x.mustStart(t, "root", "alice")
	x.fa.mu.Lock()
	x.fa.sid = ""
	x.fa.mu.Unlock()
	x.mustStart(t, "sam", "bob")
}

// otherImpID is a valid id that differs from id (its first digit changed).
func otherImpID(id string) string {
	if id[0] == '0' {
		return "1" + id[1:]
	}
	return "0" + id[1:]
}

// TestNoticeGivenUpWhenPersonGone (security review): a notice owed to a
// person deleted from the directory, or unknown to Keycloak, is never
// retried forever: the record is no longer owed after one tick and is
// pruned on schedule; a transient error keeps it owed.
func TestNoticeGivenUpWhenPersonGone(t *testing.T) {
	x := newImpFixture(t)
	x.kc.mu.Lock()
	x.kc.noticeErr = errors.New("keycloak down")
	x.kc.mu.Unlock()
	a := x.mustStart(t, "root", "alice")
	b := x.mustStart(t, "sam", "bob")
	for _, u := range []string{"alice", "bob"} {
		if err := x.h.StopImpersonation(x.ctx, u, directory.Human("root")); err != nil {
			t.Fatal(err)
		}
	}
	x.h.impersonationTick(x.ctx)
	if !x.rec(a.ID).NoticeOwed || !x.rec(b.ID).NoticeOwed {
		t.Fatal("a transient error dropped the notice")
	}
	// alice is deleted from the directory; bob is unknown to Keycloak.
	x.h.mu.RLock()
	p := x.h.people.(adminPeople).fakePeople
	x.h.mu.RUnlock()
	p.set(func(p *fakePeople) { delete(p.users, "alice") })
	x.kc.mu.Lock()
	x.kc.noticeErr = keycloak.ErrUserNotFound
	x.kc.mu.Unlock()
	x.h.impersonationTick(x.ctx)
	for _, id := range []string{a.ID, b.ID} {
		if r := x.rec(id); r.NoticeOwed || !r.Finished {
			t.Errorf("still owed after one tick: %+v", r)
		}
	}
	if st := x.saved(t); st.Impersonations[0].NoticeOwed || st.Impersonations[1].NoticeOwed {
		t.Error("not saved")
	}
	x.advance(366 * 24 * time.Hour)
	x.h.impersonationTick(x.ctx)
	if x.rec(a.ID).ID != "" || x.rec(b.ID).ID != "" {
		t.Error("not pruned on schedule")
	}
}

// TestNoticeAfterFailedFileWrite (final review M1): when the file can't
// be written at the end, the notice action waits: a sign-in before the
// next good write would find no notice in the last good file. The loop
// writes it again, then adds the action (the file holding the notice).
func TestNoticeAfterFailedFileWrite(t *testing.T) {
	x := newImpFixture(t)
	x.h.SetImpersonationApps(func(context.Context, state.Impersonation) ([]signinhistory.OpenedApp, bool) { return nil, true })
	s := x.mustStart(t, "root", "alice")
	p := filepath.Join(x.f.data, ImpersonationFileName)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(p, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if n := x.kc.noticed(); len(n) != 0 {
		t.Fatalf("notice added after a failed write: %v", n)
	}
	if r := x.rec(s.ID); !r.Finished || !r.NoticeOwed {
		t.Fatalf("record = %+v", r)
	}
	x.h.impersonationTick(x.ctx)
	if n := x.kc.noticed(); len(n) != 0 {
		t.Fatalf("notice added while the file still fails: %v", n)
	}
	if err := os.RemoveAll(p); err != nil {
		t.Fatal(err)
	}
	x.h.impersonationTick(x.ctx)
	if n := x.kc.noticed(); !slices.Equal(n, []string{"alice"}) {
		t.Fatalf("notices = %v", n)
	}
	x.kc.mu.Lock()
	at := x.kc.fileAtAdd[0]
	x.kc.mu.Unlock()
	if doc := checkImpFileStrict(t, []byte(at), x.clock()); len(doc.Notices["alice"]) != 1 || doc.Notices["alice"][0].ID != s.ID {
		t.Errorf("the file when the notice was added: %+v", doc)
	}
	if r := x.rec(s.ID); r.NoticeOwed {
		t.Errorf("still owed: %+v", r)
	}
}

// TestRefusalMatchesStart (final review M3): the person tab's refusal
// and the start answer the same rule with the same text (one helper).
func TestRefusalMatchesStart(t *testing.T) {
	x := newImpFixture(t)
	x.kc.disabled["carol"] = true
	x.kc.actions["bob"] = []string{"CONFIGURE_TOTP"}
	var limMu sync.Mutex
	lim := impT0
	x.h.entryNow = func() time.Time {
		limMu.Lock()
		defer limMu.Unlock()
		lim = lim.Add(2 * time.Minute)
		return lim
	}
	same := func(target string) {
		t.Helper()
		m, err := x.h.membership(x.ctx)
		if err != nil {
			t.Fatal(err)
		}
		ref := x.h.impersonateRefusal(x.ctx, m, "root", target)
		_, err = x.start("root", target, "checking quota")
		if ref == nil || err == nil || ref.Error() != err.Error() {
			t.Errorf("%s: refusal %v, start %v", target, ref, err)
		}
	}
	for _, u := range []string{"nobody", "root", "portcullis-x", "sam", "carol", "bob"} {
		same(u)
	}
	x.mustStart(t, "root", "alice")
	same("alice")
	setSignIn(x.f, func(si *state.SignIn) { si.ImpersonationOff = true })
	same("alice")
}

// TestFileRewrittenAfterClockBack: a written time ahead of the clock (the
// clock set back, or a write before the clock was injected) makes the
// file due at once, so it never waits for the clock to catch up while
// the readers see an odd written.
func TestFileRewrittenAfterClockBack(t *testing.T) {
	x := newImpFixture(t)
	x.h.impersonationTick(x.ctx)
	x.h.imp.fileMu.Lock()
	x.h.imp.written = x.clock().Add(time.Hour)
	x.h.imp.fileMu.Unlock()
	x.advance(time.Second)
	x.h.impersonationTick(x.ctx)
	if doc := x.file(t); doc.Written != "2026-11-12T14:02:59Z" {
		t.Errorf("written = %q after the clock went back", doc.Written)
	}
}
