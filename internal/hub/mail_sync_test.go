package hub

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailctl"
	"github.com/portcullis/hub/internal/mailctl/mailctltest"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/state"
)

// mailPeople serves a Membership (a copy per call) or an error.
type mailPeople struct {
	mu  sync.Mutex
	m   *directory.Membership
	err error
}

func (p *mailPeople) Membership(context.Context, time.Time) (*directory.Membership, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	c := *p.m
	c.Groups = map[string]directory.MemberGroup{}
	for g, mg := range p.m.Groups {
		mg.Members = append([]string{}, mg.Members...)
		c.Groups[g] = mg
	}
	return &c, nil
}

func (p *mailPeople) PrivilegeProblem(context.Context, string) (string, error) { return "", nil }

func (p *mailPeople) setMembers(group string, users ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g := p.m.Groups[group]
	g.Members = users
	p.m.Groups[group] = g
	for u, gs := range p.m.Users {
		delete(gs, group)
		_ = u
	}
	for _, u := range users {
		if p.m.Users[u] == nil {
			p.m.Users[u] = map[string]int{}
		}
		p.m.Users[u][group] = g.ID
	}
}

type mailFixture struct {
	*fixture
	mc     *mailctltest.Server
	people *mailPeople
	dom    *fakeDomainsAPI
	now    time.Time
	nowMu  sync.Mutex
}

func (f *mailFixture) advance(d time.Duration) {
	f.nowMu.Lock()
	f.now = f.now.Add(d)
	f.nowMu.Unlock()
}

// newMailFixture: core mail on, the fake mailctl wired, a directory with
// alice, bob, root (admin) in mail_users, the main domain example.org.
func newMailFixture(t *testing.T) *mailFixture {
	t.Helper()
	f := &mailFixture{fixture: newFixture(t), mc: mailctltest.New(t), now: time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)}
	setCoreMail(t, f.fixture, true)
	m := mailMembership()
	f.people = &mailPeople{m: m}
	f.h.SetPeople(f.people)
	f.h.SetMailAPI(f.mc.Client())
	f.dom = newFakeDomainsAPI()
	f.dom.list["team-b.example.net"] = domains.Domain{Name: "team-b.example.net", State: "ready"}
	f.h.SetDomainsAPI(f.dom)
	f.h.mailClock = func() time.Time {
		f.nowMu.Lock()
		defer f.nowMu.Unlock()
		return f.now
	}
	f.h.mu.Lock()
	f.h.st.Mail.Domains = map[string]state.MailDomain{}
	f.h.mu.Unlock()
	f.engine.mu.Lock()
	f.engine.containers = append(f.engine.containers, coreMailContainer("core-mail-1"))
	f.engine.mu.Unlock()
	// As if a baseline existed (no blind first document): the restart
	// tests below set it up themselves.
	f.h.mailState.loaded = true
	f.h.SetFreshAuth(ListenerPeople, &fakeFreshAuth{})
	f.h.freshAuthReady.Store(true)
	f.h.mailState.applyWait, f.h.mailState.applyPoll = 400*time.Millisecond, 20*time.Millisecond
	return f
}

func (f *mailFixture) sync(t *testing.T) time.Duration {
	t.Helper()
	return f.h.mailSyncOnce(context.Background())
}

// TestFirstSyncSendsAtOnce: the first pass after start sends; the
// document is the membership's (example.org primary) and the generation
// was saved before the PUT.
func TestFirstSyncSendsAtOnce(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	d := f.mc.Last()
	if d == nil || d.PrimaryDomain != "example.org" || len(d.Accounts) != 3 || d.Generation != 1 {
		t.Fatalf("document %+v", d)
	}
	st, _ := state.Load(f.h.statePath())
	if st.Mail.Generation != 1 {
		t.Errorf("generation saved %d", st.Mail.Generation)
	}
	// Nothing changed: nothing sent.
	f.sync(t)
	if f.mc.Puts() != 1 {
		t.Errorf("puts %d", f.mc.Puts())
	}
}

// TestRemovalSentImmediately: bob leaving mail_users is sent at once,
// waited for and followed by a restart of core mail.
func TestRemovalSentImmediately(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.people.setMembers("mail_users", "alice", "root")
	f.sync(t)
	if f.mc.Puts() != 2 || len(f.mc.Last().Accounts) != 2 {
		t.Fatalf("puts %d, %+v", f.mc.Puts(), f.mc.Last())
	}
	if r := f.engine.Restarts(); len(r) != 1 || r[0] != "core-mail-1:2s" {
		t.Errorf("restarts %v", r)
	}
	if lo := f.h.LastOp(opKeyMail); lo == nil || !lo.OK || lo.Op != OpMailRestart {
		t.Errorf("op record %+v", lo)
	}
}

// TestAdditionDebounced60s: a new member waits 60 s (fake clock).
func TestAdditionDebounced60s(t *testing.T) {
	f := newMailFixture(t)
	f.people.setMembers("mail_users", "alice", "root")
	f.sync(t)
	f.people.setMembers("mail_users", "alice", "bob", "root")
	if w := f.sync(t); w != mailDebounce || f.mc.Puts() != 1 {
		t.Fatalf("wait %s, puts %d", w, f.mc.Puts())
	}
	f.advance(59 * time.Second)
	if w := f.sync(t); w != time.Second || f.mc.Puts() != 1 {
		t.Fatalf("after 59 s: wait %s, puts %d", w, f.mc.Puts())
	}
	f.advance(time.Second)
	f.sync(t)
	if f.mc.Puts() != 2 || len(f.mc.Last().Accounts) != 3 {
		t.Fatalf("after 60 s: puts %d", f.mc.Puts())
	}
	if r := f.engine.Restarts(); len(r) != 0 {
		t.Errorf("an addition restarted mail: %v", r)
	}
	// A removal during a pending addition goes at once (with it).
	f.people.setMembers("mail_users", "alice", "bob", "root", "carol")
	f.people.mu.Lock()
	f.people.m.UUIDs["carol"] = uuidCarol
	f.people.mu.Unlock()
	f.sync(t)
	f.people.setMembers("mail_users", "bob", "carol", "root")
	f.sync(t)
	if f.mc.Puts() != 3 || len(f.mc.Last().Accounts) != 3 {
		t.Fatalf("removal with a pending addition: %d %+v", f.mc.Puts(), f.mc.Last().Accounts)
	}
}

// TestDirectoryErrorSendsNothing: a failed directory read sends no
// document at all (never an empty one).
func TestDirectoryErrorSendsNothing(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.people.mu.Lock()
	f.people.err = &directory.Error{Status: 502, Msg: "lldap down"}
	f.people.mu.Unlock()
	if w := f.sync(t); w != mailRetry {
		t.Errorf("wait %s", w)
	}
	if f.mc.Puts() != 1 {
		t.Errorf("puts %d", f.mc.Puts())
	}
}

// TestMassRemovalFlagOnlyForHubRemovals: more than half the accounts
// gone is confirmed only when an admin removed each through the Hub.
func TestMassRemovalFlagOnlyForHubRemovals(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	// alice and bob vanish without a Hub removal (an LLDAP edit): refused.
	f.people.setMembers("mail_users", "root")
	f.sync(t)
	if f.mc.Puts() != 1 {
		t.Fatalf("an unconfirmed mass removal was accepted: %d", f.mc.Puts())
	}
	// One Hub removal isn't enough.
	f.h.MailMemberRemoved("mail_users", "alice", true)
	f.sync(t)
	if f.mc.Puts() != 1 {
		t.Fatalf("partly confirmed: %d", f.mc.Puts())
	}
	f.h.MailMemberRemoved("other_group", "bob", true)
	f.sync(t)
	if f.mc.Puts() != 1 {
		t.Fatalf("another group's removal confirmed: %d", f.mc.Puts())
	}
	f.h.MailMemberRemoved("Mail_Users", "Bob", true)
	f.sync(t)
	if f.mc.Puts() != 2 || !f.mc.Last().ConfirmMassRemoval || len(f.mc.Last().Accounts) != 1 {
		t.Fatalf("confirmed: %d %+v", f.mc.Puts(), f.mc.Last())
	}
	// The record is spent: a later document doesn't carry the flag.
	f.people.setMembers("mail_users", "root", "alice")
	f.sync(t)
	f.advance(time.Minute)
	f.sync(t)
	if f.mc.Puts() != 3 || f.mc.Last().ConfirmMassRemoval {
		t.Error("flag kept")
	}
}

// coreMailContainer is core's mail container as compose labels it.
func coreMailContainer(id string) docker.Container {
	return docker.Container{ID: id, Labels: map[string]string{docker.LabelProject: "portcullis", docker.LabelService: "mail",
		"com.docker.compose.project.working_dir": "/host/project", "com.docker.compose.oneoff": "False"}}
}

// TestMailRestartOnlyTargetsCoreMail: exactly the one container of core's
// project (service mail, not a one-off, in core's directory); another
// project's mail, a one-off and another working directory are ignored;
// two candidates refuse; none refuses; a failed restart is recorded.
func TestMailRestartOnlyTargetsCoreMail(t *testing.T) {
	f := newMailFixture(t)
	oneoff := coreMailContainer("core-mail-run")
	oneoff.Labels["com.docker.compose.oneoff"] = "True"
	elsewhere := coreMailContainer("other-checkout")
	elsewhere.Labels["com.docker.compose.project.working_dir"] = "/srv/other"
	f.engine.mu.Lock()
	f.engine.containers = append(f.engine.containers,
		docker.Container{ID: "app-mail", Labels: map[string]string{docker.LabelProject: "portcullis-mailapp", docker.LabelService: "mail"}},
		docker.Container{ID: "core-mailctl", Labels: map[string]string{docker.LabelProject: "portcullis", docker.LabelService: "mailctl"}},
		oneoff, elsewhere)
	f.engine.mu.Unlock()
	ctx := context.Background()
	if err := f.h.restartCoreMail(ctx); err != nil {
		t.Fatal(err)
	}
	if r := f.engine.Restarts(); len(r) != 1 || r[0] != "core-mail-1:2s" {
		t.Fatalf("restarts %v", r)
	}
	f.engine.mu.Lock()
	f.engine.containers = append(f.engine.containers, coreMailContainer("core-mail-2"))
	f.engine.mu.Unlock()
	if err := f.h.restartCoreMail(ctx); err == nil || !strings.Contains(err.Error(), "2 containers") {
		t.Fatalf("two candidates: %v", err)
	}
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{oneoff, elsewhere}
	f.engine.mu.Unlock()
	if err := f.h.restartCoreMail(ctx); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("none: %v", err)
	}
	if r := f.engine.Restarts(); len(r) != 1 {
		t.Fatalf("refused restarts ran: %v", r)
	}
	// A failed restart is recorded and says sessions may still be open.
	if err := f.h.mailRestart(ctx, "a test"); err == nil {
		t.Fatal("no error")
	}
	if bad, why := f.h.MailRestartFailed(); !bad || !strings.Contains(why, "mail sessions may still be open") {
		t.Fatalf("record %v %q", bad, why)
	}
}

// TestKubeNeverRestartsMail: the kube runtime answers unsupported.
func TestKubeNeverRestartsMail(t *testing.T) {
	f := newFixture(t)
	f.h.rt = kubeKindRuntime{f.h.rt}
	if err := f.h.restartCoreMail(context.Background()); !errors.Is(err, runtime.ErrUnsupported) {
		t.Fatalf("kube: %v", err)
	}
	if len(f.engine.Restarts()) != 0 {
		t.Fatal("restarted")
	}
}

type kubeKindRuntime struct{ runtime.Instances }

func (kubeKindRuntime) Kind() runtime.Kind { return runtime.KindKubernetes }

// TestRestartWhenApplyTimesOut: mailctl not applying within 4 s still
// restarts mail (the 8 s budget).
func TestRestartWhenApplyTimesOut(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.mc.Lock(func(s *mailctltest.Server) { s.HoldApply = true })
	f.people.setMembers("mail_users", "alice", "root")
	start := time.Now()
	f.sync(t)
	if el := time.Since(start); el < 380*time.Millisecond || el > 3*time.Second {
		t.Errorf("waited %s", el)
	}
	if r := f.engine.Restarts(); len(r) != 1 {
		t.Fatalf("restarts %v", r)
	}
}

// TestSharedRestart: requests while a restart runs share the next one.
func TestSharedRestart(t *testing.T) {
	var s sharedRestart
	var mu sync.Mutex
	runs := 0
	release := make(chan struct{})
	run := func() error {
		mu.Lock()
		runs++
		n := runs
		mu.Unlock()
		if n == 1 {
			<-release
		}
		return nil
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.do(context.Background(), run) }()
	for {
		s.mu.Lock()
		started := s.cur != nil
		s.mu.Unlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.do(context.Background(), run) }()
	}
	for {
		s.mu.Lock()
		queued := s.next != nil
		s.mu.Unlock()
		if queued {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if runs != 2 {
		t.Fatalf("runs %d, want 2 (the running one and one shared)", runs)
	}
}

// TestSyncMailDNSSetsAndDeletes: an added domain on gets its wanted set;
// draining finished (mailctl's MTA-STS off) turns it off; off removes
// the set and retires it; the main domain is never written.
func TestSyncMailDNSSetsAndDeletes(t *testing.T) {
	f := newMailFixture(t)
	f.h.mu.Lock()
	f.h.st.Mail.Domains["team-b.example.net"] = state.MailDomain{Enabled: true, Groups: []string{"team_b"}}
	f.h.mu.Unlock()
	f.mc.Lock(func(s *mailctltest.Server) {
		s.DNSSets["team-b.example.net"] = mailctl.DNSSet{Domain: "team-b.example.net", DKIM: "auto", TLSA: "withheld: dnssec unsigned",
			Records: []mailctl.Record{{Name: "team-b.example.net", Type: "MX", TTL: 3600, Value: "10 mail.example.org."}}}
	})
	f.sync(t)
	f.dom.mu.Lock()
	calls := strings.Join(f.dom.mailCalls, ",")
	recs := f.dom.mailSets["team-b.example.net"]
	f.dom.mu.Unlock()
	if calls != "put team-b.example.net" || len(recs) != 1 || recs[0].Value != "10 mail.example.org." {
		t.Fatalf("calls %q recs %+v", calls, recs)
	}
	// No *.<e> address record in the plan: ?wildcard=false; with one, true.
	var wc string
	f.mc.Lock(func(s *mailctltest.Server) { wc = s.Wildcards["team-b.example.net"] })
	if wc != "false" {
		t.Fatalf("wildcard %q", wc)
	}
	f.dom.mu.Lock()
	f.dom.plans["team-b.example.net"] = domains.Plan{Name: "team-b.example.net", Items: []domains.PlanItem{{Set: "address", Name: "*.team-b.example.net", Type: "A", Live: []string{"203.0.113.5"}}}}
	f.dom.mu.Unlock()
	f.advance(mailDNSEvery)
	f.sync(t)
	f.mc.Lock(func(s *mailctltest.Server) { wc = s.Wildcards["team-b.example.net"] })
	if wc != "true" {
		t.Fatalf("wildcard with *.<e>: %q", wc)
	}
	// Turned off: draining; mailctl still in mode none → still written.
	f.h.mu.Lock()
	f.h.st.Mail.Domains["team-b.example.net"] = state.MailDomain{Draining: true, Groups: []string{"team_b"}}
	f.h.mu.Unlock()
	f.mc.Lock(func(s *mailctltest.Server) {
		s.StatusV.MTASTS = []mailctl.StatusMTASTS{{Domain: "team-b.example.net", Mode: "none"}}
	})
	f.sync(t)
	if d := f.mc.Last().Domains; d[1].Mail != "draining" {
		t.Fatalf("draining doc %+v", d)
	}
	// mailctl reports it off: the Hub turns it off, sends off, deletes.
	f.mc.Lock(func(s *mailctltest.Server) { s.StatusV.MTASTS[0].Mode = "off" })
	f.advance(mailDNSEvery)
	f.sync(t) // the DNS pass sees off
	f.sync(t) // sends off, then deletes the set
	f.h.mu.RLock()
	e := f.h.st.Mail.Domains["team-b.example.net"]
	f.h.mu.RUnlock()
	if !e.Retired || e.Draining || e.Enabled {
		t.Fatalf("entry %+v", e)
	}
	f.dom.mu.Lock()
	calls = strings.Join(f.dom.mailCalls, ",")
	f.dom.mu.Unlock()
	if !strings.HasSuffix(calls, "delete team-b.example.net") || strings.Contains(calls, "example.org") {
		t.Fatalf("calls %q", calls)
	}
	found := false
	for _, d := range f.mc.Docs {
		for _, x := range d.Domains {
			found = found || (x.Name == "team-b.example.net" && x.Mail == "off")
		}
	}
	if !found {
		t.Error("no off document was sent before the set was removed")
	}
	f.sync(t)
	if len(f.mc.Last().Domains) != 1 {
		t.Errorf("retired domain still sent: %+v", f.mc.Last().Domains)
	}
}

// TestMailOffSendsNothing: PORTCULLIS_MAIL=off or no secret: no request.
func TestMailOffSendsNothing(t *testing.T) {
	f := newMailFixture(t)
	setCoreMail(t, f.fixture, false)
	f.sync(t)
	if f.mc.Puts() != 0 {
		t.Fatal("sent with mail off")
	}
}

// TestMassRemovalStaleEntryDoesNotConfirm: an admin removal recorded
// before the last accepted document, or older than 10 minutes, confirms
// nothing; a person without a mailbox isn't recorded at all.
func TestMassRemovalStaleEntryDoesNotConfirm(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	// Recorded for alice and bob, then a document is accepted (a settings
	// change): the entries are spent.
	f.h.MailMemberRemoved("mail_users", "alice", true)
	f.h.MailMemberRemoved("mail_users", "bob", true)
	f.h.mu.Lock()
	f.h.st.Mail.Spam.RejectScore = 20
	f.h.mu.Unlock()
	f.sync(t)
	if f.mc.Puts() != 2 {
		t.Fatalf("settings change: puts %d", f.mc.Puts())
	}
	f.people.setMembers("mail_users", "root")
	f.sync(t)
	if f.mc.Puts() != 2 {
		t.Fatal("entries from before the last accepted document confirmed a mass removal")
	}
	// Fresh entries, but older than 10 minutes: nothing.
	f.h.MailMemberRemoved("mail_users", "alice", true)
	f.h.MailMemberRemoved("mail_users", "bob", true)
	f.advance(mailHubRemovalTTL + time.Second)
	f.sync(t)
	if f.mc.Puts() != 2 {
		t.Fatal("an expired entry confirmed a mass removal")
	}
	// Within the limit: confirmed.
	f.h.MailMemberRemoved("mail_users", "alice", true)
	f.h.MailMemberRemoved("mail_users", "bob", true)
	f.sync(t)
	if f.mc.Puts() != 3 || !f.mc.Last().ConfirmMassRemoval {
		t.Fatalf("fresh entries: puts %d", f.mc.Puts())
	}
}

// TestHubRemovalNeedsMailbox: removing someone without a mailbox (not in
// the last accepted document) records nothing.
func TestHubRemovalNeedsMailbox(t *testing.T) {
	f := newMailFixture(t)
	f.h.MailMemberRemoved("mail_users", "alice", true) // no document yet
	f.sync(t)
	f.h.MailMemberRemoved("mail_users", "dave", true) // no mailbox
	f.h.mailState.mu.Lock()
	n := len(f.h.mailState.hubRemoved)
	f.h.mailState.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d entries recorded", n)
	}
	f.h.MailMemberRemoved("mail_users", "alice", true)
	f.h.mailState.mu.Lock()
	r, ok := f.h.mailState.hubRemoved[uuidAlice]
	f.h.mailState.mu.Unlock()
	if !ok || r.gen != 1 {
		t.Fatalf("alice's entry %+v %v", r, ok)
	}
}
