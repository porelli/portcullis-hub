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
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
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
	mc     *mailprovidertest.Server
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

// newMailFixture: the slot open, mailsrv wired with the fake provider as
// its API, a directory with alice, bob, root (admin) in mail_users, the
// main domain example.org.
func newMailFixture(t *testing.T, others ...string) *mailFixture {
	t.Helper()
	f := &mailFixture{fixture: newMailSlotFixture(t, true, others...), mc: mailprovidertest.New(t), now: time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)}
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
	f.engine.containers = append(f.engine.containers, providerContainer("prov-mail-1"))
	f.engine.mu.Unlock()
	// As if a baseline existed (no blind first document): the restart
	// tests below set it up themselves.
	f.h.mailState.loaded = true
	f.h.SetFreshAuth(ListenerPeople, &fakeFreshAuth{})
	f.h.freshAuthReady.Store(true)
	f.h.mailState.applyWait, f.h.mailState.applyPoll = 400*time.Millisecond, 20*time.Millisecond
	return f
}

// sync is one pass, then the background reconcile it started.
func (f *mailFixture) sync(t *testing.T) time.Duration {
	t.Helper()
	next := f.h.mailSyncOnce(context.Background())
	f.h.mailState.reconWG.Wait()
	return next
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
	if r := f.engine.Restarts(); len(r) != 1 || r[0] != "prov-mail-1:2s" {
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
	f.h.MailMemberRemoved("mail_users", "alice", "root")
	f.sync(t)
	if f.mc.Puts() != 1 {
		t.Fatalf("partly confirmed: %d", f.mc.Puts())
	}
	f.h.MailMemberRemoved("other_group", "bob", "root")
	f.sync(t)
	if f.mc.Puts() != 1 {
		t.Fatalf("another group's removal confirmed: %d", f.mc.Puts())
	}
	f.h.MailMemberRemoved("Mail_Users", "Bob", "root")
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

// TestMailRestartTargetsWiredProvider: exactly the one container of the
// wired provider's project and sessions.restart service (not a one-off);
// another service, another project and core's are ignored; two
// candidates refuse; none refuses; nothing wired refuses.
func TestMailRestartTargetsWiredProvider(t *testing.T) {
	f := newMailFixture(t)
	oneoff := providerContainer("prov-run")
	oneoff.Labels["com.docker.compose.oneoff"] = "True"
	f.engine.mu.Lock()
	f.engine.containers = append(f.engine.containers,
		docker.Container{ID: "other-stalwart", Labels: map[string]string{docker.LabelProject: "portcullis-mailapp", docker.LabelService: "stalwart"}},
		docker.Container{ID: "prov-adapter", Labels: map[string]string{docker.LabelProject: "portcullis-mailsrv", docker.LabelService: "adapter"}},
		docker.Container{ID: "core-mail", Labels: map[string]string{docker.LabelProject: "portcullis", docker.LabelService: "stalwart"}},
		oneoff)
	f.engine.mu.Unlock()
	ctx := context.Background()
	if err := f.h.restartMailProvider(ctx); err != nil {
		t.Fatal(err)
	}
	if r := f.engine.Restarts(); len(r) != 1 || r[0] != "prov-mail-1:2s" {
		t.Fatalf("restarts %v", r)
	}
	f.engine.mu.Lock()
	f.engine.containers = append(f.engine.containers, providerContainer("prov-mail-2"))
	f.engine.mu.Unlock()
	if err := f.h.restartMailProvider(ctx); err == nil || !strings.Contains(err.Error(), "2 containers") {
		t.Fatalf("two candidates: %v", err)
	}
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{oneoff}
	f.engine.mu.Unlock()
	if err := f.h.restartMailProvider(ctx); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("none: %v", err)
	}
	f.h.mu.Lock()
	wired := f.h.st.Mail.Provider
	f.h.st.Mail.Provider = nil
	f.h.mu.Unlock()
	if err := f.h.restartMailProvider(ctx); !errors.Is(err, errMailNotWired) {
		t.Fatalf("nothing wired: %v", err)
	}
	f.h.mu.Lock()
	f.h.st.Mail.Provider = wired
	f.h.mu.Unlock()
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
	if err := f.h.restartMailProvider(context.Background()); !errors.Is(err, runtime.ErrUnsupported) {
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
	f.mc.Lock(func(s *mailprovidertest.Server) { s.HoldApply = true })
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
	f.mc.Lock(func(s *mailprovidertest.Server) {
		s.DNSSets["team-b.example.net"] = mailprovider.DNSSet{Domain: "team-b.example.net", DKIM: "auto",
			Records: []mailprovider.Record{{Name: "team-b.example.net", Type: "MX", TTL: 3600, Value: "10 mail.example.org."}, dmarcRec("team-b.example.net")}}
	})
	f.sync(t)
	f.dom.mu.Lock()
	calls := strings.Join(f.dom.mailCalls, ",")
	recs := f.dom.mailSets["team-b.example.net"]
	f.dom.mu.Unlock()
	if calls != "put team-b.example.net" || len(recs) != 2 || recs[0].Value != "10 mail.example.org." {
		t.Fatalf("calls %q recs %+v", calls, recs)
	}
	// No *.<e> address record in the plan: ?wildcard=false; with one, true.
	var wc string
	f.mc.Lock(func(s *mailprovidertest.Server) { wc = s.Wildcards["team-b.example.net"] })
	if wc != "false" {
		t.Fatalf("wildcard %q", wc)
	}
	f.dom.mu.Lock()
	f.dom.plans["team-b.example.net"] = domains.Plan{Name: "team-b.example.net", Items: []domains.PlanItem{{Set: "address", Name: "*.team-b.example.net", Type: "A", Live: []string{"203.0.113.5"}}}}
	f.dom.mu.Unlock()
	f.advance(mailDNSEvery)
	f.sync(t)
	f.mc.Lock(func(s *mailprovidertest.Server) { wc = s.Wildcards["team-b.example.net"] })
	if wc != "true" {
		t.Fatalf("wildcard with *.<e>: %q", wc)
	}
	// Turned off: draining; mailctl still in mode none → still written.
	f.h.mu.Lock()
	f.h.st.Mail.Domains["team-b.example.net"] = state.MailDomain{Draining: true, Groups: []string{"team_b"}}
	f.h.mu.Unlock()
	f.mc.Lock(func(s *mailprovidertest.Server) {
		s.StatusV.MTASTS = []mailprovider.StatusMTASTS{{Domain: "team-b.example.net", Mode: "none"}}
	})
	f.sync(t)
	if d := f.mc.Last().Domains; d[1].Mail != "draining" {
		t.Fatalf("draining doc %+v", d)
	}
	// mailctl reports it off: the Hub turns it off, sends off, deletes.
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.MTASTS[0].Mode = "off" })
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
	f.h.MailMemberRemoved("mail_users", "alice", "root")
	f.h.MailMemberRemoved("mail_users", "bob", "root")
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
	f.h.MailMemberRemoved("mail_users", "alice", "root")
	f.h.MailMemberRemoved("mail_users", "bob", "root")
	f.advance(mailHubRemovalTTL + time.Second)
	f.sync(t)
	if f.mc.Puts() != 2 {
		t.Fatal("an expired entry confirmed a mass removal")
	}
	// Within the limit: confirmed.
	f.h.MailMemberRemoved("mail_users", "alice", "root")
	f.h.MailMemberRemoved("mail_users", "bob", "root")
	f.sync(t)
	if f.mc.Puts() != 3 || !f.mc.Last().ConfirmMassRemoval {
		t.Fatalf("fresh entries: puts %d", f.mc.Puts())
	}
}

// TestHubRemovalNeedsMailbox: removing someone without a mailbox (not in
// the last accepted document) records nothing.
func TestHubRemovalNeedsMailbox(t *testing.T) {
	f := newMailFixture(t)
	f.h.MailMemberRemoved("mail_users", "alice", "root") // no document yet
	f.sync(t)
	f.h.MailMemberRemoved("mail_users", "dave", "root") // no mailbox
	f.h.mailState.mu.Lock()
	n := len(f.h.mailState.hubRemoved)
	f.h.mailState.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d entries recorded", n)
	}
	f.h.MailMemberRemoved("mail_users", "alice", "root")
	f.h.mailState.mu.Lock()
	r, ok := f.h.mailState.hubRemoved[uuidAlice]
	f.h.mailState.mu.Unlock()
	if !ok || r.gen != 1 {
		t.Fatalf("alice's entry %+v %v", r, ok)
	}
}

// TestMailDNSByHash: between the 6 h rewrites the Hub reads mailctl's
// per-domain set hashes every 60 s: a changed hash → exactly one refetch
// and PUT; the same hash → none; a failed PUT is retried on the next
// pass (the hash is recorded only after the PUT succeeded). The main
// domain is never written.
func TestMailDNSByHash(t *testing.T) {
	f := newMailFixture(t)
	const d = "team-b.example.net"
	f.h.mu.Lock()
	f.h.st.Mail.Domains[d] = state.MailDomain{Enabled: true, Groups: []string{"team_b"}}
	f.h.mu.Unlock()
	f.mc.Lock(func(s *mailprovidertest.Server) {
		s.DNSSets[d] = mailprovider.DNSSet{Domain: d, DKIM: "auto", Records: []mailprovider.Record{{Name: d, Type: "MX", TTL: 3600, Value: "10 mail.example.org."}, dmarcRec(d)}}
		s.StatusV.DNS = map[string]string{d: "h1", "example.org": "m1"}
	})
	f.sync(t) // the full pass: written, h1 recorded
	counts := func() (gets, puts int) {
		f.mc.Lock(func(s *mailprovidertest.Server) {
			for _, r := range s.Requests {
				if strings.HasPrefix(r, "GET /v1/dns/") {
					gets++
				}
			}
		})
		f.dom.mu.Lock()
		puts = len(f.dom.mailCalls)
		f.dom.mu.Unlock()
		return
	}
	g0, p0 := counts()
	if g0 != 1 || p0 != 1 {
		t.Fatalf("full pass: gets %d puts %d", g0, p0)
	}
	// Unchanged hash: nothing.
	f.advance(mailDNSHashEvery)
	f.sync(t)
	if g, p := counts(); g != g0 || p != p0 {
		t.Fatalf("unchanged: gets %d puts %d", g, p)
	}
	// Changed: exactly one refetch and PUT, then nothing again.
	f.mc.Lock(func(s *mailprovidertest.Server) {
		s.DNSSets[d] = mailprovider.DNSSet{Domain: d, DKIM: "auto", Records: []mailprovider.Record{{Name: d, Type: "MX", TTL: 3600, Value: "20 mail.example.org."}, dmarcRec(d)}}
		s.StatusV.DNS = map[string]string{d: "h2", "example.org": "m2"}
	})
	f.sync(t) // not due yet: nothing
	if g, p := counts(); g != g0 || p != p0 {
		t.Fatalf("before the tick: gets %d puts %d", g, p)
	}
	f.advance(mailDNSHashEvery)
	f.sync(t)
	f.dom.mu.Lock()
	recs := f.dom.mailSets[d]
	f.dom.mu.Unlock()
	if g, p := counts(); g != g0+1 || p != p0+1 || len(recs) != 2 || recs[0].Value != "20 mail.example.org." {
		t.Fatalf("changed: gets %d puts %d recs %+v", g, p, recs)
	}
	f.advance(mailDNSHashEvery)
	f.sync(t)
	if g, p := counts(); g != g0+1 || p != p0+1 {
		t.Fatalf("after the write: gets %d puts %d", g, p)
	}
	// A failed PUT: retried on the next tick, then recorded.
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.DNS = map[string]string{d: "h3"} })
	f.dom.mu.Lock()
	f.dom.mailSetErr = errors.New("domains service down")
	f.dom.mu.Unlock()
	f.advance(mailDNSHashEvery)
	f.sync(t)
	f.dom.mu.Lock()
	f.dom.mailSetErr = nil
	f.dom.mu.Unlock()
	f.advance(mailDNSHashEvery)
	f.sync(t)
	f.advance(mailDNSHashEvery)
	f.sync(t)
	f.dom.mu.Lock()
	calls := strings.Join(f.dom.mailCalls, ",")
	f.dom.mu.Unlock()
	if calls != "put "+d+",put "+d+",fail "+d+",put "+d {
		t.Fatalf("calls %q", calls)
	}
	if strings.Contains(calls, "example.org") {
		t.Fatalf("main domain written: %q", calls)
	}
}

// TestMailDNSHashForgottenOnFailure (final review L4, I3): a forced full
// pass whose write fails forgets the recorded hash, so the next 60 s hash
// pass writes again although mailctl's hash didn't change; a removed set
// forgets it too; mailctl's mixed-case domain keys are read lowercase.
func TestMailDNSHashForgottenOnFailure(t *testing.T) {
	f := newMailFixture(t)
	const d = "team-b.example.net"
	f.h.mu.Lock()
	f.h.st.Mail.Domains[d] = state.MailDomain{Enabled: true, Groups: []string{"team_b"}}
	f.h.mu.Unlock()
	f.mc.Lock(func(s *mailprovidertest.Server) {
		s.DNSSets[d] = mailprovider.DNSSet{Domain: d, DKIM: "auto", Records: []mailprovider.Record{{Name: d, Type: "MX", TTL: 3600, Value: "10 mail.example.org."}, dmarcRec(d)}}
		s.StatusV.DNS = map[string]string{"Team-B.Example.NET": "h1"}
	})
	f.sync(t) // written, h1 recorded (the key read lowercase)
	f.h.mailState.mu.Lock()
	have := f.h.mailState.dnsHash[d]
	f.h.mailState.mu.Unlock()
	if have != "h1" {
		t.Fatalf("recorded %q", have)
	}
	puts := func() int {
		f.dom.mu.Lock()
		defer f.dom.mu.Unlock()
		return strings.Count(strings.Join(f.dom.mailCalls, ","), "put "+d)
	}
	p0 := puts()
	// A forced full pass (an accepted document) whose write fails.
	f.dom.mu.Lock()
	f.dom.mailSetErr = errors.New("domains service down")
	f.dom.mu.Unlock()
	f.h.mailDNSIfDue(context.Background(), f.mc.Client(), f.h.mailNow(), true)
	f.dom.mu.Lock()
	f.dom.mailSetErr = nil
	f.dom.mu.Unlock()
	f.advance(mailDNSHashEvery)
	f.sync(t) // the same hash h1: written again
	if puts() != p0+1 {
		t.Fatalf("puts after the failure: %d", puts()-p0)
	}
	// Off: the set is removed and the hash forgotten.
	f.h.mu.Lock()
	f.h.st.Mail.Domains[d] = state.MailDomain{Groups: []string{"team_b"}}
	f.h.mu.Unlock()
	f.h.mailDNSIfDue(context.Background(), f.mc.Client(), f.h.mailNow(), true)
	f.h.mailState.mu.Lock()
	_, kept := f.h.mailState.dnsHash[d]
	f.h.mailState.mu.Unlock()
	if kept {
		t.Fatal("the hash of a removed set was kept")
	}
}

// dmarcRec is a valid _dmarc record for d (p=reject: every floor).
func dmarcRec(d string) mailprovider.Record {
	return mailprovider.Record{Name: "_dmarc." + d, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=reject; rua=mailto:dmarc-reports@" + d}
}
