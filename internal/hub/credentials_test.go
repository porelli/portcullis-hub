package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/credentials"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The credential service (plan 3 Task 8, contract §5.1, §13.16).

const smbProject = ProjectPrefix + smbID

// credSvc is credFixture for the credential service: alice, bob and
// root (a reserved name) in users_smbfixture, carol in LLDAP but not in
// it; smbfixture enabled with a running smb container; a fake fresh-auth
// verifier in place; the engine's timers on a fake clock.
type credSvc struct {
	f       *fixture
	audit   *fakeAudit
	secrets string
	people  *fakePeople
	fa      *fakeFreshAuth
	checks  *atomic.Int32
}

func credSvcFixture(t *testing.T) *credSvc {
	t.Helper()
	f, audit, secrets := credFixture(t)
	people := newFakePeople("carol")
	people.addGroup("users_"+smbID, "alice", "bob", "root")
	people.addGroup("admin_" + smbID)
	people.addGroup("users_"+smbB, "alice")
	people.addGroup("admin_" + smbB)
	f.h.SetPeople(people)
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{}})
	clk := &fakeClock{}
	f.h.afterFunc, f.h.sleep = clk.afterFunc, clk.sleep
	f.clk = clk
	f.h.revokeLockWait = 300 * time.Millisecond
	f.engine.mu.Lock()
	f.engine.containers = append(f.engine.containers, container("smb-c", smbProject, "smb", "running"))
	f.engine.mu.Unlock()
	if err := f.h.Enable(smbID); err != nil {
		t.Fatal(err)
	}
	settle(f)
	fa := &fakeFreshAuth{}
	f.h.SetFreshAuth(ListenerPeople, fa)
	f.h.freshAuthReady.Store(true)
	var n atomic.Int32
	f.h.credentialCheck = func() { n.Add(1) }
	return &credSvc{f: f, audit: audit, secrets: secrets, people: people, fa: fa, checks: &n}
}

func (c *credSvc) create(t *testing.T, user string) *CreatedCredential {
	t.Helper()
	cc, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, user, testProof)
	if err != nil {
		t.Fatalf("CreateCredential(%s): %v", user, err)
	}
	settle(c.f)
	return cc
}

func (c *credSvc) hashFile(user string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(c.secrets, smbID, smbKey, user+".nt"))
	return string(b), err == nil
}

// credExecs are the hook execs whose stdin names trigger (all: "").
func credExecs(f *fixture, trigger string) []settings.HookInput {
	var out []settings.HookInput
	for _, c := range f.engine.ExecCalls() {
		var in settings.HookInput
		if json.Unmarshal(c.in.Stdin, &in) != nil {
			continue
		}
		if trigger == "" || in.Trigger == trigger {
			out = append(out, in)
		}
	}
	return out
}

func credAudits(a *fakeAudit, action string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.entries {
		if e.Action == action {
			out = append(out, e.Actor+" "+e.Target+" "+e.Detail+" "+e.Result+" "+e.Error)
		}
	}
	return out
}

var passwordShape = regexp.MustCompile(`^([2-9A-HJ-NP-Ya-hjkmnp-z]{4}-){5}[2-9A-HJ-NP-Ya-hjkmnp-z]{4}$`)

func TestCreateCredential(t *testing.T) {
	c := credSvcFixture(t)
	before := len(credExecs(c.f, templates.HookCredentialChange))
	cc := c.create(t, "Alice")
	if !passwordShape.Match(cc.Password) || len(cc.Password) != 29 {
		t.Fatalf("password %q has the wrong shape", cc.Password)
	}
	hash := credentials.NTHash(cc.Password)
	if got, ok := c.hashFile("alice"); !ok || got != hash+"\n" {
		t.Errorf("hash file = %q, want %q", got, hash+"\n")
	}
	m, ok := credOf(c.f.h, smbID, "alice")
	if !ok || !m.Active() || m.Version != 1 || m.CreatedBy != "alice" || m.UUID != "uuid-alice" || m.ID == "" || cc.Credential != m {
		t.Errorf("metadata %+v (answer %+v)", m, cc.Credential)
	}
	if a := credAudits(c.audit, "credential.create"); len(a) != 1 || !strings.Contains(a[0], "instance="+smbID+" key="+smbKey+" user=alice actor=alice") || !strings.HasPrefix(a[0], "alice ") {
		t.Errorf("audit = %v", a)
	}
	if n := len(credExecs(c.f, templates.HookCredentialChange)) - before; n != 1 {
		t.Errorf("%d credential_change hook runs, want 1", n)
	}
	if c.f.h.DeliveryStatus(smbID).Trigger != TriggerCredential {
		t.Errorf("last trigger = %q", c.f.h.DeliveryStatus(smbID).Trigger)
	}
	if c.fa.calls.Load() != 1 {
		t.Errorf("Verify called %d times", c.fa.calls.Load())
	}
	// F30: the holder re-check after the commit.
	if c.checks.Load() != 1 {
		t.Errorf("holder check triggered %d times, want 1", c.checks.Load())
	}
	credentials.Zero(cc.Password)
}

func TestRegenerateReplaces(t *testing.T) {
	c := credSvcFixture(t)
	first := c.create(t, "alice")
	h1, _ := c.hashFile("alice")
	second := c.create(t, "alice")
	h2, _ := c.hashFile("alice")
	if h1 == h2 || h2 != credentials.NTHash(second.Password)+"\n" {
		t.Errorf("hash file not replaced: %q then %q", h1, h2)
	}
	if second.Credential.Version != 2 || second.Credential.ID == first.Credential.ID || !second.Credential.Active() {
		t.Errorf("regenerated %+v after %+v", second.Credential, first.Credential)
	}
	if a := credAudits(c.audit, "credential.regenerate"); len(a) != 1 || !strings.Contains(a[0], "user=alice") {
		t.Errorf("regenerate audit = %v", a)
	}
}

func TestOutsidePopulation404(t *testing.T) {
	c := credSvcFixture(t)
	ctx := context.Background()
	_, unknown := c.f.h.CreateCredential(ctx, "nope", smbKey, "alice", testProof)
	_, badKey := c.f.h.CreateCredential(ctx, smbID, "connect_address", "alice", testProof)
	_, carol := c.f.h.CreateCredential(ctx, smbID, smbKey, "carol", testProof)
	for name, err := range map[string]error{"unknown instance": unknown, "not a person_secret": badKey, "carol": carol} {
		if statusOf(err) != 404 || err.Error() != unknown.Error() {
			t.Errorf("%s: %v (want the unknown instance's 404 %q)", name, err, unknown)
		}
	}
	// smbB is not enabled: alice is in its group but the instance isn't.
	if _, err := c.f.h.CreateCredential(ctx, smbB, smbKey, "alice", testProof); statusOf(err) != 404 || err.Error() != unknown.Error() {
		t.Errorf("disabled instance: %v", err)
	}
	if c.fa.calls.Load() != 0 {
		t.Errorf("Verify called %d times", c.fa.calls.Load())
	}
	if _, ok := c.hashFile("carol"); ok {
		t.Error("carol has a hash file")
	}
}

func TestUsernameRuleRefuses(t *testing.T) {
	c := credSvcFixture(t)
	_, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "root", testProof)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "isn't a valid Samba and Unix name") {
		t.Fatalf("root: %v", err)
	}
	if c.fa.calls.Load() != 0 {
		t.Error("the proof was consumed for a refused name")
	}
	if _, ok := credOf(c.f.h, smbID, "root"); ok {
		t.Error("metadata for root")
	}
}

func TestFreshAuthRequired(t *testing.T) {
	c := credSvcFixture(t)
	c.fa.err = &freshauth.Error{Reason: "nonce mismatch"}
	_, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "alice", testProof)
	if statusOf(err) != 403 || err.Error() != freshauth.Message {
		t.Fatalf("refused proof: %v", err)
	}
	if _, ok := c.hashFile("alice"); ok {
		t.Error("a hash file was written")
	}
	if _, ok := credOf(c.f.h, smbID, "alice"); ok {
		t.Error("metadata was written")
	}
	a := credAudits(c.audit, "credential.create")
	if len(a) != 1 || !strings.Contains(a[0], "refused") || !strings.Contains(a[0], "nonce mismatch") {
		t.Fatalf("audit = %v", a)
	}
	for _, s := range []string{testProof.Code, testProof.CodeVerifier, testProof.Nonce} {
		if strings.Contains(a[0], s) {
			t.Errorf("the audit carries the proof: %s", a[0])
		}
	}
}

// F31 and §5.1: 503 before the proof when the uuid is unknown or the
// secrets volume can't be used.
func TestCreateUnavailable503(t *testing.T) {
	c := credSvcFixture(t)
	c.people.set(func(p *fakePeople) { p.uuids = map[string]string{"alice": ""} })
	if _, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "alice", testProof); statusOf(err) != 503 {
		t.Errorf("no uuid: %v", err)
	}
	c.people.set(func(p *fakePeople) { p.err = errors.New("ldap down") })
	if _, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "alice", testProof); statusOf(err) != 503 {
		t.Errorf("LLDAP down: %v", err)
	}
	if c.fa.calls.Load() != 0 {
		t.Error("the proof was consumed")
	}

	f := credFixtureWith(t, func(root string, cfg *Config) { cfg.SecretsDir = filepath.Join(root, "missing") })
	f.h.SetFreshAuth(ListenerPeople, c.fa)
	f.h.freshAuthReady.Store(true)
	if err := f.h.Enable(smbB); err == nil {
		t.Fatal("enabled without a secrets volume")
	}
	// Enabled in state by hand (the route's 503 must come before the proof).
	f.h.mu.Lock()
	f.h.st.SetEnabled(smbID, true)
	f.h.rebuildLocked()
	f.h.mu.Unlock()
	if _, err := f.h.CreateCredential(context.Background(), smbID, smbKey, "alice", testProof); statusOf(err) != 503 {
		t.Errorf("unusable secrets volume: %v", err)
	}
	if c.fa.calls.Load() != 0 {
		t.Error("the proof was consumed")
	}
}

// F45: refused creates count toward the people listener's limiter.
func TestCreateRefusalsLimited(t *testing.T) {
	c := credSvcFixture(t)
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	c.f.h.entryNow = func() time.Time { return now }
	for i := 0; i < entryRefusalLimit; i++ {
		if _, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "carol", testProof); statusOf(err) != 404 {
			t.Fatalf("refusal %d: %v", i, err)
		}
	}
	if _, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "carol", testProof); statusOf(err) != 429 {
		t.Errorf("past the limit: %v", err)
	}
	// Another caller isn't limited; a success doesn't count.
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
}

func TestRevokeOwnNeedsNoProof(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	calls := c.fa.calls.Load()
	before := len(credExecs(c.f, templates.HookCredentialChange))
	if err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "Alice"); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if _, ok := c.hashFile("alice"); ok {
		t.Error("the hash file is still there")
	}
	m, _ := credOf(c.f.h, smbID, "alice")
	if m.Active() || m.Reason != state.CredentialReasonSelf || m.RevokedBy != "alice" {
		t.Errorf("metadata %+v", m)
	}
	if a := credAudits(c.audit, "credential.revoke"); len(a) != 1 || !strings.Contains(a[0], "actor=self") || !strings.Contains(a[0], "reason=self") {
		t.Errorf("audit = %v", a)
	}
	if c.fa.calls.Load() != calls {
		t.Error("a revoke asked for a proof")
	}
	// Applied live (the hook, step 2) and the bookkeeping delivery.
	if n := len(credExecs(c.f, templates.HookCredentialChange)) - before; n < 1 {
		t.Errorf("%d credential_change hook runs", n)
	}
	for _, in := range credExecs(c.f, templates.HookCredentialChange)[before:] {
		if _, has := in.Credentials[smbKey]["alice"]; has {
			t.Errorf("a hook after the revoke still lists alice: %+v", in.Credentials)
		}
	}
	// Nothing active: 204, nothing audited; outside the population and
	// on a disabled instance too.
	if err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice"); err != nil {
		t.Error(err)
	}
	if err := c.f.h.RevokeOwnCredential(context.Background(), smbB, smbKey, "carol"); err != nil {
		t.Error(err)
	}
	if a := credAudits(c.audit, "credential.revoke"); len(a) != 1 {
		t.Errorf("audits = %v", a)
	}
}

func TestAdminRevoke(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	if err := c.f.h.AdminRevokeCredential(context.Background(), smbID, smbKey, "alice", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	m, _ := credOf(c.f.h, smbID, "alice")
	if m.Active() || m.Reason != state.CredentialReasonAdmin || m.RevokedBy != "root" {
		t.Errorf("metadata %+v", m)
	}
	if _, ok := c.hashFile("alice"); ok {
		t.Error("the hash file is still there")
	}
	if a := credAudits(c.audit, "credential.revoke"); len(a) != 1 || !strings.HasPrefix(a[0], "root ") || !strings.Contains(a[0], "actor=root") || !strings.Contains(a[0], "reason=admin") {
		t.Errorf("audit = %v", a)
	}
	if err := c.f.h.AdminRevokeCredential(context.Background(), "nope", smbKey, "alice", directory.Human("root")); statusOf(err) != 404 {
		t.Errorf("unknown instance: %v", err)
	}
	if err := c.f.h.AdminRevokeCredential(context.Background(), smbID, "connect_address", "alice", directory.Human("root")); statusOf(err) != 404 {
		t.Errorf("not a person_secret: %v", err)
	}
}

// §13.16 step 2: a running hook service gets the credential_change
// hooks directly, with the timeout capped at 8 s; exit 0 is done.
func TestRevokeAppliedLive(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	execs := len(c.f.engine.ExecCalls())
	downs := countCalls(c.f, "down:"+smbProject)
	if err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice"); err != nil {
		t.Fatal(err)
	}
	calls := c.f.engine.ExecCalls()
	if len(calls) <= execs {
		t.Fatal("no hook ran during the revoke")
	}
	first := calls[execs]
	if first.in.Timeout != revokeHookMax {
		t.Errorf("the revocation hook's timeout = %s, want %s", first.in.Timeout, revokeHookMax)
	}
	var in settings.HookInput
	json.Unmarshal(first.in.Stdin, &in)
	if in.Trigger != templates.HookCredentialChange || in.Credentials == nil || len(in.Credentials[smbKey]) != 0 {
		t.Errorf("revocation hook input: trigger %q, credentials %+v", in.Trigger, in.Credentials)
	}
	settle(c.f)
	if countCalls(c.f, "down:"+smbProject) != downs {
		t.Error("the instance was stopped although the hook applied the revocation")
	}
}

// Step 1: no running container of the hook's service: done (no hook,
// no kill); the bookkeeping delivery is still queued.
func TestRevokeNotRunningIsDone(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	c.f.engine.mu.Lock()
	c.f.engine.containers = nil
	c.f.engine.mu.Unlock()
	execs := len(c.f.engine.ExecCalls())
	downs := countCalls(c.f, "down:"+smbProject)
	if err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice"); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if len(c.f.engine.ExecCalls()) != execs || countCalls(c.f, "down:"+smbProject) != downs {
		t.Errorf("execs %d -> %d, downs %d -> %d", execs, len(c.f.engine.ExecCalls()), downs, countCalls(c.f, "down:"+smbProject))
	}
	if c.f.h.DeliveryStatus(smbID).Trigger != TriggerCredential {
		t.Error("no credential delivery queued")
	}
}

// killed reports the F26 fallback: the project taken down, op record
// credentials, the instance still enabled.
func assertKilled(t *testing.T, c *credSvc, downs int) {
	t.Helper()
	if countCalls(c.f, "down:"+smbProject) <= downs {
		t.Errorf("the project was not taken down: %v", c.f.runner.Calls())
	}
	if !c.f.h.IsEnabled(smbID) {
		t.Error("the instance was disabled")
	}
}

func assertCredentialsOp(t *testing.T, c *credSvc) {
	t.Helper()
	r := c.f.h.LastOp(smbID)
	if r == nil || r.Op != OpCredentials || r.OK || !strings.Contains(r.Error, "revocation could not be applied live; the instance was stopped") {
		t.Errorf("op record = %+v", r)
	}
}

// TestRevokeHookFailureRecreates (Review Focus 3, F26): the hook exits 1
// → forceDown, op record credentials, then a background Restart.
func TestRevokeHookFailureRecreates(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	c.f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{ExitCode: 1, Output: []byte("smbpasswd failed\n"), ExecID: "e1"}, nil
	})
	// The lifecycle lock is held, so the restart waits: the credentials
	// record can be read before it runs.
	unlock, err := c.f.h.lockApp(smbID)
	if err != nil {
		t.Fatal(err)
	}
	downs, ups := countCalls(c.f, "down:"+smbProject), countCalls(c.f, "up:"+smbProject)
	if err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice"); err != nil {
		t.Fatal(err)
	}
	assertKilled(t, c, downs)
	assertCredentialsOp(t, c)
	c.f.engine.setExec(nil)
	unlock()
	settle(c.f)
	if countCalls(c.f, "up:"+smbProject) <= ups {
		t.Errorf("no restart after the kill: %v", c.f.runner.Calls())
	}
	if r := c.f.h.LastOp(smbID); r == nil || r.Op != OpRestart || !r.OK {
		t.Errorf("after the restart: %+v", r)
	}
}

// The restart fails: the instance stays down and enabled.
func TestRevokeRestartFailureStaysDown(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	c.f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{TimedOut: true, ExecID: "slow"}, nil
	})
	c.f.runner.mu.Lock()
	c.f.runner.upErr = errors.New("up failed")
	c.f.runner.mu.Unlock()
	downs := countCalls(c.f, "down:"+smbProject)
	if err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice"); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	assertKilled(t, c, downs)
	if r := c.f.h.LastOp(smbID); r == nil || r.OK {
		t.Errorf("op record %+v", r)
	}
}

// F25: another delivery holds the lock past the 2 s wait → the kill.
func TestRevokeWhileDeliveryBusy(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	l := c.f.h.deliverLock(smbID)
	l.Lock()
	downs := countCalls(c.f, "down:"+smbProject)
	execs := len(c.f.engine.ExecCalls())
	start := time.Now()
	err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice")
	l.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < c.f.h.revokeLockWait || d > 10*time.Second {
		t.Errorf("took %s (lock wait %s)", d, c.f.h.revokeLockWait)
	}
	if len(c.f.engine.ExecCalls()) != execs {
		t.Error("a hook ran without the delivery lock")
	}
	assertKilled(t, c, downs)
	assertCredentialsOp(t, c)
	settle(c.f)
}

// F25: a timed-out hook exec still running → the kill, no new exec.
func TestRevokeWhilePreviousHookStuck(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	c.f.h.deliveryMu.Lock()
	c.f.h.hookExecs = map[string]timedOutExec{smbID: {execID: "stuck", timeout: time.Minute}}
	c.f.h.deliveryMu.Unlock()
	c.f.engine.setExecRunning("stuck", true)
	downs := countCalls(c.f, "down:"+smbProject)
	execs := len(c.f.engine.ExecCalls())
	start := time.Now()
	if err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %s", d)
	}
	if len(c.f.engine.ExecCalls()) != execs {
		t.Error("a hook ran while the previous one is stuck")
	}
	c.f.engine.mu.Lock()
	inspects := c.f.engine.execInspects
	c.f.engine.mu.Unlock()
	if inspects != 1 {
		t.Errorf("the stuck exec was inspected %d times: a revocation checks once, never waits it out", inspects)
	}
	assertKilled(t, c, downs)
	assertCredentialsOp(t, c)
	c.f.engine.setExecRunning("stuck", false)
	settle(c.f)
}

// F26: a lifecycle operation holds lockApp (and, in its up, the
// delivery lock): the containers are still killed within 10 s.
func TestRevokeWhileLifecycleBusy(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	unlock, err := c.f.h.lockApp(smbID)
	if err != nil {
		t.Fatal(err)
	}
	l := c.f.h.deliverLock(smbID)
	l.Lock()
	downs := countCalls(c.f, "down:"+smbProject)
	done := make(chan error, 1)
	go func() { done <- c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the revoke waited for the lifecycle operation")
	}
	assertKilled(t, c, downs)
	assertCredentialsOp(t, c)
	l.Unlock()
	unlock()
	settle(c.f)
}

// Zero credential_change hooks (none declared): not done → the kill.
func TestRevokeZeroHooksKills(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	c.f.h.mu.Lock()
	for i := range c.f.h.instances {
		if c.f.h.instances[i].ID == smbID {
			hs := []templates.Hook{c.f.h.instances[i].Manifest.Hooks[0]}
			hs[0].When = []string{templates.HookStart}
			c.f.h.instances[i].Manifest.Hooks = hs
		}
	}
	c.f.h.mu.Unlock()
	downs := countCalls(c.f, "down:"+smbProject)
	execs := len(c.f.engine.ExecCalls())
	if err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice"); err != nil {
		t.Fatal(err)
	}
	if len(c.f.engine.ExecCalls()) != execs {
		t.Error("a hook ran")
	}
	assertKilled(t, c, downs)
	assertCredentialsOp(t, c)
	settle(c.f)
}

func TestHookInputCredentials(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	before := len(c.f.engine.ExecCalls())
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerRetry); err != nil {
		t.Fatal(err)
	}
	calls := c.f.engine.ExecCalls()
	if len(calls) <= before {
		t.Fatal("no hook ran")
	}
	stdin := string(calls[len(calls)-1].in.Stdin)
	var in settings.HookInput
	if err := json.Unmarshal([]byte(stdin), &in); err != nil {
		t.Fatal(err)
	}
	got := in.Credentials[smbKey]["alice"]
	if got.ID != cc.Credential.ID || got.Version != 1 || len(in.Credentials[smbKey]) != 1 {
		t.Errorf("credentials = %+v", in.Credentials)
	}
	if regexp.MustCompile(`(?i)[0-9a-f]{32}`).MatchString(stdin) {
		t.Errorf("a 32-hex value in the hook stdin: %s", stdin)
	}
}

// F44, F61: neither the password nor its hash appears anywhere but the
// create answer.
func TestCredentialNotEchoed(t *testing.T) {
	c := credSvcFixture(t)
	logs := captureLog(t)
	cc := c.create(t, "alice")
	pw := string(cc.Password)
	hash := credentials.NTHash(cc.Password)
	forms := []string{pw, hash, strings.ToLower(hash)}
	// A hook echoing the hash (both cases) and failing: the op record
	// has [redacted].
	c.f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{ExitCode: 1, Output: []byte("got " + hash + " and " + strings.ToLower(hash) + "\n"), ExecID: "e"}, nil
	})
	rep, err := c.f.h.Deliver(context.Background(), smbID, TriggerRetry)
	if err != nil {
		t.Fatal(err)
	}
	if r := c.f.h.LastOp(smbID); r == nil || r.Op != OpHook || !strings.Contains(r.Error, "[redacted]") {
		t.Errorf("hook op record = %+v", r)
	}
	c.f.engine.setExec(nil)
	// Exec answers and the container logs API.
	c.f.engine.mu.Lock()
	c.f.engine.execRes = &docker.ExecResult{Output: []byte(hash + "\n" + strings.ToLower(hash) + "\n")}
	c.f.engine.logs["smb-c"] = "2026-11-04T10:00:00Z importing " + hash + "\n2026-11-04T10:00:01Z " + strings.ToLower(hash) + "\n"
	c.f.engine.mu.Unlock()
	ex, err := c.f.h.Exec(context.Background(), smbID, "smb", "cat /portcullis/secrets/alice.nt")
	if err != nil {
		t.Fatal(err)
	}
	lg, err := c.f.h.Logs(context.Background(), smbID, "smb", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ex.Output, "[redacted]") || !strings.Contains(string(lg), "[redacted]") {
		t.Errorf("exec %q, logs %q: not redacted", ex.Output, lg)
	}
	views, err := c.f.h.Credentials(context.Background(), smbID)
	if err != nil {
		t.Fatal(err)
	}
	vj, _ := json.Marshal(views)
	rj, _ := json.Marshal(rep)
	c.audit.mu.Lock()
	audits, _ := json.Marshal(c.audit.entries)
	c.audit.mu.Unlock()
	stdins := ""
	for _, e := range c.f.engine.ExecCalls() {
		stdins += string(e.in.Stdin)
	}
	where := map[string]string{
		"Credentials()": string(vj), "the delivery report": string(rj), "the audit": string(audits),
		"the log": logs.String(), "hook stdin": stdins, "Exec": ex.Output, "Logs": string(lg),
	}
	for _, p := range []string{"state.yaml", filepath.Join("settings", smbID, "delivered.json")} {
		b, err := os.ReadFile(filepath.Join(c.f.data, p))
		if err != nil {
			t.Fatal(err)
		}
		where[p] = string(b)
	}
	opsFiles, _ := filepath.Glob(filepath.Join(c.f.data, "ops", "*"))
	for _, p := range opsFiles {
		b, _ := os.ReadFile(p)
		where[p] = string(b)
	}
	for name, s := range where {
		for _, v := range forms {
			if strings.Contains(s, v) {
				t.Errorf("%s carries the password or the hash", name)
			}
		}
	}
	credentials.Zero(cc.Password)
	if strings.Trim(string(cc.Password), "\x00") != "" {
		t.Error("Zero left bytes")
	}
}

// F23: the credentials unit reconciles hash files with the metadata and
// records a digest of the active metadata only.
func TestCredentialsUnit(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	hash := credentials.NTHash(cc.Password)
	credentials.Zero(cc.Password)
	unit := "credentials:" + smbKey
	rep, err := c.f.h.Deliver(context.Background(), smbID, TriggerRetry)
	if err != nil {
		t.Fatal(err)
	}
	var u *UnitResult
	for i := range rep.Units {
		if rep.Units[i].Unit == unit {
			u = &rep.Units[i]
		}
	}
	if u == nil || !u.OK || u.Skipped != SkipUnchanged {
		t.Fatalf("unit %s = %+v (units %+v)", unit, u, rep.Units)
	}
	d := c.f.h.loadDelivered(smbID)
	if d.Hashes[unit] == "" || strings.Contains(d.Hashes[unit], hash) {
		t.Errorf("digest %q", d.Hashes[unit])
	}
	// An orphan file goes; bob's metadata without a file is voided.
	orphan := filepath.Join(c.secrets, smbID, smbKey, "mallory.nt")
	os.WriteFile(orphan, []byte(hash+"\n"), 0600)
	c.f.h.mu.Lock()
	c.f.h.st.Credentials[smbID][smbKey]["bob"] = state.Credential{ID: "b0b", Version: 1, UUID: "uuid-bob", CreatedAt: time.Now().UTC(), CreatedBy: "bob"}
	c.f.h.mu.Unlock()
	rep, err = c.f.h.Deliver(context.Background(), smbID, TriggerRetry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); err == nil {
		t.Error("the orphan hash file is still there")
	}
	if b, _ := credOf(c.f.h, smbID, "bob"); b.Active() || b.Reason != state.CredentialReasonRestore {
		t.Errorf("bob = %+v, want voided", b)
	}
	if a, _ := credOf(c.f.h, smbID, "alice"); !a.Active() {
		t.Error("alice was voided")
	}
}

// F23: the credential trigger ranks above a save, maps to the
// credential_change hooks and survives a merge.
func TestTriggerCredentialMerge(t *testing.T) {
	if triggerRank(TriggerCredential) != 5 || triggerRank(TriggerCredential) <= triggerRank(TriggerSave) {
		t.Errorf("rank %d", triggerRank(TriggerCredential))
	}
	if hookWhen(TriggerCredential) != templates.HookCredentialChange {
		t.Errorf("hookWhen = %q", hookWhen(TriggerCredential))
	}
	c := credSvcFixture(t)
	addCred(t, c.f.h, smbID, "alice", strings.Repeat("A", 32))
	before := len(credExecs(c.f, templates.HookCredentialChange))
	// A debounced credential request, then an immediate save: one run,
	// still credential_change.
	c.f.h.queueDelivery(smbID, TriggerCredential, settings.EffectNone, time.Minute)
	c.f.h.queueDelivery(smbID, TriggerSave, settings.EffectNone, 0)
	c.f.h.Wait()
	if n := len(credExecs(c.f, templates.HookCredentialChange)) - before; n != 1 {
		t.Errorf("%d credential_change runs after the merge", n)
	}
	// A hook declaring settings_change only: a pure credential run skips
	// it; a save merged into a credential run still runs it.
	c.f.h.mu.Lock()
	for i := range c.f.h.instances {
		if c.f.h.instances[i].ID == smbID {
			hs := append([]templates.Hook(nil), c.f.h.instances[i].Manifest.Hooks...)
			hs = append(hs, templates.Hook{Name: "notify", Service: "smb", Command: []string{"/notify"}, When: []string{templates.HookSettingsChange}})
			c.f.h.instances[i].Manifest.Hooks = hs
		}
	}
	c.f.h.mu.Unlock()
	notify := func() int {
		n := 0
		for _, e := range c.f.engine.ExecCalls() {
			if len(e.in.Cmd) == 1 && e.in.Cmd[0] == "/notify" {
				n++
			}
		}
		return n
	}
	addCred(t, c.f.h, smbID, "bob", strings.Repeat("B", 32))
	c.f.h.queueDelivery(smbID, TriggerCredential, settings.EffectNone, 0)
	c.f.h.Wait()
	if notify() != 0 {
		t.Error("a settings_change-only hook ran on a credential change")
	}
	addCred(t, c.f.h, smbID, "root", strings.Repeat("C", 32))
	c.f.h.queueDelivery(smbID, TriggerSave, settings.EffectNone, time.Minute)
	c.f.h.queueDelivery(smbID, TriggerCredential, settings.EffectNone, 0)
	c.f.h.Wait()
	if notify() != 1 {
		t.Errorf("the merged save's hook ran %d times, want 1", notify())
	}
}

func TestMyAppsCredentialStatuses(t *testing.T) {
	c := credSvcFixture(t)
	if err := c.f.h.save(smbID, SettingsUpdate{Values: vals("connect_address", "nas.home.arpa")}); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	card := func(user string) (MyCredential, *MyAppsView) {
		t.Helper()
		v, err := c.f.h.MyApps(context.Background(), user)
		if err != nil {
			t.Fatal(err)
		}
		a := myApp(v.Apps, smbID)
		if a == nil || len(a.Credentials) != 1 {
			t.Fatalf("%s's apps = %+v", user, v.Apps)
		}
		for _, val := range a.Values {
			if val.Key == "uid" || val.Key == smbKey {
				t.Errorf("value %s shown", val.Key)
			}
		}
		return a.Credentials[0], v
	}
	cr, v := card("alice")
	if cr.Status != "none" || cr.Since != nil || cr.Key != smbKey || cr.Label != "File-share password" {
		t.Errorf("before: %+v", cr)
	}
	if v.FreshAuth == nil || v.FreshAuth.ClientID != freshauth.ClientID {
		t.Errorf("fresh_auth = %+v", v.FreshAuth)
	}
	want := []MyInfoLine{{Label: "Server", Value: "smb://nas.home.arpa/Home"}, {Label: "Username", Value: "alice"}}
	if !jsonEq(cr.Info, want) {
		t.Errorf("info = %+v", cr.Info)
	}
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	if cr, _ = card("alice"); cr.Status != "active" || cr.Since == nil || !cr.Since.Equal(cc.Credential.CreatedAt) {
		t.Errorf("after create: %+v", cr)
	}
	c.f.h.mu.Lock()
	if _, err := c.f.h.voidCredentialsLocked(smbID, state.CredentialReasonRestore); err != nil {
		t.Fatal(err)
	}
	c.f.h.mu.Unlock()
	if cr, _ = card("alice"); cr.Status != "voided" || cr.Reason != "restore" || cr.Since == nil {
		t.Errorf("after a restore: %+v", cr)
	}
	if cr, _ = card("root"); cr.Status != "unavailable" || cr.Reason != "isn't a valid Samba and Unix name" {
		t.Errorf("root: %+v", cr)
	}
	// Another host port: :4450.
	if _, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Ports: map[string]string{"SMB": "4450"}}, directory.Human("admin")); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if cr, _ = card("bob"); len(cr.Info) == 0 || cr.Info[0].Value != "smb://nas.home.arpa:4450/Home" {
		t.Errorf("port 4450: %+v", cr.Info)
	}
	// Outside the population: not listed; no fresh_auth without such an app.
	v, _ = c.f.h.MyApps(context.Background(), "carol")
	if myApp(v.Apps, smbID) != nil || v.FreshAuth != nil {
		t.Errorf("carol: %+v", v)
	}
}

func jsonEq(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// F1: a router-less custom template with group access has a population:
// the access group's members minus expired ones.
func TestRouterlessPopulation(t *testing.T) {
	c := credSvcFixture(t)
	tm := c.f.h.Template(smbID)
	if populationWhy(tm, false) != "" || populationWhy(tm, true) != "" {
		t.Errorf("populationWhy = %q", populationWhy(tm, false))
	}
	c.people.set(func(p *fakePeople) { p.expired["bob"] = map[string]bool{"users_" + smbID: true} })
	m, err := c.f.h.membership(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.f.h.mu.RLock()
	pop := c.f.h.populationLocked(tm, m)
	entry := c.f.h.entryPopulationLocked(tm, m)
	c.f.h.mu.RUnlock()
	var users []string
	for _, p := range pop.People {
		users = append(users, p.User)
	}
	if strings.Join(users, ",") != "alice,root" || pop.Why != "" || !jsonEq(pop, entry) {
		t.Errorf("population = %v (%q), entries %+v", users, pop.Why, entry)
	}
	if ok, err := c.f.h.InPopulation(context.Background(), smbID, "alice"); !ok || err != nil {
		t.Errorf("InPopulation(alice) = %v, %v", ok, err)
	}
}

// F5: person_secret and person_id hold no admin value anywhere.
func TestHubSetOptionsSkipped(t *testing.T) {
	c := credSvcFixture(t)
	h := c.f.h
	for name, u := range map[string]SettingsUpdate{
		"person share_password": {Person: map[string]PersonChange{smbKey: {Default: raw("x")}}},
		"person uid":            {Person: map[string]PersonChange{"uid": {Default: raw(20001)}}},
		"value share_password":  {Values: vals(smbKey, "x")},
		"value uid":             {Values: vals("uid", 20001)},
		"secret share_password": {Secrets: map[string]SecretChange{smbKey: {Clear: true}}},
		"groups uid":            {Groups: map[string][]GroupValueInput{"uid": {{Group: "users_" + smbID, Value: raw(1)}}}},
	} {
		if _, err := h.SaveSettings(smbID, u, directory.Human("admin")); statusOf(err) != 400 || (!strings.HasPrefix(name, "secret") && !strings.Contains(err.Error(), "set by the Hub")) {
			t.Errorf("%s: %v, want 400 (set by the Hub)", name, err)
		}
	}
	h.mu.RLock()
	s := h.st.Settings[smbID]
	h.mu.RUnlock()
	for _, k := range []string{smbKey, "uid"} {
		if _, ok := s.Person[k]; ok {
			t.Errorf("%s seeded", k)
		}
	}
	p, err := h.SettingsPanel(context.Background(), smbID)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{smbKey, "uid"} {
		if _, ok := p.Person[k]; ok {
			t.Errorf("panel person value %s", k)
		}
		if _, ok := p.Instance[k]; ok {
			t.Errorf("panel instance value %s", k)
		}
	}
	tm := h.Template(smbID)
	for _, o := range tm.Manifest.Options() {
		if (o.Type == templates.TypePersonSecret || o.Type == templates.TypePersonID) && o.EnvName() != "" {
			t.Errorf("%s has env %s", o.Key, o.EnvName())
		}
	}
	env, _ := os.ReadFile(h.envPath(smbID))
	if strings.Contains(string(env), "SHARE_PASSWORD") || regexp.MustCompile(`(?m)^UID=`).Match(env) {
		t.Errorf(".env carries them:\n%s", env)
	}
	m, _ := h.membership(context.Background())
	h.mu.RLock()
	res := h.resolvePeopleLocked(tm, m)["alice"]
	h.mu.RUnlock()
	if _, ok := res[smbKey]; ok {
		t.Error("share_password resolved per person")
	}
	if _, ok := res["uid"]; ok {
		t.Error("uid resolved per person")
	}
	// A stored configuration of either (restored, hand-edited): never
	// shown on the panel; the prune drops it.
	h.mu.Lock()
	ss := h.st.Settings[smbID].Clone()
	if ss.Person == nil {
		ss.Person = map[string]state.PersonSetting{}
	}
	ss.Person[smbKey] = state.PersonSetting{Default: "x"}
	ss.Person["uid"] = state.PersonSetting{Default: 1}
	h.st.Settings[smbID] = ss
	h.mu.Unlock()
	if p, err = h.SettingsPanel(context.Background(), smbID); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Person[smbKey]; ok {
		t.Error("panel shows a stored share_password configuration")
	}
	if _, ok := p.Person["uid"]; ok {
		t.Error("panel shows a stored uid configuration")
	}
	h.mu.Lock()
	audits := h.pruneSettingsLocked()
	_, a := h.st.Settings[smbID].Person[smbKey]
	_, b := h.st.Settings[smbID].Person["uid"]
	h.mu.Unlock()
	for _, f := range audits {
		f()
	}
	if a || b {
		t.Error("the prune kept them")
	}
}

func TestCredentialsView(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	views, err := c.f.h.Credentials(context.Background(), smbID)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("views = %+v", views)
	}
	v := views[0]
	if v.Instance != smbID || v.Key != smbKey || v.Label != "File-share password" || v.Population != 3 || v.Active != 1 || v.Folders == nil {
		t.Errorf("view = %+v", v)
	}
	rows := map[string]CredentialRow{}
	for _, r := range v.Rows {
		rows[r.User] = r
	}
	if r := rows["alice"]; r.Status != "active" || r.Since == nil {
		t.Errorf("alice = %+v", r)
	}
	if r := rows["bob"]; r.Status != "none" {
		t.Errorf("bob = %+v", r)
	}
	if r := rows["root"]; r.Status != "unavailable" {
		t.Errorf("root = %+v", r)
	}
	if v.LastSync == nil {
		t.Error("no last sync")
	}
	if _, err := c.f.h.Credentials(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown instance: %v", err)
	}
}

// ── fix round 1 ──────────────────────────────────────────

// readOnlyData makes state.yaml unsavable until the returned func runs.
func readOnlyData(t *testing.T, f *fixture) func() {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if err := os.Chmod(f.data, 0500); err != nil {
		t.Fatal(err)
	}
	restore := func() { os.Chmod(f.data, 0755) }
	t.Cleanup(restore)
	return restore
}

// #1: the file is gone but state.yaml can't be saved: the metadata
// stays revoked, the revocation is applied live anyway, the answer 500.
func TestRevokeSaveFailureStillApplied(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	before := len(credExecs(c.f, templates.HookCredentialChange))
	restore := readOnlyData(t, c.f)
	err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice")
	restore()
	if statusOf(err) != 500 {
		t.Fatalf("revoke with an unsavable state = %v, want 500", err)
	}
	if m, _ := credOf(c.f.h, smbID, "alice"); m.Active() || m.Reason != state.CredentialReasonSelf {
		t.Errorf("metadata %+v: want revoked (self)", m)
	}
	if _, ok := c.hashFile("alice"); ok {
		t.Error("the hash file is still there")
	}
	ins := credExecs(c.f, templates.HookCredentialChange)
	if len(ins) <= before {
		t.Fatal("the revocation was not applied live")
	}
	if _, has := ins[len(ins)-1].Credentials[smbKey]["alice"]; has {
		t.Error("the live hook still lists alice")
	}
	// #8: the failed self-revoke is audited with actor self.
	a := credAudits(c.audit, "credential.revoke")
	if len(a) != 1 || !strings.Contains(a[0], "actor=self") || !strings.Contains(a[0], " error ") {
		t.Errorf("audit = %v", a)
	}
	settle(c.f)
}

// F25: the hooks need people and the directory blips: the kill.
func TestRevokeWhenDirectoryBlips(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	c.f.h.mu.Lock()
	for i := range c.f.h.instances {
		if c.f.h.instances[i].ID != smbID {
			continue
		}
		m := &c.f.h.instances[i].Manifest
		ss := *m.Settings
		ss.Options = append([]templates.Option(nil), ss.Options...)
		for j := range ss.Options {
			if ss.Options[j].Key == "uid" {
				ss.Options[j].Delivery = append(append(templates.Deliveries(nil), ss.Options[j].Delivery...), templates.Delivery{Hook: "sync"})
			}
		}
		m.Settings = &ss
	}
	c.f.h.mu.Unlock()
	if !hooksNeedPeople(c.f.h.Template(smbID)) {
		t.Fatal("the hook doesn't need people")
	}
	c.people.set(func(p *fakePeople) { p.err = errors.New("ldap blip") })
	downs := countCalls(c.f, "down:"+smbProject)
	execs := len(c.f.engine.ExecCalls())
	if err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice"); err != nil {
		t.Fatal(err)
	}
	if len(c.f.engine.ExecCalls()) != execs {
		t.Error("a hook ran without the directory")
	}
	assertKilled(t, c, downs)
	assertCredentialsOp(t, c)
	c.people.set(func(p *fakePeople) { p.err = nil })
	settle(c.f)
}

// #3: the client hanging up never turns a live revocation into a kill.
func TestRevokeCancelledRequestStillLive(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	downs := countCalls(c.f, "down:"+smbProject)
	before := len(credExecs(c.f, templates.HookCredentialChange))
	if err := c.f.h.RevokeOwnCredential(ctx, smbID, smbKey, "alice"); err != nil {
		t.Fatal(err)
	}
	if len(credExecs(c.f, templates.HookCredentialChange)) <= before {
		t.Error("no hook ran")
	}
	if countCalls(c.f, "down:"+smbProject) != downs {
		t.Error("a cancelled request killed the app")
	}
	settle(c.f)
}

// #5: a paused or restarting container counts as running: no "done".
func TestRevokePausedOrRestartingCounts(t *testing.T) {
	for _, st := range []string{"paused", "restarting"} {
		t.Run(st, func(t *testing.T) {
			c := credSvcFixture(t)
			cc := c.create(t, "alice")
			credentials.Zero(cc.Password)
			c.f.engine.mu.Lock()
			for i := range c.f.engine.containers {
				c.f.engine.containers[i].State = st
			}
			c.f.engine.mu.Unlock()
			downs := countCalls(c.f, "down:"+smbProject)
			if err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice"); err != nil {
				t.Fatal(err)
			}
			assertKilled(t, c, downs)
			settle(c.f)
		})
	}
}

// #4: a person_secret instance whose hashes can't be read answers 503
// on Exec and Logs, and its op records carry a fixed text.
func TestHashesUnreadableFailClosed(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	check := func(name string) {
		t.Helper()
		if _, err := c.f.h.Exec(context.Background(), smbID, "smb", "true"); statusOf(err) != 503 {
			t.Errorf("%s: Exec = %v, want 503", name, err)
		}
		if _, err := c.f.h.Logs(context.Background(), smbID, "smb", 10); statusOf(err) != 503 {
			t.Errorf("%s: Logs = %v, want 503", name, err)
		}
		c.f.h.finishOp(smbID, OpRestart, errors.New("boom with possibly a hash"), false)
		if r := c.f.h.LastOp(smbID); r == nil || strings.Contains(r.Error, "boom") || !strings.Contains(r.Error, "hidden") {
			t.Errorf("%s: op record %+v", name, r)
		}
	}
	if os.Geteuid() != 0 {
		os.Chmod(c.secrets, 0)
		check("unreadable volume")
		os.Chmod(c.secrets, 0700)
	}
	c.f.h.secretsErr = errors.New("volume gone")
	check("unusable volume")
	c.f.h.secretsErr = nil
	settle(c.f)
}

// #6: a regenerate whose commit fails never leaves the new hash under
// the old metadata: the credential is voided and its file removed.
func TestRegenerateFailureVoids(t *testing.T) {
	c := credSvcFixture(t)
	first := c.create(t, "alice")
	credentials.Zero(first.Password)
	restore := readOnlyData(t, c.f)
	cc, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "alice", testProof)
	restore()
	if statusOf(err) != 500 || cc != nil {
		t.Fatalf("regenerate with an unsavable state = %v, %v", cc, err)
	}
	m, _ := credOf(c.f.h, smbID, "alice")
	if m.Active() || m.Reason != state.CredentialReasonRestore {
		t.Errorf("metadata %+v: want voided", m)
	}
	if _, ok := c.hashFile("alice"); ok {
		t.Error("a hash file is left")
	}
	v, err := c.f.h.MyApps(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if a := myApp(v.Apps, smbID); a == nil || a.Credentials[0].Status != CredStatusVoided {
		t.Errorf("card = %+v", a)
	}
	settle(c.f)
	// A failed first create leaves neither metadata nor a file.
	restore = readOnlyData(t, c.f)
	_, err = c.f.h.CreateCredential(context.Background(), smbID, smbKey, "bob", testProof)
	restore()
	if statusOf(err) != 500 {
		t.Fatalf("create with an unsavable state = %v", err)
	}
	if _, ok := credOf(c.f.h, smbID, "bob"); ok {
		t.Error("metadata for bob")
	}
	if _, ok := c.hashFile("bob"); ok {
		t.Error("a hash file for bob")
	}
	settle(c.f)
}

// #9: refused 404 and 503 creates are audited refused with a fixed
// reason, never the proof.
func TestRefusedCreatesAudited(t *testing.T) {
	c := credSvcFixture(t)
	c.f.h.CreateCredential(context.Background(), smbID, smbKey, "carol", testProof)
	c.people.set(func(p *fakePeople) { p.uuids = map[string]string{"alice": ""} })
	c.f.h.CreateCredential(context.Background(), smbID, smbKey, "alice", testProof)
	a := credAudits(c.audit, "credential.create")
	if len(a) != 2 || !strings.Contains(a[0], "user=carol") || !strings.Contains(a[0], "reason=not found") || !strings.Contains(a[0], " refused ") ||
		!strings.Contains(a[1], "user=alice") || !strings.Contains(a[1], "reason=no account id") || !strings.Contains(a[1], " refused ") {
		t.Errorf("audits = %v", a)
	}
	for _, e := range a {
		for _, s := range []string{testProof.Code, testProof.CodeVerifier, testProof.Nonce} {
			if strings.Contains(e, s) {
				t.Errorf("the audit carries the proof: %s", e)
			}
		}
	}
}

// #10: a hash cut by truncation leaves no prefix in Exec or Logs.
func TestTruncatedHashPrefixBlanked(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	hash := credentials.NTHash(cc.Password)
	credentials.Zero(cc.Password)
	c.f.engine.mu.Lock()
	c.f.engine.execRes = &docker.ExecResult{Output: []byte("line\nx" + strings.ToLower(hash[:12])), Truncated: true}
	c.f.engine.logs["smb-c"] = "2026-11-04T10:00:00Z importing " + hash[:20] + "\n"
	c.f.engine.mu.Unlock()
	ex, err := c.f.h.Exec(context.Background(), smbID, "smb", "cat")
	if err != nil {
		t.Fatal(err)
	}
	lg, err := c.f.h.Logs(context.Background(), smbID, "smb", 10)
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{"exec": ex.Output, "logs": string(lg)} {
		if strings.Contains(strings.ToUpper(s), hash[:8]) || !strings.Contains(s, "[redacted]") {
			t.Errorf("%s = %q", name, s)
		}
	}
	if !strings.Contains(ex.Output, "line\nx") {
		t.Errorf("exec lost its text: %q", ex.Output)
	}
}
