package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/credentials"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/lldap/lldaptest"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Revoke on leave (plan 3 Task 9, contract §13.16 "Who is revoked" and
// "When"; F27, F28, F30, F31, F56).

// runChecks starts RunCredentialChecks with the production trigger
// wired into CreateCredential's re-check (F30); stopped at cleanup.
func runChecks(t *testing.T, h *Hub) {
	t.Helper()
	h.credentialCheck = h.TriggerCredentialCheck
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.RunCredentialChecks(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; h.Wait() })
}

// within polls cond for at most d (no fake-clock advance).
func within(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *credSvc) active(user string) bool {
	c.f.h.mu.RLock()
	defer c.f.h.mu.RUnlock()
	cr, ok := c.f.h.st.Credentials[smbID][smbKey][user]
	return ok && cr.Active()
}

func (c *credSvc) reason(user string) string {
	c.f.h.mu.RLock()
	defer c.f.h.mu.RUnlock()
	return c.f.h.st.Credentials[smbID][smbKey][user].Reason
}

// leaveAudits are the credential.revoke_leave entries naming user.
func leaveAudits(c *credSvc, user string) []string {
	var out []string
	for _, a := range credAudits(c.audit, "credential.revoke_leave") {
		if strings.Contains(a, "user="+user+" ") || strings.HasSuffix(a, "user="+user) || strings.Contains(a, "/"+user+" ") {
			out = append(out, a)
		}
	}
	return out
}

// TestRemoveMemberRevokesAtOnce: a removal through the directory service
// fires OnChange → the holder check runs at once (never debounced: the
// fake clock is not advanced): the hash is gone, the audit says leave,
// and the hook applied it (trigger credential_change).
func TestRemoveMemberRevokesAtOnce(t *testing.T) {
	c := credSvcFixture(t)
	ll := lldaptest.New(t, "portcullis-hub", "service-password-0123456789")
	ll.AddUser("root", "root@example.org", "Root", "rootpass-123456", "lldap_admin")
	ll.AddUser("alice", "alice@example.org", "Alice", "")
	ll.AddUser("bob", "bob@example.org", "Bob", "")
	ll.AddGroup("users_"+smbID, "alice", "bob")
	ll.AddGroup("admin_" + smbID)
	ll.AddGroup("users_"+smbB, "alice")
	ll.AddGroup("admin_" + smbB)
	credDir := t.TempDir()
	os.WriteFile(filepath.Join(credDir, "username"), []byte("portcullis-hub\n"), 0600)
	os.WriteFile(filepath.Join(credDir, "password"), []byte("service-password-0123456789\n"), 0600)
	dir := &directory.Service{
		LLDAP: lldap.New(ll.HTTP.URL, ll.LDAPURL(), ll.BaseDN, credDir),
		Audit: &directory.AuditLog{Path: filepath.Join(t.TempDir(), "audit.jsonl")},
		Apps:  c.f.h.DirectoryApps,
	}
	dir.OnChange = func() { c.f.h.TriggerDirectorySync(); c.f.h.TriggerCredentialCheck() }
	c.f.h.SetPeople(dir)
	c.f.h.SetGroups(dir)
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerMembership); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	cc := c.create(t, "bob")
	credentials.Zero(cc.Password)
	runChecks(t, c.f.h)
	execs := len(credExecs(c.f, templates.HookCredentialChange))
	if _, err := dir.RemoveMember(context.Background(), &directory.Caller{User: "root", Admin: true}, "users_"+smbID, "bob"); err != nil {
		t.Fatal(err)
	}
	if !within(2*time.Second, func() bool {
		_, has := c.hashFile("bob")
		return !has && len(credExecs(c.f, templates.HookCredentialChange)) > execs
	}) {
		_, has := c.hashFile("bob")
		t.Fatalf("after 2 s: hash file present %t, credential_change execs %d → %d", has, execs, len(credExecs(c.f, templates.HookCredentialChange)))
	}
	if c.active("bob") || c.reason("bob") != state.CredentialReasonLeave {
		t.Errorf("bob: active %t, reason %q", c.active("bob"), c.reason("bob"))
	}
	if a := leaveAudits(c, "bob"); len(a) != 1 || !strings.Contains(a[0], "reason=leave") {
		t.Errorf("revoke_leave audits = %v", a)
	}
}

// TestLLDAPDirectRemovalCaughtOnTick: removed straight in LLDAP (no
// OnChange); the evaluator's tick (OnEvaluated = TriggerCredentialCheck)
// catches it.
func TestLLDAPDirectRemovalCaughtOnTick(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "bob")
	credentials.Zero(cc.Password)
	runChecks(t, c.f.h)
	c.people.removeMember("users_"+smbID, "bob")
	time.Sleep(50 * time.Millisecond)
	if !c.active("bob") {
		t.Fatal("revoked before any trigger")
	}
	c.f.h.TriggerCredentialCheck() // what OnEvaluated is wired to
	if !within(2*time.Second, func() bool { return !c.active("bob") }) {
		t.Fatal("not revoked on the tick")
	}
	if c.reason("bob") != state.CredentialReasonLeave {
		t.Errorf("reason %q", c.reason("bob"))
	}
	if _, has := c.hashFile("bob"); has {
		t.Error("hash file left")
	}
}

// TestDeletedAccountRevoked: absent from LLDAP → deleted; re-created
// (new uuid) and back in the group → still revoked (deleted).
func TestDeletedAccountRevoked(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "bob")
	credentials.Zero(cc.Password)
	c.people.set(func(p *fakePeople) {
		delete(p.users, "bob")
		for _, ms := range p.members {
			delete(ms, "bob")
		}
	})
	n, err := c.f.h.CheckCredentialHolders(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("CheckCredentialHolders = %d, %v", n, err)
	}
	if c.active("bob") || c.reason("bob") != state.CredentialReasonDeleted {
		t.Errorf("absent: active %t reason %q", c.active("bob"), c.reason("bob"))
	}
	if a := leaveAudits(c, "bob"); len(a) != 1 || !strings.Contains(a[0], "reason=deleted") {
		t.Errorf("audits %v", a)
	}
	settle(c.f)

	// Re-created: a new uuid, in the group again.
	c.people.addGroup("users_"+smbID, "bob")
	cc = c.create(t, "bob")
	credentials.Zero(cc.Password)
	c.people.recreate("bob")
	c.people.addGroup("users_"+smbID, "bob")
	if n, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil || n != 1 {
		t.Fatalf("CheckCredentialHolders = %d, %v", n, err)
	}
	if c.active("bob") || c.reason("bob") != state.CredentialReasonDeleted {
		t.Errorf("re-created: active %t reason %q", c.active("bob"), c.reason("bob"))
	}
	settle(c.f)
}

// TestLLDAPDownDoesNothing: Membership fails → the error, nothing
// revoked, no hook, no op record.
func TestLLDAPDownDoesNothing(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "bob")
	credentials.Zero(cc.Password)
	c.people.removeMember("users_"+smbID, "bob")
	c.people.set(func(p *fakePeople) { p.err = errors.New("ldap down") })
	execs := len(c.f.engine.ExecCalls())
	op := c.f.h.LastOp(smbID)
	n, err := c.f.h.CheckCredentialHolders(context.Background())
	if err == nil || n != 0 {
		t.Fatalf("CheckCredentialHolders = %d, %v; want the error", n, err)
	}
	settle(c.f)
	if !c.active("bob") {
		t.Error("revoked with LLDAP down")
	}
	if _, has := c.hashFile("bob"); !has {
		t.Error("hash removed with LLDAP down")
	}
	if len(c.f.engine.ExecCalls()) != execs {
		t.Error("a hook ran")
	}
	if got := c.f.h.LastOp(smbID); (got == nil) != (op == nil) || (got != nil && got.Op != op.Op) {
		t.Errorf("op record %+v → %+v", op, got)
	}
}

// TestNoAccessGroupRevokesEveryone (F31): LLDAP answers but the access
// group is gone → every holder revoked (leave), fail closed.
func TestNoAccessGroupRevokesEveryone(t *testing.T) {
	c := credSvcFixture(t)
	for _, u := range []string{"alice", "bob"} {
		cc := c.create(t, u)
		credentials.Zero(cc.Password)
	}
	c.people.deleteGroup("users_" + smbID)
	if n, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil || n != 2 {
		t.Fatalf("CheckCredentialHolders = %d, %v", n, err)
	}
	for _, u := range []string{"alice", "bob"} {
		if c.active(u) || c.reason(u) != state.CredentialReasonLeave {
			t.Errorf("%s: active %t reason %q", u, c.active(u), c.reason(u))
		}
	}
	settle(c.f)
}

// TestEmptyUUIDNotRevoked (F31): an empty current uuid revokes nothing
// on that ground; the doctor gets an unverifiable input.
func TestEmptyUUIDNotRevoked(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "bob")
	credentials.Zero(cc.Password)
	c.people.set(func(p *fakePeople) {
		if p.uuids == nil {
			p.uuids = map[string]string{}
		}
		p.uuids["bob"] = ""
	})
	if n, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil || n != 0 {
		t.Fatalf("CheckCredentialHolders = %d, %v", n, err)
	}
	if !c.active("bob") {
		t.Error("revoked on an empty uuid")
	}
	in, err := c.f.h.doctorInputs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := (doctor.UnverifiableIn{Instance: smbID, Key: smbKey, User: "bob"}); len(in.Unverifiable) != 1 || in.Unverifiable[0] != want {
		t.Errorf("doctor Unverifiable = %+v", in.Unverifiable)
	}
}

// TestLeaveRevokeHookFailureRecreates (Review Focus 3): the hook exits 1
// → forceDown + background Restart, and the restart's op record is OK.
func TestLeaveRevokeHookFailureRecreates(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "bob")
	credentials.Zero(cc.Password)
	c.f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{ExitCode: 1, Output: []byte("smbpasswd failed\n"), ExecID: "e1"}, nil
	})
	unlock, err := c.f.h.lockApp(smbID)
	if err != nil {
		t.Fatal(err)
	}
	downs, ups := countCalls(c.f, "down:"+smbProject), countCalls(c.f, "up:"+smbProject)
	c.people.removeMember("users_"+smbID, "bob")
	if n, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil || n != 1 {
		t.Fatalf("CheckCredentialHolders = %d, %v", n, err)
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

// TestLeaveRevokeRecreateFailureStops: the hook times out and the
// restart fails → compose down, op record credentials, the instance
// still enabled (drift shows it).
func TestLeaveRevokeRecreateFailureStops(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "bob")
	credentials.Zero(cc.Password)
	c.f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{TimedOut: true, ExecID: "slow"}, nil
	})
	c.f.runner.mu.Lock()
	c.f.runner.upErr = errors.New("up failed")
	c.f.runner.mu.Unlock()
	unlock, err := c.f.h.lockApp(smbID)
	if err != nil {
		t.Fatal(err)
	}
	downs := countCalls(c.f, "down:"+smbProject)
	c.people.removeMember("users_"+smbID, "bob")
	if _, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertKilled(t, c, downs)
	assertCredentialsOp(t, c)
	unlock()
	settle(c.f)
	if !c.f.h.IsEnabled(smbID) {
		t.Error("disabled")
	}
	if r := c.f.h.LastOp(smbID); r == nil || r.OK {
		t.Errorf("op record %+v", r)
	}
}

// deliveryRuns counts instance id's engine runs (the "built" stage).
func deliveryRuns(h *Hub, id string) *atomic.Int32 {
	var n atomic.Int32
	h.deliverHook = func(i, stage string) {
		if i == id && stage == "built" {
			n.Add(1)
		}
	}
	return &n
}

// shareGroup puts share1_readers on smbfixture = [office] (alice, bob)
// and delivers, so the last delivered file holds them.
func shareGroup(t *testing.T, c *credSvc) {
	t.Helper()
	c.people.addGroup("office", "alice", "bob")
	if err := c.f.h.save(smbID, SettingsUpdate{Values: vals("share1_readers", []string{"office"})}); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerMembership); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	d := c.f.h.loadDelivered(smbID)
	if got := d.Members["share1_readers"]; !slices.Equal(got, []string{"alice", "bob"}) {
		t.Fatalf("delivered share1_readers members = %v (%+v)", got, d.Members)
	}
}

// TestShareRemovalDeliversAtOnce (F28): bob leaves a group a groups
// option names → the check sees the expanded readers shrink against the
// last delivered file → an immediate delivery (no clock advance); the
// next check finds nothing to do.
func TestShareRemovalDeliversAtOnce(t *testing.T) {
	c := credSvcFixture(t)
	shareGroup(t, c)
	runs := deliveryRuns(c.f.h, smbID)
	c.people.removeMember("office", "bob")
	if _, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.f.h.Wait() // background runs only: the fake clock is not fired
	if runs.Load() == 0 {
		t.Fatal("no immediate delivery after a share-group removal")
	}
	if got := c.f.h.loadDelivered(smbID).Members["share1_readers"]; !slices.Equal(got, []string{"alice"}) {
		t.Errorf("delivered members after = %v", got)
	}
	before := runs.Load()
	if _, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.f.h.Wait()
	if runs.Load() != before {
		t.Error("a delivery ran with nothing changed")
	}
}

// TestAccessGroupRemovalDeliversAtOnce (F28, §13.9): leaving the access
// group (no credential held) delivers at once too.
func TestAccessGroupRemovalDeliversAtOnce(t *testing.T) {
	c := credSvcFixture(t)
	shareGroup(t, c)
	runs := deliveryRuns(c.f.h, smbID)
	c.people.removeMember("users_"+smbID, "root")
	if _, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.f.h.Wait()
	if runs.Load() == 0 {
		t.Fatal("no immediate delivery after an access-group removal")
	}
}

// TestAdditionsStayDebounced: alice joining a share group triggers no
// immediate delivery; the 60 s debounce (fake clock) applies.
func TestAdditionsStayDebounced(t *testing.T) {
	c := credSvcFixture(t)
	shareGroup(t, c)
	runs := deliveryRuns(c.f.h, smbID)
	c.people.addGroup("office", "root")
	if _, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.f.h.Wait()
	if runs.Load() != 0 {
		t.Fatal("an addition was delivered at once")
	}
	if !c.f.h.DeliveryStatus(smbID).Pending {
		t.Error("no debounced delivery queued")
	}
	settle(c.f) // the debounce fires
	if runs.Load() == 0 {
		t.Error("the debounced delivery never ran")
	}
	if got := c.f.h.loadDelivered(smbID).Members["share1_readers"]; !slices.Equal(got, []string{"alice", "bob", "root"}) {
		t.Errorf("delivered members = %v", got)
	}
}

// TestInstanceDeleteRevokesDeleted (Task 6 TestInstanceDeleteRevokes covers the order): delete → the metadata and hashes gone, no
// hook ran, audited revoke_leave reason deleted.
func TestInstanceDeleteRevokesDeleted(t *testing.T) {
	c := credSvcFixture(t)
	addCred(t, c.f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	execs := len(c.f.engine.ExecCalls())
	if _, err := c.f.h.DeleteInstance(smbB, smbB, "root"); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if _, err := os.Stat(filepath.Join(c.secrets, smbB)); err == nil {
		t.Error("hash files left")
	}
	c.f.h.mu.RLock()
	_, meta := c.f.h.st.Credentials[smbB]
	c.f.h.mu.RUnlock()
	if meta {
		t.Error("metadata left")
	}
	if len(c.f.engine.ExecCalls()) != execs {
		t.Error("a hook ran on delete")
	}
	var found bool
	for _, a := range credAudits(c.audit, "credential.revoke_leave") {
		if strings.Contains(a, smbB+"/"+smbKey+"/alice") && strings.Contains(a, "reason=deleted") && strings.Contains(a, "actor=root") {
			found = true
		}
	}
	if !found {
		t.Errorf("no revoke_leave deleted audit: %v", credAudits(c.audit, "credential.revoke_leave"))
	}
}

// raceFreshAuth runs onVerify during the proof check: a change between
// the population check and the write.
type raceFreshAuth struct {
	fakeFreshAuth
	onVerify func()
}

func (r *raceFreshAuth) Verify(ctx context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	if r.onVerify != nil {
		r.onVerify()
	}
	return r.fakeFreshAuth.Verify(ctx, p, user)
}

// TestCreateRaceRevokedByRecheck (F30): bob is removed between Verify
// and the write; the create's holder re-check revokes the new password.
func TestCreateRaceRevokedByRecheck(t *testing.T) {
	c := credSvcFixture(t)
	runChecks(t, c.f.h)
	c.f.h.SetFreshAuth(&raceFreshAuth{onVerify: func() { c.people.removeMember("users_"+smbID, "bob") }})
	cc, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "bob", testProof)
	if err != nil {
		t.Fatal(err)
	}
	credentials.Zero(cc.Password)
	if !within(2*time.Second, func() bool { return !c.active("bob") }) {
		t.Fatal("the raced create was not revoked")
	}
	if c.reason("bob") != state.CredentialReasonLeave {
		t.Errorf("reason %q", c.reason("bob"))
	}
}

// TestCredentialRevocations (F56): the pure holder function the revoker
// and the doctor's canary share.
func TestCredentialRevocations(t *testing.T) {
	c := credSvcFixture(t)
	tm := c.f.h.Template(smbID)
	now := time.Now().UTC()
	cred := func(uuid string) state.Credential {
		return state.Credential{ID: "id-" + uuid, Version: 1, UUID: uuid, CreatedAt: now, CreatedBy: "x"}
	}
	revoked := cred("uuid-dave")
	revoked.RevokedAt = &now
	creds := map[string]map[string]map[string]state.Credential{smbID: {smbKey: {
		"alice": cred("uuid-alice"), // in: kept
		"bob":   cred("uuid-bob"),   // out of the group: leave
		"carol": cred("uuid-carol"), // absent: deleted
		"root":  cred("uuid-old"),   // another uuid: deleted
		"eve":   cred("uuid-eve"),   // empty current uuid: kept
		"dave":  revoked,            // not active: ignored
	}}}
	m := &directory.Membership{
		Users:  map[string]map[string]int{"alice": {"users_" + smbID: 1}, "bob": {}, "root": {"users_" + smbID: 1}, "eve": {"users_" + smbID: 1}, "dave": {}},
		Groups: map[string]directory.MemberGroup{"users_" + smbID: {ID: 1, Members: []string{"alice", "eve", "root"}}},
		UUIDs:  map[string]string{"alice": "uuid-alice", "bob": "uuid-bob", "root": "uuid-root", "eve": "", "dave": "uuid-dave"},
	}
	tmpls := map[string]*templates.Template{smbID: tm}
	got := credentialRevocations(m, creds, tmpls)
	want := []Revocation{
		{Instance: smbID, Key: smbKey, User: "bob", ID: "id-uuid-bob", Reason: state.CredentialReasonLeave},
		{Instance: smbID, Key: smbKey, User: "carol", ID: "id-uuid-carol", Reason: state.CredentialReasonDeleted},
		{Instance: smbID, Key: smbKey, User: "root", ID: "id-uuid-old", Reason: state.CredentialReasonDeleted},
	}
	if !slices.Equal(got, want) {
		t.Errorf("revocations =\n %+v\nwant\n %+v", got, want)
	}
	if u := unverifiableCredentials(m, creds, tmpls); len(u) != 1 || u[0].User != "eve" {
		t.Errorf("unverifiable = %+v", u)
	}
	// The access group missing: everyone (fail closed).
	delete(m.Groups, "users_"+smbID)
	got = credentialRevocations(m, creds, tmpls)
	if len(got) != 5 {
		t.Errorf("without the access group: %+v", got)
	}
	for _, r := range got {
		if r.User == "alice" && r.Reason != state.CredentialReasonLeave {
			t.Errorf("alice: %+v", r)
		}
	}
}

// Fix round 1 #1: an instance holding credentials whose view is gone
// (template missing) is judged too — everyone revoked (leave) — and its
// project is killed by name (no view to compose down), op credentials.
func TestNoViewRevokesAndKills(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "bob")
	credentials.Zero(cc.Password)
	c.f.h.mu.Lock()
	var kept []templates.Template
	for _, it := range c.f.h.instances {
		if it.ID != smbID {
			kept = append(kept, it)
		}
	}
	c.f.h.instances = kept
	c.f.h.mu.Unlock()
	if c.f.h.Template(smbID) != nil {
		t.Fatal("the view is still there")
	}
	byName := countCalls(c.f, "downbyname:"+smbProject)
	n, err := c.f.h.CheckCredentialHolders(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("CheckCredentialHolders = %d, %v", n, err)
	}
	if c.active("bob") || c.reason("bob") != state.CredentialReasonLeave {
		t.Errorf("bob: active %t reason %q", c.active("bob"), c.reason("bob"))
	}
	if _, has := c.hashFile("bob"); has {
		t.Error("hash file left")
	}
	if countCalls(c.f, "downbyname:"+smbProject) <= byName {
		t.Errorf("the project was not taken down by name: %v", c.f.runner.Calls())
	}
	if r := c.f.h.LastOp(smbID); r == nil || r.Op != OpCredentials || r.OK {
		t.Errorf("op record %+v", r)
	}
	if got := credentialRevocations(&directory.Membership{Users: map[string]map[string]int{}}, map[string]map[string]map[string]state.Credential{"gone": {"k": {"x": {ID: "1", UUID: "u"}}}}, nil); len(got) != 1 || got[0].Reason != state.CredentialReasonLeave {
		t.Errorf("pure: %+v", got)
	}
	settle(c.f)
}

// Fix round 1 #2: one failed commit doesn't stop the instance's other
// revocations: both leavers are revoked (in memory, files gone), the
// error returned, the revocation applied.
func TestFailedCommitKeepsRevoking(t *testing.T) {
	c := credSvcFixture(t)
	for _, u := range []string{"alice", "bob"} {
		cc := c.create(t, u)
		credentials.Zero(cc.Password)
	}
	c.people.removeMember("users_"+smbID, "alice")
	c.people.removeMember("users_"+smbID, "bob")
	before := len(credExecs(c.f, templates.HookCredentialChange))
	restore := readOnlyData(t, c.f)
	n, err := c.f.h.CheckCredentialHolders(context.Background())
	restore()
	if err == nil || n != 2 {
		t.Fatalf("CheckCredentialHolders = %d, %v; want 2 and the save error", n, err)
	}
	for _, u := range []string{"alice", "bob"} {
		if c.active(u) {
			t.Errorf("%s still active", u)
		}
		if _, has := c.hashFile(u); has {
			t.Errorf("%s's hash file left", u)
		}
	}
	if len(credExecs(c.f, templates.HookCredentialChange)) <= before {
		t.Error("not applied live")
	}
	settle(c.f)
}

// Fix round 1 #3: no Members record (never delivered with a snapshot)
// counts as changed: a debounced delivery is queued.
func TestNilMembersRecordQueuesDelivery(t *testing.T) {
	c := credSvcFixture(t)
	settle(c.f)
	d := c.f.h.loadDelivered(smbID)
	d.Members = nil
	c.f.h.saveDelivered(smbID, d)
	runs := deliveryRuns(c.f.h, smbID)
	if _, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.f.h.Wait()
	if runs.Load() != 0 {
		t.Error("ran at once")
	}
	if !c.f.h.DeliveryStatus(smbID).Pending {
		t.Error("no debounced delivery queued")
	}
	settle(c.f)
	if c.f.h.loadDelivered(smbID).Members == nil {
		t.Error("the delivery recorded no members")
	}
}

// Fix round 1 #5: a credential re-created after the check judged the
// old one is left alone (Revocation.ID).
func TestStaleJudgementSparesNewCredential(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "bob")
	credentials.Zero(cc.Password)
	c.people.removeMember("users_"+smbID, "bob")
	c.f.h.testHookHolderJudged = func() {
		c.f.h.mu.Lock()
		cr := c.f.h.st.Credentials[smbID][smbKey]["bob"]
		cr.ID, cr.Version = "recreated", cr.Version+1
		c.f.h.st.Credentials[smbID][smbKey]["bob"] = cr
		c.f.h.mu.Unlock()
	}
	n, err := c.f.h.CheckCredentialHolders(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("CheckCredentialHolders = %d, %v; want 0", n, err)
	}
	if !c.active("bob") {
		t.Error("a credential created after the judgement was revoked")
	}
}
