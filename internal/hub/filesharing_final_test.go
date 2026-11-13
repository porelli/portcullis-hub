package hub

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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

// Plan 3 final-review fixes (final-fixes.md, HUB section).

func skipRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
}

func failHooks(f *fixture) {
	f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{ExitCode: 1, Output: []byte("smbpasswd failed\n"), ExecID: "e-fail"}, nil
	})
}

// H1 (A1): the hash file can't be removed → no hook (it would find the
// file and keep the account), the instance killed, its restart refused
// until a reconcile removes the file.
func TestRevokeRemoveFailsKillsAndRefusesStart(t *testing.T) {
	skipRoot(t)
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	before := len(credExecs(c.f, templates.HookCredentialChange))
	downs, ups := countCalls(c.f, "down:"+smbProject), countCalls(c.f, "up:"+smbProject)
	unlock := lockDir(t, filepath.Join(c.secrets, smbID, smbKey))
	err := c.f.h.RevokeOwnCredential(context.Background(), smbID, smbKey, "alice")
	if statusOf(err) != 500 {
		t.Errorf("revoke with an unremovable hash file = %v, want 500", err)
	}
	if got := len(credExecs(c.f, templates.HookCredentialChange)); got != before {
		t.Errorf("%d revocation hook(s) ran although the hash file may remain", got-before)
	}
	assertKilled(t, c, downs)
	settle(c.f)
	if countCalls(c.f, "up:"+smbProject) != ups {
		t.Errorf("restarted with the old hash file still on the volume: %v", c.f.runner.Calls())
	}
	if c.f.h.SecretsUsable() == nil {
		t.Error("SecretsUsable passes while the hash file could not be removed")
	}
	if m, _ := credOf(c.f.h, smbID, "alice"); m.Active() {
		t.Error("alice still active")
	}
	if st := loadState(t, c.f); st.Credentials[smbID][smbKey]["alice"].Active() {
		t.Error("state.yaml still holds alice's credential as active")
	}
	// Fixed: the next start reconciles (the file goes) and starts.
	unlock()
	if err := c.f.h.RestartApp(smbID); err != nil {
		t.Fatalf("restart after the fix: %v", err)
	}
	if _, ok := c.hashFile("alice"); ok {
		t.Error("the old hash file is still there")
	}
	settle(c.f)
}

// H1: a lifecycle delivery (the start's) refuses on a credentials unit
// error: a reconcile failing then (here another instance's orphan that
// can't be removed) never starts the instance.
func TestStartRefusedOnCredentialsUnitError(t *testing.T) {
	skipRoot(t)
	c := credSvcFixture(t)
	dir := filepath.Join(c.secrets, smbB, smbKey)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "mallory.nt"), credentials.NTHash([]byte("m"))+"\n")
	lockDir(t, dir)
	creates := createsOf(c.f, smbID)
	err := c.f.h.RestartApp(smbID)
	if err == nil {
		t.Fatal("started while the credentials unit failed")
	}
	if createsOf(c.f, smbID) != creates {
		t.Errorf("compose created the containers: %v", c.f.runner.Calls())
	}
	settle(c.f)
}

// renameSecretKey renames smbfixture's person_secret option (a source
// sync changed the template) in the live view.
func renameSecretKey(h *Hub, id, to string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.instances {
		if h.instances[i].ID != id {
			continue
		}
		m := &h.instances[i].Manifest
		ss := *m.Settings
		ss.Options = append([]templates.Option(nil), ss.Options...)
		for j := range ss.Options {
			if ss.Options[j].Key == smbKey {
				ss.Options[j].Key = to
			}
		}
		m.Settings = &ss
	}
}

// H2 (A2): a credential on a key that is no longer a person_secret option
// is revoked (leave) and the project killed by name.
func TestStaleKeyCredentialRevokedAndKilled(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	renameSecretKey(c.f.h, smbID, "smb_password")
	c.f.h.mu.RLock()
	revs := credentialRevocations(mustMembership(t, c.f.h), c.f.h.st.Credentials, c.f.h.credentialTemplatesLocked())
	c.f.h.mu.RUnlock()
	if len(revs) != 1 || revs[0].Key != smbKey || revs[0].User != "alice" || revs[0].Reason != state.CredentialReasonLeave {
		t.Fatalf("credentialRevocations = %+v", revs)
	}
	byName := countCalls(c.f, "downbyname:"+smbProject)
	n, err := c.f.h.CheckCredentialHolders(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("CheckCredentialHolders = %d, %v", n, err)
	}
	if c.active("alice") || c.reason("alice") != state.CredentialReasonLeave {
		t.Errorf("alice: active %t reason %q", c.active("alice"), c.reason("alice"))
	}
	if countCalls(c.f, "downbyname:"+smbProject) <= byName {
		t.Errorf("the project was not killed by name: %v", c.f.runner.Calls())
	}
	settle(c.f)
}

// H3 (A3): the pool advance is saved with the epoch rotation; while the
// reconcile failed, nothing is allocated from a rewound pool.
func TestPoolAdvanceWithEpochNoRewoundAllocation(t *testing.T) {
	skipRoot(t)
	f, _, secrets := credFixture(t)
	ids, err := f.h.allocPersonIDs(templates.PoolPOSIXUID, persons("alice"), map[string]string{"alice": "a"})
	if err != nil || ids["alice"] == 0 {
		t.Fatalf("alloc = %v %v", ids, err)
	}
	base := ids["alice"]
	f.h.Wait()
	// A later mismatch in a fresh process (Init's advance already ran).
	f.h.mu.Lock()
	f.h.poolsAdvanced = false
	f.h.mu.Unlock()
	os.Remove(filepath.Join(secrets, ".epoch"))
	restore := readOnlyData(t, f)
	if _, err := f.h.reconcileSecrets("test"); err == nil {
		t.Fatal("reconcile with an unsavable state succeeded")
	}
	if err := f.h.ensurePersonIDs(smbID, persons("bob"), map[string]string{"bob": "b"}); err == nil {
		t.Error("allocated while the reconcile had failed")
	}
	restore()
	if err := f.h.ensurePersonIDs(smbID, persons("bob"), map[string]string{"bob": "b"}); err != nil {
		t.Fatalf("allocation after the fix: %v", err)
	}
	if id := mustPersonID(t, f.h, "bob"); id <= base+PoolRewindStep {
		t.Errorf("bob got %d from a rewound pool", id)
	}
	if p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]; p.Next <= base+PoolRewindStep {
		t.Errorf("saved next = %d", p.Next)
	}
}

// H4 (A4): an epoch mismatch found mid-run applies the voids live (hook,
// else the kill) for every instance it voided.
func TestRuntimeEpochMismatchAppliesLive(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	failHooks(c.f)
	os.Remove(filepath.Join(c.secrets, ".epoch"))
	downs := countCalls(c.f, "down:"+smbProject)
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerRetry); err != nil {
		t.Fatal(err)
	}
	if m, _ := credOf(c.f.h, smbID, "alice"); m.Active() {
		t.Fatal("alice not voided")
	}
	assertKilled(t, c, downs)
	c.f.engine.setExec(nil)
	settle(c.f)
}

// H5 (D-I4): a regenerate is applied like a revocation: the hook failing
// kills the instance (the old password never stays live).
func TestRegenerateAppliedLikeRevocation(t *testing.T) {
	c := credSvcFixture(t)
	first := c.create(t, "alice")
	credentials.Zero(first.Password)
	failHooks(c.f)
	downs := countCalls(c.f, "down:"+smbProject)
	unlock := holdRestarts(t, c)
	cc, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "alice", testProof)
	if err != nil {
		t.Fatal(err)
	}
	credentials.Zero(cc.Password)
	assertKilled(t, c, downs)
	assertCredentialsOp(t, c)
	unlock()
	c.f.engine.setExec(nil)
	settle(c.f)
}

// H6 (B-I1): a run superseded after it wrote a hook-file carries a force
// for its membership hooks into the re-run; the reduced members are
// recorded only after those hooks ran.
func TestSupersededAfterHookFileForcesHooks(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	c.people.removeMember("office_milan", "bob")
	var once sync.Once
	c.f.h.deliverHook = func(id, stage string) {
		if id != smbID || stage != "files" {
			return
		}
		once.Do(func() {
			// A commit that changes the generation, not the file.
			c.f.h.mu.Lock()
			c.f.h.st.SignInMode[smbID] = "x-generation"
			c.f.h.mu.Unlock()
		})
	}
	before := len(credExecs(c.f, templates.HookMembershipChange))
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerMembership); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if lines := tsvLines(t, c.f, smbID); !slices.Contains(lines, "value\tshare1_readers\talice") {
		t.Fatalf("file not written:\n%s", strings.Join(lines, "\n"))
	}
	if got := len(credExecs(c.f, templates.HookMembershipChange)); got <= before {
		t.Error("the membership hook never ran after the superseded run wrote the file")
	}
	if got := c.f.h.loadDelivered(smbID).Members["share1_readers"]; !slices.Equal(got, []string{"alice"}) {
		t.Errorf("recorded members = %v", got)
	}
}

// H7 (T18 c3): a lifecycle down waits (bounded) for an in-flight
// delivery-lock holder (a revocation hook) before compose down.
func TestLifecycleDownWaitsForDeliveryLock(t *testing.T) {
	c := credSvcFixture(t)
	c.f.h.lifecycleDeliverWait = 3 * time.Second
	l := c.f.h.deliverLock(smbID)
	l.Lock()
	downs := countCalls(c.f, "down:"+smbProject)
	done := make(chan error, 1)
	backup := func() {
		_, err := c.f.h.BackupInstance(smbID, directory.Human("root"))
		done <- err
	}
	go backup()
	time.Sleep(300 * time.Millisecond)
	if countCalls(c.f, "down:"+smbProject) != downs {
		t.Error("compose down ran while a delivery held the lock")
	}
	l.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the backup never finished")
	}
	if countCalls(c.f, "down:"+smbProject) <= downs {
		t.Error("no down")
	}
	// Bounded: a holder that never lets go doesn't stop the down.
	c.f.h.lifecycleDeliverWait = 200 * time.Millisecond
	l.Lock()
	downs = countCalls(c.f, "down:"+smbProject)
	go backup()
	if !within(5*time.Second, func() bool { return countCalls(c.f, "down:"+smbProject) > downs }) {
		t.Error("the down waited past its bound")
	}
	l.Unlock()
	<-done
	settle(c.f)
}

// H8 (B-M2/D-M1): the script's hard username rules make the card
// unavailable; a name_refused about a population member is kept.
func TestHardUsernameRulesUnavailable(t *testing.T) {
	c := credSvcFixture(t)
	c.people.addGroup("users_"+smbID, "alice", "bob", "root", "pfg2024", "a..b")
	for _, u := range []string{"pfg2024", "a..b"} {
		v, err := c.f.h.MyApps(context.Background(), u)
		if err != nil {
			t.Fatal(err)
		}
		a := myApp(v.Apps, smbID)
		if a == nil || len(a.Credentials) != 1 || a.Credentials[0].Status != CredStatusUnavailable || a.Credentials[0].Reason == "" {
			t.Errorf("%s: card = %+v", u, a)
		}
		if _, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, u, testProof); statusOf(err) != 409 {
			t.Errorf("%s: create = %v, want 409", u, err)
		}
	}
	report := `PORTCULLIS-REPORT {"version": 1, "findings": [{"code": "name_refused", "severity": "warning", "subject": "alice", "message": "alice can't be a Samba user"}]}`
	answerHooks(c.f, report+"\n", 0)
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerRetry); err != nil {
		t.Fatal(err)
	}
	got, ok := c.f.h.HookReport(smbID)
	if !ok || len(got.Report.Findings) != 1 || got.Report.Findings[0].Subject != "alice" || got.Report.Findings[0].Severity != "info" {
		t.Errorf("kept findings = %+v", got.Report.Findings)
	}
	settle(c.f)
}

// H9 (B-M1): requires_any is judged only for the keys a save touches: a
// purge-emptied slot doesn't block an unrelated save.
func TestRequiresAnyOnlyTouchedKeys(t *testing.T) {
	c := credSvcFixture(t)
	c.people.addGroup("family", "alice")
	if _, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("share1_folder", "/srv/share1", "share1_readers", []string{"family"})}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	old := c.people.id("family")
	c.people.deleteGroup("family")
	c.f.h.PurgeGroupSettings(context.Background(), directory.Human("root"), "family", old)
	settle(c.f)
	if _, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("share2_name", "Photos")}, directory.Human("root")); err != nil {
		t.Errorf("an unrelated save after the purge = %v", err)
	}
	// Touching the slot still judges it.
	if _, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("share1_writers", []string{})}, directory.Human("root")); statusOf(err) != 400 {
		t.Errorf("touching the slot = %v, want 400", err)
	}
	settle(c.f)
}

// H12 (B-M6, C-M4): a router-less entry's note is the first paragraph
// of auth.notes (≤ 300 runes), else "No web page."; always present.
func TestPortalNoteFirstParagraph(t *testing.T) {
	for _, tc := range []struct{ notes, want string }{
		{"", "No web page."},
		{"File sharing over SMB.\nConnect from Finder.\n\nOperators: cap_drop ALL, runit.", "File sharing over SMB. Connect from Finder."},
		{"  \n\nSecond only.", "No web page."},
		{strings.Repeat("x", 301), "No web page."},
		{strings.Repeat("é", 300) + "\n\nmore", strings.Repeat("é", 300)},
	} {
		if got := portalNote(tc.notes); got != tc.want {
			t.Errorf("portalNote(%q) = %q, want %q", clip(tc.notes, 40), got, tc.want)
		}
	}
	c := credSvcFixture(t)
	for _, a := range c.f.h.Portal().Apps {
		if a.ID == smbID && a.Note != "No web page: file sharing over SMB." {
			t.Errorf("portal note = %q", a.Note)
		}
	}
}

// H15 (C-M7): the fresh-auth client not in place and an unreachable
// token endpoint answer 503 and don't count as the caller's refusals.
func TestFreshAuthOutage503NotCounted(t *testing.T) {
	c := credSvcFixture(t)
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	c.f.h.entryNow = func() time.Time { return now }
	for i := 0; i < entryRefusalLimit+2; i++ {
		c.f.h.freshAuthReady.Store(i%2 == 0)
		c.fa.err = nil
		if i%2 == 0 {
			c.fa.err = &freshauth.Error{Reason: freshauth.ReasonUnreachable}
		}
		_, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "alice", testProof)
		if statusOf(err) != 503 {
			t.Fatalf("attempt %d = %v, want 503", i, err)
		}
		if strings.Contains(err.Error(), "unreachable") || strings.Contains(err.Error(), "not in place") {
			t.Errorf("the 503 names the cause: %v", err)
		}
	}
	c.fa.err = nil
	c.f.h.freshAuthReady.Store(true)
	cc, err := c.f.h.CreateCredential(context.Background(), smbID, smbKey, "alice", testProof)
	if err != nil {
		t.Fatalf("after the outage: %v (counted as refusals?)", err)
	}
	credentials.Zero(cc.Password)
	settle(c.f)
}

// H16 (D-M6): HookInput's first key is trigger.
func TestHookInputTriggerFirst(t *testing.T) {
	in := settings.HookInput{DataFileDoc: settings.NewDataFileDoc("x"), Trigger: "credential_change"}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), `{"trigger":"credential_change",`) {
		t.Errorf("HookInput JSON = %s", clip(string(b), 80))
	}
}
