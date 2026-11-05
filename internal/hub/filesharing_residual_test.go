package hub

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/credentials"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/templates"
)

// Plan 3 final fixes, residual pass (final-rereview.md N1–N5 and the
// test gaps of H2 / H6).

// N1: a restart whose prepareUp reconcile voids a credential (its hash
// file is gone) and that is then refused before the down (a shared-folder
// probe) still applies the void: a credential_change hook runs.
func TestRestartRefusedAfterVoidAppliesIt(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	fx := c.f.engine.fx()
	fx.inspect = map[string]docker.ContainerInfo{testSelfID: {ID: testSelfID, Image: testSelfImage, Labels: selfLabels}}
	c.f.h.mountinfo = func() ([]byte, error) { return []byte(testMountinfo), nil }
	d := &fakeDisk{paths: map[string]*diskPath{}, symlinks: map[string]bool{}}
	fx.run = d.run
	addFolder(t, c.f, d, "media", "Family media", "/srv/media", 60001)
	d.add("/srv/media/s1", "ext4")
	c.people.addGroup("office_milan", "alice")
	setStored(c.f, smbID, "share1_folder", "folder:media/s1", "share1_readers", []any{"office_milan"})
	settle(c.f)
	// The hash file vanishes; the subpath changes on disk.
	os.Remove(filepath.Join(c.secrets, smbID, smbKey, "alice.nt"))
	d.mu.Lock()
	d.symlinks["/srv/media/s1"] = true
	d.mu.Unlock()
	before := len(credExecs(c.f, templates.HookCredentialChange))
	downs := countCalls(c.f, "down:"+smbProject)
	err := c.f.h.RestartApp(smbID)
	if err == nil || !strings.Contains(err.Error(), "changed on disk") {
		t.Fatalf("restart = %v, want the folder refusal", err)
	}
	if countCalls(c.f, "down:"+smbProject) != downs {
		t.Fatal("the restart stopped the app (the sequence needs a refusal before the down)")
	}
	if m, _ := credOf(c.f.h, smbID, "alice"); m.Active() {
		t.Fatal("alice not voided by the restart's reconcile")
	}
	settle(c.f)
	ins := credExecs(c.f, templates.HookCredentialChange)
	if len(ins) <= before {
		t.Fatal("no credential_change hook ran: the running app keeps the voided account")
	}
	if _, has := ins[len(ins)-1].Credentials[smbKey]["alice"]; has {
		t.Error("the hook still lists alice")
	}
}

// N4: every lifecycle down waits for the delivery lock once (≤ the
// bound), never once per layer (stopProject → composeDown): backup,
// disable, delete (its backup's down and its own: two downs, two waits).
func TestLifecycleDownWaitsOnce(t *testing.T) {
	for _, op := range []string{"backup", "disable", "delete"} {
		t.Run(op, func(t *testing.T) {
			c := credSvcFixture(t)
			c.f.h.lifecycleDeliverWait = 400 * time.Millisecond
			l := c.f.h.deliverLock(smbID)
			l.Lock()
			var waited atomic.Int32
			c.f.h.testHookAwaitDelivery = func(id string) {
				if id == smbID {
					waited.Add(1)
				}
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				switch op {
				case "backup":
					c.f.h.BackupInstance(smbID, "root")
				case "disable":
					c.f.h.Disable(smbID)
				case "delete":
					c.f.h.DeleteInstance(smbID, smbID, "root")
				}
			}()
			if !within(10*time.Second, func() bool {
				return countCalls(c.f, "down:"+smbProject) > 0 || countCalls(c.f, "downbyname:"+smbProject) > 0
			}) {
				t.Fatalf("no down: %v", c.f.runner.Calls())
			}
			l.Unlock()
			<-done
			downs := countCalls(c.f, "down:"+smbProject) + countCalls(c.f, "downbyname:"+smbProject)
			if n := waited.Load(); n != int32(downs) || n == 0 {
				t.Errorf("%s waited for the delivery lock %d times for %d down(s), want once per down", op, n, downs)
			}
			settle(c.f)
		})
	}
}

// H2 gap: the kill by name of a stale key's credential is followed by a
// background Restart.
func TestStaleKeyKillRestarts(t *testing.T) {
	c := credSvcFixture(t)
	cc := c.create(t, "alice")
	credentials.Zero(cc.Password)
	renameSecretKey(c.f.h, smbID, "smb_password")
	ups := countCalls(c.f, "up:"+smbProject)
	if _, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if countCalls(c.f, "up:"+smbProject) <= ups {
		t.Errorf("no background restart after the kill: %v", c.f.runner.Calls())
	}
	if r := c.f.h.LastOp(smbID); r == nil || r.Op != OpRestart || !r.OK {
		t.Errorf("last op = %+v, want a successful restart", r)
	}
}

// H6 gap: the forced hook of a superseded hook-file run fails → the
// reduced members are not recorded and the hook is retried.
func TestSupersededForcedHookFailsNotRecorded(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	c.people.removeMember("office_milan", "bob")
	var once sync.Once
	c.f.h.deliverHook = func(id, stage string) {
		if id != smbID || stage != "files" {
			return
		}
		once.Do(func() {
			c.f.h.mu.Lock()
			c.f.h.st.AuthPolicies[smbID] = policy.AuthPolicy{}
			c.f.h.mu.Unlock()
		})
	}
	failHooks(c.f)
	before := len(credExecs(c.f, templates.HookMembershipChange))
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerMembership); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if got := len(credExecs(c.f, templates.HookMembershipChange)); got <= before {
		t.Fatal("the forced hook never ran")
	}
	if got := c.f.h.loadDelivered(smbID).Members["share1_readers"]; slices.Contains(got, "alice") && !slices.Contains(got, "bob") {
		t.Errorf("the reduced members were recorded although the hook failed: %v", got)
	}
	// Retried: the next holder check sees the old record and delivers
	// again; with the hook fixed the reduced members are recorded.
	c.f.engine.setExec(nil)
	failed := len(credExecs(c.f, templates.HookMembershipChange))
	if _, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if len(credExecs(c.f, templates.HookMembershipChange)) <= failed {
		t.Error("the failed hook was not retried")
	}
	if got := c.f.h.loadDelivered(smbID).Members["share1_readers"]; !slices.Equal(got, []string{"alice"}) {
		t.Errorf("recorded members after the retry = %v", got)
	}
}
