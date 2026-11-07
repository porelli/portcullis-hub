package hub

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
)

// Task 32 (post-deploy fix): AI hooks that run right after a compose up
// wait for their service (runAIHookAfterUp); a switch-off's revoke_all
// runs before the recreate; credential records and connections-seen
// entries go with their credential or person.

// Every other test runs hooks right after an up once, as before: no wait
// and no retry (a test that fails a hook wants that failure at once). The
// tests below set the wait themselves (withReadyWait).
func init() {
	aiReadyWait = 0
}

// withReadyWait sets aiReadyWait and aiReadyPoll for one test.
func withReadyWait(t *testing.T, wait, poll time.Duration) {
	t.Helper()
	oldWait, oldPoll := aiReadyWait, aiReadyPoll
	aiReadyWait, aiReadyPoll = wait, poll
	t.Cleanup(func() { aiReadyWait, aiReadyPoll = oldWait, oldPoll })
}

// slowApp makes project's hook service slow to answer after every compose
// up, like the app in the live check: until readyAfter of the Hub's ready
// polls (aiReadyPoll sleeps on a fake clock) have passed, every AI hook
// fails to connect (logged "<cmd>:<action>:down") and — health — the
// container's healthcheck says starting; then it is healthy and answers.
type slowApp struct {
	mu         sync.Mutex
	armed      bool
	down       bool
	health     bool
	polls      int
	readyAfter int
}

func (s *slowApp) isDown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.down
}

func (a *instAIFixture) slowApp(t *testing.T, project, cid string, health bool, readyAfter int) *slowApp {
	t.Helper()
	s := &slowApp{health: health, readyAfter: readyAfter}
	setHealth := func(h string) {
		if s.health {
			a.engine.setState(cid, docker.State{Running: true, Health: h})
		}
	}
	up := a.runner.upHook
	a.runner.upHook = func(p string) {
		up(p)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.armed && p == project {
			s.down, s.polls = true, 0
			setHealth("starting")
		}
	}
	clk := &fakeClock{}
	clk.onSleep = func(d time.Duration) {
		if d != aiReadyPoll {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.polls++
		if s.down && s.polls >= s.readyAfter {
			s.down = false
			setHealth("healthy")
		}
	}
	a.h.sleep = clk.sleep
	a.engine.mu.Lock()
	next := a.engine.execSplit
	a.engine.mu.Unlock()
	a.engine.setExecSplit(func(id string, in docker.ExecInput) (*docker.ExecSplitResult, error) {
		if id == cid && s.isDown() {
			var act struct {
				Action string `json:"action"`
			}
			json.Unmarshal(in.Stdin, &act)
			a.seq.add(in.Cmd[0] + ":" + act.Action + ":down")
			return &docker.ExecSplitResult{ExecID: "x", ExitCode: 7, Stderr: []byte("curl: (7) Failed to connect to 127.0.0.1:3000 after 0 ms: Could not connect to server\n")}, nil
		}
		return next(id, in)
	})
	return s
}

func (s *slowApp) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

// since is the part of a.seq after n events.
func (a *instAIFixture) since(n int) []string {
	return a.seq.list()[n:]
}

func (a *instAIFixture) status(t *testing.T, id, companion string) CompanionView {
	t.Helper()
	v, err := a.h.InstanceAI(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Companions {
		if c.Name == companion {
			return c
		}
	}
	t.Fatalf("no companion %s/%s", id, companion)
	return CompanionView{}
}

func (a *instAIFixture) credRecord(t *testing.T, key string) (credUUID, bool) {
	t.Helper()
	rec, err := a.h.credUUIDs()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := rec[key]
	return r, ok
}

// The live check's bug: switching a companion off on a running instance
// recreates the app, which doesn't listen for a while. The revoke_all now
// runs before the recreate, while the app still runs as it was; the
// on_change after the up waits for the healthcheck instead of failing.
func TestSwitchOffRevokesBeforeRecreate(t *testing.T) {
	withReadyWait(t, 60*time.Second, 7*time.Millisecond)
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	a.putCred(t, "aiapp", "tok", "alice")
	app := a.slowApp(t, "portcullis-aiapp", "portcullis-aiapp-c", true, 3)
	app.arm()
	var atCommit []string
	a.h.testHookAIBeforeSave = func() { atCommit = slices.Clone(a.seq.list()) }
	n := len(a.seq.list())
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", false, root); err != nil {
		t.Fatalf("switch-off = %v", err)
	}
	want := []string{"/revoke:revoke_all", "up:portcullis-aiapp", "/toggle:on_change"}
	if got := a.since(n); !slices.Equal(got, want) {
		t.Errorf("sequence = %v, want %v (revoke_all before the recreate, on_change once the app is healthy)", got, want)
	}
	if !slices.Contains(atCommit[n:], "/revoke:revoke_all") {
		t.Errorf("revoke_all didn't run before the state save: %v", atCommit[n:])
	}
	if c := a.companion("aiapp", "tok"); c.Enabled || c.RevokePending || c.OnChangePending {
		t.Errorf("state = %+v", c)
	}
	if v := a.status(t, "aiapp", "tok"); v.Status != "off" || v.LastError != "" {
		t.Errorf("status = %q, last error %q", v.Status, v.LastError)
	}
	if left := a.credsOf("aiapp", "tok"); len(left) != 0 {
		t.Errorf("entries kept: %+v", left)
	}
	if _, ok := a.credRecord(t, "aiapp/tok/alice"); ok {
		t.Error("credential-uuids.json kept the revoked credential's record")
	}
	if op := a.h.LastOp("aiapp"); op == nil || op.Op != OpAI || !op.OK {
		t.Errorf("op = %+v", op)
	}
	if got := a.stdins("/toggle"); got[len(got)-1] != `{"action":"on_change","enabled":false,"mode":"read_write","companion":"tok"}` {
		t.Errorf("on_change = %v", got)
	}
}

// A switch-off whose revoke_all can't run before the save (the app is
// already down) still switches off and owes it (RevokePending at the
// commit, entries kept revoking: the gate ignores them); after the up it
// is retried only within aiReadyWait, then fails closed. The same request
// once the app answers runs it after the up (waiting for it) and clears
// everything.
func TestSwitchOffAppNeverReadyFailsClosed(t *testing.T) {
	withReadyWait(t, 60*time.Second, 7*time.Millisecond)
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	a.putCred(t, "aiapp", "tok", "alice")
	app := a.slowApp(t, "portcullis-aiapp", "portcullis-aiapp-c", true, 1<<30)
	app.arm()
	app.mu.Lock()
	app.down = true
	app.mu.Unlock()
	a.engine.setState("portcullis-aiapp-c", docker.State{Running: true, Health: "starting"})
	withReadyWait(t, 5*aiReadyPoll, aiReadyPoll)
	var atCommit []string
	a.h.testHookAIAfterSave = func() {
		atCommit = []string{}
		if c := a.companion("aiapp", "tok"); c.RevokePending {
			atCommit = append(atCommit, "revoke_pending")
		}
	}
	n := len(a.seq.list())
	err := a.h.SetAISupport(context.Background(), "aiapp", "tok", false, root)
	var oe *OpError
	if !errors.As(err, &oe) || !strings.Contains(err.Error(), "revoke_all failed") {
		t.Fatalf("switch-off = %v, want an OpError naming revoke_all", err)
	}
	a.h.testHookAIAfterSave = nil
	if !slices.Equal(atCommit, []string{"revoke_pending"}) {
		t.Errorf("not owed at the commit: %v", atCommit)
	}
	got := a.since(n)
	if len(got) == 0 || got[0] != "/revoke:revoke_all:down" {
		t.Errorf("no revoke_all before the save: %v", got)
	}
	if downs := len(slices.DeleteFunc(slices.Clone(got), func(e string) bool { return e != "/revoke:revoke_all:down" })); downs != 2 {
		t.Errorf("revoke_all ran %d times, want 2 (before the save, then once after the bounded wait): %v", downs, got)
	}
	if c := a.companion("aiapp", "tok"); c.Enabled || !c.RevokePending {
		t.Errorf("state = %+v, want off with revoke_all owed", c)
	}
	if c := a.credsOf("aiapp", "tok"); len(c) != 1 || c[0].State != aigate.StateRevoking {
		t.Errorf("entries = %+v, want kept revoking", c)
	}
	if _, ok := a.credRecord(t, "aiapp/tok/alice"); !ok {
		t.Error("the record of a credential not yet revoked was dropped")
	}
	if v := a.status(t, "aiapp", "tok"); v.Status != "failed" || !strings.Contains(v.LastError, "Failed to connect") {
		t.Errorf("status = %q, last error %q", v.Status, v.LastError)
	}
	if r := resourceByURL(a.gate(t), "https://aiapp.example.com/mcp"); r != nil {
		t.Error("the gate still lists the companion")
	}

	// The app answers again (2 polls after the next up): the same PUT.
	app.mu.Lock()
	app.readyAfter = 2
	app.mu.Unlock()
	withReadyWait(t, 60*time.Second, aiReadyPoll)
	n = len(a.seq.list())
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", false, root); err != nil {
		t.Fatalf("re-sent switch-off = %v", err)
	}
	if got := a.since(n); !slices.Equal(got, []string{"up:portcullis-aiapp", "/revoke:revoke_all", "/toggle:on_change"}) {
		t.Errorf("re-sent sequence = %v", got)
	}
	if c := a.companion("aiapp", "tok"); c.Enabled || c.RevokePending || c.OnChangePending {
		t.Errorf("state after the re-sent PUT = %+v", c)
	}
	if v := a.status(t, "aiapp", "tok"); v.Status != "off" || v.LastError != "" {
		t.Errorf("status = %q, last error %q", v.Status, v.LastError)
	}
	if left := a.credsOf("aiapp", "tok"); len(left) != 0 {
		t.Errorf("entries kept: %+v", left)
	}
	if _, ok := a.credRecord(t, "aiapp/tok/alice"); ok {
		t.Error("credential-uuids.json kept the revoked credential's record")
	}
}

// app_oauth: the app grants its own tokens while it runs with the
// companion on, so its revoke_all stays after the up; it waits for the
// recreated app's healthcheck instead of failing.
func TestAppOAuthSwitchOffWaitsForApp(t *testing.T) {
	withReadyWait(t, 60*time.Second, 7*time.Millisecond)
	a := newInstAIFixture(t, nil)
	a.enable(t, "oauthapp")
	a.engine.mu.Lock()
	a.engine.containers = append(a.engine.containers, container("oauthapp-web", "portcullis-oauthapp", "web", "running"))
	a.engine.mu.Unlock()
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", true, root); err != nil {
		t.Fatal(err)
	}
	app := a.slowApp(t, "portcullis-oauthapp", "oauthapp-web", true, 4)
	app.arm()
	n := len(a.seq.list())
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", false, root); err != nil {
		t.Fatalf("switch-off = %v", err)
	}
	if got := a.since(n); !slices.Equal(got, []string{"up:portcullis-oauthapp", "/revoke:revoke_all", "/toggle:on_change"}) {
		t.Errorf("sequence = %v (the hooks wait for the healthy app, revoke_all after the up)", got)
	}
	if c := a.companion("oauthapp", "oauth"); c.Enabled || c.RevokePending || c.OnChangePending {
		t.Errorf("state = %+v", c)
	}
	if v := a.status(t, "oauthapp", "oauth"); v.Status != "off" || v.LastError != "" {
		t.Errorf("status = %q, last error %q", v.Status, v.LastError)
	}
}

// The hooks a start owes (switched off while stopped) run right after its
// up; a service without a healthcheck gets a bounded retry until it
// answers.
func TestOwedHooksAtStartWaitForApp(t *testing.T) {
	withReadyWait(t, 60*time.Second, 7*time.Millisecond)
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	if err := a.h.Disable("aiapp"); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", false, root); err != nil {
		t.Fatal(err)
	}
	if c := a.companion("aiapp", "tok"); !c.RevokePending || !c.OnChangePending {
		t.Fatalf("state = %+v, want both owed", c)
	}
	app := a.slowApp(t, "portcullis-aiapp", "portcullis-aiapp-c", false, 2)
	app.arm()
	n := len(a.seq.list())
	a.enable(t, "aiapp")
	want := []string{"up:portcullis-aiapp", "/revoke:revoke_all:down", "/revoke:revoke_all:down", "/revoke:revoke_all", "/toggle:on_change"}
	if got := a.since(n); !slices.Equal(got, want) {
		t.Errorf("sequence = %v, want %v", got, want)
	}
	if c := a.companion("aiapp", "tok"); c.RevokePending || c.OnChangePending {
		t.Errorf("flags kept: %+v", c)
	}
	if v := a.status(t, "aiapp", "tok"); v.Status != "off" || v.LastError != "" {
		t.Errorf("status = %q, last error %q", v.Status, v.LastError)
	}
}

// A switch-on's revoke_all runs before the up on the app as it runs (no
// wait); its on_change after the up waits for the healthy app.
func TestSwitchOnOnChangeWaitsForApp(t *testing.T) {
	withReadyWait(t, 60*time.Second, 7*time.Millisecond)
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	app := a.slowApp(t, "portcullis-aiapp", "portcullis-aiapp-c", true, 3)
	app.arm()
	n := len(a.seq.list())
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatalf("switch-on = %v", err)
	}
	if got := a.since(n); !slices.Equal(got, []string{"/revoke:revoke_all", "up:portcullis-aiapp", "/toggle:on_change"}) {
		t.Errorf("sequence = %v", got)
	}
	if v := a.status(t, "aiapp", "tok"); v.Status != "on" || v.LastError != "" {
		t.Errorf("status = %q, last error %q", v.Status, v.LastError)
	}
	// A mode change: revoke_all first again, on_change after the up waits.
	n = len(a.seq.list())
	if err := a.h.SetAIMode(context.Background(), "aiapp", "tok", "read_only", root); err != nil {
		t.Fatalf("mode change = %v", err)
	}
	if got := a.since(n); !slices.Equal(got, []string{"/revoke:revoke_all", "up:portcullis-aiapp", "/toggle:on_change"}) {
		t.Errorf("mode change sequence = %v", got)
	}
}

// Concern 2: a revoked credential's record goes with it, and a delete
// drops the instance's records (and any an earlier revoke left).
func TestCredUUIDRecordsPruned(t *testing.T) {
	a := newMintFixture(t)
	a.putCred(t, "aiapp", "tok", "alice")
	if _, ok := a.credRecord(t, "aiapp/tok/alice"); !ok {
		t.Fatal("no record after the mint")
	}
	if err := a.h.RevokeAICredentials(context.Background(), "aiapp", "tok", "alice", root); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.credRecord(t, "aiapp/tok/alice"); ok {
		t.Error("record kept after the revoke")
	}
	// A record whose entry went without a prune (as the live check's
	// leftover), and a live entry of the instance.
	a.putCred(t, "aiapp", "tok", "alice")
	if err := a.h.recordCredUUID(aigate.Credential{Instance: "aiapp", Companion: "tok", User: "carol", ID: "9"}, "uuid-carol"); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.credRecord(t, "aiapp/tok/carol"); !ok {
		t.Fatal("setup: no stale record")
	}
	if _, err := a.h.DeleteInstance("aiapp", "aiapp", root); err != nil {
		t.Fatal(err)
	}
	rec, err := a.h.credUUIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec) != 0 {
		t.Errorf("records left after the delete: %v", rec)
	}
}

// Concern 2: a person deleted through the Hub while the master switch is
// off (the reconcile keeps connections then) has their AI connections
// removed and leaves connections-seen.json; a failure keeps them there.
func TestDeletedPersonLeavesConnectionsSeen(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.reconcile() // records everyone who can use the people MCP
	seen := func() []string {
		t.Helper()
		f := connSeenFile{}
		aiStoreMu.Lock()
		err := a.h.readAIStore(connSeenName, &f)
		aiStoreMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		return f.People
	}
	if !slices.Contains(seen(), "carol") || !slices.Contains(seen(), "alice") {
		t.Fatalf("setup: seen = %v", seen())
	}
	if err := a.h.SaveAISettings(AISettingsUpdate{Enabled: ptr(false)}, root); err != nil {
		t.Fatal(err)
	}
	a.people.set(func(p *fakePeople) {
		delete(p.users, "carol")
		for _, ms := range p.members {
			delete(ms, "carol")
		}
	})
	// A Keycloak failure keeps carol recorded.
	a.kc.mu.Lock()
	a.kc.revokeErr = errors.New("keycloak 500")
	a.kc.mu.Unlock()
	if w := a.h.PersonDeleted(context.Background(), root, "Carol"); len(w) != 1 || !strings.Contains(w[0], "keycloak 500") {
		t.Errorf("warnings = %v", w)
	}
	if !slices.Contains(seen(), "carol") {
		t.Error("carol dropped although removing her connections failed")
	}
	a.kc.mu.Lock()
	a.kc.revokeErr = nil
	a.kc.revoked = nil
	a.kc.mu.Unlock()
	if w := a.h.PersonDeleted(context.Background(), root, "carol"); len(w) != 0 {
		t.Errorf("warnings = %v", w)
	}
	want := []string{"carol@" + keycloak.AIClientIDs.Claude, "carol@" + keycloak.AIClientIDs.ClaudeCode, "carol@" + keycloak.AIClientIDs.Generic}
	if got := a.kc.revokedList(); !slices.Equal(got, want) {
		t.Errorf("revoked = %v, want %v", got, want)
	}
	if got := seen(); slices.Contains(got, "carol") || !slices.Contains(got, "alice") {
		t.Errorf("seen = %v, want carol dropped, alice kept", got)
	}
	// Someone never recorded: no Keycloak call.
	a.kc.mu.Lock()
	a.kc.revoked = nil
	a.kc.mu.Unlock()
	if w := a.h.PersonDeleted(context.Background(), root, "dave"); len(w) != 0 {
		t.Errorf("warnings = %v", w)
	}
	if got := a.kc.revokedList(); len(got) != 0 {
		t.Errorf("revoked for a person never recorded: %v", got)
	}
}
