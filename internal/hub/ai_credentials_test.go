package hub

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/state"
)

// Plan 4 Task 13a fix round 1: MintCredential's locking and its revoking
// entries (the HTTP side is internal/httpapi/internal_api_test.go).

const tokResource = "https://aiapp.example.com/mcp"

// newMintFixture: aiapp enabled with tok on read_write; the mint hook
// answers {"credential":"c-<user>","id":"id-<user>"} unless hookFail says
// otherwise.
func newMintFixture(t *testing.T) *instAIFixture {
	t.Helper()
	a := newInstAIFixture(t, func(st *state.AppState) {
		st.AIInstances = map[string]state.AIInstance{"aiapp": {Companions: map[string]state.AICompanion{"tok": {Enabled: true, Mode: "read_write"}}}}
	})
	a.h.lockPoll = 5 * time.Millisecond
	a.enable(t, "aiapp")
	a.setMintAnswer(nil)
	return a
}

// setMintAnswer replaces the engine's AI hooks: gate (if set) holds every
// /mint run until closed; /mint answers per user; anything in hookFail
// answers as scripted.
func (a *instAIFixture) setMintAnswer(gate chan struct{}) {
	a.engine.setExecSplit(func(cid string, in docker.ExecInput) (*docker.ExecSplitResult, error) {
		var v struct{ Action, User string }
		json.Unmarshal(in.Stdin, &v)
		a.seq.add(in.Cmd[0] + ":" + v.Action)
		a.mu.Lock()
		r, scripted := a.hookFail[in.Cmd[0]]
		a.mu.Unlock()
		if in.Cmd[0] == "/mint" && gate != nil {
			<-gate
		}
		if scripted {
			r.Stdout, r.Stderr = slices.Clone(r.Stdout), slices.Clone(r.Stderr)
			return &r, nil
		}
		if in.Cmd[0] == "/mint" {
			return &docker.ExecSplitResult{ExecID: "x", Stdout: []byte(`{"credential":"c-` + v.User + `","id":"id-` + v.User + `"}`)}, nil
		}
		return &docker.ExecSplitResult{ExecID: "x"}, nil
	})
}

// TestMintRechecksAfterLock: a mint that waited for the AI lock re-reads
// the directory: alice removed meanwhile → 403, no hook.
func TestMintRechecksAfterLock(t *testing.T) {
	a := newMintFixture(t)
	unlock := a.h.aiLock("aiapp")
	done := make(chan error, 1)
	go func() {
		_, err := a.h.MintCredential(context.Background(), tokResource, "alice")
		done <- err
	}()
	time.Sleep(300 * time.Millisecond) // past the first check, waiting for the lock
	a.people.removeMember("users_aiapp", "alice")
	unlock()
	if err := <-done; statusOf(err) != 403 {
		t.Fatalf("mint after removal = %v, want 403", err)
	}
	if n := len(a.stdins("/mint")); n != 0 {
		t.Errorf("mint hook ran %d times", n)
	}
	if len(a.credsOf("aiapp", "tok")) != 0 {
		t.Error("an entry was written")
	}
}

// TestMintRevokesRevokingEntryFirst: a revoking entry is never
// overwritten: its id is revoked first ({"action":"revoke","user",
// "ids":[old]}); a failure keeps it and answers 502 without minting; a
// success removes it, then mints.
func TestMintRevokesRevokingEntryFirst(t *testing.T) {
	a := newMintFixture(t)
	a.putCred(t, "aiapp", "tok", "alice") // id 7
	if err := a.h.creds().MarkRevoking("aiapp", "tok", "alice"); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.hookFail["/revoke"] = docker.ExecSplitResult{ExitCode: 1, Stderr: []byte("app unreachable")}
	a.mu.Unlock()
	if _, err := a.h.MintCredential(context.Background(), tokResource, "alice"); statusOf(err) != 502 {
		t.Fatalf("mint with a failing revoke = %v, want 502", err)
	}
	if got := a.stdins("/revoke"); len(got) != 1 || got[0] != `{"action":"revoke","user":"alice","ids":["7"]}` {
		t.Errorf("revoke stdin = %q", got)
	}
	if n := len(a.stdins("/mint")); n != 0 {
		t.Errorf("minted over a revoking entry (%d runs)", n)
	}
	if c := a.credsOf("aiapp", "tok"); len(c) != 1 || c[0].State != aigate.StateRevoking || c[0].ID != "7" {
		t.Errorf("entry = %+v, want 7 still revoking", c)
	}
	v, _ := a.h.InstanceAI("aiapp")
	if !strings.Contains(v.Companions[0].LastError, "app unreachable") {
		t.Errorf("LastError = %q", v.Companions[0].LastError)
	}
	// The revoke now works: removed, then minted.
	a.mu.Lock()
	delete(a.hookFail, "/revoke")
	a.mu.Unlock()
	res, err := a.h.MintCredential(context.Background(), tokResource, "alice")
	if err != nil || res.ID != "id-alice" {
		t.Fatalf("mint = %+v, %v", res, err)
	}
	if c := a.credsOf("aiapp", "tok"); len(c) != 1 || c[0].State != aigate.StateActive || c[0].ID != "id-alice" {
		t.Errorf("entry = %+v", c)
	}
	seq := strings.Join(a.seq.list(), " ")
	if i, j := strings.LastIndex(seq, "/revoke:revoke"), strings.Index(seq, "/mint:mint"); i < 0 || j < 0 || i > j {
		t.Errorf("order = %s, want the revoke before the mint", seq)
	}
	var ok, failed int
	for _, e := range a.audits("ai.credential.revoke") {
		if e.Target == "aiapp/tok/alice" && e.Detail == "id 7" {
			switch e.Result {
			case "ok":
				ok++
			case "error":
				failed++
			}
		}
	}
	if ok != 1 || failed != 1 {
		t.Errorf("revoke audits: %d ok, %d error", ok, failed)
	}
	if v, _ := a.h.InstanceAI("aiapp"); v.Companions[0].LastError != "" {
		t.Errorf("LastError after success = %q", v.Companions[0].LastError)
	}
}

// TestMintRacingDelete: a delete waits for a mint holding the AI lock,
// then drops its entry; a mint queued meanwhile either runs before the
// delete (dropped with it) or is 404; a mint after it is 404. No entry of
// the deleted instance is left.
func TestMintRacingDelete(t *testing.T) {
	a := newMintFixture(t)
	gate := make(chan struct{})
	a.setMintAnswer(gate)
	minted := make(chan error, 1)
	go func() {
		_, err := a.h.MintCredential(context.Background(), tokResource, "alice")
		minted <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for len(a.stdins("/mint")) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	deleted := make(chan error, 1)
	go func() {
		_, err := a.h.DeleteInstance("aiapp", "aiapp", root)
		deleted <- err
	}()
	time.Sleep(300 * time.Millisecond) // the delete waits for the AI lock
	// A second person's mint queued behind the delete.
	a.people.addGroup("users_aiapp", "alice", "carol")
	late := make(chan error, 1)
	go func() {
		_, err := a.h.MintCredential(context.Background(), tokResource, "carol")
		late <- err
	}()
	time.Sleep(100 * time.Millisecond)
	close(gate)
	if err := <-minted; err != nil {
		t.Fatalf("the mint holding the lock = %v", err)
	}
	if err := <-deleted; err != nil {
		t.Fatalf("delete = %v", err)
	}
	// carol's mint either got the lock before the delete (then the
	// delete drops her entry too) or after it (404: deleting, then gone).
	if err := <-late; err != nil && statusOf(err) != 404 {
		t.Errorf("mint during the delete = %v, want ok or 404", err)
	}
	for _, e := range a.h.creds().Entries() {
		if e.Instance == "aiapp" {
			t.Errorf("entry of the deleted instance left: %+v", e)
		}
	}
	if _, err := a.h.MintCredential(context.Background(), tokResource, "alice"); statusOf(err) != 404 {
		t.Errorf("mint after the delete = %v, want 404", err)
	}
}

// TestMintRecoversPanic: a panic inside a flight is a 500 "mint:
// internal error" (never its value), not a crash.
func TestMintRecoversPanic(t *testing.T) {
	a := newMintFixture(t)
	a.engine.setExecSplit(func(string, docker.ExecInput) (*docker.ExecSplitResult, error) {
		panic("secret-panic-value")
	})
	_, err := a.h.MintCredential(context.Background(), tokResource, "alice")
	if statusOf(err) != 500 || err.Error() != "mint: internal error" {
		t.Fatalf("panicking mint = %v", err)
	}
}

// TestRestoreRunsOwedAIHooksUnderItsLock: a restore holds the AI lock
// (lockApp → aiLock) for its whole run; its own start runs the owed
// revoke_all at once instead of waiting aiPendingWait for that lock.
func TestRestoreRunsOwedAIHooksUnderItsLock(t *testing.T) {
	a := newMintFixture(t)
	entry, err := a.h.BackupInstance("aiapp", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.h.setAIPending("aiapp", "tok", pendRevoke, true); err != nil {
		t.Fatal(err)
	}
	old := aiPendingWait
	aiPendingWait = 3 * time.Second
	t.Cleanup(func() { aiPendingWait = old })
	n := len(a.stdins("/revoke"))
	start := time.Now()
	if _, err := a.h.RestoreInstance("aiapp", entry.Archive, root); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d >= aiPendingWait {
		t.Errorf("restore took %s: its start waited for the AI lock it holds", d)
	}
	got := a.stdins("/revoke")[n:]
	if len(got) == 0 || !strings.Contains(got[0], `"revoke_all"`) {
		t.Errorf("revoke hook runs after the restore = %q, want the owed revoke_all", got)
	}
	if v, _ := a.h.InstanceAI("aiapp"); strings.Contains(v.Companions[0].LastError, "AI lock was busy") {
		t.Errorf("LastError = %q", v.Companions[0].LastError)
	}
}
