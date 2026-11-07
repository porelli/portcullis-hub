package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
)

// Plan 4 Task 13b: revocation on leave, the reconcile, app_oauth leavers,
// AI connections and the access-log reader.

// ── fakeAIKC as the AIConnector ───────────────────────────

func (k *fakeAIKC) AIConnections(ctx context.Context, username string, clients []string) ([]keycloak.AIConnection, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.connErr != nil {
		return nil, k.connErr
	}
	var out []keycloak.AIConnection
	for _, c := range k.conns[username] {
		if slices.Contains(clients, c.Client) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (k *fakeAIKC) RevokeAIConnection(ctx context.Context, username, clientID string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.revoked = append(k.revoked, username+"@"+clientID)
	if k.revokeErr != nil {
		return k.revokeErr
	}
	k.conns[username] = slices.DeleteFunc(k.conns[username], func(c keycloak.AIConnection) bool { return c.Client == clientID })
	return nil
}

func (k *fakeAIKC) revokedList() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.revoked)
}

func (a *instAIFixture) reconcile() {
	a.h.ReconcileAICredentials(context.Background())
}

func (a *instAIFixture) auditsOf(action, target string) []directory.AuditEntry {
	var out []directory.AuditEntry
	for _, e := range a.audits(action) {
		if e.Target == target {
			out = append(out, e)
		}
	}
	return out
}

// credFileEntry reads mcp-credentials.json from disk (what the gate sees).
func (a *instAIFixture) credFileEntry(t *testing.T, id, comp, user string) *aigate.Credential {
	t.Helper()
	b, err := os.ReadFile(a.h.credsPath())
	if err != nil {
		t.Fatal(err)
	}
	f, err := aigate.DecodeCredFile(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Credentials {
		if c.Instance == id && c.Companion == comp && c.User == user {
			return &c
		}
	}
	return nil
}

// TestLeaverCredentialRevoked (Review Focus 1): alice leaves the access
// group → the pass after WritePolicy marks her entry revoking (the gate
// file no longer lists her and the credentials file drops the
// ciphertext), then runs revoke with her id; a failing hook keeps the
// entry revoking (retried every reconcile, shown on the AI tab, never
// audited as done); a later success removes it. Others are untouched.
func TestLeaverCredentialRevoked(t *testing.T) {
	a := newMintFixture(t)
	a.people.addGroup("users_aiapp", "carol")
	a.putCred(t, "aiapp", "tok", "alice") // id 7
	a.putCred(t, "aiapp", "tok", "carol")
	a.failHook("/revoke", 1, "app says no")

	a.people.removeMember("users_aiapp", "alice")
	if err := a.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	for _, r := range a.gate(t).Resources {
		if r.Companion == "tok" && slices.Contains(r.Population, "alice") {
			t.Fatal("the gate file still lists alice")
		}
	}
	a.reconcile()
	if got := a.stdins("/revoke"); len(got) != 1 || got[0] != `{"action":"revoke","user":"alice","ids":["7"]}` {
		t.Fatalf("revoke stdin = %q", got)
	}
	e := a.credFileEntry(t, "aiapp", "tok", "alice")
	if e == nil || e.State != aigate.StateRevoking || e.Age != "" {
		t.Fatalf("alice's entry on disk = %+v, want revoking without ciphertext", e)
	}
	if c := a.credFileEntry(t, "aiapp", "tok", "carol"); c == nil || c.State != aigate.StateActive {
		t.Errorf("carol's entry = %+v, want active", c)
	}
	v, _ := a.h.InstanceAI("aiapp")
	cv := v.Companions[slices.IndexFunc(v.Companions, func(c CompanionView) bool { return c.Name == "tok" })]
	if cv.Status != "failed" || !strings.Contains(cv.LastError, "app says no") || cv.Revoking != 1 || cv.Credentials != 1 {
		t.Errorf("AI tab = status %q, last error %q, revoking %d, credentials %d", cv.Status, cv.LastError, cv.Revoking, cv.Credentials)
	}
	if got := a.auditsOf("ai.credential.revoke", "aiapp/tok/alice"); len(got) != 1 || got[0].Result != "error" || got[0].Detail != "id 7" {
		t.Errorf("audits = %+v, want one error", got)
	}
	// Retried at every reconcile; the same failure isn't audited again
	// and is never reported as done.
	a.reconcile()
	if n := len(a.stdins("/revoke")); n != 2 {
		t.Errorf("revoke runs after the second pass = %d, want 2", n)
	}
	if got := a.auditsOf("ai.credential.revoke", "aiapp/tok/alice"); len(got) != 1 {
		t.Errorf("audits after the retry = %+v", got)
	}
	// A mint for her is refused (she left), and the entry stays.
	if _, err := a.h.MintCredential(context.Background(), tokResource, "alice"); statusOf(err) != http.StatusForbidden {
		t.Errorf("mint after leaving = %v, want 403", err)
	}
	// The app is back: removed, audited ok, last error cleared.
	a.failHook("/revoke", 0, "")
	a.reconcile()
	if e := a.credFileEntry(t, "aiapp", "tok", "alice"); e != nil {
		t.Errorf("alice's entry after a successful revoke = %+v", e)
	}
	got := a.auditsOf("ai.credential.revoke", "aiapp/tok/alice")
	if len(got) != 2 || got[1].Result != "ok" || got[1].Detail != "id 7" || got[1].Actor != "hub" {
		t.Errorf("audits = %+v, want error then ok by hub", got)
	}
	if v, _ := a.h.InstanceAI("aiapp"); v.Companions[0].LastError != "" {
		t.Errorf("LastError after success = %q", v.Companions[0].LastError)
	}
	// Nothing more to do: no further hook run.
	n := len(a.stdins("/revoke"))
	a.reconcile()
	if len(a.stdins("/revoke")) != n {
		t.Error("a pass with nothing owed ran the revoke hook")
	}
	if c := a.credFileEntry(t, "aiapp", "tok", "carol"); c == nil || c.State != aigate.StateActive {
		t.Errorf("carol's entry = %+v, want active", c)
	}
}

// A disabled instance is a leave for everyone; the directory down or the
// master switch off judges nobody (revoking entries are still retried).
func TestLeaverJudgement(t *testing.T) {
	a := newMintFixture(t)
	a.putCred(t, "aiapp", "tok", "alice")
	a.people.set(func(p *fakePeople) { p.err = errors.New("directory down") })
	a.reconcile()
	if n := len(a.stdins("/revoke")); n != 0 {
		t.Fatalf("directory down: %d revoke runs", n)
	}
	a.people.set(func(p *fakePeople) { p.err = nil })
	a.h.mu.Lock()
	a.h.st.AI.Enabled = false
	a.h.mu.Unlock()
	a.reconcile()
	if n := len(a.stdins("/revoke")); n != 0 {
		t.Fatalf("master off: %d revoke runs", n)
	}
	a.h.mu.Lock()
	a.h.st.AI.Enabled = true
	a.h.mu.Unlock()
	a.reconcile()
	if n := len(a.stdins("/revoke")); n != 0 {
		t.Fatalf("alice in the population: %d revoke runs", n)
	}
	// Disabled: her entry is revoked (the hook needs a running container:
	// it fails and stays revoking until the app runs again).
	if err := a.h.Disable("aiapp"); err != nil {
		t.Fatal(err)
	}
	a.engine.mu.Lock()
	a.engine.containers = nil
	a.engine.mu.Unlock()
	a.reconcile()
	if e := a.credFileEntry(t, "aiapp", "tok", "alice"); e == nil || e.State != aigate.StateRevoking {
		t.Errorf("entry of a disabled instance = %+v, want revoking", e)
	}
}

// RevokeAICredentials: one person (revoke with the id) or everyone
// (revoke_all), audited; the AI lock only.
func TestRevokeAICredentials(t *testing.T) {
	a := newMintFixture(t)
	a.putCred(t, "aiapp", "tok", "alice")
	if err := a.h.RevokeAICredentials(context.Background(), "aiapp", "tok", "alice", root); err != nil {
		t.Fatal(err)
	}
	if got := a.stdins("/revoke"); len(got) != 1 || got[0] != `{"action":"revoke","user":"alice","ids":["7"]}` {
		t.Errorf("stdin = %q", got)
	}
	if len(a.credsOf("aiapp", "tok")) != 0 {
		t.Error("entry left")
	}
	a.putCred(t, "aiapp", "tok", "alice")
	if err := a.h.RevokeAICredentials(context.Background(), "aiapp", "tok", "", root); err != nil {
		t.Fatal(err)
	}
	if got := a.stdins("/revoke"); len(got) != 2 || got[1] != `{"action":"revoke_all","prefix":"portcullis-ai-"}` {
		t.Errorf("stdin = %q", got)
	}
	if got := a.auditsOf("ai.credential.revoke", "aiapp/tok"); len(got) != 1 || got[0].Detail != "revoke_all" || got[0].Actor != "root" {
		t.Errorf("audit = %+v", got)
	}
	// A failure keeps the entry revoking and is a 502.
	a.putCred(t, "aiapp", "tok", "alice")
	a.failHook("/revoke", 1, "nope")
	if err := a.h.RevokeAICredentials(context.Background(), "aiapp", "tok", "alice", root); statusOf(err) != 502 {
		t.Errorf("failing revoke = %v, want 502", err)
	}
	if c := a.credsOf("aiapp", "tok"); len(c) != 1 || c[0].State != aigate.StateRevoking {
		t.Errorf("entry = %+v", c)
	}
	// identity_headers holds nothing (409); unknown companion 404; a held
	// AI lock is a 503 after the budget, never lockApp.
	if err := a.h.RevokeAICredentials(context.Background(), "aiapp", "hdr", "", root); statusOf(err) != 409 {
		t.Errorf("hdr = %v", err)
	}
	if err := a.h.RevokeAICredentials(context.Background(), "aiapp", "nope", "", root); statusOf(err) != 404 {
		t.Errorf("unknown = %v", err)
	}
	old := aiRevokeLockWait
	aiRevokeLockWait = 50 * time.Millisecond
	t.Cleanup(func() { aiRevokeLockWait = old })
	unlock := a.h.aiLock("aiapp")
	err := a.h.RevokeAICredentials(context.Background(), "aiapp", "tok", "", root)
	unlock()
	if statusOf(err) != 503 {
		t.Errorf("revoke with the AI lock held = %v, want 503", err)
	}
	appUnlock, err := a.h.lockApp("aiapp")
	if err != nil {
		t.Fatal(err)
	}
	a.failHook("/revoke", 0, "")
	err = a.h.RevokeAICredentials(context.Background(), "aiapp", "tok", "", root)
	appUnlock()
	if err != nil {
		t.Errorf("revoke while lockApp is held (a backup) = %v, want ok", err)
	}
}

// TestAppOAuthLeaverRevoked: an app_oauth companion: bob in the
// population is recorded in oauth-seen.json; bob leaves → revoke {user
// bob, ids []}; success removes him; switching the companion off runs
// revoke for everyone recorded.
func TestAppOAuthLeaverRevoked(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.h.lockPoll = 5 * time.Millisecond
	oauthWeb(a)
	a.people.addGroup("users_oauthapp", "bob", "dave")
	// The oauth fixture has no access group: its population is everyone.
	a.enable(t, "oauthapp")
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", true, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	a.reconcile()
	seen, err := a.h.oauthSeen()
	if err != nil {
		t.Fatal(err)
	}
	if got := seen["oauthapp/oauth"]; !slices.Equal(got, []string{"admin", "alice", "bob", "carol", "dave", "root"}) {
		t.Fatalf("oauth-seen = %v", got)
	}
	st, err := os.Stat(filepath.Join(a.h.cfg.DataDir, "ai", "oauth-seen.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("oauth-seen.json mode = %v (%v)", st, err)
	}
	n := len(a.stdins("/revoke"))
	a.people.set(func(p *fakePeople) { // bob is deleted
		delete(p.users, "bob")
		for _, ms := range p.members {
			delete(ms, "bob")
		}
	})
	a.failHook("/revoke", 1, "ha down")
	a.reconcile()
	got := a.stdins("/revoke")[n:]
	if len(got) != 1 || got[0] != `{"action":"revoke","user":"bob","sub":"`+fakeSub("bob")+`","ids":[]}` {
		t.Fatalf("revoke stdin = %q", got)
	}
	if seen, _ := a.h.oauthSeen(); !slices.Contains(seen["oauthapp/oauth"], "bob") {
		t.Error("bob dropped after a failed revoke")
	}
	a.failHook("/revoke", 0, "")
	a.reconcile()
	if seen, _ := a.h.oauthSeen(); !slices.Equal(seen["oauthapp/oauth"], []string{"admin", "alice", "carol", "dave", "root"}) {
		t.Errorf("oauth-seen after bob's revoke = %v", seen["oauthapp/oauth"])
	}
	if got := a.auditsOf("ai.credential.revoke", "oauthapp/oauth/bob"); len(got) != 2 || got[1].Result != "ok" || got[1].Detail != "ids []" {
		t.Errorf("audits = %+v", got)
	}
	// Switched off: everyone recorded is revoked (the switch-off's
	// revoke_all; and once the record was rebuilt, per person).
	n = len(a.stdins("/revoke"))
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", false, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	a.reconcile()
	off := strings.Join(a.stdins("/revoke")[n:], "\n")
	if !strings.Contains(off, `"revoke_all"`) {
		t.Errorf("switch-off runs = %q, want revoke_all", off)
	}
	if seen, _ := a.h.oauthSeen(); len(seen["oauthapp/oauth"]) != 0 {
		t.Errorf("oauth-seen after the switch-off = %v", seen)
	}
	// Recorded people of a companion that is off are revoked one by one
	// (a record left by a failed switch-off revoke_all).
	if err := a.h.oauthSeenUpdate(func(s map[string][]string) bool {
		s["oauthapp/oauth"] = []string{"alice", "dave"}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	n = len(a.stdins("/revoke"))
	a.reconcile()
	got = a.stdins("/revoke")[n:]
	if !slices.Equal(got, []string{`{"action":"revoke","user":"alice","sub":"` + fakeSub("alice") + `","ids":[]}`,
		`{"action":"revoke","user":"dave","sub":"` + fakeSub("dave") + `","ids":[]}`}) {
		t.Errorf("revokes for a companion that is off = %q", got)
	}
	if seen, _ := a.h.oauthSeen(); len(seen) != 0 {
		t.Errorf("oauth-seen = %v", seen)
	}
}

// TestAppOAuthRevokeSub (T27, contract §15.5): recording a person
// stores their Keycloak id; a leaver gone from LLDAP and Keycloak is
// revoked with the stored id; with none stored and the lookup failing
// nothing runs and the person stays recorded (retried), then a working
// lookup revokes them.
func TestAppOAuthRevokeSub(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.h.lockPoll = 5 * time.Millisecond
	oauthWeb(a)
	a.people.addGroup("users_oauthapp", "bob", "dave")
	a.enable(t, "oauthapp")
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", true, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	a.reconcile()
	aiStoreMu.Lock()
	f, err := a.h.oauthSeenFileLocked()
	aiStoreMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob", "carol"} {
		if got := f.Subs["oauthapp/oauth"][u]; got != fakeSub(u) {
			t.Errorf("stored sub of %s = %q, want %q", u, got, fakeSub(u))
		}
	}
	// bob leaves LLDAP and Keycloak: the stored id is used.
	a.kc.mu.Lock()
	a.kc.gone = map[string]bool{"bob": true}
	a.kc.mu.Unlock()
	a.people.set(func(p *fakePeople) {
		delete(p.users, "bob")
		for _, ms := range p.members {
			delete(ms, "bob")
		}
	})
	n := len(a.stdins("/revoke"))
	a.reconcile()
	got := a.stdins("/revoke")[n:]
	if len(got) != 1 || got[0] != `{"action":"revoke","user":"bob","sub":"`+fakeSub("bob")+`","ids":[]}` {
		t.Fatalf("revoke stdin of a deleted person = %q", got)
	}
	if seen, _ := a.h.oauthSeen(); slices.Contains(seen["oauthapp/oauth"], "bob") {
		t.Error("bob still recorded after his revoke")
	}
	aiStoreMu.Lock()
	f, _ = a.h.oauthSeenFileLocked()
	aiStoreMu.Unlock()
	if _, ok := f.Subs["oauthapp/oauth"]["bob"]; ok {
		t.Error("bob's id kept after his record went")
	}
	// No id stored and the lookup failing: no hook run, kept, retried.
	if err := a.h.oauthSeenUpdate(func(s map[string][]string) bool {
		s["oauthapp/oauth"] = append(s["oauthapp/oauth"], "erin")
		return true
	}); err != nil {
		t.Fatal(err)
	}
	a.kc.mu.Lock()
	a.kc.subErr = errors.New("keycloak down")
	a.kc.mu.Unlock()
	n = len(a.stdins("/revoke"))
	a.reconcile()
	if got := a.stdins("/revoke")[n:]; len(got) != 0 {
		t.Fatalf("a revoke ran without a sub: %q", got)
	}
	if seen, _ := a.h.oauthSeen(); !slices.Contains(seen["oauthapp/oauth"], "erin") {
		t.Fatal("erin dropped although her revoke never ran")
	}
	if au := a.auditsOf("ai.credential.revoke", "oauthapp/oauth/erin"); len(au) != 1 || au[0].Result == "ok" {
		t.Errorf("audits = %+v", au)
	}
	a.kc.mu.Lock()
	a.kc.subErr = nil
	a.kc.mu.Unlock()
	n = len(a.stdins("/revoke"))
	a.reconcile()
	got = a.stdins("/revoke")[n:]
	if len(got) != 1 || got[0] != `{"action":"revoke","user":"erin","sub":"`+fakeSub("erin")+`","ids":[]}` {
		t.Fatalf("retry stdin = %q", got)
	}
	if seen, _ := a.h.oauthSeen(); slices.Contains(seen["oauthapp/oauth"], "erin") {
		t.Error("erin still recorded after her revoke")
	}
}

// TestConnectionsCleanupWhenNoAIResource: a deleted user, or one in no AI
// population (people MCP off, no companion) → RevokeAIConnection for
// every AI client; a failure is retried; others untouched.
func TestConnectionsCleanupWhenNoAIResource(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.kc.conns = map[string][]keycloak.AIConnection{}
	all := []string{keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.ClaudeCode, keycloak.AIClientIDs.Generic}
	a.reconcile() // records everyone who can use the people MCP
	if got := a.kc.revokedList(); len(got) != 0 {
		t.Fatalf("revoked on the first pass: %v", got)
	}
	// carol is deleted.
	a.people.set(func(p *fakePeople) {
		delete(p.users, "carol")
		for _, ms := range p.members {
			delete(ms, "carol")
		}
	})
	a.reconcile()
	want := []string{}
	for _, c := range all {
		want = append(want, "carol@"+c)
	}
	if got := a.kc.revokedList(); !slices.Equal(got, want) {
		t.Fatalf("revoked = %v, want %v", got, want)
	}
	if got := a.auditsOf("ai.connection.revoke", "carol"); len(got) != 1 || got[0].Result != "ok" {
		t.Errorf("audit = %+v", got)
	}
	a.reconcile()
	if got := a.kc.revokedList(); len(got) != len(want) {
		t.Errorf("carol revoked again: %v", got)
	}
	// People MCP and admin MCP off, no companion on: nobody has an AI
	// resource; a failure keeps them for the next pass.
	a.h.mu.Lock()
	a.h.st.AI.PortcullisPeople, a.h.st.AI.PortcullisAdmin = false, false
	a.h.mu.Unlock()
	a.kc.mu.Lock()
	a.kc.revoked, a.kc.revokeErr = nil, errors.New("keycloak down")
	a.kc.mu.Unlock()
	a.reconcile()
	if got := a.kc.revokedList(); !slices.Contains(got, "alice@"+keycloak.AIClientIDs.Claude) {
		t.Fatalf("alice not revoked: %v", got)
	}
	a.kc.mu.Lock()
	a.kc.revoked, a.kc.revokeErr = nil, nil
	a.kc.mu.Unlock()
	a.reconcile()
	got := a.kc.revokedList()
	for _, c := range all {
		if !slices.Contains(got, "alice@"+c) {
			t.Errorf("alice not revoked for %s: %v", c, got)
		}
	}
	a.kc.mu.Lock()
	a.kc.revoked = nil
	a.kc.mu.Unlock()
	a.reconcile()
	if got := a.kc.revokedList(); len(got) != 0 {
		t.Errorf("revoked again: %v", got)
	}
	// alice in a companion's population keeps hers.
	a.h.mu.Lock()
	a.h.st.AI.PortcullisPeople = true
	a.h.mu.Unlock()
	a.reconcile() // alice recorded again
	a.h.mu.Lock()
	a.h.st.AI.PortcullisPeople = false
	a.h.st.AIInstances = map[string]state.AIInstance{"aiapp": {Companions: map[string]state.AICompanion{"tok": {Enabled: true, Mode: "read_write"}}}}
	a.h.mu.Unlock()
	a.enable(t, "aiapp")
	a.reconcile()
	for _, r := range a.kc.revokedList() {
		if strings.HasPrefix(r, "alice@") {
			t.Errorf("alice (in tok's population) revoked: %v", r)
		}
	}
}

// writeAccessLog writes lines (each JSON, no newline) to a temp data dir,
// the last one torn when torn.
func writeAccessLog(t *testing.T, a *instAIFixture, lines []string, torn string) {
	t.Helper()
	dir := t.TempDir()
	a.h.cfg.MCPGateDataDir = dir
	b := strings.Join(lines, "\n") + "\n" + torn
	if err := os.WriteFile(filepath.Join(dir, AccessLogName), []byte(b), 0o640); err != nil {
		t.Fatal(err)
	}
}

func accessLine(user string, i int) string {
	return fmt.Sprintf(`{"time":"2026-11-05T10:%02d:%02dZ","user":%q,"client":"portcullis-ai-claude","resource":"https://aiapp.example.com/mcp","instance":"aiapp","companion":"tok","via":"direct","method":"tools/call","tool":"t%d","args_sha256":"%064d","decision":"allow","upstream_status":200,"duration_ms":%d}`, i/60, i%60, user, i, 0, i)
}

// TestAccessLogReader: a torn last line is skipped; MyAI("alice") holds
// only alice's lines (newest first, ≤ 50) and her connections;
// DisconnectAI with a non-AI client id → StatusError 404.
func TestAccessLogReader(t *testing.T) {
	a := newInstAIFixture(t, nil)
	var lines []string
	for i := 0; i < 130; i++ {
		u := "alice"
		if i%2 == 1 {
			u = "bob"
		}
		lines = append(lines, accessLine(u, i))
	}
	lines = append(lines, `{"time":"not a time","user":"alice"}`, `{"user":"alice","unknown":1}`)
	// The gate is mid-write: a whole document with no newline yet is torn
	// too (it may still grow).
	torn := strings.Replace(accessLine("alice", 200), `"tool":"t200"`, `"tool":"torn"`, 1)
	writeAccessLog(t, a, lines, torn)
	got, err := a.h.AccessLog(nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(got, func(l AccessLine) bool { return l.Tool == "torn" }) {
		t.Fatal("the torn last line was read")
	}
	if len(got) != 130 || got[0].Tool != "t129" || got[129].Tool != "t0" {
		t.Fatalf("AccessLog = %d lines, first %+v", len(got), got[0])
	}
	if got[0].Time != time.Date(2026, 11, 5, 10, 2, 9, 0, time.UTC) || got[0].DurationMS != 129 || got[0].UpstreamStatus != 200 {
		t.Errorf("line = %+v", got[0])
	}
	a.kc.conns = map[string][]keycloak.AIConnection{
		"alice": {{Client: keycloak.AIClientIDs.Claude, Consented: ptr(time.Unix(100, 0).UTC())}},
		"bob":   {{Client: keycloak.AIClientIDs.Generic}},
	}
	v, err := a.h.MyAI(context.Background(), "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Activity) != 50 {
		t.Fatalf("activity = %d lines, want 50", len(v.Activity))
	}
	for i, l := range v.Activity {
		if l.User != "alice" {
			t.Fatalf("activity holds %s's line", l.User)
		}
		if i > 0 && !l.Time.Before(v.Activity[i-1].Time) {
			t.Fatalf("not newest first at %d", i)
		}
	}
	if v.Activity[0].Tool != "t128" {
		t.Errorf("newest = %s", v.Activity[0].Tool)
	}
	if len(v.Connections) != 1 || v.Connections[0].Client != keycloak.AIClientIDs.Claude || v.Connections[0].Label != "Claude" || v.Connections[0].ConsentedAt == nil {
		t.Errorf("connections = %+v", v.Connections)
	}
	// Disconnect: AI client ids only.
	err = a.h.DisconnectAI(context.Background(), "alice", "gitea", directory.Human("alice"))
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusNotFound {
		t.Errorf("non-AI client = %v, want StatusError 404", err)
	}
	if err := a.h.DisconnectAI(context.Background(), "alice", keycloak.AIClientIDs.Claude, directory.Human("alice")); err != nil {
		t.Fatal(err)
	}
	if got := a.kc.revokedList(); !slices.Equal(got, []string{"alice@" + keycloak.AIClientIDs.Claude}) {
		t.Errorf("revoked = %v", got)
	}
	if got := a.auditsOf("ai.connection.revoke", "alice"); len(got) != 1 || got[0].Detail != keycloak.AIClientIDs.Claude || got[0].Result != "ok" {
		t.Errorf("audit = %+v", got)
	}
	if v, _ := a.h.MyAI(context.Background(), "alice"); len(v.Connections) != 0 {
		t.Errorf("connections after disconnect = %+v", v.Connections)
	}
	if _, err := a.h.MyAI(context.Background(), ""); statusOf(err) != 401 {
		t.Errorf("no user = %v", err)
	}
	// Keycloak unreadable / no data dir = 503; no log yet = none.
	a.kc.mu.Lock()
	a.kc.connErr = errors.New("down")
	a.kc.mu.Unlock()
	if _, err := a.h.MyAI(context.Background(), "alice"); statusOf(err) != 503 {
		t.Errorf("keycloak down = %v", err)
	}
	a.h.cfg.MCPGateDataDir = ""
	if _, err := a.h.AccessLog(nil, 10); statusOf(err) != 503 {
		t.Errorf("no data dir = %v", err)
	}
	a.h.cfg.MCPGateDataDir = t.TempDir()
	if l, err := a.h.AccessLog(nil, 10); err != nil || len(l) != 0 {
		t.Errorf("no log = %v %v", l, err)
	}
}

// Only the last 4 MiB are read; the fragment at the cut is skipped.
func TestAccessLogTail(t *testing.T) {
	a := newInstAIFixture(t, nil)
	var lines []string
	size := 0
	for i := 0; size < accessLogTail+1<<20; i++ {
		l := accessLine("bob", i%3600)
		lines = append(lines, l)
		size += len(l) + 1
	}
	lines = append(lines, accessLine("alice", 1))
	writeAccessLog(t, a, lines, "")
	got, err := a.h.AccessLog(nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].User != "alice" {
		t.Errorf("newest = %+v", got[0])
	}
	b, _ := os.ReadFile(filepath.Join(a.h.cfg.MCPGateDataDir, AccessLogName))
	tail := b[len(b)-accessLogTail:]
	if i := strings.IndexByte(string(b[len(b)-accessLogTail-1:len(b)-accessLogTail]), '\n'); i < 0 {
		tail = tail[strings.IndexByte(string(tail), '\n')+1:]
	}
	if want := strings.Count(string(tail), "\n"); len(got) != want {
		t.Errorf("read %d lines, want the %d whole lines of the last 4 MiB", len(got), want)
	}
}

// G33: a switched-on companion the template dropped, or whose identity
// mode changed, is switched off (ai.disable "template changed"), its
// entries marked revoking and revoke_all run with the hook it was switched
// on with; without that hook it stays revoking (AIRevokeProblems), and a
// mint for it is refused (404, not 502).
func TestPruneAITemplateChanged(t *testing.T) {
	a := newMintFixture(t)
	a.putCred(t, "aiapp", "tok", "alice")
	// A companion the template no longer declares, minted with tok-revoke.
	a.h.mu.Lock()
	ai := a.h.st.AIInstances["aiapp"]
	ai.Companions["gone"] = state.AICompanion{Enabled: true, Mode: "read_write", IdentityMode: "app_token", RevokeHook: "tok-revoke"}
	ai.Companions["lost"] = state.AICompanion{Enabled: true, Mode: "read_write", IdentityMode: "app_token", RevokeHook: "no-such-hook"}
	// tok was switched on as identity_headers: its mode changed.
	c := ai.Companions["tok"]
	// The old definition's revoke hook differs from the new one's
	// (tok-revoke): the old hook must run (fix round 1).
	c.IdentityMode, c.RevokeHook = "identity_headers", "ai-toggle"
	ai.Companions["tok"] = c
	a.h.st.AIInstances["aiapp"] = ai
	a.h.mu.Unlock()
	for _, n := range []string{"gone", "lost"} {
		if err := a.h.creds().Put(aigate.Credential{Instance: "aiapp", Companion: n, User: "alice", ID: "9", MintedAt: aigate.At(time.Now())}, []byte("x-credential")); err != nil {
			t.Fatal(err)
		}
	}
	a.h.pruneAI(true)
	for _, n := range []string{"gone", "lost", "tok"} {
		if s := a.companion("aiapp", n); s.Enabled || !s.Pruned {
			t.Errorf("%s = %+v, want off and pruned", n, s)
		}
		if got := a.auditsOf("ai.disable", "aiapp/"+n); len(got) != 1 || got[0].Detail != "template changed" {
			t.Errorf("%s audit = %+v", n, got)
		}
	}
	for _, e := range a.h.creds().Entries() {
		if e.State != aigate.StateRevoking {
			t.Errorf("entry %+v not revoking", e)
		}
	}
	if st, _ := state.Load(a.h.statePath()); !st.AIInstances["aiapp"].Companions["gone"].Pruned {
		t.Error("pruned not saved")
	}
	if _, err := a.h.MintCredential(context.Background(), tokResource, "alice"); statusOf(err) != 404 {
		t.Errorf("mint for a pruned companion = %v, want 404", err)
	}
	a.h.Wait()
	n := len(a.stdins("/revoke"))
	nt := len(a.stdins("/toggle"))
	a.reconcile()
	got := a.stdins("/revoke")[n:]
	if len(got) != 1 || got[0] != `{"action":"revoke_all","prefix":"portcullis-ai-"}` {
		t.Errorf("tok-revoke runs = %q, want gone's revoke_all only", got)
	}
	if got := a.stdins("/toggle")[nt:]; !slices.Contains(got, `{"action":"revoke_all","prefix":"portcullis-ai-"}`) {
		t.Errorf("the old hook (ai-toggle) runs = %q, want tok's revoke_all", got)
	}
	if _, ok := a.h.st.AIInstances["aiapp"].Companions["gone"]; ok {
		t.Error("gone's state entry kept after its revoke_all")
	}
	if s := a.companion("aiapp", "tok"); s.Pruned || s.Enabled {
		t.Errorf("tok = %+v", s)
	}
	left := a.h.creds().Entries()
	if len(left) != 1 || left[0].Companion != "lost" {
		t.Errorf("entries = %+v, want only lost's", left)
	}
	p := a.h.AIRevokeProblems()
	if len(p) != 1 || p[0].Companion != "lost" || !p[0].Pruned || !p[0].NoHook || p[0].Revoking != 1 || !strings.Contains(p[0].Reason, "no longer has its revoke hook") {
		t.Errorf("problems = %+v", p)
	}
}

// §15.4: a same-instance restore owes revoke_all for every switched-on
// companion; the companion isn't listed until it succeeded.
func TestRestoreOwesRevokeAll(t *testing.T) {
	a := newMintFixture(t)
	entry, err := a.h.BackupInstance("aiapp", root)
	if err != nil {
		t.Fatal(err)
	}
	a.failHook("/revoke", 1, "restored app down")
	n := len(a.stdins("/revoke"))
	if _, err := a.h.RestoreInstance("aiapp", entry.Archive, root); err != nil {
		t.Logf("restore: %v", err)
	}
	a.h.Wait()
	if got := a.stdins("/revoke")[n:]; len(got) == 0 || got[0] != `{"action":"revoke_all","prefix":"portcullis-ai-"}` {
		t.Errorf("revokes after the restore = %q", got)
	}
	if s := a.companion("aiapp", "tok"); !s.RevokePending {
		t.Errorf("tok = %+v, want revoke pending", s)
	}
	listed := func() bool {
		if err := a.h.WritePolicy(); err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(a.gate(t).Resources, func(r aigate.Resource) bool { return r.Companion == "tok" })
	}
	if listed() {
		t.Error("tok listed before its revoke_all succeeded")
	}
	// Control: the revoke_all succeeds (the next restore) → listed again.
	a.failHook("/revoke", 0, "")
	if _, err := a.h.RestoreInstance("aiapp", entry.Archive, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	if s := a.companion("aiapp", "tok"); s.RevokePending || !s.Enabled {
		t.Errorf("tok after a good revoke_all = %+v", s)
	}
	if !listed() {
		t.Error("tok not listed after its revoke_all succeeded")
	}
}

// Fix round 1 (1): a Pruned companion can't be switched on until its
// owed revocation succeeded; the AI tab shows it revoking even if the
// state says enabled.
func TestPrunedCompanionSwitchOnRefused(t *testing.T) {
	a := newMintFixture(t)
	a.h.mu.Lock()
	ai := a.h.st.AIInstances["aiapp"]
	c := ai.Companions["tok"]
	c.IdentityMode, c.RevokeHook = "identity_headers", "tok-revoke"
	ai.Companions["tok"] = c
	a.h.mu.Unlock()
	a.putCred(t, "aiapp", "tok", "alice")
	a.failHook("/revoke", 1, "down")
	a.h.pruneAI(false)
	a.reconcile()
	if s := a.companion("aiapp", "tok"); !s.Pruned {
		t.Fatalf("tok = %+v, want still pruned", s)
	}
	err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "revocation is still owed") {
		t.Errorf("switch-on of a pruned companion = %v, want 409", err)
	}
	for _, enabled := range []bool{false, true} {
		a.h.mu.Lock()
		ai := a.h.st.AIInstances["aiapp"]
		c := ai.Companions["tok"]
		c.Enabled = enabled
		ai.Companions["tok"] = c
		a.h.mu.Unlock()
		v, _ := a.h.InstanceAI("aiapp")
		if v.Companions[0].Status != "revoking" {
			t.Errorf("enabled=%v: status = %q, want revoking", enabled, v.Companions[0].Status)
		}
	}
	// Once the revocation succeeds the switch-on works again.
	a.h.mu.Lock()
	ai = a.h.st.AIInstances["aiapp"]
	c = ai.Companions["tok"]
	c.Enabled = false
	ai.Companions["tok"] = c
	a.h.mu.Unlock()
	a.failHook("/revoke", 0, "")
	a.reconcile()
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Errorf("switch-on after the revocation = %v", err)
	}
}

// Fix round 1 (2): RevokeAICredentials on a Pruned companion runs the
// hook it was switched on with, never the new definition's.
func TestRevokePrunedUsesStoredHook(t *testing.T) {
	a := newMintFixture(t)
	a.h.mu.Lock()
	ai := a.h.st.AIInstances["aiapp"]
	ai.Companions["tok"] = state.AICompanion{Mode: "read_write", IdentityMode: "app_token", RevokeHook: "ai-toggle", Pruned: true}
	a.h.mu.Unlock()
	a.putCred(t, "aiapp", "tok", "alice")
	if err := a.h.creds().MarkRevoking("aiapp", "tok", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := a.h.RevokeAICredentials(context.Background(), "aiapp", "tok", "alice", root); err != nil {
		t.Fatal(err)
	}
	if got := a.stdins("/toggle"); len(got) != 1 || got[0] != `{"action":"revoke","user":"alice","ids":["7"]}` {
		t.Errorf("ai-toggle runs = %q", got)
	}
	if got := a.stdins("/revoke"); len(got) != 0 {
		t.Errorf("the new definition's hook ran: %q", got)
	}
	a.putCred(t, "aiapp", "tok", "alice")
	if err := a.h.RevokeAICredentials(context.Background(), "aiapp", "tok", "", root); err != nil {
		t.Fatal(err)
	}
	if got := a.stdins("/toggle"); len(got) != 2 || got[1] != `{"action":"revoke_all","prefix":"portcullis-ai-"}` {
		t.Errorf("ai-toggle runs = %q", got)
	}
	if len(a.stdins("/revoke")) != 0 {
		t.Error("the new definition's hook ran")
	}
	if s := a.companion("aiapp", "tok"); s.Pruned {
		t.Errorf("tok still pruned after its revoke_all: %+v", s)
	}
	// No stored hook left: 409, nothing run.
	a.h.mu.Lock()
	a.h.st.AIInstances["aiapp"].Companions["tok"] = state.AICompanion{Mode: "read_write", IdentityMode: "app_token", RevokeHook: "gone-hook", Pruned: true}
	a.h.mu.Unlock()
	if err := a.h.RevokeAICredentials(context.Background(), "aiapp", "tok", "", root); statusOf(err) != 409 {
		t.Errorf("no stored hook = %v, want 409", err)
	}
}

// Fix round 1 (6): the policy write itself marks leavers revoking (no
// hook); the loop revokes later.
func TestLeaverMarkedByWritePolicy(t *testing.T) {
	a := newMintFixture(t)
	a.putCred(t, "aiapp", "tok", "alice")
	a.people.removeMember("users_aiapp", "alice")
	if err := a.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if e := a.credFileEntry(t, "aiapp", "tok", "alice"); e == nil || e.State != aigate.StateRevoking || e.Age != "" {
		t.Errorf("entry right after the policy write = %+v, want revoking", e)
	}
	if n := len(a.stdins("/revoke")); n != 0 {
		t.Errorf("the policy write ran %d hooks", n)
	}
	select {
	case <-a.h.aiReconKick:
	default:
		t.Error("the reconcile loop wasn't kicked")
	}
	// A held AI lock (a mint) leaves it to the loop.
	a.putCred(t, "aiapp", "tok", "alice")
	unlock := a.h.aiLock("aiapp")
	if err := a.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	unlock()
	if e := a.credFileEntry(t, "aiapp", "tok", "alice"); e == nil || e.State != aigate.StateActive {
		t.Errorf("entry with the AI lock held = %+v, want left active", e)
	}
	a.reconcile()
	if e := a.credFileEntry(t, "aiapp", "tok", "alice"); e != nil {
		t.Errorf("entry after the loop = %+v", e)
	}
}

// Fix round 1 (8): a pruned companion with an owed revoke_all and no
// recorded hook is cleared, logged and audited as an error, never as done.
func TestPrunedNoHookRecordedAudited(t *testing.T) {
	a := newMintFixture(t)
	a.h.mu.Lock()
	a.h.st.AIInstances["aiapp"].Companions["old"] = state.AICompanion{Mode: "read_write", Pruned: true}
	a.h.mu.Unlock()
	a.reconcile()
	got := a.auditsOf("ai.credential.revoke", "aiapp/old")
	if len(got) != 1 || got[0].Result != "error" || got[0].Detail != "owed revoke_all dropped: no hook recorded" {
		t.Errorf("audit = %+v", got)
	}
	if _, ok := a.h.st.AIInstances["aiapp"].Companions["old"]; ok {
		t.Error("state entry kept")
	}
}

// Fix round 1 (9): a busy instance spares only its own population from
// the connection cleanup.
func TestConnectionsCleanupBusyInstance(t *testing.T) {
	a := newMintFixture(t) // tok on: alice in its population
	a.h.mu.Lock()
	a.h.st.AI.PortcullisPeople, a.h.st.AI.PortcullisAdmin = true, false
	a.h.mu.Unlock()
	a.reconcile() // alice, carol, … recorded
	a.h.mu.Lock()
	a.h.st.AI.PortcullisPeople = false
	// aiapp is being restored, its companion state mid-change.
	if a.h.st.Instances == nil {
		a.h.st.Instances = map[string]state.Instance{}
	}
	e := a.h.st.Instances["aiapp"]
	e.State = state.InstanceRestoring
	a.h.st.Instances["aiapp"] = e
	a.h.st.AIInstances["aiapp"].Companions["tok"] = state.AICompanion{Mode: "read_write"}
	a.h.mu.Unlock()
	a.reconcile()
	got := a.kc.revokedList()
	if slices.ContainsFunc(got, func(r string) bool { return strings.HasPrefix(r, "alice@") }) {
		t.Errorf("alice (population of a restoring instance) judged: %v", got)
	}
	if !slices.Contains(got, "carol@"+keycloak.AIClientIDs.Claude) {
		t.Errorf("carol (no AI resource, not in aiapp) not revoked: %v", got)
	}
}

// Fix round 1 (10): app_oauth records nothing can revoke are listed.
func TestRevokeProblemsListOAuthLeftovers(t *testing.T) {
	a := newMintFixture(t)
	if err := a.h.oauthSeenUpdate(func(s map[string][]string) bool {
		s["aiapp/dropped"] = []string{"alice", "bob"}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	p := a.h.AIRevokeProblems()
	if len(p) != 1 || p[0].Companion != "dropped" || p[0].Recorded != 2 || !p[0].NoHook {
		t.Errorf("problems = %+v", p)
	}
}

// 12b carry: a policy that reached LoA 3 without a policy save (a restore,
// a template update) switches AI off at the next reconcile.
func TestLoA3SwitchOffAtReconcile(t *testing.T) {
	a := newMintFixture(t)
	a.h.mu.Lock()
	a.h.st.AuthPolicies["aiapp"] = policy.AuthPolicy{Factors: []string{"mtls"}, Op: "any"}
	a.h.mu.Unlock()
	a.reconcile()
	a.h.Wait()
	if s := a.companion("aiapp", "tok"); s.Enabled {
		t.Errorf("tok = %+v, want off", s)
	}
	if got := a.auditsOf("ai.disable", "aiapp/tok"); len(got) != 1 || got[0].Detail != aiPolicyOffDetail || got[0].Actor != "hub" {
		t.Errorf("audit = %+v", got)
	}
}

// 13a carry: a credential the app minted but the Hub couldn't store is
// recorded (id only) and revoked by the reconcile.
func TestOrphanRetried(t *testing.T) {
	a := newMintFixture(t)
	a.failHook("/revoke", 1, "busy")
	// The store refuses the write: a directory where the file goes.
	if err := os.Remove(a.h.credsPath()); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	a.h.creds().mu.Lock()
	a.h.creds().file = nil
	a.h.creds().mu.Unlock()
	if err := os.MkdirAll(filepath.Join(a.h.credsPath(), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := a.h.MintCredential(context.Background(), tokResource, "alice"); statusOf(err) != 502 {
		t.Fatalf("mint with a broken store = %v", err)
	}
	b, err := os.ReadFile(filepath.Join(a.h.cfg.DataDir, "ai", "orphans.json"))
	if err != nil || !strings.Contains(string(b), `"id": "id-alice"`) || strings.Contains(string(b), "c-alice") {
		t.Fatalf("orphans.json = %s (%v)", b, err)
	}
	a.failHook("/revoke", 0, "")
	n := len(a.stdins("/revoke"))
	a.reconcile()
	if got := a.stdins("/revoke")[n:]; len(got) != 1 || got[0] != `{"action":"revoke","user":"alice","ids":["id-alice"]}` {
		t.Errorf("revoke = %q", got)
	}
	if b, _ := os.ReadFile(filepath.Join(a.h.cfg.DataDir, "ai", "orphans.json")); strings.Contains(string(b), "id-alice") {
		t.Errorf("orphan kept after its revoke: %s", b)
	}
}

// 13a carry: a backup holds the AI lock while it stops the app.
func TestBackupHoldsAILock(t *testing.T) {
	a := newMintFixture(t)
	unlock := a.h.aiLock("aiapp")
	done := make(chan error, 1)
	go func() {
		_, err := a.h.BackupInstance("aiapp", root)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("backup ran while the AI lock was held: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
