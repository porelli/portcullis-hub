package directory_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// auditLines returns the raw lines of the env's audit log.
func auditLines(t *testing.T, e *env) []string {
	t.Helper()
	b, err := os.ReadFile(e.audit)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func lastAuditLine(t *testing.T, e *env) string {
	t.Helper()
	l := auditLines(t, e)
	return l[len(l)-1]
}

// TestAuditViaFields (Task 7a, contract §9.5): an AI caller's entries carry
// "via" and "client" — refusals too —; a human's have neither key.
func TestAuditViaFields(t *testing.T) {
	e := newEnv(t)
	ai := &directory.Caller{User: "root", Admin: true, Via: directory.ViaAI, Client: "portcullis-ai-claude-code"}
	if _, err := e.svc.CreateGroup(ctx, ai, "team"); err != nil {
		t.Fatal(err)
	}
	line := lastAuditLine(t, e)
	if !strings.Contains(line, `"via":"ai","client":"portcullis-ai-claude-code"`) || !strings.Contains(line, `"actor":"root"`) || !strings.Contains(line, `"result":"ok"`) {
		t.Errorf("AI entry = %s", line)
	}
	// A refusal (a protected account) carries them too.
	if _, err := e.svc.DeleteUser(ctx, ai, "admin", "admin"); status(err) < 400 || status(err) >= 500 {
		t.Fatalf("delete admin = %v", err)
	}
	line = lastAuditLine(t, e)
	if !strings.Contains(line, `"result":"refused"`) || !strings.Contains(line, `"via":"ai","client":"portcullis-ai-claude-code"`) {
		t.Errorf("AI refusal = %s", line)
	}
	// An AI caller that isn't an admin: refused by the gate, still attributed.
	aiAlice := &directory.Caller{User: "alice", Via: directory.ViaAI, Client: "portcullis-ai-claude", Perms: map[string]bool{}}
	if _, err := e.svc.CreateGroup(ctx, aiAlice, "nope"); status(err) != 403 {
		t.Fatalf("alice creates a group = %v", err)
	}
	line = lastAuditLine(t, e)
	if !strings.Contains(line, `"actor":"alice"`) || !strings.Contains(line, `"via":"ai","client":"portcullis-ai-claude"`) || !strings.Contains(line, `"result":"refused"`) {
		t.Errorf("AI gate refusal = %s", line)
	}
	// A human call: neither key.
	if _, err := e.svc.CreateGroup(ctx, asRoot, "team2"); err != nil {
		t.Fatal(err)
	}
	line = lastAuditLine(t, e)
	if strings.Contains(line, `"via"`) || strings.Contains(line, `"client"`) {
		t.Errorf("human entry has via/client: %s", line)
	}
	// The reader returns them.
	entries, err := e.svc.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Via != "" || entries[0].Client != "" || entries[1].Via != directory.ViaAI || entries[1].Client != "portcullis-ai-claude" {
		t.Errorf("Recent = %+v", entries[:2])
	}
}

// TestAuditViaClipped: the client name is clipped like every other
// attributed value, and a newline can't split the line.
func TestAuditViaClipped(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("c", 1000) + "\nforged"
	ai := &directory.Caller{User: "root", Admin: true, Via: directory.ViaAI, Client: long}
	if _, err := e.svc.CreateGroup(ctx, ai, "team"); err != nil {
		t.Fatal(err)
	}
	lines := auditLines(t, e)
	if len(lines) != 1 {
		t.Fatalf("lines = %d", len(lines))
	}
	entries, _ := e.svc.Recent(1)
	if len(entries) != 1 || len(entries[0].Client) >= len(long) {
		t.Errorf("client not clipped: %d", len(entries[0].Client))
	}
}

// TestCreatedByIsUserOnly: a delegate's CreateUser through the AI stores
// the delegate's username in created_by, nothing else.
func TestCreatedByIsUserOnly(t *testing.T) {
	e := delegateEnv(t)
	ivy := callerFor(t, e, "ivy")
	ivy.Via, ivy.Client = directory.ViaAI, "portcullis-ai-claude"
	if _, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "nina", Email: "nina@example.org"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := e.svc.Store.Load()
	if cfg.CreatedBy["nina"] != "ivy" {
		t.Errorf("created_by = %q", cfg.CreatedBy["nina"])
	}
	b, _ := os.ReadFile(e.svc.Store.Path)
	if strings.Contains(string(b), "portcullis-ai") || strings.Contains(string(b), "via") {
		t.Errorf("directory.yaml holds the AI attribution:\n%s", b)
	}
}

// TestActor: Human, Caller.Actor and Actor.Check.
func TestActor(t *testing.T) {
	if a := directory.Human("root"); a != (directory.Actor{User: "root"}) {
		t.Errorf("Human = %+v", a)
	}
	c := &directory.Caller{User: "root", Admin: true, Via: directory.ViaAI, Client: "c"}
	if a := c.Actor(); a != (directory.Actor{User: "root", Via: directory.ViaAI, Client: "c"}) {
		t.Errorf("Caller.Actor = %+v", a)
	}
	var nilCaller *directory.Caller
	if a := nilCaller.Actor(); a != (directory.Actor{}) {
		t.Errorf("nil Caller.Actor = %+v", a)
	}
	for _, a := range []directory.Actor{{User: "root"}, {User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude"}} {
		if err := a.Check(); err != nil {
			t.Errorf("%+v: %v", a, err)
		}
	}
	for _, a := range []directory.Actor{
		{},
		{User: " "},
		{User: "root", Via: "browser"},
		{User: "root", Via: directory.ViaAI},
		{User: "root", Client: "c"},
	} {
		if err := a.Check(); status(err) != 403 {
			t.Errorf("%+v accepted: %v", a, err)
		}
	}
}

// TestCallerAs: the MCP listener's Caller keeps the AI attribution;
// permissions are resolved exactly as for CallerFor.
func TestCallerAs(t *testing.T) {
	e := newEnv(t)
	c, err := e.svc.CallerAs(ctx, directory.Actor{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Admin || c.User != "root" || c.Via != directory.ViaAI || c.Client != "portcullis-ai-claude-code" {
		t.Errorf("CallerAs = %+v", c)
	}
	c, err = e.svc.CallerAs(ctx, directory.Human("alice"))
	if err != nil || c.Admin || c.Via != "" || c.Client != "" {
		t.Errorf("CallerAs(alice) = %+v, %v", c, err)
	}
	if _, err := e.svc.CallerAs(ctx, directory.Actor{User: "root", Via: directory.ViaAI}); status(err) != 403 {
		t.Errorf("AI actor without a client = %v", err)
	}
}

// TestAuditReadsOldEntries: entries written before via/client existed
// (and unknown future keys) still read.
func TestAuditReadsOldEntries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	old := `{"time":"2026-10-01T10:00:00Z","actor":"root","action":"group.create","target":"g","result":"ok"}` + "\n" +
		`{"time":"2026-11-05T10:00:00Z","actor":"root","action":"instance.delete","target":"x","result":"ok","via":"ai","client":"c","future":1}` + "\n"
	if err := os.WriteFile(p, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	l := &directory.AuditLog{Path: p}
	got, err := l.Recent(10)
	if err != nil || len(got) != 2 {
		t.Fatalf("Recent = %+v, %v", got, err)
	}
	if got[0].Via != "ai" || got[0].Client != "c" || got[1].Via != "" || got[1].Client != "" || got[1].Action != "group.create" || !got[1].Time.Equal(time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("Recent = %+v", got)
	}
}
