package hub

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
)

// checkImpFileStrict decodes raw as the Keycloak extension does
// (ImpersonationFile: unknown fields, missing fields, nulls other than
// sessions[].ended, another version, an id twice and any value outside
// its rule refuse the whole file) and fails t when it would refuse it.
// The rules are written out here again, from the contract (§8.1), not
// from the writer's code.
func checkImpFileStrict(t *testing.T, raw []byte, now time.Time) impFile {
	t.Helper()
	fail := func(f string, a ...any) {
		t.Helper()
		t.Fatalf("impersonation.json refused: "+f+"\n%s", append(a, raw)...)
	}
	// Exactly the fields, no nulls but ended.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		fail("%v", err)
	}
	keys := func(m map[string]any, want ...string) {
		t.Helper()
		got := []string{}
		for k, v := range m {
			got = append(got, k)
			if v == nil && k != "ended" {
				fail("%s is null", k)
			}
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			fail("fields %v, want %v", got, want)
		}
	}
	keys(generic, "version", "allowed", "written", "clients", "pending", "sessions", "notices")
	for _, p := range generic["pending"].([]any) {
		keys(p.(map[string]any), "id", "admin", "admin_sid", "target", "reason", "fresh", "fresh_at", "created", "until")
	}
	for _, s := range generic["sessions"].([]any) {
		keys(s.(map[string]any), "id", "admin", "target", "reason", "started", "until", "ended")
	}
	for _, list := range generic["notices"].(map[string]any) {
		for _, n := range list.([]any) {
			keys(n.(map[string]any), "id", "admin", "started", "ended", "reason", "apps")
			for _, a := range n.(map[string]any)["apps"].([]any) {
				keys(a.(map[string]any), "name", "own_session")
			}
		}
	}
	var doc impFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		fail("%v", err)
	}
	if dec.More() {
		fail("trailing data")
	}
	user := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	id := regexp.MustCompile(`^[0-9a-f]{32}$`)
	sid := regexp.MustCompile(`^[A-Za-z0-9._:~-]{1,128}$`)
	reason := func(s string) bool {
		n := utf8.RuneCountInString(s)
		if n < 3 || n > 200 || !utf8.ValidString(s) {
			return false
		}
		for _, r := range s {
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || r == 0x061c || r == 0x200e || r == 0x200f ||
				(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
				return false
			}
		}
		return true
	}
	tm := func(what, s string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			fail("%s %q: not RFC 3339", what, s)
		}
		return v
	}
	if doc.Version != 1 {
		fail("version %d", doc.Version)
	}
	tm("written", doc.Written)
	for _, c := range doc.Clients {
		if c == "" || len(c) > 255 || strings.ContainsFunc(c, func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) }) {
			fail("client %q", c)
		}
	}
	seen := map[string]bool{}
	for _, p := range doc.Pending {
		if !id.MatchString(p.ID) || seen[p.ID] || !user.MatchString(p.Admin) || !user.MatchString(p.Target) || !sid.MatchString(p.AdminSID) ||
			!reason(p.Reason) || (p.Fresh != "security_key" && p.Fresh != "yubikey_cert") {
			fail("pending %+v", p)
		}
		seen[p.ID] = true
		created := tm("created", p.Created)
		if tm("fresh_at", p.FreshAt).After(created.Add(5 * time.Second)) {
			fail("fresh_at after created + 5 s")
		}
		if created.After(now.Add(5 * time.Second)) {
			fail("created in the future")
		}
		tm("until", p.Until)
	}
	seen = map[string]bool{}
	for _, s := range doc.Sessions {
		if !id.MatchString(s.ID) || seen[s.ID] || !user.MatchString(s.Admin) || !user.MatchString(s.Target) || !reason(s.Reason) {
			fail("session %+v", s)
		}
		seen[s.ID] = true
		tm("started", s.Started)
		tm("until", s.Until)
		if s.Ended != nil {
			tm("ended", *s.Ended)
		}
	}
	for u, list := range doc.Notices {
		if !user.MatchString(u) {
			fail("notices key %q", u)
		}
		for _, n := range list {
			if !id.MatchString(n.ID) || !user.MatchString(n.Admin) || !reason(n.Reason) {
				fail("notice %+v", n)
			}
			tm("started", n.Started)
			tm("ended", n.Ended)
			for _, a := range n.Apps {
				if a.Name == "" || utf8.RuneCountInString(a.Name) > 200 || !reason(a.Name+"xxx") {
					fail("app %q", a.Name)
				}
			}
		}
	}
	return doc
}

// TestImpersonationFileShape (D37, F1, F30): the golden shape; clients
// forward-auth plus the enabled instances' sign-in clients, never the
// fresh-auth or an AI client; sessions an hour; pending 120 s; notices
// only used ones within history_days; 0644; atomic; an instance change
// rewrites it.
func TestImpersonationFileShape(t *testing.T) {
	x := newImpFixture(t)
	if err := x.h.Enable("chat"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(x.f.data, ImpersonationFileName)
	doc := x.file(t)
	if !slices.Equal(doc.Clients, []string{"portcullis-forward-auth", "chat", "chat-admin"}) {
		t.Errorf("clients = %v", doc.Clients)
	}
	// A snapshot naming the fresh-auth and AI clients (state edited by
	// hand): never listed.
	x.h.mu.Lock()
	x.h.st.Enabled = append(x.h.st.Enabled, "gone")
	x.h.st.Published["gone"] = state.PublishedApp{Hosts: []string{"gone.example.org"},
		SignInClients: []string{"gone-app", freshauth.ClientID, keycloak.AIClientIDs.Claude, "portcullis-ai-x"}}
	x.h.mu.Unlock()
	if err := x.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if doc := x.file(t); !slices.Equal(doc.Clients, []string{"portcullis-forward-auth", "chat", "chat-admin", "gone-app"}) {
		t.Errorf("an instance change didn't rewrite the clients: %v", doc.Clients)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, %v", st.Mode().Perm(), err)
	}
	// The golden shape, with one of each.
	used := state.Impersonation{ID: strings.Repeat("9a", 16), Admin: "root", Target: "bob", AdminSID: "s", Reason: "fixing the calendar",
		Fresh: "yubikey_cert", FreshAt: impT0.Add(-49 * time.Hour), Started: impT0.Add(-48 * time.Hour), Until: impT0.Add(-48*time.Hour + 30*time.Minute),
		Ended: impT0.Add(-48*time.Hour + 12*time.Minute), How: ImpStopped, EndedBy: "root", Used: true,
		Apps: []state.ImpersonationApp{{Name: "Gitea"}, {Name: "Next‮cloud\n", OwnSession: true}}}
	notUsedOld := state.Impersonation{ID: strings.Repeat("1b", 16), Admin: "root", Target: "carol", AdminSID: "s", Reason: "nobody used it",
		Fresh: "security_key", FreshAt: impT0.Add(-3 * time.Hour), Started: impT0.Add(-3 * time.Hour), Until: impT0.Add(-2 * time.Hour),
		Ended: impT0.Add(-2 * time.Hour), How: ImpNotUsed}
	recent := state.Impersonation{ID: strings.Repeat("2c", 16), Admin: "sam", Target: "carol", AdminSID: "s", Reason: "a quick look",
		Fresh: "security_key", FreshAt: impT0.Add(-20 * time.Minute), Started: impT0.Add(-20 * time.Minute), Until: impT0.Add(10 * time.Minute),
		Ended: impT0.Add(-10 * time.Minute), How: ImpExpired, Used: false}
	tooOld := used
	tooOld.ID, tooOld.Ended = strings.Repeat("3d", 16), impT0.AddDate(-2, 0, 0)
	broken := used
	broken.ID, broken.Reason = strings.Repeat("4e", 16), "x\x07y"
	x.h.mu.Lock()
	x.h.st.Impersonations = []state.Impersonation{used, notUsedOld, recent, tooOld, broken}
	x.h.mu.Unlock()
	s := x.mustStart(t, "root", "alice")
	raw, _ := os.ReadFile(path)
	doc = checkImpFileStrict(t, raw, x.clock())
	if !doc.Allowed || doc.Version != 1 || doc.Written != "2026-11-12T14:02:58Z" {
		t.Errorf("head = %+v", doc)
	}
	if len(doc.Pending) != 1 || doc.Pending[0].ID != s.ID {
		t.Errorf("pending = %+v", doc.Pending)
	}
	var ids []string
	for _, ss := range doc.Sessions {
		ids = append(ids, ss.ID)
	}
	if !slices.Equal(ids, []string{recent.ID, s.ID}) {
		t.Errorf("sessions = %v", ids)
	}
	if len(doc.Notices) != 1 || len(doc.Notices["bob"]) != 1 {
		t.Fatalf("notices = %+v", doc.Notices)
	}
	n := doc.Notices["bob"][0]
	want := impNotice{ID: used.ID, Admin: "root", Started: "2026-11-10T14:02:58Z", Ended: "2026-11-10T14:14:58Z", Reason: "fixing the calendar",
		Apps: []impApp{{Name: "Gitea"}, {Name: "Nextcloud", OwnSession: true}}}
	if !jsonEqual(n, want) {
		t.Errorf("notice = %+v\nwant %+v", n, want)
	}
	// Exactly the readers' field names, in the contract's example.
	for _, k := range []string{`"version": 1`, `"allowed": true`, `"admin_sid": "f7c1e2d4-1b2a-4c3d-9e8f-001122334455"`, `"fresh_at": "2026-11-12T14:02:51Z"`,
		`"ended": null`, `"own_session": true`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("file lacks %s", k)
		}
	}
	// Atomic: no temporary files left.
	entries, _ := os.ReadDir(x.f.data)
	for _, e := range entries {
		if strings.Contains(e.Name(), ImpersonationFileName+".tmp") {
			t.Errorf("temp file left: %s", e.Name())
		}
	}
	// Ending at once is in the file at once.
	if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	for _, ss := range x.file(t).Sessions {
		if ss.ID == s.ID && ss.Ended == nil {
			t.Error("stopped but not ended in the file")
		}
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
