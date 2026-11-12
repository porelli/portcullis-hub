package signinhistory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/signin"
)

var t0 = time.Date(2026, 11, 10, 8, 14, 2, 0, time.UTC)

const firefoxMac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0"

func login(client string, d map[string]string) keycloak.Event {
	return keycloak.Event{Time: t0, Type: "LOGIN", ClientID: client, IP: "203.0.113.7", Details: d}
}

func TestFromEventKinds(t *testing.T) {
	names := map[string]string{"nextcloud": "Nextcloud", ForwardAuthClient: "Gateway"}
	e, ok := FromEvent(login(ForwardAuthClient, map[string]string{"pc_kind": "sign_in", "pc_methods": "security_key", "pc_session": "security_key", "pc_ua": firefoxMac}), names)
	if !ok || e.Kind != KindSignIn || !reflect.DeepEqual(e.Methods, []signin.Method{signin.SecurityKey}) ||
		e.Score == nil || e.Score.Tenths != 35 || e.IP != "203.0.113.7" || e.Browser != "Firefox · macOS" || e.Detail != "" {
		t.Errorf("sign_in = %+v (%v)", e, ok)
	}
	e, ok = FromEvent(login(ForwardAuthClient, map[string]string{"pc_kind": "step_up", "pc_methods": "yubikey_cert,password"}), names)
	if !ok || e.Kind != KindStepUp || !reflect.DeepEqual(e.Methods, []signin.Method{signin.Password, signin.YubiKeyCert}) {
		t.Errorf("step_up = %+v", e)
	}
	e, ok = FromEvent(login("nextcloud", map[string]string{"pc_kind": "sso", "pc_methods": "", "pc_session": "passkey_device"}), names)
	if !ok || e.Kind != KindOpened || e.App != "Nextcloud" || !reflect.DeepEqual(e.Methods, []signin.Method{signin.PasskeyDevice}) {
		t.Errorf("sso listed = %+v (%v)", e, ok)
	}
	if e, ok := FromEvent(login(ForwardAuthClient, map[string]string{"pc_kind": "sso"}), names); ok {
		t.Errorf("sso forward-auth kept: %+v", e)
	}
	if e, ok := FromEvent(login("unlisted", map[string]string{"pc_kind": "sso"}), names); ok {
		t.Errorf("sso unlisted kept: %+v", e)
	}
	e, ok = FromEvent(login(FreshAuthClient, map[string]string{"pc_kind": "sign_in", "pc_methods": "passkey_device"}), names)
	if !ok || e.Kind != KindConfirmed || !reflect.DeepEqual(e.Methods, []signin.Method{signin.PasskeyDevice}) {
		t.Errorf("fresh auth = %+v", e)
	}
	fail := keycloak.Event{Time: t0, Type: "LOGIN_ERROR", ClientID: ForwardAuthClient, Error: "invalid_user_credentials", Details: map[string]string{"pc_method": "password"}}
	e, ok = FromEvent(fail, names)
	if !ok || e.Kind != KindFailed || e.Reason != "wrong password" || !reflect.DeepEqual(e.Methods, []signin.Method{signin.Password}) {
		t.Errorf("failed = %+v", e)
	}
	fail.Error, fail.Details = "something_new", nil
	e, ok = FromEvent(fail, names)
	if !ok || e.Reason != "sign-in failed" || e.Methods == nil || len(e.Methods) != 0 || e.Score != nil {
		t.Errorf("unknown error = %+v", e)
	}
	for kcErr, want := range map[string]string{"user_not_found": "unknown account", "user_disabled": "account disabled",
		"user_temporarily_disabled": "too many attempts: wait", "invalid_user_certificate": "certificate refused",
		"certificate_revoked": "certificate refused", "different_user_authenticated": "another person's certificate",
		"access_denied": "access denied"} {
		if got := FailureText(kcErr); got != want {
			t.Errorf("%s → %q, want %q", kcErr, got, want)
		}
	}
	e, _ = FromEvent(login(ForwardAuthClient, map[string]string{"pc_kind": "sign_in", "pc_methods": "password,sms,passkey"}), names)
	if !reflect.DeepEqual(e.Methods, []signin.Method{signin.Password}) {
		t.Errorf("unknown pc_methods value kept: %v", e.Methods)
	}
	if _, ok := FromEvent(keycloak.Event{Type: "REGISTER"}, names); ok {
		t.Error("another event type kept")
	}
}

// TestSetupLinkSignIn (carried, Task 2 m5): a setup link's LOGIN
// (pc_kind sign_in, no method) is "Setup link used", never a methodless
// sign-in.
func TestSetupLinkSignIn(t *testing.T) {
	e, ok := FromEvent(login("account-console", map[string]string{"pc_kind": "sign_in", "pc_methods": "", "pc_session": ""}), nil)
	if !ok || e.Detail != SetupLinkDetail || len(e.Methods) != 0 || e.Score != nil {
		t.Errorf("setup link = %+v", e)
	}
	b := mustJSON(t, e)
	if !strings.Contains(b, `"methods":[]`) || !strings.Contains(b, `"score":null`) || !strings.Contains(b, `"detail":"Setup link used"`) {
		t.Errorf("json = %s", b)
	}
}

// TestSetupLinkBrokeredLogin (part 2 Task 13 e2e): the post-broker LOGIN of a
// setup link carries Keycloak's identity_provider detail and none of the
// extension's: still "Setup link used", never "methods weren't recorded".
func TestSetupLinkBrokeredLogin(t *testing.T) {
	e, ok := FromEvent(login(ForwardAuthClient, map[string]string{"identity_provider": InviteIdP, "identity_provider_identity": "alice"}), nil)
	if !ok || e.Kind != KindSignIn || e.Detail != SetupLinkDetail || len(e.Methods) != 0 || e.Score != nil {
		t.Errorf("brokered setup link = %+v", e)
	}
	// Another identity provider without pc_kind is not a setup link.
	e, ok = FromEvent(login(ForwardAuthClient, map[string]string{"identity_provider": "other"}), nil)
	if !ok || e.Detail == SetupLinkDetail {
		t.Errorf("other idp = %+v", e)
	}
}

func TestUntrustedTextClipped(t *testing.T) {
	ev := login(ForwardAuthClient, map[string]string{"pc_kind": "sign_in", "pc_methods": "password"})
	for raw, want := range map[string]string{
		"203.0.113.7":               "203.0.113.7",
		" 2001:DB8::1 ":             "2001:db8::1",
		"fe80::1%eth0":              "fe80::1",
		strings.Repeat("9", 200):    "",
		"203.0.113.7\x1b[31m":       "",
		"<script>":                  "",
		"203.0.113.7, 198.51.100.1": "",
	} {
		ev.IP = raw
		if e, _ := FromEvent(ev, nil); e.IP != want {
			t.Errorf("ip %q = %q, want %q", raw, e.IP, want)
		}
	}
	if got := Clean("a\u202eb\x00c\nd", 10); got != "abcd" {
		t.Errorf("clean = %q", got)
	}
}

func TestBrowserName(t *testing.T) {
	if got := Browser(firefoxMac); got != "Firefox · macOS" {
		t.Errorf("firefox = %q", got)
	}
	if got := Browser(""); got != "" {
		t.Errorf("empty = %q", got)
	}
	if got := Browser("\x01\x02"); got != "" {
		t.Errorf("garbage = %q", got)
	}
}

func TestFromAuditOnlyListedActions(t *testing.T) {
	at := func(actor, action, detail string) directory.AuditEntry {
		return directory.AuditEntry{Time: t0, Actor: actor, Action: action, Target: "alice", Detail: detail, Result: "ok"}
	}
	e, ok := FromAudit(at("alice", "cert.create", "browser certificate 1a:2b"), "alice")
	if !ok || e.Kind != KindCertificate || e.By != "" || !strings.Contains(e.Detail, "1a:2b") {
		t.Errorf("cert.create self = %+v (%v)", e, ok)
	}
	e, ok = FromAudit(at("root", "cert.revoke", ""), "alice")
	if !ok || e.Kind != KindHelp || e.By != "root" {
		t.Errorf("cert.revoke by root = %+v", e)
	}
	e, ok = FromAudit(at("bob", "user.remove_passkeys", "new_invite=false; as sign_in_help"), "alice")
	if !ok || e.Kind != KindHelp || e.By != "bob" || !strings.Contains(e.Detail, "as sign_in_help") {
		t.Errorf("remove_passkeys by bob = %+v", e)
	}
	if e, ok := FromAudit(at("root", "user.password", "generated=true"), "alice"); !ok || e.Kind != KindHelp || e.By != "root" {
		t.Errorf("user.password by root = %+v (%v)", e, ok)
	}
	if e, ok := FromAudit(at("bob", "user.invite", ""), "alice"); !ok || e.Kind != KindHelp {
		t.Errorf("user.invite by bob = %+v (%v)", e, ok)
	}
	for name, a := range map[string]directory.AuditEntry{
		"invite self":       at("alice", "user.invite", ""),
		"group.add":         at("root", "group.add", ""),
		"signin.password":   at("alice", "signin.password", "self set"),
		"user.password":     at("Alice", "user.password", ""),
		"refused":           {Time: t0, Actor: "root", Action: "cert.revoke", Target: "alice", Result: "refused"},
		"another's actions": at("root", "user.update", ""),
	} {
		if e, ok := FromAudit(a, "alice"); ok {
			t.Errorf("%s kept: %+v", name, e)
		}
	}
}

func TestAuditSource(t *testing.T) {
	log := &directory.AuditLog{Path: filepath.Join(t.TempDir(), "audit.jsonl")}
	for i, a := range []directory.AuditEntry{
		{Time: t0.Add(-48 * time.Hour), Actor: "root", Action: "cert.revoke", Target: "alice", Result: "ok"}, // before since
		{Time: t0.Add(-time.Hour), Actor: "root", Action: "user.invite", Target: "alice", Result: "ok"},
		{Time: t0.Add(-time.Minute), Actor: "root", Action: "user.invite", Target: "bob", Result: "ok"},
		{Time: t0.Add(-time.Second), Actor: "alice", Action: "cert.create", Target: "alice", Result: "ok"},
		{Time: t0.Add(time.Hour), Actor: "root", Action: "cert.revoke", Target: "alice", Result: "ok"}, // after before
	} {
		if err := log.Append(a); err != nil {
			t.Fatal(i, err)
		}
	}
	got, err := AuditSource{Read: log.RecentMatching}.Entries(context.Background(), "alice", t0.Add(-24*time.Hour), t0, 50)
	if err != nil || len(got) != 2 || got[0].Kind != KindCertificate || got[1].Kind != KindHelp {
		t.Errorf("audit entries = %+v, %v", got, err)
	}
	// The limit is the caller's (the history passes limit+1 itself).
	got, _ = AuditSource{Read: log.RecentMatching}.Entries(context.Background(), "alice", t0.Add(-24*time.Hour), t0, 1)
	if len(got) != 1 {
		t.Errorf("limit 1 read %d", len(got))
	}
}

func writeDay(t *testing.T, dir string, day time.Time, lines ...string) string {
	t.Helper()
	p := filepath.Join(dir, OpenedDirName, day.Format("2006-01-02")+".jsonl")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func line(at time.Time, user, session, host string) string {
	return `{"time":"` + at.Format(time.RFC3339) + `","user":"` + user + `","session":"` + session + `","host":"` + host +
		`","app":"Files","methods":["passkey_device","sms"],"ip":"198.51.100.4","ua":"` + firefoxMac + `","act":""}`
}

func TestOpenedLogDedupeAndUser(t *testing.T) {
	dir := t.TempDir()
	day := t0.Truncate(24 * time.Hour)
	writeDay(t, dir, day,
		line(t0.Add(-2*time.Hour), "alice", "s1", "files.example.com"),
		line(t0.Add(-time.Hour), "alice", "s1", "files.example.com"), // same (session, host, day)
		line(t0.Add(-30*time.Minute), "alice", "s1", "wiki.example.com"),
		line(t0.Add(-20*time.Minute), "bob", "s9", "files.example.com"),
		`{"time":"2026-11-10T07:00:00Z","user":"alice","sess`, // torn
	)
	writeDay(t, dir, day.AddDate(0, 0, -1), line(t0.Add(-24*time.Hour), "alice", "s1", "files.example.com")) // another day: kept
	l := OpenedLog{Dir: dir, Now: func() time.Time { return t0 }}
	got, err := l.Entries(context.Background(), "Alice", t0.AddDate(0, 0, -30), t0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("entries = %+v", got)
	}
	if !got[0].Time.Equal(t0.Add(-30*time.Minute)) || !got[1].Time.Equal(t0.Add(-2*time.Hour)) || !got[2].Time.Equal(t0.Add(-24*time.Hour)) {
		t.Errorf("times = %v %v %v", got[0].Time, got[1].Time, got[2].Time)
	}
	e := got[1]
	if e.Kind != KindOpened || e.App != "Files" || e.IP != "198.51.100.4" || e.Browser != "Firefox · macOS" ||
		!reflect.DeepEqual(e.Methods, []signin.Method{signin.PasskeyDevice}) || e.Score == nil {
		t.Errorf("entry = %+v", e)
	}
	for _, en := range got {
		if en.IP == "" {
			t.Errorf("bob's line returned? %+v", en)
		}
	}
	if got, _ := l.Entries(context.Background(), "bob", t0.AddDate(0, 0, -30), t0, 50); len(got) != 1 {
		t.Errorf("bob = %+v", got)
	}
	// limit; before cuts.
	if got, _ := l.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0, 1); len(got) != 1 || !got[0].Time.Equal(t0.Add(-30*time.Minute)) {
		t.Errorf("limit 1 = %+v", got)
	}
	if got, _ := l.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0.Add(-time.Hour), 50); len(got) != 2 {
		t.Errorf("before -1h = %+v", got)
	}
	// No opened/ yet: empty; no mount: an error.
	if got, err := (OpenedLog{Dir: t.TempDir()}).Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0, 50); err != nil || len(got) != 0 {
		t.Errorf("no opened dir: %v %v", got, err)
	}
	if _, err := (OpenedLog{Dir: filepath.Join(dir, "missing")}).Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0, 50); err == nil {
		t.Error("a missing mount read as empty")
	}
}

func TestOpenedLogScanLimit(t *testing.T) {
	dir := t.TempDir()
	day := t0.Truncate(24 * time.Hour)
	old := line(t0.Add(-3*time.Hour), "alice", "old", "a.example.com")
	pad := strings.Repeat("x", OpenedScan)
	p := writeDay(t, dir, day, old, pad, line(t0.Add(-time.Hour), "alice", "new", "b.example.com"))
	_ = p
	got, err := OpenedLog{Dir: dir}.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0, 50)
	if err != nil || len(got) != 1 || !got[0].Time.Equal(t0.Add(-time.Hour)) {
		t.Errorf("past the scan = %+v, %v", got, err)
	}
}

func TestOpenedLogSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	day := t0.Truncate(24 * time.Hour)
	target := filepath.Join(t.TempDir(), "elsewhere.jsonl")
	if err := os.WriteFile(target, []byte(line(t0.Add(-time.Hour), "alice", "s", "h")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, OpenedDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, OpenedDirName, day.Format("2006-01-02")+".jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := (OpenedLog{Dir: dir}).Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0, 50); err == nil {
		t.Error("a symlinked day file was followed")
	}
}

func TestOpenedLogPruneKeepsToday(t *testing.T) {
	dir := t.TempDir()
	today := t0.Truncate(24 * time.Hour)
	old := writeDay(t, dir, today.AddDate(0, 0, -31), line(t0, "alice", "s", "h"))
	edge := writeDay(t, dir, today.AddDate(0, 0, -30), line(t0, "alice", "s", "h"))
	now := writeDay(t, dir, today, line(t0, "alice", "s", "h"))
	other := filepath.Join(dir, OpenedDirName, "notes.txt")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	l := OpenedLog{Dir: dir, Now: func() time.Time { return t0 }}
	n, err := l.Prune(30)
	if err != nil || n != 1 {
		t.Errorf("prune 30 = %d, %v", n, err)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Error("the 31-day-old file is still there")
	}
	for _, p := range []string{edge, now, other} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s removed", filepath.Base(p))
		}
	}
	if n, err := l.Prune(0); err != nil || n != 1 {
		t.Errorf("prune 0 = %d, %v", n, err)
	}
	if _, err := os.Stat(now); err != nil {
		t.Error("today's file removed with days 0")
	}
	if n, err := (OpenedLog{Dir: t.TempDir()}).Prune(30); err != nil || n != 0 {
		t.Errorf("no log: %d %v", n, err)
	}
}

func TestMergeOrderAndLimit(t *testing.T) {
	a := []Entry{{Time: t0, Kind: KindSignIn}, {Time: t0.Add(-2 * time.Hour), Kind: KindFailed}}
	b := []Entry{{Time: t0, Kind: KindOpened}, {Time: t0.Add(-time.Hour), Kind: KindHelp}}
	got := Merge(3, a, b)
	kinds := []Kind{}
	for _, e := range got {
		kinds = append(kinds, e.Kind)
	}
	if !reflect.DeepEqual(kinds, []Kind{KindSignIn, KindOpened, KindHelp}) {
		t.Errorf("merge = %v", kinds)
	}
	if got := Merge(0, a); got == nil || len(got) != 0 {
		t.Errorf("limit 0 = %v", got)
	}
	if got := Merge(10); got == nil || len(got) != 0 {
		t.Errorf("no lists = %v", got)
	}
	if got := Within(append(a, b...), t0.Add(-90*time.Minute), t0); len(got) != 1 || got[0].Kind != KindHelp {
		t.Errorf("within = %+v", got)
	}
}

func TestKeycloakSourcePages(t *testing.T) {
	since, before := t0.AddDate(0, 0, -30), t0
	// Keycloak answers its window (from <= time < to), newest first.
	var evs []keycloak.Event
	for i := range 3 {
		evs = append(evs, keycloak.Event{Time: t0.Add(-time.Duration(i+1) * time.Minute), Type: "LOGIN_ERROR"})
	}
	src := KeycloakSource{Events: func(_ context.Context, user string, from, to time.Time, first, max int) ([]keycloak.Event, error) {
		if user != "alice" || !from.Equal(since) || !to.Equal(before) {
			t.Errorf("query %s %v %v", user, from, to)
		}
		return evs[min(first, len(evs)):min(first+max, len(evs))], nil
	}}
	// The limit is the caller's: no +1 here.
	got, err := src.Entries(context.Background(), "alice", since, before, 2)
	if err != nil || len(got) != 2 || got[0].Kind != KindFailed {
		t.Errorf("entries = %+v, %v", got, err)
	}
	if got, _ := src.Entries(context.Background(), "alice", since, before, 50); len(got) != 3 {
		t.Errorf("all = %+v", got)
	}
	src.Events = func(context.Context, string, time.Time, time.Time, int, int) ([]keycloak.Event, error) {
		return nil, errors.New("500")
	}
	if _, err := src.Entries(context.Background(), "alice", since, before, 50); err == nil {
		t.Error("a failure was hidden")
	}
}

// TestKeycloakSourceBudget (fix round 1, I2): past the page budget the
// source answers *Partial with the oldest event read, and only entries
// newer than it.
func TestKeycloakSourceBudget(t *testing.T) {
	var evs []keycloak.Event
	evs = append(evs, login(ForwardAuthClient, map[string]string{"pc_kind": "sign_in", "pc_methods": "password"}))
	for i := range keycloakPages * 3 {
		evs = append(evs, keycloak.Event{Time: t0.Add(-time.Duration(i+1) * time.Second), Type: "LOGIN", ClientID: ForwardAuthClient,
			Details: map[string]string{"pc_kind": "sso"}})
	}
	evs = append(evs, keycloak.Event{Time: t0.Add(-time.Hour), Type: "LOGIN_ERROR"})
	src := KeycloakSource{Events: func(_ context.Context, _ string, _, _ time.Time, first, max int) ([]keycloak.Event, error) {
		return evs[min(first, len(evs)):min(first+max, len(evs))], nil
	}}
	got, err := src.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0.Add(time.Second), 3)
	var p *Partial
	if !errors.As(err, &p) || len(got) != 1 || got[0].Kind != KindSignIn {
		t.Fatalf("budget = %+v, %v", got, err)
	}
	if want := evs[keycloakPages*3-1].Time; !p.Through.Equal(want) {
		t.Errorf("through %v, want %v (the oldest read)", p.Through, want)
	}
}

func TestOpenedLogSymlinkDirRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(t.TempDir(), "real")
	writeDay(t, real, t0.Truncate(24*time.Hour).AddDate(0, 0, -40), line(t0, "alice", "s", "h"))
	if err := os.Symlink(filepath.Join(real, OpenedDirName), filepath.Join(dir, OpenedDirName)); err != nil {
		t.Fatal(err)
	}
	l := OpenedLog{Dir: dir, Now: func() time.Time { return t0 }}
	if _, err := l.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0, 50); err == nil {
		t.Error("a symlinked opened/ was read")
	}
	if _, err := l.Prune(30); err == nil {
		t.Error("a symlinked opened/ was pruned")
	}
	if ents, _ := os.ReadDir(filepath.Join(real, OpenedDirName)); len(ents) != 1 {
		t.Error("the symlink's target was pruned")
	}
}

// TestOpenedLogExactUserAndBudget (fix round 1, m2): a line merely
// mentioning the user (another user's, or the name in another case) is
// never returned; past the read budget the read stops at a day boundary
// with *Partial, and the days after it are complete.
func TestOpenedLogExactUserAndBudget(t *testing.T) {
	dir := t.TempDir()
	today := t0.Truncate(24 * time.Hour)
	writeDay(t, dir, today, line(t0.Add(-time.Hour), "bob", "s", "alice.example.com"), line(t0.Add(-time.Hour), "Alice", "s", "x"),
		line(t0.Add(-2*time.Hour), "alice", "s", "a.example.com"))
	writeDay(t, dir, today.AddDate(0, 0, -1), line(t0.Add(-24*time.Hour), "alice", "s", "b.example.com"))
	writeDay(t, dir, today.AddDate(0, 0, -2), line(t0.Add(-48*time.Hour), "alice", "s", "c.example.com"))
	l := OpenedLog{Dir: dir}
	got, err := l.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0, 50)
	if err != nil || len(got) != 3 || !got[0].Time.Equal(t0.Add(-2*time.Hour)) {
		t.Fatalf("entries = %+v, %v", got, err)
	}
	l.MaxScan = 1
	got, err = l.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0, 50)
	var p *Partial
	if !errors.As(err, &p) || len(got) != 1 || !got[0].Time.Equal(t0.Add(-2*time.Hour)) {
		t.Fatalf("budget = %+v, %v", got, err)
	}
	if want := today.Add(-time.Nanosecond); !p.Through.Equal(want) {
		t.Errorf("through %v, want %v", p.Through, want)
	}
}
