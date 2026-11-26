package hub

import (
	"context"
	"errors"
	netmail "net/mail"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The app mail senders (contract §19.14).

const senderAppManifest = `name: FX App
category: misc
ai: {unsupported: "test fixture"}
auth:
  method: custom
mail_sender:
  label: Firefox accounts
`

func senderAppCompose(id string) string {
	return "services:\n  web:\n    image: x\n    environment:\n      SMTP_HOST: ${PORTCULLIS_MAIL_SENDER_HOST}\n      SMTP_PASS: ${PORTCULLIS_MAIL_SENDER_PASSWORD}\n    labels:\n      traefik.http.routers." + id + ".rule: Host(`" + id + ".${PORTCULLIS_DOMAIN}`)\n"
}

// newSenderFixture: the mail fixture with two sender templates, fxapp
// (enabled) and fxoff (never enabled).
func newSenderFixture(t *testing.T) *mailFixture {
	t.Helper()
	f := newSenderFixtureOff(t)
	if err := f.h.Enable("fxapp"); err != nil {
		t.Fatal(err)
	}
	return f
}

// newSenderFixtureOff: newSenderFixture with neither instance enabled.
func newSenderFixtureOff(t *testing.T) *mailFixture {
	t.Helper()
	apps := map[string]map[string]string{}
	for _, id := range []string{"fxapp", "fxoff"} {
		apps[id] = map[string]string{"manifest.yaml": senderAppManifest, "compose.yml": senderAppCompose(id)}
	}
	f := newMailFixtureApps(t, apps)
	if f.h.Template("fxapp") == nil || f.h.Template("fxapp").Manifest.MailSender == nil {
		t.Fatal("the sender template didn't load (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	return f
}

var v4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func senderEntry(f *mailFixture, key string) state.MailSender {
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	return f.h.st.MailSenders[key]
}

func senderDotEnv(t *testing.T, f *mailFixture, id string) map[string]string {
	t.Helper()
	return readEnvFile(f.h.envPath(id))
}

func owedOf(f *mailFixture, id string) string {
	f.h.owedMu.Lock()
	defer f.h.owedMu.Unlock()
	return f.h.owedLocked(id)
}

func clearOwed(f *mailFixture, id string) {
	f.h.owedMu.Lock()
	defer f.h.owedMu.Unlock()
	f.h.owed[id] = ""
}

func TestSenderInMailState(t *testing.T) {
	f := newSenderFixture(t)
	f.sync(t)
	doc := f.mc.Last()
	if doc == nil || doc.Senders == nil {
		t.Fatalf("no senders sent: %+v", doc)
	}
	app, hub := senderEntry(f, "fxapp"), senderEntry(f, state.MailSenderHub)
	want := []mailprovider.Sender{
		{Username: "portcullis-app-fxapp", UUID: app.UUID, Address: "portcullis-app-fxapp@example.org"},
		{Username: "portcullis-hub-mail", UUID: hub.UUID, Address: "portcullis-hub-mail@example.org"},
	}
	if !slices.Equal(*doc.Senders, want) {
		t.Fatalf("senders %+v, want %+v", *doc.Senders, want)
	}
	if !v4Re.MatchString(app.UUID) || !v4Re.MatchString(hub.UUID) || app.UUID == hub.UUID {
		t.Fatalf("uuids %q %q aren't two v4 uuids", app.UUID, hub.UUID)
	}
	if _, ok := f.h.st.MailSenders["fxoff"]; ok {
		t.Fatal("a disabled instance has a sender")
	}
	// Kept across syncs (a new document: someone leaves mail_users).
	f.people.setMembers(MailUsersGroup, "alice", "root")
	f.sync(t)
	if senderEntry(f, "fxapp").UUID != app.UUID || senderEntry(f, state.MailSenderHub).UUID != hub.UUID {
		t.Fatal("a sender's uuid changed across syncs")
	}
	if n := f.mc.Puts(); n < 2 {
		t.Fatalf("%d documents", n)
	}
	// State.yaml holds the uuids, never a password.
	raw, err := os.ReadFile(f.h.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), app.UUID) {
		t.Fatal("state.yaml lacks the sender uuid")
	}
	for _, sec := range f.mc.Created {
		if strings.Contains(string(raw), sec) {
			t.Fatal("state.yaml holds a sender password")
		}
	}
	// Disabled: its sender leaves the next document.
	f.h.mu.Lock()
	f.h.st.Enabled = slices.DeleteFunc(f.h.st.Enabled, func(id string) bool { return id == "fxapp" })
	f.h.mu.Unlock()
	f.sync(t)
	got := *f.mc.Last().Senders
	if len(got) != 1 || got[0].Username != "portcullis-hub-mail" {
		t.Fatalf("after the disable: %+v", got)
	}
}

func TestSenderEnvWired(t *testing.T) {
	f := newSenderFixture(t)
	f.sync(t)
	creds := f.mc.Creds("portcullis-app-fxapp")
	if len(creds) != 1 || creds[0].Label != "Firefox accounts" || len(f.mc.Creds("portcullis-hub-mail")) != 1 {
		t.Fatalf("creds %+v / %+v", creds, f.mc.Creds("portcullis-hub-mail"))
	}
	e := senderEntry(f, "fxapp")
	if e.CredentialID != creds[0].ID || e.CreatedAt == nil {
		t.Fatalf("entry %+v", e)
	}
	env := senderDotEnv(t, f, "fxapp")
	var secret string
	for _, s := range f.mc.Created {
		if strings.HasPrefix(s, "mailpw-portcullis-app-fxapp-") {
			secret = s
		}
	}
	want := map[string]string{
		templates.VarMailSenderHost:     "mail.example.org",
		templates.VarMailSenderPort:     "587",
		templates.VarMailSenderUser:     "portcullis-app-fxapp@example.org",
		templates.VarMailSenderPassword: secret,
		templates.VarMailSenderFrom:     `"Firefox accounts" <portcullis-app-fxapp@example.org>`,
	}
	for k, v := range want {
		if env[k] != v || v == "" {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
	fi, err := os.Stat(f.h.envPath("fxapp"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf(".env mode %v (%v)", fi.Mode(), err)
	}
	// Made by the enable before the first start (enableSender): that
	// start had it, so no restart is owed for it.
	if owedOf(f, "fxapp") != "" {
		t.Fatalf("a restart owed for the password the first start already had: %q", owedOf(f, "fxapp"))
	}
	// The password is masked like a secret and redacted from records.
	if !SecretEnvNames(f.h.Template("fxapp"))[templates.VarMailSenderPassword] {
		t.Fatal("the password isn't a secret env name")
	}
	if got := f.h.RedactErr("fxapp", errors.New("compose: "+secret)); strings.Contains(got, secret) {
		t.Fatalf("not redacted: %s", got)
	}
	// The audit names the key only.
	a := f.h.audit.(*fakeAudit)
	found := false
	a.mu.Lock()
	entries := slices.Clone(a.entries)
	a.mu.Unlock()
	for _, x := range entries {
		if strings.Contains(x.Detail+x.Error+x.Target, secret) {
			t.Fatal("a password in the audit")
		}
		found = found || (x.Action == "mail_sender.created" && x.Target == "fxapp")
	}
	if !found {
		t.Fatal("mail_sender.created not audited")
	}
	// The next pass keeps the password (no new credential, no restart).
	clearOwed(f, "fxapp")
	n := len(f.mc.Created)
	f.sync(t)
	if len(f.mc.Created) != n || owedOf(f, "fxapp") != "" {
		t.Fatalf("an unchanged pass created %d passwords (owed %q)", len(f.mc.Created)-n, owedOf(f, "fxapp"))
	}
	// A password the provider no longer holds (a restore of the
	// provider) is replaced by the background reconcile.
	f.mc.DropCreds("portcullis-app-fxapp")
	later := f.now.Add(time.Minute)
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.RestoredAt = &later })
	f.advance(mailRestoreEvery)
	f.sync(t)
	if len(f.mc.Creds("portcullis-app-fxapp")) != 1 || len(f.mc.Created) <= n || senderDotEnv(t, f, "fxapp")[templates.VarMailSenderPassword] != lastSecret(f, "portcullis-app-fxapp") || owedOf(f, "fxapp") != settings.EffectRestart {
		t.Fatalf("the lost password wasn't replaced: %+v, %d docs", f.mc.Creds("portcullis-app-fxapp"), f.mc.Puts())
	}
}

func TestSenderEnvUnwired(t *testing.T) {
	f := newSenderFixture(t)
	f.h.mu.Lock()
	f.h.st.Mail.Provider = nil
	f.h.mu.Unlock()
	f.h.mu.Lock()
	tp := f.h.findLocked("fxapp")
	err := f.h.refreshInstanceEnvLocked(tp, nil)
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	env := readEnvRaw(f.h.envPath("fxapp"))
	for _, k := range templates.MailSenderVars {
		if v, ok := env[k]; !ok || v != "" {
			t.Errorf("%s = %q (present %v), want present and empty", k, v, ok)
		}
	}
	f.h.mu.RLock()
	unwired, on := f.h.mailSendersUnwiredLocked(true), f.h.mailSendersUnwiredLocked(false)
	f.h.mu.RUnlock()
	if !slices.Equal(unwired, []string{"fxapp"}) || !slices.Equal(on, []string{"fxapp"}) {
		t.Fatalf("unwired %v / mail off %v", unwired, on)
	}
	// Wired and on: no finding.
	f.h.mu.Lock()
	f.h.st.Mail.Provider = &state.MailProvider{Instance: mailProviderID}
	wired := f.h.mailSendersUnwiredLocked(true)
	f.h.mu.Unlock()
	if len(wired) != 0 {
		t.Fatalf("wired: %v", wired)
	}
	rep := doctor.Run(&doctor.Inputs{MailSendersUnwired: unwired}, nil)
	var hit []doctor.Finding
	for _, x := range rep.Findings {
		if x.Kind == doctor.KindMailSenderUnwired {
			hit = append(hit, x)
		}
	}
	if len(hit) != 1 || hit[0].Severity != doctor.Warning || !strings.Contains(hit[0].Title, "fxapp") || hit[0].Steps[0] != doctor.MailSenderUnwiredStep {
		t.Fatalf("findings %+v", hit)
	}
}

func TestSenderVoidedOnSwitch(t *testing.T) {
	f := newSenderFixture(t)
	f.sync(t)
	old := senderEntry(f, "fxapp")
	oldHub := senderEntry(f, state.MailSenderHub)
	oldPW := senderDotEnv(t, f, "fxapp")[templates.VarMailSenderPassword]
	if old.CredentialID == "" || oldPW == "" {
		t.Fatal("no first credential")
	}
	clearOwed(f, "fxapp")
	// A switch owes a void (wire), which the provider runs.
	f.h.mu.Lock()
	f.h.raiseVoidDebtLocked(state.MailVoidWire)
	empty := len(f.h.st.MailSenders) == 0
	f.h.saveLocked()
	f.h.mu.Unlock()
	if !empty {
		t.Fatal("the void kept the senders")
	}
	if v := senderDotEnv(t, f, "fxapp")[templates.VarMailSenderPassword]; v != "" {
		t.Fatalf("the old password stays in the .env: %q", v)
	}
	f.h.mu.RLock()
	vals, err := f.h.senderPasswordsLocked()
	f.h.mu.RUnlock()
	if err != nil || len(vals) != 0 {
		t.Fatalf("stored passwords %d (%v)", len(vals), err)
	}
	f.mc.DropCreds("portcullis-app-fxapp")
	f.mc.DropCreds("portcullis-hub-mail")
	f.h.mu.Lock()
	f.h.st.Mail.VoidOwed = nil
	f.h.mu.Unlock()
	f.sync(t)
	now := senderEntry(f, "fxapp")
	if now.UUID == old.UUID || senderEntry(f, state.MailSenderHub).UUID == oldHub.UUID || !v4Re.MatchString(now.UUID) {
		t.Fatal("the void kept the uuids")
	}
	c := f.mc.Creds("portcullis-app-fxapp")
	if len(c) != 1 || c[0].UUID != now.UUID {
		t.Fatalf("new credentials %+v", c)
	}
	if pw := senderDotEnv(t, f, "fxapp")[templates.VarMailSenderPassword]; pw == "" || pw != lastSecret(f, "portcullis-app-fxapp") || len(f.mc.Created) < 4 {
		t.Fatalf("the new password isn't in the .env: %q", pw)
	}
	if owedOf(f, "fxapp") != settings.EffectRestart {
		t.Fatal("no restart queued")
	}
}

// lastSecret is the last password the fake created for user.
func lastSecret(f *mailFixture, user string) string {
	out := ""
	f.mc.Lock(func(s *mailprovidertest.Server) {
		for _, x := range s.Created {
			if strings.HasPrefix(x, "mailpw-"+user+"-") {
				out = x
			}
		}
	})
	return out
}

func TestSenderVoidedOnRestore(t *testing.T) {
	f := newSenderFixture(t)
	f.sync(t)
	old := senderEntry(f, "fxapp")
	f.h.mu.Lock()
	err := f.h.markVoidOwedLocked(state.MailVoidRestore)
	n := len(f.h.st.MailSenders)
	f.h.mu.Unlock()
	if err != nil || n != 0 {
		t.Fatalf("restore void: %v, %d senders left", err, n)
	}
	if v := senderDotEnv(t, f, "fxapp")[templates.VarMailSenderPassword]; v != "" {
		t.Fatal("the restore left the password in the .env")
	}
	f.mc.DropCreds("portcullis-app-fxapp")
	f.h.mu.Lock()
	f.h.st.Mail.VoidOwed = nil
	f.h.mu.Unlock()
	f.sync(t)
	if e := senderEntry(f, "fxapp"); e.UUID == old.UUID || e.CredentialID == "" {
		t.Fatalf("after the restore: %+v (was %+v)", e, old)
	}
	// An unwire drops them too.
	f.h.mu.Lock()
	f.h.voidSendersLocked()
	f.h.mu.Unlock()
	if v := senderDotEnv(t, f, "fxapp")[templates.VarMailSenderUser]; v != "" {
		t.Fatal("unwired: the sender variables aren't empty")
	}
}

func TestSenderNoMailboxLeak(t *testing.T) {
	f := newSenderFixture(t)
	f.sync(t)
	doc := f.mc.Last()
	for _, a := range doc.Accounts {
		if strings.HasPrefix(a.Username, "portcullis-") {
			t.Fatalf("a sender in accounts: %+v", a)
		}
	}
	for _, p := range doc.Postmaster {
		if strings.HasPrefix(p, "portcullis-") {
			t.Fatal("a sender is a postmaster")
		}
	}
	if _, err := f.h.MyMail(context.Background(), "portcullis-hub-mail"); err == nil {
		t.Fatal("MyMail answers for the Hub's sender")
	}
	if rows := f.h.MailPasswords("portcullis-app-fxapp", senderEntry(f, "fxapp").UUID); len(rows) != 0 {
		t.Fatalf("a sender has mail password rows: %+v", rows)
	}
	// portcullis-* usernames are the senders': a person created with one
	// (straight in LLDAP) gets no mailbox, and the sender stays.
	in := mailInput(mailMembership())
	in.Membership.Users["portcullis-hub-mail"] = map[string]int{"mail_users": 1}
	g := in.Membership.Groups["mail_users"]
	g.Members = append(g.Members, "portcullis-hub-mail")
	in.Membership.Groups["mail_users"] = g
	in.Membership.UUIDs["portcullis-hub-mail"] = "12345678-2222-4333-8444-555555555555"
	in.Senders = []mailprovider.Sender{{Username: "portcullis-hub-mail", UUID: "1a2b3c4d-5e6f-4a7b-9c0d-1e2f3a4b5c6d"},
		{Username: "portcullis-app-x", UUID: "12345678-2222-4333-8444-555555555555"}}
	d, _ := BuildMailState(in)
	if d == nil || d.Senders == nil || len(*d.Senders) != 2 || (*d.Senders)[0].Username != "portcullis-hub-mail" {
		t.Fatalf("senders %+v", d.Senders)
	}
	for _, a := range d.Accounts {
		if a.Username == "portcullis-hub-mail" {
			t.Fatal("a person named portcullis-hub-mail got a mailbox")
		}
	}
	// A sender colliding with a person's uuid is still left out.
	in.Senders = []mailprovider.Sender{{Username: "portcullis-app-y", UUID: uuidAlice}}
	if d, _ = BuildMailState(in); len(*d.Senders) != 0 {
		t.Fatalf("a sender on alice's uuid: %+v", *d.Senders)
	}
	// No sender at all: present and empty, never null.
	in = mailInput(mailMembership())
	d, _ = BuildMailState(in)
	if d.Senders == nil || len(*d.Senders) != 0 {
		t.Fatalf("senders %+v", d.Senders)
	}
}

func TestSendHubMailUnwired(t *testing.T) {
	f := newSenderFixtureOff(t)
	if err := f.h.SendHubMail(context.Background(), "alice@example.org", "x", "y"); err != ErrNoHubSender {
		t.Fatalf("no credential yet: %v", err)
	}
	f.sync(t)
	if err := f.h.Enable("fxapp"); err != nil {
		t.Fatal(err)
	}
	setCoreMail(t, f.fixture, false)
	if err := f.h.SendHubMail(context.Background(), "alice@example.org", "x", "y"); err != ErrNoHubSender {
		t.Fatalf("mail off: %v", err)
	}
	setCoreMail(t, f.fixture, true)
	f.h.mu.Lock()
	f.h.st.Mail.Provider = nil
	f.h.mu.Unlock()
	if err := f.h.SendHubMail(context.Background(), "alice@example.org", "x", "y"); err != ErrNoHubSender {
		t.Fatalf("unwired: %v", err)
	}
}

// The Hub's own sender is never an app's (security review): its key is
// no id, an id "hub" is refused, and nothing an app's id reaches reads or
// writes it.
func TestSenderHubKeyNotAnApp(t *testing.T) {
	f := newSenderFixture(t)
	f.sync(t)
	if err := f.h.CreateInstance("fxapp", "hub", nil); err == nil {
		t.Fatal("an instance named hub was created")
	}
	if templates.ValidID(state.MailSenderHub) || templates.InstanceIDRe.MatchString(state.MailSenderHub) {
		t.Fatalf("the Hub's sender key %q is a valid id", state.MailSenderHub)
	}
	f.h.mu.Lock()
	hub := f.h.storedSenderLocked(state.MailSenderHub)
	if hub == nil || hub.Password == "" {
		f.h.mu.Unlock()
		t.Fatal("no Hub sender password")
	}
	// Defence in depth: an entry and a password under "hub" (a hand
	// edit) and a view with id "hub" reach none of it.
	f.h.st.MailSenders["hub"] = f.h.st.MailSenders[state.MailSenderHub]
	vals, _ := f.h.senderPasswordsLocked()
	vals["hub"] = hub.Password
	if err := f.h.writeSenderPasswordsLocked(vals); err != nil {
		f.h.mu.Unlock()
		t.Fatal(err)
	}
	got := f.h.storedSenderLocked("hub")
	view := templates.Template{ID: "hub", Manifest: templates.Manifest{MailSender: &templates.MailSender{Label: "X"}}}
	env := f.h.senderEnvForLocked(&view)
	_, wanted := f.h.senderWantedLocked()["hub"]
	f.h.mu.Unlock()
	if got != nil || wanted {
		t.Fatalf("the id hub reached a sender: %+v (wanted %v)", got, wanted)
	}
	for _, k := range templates.MailSenderVars {
		if v, ok := env[k]; !ok || v != "" {
			t.Errorf("%s = %q for the id hub", k, v)
		}
	}
	// No app .env ever holds the Hub sender's password.
	es, err := os.ReadDir(filepath.Join(f.data, "env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		b, _ := os.ReadFile(filepath.Join(f.data, "env", e.Name()))
		if strings.Contains(string(b), hub.Password) {
			t.Fatalf("%s holds the Hub sender's password", e.Name())
		}
	}
}

// Fix round 1: no sender variable without mail_sender (a template update
// dropping it removes all five), FROM is an RFC 5322 name-addr, the
// sender set kicks the mail sync, nothing unwired on Kubernetes, the
// Hub's own sender only while mail is on.
func TestSenderEnvDroppedWithMailSender(t *testing.T) {
	f := newSenderFixture(t)
	f.sync(t)
	if senderDotEnv(t, f, "fxapp")[templates.VarMailSenderPassword] == "" {
		t.Fatal("no password first")
	}
	select {
	case <-f.h.mailKick:
	default:
	}
	writeFile(t, filepath.Join(f.src, "fxapp", "manifest.yaml"), strings.Replace(senderAppManifest, "mail_sender:\n  label: Firefox accounts\n", "", 1))
	f.h.Discover()
	if f.h.Template("fxapp").Manifest.MailSender != nil {
		t.Fatal("the template still has mail_sender")
	}
	select {
	case <-f.h.mailKick:
	default:
		t.Fatal("dropping mail_sender didn't kick the mail sync")
	}
	f.h.mu.Lock()
	tp := f.h.findLocked("fxapp")
	err := f.h.refreshInstanceEnvLocked(tp, nil)
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.h.envPath("fxapp"))
	if strings.Contains(string(b), templates.VarMailSenderPrefix) {
		t.Fatalf("refresh kept sender variables:\n%s", b)
	}
	// A full write keeps none either (an old line put back by hand).
	f.h.mu.Lock()
	setEnvVar(f.h.envPath("fxapp"), templates.VarMailSenderPassword, "stale")
	err = f.h.generateAppEnvLocked(f.h.findLocked("fxapp"), nil)
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(f.h.envPath("fxapp"))
	if strings.Contains(string(b), templates.VarMailSenderPrefix) {
		t.Fatalf("generate kept sender variables:\n%s", b)
	}
	// The next document drops the sender.
	f.sync(t)
	for _, s := range *f.mc.Last().Senders {
		if s.Username == "portcullis-app-fxapp" {
			t.Fatal("the sender stays after mail_sender went")
		}
	}
}

func TestSenderFromNameAddr(t *testing.T) {
	s := &storedSender{Address: "portcullis-app-x@example.org", Password: "pw"}
	mc := mailCoreEnv{On: true, Hostname: "mail.example.org"}
	for _, label := range []string{"Firefox, accounts", `The "best" <app>`, "Café"} {
		if p := templates.MailSenderLabelProblem(label); p != "" {
			t.Fatalf("%q refused: %s", label, p)
		}
		from := senderEnv("x", s, mc, label)[templates.VarMailSenderFrom]
		var dec netmail.AddressParser
		as, err := dec.ParseList(from)
		if err != nil || len(as) != 1 || as[0].Address != s.Address || as[0].Name != label {
			t.Errorf("%q: FROM %q parses as %+v (%v)", label, from, as, err)
		}
		if _, err := envQuote(from); err != nil {
			t.Errorf("%q: FROM %q can't be written to an .env: %v", label, from, err)
		}
	}
	for _, label := range []string{"it's", `back\slash`} {
		if templates.MailSenderLabelProblem(label) == "" {
			t.Errorf("%q accepted", label)
		}
	}
}

func TestSenderKicksAndGates(t *testing.T) {
	f := newSenderFixture(t)
	drain := func() bool {
		select {
		case <-f.h.mailKick:
			return true
		default:
			return false
		}
	}
	drain()
	if err := f.h.Enable("fxoff"); err != nil {
		t.Fatal(err)
	}
	if !drain() {
		t.Fatal("enabling a sender instance didn't kick the mail sync")
	}
	f.h.mu.Lock()
	f.h.rebuildLocked()
	f.h.mu.Unlock()
	if drain() {
		t.Fatal("an unchanged rebuild kicked the mail sync")
	}
	if err := f.h.Disable("fxoff"); err != nil {
		t.Fatal(err)
	}
	if !drain() {
		t.Fatal("disabling a sender instance didn't kick the mail sync")
	}
	// The Hub's own sender only while mail is on.
	setCoreMail(t, f.fixture, false)
	f.h.mu.RLock()
	_, hub := f.h.senderWantedLocked()[state.MailSenderHub]
	f.h.mu.RUnlock()
	if hub {
		t.Fatal("the Hub's sender is wanted with mail off")
	}
	// Kubernetes: mail can't be wired, mail_sender_unwired never fires.
	f.setRuntime(runtime.KindKubernetes)
	f.h.mu.RLock()
	got := f.h.mailSendersUnwiredLocked(false)
	f.h.mu.RUnlock()
	if len(got) != 0 {
		t.Fatalf("unwired on Kubernetes: %v", got)
	}
}

// The first start of a mail_sender instance already has its sender
// (§19.14, enableSender): an app that refuses to start without the five
// PORTCULLIS_MAIL_SENDER_* values (firefox-sync-fxa's fxa-mail-check)
// could otherwise never be enabled, since senders exist only for enabled
// instances. Mail off: nothing is waited for (the app decides). A
// provider that gives no password: the enable fails before any start and
// the instance stays disabled, with no sender wanted.
func TestSenderReadyAtFirstStart(t *testing.T) {
	f := newSenderFixtureOff(t)
	atUp := map[string]map[string]string{}
	up := f.runner.upHook
	f.runner.upHook = func(p string) {
		id := strings.TrimPrefix(p, ProjectPrefix)
		if _, seen := atUp[id]; !seen {
			atUp[id] = readEnvFile(f.h.envPath(id))
		}
		if up != nil {
			up(p)
		}
	}
	if err := f.h.Enable("fxapp"); err != nil {
		t.Fatal(err)
	}
	env := atUp["fxapp"]
	if env == nil {
		t.Fatal("fxapp never started")
	}
	if env[templates.VarMailSenderHost] != "mail.example.org" || env[templates.VarMailSenderUser] != "portcullis-app-fxapp@example.org" ||
		env[templates.VarMailSenderPassword] == "" || env[templates.VarMailSenderPassword] != lastSecret(f, "portcullis-app-fxapp") {
		t.Fatalf("the first start's sender values: host %q user %q password set %v", env[templates.VarMailSenderHost],
			env[templates.VarMailSenderUser], env[templates.VarMailSenderPassword] != "")
	}
	if !f.h.IsEnabled("fxapp") || owedOf(f, "fxapp") != "" {
		t.Fatalf("enabled %v, owed %q", f.h.IsEnabled("fxapp"), owedOf(f, "fxapp"))
	}
	f.h.mu.RLock()
	pending := len(f.h.senderEnabling)
	f.h.mu.RUnlock()
	if pending != 0 {
		t.Fatalf("senderEnabling kept %d entries", pending)
	}
	// Kept as an enabled instance's sender.
	f.sync(t)
	if got := f.mc.Creds("portcullis-app-fxapp"); len(got) != 1 {
		t.Fatalf("after the next pass: %+v", got)
	}

	// Mail off: started at once with the five empty.
	setCoreMail(t, f.fixture, false)
	if err := f.h.Enable("fxoff"); err != nil {
		t.Fatal(err)
	}
	if env := atUp["fxoff"]; env == nil || env[templates.VarMailSenderPassword] != "" || env[templates.VarMailSenderHost] != "" {
		t.Fatalf("fxoff with mail off: %v", env)
	}
}

func TestSenderNotReadyRefusesEnable(t *testing.T) {
	defer func(w, p time.Duration) { senderEnableWait, senderEnablePoll = w, p }(senderEnableWait, senderEnablePoll)
	senderEnableWait, senderEnablePoll = 300*time.Millisecond, 20*time.Millisecond
	f := newSenderFixtureOff(t)
	started := false
	f.runner.upHook = func(p string) { started = started || p == ProjectPrefix+"fxapp" }
	f.mc.Close() // the provider answers nothing
	err := f.h.Enable("fxapp")
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 503 || !strings.Contains(err.Error(), "portcullis-app-fxapp") {
		t.Fatalf("enable with no sender password: %v", err)
	}
	if started || f.h.IsEnabled("fxapp") {
		t.Fatalf("started %v, enabled %v", started, f.h.IsEnabled("fxapp"))
	}
	f.h.mu.RLock()
	_, wanted := f.h.senderWantedLocked()["fxapp"]
	f.h.mu.RUnlock()
	if wanted {
		t.Fatal("the failed enable's sender is still wanted")
	}
}
