package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fidomds"
	"github.com/portcullis/hub/internal/fidomds/fidomdstest"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

func mineRow(v *MySignIn, m signin.Method) MethodRow {
	for _, r := range v.Methods {
		if r.ID == m {
			return r
		}
	}
	return MethodRow{}
}

// TestMySignInMethodStates: seven rows in canonical order; password off →
// off; browser_cert on and set with the certificate listed; passkeys
// listed for their kind; certificates unknown → unknown.
func TestMySignInMethodStates(t *testing.T) {
	later := time.Now().Add(100 * 24 * time.Hour)
	c := newCertFixture(t, invite.CertRecord{User: "alice", Serial: "0a:02", Kind: invite.KindBrowser, NotBefore: time.Now().Add(-30 * 24 * time.Hour), NotAfter: later})
	v, err := c.f.h.MySignInView(c.ctx, "ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if v.User != "alice" || len(v.Methods) != 7 {
		t.Fatalf("view = %+v", v)
	}
	for i, m := range signin.Methods {
		if v.Methods[i].ID != m {
			t.Errorf("row %d = %s, want %s", i, v.Methods[i].ID, m)
		}
	}
	want := map[signin.Method]string{signin.Password: MethodOff, signin.PasskeySynced: MethodNone, signin.BrowserCert: MethodSet,
		signin.PasskeyDevice: MethodNone, signin.SecurityKey: MethodSet, signin.YubiKeyCert: MethodNone}
	for m, s := range want {
		if r := mineRow(v, m); r.State != s {
			t.Errorf("%s = %s, want %s", m, r.State, s)
		}
	}
	if r := mineRow(v, signin.SecurityKey); len(r.Passkeys) != 1 || r.Passkeys[0].Kind != signin.SecurityKey {
		t.Errorf("security key passkeys = %+v", r.Passkeys)
	}
	if len(v.Certificates) != 1 || v.Certificates[0].Kind != "browser" || v.Certificates[0].Status != CertValid || v.ActiveBrowserCerts != 1 {
		t.Errorf("certificates = %+v (%d active)", v.Certificates, v.ActiveBrowserCerts)
	}
	if v.FreshAuth == nil || v.Limits.Effective.BrowserCertDays != 30 {
		t.Errorf("fresh auth %+v, limits %+v", v.FreshAuth, v.Limits)
	}
	// Certificates unknown: both certificate rows unknown, none listed.
	c.src.set(func(s *fakeSignInSrc) { s.certErr = errInventoryUnknown })
	c.f.h.MarkInventoryStale()
	v, _ = c.f.h.MySignInView(c.ctx, "alice")
	if mineRow(v, signin.BrowserCert).State != MethodUnknown || mineRow(v, signin.YubiKeyCert).State != MethodUnknown || len(v.Certificates) != 0 {
		t.Errorf("unknown certificates: %+v %+v", v.Methods, v.Certificates)
	}
	// A recorded password for this account is set once password is on.
	setSignIn(c.f, func(si *state.SignIn) {
		si.Methods["password"] = true
		si.Passwords["alice"] = state.PasswordRecord{SetAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), SetBy: "alice", UUID: "uuid-alice"}
	})
	c.f.h.MarkInventoryStale()
	v, _ = c.f.h.MySignInView(c.ctx, "alice")
	if r := mineRow(v, signin.Password); r.State != MethodSet || r.PasswordSetAt == nil {
		t.Errorf("password = %+v", r)
	}
}

// TestMySignInShowsRevoked: revoked, expired, 5 days left (expiring).
func TestMySignInShowsRevoked(t *testing.T) {
	now := time.Now()
	c := newCertFixture(t,
		invite.CertRecord{User: "alice", Serial: "01", Kind: invite.KindBrowser, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(20 * 24 * time.Hour), Revoked: true},
		invite.CertRecord{User: "alice", Serial: "02", Kind: invite.KindYubiKey, NotBefore: now.Add(-72 * time.Hour), NotAfter: now.Add(-time.Hour)},
		invite.CertRecord{User: "alice", Serial: "03", Kind: invite.KindBrowser, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(5 * 24 * time.Hour)},
		invite.CertRecord{User: "bob", Serial: "04", Kind: invite.KindBrowser, NotAfter: now.Add(20 * 24 * time.Hour)})
	v, err := c.f.h.MySignInView(c.ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range v.Certificates {
		got[r.Serial] = r.Status
	}
	if len(got) != 3 || got["01"] != CertRevoked || got["02"] != CertExpired || got["03"] != CertExpiring {
		t.Errorf("statuses = %v", got)
	}
	if v.ActiveBrowserCerts != 1 {
		t.Errorf("active = %d", v.ActiveBrowserCerts)
	}
}

// TestMySignInJSONNames: the snake_case names of the contract.
func TestMySignInJSONNames(t *testing.T) {
	c := newCertFixture(t, invite.CertRecord{User: "alice", Serial: "01", Kind: invite.KindBrowser, NotAfter: time.Now().Add(time.Hour)})
	setSignIn(c.f, func(si *state.SignIn) {
		si.Methods["password"] = true
		si.Passwords["alice"] = state.PasswordRecord{SetAt: time.Now(), SetBy: "alice", UUID: "uuid-alice"}
	})
	v, err := c.f.h.MySignInView(c.ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	for _, k := range []string{`"active_browser_certs":`, `"add_stronger":`, `"fresh_auth":`, `"password_set_at":`, `"not_before":`, `"not_after":`,
		`"ceiling_days":`, `"template_name":`, `"created_at":`, `"passkeys":`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("no %s in %s", k, b)
		}
	}
}

// TestMySignInApps: grafana (standard) for its users with ok; the core
// people page for everyone, hub (strong) only for administrators; ok
// nil while the inventory doesn't know the person.
func TestMySignInApps(t *testing.T) {
	c := newCertFixture(t)
	if err := c.f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	c.f.h.Wait()
	p := newFakePeople("alice", "bob", "zed")
	p.addGroup("users_grafana", "alice")
	p.addGroup(lldap.AdminGroup, "ann")
	c.src.set(func(s *fakeSignInSrc) {
		s.keys = map[string][]signin.Method{"alice": {signin.PasskeySynced}, "ann": {signin.SecurityKey}}
	})
	wireSignIn(c.f.h, p, c.src)
	apps := func(u string) map[string]AppNeed {
		v, err := c.f.h.MySignInView(c.ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]AppNeed{}
		for _, a := range v.Apps {
			out[a.Kind+":"+a.ID] = a
		}
		return out
	}
	a := apps("alice")
	if g := a["instance:grafana"]; g.Template != "standard" || g.TemplateName != "Standard" || g.OK == nil || !*g.OK || g.Score.Tenths == 0 {
		t.Errorf("alice grafana = %+v", g)
	}
	if pp := a["core:people"]; pp.Template != "strong" || pp.OK == nil || *pp.OK {
		t.Errorf("alice people = %+v", pp)
	}
	if _, ok := a["core:hub"]; ok || len(a) != 2 {
		t.Errorf("alice apps = %v", a)
	}
	n := apps("ann")
	if hb := n["core:hub"]; hb.Template != "strong" || hb.OK == nil || !*hb.OK {
		t.Errorf("ann hub = %+v", hb)
	}
	if _, ok := n["instance:grafana"]; ok {
		t.Error("ann sees grafana")
	}
	if z := apps("zed")["core:people"]; z.OK != nil {
		t.Errorf("zed (unknown to the inventory) = %+v", z)
	}
}

// fakeOwnPasswords is the directory's own-password side.
type fakeOwnPasswords struct {
	mu    sync.Mutex
	calls []string
	h     *Hub
}

func (f *fakeOwnPasswords) SetOwnPassword(_ context.Context, a directory.Actor, pw string) (*directory.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "set "+a.User)
	f.mu.Unlock()
	return &directory.Result{}, f.h.RecordPassword(a.User, "uuid-"+a.User, a.User)
}

func (f *fakeOwnPasswords) RemoveOwnPassword(_ context.Context, a directory.Actor) (*directory.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "remove "+a.User)
	f.mu.Unlock()
	return &directory.Result{}, nil
}

// TestOwnPasswordRules: off 409; CheckPassword 400; admin 409; the
// proof under the plain FreshAccepted (a password proof works when the
// people template takes passwords); the record set_by the caller; the
// removal drops it.
func TestOwnPasswordRules(t *testing.T) {
	c := newCertFixture(t)
	h := c.f.h
	op := &fakeOwnPasswords{h: h}
	h.SetOwnPasswords(op)
	const good = "correct horse battery staple 42"
	if err := h.SetOwnPassword(c.ctx, "alice", good, testProof); statusOf(err) != 409 || err.Error() != "password sign-in is off on this server" {
		t.Errorf("off: %v", err)
	}
	setSignIn(c.f, func(si *state.SignIn) { si.Methods["password"] = true })
	for _, bad := range []string{"short", "abcdefghijkl\x01mnop", strings.Repeat("x", 129)} {
		if err := h.SetOwnPassword(c.ctx, "alice", bad, testProof); statusOf(err) != 400 {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for _, u := range []string{"admin", "portcullis-hub", "portcullis-x"} {
		if err := h.SetOwnPassword(c.ctx, u, good, testProof); statusOf(err) != 409 || err.Error() != "Password sign-in isn't available for this account" {
			t.Errorf("%s set: %v", u, err)
		}
		if err := h.RemoveOwnPassword(c.ctx, u); statusOf(err) != 409 {
			t.Errorf("%s remove: %v", u, err)
		}
	}
	if c.fa.calls.Load() != 0 || len(op.calls) != 0 {
		t.Fatal("a refused change reached the proof or the directory")
	}
	if err := h.SetOwnPassword(c.ctx, "alice", good, testProof); err != nil {
		t.Fatal(err)
	}
	h.mu.RLock()
	rec := h.st.SignIn.Passwords["alice"]
	h.mu.RUnlock()
	if rec.SetBy != "alice" {
		t.Errorf("record = %+v", rec)
	}
	// A proof the template doesn't accept: 403.
	c.fa.method = "passkey_synced"
	if err := h.SetOwnPassword(c.ctx, "alice", good, testProof); statusOf(err) != 403 {
		t.Errorf("synced: %v", err)
	}
	if err := h.RemoveOwnPassword(c.ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	h.mu.RLock()
	_, still := h.st.SignIn.Passwords["alice"]
	h.mu.RUnlock()
	if still {
		t.Error("the record stayed after the removal")
	}
	if strings.Join(op.calls, ",") != "set alice,remove alice" {
		t.Errorf("directory calls %v", op.calls)
	}
}

// TestOwnPasswordFreshMethod (security review, fix round 1): a stolen
// browser certificate never sets a password; a password sign-in never
// adds the first one; it may change an existing one; a security key
// sets it. People's template accepts all three here.
func TestOwnPasswordFreshMethod(t *testing.T) {
	c := newCertFixture(t)
	h := c.f.h
	h.SetOwnPasswords(&fakeOwnPasswords{h: h})
	setSignIn(c.f, func(si *state.SignIn) { si.Methods["password"] = true })
	setPeopleRule(c.f, siLeaves("any", "browser_cert", "password", "security_key"))
	const good = "correct horse battery staple 42"
	c.fa.method = "browser_cert"
	if err := h.SetOwnPassword(c.ctx, "alice", good, testProof); statusOf(err) != 403 || err.Error() != "a fresh sign-in is required" {
		t.Errorf("browser_cert: %v", err)
	}
	if e := c.audit.last(); e.Action != "signin.password" || e.Result != "refused" || !strings.Contains(e.Detail, "browser_cert") {
		t.Errorf("audit = %+v", e)
	}
	c.fa.method = "password"
	if err := h.SetOwnPassword(c.ctx, "alice", good, testProof); statusOf(err) != 403 {
		t.Errorf("no password yet + password: %v", err)
	}
	c.fa.method = "security_key"
	if err := h.SetOwnPassword(c.ctx, "alice", good, testProof); err != nil {
		t.Fatalf("security_key: %v", err)
	}
	c.fa.method = "password"
	if err := h.SetOwnPassword(c.ctx, "alice", good+"!", testProof); err != nil {
		t.Errorf("existing password + password: %v", err)
	}
	// A record of an older account under the name counts as none.
	setSignIn(c.f, func(si *state.SignIn) {
		r := si.Passwords["alice"]
		r.UUID = "uuid-old"
		si.Passwords["alice"] = r
	})
	if err := h.SetOwnPassword(c.ctx, "alice", good, testProof); statusOf(err) != 403 {
		t.Errorf("stale record + password: %v", err)
	}
	// portcullis-* is refused with D13's text before any proof.
	calls := c.fa.calls.Load()
	if err := h.SetOwnPassword(c.ctx, "portcullis-x", good, testProof); statusOf(err) != 409 || err.Error() != "Password sign-in isn't available for this account" {
		t.Errorf("portcullis-x: %v", err)
	}
	if c.fa.calls.Load() != calls {
		t.Error("a proof was spent for portcullis-x")
	}
}

// TestMySignInPasskeyModel: a passkey's model is the FIDO list's
// description for its AAGUID ("" when the AAGUID is unknown), its id the
// credential id; the method labels are the plain names (one table).
func TestMySignInPasskeyModel(t *testing.T) {
	c := newCertFixture(t)
	const keyID = "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"
	c.src.set(func(s *fakeSignInSrc) {
		s.keys["alice"] = []signin.Method{signin.SecurityKey, signin.PasskeySynced}
		s.creds = map[string][]keycloak.PasskeyCredential{"alice": {
			{ID: keyID, Type: string(signin.SecurityKey), Label: "YubiKey", AAGUID: mdsKeyAAGUID},
			{ID: "0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d", Type: string(signin.PasskeySynced), Label: "iPhone"},
		}}
	})
	next := time.Now().AddDate(0, 1, 0)
	b, _ := json.Marshal(fidomdstest.Payload(3, next, fidomdstest.Entry(mdsKeyAAGUID, []string{"external"}, []string{"secure_element"}, "", fidomdstest.Reports("FIDO_CERTIFIED"))))
	var p metadata.PayloadJSON
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	d, _ := metadata.NewDecoder()
	m, err := d.Parse(&p)
	if err != nil {
		t.Fatal(err)
	}
	c.f.h.setMDS(m, &fidomds.Status{Serial: 3, NextUpdate: next})
	c.f.h.MarkInventoryStale()
	v, err := c.f.h.MySignInView(c.ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if r := mineRow(v, signin.SecurityKey); len(r.Passkeys) != 1 || r.Passkeys[0].Model != "test "+mdsKeyAAGUID || r.Passkeys[0].ID != keyID || r.Passkeys[0].Label != "YubiKey" {
		t.Errorf("security key = %+v", r.Passkeys)
	}
	if r := mineRow(v, signin.PasskeySynced); len(r.Passkeys) != 1 || r.Passkeys[0].Model != "" {
		t.Errorf("synced = %+v", r.Passkeys)
	}
	labels := map[signin.Method]string{signin.Password: "Password", signin.TOTP: "Authenticator app", signin.PasskeySynced: "Synced passkey", signin.BrowserCert: "Browser certificate",
		signin.PasskeyDevice: "Device-bound passkey", signin.SecurityKey: "Security key", signin.YubiKeyCert: "YubiKey certificate"}
	for _, r := range v.Methods {
		if r.Label != labels[r.ID] {
			t.Errorf("%s label = %q, want %q", r.ID, r.Label, labels[r.ID])
		}
	}
	js, _ := json.Marshal(mineRow(v, signin.SecurityKey).Passkeys[0])
	for _, k := range []string{`"id":`, `"model":`} {
		if !strings.Contains(string(js), k) {
			t.Errorf("no %s in %s", k, js)
		}
	}
}

// fakePasskeyLabels is SignInSources.PasskeyLabel: it records its calls,
// answers err, and on success renames the key in src's alice list.
type fakePasskeyLabels struct {
	mu    sync.Mutex
	calls []string
	err   error
	src   *fakeSignInSrc
}

func (f *fakePasskeyLabels) set(_ context.Context, user, id, label string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, user+" "+id+" "+label)
	if f.err != nil {
		return "", f.err
	}
	old := ""
	f.src.set(func(s *fakeSignInSrc) {
		for i, c := range s.creds[user] {
			if c.ID == id {
				old = c.Label
				s.creds[user][i].Label = label
			}
		}
	})
	return old, nil
}

func (f *fakePasskeyLabels) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

const renameKeyID = "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"

// renameFixture: alice has security key renameKeyID "YubiKey" and a
// synced "iPhone"; the rename source is wired.
func renameFixture(t *testing.T) (*certFixture, *fakePasskeyLabels) {
	t.Helper()
	c := newCertFixture(t)
	c.src.set(func(s *fakeSignInSrc) {
		s.keys["alice"] = []signin.Method{signin.SecurityKey, signin.PasskeySynced}
		s.creds = map[string][]keycloak.PasskeyCredential{"alice": {
			{ID: renameKeyID, Type: string(signin.SecurityKey), Label: "YubiKey"},
			{ID: "0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d", Type: string(signin.PasskeySynced), Label: "iPhone"},
		}}
	})
	pl := &fakePasskeyLabels{src: c.src}
	c.f.h.SetSignInSources(SignInSources{Passkeys: c.src.passkeys, Certificates: c.src.certificates, PasskeyLabel: pl.set})
	return c, pl
}

// TestRenameOwnPasskey: the label trimmed, checked (400, no call), the
// source's answers mapped (404 / 409 / 503), audited signin.passkey.label
// "<old> → <new>", refusals limited.
func TestRenameOwnPasskey(t *testing.T) {
	c, pl := renameFixture(t)
	h := c.f.h
	if err := h.RenameOwnPasskey(c.ctx, "alice", renameKeyID, "  Office key  "); err != nil {
		t.Fatal(err)
	}
	if strings.Join(pl.calls, ",") != "alice "+renameKeyID+" Office key" {
		t.Errorf("calls = %v", pl.calls)
	}
	if e := c.audit.last(); e.Action != "signin.passkey.label" || e.Target != "alice" || e.Detail != "YubiKey → Office key" || e.Result != "ok" || e.Actor != "alice" {
		t.Errorf("audit = %+v", e)
	}
	for _, bad := range []string{"", "   ", strings.Repeat("é", 65), "a\nb", "a\u202eb"} {
		err := h.RenameOwnPasskey(c.ctx, "alice", renameKeyID, bad)
		if statusOf(err) != 400 || err.Error() != "a passkey name is 1–64 characters on one line" {
			t.Errorf("%q: %v", bad, err)
		}
		if e := c.audit.last(); e.Action != "signin.passkey.label" || e.Result != "refused" || e.Detail != "credential "+renameKeyID {
			t.Errorf("%q audit = %+v", bad, e)
		}
	}
	if pl.n() != 1 {
		t.Errorf("a refused label reached the source: %v", pl.calls)
	}
	// Not a canonical UUID: 404 without a call, audited as invalid (own
	// fixture: these refusals would trip the limit).
	c3, pl3 := renameFixture(t)
	for _, id := range []string{strings.Repeat("é", 64), "deadbeef", "abc-def", "6f1c2a9e3b4d4e5f8a7b1c2d3e4f5a6b", "{" + renameKeyID + "}", "urn:uuid:" + renameKeyID, "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6g"} {
		if err := c3.f.h.RenameOwnPasskey(c3.ctx, "alice", id, "Fine"); statusOf(err) != 404 || err.Error() != "no such passkey" {
			t.Errorf("non-UUID id %q: %v", id, err)
		}
		if e := c3.audit.last(); e.Result != "refused" || e.Detail != "credential (invalid)" {
			t.Errorf("non-UUID id %q audit = %+v", id, e)
		}
	}
	if pl3.n() != 0 {
		t.Error("a non-UUID id reached the source")
	}
	for _, se := range []struct {
		err    error
		status int
		text   string
	}{
		{keycloak.ErrPasskeyNotFound, 404, "no such passkey"},
		{keycloak.ErrUserNotFound, 404, "no such passkey"},
		{keycloak.ErrPasskeyLabelTaken, 409, "you already have a sign-in method named “iPhone”"},
		{errors.New("keycloak: connection refused"), 503, ""},
	} {
		pl.err = se.err
		err := h.RenameOwnPasskey(c.ctx, "alice", renameKeyID, "iPhone")
		if statusOf(err) != se.status || (se.text != "" && err.Error() != se.text) || strings.Contains(err.Error(), "connection refused") {
			t.Errorf("%v: %v", se.err, err)
		}
	}
	pl.err = nil
	// No source: 503.
	h.SetSignInSources(SignInSources{Passkeys: c.src.passkeys, Certificates: c.src.certificates})
	if err := h.RenameOwnPasskey(c.ctx, "alice", renameKeyID, "X"); statusOf(err) != 503 {
		t.Errorf("no source: %v", err)
	}
	// Ten refusals in a minute, then 429.
	c2, _ := renameFixture(t)
	for i := 0; i < 10; i++ {
		if err := c2.f.h.RenameOwnPasskey(c2.ctx, "alice", renameKeyID, ""); statusOf(err) != 400 {
			t.Fatalf("refusal %d: %v", i, err)
		}
	}
	if err := c2.f.h.RenameOwnPasskey(c2.ctx, "alice", renameKeyID, "Fine"); !errors.Is(err, errEntryLimited) {
		t.Errorf("11th: %v, want errEntryLimited", err)
	}
}

// TestRenameOwnPasskeyFreshView: the view right after a rename shows the
// new name (MarkInventoryStale: the 30 s cache doesn't serve the old).
func TestRenameOwnPasskeyFreshView(t *testing.T) {
	c, _ := renameFixture(t)
	h := c.f.h
	h.MarkInventoryStale()
	v, err := h.MySignInView(c.ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if r := mineRow(v, signin.SecurityKey); len(r.Passkeys) != 1 || r.Passkeys[0].Label != "YubiKey" {
		t.Fatalf("before = %+v", r.Passkeys)
	}
	if err := h.RenameOwnPasskey(c.ctx, "alice", renameKeyID, "Office key"); err != nil {
		t.Fatal(err)
	}
	v, _ = h.MySignInView(c.ctx, "alice")
	if r := mineRow(v, signin.SecurityKey); len(r.Passkeys) != 1 || r.Passkeys[0].Label != "Office key" {
		t.Errorf("after = %+v", r.Passkeys)
	}
}

// TestOwnPasswordFreshTOTP (T10): a fresh code never adds a first password
// (refused like a fresh password); it may change an existing one; a
// passkey adds one; a method id the allowlists don't name is refused.
func TestOwnPasswordFreshTOTP(t *testing.T) {
	c := newCertFixture(t)
	h := c.f.h
	h.SetOwnPasswords(&fakeOwnPasswords{h: h})
	setSignIn(c.f, func(si *state.SignIn) { si.Methods["password"] = true; si.Methods["totp"] = true })
	setPeopleRule(c.f, signin.Node{Op: "any", Items: []signin.Node{siLeaves("all", "password", "totp"), {Leaf: "passkey_synced"}}})
	const good = "correct horse battery staple 42"
	for _, m := range []string{"totp", "password", "sms"} {
		c.fa.method = m
		if err := h.SetOwnPassword(c.ctx, "alice", good, testProof); statusOf(err) != 403 || err.Error() != "a fresh sign-in is required" {
			t.Errorf("no password yet + %s: %v", m, err)
		}
		if e := c.audit.last(); e.Action != "signin.password" || e.Result != "refused" || !strings.Contains(e.Detail, "pc_fresh names") {
			t.Errorf("%s audit = %+v", m, e)
		}
	}
	h.mu.RLock()
	_, set := h.st.SignIn.Passwords["alice"]
	h.mu.RUnlock()
	if set {
		t.Fatal("a refused proof set a password")
	}
	c.fa.method = "passkey_synced"
	if err := h.SetOwnPassword(c.ctx, "alice", good, testProof); err != nil {
		t.Fatalf("passkey_synced: %v", err)
	}
	c.fa.method = "totp"
	if err := h.SetOwnPassword(c.ctx, "alice", good+"!", testProof); err != nil {
		t.Errorf("existing password + totp: %v", err)
	}
	c.fa.method = "sms"
	if err := h.SetOwnPassword(c.ctx, "alice", good, testProof); statusOf(err) != 403 {
		t.Errorf("existing password + sms: %v", err)
	}
}

func TestPasswordFreshAllowlist(t *testing.T) {
	for _, c := range []struct {
		m        signin.Method
		has, out bool
	}{
		{signin.SecurityKey, false, true}, {signin.PasskeySynced, false, true}, {signin.PasskeyDevice, false, true}, {signin.YubiKeyCert, false, true},
		{signin.TOTP, false, false}, {signin.Password, false, false}, {signin.BrowserCert, false, false}, {"sms", false, false},
		{signin.TOTP, true, true}, {signin.Password, true, true}, {signin.BrowserCert, true, false}, {"sms", true, false}, {"", true, false},
	} {
		if got := passwordFreshAllowed(c.m, func() bool { return c.has }); got != c.out {
			t.Errorf("%q (has password %v) = %v", c.m, c.has, got)
		}
	}
}

const (
	otpID1 = "11111111-1111-4111-8111-111111111111"
	otpID2 = "22222222-2222-4222-8222-222222222222"
)

// totpFixture: totp on; alice has a security key and two authenticator
// apps (listed newest first by the source).
func totpFixture(t *testing.T) *certFixture {
	t.Helper()
	c := newCertFixture(t)
	setSignIn(c.f, func(si *state.SignIn) { si.Methods["totp"] = true })
	early := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	c.src.set(func(s *fakeSignInSrc) {
		s.keys["alice"] = []signin.Method{signin.SecurityKey, signin.TOTP}
		s.creds = map[string][]keycloak.PasskeyCredential{"alice": {
			{ID: renameKeyID, Type: string(signin.SecurityKey), Label: "YubiKey"},
			{ID: otpID2, Type: string(signin.TOTP), Label: "Tablet", Created: early.AddDate(0, 1, 0)},
			{ID: otpID1, Type: string(signin.TOTP), Label: "Phone", Created: early},
		}}
	})
	c.f.h.MarkInventoryStale()
	return c
}

// TestMySignInTOTPRow (T4, T18, P28): set with its rows sorted by
// created_at and max_authenticators 3; off → off, no rows; admin → none
// even with a credential.
func TestMySignInTOTPRow(t *testing.T) {
	c := totpFixture(t)
	v, err := c.f.h.MySignInView(c.ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	r := mineRow(v, signin.TOTP)
	if r.State != MethodSet || !r.On || r.Label != "Authenticator app" || len(r.Authenticators) != 2 ||
		r.Authenticators[0].ID != otpID1 || r.Authenticators[0].Label != "Phone" || r.Authenticators[1].Label != "Tablet" || r.Authenticators[0].CreatedAt.IsZero() {
		t.Errorf("totp row = %+v", r)
	}
	if len(r.Passkeys) != 0 || v.MaxAuthenticators != 3 || MaxAuthenticators != 3 {
		t.Errorf("passkeys %v, max %d", r.Passkeys, v.MaxAuthenticators)
	}
	if k := mineRow(v, signin.SecurityKey); len(k.Passkeys) != 1 {
		t.Errorf("security key row = %+v", k)
	}
	b, _ := json.Marshal(v)
	for _, k := range []string{`"authenticators":[{"id":"` + otpID1 + `","label":"Phone","created_at":`, `"max_authenticators":3`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("no %s in %s", k, b)
		}
	}
	setSignIn(c.f, func(si *state.SignIn) { si.Methods["totp"] = false })
	v, _ = c.f.h.MySignInView(c.ctx, "alice")
	if r := mineRow(v, signin.TOTP); r.State != MethodOff || r.Authenticators != nil {
		t.Errorf("off row = %+v", r)
	}
	// Unknown while Keycloak can't be read.
	setSignIn(c.f, func(si *state.SignIn) { si.Methods["totp"] = true })
	c.src.set(func(s *fakeSignInSrc) { s.down = true })
	c.f.h.MarkInventoryStale()
	v, _ = c.f.h.MySignInView(c.ctx, "alice")
	if r := mineRow(v, signin.TOTP); r.State != MethodUnknown {
		t.Errorf("down row = %+v", r)
	}
	// admin never has one.
	c2 := totpFixture(t)
	p := newFakePeople("alice", "admin")
	c2.src.set(func(s *fakeSignInSrc) {
		s.keys["admin"] = []signin.Method{signin.TOTP}
		s.creds["admin"] = []keycloak.PasskeyCredential{{ID: otpID1, Type: string(signin.TOTP), Label: "Phone"}}
	})
	wireSignIn(c2.f.h, p, c2.src)
	v, err = c2.f.h.MySignInView(c2.ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if r := mineRow(v, signin.TOTP); r.State != MethodNone || r.Authenticators != nil {
		t.Errorf("admin row = %+v", r)
	}
}

// TestRemoveImpactLastAuthenticator (T7): with one authenticator app, the
// apps whose ✓ turns ✗ without it; with two, none.
func TestRemoveImpactLastAuthenticator(t *testing.T) {
	c := totpFixture(t)
	h := c.f.h
	if err := h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	h.Wait()
	p := newFakePeople("alice", "bob")
	p.addGroup("users_grafana", "alice")
	setSignIn(c.f, func(si *state.SignIn) {
		si.Methods["password"] = true
		b := si.Templates["password-and-code"]
		b.Enabled = true
		si.Templates["password-and-code"] = b
		si.Passwords["alice"] = state.PasswordRecord{UUID: "uuid-alice", SetAt: time.Now(), SetBy: "alice"}
	})
	h.mu.Lock()
	in := h.st.Instances["grafana"]
	in.SignInTemplate = "password-and-code"
	h.st.Instances["grafana"] = in
	h.mu.Unlock()
	wireSignIn(h, p, c.src)
	one := func() {
		c.src.set(func(s *fakeSignInSrc) {
			s.creds["alice"] = s.creds["alice"][:2] // the key and one app
		})
	}
	v, err := h.MySignInView(c.ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	var g AppNeed
	for _, a := range v.Apps {
		if a.ID == "grafana" {
			g = a
		}
	}
	if g.Template != "password-and-code" || g.OK == nil || !*g.OK {
		t.Fatalf("grafana = %+v (password row %+v)", g, mineRow(v, signin.Password))
	}
	if r := mineRow(v, signin.TOTP); len(r.RemoveImpact) != 0 {
		t.Errorf("two apps: impact %v", r.RemoveImpact)
	}
	one()
	h.MarkInventoryStale()
	v, _ = h.MySignInView(c.ctx, "alice")
	r := mineRow(v, signin.TOTP)
	if len(r.Authenticators) != 1 || !slices.Equal(r.RemoveImpact, []string{g.Name}) {
		t.Errorf("one app: %+v", r)
	}
}

// TestInventoryTOTPReservedNeverCounted (T4): admin, portcullis-hub and
// every portcullis-* name never count an authenticator app.
func TestInventoryTOTPReservedNeverCounted(t *testing.T) {
	c := totpFixture(t)
	c.src.set(func(s *fakeSignInSrc) {
		for _, u := range []string{"admin", "portcullis-hub", "portcullis-x"} {
			s.keys[u] = []signin.Method{signin.TOTP, signin.SecurityKey}
		}
	})
	c.f.h.MarkInventoryStale()
	inv, err := c.f.h.SignInInventory(c.ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"admin", "portcullis-hub", "portcullis-x"} {
		if ms := inv.People[u].Methods; slices.Contains(ms, signin.TOTP) || !slices.Contains(ms, signin.SecurityKey) {
			t.Errorf("%s: %v", u, ms)
		}
	}
	if ms := inv.People["alice"].Methods; !slices.Contains(ms, signin.TOTP) {
		t.Errorf("alice: %v", ms)
	}
}

// fakeAuthLabels is SignInSources.AuthenticatorLabel.
type fakeAuthLabels struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeAuthLabels) set(_ context.Context, user, id, label string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, user+" "+id+" "+label)
	return "Phone", f.err
}

// TestRenameOwnAuthenticator (T6).
func TestRenameOwnAuthenticator(t *testing.T) {
	c := totpFixture(t)
	h := c.f.h
	al := &fakeAuthLabels{}
	h.SetSignInSources(SignInSources{Passkeys: c.src.passkeys, Certificates: c.src.certificates, AuthenticatorLabel: al.set})
	if err := h.RenameOwnAuthenticator(c.ctx, "alice", otpID1, "  Work phone "); err != nil {
		t.Fatal(err)
	}
	if strings.Join(al.calls, ",") != "alice "+otpID1+" Work phone" {
		t.Errorf("calls = %v", al.calls)
	}
	if e := c.audit.last(); e.Action != "signin.authenticator.label" || e.Target != "alice" || e.Detail != "Phone → Work phone" || e.Result != "ok" {
		t.Errorf("audit = %+v", e)
	}
	err := h.RenameOwnAuthenticator(c.ctx, "alice", otpID1, strings.Repeat("é", 65))
	if statusOf(err) != 400 || err.Error() != "an authenticator name is 1–64 characters on one line" {
		t.Errorf("65 runes: %v", err)
	}
	if e := c.audit.last(); e.Action != "signin.authenticator.label" || e.Result != "refused" {
		t.Errorf("refused audit = %+v", e)
	}
	for _, se := range []struct {
		err    error
		status int
		text   string
	}{
		{keycloak.ErrAuthenticatorNotFound, 404, "no such authenticator app"},
		{keycloak.ErrUserNotFound, 404, "no such authenticator app"},
		{keycloak.ErrPasskeyLabelTaken, 409, "you already have a sign-in method named “tablet”"},
		{errors.New("keycloak: connection refused"), 503, "authenticator names can't be changed right now: try again later"},
	} {
		al.mu.Lock()
		al.err = se.err
		al.mu.Unlock()
		err := h.RenameOwnAuthenticator(c.ctx, "alice", otpID1, "tablet")
		if statusOf(err) != se.status || err.Error() != se.text {
			t.Errorf("%v: %v", se.err, err)
		}
	}
	if err := h.RenameOwnAuthenticator(c.ctx, "alice", "nope", "X"); statusOf(err) != 404 || err.Error() != "no such authenticator app" {
		t.Errorf("non-UUID: %v", err)
	}
	h.SetSignInSources(SignInSources{Passkeys: c.src.passkeys})
	if err := h.RenameOwnAuthenticator(c.ctx, "alice", otpID1, "X"); statusOf(err) != 503 {
		t.Errorf("no source: %v", err)
	}
}

// TestRefreshMySignInThrottle (T5): at most one MarkInventoryStale per
// caller per 10 s.
func TestRefreshMySignInThrottle(t *testing.T) {
	c := newCertFixture(t)
	h := c.f.h
	now := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	h.entryNow = func() time.Time { return now }
	gen := func() uint64 {
		h.signInInv.mu.Lock()
		defer h.signInInv.mu.Unlock()
		return h.signInInv.gen
	}
	g0 := gen()
	h.RefreshMySignIn("alice")
	h.RefreshMySignIn("ALICE")
	if gen() != g0+1 {
		t.Errorf("two calls: %d marks", gen()-g0)
	}
	h.RefreshMySignIn("bob")
	if gen() != g0+2 {
		t.Errorf("another caller: %d marks", gen()-g0)
	}
	now = now.Add(10 * time.Second)
	h.RefreshMySignIn("alice")
	if gen() != g0+3 {
		t.Errorf("after 10 s: %d marks", gen()-g0)
	}
	h.RefreshMySignIn("")
	if gen() != g0+3 {
		t.Error("an empty user marked")
	}
}

// TestMySignInTOTPRowGuardAlone (review T7-L2): the row's own guard (P28)
// shows admin "none" even when the inventory lists a code for them (the
// loadInventory drop bypassed with a seeded cache); an ordinary person
// without an app is "none" too.
func TestMySignInTOTPRowGuardAlone(t *testing.T) {
	c := totpFixture(t)
	h := c.f.h
	p := newFakePeople("alice", "admin", "bob")
	wireSignIn(h, p, c.src)
	at := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	h.signInInv.now = func() time.Time { return at }
	h.signInInv.mu.Lock()
	h.signInInv.base = &invBase{at: at,
		passkeys: map[string][]signin.Method{"admin": {signin.TOTP}, "bob": {}},
		keys:     map[string][]keycloak.PasskeyCredential{"admin": {{ID: otpID1, Type: string(signin.TOTP), Label: "Phone"}}, "bob": {}},
		disabled: map[string]bool{}, certs: map[string][]signin.Method{}, uuids: map[string]string{}}
	h.signInInv.tried, h.signInInv.err = at, nil
	h.signInInv.mu.Unlock()
	for _, u := range []string{"admin", "bob"} {
		// The hand-made inventory stays: no forced re-read before a
		// fresh-auth refusal (freshRecheck) replaces it.
		h.freshRecheckT.allow(u, h.entryClock(), freshRecheckGap)
		v, err := h.MySignInView(c.ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		if r := mineRow(v, signin.TOTP); r.State != MethodNone || r.Authenticators != nil {
			t.Errorf("%s row = %+v", u, r)
		}
	}
}

// TestMaxAuthenticatorsMatchesContract (review T7-L5): the Hub's limit is
// the contract's (§5.1 / §8.1: "`max_authenticators` is
// `hub.MaxAuthenticators` (N)", "the limit of N"), which the extension's
// TotpRegister.MAX enforces; the keycloak repo pins the same text.
func TestMaxAuthenticatorsMatchesContract(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "web", "docs", "integration-contracts.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, want := range []string{
		"`max_authenticators` is `hub.MaxAuthenticators` (" + strconv.Itoa(MaxAuthenticators) + ")",
		"the limit of " + strconv.Itoa(MaxAuthenticators) + " ",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the contract doesn't say %q", want)
		}
	}
}
