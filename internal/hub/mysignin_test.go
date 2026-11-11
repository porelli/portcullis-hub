package hub

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/invite"
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

// TestMySignInMethodStates: six rows in canonical order; password off →
// off; browser_cert on and set with the certificate listed; passkeys
// listed for their kind; certificates unknown → unknown.
func TestMySignInMethodStates(t *testing.T) {
	later := time.Now().Add(100 * 24 * time.Hour)
	c := newCertFixture(t, invite.CertRecord{User: "alice", Serial: "0a:02", Kind: invite.KindBrowser, NotBefore: time.Now().Add(-30 * 24 * time.Hour), NotAfter: later})
	v, err := c.f.h.MySignInView(c.ctx, "ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if v.User != "alice" || len(v.Methods) != 6 {
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
	for _, u := range []string{"admin", "portcullis-hub"} {
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
	// The plain FreshAccepted: a password proof counts under any[password].
	setPeopleRule(c.f, siLeaves("any", "password"))
	c.fa.method = "password"
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
