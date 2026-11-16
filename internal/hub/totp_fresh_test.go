package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/confirm"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/signinhistory"
	"github.com/portcullis/hub/internal/state"
)

func allMethodsOn() map[signin.Method]bool {
	on := map[signin.Method]bool{}
	for _, m := range signin.Methods {
		on[m] = true
	}
	return on
}

// TestFreshPcMethodTOTPOnly (T9): "totp" only when the rule's fresh
// methods are exactly {totp}.
func TestFreshPcMethodTOTPOnly(t *testing.T) {
	on := allMethodsOn()
	for _, c := range []struct {
		rule signin.Node
		want string
	}{
		{siLeaves("all", "password", "totp"), "totp"},
		{signin.Node{Op: "any", Items: []signin.Node{{Leaf: "security_key"}, siLeaves("all", "password", "totp")}}, ""},
		{siLeaves("any", "security_key", "yubikey_cert"), ""},
		{siLeaves("any", "password"), ""},
		{siLeaves("all", "passkey_synced", "totp"), ""},
	} {
		compiled, err := signin.Compile(c.rule, on)
		if err != nil {
			t.Fatal(err)
		}
		if got := freshPcMethod(compiled, on); got != c.want {
			t.Errorf("%v: %q, want %q", c.rule, got, c.want)
		}
	}
	if got := freshPcMethod(signin.Node{}, on); got != "" {
		t.Errorf("no rule: %q", got)
	}
	// totp switched off: the rule doesn't compile; a stale compiled rule
	// never yields "totp".
	compiled, _ := signin.Compile(siLeaves("all", "password", "totp"), on)
	off := allMethodsOn()
	off[signin.TOTP] = false
	if got := freshPcMethod(compiled, off); got != "" {
		t.Errorf("totp off: %q", got)
	}
}

// totpPeople: password and totp on, the people page on password-and-code.
func totpPeople(t *testing.T) *certFixture {
	t.Helper()
	c := newCertFixture(t)
	setSignIn(c.f, func(si *state.SignIn) {
		si.Methods["password"], si.Methods["totp"] = true, true
		b := si.Templates["password-and-code"]
		b.Enabled = true
		si.Templates["password-and-code"] = b
		si.Core["people"] = "password-and-code"
	})
	return c
}

// TestCheckFreshAuthPasswordUnderPasswordAndCode: under all[password,
// totp] the proof must be the code; a password proof is 403.
func TestCheckFreshAuthPasswordUnderPasswordAndCode(t *testing.T) {
	c := totpPeople(t)
	h := c.f.h
	c.fa.method = "password"
	if _, reason, err := h.checkFreshAuth(c.ctx, govCore("people"), testProof, "alice"); statusOf(err) != 403 || !strings.Contains(reason, "doesn't accept") {
		t.Errorf("password: %v (%s)", err, reason)
	}
	c.fa.method = "totp"
	if r, _, err := h.checkFreshAuth(c.ctx, govCore("people"), testProof, "alice"); err != nil || r.Method != "totp" {
		t.Errorf("totp: %+v %v", r, err)
	}
	// MySignIn's popup: alice has only a key, which password-and-code
	// doesn't take: refused with the needs-stronger text (final review M1).
	v, err := h.MySignInView(c.ctx, "alice")
	if err != nil || v.FreshAuth == nil || v.FreshAuth.PcMethod != "" || v.FreshAuth.Refusal != freshNeedsStronger {
		t.Errorf("key-only view fresh_auth = %+v %v", v.FreshAuth, err)
	}
	// With a password and a code: the popup asks for the code.
	withPasswordAndCode(t, c, "alice")
	v, err = h.MySignInView(c.ctx, "alice")
	if err != nil || v.FreshAuth == nil || v.FreshAuth.PcMethod != "totp" || v.FreshAuth.Refusal != "" {
		t.Errorf("view fresh_auth = %+v %v", v.FreshAuth, err)
	}
	// The shared info is never changed (other views keep no pc_method).
	if info := h.FreshAuthInfo(); info != nil && info.PcMethod != "" {
		t.Errorf("shared info = %+v", info)
	}
	setSignIn(c.f, func(si *state.SignIn) { si.Core["people"] = "strong" })
	if v, _ := h.MySignInView(c.ctx, "alice"); v.FreshAuth == nil || v.FreshAuth.PcMethod != "" || v.FreshAuth.Refusal != freshNeedsStronger {
		t.Errorf("strong fresh_auth (alice has no key now) = %+v", v.FreshAuth)
	}
	b, _ := json.Marshal(freshauth.AuthorizeInfo{PcMethod: "totp"})
	if !strings.Contains(string(b), `"pc_method":"totp"`) {
		t.Errorf("json %s", b)
	}
	if b, _ := json.Marshal(freshauth.AuthorizeInfo{}); strings.Contains(string(b), "pc_method") {
		t.Errorf("empty json %s", b)
	}
}

// TestCertFreshNeverTOTP (T10, P20): a code never approves a certificate:
// people on password-and-code is 409 before any proof; where a security
// key would do, a code proof is 403.
func TestCertFreshNeverTOTP(t *testing.T) {
	c := totpPeople(t)
	h := c.f.h
	calls := c.fa.calls.Load()
	if _, err := h.CreateBrowserCertificate(c.ctx, "alice", 30, testProof); statusOf(err) != 409 ||
		err.Error() != "creating a certificate needs a passkey or YubiKey sign-in that people.example.org accepts" {
		t.Errorf("password-and-code: %v", err)
	}
	if c.fa.calls.Load() != calls {
		t.Error("the proof was spent")
	}
	if v, _ := h.MySignInView(c.ctx, "alice"); len(v.CertFresh) != 0 {
		t.Errorf("cert_fresh = %v", v.CertFresh)
	}
	setPeopleRule(c.f, signin.Node{Op: "any", Items: []signin.Node{siLeaves("all", "password", "totp"), {Leaf: "security_key"}}})
	c.fa.method = "totp"
	if _, err := h.CreateBrowserCertificate(c.ctx, "alice", 30, testProof); statusOf(err) != 403 {
		t.Errorf("totp proof: %v", err)
	}
	if e := c.audit.last(); e.Action != "cert.create" || e.Result != "refused" || !strings.Contains(e.Detail, "pc_fresh names totp, which can't add a certificate") {
		t.Errorf("audit = %+v", e)
	}
	if v, _ := h.MySignInView(c.ctx, "alice"); !slices.Equal(v.CertFresh, []signin.Method{signin.SecurityKey}) {
		t.Errorf("cert_fresh = %v", v.CertFresh)
	}
}

// TestSetOwnPasswordFreshTOTPNoPasswordYet (T10): a fresh code never adds
// the first password: 403, audited with the reason.
func TestSetOwnPasswordFreshTOTPNoPasswordYet(t *testing.T) {
	c := totpPeople(t)
	h := c.f.h
	h.SetOwnPasswords(&fakeOwnPasswords{h: h})
	c.fa.method = "totp"
	if err := h.SetOwnPassword(c.ctx, "alice", "correct horse battery staple 42", testProof); statusOf(err) != 403 || err.Error() != freshauth.Message {
		t.Errorf("totp: %v", err)
	}
	if e := c.audit.last(); e.Action != "signin.password" || e.Result != "refused" ||
		!strings.Contains(e.Detail, "pc_fresh names totp, but there is no password yet: adding one needs a passkey or YubiKey sign-in") {
		t.Errorf("audit = %+v", e)
	}
}

// TestCoreWarningPasswordAndCode (T17): a core pick with a password +
// code way in carries the warning; Strong none.
func TestCoreWarningPasswordAndCode(t *testing.T) {
	c := totpPeople(t)
	h := c.f.h
	const want = "The Hub can be opened with a password and a code: both can be phished"
	v, _ := h.SignInView(c.ctx)
	if v.CoreWarnings["people"] != want || v.CoreWarnings["hub"] != "" {
		t.Errorf("people pick = %v", v.CoreWarnings)
	}
	setSignIn(c.f, func(si *state.SignIn) { si.Core["hub"] = "password-and-code"; si.Core["people"] = "strong" })
	v, _ = h.SignInView(c.ctx)
	if v.CoreWarnings["hub"] != want || len(v.CoreWarnings) != 1 {
		t.Errorf("hub pick = %v", v.CoreWarnings)
	}
	// A key alternative beside it doesn't hide the password + code one.
	setSignIn(c.f, func(si *state.SignIn) {
		si.Templates["mixed"] = state.SignInTemplate{Name: "Mixed", Rule: signin.Node{Op: "any", Items: []signin.Node{{Leaf: "security_key"}, siLeaves("all", "password", "totp")}}, Enabled: true}
		si.Core["hub"] = "mixed"
	})
	if v, _ = h.SignInView(c.ctx); v.CoreWarnings["hub"] != want {
		t.Errorf("mixed = %v", v.CoreWarnings)
	}
	setSignIn(c.f, func(si *state.SignIn) { si.Core["hub"] = "strong" })
	v, _ = h.SignInView(c.ctx)
	if len(v.CoreWarnings) != 0 {
		t.Errorf("strong = %v", v.CoreWarnings)
	}
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), `"core_warnings":{}`) {
		t.Errorf("json: %s", b)
	}
}

// TestPreviewCodeOnlyPath (T2, P5): a code-only draft previews with 200,
// its problem and the group to mark.
func TestPreviewCodeOnlyPath(t *testing.T) {
	c := totpPeople(t)
	rule := signin.Node{Op: "any", Items: []signin.Node{{Leaf: "security_key"}, siLeaves("any", "totp", "passkey_synced")}}
	p, err := c.f.h.PreviewTemplate(c.ctx, "", TemplateInput{Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	if p.Problem != "an authenticator code can't be the only way in: combine it with another method (all of)" ||
		len(p.CodeOnly) != 1 || !slices.Equal(p.CodeOnly[0], signin.Path{1}) {
		t.Errorf("preview = %+v", p)
	}
	b, _ := json.Marshal(p)
	if !strings.Contains(string(b), `"code_only":[[1]]`) {
		t.Errorf("json %s", b)
	}
	// A fine draft: code_only [].
	p, _ = c.f.h.PreviewTemplate(c.ctx, "", TemplateInput{Rule: siLeaves("all", "password", "totp")})
	if p.Problem != "" || p.CodeOnly == nil || len(p.CodeOnly) != 0 {
		t.Errorf("fine = %+v", p)
	}
	// Any other invalid rule stays 400.
	if _, err := c.f.h.PreviewTemplate(c.ctx, "", TemplateInput{Rule: siLeaves("any", "bogus")}); statusOf(err) != 400 {
		t.Errorf("bogus: %v", err)
	}
}

// TestSaveTemplateCodeOnly400 (T2): a save with a code-only way in is
// 400 "rule: " + the text.
func TestSaveTemplateCodeOnly400(t *testing.T) {
	c := totpPeople(t)
	_, err := c.f.h.SaveTemplate(c.ctx, "codes", TemplateInput{Name: "Codes", Rule: siLeaves("any", "totp", "security_key")}, true, siAdmin)
	if statusOf(err) != 400 || err.Error() != "rule: an authenticator code can't be the only way in: combine it with another method (all of)" {
		t.Errorf("save: %v", err)
	}
}

// TestMyAppsFreshPcMethodPerApp (T9, P11): an app with credential cards
// carries fresh_pc_method from its own template; the top-level fresh_auth
// never carries pc_method.
func TestMyAppsFreshPcMethodPerApp(t *testing.T) {
	c := credSvcFixture(t)
	h := c.f.h
	v, err := h.MyApps(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if a := myApp(v.Apps, smbID); a == nil || len(a.Credentials) == 0 || a.FreshPcMethod != "" {
		t.Fatalf("default template: %+v", a)
	}
	setSignIn(c.f, func(si *state.SignIn) {
		si.Methods["password"], si.Methods["totp"] = true, true
		b := si.Templates["password-and-code"]
		b.Enabled = true
		si.Templates["password-and-code"] = b
	})
	h.mu.Lock()
	in := h.st.Instances[smbID]
	in.SignInTemplate = "password-and-code"
	h.st.Instances[smbID] = in
	h.mu.Unlock()
	v, _ = h.MyApps(context.Background(), "alice")
	if a := myApp(v.Apps, smbID); a == nil || a.FreshPcMethod != "totp" {
		t.Errorf("password-and-code: %+v", a)
	}
	if v.FreshAuth != nil && v.FreshAuth.PcMethod != "" {
		t.Errorf("top-level fresh_auth = %+v", v.FreshAuth)
	}
	b, _ := json.Marshal(myApp(v.Apps, smbID))
	if !strings.Contains(string(b), `"fresh_pc_method":"totp"`) {
		t.Errorf("json %s", b)
	}
}

// TestConfirmationPagePcMethod (T9): the confirmation page's popup asks
// for the code when its governing template (here the hub core page)
// accepts only a code.
func TestConfirmationPagePcMethod(t *testing.T) {
	c := totpPeople(t)
	h := c.f.h
	h.SetFreshAuth(ListenerHub, c.fa)
	setSignIn(c.f, func(si *state.SignIn) { si.Core["hub"] = "password-and-code" })
	cf, err := h.CreateConfirmation(directory.Actor{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude"}, confirm.Request{
		User: "root", Client: "portcullis-ai-claude", Resource: "https://hub.example.org/mcp", Tool: "delete_instance", ArgsSHA256: strings.Repeat("a", 64),
		ArgsPreview: `{}`, Listener: confirm.ListenerHub, Typed: "grafana", Label: "instance grafana"})
	if err != nil {
		t.Fatal(err)
	}
	// root has only a key: refused (final review M1).
	v, err := h.ConfirmationPage(context.Background(), ListenerHub, cf.ID, "root")
	if err != nil || v.FreshAuth == nil || v.FreshAuth.PcMethod != "" || v.FreshAuth.Refusal != freshNeedsStronger {
		t.Fatalf("key-only page = %+v %v", v.FreshAuth, err)
	}
	withPasswordAndCode(t, c, "root")
	if v, _ = h.ConfirmationPage(context.Background(), ListenerHub, cf.ID, "root"); v.FreshAuth == nil || v.FreshAuth.PcMethod != "totp" || v.FreshAuth.Refusal != "" {
		t.Errorf("password + code: %+v", v.FreshAuth)
	}
	// A key-or-code rule with root's key back: the key, no pc_method.
	c.src.set(func(s *fakeSignInSrc) { s.keys["root"] = []signin.Method{signin.SecurityKey, signin.TOTP} })
	c.f.h.MarkInventoryStale()
	setSignIn(c.f, func(si *state.SignIn) {
		si.Templates["mixed"] = state.SignInTemplate{Name: "Mixed", Rule: signin.Node{Op: "any", Items: []signin.Node{{Leaf: "security_key"}, siLeaves("all", "password", "totp")}}, Enabled: true}
		si.Core["hub"] = "mixed"
	})
	if v, _ = h.ConfirmationPage(context.Background(), ListenerHub, cf.ID, "root"); v.FreshAuth == nil || v.FreshAuth.PcMethod != "" || v.FreshAuth.Refusal != "" {
		t.Errorf("mixed with a key: %+v", v.FreshAuth)
	}
}

// TestLockoutGuardCountsTOTP: the only administrator has a password and
// an authenticator app: the Hub may go on password-and-code; without the
// app the same save is the guard's 409.
func TestLockoutGuardCountsTOTP(t *testing.T) {
	c := totpPeople(t)
	h := c.f.h
	p := newFakePeople("alice")
	p.addGroup(lldap.AdminGroup, "root")
	c.src.set(func(s *fakeSignInSrc) {
		s.keys = map[string][]signin.Method{"root": {signin.TOTP}, "alice": {signin.SecurityKey}}
		s.creds = nil
	})
	wireSignIn(h, p, c.src)
	if err := h.RecordPassword("root", p.uuidOf("root"), "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SetCoreTemplate(c.ctx, "hub", "password-and-code", siAdmin); err != nil {
		t.Fatalf("hub on password-and-code: %v", err)
	}
	// root swaps the app for a security key: Strong is met, and moving
	// the Hub back to password-and-code would leave no administrator.
	c.src.set(func(s *fakeSignInSrc) { s.keys["root"] = []signin.Method{signin.SecurityKey} })
	h.MarkInventoryStale()
	if _, err := h.SetCoreTemplate(c.ctx, "hub", "strong", siAdmin); err != nil {
		t.Fatalf("hub back on strong: %v", err)
	}
	_, err := h.SetCoreTemplate(c.ctx, "hub", "password-and-code", siAdmin)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "root") {
		t.Errorf("without the app: %v, want the guard's 409", err)
	}
}

// TestFreshPcForPerson (final review M1, ruling): pc_method per person —
// a method that meets the fresh rule on its own: as today (none); else a
// password + code way in the person has both of: "totp"; else the
// needs-stronger refusal. Unknown to the inventory: the rule alone.
func TestFreshPcForPerson(t *testing.T) {
	on := allMethodsOn()
	mixed := signin.Node{Op: "any", Items: []signin.Node{{Leaf: "security_key"}, siLeaves("all", "password", "totp")}}
	pac := siLeaves("all", "password", "totp")
	strong := siLeaves("any", "security_key", "yubikey_cert")
	basic := siLeaves("any", "family:passkey", "password")
	keyAndCode := siLeaves("all", "security_key", "totp")
	set := func(ms ...signin.Method) map[signin.Method]bool {
		out := map[signin.Method]bool{}
		for _, m := range ms {
			out[m] = true
		}
		return out
	}
	for _, c := range []struct {
		name    string
		rule    signin.Node
		has     map[signin.Method]bool
		known   bool
		pc      string
		refused bool
	}{
		{"mixed, a key", mixed, set(signin.SecurityKey, signin.Password, signin.TOTP), true, "", false},
		{"mixed, password + code", mixed, set(signin.Password, signin.TOTP), true, "totp", false},
		{"mixed, password only", mixed, set(signin.Password), true, "", true},
		{"mixed, code only", mixed, set(signin.TOTP), true, "", true},
		{"mixed, nothing", mixed, set(), true, "", true},
		{"password-and-code, both", pac, set(signin.Password, signin.TOTP), true, "totp", false},
		{"password-and-code, a key only", pac, set(signin.SecurityKey), true, "", true},
		{"strong, a key", strong, set(signin.SecurityKey), true, "", false},
		{"strong, password + code", strong, set(signin.Password, signin.TOTP), true, "", true},
		{"basic, a password", basic, set(signin.Password), true, "", false},
		{"key and code, both", keyAndCode, set(signin.SecurityKey, signin.TOTP), true, "", false},
		{"unknown person, password-and-code", pac, nil, false, "totp", false},
		{"unknown person, mixed", mixed, nil, false, "", false},
	} {
		compiled, err := signin.Compile(c.rule, on)
		if err != nil {
			t.Fatal(err)
		}
		pc, refusal := freshPcFor(compiled, on, c.has, c.known)
		if pc != c.pc || (refusal != "") != c.refused {
			t.Errorf("%s: pc %q, refusal %q", c.name, pc, refusal)
		}
		if c.refused && refusal != freshNeedsStronger {
			t.Errorf("%s: refusal text %q", c.name, refusal)
		}
	}
	// totp switched off: never "totp".
	off := allMethodsOn()
	off[signin.TOTP] = false
	compiled, _ := signin.Compile(mixed, off)
	if pc, _ := freshPcFor(compiled, off, set(signin.Password, signin.TOTP), true); pc != "" {
		t.Errorf("totp off: %q", pc)
	}
}

// withPasswordAndCode gives user (in c's fixture) a Hub-recorded password
// and an authenticator app in place of their other methods.
func withPasswordAndCode(t *testing.T, c *certFixture, user string) {
	t.Helper()
	p := newFakePeople("alice", "bob")
	p.addGroup(lldap.AdminGroup, "root", "ann")
	c.src.set(func(s *fakeSignInSrc) {
		s.keys[user] = []signin.Method{signin.TOTP}
		delete(s.creds, user)
	})
	wireSignIn(c.f.h, p, c.src)
	if err := c.f.h.RecordPassword(user, p.uuidOf(user), "root"); err != nil {
		t.Fatal(err)
	}
	c.f.h.MarkInventoryStale()
}

// recheckFixture: the people page on a key-only rule, alice known with
// no method, both clocks at *now; perPerson false wires no one-person
// source (a forced re-read is a full one).
func recheckFixture(t *testing.T, perPerson bool) (*certFixture, *time.Time) {
	t.Helper()
	c := newCertFixture(t)
	h := c.f.h
	if !perPerson {
		h.SetSignInSources(SignInSources{Passkeys: c.src.passkeys, Certificates: c.src.certificates})
	}
	setPeopleRule(c.f, siLeaves("any", "security_key"))
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	h.entryNow = clock
	h.signInInv.mu.Lock()
	h.signInInv.now = clock
	h.signInInv.mu.Unlock()
	c.src.set(func(s *fakeSignInSrc) { s.keys["alice"] = []signin.Method{} })
	h.MarkInventoryStale()
	return c, &now
}

func (c *certFixture) reads() (full, person int) {
	c.src.mu.Lock()
	defer c.src.mu.Unlock()
	return c.src.calls, c.src.personCalls
}

func (c *certFixture) refusal(t *testing.T, u string) string {
	t.Helper()
	v, err := c.f.h.MySignInView(c.ctx, u)
	if err != nil || v.FreshAuth == nil {
		t.Fatalf("view %+v %v", v, err)
	}
	return v.FreshAuth.Refusal
}

// TestFreshRecheckBeforeRefusal: a known person with none of the rule's
// accepted methods gets exactly one re-read of their own methods (past
// the 30 s throttle) before the refusal, still refused when they truly
// have none; at most once per 5 s per person; a method set up just now (a
// setup link redeemed seconds after the last read) is seen at once and
// the popup is offered. Never a full reload.
func TestFreshRecheckBeforeRefusal(t *testing.T) {
	c, now := recheckFixture(t, true)
	if r := c.refusal(t, "alice"); r != freshNeedsStronger {
		t.Fatalf("no method: refusal %q", r)
	}
	f0, p0 := c.reads()
	if p0 != 1 {
		t.Fatalf("one-person reads %d, want 1", p0)
	}
	// Within 5 s: no re-read (the 30 s throttle holds too).
	*now = now.Add(2 * time.Second)
	if r := c.refusal(t, "alice"); r != freshNeedsStronger {
		t.Fatalf("throttled: refusal %q", r)
	}
	if f, p := c.reads(); f != f0 || p != p0 {
		t.Fatalf("throttled: reads %d/%d", f-f0, p-p0)
	}
	// A setup link redeemed: a key, nothing marked stale.
	c.src.set(func(s *fakeSignInSrc) { s.keys["alice"] = []signin.Method{signin.SecurityKey} })
	*now = now.Add(4 * time.Second) // 6 s after the last re-read, inside the 30 s
	if r := c.refusal(t, "alice"); r != "" {
		t.Fatalf("after the redeem: refusal %q", r)
	}
	if f, p := c.reads(); f != f0 || p != p0+1 {
		t.Fatalf("after the redeem: reads %d/%d, want 0/1", f-f0, p-p0)
	}
	// Offered: no re-read at all.
	*now = now.Add(10 * time.Second)
	if r := c.refusal(t, "alice"); r != "" {
		t.Fatalf("offered: refusal %q", r)
	}
	if f, p := c.reads(); f != f0 || p != p0+1 {
		t.Fatalf("offered: reads %d/%d", f-f0, p-p0+1)
	}
}

// TestFreshRecheckManyPeople: 100 people refused in one window are 100
// one-person reads and no full reload; without a one-person source, at
// most one full reload per 5 s overall (none while the inventory is
// under 5 s old).
func TestFreshRecheckManyPeople(t *testing.T) {
	people := make([]string, 100)
	for i := range people {
		people[i] = fmt.Sprintf("p%03d", i)
	}
	for _, perPerson := range []bool{true, false} {
		c, now := recheckFixture(t, perPerson)
		c.src.set(func(s *fakeSignInSrc) {
			for _, u := range people {
				s.keys[u] = []signin.Method{}
			}
		})
		if _, err := c.f.h.inventoryBase(c.ctx, true); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(6 * time.Second) // the inventory is 6 s old
		f0, p0 := c.reads()
		for _, u := range people {
			if r := c.refusal(t, u); r != freshNeedsStronger {
				t.Fatalf("%s: refusal %q", u, r)
			}
		}
		f, p := c.reads()
		if perPerson && (f != f0 || p-p0 != len(people)) {
			t.Errorf("per person: full %d, one-person %d", f-f0, p-p0)
		}
		if !perPerson && (f-f0 != 1 || p != p0) {
			t.Errorf("full only: full %d, want 1", f-f0)
		}
		if !perPerson {
			// Under 5 s since that reload, even after the people's own 5 s.
			*now = now.Add(4 * time.Second)
			c.f.h.freshRecheckT = refreshThrottle{}
			c.refusal(t, people[0])
			if f2, _ := c.reads(); f2 != f {
				t.Errorf("a fresh inventory was read again (%d)", f2-f)
			}
		}
	}
}

// TestHistoryCredentialEventMarksStale: a setup link used or an
// authenticator app change Keycloak shows after a person's methods were
// read marks them dirty, each event once; an older one, or a plain
// sign-in, doesn't. With the one-person read wired, a fresh read reads
// the dirty people one by one (at most dirtyPeopleMax per 5 s, never a
// full reload); without it, a burst is one full reload, then none for
// 5 s.
func TestHistoryCredentialEventMarksStale(t *testing.T) {
	for _, perPerson := range []bool{true, false} {
		c, now := recheckFixture(t, perPerson)
		h := c.f.h
		if _, err := h.inventoryBase(c.ctx, true); err != nil {
			t.Fatal(err)
		}
		at := h.signInInv.currentBase().at
		dirty := func() int {
			h.signInInv.mu.Lock()
			defer h.signInInv.mu.Unlock()
			return len(h.signInInv.dirty)
		}
		h.staleOnCredentialEvents("alice", []signinhistory.Entry{
			{Time: at.Add(-time.Minute), Kind: signinhistory.KindSignIn, Detail: signinhistory.SetupLinkDetail},
			{Time: at.Add(time.Minute), Kind: signinhistory.KindSignIn},
		})
		if dirty() != 0 {
			t.Fatal("an older setup link or a plain sign-in marked it")
		}
		n := 20
		for i := 0; i < n; i++ {
			u := fmt.Sprintf("p%03d", i)
			h.staleOnCredentialEvents(u, []signinhistory.Entry{{Time: at.Add(time.Second), Kind: signinhistory.KindSignIn, Detail: signinhistory.SetupLinkDetail}})
			h.staleOnCredentialEvents(u, []signinhistory.Entry{{Time: at.Add(time.Second), Kind: signinhistory.KindMethod, Detail: "authenticator app added: phone"}})
		}
		if dirty() != n {
			t.Fatalf("dirty %d, want %d", dirty(), n)
		}
		// The same events again: no new mark (each acts once).
		h.signInInv.mu.Lock()
		h.signInInv.dirty = nil
		h.signInInv.mu.Unlock()
		h.staleOnCredentialEvents("p000", []signinhistory.Entry{{Time: at.Add(time.Second), Kind: signinhistory.KindMethod}})
		if dirty() != 0 {
			t.Fatal("an event acted on marked the person again")
		}
		for i := 0; i < n; i++ {
			h.markPersonDirty(fmt.Sprintf("p%03d", i))
		}
		f0, p0 := c.reads()
		*now = now.Add(time.Second) // well inside the 30 s
		for range 10 {
			if _, err := h.inventoryBase(c.ctx, true); err != nil {
				t.Fatal(err)
			}
		}
		f, p := c.reads()
		if perPerson {
			if f != f0 || p-p0 != dirtyPeopleMax || dirty() != n-dirtyPeopleMax {
				t.Fatalf("per person: full %d, one-person %d, %d dirty left", f-f0, p-p0, dirty())
			}
			*now = now.Add(5 * time.Second)
			h.inventoryBase(c.ctx, true)
			if f2, p2 := c.reads(); f2 != f0 || p2-p0 != n || dirty() != 0 {
				t.Fatalf("next window: full %d, one-person %d, %d dirty", f2-f0, p2-p0, dirty())
			}
			continue
		}
		if f-f0 != 1 || dirty() != 0 {
			t.Fatalf("burst: %d reloads, %d dirty left", f-f0, dirty())
		}
		// More events inside the 5 s: wait for it, then one reload.
		h.staleOnCredentialEvents("alice", []signinhistory.Entry{{Time: now.Add(time.Second), Kind: signinhistory.KindMethod}})
		*now = now.Add(2 * time.Second)
		h.inventoryBase(c.ctx, true)
		if f, _ := c.reads(); f-f0 != 1 {
			t.Fatalf("inside 5 s: %d reloads", f-f0)
		}
		*now = now.Add(4 * time.Second)
		h.inventoryBase(c.ctx, true)
		h.inventoryBase(c.ctx, true)
		if f, _ := c.reads(); f-f0 != 2 || dirty() != 0 {
			t.Fatalf("after 5 s: %d reloads, %d dirty", f-f0, dirty())
		}
	}
	// A person read on their own after the event isn't marked by it.
	c, now := recheckFixture(t, true)
	h := c.f.h
	if _, err := h.inventoryBase(c.ctx, true); err != nil {
		t.Fatal(err)
	}
	ev := now.Add(time.Second)
	*now = now.Add(2 * time.Second)
	c.refusal(t, "alice") // refused: their own read, after ev
	h.staleOnCredentialEvents("alice", []signinhistory.Entry{{Time: ev, Kind: signinhistory.KindMethod}})
	h.signInInv.mu.Lock()
	d := len(h.signInInv.dirty)
	h.signInInv.mu.Unlock()
	if d != 0 {
		t.Fatal("an event older than the person's own read marked them")
	}
}

// TestRefreshPersonNeverBlocksReads (final review L3): a slow one-person
// read holds no inventory lock: a fresh read with a recent inventory
// answers at once; a full load that started before the person's read
// keeps that person's newer entry.
func TestRefreshPersonNeverBlocksReads(t *testing.T) {
	c, _ := recheckFixture(t, true)
	h := c.f.h
	if _, err := h.inventoryBase(c.ctx, true); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	started := make(chan struct{})
	slow := func(ctx context.Context, u string) ([]keycloak.PasskeyCredential, bool, error) {
		close(started)
		<-release
		return []keycloak.PasskeyCredential{{ID: "k", Type: string(signin.SecurityKey)}}, true, nil
	}
	done := make(chan bool)
	go func() { done <- h.refreshPerson(c.ctx, slow, "alice") }()
	<-started
	got := make(chan error, 1)
	go func() {
		_, err := h.inventoryBase(c.ctx, true)
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("a fresh read waited for a one-person read")
	}
	close(release)
	if !<-done {
		t.Fatal("the patch wasn't applied")
	}
	if ms := h.signInInv.currentBase().passkeys["alice"]; len(ms) != 1 || ms[0] != signin.SecurityKey {
		t.Fatalf("alice %v", ms)
	}
	// A full load started before alice's own read keeps her entry.
	old := h.signInInv.currentBase()
	nb := patchPerson(old, "bob", true, nil, old.at) // any copy
	nb.read = map[string]time.Time{}
	delete(nb.passkeys, "alice")
	carryPersonReads(old, nb, old.at.Add(-time.Hour))
	if ms := nb.passkeys["alice"]; len(ms) != 1 {
		t.Fatalf("carried: %v", ms)
	}
}
