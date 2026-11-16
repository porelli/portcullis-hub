package hub

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/confirm"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
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

// TestFreshRecheckBeforeRefusal: a known person with none of the rule's
// accepted methods gets exactly one forced inventory re-read (past the
// 30 s throttle) before the refusal, still refused when they truly have
// none; at most once per 5 s per person; a method set up just now (a
// setup link redeemed, the inventory read seconds ago) is seen at once
// and the popup is offered.
func TestFreshRecheckBeforeRefusal(t *testing.T) {
	c := newCertFixture(t)
	h := c.f.h
	setPeopleRule(c.f, siLeaves("any", "security_key"))
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	h.entryNow = clock
	h.signInInv.mu.Lock()
	h.signInInv.now = clock
	h.signInInv.mu.Unlock()
	c.src.set(func(s *fakeSignInSrc) { s.keys["alice"] = []signin.Method{} })
	h.MarkInventoryStale()
	calls := func() int {
		c.src.mu.Lock()
		defer c.src.mu.Unlock()
		return c.src.calls
	}
	view := func() string {
		t.Helper()
		v, err := h.MySignInView(c.ctx, "alice")
		if err != nil || v.FreshAuth == nil {
			t.Fatalf("view %+v %v", v, err)
		}
		return v.FreshAuth.Refusal
	}
	n0 := calls()
	if r := view(); r != freshNeedsStronger {
		t.Fatalf("no method: refusal %q", r)
	}
	if got := calls() - n0; got != 2 { // the page's read, one forced re-read
		t.Fatalf("reads %d, want 2", got)
	}
	// Within 5 s: no forced re-read (the 30 s throttle holds too).
	now = now.Add(2 * time.Second)
	n1 := calls()
	if r := view(); r != freshNeedsStronger || calls() != n1 {
		t.Fatalf("throttled: refusal %q, reads %d", r, calls()-n1)
	}
	// A setup link redeemed: a key, nothing marked stale.
	c.src.set(func(s *fakeSignInSrc) { s.keys["alice"] = []signin.Method{signin.SecurityKey} })
	now = now.Add(4 * time.Second) // 6 s after the last forced read, inside the 30 s
	if r := view(); r != "" {
		t.Fatalf("after the redeem: refusal %q", r)
	}
	if got := calls() - n1; got != 1 {
		t.Fatalf("reads after the redeem %d, want 1", got)
	}
	// Offered: no re-read at all.
	n2 := calls()
	now = now.Add(10 * time.Second)
	if r := view(); r != "" || calls() != n2 {
		t.Fatalf("offered: refusal %q, reads %d", r, calls()-n2)
	}
}

// TestHistoryCredentialEventMarksStale: a setup link used or an
// authenticator app change Keycloak shows after the cached inventory was
// read marks it stale; an older one doesn't.
func TestHistoryCredentialEventMarksStale(t *testing.T) {
	c := newCertFixture(t)
	h := c.f.h
	if _, err := h.inventoryBase(c.ctx, true); err != nil {
		t.Fatal(err)
	}
	base := h.signInInv.currentBase()
	tried := func() bool {
		h.signInInv.mu.Lock()
		defer h.signInInv.mu.Unlock()
		return !h.signInInv.tried.IsZero()
	}
	h.staleOnCredentialEvents([]signinhistory.Entry{
		{Time: base.at.Add(-time.Minute), Kind: signinhistory.KindSignIn, Detail: signinhistory.SetupLinkDetail},
		{Time: base.at.Add(time.Minute), Kind: signinhistory.KindSignIn},
	})
	if !tried() {
		t.Fatal("an older setup link or a plain sign-in marked it stale")
	}
	for _, e := range []signinhistory.Entry{
		{Time: base.at.Add(time.Second), Kind: signinhistory.KindSignIn, Detail: signinhistory.SetupLinkDetail},
		{Time: base.at.Add(time.Second), Kind: signinhistory.KindMethod, Detail: "authenticator app added: phone"},
	} {
		if _, err := h.inventoryBase(c.ctx, true); err != nil {
			t.Fatal(err)
		}
		e.Time = h.signInInv.currentBase().at.Add(time.Second)
		h.staleOnCredentialEvents([]signinhistory.Entry{e})
		if tried() {
			t.Fatalf("%+v didn't mark it stale", e)
		}
	}
}
