package hub

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/confirm"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
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
	// MySignIn's popup asks for the code.
	v, err := h.MySignInView(c.ctx, "alice")
	if err != nil || v.FreshAuth == nil || v.FreshAuth.PcMethod != "totp" {
		t.Errorf("view fresh_auth = %+v %v", v.FreshAuth, err)
	}
	// The shared info is never changed (other views keep no pc_method).
	if info := h.FreshAuthInfo(); info != nil && info.PcMethod != "" {
		t.Errorf("shared info = %+v", info)
	}
	setSignIn(c.f, func(si *state.SignIn) { si.Core["people"] = "strong" })
	if v, _ := h.MySignInView(c.ctx, "alice"); v.FreshAuth == nil || v.FreshAuth.PcMethod != "" {
		t.Errorf("strong fresh_auth = %+v", v.FreshAuth)
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
	v, err := h.ConfirmationPage(ListenerHub, cf.ID, "root")
	if err != nil || v.FreshAuth == nil || v.FreshAuth.PcMethod != "totp" {
		t.Fatalf("page = %+v %v", v, err)
	}
	setSignIn(c.f, func(si *state.SignIn) { si.Core["hub"] = "strong" })
	if v, _ = h.ConfirmationPage(ListenerHub, cf.ID, "root"); v.FreshAuth == nil || v.FreshAuth.PcMethod != "" {
		t.Errorf("strong: %+v", v.FreshAuth)
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
