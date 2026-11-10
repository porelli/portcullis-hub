package hub

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

func TestSignInLockoutGuard(t *testing.T) {
	f, audit := signInFixture(t)
	ctx := context.Background()
	p := newFakePeople("bob")
	p.addGroup(lldap.AdminGroup, "ann")
	p.addGroup("users_x", "bob")
	src := &fakeSignInSrc{keys: map[string][]signin.Method{"ann": {signin.SecurityKey}, "bob": {signin.YubiKeyCert}}}
	wireSignIn(f.h, p, src)
	refused := func(what string, err error) {
		t.Helper()
		if statusOf(err) != 409 || !strings.Contains(err.Error(), "ann") || !strings.Contains(err.Error(), "no administrator") {
			t.Errorf("%s: %v, want the guard's 409 naming ann", what, err)
		}
	}

	// A template change: the Hub's Strong would need a YubiKey certificate.
	_, err := f.h.SaveTemplate(ctx, "strong", TemplateInput{Name: "Strong", Rule: siLeaves("all", "yubikey_cert")}, false, siAdmin)
	refused("save strong", err)
	if e := audit.last(); e.Action != "signin.template" || e.Result != "refused" {
		t.Errorf("audit = %+v", e)
	}
	if v, _ := f.h.SignInView(ctx); v.Templates[2].ID != "strong" || v.Templates[2].Sentence != signin.Sentence(siLeaves("any", "security_key", "yubikey_cert")) {
		t.Errorf("strong changed: %+v", v.Templates[2])
	}

	// A method: hub and people on Standard, Strong disabled; switching the
	// security key off leaves Standard meetable (D3 lets it), but not by ann.
	for _, k := range []string{"hub", "people"} {
		if _, err := f.h.SetCoreTemplate(ctx, k, "standard", siAdmin); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.h.SetTemplateEnabled(ctx, "strong", false, siAdmin); err != nil {
		t.Fatal(err)
	}
	_, err = f.h.SetMethod(ctx, signin.SecurityKey, false, siAdmin)
	refused("security_key off", err)
	if strings.Contains(err.Error(), "can't be switched off") {
		t.Errorf("a D3 refusal, not the guard's: %v", err)
	}
	if v, _ := f.h.SignInView(ctx); !methodRow(v, signin.SecurityKey).On {
		t.Error("security_key was switched off")
	}

	// A core pick: the Hub page on YubiKey + certificate.
	if _, err := f.h.SetTemplateEnabled(ctx, certOnlyTemplate, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	_, err = f.h.SetCoreTemplate(ctx, "hub", certOnlyTemplate, siAdmin)
	refused("hub core", err)
	// Another page's pick isn't guarded: people may go there.
	if _, err := f.h.SetCoreTemplate(ctx, "people", certOnlyTemplate, siAdmin); err != nil {
		t.Errorf("people core: %v", err)
	}
	// So isn't the default while the Hub has its own pick.
	if _, err := f.h.SetDefaultTemplate(ctx, certOnlyTemplate, siAdmin); err != nil {
		t.Errorf("default: %v", err)
	}
	if _, err := f.h.SetDefaultTemplate(ctx, "standard", siAdmin); err != nil {
		t.Fatal(err)
	}
	// ann gets a certificate: the pick goes through.
	src.set(func(s *fakeSignInSrc) { s.keys["ann"] = []signin.Method{signin.SecurityKey, signin.YubiKeyCert} })
	if ch, err := f.h.SetCoreTemplate(ctx, "hub", certOnlyTemplate, siAdmin); err != nil || len(ch.Warnings) != 0 {
		t.Fatalf("hub core with ann able: %+v, %v", ch, err)
	}

	// No administrator able before: allowed, with the warning.
	if _, err := f.h.SetCoreTemplate(ctx, "hub", "standard", siAdmin); err != nil {
		t.Fatal(err)
	}
	src.set(func(s *fakeSignInSrc) { s.keys["ann"] = nil })
	ch, err := f.h.SetCoreTemplate(ctx, "hub", certOnlyTemplate, siAdmin)
	if err != nil || !slices.ContainsFunc(ch.Warnings, func(w string) bool { return strings.Contains(w, noAdminWarning) }) {
		t.Errorf("0 able before: %+v, %v", ch, err)
	}
	if v, _ := f.h.SignInView(ctx); v.Core["hub"] != certOnlyTemplate {
		t.Errorf("not committed: %v", v.Core)
	}
	// An expired admin membership doesn't count.
	if _, err := f.h.SetCoreTemplate(ctx, "hub", "standard", siAdmin); err != nil {
		t.Fatal(err)
	}
	src.set(func(s *fakeSignInSrc) { s.keys["ann"] = []signin.Method{signin.SecurityKey, signin.YubiKeyCert} })
	p.set(func(p *fakePeople) { p.expired["ann"] = map[string]bool{lldap.AdminGroup: true} })
	if ch, err := f.h.SetCoreTemplate(ctx, "hub", certOnlyTemplate, siAdmin); err != nil || len(ch.Warnings) == 0 {
		t.Errorf("expired admin: %+v, %v", ch, err)
	}
	p.set(func(p *fakePeople) { delete(p.expired, "ann") })
	if _, err := f.h.SetCoreTemplate(ctx, "hub", "standard", siAdmin); err != nil {
		t.Fatal(err)
	}

	// Keycloak down: 503 for a change that could lock someone out; a
	// change that can't (the Hub's rule unchanged or weaker) still works.
	src.set(func(s *fakeSignInSrc) { s.down = true })
	if _, err := f.h.SetCoreTemplate(ctx, "hub", certOnlyTemplate, siAdmin); statusOf(err) != 503 {
		t.Errorf("Keycloak down: %v, want 503", err)
	}
	if err := f.h.SetAddStronger(true, siAdmin); err != nil {
		t.Errorf("unguarded change with Keycloak down: %v", err)
	}
	// LLDAP down: 503 too.
	src.set(func(s *fakeSignInSrc) { s.down = false })
	p.set(func(p *fakePeople) { p.err = errors.New("lldap down") })
	if _, err := f.h.SetCoreTemplate(ctx, "hub", certOnlyTemplate, siAdmin); statusOf(err) != 503 {
		t.Errorf("LLDAP down: %v, want 503", err)
	}
}

// The guard runs before AI support is switched off (controller ruling,
// Task 4 review): a refused change leaves AI on and commits nothing.
func TestLockoutGuardBeforeAIOff(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	ctx := context.Background()
	if err := a.h.SetAISupport(ctx, "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	if _, err := a.h.SetCoreTemplate(ctx, "hub", "", root); err != nil {
		t.Fatal(err)
	}
	p := a.people
	if p == nil {
		p = newFakePeople()
	}
	p.addGroup(lldap.AdminGroup, "ann")
	wireSignIn(a.h, p, &fakeSignInSrc{keys: map[string][]signin.Method{"ann": {signin.PasskeySynced}}})
	// The default (the Hub's template now, and aiapp's) made
	// certificate-only: ann can't meet it.
	_, err := a.h.SaveTemplate(ctx, "standard", TemplateInput{Name: "Standard", Rule: siLeaves("all", "yubikey_cert", "security_key")}, false, root)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "ann") {
		t.Fatalf("save = %v, want the guard's 409", err)
	}
	if c := a.companion("aiapp", "tok"); !c.Enabled {
		t.Errorf("AI support was switched off by a refused change: %+v", c)
	}
	if e := a.audits("ai.disable"); len(e) != 0 {
		t.Errorf("ai.disable audited: %+v", e)
	}
	a.h.Wait()
}

// ableAdmin wires an administrator, root, who has every method set up,
// so the lockout guard lets every sign-in change through (tests about
// other refusals).
func ableAdmin(h *Hub) {
	p := newFakePeople()
	p.addGroup(lldap.AdminGroup, "root")
	wireSignIn(h, p, &fakeSignInSrc{keys: map[string][]signin.Method{"root": {signin.PasskeySynced, signin.PasskeyDevice, signin.SecurityKey}},
		certs: []invite.CertRecord{{User: "root", Serial: "01", NotAfter: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}}})
	h.mu.Lock()
	h.st.SignIn.Passwords["root"] = state.PasswordRecord{SetBy: "root"}
	h.mu.Unlock()
}
