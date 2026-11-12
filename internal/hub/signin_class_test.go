package hub

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
)

// TestNewlyBlocked (contract §15.10, item-9 ruling): who a sign-in draft
// newly blocks — people who meet their template before and not after —
// per core page and enabled instance; people already blocked never
// count; people the inventory doesn't have make it unknown.
func TestNewlyBlocked(t *testing.T) {
	f, _ := signInFixture(t)
	ctx := context.Background()
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	p := newFakePeople()
	p.addGroup("users_grafana", "gus", "gia")
	p.addGroup(lldap.AdminGroup, "ann")
	src := &fakeSignInSrc{
		keys:  map[string][]signin.Method{"gus": {signin.PasskeySynced}, "gia": {}, "ann": {signin.SecurityKey}, "admin": {signin.SecurityKey}},
		certs: []invite.CertRecord{},
	}
	wireSignIn(f.h, p, src)
	names := func(imp *SignInImpact) []string {
		var out []string
		for _, a := range imp.Affected {
			for _, b := range a.Blocked {
				out = append(out, a.Kind+":"+a.Instance+":"+b.User)
			}
		}
		return out
	}

	// grafana standard → strong: gus (a synced passkey) is newly blocked
	// there; gia had nothing (blocked before too); ann has a security key.
	strong := "strong"
	imp := f.h.NewlyBlocked(ctx, SignInDraft{Instance: "grafana", Pick: &strong})
	if imp.Unknown != "" || !slices.Equal(names(imp), []string{"instance:grafana:gus"}) {
		t.Errorf("grafana → strong = %+v", imp)
	}
	// Unchanged: nobody.
	none := ""
	if imp := f.h.NewlyBlocked(ctx, SignInDraft{Instance: "grafana", Pick: &none}); imp.Unknown != "" || len(imp.Affected) != 0 {
		t.Errorf("grafana unchanged = %+v", imp)
	}
	// The default standard → strong: the portal (everyone: gus) and grafana.
	imp = f.h.NewlyBlocked(ctx, SignInDraft{Default: &strong})
	if imp.Unknown != "" || !slices.Equal(names(imp), []string{"core:portal:gus", "instance:grafana:gus"}) {
		t.Errorf("default → strong = %+v", imp)
	}
	// Switching passkey_synced off blocks gus where standard applies.
	imp = f.h.NewlyBlocked(ctx, SignInDraft{Method: signin.PasskeySynced, On: false})
	if imp.Unknown != "" || !slices.Equal(names(imp), []string{"core:portal:gus", "instance:grafana:gus"}) {
		t.Errorf("passkey_synced off = %+v", imp)
	}
	// A template update, as the preview judges it.
	rule := siLeaves("any", "security_key")
	imp = f.h.NewlyBlocked(ctx, SignInDraft{Template: "standard", Name: "Standard", Rule: &rule})
	if imp.Unknown != "" || !slices.Equal(names(imp), []string{"core:portal:gus", "instance:grafana:gus"}) {
		t.Errorf("standard → security key = %+v", imp)
	}
	// An enabled instance without a view (its template is missing): who
	// it blocks can't be judged — unknown, never "nobody blocked".
	f.h.mu.Lock()
	f.h.st.Enabled = append(f.h.st.Enabled, "ghost")
	f.h.mu.Unlock()
	if imp := f.h.NewlyBlocked(ctx, SignInDraft{Default: &strong}); !strings.Contains(imp.Unknown, "ghost") {
		t.Errorf("view-less enabled instance = %+v, want unknown", imp)
	}
	f.h.mu.Lock()
	f.h.st.Enabled = slices.DeleteFunc(f.h.st.Enabled, func(id string) bool { return id == "ghost" })
	f.h.mu.Unlock()
	if imp := f.h.NewlyBlocked(ctx, SignInDraft{Default: &strong}); imp.Unknown != "" {
		t.Errorf("after the ghost: %+v", imp)
	}
	// Someone the inventory doesn't have (gus not in Keycloak's list):
	// unknown, fail closed.
	src.set(func(s *fakeSignInSrc) { delete(s.keys, "gus") })
	f.h.SetSignInSources(SignInSources{Passkeys: src.passkeys, Certificates: src.certificates})
	if imp := f.h.NewlyBlocked(ctx, SignInDraft{Instance: "grafana", Pick: &strong}); imp.Unknown == "" {
		t.Errorf("gus unknown = %+v", imp)
	}
	// Keycloak down: unknown.
	src.set(func(s *fakeSignInSrc) { s.down = true })
	f.h.SetSignInSources(SignInSources{Passkeys: src.passkeys, Certificates: src.certificates})
	if imp := f.h.NewlyBlocked(ctx, SignInDraft{Instance: "grafana", Pick: &strong}); imp.Unknown == "" {
		t.Errorf("Keycloak down = %+v", imp)
	}
}

// TestPrecheckSignIn: the twin routes' refusals, before any confirmation.
func TestPrecheckSignIn(t *testing.T) {
	f, _ := signInFixture(t)
	s := func(v string) *string { return &v }
	bad := siLeaves("any")
	ok := siLeaves("any", "security_key")
	for _, c := range []struct {
		d    SignInDraft
		want int
	}{
		{SignInDraft{Method: "nope", On: true}, 404},
		{SignInDraft{Method: signin.BrowserCert, On: true}, 0},
		{SignInDraft{Method: signin.Password}, 0},
		{SignInDraft{Template: "Bad ID", Name: "X", Rule: &ok}, 400},
		{SignInDraft{Template: "standard", Name: "Standard", Rule: &bad}, 400},
		{SignInDraft{Template: "standard", Name: "Standard"}, 400},
		{SignInDraft{Template: "standard", Name: "Standard", Rule: &ok, Create: true}, 409},
		{SignInDraft{Template: "nope", Name: "Nope", Rule: &ok}, 404},
		{SignInDraft{Template: "standard", Name: "Standard", Rule: &ok}, 0},
		{SignInDraft{Default: s("nope")}, 404},
		{SignInDraft{Default: s("basic")}, 409},
		{SignInDraft{Default: s("strong")}, 0},
		{SignInDraft{CoreKey: "nope", Core: s("")}, 400},
		{SignInDraft{CoreKey: "enroll", Core: s("")}, 400},
		{SignInDraft{CoreKey: "hub", Core: s("nope")}, 404},
		{SignInDraft{CoreKey: "hub", Core: s("")}, 0},
		{SignInDraft{Instance: "nope", Pick: s("")}, 404},
		{SignInDraft{Instance: "grafana", Pick: s("nope")}, 404},
		{SignInDraft{Instance: "grafana", Pick: s("basic")}, 409},
		{SignInDraft{Instance: "grafana", Pick: s("strong")}, 0},
		{SignInDraft{}, 400},
	} {
		if got := statusOf(f.h.PrecheckSignIn(c.d)); got != c.want {
			t.Errorf("%+v: status %d, want %d", c.d, got, c.want)
		}
	}
}
