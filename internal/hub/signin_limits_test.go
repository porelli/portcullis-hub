package hub

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

func (a *fakeAudit) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

// TestBrowserCertCanBeSwitchedOn (sign-in part 2, D27): the switch is no
// longer refused; it is audited signin.method; Standard then compiles
// with browser_cert, and a template of browser_cert alone can be enabled.
func TestBrowserCertCanBeSwitchedOn(t *testing.T) {
	f, audit := signInFixture(t)
	ctx := context.Background()
	if _, err := f.h.SetMethod(ctx, signin.BrowserCert, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "signin.method" || e.Result != "ok" || e.Target != "browser_cert" || e.Detail != "off -> on" {
		t.Errorf("audit = %+v", e)
	}
	f.h.mu.RLock()
	c, ok := f.h.compiledLocked("standard")
	f.h.mu.RUnlock()
	if j, _ := c.MarshalJSON(); !ok || !strings.Contains(string(j), `"yubikey_cert","browser_cert"`) {
		t.Errorf("standard compiled = %s (%v)", j, ok)
	}
	v := f.h.SignInState()
	for _, m := range v.Methods {
		if m.ID == signin.BrowserCert && (!m.On || !m.Available) {
			t.Errorf("view row = %+v", m)
		}
	}
	if _, err := f.h.SaveTemplate(ctx, "files", TemplateInput{Name: "Files", Rule: siLeaves("any", "browser_cert")}, true, siAdmin); err != nil {
		t.Errorf("a browser-certificate template: %v", err)
	}
	if err := f.h.PrecheckSignIn(SignInDraft{Method: signin.BrowserCert, On: true}); err != nil {
		t.Errorf("precheck: %v", err)
	}
	// Off again is refused while the enabled template needs it.
	if _, err := f.h.SetMethod(ctx, signin.BrowserCert, false, siAdmin); statusOf(err) != 409 {
		t.Errorf("off while needed: %v", err)
	}
}

func TestSetSignInLimitsBounds(t *testing.T) {
	f, audit := signInFixture(t)
	ctx := context.Background()
	ok := state.SignInLimits{BrowserCertDays: 30, BrowserCertMaxActive: 3, HistoryDays: 365}
	for name, in := range map[string]state.SignInLimits{
		"days 0":       {BrowserCertDays: 0, BrowserCertMaxActive: 3, HistoryDays: 365},
		"days ceiling": {BrowserCertDays: 31, BrowserCertMaxActive: 3, HistoryDays: 365},
		"max 0":        {BrowserCertDays: 30, BrowserCertMaxActive: 0, HistoryDays: 365},
		"max 21":       {BrowserCertDays: 30, BrowserCertMaxActive: 21, HistoryDays: 365},
		"history 29":   {BrowserCertDays: 30, BrowserCertMaxActive: 3, HistoryDays: 29},
		"history 3651": {BrowserCertDays: 30, BrowserCertMaxActive: 3, HistoryDays: 3651},
	} {
		if _, err := f.h.SetSignInLimits(ctx, in, siAdmin); statusOf(err) != 400 {
			t.Errorf("%s: %v, want 400", name, err)
		}
		if e := audit.last(); e.Action != "signin.limits" || e.Result != "refused" {
			t.Errorf("%s: audit = %+v", name, e)
		}
	}
	if got := f.h.SignInLimits().Limits; got != ok {
		t.Errorf("a refusal changed the limits: %+v", got)
	}
	if _, err := f.h.SetSignInLimits(ctx, ok, siAdmin); err != nil {
		t.Errorf("unchanged: %v", err)
	}
	if _, err := f.h.SetSignInLimits(ctx, ok, directory.Human("")); statusOf(err) != 401 {
		t.Errorf("no actor: %v", err)
	}
	n := audit.count()
	v, err := f.h.SetSignInLimits(ctx, state.SignInLimits{BrowserCertDays: 10, BrowserCertMaxActive: 20, HistoryDays: 3650}, siAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if v.Limits != (state.SignInLimits{BrowserCertDays: 10, BrowserCertMaxActive: 20, HistoryDays: 3650}) || v.Effective != v.Limits || v.CeilingDays != 30 || v.Warning != "" {
		t.Errorf("view = %+v", v)
	}
	if audit.count() != n+1 {
		t.Errorf("%d audit entries for one change", audit.count()-n)
	}
	if e := audit.last(); e.Action != "signin.limits" || e.Result != "ok" || e.Detail != "browser_cert_days 30 -> 10; browser_cert_max_active 3 -> 20; history_days 365 -> 3650" {
		t.Errorf("audit = %+v", e)
	}
	// Saved: a reload keeps it.
	st, err := state.Load(f.data + "/state.yaml")
	if err != nil || st.SignIn.Limits != v.Limits {
		t.Errorf("stored: %v %+v", err, st)
	}
}

// A stored lifetime above the ceiling (HUB_CLIENT_CERT_TTL went down)
// applies as the ceiling, with a warning.
func TestLimitsAboveCeilingApplyAsCeiling(t *testing.T) {
	f, _ := signInFixture(t)
	f.h.mu.Lock()
	f.h.st.SignIn.Limits.BrowserCertDays = 60
	f.h.mu.Unlock()
	v := f.h.SignInLimits()
	if v.Limits.BrowserCertDays != 60 || v.CeilingDays != 30 || v.Effective.BrowserCertDays != 30 || v.Warning == "" {
		t.Errorf("view = %+v", v)
	}
	if sv := f.h.SignInState(); sv.Effective.BrowserCertDays != 30 || sv.Warning == "" {
		t.Errorf("sign-in view limits = %+v", sv.LimitsView)
	}
	// No ceiling at all (a Hub without HUB_CLIENT_CERT_TTL): nothing
	// applies, every lifetime is refused.
	f.h.cfg.ClientCertTTL = 23 * time.Hour
	if v := f.h.SignInLimits(); v.CeilingDays != 0 || v.Effective.BrowserCertDays != 0 {
		t.Errorf("no ceiling: %+v", v)
	}
	if _, err := f.h.SetSignInLimits(context.Background(), state.SignInLimits{BrowserCertDays: 1, BrowserCertMaxActive: 3, HistoryDays: 365}, siAdmin); statusOf(err) != 400 {
		t.Errorf("no ceiling, 1 day: %v", err)
	}
}

// TestSetLimitsReassertsEvents: a limits change re-asserts Keycloak's
// events config with history_days; an unchanged save doesn't; a failing
// ensure doesn't fail the save (the sync loop retries).
func TestSetLimitsReassertsEvents(t *testing.T) {
	f, _ := signInFixture(t)
	ctx := context.Background()
	var mu sync.Mutex
	var got []int
	fail := false
	f.h.SetEventsConfig(func(_ context.Context, days int) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, days)
		if fail {
			return errors.New("keycloak down")
		}
		return nil
	})
	if _, err := f.h.SetSignInLimits(ctx, state.SignInLimits{BrowserCertDays: 30, BrowserCertMaxActive: 3, HistoryDays: 90}, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetSignInLimits(ctx, state.SignInLimits{BrowserCertDays: 30, BrowserCertMaxActive: 3, HistoryDays: 90}, siAdmin); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	if _, err := f.h.SetSignInLimits(ctx, state.SignInLimits{BrowserCertDays: 20, BrowserCertMaxActive: 3, HistoryDays: 90}, siAdmin); err != nil {
		t.Errorf("a failing events ensure failed the save: %v", err)
	}
	mu.Lock()
	calls := append([]int(nil), got...)
	mu.Unlock()
	if len(calls) != 2 || calls[0] != 90 || calls[1] != 90 {
		t.Errorf("ensure calls = %v, want [90 90]", calls)
	}
	if err := f.h.ensureEvents(ctx); err == nil {
		t.Error("ensureEvents hid the error")
	}
}

// TestTierProtectedAnyOverride (contract §5 "TLS tier per host", sign-in
// part 2): an app whose template needs some certificate on every way in,
// browser certificates included, gets protected-any@file; the mtls app
// stays on protected@file (YubiKey CA only) with browser_cert on.
func TestTierProtectedAnyOverride(t *testing.T) {
	f := newAccessFixture(t)
	ctx := context.Background()
	ableAdmin(f.h)
	if _, err := f.h.SetMethod(ctx, signin.BrowserCert, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveTemplate(ctx, "certs", TemplateInput{Name: "Certificates", Rule: siLeaves("any", "family:certificate")}, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	if err := saveApp(t, f, "grafana", SettingsUpdate{SignInTemplate: pickTemplate("certs")}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"grafana", "vault"} {
		if err := f.h.Enable(id); err != nil {
			t.Fatal(err)
		}
	}
	f.h.Wait()
	if v := view(t, f, "grafana"); v.Tier != "protected-any@file" {
		t.Errorf("grafana tier %s", v.Tier)
	}
	if ov := readOverride(t, f, "grafana"); !strings.Contains(ov, "tls.options: protected-any@file") {
		t.Errorf("grafana override:\n%s", ov)
	}
	if v := view(t, f, "vault"); v.Tier != "protected@file" {
		t.Errorf("vault tier %s", v.Tier)
	}
	notes := strings.Join(view(t, f, "grafana").SignInNotes, "\n")
	if !strings.Contains(notes, "protected-any@file") {
		t.Errorf("notes = %s", notes)
	}
}

// Review fix 3 (contract §5): an app whose template can't be published
// is protected@file, but while its public router is open every router of
// the host shares authaware@file (policy.HostTier) — and every gated
// request is still denied (no published rule for the host).
func TestUnusableTemplateWithPublicRouter(t *testing.T) {
	a := access{Capability: policy.Capability{Templates: true, Enforcement: policy.EnforcePerRequest}, Unusable: true}
	if got := a.tier(nil, false); got != policy.TierProtected {
		t.Errorf("unusable, no public router: %s", got)
	}
	if got := a.tier(nil, true); got != policy.TierAuthAware {
		t.Errorf("unusable, public router open: %s", got)
	}

	f := newCloudFixture(t)
	if err := f.h.Enable("cloud"); err != nil {
		t.Fatal(err)
	}
	enableTemplate(t, f, certOnlyTemplate)
	save(t, f, SettingsUpdate{SignInTemplate: pickTemplate(certOnlyTemplate), PublicTokens: listp("AbC123")})
	// The picked template stops being publishable (disabled under it, as
	// a corrupt edit would leave it): the override follows.
	f.h.mu.Lock()
	tm := f.h.st.SignIn.Templates[certOnlyTemplate]
	tm.Enabled = false
	f.h.st.SignIn.Templates[certOnlyTemplate] = tm
	err := f.h.generateOverrideLocked(f.h.findLocked("cloud"), f.h.st.Settings["cloud"])
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	ov := readOverride(t, f, "cloud")
	if !strings.Contains(ov, "portcullis-public-cloud") || strings.Contains(ov, "protected") || !strings.Contains(ov, "tls.options: authaware@file") {
		t.Errorf("override:\n%s", ov)
	}
	doc := readPolicy(t, f)
	if _, ok := doc.Templates[certOnlyTemplate]; ok {
		t.Errorf("the unusable template was published: %v", doc.Templates)
	}
	if id, ok := doc.Hosts["cloud.example.org"]; ok && id != certOnlyTemplate {
		t.Errorf("host published onto another template: %q", id)
	}
	if _, ok := doc.Hosts["cloud.example.org"]; !ok && doc.Groups["cloud.example.org"] != policy.DenyGroup {
		t.Errorf("gated requests not denied: hosts %v groups %v", doc.Hosts, doc.Groups)
	}
}

// Review fix 2: ensureEvents runs one at a time, and the last write
// always carries the history_days stored last.
func TestEnsureEventsSerialised(t *testing.T) {
	f, _ := signInFixture(t)
	ctx := context.Background()
	var mu sync.Mutex
	inFlight, maxInFlight, last := 0, 0, 0
	f.h.SetEventsConfig(func(_ context.Context, days int) error {
		mu.Lock()
		inFlight++
		maxInFlight = max(maxInFlight, inFlight)
		mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		mu.Lock()
		inFlight--
		last = days
		mu.Unlock()
		return nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = f.h.ensureEvents(ctx) }()
		go func(d int) {
			defer wg.Done()
			_, _ = f.h.SetSignInLimits(ctx, state.SignInLimits{BrowserCertDays: 30, BrowserCertMaxActive: 3, HistoryDays: d}, siAdmin)
		}(100 + i)
	}
	wg.Wait()
	_ = f.h.ensureEvents(ctx)
	mu.Lock()
	defer mu.Unlock()
	if maxInFlight != 1 {
		t.Errorf("%d events writes in flight at once", maxInFlight)
	}
	if want := f.h.SignInLimits().Limits.HistoryDays; last != want {
		t.Errorf("last write %d, stored %d", last, want)
	}
}
