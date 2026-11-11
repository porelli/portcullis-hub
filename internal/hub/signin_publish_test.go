package hub

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/signin"
)

func readKeycloakSignIn(t *testing.T, f *fixture) KeycloakSignIn {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.data, SignInKeycloakFile))
	if err != nil {
		t.Fatal(err)
	}
	var doc KeycloakSignIn
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("signin-keycloak.json: %v\n%s", err, b)
	}
	return doc
}

// Every Keycloak client of every enabled native-OIDC instance is listed
// with the instance's exact template; a disabled instance and a
// forward-auth one are not.
func TestSignInKeycloakFileListsEveryNativeClient(t *testing.T) {
	f := newInstanceFixture(t, nil)
	simulateCompose(f, 0)
	for _, id := range []string{"chat-b", "chat-c"} {
		if err := f.h.CreateInstance("chat", id, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.h.SaveSettings("chat-b", SettingsUpdate{SignInTemplate: pickTemplate("strong")}, siAdmin); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"chat", "chat-b", "relay"} {
		if err := f.h.Enable(id); err != nil {
			t.Fatal(err)
		}
	}
	f.h.Wait()
	doc := readKeycloakSignIn(t, f)
	name := func(id string) string {
		f.h.mu.RLock()
		defer f.h.mu.RUnlock()
		return instanceName(f.h.findLocked(id))
	}
	want := map[string]KeycloakClientTemplate{
		"chat":              {Template: "standard", Name: name("chat")},
		"chat-admin":        {Template: "standard", Name: name("chat")},
		"chat-b":            {Template: "strong", Name: name("chat-b")},
		"chat-b-chat-admin": {Template: "strong", Name: name("chat-b")},
	}
	if !reflect.DeepEqual(doc.Clients, want) {
		t.Errorf("clients = %+v\nwant %+v", doc.Clients, want)
	}
	if doc.Version != 1 || !slices.Equal(doc.Methods, []string{"passkey_device", "passkey_synced", "security_key", "yubikey_cert"}) || doc.AddStronger {
		t.Errorf("header = %d %v %v", doc.Version, doc.Methods, doc.AddStronger)
	}
	for _, c := range doc.Clients {
		if _, ok := doc.Templates[c.Template]; !ok {
			t.Errorf("client template %q not among the templates %v", c.Template, doc.Templates)
		}
	}
	if _, ok := doc.Templates["basic"]; ok {
		t.Error("a disabled template published")
	}
	if doc.Authenticators == nil || len(doc.Authenticators) != 0 || doc.MDS.Serial != 0 || !doc.MDS.NextUpdate.IsZero() {
		t.Errorf("authenticators %v mds %+v", doc.Authenticators, doc.MDS)
	}
	// A pick that can't be published (disabled behind the in-use
	// refusal) is still named: the extension refuses the whole file, never
	// an unlisted client let through.
	f.h.mu.Lock()
	tm := f.h.st.SignIn.Templates["strong"]
	tm.Enabled = false
	f.h.st.SignIn.Templates["strong"] = tm
	f.h.mu.Unlock()
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	doc = readKeycloakSignIn(t, f)
	if _, ok := doc.Templates["strong"]; ok || doc.Clients["chat-b"].Template != "strong" {
		t.Errorf("unpublishable pick: templates %v clients %+v", doc.Templates, doc.Clients)
	}
	f.h.mu.Lock()
	tm.Enabled = true
	f.h.st.SignIn.Templates["strong"] = tm
	f.h.mu.Unlock()
	// Two instances declaring one client (state edited by hand): the
	// stricter template, or none when neither implies the other.
	f.h.mu.Lock()
	addTemplateLocked(f.h, "certs", siLeaves("any", "yubikey_cert"))
	addTemplateLocked(f.h, "keys", siLeaves("any", "security_key"))
	f.h.mu.Unlock()
	f.h.mu.RLock()
	tmpls := f.h.publishedTemplatesLocked()
	f.h.mu.RUnlock()
	for _, c := range []struct{ a, b, want string }{
		{"standard", "strong", "strong"}, {"strong", "standard", "strong"}, {"certs", "keys", unpublishedTemplate},
		{"strong", "gone", "gone"}, {"gone", "strong", "gone"},
	} {
		d := KeycloakSignIn{Templates: tmpls, Clients: map[string]KeycloakClientTemplate{}}
		d.addClient("x", "dup", c.a, "X")
		d.addClient("y", "dup", c.b, "Y")
		if got := d.Clients["dup"]; got.Template != c.want || got.Name != "X" {
			t.Errorf("%s + %s = %+v, want %s", c.a, c.b, got, c.want)
		}
	}
	// Written before the policy file, in the same pass.
	if err := f.h.Disable("chat-b"); err != nil {
		t.Fatal(err)
	}
	if doc := readKeycloakSignIn(t, f); len(doc.Clients) != 2 {
		t.Errorf("after disable: %+v", doc.Clients)
	}
}

// The TLS option follows the certificate switch and the template (D18).
func TestTierFollowsCertificateSwitch(t *testing.T) {
	f := newInstanceFixture(t, nil)
	ctx := context.Background()
	ableAdmin(f.h)
	simulateCompose(f, 0)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	if ov := readOverride(t, f, "grafana"); !strings.Contains(ov, "tls.options: authaware@file") {
		t.Fatalf("grafana on standard:\n%s", ov)
	}
	passkeys := TemplateInput{Name: "Standard", Rule: siLeaves("any", "family:passkey")}
	calls := len(f.runner.Calls())
	ch, err := f.h.SaveTemplate(ctx, "standard", passkeys, false, siAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ch.Restarts, []string{"grafana"}) {
		t.Errorf("restarts = %v", ch.Restarts)
	}
	// The restart is owed (delivered.json) or has already run.
	f.h.owedMu.Lock()
	owed := f.h.owedLocked("grafana")
	f.h.owedMu.Unlock()
	f.h.Wait()
	if owed != settings.EffectRestart && len(f.runner.Calls()) == calls {
		t.Errorf("no restart queued: owed %q, runner calls unchanged", owed)
	}
	if ov := readOverride(t, f, "grafana"); !strings.Contains(ov, "tls.options: public@file") || strings.Contains(ov, "authaware") {
		t.Errorf("grafana on passkeys only:\n%s", ov)
	}
	ch, err = f.h.SaveTemplate(ctx, "standard", TemplateInput{Name: "Standard", Rule: siLeaves("any", "family:passkey", "family:certificate")}, false, siAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ch.Restarts, []string{"grafana"}) || !strings.Contains(readOverride(t, f, "grafana"), "tls.options: authaware@file") {
		t.Errorf("back to certificates: restarts %v\n%s", ch.Restarts, readOverride(t, f, "grafana"))
	}
	// Nothing needs the certificate: it can be switched off, and on
	// again without moving any tier.
	for _, k := range []string{"hub", "people"} {
		if _, err := f.h.SetCoreTemplate(ctx, k, "standard", siAdmin); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.h.SetTemplateEnabled(ctx, "strong", false, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveTemplate(ctx, "standard", passkeys, false, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetMethod(ctx, signin.YubiKeyCert, false, siAdmin); err != nil {
		t.Fatalf("yubikey_cert off: %v", err)
	}
	ch, err = f.h.SetMethod(ctx, signin.YubiKeyCert, true, siAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Restarts) != 0 {
		t.Errorf("switching the certificate on moved %v", ch.Restarts)
	}
	// Basic (password on), no certificate method on: public@file.
	if _, err := f.h.SetMethod(ctx, signin.YubiKeyCert, false, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetMethod(ctx, signin.Password, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetTemplateEnabled(ctx, "basic", true, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveSettings("grafana", SettingsUpdate{SignInTemplate: pickTemplate("basic")}, siAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if ov := readOverride(t, f, "grafana"); !strings.Contains(ov, "tls.options: public@file") {
		t.Errorf("grafana on basic:\n%s", ov)
	}
	if p := readPolicy(t, f).Hosts["grafana.example.org"]; p != "basic" {
		t.Errorf("hosts = %q", p)
	}
	// The Hub never writes Traefik's dynamic configuration.
	if _, err := os.Stat(filepath.Join(f.project, "traefik")); !os.IsNotExist(err) {
		t.Errorf("something was written under %s/traefik: %v", f.project, err)
	}
}

// A signin-keycloak.json that can't be written never skips group-gate's
// policy file: both are attempted, the error is reported (B1).
func TestSignInKeycloakWriteFailureStillWritesPolicy(t *testing.T) {
	f := newInstanceFixture(t, nil)
	simulateCompose(f, 0)
	if err := f.h.Enable("chat"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	kc := filepath.Join(f.data, SignInKeycloakFile)
	pol := filepath.Join(f.data, "group-gate-policy.json")
	// A non-empty directory in its place: the rename onto it fails.
	if err := os.Remove(kc); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(kc, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pol); err != nil {
		t.Fatal(err)
	}
	if err := f.h.WritePolicy(); err == nil {
		t.Error("WritePolicy reported no error for a signin-keycloak.json it couldn't write")
	}
	b, err := os.ReadFile(pol)
	if err != nil {
		t.Fatalf("policy file not written after the signin-keycloak.json failure: %v", err)
	}
	var doc struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || doc.Version != 6 {
		t.Errorf("policy file = %s (%v)", b, err)
	}
	if err := os.RemoveAll(kc); err != nil {
		t.Fatal(err)
	}
	if err := f.h.WritePolicy(); err != nil {
		t.Errorf("WritePolicy after the fix: %v", err)
	}
	readKeycloakSignIn(t, f)
}
