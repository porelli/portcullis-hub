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
	simulateCompose(f, 0)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	if ov := readOverride(t, f, "grafana"); !strings.Contains(ov, "tls.options: authaware@file") {
		t.Fatalf("grafana on standard:\n%s", ov)
	}
	passkeys := TemplateInput{Name: "Standard", Rule: siLeaves("any", "family:passkey")}
	ch, err := f.h.SaveTemplate(ctx, "standard", passkeys, false, siAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ch.Restarts, []string{"grafana"}) {
		t.Errorf("restarts = %v", ch.Restarts)
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
