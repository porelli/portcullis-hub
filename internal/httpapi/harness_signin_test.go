//go:build harness

package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/signin"
)

// Settings → Sign-in (sign-in Task 9). The FIDO list's URL is a closed
// port (Settings shows the "isn't available" warning); vault is an mtls
// app (no drop-down: "client certificate required").
//
// The inventory: root has only a YubiKey touch (switching security_key
// off is refused by the lockout guard: no administrator could sign in to
// the Hub); alice a synced passkey and a YubiKey touch; bob and carol a
// password only (Hub-recorded); dave nothing; erin a device-bound passkey;
// the userNN accounts a synced passkey; nobody a YubiKey certificate.
// Password is switched on and Basic enabled; templates Family (password
// and a passkey, or a YubiKey touch) and Engineering (the spec's nested
// example). hookapp (users_hookapp: root, alice, bob, carol) keeps the
// default (Standard): bob and carol can't meet it. gitea-ops picks
// Family. Disabling Strong is refused (in use by the Hub and People).
const harnessVaultManifest = "name: Vault\ncategory: security\nicon: \"🔐\"\ndescription: \"Secrets (the sign-in fixture: auth.method mtls)\"\nai: {unsupported: \"test fixture\"}\nauth:\n  method: mtls\n  sso: false\n"

const harnessVaultCompose = "services:\n  server:\n    image: hashicorp/vault:1.18\n    labels:\n      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.vault.rule: Host(`${PORTCULLIS_HOST_VAULT:-vault.portcullis.local}`)\n      traefik.http.routers.vault.tls.options: protected@file\n" +
	"      traefik.http.services.vault.loadbalancer.server.port: \"8200\"\n"

// harnessMDSURL is a closed port: every FIDO list fetch fails.
const harnessMDSURL = "http://127.0.0.1:9/mds.jwt"

var harnessSignInMethods = map[string][]signin.Method{
	"root":  {signin.SecurityKey},
	"alice": {signin.PasskeySynced, signin.SecurityKey},
	"bob":   {},
	"carol": {},
	"dave":  {},
	"erin":  {signin.PasskeyDevice},
}

func seedSignIn(t *testing.T, e *instEnv) {
	t.Helper()
	h := e.s.Hub
	ctx := context.Background()
	root := directory.Human("root")
	// As cmd/hub wires them.
	e.s.Directory.PasswordSet = h.RecordPassword
	e.s.Directory.PasswordMethodOn = h.PasswordMethodOn
	h.SetSignInSources(hub.SignInSources{
		Passkeys: func(context.Context) (map[string][]keycloak.PasskeyCredential, error) {
			out := map[string][]keycloak.PasskeyCredential{}
			for _, u := range e.ll.UserIDs() {
				ms, ok := harnessSignInMethods[u]
				if !ok && strings.HasPrefix(u, "user") {
					ms = []signin.Method{signin.PasskeySynced}
				}
				list := []keycloak.PasskeyCredential{}
				for _, m := range ms {
					list = append(list, keycloak.PasskeyCredential{ID: u + "-" + string(m), Type: string(m)})
				}
				out[u] = list
			}
			return out, nil
		},
		Certificates: func(context.Context) ([]invite.CertRecord, error) { return []invite.CertRecord{}, nil },
	})
	for _, u := range []string{"bob", "carol"} {
		if err := h.RecordPassword(u, e.ll.UUIDOf(u), "root"); err != nil {
			t.Fatalf("recording %s's password: %v", u, err)
		}
	}
	if _, err := h.SetMethod(ctx, signin.Password, true, root); err != nil {
		t.Fatalf("switching password on: %v", err)
	}
	if _, err := h.SetTemplateEnabled(ctx, "basic", true, root); err != nil {
		t.Fatalf("enabling basic: %v", err)
	}
	rule := func(s string) signin.Node {
		var n signin.Node
		if err := json.Unmarshal([]byte(s), &n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, c := range []struct{ id, name, rule string }{
		{"family", "Family", `{"op":"any","items":[{"op":"all","items":["password","family:passkey"]},"security_key"]}`},
		{"engineering", "Engineering", `{"op":"all","items":[{"op":"any","items":[{"op":"all","items":["password","security_key"]},{"op":"all","items":["family:yubikey","family:passkey"]}]},"family:certificate"]}`},
	} {
		if _, err := h.SaveTemplate(ctx, c.id, hub.TemplateInput{Name: c.name, Rule: rule(c.rule)}, true, root); err != nil {
			t.Fatalf("creating %s: %v", c.id, err)
		}
	}
	if _, err := h.CreateInstanceAs(hub.CreateRequest{Template: "vault", ID: "vault", Label: "Vault"}, root); err != nil {
		t.Fatalf("creating vault: %v", err)
	}
	pick := "family"
	if _, err := h.SaveSettings("gitea-ops", hub.SettingsUpdate{SignInTemplate: &pick}, root); err != nil {
		t.Fatalf("gitea-ops picks family: %v", err)
	}
	// The FIDO list: every fetch fails (Settings → Sign-in's warning).
	go h.RunMDS(ctx, time.Hour)
}
