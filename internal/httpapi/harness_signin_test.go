//go:build harness

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
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
	certs := newHarnessCerts()
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
		Certificates: certs.list,
	})
	// The Sign-in page (sign-in part 2 Task 8): enroll's certificate
	// actions in memory, Keycloak's login events for alice, the real audit;
	// the opened log isn't mounted (the page names it as unknown).
	h.SetCertActions(certs)
	h.SetSignInHelp(e.s.Directory)
	h.SetOwnPasswords(e.s.Directory)
	h.SetHistorySources(hub.HistorySources{Events: harnessLoginEvents, Audit: e.s.Directory.RecentMatching})
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
	// Browser and YubiKey certificates are on (the Sign-in page's rows).
	for _, m := range []signin.Method{signin.BrowserCert, signin.YubiKeyCert} {
		if _, err := h.SetMethod(ctx, m, true, root); err != nil {
			t.Fatalf("switching %s on: %v", m, err)
		}
	}
	// The FIDO list: every fetch fails (Settings → Sign-in's warning).
	go h.RunMDS(ctx, time.Hour)
}

// harnessCerts is enroll's certificates in memory: alice holds a YubiKey
// certificate expiring in 5 days, a valid browser certificate and a
// revoked one; bob a browser certificate. Creating one answers a fake
// .p12 and a fixed-format password; revoking marks the record.
type harnessCerts struct {
	mu   sync.Mutex
	recs []invite.CertRecord
	n    int
}

func newHarnessCerts() *harnessCerts {
	now := time.Now().UTC().Truncate(time.Second)
	return &harnessCerts{recs: []invite.CertRecord{
		{User: "alice", Serial: "4f:2a:9c:01", Kind: invite.KindYubiKey, NotBefore: now.Add(-353 * 24 * time.Hour), NotAfter: now.Add(5 * 24 * time.Hour)},
		{User: "alice", Serial: "1a:2b:3c:04", Kind: invite.KindBrowser, NotBefore: now.Add(-3 * 24 * time.Hour), NotAfter: now.Add(27 * 24 * time.Hour)},
		{User: "alice", Serial: "0b:0b:0b:05", Kind: invite.KindBrowser, NotBefore: now.Add(-40 * 24 * time.Hour), NotAfter: now.Add(-10 * 24 * time.Hour), Revoked: true},
		{User: "bob", Serial: "0c:0c:0c:06", Kind: invite.KindBrowser, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(29 * 24 * time.Hour)},
	}}
}

func (c *harnessCerts) list(context.Context) ([]invite.CertRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.recs), nil
}

func (c *harnessCerts) add(user string, kind invite.CertKind, d time.Duration) invite.CertRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	now := time.Now().UTC().Truncate(time.Second)
	r := invite.CertRecord{User: user, Serial: fmt.Sprintf("7e:%02x:%02x:%02x", c.n, c.n*7%256, c.n*13%256), Kind: kind, NotBefore: now, NotAfter: now.Add(d)}
	c.recs = append(c.recs, r)
	return r
}

func (c *harnessCerts) CreateBrowserCertificate(_ context.Context, r invite.BrowserCertRequest) (*invite.BrowserCert, error) {
	rec := c.add(r.User, invite.KindBrowser, time.Duration(r.Days)*24*time.Hour)
	return &invite.BrowserCert{P12: []byte("harness: not a real PKCS#12 file\n"), Password: "H4RN5-ESS7Q-ABCDE-FGHJK", Serial: rec.Serial,
		Filename: r.User + "-browser-certificate-" + rec.NotBefore.Format("20060102") + ".p12", NotAfter: rec.NotAfter}, nil
}

const harnessPEM = "-----BEGIN CERTIFICATE-----\nMIIBharness\n-----END CERTIFICATE-----\n"

func (c *harnessCerts) IssueYubiKeyCertificate(_ context.Context, user, _ string) (*invite.IssuedCert, error) {
	rec := c.add(user, invite.KindYubiKey, 365*24*time.Hour)
	return &invite.IssuedCert{PEM: harnessPEM, Serial: rec.Serial, NotAfter: rec.NotAfter}, nil
}

func (c *harnessCerts) RenewYubiKeyCertificate(_ context.Context, user, _, _ string) (*invite.IssuedCert, error) {
	rec := c.add(user, invite.KindYubiKey, 365*24*time.Hour)
	return &invite.IssuedCert{PEM: harnessPEM, Serial: rec.Serial, NotAfter: rec.NotAfter}, nil
}

func (c *harnessCerts) RevokeCertificate(_ context.Context, user, serial string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.recs {
		if c.recs[i].User == user && c.recs[i].Serial == serial {
			c.recs[i].Revoked = true
			return nil
		}
	}
	return &hub.StatusError{Status: 404, Err: errors.New("no such certificate")}
}

// harnessLoginEvents is Keycloak's login events: alice's sign-ins, a
// failed password, a setup-link sign-in and a fresh sign-in; one
// User-Agent carries markup.
func harnessLoginEvents(_ context.Context, user string, from, to time.Time, first, max int) ([]keycloak.Event, error) {
	if user != "alice" {
		return nil, nil
	}
	now := time.Now().UTC()
	ff := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:132.0) Gecko/20100101 Firefox/132.0"
	sa := "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
	all := []keycloak.Event{
		{Time: now.Add(-20 * time.Minute), Type: "LOGIN", ClientID: "portcullis-fresh-auth", IP: "203.0.113.7", Details: map[string]string{"pc_kind": "sign_in", "pc_methods": "security_key", "pc_ua": ff}},
		{Time: now.Add(-2 * time.Hour), Type: "LOGIN", ClientID: "oauth2-proxy", IP: "203.0.113.7", Details: map[string]string{"pc_kind": "sign_in", "pc_methods": "security_key", "pc_ua": ff}},
		{Time: now.Add(-26 * time.Hour), Type: "LOGIN_ERROR", ClientID: "oauth2-proxy", IP: "198.51.100.4", Error: "invalid_user_credentials", Details: map[string]string{"pc_method": "password", "pc_ua": sa}},
		{Time: now.Add(-27 * time.Hour), Type: "LOGIN", ClientID: "oauth2-proxy", IP: "198.51.100.4", Details: map[string]string{"pc_kind": "step_up", "pc_methods": "passkey_synced", "pc_ua": sa + " <img src=x onerror=alert(1)>"}},
		{Time: now.Add(-9 * 24 * time.Hour), Type: "LOGIN", ClientID: "portcullis-invite-client", IP: "198.51.100.4", Details: map[string]string{"pc_kind": "sign_in", "pc_ua": sa}},
	}
	var out []keycloak.Event
	for _, e := range all {
		if !e.Time.Before(from) && e.Time.Before(to) {
			out = append(out, e)
		}
	}
	if first >= len(out) {
		return nil, nil
	}
	return out[first:min(len(out), first+max)], nil
}

// harnessImpKC is the harness's Keycloak for signing in as someone else
// (sign-in part 3 Task 8 fix round 1): every person enabled, no
// required action, the notice a no-op.
type harnessImpKC struct{}

func (harnessImpKC) UserEnabled(context.Context, string) (bool, error)         { return true, nil }
func (harnessImpKC) RequiredActions(context.Context, string) ([]string, error) { return nil, nil }
func (harnessImpKC) RequireImpersonationNotice(context.Context, string) error  { return nil }

// harnessImpPerson is the person the harness's running impersonation
// is of; harnessImpAdmin the second administrator who runs it (sam
// signed in as erin), so root may still start one (one at a time).
const (
	harnessImpPerson = "erin"
	harnessImpAdmin  = "sam"
)

// seedImpersonation wires harnessImpKC (so root's view of alice offers
// "Sign in as alice…"), adds the administrator sam and starts sam's
// impersonation of erin through
// the real start (a fake fresh-auth code: a security key touch), so
// erin's person page shows the running line and Settings → Sign-in
// lists it. A people-listener request with the cookie harness_imp=1 gets
// X-Forwarded-Impersonation = its id (as group-gate sets it): signed in
// as erin (harness_user=erin) the pages show the banner and are
// read-only. No expiry loop runs: it stays running until its until.
func seedImpersonation(t *testing.T, e *instEnv, fa *harnessFreshAuth) string {
	t.Helper()
	h := e.s.Hub
	h.SetImpersonationKeycloak(harnessImpKC{})
	e.ll.AddUser(harnessImpAdmin, harnessImpAdmin+"@example.org", "Sam", "", "lldap_admin")
	const verifier = "imp-verifier-0123456789012345678901234567890123"
	fa.mu.Lock()
	fa.codes["imp-seed"] = harnessCode{challenge: s256B64(verifier), nonce: "imp-nonce", user: harnessImpAdmin}
	fa.mu.Unlock()
	st, err := h.StartImpersonation(context.Background(), hub.StartImpersonation{Target: harnessImpPerson, Reason: "checking the <b>harness</b> banner",
		AdminSID: "harness-sid", Listener: hub.ListenerPeople, Proof: freshauth.Proof{Code: "imp-seed", CodeVerifier: verifier, Nonce: "imp-nonce"}}, directory.Human(harnessImpAdmin))
	if err != nil {
		t.Logf("harness: no running impersonation: %v", err)
		return ""
	}
	return st.ID
}
