package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// vpn is netbird-like: native OIDC, the app checks no group.
const vpnManifest = `name: VPN
category: network
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: native-oidc
  sso: true
  group_access: false
  access_group: users_vpn
keycloak_clients:
  - client_id: vpn
    redirect_uri: https://{{HOST_VPN}}/cb
`

const vpnCompose = "services:\n  web:\n    image: x\n    labels:\n" +
	"      traefik.http.routers.vpn.rule: Host(`${PORTCULLIS_HOST_VPN:-vpn.portcullis.local}`)\n"

// home is synapse-like: its hostname is part of every id.
const homeManifest = `name: Home
category: chat
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: native-oidc
  sso: true
  group_access: true
  access_group: users_home
hosts:
  immutable: [home]
keycloak_clients:
  - client_id: home
    redirect_uri: https://{{HOST_HOME}}/cb
    backchannel_logout_url: https://{{HOST_HOME}}/_synapse/client/oidc/backchannel_logout
`

const homeCompose = "services:\n  web:\n    image: x\n    labels:\n" +
	"      traefik.http.routers.home.rule: Host(`${PORTCULLIS_HOST_HOME:-home.portcullis.local}`)\n" +
	"      traefik.http.routers.media.rule: Host(`${PORTCULLIS_HOST_MEDIA:-media.portcullis.local}`)\n"

var accessTemplates = map[string][2]string{"vpn": {vpnManifest, vpnCompose}, "home": {homeManifest, homeCompose}}

func accessFixture(t *testing.T) (*fixture, *kctest.Server) {
	t.Helper()
	kc := kctest.New(t)
	kc.SeedUniversalFlow()
	kc.AddGroupMapper()
	kc.AddLDAPGroup("users_vpn")
	kc.Importable = func(string) bool { return true }
	for _, u := range []string{"alice", "bob"} {
		kc.Import(u)
	}
	kc.JoinGroup("alice", "users_vpn")
	f := newInstanceFixtureExtra(t, nil, keycloak.New(kc.HTTP.URL, "admin", "admin"), accessTemplates)
	f.h.SetAudit(&fakeAudit{})
	return f, kc
}

func mutatingCalls(kc *kctest.Server) int {
	return kc.CountCalls("POST /admin/realms") + kc.CountCalls("PUT ") + kc.CountCalls("DELETE ")
}

func TestEnableEnforcesAccessRole(t *testing.T) {
	ctx := context.Background()
	f, kc := accessFixture(t)
	if err := f.h.Enable("vpn"); err != nil {
		t.Fatal(err)
	}
	if !kc.ClientRole("vpn", keycloak.AccessRole) || strings.Join(kc.RoleGroups("vpn", keycloak.AccessRole), ",") != "users_vpn" {
		t.Fatalf("vpn: role %v groups %v", kc.ClientRole("vpn", keycloak.AccessRole), kc.RoleGroups("vpn", keycloak.AccessRole))
	}
	if err := kc.Login("vpn", "alice", true); err != nil {
		t.Errorf("alice on vpn: %v", err)
	}
	if err := kc.Login("vpn", "bob", true); !errors.Is(err, kctest.ErrDenied) {
		t.Errorf("bob on vpn: %v, want denied", err)
	}

	// A second instance: its group users_vpn-b doesn't exist yet. Enable
	// still starts it, and its client denies everybody (fail closed).
	if err := f.h.CreateInstance("vpn", "vpn-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("vpn-b"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob"} {
		if err := kc.Login("vpn-b", u, true); !errors.Is(err, kctest.ErrDenied) {
			t.Errorf("%s on vpn-b before its group exists: %v", u, err)
		}
	}
	// The sync reports no error for the missing group (no quick retry
	// loop of LDAP group syncs) and the client keeps denying.
	if err := f.h.SyncClientAccess(ctx); err != nil {
		t.Fatalf("sync with vpn-b's group missing: %v", err)
	}
	if err := kc.Login("vpn-b", "bob", true); !errors.Is(err, kctest.ErrDenied) {
		t.Errorf("bob on vpn-b before its group exists: %v", err)
	}
	// The group is created and bob added: the sync maps it. Team A's
	// member still can't open team B's instance, and vice versa.
	kc.AddLDAPGroup("users_vpn-b")
	kc.JoinGroup("bob", "users_vpn-b")
	if err := f.h.SyncClientAccess(ctx); err != nil {
		t.Fatal(err)
	}
	if err := kc.Login("vpn-b", "bob", true); err != nil {
		t.Errorf("bob on vpn-b: %v", err)
	}
	if err := kc.Login("vpn-b", "alice", true); !errors.Is(err, kctest.ErrDenied) {
		t.Errorf("alice on vpn-b: %v", err)
	}
	if err := kc.Login("vpn", "bob", true); !errors.Is(err, kctest.ErrDenied) {
		t.Errorf("bob on vpn: %v", err)
	}
	// group_access: true apps without the flag keep the realm's flow.
	if err := f.h.Enable("chat"); err != nil {
		t.Fatal(err)
	}
	if kc.ClientByClientID("chat").AuthenticationFlowBindingOverrides["browser"] != "" || kc.ClientRole("chat", keycloak.AccessRole) {
		t.Error("chat got an access role")
	}

	// Idempotent reconcile.
	before := mutatingCalls(kc)
	if err := f.h.SyncClientAccess(ctx); err != nil {
		t.Fatal(err)
	}
	if n := mutatingCalls(kc) - before; n != 0 {
		t.Errorf("second sync: %d mutating calls", n)
	}

	// Cleanup (guarded delete calls it): role, mapping, binding and the
	// access flows go; the other instance is untouched.
	flowsBefore := kc.TopLevelFlows()
	v := f.h.Template("vpn-b")
	if err := f.h.RemoveInstanceAccess(ctx, v); err != nil {
		t.Fatal(err)
	}
	if kc.ClientRole("vpn-b", keycloak.AccessRole) || kc.ClientByClientID("vpn-b").AuthenticationFlowBindingOverrides["browser"] != "" {
		t.Error("vpn-b access left")
	}
	for _, a := range kc.TopLevelFlows() {
		if strings.HasPrefix(a, keycloak.AccessFlowPrefix+"-vpn-b-") {
			t.Errorf("flow %s left", a)
		}
	}
	if len(kc.TopLevelFlows()) != len(flowsBefore)-1 {
		t.Errorf("flows %v → %v", flowsBefore, kc.TopLevelFlows())
	}
	if err := kc.Login("vpn", "bob", true); !errors.Is(err, kctest.ErrDenied) {
		t.Errorf("vpn after vpn-b cleanup: %v", err)
	}
	if err := f.h.RemoveInstanceAccess(ctx, v); err != nil {
		t.Errorf("second cleanup: %v", err)
	}
}

func TestEnableRefusesWithoutAccessRole(t *testing.T) {
	f, kc := accessFixture(t)
	// Keycloak can't build the flow: the app must not start.
	kc.SetFailPrefix("POST /admin/realms/portcullis/authentication/flows")
	err := f.h.Enable("vpn")
	kc.SetFailPrefix("")
	if statusOf(err) != 502 {
		t.Fatalf("enable: %v", err)
	}
	for _, c := range f.runner.Calls() {
		if strings.HasPrefix(c, "up:") {
			t.Errorf("compose ran: %v", f.runner.Calls())
		}
	}
	if f.h.Template("vpn").Enabled {
		t.Error("vpn enabled")
	}
	// fakeIdP: a missing group is no reason to refuse; anything else is.
	g := newInstanceFixtureExtra(t, nil, nil, accessTemplates)
	g.idp.accessErr = keycloak.ErrGroupNotFound
	if err := g.h.Enable("vpn"); err != nil {
		t.Errorf("missing group: %v", err)
	}
	if got := strings.Join(g.idp.accessCalls(), ","); got != "+vpn:vpn:users_vpn" {
		t.Errorf("access calls = %s", got)
	}
}

func TestBackchannelLogoutURLRegistered(t *testing.T) {
	f, kc := accessFixture(t)
	if err := f.h.CreateInstance("home", "home-b", map[string]string{"home": "matrix-b.example.org", "media": "media-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("home-b"); err != nil {
		t.Fatal(err)
	}
	a := kc.ClientByClientID("home-b").Attributes
	if a["backchannel.logout.url"] != "https://matrix-b.example.org/_synapse/client/oidc/backchannel_logout" || a["backchannel.logout.session.required"] != "true" {
		t.Errorf("attributes = %v", a)
	}
}

func TestImmutableHostRefused(t *testing.T) {
	f, kc := accessFixture(t)
	// CreateInstance may choose it.
	if err := f.h.CreateInstance("home", "home-b", map[string]string{"home": "matrix-b.example.org", "media": "media-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("home-b"); err != nil {
		t.Fatal(err)
	}
	clientBefore := kc.ClientByClientID("home-b")
	err := f.h.SetHosts("home-b", map[string]string{"home": "chat-b.example.org", "media": "media-b.example.org"}, directory.Human("alice"))
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "can't change") {
		t.Fatalf("immutable change: %v", err)
	}
	if v := f.h.Template("home-b"); v.Hosts["home"] != "matrix-b.example.org" {
		t.Errorf("hosts = %v", v.Hosts)
	}
	if got := kc.ClientByClientID("home-b"); strings.Join(got.RedirectURIs, ",") != strings.Join(clientBefore.RedirectURIs, ",") {
		t.Errorf("Keycloak touched: %v", got.RedirectURIs)
	}
	// The other host router may move; the default instance's immutable
	// host is fixed too.
	if err := f.h.SetHosts("home-b", map[string]string{"home": "matrix-b.example.org", "media": "files-b.example.org"}, directory.Human("alice")); err != nil {
		t.Errorf("mutable router: %v", err)
	}
	if err := f.h.SetHosts("home", map[string]string{"home": "matrix.example.org", "media": "media.example.org"}, directory.Human("alice")); statusOf(err) != 409 || !strings.Contains(err.Error(), "can't change") {
		t.Errorf("default instance: %v", err)
	}
}
