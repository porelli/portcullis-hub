package keycloak_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// accessRealm is a realm like core's: portcullis-universal as the browser
// flow, the LDAP group mapper, users_netbird in LLDAP only (not imported
// yet), alice a member, bob not; clients netbird (owned by instance
// netbird) and other.
func accessRealm(t *testing.T) (*kctest.Server, *keycloak.Client) {
	t.Helper()
	kc := kctest.New(t)
	kc.SeedUniversalFlow()
	kc.AddGroupMapper()
	kc.AddLDAPGroup("users_netbird")
	kc.AddLDAPGroup("users_other")
	kc.AddClient("netbird", map[string]string{keycloak.OwnerAttr: "netbird"})
	kc.AddClient("other", map[string]string{keycloak.OwnerAttr: "other"})
	kc.Import("alice")
	kc.Import("bob")
	kc.JoinGroup("alice", "users_netbird")
	return kc, keycloak.New(kc.HTTP.URL, "admin", "admin")
}

var netbirdAccess = keycloak.AccessSpec{ClientID: "netbird", TemplateID: "netbird", Group: "users_netbird"}

func mutations(kc *kctest.Server) int {
	return kc.CountCalls("POST /admin/realms") + kc.CountCalls("PUT ") + kc.CountCalls("DELETE ")
}

func TestClientAccessRoleEnforced(t *testing.T) {
	ctx := context.Background()
	kc, c := accessRealm(t)
	// Before: any realm user signs in (the app checks no group).
	if err := kc.Login("netbird", "bob", false); err != nil {
		t.Fatalf("before: %v", err)
	}
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	if !kc.ClientRole("netbird", keycloak.AccessRole) {
		t.Error("no access role")
	}
	if got := kc.RoleGroups("netbird", keycloak.AccessRole); strings.Join(got, ",") != "users_netbird" {
		t.Errorf("role groups = %v (the group must have been imported by the LDAP sync)", got)
	}
	cl := kc.ClientByClientID("netbird")
	fid := cl.AuthenticationFlowBindingOverrides["browser"]
	flow := kc.FlowByID(fid)
	if flow == nil || !strings.HasPrefix(flow.Alias, keycloak.AccessFlowPrefix+"-netbird-") || !flow.TopLevel {
		t.Fatalf("browser override = %q (%+v)", fid, flow)
	}
	if cl.DirectAccessGrantsEnabled == nil || *cl.DirectAccessGrantsEnabled || cl.Attributes["oauth2.device.authorization.grant.enabled"] != "false" {
		t.Errorf("grants that skip the browser flow left on: %+v %v", cl.DirectAccessGrantsEnabled, cl.Attributes)
	}
	// Shape: the whole sign-in, then the deny at the top level; the invite
	// IdP redirector is not copied.
	got := strings.Join(kc.FlowProviders(fid), "\n")
	for _, want := range []string{
		"0:REQUIRED:[" + flow.Alias + ".sign-in]",
		"1:ALTERNATIVE:auth-cookie",
		"1:ALTERNATIVE:[" + flow.Alias + ".portcullis-step-up]",
		"3:REQUIRED:[" + flow.Alias + ".portcullis-loa-1-factors]",
		"0:CONDITIONAL:[" + flow.Alias + ".deny]",
		"1:REQUIRED:conditional-user-role",
		"1:REQUIRED:deny-access-authenticator",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("flow lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "identity-provider-redirector") {
		t.Errorf("copied the IdP redirector:\n%s", got)
	}

	// alice (member) signs in, with or without an SSO session; bob is
	// denied on both paths — the SSO cookie is no way around the check.
	for _, sso := range []bool{false, true} {
		if err := kc.Login("netbird", "alice", sso); err != nil {
			t.Errorf("alice (sso %v): %v", sso, err)
		}
		if err := kc.Login("netbird", "bob", sso); !errors.Is(err, kctest.ErrDenied) {
			t.Errorf("bob (sso %v): %v, want denied", sso, err)
		}
		// Other clients keep the realm's flow.
		if err := kc.Login("other", "bob", sso); err != nil {
			t.Errorf("bob on other (sso %v): %v", sso, err)
		}
	}

	// Another instance's client is no way in for netbird's members.
	other := keycloak.AccessSpec{ClientID: "other", TemplateID: "other", Group: "users_other"}
	if err := c.EnsureClientAccess(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := kc.Login("other", "alice", true); !errors.Is(err, kctest.ErrDenied) {
		t.Errorf("alice on other: %v, want denied", err)
	}

	// Keycloak's user-role condition doesn't hold for a role that doesn't
	// exist: deleting the role opens the client. The next ensure puts it
	// back (and RemoveClientAccess unbinds before deleting the role).
	kc.DeleteClientRole("netbird", keycloak.AccessRole)
	if err := kc.Login("netbird", "bob", true); err != nil {
		t.Fatalf("fake: a missing role should not deny (Keycloak's behaviour): %v", err)
	}
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	if err := kc.Login("netbird", "bob", true); !errors.Is(err, kctest.ErrDenied) {
		t.Errorf("bob after re-ensure: %v", err)
	}
	if err := kc.Login("netbird", "alice", true); err != nil {
		t.Errorf("alice after re-ensure: %v", err)
	}
}

func TestClientAccessIdempotent(t *testing.T) {
	ctx := context.Background()
	kc, c := accessRealm(t)
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	flows, configs := kc.FlowCount(), kc.ConfigCount()
	before := mutations(kc)
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	if n := mutations(kc) - before; n != 0 {
		t.Errorf("a second ensure changed things: %d mutating calls", n)
	}

	// Drift is put back: the role on another group, granted directly, the
	// override removed, direct grants switched on.
	kc.AddGroup("intruders")
	kc.JoinGroup("bob", "intruders")
	if err := c.EnsureClientAccess(ctx, keycloak.AccessSpec{ClientID: "netbird", TemplateID: "netbird", Group: "intruders"}); err != nil {
		t.Fatal(err)
	}
	kc.Import("carol")
	kc.GrantClientRole("carol", "netbird", keycloak.AccessRole)
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	if got := kc.RoleGroups("netbird", keycloak.AccessRole); strings.Join(got, ",") != "users_netbird" {
		t.Errorf("role groups = %v", got)
	}
	for _, u := range []string{"bob", "carol"} {
		if err := kc.Login("netbird", u, true); !errors.Is(err, kctest.ErrDenied) {
			t.Errorf("%s: %v, want denied", u, err)
		}
	}
	if kc.FlowCount() != flows || kc.ConfigCount() != configs {
		t.Errorf("flows/configs %d/%d, want %d/%d", kc.FlowCount(), kc.ConfigCount(), flows, configs)
	}

	// Core rebuilds its browser flow with a different config: the next
	// ensure builds a new copy, rebinds the client and deletes the old one
	// with its configs.
	old := kc.ClientByClientID("netbird").AuthenticationFlowBindingOverrides["browser"]
	kc.With(func() {
		for _, cfg := range kc.AuthConfigs {
			if cfg.Config["loa-condition-level"] == "2" {
				cfg.Config["loa-max-age"] = "0"
			}
		}
	})
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	cur := kc.ClientByClientID("netbird").AuthenticationFlowBindingOverrides["browser"]
	if cur == old || kc.FlowByID(old) != nil || kc.FlowByID(cur) == nil {
		t.Errorf("source change: old %s (still there: %v), new %s", old, kc.FlowByID(old) != nil, cur)
	}
	if kc.FlowCount() != flows || kc.ConfigCount() != configs {
		t.Errorf("after rebuild flows/configs %d/%d, want %d/%d", kc.FlowCount(), kc.ConfigCount(), flows, configs)
	}

	// A leftover of an interrupted build (same alias, no completion
	// marker, never bound) is deleted and built again.
	alias := kc.FlowByID(cur).Alias
	if err := c.RemoveClientAccess(ctx, "netbird", "netbird", nil); err != nil {
		t.Fatal(err)
	}
	kc.AddFlow(alias, "half-built", kctest.Node{Requirement: "REQUIRED", Provider: "auth-cookie"})
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	f := kc.FlowByID(kc.ClientByClientID("netbird").AuthenticationFlowBindingOverrides["browser"])
	if f == nil || f.Alias != alias || !strings.HasSuffix(f.Description, "[complete]") {
		t.Errorf("rebuilt flow = %+v", f)
	}
	if kc.FlowCount() != flows || kc.ConfigCount() != configs {
		t.Errorf("after an interrupted build flows/configs %d/%d, want %d/%d", kc.FlowCount(), kc.ConfigCount(), flows, configs)
	}
	if err := kc.Login("netbird", "bob", true); !errors.Is(err, kctest.ErrDenied) {
		t.Errorf("bob: %v", err)
	}
}

func TestClientAccessGroupMissing(t *testing.T) {
	ctx := context.Background()
	kc, c := accessRealm(t)
	spec := keycloak.AccessSpec{ClientID: "netbird", TemplateID: "netbird", Group: "users_netbird-b"}
	err := c.EnsureClientAccess(ctx, spec)
	if !errors.Is(err, keycloak.ErrGroupNotFound) {
		t.Fatalf("missing group: %v", err)
	}
	// Fail closed: the role and the flow are in place, nobody gets in.
	if kc.ClientByClientID("netbird").AuthenticationFlowBindingOverrides["browser"] == "" || !kc.ClientRole("netbird", keycloak.AccessRole) {
		t.Fatal("no role/binding while the group is missing")
	}
	for _, u := range []string{"alice", "bob"} {
		if err := kc.Login("netbird", u, true); !errors.Is(err, kctest.ErrDenied) {
			t.Errorf("%s: %v, want denied", u, err)
		}
	}
	// The group shows up in LLDAP: the next ensure imports and maps it.
	kc.AddLDAPGroup("users_netbird-b")
	kc.JoinGroup("bob", "users_netbird-b")
	if err := c.EnsureClientAccess(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := kc.Login("netbird", "bob", true); err != nil {
		t.Errorf("bob after the group exists: %v", err)
	}
}

func TestClientAccessCleanup(t *testing.T) {
	ctx := context.Background()
	kc, c := accessRealm(t)
	baseFlows, baseConfigs := kc.FlowCount(), kc.ConfigCount()
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveClientAccess(ctx, "netbird", "netbird", nil); err != nil {
		t.Fatal(err)
	}
	cl := kc.ClientByClientID("netbird")
	if cl.AuthenticationFlowBindingOverrides["browser"] != "" || kc.ClientRole("netbird", keycloak.AccessRole) {
		t.Errorf("after cleanup: override %v, role %v", cl.AuthenticationFlowBindingOverrides, kc.ClientRole("netbird", keycloak.AccessRole))
	}
	if len(kc.RoleGroups("netbird", keycloak.AccessRole)) != 0 {
		t.Error("group mapping left")
	}
	if kc.FlowCount() != baseFlows || kc.ConfigCount() != baseConfigs {
		t.Errorf("flows/configs %d/%d, want %d/%d", kc.FlowCount(), kc.ConfigCount(), baseFlows, baseConfigs)
	}
	for _, a := range kc.TopLevelFlows() {
		if strings.HasPrefix(a, keycloak.AccessFlowPrefix) {
			t.Errorf("flow %s left", a)
		}
	}
	// Idempotent; and with the client already deleted the flows still go.
	if err := c.RemoveClientAccess(ctx, "netbird", "netbird", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	id := kc.ClientByClientID("netbird").ID
	kc.With(func() { delete(kc.Clients, id) }) // Keycloak drops its role and overrides with it
	if err := c.RemoveClientAccess(ctx, "netbird", "netbird", nil); err != nil {
		t.Fatal(err)
	}
	if kc.FlowCount() != baseFlows {
		t.Errorf("flows of a deleted client left: %v", kc.TopLevelFlows())
	}
	// An admin's own "access" role on a Hub client (not the Hub's) stays.
	kc.AddClientRole("other", keycloak.AccessRole, "ours, not the Hub's")
	if err := c.RemoveClientAccess(ctx, "other", "other", nil); err != nil {
		t.Fatal(err)
	}
	if !kc.ClientRole("other", keycloak.AccessRole) {
		t.Error("removed a role the Hub didn't create")
	}
	// A client of another owner is refused / left alone.
	var ce *keycloak.ConflictError
	if err := c.EnsureClientAccess(ctx, keycloak.AccessSpec{ClientID: "other", TemplateID: "netbird", Group: "users_netbird"}); !errors.As(err, &ce) {
		t.Errorf("foreign client: %v", err)
	}
	if err := c.EnsureClientAccess(ctx, keycloak.AccessSpec{ClientID: keycloak.ForwardAuthClient, TemplateID: "x", Group: "g"}); !errors.As(err, &ce) {
		t.Errorf("core client: %v", err)
	}
}

func TestBackchannelLogoutURL(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	url := "https://cloud.example.org/index.php/apps/user_oidc/backchannel-logout/Portcullis"
	spec := keycloak.ClientSpec{ClientID: "nextcloud", TemplateID: "nextcloud", RedirectURIs: []string{"https://cloud.example.org/cb"}, BackchannelLogoutURL: url}
	if err := c.RegisterClient(ctx, spec); err != nil {
		t.Fatal(err)
	}
	a := kc.ClientByClientID("nextcloud").Attributes
	if a["backchannel.logout.url"] != url || a["backchannel.logout.session.required"] != "true" {
		t.Errorf("created: %v", a)
	}
	// Reconcile keeps it; a spec without one leaves the client's setting.
	kc.With(func() {
		for _, cl := range kc.Clients {
			cl.Attributes["backchannel.logout.url"] = "https://stale.example.org/x"
		}
	})
	if err := c.RegisterClient(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if got := kc.ClientByClientID("nextcloud").Attributes["backchannel.logout.url"]; got != url {
		t.Errorf("reconciled: %s", got)
	}
	spec.BackchannelLogoutURL = ""
	if err := c.RegisterClient(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if got := kc.ClientByClientID("nextcloud").Attributes["backchannel.logout.url"]; got != url {
		t.Errorf("spec without one: %s", got)
	}
	// A hostname change moves it with the host.
	spec.RedirectURIs = []string{"https://files.example.org/cb"}
	if err := c.UpdateClientHosts(ctx, spec, []string{"https://cloud.example.org/cb"}, map[string]string{"cloud.example.org": "files.example.org"}); err != nil {
		t.Fatal(err)
	}
	if got := kc.ClientByClientID("nextcloud").Attributes["backchannel.logout.url"]; got != "https://files.example.org/index.php/apps/user_oidc/backchannel-logout/Portcullis" {
		t.Errorf("after a host change: %s", got)
	}
}
