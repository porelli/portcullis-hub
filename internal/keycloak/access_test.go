package keycloak_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
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
	// Shape: the whole sign-in, then the positive membership check, then
	// the deny unless that check succeeded, at the top level; the invite
	// IdP redirector is not copied.
	got := strings.Join(kc.FlowProviders(fid), "\n")
	for _, want := range []string{
		"0:REQUIRED:[" + flow.Alias + ".sign-in]",
		"1:ALTERNATIVE:auth-cookie",
		"1:ALTERNATIVE:[" + flow.Alias + ".portcullis-step-up]",
		"3:REQUIRED:[" + flow.Alias + ".portcullis-loa-1-factors]",
		"0:CONDITIONAL:[" + flow.Alias + ".member]\n1:REQUIRED:conditional-user-role\n1:REQUIRED:allow-access-authenticator\n" +
			"0:CONDITIONAL:[" + flow.Alias + ".deny]\n1:REQUIRED:conditional-sub-flow-executed\n1:REQUIRED:deny-access-authenticator",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("flow lacks %q:\n%s", want, got)
		}
	}
	if cfg := kc.ExecConfig(fid, "conditional-user-role"); cfg["condUserRole"] != "netbird.access" || cfg["negate"] != "false" {
		t.Errorf("role condition config = %v", cfg)
	}
	if cfg := kc.ExecConfig(fid, "conditional-sub-flow-executed"); cfg["flow_to_check"] != flow.Alias+".member" || cfg["check_result"] != "not-executed" {
		t.Errorf("sub-flow condition config = %v", cfg)
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
	// exist (even negated): the member check is then skipped and the deny
	// fires — deleting the role locks everybody out, it opens nothing. The
	// next ensure puts it back.
	kc.DeleteClientRole("netbird", keycloak.AccessRole)
	for _, u := range []string{"alice", "bob"} {
		if err := kc.Login("netbird", u, true); !errors.Is(err, kctest.ErrDenied) {
			t.Fatalf("%s with the role deleted: %v, want denied (fail closed)", u, err)
		}
	}
	// The member sub-flow renamed (flow_to_check finds nothing): denied too.
	kc.With(func() {
		for _, f := range kc.Flows {
			if f.Alias == flow.Alias+".member" {
				f.Alias += "-renamed"
			}
		}
	})
	if err := kc.Login("netbird", "alice", true); !errors.Is(err, kctest.ErrDenied) {
		t.Fatalf("alice with the member sub-flow renamed: %v, want denied", err)
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
			if cfg.Config["loa-condition-level"] == "2" && !strings.HasPrefix(cfg.Alias, keycloak.AccessFlowPrefix) {
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

	// A leftover of an interrupted build (no completion marker, never
	// bound) is ignored and deleted; so is a complete copy of an older
	// shape version.
	if err := c.RemoveClientAccess(ctx, "netbird", "netbird", nil); err != nil {
		t.Fatal(err)
	}
	half := kc.AddFlow(keycloak.AccessFlowPrefix+"-netbird-0123456789", "half-built", kctest.Node{Requirement: "REQUIRED", Provider: "auth-cookie"})
	v1 := kc.AddFlow(keycloak.AccessFlowPrefix+"-netbird-abcdefabcd", "old [complete]", kctest.Node{Requirement: "REQUIRED", Provider: "auth-cookie"})
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	f := kc.FlowByID(kc.ClientByClientID("netbird").AuthenticationFlowBindingOverrides["browser"])
	if f == nil || f.ID == half || f.ID == v1 || !strings.HasSuffix(f.Description, "[complete v3]") || kc.FlowByID(half) != nil || kc.FlowByID(v1) != nil {
		t.Errorf("rebuilt flow = %+v (half-built left: %v, v1 left: %v)", f, kc.FlowByID(half) != nil, kc.FlowByID(v1) != nil)
	}
	if kc.FlowCount() != flows || kc.ConfigCount() != configs {
		t.Errorf("after an interrupted build flows/configs %d/%d, want %d/%d", kc.FlowCount(), kc.ConfigCount(), flows, configs)
	}
	if err := kc.Login("netbird", "bob", true); !errors.Is(err, kctest.ErrDenied) {
		t.Errorf("bob: %v", err)
	}
}

// TestClientAccessCopyRepaired: an edit to the Hub's bound copy is
// noticed on the next ensure (the copy is compared with what the Hub would
// build) and replaced by a fresh copy.
func TestClientAccessCopyRepaired(t *testing.T) {
	ctx := context.Background()
	for name, tamper := range map[string]func(kc *kctest.Server, alias string){
		"deny disabled": func(kc *kctest.Server, alias string) {
			for _, f := range kc.Flows {
				if f.Alias == alias {
					for _, e := range f.Execs {
						if e.FlowID != "" && kc.Flows[e.FlowID].Alias == alias+".deny" {
							e.Requirement = "DISABLED"
						}
					}
				}
			}
		},
		"role condition repointed": func(kc *kctest.Server, alias string) {
			for _, cfg := range kc.AuthConfigs {
				if cfg.Config["condUserRole"] != "" {
					cfg.Config["condUserRole"] = "other.access"
				}
			}
		},
		"deny removed": func(kc *kctest.Server, alias string) {
			for _, f := range kc.Flows {
				if f.Alias == alias+".deny" {
					delete(kc.AuthConfigs, f.Execs[1].ConfigID) // Keycloak deletes an execution's config with it
					f.Execs = f.Execs[:1]
				}
			}
		},
		"member sub-flow renamed": func(kc *kctest.Server, alias string) {
			for _, f := range kc.Flows {
				if f.Alias == alias+".member" {
					f.Alias = "x"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			kc, c := accessRealm(t)
			kc.AddClientRole("other", keycloak.AccessRole, "x")
			kc.GrantClientRole("bob", "other", keycloak.AccessRole)
			if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
				t.Fatal(err)
			}
			flows, configs := kc.FlowCount(), kc.ConfigCount()
			old := kc.ClientByClientID("netbird").AuthenticationFlowBindingOverrides["browser"]
			alias := kc.FlowByID(old).Alias
			kc.With(func() { tamper(kc, alias) })
			if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
				t.Fatal(err)
			}
			cur := kc.ClientByClientID("netbird").AuthenticationFlowBindingOverrides["browser"]
			if cur == old || kc.FlowByID(old) != nil {
				t.Fatalf("edited copy kept: old %s, bound %s", old, cur)
			}
			if err := kc.Login("netbird", "bob", true); !errors.Is(err, kctest.ErrDenied) {
				t.Errorf("bob: %v, want denied", err)
			}
			if err := kc.Login("netbird", "alice", true); err != nil {
				t.Errorf("alice: %v", err)
			}
			if kc.FlowCount() > flows || kc.ConfigCount() > configs {
				t.Errorf("flows/configs %d/%d, want ≤ %d/%d", kc.FlowCount(), kc.ConfigCount(), flows, configs)
			}
		})
	}
}

// TestClientAccessForeignGrants: every way to hold the role other than
// membership of the access group is removed — composites (realm and
// client roles), other groups and direct grants beyond the first page.
func TestClientAccessForeignGrants(t *testing.T) {
	ctx := context.Background()
	kc, c := accessRealm(t)
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	// default-roles-portcullis (everybody) and a client role bob holds.
	kc.AddComposite("default-roles-portcullis", "netbird", keycloak.AccessRole)
	if err := kc.Login("netbird", "bob", true); err != nil {
		t.Fatalf("fake: a composite should grant the role: %v", err)
	}
	kc.AddClientRole("other", "viewer", "x")
	kc.GrantClientRole("bob", "other", "viewer")
	kc.AddComposite("other.viewer", "netbird", keycloak.AccessRole)
	// More than a page of groups and direct grants.
	for i := 0; i < 130; i++ {
		g := fmt.Sprintf("g%03d", i)
		kc.AddGroup(g)
		u := fmt.Sprintf("u%03d", i)
		kc.Import(u)
		kc.GrantClientRole(u, "netbird", keycloak.AccessRole)
	}
	nb := kc.ClientByClientID("netbird").ID
	kc.With(func() {
		for _, g := range kc.Groups {
			if strings.HasPrefix(g.Name, "g") {
				g.ClientRoles[nb] = []string{keycloak.AccessRole}
			}
		}
	})
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	if got := kc.CompositeParents("netbird", keycloak.AccessRole); len(got) != 0 {
		t.Errorf("composites left: %v", got)
	}
	if got := kc.RoleGroups("netbird", keycloak.AccessRole); strings.Join(got, ",") != "users_netbird" {
		t.Errorf("role groups = %d (%v...)", len(got), got[:min(3, len(got))])
	}
	for _, u := range []string{"bob", "u000", "u129"} {
		if err := kc.Login("netbird", u, true); !errors.Is(err, kctest.ErrDenied) {
			t.Errorf("%s: %v, want denied", u, err)
		}
	}
	if err := kc.Login("netbird", "alice", true); err != nil {
		t.Errorf("alice: %v", err)
	}
	if err := kc.Login("other", "bob", true); err != nil {
		t.Errorf("bob on other (its viewer role kept): %v", err)
	}
}

// TestClientAccessKeepsOrder: a copy keeps the source's execution order,
// DISABLED executions included (Keycloak's execution PUT resets the
// priority unless the representation carries it — gocloak's doesn't).
func TestClientAccessKeepsOrder(t *testing.T) {
	ctx := context.Background()
	kc, c := accessRealm(t)
	// Keycloak's built-in "browser" flow.
	kc.AddFlow("browser", "browser based authentication",
		kctest.Node{Requirement: "ALTERNATIVE", Provider: "auth-cookie"},
		kctest.Node{Requirement: "DISABLED", Provider: "auth-spnego"},
		kctest.Node{Requirement: "ALTERNATIVE", Provider: "identity-provider-redirector"},
		kctest.Node{Requirement: "ALTERNATIVE", Alias: "forms", Children: []kctest.Node{
			{Requirement: "REQUIRED", Provider: "auth-username-password-form"},
			{Requirement: "CONDITIONAL", Alias: "Browser - Conditional OTP", Children: []kctest.Node{
				{Requirement: "REQUIRED", Provider: "conditional-user-configured"},
				{Requirement: "REQUIRED", Provider: "auth-otp-form"},
			}},
		}},
	)
	kc.SetRealmBrowserFlow("browser")
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	fid := kc.ClientByClientID("netbird").AuthenticationFlowBindingOverrides["browser"]
	got := strings.Join(kc.FlowProviders(fid), ",")
	a := kc.FlowByID(fid).Alias
	want := "0:REQUIRED:[" + a + ".sign-in],1:ALTERNATIVE:auth-cookie,1:DISABLED:auth-spnego,1:ALTERNATIVE:[" + a + ".forms]," +
		"2:REQUIRED:auth-username-password-form,2:CONDITIONAL:[" + a + ".Browser - Conditional OTP],3:REQUIRED:conditional-user-configured,3:REQUIRED:auth-otp-form,"
	if !strings.HasPrefix(got, want) {
		t.Errorf("copy order:\n%s\nwant prefix\n%s", got, want)
	}
	before := mutations(kc)
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	if n := mutations(kc) - before; n != 0 {
		t.Errorf("second ensure: %d mutating calls", n)
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
	if _, err := c.RegisterClient(ctx, spec); err != nil {
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
	if _, err := c.RegisterClient(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if got := kc.ClientByClientID("nextcloud").Attributes["backchannel.logout.url"]; got != url {
		t.Errorf("reconciled: %s", got)
	}
	spec.BackchannelLogoutURL = ""
	if _, err := c.RegisterClient(ctx, spec); err != nil {
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

// TestClientAccessTemplateLast (contract §8 "Access role", §8.1): over
// core's sign-in flow the copy leaves out portcullis-template, which the
// access flow runs last, after the member / deny check — a non-member is
// denied before the template step could show a page naming the app. An
// access flow of an older shape (the template inside the copy) is
// rebuilt and rebound.
func TestClientAccessTemplateLast(t *testing.T) {
	ctx := context.Background()
	kc, c := accessRealm(t)
	kc.AddFlow("core-universal", "core's sign-in browser flow",
		kctest.Node{Requirement: "REQUIRED", Alias: "portcullis-authenticate", Children: []kctest.Node{
			{Requirement: "ALTERNATIVE", Provider: "auth-cookie"},
			{Requirement: "ALTERNATIVE", Provider: "identity-provider-redirector"},
			{Requirement: "ALTERNATIVE", Alias: "portcullis-signin", Children: []kctest.Node{
				{Requirement: "ALTERNATIVE", Provider: "portcullis-x509", Config: map[string]string{"default.reference.value": "mtls"}},
				{Requirement: "ALTERNATIVE", Provider: "portcullis-passkey"},
			}},
		}},
		kctest.Node{Requirement: "REQUIRED", Provider: keycloak.TemplateProvider},
	)
	kc.SetRealmBrowserFlow("core-universal")

	// An older Hub's copy, bound: the template inside the sign-in copy.
	oldAlias := keycloak.AccessFlowPrefix + "-netbird-0000000000"
	oldID := kc.AddFlow(oldAlias, "an older copy, current marker (only its shape differs) [complete v3]",
		kctest.Node{Requirement: "REQUIRED", Alias: oldAlias + ".sign-in", Children: []kctest.Node{
			{Requirement: "REQUIRED", Alias: oldAlias + ".portcullis-authenticate", Children: []kctest.Node{
				{Requirement: "ALTERNATIVE", Provider: "auth-cookie"},
			}},
			{Requirement: "REQUIRED", Provider: keycloak.TemplateProvider},
		}},
	)
	kc.With(func() {
		for _, cl := range kc.Clients {
			if cl.ClientID == "netbird" {
				cl.AuthenticationFlowBindingOverrides = map[string]string{"browser": oldID}
			}
		}
	})

	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	fid := kc.ClientByClientID("netbird").AuthenticationFlowBindingOverrides["browser"]
	if fid == oldID {
		t.Fatal("the older-shape access flow was kept")
	}
	a := kc.FlowByID(fid).Alias
	got := kc.FlowProviders(fid)
	if n := strings.Count(strings.Join(got, "\n"), keycloak.TemplateProvider); n != 1 {
		t.Errorf("portcullis-template %d times:\n%s", n, strings.Join(got, "\n"))
	}
	if last := got[len(got)-1]; last != "0:REQUIRED:"+keycloak.TemplateProvider {
		t.Errorf("last step = %q, want the top-level REQUIRED template:\n%s", last, strings.Join(got, "\n"))
	}
	deny := -1
	for i, l := range got {
		if l == "0:CONDITIONAL:["+a+".deny]" {
			deny = i
		}
	}
	if deny < 0 || deny > len(got)-2 {
		t.Errorf("the deny isn't before the template:\n%s", strings.Join(got, "\n"))
	}

	// bob (not a member) is denied without the template step running;
	// alice reaches it, after the member check.
	for _, sso := range []bool{false, true} {
		if err := kc.Login("netbird", "bob", sso); !errors.Is(err, kctest.ErrDenied) {
			t.Errorf("bob (sso %v): %v, want denied", sso, err)
		}
		if ran := kc.LastRun(); slices.Contains(ran, keycloak.TemplateProvider) {
			t.Errorf("bob (sso %v) reached the template step: %v", sso, ran)
		}
		if err := kc.Login("netbird", "alice", sso); err != nil {
			t.Errorf("alice (sso %v): %v", sso, err)
		}
		ran := kc.LastRun()
		if len(ran) < 2 || ran[len(ran)-1] != keycloak.TemplateProvider || ran[len(ran)-2] != "allow-access-authenticator" {
			t.Errorf("alice (sso %v) ran %v, want … allow-access-authenticator, portcullis-template", sso, ran)
		}
	}

	// Stable: the next ensure keeps it.
	before := mutations(kc)
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	if n := mutations(kc) - before; n != 0 {
		t.Errorf("second ensure: %d mutating calls", n)
	}
}

// TestAccessFlowCopiesBothX509Executions (contract §8.1, D29): core's
// portcullis-signin holds two portcullis-x509 executions, the YubiKey one
// (x509-config) and the browser one (x509-browser-config); an access flow
// copies both, in order, each with its own config.
func TestAccessFlowCopiesBothX509Executions(t *testing.T) {
	ctx := context.Background()
	kc, c := accessRealm(t)
	yubikey := map[string]string{"portcullis.method": "yubikey_cert", "default.reference.value": "mtls",
		"portcullis.ca":                    "/opt/keycloak/conf/truststores/portcullis/portcullis-yubikey-ca.pem",
		"x509-cert-auth.crl-relative-path": "pki_int/crl##pki_int/crl/delta"}
	browser := map[string]string{"portcullis.method": "browser_cert", "default.reference.value": "file",
		"portcullis.ca":                    "/opt/keycloak/conf/truststores/portcullis/portcullis-browser-ca.pem",
		"x509-cert-auth.crl-relative-path": "pki_file/crl##pki_file/crl/delta"}
	kc.AddFlow("core-universal", "core's sign-in browser flow",
		kctest.Node{Requirement: "REQUIRED", Alias: "portcullis-authenticate", Children: []kctest.Node{
			{Requirement: "ALTERNATIVE", Provider: "auth-cookie"},
			{Requirement: "ALTERNATIVE", Alias: "portcullis-signin", Children: []kctest.Node{
				{Requirement: "ALTERNATIVE", Provider: "portcullis-x509", Config: yubikey},
				{Requirement: "ALTERNATIVE", Provider: "portcullis-x509", Config: browser},
				{Requirement: "ALTERNATIVE", Provider: "portcullis-passkey"},
			}},
		}},
		kctest.Node{Requirement: "REQUIRED", Provider: keycloak.TemplateProvider},
	)
	kc.SetRealmBrowserFlow("core-universal")
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	fid := kc.ClientByClientID("netbird").AuthenticationFlowBindingOverrides["browser"]
	got := kc.ExecConfigs(fid, "portcullis-x509")
	if len(got) != 2 || !maps.Equal(got[0], yubikey) || !maps.Equal(got[1], browser) {
		t.Errorf("copied x509 configs = %v", got)
	}
	provs := strings.Join(kc.FlowProviders(fid), "\n")
	if n := strings.Count(provs, ":ALTERNATIVE:portcullis-x509"); n != 2 {
		t.Errorf("%d x509 executions:\n%s", n, provs)
	}
	// Stable: the next ensure keeps the copy.
	before := mutations(kc)
	if err := c.EnsureClientAccess(ctx, netbirdAccess); err != nil {
		t.Fatal(err)
	}
	if n := mutations(kc) - before; n != 0 {
		t.Errorf("second ensure: %d mutating calls", n)
	}
}
