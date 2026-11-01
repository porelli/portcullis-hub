package keycloak_test

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

func names[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestEnsureAttributeMappersIdempotent(t *testing.T) {
	f := kctest.New(t)
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	hubApp := f.AddClient("app", map[string]string{keycloak.OwnerAttr: "app"}, "openid", "acr")
	foreign := f.AddClient("other", nil, "openid")
	// Mappers the Hub doesn't own are never touched.
	f.AddLDAPMapper("email", "user-attribute-ldap-mapper", map[string][]string{"ldap.attribute": {"mail"}})

	fields := []keycloak.AttrField{{Name: "department"}, {Name: "cost_center"}, {Name: "teams", Multi: true}}
	if err := c.EnsureAttributeMappers(ctx, fields); err != nil {
		t.Fatal(err)
	}

	ldap := f.LDAPMappers()
	if got := fmt.Sprint(names(ldap)); got != "[email portcullis-attr-cost_center portcullis-attr-department portcullis-attr-teams]" {
		t.Fatalf("LDAP mappers = %s", got)
	}
	m := ldap["portcullis-attr-cost_center"]
	want := map[string][]string{"ldap.attribute": {"cost_center"}, "user.model.attribute": {"attr_cost_center"}, "read.only": {"true"},
		"always.read.value.from.ldap": {"true"}, "is.mandatory.in.ldap": {"false"}}
	if m.ProviderID != "user-attribute-ldap-mapper" || m.ProviderType != "org.keycloak.storage.ldap.mappers.LDAPStorageMapper" ||
		m.ParentID != kctest.LDAPProviderID || !reflect.DeepEqual(m.Config, want) {
		t.Errorf("LDAP mapper = %+v", m)
	}

	sc := f.Scope(keycloak.AttributesScope)
	if sc == nil || sc.Protocol != "openid-connect" {
		t.Fatalf("scope = %+v", sc)
	}
	pms := f.ScopeMappers(keycloak.AttributesScope)
	if got := fmt.Sprint(names(pms)); got != "[portcullis-attr-cost_center portcullis-attr-department portcullis-attr-teams]" {
		t.Fatalf("protocol mappers = %s", got)
	}
	pm := pms["portcullis-attr-teams"]
	wantPM := map[string]string{"user.attribute": "attr_teams", "claim.name": "attr_teams", "jsonType.label": "String", "multivalued": "true",
		"access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"}
	if pm.ProtocolMapper != "oidc-usermodel-attribute-mapper" || pm.Protocol != "openid-connect" || !reflect.DeepEqual(pm.Config, wantPM) {
		t.Errorf("protocol mapper = %+v", pm)
	}
	if pms["portcullis-attr-department"].Config["multivalued"] != "false" {
		t.Errorf("single-valued mapper = %+v", pms["portcullis-attr-department"])
	}

	if got := fmt.Sprint(f.ClientScopes(hubApp)); got != "[acr openid portcullis-attributes]" {
		t.Errorf("Hub client scopes = %s", got)
	}
	if got := fmt.Sprint(f.ClientScopes(foreign)); got != "[openid]" {
		t.Errorf("foreign client scopes = %s", got)
	}

	// Second run: nothing to write.
	before := len(f.Calls)
	if err := c.EnsureAttributeMappers(ctx, fields); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.Calls[before:] {
		if call[:4] != "GET " && call != "POST /realms/master/protocol/openid-connect/token" {
			t.Errorf("idempotent run wrote: %s", call)
		}
	}

	// A changed field (now multi-valued) is updated in place.
	fields[0].Multi = true
	if err := c.EnsureAttributeMappers(ctx, fields); err != nil {
		t.Fatal(err)
	}
	if got := f.ScopeMappers(keycloak.AttributesScope)["portcullis-attr-department"].Config["multivalued"]; got != "true" {
		t.Errorf("multivalued after update = %q", got)
	}
	if n := len(f.ScopeMappers(keycloak.AttributesScope)); n != 3 {
		t.Errorf("%d protocol mappers after update", n)
	}
}

func TestEnsureAttributeMappersRemoval(t *testing.T) {
	f := kctest.New(t)
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	f.AddLDAPMapper("email", "user-attribute-ldap-mapper", map[string][]string{"ldap.attribute": {"mail"}})

	if err := c.EnsureAttributeMappers(ctx, []keycloak.AttrField{{Name: "department"}, {Name: "cost_center"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureAttributeMappers(ctx, []keycloak.AttrField{{Name: "department"}}); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(f.LDAPMappers())); got != "[email portcullis-attr-department]" {
		t.Errorf("LDAP mappers = %s", got)
	}
	if got := fmt.Sprint(names(f.ScopeMappers(keycloak.AttributesScope))); got != "[portcullis-attr-department]" {
		t.Errorf("protocol mappers = %s", got)
	}

	// No shared field left: the Hub's mappers go, the scope stays (empty).
	if err := c.EnsureAttributeMappers(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(f.LDAPMappers())); got != "[email]" {
		t.Errorf("LDAP mappers = %s", got)
	}
	if pms := f.ScopeMappers(keycloak.AttributesScope); pms == nil || len(pms) != 0 {
		t.Errorf("protocol mappers = %v", pms)
	}
}

// A failing step doesn't stop the others; the error is returned.
func TestEnsureAttributeMappersPartialFailure(t *testing.T) {
	f := kctest.New(t)
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	f.FailPrefix = "POST /admin/realms/portcullis/components"
	if err := c.EnsureAttributeMappers(context.Background(), []keycloak.AttrField{{Name: "department"}}); err == nil {
		t.Fatal("no error")
	}
	if len(f.ScopeMappers(keycloak.AttributesScope)) != 1 {
		t.Errorf("scope not reconciled past the LDAP failure")
	}
	f.SetDown(true)
	if err := c.EnsureAttributeMappers(context.Background(), nil); err == nil {
		t.Error("outage: no error")
	}
}

// A Hub client with the scope as optional gets it moved to default, once.
func TestAttributesScopeMovedFromOptional(t *testing.T) {
	f := kctest.New(t)
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	id := f.AddClient("app", map[string]string{keycloak.OwnerAttr: "app"}, "openid")
	f.SetOptionalScopes(id, keycloak.AttributesScope, "offline_access")
	if err := c.EnsureAttributeMappers(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(f.ClientScopes(id), f.OptionalScopes(id)); got != "[openid portcullis-attributes] [offline_access]" {
		t.Errorf("scopes = %s", got)
	}
	puts := f.CountCalls("PUT /admin/realms/portcullis/clients/")
	if err := c.EnsureAttributeMappers(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if n := f.CountCalls("PUT /admin/realms/portcullis/clients/"); n != puts {
		t.Errorf("second run attached again (%d -> %d)", puts, n)
	}
}
