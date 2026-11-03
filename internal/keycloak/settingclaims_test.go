package keycloak_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

const (
	quotaAttr = "ps-0123456789ab"
	roleAttr  = "ps-ba9876543210"
)

func TestEnsureSettingClaims(t *testing.T) {
	f := kctest.New(t)
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	immich := f.AddClient("immich", map[string]string{keycloak.OwnerAttr: "immich"}, "openid")
	other := f.AddClient("other", map[string]string{keycloak.OwnerAttr: "other"}, "openid")
	// Mappers the Hub doesn't own are kept: an LDAP one and a client one.
	f.AddLDAPMapper("email", "user-attribute-ldap-mapper", map[string][]string{"ldap.attribute": {"mail"}})
	f.AddClientMapper(immich, "audience", "oidc-audience-mapper", map[string]string{"included.client.audience": "immich"})

	claims := []keycloak.SettingClaim{
		{Attr: quotaAttr, Claim: "immich_quota", JSONType: "int"},
		{Attr: roleAttr, Claim: "immich_role", JSONType: "string"},
	}
	if err := c.EnsureSettingClaims(ctx, "immich", "immich", claims); err != nil {
		t.Fatal(err)
	}

	ldap := f.LDAPMappers()
	if got := fmt.Sprint(names(ldap)); got != "[email portcullis-setting-"+quotaAttr+" portcullis-setting-"+roleAttr+"]" {
		t.Fatalf("LDAP mappers = %s", got)
	}
	m := ldap["portcullis-setting-"+quotaAttr]
	want := map[string][]string{"ldap.attribute": {quotaAttr}, "user.model.attribute": {quotaAttr}, "read.only": {"true"},
		"always.read.value.from.ldap": {"true"}, "is.mandatory.in.ldap": {"false"}}
	if m.ProviderID != "user-attribute-ldap-mapper" || m.ProviderType != "org.keycloak.storage.ldap.mappers.LDAPStorageMapper" ||
		m.ParentID != kctest.LDAPProviderID || !reflect.DeepEqual(m.Config, want) {
		t.Errorf("LDAP mapper = %+v", m)
	}

	pms := f.ClientMappers(immich)
	if got := fmt.Sprint(names(pms)); got != "[audience portcullis-setting-"+quotaAttr+" portcullis-setting-"+roleAttr+"]" {
		t.Fatalf("immich mappers = %s", got)
	}
	pm := pms["portcullis-setting-"+quotaAttr]
	wantPM := map[string]string{"user.attribute": quotaAttr, "claim.name": "immich_quota", "jsonType.label": "int", "multivalued": "false",
		"access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"}
	if pm.ProtocolMapper != "oidc-usermodel-attribute-mapper" || pm.Protocol != "openid-connect" || !reflect.DeepEqual(pm.Config, wantPM) {
		t.Errorf("protocol mapper = %+v", pm)
	}
	if got := pms["portcullis-setting-"+roleAttr].Config["jsonType.label"]; got != "String" {
		t.Errorf("role json type = %q", got)
	}
	// On that client only.
	if n := len(f.ClientMappers(other)); n != 0 {
		t.Errorf("other client has %d mappers", n)
	}
	// Nothing on the shared-fields scope either.
	if f.Scope(keycloak.AttributesScope) != nil {
		t.Errorf("a client scope was created")
	}

	// Idempotent: nothing to write.
	before := len(f.Calls)
	if err := c.EnsureSettingClaims(ctx, "immich", "immich", claims); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.Calls[before:] {
		if call[:4] != "GET " && call != "POST /realms/master/protocol/openid-connect/token" {
			t.Errorf("idempotent run wrote: %s", call)
		}
	}

	// A changed type is updated in place; a claim no longer delivered
	// loses its client mapper (the exact set), other mappers stay.
	if err := c.EnsureSettingClaims(ctx, "immich", "immich", []keycloak.SettingClaim{{Attr: quotaAttr, Claim: "immich_quota", JSONType: "json"}}); err != nil {
		t.Fatal(err)
	}
	pms = f.ClientMappers(immich)
	if got := fmt.Sprint(names(pms)); got != "[audience portcullis-setting-"+quotaAttr+"]" {
		t.Errorf("after shrink: immich mappers = %s", got)
	}
	if got := pms["portcullis-setting-"+quotaAttr].Config["jsonType.label"]; got != "JSON" {
		t.Errorf("after update: json type = %q", got)
	}

	// Not owner-tagged (or another owner's, or core's): refused.
	f.AddClient("foreign", nil)
	var ce *keycloak.ConflictError
	for _, tc := range [][2]string{{"foreign", "foreign"}, {"other", "immich"}, {keycloak.ForwardAuthClient, keycloak.ForwardAuthClient}, {"immich", ""}} {
		if err := c.EnsureSettingClaims(ctx, tc[0], tc[1], claims); !errors.As(err, &ce) {
			t.Errorf("EnsureSettingClaims(%s, %s) = %v", tc[0], tc[1], err)
		}
	}
	if n := len(f.ClientMappers(other)); n != 0 {
		t.Errorf("a refused client got %d mappers", n)
	}
	// A bad attribute name or JSON type is refused before any call.
	for _, bad := range []keycloak.SettingClaim{{Attr: "department", Claim: "x", JSONType: "int"}, {Attr: quotaAttr, Claim: "x", JSONType: "float"}} {
		if err := c.EnsureSettingClaims(ctx, "immich", "immich", []keycloak.SettingClaim{bad}); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	// A missing client is an error (the claims can't be delivered).
	if err := c.EnsureSettingClaims(ctx, "nope", "nope", claims); !errors.Is(err, keycloak.ErrClientNotFound) {
		t.Errorf("missing client: %v", err)
	}
}

func TestRemoveSettingClaims(t *testing.T) {
	f := kctest.New(t)
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	immich := f.AddClient("immich", map[string]string{keycloak.OwnerAttr: "immich"}, "openid")
	f.AddClientMapper(immich, "audience", "oidc-audience-mapper", nil)
	claims := []keycloak.SettingClaim{{Attr: quotaAttr, Claim: "immich_quota", JSONType: "int"}, {Attr: roleAttr, Claim: "immich_role", JSONType: "string"}}
	if err := c.EnsureSettingClaims(ctx, "immich", "immich", claims); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveSettingClaims(ctx, "immich", "immich", []string{quotaAttr}); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(f.ClientMappers(immich))); got != "[audience portcullis-setting-"+roleAttr+"]" {
		t.Errorf("client mappers = %s", got)
	}
	if got := fmt.Sprint(names(f.LDAPMappers())); got != "[portcullis-setting-"+roleAttr+"]" {
		t.Errorf("LDAP mappers = %s", got)
	}
	// A missing one (already removed, or a missing client) is nil.
	if err := c.RemoveSettingClaims(ctx, "immich", "immich", []string{quotaAttr}); err != nil {
		t.Errorf("again: %v", err)
	}
	if err := c.RemoveSettingClaims(ctx, "gone", "gone", []string{roleAttr}); err != nil {
		t.Errorf("missing client: %v", err)
	}
	if n := len(f.LDAPMappers()); n != 0 {
		t.Errorf("missing client: LDAP mapper of %s kept", roleAttr)
	}
	// Another owner's client: its mappers are left alone (*ConflictError).
	f.AddClient("foreign", map[string]string{keycloak.OwnerAttr: "someone"})
	var ce *keycloak.ConflictError
	if err := c.RemoveSettingClaims(ctx, "foreign", "immich", []string{roleAttr}); !errors.As(err, &ce) {
		t.Errorf("foreign client: %v", err)
	}
	if err := c.RemoveSettingClaims(ctx, "immich", "immich", []string{"department"}); err == nil {
		t.Error("a non-setting attribute accepted")
	}
}

// T-7: the shared-field mappers (portcullis-attr-) and the setting
// mappers (portcullis-setting-) are disjoint: neither prunes the other.
func TestSettingAndAttributeMappersDisjoint(t *testing.T) {
	f := kctest.New(t)
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	immich := f.AddClient("immich", map[string]string{keycloak.OwnerAttr: "immich"}, "openid")
	if err := c.EnsureSettingClaims(ctx, "immich", "immich", []keycloak.SettingClaim{{Attr: quotaAttr, Claim: "immich_quota", JSONType: "int"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureAttributeMappers(ctx, []keycloak.AttrField{{Name: "department"}}); err != nil {
		t.Fatal(err)
	}
	// No shared field left: the attr mappers go, the setting ones stay.
	if err := c.EnsureAttributeMappers(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(f.LDAPMappers())); got != "[portcullis-setting-"+quotaAttr+"]" {
		t.Errorf("after attribute prune: LDAP mappers = %s", got)
	}
	if err := c.EnsureAttributeMappers(ctx, []keycloak.AttrField{{Name: "department"}}); err != nil {
		t.Fatal(err)
	}
	// No claim left on the client: its setting mappers go, the attr
	// mappers (LDAP and scope) stay.
	if err := c.EnsureSettingClaims(ctx, "immich", "immich", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveSettingClaims(ctx, "immich", "immich", []string{quotaAttr}); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(f.LDAPMappers())); got != "[portcullis-attr-department]" {
		t.Errorf("after setting prune: LDAP mappers = %s", got)
	}
	if got := fmt.Sprint(names(f.ScopeMappers(keycloak.AttributesScope))); got != "[portcullis-attr-department]" {
		t.Errorf("scope mappers = %s", got)
	}
	if n := len(f.ClientMappers(immich)); n != 0 {
		t.Errorf("client mappers left: %d", n)
	}
}
