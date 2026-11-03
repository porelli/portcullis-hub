package keycloak

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Nerzal/gocloak/v14"
)

// Per-person setting claims (contract §13.6, spec call 12): each
// (instance, option) with a claim delivery has a Hub-owned LLDAP
// attribute ps-<12 hex>; Keycloak reads it through an LDAP mapper and a
// protocol mapper on that instance's client only puts it into the
// tokens. Both mappers are named portcullis-setting-<attr>.
//
// The set is disjoint from the shared-field mappers (AttrMapperPrefix
// portcullis-attr-, EnsureAttributeMappers): neither prunes the other's.

// SettingMapperPrefix names the LDAP and client protocol mappers of
// setting claims.
const SettingMapperPrefix = "portcullis-setting-"

// settingAttrRe is the Hub-owned attribute form (hub.SettingAttr).
var settingAttrRe = regexp.MustCompile(`^ps-[0-9a-f]{12}$`)

// settingJSONTypes maps a template's json_type to Keycloak's
// jsonType.label ("" = string).
var settingJSONTypes = map[string]string{"": "String", "string": "String", "int": "int", "bool": "boolean", "json": "JSON"}

// SettingClaim is one claim on a client: LLDAP attribute Attr (ps-…) as
// claim Claim, JSONType int|string|bool|json.
type SettingClaim struct{ Attr, Claim, JSONType string }

func checkSettingAttr(attr string) error {
	if !settingAttrRe.MatchString(attr) {
		return fmt.Errorf("%q is not a setting attribute (ps- + 12 hex)", attr)
	}
	return nil
}

func settingLDAPConfig(attr string) map[string][]string {
	return map[string][]string{
		"ldap.attribute":              {attr},
		"user.model.attribute":        {attr},
		"read.only":                   {"true"},
		"always.read.value.from.ldap": {"true"},
		"is.mandatory.in.ldap":        {"false"},
	}
}

func settingProtocolMapper(sc SettingClaim) gocloak.ProtocolMapperRepresentation {
	return gocloak.ProtocolMapperRepresentation{
		Name:           gocloak.StringP(SettingMapperPrefix + sc.Attr),
		Protocol:       gocloak.StringP(oidcProtocol),
		ProtocolMapper: gocloak.StringP(oidcAttrMapper),
		Config: map[string]string{
			"user.attribute":       sc.Attr,
			"claim.name":           sc.Claim,
			"jsonType.label":       settingJSONTypes[sc.JSONType],
			"multivalued":          "false",
			"access.token.claim":   "true",
			"id.token.claim":       "true",
			"userinfo.token.claim": "true",
		},
	}
}

// sameSettingMapper: have already has want's type and every key of
// want's config (other keys Keycloak adds are ignored).
func sameSettingMapper(have gocloak.ProtocolMapperRepresentation, want gocloak.ProtocolMapperRepresentation) bool {
	if str(have.ProtocolMapper) != str(want.ProtocolMapper) {
		return false
	}
	for k, v := range want.Config {
		if have.Config[k] != v {
			return false
		}
	}
	return true
}

// ownedSettingClient finds clientID and checks it is tagged with owner
// (core's clients and an empty owner never are).
func (c *Client) ownedSettingClient(ctx context.Context, tok, clientID, owner string) (*gocloak.Client, error) {
	if protectedClients[clientID] || owner == "" {
		return nil, &ConflictError{ClientID: clientID, TemplateID: owner, Owner: "core"}
	}
	cl, err := c.findClient(ctx, tok, clientID)
	if err != nil {
		return nil, err
	}
	if got := cl.Attributes[OwnerAttr]; got != owner {
		return nil, &ConflictError{ClientID: clientID, TemplateID: owner, Owner: got}
	}
	return cl, nil
}

// EnsureSettingClaims makes client clientID (tagged with owner, else a
// *ConflictError; missing: ErrClientNotFound) carry exactly claims:
//   - on every LDAP user storage provider, a user-attribute-ldap-mapper
//     portcullis-setting-<attr> (LDAP attribute <attr> → user attribute
//     <attr>, read-only, always read from LDAP) — created or updated,
//     never pruned here (another client of the instance may still need
//     it; RemoveSettingClaims removes them);
//   - on that client only, an oidc-usermodel-attribute-mapper
//     portcullis-setting-<attr> (claim Claim, jsonType.label from
//     JSONType, single-valued, in ID, access and userinfo tokens);
//     portcullis-setting-* mappers of that client not in claims are
//     removed, no other mapper is touched.
//
// Idempotent; it carries on past a failing step and returns every error
// joined.
func (c *Client) EnsureSettingClaims(ctx context.Context, clientID, owner string, claims []SettingClaim) error {
	want := map[string]SettingClaim{}
	for _, sc := range claims {
		if err := checkSettingAttr(sc.Attr); err != nil {
			return err
		}
		if _, ok := settingJSONTypes[sc.JSONType]; !ok {
			return fmt.Errorf("claim %s: json type %q must be int, string, bool or json", sc.Claim, sc.JSONType)
		}
		if sc.Claim == "" {
			return fmt.Errorf("attribute %s: empty claim name", sc.Attr)
		}
		want[SettingMapperPrefix+sc.Attr] = sc
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	cl, err := c.ownedSettingClient(ctx, tok, clientID, owner)
	if err != nil {
		return err
	}
	var errs []error
	if len(want) > 0 {
		providers, err := c.ldapProviders(ctx, tok)
		if err != nil {
			errs = append(errs, err)
		}
		for _, pid := range sortedProviderIDs(providers) {
			errs = append(errs, c.ensureSettingLDAPMappers(ctx, tok, pid, want)...)
		}
	}
	errs = append(errs, c.ensureSettingClientMappers(ctx, tok, cl, want)...)
	return errors.Join(errs...)
}

func sortedProviderIDs(p map[string]bool) []string {
	out := make([]string, 0, len(p))
	for id := range p {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (c *Client) settingLDAPMappers(ctx context.Context, tok, providerID string) ([]*gocloak.Component, error) {
	existing, err := c.api().GetComponentsWithParams(ctx, tok, Realm, gocloak.GetComponentsParams{
		ParentID: gocloak.StringP(providerID), ProviderType: gocloak.StringP(ldapMapperType)})
	if err != nil {
		return nil, opErr("list LDAP mappers", err)
	}
	var out []*gocloak.Component
	for _, m := range existing {
		if m != nil && strings.HasPrefix(str(m.Name), SettingMapperPrefix) {
			out = append(out, m)
		}
	}
	return out, nil
}

func (c *Client) ensureSettingLDAPMappers(ctx context.Context, tok, providerID string, want map[string]SettingClaim) []error {
	g := c.api()
	existing, err := c.settingLDAPMappers(ctx, tok, providerID)
	if err != nil {
		return []error{err}
	}
	have := map[string]*gocloak.Component{}
	for _, m := range existing {
		if have[str(m.Name)] == nil {
			have[str(m.Name)] = m
		}
	}
	var errs []error
	for _, name := range sortedClaimKeys(want) {
		cfg := settingLDAPConfig(want[name].Attr)
		if m := have[name]; m != nil {
			if sameLDAPMapper(m, cfg) {
				continue
			}
			merged := maps.Clone(m.ComponentConfig)
			if merged == nil {
				merged = map[string][]string{}
			}
			maps.Copy(merged, cfg)
			m.ComponentConfig = merged
			m.ProviderID = gocloak.StringP(ldapAttrMapper)
			if err := g.UpdateComponent(ctx, tok, Realm, *m); err != nil {
				errs = append(errs, opErr("update LDAP mapper "+name, err))
			}
			continue
		}
		comp := gocloak.Component{
			Name:            gocloak.StringP(name),
			ProviderID:      gocloak.StringP(ldapAttrMapper),
			ProviderType:    gocloak.StringP(ldapMapperType),
			ParentID:        gocloak.StringP(providerID),
			ComponentConfig: cfg,
		}
		if _, err := g.CreateComponent(ctx, tok, Realm, comp); err != nil {
			errs = append(errs, opErr("create LDAP mapper "+name, err))
		}
	}
	return errs
}

// clientMappers lists a client's own protocol mappers (gocloak has no
// call for it: raw GET on its request builder).
func (c *Client) clientMappers(ctx context.Context, tok string, cl *gocloak.Client) ([]gocloak.ProtocolMapperRepresentation, error) {
	var out []gocloak.ProtocolMapperRepresentation
	resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).SetResult(&out).
		Get(c.BaseURL + "/admin/realms/" + Realm + "/clients/" + url.PathEscape(str(cl.ID)) + "/protocol-mappers/models")
	if err != nil {
		return nil, fmt.Errorf("list protocol mappers of client %s: %w", str(cl.ClientID), err)
	}
	if resp.IsError() {
		return nil, &HTTPError{Op: "list protocol mappers of client " + str(cl.ClientID), Status: resp.StatusCode()}
	}
	return out, nil
}

func (c *Client) ensureSettingClientMappers(ctx context.Context, tok string, cl *gocloak.Client, want map[string]SettingClaim) []error {
	g := c.api()
	cid := url.PathEscape(str(cl.ID))
	existing, err := c.clientMappers(ctx, tok, cl)
	if err != nil {
		return []error{err}
	}
	var errs []error
	have := map[string]gocloak.ProtocolMapperRepresentation{}
	for _, m := range existing {
		name := str(m.Name)
		if !strings.HasPrefix(name, SettingMapperPrefix) {
			continue
		}
		if _, ok := want[name]; !ok || have[name].ID != nil {
			// No longer delivered on this client (or a duplicate).
			if err := g.DeleteClientProtocolMapper(ctx, tok, Realm, cid, url.PathEscape(str(m.ID))); err != nil && statusCode(err) != http.StatusNotFound {
				errs = append(errs, opErr("delete protocol mapper "+name+" of client "+str(cl.ClientID), err))
			}
			continue
		}
		have[name] = m
	}
	for _, name := range sortedClaimKeys(want) {
		pm := settingProtocolMapper(want[name])
		if m, ok := have[name]; ok {
			if sameSettingMapper(m, pm) {
				continue
			}
			pm.ID = m.ID
			if err := g.UpdateClientProtocolMapper(ctx, tok, Realm, cid, url.PathEscape(str(m.ID)), pm); err != nil {
				errs = append(errs, opErr("update protocol mapper "+name+" of client "+str(cl.ClientID), err))
			}
			continue
		}
		if _, err := g.CreateClientProtocolMapper(ctx, tok, Realm, cid, pm); err != nil {
			errs = append(errs, opErr("create protocol mapper "+name+" of client "+str(cl.ClientID), err))
		}
	}
	return errs
}

// RemoveSettingClaims removes the setting mappers of attrs: client
// clientID's protocol mappers (only a client tagged with owner; another
// owner's or an untagged one is left alone, a *ConflictError; a missing
// client is fine) and the LDAP mappers on every LDAP provider (Hub-owned
// by name: always). Missing mappers are nil (idempotent).
func (c *Client) RemoveSettingClaims(ctx context.Context, clientID, owner string, attrs []string) error {
	drop := map[string]bool{}
	for _, a := range attrs {
		if err := checkSettingAttr(a); err != nil {
			return err
		}
		drop[SettingMapperPrefix+a] = true
	}
	if len(drop) == 0 {
		return nil
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	g := c.api()
	var errs []error
	cl, err := c.ownedSettingClient(ctx, tok, clientID, owner)
	var conflict error
	switch {
	case errors.Is(err, ErrClientNotFound):
	case err != nil:
		var ce *ConflictError
		if !errors.As(err, &ce) {
			return err
		}
		conflict = err
	default:
		existing, err := c.clientMappers(ctx, tok, cl)
		if err != nil {
			return err
		}
		for _, m := range existing {
			if !drop[str(m.Name)] {
				continue
			}
			if err := g.DeleteClientProtocolMapper(ctx, tok, Realm, url.PathEscape(str(cl.ID)), url.PathEscape(str(m.ID))); err != nil && statusCode(err) != http.StatusNotFound {
				errs = append(errs, opErr("delete protocol mapper "+str(m.Name)+" of client "+clientID, err))
			}
		}
	}
	providers, err := c.ldapProviders(ctx, tok)
	if err != nil {
		errs = append(errs, err)
	}
	for _, pid := range sortedProviderIDs(providers) {
		existing, err := c.settingLDAPMappers(ctx, tok, pid)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, m := range existing {
			if !drop[str(m.Name)] {
				continue
			}
			if err := g.DeleteComponent(ctx, tok, Realm, url.PathEscape(str(m.ID))); err != nil && statusCode(err) != http.StatusNotFound {
				errs = append(errs, opErr("delete LDAP mapper "+str(m.Name), err))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return conflict
}

func sortedClaimKeys(m map[string]SettingClaim) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
