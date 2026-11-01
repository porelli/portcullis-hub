package keycloak

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/Nerzal/gocloak/v14"
)

// AttrField is a custom user field shared with apps (contract §9.6).
type AttrField struct {
	Name  string
	Multi bool
}

// AttributesScope is the client scope carrying one attr_<field> claim per
// shared field. It is a default client scope of every Hub-registered client.
const AttributesScope = "portcullis-attributes"

// AttrMapperPrefix names the LDAP and protocol mappers the Hub owns
// (portcullis-attr-<field>); only these are ever removed.
const AttrMapperPrefix = "portcullis-attr-"

const (
	ldapProviderType = "org.keycloak.storage.UserStorageProvider"
	ldapMapperType   = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
	ldapAttrMapper   = "user-attribute-ldap-mapper"
	oidcAttrMapper   = "oidc-usermodel-attribute-mapper"
	oidcProtocol     = "openid-connect"
)

func ldapMapperConfig(f AttrField) map[string][]string {
	return map[string][]string{
		"ldap.attribute":              {f.Name},
		"user.model.attribute":        {"attr_" + f.Name},
		"read.only":                   {"true"},
		"always.read.value.from.ldap": {"true"},
		"is.mandatory.in.ldap":        {"false"},
	}
}

func protocolMapper(f AttrField) gocloak.ProtocolMappers {
	return gocloak.ProtocolMappers{
		Name:           gocloak.StringP(AttrMapperPrefix + f.Name),
		Protocol:       gocloak.StringP(oidcProtocol),
		ProtocolMapper: gocloak.StringP(oidcAttrMapper),
		ProtocolMappersConfig: &gocloak.ProtocolMappersConfig{
			UserAttribute:      gocloak.StringP("attr_" + f.Name),
			ClaimName:          gocloak.StringP("attr_" + f.Name),
			JSONTypeLabel:      gocloak.StringP("String"),
			Multivalued:        gocloak.StringP(strconv.FormatBool(f.Multi)),
			AccessTokenClaim:   gocloak.StringP("true"),
			IDTokenClaim:       gocloak.StringP("true"),
			UserinfoTokenClaim: gocloak.StringP("true"),
		},
	}
}

// sameProtocolMapper reports whether an existing mapper already has want's
// type and claim settings.
func sameProtocolMapper(have *gocloak.ProtocolMappers, want gocloak.ProtocolMappers) bool {
	if str(have.ProtocolMapper) != str(want.ProtocolMapper) || have.ProtocolMappersConfig == nil {
		return false
	}
	h, w := have.ProtocolMappersConfig, want.ProtocolMappersConfig
	return str(h.UserAttribute) == str(w.UserAttribute) && str(h.ClaimName) == str(w.ClaimName) &&
		str(h.JSONTypeLabel) == str(w.JSONTypeLabel) && str(h.Multivalued) == str(w.Multivalued) &&
		str(h.AccessTokenClaim) == "true" && str(h.IDTokenClaim) == "true" && str(h.UserinfoTokenClaim) == "true"
}

// sameLDAPMapper reports whether an existing LDAP mapper has want's type
// and every key of want's config (other keys Keycloak adds are ignored).
func sameLDAPMapper(have *gocloak.Component, want map[string][]string) bool {
	if str(have.ProviderID) != ldapAttrMapper {
		return false
	}
	for k, v := range want {
		hv := have.ComponentConfig[k]
		if len(hv) != len(v) || (len(v) > 0 && hv[0] != v[0]) {
			return false
		}
	}
	return true
}

func ownedMapper(name string) bool { return strings.HasPrefix(name, AttrMapperPrefix) }

// EnsureAttributeMappers makes Keycloak carry exactly fields (contract
// §9.6). Idempotent:
//   - on every LDAP user storage provider, a user-attribute-ldap-mapper
//     portcullis-attr-<name> (LDAP attribute <name> → user attribute
//     attr_<name>, read-only, always read from LDAP);
//   - the openid-connect client scope portcullis-attributes, with an
//     oidc-usermodel-attribute-mapper portcullis-attr-<name> per field
//     (claim attr_<name> in access, ID and userinfo tokens; multivalued =
//     Multi);
//   - portcullis-* mappers of fields not in fields are removed (no others);
//   - the scope is a default client scope of every Hub-registered client.
//
// It carries on past a failing step and returns every error joined; the
// caller logs and retries on the next trigger.
func (c *Client) EnsureAttributeMappers(ctx context.Context, fields []AttrField) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	want := map[string]AttrField{}
	for _, f := range fields {
		want[f.Name] = f
	}
	var errs []error
	providers, err := c.ldapProviders(ctx, tok)
	if err != nil {
		errs = append(errs, err)
	}
	ids := make([]string, 0, len(providers))
	for id := range providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		errs = append(errs, c.ensureLDAPMappers(ctx, tok, id, want)...)
	}
	scopeID, serrs := c.ensureAttributesScope(ctx, tok, want)
	errs = append(errs, serrs...)
	if scopeID != "" {
		errs = append(errs, c.attachAttributesScope(ctx, tok, scopeID)...)
	}
	return errors.Join(errs...)
}

func (c *Client) ensureLDAPMappers(ctx context.Context, tok, providerID string, want map[string]AttrField) []error {
	g := c.api()
	existing, err := g.GetComponentsWithParams(ctx, tok, Realm, gocloak.GetComponentsParams{
		ParentID: gocloak.StringP(providerID), ProviderType: gocloak.StringP(ldapMapperType)})
	if err != nil {
		return []error{opErr("list LDAP mappers", err)}
	}
	have := map[string]*gocloak.Component{}
	var errs []error
	for _, m := range existing {
		if m == nil || !ownedMapper(str(m.Name)) {
			continue
		}
		if _, ok := want[strings.TrimPrefix(str(m.Name), AttrMapperPrefix)]; !ok || have[str(m.Name)] != nil {
			// Field no longer shared (or a duplicate): remove.
			if err := g.DeleteComponent(ctx, tok, Realm, url.PathEscape(str(m.ID))); err != nil {
				errs = append(errs, opErr("delete LDAP mapper "+str(m.Name), err))
			}
			continue
		}
		have[str(m.Name)] = m
	}
	for _, name := range sortedKeys(want) {
		f := want[name]
		cfg := ldapMapperConfig(f)
		mname := AttrMapperPrefix + f.Name
		if m := have[mname]; m != nil {
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
				errs = append(errs, opErr("update LDAP mapper "+mname, err))
			}
			continue
		}
		comp := gocloak.Component{
			Name:            gocloak.StringP(mname),
			ProviderID:      gocloak.StringP(ldapAttrMapper),
			ProviderType:    gocloak.StringP(ldapMapperType),
			ParentID:        gocloak.StringP(providerID),
			ComponentConfig: cfg,
		}
		if _, err := g.CreateComponent(ctx, tok, Realm, comp); err != nil {
			errs = append(errs, opErr("create LDAP mapper "+mname, err))
		}
	}
	return errs
}

// ensureAttributesScope creates the scope if needed and reconciles its
// mappers. It returns the scope id ("" if it could not be found or made).
func (c *Client) ensureAttributesScope(ctx context.Context, tok string, want map[string]AttrField) (string, []error) {
	g := c.api()
	scopeID, err := c.scopeID(ctx, tok, AttributesScope)
	if err != nil {
		return "", []error{err}
	}
	if scopeID == "" {
		_, err := g.CreateClientScope(ctx, tok, Realm, gocloak.ClientScope{
			Name:        gocloak.StringP(AttributesScope),
			Protocol:    gocloak.StringP(oidcProtocol),
			Description: gocloak.StringP("Portcullis custom user fields shared with apps (attr_<field> claims; managed by the Hub)"),
			ClientScopeAttributes: &gocloak.ClientScopeAttributes{
				IncludeInTokenScope:    gocloak.StringP("true"),
				DisplayOnConsentScreen: gocloak.StringP("false"),
			},
		})
		if err != nil {
			return "", []error{opErr("create client scope "+AttributesScope, err)}
		}
		// Look it up rather than trusting the Location header.
		if scopeID, err = c.scopeID(ctx, tok, AttributesScope); err != nil {
			return "", []error{err}
		}
		if scopeID == "" {
			return "", []error{fmt.Errorf("client scope %s missing after create", AttributesScope)}
		}
	}
	sid := url.PathEscape(scopeID)
	existing, err := g.GetClientScopeProtocolMappers(ctx, tok, Realm, sid)
	if err != nil {
		return scopeID, []error{opErr("list protocol mappers", err)}
	}
	var errs []error
	have := map[string]*gocloak.ProtocolMappers{}
	for _, m := range existing {
		if m == nil || !ownedMapper(str(m.Name)) {
			continue
		}
		if _, ok := want[strings.TrimPrefix(str(m.Name), AttrMapperPrefix)]; !ok || have[str(m.Name)] != nil {
			if err := g.DeleteClientScopeProtocolMapper(ctx, tok, Realm, sid, url.PathEscape(str(m.ID))); err != nil {
				errs = append(errs, opErr("delete protocol mapper "+str(m.Name), err))
			}
			continue
		}
		have[str(m.Name)] = m
	}
	for _, name := range sortedKeys(want) {
		pm := protocolMapper(want[name])
		if m := have[str(pm.Name)]; m != nil {
			if sameProtocolMapper(m, pm) {
				continue
			}
			pm.ID = m.ID
			if err := g.UpdateClientScopeProtocolMapper(ctx, tok, Realm, sid, pm); err != nil {
				errs = append(errs, opErr("update protocol mapper "+str(pm.Name), err))
			}
			continue
		}
		if _, err := g.CreateClientScopeProtocolMapper(ctx, tok, Realm, sid, pm); err != nil {
			errs = append(errs, opErr("create protocol mapper "+str(pm.Name), err))
		}
	}
	return scopeID, errs
}

// attachAttributesScope makes the scope a default client scope of every
// Hub-registered client (tagged with OwnerAttr).
func (c *Client) attachAttributesScope(ctx context.Context, tok, scopeID string) []error {
	g := c.api()
	clients, err := g.GetClients(ctx, tok, Realm, gocloak.GetClientsParams{})
	if err != nil {
		return []error{opErr("list clients", err)}
	}
	var errs []error
	for _, cl := range clients {
		if cl == nil || str(cl.ID) == "" || cl.Attributes[OwnerAttr] == "" || protectedClients[str(cl.ClientID)] {
			continue
		}
		if containsName(cl.DefaultClientScopes, AttributesScope) {
			continue
		}
		if err := g.AddDefaultScopeToClient(ctx, tok, Realm, url.PathEscape(str(cl.ID)), url.PathEscape(scopeID)); err != nil {
			errs = append(errs, opErr("attach scope "+AttributesScope+" to client "+str(cl.ClientID), err))
		}
	}
	return errs
}

// scopeID returns the id of the realm client scope name ("" if absent).
func (c *Client) scopeID(ctx context.Context, tok, name string) (string, error) {
	scopes, err := c.api().GetClientScopes(ctx, tok, Realm)
	if err != nil {
		return "", opErr("list client scopes", err)
	}
	for _, sc := range scopes {
		if sc != nil && str(sc.Name) == name {
			return str(sc.ID), nil
		}
	}
	return "", nil
}

func containsName(list []string, name string) bool {
	for _, s := range list {
		if s == name {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]AttrField) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
