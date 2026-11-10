package keycloak

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/url"

	"github.com/Nerzal/gocloak/v14"

	"github.com/portcullis/hub/internal/freshauth"
)

// FreshAuthScopes are exactly the default client scopes of the fresh-auth
// client (contract §8): basic (sub, auth_time) and acr (acr, and core's
// amr mapper). No groups, no attributes scope, never
// portcullis-invite-client (its invite flow emits amr=hwk without a
// passkey); no optional scopes.
var FreshAuthScopes = []string{"basic", "acr"}

// FreshAuthUsernameMapper is the fresh-auth client's username mapper:
// preferred_username in the ID token. The profile scope, which normally
// carries it, would add name/email claims nobody needs.
const FreshAuthUsernameMapper = "portcullis-fresh-auth-username"

// FreshAuthMethodMapper is the fresh-auth client's other mapper (contract
// §8, §8.1): the portcullis-keycloak extension's portcullis-fresh, the
// claim pc_fresh in the ID token only — the method id of the
// authenticator that ran in this authentication (never a user-session
// note). It is the only input of the Hub's fresh-auth method check
// (freshauth.FreshMethods); amr is never used. Name and provider id are
// the same.
const FreshAuthMethodMapper = "portcullis-fresh"

func freshAuthMethodMapper() gocloak.ProtocolMapperRepresentation {
	return gocloak.ProtocolMapperRepresentation{
		Name:           gocloak.StringP(FreshAuthMethodMapper),
		Protocol:       gocloak.StringP(oidcProtocol),
		ProtocolMapper: gocloak.StringP(FreshAuthMethodMapper),
		Config: map[string]string{
			"id.token.claim":       "true",
			"access.token.claim":   "false",
			"userinfo.token.claim": "false",
		},
	}
}

// freshAuthAttrs are the client attributes the Hub asserts.
var freshAuthAttrs = map[string]string{
	OwnerAttr:                                   freshauth.ClientID,
	"pkce.code.challenge.method":                "S256",
	"use.refresh.tokens":                        "false",
	"client_credentials.use_refresh_token":      "false",
	"oauth2.device.authorization.grant.enabled": "false",
	"oidc.ciba.grant.enabled":                   "false",
	"standard.token.exchange.enabled":           "false",
}

func freshAuthMapper() gocloak.ProtocolMapperRepresentation {
	return gocloak.ProtocolMapperRepresentation{
		Name:           gocloak.StringP(FreshAuthUsernameMapper),
		Protocol:       gocloak.StringP(oidcProtocol),
		ProtocolMapper: gocloak.StringP(oidcAttrMapper),
		Config: map[string]string{
			"user.attribute":       "username",
			"claim.name":           "preferred_username",
			"jsonType.label":       "String",
			"multivalued":          "false",
			"id.token.claim":       "true",
			"access.token.claim":   "false",
			"userinfo.token.claim": "false",
		},
	}
}

// checkFreshAuthURIs: redirectURIs[i] is https://<host>/ exactly and
// webOrigins[i] https://<the same host>; at least one pair, the same
// number of each, no host twice (contract §8: the people and hub hosts).
func checkFreshAuthURIs(redirectURIs, webOrigins []string) error {
	if len(redirectURIs) == 0 || len(redirectURIs) != len(webOrigins) {
		return fmt.Errorf("fresh-auth client: want one web origin per redirect URI, got %d and %d", len(redirectURIs), len(webOrigins))
	}
	seen := map[string]bool{}
	for i, redirectURI := range redirectURIs {
		u, err := url.Parse(redirectURI)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return fmt.Errorf("fresh-auth client: redirect URI %q must be https://<host>/", redirectURI)
		}
		if webOrigins[i] != "https://"+u.Host {
			return fmt.Errorf("fresh-auth client: web origin %q must be https://%s", webOrigins[i], u.Host)
		}
		if seen[u.Host] {
			return fmt.Errorf("fresh-auth client: host %s listed twice", u.Host)
		}
		seen[u.Host] = true
	}
	return nil
}

// withFreshAuthSettings sets every asserted setting on rep.
func withFreshAuthSettings(rep *gocloak.Client, redirectURIs, webOrigins []string) {
	rep.Name = gocloak.StringP("Portcullis fresh sign-in")
	rep.Enabled = gocloak.BoolP(true)
	rep.Protocol = gocloak.StringP(oidcProtocol)
	rep.PublicClient = gocloak.BoolP(true)
	rep.BearerOnly = gocloak.BoolP(false)
	rep.ConsentRequired = gocloak.BoolP(false)
	rep.StandardFlowEnabled = gocloak.BoolP(true)
	rep.ImplicitFlowEnabled = gocloak.BoolP(false)
	rep.DirectAccessGrantsEnabled = gocloak.BoolP(false)
	rep.ServiceAccountsEnabled = gocloak.BoolP(false)
	rep.AuthorizationServicesEnabled = gocloak.BoolP(false)
	rep.FullScopeAllowed = gocloak.BoolP(false)
	rep.Secret = nil
	rep.RedirectURIs = append([]string{}, redirectURIs...)
	rep.WebOrigins = append([]string{}, webOrigins...)
	rep.RootURL, rep.BaseURL, rep.AdminURL = nil, nil, nil
	if rep.Attributes == nil {
		rep.Attributes = map[string]string{}
	}
	maps.Copy(rep.Attributes, freshAuthAttrs)
	// The realm's browser flow only: an override could bind a flow that
	// emits amr=hwk without a passkey ("" removes a binding).
	rep.AuthenticationFlowBindingOverrides = map[string]string{"browser": "", "direct_grant": ""}
}

// EnsureFreshAuthClient creates or re-asserts the Hub-owned client
// freshauth.ClientID (contract §8): owner-tagged; public, standard flow
// only, PKCE S256; no direct grants, implicit flow, service accounts,
// device or CIBA grant, token exchange or refresh tokens; redirect URIs
// exactly redirectURIs, web origins exactly webOrigins (the Hub passes
// [https://people.<d>/, https://hub.<d>/] and their origins: one
// verifier per listener, contract §8 / G11); default scopes
// exactly FreshAuthScopes, no optional scopes; exactly two protocol
// mappers (FreshAuthUsernameMapper, FreshAuthMethodMapper); no flow
// overrides. An existing client of that
// id without the tag (or tagged by anyone else) is a *ConflictError and
// left alone: fresh auth then fails closed. A realm without one of the
// scopes is an error (without acr there is no amr: every proof refused).
func (c *Client) EnsureFreshAuthClient(ctx context.Context, redirectURIs, webOrigins []string) error {
	if err := checkFreshAuthURIs(redirectURIs, webOrigins); err != nil {
		return err
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	g := c.api()
	id := freshauth.ClientID
	existing, err := c.findClient(ctx, tok, id)
	if errors.Is(err, ErrClientNotFound) {
		rep := gocloak.Client{ClientID: gocloak.StringP(id), DefaultClientScopes: append([]string{}, FreshAuthScopes...),
			ProtocolMappers: []gocloak.ProtocolMapperRepresentation{freshAuthMapper(), freshAuthMethodMapper()}}
		withFreshAuthSettings(&rep, redirectURIs, webOrigins)
		rep.AuthenticationFlowBindingOverrides = nil
		_, err = g.CreateClient(ctx, tok, Realm, rep)
		if err != nil && statusCode(err) != http.StatusConflict {
			return opErr("create client "+id, err)
		}
		if err == nil {
			log.Printf("Registered Keycloak client %s", id)
		}
		// Keycloak drops unknown scope names and adds the realm's default
		// optional scopes on create: re-read and reconcile like any other.
		existing, err = c.findClient(ctx, tok, id)
	}
	if err != nil {
		return err
	}
	if owner := existing.Attributes[OwnerAttr]; owner != id {
		return &ConflictError{ClientID: id, TemplateID: id, Owner: owner}
	}
	withFreshAuthSettings(existing, redirectURIs, webOrigins)
	existing.ProtocolMappers = nil // the sub-resource below does those
	if err := c.putClient(ctx, tok, existing); err != nil {
		return err
	}
	if err := c.ensureFreshAuthScopes(ctx, tok, existing); err != nil {
		return err
	}
	// Any other client mapper (a hardcoded amr or pc_fresh claim would
	// forge a proof) is deleted.
	return c.ensureOnlyClientMapper(ctx, tok, existing, freshAuthMapper(), freshAuthMethodMapper())
}

// ensureFreshAuthScopes makes the client's default scopes exactly
// FreshAuthScopes and its optional scopes none.
func (c *Client) ensureFreshAuthScopes(ctx context.Context, tok string, cl *gocloak.Client) error {
	ids, err := c.scopeIDs(ctx, tok)
	if err != nil {
		return err
	}
	for _, s := range FreshAuthScopes {
		if ids[s] == "" {
			return fmt.Errorf("client %s: the Keycloak realm has no %q client scope (run `portcullis keycloak configure`); fresh auth refuses every proof until it exists", str(cl.ClientID), s)
		}
	}
	return c.exactScopes(ctx, tok, cl, ids, FreshAuthScopes, nil)
}

// sameMapper: the same type and exactly want's config values (keys
// Keycloak adds itself are ignored).
func sameMapper(have, want gocloak.ProtocolMapperRepresentation) bool {
	if str(have.ProtocolMapper) != str(want.ProtocolMapper) || str(have.Protocol) != str(want.Protocol) {
		return false
	}
	for k, v := range want.Config {
		if have.Config[k] != v {
			return false
		}
	}
	return true
}
