package keycloak

import (
	"context"
	"errors"
	"log"
	"maps"
	"net/http"

	"github.com/Nerzal/gocloak/v14"

	"github.com/portcullis/hub/internal/cliapi"
)

// CLIClientID is the Hub-owned client of `portcullis login` (contract
// §18.2): the loopback PKCE sign-in whose code the Hub exchanges.
const CLIClientID = cliapi.ClientID

// CLIUsernameMapper is the CLI client's preferred_username mapper (ID
// token only), like FreshAuthUsernameMapper.
const CLIUsernameMapper = "portcullis-cli-username"

// cliAttrs are the CLI client's asserted attributes: the fresh-auth ones
// with its own owner tag (device grant, CIBA, token exchange and refresh
// tokens off).
func cliAttrs() map[string]string {
	a := maps.Clone(freshAuthAttrs)
	a[OwnerAttr] = CLIClientID
	return a
}

func cliUsernameMapper() gocloak.ProtocolMapperRepresentation {
	m := freshAuthMapper()
	m.Name = gocloak.StringP(CLIUsernameMapper)
	return m
}

// withCLISettings sets every asserted setting: withFreshAuthSettings' flow
// switches, the three loopback redirect URIs and no web origins (the
// CLI's code never reaches a browser page script).
func withCLISettings(rep *gocloak.Client) {
	withFreshAuthSettings(rep, cliapi.RedirectURIs(), nil)
	rep.Name = gocloak.StringP("Portcullis CLI")
	rep.WebOrigins = []string{}
	maps.Copy(rep.Attributes, cliAttrs())
}

// EnsureCLIClient creates or re-asserts CLIClientID (contract §18.2):
// owner-tagged; public, standard flow only, PKCE S256; implicit flow,
// direct grants, service accounts, device grant, CIBA, token exchange and
// refresh tokens off; no consent; redirect URIs exactly the three
// loopback URLs; no web origins; default scopes exactly FreshAuthScopes,
// no optional scopes; exactly two mappers (CLIUsernameMapper and
// portcullis-fresh); no flow overrides. A holder of the id without the
// tag, or tagged by anyone else, is a *ConflictError and left alone:
// every CLI proof then fails closed.
func (c *Client) EnsureCLIClient(ctx context.Context) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	g := c.api()
	id := CLIClientID
	existing, err := c.findClient(ctx, tok, id)
	if errors.Is(err, ErrClientNotFound) {
		rep := gocloak.Client{ClientID: gocloak.StringP(id), DefaultClientScopes: append([]string{}, FreshAuthScopes...),
			ProtocolMappers: []gocloak.ProtocolMapperRepresentation{cliUsernameMapper(), freshAuthMethodMapper()}}
		withCLISettings(&rep)
		rep.AuthenticationFlowBindingOverrides = nil
		_, err = g.CreateClient(ctx, tok, Realm, rep)
		if err != nil && statusCode(err) != http.StatusConflict {
			return opErr("create client "+id, err)
		}
		if err == nil {
			log.Printf("Registered Keycloak client %s", id)
		}
		existing, err = c.findClient(ctx, tok, id)
	}
	if err != nil {
		return err
	}
	if owner := existing.Attributes[OwnerAttr]; owner != id {
		return &ConflictError{ClientID: id, TemplateID: id, Owner: owner}
	}
	withCLISettings(existing)
	existing.ProtocolMappers = nil
	// putClientExact sends "webOrigins": [] (gocloak's omitempty would
	// drop it, and Keycloak fills a new client's origins from its
	// redirect URIs).
	if err := c.putClientExact(ctx, tok, existing); err != nil {
		return err
	}
	if err := c.ensureFreshAuthScopes(ctx, tok, existing); err != nil {
		return err
	}
	return c.ensureOnlyClientMapper(ctx, tok, existing, cliUsernameMapper(), freshAuthMethodMapper())
}
