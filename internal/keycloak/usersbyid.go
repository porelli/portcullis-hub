package keycloak

import (
	"context"
	"strings"

	"github.com/Nerzal/gocloak/v14"
)

// usersByIDPage is UsernamesByID's page size.
const usersByIDPage = 200

// UsernamesByID maps every LDAP-federated Keycloak user's id (the OIDC
// sub an app keys its users on) to the lowercase LLDAP username: how a
// VPN provider's oidc_sub owners resolve to Portcullis people (contract
// §3.3, identity = the LLDAP username, never an email). Users that
// aren't linked to the realm's LDAP federation are left out.
func (c *Client) UsernamesByID(ctx context.Context) (map[string]string, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	ldap, err := c.ldapProviders(ctx, tok)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for first := 0; ; first += usersByIDPage {
		users, err := c.api().GetUsers(ctx, tok, Realm, gocloak.GetUsersParams{First: gocloak.IntP(first), Max: gocloak.IntP(usersByIDPage), BriefRepresentation: gocloak.BoolP(false)})
		if err != nil {
			return nil, opErr("list users", err)
		}
		for _, u := range users {
			if u == nil || str(u.ID) == "" || str(u.Username) == "" {
				continue
			}
			if fl := str(u.FederationLink); fl == "" || !ldap[fl] {
				continue
			}
			out[str(u.ID)] = strings.ToLower(str(u.Username))
		}
		if len(users) < usersByIDPage {
			return out, nil
		}
	}
}
