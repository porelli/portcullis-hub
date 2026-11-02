package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v14"
)

// RevalidatePageSize is the page size of RevalidateUsers.
const RevalidatePageSize = 200

// RevalidateUsers lists every user of the realm, page by page, and
// returns how many Keycloak still has. Listing is what makes Keycloak
// drop its copy of a user LLDAP no longer has: each imported user is
// validated against LDAP on the way out and, with the LDAP federation's
// removeInvalidUsersEnabled (core's keycloak configure sets it), removed
// when LDAP answers that it doesn't exist. Keycloak's periodic LDAP
// sync only imports and updates (it never removes users), so the Hub
// runs this periodically. The Hub deletes nothing itself: an LDAP error
// keeps every user (Keycloak marks them unavailable instead), and
// users not linked to LDAP (and the master realm's admin) are never
// touched.
func (c *Client) RevalidateUsers(ctx context.Context) (int, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return 0, err
	}
	n, first := 0, 0
	for {
		users, err := c.api().GetUsers(ctx, tok, Realm, gocloak.GetUsersParams{First: gocloak.IntP(first), Max: gocloak.IntP(RevalidatePageSize), BriefRepresentation: gocloak.BoolP(true)})
		if err != nil {
			return n, opErr("list users", err)
		}
		n += len(users)
		// Users Keycloak removed while listing shift the later pages: a
		// user skipped that way is validated by the next run.
		if len(users) < RevalidatePageSize {
			return n, nil
		}
		first += len(users)
		if err := ctx.Err(); err != nil {
			return n, err
		}
	}
}
