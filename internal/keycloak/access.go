package keycloak

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Nerzal/gocloak/v14"
)

// Per-instance access role (contract §8 "Access role"): for native-OIDC
// apps that can't restrict sign-in to their access group themselves, the
// Hub gives the instance's client a client role AccessRole, maps it to the
// instance's access group (a realm group the LDAP group mapper imports
// from LLDAP) and binds, as the client's browser flow, a Hub-managed copy
// of the realm's browser flow that admits only users with that role:
//
//	<AccessFlowPrefix>-<clientId>-<random>       (top level)
//	├─ REQUIRED    <top>.sign-in                 copy of the realm's browser
//	│                                            flow (minus the identity
//	│                                            provider redirector)
//	├─ CONDITIONAL <top>.member
//	│  ├─ REQUIRED conditional-user-role         <clientId>.access
//	│  └─ REQUIRED allow-access-authenticator
//	└─ CONDITIONAL <top>.deny
//	   ├─ REQUIRED conditional-sub-flow-executed <top>.member, not-executed
//	   └─ REQUIRED deny-access-authenticator
//
// Positive membership, then deny unless it succeeded: Keycloak's
// ConditionalRoleAuthenticator returns false for a role that doesn't
// resolve, before applying "negate", so a negated role condition would
// admit everybody once the role is gone. Here a missing role skips
// <top>.member and the deny fires (ConditionalSubFlowExecutedAuthenticator
// also holds for "not-executed" when the flow to check is missing). The
// deny sub-flow sits after the whole sign-in at the top level, so the
// SSO-cookie path is checked too (a deny inside the forms branch would let
// an existing Portcullis session straight through).
//
// The Hub reads the bound copy back on every ensure and compares it with
// what it would build from the realm's current browser flow (structure,
// requirements, aliases, authenticator configs): a core rebuild of the
// browser flow or an edit to the copy makes the Hub build a fresh copy
// (new random suffix), rebind the client and delete the old one. Copies
// own their configs, so a core rebuild never changes a bound copy
// underneath it.

// AccessRole is the client role an instance's access group gets.
const AccessRole = "access"

// accessRoleDescription starts the description of the Hub's AccessRole
// (RemoveClientAccess deletes only that one).
const accessRoleDescription = "Sign-in to this app (Portcullis Hub"

// AccessFlowPrefix starts the alias of every Hub-managed access flow.
const AccessFlowPrefix = "portcullis-client-access"

// accessFlowVersion is part of the completion marker: bump it when the
// shape the Hub builds changes, so existing copies are rebuilt (the shape
// check would catch most changes anyway).
const accessFlowVersion = "2"

// completeMarker ends the description of a fully built access flow; a flow
// without it is a leftover of an interrupted build (never bound).
const completeMarker = "[complete v" + accessFlowVersion + "]"

// AccessDeniedMessage is what Keycloak shows a user without the role.
const AccessDeniedMessage = "You don't have access to this app. Ask an administrator to add you to its group."

// ErrGroupNotFound: the access group isn't in Keycloak, even after an LDAP
// group sync (it doesn't exist in LLDAP yet). The client then denies
// everybody until the group exists (fail closed).
var ErrGroupNotFound = errors.New("group not found in keycloak")

// AccessSpec is an instance client whose sign-in the access role guards.
type AccessSpec struct {
	ClientID string
	// TemplateID is the owner tag (the instance id) and AllowedHosts its
	// hosts, as in ClientSpec (MayReconcile).
	TemplateID   string
	AllowedHosts []string
	// Group is the instance's access group (realm group name).
	Group string
}

var suffixRe = regexp.MustCompile(`^[0-9a-f]{10}$`)

// isAccessFlow reports whether alias is an access flow of clientID.
func isAccessFlow(alias, clientID string) bool {
	rest, ok := strings.CutPrefix(alias, AccessFlowPrefix+"-"+clientID+"-")
	return ok && suffixRe.MatchString(rest)
}

// AccessCondition is the conditional-user-role value for clientID's role
// (Keycloak resolves "<clientId>.<role>", split at the last dot).
func AccessCondition(clientID string) string { return clientID + "." + AccessRole }

// pageSize is the page size of the Hub's paginated role-mapping reads
// (Keycloak's default max for them is 100).
const pageSize = 100

// EnsureClientAccess makes the client's sign-in require AccessRole and
// gives s.Group that role. Idempotent; in this order, so a failure part-way
// leaves the client denying rather than admitting:
//  1. the client role exists;
//  2. the access flow (verified against the realm's current browser flow)
//     exists and is the client's browser flow override; direct access
//     grants, implicit flow, service accounts, device and CIBA grants and
//     standard token exchange are off (no grant may bypass the browser
//     flow); stale access flows of the client are deleted;
//  3. nobody but s.Group's members holds the role: other groups, direct
//     user grants and roles that have it as a composite (realm or client
//     roles, e.g. default-roles-portcullis) lose it;
//  4. s.Group has it. A group Keycloak doesn't have yet is imported with
//     an LDAP group sync; still missing = ErrGroupNotFound (after 1–3).
//
// Only a client the instance may reconcile (MayReconcile) is touched.
func (c *Client) EnsureClientAccess(ctx context.Context, s AccessSpec) error {
	if protectedClients[s.ClientID] {
		return &ConflictError{ClientID: s.ClientID, TemplateID: s.TemplateID, Owner: "core"}
	}
	if s.Group == "" {
		return fmt.Errorf("client %s: no access group to grant the %s role to", s.ClientID, AccessRole)
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	cl, err := c.findClient(ctx, tok, s.ClientID)
	if err != nil {
		return err
	}
	if !mayReconcile(cl, s.TemplateID, s.AllowedHosts) {
		return &ConflictError{ClientID: s.ClientID, TemplateID: s.TemplateID, Owner: cl.Attributes[OwnerAttr]}
	}
	g := c.api()
	uuid := str(cl.ID)
	role, err := c.ensureClientRole(ctx, tok, uuid)
	if err != nil {
		return fmt.Errorf("client %s: %w", s.ClientID, err)
	}
	flowID, flowAlias, err := c.ensureAccessFlow(ctx, tok, s.ClientID, cl.AuthenticationFlowBindingOverrides["browser"])
	if err != nil {
		return fmt.Errorf("client %s: access flow: %w", s.ClientID, err)
	}
	if hardenAccessClient(cl, flowID) {
		if err := c.putClient(ctx, tok, cl); err != nil {
			return err
		}
		log.Printf("Keycloak client %s: sign-in requires the %s role (flow %s)", s.ClientID, AccessRole, flowAlias)
	}
	if err := c.deleteAccessFlows(ctx, tok, s.ClientID, flowAlias); err != nil {
		log.Printf("Keycloak client %s: removing stale access flows: %v", s.ClientID, err)
	}

	// Look the group up first (an LDAP sync imports it), but strip every
	// other grant whether or not that worked.
	group, gerr := c.findGroup(ctx, tok, s.Group)
	if gerr == nil && group == nil {
		if serr := c.syncLDAPGroups(ctx, tok); serr != nil {
			gerr = fmt.Errorf("client %s: group %s not in Keycloak and the LDAP group sync failed: %w", s.ClientID, s.Group, serr)
		} else {
			group, gerr = c.findGroup(ctx, tok, s.Group)
		}
	}
	keep := ""
	if gerr == nil && group != nil {
		keep = str(group.ID)
	}
	mapped, err := c.stripGroupGrants(ctx, tok, uuid, role, keep, s)
	if err != nil {
		return err
	}
	if err := c.stripUserGrants(ctx, tok, uuid, role, s); err != nil {
		return err
	}
	if err := c.stripCompositeGrants(ctx, tok, uuid, role, s); err != nil {
		return err
	}
	if gerr != nil {
		return gerr
	}
	if group == nil {
		return fmt.Errorf("client %s: group %s: %w (create it in Users & Groups; until then nobody can sign in)", s.ClientID, s.Group, ErrGroupNotFound)
	}
	if !mapped {
		if err := g.AddClientRolesToGroup(ctx, tok, Realm, url.PathEscape(uuid), url.PathEscape(str(group.ID)), []gocloak.Role{*role}); err != nil {
			return opErr("grant the access role to group "+s.Group, err)
		}
		log.Printf("Keycloak client %s: group %s has the %s role", s.ClientID, s.Group, AccessRole)
	}
	return nil
}

// stripGroupGrants removes the access role from every group but keepID;
// true if keepID has it.
func (c *Client) stripGroupGrants(ctx context.Context, tok, uuid string, role *gocloak.Role, keepID string, s AccessSpec) (bool, error) {
	var have []*gocloak.Group
	for first := 0; ; first += pageSize {
		var page []*gocloak.Group
		resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).SetResult(&page).
			SetQueryParams(map[string]string{"first": fmt.Sprint(first), "max": fmt.Sprint(pageSize), "briefRepresentation": "true"}).
			Get(c.BaseURL + "/admin/realms/" + Realm + "/clients/" + url.PathEscape(uuid) + "/roles/" + url.PathEscape(AccessRole) + "/groups")
		if err != nil {
			return false, fmt.Errorf("list groups with the access role: %w", err)
		}
		if resp.IsError() {
			return false, &HTTPError{Op: "list groups with the access role", Status: resp.StatusCode()}
		}
		have = append(have, page...)
		if len(page) < pageSize {
			break
		}
	}
	mapped := false
	for _, o := range have {
		if o == nil || str(o.ID) == "" {
			continue
		}
		if keepID != "" && str(o.ID) == keepID {
			mapped = true
			continue
		}
		if err := c.api().DeleteClientRoleFromGroup(ctx, tok, Realm, url.PathEscape(uuid), url.PathEscape(str(o.ID)), []gocloak.Role{*role}); err != nil {
			return false, opErr("remove the access role from group "+str(o.Name), err)
		}
		log.Printf("Keycloak client %s: removed the %s role from group %s (only %s has it)", s.ClientID, AccessRole, str(o.Name), s.Group)
	}
	return mapped, nil
}

// stripUserGrants removes direct grants of the access role (membership of
// the access group is the only grant). All pages are read before anything
// is removed.
func (c *Client) stripUserGrants(ctx context.Context, tok, uuid string, role *gocloak.Role, s AccessSpec) error {
	var users []*gocloak.User
	for first := 0; ; first += pageSize {
		page, err := c.api().GetUsersByClientRoleName(ctx, tok, Realm, url.PathEscape(uuid), AccessRole, gocloak.GetUsersByRoleParams{First: gocloak.IntP(first), Max: gocloak.IntP(pageSize)})
		if err != nil {
			return opErr("list users with the access role", err)
		}
		users = append(users, page...)
		if len(page) < pageSize {
			break
		}
	}
	for _, u := range users {
		if u == nil || !ValidUserID(str(u.ID)) {
			continue
		}
		if err := c.api().DeleteClientRolesFromUser(ctx, tok, Realm, url.PathEscape(uuid), url.PathEscape(str(u.ID)), []gocloak.Role{*role}); err != nil {
			return opErr("remove a direct access role grant", err)
		}
		log.Printf("Keycloak client %s: removed the %s role granted directly to %s (membership of %s is the only grant)", s.ClientID, AccessRole, str(u.Username), s.Group)
	}
	return nil
}

// stripCompositeGrants removes the access role from every composite role
// that contains it (realm roles such as default-roles-portcullis, and
// client roles of any client): whoever holds such a role would hold the
// access role too. Keycloak has no "parents of a role" endpoint, so every
// composite role is checked.
func (c *Client) stripCompositeGrants(ctx context.Context, tok, uuid string, role *gocloak.Role, s AccessSpec) error {
	g := c.api()
	brief := gocloak.GetRoleParams{BriefRepresentation: gocloak.BoolP(true)}
	roles, err := g.GetRealmRoles(ctx, tok, Realm, brief)
	if err != nil {
		return opErr("list realm roles", err)
	}
	clients, err := g.GetClients(ctx, tok, Realm, gocloak.GetClientsParams{})
	if err != nil {
		return opErr("list clients", err)
	}
	owner := map[string]string{} // role id → "client/role" or "role" (logs)
	for _, r := range roles {
		if r != nil {
			owner[str(r.ID)] = "realm role " + str(r.Name)
		}
	}
	for _, other := range clients {
		if other == nil || str(other.ID) == "" {
			continue
		}
		crs, err := g.GetClientRoles(ctx, tok, Realm, url.PathEscape(str(other.ID)), brief)
		if err != nil {
			return opErr("list roles of client "+str(other.ClientID), err)
		}
		for _, r := range crs {
			if r != nil {
				owner[str(r.ID)] = "client role " + str(other.ClientID) + "." + str(r.Name)
			}
		}
		roles = append(roles, crs...)
	}
	for _, r := range roles {
		if r == nil || r.Composite == nil || !*r.Composite || str(r.ID) == "" || str(r.ID) == str(role.ID) {
			continue
		}
		kids, err := g.GetCompositeClientRolesByRoleID(ctx, tok, Realm, url.PathEscape(uuid), url.PathEscape(str(r.ID)))
		if err != nil {
			return opErr("read the composites of "+owner[str(r.ID)], err)
		}
		for _, k := range kids {
			if k == nil || str(k.ID) != str(role.ID) {
				continue
			}
			if err := g.DeleteClientRoleComposite(ctx, tok, Realm, url.PathEscape(str(r.ID)), []gocloak.Role{{ID: role.ID, Name: role.Name}}); err != nil {
				return opErr("remove the access role from the composite "+owner[str(r.ID)], err)
			}
			log.Printf("Keycloak client %s: removed the %s role from the composite %s (membership of %s is the only grant)", s.ClientID, AccessRole, owner[str(r.ID)], s.Group)
		}
	}
	return nil
}

// hardenAccessClient binds flowID as the browser flow and turns off every
// grant that wouldn't run it; true if anything changed.
func hardenAccessClient(cl *gocloak.Client, flowID string) bool {
	changed := false
	if cl.AuthenticationFlowBindingOverrides["browser"] != flowID {
		if cl.AuthenticationFlowBindingOverrides == nil {
			cl.AuthenticationFlowBindingOverrides = map[string]string{}
		}
		cl.AuthenticationFlowBindingOverrides["browser"] = flowID
		changed = true
	}
	for _, p := range []**bool{&cl.DirectAccessGrantsEnabled, &cl.ImplicitFlowEnabled, &cl.ServiceAccountsEnabled} {
		if *p == nil || **p {
			*p = gocloak.BoolP(false)
			changed = true
		}
	}
	if cl.Attributes == nil {
		cl.Attributes = map[string]string{}
	}
	for _, a := range []string{"oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled", "standard.token.exchange.enabled"} {
		if cl.Attributes[a] != "false" {
			cl.Attributes[a] = "false"
			changed = true
		}
	}
	return changed
}

// RemoveClientAccess undoes EnsureClientAccess for clientID (instance
// delete, or a template that no longer needs it): the browser flow
// override is removed first, then the role (with its group and user
// mappings) — a bound flow whose role is gone denies everybody, so this
// order opens the client in one step — then every access flow of the
// client that no client binds, with its configs. A missing client or role is fine; a
// client the instance may not reconcile is left alone (its flows are
// still removed when unbound). Idempotent.
func (c *Client) RemoveClientAccess(ctx context.Context, clientID, owner string, allowedHosts []string) error {
	if protectedClients[clientID] {
		return &ConflictError{ClientID: clientID, TemplateID: owner, Owner: "core"}
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	cl, err := c.findClient(ctx, tok, clientID)
	switch {
	case errors.Is(err, ErrClientNotFound):
	case err != nil:
		return err
	case !mayReconcile(cl, owner, allowedHosts):
		log.Printf("Keycloak client %s: not owned by %s, its access role and flow binding are left alone", clientID, owner)
	default:
		if cur := cl.AuthenticationFlowBindingOverrides["browser"]; cur != "" {
			f, ferr := c.api().GetAuthenticationFlow(ctx, tok, Realm, url.PathEscape(cur))
			switch {
			case statusCode(ferr) == http.StatusNotFound || (ferr == nil && isAccessFlow(str(f.Alias), clientID)):
				// Keycloak removes an override whose value is "".
				cl.AuthenticationFlowBindingOverrides = map[string]string{"browser": ""}
				if err := c.putClient(ctx, tok, cl); err != nil {
					return err
				}
			case ferr != nil:
				return opErr("read the client's browser flow", ferr)
			}
		}
		// Only the Hub's own role (by its description) is deleted.
		role, err := c.api().GetClientRole(ctx, tok, Realm, url.PathEscape(str(cl.ID)), AccessRole)
		switch {
		case statusCode(err) == http.StatusNotFound:
		case err != nil:
			return opErr("read the access role", err)
		case role != nil && strings.HasPrefix(str(role.Description), accessRoleDescription):
			err := c.api().DeleteClientRole(ctx, tok, Realm, url.PathEscape(str(cl.ID)), AccessRole)
			if err != nil && statusCode(err) != http.StatusNotFound {
				return opErr("delete the access role", err)
			}
			log.Printf("Keycloak client %s: removed the %s role", clientID, AccessRole)
		}
	}
	return c.deleteAccessFlows(ctx, tok, clientID, "")
}

func (c *Client) ensureClientRole(ctx context.Context, tok, uuid string) (*gocloak.Role, error) {
	g := c.api()
	role, err := g.GetClientRole(ctx, tok, Realm, url.PathEscape(uuid), AccessRole)
	if statusCode(err) == http.StatusNotFound {
		_, err = g.CreateClientRole(ctx, tok, Realm, url.PathEscape(uuid), gocloak.Role{
			Name:        gocloak.StringP(AccessRole),
			Description: gocloak.StringP(accessRoleDescription + ": granted to the instance's access group)"),
		})
		if err != nil && statusCode(err) != http.StatusConflict {
			return nil, opErr("create the access role", err)
		}
		role, err = g.GetClientRole(ctx, tok, Realm, url.PathEscape(uuid), AccessRole)
	}
	if err != nil {
		return nil, opErr("read the access role", err)
	}
	if role == nil || str(role.ID) == "" {
		return nil, fmt.Errorf("access role: no id")
	}
	return &gocloak.Role{ID: role.ID, Name: role.Name}, nil
}

// findGroup returns the top-level realm group called name (nil: none).
func (c *Client) findGroup(ctx context.Context, tok, name string) (*gocloak.Group, error) {
	groups, err := c.api().GetGroups(ctx, tok, Realm, gocloak.GetGroupsParams{Search: gocloak.StringP(name), Exact: gocloak.BoolP(true), Max: gocloak.IntP(100)})
	if err != nil {
		return nil, opErr("find group", err)
	}
	for _, gr := range groups {
		if gr != nil && str(gr.Name) == name && (gr.Path == nil || str(gr.Path) == "/"+name) && str(gr.ID) != "" {
			return gr, nil
		}
	}
	return nil, nil
}

// syncLDAPGroups imports LLDAP's groups into Keycloak (every group-ldap-
// mapper of every LDAP provider; Keycloak's "Sync LDAP groups to
// Keycloak"). Raw request: gocloak has no endpoint for it.
func (c *Client) syncLDAPGroups(ctx context.Context, tok string) error {
	providers, err := c.ldapProviders(ctx, tok)
	if err != nil {
		return err
	}
	n := 0
	for pid := range providers {
		comps, err := c.api().GetComponentsWithParams(ctx, tok, Realm, gocloak.GetComponentsParams{ParentID: gocloak.StringP(pid), ProviderType: gocloak.StringP(ldapMapperType)})
		if err != nil {
			return opErr("list LDAP mappers", err)
		}
		for _, m := range comps {
			if m == nil || str(m.ProviderID) != "group-ldap-mapper" || str(m.ID) == "" {
				continue
			}
			resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).SetQueryParam("direction", "fedToKeycloak").
				Post(c.BaseURL + "/admin/realms/" + Realm + "/user-storage/" + url.PathEscape(pid) + "/mappers/" + url.PathEscape(str(m.ID)) + "/sync")
			if err != nil {
				return fmt.Errorf("LDAP group sync: %w", err)
			}
			if resp.IsError() {
				return &HTTPError{Op: "LDAP group sync", Status: resp.StatusCode()}
			}
			n++
		}
	}
	if n == 0 {
		return fmt.Errorf("the realm has no LDAP group mapper")
	}
	return nil
}

// flowNode is an execution of a flow tree read from Keycloak.
type flowNode struct {
	exec     *gocloak.ModifyAuthenticationExecutionRepresentation
	flow     *gocloak.AuthenticationFlowRepresentation // sub-flow
	config   *gocloak.AuthenticatorConfigRepresentation
	children []*flowNode
}

// errUncopyable: the flow has a sub-flow the Hub can't copy (not a
// basic-flow).
var errUncopyable = errors.New("sub-flow the Hub can't copy")

// readFlowTree reads a flow's executions (Keycloak lists them depth-first
// with their level) into a tree, with sub-flows and configs.
func (c *Client) readFlowTree(ctx context.Context, tok, alias string) ([]*flowNode, error) {
	g := c.api()
	execs, err := g.GetAuthenticationExecutions(ctx, tok, Realm, url.PathEscape(alias))
	if err != nil {
		return nil, opErr("read flow "+alias, err)
	}
	var roots []*flowNode
	var stack []*flowNode // stack[i] = the last node at level i
	for _, e := range execs {
		if e == nil {
			continue
		}
		lvl := 0
		if e.Level != nil {
			lvl = *e.Level
		}
		if lvl > len(stack) {
			return nil, fmt.Errorf("flow %s: unexpected execution level %d", alias, lvl)
		}
		n := &flowNode{exec: e}
		if e.AuthenticationFlow != nil && *e.AuthenticationFlow {
			f, err := g.GetAuthenticationFlow(ctx, tok, Realm, url.PathEscape(str(e.FlowID)))
			if err != nil {
				return nil, opErr("read sub-flow "+str(e.DisplayName), err)
			}
			if p := str(f.ProviderID); p != "basic-flow" {
				return nil, fmt.Errorf("flow %s: sub-flow %s is a %q flow: %w", alias, str(f.Alias), p, errUncopyable)
			}
			n.flow = f
		}
		if id := str(e.AuthenticationConfig); id != "" {
			cfg, err := g.GetAuthenticatorConfig(ctx, tok, Realm, url.PathEscape(id))
			if err != nil {
				return nil, opErr("read authenticator config", err)
			}
			n.config = cfg
		}
		stack = stack[:lvl]
		if lvl == 0 {
			roots = append(roots, n)
		} else {
			stack[lvl-1].children = append(stack[lvl-1].children, n)
		}
		stack = append(stack, n)
	}
	return roots, nil
}

// skipInCopy: the identity provider redirector (core's invite IdP, only
// with kc_idp_hint) has no place in an app client's sign-in.
func skipInCopy(n *flowNode) bool {
	return n.flow == nil && str(n.exec.ProviderID) == "identity-provider-redirector"
}

// shapeNode is one execution of an access flow as the Hub builds it and
// compares it: a sub-flow (Alias, Children) or an authenticator
// (Provider, Config).
type shapeNode struct {
	Req      string            `json:"req"`
	Provider string            `json:"provider,omitempty"`
	Alias    string            `json:"alias,omitempty"`
	Config   map[string]string `json:"config,omitempty"`
	Children []shapeNode       `json:"children,omitempty"`
	desc     string            // sub-flow description (not compared)
}

// sourceShape is the copy of the realm's browser flow tree under the
// access flow top: sub-flows renamed "<top>.<source alias>", the IdP
// redirector dropped.
func sourceShape(top string, nodes []*flowNode) []shapeNode {
	out := []shapeNode{}
	for _, n := range nodes {
		if skipInCopy(n) {
			continue
		}
		sn := shapeNode{Req: str(n.exec.Requirement)}
		if n.flow != nil {
			sn.Alias, sn.desc, sn.Children = top+"."+str(n.flow.Alias), str(n.flow.Description), sourceShape(top, n.children)
		} else {
			sn.Provider = str(n.exec.ProviderID)
		}
		if n.config != nil && len(n.config.Config) > 0 {
			sn.Config = n.config.Config
		}
		out = append(out, sn)
	}
	return out
}

// readShape is a tree read from Keycloak as is.
func readShape(nodes []*flowNode) []shapeNode {
	out := []shapeNode{}
	for _, n := range nodes {
		sn := shapeNode{Req: str(n.exec.Requirement)}
		if n.flow != nil {
			sn.Alias, sn.Children = str(n.flow.Alias), readShape(n.children)
		} else {
			sn.Provider = str(n.exec.ProviderID)
		}
		if n.config != nil && len(n.config.Config) > 0 {
			sn.Config = n.config.Config
		}
		out = append(out, sn)
	}
	return out
}

// accessShape is the access flow top for clientID over the realm's
// browser flow tree src.
func accessShape(top, clientID, srcAlias string, src []*flowNode) []shapeNode {
	member := top + ".member"
	return []shapeNode{
		{Req: "REQUIRED", Alias: top + ".sign-in", desc: "Sign-in: a copy of " + srcAlias, Children: sourceShape(top, src)},
		{Req: "CONDITIONAL", Alias: member, desc: "Users with the " + AccessCondition(clientID) + " role", Children: []shapeNode{
			{Req: "REQUIRED", Provider: "conditional-user-role", Config: map[string]string{"condUserRole": AccessCondition(clientID), "negate": "false"}},
			{Req: "REQUIRED", Provider: "allow-access-authenticator"},
		}},
		{Req: "CONDITIONAL", Alias: top + ".deny", desc: "Deny everybody " + member + " didn't admit", Children: []shapeNode{
			{Req: "REQUIRED", Provider: "conditional-sub-flow-executed", Config: map[string]string{"flow_to_check": member, "check_result": "not-executed"}},
			{Req: "REQUIRED", Provider: "deny-access-authenticator", Config: map[string]string{"denyErrorMessage": AccessDeniedMessage}},
		}},
	}
}

func sameShape(a, b []shapeNode) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// ensureAccessFlow returns the id and alias of clientID's access flow for
// the realm's current browser flow: the bound one (boundID) or another
// complete one if it has exactly the shape the Hub would build, else a
// freshly built one.
func (c *Client) ensureAccessFlow(ctx context.Context, tok, clientID, boundID string) (id, alias string, err error) {
	g := c.api()
	realm, err := g.GetRealm(ctx, tok, Realm)
	if err != nil {
		return "", "", opErr("read realm", err)
	}
	src := str(realm.BrowserFlow)
	if src == "" {
		src = "browser"
	}
	if strings.HasPrefix(src, AccessFlowPrefix) {
		return "", "", fmt.Errorf("the realm's browser flow is %s, a Hub access flow: refusing to copy it", src)
	}
	tree, err := c.readFlowTree(ctx, tok, src)
	if err != nil {
		return "", "", err
	}

	flows, err := g.GetAuthenticationFlows(ctx, tok, Realm)
	if err != nil {
		return "", "", opErr("list flows", err)
	}
	var cands []*gocloak.AuthenticationFlowRepresentation
	for _, f := range flows {
		if f == nil || !isAccessFlow(str(f.Alias), clientID) || !strings.HasSuffix(str(f.Description), completeMarker) ||
			str(f.ProviderID) != "basic-flow" || f.TopLevel == nil || !*f.TopLevel {
			continue
		}
		if str(f.ID) == boundID {
			cands = append([]*gocloak.AuthenticationFlowRepresentation{f}, cands...)
		} else {
			cands = append(cands, f)
		}
	}
	for _, f := range cands {
		a := str(f.Alias)
		have, err := c.readFlowTree(ctx, tok, a)
		if errors.Is(err, errUncopyable) {
			log.Printf("Keycloak: access flow %s was edited (%v): building a new one", a, err)
			continue
		}
		if err != nil {
			return "", "", err
		}
		if sameShape(readShape(have), accessShape(a, clientID, src, tree)) {
			return str(f.ID), a, nil
		}
		log.Printf("Keycloak: access flow %s doesn't match %s or was edited: building a new one", a, src)
	}

	var rnd [5]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", "", err
	}
	alias = AccessFlowPrefix + "-" + clientID + "-" + hex.EncodeToString(rnd[:])
	want := accessShape(alias, clientID, src, tree)
	err = c.buildAccessFlow(ctx, tok, alias, src, clientID, want)
	if err == nil {
		// Read it back: a copy the next ensure wouldn't accept would be
		// rebuilt on every sync (and isn't what the Hub meant to bind).
		var have []*flowNode
		if have, err = c.readFlowTree(ctx, tok, alias); err == nil && !sameShape(readShape(have), want) {
			err = fmt.Errorf("flow %s: Keycloak's copy differs from what the Hub built", alias)
		}
	}
	if err != nil {
		// Leave nothing half-built behind (best effort; the next ensure
		// deletes any leftover too).
		if flows, lerr := g.GetAuthenticationFlows(ctx, tok, Realm); lerr == nil {
			for _, f := range flows {
				if f != nil && str(f.Alias) == alias {
					c.deleteFlowTree(ctx, tok, f)
				}
			}
		}
		return "", "", err
	}
	flows, err = g.GetAuthenticationFlows(ctx, tok, Realm)
	if err != nil {
		return "", "", opErr("list flows", err)
	}
	for _, f := range flows {
		if f != nil && str(f.Alias) == alias {
			log.Printf("Keycloak: built access flow %s from %s", alias, src)
			return str(f.ID), alias, nil
		}
	}
	return "", "", fmt.Errorf("flow %s vanished after it was built", alias)
}

func (c *Client) buildAccessFlow(ctx context.Context, tok, alias, src, clientID string, want []shapeNode) error {
	g := c.api()
	desc := fmt.Sprintf("Portcullis Hub: sign-in to client %s (a copy of %s) for users with its %s role only. Managed by the Hub — edits are overwritten.", clientID, src, AccessRole)
	// Raw requests for the flow itself: Keycloak answers both with an empty
	// body, which gocloak's Create/UpdateAuthenticationFlow try to decode.
	if err := c.rawSend(ctx, tok, "POST", "/authentication/flows", "create flow "+alias, gocloak.AuthenticationFlowRepresentation{
		Alias: gocloak.StringP(alias), Description: gocloak.StringP(desc), ProviderID: gocloak.StringP("basic-flow"),
		TopLevel: gocloak.BoolP(true), BuiltIn: gocloak.BoolP(false),
	}); err != nil {
		return err
	}
	n := 0
	if err := c.buildNodes(ctx, tok, alias, alias, want, &n); err != nil {
		return err
	}
	// Mark it complete last: only a complete flow is ever bound.
	flows, err := g.GetAuthenticationFlows(ctx, tok, Realm)
	if err != nil {
		return opErr("list flows", err)
	}
	for _, f := range flows {
		if f != nil && str(f.Alias) == alias {
			upd := gocloak.AuthenticationFlowRepresentation{ID: f.ID, Alias: f.Alias, ProviderID: f.ProviderID, TopLevel: f.TopLevel,
				BuiltIn: f.BuiltIn, Description: gocloak.StringP(desc + " " + completeMarker)}
			return c.rawSend(ctx, tok, "PUT", "/authentication/flows/"+url.PathEscape(str(f.ID)), "mark flow "+alias+" complete", upd)
		}
	}
	return fmt.Errorf("flow %s vanished while it was built", alias)
}

// rawSend sends body to the realm admin path; any 2xx is success.
func (c *Client) rawSend(ctx context.Context, tok, method, path, op string, body interface{}) error {
	resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).SetBody(body).
		Execute(method, c.BaseURL+"/admin/realms/"+Realm+path)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if resp.IsError() {
		return &HTTPError{Op: op, Status: resp.StatusCode()}
	}
	return nil
}

// buildNodes adds nodes (recursively) to the flow called parent; configs
// are named "<top>.cfg<n>".
func (c *Client) buildNodes(ctx context.Context, tok, top, parent string, nodes []shapeNode, n *int) error {
	for _, sn := range nodes {
		if sn.Alias != "" {
			if err := c.addSubFlow(ctx, tok, parent, sn.Alias, sn.desc, sn.Req); err != nil {
				return err
			}
			if err := c.buildNodes(ctx, tok, top, sn.Alias, sn.Children, n); err != nil {
				return err
			}
			continue
		}
		var cfg *gocloak.AuthenticatorConfigRepresentation
		if len(sn.Config) > 0 {
			*n++
			cfg = &gocloak.AuthenticatorConfigRepresentation{Alias: gocloak.StringP(fmt.Sprintf("%s.cfg%d", top, *n)), Config: sn.Config}
		}
		if err := c.addExecution(ctx, tok, parent, sn.Provider, sn.Req, cfg); err != nil {
			return err
		}
	}
	return nil
}

// execRep is an execution as Keycloak lists it, with its priority:
// gocloak's ModifyAuthenticationExecutionRepresentation has none, and
// Keycloak's PUT /flows/{alias}/executions copies the (then 0) priority
// onto the execution — moving it to the front of its flow.
type execRep struct {
	gocloak.ModifyAuthenticationExecutionRepresentation
	Priority *int `json:"priority,omitempty"`
}

// lastExecution returns the newest direct execution of flow alias (Keycloak
// appends new executions: priority = the last one's + 1).
func (c *Client) lastExecution(ctx context.Context, tok, alias string) (*execRep, error) {
	var execs []*execRep
	resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).SetResult(&execs).
		Get(c.BaseURL + "/admin/realms/" + Realm + "/authentication/flows/" + url.PathEscape(alias) + "/executions")
	if err != nil {
		return nil, fmt.Errorf("read flow %s: %w", alias, err)
	}
	if resp.IsError() {
		return nil, &HTTPError{Op: "read flow " + alias, Status: resp.StatusCode()}
	}
	var last *execRep
	for _, e := range execs {
		if e != nil && (e.Level == nil || *e.Level == 0) && (last == nil || (e.Index != nil && last.Index != nil && *e.Index > *last.Index)) {
			last = e
		}
	}
	if last == nil {
		return nil, fmt.Errorf("flow %s: the new execution is missing", alias)
	}
	if last.Priority == nil {
		return nil, fmt.Errorf("flow %s: Keycloak listed an execution without a priority", alias)
	}
	return last, nil
}

// setRequirement sets e's requirement (raw PUT of the full representation,
// priority included, so the execution keeps its place).
func (c *Client) setRequirement(ctx context.Context, tok, parent string, e *execRep, req string) error {
	if str(e.Requirement) == req {
		return nil
	}
	e.Requirement = gocloak.StringP(req)
	return c.rawSend(ctx, tok, "PUT", "/authentication/flows/"+url.PathEscape(parent)+"/executions", "set requirement in "+parent, e)
}

func (c *Client) addSubFlow(ctx context.Context, tok, parent, alias, desc, req string) error {
	err := c.api().CreateAuthenticationExecutionFlow(ctx, tok, Realm, url.PathEscape(parent), gocloak.CreateAuthenticationExecutionFlowRepresentation{
		Alias: gocloak.StringP(alias), Description: gocloak.StringP(desc), Provider: gocloak.StringP("registration-page-form"), Type: gocloak.StringP("basic-flow"),
	})
	if err != nil {
		return opErr("add sub-flow "+alias, err)
	}
	e, err := c.lastExecution(ctx, tok, parent)
	if err != nil {
		return err
	}
	return c.setRequirement(ctx, tok, parent, e, req)
}

func (c *Client) addExecution(ctx context.Context, tok, parent, provider, req string, cfg *gocloak.AuthenticatorConfigRepresentation) error {
	err := c.api().CreateAuthenticationExecution(ctx, tok, Realm, url.PathEscape(parent), gocloak.CreateAuthenticationExecutionRepresentation{Provider: gocloak.StringP(provider)})
	if err != nil {
		return opErr("add "+provider+" to "+parent, err)
	}
	e, err := c.lastExecution(ctx, tok, parent)
	if err != nil {
		return err
	}
	if err := c.setRequirement(ctx, tok, parent, e, req); err != nil {
		return err
	}
	if cfg != nil {
		if _, err := c.api().CreateAuthenticationExecutionConfig(ctx, tok, Realm, url.PathEscape(str(e.ID)), *cfg); err != nil {
			return opErr("configure "+provider+" in "+parent, err)
		}
	}
	return nil
}

// deleteFlowTree deletes a top-level flow (Keycloak deletes its sub-flows)
// and then the authenticator configs its executions used.
func (c *Client) deleteFlowTree(ctx context.Context, tok string, f *gocloak.AuthenticationFlowRepresentation) error {
	g := c.api()
	var cfgs []string
	if execs, err := g.GetAuthenticationExecutions(ctx, tok, Realm, url.PathEscape(str(f.Alias))); err == nil {
		for _, e := range execs {
			if e != nil && str(e.AuthenticationConfig) != "" {
				cfgs = append(cfgs, str(e.AuthenticationConfig))
			}
		}
	}
	if err := g.DeleteAuthenticationFlow(ctx, tok, Realm, url.PathEscape(str(f.ID))); err != nil && statusCode(err) != http.StatusNotFound {
		return opErr("delete flow "+str(f.Alias), err)
	}
	for _, id := range cfgs {
		if err := g.DeleteAuthenticatorConfig(ctx, tok, Realm, url.PathEscape(id)); err != nil && statusCode(err) != http.StatusNotFound {
			log.Printf("Keycloak: deleting config %s of flow %s: %v", id, str(f.Alias), err)
		}
	}
	return nil
}

// deleteAccessFlows deletes clientID's access flows except keep, skipping
// any that a client still binds.
func (c *Client) deleteAccessFlows(ctx context.Context, tok, clientID, keep string) error {
	g := c.api()
	flows, err := g.GetAuthenticationFlows(ctx, tok, Realm)
	if err != nil {
		return opErr("list flows", err)
	}
	var stale []*gocloak.AuthenticationFlowRepresentation
	for _, f := range flows {
		if f != nil && str(f.Alias) != keep && isAccessFlow(str(f.Alias), clientID) {
			stale = append(stale, f)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	clients, err := g.GetClients(ctx, tok, Realm, gocloak.GetClientsParams{})
	if err != nil {
		return opErr("list clients", err)
	}
	bound := map[string]string{}
	for _, cl := range clients {
		if cl == nil {
			continue
		}
		for _, v := range cl.AuthenticationFlowBindingOverrides {
			bound[v] = str(cl.ClientID)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return str(stale[i].Alias) < str(stale[j].Alias) })
	var errs []error
	for _, f := range stale {
		if by := bound[str(f.ID)]; by != "" {
			log.Printf("Keycloak: access flow %s is still bound by client %s, keeping it", str(f.Alias), by)
			continue
		}
		if err := c.deleteFlowTree(ctx, tok, f); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
