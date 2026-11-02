package keycloak

import (
	"context"
	"crypto/sha256"
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
// of the realm's browser flow that denies sign-in without that role:
//
//	<AccessFlowPrefix>-<clientId>-<hash>        (top level)
//	├─ REQUIRED    <top>.sign-in                 copy of the realm's browser
//	│                                            flow (minus the identity
//	│                                            provider redirector)
//	└─ CONDITIONAL <top>.deny
//	   ├─ REQUIRED conditional-user-role         <clientId>.access, negated
//	   └─ REQUIRED deny-access-authenticator
//
// The deny sub-flow sits after the whole sign-in at the top level, so the
// SSO-cookie path is checked too (a deny inside the forms branch would
// let an existing Portcullis session straight through). <hash> covers the
// source flow's structure and authenticator configs: when core rebuilds
// its browser flow, the next EnsureClientAccess builds a fresh copy,
// rebinds the client and deletes the stale one. Copies own their configs,
// so a core rebuild never changes a bound copy underneath it.

// AccessRole is the client role an instance's access group gets.
const AccessRole = "access"

// accessRoleDescription starts the description of the Hub's AccessRole
// (RemoveClientAccess deletes only that one).
const accessRoleDescription = "Sign-in to this app (Portcullis Hub"

// AccessFlowPrefix starts the alias of every Hub-managed access flow.
const AccessFlowPrefix = "portcullis-client-access"

// accessFlowVersion is part of the flow hash: bump it when the shape the
// Hub builds changes, so existing copies are rebuilt.
const accessFlowVersion = "1"

// completeMarker ends the description of a fully built access flow; a flow
// without it is a leftover of an interrupted build (never bound).
const completeMarker = "[complete]"

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

var hashRe = regexp.MustCompile(`^[0-9a-f]{10}$`)

// accessFlowHash returns the hash suffix of alias if it is an access flow
// of clientID ("" otherwise).
func accessFlowHash(alias, clientID string) string {
	rest, ok := strings.CutPrefix(alias, AccessFlowPrefix+"-"+clientID+"-")
	if !ok || !hashRe.MatchString(rest) {
		return ""
	}
	return rest
}

// AccessCondition is the conditional-user-role value for clientID's role
// (Keycloak resolves "<clientId>.<role>", split at the last dot).
func AccessCondition(clientID string) string { return clientID + "." + AccessRole }

// EnsureClientAccess makes the client's sign-in require AccessRole and
// gives s.Group that role. Idempotent; in this order, so a failure part-way
// leaves the client denying rather than admitting:
//  1. the client role exists;
//  2. the access flow (current hash) exists and is the client's browser
//     flow override; direct access grants, implicit flow, service
//     accounts, device and CIBA grants and standard token exchange are
//     off (no grant may bypass the browser flow); stale access flows of
//     the client are deleted;
//  3. exactly s.Group has the role: other groups and direct user grants
//     lose it. A group Keycloak doesn't have yet is imported with an LDAP
//     group sync; still missing = ErrGroupNotFound (after steps 1–2).
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
	flowID, flowAlias, err := c.ensureAccessFlow(ctx, tok, s.ClientID)
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

	group, err := c.findGroup(ctx, tok, s.Group)
	if err == nil && group == nil {
		if serr := c.syncLDAPGroups(ctx, tok); serr != nil {
			return fmt.Errorf("client %s: group %s not in Keycloak and the LDAP group sync failed: %w", s.ClientID, s.Group, serr)
		}
		group, err = c.findGroup(ctx, tok, s.Group)
	}
	if err != nil {
		return err
	}
	if group == nil {
		return fmt.Errorf("client %s: group %s: %w (create it in Users & Groups; until then nobody can sign in)", s.ClientID, s.Group, ErrGroupNotFound)
	}
	have, err := g.GetGroupsByClientRole(ctx, tok, Realm, AccessRole, url.PathEscape(uuid))
	if err != nil {
		return opErr("list groups with the access role", err)
	}
	mapped := false
	for _, o := range have {
		if o == nil {
			continue
		}
		if str(o.ID) == str(group.ID) {
			mapped = true
			continue
		}
		if err := g.DeleteClientRoleFromGroup(ctx, tok, Realm, url.PathEscape(uuid), url.PathEscape(str(o.ID)), []gocloak.Role{*role}); err != nil {
			return opErr("remove the access role from group "+str(o.Name), err)
		}
		log.Printf("Keycloak client %s: removed the %s role from group %s (only %s has it)", s.ClientID, AccessRole, str(o.Name), s.Group)
	}
	if !mapped {
		if err := g.AddClientRolesToGroup(ctx, tok, Realm, url.PathEscape(uuid), url.PathEscape(str(group.ID)), []gocloak.Role{*role}); err != nil {
			return opErr("grant the access role to group "+s.Group, err)
		}
		log.Printf("Keycloak client %s: group %s has the %s role", s.ClientID, s.Group, AccessRole)
	}
	users, err := g.GetUsersByClientRoleName(ctx, tok, Realm, url.PathEscape(uuid), AccessRole, gocloak.GetUsersByRoleParams{Max: gocloak.IntP(1000)})
	if err != nil {
		return opErr("list users with the access role", err)
	}
	for _, u := range users {
		if u == nil || !ValidUserID(str(u.ID)) {
			continue
		}
		if err := g.DeleteClientRolesFromUser(ctx, tok, Realm, url.PathEscape(uuid), url.PathEscape(str(u.ID)), []gocloak.Role{*role}); err != nil {
			return opErr("remove a direct access role grant", err)
		}
		log.Printf("Keycloak client %s: removed the %s role granted directly to %s (membership of %s is the only grant)", s.ClientID, AccessRole, str(u.Username), s.Group)
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
// mappings) — never the other way round, since a bound flow whose role is
// gone admits everybody — then every access flow of the client that no
// client binds, with its configs. A missing client or role is fine; a
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
			case statusCode(ferr) == http.StatusNotFound || (ferr == nil && accessFlowHash(str(f.Alias), clientID) != ""):
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
				return nil, fmt.Errorf("flow %s: sub-flow %s is a %q flow, which the Hub can't copy", alias, str(f.Alias), p)
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

// treeShape is what the access flow hash covers.
func treeShape(nodes []*flowNode) []interface{} {
	out := []interface{}{}
	for _, n := range nodes {
		if skipInCopy(n) {
			continue
		}
		m := map[string]interface{}{"req": str(n.exec.Requirement)}
		if n.flow != nil {
			m["flow"] = treeShape(n.children)
		} else {
			m["provider"] = str(n.exec.ProviderID)
		}
		if n.config != nil {
			m["config"] = n.config.Config
		}
		out = append(out, m)
	}
	return out
}

// ensureAccessFlow returns the id and alias of clientID's access flow for
// the realm's current browser flow, building it if needed.
func (c *Client) ensureAccessFlow(ctx context.Context, tok, clientID string) (id, alias string, err error) {
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
	b, err := json.Marshal(map[string]interface{}{"v": accessFlowVersion, "client": clientID, "role": AccessCondition(clientID), "tree": treeShape(tree)})
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(b)
	alias = AccessFlowPrefix + "-" + clientID + "-" + hex.EncodeToString(sum[:])[:10]

	flows, err := g.GetAuthenticationFlows(ctx, tok, Realm)
	if err != nil {
		return "", "", opErr("list flows", err)
	}
	for _, f := range flows {
		if f == nil || str(f.Alias) != alias {
			continue
		}
		if strings.HasSuffix(str(f.Description), completeMarker) {
			return str(f.ID), alias, nil
		}
		// An interrupted build (never bound): start over.
		if err := c.deleteFlowTree(ctx, tok, f); err != nil {
			return "", "", err
		}
	}
	if err := c.buildAccessFlow(ctx, tok, alias, src, clientID, tree); err != nil {
		// Leave nothing half-built behind (best effort; retried anyway).
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

func (c *Client) buildAccessFlow(ctx context.Context, tok, alias, src, clientID string, tree []*flowNode) error {
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
	signIn := alias + ".sign-in"
	if err := c.addSubFlow(ctx, tok, alias, signIn, "Sign-in: a copy of "+src, "REQUIRED"); err != nil {
		return err
	}
	if err := c.copyNodes(ctx, tok, alias, signIn, tree); err != nil {
		return err
	}
	deny := alias + ".deny"
	if err := c.addSubFlow(ctx, tok, alias, deny, "Deny users without the "+AccessCondition(clientID)+" role", "CONDITIONAL"); err != nil {
		return err
	}
	if err := c.addExecution(ctx, tok, deny, "conditional-user-role", "REQUIRED", &gocloak.AuthenticatorConfigRepresentation{
		Alias:  gocloak.StringP(alias + ".role"),
		Config: map[string]string{"condUserRole": AccessCondition(clientID), "negate": "true"},
	}); err != nil {
		return err
	}
	if err := c.addExecution(ctx, tok, deny, "deny-access-authenticator", "REQUIRED", &gocloak.AuthenticatorConfigRepresentation{
		Alias:  gocloak.StringP(alias + ".denied"),
		Config: map[string]string{"denyErrorMessage": AccessDeniedMessage},
	}); err != nil {
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

// copyNodes adds nodes (recursively) to the flow called parent; sub-flows
// are named "<top>.<source alias>".
func (c *Client) copyNodes(ctx context.Context, tok, top, parent string, nodes []*flowNode) error {
	for _, n := range nodes {
		if skipInCopy(n) {
			continue
		}
		var cfg *gocloak.AuthenticatorConfigRepresentation
		if n.config != nil {
			cfg = &gocloak.AuthenticatorConfigRepresentation{Alias: gocloak.StringP(top + "." + str(n.exec.ID) + "." + str(n.config.Alias)), Config: n.config.Config}
		}
		if n.flow != nil {
			sub := top + "." + str(n.flow.Alias)
			if err := c.addSubFlow(ctx, tok, parent, sub, str(n.flow.Description), str(n.exec.Requirement)); err != nil {
				return err
			}
			if err := c.copyNodes(ctx, tok, top, sub, n.children); err != nil {
				return err
			}
			continue
		}
		if err := c.addExecution(ctx, tok, parent, str(n.exec.ProviderID), str(n.exec.Requirement), cfg); err != nil {
			return err
		}
	}
	return nil
}

// lastExecution returns the newest direct execution of flow alias (Keycloak
// appends new executions).
func (c *Client) lastExecution(ctx context.Context, tok, alias string) (*gocloak.ModifyAuthenticationExecutionRepresentation, error) {
	execs, err := c.api().GetAuthenticationExecutions(ctx, tok, Realm, url.PathEscape(alias))
	if err != nil {
		return nil, opErr("read flow "+alias, err)
	}
	var last *gocloak.ModifyAuthenticationExecutionRepresentation
	for _, e := range execs {
		if e != nil && (e.Level == nil || *e.Level == 0) && (last == nil || (e.Index != nil && last.Index != nil && *e.Index > *last.Index)) {
			last = e
		}
	}
	if last == nil {
		return nil, fmt.Errorf("flow %s: the new execution is missing", alias)
	}
	return last, nil
}

func (c *Client) setRequirement(ctx context.Context, tok, parent string, e *gocloak.ModifyAuthenticationExecutionRepresentation, req string) error {
	if str(e.Requirement) == req {
		return nil
	}
	e.Requirement = gocloak.StringP(req)
	if err := c.api().UpdateAuthenticationExecution(ctx, tok, Realm, url.PathEscape(parent), *e); err != nil {
		return opErr("set requirement in "+parent, err)
	}
	return nil
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
		if f != nil && str(f.Alias) != keep && accessFlowHash(str(f.Alias), clientID) != "" {
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
