package kctest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Authentication flows, authenticator configs, realm groups and client
// roles, plus a small model of Keycloak's flow processor (Login) so tests
// can check who a client's browser flow lets in.

// Flow is a fake authentication flow (top-level or sub-flow).
type Flow struct {
	ID          string
	Alias       string
	Description string
	ProviderID  string
	TopLevel    bool
	BuiltIn     bool
	Execs       []*Execution
}

// Execution is one step of a flow: an authenticator (Provider) or a
// sub-flow (FlowID).
type Execution struct {
	ID          string
	Provider    string
	FlowID      string
	Requirement string
	ConfigID    string
}

// AuthConfig is a fake authenticator config.
type AuthConfig struct {
	ID     string            `json:"id"`
	Alias  string            `json:"alias"`
	Config map[string]string `json:"config"`
}

// Group is a fake realm group (imported from LDAP by the group mapper).
type Group struct {
	ID   string
	Name string
	// ClientRoles: client uuid → role names mapped to the group.
	ClientRoles map[string][]string
}

// GroupMapperID is the id of the fake's LDAP group mapper (AddGroupMapper).
const GroupMapperID = "group-mapper-1"

// AddClientRole adds a client role (client by clientId) as an admin would.
func (s *Server) AddClientRole(clientID, role, description string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clientByClientIDLocked(clientID)
	if c == nil {
		return
	}
	if s.Roles[c.ID] == nil {
		s.Roles[c.ID] = map[string]string{}
	}
	s.Roles[c.ID][role] = s.newID("role")
	s.roleDesc[s.Roles[c.ID][role]] = description
}

// AddGroupMapper adds the LDAP provider's group-ldap-mapper.
func (s *Server) AddGroupMapper() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Components[GroupMapperID] = &Component{ID: GroupMapperID, Name: "groups", ProviderID: "group-ldap-mapper",
		ProviderType: "org.keycloak.storage.ldap.mappers.LDAPStorageMapper", ParentID: LDAPProviderID, Config: map[string][]string{}}
}

// AddLDAPGroup puts a group in LDAP only (Keycloak sees it after a sync).
func (s *Server) AddLDAPGroup(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LDAPGroups = append(s.LDAPGroups, name)
}

// AddGroup adds a realm group (already imported) and returns its id.
func (s *Server) AddGroup(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addGroupLocked(name)
}

func (s *Server) addGroupLocked(name string) string {
	id := s.newID("group")
	s.Groups[id] = &Group{ID: id, Name: name, ClientRoles: map[string][]string{}}
	return id
}

func (s *Server) groupByName(name string) *Group {
	for _, g := range s.Groups {
		if g.Name == name {
			return g
		}
	}
	return nil
}

// JoinGroup makes an imported user a member of a group (by name).
func (s *Server) JoinGroup(username, group string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.Users[username]; u != nil {
		u.Groups = append(u.Groups, group)
	}
}

// GrantClientRole maps a client role (client by clientId) directly to an
// imported user.
func (s *Server) GrantClientRole(username, clientID, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, c := s.Users[username], s.clientByClientIDLocked(clientID)
	if u == nil || c == nil {
		return
	}
	if u.ClientRoles == nil {
		u.ClientRoles = map[string][]string{}
	}
	u.ClientRoles[c.ID] = append(u.ClientRoles[c.ID], role)
}

// DeleteClientRole removes a client role (and its mappings), as an admin
// clicking in the console would.
func (s *Server) DeleteClientRole(clientID, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.clientByClientIDLocked(clientID); c != nil {
		s.deleteRoleLocked(c.ID, role)
	}
}

// ClientRole reports whether the client (by clientId) has role.
func (s *Server) ClientRole(clientID, role string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clientByClientIDLocked(clientID)
	return c != nil && s.Roles[c.ID][role] != ""
}

// RoleGroups returns the names of the groups the client role is mapped to
// (sorted).
func (s *Server) RoleGroups(clientID, role string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clientByClientIDLocked(clientID)
	if c == nil {
		return nil
	}
	var out []string
	for _, g := range s.Groups {
		if contains(g.ClientRoles[c.ID], role) {
			out = append(out, g.Name)
		}
	}
	sort.Strings(out)
	return out
}

// FlowByID returns a copy of a flow (nil: none).
func (s *Server) FlowByID(id string) *Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.Flows[id]
	if f == nil {
		return nil
	}
	c := *f
	return &c
}

// TopLevelFlows returns the aliases of the top-level flows (sorted).
func (s *Server) TopLevelFlows() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, f := range s.Flows {
		if f.TopLevel {
			out = append(out, f.Alias)
		}
	}
	sort.Strings(out)
	return out
}

// FlowCount is the number of flows (top-level and sub-flows); ConfigCount
// the number of authenticator configs.
func (s *Server) FlowCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Flows)
}

// ConfigCount is the number of authenticator configs.
func (s *Server) ConfigCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.AuthConfigs)
}

// FlowProviders lists a flow's executions depth-first as
// "<depth>:<requirement>:<provider or sub-flow alias>".
func (s *Server) FlowProviders(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	var walk func(f *Flow, depth int)
	walk = func(f *Flow, depth int) {
		for _, e := range f.Execs {
			if e.FlowID != "" {
				sub := s.Flows[e.FlowID]
				out = append(out, fmt.Sprintf("%d:%s:[%s]", depth, e.Requirement, sub.Alias))
				walk(sub, depth+1)
				continue
			}
			out = append(out, fmt.Sprintf("%d:%s:%s", depth, e.Requirement, e.Provider))
		}
	}
	if f := s.Flows[id]; f != nil {
		walk(f, 0)
	}
	return out
}

// SetRealmBrowserFlow sets the realm's browser flow alias.
func (s *Server) SetRealmBrowserFlow(alias string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BrowserFlow = alias
}

// Node describes a flow tree for AddFlow: an authenticator (Provider,
// optional Config) or a sub-flow (Alias + Children).
type Node struct {
	Requirement string
	Provider    string
	Config      map[string]string
	Alias       string
	Children    []Node
}

// AddFlow adds a top-level flow built from children and returns its id.
func (s *Server) AddFlow(alias, description string, children ...Node) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := &Flow{ID: s.newID("flow"), Alias: alias, Description: description, ProviderID: "basic-flow", TopLevel: true}
	s.Flows[f.ID] = f
	s.addNodesLocked(f, children)
	return f.ID
}

func (s *Server) addNodesLocked(f *Flow, nodes []Node) {
	for _, n := range nodes {
		e := &Execution{ID: s.newID("exec"), Requirement: n.Requirement}
		if n.Alias != "" {
			sub := &Flow{ID: s.newID("flow"), Alias: n.Alias, ProviderID: "basic-flow"}
			s.Flows[sub.ID] = sub
			e.FlowID = sub.ID
			s.addNodesLocked(sub, n.Children)
		} else {
			e.Provider = n.Provider
			if n.Config != nil {
				cfg := &AuthConfig{ID: s.newID("cfg"), Alias: fmt.Sprintf("%s-%s", n.Provider, e.ID), Config: n.Config}
				s.AuthConfigs[cfg.ID] = cfg
				e.ConfigID = cfg.ID
			}
		}
		f.Execs = append(f.Execs, e)
	}
}

// SeedUniversalFlow adds core's portcullis-universal browser flow (shape
// of keycloak/realm-export.json) and makes it the realm's browser flow.
func (s *Server) SeedUniversalFlow() string {
	loa := func(level string) Node {
		return Node{Requirement: "REQUIRED", Provider: "conditional-level-of-authentication", Config: map[string]string{"loa-condition-level": level, "loa-max-age": "36000"}}
	}
	x509 := map[string]string{"x509-cert-auth.mapping-source-selection": "Subject's Common Name"}
	id := s.AddFlow("portcullis-universal", "Passkey-first, LoA-aware browser flow",
		Node{Requirement: "ALTERNATIVE", Provider: "auth-cookie"},
		Node{Requirement: "ALTERNATIVE", Provider: "identity-provider-redirector"},
		Node{Requirement: "ALTERNATIVE", Alias: "portcullis-step-up", Children: []Node{
			{Requirement: "CONDITIONAL", Alias: "portcullis-loa-1", Children: []Node{
				loa("1"),
				{Requirement: "REQUIRED", Alias: "portcullis-loa-1-factors", Children: []Node{
					{Requirement: "ALTERNATIVE", Provider: "auth-x509-client-username-form", Config: x509},
					{Requirement: "ALTERNATIVE", Provider: "webauthn-authenticator-passwordless", Config: map[string]string{"amr": "hwk"}},
				}},
			}},
			{Requirement: "CONDITIONAL", Alias: "portcullis-loa-2", Children: []Node{
				loa("2"),
				{Requirement: "REQUIRED", Provider: "allow-access-authenticator"},
			}},
			{Requirement: "CONDITIONAL", Alias: "portcullis-loa-3", Children: []Node{
				loa("3"),
				{Requirement: "REQUIRED", Provider: "auth-x509-client-username-form", Config: x509},
			}},
		}},
	)
	s.SetRealmBrowserFlow("portcullis-universal")
	return id
}

// Login outcomes.
var (
	ErrDenied     = errors.New("access denied by the flow")
	ErrAuthFailed = errors.New("authentication failed")
)

// Login models a browser sign-in of username to clientID: the client's
// browser flow override (else the realm's browser flow) is processed like
// Keycloak's DefaultAuthenticationFlow — REQUIRED and CONDITIONAL
// executions run in order and ALTERNATIVE ones at the same level are then
// ignored, else the first ALTERNATIVE that succeeds wins; a CONDITIONAL
// sub-flow runs only if all its conditional-* executions hold. sso: the
// browser has an SSO cookie (auth-cookie succeeds). Every other
// authenticator succeeds (the user presents a passkey); deny-access
// fails. conditional-level-of-authentication holds for level 1 only (an
// app asking for LoA 1). conditional-user-role resolves its role like
// Keycloak (clientId.role, split at the last dot) and, if that role does
// not exist, does not hold.
func (s *Server) Login(clientID, username string, sso bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.Users[username]
	if u == nil {
		return fmt.Errorf("no user %s", username)
	}
	var flow *Flow
	if c := s.clientByClientIDLocked(clientID); c != nil && c.AuthenticationFlowBindingOverrides["browser"] != "" {
		flow = s.Flows[c.AuthenticationFlowBindingOverrides["browser"]]
	} else {
		flow = s.flowByAlias(s.BrowserFlow)
	}
	if flow == nil {
		return fmt.Errorf("no browser flow")
	}
	lc := &loginCtx{user: u, sso: sso}
	if !s.runFlow(flow, lc, false) {
		if lc.denied {
			return ErrDenied
		}
		return ErrAuthFailed
	}
	return nil
}

type loginCtx struct {
	user   *User
	sso    bool
	denied bool
}

func isCondition(p string) bool { return strings.HasPrefix(p, "conditional-") }

func (s *Server) runFlow(f *Flow, lc *loginCtx, skipConditions bool) bool {
	var required, alts []*Execution
	for _, e := range f.Execs {
		if skipConditions && e.FlowID == "" && isCondition(e.Provider) {
			continue
		}
		switch e.Requirement {
		case "REQUIRED", "CONDITIONAL":
			required = append(required, e)
		case "ALTERNATIVE":
			alts = append(alts, e)
		}
	}
	if len(required) > 0 {
		for _, e := range required {
			if e.Requirement == "CONDITIONAL" {
				sub := s.Flows[e.FlowID]
				if sub == nil || !s.conditionsHold(sub, lc) {
					continue
				}
				if !s.runFlow(sub, lc, true) {
					return false
				}
				continue
			}
			if !s.runExec(e, lc) {
				return false
			}
		}
		return true
	}
	for _, e := range alts {
		if s.runExec(e, lc) {
			return true
		}
	}
	return len(alts) == 0
}

func (s *Server) runExec(e *Execution, lc *loginCtx) bool {
	if e.FlowID != "" {
		sub := s.Flows[e.FlowID]
		return sub != nil && s.runFlow(sub, lc, false)
	}
	switch e.Provider {
	case "auth-cookie":
		return lc.sso
	case "identity-provider-redirector":
		return false // no kc_idp_hint
	case "deny-access-authenticator":
		lc.denied = true
		return false
	}
	return true
}

func (s *Server) conditionsHold(f *Flow, lc *loginCtx) bool {
	for _, e := range f.Execs {
		if e.FlowID != "" || !isCondition(e.Provider) {
			continue
		}
		var cfg map[string]string
		if c := s.AuthConfigs[e.ConfigID]; c != nil {
			cfg = c.Config
		}
		switch e.Provider {
		case "conditional-level-of-authentication":
			if cfg["loa-condition-level"] != "1" {
				return false
			}
		case "conditional-user-role":
			if !s.userRoleCondition(cfg, lc.user) {
				return false
			}
		}
	}
	return true
}

func (s *Server) userRoleCondition(cfg map[string]string, u *User) bool {
	ref := cfg["condUserRole"]
	i := strings.LastIndex(ref, ".")
	if i < 0 {
		return false
	}
	c := s.clientByClientIDLocked(ref[:i])
	role := ref[i+1:]
	if c == nil || s.Roles[c.ID][role] == "" {
		return false // Keycloak: unknown role → the condition doesn't hold
	}
	has := contains(u.ClientRoles[c.ID], role)
	for _, gn := range u.Groups {
		if g := s.groupByName(gn); g != nil && contains(g.ClientRoles[c.ID], role) {
			has = true
		}
	}
	return has != (cfg["negate"] == "true")
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) clientByClientIDLocked(clientID string) *Client {
	for _, c := range s.Clients {
		if c.ClientID == clientID {
			return c
		}
	}
	return nil
}

func (s *Server) flowByAlias(alias string) *Flow {
	for _, f := range s.Flows {
		if f.Alias == alias {
			return f
		}
	}
	return nil
}

func (s *Server) flowRep(f *Flow) map[string]interface{} {
	return map[string]interface{}{"id": f.ID, "alias": f.Alias, "description": f.Description, "providerId": f.ProviderID, "topLevel": f.TopLevel, "builtIn": f.BuiltIn}
}

// flowUsed: Keycloak refuses to delete a flow bound to the realm or a
// client.
func (s *Server) flowUsed(f *Flow) bool {
	if f.Alias == s.BrowserFlow {
		return true
	}
	for _, c := range s.Clients {
		for _, v := range c.AuthenticationFlowBindingOverrides {
			if v == f.ID {
				return true
			}
		}
	}
	return false
}

func (s *Server) deleteFlowLocked(f *Flow) {
	for _, e := range f.Execs {
		if sub := s.Flows[e.FlowID]; sub != nil {
			s.deleteFlowLocked(sub)
		}
	}
	delete(s.Flows, f.ID)
}

func (s *Server) deleteRoleLocked(clientUUID, role string) {
	if s.Roles[clientUUID][role] == "" {
		return
	}
	delete(s.Roles[clientUUID], role)
	for _, g := range s.Groups {
		g.ClientRoles[clientUUID] = without(g.ClientRoles[clientUUID], role)
	}
	for _, u := range s.Users {
		if u.ClientRoles != nil {
			u.ClientRoles[clientUUID] = without(u.ClientRoles[clientUUID], role)
		}
	}
}

func without(list []string, v string) []string {
	out := []string{}
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func groupRep(g *Group) map[string]interface{} {
	return map[string]interface{}{"id": g.ID, "name": g.Name, "path": "/" + g.Name, "subGroups": []interface{}{}}
}

// serveAccess answers the realm, authentication, groups, user-storage
// and client-role endpoints; false: not one of them.
func (s *Server) serveAccess(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	switch {
	case p == realm && r.Method == "GET":
		json.NewEncoder(w).Encode(map[string]interface{}{"realm": "portcullis", "browserFlow": s.BrowserFlow})
	case strings.HasPrefix(p, realm+"/authentication/"):
		s.serveAuthentication(w, r, strings.Trim(strings.TrimPrefix(p, realm+"/authentication/"), "/"))
	case strings.HasPrefix(p, realm+"/groups"):
		s.serveGroups(w, r, strings.Trim(strings.TrimPrefix(p, realm+"/groups"), "/"))
	case strings.HasPrefix(p, realm+"/user-storage/"):
		// POST /user-storage/{provider}/mappers/{mapper}/sync?direction=fedToKeycloak
		parts := strings.Split(strings.Trim(strings.TrimPrefix(p, realm+"/user-storage/"), "/"), "/")
		if len(parts) != 4 || parts[1] != "mappers" || parts[3] != "sync" || r.Method != "POST" ||
			r.URL.Query().Get("direction") != "fedToKeycloak" || s.Components[parts[2]] == nil || s.Components[parts[2]].ParentID != parts[0] {
			http.NotFound(w, r)
			return true
		}
		n := 0
		for _, name := range s.LDAPGroups {
			if s.groupByName(name) == nil {
				s.addGroupLocked(name)
				n++
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"added": n, "status": fmt.Sprintf("%d imported groups", n)})
	case strings.HasPrefix(p, realm+"/clients/") && strings.Contains(strings.TrimPrefix(p, realm+"/clients/"), "/roles"):
		s.serveClientRoles(w, r, strings.Split(strings.Trim(strings.TrimPrefix(p, realm+"/clients/"), "/"), "/"))
	case strings.HasPrefix(p, prefix+"/") && strings.Contains(p, "/role-mappings/clients/"):
		// DELETE /users/{id}/role-mappings/clients/{client}
		parts := strings.Split(strings.Trim(strings.TrimPrefix(p, prefix+"/"), "/"), "/")
		u := s.byID(parts[0])
		if u == nil || len(parts) != 4 || r.Method != "DELETE" {
			http.NotFound(w, r)
			return true
		}
		var roles []struct{ Name string }
		json.NewDecoder(r.Body).Decode(&roles)
		for _, ro := range roles {
			if u.ClientRoles != nil {
				u.ClientRoles[parts[3]] = without(u.ClientRoles[parts[3]], ro.Name)
			}
		}
		w.WriteHeader(204)
	default:
		return false
	}
	return true
}

func (s *Server) serveClientRoles(w http.ResponseWriter, r *http.Request, parts []string) {
	// parts: {client}, "roles", [name, [groups|users]]
	c := s.Clients[parts[0]]
	if c == nil || parts[1] != "roles" {
		http.NotFound(w, r)
		return
	}
	roles := s.Roles[c.ID]
	switch {
	case len(parts) == 2 && r.Method == "POST":
		var body struct{ Name, Description string }
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name == "" {
			w.WriteHeader(400)
			return
		}
		if roles[body.Name] != "" {
			w.WriteHeader(409)
			return
		}
		if roles == nil {
			roles = map[string]string{}
			s.Roles[c.ID] = roles
		}
		roles[body.Name] = s.newID("role")
		s.roleDesc[roles[body.Name]] = body.Description
		created(w, r, body.Name)
	case len(parts) >= 3 && roles[parts[2]] == "":
		http.NotFound(w, r)
	case len(parts) == 3 && r.Method == "GET":
		json.NewEncoder(w).Encode(map[string]interface{}{"id": roles[parts[2]], "name": parts[2], "description": s.roleDesc[roles[parts[2]]], "clientRole": true, "containerId": c.ID})
	case len(parts) == 3 && r.Method == "DELETE":
		s.deleteRoleLocked(c.ID, parts[2])
		w.WriteHeader(204)
	case len(parts) == 4 && parts[3] == "groups" && r.Method == "GET":
		out := []map[string]interface{}{}
		for _, g := range s.sortedGroups() {
			if contains(g.ClientRoles[c.ID], parts[2]) {
				out = append(out, groupRep(g))
			}
		}
		json.NewEncoder(w).Encode(out)
	case len(parts) == 4 && parts[3] == "users" && r.Method == "GET":
		out := []map[string]interface{}{}
		for _, u := range s.Users {
			if u.ClientRoles != nil && contains(u.ClientRoles[c.ID], parts[2]) {
				out = append(out, rep(u))
			}
		}
		json.NewEncoder(w).Encode(out)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) sortedGroups() []*Group {
	out := make([]*Group, 0, len(s.Groups))
	for _, g := range s.Groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) serveGroups(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(rest, "/")
	switch {
	case rest == "" && r.Method == "GET":
		q := r.URL.Query()
		search, exact := q.Get("search"), q.Get("exact") == "true"
		out := []map[string]interface{}{}
		for _, g := range s.sortedGroups() {
			if search == "" || (exact && g.Name == search) || (!exact && strings.Contains(strings.ToLower(g.Name), strings.ToLower(search))) {
				out = append(out, groupRep(g))
			}
		}
		json.NewEncoder(w).Encode(out)
	case len(parts) == 4 && parts[1] == "role-mappings" && parts[2] == "clients" && (r.Method == "POST" || r.Method == "DELETE"):
		g, c := s.Groups[parts[0]], s.Clients[parts[3]]
		if g == nil || c == nil {
			http.NotFound(w, r)
			return
		}
		var roles []struct{ ID, Name string }
		if json.NewDecoder(r.Body).Decode(&roles) != nil {
			w.WriteHeader(400)
			return
		}
		for _, ro := range roles {
			if s.Roles[c.ID][ro.Name] == "" || s.Roles[c.ID][ro.Name] != ro.ID {
				http.NotFound(w, r)
				return
			}
			g.ClientRoles[c.ID] = without(g.ClientRoles[c.ID], ro.Name)
			if r.Method == "POST" {
				g.ClientRoles[c.ID] = append(g.ClientRoles[c.ID], ro.Name)
			}
		}
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) execReps(f *Flow, level int, out *[]map[string]interface{}) {
	for i, e := range f.Execs {
		m := map[string]interface{}{"id": e.ID, "requirement": e.Requirement, "level": level, "index": i, "authenticationFlow": e.FlowID != ""}
		if e.ConfigID != "" {
			m["authenticationConfig"] = e.ConfigID
		}
		if e.FlowID != "" {
			sub := s.Flows[e.FlowID]
			m["flowId"], m["displayName"], m["description"] = sub.ID, sub.Alias, sub.Description
			*out = append(*out, m)
			s.execReps(sub, level+1, out)
			continue
		}
		m["providerId"], m["displayName"] = e.Provider, e.Provider
		*out = append(*out, m)
	}
}

func (s *Server) execByID(id string) *Execution {
	for _, f := range s.Flows {
		for _, e := range f.Execs {
			if e.ID == id {
				return e
			}
		}
	}
	return nil
}

func (s *Server) serveAuthentication(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(rest, "/")
	switch {
	case rest == "flows" && r.Method == "GET":
		out := []map[string]interface{}{}
		ids := make([]string, 0, len(s.Flows))
		for id, f := range s.Flows {
			if f.TopLevel {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			out = append(out, s.flowRep(s.Flows[id]))
		}
		json.NewEncoder(w).Encode(out)
	case rest == "flows" && r.Method == "POST":
		var body struct {
			Alias, Description, ProviderID string
			TopLevel, BuiltIn              bool
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Alias == "" || !body.TopLevel {
			w.WriteHeader(400)
			return
		}
		if s.flowByAlias(body.Alias) != nil {
			w.WriteHeader(409)
			return
		}
		f := &Flow{ID: s.newID("flow"), Alias: body.Alias, Description: body.Description, ProviderID: body.ProviderID, TopLevel: true}
		s.Flows[f.ID] = f
		created(w, r, f.ID)
	case len(parts) == 2 && parts[0] == "flows" && s.Flows[parts[1]] != nil:
		f := s.Flows[parts[1]]
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(s.flowRep(f))
		case "PUT":
			var body struct{ Alias, Description string }
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Alias == "" {
				w.WriteHeader(400)
				return
			}
			if o := s.flowByAlias(body.Alias); o != nil && o != f {
				w.WriteHeader(409)
				return
			}
			f.Alias, f.Description = body.Alias, body.Description
			json.NewEncoder(w).Encode(s.flowRep(f))
		case "DELETE":
			if f.BuiltIn || s.flowUsed(f) {
				w.WriteHeader(400)
				return
			}
			s.deleteFlowLocked(f)
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	case len(parts) >= 3 && parts[0] == "flows" && parts[2] == "executions":
		f := s.flowByAlias(parts[1])
		if f == nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case len(parts) == 3 && r.Method == "GET":
			out := []map[string]interface{}{}
			s.execReps(f, 0, &out)
			json.NewEncoder(w).Encode(out)
		case len(parts) == 3 && r.Method == "PUT":
			var body struct{ ID, Requirement string }
			json.NewDecoder(r.Body).Decode(&body)
			e := s.execByID(body.ID)
			if e == nil {
				http.NotFound(w, r)
				return
			}
			e.Requirement = body.Requirement
			w.WriteHeader(204)
		case len(parts) == 4 && parts[3] == "execution" && r.Method == "POST":
			var body struct{ Provider string }
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Provider == "" {
				w.WriteHeader(400)
				return
			}
			e := &Execution{ID: s.newID("exec"), Provider: body.Provider, Requirement: "DISABLED"}
			f.Execs = append(f.Execs, e)
			created(w, r, e.ID)
		case len(parts) == 4 && parts[3] == "flow" && r.Method == "POST":
			var body struct{ Alias, Type, Provider, Description string }
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Alias == "" || body.Type == "" {
				w.WriteHeader(400)
				return
			}
			if s.flowByAlias(body.Alias) != nil {
				w.WriteHeader(409)
				return
			}
			sub := &Flow{ID: s.newID("flow"), Alias: body.Alias, Description: body.Description, ProviderID: body.Type}
			s.Flows[sub.ID] = sub
			e := &Execution{ID: s.newID("exec"), FlowID: sub.ID, Requirement: "DISABLED"}
			f.Execs = append(f.Execs, e)
			created(w, r, e.ID)
		default:
			http.NotFound(w, r)
		}
	case len(parts) == 3 && parts[0] == "executions" && parts[2] == "config" && r.Method == "POST":
		e := s.execByID(parts[1])
		var cfg AuthConfig
		if e == nil || json.NewDecoder(r.Body).Decode(&cfg) != nil || cfg.Alias == "" {
			w.WriteHeader(400)
			return
		}
		cfg.ID = s.newID("cfg")
		s.AuthConfigs[cfg.ID] = &cfg
		e.ConfigID = cfg.ID
		created(w, r, cfg.ID)
	case len(parts) == 2 && parts[0] == "config":
		cfg := s.AuthConfigs[parts[1]]
		if cfg == nil {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(cfg)
		case "DELETE":
			delete(s.AuthConfigs, cfg.ID)
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

// With runs fn under the fake's lock (tests editing Flows, AuthConfigs,
// Clients, ... directly).
func (s *Server) With(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}
