// Package kctest is an in-memory Keycloak admin API fake covering the user
// endpoints the Hub uses, with lazy LDAP import like a federated realm:
// GET /users lists only imported users; an exact username search imports
// the user if Importable says LDAP has them. It also keeps components (one
// LDAP provider plus its mappers), client scopes with protocol mappers, and
// clients (create, update, redirect URIs, web origins) with their default
// client scopes and their own protocol mappers.
package kctest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Credential is a fake credential.
type Credential struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	UserLabel   string `json:"userLabel,omitempty"`
	CreatedDate int64  `json:"createdDate,omitempty"`
}

// User is a fake Keycloak user.
type User struct {
	ID              string
	Username        string
	Enabled         bool
	RequiredActions []string
	Credentials     []Credential
	Sessions        int
	// FederationLink: LDAPProviderID for users imported from LDAP (the
	// default), "" for local users.
	FederationLink string
	// LDAPID is the LDAP_ID attribute of an imported user: LLDAP's
	// account uuid (the federation links by entryUUID), set at import.
	LDAPID string
	// CredentialsStatus, if non-zero, is the HTTP status GET
	// /users/{id}/credentials answers (Keycloak gives 404 or 500 for a
	// federated user whose LDAP entry is gone).
	CredentialsStatus int
	// Groups are the realm groups (by name) the user is a member of;
	// ClientRoles the client roles mapped to the user directly (client
	// uuid → role names).
	Groups      []string
	ClientRoles map[string][]string
	// Consents by clientId and offline sessions (ai.go).
	Consents        map[string]*Consent
	OfflineSessions []*OfflineSession
}

// LDAPProviderID is the id of the fake's LDAP user storage provider.
const LDAPProviderID = "ldap-provider-1"

// Component is a fake component (LDAP mapper, ...).
type Component struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	ProviderID   string              `json:"providerId"`
	ProviderType string              `json:"providerType"`
	ParentID     string              `json:"parentId"`
	Config       map[string][]string `json:"config"`
}

// ProtocolMapper is a fake protocol mapper.
type ProtocolMapper struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Protocol       string            `json:"protocol"`
	ProtocolMapper string            `json:"protocolMapper"`
	Config         map[string]string `json:"config"`
}

// ClientScope is a fake client scope.
type ClientScope struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Protocol   string            `json:"protocol"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Mappers    []ProtocolMapper  `json:"-"`
}

// Client is a fake OIDC client.
type Client struct {
	ID                   string            `json:"id"`
	ClientID             string            `json:"clientId"`
	Attributes           map[string]string `json:"attributes"`
	DefaultClientScopes  []string          `json:"defaultClientScopes"`
	OptionalClientScopes []string          `json:"optionalClientScopes"`
	Name                 string            `json:"name,omitempty"`
	Secret               string            `json:"secret,omitempty"`
	RedirectURIs         []string          `json:"redirectUris"`
	WebOrigins           []string          `json:"webOrigins"`
	// AuthenticationFlowBindingOverrides: "browser" / "direct_grant" →
	// flow id. A PUT merges them like Keycloak (an empty value removes
	// the binding; an unknown flow id is a 400).
	AuthenticationFlowBindingOverrides map[string]string `json:"authenticationFlowBindingOverrides"`
	DirectAccessGrantsEnabled          *bool             `json:"directAccessGrantsEnabled,omitempty"`
	ImplicitFlowEnabled                *bool             `json:"implicitFlowEnabled,omitempty"`
	ServiceAccountsEnabled             *bool             `json:"serviceAccountsEnabled,omitempty"`
	PublicClient                       *bool             `json:"publicClient,omitempty"`
	StandardFlowEnabled                *bool             `json:"standardFlowEnabled,omitempty"`
	FullScopeAllowed                   *bool             `json:"fullScopeAllowed,omitempty"`
	ConsentRequired                    *bool             `json:"consentRequired,omitempty"`
	Enabled                            *bool             `json:"enabled,omitempty"`
	BearerOnly                         *bool             `json:"bearerOnly,omitempty"`
	// ProtocolMappers: the client's own protocol mappers (a client PUT
	// keeps them; the protocol-mappers sub-resource changes them).
	ProtocolMappers []ProtocolMapper `json:"protocolMappers,omitempty"`
}

// Server is the fake.
type Server struct {
	HTTP *httptest.Server
	// Importable reports whether LDAP has username (nil: nobody).
	Importable func(username string) bool
	// LDAPUUID is LDAP's account uuid of username, an imported user's
	// LDAP_ID (Keycloak links by LLDAP's entryUUID); nil or "" = a fresh
	// uuid per import.
	LDAPUUID func(username string) string
	// Down makes every request answer 503 (Keycloak outage).
	Down bool
	// RemoveInvalid: listing users drops the LDAP-linked ones Importable
	// says LDAP no longer has (Keycloak's validation on lookup with the
	// LDAP federation's removeInvalidUsersEnabled); LDAPDown makes that
	// validation fail, which keeps them (Keycloak: unavailable, kept).
	RemoveInvalid bool
	LDAPDown      bool
	// DeleteStatus, if non-zero, is what DELETE /users/{id} answers.
	DeleteStatus int
	// DeleteStatusAfter, if non-zero, is what DELETE /users/{id} answers
	// AFTER deleting the user (Keycloak's federated delete that removes the
	// copy and then fails on an optimistic lock).
	DeleteStatusAfter int

	mu     sync.Mutex
	Users  map[string]*User // by username
	nextID int
	Calls  []string
	// lastRun: the authenticators the last Login ran (LastRun).
	lastRun []string
	// Components besides the LDAP provider (LDAP mappers), by id.
	Components map[string]*Component
	Scopes     map[string]*ClientScope // by id
	Clients    map[string]*Client      // by id
	// FailPrefix, if set, makes every request whose "METHOD path" starts
	// with it answer 500.
	FailPrefix string
	// FailFunc, if set, makes every request it returns true for answer
	// 500 (called under the fake's lock with the method and path).
	FailFunc func(method, path string) bool

	// Authentication flows, authenticator configs, groups and client
	// roles (access.go).
	Flows       map[string]*Flow       // by id
	AuthConfigs map[string]*AuthConfig // by id
	BrowserFlow string                 // the realm's browser flow alias
	Groups      map[string]*Group      // by id
	// Roles: client uuid → role name → role id.
	Roles map[string]map[string]string
	// LDAPGroups are LLDAP group names; the group mapper's sync imports
	// the missing ones into Groups (as Keycloak's READ_ONLY mapper does).
	LDAPGroups []string
	roleDesc   map[string]string // role id → description
	// RealmRoles: realm role name → id. Every user holds
	// default-roles-portcullis (as in Keycloak).
	RealmRoles map[string]string
	// Composites: role id → the ids of the roles it contains.
	Composites map[string][]string
	// RealmDefaultScopes / RealmOptionalScopes: the realm's default
	// client scopes (names) a new client gets when its representation
	// names none (ai.go).
	RealmDefaultScopes  []string
	RealmOptionalScopes []string
	// EventsConfig is the realm's events config as Keycloak returns it
	// (GET / PUT …/events/config); a PUT replaces it with the body.
	EventsConfig map[string]any
}

const (
	realm  = "/admin/realms/portcullis"
	prefix = realm + "/users"
)

// New starts the fake (admin credentials admin/admin).
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{Users: map[string]*User{}, nextID: 1, Components: map[string]*Component{},
		Scopes: map[string]*ClientScope{}, Clients: map[string]*Client{},
		Flows: map[string]*Flow{}, AuthConfigs: map[string]*AuthConfig{}, Groups: map[string]*Group{}, Roles: map[string]map[string]string{}, roleDesc: map[string]string{},
		RealmRoles: map[string]string{"default-roles-portcullis": "role-default"}, Composites: map[string][]string{},
		EventsConfig: map[string]any{"eventsEnabled": false, "eventsListeners": []any{"jboss-logging"}, "enabledEventTypes": []any{},
			"adminEventsEnabled": false, "adminEventsDetailsEnabled": false}}
	s.HTTP = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.HTTP.Close)
	return s
}

// Import adds an imported user and returns it.
func (s *Server) Import(username string, creds ...Credential) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.importLocked(username, creds...)
}

func (s *Server) importLocked(username string, creds ...Credential) *User {
	ldapID := ""
	if s.LDAPUUID != nil {
		ldapID = s.LDAPUUID(username)
	}
	if ldapID == "" {
		ldapID = fmt.Sprintf("00000000-0000-4000-9000-%012d", s.nextID)
	}
	u := &User{ID: fmt.Sprintf("00000000-0000-0000-0000-%012d", s.nextID), Username: username, Enabled: true, RequiredActions: []string{}, Credentials: creds, Sessions: 1, FederationLink: LDAPProviderID, LDAPID: ldapID}
	s.nextID++
	s.Users[username] = u
	return u
}

// Get returns a copy of a user (nil if not imported).
func (s *Server) Get(username string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.Users[username]
	if !ok {
		return nil
	}
	c := *u
	return &c
}

// Update changes an imported user in place (no-op if absent).
func (s *Server) Update(username string, fn func(*User)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.Users[username]; ok {
		fn(u)
	}
}

// SetDown switches the outage simulation.
func (s *Server) SetDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Down = down
}

// SetDeleteStatus makes DELETE /users/{id} answer code (0: normal).
func (s *Server) SetDeleteStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DeleteStatus = code
}

// SetDeleteStatusAfter makes DELETE /users/{id} delete the user and then
// answer code (0: normal).
func (s *Server) SetDeleteStatusAfter(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DeleteStatusAfter = code
}

// AddClient adds a client (attrs may be nil) and returns its id.
func (s *Server) AddClient(clientID string, attrs map[string]string, scopes ...string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.newID("client")
	if attrs == nil {
		attrs = map[string]string{}
	}
	s.Clients[id] = &Client{ID: id, ClientID: clientID, Attributes: attrs, DefaultClientScopes: append([]string{}, scopes...)}
	return id
}

// AddScope adds a realm client scope (no mappers) and returns its id.
func (s *Server) AddScope(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.newID("scope")
	s.Scopes[id] = &ClientScope{ID: id, Name: name, Protocol: "openid-connect"}
	return id
}

// UpdateClient changes client id in place (fn gets the stored client;
// scope lists by name, as an admin could leave them).
func (s *Server) UpdateClient(id string, fn func(*Client)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.Clients[id]; c != nil {
		if c.Attributes == nil {
			c.Attributes = map[string]string{}
		}
		fn(c)
	}
}

// AddClientMapper adds a protocol mapper to client id (config may be
// nil) and returns its id.
func (s *Server) AddClientMapper(id, name, mapperType string, config map[string]string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.Clients[id]
	if c == nil {
		return ""
	}
	if config == nil {
		config = map[string]string{}
	}
	mid := s.newID("cpm")
	c.ProtocolMappers = append(c.ProtocolMappers, ProtocolMapper{ID: mid, Name: name, Protocol: "openid-connect", ProtocolMapper: mapperType, Config: config})
	return mid
}

// ClientMappers returns copies of client id's protocol mappers, by name
// (nil: no such client).
func (s *Server) ClientMappers(id string) map[string]ProtocolMapper {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.Clients[id]
	if c == nil {
		return nil
	}
	out := map[string]ProtocolMapper{}
	for _, m := range c.ProtocolMappers {
		out[m.Name] = m
	}
	return out
}

// ClientByClientID returns a copy of the client with that clientId (nil:
// none).
func (s *Server) ClientByClientID(clientID string) *Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.Clients {
		if c.ClientID == clientID {
			cp := *c
			cp.RedirectURIs = append([]string(nil), c.RedirectURIs...)
			cp.WebOrigins = append([]string(nil), c.WebOrigins...)
			cp.ProtocolMappers = append([]ProtocolMapper(nil), c.ProtocolMappers...)
			cp.Attributes = map[string]string{}
			for k, v := range c.Attributes {
				cp.Attributes[k] = v
			}
			cp.AuthenticationFlowBindingOverrides = map[string]string{}
			for k, v := range c.AuthenticationFlowBindingOverrides {
				cp.AuthenticationFlowBindingOverrides[k] = v
			}
			return &cp
		}
	}
	return nil
}

// SetClientURIs sets a client's redirect URIs and web origins.
func (s *Server) SetClientURIs(id string, redirects, origins []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.Clients[id]; c != nil {
		c.RedirectURIs, c.WebOrigins = append([]string(nil), redirects...), append([]string(nil), origins...)
	}
}

// SetFailFunc sets FailFunc under the fake's lock.
func (s *Server) SetFailFunc(f func(method, path string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FailFunc = f
}

// SetFailPrefix sets FailPrefix under the fake's lock.
func (s *Server) SetFailPrefix(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FailPrefix = p
}

// SetOptionalScopes sets a client's optional client scope names.
func (s *Server) SetOptionalScopes(id string, names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.Clients[id]; c != nil {
		c.OptionalClientScopes = append([]string{}, names...)
	}
}

// OptionalScopes returns a client's optional client scope names (sorted).
func (s *Server) OptionalScopes(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.Clients[id]
	if c == nil {
		return nil
	}
	out := append([]string{}, c.OptionalClientScopes...)
	sort.Strings(out)
	return out
}

// ClientScopes returns a client's default client scope names (sorted).
func (s *Server) ClientScopes(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.Clients[id]
	if c == nil {
		return nil
	}
	out := append([]string{}, c.DefaultClientScopes...)
	sort.Strings(out)
	return out
}

// LDAPMappers returns copies of the LDAP provider's mappers, by name.
func (s *Server) LDAPMappers() map[string]Component {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]Component{}
	for _, c := range s.Components {
		if c.ParentID == LDAPProviderID {
			out[c.Name] = *c
		}
	}
	return out
}

// AddLDAPMapper adds a mapper to the LDAP provider and returns its id.
func (s *Server) AddLDAPMapper(name, providerID string, config map[string][]string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.newID("comp")
	s.Components[id] = &Component{ID: id, Name: name, ProviderID: providerID, ProviderType: "org.keycloak.storage.ldap.mappers.LDAPStorageMapper", ParentID: LDAPProviderID, Config: config}
	return id
}

// Scope returns a copy of the client scope called name (nil if absent).
func (s *Server) Scope(name string) *ClientScope {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.Scopes {
		if sc.Name == name {
			c := *sc
			c.Mappers = append([]ProtocolMapper{}, sc.Mappers...)
			return &c
		}
	}
	return nil
}

// ScopeMappers returns a scope's protocol mappers by name (nil: no scope).
func (s *Server) ScopeMappers(name string) map[string]ProtocolMapper {
	sc := s.Scope(name)
	if sc == nil {
		return nil
	}
	out := map[string]ProtocolMapper{}
	for _, m := range sc.Mappers {
		out[m.Name] = m
	}
	return out
}

// CountCalls counts recorded calls starting with prefix ("POST /admin/...").
func (s *Server) CountCalls(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.Calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (s *Server) newID(kind string) string {
	id := fmt.Sprintf("%s-%d", kind, s.nextID)
	s.nextID++
	return id
}

func (s *Server) byID(id string) *User {
	for _, u := range s.Users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

func rep(u *User) map[string]interface{} {
	attrs := map[string]interface{}{}
	if u.LDAPID != "" {
		attrs["LDAP_ID"] = []string{u.LDAPID}
	}
	return map[string]interface{}{"id": u.ID, "username": u.Username, "enabled": u.Enabled, "requiredActions": u.RequiredActions, "federationLink": u.FederationLink, "attributes": attrs}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Calls = append(s.Calls, r.Method+" "+r.URL.Path)
	if s.Down {
		w.WriteHeader(503)
		return
	}
	if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
		r.ParseForm()
		if r.PostForm.Get("username") != "admin" || r.PostForm.Get("password") != "admin" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" {
		w.WriteHeader(401)
		return
	}
	if (s.FailPrefix != "" && strings.HasPrefix(r.Method+" "+r.URL.Path, s.FailPrefix)) || (s.FailFunc != nil && s.FailFunc(r.Method, r.URL.Path)) {
		w.WriteHeader(500)
		return
	}
	if s.serveAccess(w, r) {
		return
	}
	if s.serveAI(w, r) {
		return
	}
	if r.URL.Path == realm+"/events/config" {
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(s.EventsConfig)
		case http.MethodPut:
			cfg := map[string]any{}
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				w.WriteHeader(400)
				return
			}
			s.EventsConfig = cfg
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, realm+"/components") {
		s.serveComponents(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, realm+"/client-scopes") {
		s.serveScopes(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, realm+"/clients") {
		s.serveClients(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/")
	parts := strings.Split(rest, "/")
	switch {
	case rest == "" && r.Method == "GET":
		q := r.URL.Query()
		out := []map[string]interface{}{}
		if name := q.Get("username"); name != "" {
			name = strings.ToLower(name)
			u, ok := s.Users[name]
			if !ok && s.Importable != nil && s.Importable(name) {
				u, ok = s.importLocked(name), true
			}
			if ok {
				out = append(out, rep(u))
			}
		} else {
			names := make([]string, 0, len(s.Users))
			for n := range s.Users {
				names = append(names, n)
			}
			sort.Strings(names)
			first, max := 0, 100
			fmt.Sscan(q.Get("first"), &first)
			fmt.Sscan(q.Get("max"), &max)
			if first > len(names) {
				first = len(names)
			}
			names = names[first:]
			if max >= 0 && len(names) > max {
				names = names[:max]
			}
			for _, n := range names {
				u := s.Users[n]
				if s.RemoveInvalid && !s.LDAPDown && u.FederationLink == LDAPProviderID && (s.Importable == nil || !s.Importable(n)) {
					delete(s.Users, n)
					continue
				}
				out = append(out, rep(u))
			}
		}
		json.NewEncoder(w).Encode(out)
	case len(parts) >= 1:
		u := s.byID(parts[0])
		if u == nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case len(parts) == 1 && r.Method == "GET":
			json.NewEncoder(w).Encode(rep(u))
		case len(parts) == 1 && r.Method == "PUT":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			acts, ok := body["requiredActions"].([]interface{})
			if !ok || body["id"] != u.ID {
				w.WriteHeader(400)
				return
			}
			u.RequiredActions = []string{}
			for _, a := range acts {
				u.RequiredActions = append(u.RequiredActions, a.(string))
			}
			w.WriteHeader(204)
		case len(parts) == 1 && r.Method == "DELETE":
			if s.DeleteStatus != 0 {
				w.WriteHeader(s.DeleteStatus)
				return
			}
			delete(s.Users, u.Username)
			if s.DeleteStatusAfter != 0 {
				w.WriteHeader(s.DeleteStatusAfter)
				return
			}
			w.WriteHeader(204)
		case len(parts) == 2 && parts[1] == "credentials" && r.Method == "GET":
			if u.CredentialsStatus != 0 {
				w.WriteHeader(u.CredentialsStatus)
				return
			}
			json.NewEncoder(w).Encode(append([]Credential{}, u.Credentials...))
		case len(parts) == 3 && parts[1] == "credentials" && r.Method == "DELETE":
			kept := []Credential{}
			for _, c := range u.Credentials {
				if c.ID != parts[2] {
					kept = append(kept, c)
				}
			}
			u.Credentials = kept
			w.WriteHeader(204)
		case len(parts) == 2 && parts[1] == "logout" && r.Method == "POST":
			u.Sessions = 0
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}
}

// created answers 201 with a Location header, as Keycloak does.
func created(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Location", "http://"+r.Host+r.URL.Path+"/"+id)
	w.WriteHeader(201)
}

func (s *Server) serveComponents(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, realm+"/components"), "/")
	switch {
	case rest == "" && r.Method == "GET":
		q := r.URL.Query()
		out := []interface{}{}
		if q.Get("type") == "org.keycloak.storage.UserStorageProvider" && q.Get("parent") == "" {
			out = append(out, map[string]string{"id": LDAPProviderID, "providerId": "ldap", "name": "lldap"})
		}
		ids := make([]string, 0, len(s.Components))
		for id := range s.Components {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			c := s.Components[id]
			if (q.Get("parent") == "" || q.Get("parent") == c.ParentID) && (q.Get("type") == "" || q.Get("type") == c.ProviderType) {
				out = append(out, c)
			}
		}
		json.NewEncoder(w).Encode(out)
	case rest == "" && r.Method == "POST":
		var c Component
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil || c.Name == "" || c.ParentID == "" {
			w.WriteHeader(400)
			return
		}
		c.ID = s.newID("comp")
		s.Components[c.ID] = &c
		created(w, r, c.ID)
	case rest != "" && r.Method == "PUT":
		old := s.Components[rest]
		var c Component
		if old == nil || json.NewDecoder(r.Body).Decode(&c) != nil || c.ID != rest {
			w.WriteHeader(400)
			return
		}
		s.Components[rest] = &c
		w.WriteHeader(204)
	case rest != "" && r.Method == "DELETE":
		if s.Components[rest] == nil {
			http.NotFound(w, r)
			return
		}
		delete(s.Components, rest)
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveScopes(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, realm+"/client-scopes"), "/")
	parts := strings.Split(rest, "/")
	switch {
	case rest == "" && r.Method == "GET":
		out := []*ClientScope{}
		for _, sc := range s.Scopes {
			out = append(out, sc)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		json.NewEncoder(w).Encode(out)
	case rest == "" && r.Method == "POST":
		var sc ClientScope
		if err := json.NewDecoder(r.Body).Decode(&sc); err != nil || sc.Name == "" {
			w.WriteHeader(400)
			return
		}
		for _, o := range s.Scopes {
			if o.Name == sc.Name {
				w.WriteHeader(409)
				return
			}
		}
		sc.ID = s.newID("scope")
		s.Scopes[sc.ID] = &sc
		created(w, r, sc.ID)
	case len(parts) == 1 && r.Method == "GET":
		sc := s.Scopes[parts[0]]
		if sc == nil {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(sc)
	case len(parts) == 1 && r.Method == "PUT":
		sc := s.Scopes[parts[0]]
		var in ClientScope
		if sc == nil {
			http.NotFound(w, r)
			return
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Name == "" {
			w.WriteHeader(400)
			return
		}
		// Keycloak renames the scope in every client's lists; the Hub
		// never renames, so a rename is refused here.
		if in.Name != sc.Name {
			w.WriteHeader(400)
			return
		}
		sc.Protocol, sc.Attributes = in.Protocol, in.Attributes
		w.WriteHeader(204)
	case len(parts) == 1 && r.Method == "DELETE":
		sc := s.Scopes[parts[0]]
		if sc == nil {
			http.NotFound(w, r)
			return
		}
		// Keycloak refuses to delete a scope still linked to a client
		// (400 "Cannot remove client scope, it is currently in use") or
		// to the realm's defaults.
		for _, c := range s.Clients {
			if contains(c.DefaultClientScopes, sc.Name) || contains(c.OptionalClientScopes, sc.Name) {
				w.WriteHeader(400)
				return
			}
		}
		if contains(s.RealmDefaultScopes, sc.Name) || contains(s.RealmOptionalScopes, sc.Name) {
			w.WriteHeader(400)
			return
		}
		delete(s.Scopes, sc.ID)
		w.WriteHeader(204)
	case len(parts) >= 3 && parts[1] == "protocol-mappers" && parts[2] == "models":
		sc := s.Scopes[parts[0]]
		if sc == nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case len(parts) == 3 && r.Method == "GET":
			json.NewEncoder(w).Encode(append([]ProtocolMapper{}, sc.Mappers...))
		case len(parts) == 3 && r.Method == "POST":
			var m ProtocolMapper
			if err := json.NewDecoder(r.Body).Decode(&m); err != nil || m.Name == "" {
				w.WriteHeader(400)
				return
			}
			for _, o := range sc.Mappers {
				if o.Name == m.Name {
					w.WriteHeader(409)
					return
				}
			}
			m.ID = s.newID("pm")
			sc.Mappers = append(sc.Mappers, m)
			created(w, r, m.ID)
		case len(parts) == 4 && (r.Method == "PUT" || r.Method == "DELETE"):
			for i, o := range sc.Mappers {
				if o.ID != parts[3] {
					continue
				}
				if r.Method == "DELETE" {
					sc.Mappers = append(sc.Mappers[:i], sc.Mappers[i+1:]...)
				} else {
					var m ProtocolMapper
					if json.NewDecoder(r.Body).Decode(&m) != nil || m.ID != o.ID {
						w.WriteHeader(400)
						return
					}
					sc.Mappers[i] = m
				}
				w.WriteHeader(204)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveClients(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, realm+"/clients"), "/")
	parts := strings.Split(rest, "/")
	switch {
	case rest == "" && r.Method == "GET":
		out := []*Client{}
		for _, c := range s.Clients {
			if q := r.URL.Query().Get("clientId"); q == "" || q == c.ClientID {
				out = append(out, c)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		json.NewEncoder(w).Encode(out)
	case rest == "" && r.Method == "POST":
		var c Client
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil || c.ClientID == "" {
			w.WriteHeader(400)
			return
		}
		for _, o := range s.Clients {
			if o.ClientID == c.ClientID {
				w.WriteHeader(409)
				return
			}
		}
		// Keycloak silently drops scope names the realm doesn't have.
		known := map[string]bool{}
		for _, sc := range s.Scopes {
			known[sc.Name] = true
		}
		// A list the representation leaves out is the realm's defaults.
		if c.DefaultClientScopes == nil {
			c.DefaultClientScopes = append([]string{}, s.RealmDefaultScopes...)
		}
		if c.OptionalClientScopes == nil {
			c.OptionalClientScopes = append([]string{}, s.RealmOptionalScopes...)
		}
		scopes, optional := []string{}, []string{}
		for _, n := range c.DefaultClientScopes {
			if known[n] {
				scopes = append(scopes, n)
			}
		}
		for _, n := range c.OptionalClientScopes {
			if known[n] && !contains(scopes, n) {
				optional = append(optional, n)
			}
		}
		c.ID, c.DefaultClientScopes, c.OptionalClientScopes = s.newID("client"), scopes, optional
		for i := range c.ProtocolMappers {
			c.ProtocolMappers[i].ID = s.newID("cpm")
		}
		if c.Attributes == nil {
			c.Attributes = map[string]string{}
		}
		s.Clients[c.ID] = &c
		created(w, r, c.ID)
	case len(parts) == 1 && r.Method == "DELETE":
		if s.Clients[parts[0]] == nil {
			http.NotFound(w, r)
			return
		}
		delete(s.Clients, parts[0])
		w.WriteHeader(204)
	case len(parts) == 1 && r.Method == "PUT":
		old := s.Clients[parts[0]]
		if old == nil {
			http.NotFound(w, r)
			return
		}
		var c Client
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil || c.ClientID != old.ClientID {
			w.WriteHeader(400)
			return
		}
		// A client PUT ignores the scope lists (sub-resources do those).
		c.ID, c.DefaultClientScopes, c.OptionalClientScopes = old.ID, old.DefaultClientScopes, old.OptionalClientScopes
		c.ProtocolMappers = old.ProtocolMappers
		// Flow binding overrides merge; "" removes one.
		merged := map[string]string{}
		for k, v := range old.AuthenticationFlowBindingOverrides {
			merged[k] = v
		}
		for k, v := range c.AuthenticationFlowBindingOverrides {
			if v == "" {
				delete(merged, k)
				continue
			}
			if s.Flows[v] == nil {
				w.WriteHeader(400)
				return
			}
			merged[k] = v
		}
		c.AuthenticationFlowBindingOverrides = merged
		if c.Attributes == nil {
			c.Attributes = map[string]string{}
		}
		s.Clients[c.ID] = &c
		w.WriteHeader(204)
	case len(parts) >= 3 && parts[1] == "protocol-mappers" && parts[2] == "models":
		s.serveClientMappers(w, r, s.Clients[parts[0]], parts[3:])
	case len(parts) == 3 && parts[1] == "default-client-scopes" && r.Method == "PUT":
		c, sc := s.Clients[parts[0]], s.Scopes[parts[2]]
		if c == nil || sc == nil {
			http.NotFound(w, r)
			return
		}
		for _, n := range c.OptionalClientScopes {
			if n == sc.Name {
				w.WriteHeader(409) // Keycloak: already linked as optional
				return
			}
		}
		for _, n := range c.DefaultClientScopes {
			if n == sc.Name {
				w.WriteHeader(204)
				return
			}
		}
		c.DefaultClientScopes = append(c.DefaultClientScopes, sc.Name)
		w.WriteHeader(204)
	case len(parts) == 3 && parts[1] == "default-client-scopes" && r.Method == "DELETE":
		c, sc := s.Clients[parts[0]], s.Scopes[parts[2]]
		if c == nil || sc == nil {
			http.NotFound(w, r)
			return
		}
		kept := []string{}
		for _, n := range c.DefaultClientScopes {
			if n != sc.Name {
				kept = append(kept, n)
			}
		}
		c.DefaultClientScopes = kept
		w.WriteHeader(204)
	case len(parts) == 3 && parts[1] == "optional-client-scopes" && r.Method == "PUT":
		c, sc := s.Clients[parts[0]], s.Scopes[parts[2]]
		if c == nil || sc == nil {
			http.NotFound(w, r)
			return
		}
		if contains(c.DefaultClientScopes, sc.Name) {
			w.WriteHeader(409) // Keycloak: already linked as default
			return
		}
		if !contains(c.OptionalClientScopes, sc.Name) {
			c.OptionalClientScopes = append(c.OptionalClientScopes, sc.Name)
		}
		w.WriteHeader(204)
	case len(parts) == 3 && parts[1] == "optional-client-scopes" && r.Method == "DELETE":
		c, sc := s.Clients[parts[0]], s.Scopes[parts[2]]
		if c == nil || sc == nil {
			http.NotFound(w, r)
			return
		}
		kept := []string{}
		for _, n := range c.OptionalClientScopes {
			if n != sc.Name {
				kept = append(kept, n)
			}
		}
		c.OptionalClientScopes = kept
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}

// serveClientMappers is /clients/{id}/protocol-mappers/models[/{mapper}]
// (GET, POST; PUT, DELETE), like Keycloak: a duplicate name is a 409.
func (s *Server) serveClientMappers(w http.ResponseWriter, r *http.Request, c *Client, rest []string) {
	if c == nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case len(rest) == 0 && r.Method == "GET":
		json.NewEncoder(w).Encode(append([]ProtocolMapper{}, c.ProtocolMappers...))
	case len(rest) == 0 && r.Method == "POST":
		var m ProtocolMapper
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil || m.Name == "" {
			w.WriteHeader(400)
			return
		}
		for _, o := range c.ProtocolMappers {
			if o.Name == m.Name {
				w.WriteHeader(409)
				return
			}
		}
		m.ID = s.newID("cpm")
		c.ProtocolMappers = append(c.ProtocolMappers, m)
		created(w, r, m.ID)
	case len(rest) == 1 && (r.Method == "PUT" || r.Method == "DELETE"):
		for i, o := range c.ProtocolMappers {
			if o.ID != rest[0] {
				continue
			}
			if r.Method == "DELETE" {
				c.ProtocolMappers = append(c.ProtocolMappers[:i:i], c.ProtocolMappers[i+1:]...)
			} else {
				var m ProtocolMapper
				if json.NewDecoder(r.Body).Decode(&m) != nil || m.ID != o.ID {
					w.WriteHeader(400)
					return
				}
				c.ProtocolMappers[i] = m
			}
			w.WriteHeader(204)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}
