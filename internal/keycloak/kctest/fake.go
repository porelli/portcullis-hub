// Package kctest is an in-memory Keycloak admin API fake covering the user
// endpoints the Hub uses, with lazy LDAP import like a federated realm:
// GET /users lists only imported users; an exact username search imports
// the user if Importable says LDAP has them. It also keeps components (one
// LDAP provider plus its mappers), client scopes with protocol mappers, and
// clients with their default client scopes.
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
	ID   string `json:"id"`
	Type string `json:"type"`
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
	// CredentialsStatus, if non-zero, is the HTTP status GET
	// /users/{id}/credentials answers (Keycloak gives 404 or 500 for a
	// federated user whose LDAP entry is gone).
	CredentialsStatus int
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
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Protocol string           `json:"protocol"`
	Mappers  []ProtocolMapper `json:"-"`
}

// Client is a fake OIDC client.
type Client struct {
	ID                   string            `json:"id"`
	ClientID             string            `json:"clientId"`
	Attributes           map[string]string `json:"attributes"`
	DefaultClientScopes  []string          `json:"defaultClientScopes"`
	OptionalClientScopes []string          `json:"optionalClientScopes"`
}

// Server is the fake.
type Server struct {
	HTTP *httptest.Server
	// Importable reports whether LDAP has username (nil: nobody).
	Importable func(username string) bool
	// Down makes every request answer 503 (Keycloak outage).
	Down bool
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
	// Components besides the LDAP provider (LDAP mappers), by id.
	Components map[string]*Component
	Scopes     map[string]*ClientScope // by id
	Clients    map[string]*Client      // by id
	// FailPrefix, if set, makes every request whose "METHOD path" starts
	// with it answer 500.
	FailPrefix string
}

const (
	realm  = "/admin/realms/portcullis"
	prefix = realm + "/users"
)

// New starts the fake (admin credentials admin/admin).
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{Users: map[string]*User{}, nextID: 1, Components: map[string]*Component{},
		Scopes: map[string]*ClientScope{}, Clients: map[string]*Client{}}
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
	u := &User{ID: fmt.Sprintf("00000000-0000-0000-0000-%012d", s.nextID), Username: username, Enabled: true, RequiredActions: []string{}, Credentials: creds, Sessions: 1, FederationLink: LDAPProviderID}
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
	return map[string]interface{}{"id": u.ID, "username": u.Username, "enabled": u.Enabled, "requiredActions": u.RequiredActions, "federationLink": u.FederationLink, "attributes": map[string]interface{}{"LDAP_ID": []string{u.Username}}}
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
	if s.FailPrefix != "" && strings.HasPrefix(r.Method+" "+r.URL.Path, s.FailPrefix) {
		w.WriteHeader(500)
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
			for _, n := range names {
				out = append(out, rep(s.Users[n]))
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
