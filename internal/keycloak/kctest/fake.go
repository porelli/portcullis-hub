// Package kctest is an in-memory Keycloak admin API fake covering the user
// endpoints the Hub uses, with lazy LDAP import like a federated realm:
// GET /users lists only imported users; an exact username search imports
// the user if Importable says LDAP has them.
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

// Server is the fake.
type Server struct {
	HTTP *httptest.Server
	// Importable reports whether LDAP has username (nil: nobody).
	Importable func(username string) bool
	// Down makes every request answer 503 (Keycloak outage).
	Down bool
	// DeleteStatus, if non-zero, is what DELETE /users/{id} answers.
	DeleteStatus int

	mu     sync.Mutex
	Users  map[string]*User // by username
	nextID int
	Calls  []string
}

const prefix = "/admin/realms/portcullis/users"

// New starts the fake (admin credentials admin/admin).
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{Users: map[string]*User{}, nextID: 1}
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
	if r.URL.Path == "/admin/realms/portcullis/components" && r.Method == "GET" {
		out := []map[string]string{}
		if r.URL.Query().Get("type") == "org.keycloak.storage.UserStorageProvider" {
			out = append(out, map[string]string{"id": LDAPProviderID, "providerId": "ldap", "name": "lldap"})
		}
		json.NewEncoder(w).Encode(out)
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
