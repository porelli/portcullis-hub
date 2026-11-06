package kctest

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Consent is a user's consent to a client (Keycloak's
// UserConsentRepresentation): the granted client scopes, by name.
type Consent struct {
	Scopes  []string
	Created time.Time
	Updated time.Time
}

// OfflineSession is a user's offline session; Clients maps client uuid →
// clientId (Keycloak's UserSessionRepresentation.clients).
type OfflineSession struct {
	ID         string
	Start      time.Time
	LastAccess time.Time
	Clients    map[string]string
}

// AddConsent records username's consent to clientID (an imported user).
func (s *Server) AddConsent(username, clientID string, created time.Time, scopes ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.Users[username]
	if u == nil {
		return
	}
	if u.Consents == nil {
		u.Consents = map[string]*Consent{}
	}
	u.Consents[clientID] = &Consent{Scopes: append([]string{}, scopes...), Created: created, Updated: created}
}

// AddOfflineSession adds an offline session of username holding the
// clients (by uuid) and returns its id.
func (s *Server) AddOfflineSession(username string, start, lastAccess time.Time, clientUUIDs ...string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.Users[username]
	if u == nil {
		return ""
	}
	os := &OfflineSession{ID: s.newID("offline"), Start: start, LastAccess: lastAccess, Clients: map[string]string{}}
	for _, id := range clientUUIDs {
		if c := s.Clients[id]; c != nil {
			os.Clients[id] = c.ClientID
		}
	}
	u.OfflineSessions = append(u.OfflineSessions, os)
	return os.ID
}

// UserConsents returns the clientIds username has consented to (sorted).
func (s *Server) UserConsents(username string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.Users[username]
	if u == nil {
		return nil
	}
	out := []string{}
	for k := range u.Consents {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// OfflineClients returns, per offline session of username, its clientIds
// joined with "+" (sorted).
func (s *Server) OfflineClients(username string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.Users[username]
	if u == nil {
		return nil
	}
	out := []string{}
	for _, os := range u.OfflineSessions {
		var ids []string
		for _, cid := range os.Clients {
			ids = append(ids, cid)
		}
		sort.Strings(ids)
		out = append(out, strings.Join(ids, "+"))
	}
	sort.Strings(out)
	return out
}

// SetRealmDefaultScopes sets the realm's default and optional default
// client scopes (names).
func (s *Server) SetRealmDefaultScopes(def, opt []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RealmDefaultScopes, s.RealmOptionalScopes = append([]string{}, def...), append([]string{}, opt...)
}

// RealmScopes returns the realm's default and optional default client
// scopes (sorted).
func (s *Server) RealmScopes() (def, opt []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	def, opt = append([]string{}, s.RealmDefaultScopes...), append([]string{}, s.RealmOptionalScopes...)
	sort.Strings(def)
	sort.Strings(opt)
	return def, opt
}

func ms(t time.Time) int64 { return t.UnixMilli() }

// serveAI: the realm's default client scopes, users' consents and offline
// sessions, like Keycloak:
//   - GET/PUT/DELETE /default-default-client-scopes[/{id}] and
//     /default-optional-client-scopes[/{id}];
//   - GET /users/{id}/consents (also, like Keycloak, an entry without
//     createdDate for each client holding only offline tokens); DELETE /users/{id}/consents/{clientId}
//     revokes the consent AND the client's offline tokens (404 when
//     there was neither);
//   - GET /users/{id}/offline-sessions/{clientUuid}.
func (s *Server) serveAI(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	for _, kind := range []string{"default-default-client-scopes", "default-optional-client-scopes"} {
		base := realm + "/" + kind
		if p != base && !strings.HasPrefix(p, base+"/") {
			continue
		}
		list := &s.RealmDefaultScopes
		if kind == "default-optional-client-scopes" {
			list = &s.RealmOptionalScopes
		}
		id := strings.Trim(strings.TrimPrefix(p, base), "/")
		switch {
		case id == "" && r.Method == "GET":
			out := []*ClientScope{}
			for _, n := range *list {
				if sc := s.scopeByName(n); sc != nil {
					out = append(out, sc)
				}
			}
			json.NewEncoder(w).Encode(out)
		case id != "" && (r.Method == "PUT" || r.Method == "DELETE"):
			sc := s.Scopes[id]
			if sc == nil {
				http.NotFound(w, r)
				return true
			}
			kept := []string{}
			for _, n := range *list {
				if n != sc.Name {
					kept = append(kept, n)
				}
			}
			if r.Method == "PUT" {
				kept = append(kept, sc.Name)
			}
			*list = kept
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
		return true
	}
	if !strings.HasPrefix(p, prefix+"/") {
		return false
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(p, prefix), "/"), "/")
	if len(parts) < 2 || (parts[1] != "consents" && parts[1] != "offline-sessions") {
		return false
	}
	u := s.byID(parts[0])
	if u == nil {
		http.NotFound(w, r)
		return true
	}
	switch {
	case parts[1] == "consents" && len(parts) == 2 && r.Method == "GET":
		out := []map[string]interface{}{}
		keys := make([]string, 0, len(u.Consents))
		for k := range u.Consents {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			c := u.Consents[k]
			// Keycloak 26.8 lists the granted scopes by name.
			scopes := []string{}
			for _, n := range c.Scopes {
				if s.scopeByName(n) != nil {
					scopes = append(scopes, n)
				}
			}
			out = append(out, map[string]interface{}{"clientId": k, "grantedClientScopes": scopes,
				"createdDate": ms(c.Created), "lastUpdatedDate": ms(c.Updated)})
		}
		offlineOnly := map[string]bool{}
		for _, os := range u.OfflineSessions {
			for _, cid := range os.Clients {
				if u.Consents[cid] == nil {
					offlineOnly[cid] = true
				}
			}
		}
		for _, cid := range sortedSet(offlineOnly) {
			out = append(out, map[string]interface{}{"clientId": cid, "grantedClientScopes": []string{},
				"additionalGrants": []map[string]string{{"client": "Offline Token", "key": "Offline Token"}}})
		}
		json.NewEncoder(w).Encode(out)
	case parts[1] == "consents" && len(parts) == 3 && r.Method == "DELETE":
		clientID := parts[2]
		_, had := u.Consents[clientID]
		delete(u.Consents, clientID)
		kept := []*OfflineSession{}
		for _, os := range u.OfflineSessions {
			for uuid, cid := range os.Clients {
				if cid == clientID {
					delete(os.Clients, uuid)
					had = true
				}
			}
			if len(os.Clients) > 0 {
				kept = append(kept, os)
			}
		}
		u.OfflineSessions = kept
		if !had {
			http.NotFound(w, r)
			return true
		}
		w.WriteHeader(204)
	case parts[1] == "offline-sessions" && len(parts) == 3 && r.Method == "GET":
		if s.Clients[parts[2]] == nil {
			http.NotFound(w, r)
			return true
		}
		out := []map[string]interface{}{}
		for _, os := range u.OfflineSessions {
			if _, ok := os.Clients[parts[2]]; ok {
				out = append(out, map[string]interface{}{"id": os.ID, "username": u.Username, "userId": u.ID,
					"start": ms(os.Start), "lastAccess": ms(os.LastAccess), "clients": os.Clients})
			}
		}
		json.NewEncoder(w).Encode(out)
	default:
		http.NotFound(w, r)
	}
	return true
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Server) scopeByName(name string) *ClientScope {
	for _, sc := range s.Scopes {
		if sc.Name == name {
			return sc
		}
	}
	return nil
}

// AddScopeMapper adds a protocol mapper to the client scope called name
// (config may be nil) and returns its id ("" if there is no such scope).
func (s *Server) AddScopeMapper(name, mapperName, mapperType string, config map[string]string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.scopeByName(name)
	if sc == nil {
		return ""
	}
	if config == nil {
		config = map[string]string{}
	}
	id := s.newID("pm")
	sc.Mappers = append(sc.Mappers, ProtocolMapper{ID: id, Name: mapperName, Protocol: "openid-connect", ProtocolMapper: mapperType, Config: config})
	return id
}

// ScopeCount returns how many client scopes the realm has.
func (s *Server) ScopeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Scopes)
}
