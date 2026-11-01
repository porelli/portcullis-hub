// Package lldaptest is an in-memory LLDAP fake for tests: the HTTP login /
// refresh / GraphQL endpoints the Hub uses, and an LDAP listener that
// understands simple bind and the Password Modify extended operation.
package lldaptest

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Group is a fake group.
type Group struct {
	ID      int
	Name    string
	Members map[string]bool
}

// AttributeSchema records how an attribute was defined.
type AttributeSchema struct {
	AttributeType string
	IsList        bool
	IsVisible     bool
	IsEditable    bool
}

// Server is the fake.
type Server struct {
	HTTP   *httptest.Server
	LDAP   net.Listener
	BaseDN string

	mu        sync.Mutex
	Users     map[string]map[string]string // id → email, displayName
	Passwords map[string]string
	Groups    map[int]*Group
	nextGroup int
	tokens    map[string]string // token → user
	refresh   map[string]string // refresh → user
	Logins    int
	Refreshes int
	// ExpireTokens makes every issued token invalid on its next use
	// (to exercise the 401 → re-login path).
	ExpireTokens bool
	// FailPassword makes the next password modify fail with this code
	// (set it between requests, not concurrently with them).
	FailPassword        int
	Mutations           []string
	UserAttributeSchema map[string]AttributeSchema     // name → schema
	UserAttributeValues map[string]map[string][]string // user id → attribute name → values
}

// New starts a fake with users admin and the service account (both in
// lldap_admin, group 1), base DN dc=example,dc=org.
func New(t *testing.T, service, servicePass string) *Server {
	t.Helper()
	s := &Server{
		BaseDN:              "dc=example,dc=org",
		Users:               map[string]map[string]string{},
		Passwords:           map[string]string{},
		Groups:              map[int]*Group{},
		nextGroup:           4,
		tokens:              map[string]string{},
		refresh:             map[string]string{},
		UserAttributeSchema: map[string]AttributeSchema{},
		UserAttributeValues: map[string]map[string][]string{},
	}
	s.Groups[1] = &Group{ID: 1, Name: "lldap_admin", Members: map[string]bool{}}
	s.Groups[2] = &Group{ID: 2, Name: "lldap_password_manager", Members: map[string]bool{}}
	s.Groups[3] = &Group{ID: 3, Name: "lldap_strict_readonly", Members: map[string]bool{}}
	s.AddUser("admin", "admin@example.org", "Administrator", "adminpass", "lldap_admin")
	s.AddUser(service, "hub@example.org", "Hub", servicePass, "lldap_admin")
	s.HTTP = httptest.NewServer(http.HandlerFunc(s.serveHTTP))
	t.Cleanup(s.HTTP.Close)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.LDAP = l
	t.Cleanup(func() { l.Close() })
	go s.serveLDAP()
	return s
}

// LDAPURL is the fake's ldap:// URL.
func (s *Server) LDAPURL() string { return "ldap://" + s.LDAP.Addr().String() }

// AddUser adds a user (password "" = none) to the given groups.
func (s *Server) AddUser(id, email, display, password string, groups ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Users[id] = map[string]string{"email": email, "displayName": display}
	if password != "" {
		s.Passwords[id] = password
	}
	for _, g := range groups {
		for _, grp := range s.Groups {
			if grp.Name == g {
				grp.Members[id] = true
			}
		}
	}
}

// AddGroup adds a group and returns its id.
func (s *Server) AddGroup(name string, members ...string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextGroup
	s.nextGroup++
	g := &Group{ID: id, Name: name, Members: map[string]bool{}}
	for _, m := range members {
		g.Members[m] = true
	}
	s.Groups[id] = g
	return id
}

// GroupMembers returns a group's sorted members (nil if no such group).
func (s *Server) GroupMembers(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.Groups {
		if g.Name == name {
			out := []string{}
			for m := range g.Members {
				out = append(out, m)
			}
			sort.Strings(out)
			return out
		}
	}
	return nil
}

// RemoveMember drops user from group behind the Hub's back (as the LLDAP
// UI would).
func (s *Server) RemoveMember(group, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.Groups {
		if g.Name == group {
			delete(g.Members, user)
		}
	}
}

// HasGroup reports whether a group exists.
func (s *Server) HasGroup(name string) bool { return s.GroupMembers(name) != nil }

// HasUser reports whether a user exists.
func (s *Server) HasUser(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.Users[id]
	return ok
}

// Password returns a user's current password.
func (s *Server) Password(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Passwords[id]
}

func jwt(user string, n int) string {
	enc := base64.RawURLEncoding.EncodeToString
	claims, _ := json.Marshal(map[string]interface{}{"sub": user, "exp": time.Now().Add(24 * time.Hour).Unix(), "n": n})
	return enc([]byte(`{"alg":"HS512"}`)) + "." + enc(claims) + ".sig"
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/auth/simple/login":
		var req struct{ Username, Password string }
		json.NewDecoder(r.Body).Decode(&req)
		if p, ok := s.Passwords[req.Username]; !ok || p != req.Password {
			http.Error(w, `{"error":"invalid credentials"}`, 401)
			return
		}
		s.Logins++
		tok := jwt(req.Username, s.Logins)
		ref := fmt.Sprintf("r%d+%s", s.Logins, req.Username)
		s.tokens[tok], s.refresh[ref] = req.Username, req.Username
		json.NewEncoder(w).Encode(map[string]string{"token": tok, "refreshToken": ref})
	case "/auth/refresh":
		u, ok := s.refresh[r.Header.Get("Refresh-Token")]
		if !ok {
			http.Error(w, "bad refresh", 401)
			return
		}
		s.Refreshes++
		tok := jwt(u, 1000+s.Refreshes)
		s.tokens[tok] = u
		json.NewEncoder(w).Encode(map[string]interface{}{"token": tok, "refreshToken": nil})
	case "/api/graphql":
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		user, ok := s.tokens[tok]
		if !ok {
			http.Error(w, "unauthorized", 401)
			return
		}
		if s.ExpireTokens {
			delete(s.tokens, tok)
		}
		if !s.Groups[1].Members[user] {
			json.NewEncoder(w).Encode(map[string]interface{}{"errors": []map[string]string{{"message": "Unauthorized"}}})
			return
		}
		var req struct {
			Query     string                 `json:"query"`
			Variables map[string]interface{} `json:"variables"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		data, err := s.graphql(user, req.Query, req.Variables)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"data": nil, "errors": []map[string]string{{"message": err.Error()}}})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) userGroups(id string) []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, g := range s.Groups {
		if g.Members[id] {
			out = append(out, map[string]interface{}{"id": g.ID, "displayName": g.Name})
		}
	}
	return out
}

func num(v interface{}) int {
	f, _ := v.(float64)
	return int(f)
}

func str(v interface{}) string { s, _ := v.(string); return s }

// graphql dispatches on the operation the Hub's client sends.
func (s *Server) graphql(caller, q string, vars map[string]interface{}) (interface{}, error) {
	op := func(name string) bool { return strings.Contains(q, name+"(") || strings.Contains(q, "{ "+name+" {") }
	switch {
	case op("schema"):
		var attrs []map[string]interface{}
		for name, schema := range s.UserAttributeSchema {
			attrs = append(attrs, map[string]interface{}{
				"name":        name,
				"isList":      schema.IsList,
				"isHardcoded": false,
			})
		}
		return map[string]interface{}{
			"schema": map[string]interface{}{
				"userSchema": map[string]interface{}{
					"attributes": attrs,
				},
			},
		}, nil
	case op("addUserAttribute"):
		name := str(vars["name"])
		s.UserAttributeSchema[name] = AttributeSchema{
			AttributeType: str(vars["attributeType"]),
			IsList:        vars["isList"].(bool),
			IsVisible:     vars["isVisible"].(bool),
			IsEditable:    vars["isEditable"].(bool),
		}
		s.Mutations = append(s.Mutations, "addUserAttribute "+name)
		return map[string]interface{}{"addUserAttribute": map[string]bool{"ok": true}}, nil
	case op("deleteUserAttribute"):
		name := str(vars["name"])
		delete(s.UserAttributeSchema, name)
		for _, userAttrs := range s.UserAttributeValues {
			delete(userAttrs, name)
		}
		s.Mutations = append(s.Mutations, "deleteUserAttribute "+name)
		return map[string]interface{}{"deleteUserAttribute": map[string]bool{"ok": true}}, nil
	case op("createUser"):
		in, _ := vars["user"].(map[string]interface{})
		id := strings.ToLower(str(in["id"]))
		if _, ok := s.Users[id]; ok {
			return nil, fmt.Errorf("user already exists")
		}
		if str(in["email"]) == "" {
			return nil, fmt.Errorf("Email is required when creating a new user")
		}
		s.Users[id] = map[string]string{"email": str(in["email"]), "displayName": str(in["displayName"])}
		s.Mutations = append(s.Mutations, "createUser "+id)
		return map[string]interface{}{"createUser": map[string]string{"id": id}}, nil
	case op("updateUser"):
		in, _ := vars["user"].(map[string]interface{})
		id := str(in["id"])
		u, ok := s.Users[id]
		if !ok {
			return nil, fmt.Errorf("no such user")
		}
		if v, ok := in["email"]; ok {
			u["email"] = str(v)
		}
		if v, ok := in["displayName"]; ok {
			u["displayName"] = str(v)
		}
		// Validate insertAttributes BEFORE mutating anything.
		var validatedInserts []struct {
			name   string
			values []string
		}
		if insert, ok := in["insertAttributes"].([]interface{}); ok {
			for _, item := range insert {
				attr := item.(map[string]interface{})
				name := str(attr["name"])
				// Validate: attribute must be in schema.
				schema, exists := s.UserAttributeSchema[name]
				if !exists {
					return nil, fmt.Errorf("Attribute %s must be declared in the schema first", name)
				}
				values := []string{}
				if valArr, ok := attr["value"].([]interface{}); ok {
					for _, v := range valArr {
						values = append(values, str(v))
					}
				}
				// Validate: non-list attributes need exactly 1 value.
				if !schema.IsList && len(values) != 1 {
					return nil, fmt.Errorf("Attribute %s is not a list but got %d values", name, len(values))
				}
				validatedInserts = append(validatedInserts, struct {
					name   string
					values []string
				}{name, values})
			}
		}
		// All validations passed. Now apply changes atomically.
		// Handle removeAttributes first (as the real LLDAP does).
		if remove, ok := in["removeAttributes"].([]interface{}); ok {
			if s.UserAttributeValues[id] == nil {
				s.UserAttributeValues[id] = map[string][]string{}
			}
			for _, name := range remove {
				delete(s.UserAttributeValues[id], str(name))
			}
		}
		// Handle insertAttributes (set or update).
		if len(validatedInserts) > 0 {
			if s.UserAttributeValues[id] == nil {
				s.UserAttributeValues[id] = map[string][]string{}
			}
			for _, vi := range validatedInserts {
				s.UserAttributeValues[id][vi.name] = vi.values
			}
		}
		s.Mutations = append(s.Mutations, "updateUser "+id)
		return map[string]interface{}{"updateUser": map[string]bool{"ok": true}}, nil
	case op("deleteUser"):
		id := str(vars["id"])
		if id == caller {
			return nil, fmt.Errorf("Cannot delete current user")
		}
		delete(s.Users, id)
		delete(s.Passwords, id)
		for _, g := range s.Groups {
			delete(g.Members, id)
		}
		s.Mutations = append(s.Mutations, "deleteUser "+id)
		return map[string]interface{}{"deleteUser": map[string]bool{"ok": true}}, nil
	case op("createGroup"):
		id := s.nextGroup
		s.nextGroup++
		s.Groups[id] = &Group{ID: id, Name: str(vars["name"]), Members: map[string]bool{}}
		s.Mutations = append(s.Mutations, "createGroup "+str(vars["name"]))
		return map[string]interface{}{"createGroup": map[string]int{"id": id}}, nil
	case op("deleteGroup"):
		id := num(vars["id"])
		if id == 1 {
			return nil, fmt.Errorf("Cannot delete admin group")
		}
		delete(s.Groups, id)
		s.Mutations = append(s.Mutations, fmt.Sprintf("deleteGroup %d", id))
		return map[string]interface{}{"deleteGroup": map[string]bool{"ok": true}}, nil
	case op("addUserToGroup"):
		g, ok := s.Groups[num(vars["g"])]
		if !ok {
			return nil, fmt.Errorf("no such group")
		}
		g.Members[str(vars["u"])] = true
		s.Mutations = append(s.Mutations, "addUserToGroup "+str(vars["u"])+" "+g.Name)
		return map[string]interface{}{"addUserToGroup": map[string]bool{"ok": true}}, nil
	case op("removeUserFromGroup"):
		g, ok := s.Groups[num(vars["g"])]
		if !ok {
			return nil, fmt.Errorf("no such group")
		}
		if str(vars["u"]) == caller && g.ID == 1 {
			return nil, fmt.Errorf("Cannot remove admin rights for current user")
		}
		delete(g.Members, str(vars["u"]))
		s.Mutations = append(s.Mutations, "removeUserFromGroup "+str(vars["u"])+" "+g.Name)
		return map[string]interface{}{"removeUserFromGroup": map[string]bool{"ok": true}}, nil
	case op("users"):
		ids := make([]string, 0, len(s.Users))
		for id := range s.Users {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out := []map[string]interface{}{}
		for _, id := range ids {
			u := s.Users[id]
			userAttrs := []map[string]interface{}{}
			if s.UserAttributeValues[id] != nil {
				for name, values := range s.UserAttributeValues[id] {
					userAttrs = append(userAttrs, map[string]interface{}{
						"name":  name,
						"value": values,
						"schema": map[string]interface{}{
							"isHardcoded": false,
						},
					})
				}
			}
			out = append(out, map[string]interface{}{
				"id":           id,
				"email":        u["email"],
				"displayName":  u["displayName"],
				"creationDate": "2026-01-01T00:00:00+00:00",
				"groups":       s.userGroups(id),
				"attributes":   userAttrs,
			})
		}
		return map[string]interface{}{"users": out}, nil
	case op("groups"):
		out := []map[string]interface{}{}
		for _, g := range s.Groups {
			members := []map[string]string{}
			for m := range g.Members {
				members = append(members, map[string]string{"id": m})
			}
			out = append(out, map[string]interface{}{"id": g.ID, "displayName": g.Name, "creationDate": "2026-01-01T00:00:00+00:00", "users": members})
		}
		return map[string]interface{}{"groups": out}, nil
	}
	return nil, fmt.Errorf("fake: unsupported query %q", q)
}

// ── LDAP ──────────────────────────────────────────────────

func readTLV(r *bufio.Reader) (byte, []byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	l, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n := int(l)
	if l&0x80 != 0 {
		n = 0
		for i := 0; i < int(l&0x7f); i++ {
			b, _ := r.ReadByte()
			n = n<<8 | int(b)
		}
	}
	v := make([]byte, n)
	_, err = io.ReadFull(r, v)
	return tag, v, err
}

func split(b []byte) (byte, []byte, []byte) {
	if len(b) < 2 {
		return 0, nil, nil
	}
	tag, l := b[0], int(b[1])
	b = b[2:]
	if l&0x80 != 0 {
		k := l & 0x7f
		l = 0
		for i := 0; i < k; i++ {
			l = l<<8 | int(b[i])
		}
		b = b[k:]
	}
	if l > len(b) {
		return 0, nil, nil
	}
	return tag, b[:l], b[l:]
}

func enc(tag byte, v []byte) []byte {
	if len(v) < 0x80 {
		return append([]byte{tag, byte(len(v))}, v...)
	}
	return append([]byte{tag, 0x82, byte(len(v) >> 8), byte(len(v))}, v...)
}

func result(id int, op byte, code int, msg string) []byte {
	body := append(enc(0x0a, []byte{byte(code)}), enc(0x04, nil)...)
	body = append(body, enc(0x04, []byte(msg))...)
	return enc(0x30, append(enc(0x02, []byte{byte(id)}), enc(op, body)...))
}

func (s *Server) uidOf(dn string) (string, bool) {
	dn = strings.ToLower(dn)
	suffix := ",ou=people," + s.BaseDN
	if !strings.HasPrefix(dn, "uid=") || !strings.HasSuffix(dn, suffix) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(dn, "uid="), suffix), true
}

func (s *Server) serveLDAP() {
	for {
		c, err := s.LDAP.Accept()
		if err != nil {
			return
		}
		go s.ldapConn(c)
	}
}

func (s *Server) ldapConn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	bound := ""
	for {
		tag, msg, err := readTLV(r)
		if err != nil || tag != 0x30 {
			return
		}
		_, idb, rest := split(msg)
		id := 0
		for _, b := range idb {
			id = id<<8 | int(b)
		}
		opTag, op, _ := split(rest)
		switch opTag {
		case 0x60: // bind
			_, _, op = split(op) // version
			_, dn, op := split(op)
			_, pw, _ := split(op)
			uid, ok := s.uidOf(string(dn))
			s.mu.Lock()
			good := ok && s.Passwords[uid] == string(pw) && s.Passwords[uid] != ""
			s.mu.Unlock()
			if !good {
				c.Write(result(id, 0x61, 49, "")) // invalidCredentials
				continue
			}
			bound = uid
			c.Write(result(id, 0x61, 0, ""))
		case 0x77: // extended
			_, oid, op := split(op)
			_, val, _ := split(op)
			if string(oid) != "1.3.6.1.4.1.4203.1.11.1" {
				c.Write(result(id, 0x78, 2, "unsupported"))
				continue
			}
			_, seq, _ := split(val)
			var userDN, newPw string
			for len(seq) > 0 {
				var t byte
				var v []byte
				t, v, seq = split(seq)
				switch t {
				case 0x80:
					userDN = string(v)
				case 0x82:
					newPw = string(v)
				case 0:
					seq = nil
				}
			}
			s.mu.Lock()
			uid, ok := s.uidOf(userDN)
			_, exists := s.Users[uid]
			switch {
			case bound == "" || !s.Groups[1].Members[bound]:
				s.mu.Unlock()
				c.Write(result(id, 0x78, 50, "insufficient access"))
			case s.FailPassword != 0:
				code := s.FailPassword
				s.FailPassword = 0
				s.mu.Unlock()
				c.Write(result(id, 0x78, code, "simulated failure"))
			case !ok || !exists || newPw == "":
				s.mu.Unlock()
				c.Write(result(id, 0x78, 34, "invalid DN"))
			default:
				s.Passwords[uid] = newPw
				s.Mutations = append(s.Mutations, "password "+uid)
				s.mu.Unlock()
				c.Write(result(id, 0x78, 0, ""))
			}
		case 0x42: // unbind
			return
		default:
			return
		}
	}
}
