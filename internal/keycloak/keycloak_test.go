package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMayReconcile(t *testing.T) {
	hosts := []string{"app.example.org"}
	untagged := func(redirects, origins []interface{}) map[string]interface{} {
		m := map[string]interface{}{"clientId": "app"}
		if redirects != nil {
			m["redirectUris"] = redirects
		}
		if origins != nil {
			m["webOrigins"] = origins
		}
		return m
	}
	l := func(s ...string) []interface{} {
		out := []interface{}{}
		for _, v := range s {
			out = append(out, v)
		}
		return out
	}
	cases := []struct {
		name     string
		existing map[string]interface{}
		hosts    []string
		ok       bool
	}{
		{"owned", map[string]interface{}{"clientId": "app", "attributes": map[string]interface{}{OwnerAttr: "app"}}, nil, true},
		{"owned by other template", map[string]interface{}{"clientId": "app", "attributes": map[string]interface{}{OwnerAttr: "evil"}}, hosts, false},
		{"protected even if tagged", map[string]interface{}{"clientId": "portcullis-forward-auth", "attributes": map[string]interface{}{OwnerAttr: "app"}}, hosts, false},
		{"untagged own host", untagged(l("https://APP.example.org/cb", "https://app.example.org:8443/x"), l("+", "https://app.example.org")), hosts, true},
		{"untagged no redirect uris", untagged(nil, nil), hosts, false},
		{"untagged empty redirect uris", untagged(l(), nil), hosts, false},
		{"untagged foreign host", untagged(l("https://app.example.org/cb", "https://evil.example.com/cb"), nil), hosts, false},
		{"untagged sibling app host", untagged(l("https://passwords.example.org/cb"), nil), hosts, false},
		{"untagged wildcard", untagged(l("https://app.example.org/*"), nil), hosts, false},
		{"untagged bare wildcard", untagged(l("*"), nil), hosts, false},
		{"untagged wildcard origin", untagged(l("https://app.example.org/cb"), l("*")), hosts, false},
		{"untagged foreign origin", untagged(l("https://app.example.org/cb"), l("https://evil.example.com")), hosts, false},
		{"untagged custom scheme", untagged(l("myapp://cb"), nil), hosts, false},
		{"untagged userinfo trick", untagged(l("https://app.example.org@evil.com/cb"), nil), hosts, false},
		{"untagged without allowed hosts", untagged(l("https://app.example.org/cb"), nil), nil, false},
	}
	for _, c := range cases {
		if got := MayReconcile(c.existing, "app", c.hosts); got != c.ok {
			t.Errorf("%s: MayReconcile = %v, want %v", c.name, got, c.ok)
		}
	}
}

// fakeKeycloak is a minimal admin API with one pre-existing client.
type fakeKeycloak struct {
	mu       sync.Mutex
	existing map[string]interface{}
	puts     []map[string]interface{}
	posts    int
	created  map[string]interface{}
	// realm scopes (name → id) and attached scope PUTs ("client/scopeId")
	scopes   map[string]string
	attached []string
	detached []string // "client/kind/scopeId"
}

func (f *fakeKeycloak) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/realms/master/protocol/openid-connect/token":
		r.ParseForm()
		if r.Form.Get("password") != "pw" {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `{"access_token":"tok"}`)
		return
	case r.Header.Get("Authorization") != "Bearer tok":
		w.WriteHeader(401)
		return
	case r.Method == "POST" && r.URL.Path == "/admin/realms/portcullis/clients":
		f.posts++
		if f.existing != nil {
			w.WriteHeader(409)
			return
		}
		var rep map[string]interface{}
		json.NewDecoder(r.Body).Decode(&rep)
		f.created = rep
		// Keycloak drops scope names the realm doesn't have.
		var kept []interface{}
		for _, sc := range rep["defaultClientScopes"].([]interface{}) {
			if (sc != "groups" && sc != EmailUnverifiedScope && sc != AttributesScope) || f.scopes[sc.(string)] != "" {
				kept = append(kept, sc)
			}
		}
		f.existing = map[string]interface{}{"id": "new-uuid", "clientId": rep["clientId"], "attributes": rep["attributes"], "defaultClientScopes": kept}
		f.existing["_new"] = true
		w.WriteHeader(201)
	case r.Method == "GET" && r.URL.Path == "/admin/realms/portcullis/clients":
		json.NewEncoder(w).Encode([]interface{}{f.existing})
	case r.Method == "GET" && r.URL.Path == "/admin/realms/portcullis/client-scopes":
		var out []map[string]string
		for n, id := range f.scopes {
			out = append(out, map[string]string{"name": n, "id": id})
		}
		json.NewEncoder(w).Encode(out)
	case r.Method == "DELETE" && strings.Contains(r.URL.Path, "-client-scopes/"):
		parts := strings.Split(r.URL.Path, "/")
		f.detached = append(f.detached, parts[5]+"/"+strings.TrimSuffix(parts[6], "-client-scopes")+"/"+parts[7])
		w.WriteHeader(204)
	case r.Method == "PUT" && strings.Contains(r.URL.Path, "/default-client-scopes/"):
		parts := strings.Split(r.URL.Path, "/")
		f.attached = append(f.attached, parts[5]+"/"+parts[7])
		w.WriteHeader(204)
	case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/admin/realms/portcullis/clients/"):
		var rep map[string]interface{}
		json.NewDecoder(r.Body).Decode(&rep)
		f.puts = append(f.puts, rep)
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}

func TestRegisterClient(t *testing.T) {
	fk := &fakeKeycloak{}
	srv := httptest.NewServer(fk)
	defer srv.Close()
	c := New(srv.URL, "admin", "pw")
	ctx := context.Background()
	spec := ClientSpec{ClientID: "app", Secret: "s3cret", RedirectURIs: []string{"https://app.example.org/cb"}, TemplateID: "app", ACR: "hwk", AllowedHosts: []string{"app.example.org"}}

	if err := c.RegisterClient(ctx, spec); err != nil || fk.posts != 1 {
		t.Fatalf("create: %v (posts %d)", err, fk.posts)
	}
	if got := fmt.Sprint(fk.created["defaultClientScopes"]); got != "[openid profile email acr groups portcullis-attributes]" {
		t.Errorf("create scopes = %s", got)
	}
	// The realm has no groups scope yet: create succeeds, nothing attached.
	if len(fk.attached) != 0 {
		t.Errorf("attached = %v", fk.attached)
	}

	// Exists and owned by another template: left untouched.
	fk.existing = map[string]interface{}{"id": "u1", "clientId": "app", "attributes": map[string]interface{}{OwnerAttr: "other"}}
	var ce *ConflictError
	if err := c.RegisterClient(ctx, spec); !errors.As(err, &ce) || ce.Owner != "other" || len(fk.puts) != 0 {
		t.Errorf("foreign client: err %v, puts %v", err, fk.puts)
	}
	if err := c.UpdateClientACR(ctx, spec); !errors.As(err, &ce) || len(fk.puts) != 0 {
		t.Errorf("UpdateClientACR on foreign client: %v", err)
	}
	fk.existing = map[string]interface{}{"id": "u0", "clientId": "app", "redirectUris": []interface{}{"https://evil.example.com/cb"}}
	if err := c.RegisterClient(ctx, spec); !errors.As(err, &ce) || ce.Owner != "" || !strings.Contains(err.Error(), "not tagged") || len(fk.puts) != 0 {
		t.Errorf("untagged foreign client: %v", err)
	}

	// Exists and owned: secret, URIs, acr reconciled; tag kept; missing
	// default scopes attached through the sub-resource (a client PUT
	// ignores defaultClientScopes).
	fk.scopes = map[string]string{"acr": "s-acr", "groups": "s-groups", "profile": "s-profile"}
	fk.existing = map[string]interface{}{"id": "u1", "clientId": "app", "attributes": map[string]interface{}{OwnerAttr: "app"}, "defaultClientScopes": []interface{}{"openid", "acr"}}
	if err := c.RegisterClient(ctx, spec); err != nil || len(fk.puts) != 1 {
		t.Fatalf("reconcile: %v %v", err, fk.puts)
	}
	p := fk.puts[0]
	attrs := p["attributes"].(map[string]interface{})
	if p["secret"] != "s3cret" || attrs["default.acr.values"] != "hwk" || attrs[OwnerAttr] != "app" {
		t.Errorf("put = %v", p)
	}
	if fmt.Sprint(fk.attached) != "[u1/s-groups]" {
		t.Errorf("attached = %v, want only the missing groups scope", fk.attached)
	}
	fk.attached = nil
	if err := c.UpdateClientACR(ctx, spec); err != nil || fmt.Sprint(fk.attached) != "[u1/s-groups]" {
		t.Errorf("UpdateClientACR: %v, attached %v", err, fk.attached)
	}

	// Fresh create with the scope present in the realm: nothing to attach.
	fk.existing, fk.attached = nil, nil
	if err := c.RegisterClient(ctx, spec); err != nil || len(fk.attached) != 0 {
		t.Errorf("create with groups scope: %v, attached %v", err, fk.attached)
	}

	if err := c.RegisterClient(ctx, ClientSpec{ClientID: "admin-cli", TemplateID: "app"}); !errors.As(err, &ce) {
		t.Errorf("protected client: %v", err)
	}
	bad := New(srv.URL, "admin", "wrong")
	if err := bad.RegisterClient(ctx, spec); err == nil {
		t.Error("bad credentials accepted")
	}
	if err := c.DeleteUserByID(ctx, "../../x"); err == nil {
		t.Error("invalid user id accepted")
	}
}

func TestRegisterClientEmailUnverified(t *testing.T) {
	fk := &fakeKeycloak{}
	srv := httptest.NewServer(fk)
	defer srv.Close()
	c := New(srv.URL, "admin", "pw")
	ctx := context.Background()
	spec := ClientSpec{ClientID: "vw", Secret: "s", RedirectURIs: []string{"https://vw.example.org/cb"}, TemplateID: "vw", ACR: "pwd",
		AllowedHosts: []string{"vw.example.org"}, OmitEmailVerified: true}
	all := map[string]string{"acr": "s-acr", "groups": "s-groups", "email": "s-email", EmailUnverifiedScope: "s-eu"}

	// Create: email-unverified instead of email, nothing to fix afterwards.
	fk.scopes = all
	if err := c.RegisterClient(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(fk.created["defaultClientScopes"]); got != "[openid profile email-unverified acr groups portcullis-attributes]" {
		t.Errorf("create scopes = %s", got)
	}
	if len(fk.attached)+len(fk.detached) != 0 {
		t.Errorf("create: attached %v, detached %v", fk.attached, fk.detached)
	}

	// Reconcile an owned client that still has email (default and
	// optional): attach email-unverified first, then detach email.
	fk.existing = map[string]interface{}{"id": "u1", "clientId": "vw", "attributes": map[string]interface{}{OwnerAttr: "vw"},
		"defaultClientScopes": []interface{}{"profile", "email", "acr", "groups"}, "optionalClientScopes": []interface{}{"email"}}
	if err := c.RegisterClient(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(fk.attached) != "[u1/s-eu]" || len(fk.detached) != 2 || !strings.Contains(fmt.Sprint(fk.detached), "u1/default/s-email") || !strings.Contains(fmt.Sprint(fk.detached), "u1/optional/s-email") {
		t.Errorf("reconcile: attached %v, detached %v", fk.attached, fk.detached)
	}

	// The ACR push reconciles scopes too.
	fk.attached, fk.detached = nil, nil
	if err := c.UpdateClientACR(ctx, spec); err != nil || fmt.Sprint(fk.attached) != "[u1/s-eu]" || len(fk.detached) != 2 {
		t.Errorf("UpdateClientACR: %v, attached %v, detached %v", err, fk.attached, fk.detached)
	}

	// Already right: no scope calls.
	fk.existing["defaultClientScopes"] = []interface{}{"profile", EmailUnverifiedScope, "acr", "groups"}
	delete(fk.existing, "optionalClientScopes")
	fk.attached, fk.detached = nil, nil
	if err := c.RegisterClient(ctx, spec); err != nil || len(fk.attached)+len(fk.detached) != 0 {
		t.Errorf("settled: %v, attached %v, detached %v", err, fk.attached, fk.detached)
	}

	// Back to the default: email returns, email-unverified goes.
	def := spec
	def.OmitEmailVerified = false
	if err := c.RegisterClient(ctx, def); err != nil || fmt.Sprint(fk.attached) != "[u1/s-email]" || fmt.Sprint(fk.detached) != "[u1/default/s-eu]" {
		t.Errorf("default again: %v, attached %v, detached %v", err, fk.attached, fk.detached)
	}

	// Realm without email-unverified (core not configured): error, and the
	// client keeps its email scope.
	fk.scopes = map[string]string{"acr": "s-acr", "groups": "s-groups", "email": "s-email"}
	fk.existing["defaultClientScopes"] = []interface{}{"profile", "email", "acr", "groups"}
	fk.attached, fk.detached = nil, nil
	if err := c.RegisterClient(ctx, spec); err == nil || !strings.Contains(err.Error(), "keycloak configure") || len(fk.detached) != 0 {
		t.Errorf("missing scope: %v, detached %v", err, fk.detached)
	}

	// Foreign client: never touched, whatever the email setting.
	fk.existing = map[string]interface{}{"id": "u2", "clientId": "vw", "attributes": map[string]interface{}{OwnerAttr: "other"},
		"defaultClientScopes": []interface{}{"email"}}
	fk.attached, fk.detached, fk.puts = nil, nil, nil
	var ce *ConflictError
	if err := c.RegisterClient(ctx, spec); !errors.As(err, &ce) || len(fk.attached)+len(fk.detached)+len(fk.puts) != 0 {
		t.Errorf("foreign client: %v, attached %v, detached %v", err, fk.attached, fk.detached)
	}
	if err := c.UpdateClientACR(ctx, spec); !errors.As(err, &ce) || len(fk.attached)+len(fk.detached) != 0 {
		t.Errorf("UpdateClientACR foreign: %v", err)
	}
}
