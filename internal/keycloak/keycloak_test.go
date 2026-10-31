package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMayReconcile(t *testing.T) {
	want := []string{"https://app.example.org/cb"}
	cases := []struct {
		name     string
		existing map[string]interface{}
		id       string
		uris     []string
		ok       bool
	}{
		{"owned", map[string]interface{}{"clientId": "app", "attributes": map[string]interface{}{OwnerAttr: "app"}}, "app", nil, true},
		{"owned by other template", map[string]interface{}{"clientId": "app", "attributes": map[string]interface{}{OwnerAttr: "evil"}}, "app", want, false},
		{"protected", map[string]interface{}{"clientId": "portcullis-forward-auth", "attributes": map[string]interface{}{OwnerAttr: "app"}}, "app", want, false},
		{"untagged same host", map[string]interface{}{"clientId": "app", "redirectUris": []interface{}{"https://APP.example.org/other"}}, "app", want, true},
		{"untagged foreign host", map[string]interface{}{"clientId": "app", "redirectUris": []interface{}{"https://app.example.org/cb", "https://evil.example.com/cb"}}, "app", want, false},
		{"untagged no wanted uris", map[string]interface{}{"clientId": "app"}, "app", nil, false},
	}
	for _, c := range cases {
		if got := MayReconcile(c.existing, c.id, c.uris); got != c.ok {
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
		w.WriteHeader(201)
	case r.Method == "GET" && r.URL.Path == "/admin/realms/portcullis/clients":
		json.NewEncoder(w).Encode([]interface{}{f.existing})
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
	spec := ClientSpec{ClientID: "app", Secret: "s3cret", RedirectURIs: []string{"https://app.example.org/cb"}, TemplateID: "app", ACR: "hwk"}

	if err := c.RegisterClient(ctx, spec); err != nil || fk.posts != 1 {
		t.Fatalf("create: %v (posts %d)", err, fk.posts)
	}

	// Exists and owned by another template: left untouched.
	fk.existing = map[string]interface{}{"id": "u1", "clientId": "app", "attributes": map[string]interface{}{OwnerAttr: "other"}}
	if err := c.RegisterClient(ctx, spec); err != nil || len(fk.puts) != 0 {
		t.Errorf("foreign client modified: %v %v", err, fk.puts)
	}
	if err := c.UpdateClientACR(ctx, spec); err == nil || len(fk.puts) != 0 {
		t.Errorf("UpdateClientACR on foreign client: %v", err)
	}

	// Exists and owned: secret, URIs, acr reconciled; tag kept.
	fk.existing = map[string]interface{}{"id": "u1", "clientId": "app", "attributes": map[string]interface{}{OwnerAttr: "app"}, "defaultClientScopes": []interface{}{"openid"}}
	if err := c.RegisterClient(ctx, spec); err != nil || len(fk.puts) != 1 {
		t.Fatalf("reconcile: %v %v", err, fk.puts)
	}
	p := fk.puts[0]
	attrs := p["attributes"].(map[string]interface{})
	if p["secret"] != "s3cret" || attrs["default.acr.values"] != "hwk" || attrs[OwnerAttr] != "app" ||
		fmt.Sprint(p["defaultClientScopes"]) != "[openid acr]" {
		t.Errorf("put = %v", p)
	}

	if err := c.RegisterClient(ctx, ClientSpec{ClientID: "admin-cli", TemplateID: "app"}); err == nil {
		t.Error("protected client accepted")
	}
	bad := New(srv.URL, "admin", "wrong")
	if err := bad.RegisterClient(ctx, spec); err == nil {
		t.Error("bad credentials accepted")
	}
	if err := c.SetRequiredActions(ctx, "../../x", nil); err == nil {
		t.Error("invalid user id accepted")
	}
}
