package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/signin"
)

// TestSignInRoutesAdminOnly: non-admin 403 on every route; people listener 404.
func TestSignInRoutesAdminOnly(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	routes := []struct {
		method, path string
		body         string
	}{
		{"GET", "/api/signin", ""},
		{"PUT", "/api/signin/methods/password", `{"on":true}`},
		{"POST", "/api/signin/templates", `{"id":"test","name":"Test","rule":{"op":"any","items":["security_key"]}}`},
		{"PUT", "/api/signin/templates/standard", `{"name":"Standard","rule":{"op":"any","items":["security_key"]}}`},
		{"PUT", "/api/signin/templates/standard/enabled", `{"on":true}`},
		{"DELETE", "/api/signin/templates/test", ""},
		{"POST", "/api/signin/templates/preview", `{"name":"Test","rule":{"op":"any","items":["security_key"]}}`},
		{"POST", "/api/signin/impact", `{"default":"standard"}`},
		{"PUT", "/api/signin/default", `{"template":"standard"}`},
		{"PUT", "/api/signin/core/hub", `{"template":"standard"}`},
		{"PUT", "/api/signin/add-stronger", `{"on":true}`},
		{"GET", "/api/instances/grafana/signin", ""},
	}

	for _, tc := range routes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			// Non-admin: 403
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte(tc.body)))
			req.Header.Set("X-Forwarded-User", "alice") // not an admin
			rec := httptest.NewRecorder()
			e.s.hubMux().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s as non-admin: got %d, want 403", tc.method, tc.path, rec.Code)
			}

			// People listener: 404
			req = httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte(tc.body)))
			req.Header.Set("X-Forwarded-User", "admin")
			rec = httptest.NewRecorder()
			e.s.peopleMux().ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s on people listener: got %d, want 404", tc.method, tc.path, rec.Code)
			}
		})
	}
}

// TestSignInRoutesStatuses: PUT methods/browser_cert {on:true} 409; unknown 404; preview 200 no write.
func TestSignInRoutesStatuses(t *testing.T) {
	e := newToolEnv(t, nil, nil)

	// browser_cert on → 409
	req := httptest.NewRequest("PUT", "/api/signin/methods/browser_cert", bytes.NewReader([]byte(`{"on":true}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec := httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("PUT methods/browser_cert on=true: got %d, want 409", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("browser certificates aren't available yet")) {
		t.Errorf("browser_cert on: got %q, want 'browser certificates aren't available yet'", rec.Body.String())
	}

	// unknown method → 404
	req = httptest.NewRequest("PUT", "/api/signin/methods/unknown_method", bytes.NewReader([]byte(`{"on":true}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec = httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("PUT methods/unknown: got %d, want 404", rec.Code)
	}

	// preview 200, no write
	before := readSignInView(t, e)
	req = httptest.NewRequest("POST", "/api/signin/templates/preview", bytes.NewReader([]byte(`{"name":"Test","rule":{"op":"any","items":["security_key"]}}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec = httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("POST preview: got %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	after := readSignInView(t, e)
	if !signInViewEqual(before, after) {
		t.Error("preview changed the view")
	}
}

// readSignInView reads the sign-in view via the HTTP API.
func readSignInView(t *testing.T, e *toolEnv) interface{} {
	req := httptest.NewRequest("GET", "/api/signin", nil)
	req.Header.Set("X-Forwarded-User", "admin")
	rec := httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/signin: got %d", rec.Code)
	}
	var v interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return v
}

// signInViewEqual checks if two SignInView values are equal (deep comparison).
func signInViewEqual(a, b interface{}) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return bytes.Equal(aj, bj)
}

// signInInv is a fake sign-in inventory wired into an env's Hub: every
// directory user has every method (passkeys, password, a YubiKey
// certificate) but those listed in only; fail makes Keycloak unreadable.
type signInInv struct {
	e    *toolEnv
	mu   sync.Mutex
	only map[string][]signin.Method
	fail bool
}

// wireSignInInventory wires a fake inventory into e (nobody restricted).
func wireSignInInventory(e *toolEnv) *signInInv {
	inv := &signInInv{e: e, only: map[string][]signin.Method{}}
	inv.wire()
	return inv
}

// set restricts user to methods (none: every method again) and drops
// the cached inventory.
func (inv *signInInv) set(user string, methods ...signin.Method) {
	inv.mu.Lock()
	if len(methods) == 0 {
		delete(inv.only, user)
	} else {
		inv.only[user] = methods
	}
	inv.mu.Unlock()
	inv.wire()
}

// setFail makes Keycloak unreadable (or readable again).
func (inv *signInInv) setFail(fail bool) {
	inv.mu.Lock()
	inv.fail = fail
	inv.mu.Unlock()
	inv.wire()
}

func (inv *signInInv) methodsOf(u string) []signin.Method {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if ms, ok := inv.only[u]; ok {
		return ms
	}
	return slices.Clone(signin.Methods)
}

func (inv *signInInv) wire() {
	inv.e.s.Hub.SetSignInSources(hub.SignInSources{
		Passkeys: func(context.Context) (map[string][]keycloak.PasskeyCredential, error) {
			inv.mu.Lock()
			fail := inv.fail
			inv.mu.Unlock()
			if fail {
				return nil, errors.New("keycloak down")
			}
			out := map[string][]keycloak.PasskeyCredential{}
			for _, u := range inv.e.ll.UserIDs() {
				list := []keycloak.PasskeyCredential{}
				for _, m := range inv.methodsOf(u) {
					if m != signin.YubiKeyCert {
						list = append(list, keycloak.PasskeyCredential{ID: u + "-" + string(m), Type: string(m)})
					}
				}
				out[u] = list
			}
			return out, nil
		},
		Certificates: func(context.Context) ([]invite.CertRecord, error) {
			var out []invite.CertRecord
			for _, u := range inv.e.ll.UserIDs() {
				if slices.Contains(inv.methodsOf(u), signin.YubiKeyCert) {
					out = append(out, invite.CertRecord{User: u, Serial: u, NotAfter: time.Now().Add(24 * time.Hour)})
				}
			}
			return out, nil
		},
	})
}

// TestSignInToolClasses (§15.10, item-9 ruling): each per-call sign-in
// tool's class on exact cases — W only when the new rule implies the old
// one (switched-on and all available methods), nobody is newly blocked
// and nobody is unknown; switching a method on is always D.
func TestSignInToolClasses(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	inv := wireSignInInventory(e)
	ctx := context.Background()
	tools := map[string]Tool{}
	for _, tl := range e.s.tools(ScopeAdmin) {
		tools[tl.Name] = tl
	}
	root := directory.Human("root")
	class := func(tool string, args any) ToolClass {
		t.Helper()
		b, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		return tools[tool].ClassFor(ctx, b)
	}
	check := func(what string, got, want ToolClass) {
		t.Helper()
		if got != want {
			t.Errorf("%s: class %s, want %s", what, got, want)
		}
	}
	for _, n := range []string{"set_sign_in_method", "save_sign_in_template", "set_default_template", "set_core_template", "set_sign_in_template", "set_add_stronger"} {
		if tools[n].Class != ClassDestructive || tools[n].ClassFor == nil || tools[n].Precheck == nil && n != "set_add_stronger" {
			t.Errorf("tool %s: class %s, ClassFor %v, Precheck %v", n, tools[n].Class, tools[n].ClassFor != nil, tools[n].Precheck != nil)
		}
	}

	// The default: standard → strong is narrower: W while nobody is newly
	// blocked; D once bob (a synced passkey only) is.
	check("default standard→strong", class("set_default_template", map[string]any{"template": "strong"}), ClassWrite)
	inv.set("bob", signin.PasskeySynced)
	check("default standard→strong, bob newly blocked", class("set_default_template", map[string]any{"template": "strong"}), ClassDestructive)
	cons := tools["set_default_template"].Consequences(ctx, json.RawMessage(`{"template":"strong"}`))
	if j := strings.Join(cons, "\n"); !strings.Contains(j, `"bob"`) || !strings.Contains(j, `"Portal"`) || !strings.Contains(j, `"Strong"`) {
		t.Errorf("set_default_template consequences = %q, want bob, the core pages and the template", cons)
	}
	inv.set("bob")
	// People unknown (Keycloak down): D.
	inv.setFail(true)
	check("default standard→strong, people unknown", class("set_default_template", map[string]any{"template": "strong"}), ClassDestructive)
	inv.setFail(false)
	// The default: strong → standard is weaker: D whoever has what.
	if _, err := e.s.Hub.SetDefaultTemplate(ctx, "strong", root); err != nil {
		t.Fatal(err)
	}
	check("default strong→standard", class("set_default_template", map[string]any{"template": "standard"}), ClassDestructive)
	check("default strong→strong", class("set_default_template", map[string]any{"template": "strong"}), ClassWrite)
	if _, err := e.s.Hub.SetDefaultTemplate(ctx, "standard", root); err != nil {
		t.Fatal(err)
	}

	// Methods: on always D, whatever it widens; off W while nobody is
	// newly blocked, D when bob (a synced passkey only) is.
	if _, err := e.s.Hub.SetMethod(ctx, signin.Password, false, root); err != nil {
		t.Fatal(err)
	}
	check("method password on (nothing uses it)", class("set_sign_in_method", map[string]any{"method": "password", "on": true}), ClassDestructive)
	check("method passkey_synced off", class("set_sign_in_method", map[string]any{"method": "passkey_synced", "on": false}), ClassWrite)
	inv.set("bob", signin.PasskeySynced)
	check("method passkey_synced off, bob newly blocked", class("set_sign_in_method", map[string]any{"method": "passkey_synced", "on": false}), ClassDestructive)
	inv.setFail(true)
	inv.set("bob")
	check("method passkey_synced off, people unknown", class("set_sign_in_method", map[string]any{"method": "passkey_synced", "on": false}), ClassDestructive)
	inv.setFail(false)

	// Core pages: portal "" = the default (standard); → strong W, back D
	// (hub and people start on strong).
	check("core portal \"\" (unchanged)", class("set_core_template", map[string]any{"key": "portal", "template": ""}), ClassWrite)
	check("core portal → strong", class("set_core_template", map[string]any{"key": "portal", "template": "strong"}), ClassWrite)
	check("core hub strong → \"\" (standard)", class("set_core_template", map[string]any{"key": "hub", "template": ""}), ClassDestructive)
	if _, err := e.s.Hub.SetCoreTemplate(ctx, "portal", "strong", root); err != nil {
		t.Fatal(err)
	}
	check("core portal strong → \"\" (standard)", class("set_core_template", map[string]any{"key": "portal", "template": ""}), ClassDestructive)

	// Template saves: a create is W; an update W only when narrower and
	// nobody is newly blocked; a dormant alternative (password is off) D.
	check("save create", class("save_sign_in_template", map[string]any{"id": "mine", "name": "Mine", "rule": map[string]any{"op": "any", "items": []string{"password"}}, "create": true}), ClassWrite)
	narrower := map[string]any{"id": "standard", "name": "Standard", "rule": map[string]any{"op": "any", "items": []string{"security_key"}}}
	check("save standard narrower", class("save_sign_in_template", narrower), ClassWrite)
	// standard is the default of the consoles (lldap_admin: root).
	inv.set("root", signin.PasskeySynced)
	check("save standard narrower, root newly blocked", class("save_sign_in_template", narrower), ClassDestructive)
	inv.set("root")
	check("save standard + dormant password", class("save_sign_in_template", map[string]any{"id": "standard", "name": "Standard",
		"rule": map[string]any{"op": "any", "items": []string{"family:passkey", "family:certificate", "password"}}}), ClassDestructive)
	check("save standard create:false unknown id", class("save_sign_in_template", map[string]any{"id": "nope", "name": "Nope", "rule": map[string]any{"op": "any", "items": []string{"security_key"}}}), ClassDestructive)

	// An app's pick ("" = the default, standard): → strong W; enabled
	// with a member restricted to a synced passkey, D; back to "" D.
	check("notes pick → strong", class("set_sign_in_template", map[string]any{"id": "notes", "template": "strong"}), ClassWrite)
	check("notes pick \"\" (unchanged)", class("set_sign_in_template", map[string]any{"id": "notes", "template": ""}), ClassWrite)
	pick := "strong"
	if _, err := e.s.Hub.SaveSettings("notes", hub.SettingsUpdate{SignInTemplate: &pick}, root); err != nil {
		t.Fatal(err)
	}
	check("notes pick strong → \"\" (standard)", class("set_sign_in_template", map[string]any{"id": "notes", "template": ""}), ClassDestructive)
	check("unknown instance", class("set_sign_in_template", map[string]any{"id": "nope", "template": ""}), ClassDestructive)

	// add_stronger: on D, off W.
	check("add_stronger on", class("set_add_stronger", map[string]any{"on": true}), ClassDestructive)
	check("add_stronger off", class("set_add_stronger", map[string]any{"on": false}), ClassWrite)
}

// TestSignInPrecheck (§15.10 "Names before a confirmation"): unknown
// template ids, core keys, methods, instances and invalid rules are
// refused with the twin route's status before any confirmation.
func TestSignInPrecheck(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	ctx := context.Background()
	tools := map[string]Tool{}
	for _, tl := range e.s.tools(ScopeAdmin) {
		tools[tl.Name] = tl
	}
	for _, c := range []struct {
		tool, args string
		status     int
	}{
		{"set_sign_in_method", `{"method":"nope","on":true}`, 404},
		{"set_sign_in_method", `{"method":"browser_cert","on":true}`, 409},
		{"set_default_template", `{"template":"nope"}`, 404},
		{"set_default_template", `{"template":"basic"}`, 409},
		{"set_core_template", `{"key":"nope","template":""}`, 400},
		{"set_core_template", `{"key":"hub","template":"nope"}`, 404},
		{"save_sign_in_template", `{"id":"nope","name":"Nope","rule":{"op":"any","items":["security_key"]}}`, 404},
		{"save_sign_in_template", `{"id":"standard","name":"Standard","rule":{"op":"any","items":["security_key"]},"create":true}`, 409},
		{"save_sign_in_template", `{"id":"standard","name":"Standard","rule":{"op":"any","items":[]}}`, 400},
		{"save_sign_in_template", `{"id":"standard","name":"Standard","rule":{"op":"some","items":["security_key"]}}`, 400},
		{"set_sign_in_template", `{"id":"nope","template":""}`, 404},
		{"set_sign_in_template", `{"id":"notes","template":"nope"}`, 404},
	} {
		err := tools[c.tool].Precheck(ctx, nil, json.RawMessage(c.args))
		var se *hub.StatusError
		if !errors.As(err, &se) || se.Status != c.status {
			t.Errorf("%s %s: precheck %v, want %d", c.tool, c.args, err, c.status)
		}
	}
	for _, c := range []struct{ tool, args string }{
		{"set_sign_in_method", `{"method":"password","on":false}`},
		{"set_default_template", `{"template":"strong"}`},
		{"set_core_template", `{"key":"hub","template":""}`},
		{"save_sign_in_template", `{"id":"standard","name":"Standard","rule":{"op":"any","items":["security_key"]}}`},
		{"set_sign_in_template", `{"id":"notes","template":"strong"}`},
	} {
		if err := tools[c.tool].Precheck(ctx, nil, json.RawMessage(c.args)); err != nil {
			t.Errorf("%s %s: precheck %v, want none", c.tool, c.args, err)
		}
	}
}

// TestSignInImpactRoute: POST /api/signin/impact answers who a draft
// newly blocks (the editor's and the drop-downs' confirm step), with the
// people unknown when Keycloak can't be read; refusals are the twin
// route's; nothing is written.
func TestSignInImpactRoute(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	inv := wireSignInInventory(e)
	call := func(body string) (int, hub.SignInImpact, string) {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/signin/impact", strings.NewReader(body))
		req.Header.Set("X-Forwarded-User", "admin")
		rec := httptest.NewRecorder()
		e.s.hubMux().ServeHTTP(rec, req)
		var imp hub.SignInImpact
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &imp); err != nil {
				t.Fatal(err)
			}
			if imp.Affected == nil || !strings.Contains(rec.Body.String(), `"affected":`) || !strings.Contains(rec.Body.String(), `"unknown":`) {
				t.Errorf("%s: body %s lacks affected / unknown", body, rec.Body)
			}
		}
		return rec.Code, imp, rec.Body.String()
	}
	blockedIn := func(imp hub.SignInImpact, user string) []string {
		var where []string
		for _, a := range imp.Affected {
			for _, b := range a.Blocked {
				if b.User == user {
					where = append(where, a.Name)
				}
			}
		}
		return where
	}
	before := readSignInView(t, e)

	// Nobody restricted: the default standard → strong blocks nobody.
	if code, imp, body := call(`{"default":"strong"}`); code != 200 || len(imp.Affected) != 0 || imp.Unknown != "" {
		t.Errorf("default → strong, nobody restricted: %d %s", code, body)
	}
	// bob has a synced passkey only: strong (security key) blocks him on
	// the pages that inherit the default; so does switching it off.
	inv.set("bob", signin.PasskeySynced)
	if code, imp, body := call(`{"default":"strong"}`); code != 200 || !slices.Contains(blockedIn(imp, "bob"), "Portal") {
		t.Errorf("default → strong, bob synced only: %d %s", code, body)
	}
	if code, imp, body := call(`{"method":"passkey_synced","on":false}`); code != 200 || len(blockedIn(imp, "bob")) == 0 {
		t.Errorf("passkey_synced off, bob synced only: %d %s", code, body)
	}
	if code, imp, body := call(`{"core_page":"portal","core":"strong"}`); code != 200 || !slices.Equal(blockedIn(imp, "bob"), []string{"Portal"}) {
		t.Errorf("portal → strong: %d %s", code, body)
	}
	// Keycloak down: unknown, nobody listed.
	inv.setFail(true)
	if code, imp, body := call(`{"default":"strong"}`); code != 200 || imp.Unknown == "" || len(imp.Affected) != 0 {
		t.Errorf("people unknown: %d %s", code, body)
	}
	inv.setFail(false)
	inv.set("bob")

	// The twin routes' refusals.
	for body, want := range map[string]int{
		`{}`:                                   http.StatusBadRequest,
		`{"method":"nope","on":false}`:         http.StatusNotFound,
		`{"method":"browser_cert","on":true}`:  http.StatusConflict,
		`{"default":"nope"}`:                   http.StatusNotFound,
		`{"core_page":"nope","core":"strong"}`: http.StatusBadRequest,
		`{"instance":"nope","pick":"strong"}`:  http.StatusNotFound,
		`{"default":"strong","surprise":true}`: http.StatusBadRequest,
	} {
		if code, _, b := call(body); code != want {
			t.Errorf("%s: %d %s, want %d", body, code, b, want)
		}
	}
	if !signInViewEqual(before, readSignInView(t, e)) {
		t.Error("the impact route changed the sign-in state")
	}
}
