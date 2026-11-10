package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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

// TestSignInToolClasses tests the sign-in tool classes with ClassFor.
func TestSignInToolClasses(t *testing.T) {
	e := newToolEnv(t, nil, nil)

	// Find the tools and check they have ClassFor
	tools := e.s.tools(ScopeAdmin)
	toolMap := make(map[string]Tool)
	for _, tl := range tools {
		toolMap[tl.Name] = tl
	}

	// Check that per-call class tools have ClassFor
	perCallTools := []string{
		"set_sign_in_method",
		"save_sign_in_template",
		"set_default_template",
		"set_core_template",
		"set_add_stronger",
	}

	for _, name := range perCallTools {
		tl, ok := toolMap[name]
		if !ok {
			t.Errorf("tool %s not found", name)
			continue
		}
		if tl.Class != ClassDestructive {
			t.Errorf("tool %s: class %s, want D", name, tl.Class)
		}
		if tl.ClassFor == nil {
			t.Errorf("tool %s: ClassFor is nil, want a function", name)
		}
	}
}
