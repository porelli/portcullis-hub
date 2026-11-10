package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/signin"
)

// Security tests for sign-in class determination (coordinator finding on 0596db7).

// TestDormantPasswordTemplate tests that adding a dormant password alternative is D.
func TestDormantPasswordTemplate(t *testing.T) {
	e := newToolEnv(t, nil, nil)

	// Turn password off first
	req := httptest.NewRequest("PUT", "/api/signin/methods/password", bytes.NewReader([]byte(`{"on":false}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec := httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("turn password off: got %d, want 200", rec.Code)
	}

	// Get the current standard template
	view, err := e.s.Hub.SignInView(context.Background())
	if err != nil {
		t.Fatalf("SignInView: %v", err)
	}
	var standardRule signin.Node
	for _, tmpl := range view.Templates {
		if tmpl.ID == "standard" {
			standardRule = tmpl.Rule
			break
		}
	}

	// Create a new rule that adds password to standard (dormant alternative)
	newRule := signin.Node{
		Op: "any",
		Items: []signin.Node{
			standardRule,      // existing rule
			{Leaf: "password"}, // + password (dormant)
		},
	}

	// Check the class for updating standard with this rule
	ruleBytes, _ := json.Marshal(newRule)
	argsBytes, _ := json.Marshal(map[string]json.RawMessage{
		"id":   json.RawMessage(`"standard"`),
		"name": json.RawMessage(`"Standard"`),
		"rule": ruleBytes,
	})
	tools := e.s.tools(ScopeAdmin)
	toolMap := make(map[string]Tool)
	for _, tl := range tools {
		toolMap[tl.Name] = tl
	}
	tool := toolMap["save_sign_in_template"]
	cl := tool.ClassFor(context.Background(), argsBytes)

	// Should be D because adding password would widen when it's switched on later
	if cl != ClassDestructive {
		t.Errorf("dormant password template: got class %s, want D", cl)
	}
}

// TestPasswordSwitchOnWidening tests that switching password on is D when it widens a template.
func TestPasswordSwitchOnWidening(t *testing.T) {
	e := newToolEnv(t, nil, nil)

	// Turn password off
	req := httptest.NewRequest("PUT", "/api/signin/methods/password", bytes.NewReader([]byte(`{"on":false}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec := httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("turn password off: got %d", rec.Code)
	}

	// Create a template with password in it
	req = httptest.NewRequest("POST", "/api/signin/templates", bytes.NewReader([]byte(`{"id":"withpw","name":"With Password","rule":{"op":"any","items":["password","security_key"]}}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec = httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("create template: got %d, want 201; body: %s", rec.Code, rec.Body.String())
	}

	// Set it as default so it's "in use"
	req = httptest.NewRequest("PUT", "/api/signin/default", bytes.NewReader([]byte(`{"template":"withpw"}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec = httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("set default: got %d", rec.Code)
	}

	// Check class for switching password on
	argsBytes, _ := json.Marshal(map[string]any{"method": "password", "on": true})
	tools := e.s.tools(ScopeAdmin)
	toolMap := make(map[string]Tool)
	for _, tl := range tools {
		toolMap[tl.Name] = tl
	}
	tool := toolMap["set_sign_in_method"]
	cl := tool.ClassFor(context.Background(), argsBytes)

	// Should be D because it widens the in-use template
	if cl != ClassDestructive {
		t.Errorf("password switch-on with template in use: got class %s, want D", cl)
	}

	// Check that consequences name the template
	cons := tool.Consequences(context.Background(), argsBytes)
	if len(cons) == 0 {
		t.Error("password switch-on: no consequences")
	} else {
		found := false
		for _, c := range cons {
			if strings.Contains(c, "With Password") || strings.Contains(c, "withpw") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("password switch-on consequences don't name the template: %v", cons)
		}
	}
}

// TestPasswordSwitchOnNoWidening tests that switching password on is W when it doesn't widen anything.
func TestPasswordSwitchOnNoWidening(t *testing.T) {
	e := newToolEnv(t, nil, nil)

	// Turn password off
	req := httptest.NewRequest("PUT", "/api/signin/methods/password", bytes.NewReader([]byte(`{"on":false}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec := httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("turn password off: got %d", rec.Code)
	}

	// Don't create any template that uses password
	// The default is "standard" which doesn't use password

	// Check class for switching password on
	argsBytes, _ := json.Marshal(map[string]any{"method": "password", "on": true})
	tools := e.s.tools(ScopeAdmin)
	toolMap := make(map[string]Tool)
	for _, tl := range tools {
		toolMap[tl.Name] = tl
	}
	tool := toolMap["set_sign_in_method"]
	cl := tool.ClassFor(context.Background(), argsBytes)

	// Should be W because no in-use template needs it
	if cl != ClassWrite {
		t.Errorf("password switch-on with no widening: got class %s, want W", cl)
	}
}

// TestPasswordOnlyTemplate tests the fail-closed logic for switching a method on.
// The scenario: a template that uses a method as one alternative among many, the method is off,
// then turning it on widens the template (more ways to sign in).
// Note: The Hub prevents creating/using templates that can't be met, so the pure "nobody → somebody"
// scenario (template requiring ONLY an off method) can't be set up through the API. The fail-closed
// logic in the code is defensive programming for edge cases.
func TestPasswordOnlyTemplate(t *testing.T) {
	e := newToolEnv(t, nil, nil)

	// Turn password off
	req := httptest.NewRequest("PUT", "/api/signin/methods/password", bytes.NewReader([]byte(`{"on":false}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec := httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("turn password off: got %d", rec.Code)
	}

	// Create a template with password and security_key as alternatives
	req = httptest.NewRequest("POST", "/api/signin/templates", bytes.NewReader([]byte(`{"id":"mixed","name":"Mixed","rule":{"op":"any","items":["password","security_key"]}}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec = httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("create template: got %d, want 201; body: %s", rec.Code, rec.Body.String())
	}

	// Set it as default so it's in use
	req = httptest.NewRequest("PUT", "/api/signin/default", bytes.NewReader([]byte(`{"template":"mixed"}`)))
	req.Header.Set("X-Forwarded-User", "admin")
	rec = httptest.NewRecorder()
	e.s.hubMux().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("set default: got %d", rec.Code)
	}

	// Check class for switching password on
	argsBytes, _ := json.Marshal(map[string]any{"method": "password", "on": true})
	tools := e.s.tools(ScopeAdmin)
	toolMap := make(map[string]Tool)
	for _, tl := range tools {
		toolMap[tl.Name] = tl
	}
	tool := toolMap["set_sign_in_method"]
	cl := tool.ClassFor(context.Background(), argsBytes)

	// Should be D because switching on widens the template (adds an alternative)
	if cl != ClassDestructive {
		t.Errorf("password switch-on with mixed template: got class %s, want D", cl)
	}

	// Check that consequences name the template
	cons := tool.Consequences(context.Background(), argsBytes)
	if len(cons) == 0 {
		t.Error("password switch-on: no consequences")
	} else {
		found := false
		for _, c := range cons {
			if strings.Contains(c, "Mixed") || strings.Contains(c, "mixed") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("password switch-on consequences don't name the template: %v", cons)
		}
	}
}
