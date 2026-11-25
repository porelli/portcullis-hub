package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// Verified emails and the AI (security review of Task 3): an email the AI
// sets — through an admin's or a delegate's update_person, even with a
// browser confirmation — is stored unverified, and no tool marks an email
// verified.

func toolEnvVerified(t *testing.T, e *toolEnv, user string) bool {
	t.Helper()
	_, b := doAs(t, e.hub, "root", "GET", "/api/directory", "")
	var ov struct {
		Users []struct {
			Username      string `json:"username"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		} `json:"users"`
	}
	if err := json.Unmarshal([]byte(b), &ov); err != nil {
		t.Fatal(err)
	}
	for _, u := range ov.Users {
		if u.Username == user {
			return u.EmailVerified
		}
	}
	t.Fatalf("%s not listed: %s", user, b)
	return false
}

func TestUpdatePersonThroughMCPNotVerified(t *testing.T) {
	e, _ := peopleToolEnv(t, directory.PermEditDetails)
	// A delegate's AI (people MCP).
	if txt, isErr := e.people(t, "dana", "update_person", map[string]any{"username": "erin", "email": "erin.ai@example.org"}); isErr {
		t.Fatalf("dana's update_person = %q", txt)
	}
	if toolEnvVerified(t, e, "erin") {
		t.Error("a delegate's AI verified erin's email")
	}
	// An admin's AI (admin MCP; a confirmation, if asked, is approved).
	if txt, isErr, _ := e.tool(t, "update_person", map[string]any{"username": "erin", "email": "erin.admin-ai@example.org"}); isErr {
		t.Fatalf("root's update_person = %q", txt)
	}
	if toolEnvVerified(t, e, "erin") {
		t.Error("an admin's AI verified erin's email")
	}
	// The same change in the browser does verify it (the rule holds).
	mustDo(t, e.hub, "root", "PUT", "/api/directory/users/erin", `{"email":"erin.browser@example.org"}`, 200)
	if !toolEnvVerified(t, e, "erin") {
		t.Fatal("an admin's browser change isn't verified")
	}
	// An AI change after it clears the verification.
	if txt, isErr, _ := e.tool(t, "update_person", map[string]any{"username": "erin", "email": "erin.again@example.org"}); isErr {
		t.Fatalf("root's update_person = %q", txt)
	}
	if toolEnvVerified(t, e, "erin") {
		t.Error("an AI change kept the verification")
	}
}

// TestNoMarkVerifiedTool: neither MCP lists a tool that verifies an email.
func TestNoMarkVerifiedTool(t *testing.T) {
	e, _ := peopleToolEnv(t, directory.PermEditDetails)
	for _, l := range [][]string{e.list(t, "/mcp/admin", "root", "2025-11-25"), e.list(t, "/mcp/people", "root", "2025-11-25"), e.list(t, "/mcp/people", "dana", "2025-11-25")} {
		for _, name := range l {
			if strings.Contains(name, "verif") || strings.Contains(name, "email") {
				t.Errorf("an MCP tool %q may verify an email", name)
			}
		}
	}
	for _, scope := range []string{ScopeAdmin, ScopePeople} {
		for _, tl := range e.s.tools(scope) {
			for _, r := range append([]string{tl.Twin}, tl.AlsoTwins...) {
				if strings.Contains(r, "/email/") {
					t.Errorf("tool %s mirrors %s", tl.Name, r)
				}
			}
		}
	}
}
