package httpapi

import (
	"testing"
)

// TestSignInMCPToolsExist tests that the sign-in MCP tools are registered.
func TestSignInMCPToolsExist(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	tools := e.s.tools(ScopeAdmin)

	expectedTools := []string{
		"get_sign_in",
		"set_sign_in_method",
		"save_sign_in_template",
		"set_sign_in_template_enabled",
		"delete_sign_in_template",
		"preview_sign_in_template",
		"set_default_template",
		"set_core_template",
		"set_add_stronger",
	}

	toolMap := make(map[string]bool)
	for _, tl := range tools {
		toolMap[tl.Name] = true
	}

	for _, name := range expectedTools {
		if !toolMap[name] {
			t.Errorf("expected tool %s not found", name)
		}
	}
}
