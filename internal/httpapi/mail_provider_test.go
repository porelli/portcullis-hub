package httpapi

import (
	"strings"
	"testing"
)

// TestNoMailWiringTool: no MCP tool wires, switches or unwires a mail
// provider (contract §19.9: never, through any scope); mail_status is the
// only mail tool.
func TestNoMailWiringTool(t *testing.T) {
	e, _ := mailEnv(t)
	e.s.mcp.mu.Lock()
	defer e.s.mcp.mu.Unlock()
	for scope, ts := range e.s.mcp.tools {
		for _, m := range ts {
			n := m.Name
			if strings.Contains(n, "mail") && n != "mail_status" {
				t.Errorf("scope %s: mail tool %s", scope, n)
			}
			for _, bad := range []string{"wire", "provider_switch", "switch_mail", "unwire"} {
				if strings.Contains(n, bad) {
					t.Errorf("scope %s: tool %s", scope, n)
				}
			}
		}
	}
}

// TestMailProviderRoutesAdminOnly: the Mail tab's routes answer
// administrators only; an instance without a mail: block is 404.
func TestMailProviderRoutesAdminOnly(t *testing.T) {
	e, _ := mailEnv(t)
	if r, _ := doAs(t, e.hub, "bob", "GET", "/api/instances/grafana/mail-provider", ""); r.StatusCode != 403 {
		t.Fatalf("bob: %d", r.StatusCode)
	}
	if r, b := doAs(t, e.hub, "root", "GET", "/api/instances/grafana/mail-provider", ""); r.StatusCode != 404 {
		t.Fatalf("root on grafana: %d %s", r.StatusCode, b)
	}
	if r, b := doAs(t, e.hub, "root", "PUT", "/api/instances/grafana/mail-provider", `{"wired": true, "confirm": "grafana", "extra": 1}`); r.StatusCode != 400 {
		t.Fatalf("unknown field: %d %s", r.StatusCode, b)
	}
	if r, b := doAs(t, e.hub, "root", "PUT", "/api/instances/grafana/mail-provider", `{"wired": true, "confirm": "grafana"}`); r.StatusCode != 403 {
		t.Fatalf("no proof: %d %s", r.StatusCode, b)
	}
}
