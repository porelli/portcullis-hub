package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
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

// TestMCPHasNoMailWiring (T15): the name the plan gives the no-wiring
// rule; TestNoMailWiringTool is its body.
func TestMCPHasNoMailWiring(t *testing.T) { TestNoMailWiringTool(t) }

// TestMCPMailStatusProvider (T15): mail_status (and its twin route)
// carries the wired provider: instance, template, mode; never a secret.
func TestMCPMailStatusProvider(t *testing.T) {
	e, _ := mailEnv(t)
	e.s.registerMCPTools()
	var tool *Tool
	for _, tl := range e.s.tools(ScopeAdmin) {
		if tl.Name == "mail_status" {
			tl := tl
			tool = &tl
		}
	}
	if tool == nil {
		t.Fatal("no mail_status")
	}
	out, err := tool.Run(context.Background(), nil, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	var v struct {
		Provider *struct {
			Instance, Template, Mode, Version string
		} `json:"provider"`
	}
	if err := json.Unmarshal(b, &v); err != nil || v.Provider == nil || v.Provider.Instance != "mailsrv" || v.Provider.Mode != "normal" || v.Provider.Version == "" {
		t.Fatalf("%s %v", b, err)
	}
	if strings.Contains(string(b), "secret") {
		t.Fatalf("a secret in %s", b)
	}
}

// mailErrStatus is err's HTTP status (0: none).
func mailErrStatus(err error) int {
	var se *hub.StatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// TestNoAIExecIntoMailProvider (Ruling R-L23): an AI or MCP actor never
// execs into the wired provider's containers: 403, audited refused; a
// person at the browser still can (the route's own rules).
func TestNoAIExecIntoMailProvider(t *testing.T) {
	e, _ := mailEnv(t)
	ai := directory.Actor{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude-code"}
	before := len(readAudit(t, e.audit))
	if _, err := e.s.execInstance(context.Background(), ai, "mailsrv", "stalwart", "cat /run/secrets/x"); mailErrStatus(err) != 403 {
		t.Fatalf("AI exec: %v", err)
	}
	var found bool
	for _, a := range readAudit(t, e.audit)[before:] {
		if a.Action == "instance.exec" && a.Target == "mailsrv" && a.Result != "ok" {
			found = true
		}
	}
	if !found {
		t.Fatal("the refusal isn't audited")
	}
	if _, err := e.s.execInstance(context.Background(), directory.Human("root"), "mailsrv", "stalwart", "true"); mailErrStatus(err) == 403 {
		t.Fatal("a person was refused as an AI")
	}

}

// TestMailProviderRefusalsAudited (final review L8): a non-admin's
// mail-provider write is audited as refused.
func TestMailProviderRefusalsAudited(t *testing.T) {
	e, _ := mailEnv(t)
	before := len(readAudit(t, e.audit))
	if r, _ := doAs(t, e.hub, "bob", "PUT", "/api/instances/mailsrv/mail-provider", `{"wired": true, "confirm": "mailsrv"}`); r.StatusCode != 403 {
		t.Fatalf("bob: %d", r.StatusCode)
	}
	for _, a := range readAudit(t, e.audit)[before:] {
		if a.Action == "mail.provider" && a.Actor == "bob" && a.Result != "ok" {
			return
		}
	}
	t.Fatal("the refusal isn't audited")
}
