package httpapi

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/signin"
)

// TestImpersonationTools (D46): impersonations R, stop_impersonation W
// and turn_off_impersonation W, admin scope, with their twins; no tool
// starts one or switches it on; a Stop and the switch off by an AI are
// audited via ai with the AI client.
func TestImpersonationTools(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	byName := map[string]Tool{}
	for _, tl := range e.s.tools(ScopeAdmin) {
		byName[tl.Name] = tl
	}
	for _, c := range []struct {
		name, twin, audit string
		class             ToolClass
	}{
		{"impersonations", "GET /api/impersonations", "", ClassRead},
		{"stop_impersonation", "POST /api/directory/users/{username}/impersonation/stop", "impersonation.end", ClassWrite},
		{"turn_off_impersonation", "PUT /api/signin/impersonation", "signin.impersonation", ClassWrite},
	} {
		tl, ok := byName[c.name]
		if !ok || tl.Class != c.class || tl.Twin != c.twin || tl.Audit != c.audit || tl.Scope != ScopeAdmin || tl.ClassFor != nil {
			t.Errorf("%s = %v %q %q %q", c.name, ok, tl.Class, tl.Twin, tl.Audit)
		}
	}
	for _, sc := range []string{ScopeAdmin, ScopePeople} {
		for _, tl := range e.s.tools(sc) {
			for _, r := range append([]string{tl.Twin}, tl.AlsoTwins...) {
				if r == "POST /api/directory/users/{username}/impersonation" || strings.HasPrefix(r, "GET /api/me/impersonation") ||
					strings.HasPrefix(r, "POST /api/me/impersonation") || r == "GET /impersonation/stop" {
					t.Errorf("%s tool %s mirrors %s (D46: none may)", sc, tl.Name, r)
				}
			}
			if strings.Contains(tl.Name, "imperson") && !slices.Contains([]string{"impersonations", "stop_impersonation", "turn_off_impersonation"}, tl.Name) {
				t.Errorf("%s tool %s: D46 lists no such tool", sc, tl.Name)
			}
		}
	}
	listed := e.list(t, "/mcp/admin", "root", "2025-11-25")
	for _, n := range []string{"impersonations", "stop_impersonation", "turn_off_impersonation"} {
		if !slices.Contains(listed, n) {
			t.Errorf("tools/list lacks %s", n)
		}
	}
	for _, n := range listed {
		if strings.Contains(n, "start") && strings.Contains(n, "imperson") {
			t.Errorf("tools/list has a start tool: %s", n)
		}
	}
	if slices.Contains(e.list(t, "/mcp/people", "root", "2025-11-25"), "stop_impersonation") {
		t.Error("people scope lists stop_impersonation")
	}
	// The no-argument tools take no argument; the input schema of
	// stop_impersonation is {user}.
	if txt, isErr, _ := e.tool(t, "turn_off_impersonation", map[string]any{"allowed": true}); !isErr {
		t.Errorf("turn_off_impersonation {allowed:true} = %s, want refused", txt)
	}
	if txt, isErr, _ := e.tool(t, "stop_impersonation", map[string]any{"username": "alice"}); !isErr {
		t.Errorf("stop_impersonation {username} = %s, want refused", txt)
	}

	// A running one: root signed in as alice.
	h := e.s.Hub
	if _, err := h.SetMethod(context.Background(), signin.SecurityKey, true, directory.Human("root")); err != nil && !strings.Contains(err.Error(), "already") {
		t.Logf("security_key on: %v", err)
	}
	h.SetFreshAuth(hub.ListenerHub, &fakeFreshAuth{})
	h.SetFreshAuthReadyForTest(true)
	h.SetImpersonationKeycloak(&fakeImpKC{disabled: map[string]bool{}, actions: map[string][]string{}})
	if _, err := h.StartImpersonation(context.Background(), hub.StartImpersonation{Target: "alice", Reason: "checking quota", AdminSID: "sid-root",
		Listener: hub.ListenerHub, Proof: freshauth.Proof{Code: "c", CodeVerifier: "v", Nonce: "n"}}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	txt, isErr, _ := e.tool(t, "impersonations", map[string]any{})
	var v hub.ImpersonationsView
	if isErr || json.Unmarshal([]byte(txt), &v) != nil || len(v.Running) != 1 || v.Running[0].Person != "alice" || !v.Allowed {
		t.Fatalf("impersonations = %s %v", txt, isErr)
	}
	if txt, isErr, conf := e.tool(t, "stop_impersonation", map[string]any{"user": "alice"}); isErr || conf != "" || !strings.Contains(txt, `"stopped"`) {
		t.Errorf("stop_impersonation = %s %v %q", txt, isErr, conf)
	}
	if txt, isErr, _ := e.tool(t, "stop_impersonation", map[string]any{"user": "alice"}); !isErr || !strings.HasPrefix(txt, "404") {
		t.Errorf("second stop = %s %v", txt, isErr)
	}
	if txt, isErr, conf := e.tool(t, "turn_off_impersonation", map[string]any{}); isErr || conf != "" || !strings.Contains(txt, `"allowed":false`) {
		t.Errorf("turn_off_impersonation = %s %v %q", txt, isErr, conf)
	}
	if h.Impersonations().Allowed {
		t.Error("still allowed after turn_off_impersonation")
	}
	var end, sw []directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		switch {
		case a.Action == "impersonation.end" && a.Result == "ok":
			end = append(end, a)
		case a.Action == "signin.impersonation":
			sw = append(sw, a)
		}
	}
	if len(end) != 1 || end[0].Actor != "root" || end[0].Via != directory.ViaAI || end[0].Client == "" || end[0].Target != "alice" || !strings.Contains(end[0].Detail, " · stopped · ") {
		t.Errorf("end audit = %+v", end)
	}
	if len(sw) != 1 || sw[0].Via != directory.ViaAI || sw[0].Client == "" || sw[0].Detail != "off" || sw[0].Result != "ok" {
		t.Errorf("switch audit = %+v", sw)
	}
}
