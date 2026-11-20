package httpapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/gatelogs"
	"github.com/portcullis/hub/internal/hub"
)

// TestAIViewsIncomplete (contract §20.10, D6): with the access log read
// from mcp-gate's replicas and one of them unreadable, every view says
// incomplete: GET /api/ai/activity and the ai_activity tool
// ("incomplete": true), the audit view with include=access (the
// X-Portcullis-Incomplete header; the items stay a list).
func TestAIViewsIncomplete(t *testing.T) {
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	line, _ := json.Marshal(map[string]any{"time": at.Format(time.RFC3339), "user": "alice", "client": mcpClient,
		"resource": aiappResource, "instance": "aiapp", "companion": "tok", "via": "direct", "method": "tools/call",
		"tool": "list_things", "args_sha256": strings.Repeat("a", 64), "decision": "allow", "upstream_status": 200, "duration_ms": 3})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Portcullis-Next", "c1")
		w.Header().Set("X-Portcullis-Truncated", "false")
		// Anything older than the line can't be fetched: the backward
		// fill gives up (older activity not loaded).
		if f := r.URL.Query().Get("from"); f != "" && f < at.Format(time.RFC3339) {
			http.Error(w, "busy", 503)
			return
		}
		if r.URL.Query().Get("cursor") == "" {
			w.Write(append(line, '\n'))
		}
	}))
	defer up.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "busy", 503) }))
	defer down.Close()
	ports := map[string]string{"10.0.0.1": up.Listener.Addr().String(), "10.0.0.2": down.Listener.Addr().String()}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
		h, _, _ := net.SplitHostPort(a)
		return (&net.Dialer{}).DialContext(ctx, network, ports[h])
	}}}
	tail := &gatelogs.Tail{R: gatelogs.Replicas{Service: "mcp-gate", Port: gatelogs.MCPGatePort, Client: client,
		Lister: func(context.Context) ([]gatelogs.Replica, error) {
			return []gatelogs.Replica{{Name: "mcp-gate-0", Addr: "10.0.0.1"}, {Name: "mcp-gate-1", Addr: "10.0.0.2"}}, nil
		}}, Now: func() time.Time { return at.Add(time.Hour) }}
	e := newToolEnvWith(t, mcpEnvOpts{cfg: func(c *hub.Config) {
		c.MCPGateDataDir = ""
		c.GateLogs = &hub.GateLogSources{Access: tail}
	}})
	var act struct {
		Lines          []hub.AccessLine `json:"lines"`
		Incomplete     bool             `json:"incomplete"`
		OlderNotLoaded *bool            `json:"older_not_loaded"`
	}
	if err := json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/ai/activity", "", 200)), &act); err != nil {
		t.Fatal(err)
	}
	if len(act.Lines) != 1 || !act.Incomplete || act.OlderNotLoaded == nil {
		t.Errorf("activity = %+v", act)
	}
	// The older segment can't be fetched: each read halves it (the part
	// skipped is older activity not loaded) until the fill gives up;
	// older_not_loaded from then on (permanent).
	for i := 0; i < 30 && !*act.OlderNotLoaded; i++ {
		act.OlderNotLoaded = nil
		json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/ai/activity", "", 200)), &act)
		if act.OlderNotLoaded == nil {
			t.Fatal("no older_not_loaded field")
		}
	}
	if !*act.OlderNotLoaded || len(act.Lines) != 1 {
		t.Errorf("never older_not_loaded: %+v", act)
	}
	if txt, _, _ := e.tool(t, "ai_activity", nil); !strings.Contains(txt, `"older_not_loaded":true`) {
		t.Errorf("ai_activity = %q", txt)
	}
	if !e.s.Hub.AccessOlderNotLoaded() {
		t.Error("AccessOlderNotLoaded false")
	}
	txt, isErr, _ := e.tool(t, "ai_activity", nil)
	if isErr || !strings.Contains(txt, `"incomplete":true`) || !strings.Contains(txt, "list_things") {
		t.Errorf("ai_activity = %q %v", txt, isErr)
	}
	r, body := doAs(t, e.hub, "root", "GET", "/api/directory/audit?via=ai&include=access", "")
	if r.StatusCode != 200 || r.Header.Get("X-Portcullis-Incomplete") != "access" || !strings.HasPrefix(strings.TrimSpace(body), "[") {
		t.Errorf("audit = %d %q %s", r.StatusCode, r.Header.Get("X-Portcullis-Incomplete"), body)
	}
}
