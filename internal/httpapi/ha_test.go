package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHAEnableIsNotAnAPI (D5): turning HA on is CLI-only: no enable
// route (POST /api/ha/enable is 404; POST /api/ha 404 or 405), no tool; the
// page's answer carries the command, experimental, and the GET is
// read-only. The CLI twin GET /host/ha answers the same; off Kubernetes
// the page is 409 and the twin isn't there.
func TestHAEnableIsNotAnAPI(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	for _, p := range []string{"/api/ha/enable", "/api/ha/convert"} {
		if code, body := e.do(t, "root", "POST", p, `{}`); code != http.StatusNotFound {
			t.Errorf("POST %s: %d %s", p, code, body)
		}
	}
	if code, _ := e.do(t, "root", "POST", "/api/ha", `{}`); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/ha: %d", code)
	}
	code, body := e.do(t, "root", "GET", "/api/ha", "")
	if code != 200 {
		t.Fatalf("GET /api/ha: %d %s", code, body)
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"experimental", "enabled", "checklist", "guarantee", "nodes", "quorum", "sites", "dns", "credentials_note", "command"} {
		if _, ok := v[k]; !ok {
			t.Errorf("no %s in %s", k, body)
		}
	}
	if string(v["command"]) != `"./portcullis ha enable"` || string(v["experimental"]) != "true" {
		t.Errorf("command %s experimental %s", v["command"], v["experimental"])
	}
	for _, tl := range e.s.tools(ScopeAdmin) {
		if strings.HasPrefix(tl.Twin, "POST /api/ha") || strings.Contains(tl.Name, "ha_enable") || strings.Contains(tl.Name, "enable_ha") {
			t.Errorf("tool %s turns HA on", tl.Name)
		}
		if tl.Name == "ha_status" && (tl.Class != ClassRead || tl.Twin != "GET /api/ha") {
			t.Errorf("ha_status: %s %s", tl.Class, tl.Twin)
		}
	}

	srv := httptest.NewServer(HostHandler(e.s.Hub))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/host/ha")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"command":"./portcullis ha enable"`) {
		t.Errorf("GET /host/ha: %d %s", resp.StatusCode, b)
	}

	d := newAvailEnv(t, false, nil)
	if code, body := d.do(t, "root", "GET", "/api/ha", ""); code != 409 || !strings.Contains(body, "high availability needs Kubernetes") {
		t.Errorf("docker: %d %s", code, body)
	}
	dsrv := httptest.NewServer(HostHandler(d.s.Hub))
	defer dsrv.Close()
	resp, err = http.Get(dsrv.URL + "/host/ha")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("GET /host/ha on docker: %d", resp.StatusCode)
	}
}
