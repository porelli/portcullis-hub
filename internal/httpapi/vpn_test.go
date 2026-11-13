package httpapi

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/portcullis/hub/web"
)

// vpnAdminRoutes are the §11 VPN admin routes (Hub listener only).
var vpnAdminRoutes = []struct{ method, path, body string }{
	{"GET", "/api/vpn", ""},
	{"PUT", "/api/vpn/settings", `{"devices_per_person":5}`},
	{"PUT", "/api/instances/grafana/vpn-provider", `{"wired":true}`},
	{"PUT", "/api/instances/grafana/reach", `{"mode":"vpn","via":["*"]}`},
	{"PUT", "/api/instances/grafana/vpn-static/10.8.0.5", `{"user":"root","name":"x"}`},
	{"DELETE", "/api/instances/grafana/vpn-static/10.8.0.5", ""},
	{"POST", "/api/instances/grafana/vpn-dns/ack", ""},
	{"GET", "/api/vpn/devices", ""},
	{"DELETE", "/api/vpn/devices/x", ""},
}

func TestVPNRoutesAdminOnly(t *testing.T) {
	e := newInstEnv(t)
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/invite", `{"group":"helpers"}`, 200)
	for _, user := range []string{"dana", "nobody", ""} {
		for _, r := range vpnAdminRoutes {
			if code, b := e.do(t, user, r.method, r.path, r.body); code != 403 {
				t.Errorf("%q %s %s = %d %s, want 403", user, r.method, r.path, code, b)
			}
		}
	}
	for _, r := range vpnAdminRoutes {
		if resp, _ := doAs(t, e.ppl, "root", r.method, r.path, r.body); resp.StatusCode != 404 && resp.StatusCode != 405 {
			t.Errorf("people %s %s = %d, want 404", r.method, r.path, resp.StatusCode)
		}
	}
	if a := e.auditActions(t, "vpn."); len(a) != 0 {
		t.Fatalf("refused requests reached the Hub: %v", a)
	}
}

func TestVPNRoutesStatus(t *testing.T) {
	e := newInstEnv(t)
	for _, c := range []struct {
		method, path, body string
		code               int
		want               string
	}{
		{"GET", "/api/vpn", "", 200, `"mode":"apps"`},
		// No wg service here (fail closed).
		{"PUT", "/api/instances/grafana/vpn-provider", `{"wired":true}`, 409, "the VPN service isn't running: run ./portcullis vpn init on the host"},
		{"PUT", "/api/instances/grafana/reach", `{"mode":"vpn","via":["*"]}`, 409, "wire a VPN first"},
		{"PUT", "/api/instances/grafana/reach", `{"mode":"vpn","via":["nope"]}`, 400, "nope is not a wired VPN provider"},
		{"PUT", "/api/instances/nope/reach", `{"mode":"internet"}`, 404, "no instance nope"},
		{"PUT", "/api/instances/grafana/reach", `{"mode":"internet","x":1}`, 400, "body must be"},
		{"PUT", "/api/instances/grafana/vpn-static/10.8.0.5", `{"user":"root","name":"x"}`, 400, ""},
		{"POST", "/api/instances/grafana/vpn-dns/ack", "", 400, "not a VPN provider"},
		{"PUT", "/api/vpn/settings", `{"devices_per_person":0}`, 400, "devices_per_person"},
		{"PUT", "/api/vpn/settings", `{"expiry":"7d"}`, 400, "expiry"},
		{"PUT", "/api/vpn/settings", `{"expiry":"90d","devices_per_person":3}`, 200, `"expiry":"90d"`},
		{"GET", "/api/vpn/devices", "", 200, `[]`},
		{"DELETE", "/api/vpn/devices/x", "", 404, "no such device"},
	} {
		code, b := e.do(t, "root", c.method, c.path, c.body)
		if code != c.code || !strings.Contains(b, c.want) {
			t.Errorf("%s %s %s = %d %q, want %d %q", c.method, c.path, c.body, code, b, c.code, c.want)
		}
	}
}

// TestVPNAuditParity: every mutating VPN route writes its action (ok or
// refused), attributed to the caller.
func TestVPNAuditParity(t *testing.T) {
	e := newInstEnv(t)
	for _, c := range []struct {
		method, path, body, action string
	}{
		{"PUT", "/api/vpn/settings", `{"devices_per_person":3}`, "vpn.settings"},
		{"PUT", "/api/instances/grafana/vpn-provider", `{"wired":true}`, "vpn.provider_wired"},
		{"PUT", "/api/instances/grafana/vpn-provider", `{"wired":false}`, "vpn.provider_unwired"},
		{"PUT", "/api/instances/grafana/reach", `{"mode":"vpn","via":["*"]}`, "instance.reach"},
		{"PUT", "/api/instances/grafana/vpn-static/10.8.0.5", `{"user":"root","name":"x"}`, "vpn.static_assigned"},
		{"DELETE", "/api/instances/grafana/vpn-static/10.8.0.5", "", "vpn.static_unassigned"},
		{"POST", "/api/instances/grafana/vpn-dns/ack", "", "vpn.dns_acknowledged"},
	} {
		before := len(readAudit(t, e.audit))
		e.do(t, "root", c.method, c.path, c.body)
		got := readAudit(t, e.audit)[before:]
		found := false
		for _, a := range got {
			if a.Action == c.action && a.Actor == "root" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s %s: no %s audit (got %+v)", c.method, c.path, c.action, got)
		}
	}
}

// TestNoKeyInMCPOutput: list_vpn_devices and get_vpn carry no key
// material (no public_key field, nothing from a config).
func TestNoKeyInMCPOutput(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	for _, tool := range []string{"list_vpn_devices", "get_vpn"} {
		txt, isErr, _ := e.tool(t, tool, map[string]any{})
		if isErr {
			t.Fatalf("%s: %s", tool, txt)
		}
		for _, banned := range []string{"public_key", "private_key", "PrivateKey", "[Interface]", "server_public_key"} {
			if strings.Contains(txt, banned) {
				t.Errorf("%s output carries %s: %s", tool, banned, txt)
			}
		}
	}
}

// TestHubVPNUI (static): the instance page's Access, the VPN tab and
// Settings → VPN; the unwire confirmation lists the instances whose
// Through names only that provider first.
func TestHubVPNUI(t *testing.T) {
	b, err := fs.ReadFile(web.FS, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	h := string(b)
	for _, want := range []string{"data-reach=", "data-vpn-provider=", "function renderVPNTab(", "function loadVPNSettings(", "function vpnOnlyThrough(",
		"become unreachable", "Use for Portcullis access", "./portcullis vpn mode apps|admin|server", "Public links stay on the internet", "id=\"vpn-settings-root\""} {
		if !strings.Contains(h, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	i, j := strings.Index(h, "const dead = vpnOnlyThrough("), strings.Index(h, "'Stop using ' + id")
	if i < 0 || j < 0 || i > j {
		t.Error("the unwire confirmation doesn't list the instances it cuts off first")
	}
}
