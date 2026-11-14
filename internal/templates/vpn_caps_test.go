package templates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vpnWith is the headscale-shaped vector with the ingress hardened
// (cap_drop: [ALL]) and edit applied to its compose.
func vpnWith(t *testing.T, edit func(compose string) string) error {
	t.Helper()
	v := vpnVectorByName(t, "headscale-shaped ok")
	// The vectors' gateway is hardened already: cap_drop moved after
	// image so the edits below can append to it.
	c := strings.Replace(v.Compose, "    cap_drop: [ALL]\n    image: ghcr.io/porelli/portcullis-forwarder:1\n    command: [\"sh\", \"-c\", \"exec fwd --to $$PORTCULLIS_VPN_EDGE\"]\n",
		"    image: ghcr.io/porelli/portcullis-forwarder:1\n    command: [\"sh\", \"-c\", \"exec fwd --to $$PORTCULLIS_VPN_EDGE\"]\n    cap_drop: [ALL]\n", 1)
	if edit != nil {
		c = edit(c)
	}
	_, err := build("mesh", "src", "", []byte(v.Manifest), []byte(c), "example.org", nil)
	return err
}

const fwdSibling = "  fwd:\n    image: ghcr.io/porelli/portcullis-forwarder:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    network_mode: service:gateway\n"

// Task 19: the ingress and every service in its network namespace drop
// every capability, add none of NET_ADMIN, NET_RAW or SYS_ADMIN (only
// NET_BIND_SERVICE, for the forwarder) and pass no /dev/net/tun: without
// NET_ADMIN or NET_RAW a gateway can't take another gateway's address on
// portcullis-vpn.
func TestVPNIngressCapabilities(t *testing.T) {
	if err := vpnWith(t, nil); err != nil {
		t.Fatalf("hardened ingress refused: %v", err)
	}
	gw := "    cap_drop: [ALL]\n"
	for _, c := range []struct {
		name string
		edit func(string) string
		want string // substring of the refusal ("" = loads)
	}{
		{"no cap_drop", func(s string) string { return strings.Replace(s, gw, "", 1) }, "cap_drop"},
		{"cap_drop without ALL", func(s string) string { return strings.Replace(s, gw, "    cap_drop: [NET_RAW]\n", 1) }, "cap_drop"},
		{"cap_drop all lowercase", func(s string) string { return strings.Replace(s, gw, "    cap_drop: [all]\n", 1) }, ""},
		{"NET_BIND_SERVICE", func(s string) string { return strings.Replace(s, gw, gw+"    cap_add: [NET_BIND_SERVICE]\n", 1) }, ""},
		{"NET_ADMIN", func(s string) string { return strings.Replace(s, gw, gw+"    cap_add: [NET_ADMIN]\n", 1) }, "NET_ADMIN"},
		{"CAP_NET_RAW", func(s string) string { return strings.Replace(s, gw, gw+"    cap_add: [CAP_NET_RAW]\n", 1) }, "NET_RAW"},
		{"sys_admin", func(s string) string { return strings.Replace(s, gw, gw+"    cap_add: [sys_admin]\n", 1) }, "adds sys_admin"},
		{"cap_add ALL", func(s string) string { return strings.Replace(s, gw, gw+"    cap_add: [ALL]\n", 1) }, "ALL"},
		{"tun", func(s string) string {
			return strings.Replace(s, gw, gw+"    devices: [\"/dev/net/tun:/dev/net/tun\"]\n", 1)
		}, "devices"},
		{"any device", func(s string) string { return strings.Replace(s, gw, gw+"    devices: [\"/dev/dri:/dev/dri\"]\n", 1) }, "devices"},
		{"device_cgroup_rules", func(s string) string {
			return strings.Replace(s, gw, gw+"    device_cgroup_rules: [\"c 10:200 rwm\"]\n", 1)
		}, "devices"},
		{"other cap", func(s string) string { return strings.Replace(s, gw, gw+"    cap_add: [CHOWN]\n", 1) }, "CHOWN"},
		{"privileged false", func(s string) string { return strings.Replace(s, gw, gw+"    privileged: false\n", 1) }, ""},
		{"privileged string false", func(s string) string { return strings.Replace(s, gw, gw+"    privileged: \"false\"\n", 1) }, ""},
		{"privileged string true", func(s string) string { return strings.Replace(s, gw, gw+"    privileged: \"true\"\n", 1) }, "is privileged"},
		{"privileged null", func(s string) string { return strings.Replace(s, gw, gw+"    privileged:\n", 1) }, "is privileged"},
		{"empty devices", func(s string) string { return strings.Replace(s, gw, gw+"    devices: []\n", 1) }, "has devices"},
		{"cap_add variable", func(s string) string {
			return strings.Replace(s, gw, gw+"    cap_add: [\"${CAP:-NET_BIND_SERVICE}\"]\n", 1)
		}, "adds"},
		{"devices long syntax", func(s string) string {
			return strings.Replace(s, gw, gw+"    devices:\n      - {source: /dev/net/tun, target: /dev/net/tun}\n", 1)
		}, "devices"},
		{"devices variable", func(s string) string { return strings.Replace(s, gw, gw+"    devices: [\"${TUN}:/dev/net/tun\"]\n", 1) }, "devices"},
		{"privileged", func(s string) string { return strings.Replace(s, gw, gw+"    privileged: true\n", 1) }, "privileged"},
		{"sibling without cap_drop", func(s string) string { return strings.Replace(s, "  glue:\n", fwdSibling+"  glue:\n", 1) }, "fwd"},
		{"sibling hardened", func(s string) string {
			return strings.Replace(s, "  glue:\n", fwdSibling+"    cap_drop: [ALL]\n    cap_add: [NET_BIND_SERVICE]\n  glue:\n", 1)
		}, ""},
		{"sibling NET_ADMIN", func(s string) string {
			return strings.Replace(s, "  glue:\n", fwdSibling+"    cap_drop: [ALL]\n    cap_add: [NET_ADMIN]\n  glue:\n", 1)
		}, "NET_ADMIN"},
		// A service outside the ingress namespace isn't constrained.
		{"glue NET_ADMIN", func(s string) string {
			return strings.Replace(s, "  glue:\n    image: x\n", "  glue:\n    image: x\n    cap_add: [NET_ADMIN]\n", 1)
		}, ""},
	} {
		err := vpnWith(t, c.edit)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
	}
}

// Task 19: a control router is Host(...) alone or Host(...) &&
// PathPrefix(...); anything else is refused.
func TestVPNControlRouterShapes(t *testing.T) {
	v := vpnVectorByName(t, "headscale-shaped ok")
	rule := "traefik.http.routers.mesh.rule: Host(`${PORTCULLIS_HOST_MESH:-mesh.portcullis.local}`)"
	ctl := "      traefik.http.routers.meshctl.rule: "
	for _, c := range []struct {
		name, rule string
		ok         bool
	}{
		{"host and path prefix", "Host(`${PORTCULLIS_HOST_MESH:-mesh.portcullis.local}`) && PathPrefix(`/ts2021`)", true},
		{"path prefix first", "PathPrefix(`/ts2021`) && Host(`${PORTCULLIS_HOST_MESH:-mesh.portcullis.local}`)", false},
		{"host and exact path", "Host(`${PORTCULLIS_HOST_MESH:-mesh.portcullis.local}`) && Path(`/ts2021`)", false},
		{"host or path prefix", "Host(`${PORTCULLIS_HOST_MESH:-mesh.portcullis.local}`) || (Host(`${PORTCULLIS_HOST_MESH:-mesh.portcullis.local}`) && PathPrefix(`/x`))", false},
		{"two path prefixes", "Host(`${PORTCULLIS_HOST_MESH:-mesh.portcullis.local}`) && (PathPrefix(`/a`) || PathPrefix(`/b`))", false},
		{"path regexp", "Host(`${PORTCULLIS_HOST_MESH:-mesh.portcullis.local}`) && PathRegexp(`^/ts`)", false},
		{"negated path prefix", "Host(`${PORTCULLIS_HOST_MESH:-mesh.portcullis.local}`) && !PathPrefix(`/ts`)", false},
		{"header matcher", "Host(`${PORTCULLIS_HOST_MESH:-mesh.portcullis.local}`) && Header(`X`, `y`)", false},
	} {
		comp := strings.Replace(v.Compose, "      "+rule+"\n", "      "+rule+"\n"+ctl+c.rule+"\n", 1)
		man := strings.Replace(v.Manifest, "control_routers: [mesh]", "control_routers: [meshctl]", 1)
		_, err := build("mesh", "src", "", []byte(man), []byte(comp), "example.org", nil)
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), "vpn.control_routers: meshctl")) {
			t.Errorf("%s: err %v", c.name, err)
		}
	}
}

// A bind under ./templates/<id>/ never resolves out of the template's
// directory through a symlink (validate.py's vpn_bind_escapes).
func TestVPNBindEscapes(t *testing.T) {
	v := vpnVectorByName(t, "headscale-shaped ok")
	gw := "    command: [\"sh\", \"-c\", \"exec fwd --to $$PORTCULLIS_VPN_EDGE\"]\n"
	comp := strings.Replace(v.Compose, gw, gw+"    volumes:\n      - ./templates/mesh/vpn/gw.sh:/gw.sh:ro\n", 1)
	outside := filepath.Join(t.TempDir(), "secret.sh")
	os.WriteFile(outside, []byte("x"), 0o644)
	for name, c := range map[string]struct {
		setup func(vpnDir string)
		want  string
	}{
		"a file": {func(d string) { os.WriteFile(filepath.Join(d, "gw.sh"), []byte("x"), 0o644) }, ""},
		"a link inside": {func(d string) {
			os.WriteFile(filepath.Join(d, "real.sh"), []byte("x"), 0o644)
			os.Symlink("real.sh", filepath.Join(d, "gw.sh"))
		}, ""},
		"a link outside":     {func(d string) { os.Symlink(outside, filepath.Join(d, "gw.sh")) }, "vpn.ingress.service: gateway mounts ./templates/mesh/vpn/gw.sh:/gw.sh:ro: it resolves outside templates/mesh/ (a symlink)"},
		"a dir link outside": {func(d string) { os.RemoveAll(d); os.Symlink(filepath.Dir(outside), d) }, "vpn.ingress.service: gateway mounts ./templates/mesh/vpn/gw.sh:/gw.sh:ro: it resolves outside templates/mesh/ (a symlink)"},
		"missing":            {func(string) {}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "mesh")
			os.MkdirAll(filepath.Join(dir, "vpn"), 0o755)
			os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(v.Manifest), 0o644)
			os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(comp), 0o644)
			c.setup(filepath.Join(dir, "vpn"))
			_, err := Load(root, "mesh", "src", "example.org", nil)
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
