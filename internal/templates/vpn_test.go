package templates

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// vpnVector is one entry of testdata/vpn_vectors.json, shared byte for
// byte with portcullis-templates tests/vpn_vectors.json (its lint
// compares the two): a manifest and compose file and the exact first
// refusal ("" = the template loads).
type vpnVector struct {
	Name      string `json:"name"`
	Manifest  string `json:"manifest"`
	Compose   string `json:"compose"`
	WantError string `json:"want_error"`
}

func TestVPNVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/vpn_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vpnVector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 30 {
		t.Fatalf("%d vectors", len(vs))
	}
	names := map[string]bool{}
	for _, v := range vs {
		if names[v.Name] {
			t.Errorf("vector %q twice", v.Name)
		}
		names[v.Name] = true
		_, err := build("mesh", "src", "", []byte(v.Manifest), []byte(v.Compose), "example.org", nil)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != v.WantError {
			t.Errorf("%s:\n got %q\nwant %q", v.Name, got, v.WantError)
		}
	}
	for _, n := range []string{"headscale-shaped ok", "static ok", "range via cidr setting ok", "range via a string setting refused",
		"ingress has a router refused", "hook with [vpn, start] refused", "vpn hook nobody names refused",
		"control router = the admin_paths router refused", "ingress is an AI companion refused"} {
		if !names[n] {
			t.Errorf("vector %q missing", n)
		}
	}
}

func vpnVectorByName(t *testing.T, name string) vpnVector {
	t.Helper()
	b, err := os.ReadFile("testdata/vpn_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vpnVector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("no vector %q", name)
	return vpnVector{}
}

func TestVPNBlockLoads(t *testing.T) {
	v := vpnVectorByName(t, "headscale-shaped ok")
	tp, err := build("mesh", "src", "", []byte(v.Manifest), []byte(v.Compose), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	b := tp.Manifest.VPN
	if b == nil || b.Label != "Mesh tailnet" || b.Ingress.Service != "gateway" || b.Identity.Owner != VPNOwnerOIDCSub ||
		b.Identity.EffectiveRefresh() != time.Minute || b.DNS.Hook != "vpn-dns" || len(b.ControlRouters) != 1 {
		t.Fatalf("%+v", b)
	}
	if (VPNIdentity{}).EffectiveRefresh() != 60*time.Second {
		t.Fatal("default refresh")
	}
}

func TestVPNBlockStrict(t *testing.T) {
	v := vpnVectorByName(t, "headscale-shaped ok")
	for _, edit := range [][2]string{
		{"  label: Mesh tailnet\n", "  label: Mesh tailnet\n  extra: 1\n"},
		{"proxy_protocol: v2}", "proxy_protocol: v2, port: 1}"},
		{"refresh: 60s}", "refresh: 60s, every: 1}"},
		{"dns: {hook: vpn-dns}", "dns: {hook: vpn-dns, zone: x}"},
	} {
		m := strings.Replace(v.Manifest, edit[0], edit[1], 1)
		if m == v.Manifest {
			t.Fatalf("edit %q missed", edit[0])
		}
		if _, err := build("mesh", "src", "", []byte(m), []byte(v.Compose), "example.org", nil); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("%q: %v", edit[1], err)
		}
	}
}

func TestTemplateMentioningPortcullisVPNRefused(t *testing.T) {
	for _, c := range []string{
		"services:\n  a:\n    image: x\n    labels:\n      traefik.http.routers.a.middlewares: portcullis-vpnallow-x@docker\n",
		"services:\n  a:\n    image: x\n    networks: [portcullis-vpn]\n",
		"services:\n  a:\n    image: x\n    labels:\n      traefik.http.routers.portcullis-VPNonly-a.rule: Host(`a`)\n",
	} {
		err := checkCoreRefs([]byte(c), nil)
		if err == nil || !strings.Contains(err.Error(), `"portcullis-vpn"`) {
			t.Errorf("%q: %v", c, err)
		}
	}
	// Core's forwarder image is not a reserved name.
	if err := checkCoreRefs([]byte("services:\n  a:\n    image: ghcr.io/porelli/portcullis-forwarder:1@sha256:"+strings.Repeat("a", 64)+"\n"), nil); err != nil {
		t.Errorf("forwarder image: %v", err)
	}
}

func TestReservedVPNVarRefused(t *testing.T) {
	v := vpnVectorByName(t, "headscale-shaped ok")
	if !strings.Contains(v.Compose, "$$PORTCULLIS_VPN_EDGE") {
		t.Fatal("fixture reads $$PORTCULLIS_VPN_EDGE")
	}
	if _, err := build("mesh", "src", "", []byte(v.Manifest), []byte(v.Compose), "example.org", nil); err != nil {
		t.Fatalf("$$PORTCULLIS_VPN_EDGE: %v", err)
	}
	for _, ref := range []string{"${PORTCULLIS_VPN_EDGE}", "$PORTCULLIS_VPN_EDGE", "${PORTCULLIS_VPN_EDGE:-x}", "${PORTCULLIS_VPN_MODE}"} {
		c := strings.Replace(v.Compose, "$$PORTCULLIS_VPN_EDGE", ref, 1)
		_, err := build("mesh", "src", "", []byte(v.Manifest), []byte(c), "example.org", nil)
		if err == nil || !strings.Contains(err.Error(), "is reserved: PORTCULLIS_VPN_*") {
			t.Errorf("%s: %v", ref, err)
		}
	}
}

func TestVPNCoreNames(t *testing.T) {
	if !coreServices["wg"] || !coreVolumes["wg_data"] || !reservedDNSName("wg") {
		t.Fatal("wg / wg_data are core names")
	}
}

func TestResolveVPNRanges(t *testing.T) {
	m := &Manifest{
		Settings: &SettingsSpec{Options: []Option{{Key: "r", Type: TypeString, Format: "cidr"}, {Key: "s", Type: TypeString}}},
		VPN:      &VPN{Ranges: []string{"100.64.0.0/10", "{{setting:r}}"}},
	}
	got, err := ResolveVPNRanges(m, map[string]any{"r": "10.8.0.0/24"})
	if err != nil || len(got) != 2 || got[1] != netip.MustParsePrefix("10.8.0.0/24") {
		t.Fatalf("%v %v", got, err)
	}
	for _, c := range []struct {
		vals map[string]any
		want string
	}{
		{map[string]any{}, "has no value"},
		{map[string]any{"r": "10.8.0.0/31"}, "is not an IPv4 prefix"},
		{map[string]any{"r": "fd00::/8"}, "is not an IPv4 prefix"},
		{map[string]any{"r": "100.100.0.0/16"}, "overlaps"},
		{map[string]any{"r": 7}, "has no value"},
	} {
		if _, err := ResolveVPNRanges(m, c.vals); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v", c.vals, err)
		}
	}
	m.VPN.Ranges = []string{"{{setting:s}}"}
	if _, err := ResolveVPNRanges(m, map[string]any{"s": "10.8.0.0/24"}); err == nil {
		t.Error("string setting resolved")
	}
	if _, err := ResolveVPNRanges(&Manifest{}, nil); err == nil {
		t.Error("no block")
	}
}

func TestVPNHookExclusive(t *testing.T) {
	h := Hook{When: []string{HookVPN}}
	if !h.IsVPN() || h.IsAI() || !HookTriggers[HookVPN] {
		t.Fatal("vpn trigger")
	}
}

// Templates set only entrypoints: websecure (contract §3): the Hub's
// override adds vpnsecure per reach.
func TestTemplateEntrypointsWebsecureOnly(t *testing.T) {
	for _, ep := range []string{"vpnsecure", "websecure,vpnsecure", "web", "${EP:-websecure}"} {
		c := "services:\n  a:\n    image: x\n    labels:\n      traefik.http.routers.a.entrypoints: \"" + ep + "\"\n"
		if err := checkCoreRefs([]byte(c), nil); err == nil || err.Error() != "router a: entrypoints must be 'websecure'" {
			t.Errorf("%s: %v", ep, err)
		}
	}
	c := "services:\n  a:\n    image: x\n    labels:\n      traefik.tcp.routers.a.entrypoints: vpnsecure\n"
	if err := checkCoreRefs([]byte(c), nil); err == nil {
		t.Error("a TCP router on vpnsecure")
	}
	if err := checkCoreRefs([]byte("services:\n  a:\n    image: x\n    labels:\n      traefik.http.routers.a.entrypoints: websecure\n"), nil); err != nil {
		t.Error(err)
	}
}
