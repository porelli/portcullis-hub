package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/state"
)

// reachCloud is a VPN-renderable app with public exceptions: two routers
// (cloud, cloud-login) and a public router.
const reachCloudCompose = "services:\n  cloud:\n    image: nc\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.cloud.rule: Host(`${PORTCULLIS_HOST_CLOUD:-cloud.portcullis.local}`)\n" +
	"      traefik.http.routers.cloud.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"      traefik.http.routers.cloud-login.rule: Host(`${PORTCULLIS_HOST_CLOUD:-cloud.portcullis.local}`) && PathPrefix(`/login`)\n" +
	"      traefik.http.routers.cloud-login.priority: \"100\"\n" +
	"      traefik.http.services.cloud.loadbalancer.server.port: \"80\"\n" +
	"  db:\n    image: pg\n"

const reachCloudManifest = `name: Cloud
category: productivity
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_cloud
  public_access:
    enabled_by_default: true
    description: Public share links
    default_mode: all
    paths:
      - prefix: /s
        description: Share pages
`

func newReachFixture(t *testing.T, mode string) *vpnFixture {
	t.Helper()
	v := newVPNFixtureExtra(t, nil, map[string][2]string{"cloud": {reachCloudManifest, reachCloudCompose}}, mode)
	for _, id := range []string{"cloud", "mesh"} {
		if err := v.h.Enable(id); err != nil {
			t.Fatal(err)
		}
	}
	v.h.Wait()
	return v
}

func overrideOf(t *testing.T, v *vpnFixture, id string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(v.data, "overrides", id+".override.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func setReach(t *testing.T, v *vpnFixture, id string, r state.Reach) {
	t.Helper()
	if err := v.h.SetInstanceReach(context.Background(), root, id, r); err != nil {
		t.Fatalf("reach %s %+v: %v", id, r, err)
	}
	v.h.Wait()
}

func TestRenderReachMatrix(t *testing.T) {
	for _, mode := range []string{VPNModeApps, VPNModeServer} {
		for _, rc := range []struct {
			name string
			r    *state.Reach
		}{{"internet", nil}, {"vpn_any", &state.Reach{Mode: state.ReachVPN, Via: []string{"*"}}}, {"vpn_builtin", &state.Reach{Mode: state.ReachVPN, Via: []string{"builtin"}}}} {
			t.Run(mode+"_"+rc.name, func(t *testing.T) {
				v := newReachFixture(t, mode)
				v.wire(t, "mesh")
				v.devicesOut = devicesDoc("100.64.0.1")
				v.h.runVPNProvider(context.Background(), "mesh")
				if rc.r != nil {
					setReach(t, v, "cloud", *rc.r)
				}
				ov := overrideOf(t, v, "cloud")
				vpnOnly := rc.r != nil || mode == VPNModeServer
				ep := EntrypointsBoth
				if vpnOnly {
					ep = EntrypointsVPN
				}
				for _, r := range []string{"cloud", "cloud-login", "portcullis-public-cloud"} {
					if !strings.Contains(ov, "traefik.http.routers."+r+".entrypoints: "+ep+"\n") {
						t.Errorf("router %s not on %s:\n%s", r, ep, ov)
					}
				}
				first := "portcullis-vpnallow-cloud@docker"
				for _, r := range []string{"cloud", "cloud-login", "portcullis-public-cloud"} {
					has := strings.Contains(ov, "traefik.http.routers."+r+".middlewares: "+first)
					if has != vpnOnly {
						t.Errorf("router %s allowlist first = %v, want %v:\n%s", r, has, vpnOnly, ov)
					}
				}
				// The app router's group check is core's VPN variant.
				if vpnOnly != strings.Contains(ov, "traefik.http.routers.cloud.middlewares: portcullis-vpnallow-cloud@docker,portcullis-auth@docker,"+VPNGroupsMiddleware+"\n") {
					t.Errorf("cloud's chain (VPN groups = %v):\n%s", vpnOnly, ov)
				}
				if vpnOnly && strings.Contains(ov, "portcullis-groups@docker") {
					t.Errorf("portcullis-groups@docker on a VPN-only instance:\n%s", ov)
				}
				friendly := `"traefik.http.routers.portcullis-vpnonly-cloud.rule": "Host(` + "`cloud.example.org`" + `)"`
				if strings.Contains(ov, friendly) != vpnOnly {
					t.Errorf("friendly router = %v:\n%s", !vpnOnly, ov)
				}
				if vpnOnly {
					for _, l := range []string{
						`"traefik.http.routers.portcullis-vpnonly-cloud.entrypoints": "websecure"`,
						`"traefik.http.routers.portcullis-vpnonly-cloud.priority": "1"`,
						`"traefik.http.routers.portcullis-vpnonly-cloud.middlewares": "vpn-required-path@docker"`,
						`"traefik.http.routers.portcullis-vpnonly-cloud.service": "group-gate@docker"`,
						`"traefik.http.routers.portcullis-vpnonly-cloud.tls.options":`,
						`"traefik.http.middlewares.portcullis-vpnallow-cloud.ipallowlist.rejectstatuscode": "403"`,
					} {
						if !strings.Contains(ov, l) {
							t.Errorf("missing %s:\n%s", l, ov)
						}
					}
					want := "10.213.0.0/22,100.64.0.0/10"
					if rc.r != nil && rc.r.Via[0] == "builtin" {
						want = "10.213.0.0/22"
					}
					if !strings.Contains(ov, `"traefik.http.middlewares.portcullis-vpnallow-cloud.ipallowlist.sourcerange": "`+want+`"`) {
						t.Errorf("sourcerange want %s:\n%s", want, ov)
					}
				}
				if g := "vpn_" + mode + "_" + rc.name + ".override.yml"; os.Getenv("UPDATE_GOLDEN") != "" {
					os.WriteFile(filepath.Join("testdata", "golden", g), []byte(ov), 0o644)
				} else if ov != golden(t, g) {
					t.Errorf("%s differs:\n%s", g, ov)
				}
			})
		}
	}
}

func TestPublicLinksStayInServerMode(t *testing.T) {
	v := newReachFixture(t, VPNModeServer)
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachInternet, PublicLinks: true})
	ov := overrideOf(t, v, "cloud")
	if !strings.Contains(ov, "traefik.http.routers.portcullis-public-cloud.entrypoints: websecure,vpnsecure\n") ||
		strings.Contains(ov, "traefik.http.routers.portcullis-public-cloud.middlewares: portcullis-vpnallow") {
		t.Fatalf("public router:\n%s", ov)
	}
	if !strings.Contains(ov, "traefik.http.routers.cloud.entrypoints: vpnsecure\n") {
		t.Fatalf("app router:\n%s", ov)
	}
	// Only for instances with public exceptions.
	var se *StatusError
	if err := v.h.SetInstanceReach(context.Background(), root, "mesh", state.Reach{Mode: state.ReachInternet, PublicLinks: true}); !errors.As(err, &se) || se.Status != 400 {
		t.Fatalf("mesh public links: %v", err)
	}
}

func TestControlRoutersStayPublic(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	setReach(t, v, "mesh", state.Reach{Mode: state.ReachVPN, Via: []string{"builtin"}})
	ov := overrideOf(t, v, "mesh")
	if !strings.Contains(ov, "traefik.http.routers.mesh.entrypoints: websecure,vpnsecure\n") ||
		strings.Contains(ov, "traefik.http.routers.mesh.middlewares: portcullis-vpnallow") {
		t.Fatalf("control router mesh:\n%s", ov)
	}
	// mesh2 has a control router meshtwo and nothing else: a second test
	// template with a non-control router: the cloud fixture's routers go
	// VPN-only (TestRenderReachMatrix); here the policy keeps mesh's
	// control-only host out of vpn.hosts.
	v.h.mu.RLock()
	pol := v.h.vpnPolicyLocked()
	v.h.mu.RUnlock()
	if _, ok := pol.Hosts["mesh.example.org"]; ok {
		t.Fatalf("a control-only host in vpn.hosts: %+v", pol.Hosts)
	}
}

func TestAllowlistRangesFollowProviders(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	if err := v.h.Enable("wgplain"); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(context.Background(), "mesh")
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"*"}})
	setReach(t, v, "wgplain", state.Reach{Mode: state.ReachVPN, Via: []string{"builtin"}})
	before := overrideOf(t, v, "wgplain")
	v.wire(t, "wgplain")
	v.h.Wait()
	if ov := overrideOf(t, v, "cloud"); !strings.Contains(ov, `ipallowlist.sourcerange": "10.213.0.0/22,10.8.0.0/24,100.64.0.0/10"`) {
		t.Fatalf("cloud (via *) after a second wiring:\n%s", ov)
	}
	after := overrideOf(t, v, "wgplain")
	if !strings.Contains(after, `ipallowlist.sourcerange": "10.213.0.0/22"`) || !strings.Contains(before, `ipallowlist.sourcerange": "10.213.0.0/22"`) {
		t.Fatalf("wgplain (via builtin) ranges moved:\n%s", after)
	}
}

func TestGatewayOverrideKeepsTemplateNetworks(t *testing.T) {
	for _, c := range []struct {
		name, gateway, want string
	}{
		{"none declared", "  gateway:\n    image: x\n", "    networks:\n      \"default\": {}\n      portcullis-vpn:\n        ipv4_address: 172.31.254.16\n"},
		{"list", "  gateway:\n    image: x\n    networks: [default, portcullis-proxy]\n", "    networks:\n      \"default\": {}\n      \"portcullis-proxy\": {}\n      portcullis-vpn:\n        ipv4_address: 172.31.254.16\n"},
		{"map with aliases", "  gateway:\n    image: x\n    networks:\n      default:\n        aliases: [gw]\n", "    networks:\n      \"default\": {}\n      portcullis-vpn:\n        ipv4_address: 172.31.254.16\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := meshTemplate("mesh", "100.64.0.0/10", "oidc_sub")
			m[1] = strings.Replace(m[1], "  gateway:\n    image: x\n", c.gateway+"  fwd:\n    image: ghcr.io/porelli/portcullis-forwarder:1@sha256:"+strings.Repeat("a", 64)+"\n    network_mode: service:gateway\n", 1)
			v := newVPNFixtureExtra(t, nil, map[string][2]string{"mesh": m}, VPNModeApps)
			if v.h.Template("mesh") == nil {
				t.Fatal("mesh not loaded")
			}
			if err := v.h.Enable("mesh"); err != nil {
				t.Fatal(err)
			}
			v.h.Wait()
			v.wire(t, "mesh")
			v.h.Wait()
			ov := overrideOf(t, v, "mesh")
			if !strings.Contains(ov, "  gateway:\n") || !strings.Contains(ov, c.want) {
				t.Fatalf("gateway networks, want\n%s\n in:\n%s", c.want, ov)
			}
			if strings.Count(ov, `PORTCULLIS_VPN_EDGE: "172.31.254.3:9001"`) != 2 {
				t.Fatalf("PORTCULLIS_VPN_EDGE on the gateway and the forwarder:\n%s", ov)
			}
			if !strings.Contains(ov, "networks:\n  portcullis-vpn:\n    external: true\n    name: portcullis-vpn\n") {
				t.Fatalf("top-level network:\n%s", ov)
			}
			// Unwired: no attachment.
			if err := v.h.SetVPNProvider(context.Background(), root, "mesh", false, 0); err != nil {
				t.Fatal(err)
			}
			v.h.Wait()
			if ov := overrideOf(t, v, "mesh"); strings.Contains(ov, "portcullis-vpn") || strings.Contains(ov, "PORTCULLIS_VPN_EDGE") {
				t.Fatalf("after unwiring:\n%s", ov)
			}
		})
	}
}

func TestReachRefusedWithoutProvider(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	os.Remove(v.status) // wg down: no live provider at all
	err := v.h.SetInstanceReach(context.Background(), root, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"*"}})
	if !errors.Is(err, ErrNoLiveProvider) || err.Error() != "wire a VPN first" {
		t.Fatalf("err = %v", err)
	}
	v.writeStatus(t, true)
	// mesh wired but never refreshed: not live; via [mesh] refused.
	v.wire(t, "mesh")
	if err := v.h.SetInstanceReach(context.Background(), root, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"mesh"}}); !errors.Is(err, ErrNoLiveProvider) {
		t.Fatalf("stale mesh: %v", err)
	}
	var se *StatusError
	for _, bad := range [][]string{{"nope"}, {"*", "mesh"}, {"mesh", "mesh"}} {
		if err := v.h.SetInstanceReach(context.Background(), root, "cloud", state.Reach{Mode: state.ReachVPN, Via: bad}); !errors.As(err, &se) || se.Status != 400 {
			t.Errorf("via %v: %v", bad, err)
		}
	}
	if err := v.h.SetInstanceReach(context.Background(), root, "nope", state.Reach{Mode: state.ReachInternet}); !errors.As(err, &se) || se.Status != 404 {
		t.Errorf("unknown instance: %v", err)
	}
	if err := v.h.SetInstanceReach(context.Background(), root, "cloud", state.Reach{Mode: "lan"}); !errors.As(err, &se) || se.Status != 400 {
		t.Errorf("bad mode: %v", err)
	}
}

func TestReachAudited(t *testing.T) {
	v := newReachFixture(t, VPNModeServer)
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN})
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachInternet, PublicLinks: true})
	var got []string
	for _, e := range v.audit.entries {
		if e.Action == "instance.reach" || e.Action == "vpn.public_links" {
			got = append(got, e.Action+" "+e.Target+" "+e.Detail+" "+e.Result)
		}
	}
	want := "instance.reach cloud internet -> vpn via=* ok|instance.reach cloud vpn via=* -> internet ok|vpn.public_links cloud off -> on ok"
	if strings.Join(got, "|") != want {
		t.Fatalf("audit\n got %s\nwant %s", strings.Join(got, "|"), want)
	}
}

func TestVPNGroupsChain(t *testing.T) {
	for in, want := range map[string]string{
		"portcullis-auth@docker,portcullis-groups@docker,security-headers@file": "portcullis-auth@docker," + VPNGroupsMiddleware + ",security-headers@file",
		"portcullis-groups":          VPNGroupsMiddleware,
		"portcullis-groups@file":     "portcullis-groups@file",
		"portcullis-groups-x@docker": "portcullis-groups-x@docker",
		"rate-limit@file":            "rate-limit@file",
	} {
		if got := vpnGroupsChain(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestDriftComparesEntrypointsAndAllowlist(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN})
	v.h.mu.RLock()
	want, err := v.h.desiredRouteLabelsLocked(v.h.findLocked("cloud"))
	v.h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]string{}
	for k, val := range want["cloud"] {
		have[k] = val
	}
	if d := diffExposure("cloud", want["cloud"], have, false); d != "" {
		t.Fatalf("equal labels drift: %s", d)
	}
	for _, c := range []struct{ k, v string }{
		{"traefik.http.routers.cloud.entrypoints", "websecure"},
		{"traefik.http.routers.cloud.middlewares", "portcullis-auth@docker,portcullis-vpnallow-cloud@docker," + VPNGroupsMiddleware},
		{"traefik.http.routers.cloud.middlewares", "portcullis-vpnallow-cloud@docker,portcullis-auth@docker,portcullis-groups@docker"},
		{"traefik.http.middlewares.portcullis-vpnallow-cloud.ipallowlist.sourcerange", "0.0.0.0/0"},
	} {
		h2 := map[string]string{}
		for k, val := range have {
			h2[k] = val
		}
		h2[c.k] = c.v
		if d := diffExposure("cloud", want["cloud"], h2, false); d == "" {
			t.Errorf("%s = %s is no drift", c.k, c.v)
		}
	}
	// A leftover friendly router or allowlist on an internet instance is.
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachInternet})
	v.h.mu.RLock()
	want, _ = v.h.desiredRouteLabelsLocked(v.h.findLocked("cloud"))
	v.h.mu.RUnlock()
	h3 := map[string]string{}
	for k, val := range want["cloud"] {
		h3[k] = val
	}
	h3["traefik.http.routers.portcullis-vpnonly-cloud.rule"] = "Host(`cloud.example.org`)"
	if d := diffExposure("cloud", want["cloud"], h3, false); !strings.Contains(d, "unexpected") {
		t.Errorf("leftover friendly router: %q", d)
	}
}

func TestPolicyV7VPNSection(t *testing.T) {
	v := newReachFixture(t, VPNModeAdmin)
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(context.Background(), "mesh")
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"mesh"}})
	b, err := os.ReadFile(filepath.Join(v.data, "group-gate-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int `json:"version"`
		VPN     struct {
			Hosts       map[string]struct{ Via []string } `json:"hosts"`
			ServerMode  bool                              `json:"server_mode"`
			AdminOnly   bool                              `json:"admin_only"`
			PublicEnrol bool                              `json:"public_enrol"`
			DevicesFile string                            `json:"devices_file"`
		} `json:"vpn"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 7 || doc.VPN.DevicesFile != "vpn.json" || doc.VPN.ServerMode || !doc.VPN.AdminOnly || doc.VPN.PublicEnrol {
		t.Fatalf("%s", b)
	}
	if h := doc.VPN.Hosts["cloud.example.org"]; len(doc.VPN.Hosts) != 1 || len(h.Via) != 1 || h.Via[0] != "mesh" {
		t.Fatalf("hosts %+v", doc.VPN.Hosts)
	}
}

func TestUnwireLastViaMakesInstanceUnreachable(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(context.Background(), "mesh")
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"mesh"}})
	if err := v.h.SetVPNProvider(context.Background(), root, "mesh", false, 0); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	ov := overrideOf(t, v, "cloud")
	if !strings.Contains(ov, "traefik.http.routers.cloud.entrypoints: vpnsecure\n") || !strings.Contains(ov, `ipallowlist.sourcerange": "0.0.0.0/32"`) {
		t.Fatalf("after unwiring its only provider:\n%s", ov)
	}
	v.h.mu.RLock()
	r := v.h.st.Reach["cloud"]
	v.h.mu.RUnlock()
	if r.Mode != state.ReachVPN {
		t.Fatalf("reach %+v", r)
	}
}

var _ = docker.Network{}

// set_instance_reach's class (security review): W only when the change
// keeps or narrows the instance's access as it is now.
func TestReachChangeNarrows(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	ctx := context.Background()
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(ctx, "mesh")
	vpnAny := state.Reach{Mode: state.ReachVPN, Via: []string{"*"}}
	vpnMesh := state.Reach{Mode: state.ReachVPN, Via: []string{"mesh"}}
	internet := state.Reach{Mode: state.ReachInternet}
	check := func(name string, next state.Reach, want bool) {
		t.Helper()
		if got := v.h.ReachChangeNarrows("cloud", next); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	check("internet → internet", internet, true)
	check("internet → vpn *", vpnAny, true)
	check("internet → vpn [mesh]", vpnMesh, true)
	check("internet → public links", state.Reach{Mode: state.ReachInternet, PublicLinks: true}, false)
	setReach(t, v, "cloud", vpnMesh)
	check("vpn [mesh] → vpn *", vpnAny, false)
	check("vpn [mesh] → vpn [mesh, builtin]", state.Reach{Mode: state.ReachVPN, Via: []string{"mesh", "builtin"}}, false)
	check("vpn [mesh] → vpn [mesh]", vpnMesh, true)
	check("vpn [mesh] → vpn [builtin]", state.Reach{Mode: state.ReachVPN, Via: []string{"builtin"}}, false)
	check("vpn [mesh] → internet", internet, false)
	check("vpn [mesh] → vpn [mesh] with public links", state.Reach{Mode: state.ReachVPN, Via: []string{"mesh"}, PublicLinks: true}, false)
	setReach(t, v, "cloud", vpnAny)
	check("vpn * → vpn [mesh]", vpnMesh, true)
	check("vpn * → vpn *", vpnAny, true)
	check("vpn * → internet", internet, false)
	if v.h.ReachChangeNarrows("nope", vpnAny) {
		t.Error("an unknown instance")
	}
	if v.h.ReachChangeNarrows("cloud", state.Reach{Mode: "lan"}) {
		t.Error("an unknown mode")
	}
}

// Modes × reach × public links: what SetInstanceReach accepts, the
// render key, the class of a change and the rendered labels all come
// from the one effective access (vpnAccess), so they agree.
func TestReachEffectiveAccessTable(t *testing.T) {
	for _, mode := range []string{VPNModeApps, VPNModeServer} {
		for _, rm := range []string{state.ReachInternet, state.ReachVPN} {
			for _, pl := range []bool{false, true} {
				name := mode + "_" + rm
				if pl {
					name += "_public-links"
				}
				t.Run(name, func(t *testing.T) {
					v := newReachFixture(t, mode)
					r := state.Reach{Mode: rm, PublicLinks: pl}
					if rm == state.ReachVPN {
						r.Via = []string{"*"}
					}
					err := v.h.SetInstanceReach(context.Background(), root, "cloud", r)
					wantRefused := pl && (rm == state.ReachVPN || mode != VPNModeServer)
					if wantRefused {
						if statusCode(err) != 400 {
							t.Fatalf("a contradictory reach was accepted: %v", err)
						}
						v.h.mu.RLock()
						_, stored := v.h.st.Reach["cloud"]
						v.h.mu.RUnlock()
						if stored {
							t.Fatal("a refused reach was stored")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					v.h.Wait()
					vpnOnly := rm == state.ReachVPN || mode == VPNModeServer
					effPL := pl && rm == state.ReachInternet && mode == VPNModeServer
					v.h.mu.RLock()
					key := v.h.vpnRenderKeyLocked(v.h.findLocked("cloud"))
					v.h.mu.RUnlock()
					f := vpnKeyFields(key)
					if (f["r"] != "") != vpnOnly || (f["pl"] == "1") != effPL {
						t.Fatalf("key %q: vpnOnly %v public links %v", key, vpnOnly, effPL)
					}
					ov := overrideOf(t, v, "cloud")
					appEP, pubEP := EntrypointsBoth, EntrypointsBoth
					if vpnOnly {
						appEP = EntrypointsVPN
						if !effPL {
							pubEP = EntrypointsVPN
						}
					}
					if !strings.Contains(ov, "traefik.http.routers.cloud.entrypoints: "+appEP+"\n") || !strings.Contains(ov, "traefik.http.routers.portcullis-public-cloud.entrypoints: "+pubEP+"\n") {
						t.Fatalf("labels disagree with the key %q:\n%s", key, ov)
					}
					// The class of going back to plain internet: W only if
					// that keeps or narrows what is served now.
					back := v.h.ReachChangeNarrows("cloud", state.Reach{Mode: state.ReachInternet})
					// Server mode: "internet" is VPN-only through every provider
					// anyway, the same access as vpn via *.
					wantBack := !vpnOnly || mode == VPNModeServer
					if effPL {
						wantBack = true // dropping public links narrows
					}
					if back != wantBack {
						t.Fatalf("back to internet: W %v, want %v (key %q)", back, wantBack, key)
					}
				})
			}
		}
	}
}
