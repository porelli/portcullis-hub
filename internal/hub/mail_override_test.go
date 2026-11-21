package hub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

const testVoidSession = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// mailOverrideFixture: the slot open (mail.example.org), mailsrv wired,
// a secrets directory with a void-session nonce.
func mailOverrideFixture(t *testing.T) *fixture {
	t.Helper()
	f := newMailSlotFixture(t, true)
	f.h.SetMailCoreForTest(true, "mail.example.org")
	writeFile(t, filepath.Join(f.h.cfg.MailProviderSlotDir, "void-session"), testVoidSession+"\n")
	return f
}

// renderMail renders mailsrv's override in mode.
func renderMail(t *testing.T, f *fixture, mode mailMode) string {
	t.Helper()
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	tp := f.h.findLocked(mailProviderID)
	if tp == nil {
		t.Fatal("no mailsrv instance")
	}
	out, err := f.h.mailOverrideLocked(tp, mailProviderID, mode)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// overrideDoc is a rendered override, decoded.
type overrideDoc struct {
	Services map[string]struct {
		Ports       []string          `yaml:"ports"`
		GroupAdd    []string          `yaml:"group_add"`
		Environment map[string]string `yaml:"environment"`
		Labels      map[string]string `yaml:"labels"`
		Networks    map[string]*struct {
			IPv4    string   `yaml:"ipv4_address"`
			Aliases []string `yaml:"aliases"`
		} `yaml:"networks"`
		Volumes []yaml.Node `yaml:"volumes"`
	} `yaml:"services"`
	Networks map[string]map[string]any `yaml:"networks"`
	Volumes  map[string]map[string]any `yaml:"volumes"`
}

func decodeOverride(t *testing.T, s string) overrideDoc {
	t.Helper()
	var d overrideDoc
	if err := yaml.Unmarshal([]byte(s), &d); err != nil {
		t.Fatalf("%v\n%s", err, s)
	}
	return d
}

// mounts are a service's long-syntax mounts as source → target, ro.
func mountsOf(t *testing.T, vols []yaml.Node) map[string]struct {
	target, sub string
	ro          bool
} {
	t.Helper()
	out := map[string]struct {
		target, sub string
		ro          bool
	}{}
	for _, n := range vols {
		var m struct {
			Source   string `yaml:"source"`
			Target   string `yaml:"target"`
			ReadOnly bool   `yaml:"read_only"`
			Volume   struct {
				Subpath string `yaml:"subpath"`
			} `yaml:"volume"`
		}
		if n.Kind != yaml.MappingNode {
			continue
		}
		if err := n.Decode(&m); err != nil {
			t.Fatal(err)
		}
		out[m.Source] = struct {
			target, sub string
			ro          bool
		}{m.Target, m.Volume.Subpath, m.ReadOnly}
	}
	return out
}

// TestMailOverrideGoldens: the three modes of the stalwart-shaped
// fixture (UPDATE_GOLDEN=1 rewrites them).
func TestMailOverrideGoldens(t *testing.T) {
	f := mailOverrideFixture(t)
	for _, c := range []struct {
		mode mailMode
		name string
	}{{mailNormal, "mail_normal"}, {mailVoid, "mail_void"}, {mailUnwired, "mail_unwired"}} {
		ov := renderMail(t, f, c.mode)
		g := c.name + ".override.yml"
		if os.Getenv("UPDATE_GOLDEN") != "" {
			os.WriteFile(filepath.Join("testdata", "golden", g), []byte(ov), 0o644)
		} else if ov != golden(t, g) {
			t.Errorf("%s differs:\n%s", g, ov)
		}
	}
}

// TestMailNormalOverride: ports on the listener service only, the API
// attachment at the pinned address with its alias, the metrics aliases,
// group 2000, the env, the well-known router on PORTCULLIS_EP_CORE.
func TestMailNormalOverride(t *testing.T) {
	f := mailOverrideFixture(t)
	d := decodeOverride(t, renderMail(t, f, mailNormal))
	st, ad := d.Services["stalwart"], d.Services["adapter"]
	if strings.Join(st.Ports, " ") != "0.0.0.0:25:10025 0.0.0.0:465:10465 0.0.0.0:587:10587 0.0.0.0:993:10993" || len(ad.Ports) != 0 {
		t.Fatalf("ports %v %v", st.Ports, ad.Ports)
	}
	if n := ad.Networks[mailAPINetwork]; n == nil || n.IPv4 != "172.31.255.19" || strings.Join(n.Aliases, ",") != mailAPIAlias {
		t.Fatalf("api attachment %+v", ad.Networks)
	}
	if ad.Networks["internal"] == nil || ad.Networks[mailProxyNetwork] == nil {
		t.Fatalf("adapter keeps its networks and joins the proxy: %+v", ad.Networks)
	}
	if n := ad.Networks[mailMetricsNetwork]; n == nil || strings.Join(n.Aliases, ",") != mailMetricsAlias {
		t.Fatalf("metrics %+v", ad.Networks)
	}
	if n := st.Networks[mailMetricsNetwork]; n == nil || strings.Join(n.Aliases, ",") != mailServerMetricsAlias {
		t.Fatalf("server metrics %+v", st.Networks)
	}
	if _, ok := st.Networks[mailAPINetwork]; ok {
		t.Fatal("the listener service joined the API network")
	}
	for _, s := range []string{"stalwart", "adapter"} {
		sv := d.Services[s]
		if strings.Join(sv.GroupAdd, ",") != "2000" {
			t.Errorf("%s group_add %v", s, sv.GroupAdd)
		}
		if sv.Environment[VarMailSlotDir] != MailSlotMount || sv.Environment[VarMailTLSDir] != MailTLSMount ||
			sv.Environment[VarMailAPISubnet] != "172.31.255.16/28" || sv.Environment[VarMailAPIHubIP] != "172.31.255.18" ||
			sv.Environment[VarMailWellknownEntrypoints] != EntrypointsBoth {
			t.Errorf("%s env %v", s, sv.Environment)
		}
		if _, ok := sv.Environment[VarMailVoidSession]; ok {
			t.Errorf("%s: a void session in normal mode", s)
		}
	}
	l := ad.Labels
	pre := "traefik.http.routers." + MailWellknownRouter
	if l[pre+".rule"] != "Host(`mta-sts.example.org`) || Host(`autoconfig.example.org`) || Host(`autodiscover.example.org`)" ||
		l[pre+".entrypoints"] != EntrypointsBoth || l[pre+".middlewares"] != mailWellknownMiddlewares || l[pre+".tls.options"] != "public@file" ||
		l["traefik.http.services."+MailWellknownRouter+".loadbalancer.server.port"] != "8081" || len(st.Labels) != 0 {
		t.Fatalf("labels %v", l)
	}
	if _, ok := d.Services["resolver"]; ok {
		t.Fatal("the resolver (named by no field) was touched")
	}
	for _, n := range []string{mailAPINetwork, mailMetricsNetwork, mailProxyNetwork} {
		if d.Networks[n]["external"] != true || d.Networks[n]["name"] != n {
			t.Errorf("network %s: %v", n, d.Networks[n])
		}
	}
	// R-POD2: the whole slot volume, never hub_secrets.
	if d.Volumes[mailTLSVolumeKey]["name"] != mailTLSVolume || d.Volumes[mailProviderSlotVolumeKey]["name"] != mailProviderSlotVolume ||
		d.Volumes[mailProviderSlotVolumeKey]["external"] != true || d.Volumes[templates.SecretsVolumeKey] != nil {
		t.Fatalf("volumes %v", d.Volumes)
	}
}

// TestVoidModeNoPortsInternalNetworks: void mode has the API attachment,
// the mounts and the env with the void session, every template network
// internal, and no port, router or metrics attachment.
func TestVoidModeNoPortsInternalNetworks(t *testing.T) {
	f := mailOverrideFixture(t)
	ov := renderMail(t, f, mailVoid)
	d := decodeOverride(t, ov)
	for name, sv := range d.Services {
		if len(sv.Ports) > 0 || len(sv.Labels) > 0 {
			t.Errorf("%s: ports %v labels %v", name, sv.Ports, sv.Labels)
		}
		if _, ok := sv.Networks[mailMetricsNetwork]; ok {
			t.Errorf("%s joins the metrics network", name)
		}
		if _, ok := sv.Networks[mailProxyNetwork]; ok {
			t.Errorf("%s joins the proxy", name)
		}
	}
	if d.Services["adapter"].Networks[mailAPINetwork] == nil {
		t.Fatal("no API attachment in void mode")
	}
	for _, n := range []string{"internal", "egress", "default"} {
		if d.Networks[n]["internal"] != true {
			t.Errorf("network %s not internal: %v", n, d.Networks[n])
		}
	}
	for _, s := range []string{"stalwart", "adapter"} {
		if d.Services[s].Environment[VarMailVoidSession] != testVoidSession {
			t.Errorf("%s: void session %q", s, d.Services[s].Environment[VarMailVoidSession])
		}
		m := mountsOf(t, d.Services[s].Volumes)
		if m[mailTLSVolumeKey].target != MailTLSMount || !m[mailTLSVolumeKey].ro {
			t.Errorf("%s tls mount %+v", s, m)
		}
	}
	// The state's void owed renders void mode; a hold changes no mode
	// (R-HH1: it refuses ups instead).
	f.h.mu.Lock()
	f.h.st.Mail.VoidOwed = &state.MailVoid{Reason: state.MailVoidWire}
	mode := f.h.mailModeLocked(mailProviderID)
	f.h.st.Mail.VoidOwed, f.h.st.Mail.Held = nil, &state.MailHold{Reason: "template changed"}
	held := f.h.mailModeLocked(mailProviderID)
	f.h.st.Mail.Held = nil
	f.h.mu.Unlock()
	if mode != mailVoid || held != mailNormal {
		t.Fatalf("modes %v %v", mode, held)
	}
}

// TestUnwiredInstancePublishesNothing: an unwired mail instance's
// override adds nothing mail; the state's mode follows the wiring.
func TestUnwiredInstancePublishesNothing(t *testing.T) {
	f := mailOverrideFixture(t)
	ov := renderMail(t, f, mailUnwired)
	for _, s := range []string{"PORTCULLIS_MAIL", "ports:", mailAPINetwork, mailTLSVolume, "_mail", "group_add", "traefik"} {
		if strings.Contains(ov, s) {
			t.Errorf("unwired override has %q:\n%s", s, ov)
		}
	}
	f.h.mu.Lock()
	f.h.st.Mail.Provider.Instance = "other"
	m := f.h.mailModeLocked(mailProviderID)
	f.h.st.Mail.Provider = nil
	m2 := f.h.mailModeLocked(mailProviderID)
	f.h.mu.Unlock()
	if m != mailUnwired || m2 != mailUnwired {
		t.Fatalf("modes %v %v", m, m2)
	}
}

// TestNoIPv6Publish: no [::] line, IPv4 0.0.0.0 only.
func TestNoIPv6Publish(t *testing.T) {
	f := mailOverrideFixture(t)
	ov := renderMail(t, f, mailNormal)
	if strings.Contains(ov, "[::") || strings.Contains(ov, "::]") || strings.Count(ov, `"0.0.0.0:`) != 4 {
		t.Fatalf("%s", ov)
	}
}

// TestWellknownEntrypointsFollowVPNMode: apps mode → websecure,vpnsecure;
// server mode → vpnsecure, on the router and in the env alike.
func TestWellknownEntrypointsFollowVPNMode(t *testing.T) {
	f := mailOverrideFixture(t)
	for _, c := range []struct{ mode, want string }{{VPNModeApps, EntrypointsBoth}, {VPNModeServer, EntrypointsVPN}, {VPNModeAdmin, EntrypointsBoth}} {
		writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\n"+VarVPNMode+"="+c.mode+"\n")
		d := decodeOverride(t, renderMail(t, f, mailNormal))
		ad := d.Services["adapter"]
		if ad.Labels["traefik.http.routers."+MailWellknownRouter+".entrypoints"] != c.want || ad.Environment[VarMailWellknownEntrypoints] != c.want ||
			d.Services["stalwart"].Environment[VarMailWellknownEntrypoints] != c.want {
			t.Errorf("%s: %v %v", c.mode, ad.Labels, ad.Environment)
		}
	}
}

// TestMailTLSMountedOnlyIntoTLSServices and the _mail subpath into the
// gated services only, both read-only.
func TestMailTLSMountedOnlyIntoTLSServices(t *testing.T) {
	f := mailOverrideFixture(t)
	for _, mode := range []mailMode{mailNormal, mailVoid} {
		d := decodeOverride(t, renderMail(t, f, mode))
		for name, sv := range d.Services {
			m := mountsOf(t, sv.Volumes)
			_, tls := m[mailTLSVolumeKey]
			sec, gated := m[mailProviderSlotVolumeKey]
			if _, sub := m[templates.SecretsVolumeKey]; sub {
				t.Errorf("%v %s: hub_secrets mounted (R-POD2: never a subpath for mail)", mode, name)
			}
			want := name == "stalwart" || name == "adapter"
			if tls != want || gated != want {
				t.Errorf("%v %s: tls %v gated %v", mode, name, tls, gated)
			}
			if gated && (sec.target != MailSlotMount || sec.sub != "" || !sec.ro) {
				t.Errorf("%v %s: gate mount %+v", mode, name, sec)
			}
		}
	}
}

// TestHubSecretsMailSubpathOnlyGated and TestOtherInstanceMountingMailTLSRefused:
// the pre-up checks refuse the certificate outside the wired tls
// services or writable, and an unwired instance mounting it at all.
func TestOtherInstanceMountingMailTLSRefused(t *testing.T) {
	f := mailOverrideFixture(t)
	f.h.mu.RLock()
	tp := *f.h.findLocked(mailProviderID)
	f.h.mu.RUnlock()
	proj := func(svc string, ro bool) *types.Project {
		return &types.Project{Name: "portcullis-mailsrv",
			Volumes:  types.Volumes{"certs": {Name: mailTLSVolume, External: true}},
			Services: types.Services{svc: {Name: svc, Volumes: []types.ServiceVolumeConfig{{Type: types.VolumeTypeVolume, Source: "certs", Target: "/x", ReadOnly: ro}}}}}
	}
	if err := checkMailMounts(proj("stalwart", true), &tp, mailNormal); err != nil {
		t.Fatalf("the wired tls service refused: %v", err)
	}
	for _, c := range []struct {
		svc  string
		ro   bool
		mode mailMode
	}{{"stalwart", false, mailNormal}, {"resolver", true, mailNormal}, {"stalwart", true, mailUnwired}} {
		err := checkMailMounts(proj(c.svc, c.ro), &tp, c.mode)
		if se, ok := err.(*StatusError); !ok || se.Status != 409 {
			t.Errorf("%+v: %v", c, err)
		}
	}
	// Any other instance (no mail block) mounting it.
	other := templates.Template{ID: "grafana"}
	if err := checkMailMounts(proj("grafana", true), &other, mailUnwired); err == nil {
		t.Error("another instance mounted the mail certificate")
	}
}

// TestSlotPortCollision: while the slot is open no other instance may
// publish 25, 465, 587 or 993.
func TestSlotPortCollision(t *testing.T) {
	f := mailOverrideFixture(t)
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	tp := f.h.findLocked("grafana")
	for _, p := range []int{25, 465, 587, 993} {
		err := f.h.checkPortsLocked(tp, []portBinding{{Key: "X", Bind: "0.0.0.0", Port: p, Protocol: "tcp"}})
		if err == nil || !strings.Contains(err.Error(), "mail slot is open") {
			t.Errorf("%d: %v", p, err)
		}
	}
	if err := f.h.checkPortsLocked(tp, []portBinding{{Key: "X", Bind: "0.0.0.0", Port: 588, Protocol: "tcp"}}); err != nil {
		t.Errorf("588: %v", err)
	}
}

// TestNoRestartCoreService: the runtime has no verb on a core container.
func TestNoRestartCoreService(t *testing.T) {
	it := reflect.TypeOf((*runtime.Instances)(nil)).Elem()
	if _, ok := it.MethodByName("RestartCoreService"); ok {
		t.Fatal("runtime.Instances still has RestartCoreService")
	}
	if _, ok := it.MethodByName("RestartService"); !ok {
		t.Fatal("no RestartService")
	}
}

// TestMailCoreEnvStrict: core.env's mail keys (Task 20's names) are
// validated strictly; a bad value closes the slot (fail closed).
func TestMailCoreEnvStrict(t *testing.T) {
	ok := map[string]string{VarMail: "on", VarMailHostname: "mail.example.org", VarMailSubmissionLANOnly: "false", VarMailClientIP: "preserved",
		VarMailAPISubnet: "172.31.255.16/28", VarMailAPIHubIP: "172.31.255.18", VarMailAPIProviderIP: "172.31.255.19"}
	m := parseMailCore(ok, "example.org")
	if !m.On || m.Err != "" || m.ClientIPRewritten || m.ProviderIP.String() != "172.31.255.19" || m.Hostname != "mail.example.org" {
		t.Fatalf("%+v", m)
	}
	for k, v := range map[string]string{VarMail: "yes", VarMailHostname: "mail_x.example.org", VarMailSubmissionLANOnly: "1", VarMailClientIP: "nat",
		VarMailAPISubnet: "172.31.255.17/28", VarMailAPIHubIP: "172.31.254.18", VarMailAPIProviderIP: "172.31.255.18"} {
		bad := maps.Clone(ok)
		bad[k] = v
		if m := parseMailCore(bad, "example.org"); m.On || !strings.Contains(m.Err, k) {
			t.Errorf("%s=%s: %+v", k, v, m)
		}
	}
	for _, v := range []string{"172.31.255.16", "172.31.255.31"} { // network, broadcast
		bad := maps.Clone(ok)
		bad[VarMailAPIProviderIP] = v
		if m := parseMailCore(bad, "example.org"); m.On {
			t.Errorf("provider at %s accepted", v)
		}
	}
	// Absent keys: the defaults; an absent client mode counts rewritten.
	m = parseMailCore(map[string]string{VarMail: "on"}, "example.org")
	if !m.On || m.Err != "" || !m.ClientIPRewritten || m.Hostname != "mail.example.org" || !m.HostnameMissing || m.APISubnet != DefaultMailAPISubnet {
		t.Fatalf("defaults %+v", m)
	}
}

// TestHubSecretsMailSubpathOnlyGated: the pre-up check passes the wired
// provider's own override and refuses the _mail subpath anywhere else,
// another subpath, a writable mount, or the certificate on another
// service (custom overrides stored without their save checks).
func TestHubSecretsMailSubpathOnlyGated(t *testing.T) {
	f := mailOverrideFixture(t)
	f.h.mu.Lock()
	tp := f.h.findLocked(mailProviderID)
	err := f.h.generateOverrideLocked(tp, f.h.st.Settings[mailProviderID])
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	live := func() *templates.Template { return f.h.Template(mailProviderID) }
	if err := f.h.checkSecretsMounts(t.Context(), live()); err != nil {
		t.Fatalf("the Hub's own mounts refused: %v", err)
	}
	mount := func(svc, src, target, sub string, ro bool) string {
		s := "services:\n  " + svc + ":\n    volumes:\n      - type: volume\n        source: " + src + "\n        target: " + target + "\n        read_only: " + map[bool]string{true: "true", false: "false"}[ro] + "\n"
		if sub != "" {
			s += "        volume: {subpath: " + sub + "}\n"
		}
		return s
	}
	for name, ov := range map[string]string{
		"slot on a non-gated service": mount("resolver", mailProviderSlotVolumeKey, "/x", "", true),
		"slot by a subpath":           mount("stalwart", mailProviderSlotVolumeKey, "/y", "x", true),
		"writable slot":               mount("adapter", mailProviderSlotVolumeKey, MailSlotMount, "", false),
		"certificate on the resolver": mount("resolver", mailTLSVolumeKey, "/tls", "", true),
		"certificate writable":        mount("stalwart", mailTLSVolumeKey, MailTLSMount, "", false),
	} {
		writeFile(t, f.h.userOverridePath(mailProviderID), ov)
		err := f.h.checkSecretsMounts(t.Context(), live())
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 409 {
			t.Errorf("%s: %v, want 409", name, err)
		}
	}
	os.Remove(f.h.userOverridePath(mailProviderID))
	// Unwired, the same rendered gate mount is refused.
	f.h.mu.Lock()
	f.h.st.Mail.Provider = nil
	f.h.mu.Unlock()
	if err := f.h.checkSecretsMounts(t.Context(), live()); err == nil {
		t.Fatal("an unwired instance's gate mount passed")
	}
}

// TestClosedSlotRendersNoPorts (L18): a wired provider with the slot
// closed renders void mode (no public listeners).
func TestClosedSlotRendersNoPorts(t *testing.T) {
	f := mailOverrideFixture(t)
	f.h.SetMailCoreForTest(false, "mail.example.org")
	f.h.mu.RLock()
	mode := f.h.mailModeLocked(mailProviderID)
	f.h.mu.RUnlock()
	if mode != mailVoid {
		t.Fatalf("mode %v", mode)
	}
}

// TestRenderRefusesTemplateCoreNetwork (FH-H1, post-render): a template
// whose compose declares a core network the Hub's override joins never
// renders (its attributes would merge into the Hub's entry).
func TestRenderRefusesTemplateCoreNetwork(t *testing.T) {
	f := mailOverrideFixture(t)
	tp := f.h.Template(mailProviderID)
	b, err := os.ReadFile(tp.ComposePath())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, tp.ComposePath(), strings.Replace(string(b), "\nnetworks:\n", "\nnetworks:\n  portcullis-mail-api:\n    internal: true\n", 1))
	f.h.mu.Lock()
	_, err = f.h.mailRenderLocked(f.h.findLocked(mailProviderID), mailNormal)
	f.h.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "core network") {
		t.Fatalf("%v", err)
	}
}

// TestMailPublicIPsPassed (final cross review M2): core.env's
// PORTCULLIS_MAIL_PUBLIC_IPV4/IPV6 reach every service the block names
// (empty when unknown); no other public-address key of core's does; a
// malformed one closes the slot like any mail key.
func TestMailPublicIPsPassed(t *testing.T) {
	f := mailOverrideFixture(t)
	m := parseMailCore(map[string]string{VarMail: "on", VarMailPublicIPv4: "203.0.113.10", VarMailPublicIPv6: "2001:db8::10",
		"PORTCULLIS_PUBLIC_IPV4": "198.51.100.1"}, "example.org")
	if m.Err != "" || m.PublicIPv4 != "203.0.113.10" || m.PublicIPv6 != "2001:db8::10" {
		t.Fatalf("%+v", m)
	}
	f.h.mailCoreForTest.Store(&m)
	ov := renderMail(t, f, mailNormal)
	if strings.Count(ov, VarMailPublicIPv4+`: "203.0.113.10"`) == 0 || strings.Count(ov, VarMailPublicIPv6+`: "2001:db8::10"`) == 0 {
		t.Fatalf("public addresses not passed:\n%s", ov)
	}
	if strings.Contains(ov, "198.51.100.1") || strings.Contains(ov, "PORTCULLIS_PUBLIC_IPV4") {
		t.Fatal("another core public-address key passed")
	}
	for k, v := range map[string]string{VarMailPublicIPv4: "2001:db8::1", VarMailPublicIPv6: "203.0.113.1"} {
		bad := map[string]string{VarMail: "on", k: v}
		if m := parseMailCore(bad, "example.org"); m.On || !strings.Contains(m.Err, k) {
			t.Errorf("%s=%s: %+v", k, v, m)
		}
	}
	for _, v := range []string{"not-an-ip", "fe80::1%eth0", "::ffff:203.0.113.1"} {
		if m := parseMailCore(map[string]string{VarMail: "on", VarMailPublicIPv6: v}, "example.org"); m.On {
			t.Errorf("IPv6 %q accepted", v)
		}
	}
}

// TestMailSubnetOverlapRefused (final cross review L9): a provider
// network whose ipam subnet overlaps a range core reserves is refused at
// wiring and at render (409, naming the subnet); Docker's default pools
// aren't a conflict; an unreadable reserved list refuses (fail closed).
func TestMailSubnetOverlapRefused(t *testing.T) {
	f := mailOverrideFixture(t)
	tp := f.h.Template(mailProviderID)
	c := strings.Replace(string(tp.ReadCompose()), "  internal: {internal: true}\n",
		"  internal:\n    internal: true\n    ipam:\n      config:\n        - subnet: 172.31.255.0/28\n", 1)
	if !strings.Contains(c, "172.31.255.0/28") {
		t.Fatal("fixture compose changed")
	}
	writeFile(t, tp.ComposePath(), c)
	core := filepath.Join(f.h.cfg.ProjectDir, ".env")
	refusal := func() []string {
		f.h.mu.Lock()
		defer f.h.mu.Unlock()
		return f.h.mailSubnetRefusals(f.h.findLocked(mailProviderID))
	}
	// Core's reserved list as core writes it: the broad pools and core's
	// subnets, none of them the template's.
	writeFile(t, core, "PORTCULLIS_VPN_RESERVED_RANGES=172.16.0.0/12 192.168.0.0/16 10.214.0.0/24 172.31.250.0/24 172.31.255.16/28\n")
	if r := refusal(); len(r) != 0 {
		t.Fatalf("clear subnet refused: %v", r)
	}
	renderMail(t, f, mailNormal)
	// A VPN pool moved onto the template's subnet.
	writeFile(t, core, "PORTCULLIS_VPN_RESERVED_RANGES=172.16.0.0/12 192.168.0.0/16 172.31.255.8/29\n")
	want := "the provider's network internal has subnet 172.31.255.0/28, which overlaps core's reserved range 172.31.255.8/29: pick another subnet in the template"
	if r := refusal(); len(r) != 1 || r[0] != want {
		t.Fatalf("refusal %q", r)
	}
	f.h.mu.Lock()
	_, err := f.h.mailRenderLocked(f.h.findLocked(mailProviderID), mailNormal)
	wire := f.h.mailWireRefusalsLocked(f.h.findLocked(mailProviderID), "")
	f.h.mu.Unlock()
	if statusOf(err) != 409 || err.Error() != want {
		t.Fatalf("render: %v", err)
	}
	if !slices.Contains(wire, want) {
		t.Fatalf("wiring refusals %q", wire)
	}
	// The mail API subnet moved there (core.env).
	writeFile(t, core, "PORTCULLIS_MAIL_API_SUBNET=172.31.255.0/28\nPORTCULLIS_VPN_RESERVED_RANGES=172.16.0.0/12\n")
	f.h.mailCoreForTest.Store(nil)
	if r := refusal(); len(r) != 1 || !strings.Contains(r[0], "overlaps core's reserved range 172.31.255.0/28") {
		t.Fatalf("API subnet: %q", r)
	}
	// Unreadable: refused.
	writeFile(t, core, "PORTCULLIS_VPN_RESERVED_RANGES=not-a-cidr\n")
	if r := refusal(); len(r) != 1 || !strings.Contains(r[0], "can't be read") {
		t.Fatalf("unreadable: %q", r)
	}
}

// TestMailAdminViewOverride (contract §19.1, §19.13): a block with
// admin_view gets, in normal mode, portcullis-proxy and the two admin
// routers (the Hub's admin chain, authaware TLS) on that service, the
// admin host on every named service and the pinned SPKIs on the view
// only; the websecure router goes in the VPN modes admin and server;
// void and unwired modes route nothing.
func TestMailAdminViewOverride(t *testing.T) {
	f := newMailSlotFixtureFrom(t, mailVectorFiles(t, "admin_view ok"), true)
	f.h.SetMailCoreForTest(true, "mail.example.org")
	f.h.mu.Lock()
	f.h.st.Mail.TLS = state.MailTLS{SPKISHA256: []string{strings.Repeat("ab", 32), strings.Repeat("cd", 32)}}
	f.h.mu.Unlock()
	host := "mail-admin." + f.h.cfg.Domain
	d := decodeOverride(t, renderMail(t, f, mailNormal))
	av := d.Services["admin-view"]
	if _, ok := av.Networks[mailProxyNetwork]; !ok {
		t.Fatalf("admin-view not on %s: %v", mailProxyNetwork, av.Networks)
	}
	want := map[string]string{
		"traefik.enable":         "true",
		"traefik.docker.network": mailProxyNetwork,
		"traefik.http.routers." + MailAdminRouter + ".rule":                      "Host(`" + host + "`)",
		"traefik.http.routers." + MailAdminRouter + ".entrypoints":               "websecure",
		"traefik.http.routers." + MailAdminRouter + ".middlewares":               mailAdminMiddlewares,
		"traefik.http.routers." + MailAdminRouter + ".tls":                       "true",
		"traefik.http.routers." + MailAdminRouter + ".tls.options":               "authaware@file",
		"traefik.http.routers." + MailAdminRouter + ".service":                   MailAdminRouter,
		"traefik.http.routers." + MailAdminRouter + "-vpn.rule":                  "Host(`" + host + "`)",
		"traefik.http.routers." + MailAdminRouter + "-vpn.entrypoints":           "vpnsecure",
		"traefik.http.routers." + MailAdminRouter + "-vpn.middlewares":           mailAdminMiddlewaresVPN,
		"traefik.http.routers." + MailAdminRouter + "-vpn.tls":                   "true",
		"traefik.http.routers." + MailAdminRouter + "-vpn.tls.options":           "authaware@file",
		"traefik.http.routers." + MailAdminRouter + "-vpn.service":               MailAdminRouter,
		"traefik.http.services." + MailAdminRouter + ".loadbalancer.server.port": "8090",
	}
	// The route key: one per install, set by the router after forward-auth
	// and group-gate, and handed to the proxy with Traefik's address.
	key := av.Environment[VarMailAdminRouteKey]
	if len(key) != 48 || av.Labels["traefik.http.middlewares."+MailAdminKeyMiddleware+".headers.customrequestheaders."+MailAdminKeyHeader] != key {
		t.Fatalf("route key %q / label %v", key, av.Labels)
	}
	want["traefik.http.middlewares."+MailAdminKeyMiddleware+".headers.customrequestheaders."+MailAdminKeyHeader] = key
	if av.Environment[VarMailAdminGroup] != "lldap_admin" {
		t.Fatalf("admin group %q", av.Environment[VarMailAdminGroup])
	}
	if av.Environment[VarMailAdminTraefikIP] != "172.31.250.2" {
		t.Fatalf("Traefik IP %q", av.Environment[VarMailAdminTraefikIP])
	}
	for _, chain := range []string{mailAdminMiddlewares, mailAdminMiddlewaresVPN} {
		g := strings.Index(chain, "portcullis-groups")
		k := strings.Index(chain, MailAdminKeyMiddleware+"@docker")
		if g < 0 || k < g {
			t.Errorf("the key is set before group-gate: %s", chain)
		}
	}
	if again := decodeOverride(t, renderMail(t, f, mailNormal)).Services["admin-view"].Environment[VarMailAdminRouteKey]; again != key {
		t.Fatal("the route key changed between renders")
	}
	for _, s := range []string{"stalwart", "adapter"} {
		if strings.Contains(renderMail(t, f, mailNormal), "\n      "+VarMailAdminRouteKey) && d.Services[s].Environment[VarMailAdminRouteKey] != "" {
			t.Errorf("%s got the route key", s)
		}
	}
	if !reflect.DeepEqual(av.Labels, want) {
		t.Fatalf("admin-view labels\n got %v\nwant %v", av.Labels, want)
	}
	if !strings.Contains(mailAdminMiddlewares, "portcullis-auth@docker,portcullis-groups@docker") || !strings.Contains(mailAdminMiddlewaresVPN, "portcullis-groups-vpn@docker") {
		t.Fatal("the admin chain lost forward-auth or group-gate")
	}
	if av.Environment[VarMailTLSSPKI] != strings.Repeat("ab", 32)+","+strings.Repeat("cd", 32) || av.Environment[VarMailAdminHost] != host {
		t.Fatalf("admin-view env %v", av.Environment)
	}
	for _, s := range []string{"stalwart", "adapter"} {
		e := d.Services[s].Environment
		if e[VarMailAdminHost] != host || e[VarMailTLSSPKI] != "" {
			t.Errorf("%s env %v", s, e)
		}
	}
	// The view gets no certificate, slot file, group 2000 or core network
	// beyond portcullis-proxy.
	if len(av.Volumes) != 0 || len(av.GroupAdd) != 0 || av.Networks[mailAPINetwork] != nil || av.Networks[mailMetricsNetwork] != nil {
		t.Fatalf("admin-view got %v %v %v", av.Volumes, av.GroupAdd, av.Networks)
	}
	if len(d.Services["adapter"].Labels) == 0 || d.Services["adapter"].Labels["traefik.http.routers."+MailAdminRouter+".rule"] != "" {
		t.Fatal("the admin router is on the adapter")
	}
	for _, m := range []string{VPNModeAdmin, VPNModeServer} {
		writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\n"+VarVPNMode+"="+m+"\n")
		l := decodeOverride(t, renderMail(t, f, mailNormal)).Services["admin-view"].Labels
		if l["traefik.http.routers."+MailAdminRouter+".rule"] != "" || l["traefik.http.routers."+MailAdminRouter+"-vpn.entrypoints"] != "vpnsecure" {
			t.Errorf("VPN mode %s: %v", m, l)
		}
	}
	for _, mode := range []mailMode{mailVoid, mailUnwired} {
		ov := renderMail(t, f, mode)
		if strings.Contains(ov, MailAdminRouter) || strings.Contains(ov, VarMailTLSSPKI) {
			t.Errorf("%s routes the admin view:\n%s", mode, ov)
		}
	}
	// The plain stalwart-shaped block has no admin view at all.
	if ov := renderMail(t, mailOverrideFixture(t), mailNormal); strings.Contains(ov, MailAdminRouter) || strings.Contains(ov, VarMailAdminHost) {
		t.Fatal("a block without admin_view rendered the admin view")
	}
}

// TestMailAdminViewPolicy (contract §19.13): the wired provider's admin
// view host is published with the group lldap_admin while it is routed
// (normal mode) and never otherwise, and no app may take the host while
// mail is on.
func TestMailAdminViewPolicy(t *testing.T) {
	f := newMailSlotFixtureFrom(t, mailVectorFiles(t, "admin_view ok"), true)
	f.h.SetMailCoreForTest(true, "mail.example.org")
	f.h.mu.Lock()
	f.h.st.Enabled = append(f.h.st.Enabled, mailProviderID)
	for i := range f.h.instances {
		if f.h.instances[i].ID == mailProviderID {
			f.h.instances[i].Enabled = true
		}
	}
	f.h.mu.Unlock()
	host := "mail-admin." + f.h.cfg.Domain
	read := func() map[string]any {
		if err := f.h.WritePolicy(); err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(readFile(t, f.h.policyPath())), &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	doc := read()
	groups, _ := doc["groups"].(map[string]any)
	hosts, _ := doc["hosts"].(map[string]any)
	if groups[host] != "lldap_admin" || hosts[host] == nil {
		t.Fatalf("admin view host not published for admins: groups %v hosts %v", groups, hosts)
	}
	// Void mode: no router, nothing published.
	f.h.mu.Lock()
	f.h.st.Mail.VoidOwed = &state.MailVoid{Reason: "wire"}
	f.h.mu.Unlock()
	doc = read()
	if g, _ := doc["groups"].(map[string]any); g[host] != nil {
		t.Fatalf("published in void mode: %v", g)
	}
	for h, want := range map[string]bool{host: true, "x." + host: true, "mail-adminx." + f.h.cfg.Domain: false} {
		if got := f.h.mailAdminReserved(h, true) != ""; got != want {
			t.Errorf("%s reserved %v, want %v", h, got, want)
		}
	}
	if f.h.mailAdminReserved(host, false) != "" {
		t.Error("reserved with mail off")
	}
}

// The admin view's ticket format is mailctl's (viewer.MintTicket): the
// shared vector of mailctl's ticket_vector_test.go.
func TestMailAdminTicketVector(t *testing.T) {
	got := MailAdminTicket(strings.Repeat("k", 40), "root", "nonce-1", time.Unix(1800000060, 0))
	if got != "v1.eyJ1Ijoicm9vdCIsIm4iOiJub25jZS0xIiwiZSI6MTgwMDAwMDA2MH0.h2gtGNmy3A1GfbF6Moa38GqR-VZE79oSyYECzGzrUCs" {
		t.Fatalf("ticket %s", got)
	}
}

// TestMailAdminViewURL (contract §19.13): the Open action's link carries
// a single-use ticket for the actor, MAC'd with the route key the view
// gets, ≤ 60 s; every call a new one; audited with the nonce.
func TestMailAdminViewURL(t *testing.T) {
	f := newMailSlotFixtureFrom(t, mailVectorFiles(t, "admin_view ok"), true)
	f.h.SetMailCoreForTest(true, "mail.example.org")
	u1, err := f.h.MailAdminViewURL(directory.Actor{User: "root"})
	if err != nil {
		t.Fatal(err)
	}
	u2, _ := f.h.MailAdminViewURL(directory.Actor{User: "root"})
	pre := "https://mail-admin." + f.h.cfg.Domain + "/portcullis/open?t="
	if !strings.HasPrefix(u1, pre) || u1 == u2 {
		t.Fatalf("links %s %s", u1, u2)
	}
	key, _ := f.h.mailAdminRouteKey()
	tk, _ := url.QueryUnescape(strings.TrimPrefix(u1, pre))
	parts := strings.Split(tk, ".")
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var body struct {
		U, N string
		E    int64
	}
	json.Unmarshal(b, &body)
	if body.U != "root" || len(body.N) < 16 || time.Until(time.Unix(body.E, 0)) > MailAdminTicketTTL || MailAdminTicket(key, "root", body.N, time.Unix(body.E, 0)) != tk {
		t.Fatalf("ticket %+v", body)
	}
	if _, err := f.h.MailAdminViewURL(directory.Actor{}); err == nil {
		t.Fatal("a link without a user")
	}
}
