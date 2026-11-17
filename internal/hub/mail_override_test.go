package hub

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"gopkg.in/yaml.v3"

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
	writeFile(t, filepath.Join(f.h.cfg.SecretsDir, mailProviderID, "_mail", "void-session"), testVoidSession+"\n")
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
	if d.Volumes[mailTLSVolumeKey]["name"] != mailTLSVolume || d.Volumes[templates.SecretsVolumeKey]["external"] != true {
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
			sec, gated := m[templates.SecretsVolumeKey]
			want := name == "stalwart" || name == "adapter"
			if tls != want || gated != want {
				t.Errorf("%v %s: tls %v gated %v", mode, name, tls, gated)
			}
			if gated && (sec.target != MailSlotMount || sec.sub != "mailsrv/_mail" || !sec.ro) {
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
		"gate on a non-gated service": mount("resolver", templates.SecretsVolumeKey, "/x", "mailsrv/_mail", true),
		"another instance's gate":     mount("stalwart", templates.SecretsVolumeKey, "/y", "other/_mail", true),
		"writable gate":               mount("adapter", templates.SecretsVolumeKey, MailSlotMount, "mailsrv/_mail", false),
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
