package hub

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/templates"
)

// mailRender is what the override adds for a mail template's instance
// (contract §19.1): per service its environment lines, groups, mounts,
// network attachments, ports and labels, and the top-level networks and
// volumes those need. The zero value adds nothing (mode unwired).
type mailRender struct {
	mode     mailMode
	env      map[string][]string
	groups   map[string]bool
	mounts   map[string][]string
	networks map[string]map[string]string // service → network → its YAML body (" {}" or "\n" and a mapping)
	ports    map[string][]string
	labels   map[string]map[string]string
	// topNetworks: network key → its top-level YAML body.
	topNetworks map[string]string
	// tlsVolume / secretsVolume: the top-level volumes to declare.
	tlsVolume, secretsVolume bool
}

// services are every service the render touches, sorted.
func (r *mailRender) services() []string {
	set := map[string]bool{}
	for _, m := range []map[string][]string{r.env, r.mounts, r.ports} {
		for s := range m {
			set[s] = true
		}
	}
	for s := range r.groups {
		set[s] = true
	}
	for s := range r.networks {
		set[s] = true
	}
	for s := range r.labels {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// mailEntrypointsLocked is PORTCULLIS_EP_CORE as core derives it from
// the VPN mode (contract §5): vpnsecure in server mode, else websecure
// and vpnsecure. The well-known router follows it with no public
// exception (user ruling 2026-11-15).
func (h *Hub) mailEntrypointsLocked() string {
	if h.vpnCoreEnv().Mode == VPNModeServer {
		return EntrypointsVPN
	}
	return EntrypointsBoth
}

// mailVoidSession is the instance's void-session nonce ("" = none).
func (h *Hub) mailVoidSession(id string) string {
	dir := h.mailSlotDir(id)
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, mailGateFileVoidSession))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if !voidSessionRe.MatchString(s) {
		return ""
	}
	return s
}

// voidSessionRe is a void-session nonce (32 bytes, hex).
var voidSessionRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// topLevelNetworks are compose's top-level network keys in file order and
// whether each is external.
func topLevelNetworks(compose []byte) (names []string, external map[string]bool) {
	names, external, _ = topLevelNetworkFlags(compose)
	return names, external
}

// topLevelNetworkFlags is topLevelNetworks with each network's internal
// flag as declared.
func topLevelNetworkFlags(compose []byte) (names []string, external, internal map[string]bool) {
	external, internal = map[string]bool{}, map[string]bool{}
	var doc yaml.Node
	if yaml.Unmarshal(compose, &doc) != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, external, internal
	}
	top := doc.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value != "networks" || top.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		nets := top.Content[i+1]
		for j := 0; j+1 < len(nets.Content); j += 2 {
			n := nets.Content[j].Value
			names = append(names, n)
			body := nets.Content[j+1]
			for k := 0; body.Kind == yaml.MappingNode && k+1 < len(body.Content); k += 2 {
				if body.Content[k].Value == "external" && body.Content[k+1].Value != "false" {
					external[n] = true
				}
				if body.Content[k].Value == "internal" && body.Content[k+1].Value == "true" {
					internal[n] = true
				}
			}
		}
	}
	return names, external, internal
}

// mailRenderLocked is the mail part of t's override in mode (contract
// §19.1). Caller must hold mu.
func (h *Hub) mailRenderLocked(t *templates.Template, mode mailMode) (*mailRender, error) {
	r := &mailRender{mode: mode}
	b := t.Manifest.Mail
	if b == nil || mode == mailUnwired {
		return r, nil
	}
	core := h.mailCore()
	r.env, r.groups, r.mounts = map[string][]string{}, map[string]bool{}, map[string][]string{}
	r.networks, r.ports, r.labels = map[string]map[string]string{}, map[string][]string{}, map[string]map[string]string{}
	r.topNetworks = map[string]string{}
	compose := t.ReadCompose()
	svcNets := templates.ServiceNetworks(compose)
	attach := func(svc, net, body string) {
		if r.networks[svc] == nil {
			r.networks[svc] = map[string]string{}
			// The service keeps its own networks (an implicit default
			// included): an override's networks: replaces the implicit one.
			own := svcNets[svc].Networks
			if len(own) == 0 {
				own = []string{"default"}
			}
			for _, n := range own {
				r.networks[svc][n] = " {}"
			}
		}
		r.networks[svc][net] = body
	}
	// The environment, on every service the block names.
	named := map[string]bool{b.API.Service: true, b.Listeners.Service: true, b.Wellknown.Service: true, b.Metrics.Service: true, b.Sessions.Restart: true}
	if b.ServerMetrics != nil {
		named[b.ServerMetrics.Service] = true
	}
	if b.Export != nil {
		named[b.Export.Service] = true
	}
	for _, s := range append(slices.Clone(b.TLS), b.Gated...) {
		named[s] = true
	}
	env := []string{
		VarMailAPISubnet + ": " + yamlQuote(core.APISubnet.String()),
		VarMailAPIHubIP + ": " + yamlQuote(core.HubIP.String()),
		VarMailSlotDir + ": " + yamlQuote(MailSlotMount),
		VarMailTLSDir + ": " + yamlQuote(MailTLSMount),
		VarMailWellknownEntrypoints + ": " + yamlQuote(h.mailEntrypointsLocked()),
	}
	if mode == mailVoid {
		if nonce := h.mailVoidSession(t.ID); nonce != "" {
			env = append(env, VarMailVoidSession+": "+yamlQuote(nonce))
		}
	}
	for s := range named {
		if s != "" {
			r.env[s] = append(r.env[s], env...)
		}
	}
	// The certificate (tls), the gate files (gated), group 2000 on both.
	for _, s := range b.TLS {
		r.groups[s] = true
		r.tlsVolume = true
		r.mounts[s] = append(r.mounts[s], "type: volume\n"+
			"        source: "+mailTLSVolumeKey+"\n"+
			"        target: "+MailTLSMount+"\n"+
			"        read_only: true")
	}
	for _, s := range b.Gated {
		r.groups[s] = true
		r.secretsVolume = true
		r.mounts[s] = append(r.mounts[s], secretsMountEntry(MailSlotMount, mailSlotDirRel(t.ID)))
	}
	// The API attachment, at the pinned address with the alias.
	attach(b.API.Service, mailAPINetwork, "\n        ipv4_address: "+core.ProviderIP.String()+"\n        aliases:\n          - "+mailAPIAlias)
	r.topNetworks[mailAPINetwork] = "\n    external: true\n    name: " + mailAPINetwork
	if mode == mailVoid {
		// Every network of the template internal: no egress, no inbound.
		names, external := topLevelNetworks(compose)
		if !slices.Contains(names, "default") {
			names = append(names, "default")
		}
		for _, n := range names {
			if external[n] {
				return nil, fmt.Errorf("mail: void mode can't make the external network %s internal", n)
			}
			r.topNetworks[n] = "\n    internal: true"
		}
		return r, nil
	}
	// Normal mode: the ports, the metrics attachments, the well-known
	// router.
	l := b.Listeners
	for _, p := range [][2]int{{25, l.SMTP}, {465, l.Submissions}, {587, l.Submission}, {993, l.IMAPS}} {
		r.ports[l.Service] = append(r.ports[l.Service], yamlQuote("0.0.0.0:"+strconv.Itoa(p[0])+":"+strconv.Itoa(p[1])))
	}
	attach(b.Metrics.Service, mailMetricsNetwork, "\n        aliases:\n          - "+mailMetricsAlias)
	if sm := b.ServerMetrics; sm != nil {
		if sm.Service == b.Metrics.Service {
			r.networks[sm.Service][mailMetricsNetwork] = "\n        aliases:\n          - " + mailMetricsAlias + "\n          - " + mailServerMetricsAlias
		} else {
			attach(sm.Service, mailMetricsNetwork, "\n        aliases:\n          - "+mailServerMetricsAlias)
		}
	}
	r.topNetworks[mailMetricsNetwork] = "\n    external: true\n    name: " + mailMetricsNetwork
	if hosts := h.mailWellknownHostsLocked(); len(hosts) > 0 {
		s := b.Wellknown.Service
		attach(s, mailProxyNetwork, " {}")
		r.topNetworks[mailProxyNetwork] = "\n    external: true\n    name: " + mailProxyNetwork
		rule := make([]string, len(hosts))
		for i, x := range hosts {
			rule[i] = "Host(`" + x + "`)"
		}
		pre := "traefik.http.routers." + MailWellknownRouter
		r.labels[s] = map[string]string{
			"traefik.enable":         "true",
			"traefik.docker.network": mailProxyNetwork,
			pre + ".rule":            strings.Join(rule, " || "),
			pre + ".entrypoints":     h.mailEntrypointsLocked(),
			pre + ".tls":             "true",
			pre + ".tls.options":     mailWellknownTLSOptions,
			pre + ".middlewares":     mailWellknownMiddlewares,
			pre + ".service":         MailWellknownRouter,
			"traefik.http.services." + MailWellknownRouter + ".loadbalancer.server.port": strconv.Itoa(b.Wellknown.Port),
		}
	}
	return r, nil
}

// mailWellknownHostsLocked are mta-sts., autoconfig. and autodiscover.
// of every mail domain on or draining, sorted by domain. Caller must
// hold mu.
func (h *Hub) mailWellknownHostsLocked() []string {
	var out []string
	for _, e := range h.mailDomainsLocked(h.mailOn()) {
		for _, l := range []string{"mta-sts", "autoconfig", "autodiscover"} {
			out = append(out, l+"."+e)
		}
	}
	return out
}

// mailOverrideLocked renders instance id's whole override with the mail
// part in mode (the goldens and the mode tests). Caller must hold mu.
func (h *Hub) mailOverrideLocked(t *templates.Template, id string, mode mailMode) (string, error) {
	if t.ID != id {
		return "", fmt.Errorf("instance %s: the view is %s's", id, t.ID)
	}
	h.mailModeForRender = &mode
	defer func() { h.mailModeForRender = nil }()
	return h.renderOverrideLocked(t, h.st.Settings[id])
}

// mailRenderModeLocked is the mode the render uses for t (the forced
// one in mailOverrideLocked, else the state's).
func (h *Hub) mailRenderModeLocked(t *templates.Template) mailMode {
	if t.Manifest.Mail == nil {
		return mailUnwired
	}
	if h.mailModeForRender != nil {
		return *h.mailModeForRender
	}
	return h.mailModeLocked(t.ID)
}

// Ruling T8-void (coordinator): the Hub owns the void-mode network flip.
// (1) Before an up that changes a mail provider's mode (normal ↔ void;
// an unknown previous mode counts as a change) the project goes down,
// volumes kept, so compose recreates its networks. (2) After the up every
// template network's internal flag on the engine must match the mode
// (void: all internal; normal: as the template declares): else the
// instance is stopped and the error kept for the doctor.

// mailUpModes are the modes each mail instance was last brought up in.
type mailUpModes struct {
	mu sync.Mutex
	m  map[string]mailMode
}

// mailModeBeforeUp downs t's project when its mode changes; answers the
// mode the up renders. Caller holds the app lock.
func (h *Hub) mailModeBeforeUp(ctx context.Context, t *templates.Template) (mailMode, error) {
	h.mu.Lock()
	mode := h.mailRenderModeLocked(t)
	wired := h.st.Mail.Provider != nil && h.st.Mail.Provider.Instance == t.ID
	// Right before the up again: the hold (R-HH3) and one mode per up
	// (the override was rendered in rendered; a change since is refused).
	err := h.mailHoldGateLocked(t)
	h.mu.Unlock()
	h.mailRendered.mu.Lock()
	rendered, known := h.mailRendered.m[t.ID]
	h.mailRendered.mu.Unlock()
	if err != nil {
		return mode, err
	}
	if known && rendered != mode {
		return mode, statusErr(http.StatusConflict, "%s's mail mode changed to %s during the start: try again", t.ID, mode)
	}
	if wired && !mailRestoreCommitted(ctx, t.ID) && h.mailRestoreHolds(t.ID) {
		return mode, errMailRestorePending
	}
	h.mailUpModes.mu.Lock()
	prev, known := h.mailUpModes.m[t.ID]
	h.mailUpModes.mu.Unlock()
	if known && prev == mode {
		return mode, nil
	}
	if mode == mailUnwired && !known {
		// An ordinary app's first up (never wired since this start):
		// nothing to flip.
		return mode, nil
	}
	if err := h.composeDown(t); err != nil {
		return mode, fmt.Errorf("taking %s down before its mail mode changes to %s: %w", t.ID, mode, err)
	}
	return mode, nil
}

// mailModeAfterUp records mode and checks the engine's networks.
func (h *Hub) mailModeAfterUp(ctx context.Context, t *templates.Template, mode mailMode) error {
	// The hold once more, after the up (M6): a tree that changed on
	// disk while compose read it (a pull mid-start) is stopped at once.
	h.mu.Lock()
	holdErr := h.mailHoldGateLocked(t)
	h.mu.Unlock()
	if holdErr != nil {
		h.mailUpModes.mu.Lock()
		delete(h.mailUpModes.m, t.ID)
		h.mailUpModes.mu.Unlock()
		log.Printf("mail: %s: its template changed during the start: stopping it", t.ID)
		h.mailStopHeld("its template changed during the start")
		return holdErr
	}
	err := h.mailCheckNetworks(ctx, t, mode)
	h.mailUpModes.mu.Lock()
	if h.mailUpModes.m == nil {
		h.mailUpModes.m = map[string]mailMode{}
	}
	if err != nil {
		delete(h.mailUpModes.m, t.ID)
	} else {
		h.mailUpModes.m[t.ID] = mode
	}
	h.mailUpModes.mu.Unlock()
	if err == nil {
		return nil
	}
	h.setMailVoidErr(err.Error())
	log.Printf("mail: %s: %v: stopping it", t.ID, err)
	if derr := h.composeDown(t); derr != nil {
		log.Printf("mail: stopping %s: %v", t.ID, derr)
	}
	return statusErr(http.StatusConflict, "%s was stopped: %v", t.ID, err)
}

// mailCheckNetworks compares the project's networks on the engine with
// the mode (unwired: nothing checked).
func (h *Hub) mailCheckNetworks(ctx context.Context, t *templates.Template, mode mailMode) error {
	if mode == mailUnwired || h.noEngine() {
		return nil
	}
	info, err := h.rt.Info(ctx)
	if err != nil {
		return fmt.Errorf("the engine's networks can't be read (%v): the mail mode can't be confirmed", err)
	}
	_, external, declared := topLevelNetworkFlags(t.ReadCompose())
	project := projectName(t.ID)
	for _, n := range info.Networks {
		if n.Labels["com.docker.compose.project"] != project {
			continue
		}
		key := n.Labels["com.docker.compose.network"]
		if key == "" || external[key] {
			continue
		}
		want := mode == mailVoid || declared[key]
		if n.Internal != want {
			return fmt.Errorf("the provider's network %s is %s, not %s, in %s mode", n.Name, map[bool]string{true: "internal", false: "not internal"}[n.Internal],
				map[bool]string{true: "internal", false: "not internal"}[want], mode)
		}
	}
	return nil
}
