package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/lldap"
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
	// extraGroups are further groups per service (the admin view's 10001,
	// the group of its ticket key file).
	extraGroups map[string][]int
	// topNetworks: network key → its top-level YAML body.
	topNetworks map[string]string
	// tlsVolume / secretsVolume: the top-level volumes to declare.
	tlsVolume, secretsVolume, slotVolume bool
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
	r, err := h.mailRenderBodyLocked(t, mode)
	if err != nil || r == nil {
		return r, err
	}
	// Post-render (Ruling FH-H1): every core network the override joins
	// is exactly the override's own entry: the template declares no
	// network under that key (its attributes would merge into it).
	names, _ := topLevelNetworks(t.ReadCompose())
	for n, body := range r.topNetworks {
		if !strings.Contains(body, "external: true") {
			continue
		}
		for _, tn := range names {
			if strings.EqualFold(strings.TrimSpace(tn), n) {
				return nil, fmt.Errorf("mail: the template declares the core network %s the Hub joins: refused", tn)
			}
		}
	}
	// The template's own subnets clear of core's (L9).
	if why := h.mailSubnetRefusals(t); len(why) > 0 {
		return nil, statusErr(http.StatusConflict, "%s", why[0])
	}
	return r, nil
}

// mailSubnetRefusals (final cross review L9): a mail template picks its
// own ipam subnets; one overlapping a range core reserves (core.env's
// PORTCULLIS_VPN_RESERVED_RANGES: core's fixed networks, the link subnet,
// the VPN and Podman pools; plus portcullis-mail-api and portcullis-vpn as
// core.env sets them) is refused, naming the subnet. Docker's default
// pools 172.16.0.0/12 and 192.168.0.0/16 are where every app network
// lives: not a conflict. An unreadable reserved list refuses (fail
// closed).
func (h *Hub) mailSubnetRefusals(t *templates.Template) []string {
	subnets := templateSubnets(t.ReadCompose())
	if len(subnets) == 0 {
		return nil
	}
	vc := h.vpnCoreEnv()
	if vc.ReservedBad {
		return []string{"core.env's " + VarVPNReserved + " can't be read: the mail provider's own subnets can't be checked"}
	}
	reserved := []netip.Prefix{h.mailCore().APISubnet, vc.Net}
	for _, p := range vc.Reserved {
		if p == mailDockerPool172 || p == mailDockerPool192 {
			continue
		}
		reserved = append(reserved, p)
	}
	var out []string
	for _, s := range subnets {
		for _, r := range reserved {
			if r.IsValid() && s.prefix.Overlaps(r) {
				out = append(out, fmt.Sprintf("the provider's network %s has subnet %s, which overlaps core's reserved range %s: pick another subnet in the template", s.network, s.prefix, r))
				break
			}
		}
	}
	return out
}

var (
	mailDockerPool172 = netip.MustParsePrefix("172.16.0.0/12")
	mailDockerPool192 = netip.MustParsePrefix("192.168.0.0/16")
)

type templateSubnet struct {
	network string
	prefix  netip.Prefix
}

// templateSubnets are compose's non-external top-level networks' ipam
// subnets in file order (an unparsable one is ValidateMail's refusal).
func templateSubnets(compose []byte) []templateSubnet {
	var doc struct {
		Networks yaml.Node `yaml:"networks"`
	}
	if yaml.Unmarshal(compose, &doc) != nil || doc.Networks.Kind != yaml.MappingNode {
		return nil
	}
	var out []templateSubnet
	for j := 0; j+1 < len(doc.Networks.Content); j += 2 {
		key := doc.Networks.Content[j].Value
		var n struct {
			External any `yaml:"external"`
			IPAM     struct {
				Config []struct {
					Subnet string `yaml:"subnet"`
				} `yaml:"config"`
			} `yaml:"ipam"`
		}
		if doc.Networks.Content[j+1].Decode(&n) != nil {
			continue
		}
		if b, ok := n.External.(bool); (ok && b) || (!ok && n.External != nil) {
			continue
		}
		for _, c := range n.IPAM.Config {
			if p, err := netip.ParsePrefix(strings.TrimSpace(c.Subnet)); err == nil {
				out = append(out, templateSubnet{key, p.Masked()})
			}
		}
	}
	return out
}

func (h *Hub) mailRenderBodyLocked(t *templates.Template, mode mailMode) (*mailRender, error) {
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
	if b.AdminView != nil {
		named[b.AdminView.Service] = true
	}
	env := []string{
		VarMailAPISubnet + ": " + yamlQuote(core.APISubnet.String()),
		VarMailAPIHubIP + ": " + yamlQuote(core.HubIP.String()),
		VarMailSlotDir + ": " + yamlQuote(MailSlotMount),
		VarMailTLSDir + ": " + yamlQuote(MailTLSMount),
		VarMailWellknownEntrypoints + ": " + yamlQuote(h.mailEntrypointsLocked()),
		// The public addresses (M2): only these two of core's.
		VarMailPublicIPv4 + ": " + yamlQuote(core.PublicIPv4),
		VarMailPublicIPv6 + ": " + yamlQuote(core.PublicIPv6),
	}
	if b.AdminView != nil {
		// The read-only admin view's hostname (contract §19.13): Stalwart's
		// trusted host and the proxy's.
		env = append(env, VarMailAdminHost+": "+yamlQuote(h.mailAdminHost()))
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
	// The whole slot volume, read-only, on every gated service — never
	// a subpath (Ruling R-POD2: Podman's compat API ignores subpath).
	for _, s := range b.Gated {
		r.groups[s] = true
		r.slotVolume = true
		r.mounts[s] = append(r.mounts[s], "type: volume\n"+
			"        source: "+mailProviderSlotVolumeKey+"\n"+
			"        target: "+MailSlotMount+"\n"+
			"        read_only: true")
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
	if av := b.AdminView; av != nil {
		if err := h.mailAdminViewLocked(r, av, attach, t.ID); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// mailAdminHost is the read-only mail admin view's hostname (contract
// §19.13): mail-admin.<main domain>.
func (h *Hub) mailAdminHost() string {
	return MailAdminLabel + "." + strings.ToLower(h.cfg.Domain)
}

// mailAdminViewLocked renders the admin view router (contract §19.1,
// §19.13) on the admin_view service: portcullis-proxy, the pinned SPKIs
// and the Hub's admin chain — on websecure unless admin hosts are
// VPN-only (VPN modes admin and server), always on vpnsecure. Caller
// holds mu.
func (h *Hub) mailAdminViewLocked(r *mailRender, av *templates.Endpoint, attach func(svc, net, body string), id string) error {
	np, err := h.networkParams()
	if err != nil {
		return err
	}
	key, err := h.mailAdminRouteKey()
	if err != nil {
		return fmt.Errorf("mail: the admin view's route key: %w", err)
	}
	// The ticket key (contract §19.13): its own per-install secret, a file
	// the view reads through this read-only bind (group 10001, 0640) —
	// never a label or an environment value Traefik or its API could show.
	if _, err := h.mailAdminTicketKey(id); err != nil {
		return fmt.Errorf("mail: the admin view's ticket key: %w", err)
	}
	s := av.Service
	host := path.Join(h.appFilesHostFor(id), id, mailAdminTicketDir)
	if h.relabelFor(id) {
		r.mounts[s] = append(r.mounts[s], relabelBindEntry(host, MailAdminTicketMount, true))
	} else {
		b, _ := json.Marshal(composeLiteral(host) + ":" + composeLiteral(MailAdminTicketMount) + ":ro")
		r.mounts[s] = append(r.mounts[s], string(b))
	}
	if r.extraGroups == nil {
		r.extraGroups = map[string][]int{}
	}
	r.extraGroups[s] = append(r.extraGroups[s], hubGID)
	attach(s, mailProxyNetwork, " {}")
	r.topNetworks[mailProxyNetwork] = "\n    external: true\n    name: " + mailProxyNetwork
	r.env[s] = append(r.env[s], VarMailTLSSPKI+": "+yamlQuote(strings.Join(h.st.Mail.TLS.SPKISHA256, ",")),
		// The proxy's gate: Traefik's address and the route key its router
		// sets once forward-auth admitted a full administrator.
		VarMailAdminTraefikIP+": "+yamlQuote(np.TraefikIP.String()),
		VarMailAdminRouteKey+": "+yamlQuote(key),
		// The proxy's second identity check: forward-auth's groups header
		// must hold the admin group (contract §19.13).
		VarMailAdminGroup+": "+yamlQuote(lldap.AdminGroup))
	rule := "Host(`" + h.mailAdminHost() + "`)"
	labels := r.labels[s]
	if labels == nil {
		labels = map[string]string{}
		r.labels[s] = labels
	}
	labels["traefik.enable"] = "true"
	labels["traefik.docker.network"] = mailProxyNetwork
	labels["traefik.http.services."+MailAdminRouter+".loadbalancer.server.port"] = strconv.Itoa(av.Port)
	labels["traefik.http.middlewares."+MailAdminKeyMiddleware+".headers.customrequestheaders."+MailAdminKeyHeader] = key
	router := func(name, ep, chain string) {
		pre := "traefik.http.routers." + name
		labels[pre+".rule"] = rule
		labels[pre+".entrypoints"] = ep
		labels[pre+".tls"] = "true"
		labels[pre+".tls.options"] = mailAdminTLSOptions
		labels[pre+".middlewares"] = chain
		labels[pre+".service"] = MailAdminRouter
	}
	if m := h.vpnCoreEnv().Mode; m != VPNModeAdmin && m != VPNModeServer {
		router(MailAdminRouter, "websecure", mailAdminMiddlewares)
	}
	router(MailAdminRouter+"-vpn", EntrypointsVPN, mailAdminMiddlewaresVPN)
	return nil
}

// mailAdminRouteKey is the per-install key the admin view router sets
// for the proxy (hub_data/mail-admin-route-key, 0600, 48 characters
// [A-Za-z0-9], made once): only Traefik (the router's label) and the
// admin-view service (its environment) hold it.
func (h *Hub) mailAdminRouteKey() (string, error) {
	p := filepath.Join(h.cfg.DataDir, "mail-admin-route-key")
	if b, err := os.ReadFile(p); err == nil {
		if k := strings.TrimSpace(string(b)); len(k) >= 32 {
			return k, nil
		}
	}
	k, err := mailRandString(mailSecretLen)
	if err != nil {
		return "", err
	}
	if err := writeAtomic0600(p, []byte(k+"\n")); err != nil {
		return "", err
	}
	return k, nil
}

// The admin view's ticket key: <appfiles>/<id>/mail-admin/ticket-key
// (the Hub's side), mounted read-only at MailAdminTicketMount.
const (
	mailAdminTicketDir   = "mail-admin"
	MailAdminTicketMount = "/run/portcullis/mail-admin"
	hubGID               = 10001
)

// mailAdminTicketKey is instance id's ticket secret (48 characters
// [A-Za-z0-9], made once; 0640 in a 0750 directory, group the Hub's).
func (h *Hub) mailAdminTicketKey(id string) (string, error) {
	if !templates.ValidID(id) {
		return "", fmt.Errorf("invalid instance id")
	}
	dir := filepath.Join(h.appFilesDir(id), mailAdminTicketDir)
	p := filepath.Join(dir, "ticket-key")
	if b, err := os.ReadFile(p); err == nil {
		if k := strings.TrimSpace(string(b)); len(k) >= 32 {
			return k, nil
		}
	}
	for _, d := range []string{h.cfg.AppFilesDir, h.appFilesDir(id), dir} {
		if err := os.MkdirAll(d, appFilesDirMode); err != nil {
			return "", err
		}
	}
	if err := os.Chmod(dir, appFilesDirMode); err != nil {
		return "", err
	}
	k, err := mailRandString(mailSecretLen)
	if err != nil {
		return "", err
	}
	if err := fsutil.WriteFileAtomic(p, []byte(k+"\n"), dataFileMode); err != nil {
		return "", err
	}
	return k, nil
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
		h.mailPersistUpMode(t.ID, mailUnwired, false)
		log.Printf("mail: %s: its template changed during the start: stopping it", t.ID)
		h.mailStopHeld("its template changed during the start")
		// The caller holds the app lock (the owed down's retry is busy
		// now): down here at once.
		if derr := h.composeDown(t); derr != nil {
			log.Printf("mail: stopping %s: %v", t.ID, derr)
		}
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
	h.mailPersistUpMode(t.ID, mode, err == nil)
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

// mailSeedUpMode (Hub start): the wired provider's persisted mode is
// trusted for the next up only when the running project's networks
// confirm it — every declared network found, each internal flag as that
// mode wants. Anything else (a mismatch, unreadable networks, nothing
// recorded) keeps the down before the first up (fail closed).
func (h *Hub) mailSeedUpMode(ctx context.Context) {
	h.mu.RLock()
	p := h.st.Mail.Provider
	upMode, upInst := h.st.Mail.UpMode, h.st.Mail.UpModeInstance
	var t *templates.Template
	if p != nil {
		if lt := h.findLocked(p.Instance); lt != nil {
			c := *lt
			t = &c
		}
	}
	h.mu.RUnlock()
	if p == nil || t == nil || upInst != p.Instance || h.noEngine() {
		return
	}
	var mode mailMode
	switch upMode {
	case mailNormal.String():
		mode = mailNormal
	case mailVoid.String():
		mode = mailVoid
	default:
		return
	}
	info, err := h.rt.Info(ctx)
	if err != nil {
		return
	}
	names, external, declared := topLevelNetworkFlags(t.ReadCompose())
	project := projectName(t.ID)
	seen := map[string]bool{}
	for _, n := range info.Networks {
		if n.Labels["com.docker.compose.project"] != project {
			continue
		}
		key := n.Labels["com.docker.compose.network"]
		if key == "" || external[key] {
			continue
		}
		if n.Internal != (mode == mailVoid || declared[key]) {
			return // the running networks contradict the record
		}
		seen[key] = true
	}
	found := 0
	for _, k := range names {
		if external[k] {
			continue
		}
		if !seen[k] {
			return // a declared network isn't there: can't confirm
		}
		found++
	}
	if found == 0 {
		return
	}
	h.mailUpModes.mu.Lock()
	if h.mailUpModes.m == nil {
		h.mailUpModes.m = map[string]mailMode{}
	}
	if _, known := h.mailUpModes.m[t.ID]; !known {
		h.mailUpModes.m[t.ID] = mode
	}
	h.mailUpModes.mu.Unlock()
}

// mailPersistUpMode records the wired provider's applied mode for the
// next Hub start (mailSeedUpMode); a failed or unconfirmed up clears it.
func (h *Hub) mailPersistUpMode(id string, mode mailMode, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	nm, ni := "", ""
	if p := h.st.Mail.Provider; p != nil && p.Instance == id && ok && mode != mailUnwired {
		nm, ni = mode.String(), id
	} else if h.st.Mail.UpModeInstance != id && h.st.Mail.UpModeInstance != "" {
		return // another instance's record: not this up's to touch
	}
	if h.st.Mail.UpMode != nm || h.st.Mail.UpModeInstance != ni {
		h.st.Mail.UpMode, h.st.Mail.UpModeInstance = nm, ni
		h.saveLocked()
	}
}
