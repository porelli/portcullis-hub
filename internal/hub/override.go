package hub

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// generateOverrideLocked writes the per-app compose override: user volume
// mounts, port bindings, per-router Traefik tls.options labels driven by
// the app's effective auth policy, the router middlewares of apps with
// their own login (Portcullis sign-in added, or the template's own chain
// for "own login only"), and the public-exception router when it is on.
// Port ranges and network_mode: host ports stay in the base compose.yml.
// It is always regenerated (never hand-edited); the admin's own additions
// go in the custom override (useroverride.go). Caller must hold mu.
func (h *Hub) generateOverrideLocked(t *templates.Template, s state.InstanceSettings) error {
	content, err := h.renderOverrideLocked(t, s)
	if err != nil {
		return err
	}
	if content == "" {
		os.Remove(h.overridePath(t.ID))
		return nil
	}
	return fsutil.WriteFileAtomic(h.overridePath(t.ID), []byte(content), 0600)
}

// mountSourceLocked is a path option value's host directory: a shared
// folder through h.folders (none: refused), anything else through the
// kind's Mounter (re-checked: stored values are never trusted blindly).
// Caller must hold mu.
func (h *Hub) mountSourceLocked(o *templates.Option, v any) (string, error) {
	if str, ok := v.(string); ok && strings.HasPrefix(str, settings.FolderRefPrefix) {
		return folderHostPath(h.folders, str)
	}
	k, err := h.kinds.Kind(o.Type)
	if err != nil {
		return "", err
	}
	m, ok := k.(settings.Mounter)
	if !ok {
		return "", fmt.Errorf("type %s is not a host directory", o.Type)
	}
	p, err := m.HostPath(o, v)
	if err != nil {
		return "", err
	}
	if err := templates.ValidatePathSetting(p); err != nil {
		return "", err
	}
	return p, nil
}

// composeLiteral escapes $ as $$: compose interpolates the override, and
// a host path is literal.
func composeLiteral(s string) string { return strings.ReplaceAll(s, "$", "$$") }

// renderOverrideLocked returns the Hub override's content ("" = none
// needed). Caller must hold mu.
func (h *Hub) renderOverrideIn(rv renderView, t *templates.Template, s state.InstanceSettings) (string, error) {
	values := s.Ports
	// A gid reference holding a folder group's gid that no folder
	// assignment wrote fails closed (preflight ruling 30).
	if err := h.gidRangeRenderErrIn(rv, t, s); err != nil {
		return "", err
	}
	serviceMounts := make(map[string][]string)
	var folderMounts []*folderMount
	for _, o := range mountOptions(t) {
		v, ok := h.effectiveValue(t, o, s)
		if !ok {
			continue
		}
		// A shared folder (contract §13.15): long syntax, never created
		// by Docker, read-only unless the use writes, plus its group.
		fm, err := h.folderMountIn(rv, t, o, v)
		if err != nil {
			return "", fmt.Errorf("setting %s: %w", o.Key, err)
		}
		if fm != nil {
			folderMounts = append(folderMounts, fm)
			serviceMounts[o.Target.Service] = append(serviceMounts[o.Target.Service], folderBindEntry(fm))
			continue
		}
		host, err := h.mountSourceLocked(o, v)
		if err != nil {
			return "", fmt.Errorf("setting %s: %w", o.Key, err)
		}
		vol := composeLiteral(host) + ":" + o.Target.Mount
		if o.EffectiveMode() == "ro" {
			vol += ":ro"
		}
		// JSON string == valid YAML double-quoted scalar: safe for spaces,
		// quotes and '#'.
		mountJSON, _ := json.Marshal(vol)
		serviceMounts[o.Target.Service] = append(serviceMounts[o.Target.Service], string(mountJSON))
	}
	serviceGroups := folderGroupAdd(folderMounts)

	// Settings data files (contract §13.7): each file's directory,
	// read-only at its mount (deliver_files.go).
	for svc, mounts := range h.dataFileMounts(t) {
		serviceMounts[svc] = append(serviceMounts[svc], mounts...)
	}
	// An AI page's selected provider variables, on ai.chat.env.service
	// only (G31: the values are in its .env; compose interpolates them).
	serviceEnv := h.providerOverrideEnvLocked(t)

	// Per-person credentials (contract §6, §13.16): each person_secret
	// option's hash directory, read-only, as a subpath of the external
	// secrets volume, on its mount.service only.
	secretOpts := personSecretOptions(t)
	for _, o := range secretOpts {
		sub, err := secretDirRel(t.ID, o.Key)
		if err != nil {
			return "", fmt.Errorf("setting %s: %w", o.Key, err)
		}
		serviceMounts[o.Mount.Service] = append(serviceMounts[o.Mount.Service], secretsMountEntry(o.Mount.Path, sub))
	}

	servicePorts := make(map[string][]string)
	for _, p := range t.Manifest.Ports {
		if p.Service == "" || p.NetworkModeHost || p.Range != "" {
			continue
		}
		proto := strings.ToLower(p.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		bind := p.Bind
		if v, ok := values[p.Key+"_BIND"]; ok && v != "" {
			bind = v
		}
		if bind == "" {
			bind = "0.0.0.0"
		}
		if net.ParseIP(bind) == nil {
			return "", fmt.Errorf("port %s: bind %q is not an IP address", p.Key, bind)
		}
		host := p.Default
		if v, ok := values[p.Key]; ok {
			if v == "" && !p.Required {
				continue
			}
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				host = n
			}
		}
		if host <= 0 || p.Container <= 0 {
			continue
		}
		hostIP := bind
		if strings.Contains(bind, ":") { // IPv6 needs brackets
			hostIP = "[" + bind + "]"
		}
		servicePorts[p.Service] = append(servicePorts[p.Service], fmt.Sprintf("\"%s:%d:%d/%s\"", hostIP, host, p.Container, proto))
	}

	rl, err := h.routeLabelsLocked(t)
	if err != nil {
		return "", err
	}
	serviceRouters, plan, tier, publicLines := rl.routes.Routers, rl.plan, rl.tier, rl.public

	// Instances other than the default one replace each labelled service's
	// labels (compose's !override): the template's, with every Traefik
	// name it defines renamed per instance (contract §3.1), plus the Hub's.
	var replaced map[string]map[string]string
	if !t.IsDefault() {
		if replaced, err = h.instanceLabelsLocked(t, rl); err != nil {
			return "", err
		}
	}

	services := map[string]bool{}
	for svc := range serviceMounts {
		services[svc] = true
	}
	for svc := range servicePorts {
		services[svc] = true
	}
	for svc := range serviceGroups {
		services[svc] = true
	}
	for svc := range serviceEnv {
		services[svc] = true
	}
	for svc := range serviceRouters {
		services[svc] = true
	}
	for svc := range replaced {
		services[svc] = true
	}
	// The extra-domain sign-in routers' service may route nothing itself.
	if len(rl.signInLabels) > 0 {
		services[rl.signInService] = true
	}
	if len(rl.mcpLabels) > 0 {
		services[rl.mcpService] = true
	}
	// Companion services: scale, the alias on portcullis-proxy (§3.2).
	companionSvcs := h.companionServicesLocked(t)
	for svc := range companionSvcs {
		services[svc] = true
	}
	names := make([]string, 0, len(services))
	for svc := range services {
		names = append(names, svc)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("# Auto-generated by Portcullis Hub -- do not edit\n")
	if len(names) > 0 {
		b.WriteString("services:\n")
	}
	for _, svc := range names {
		fmt.Fprintf(&b, "  %s:\n", svc)
		if mounts := serviceMounts[svc]; len(mounts) > 0 {
			b.WriteString("    volumes:\n")
			for _, m := range mounts {
				fmt.Fprintf(&b, "      - %s\n", m)
			}
		}
		if env := serviceEnv[svc]; len(env) > 0 {
			b.WriteString("    environment:\n")
			for _, l := range env {
				fmt.Fprintf(&b, "      %s\n", l)
			}
		}
		if gids := serviceGroups[svc]; len(gids) > 0 {
			// Strings: compose merges them with the template's own list.
			b.WriteString("    group_add:\n")
			for _, g := range gids {
				fmt.Fprintf(&b, "      - \"%d\"\n", g)
			}
		}
		if ports := servicePorts[svc]; len(ports) > 0 {
			b.WriteString("    ports:\n")
			for _, p := range ports {
				fmt.Fprintf(&b, "      - %s\n", p)
			}
		}
		if cs, ok := companionSvcs[svc]; ok {
			if cs.scale != nil {
				fmt.Fprintf(&b, "    scale: %d\n", *cs.scale)
			}
			if len(cs.aliases) > 0 {
				b.WriteString("    networks:\n")
				if cs.addDefault {
					b.WriteString("      default: {}\n")
				}
				fmt.Fprintf(&b, "      %s:\n        aliases:\n", aiProxyNetwork)
				for _, a := range cs.aliases {
					fmt.Fprintf(&b, "          - %s\n", yamlQuote(a))
				}
			}
		}
		if replaced != nil {
			if labels := replaced[svc]; len(labels) > 0 {
				b.WriteString("    labels: !override\n")
				keys := make([]string, 0, len(labels))
				for k := range labels {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					fmt.Fprintf(&b, "      %s: %s\n", yamlQuote(k), yamlQuote(labels[k]))
				}
			}
			continue
		}
		routers := serviceRouters[svc]
		public := plan != nil && svc == plan.Service && len(publicLines) > 0
		signIn := svc == rl.signInService && len(rl.signInLabels) > 0
		mcp := svc == rl.mcpService && len(rl.mcpLabels) > 0
		if len(routers) > 0 || public || signIn || mcp {
			b.WriteString("    labels:\n")
			for _, r := range routers {
				fmt.Fprintf(&b, "      traefik.http.routers.%s.tls.options: %s\n", r, tier)
				if mw, ok := rl.middlewares[r]; ok {
					fmt.Fprintf(&b, "      traefik.http.routers.%s.middlewares: %s\n", r, mw)
				}
			}
			if public {
				for _, l := range publicLines {
					fmt.Fprintf(&b, "      %s\n", l)
				}
			}
			if signIn {
				keys := make([]string, 0, len(rl.signInLabels))
				for k := range rl.signInLabels {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					fmt.Fprintf(&b, "      %s: %s\n", yamlQuote(k), yamlQuote(rl.signInLabels[k]))
				}
			}
			if mcp {
				for _, k := range slices.Sorted(maps.Keys(rl.mcpLabels)) {
					fmt.Fprintf(&b, "      %s: %s\n", yamlQuote(k), yamlQuote(rl.mcpLabels[k]))
				}
			}
		}
	}
	// Volume names (§11.2), multi templates only (they declare none): the
	// default instance gets portcullis_<key>, others portcullis_<id>-<key>.
	// A single template's volumes stay exactly as compose names them.
	multiVols := t.Manifest.Multi() && len(t.Volumes) > 0
	if multiVols || len(secretOpts) > 0 {
		b.WriteString("volumes:\n")
	}
	if vols := t.NamesFor(t.ID).Volumes; multiVols {
		for _, k := range t.Volumes {
			fmt.Fprintf(&b, "  %s:\n    name: %s\n", yamlQuote(k), yamlQuote(vols[k]))
		}
	}
	if len(secretOpts) > 0 {
		fmt.Fprintf(&b, "  %s:\n    external: true\n    name: %s\n", templates.SecretsVolumeKey, yamlQuote(h.cfg.SecretsVolume))
	}
	if len(names) == 0 && !multiVols {
		return "", nil
	}
	return b.String(), nil
}

// secretsMountEntry is the long-syntax mount of a person_secret option's
// hash directory (sub = <instance>/<key>) at target, read-only.
func secretsMountEntry(target, sub string) string {
	return "type: volume\n" +
		"        source: " + templates.SecretsVolumeKey + "\n" +
		"        target: " + yamlQuote(composeLiteral(target)) + "\n" +
		"        read_only: true\n" +
		"        volume:\n" +
		"          subpath: " + yamlQuote(sub)
}

// renderOverrideLocked is renderOverrideIn over the Hub's state. Caller
// must hold mu.
func (h *Hub) renderOverrideLocked(t *templates.Template, s state.InstanceSettings) (string, error) {
	return h.renderOverrideIn(h.liveView(), t, s)
}

// yamlQuote renders s as a YAML double-quoted scalar (a JSON string).
func yamlQuote(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimSpace(b.String())
}

// hubLabels are the labels the Hub's override sets, per compose service,
// with the template's Traefik names (values as compose reads them, before
// interpolation).
func hubLabels(rl *routeLabels) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for svc, routers := range rl.routes.Routers {
		m := map[string]string{}
		for _, r := range routers {
			m["traefik.http.routers."+r+".tls.options"] = rl.tier
			if mw, ok := rl.middlewares[r]; ok {
				m["traefik.http.routers."+r+".middlewares"] = mw
			}
		}
		out[svc] = m
	}
	if len(rl.signInLabels) > 0 {
		if out[rl.signInService] == nil {
			out[rl.signInService] = map[string]string{}
		}
		for k, v := range rl.signInLabels {
			out[rl.signInService][k] = v
		}
	}
	if len(rl.mcpLabels) > 0 {
		if out[rl.mcpService] == nil {
			out[rl.mcpService] = map[string]string{}
		}
		for k, v := range rl.mcpLabels {
			out[rl.mcpService][k] = v
		}
	}
	if rl.plan != nil {
		for _, l := range rl.public {
			k, v, _ := strings.Cut(l, ": ")
			if strings.HasPrefix(v, `"`) {
				var s string
				if err := json.Unmarshal([]byte(v), &s); err != nil {
					return nil, err
				}
				v = s
			}
			if out[rl.plan.Service] == nil {
				out[rl.plan.Service] = map[string]string{}
			}
			out[rl.plan.Service][k] = v
		}
	}
	return out, nil
}

// instanceLabelsLocked is, per labelled service, the full label set of a
// non-default instance: the template's labels and the Hub's, renamed.
// Caller must hold mu.
func (h *Hub) instanceLabelsLocked(t *templates.Template, rl *routeLabels) (map[string]map[string]string, error) {
	base, err := templates.ServiceLabels(t.ReadCompose())
	if err != nil {
		return nil, err
	}
	mine, err := hubLabels(rl)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	for svc, l := range base {
		merged := make(map[string]string, len(l))
		for k, v := range l {
			merged[k] = v
		}
		for k, v := range mine[svc] {
			merged[k] = v
		}
		out[svc] = templates.RenameLabels(merged, t.Names, t.ID)
	}
	for svc, l := range mine {
		if _, ok := out[svc]; !ok {
			out[svc] = templates.RenameLabels(l, t.Names, t.ID)
		}
	}
	return out, nil
}

// routeLabels is the Traefik part of an app's override.
type routeLabels struct {
	routes *templates.Routes
	plan   *templates.PublicPlan // nil without public_access
	tier   string                // TLS options of every router of the app
	public []string              // public router + strip middleware lines ("key: value"), on plan.Service
	// middlewares are the routers' middleware chains the Hub sets (apps
	// with auth.native_login only); a router without an entry keeps the
	// template's. Routers on extra-domain hosts get the template's (or
	// the native_login) chain with portcullis-auth-ext@docker in place of
	// portcullis-auth@docker (contract §5).
	middlewares map[string]string
	// signIn maps each router that uses portcullis-auth-ext@docker to its
	// extra-domain hosts (sorted); signInService carries the sign-in
	// routers' labels (signInLabels, full keys) — the first compose service
	// with traefik.enable=true.
	signIn        map[string][]string
	signInService string
	signInLabels  map[string]string
	// mcpService carries the MCP routers' labels (mcpLabels, full keys) —
	// the first compose service with traefik.enable=true (contract §5).
	mcpService string
	mcpLabels  map[string]string
}

// ExtAuthMiddleware is core's forwardAuth middleware for extra-domain
// hosts (forward-auth-ext, contract §5).
const ExtAuthMiddleware = "portcullis-auth-ext@docker"

// SignInRouterPrefix starts the name of every extra-domain sign-in router
// the Hub renders: portcullis-oauth2-<instance-id>_<host router>.
const SignInRouterPrefix = "portcullis-oauth2-"

// SignInRouterName is the sign-in router of instance id's router r.
func SignInRouterName(id, r string) string { return SignInRouterPrefix + id + "_" + r }

// routeLabelsLocked computes the tier and public-router labels from the
// template's compose file and state. The custom override can't change any
// of this: it may not set traefik.* labels or network attachments.
// Caller must hold mu.
func (h *Hub) routeLabelsLocked(t *templates.Template) (*routeLabels, error) {
	routes, err := templates.ParseRoutes(t.ReadCompose())
	if err != nil {
		return nil, err
	}
	plan, err := templates.PlanPublic(&t.Manifest, routes)
	if err != nil {
		return nil, err
	}
	pub := h.publicLocked(t, plan)
	acc := h.accessLocked(t)
	rl := &routeLabels{routes: routes, plan: plan, tier: policy.HostTier(acc.Resolved.Policy, pub.Active())}
	if acc.SignIn != "" {
		rl.middlewares = map[string]string{}
		for name, ri := range routes.Info {
			mw := nativeRouterMiddlewares(ri.Middlewares)
			if acc.SignIn == SignInGateway {
				mw = gatewayRouterMiddlewares(ri.Middlewares)
			}
			if mw != "" {
				rl.middlewares[name] = mw
			}
		}
	}
	if err := h.extraSignInLocked(t, rl); err != nil {
		return nil, err
	}
	if err := h.mcpRoutersLocked(t, rl); err != nil {
		return nil, err
	}
	if pub.Active() {
		if rl.public, err = publicLabels(t.ID, &t.Manifest, plan, pub.Routed, rl.tier); err != nil {
			return nil, err
		}
	}
	return rl, nil
}

// extraSignInLocked renders the extra-domain sign-in (contract §5): every
// router whose hosts lie on an enrolled domain and whose chain (as
// rendered) has portcullis-auth@docker gets portcullis-auth-ext@docker in
// its place, and one Host()-scoped /oauth2/ router per such router sends
// the sign-in endpoints to forward-auth-ext. A router may not mix
// extra-domain and main-domain hosts (one chain can't serve both).
// Caller must hold mu.
func (h *Hub) extraSignInLocked(t *templates.Template, rl *routeLabels) error {
	if len(t.ExtraHosts) == 0 {
		return nil
	}
	extra := map[string]bool{}
	for _, x := range t.ExtraHosts {
		extra[x] = true
	}
	names := make([]string, 0, len(rl.routes.Info))
	for name := range rl.routes.Info {
		names = append(names, name)
	}
	sort.Strings(names)
	chains, err := templateChains(t.ReadCompose())
	if err != nil {
		return err
	}
	for _, name := range names {
		ri := rl.routes.Info[name]
		var hosts []string
		mainHosts := 0
		seen := map[string]bool{}
		for _, hv := range ri.HostVars {
			host := t.InstanceEnv[hv]
			if hv == "" || !extra[host] {
				mainHosts++
				continue
			}
			if !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
		}
		if len(hosts) == 0 {
			continue
		}
		if mainHosts > 0 {
			return fmt.Errorf("router %s routes both extra-domain and main-domain hosts; one sign-in chain can't serve both", name)
		}
		mws := ri.Middlewares
		if m, ok := rl.middlewares[name]; ok {
			mws = strings.Split(m, ",")
		}
		uses := false
		out := make([]string, 0, len(mws))
		for _, m := range mws {
			m = strings.TrimSpace(m)
			base, prov, _ := strings.Cut(m, "@")
			docker := prov == "" || prov == "docker"
			switch {
			case docker && base == authMiddlewareName:
				m, uses = ExtAuthMiddleware, true
			case docker && chainReachesAuth(chains, base, map[string]bool{}):
				// Its chain would keep the main-domain sign-in on an
				// extra-domain host (the Hub swaps only the router's own
				// list).
				return fmt.Errorf("router %s routes extra-domain hosts but reaches portcullis-auth@docker through the template's chain middleware %s: list portcullis-auth@docker on the router itself to use an extra domain", name, m)
			}
			out = append(out, m)
		}
		if !uses {
			continue
		}
		if rl.middlewares == nil {
			rl.middlewares = map[string]string{}
		}
		rl.middlewares[name] = strings.Join(out, ",")
		if rl.signIn == nil {
			rl.signIn = map[string][]string{}
		}
		sort.Strings(hosts)
		rl.signIn[name] = hosts
	}
	if len(rl.signIn) == 0 {
		return nil
	}
	svc, err := templates.FirstEnabledService(t.ReadCompose())
	if err != nil {
		return err
	}
	if svc == "" {
		return fmt.Errorf("no service with traefik.enable=true for the extra-domain sign-in routers")
	}
	// Above every router of the instance and its public router (whose
	// priority is the same bound + 1).
	prio := strconv.Itoa(rl.routes.MaxPriorityBound() + 2)
	rl.signInService, rl.signInLabels = svc, map[string]string{}
	for r, hosts := range rl.signIn {
		match := make([]string, len(hosts))
		for i, host := range hosts {
			match[i] = "Host(`" + host + "`)"
		}
		rule := match[0]
		if len(match) > 1 {
			rule = "(" + strings.Join(match, " || ") + ")"
		}
		k := "traefik.http.routers." + SignInRouterName(t.ID, r) + "."
		rl.signInLabels[k+"rule"] = rule + " && PathPrefix(`/oauth2/`)"
		rl.signInLabels[k+"entrypoints"] = "websecure"
		rl.signInLabels[k+"tls.options"] = rl.tier
		rl.signInLabels[k+"priority"] = prio
		rl.signInLabels[k+"service"] = "forward-auth-ext@docker"
	}
	return nil
}

// authMiddlewareName is core's forwardAuth middleware (as
// portcullis-auth@docker, or without a provider on a docker label).
const authMiddlewareName = "portcullis-auth"

// templateChains maps each chain middleware the template's labels define
// (folded name) to its members.
func templateChains(compose []byte) (map[string][]string, error) {
	labels, err := templates.ServiceLabels(compose)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, l := range labels {
		for k, v := range l {
			segs := strings.Split(templates.FoldKey(strings.TrimSpace(k)), ".")
			if len(segs) == 6 && segs[0] == "traefik" && segs[1] == "http" && segs[2] == "middlewares" && segs[4] == "chain" && segs[5] == "middlewares" {
				for _, m := range strings.Split(v, ",") {
					if m = strings.TrimSpace(m); m != "" {
						out[segs[3]] = append(out[segs[3]], m)
					}
				}
			}
		}
	}
	return out, nil
}

// chainReachesAuth: chain middleware name (the template's own, docker
// provider) includes portcullis-auth, directly or through nested chains.
func chainReachesAuth(chains map[string][]string, name string, seen map[string]bool) bool {
	name = strings.ToLower(name)
	if seen[name] {
		return false
	}
	seen[name] = true
	for _, m := range chains[name] {
		base, prov, _ := strings.Cut(m, "@")
		if prov != "" && prov != "docker" {
			continue
		}
		if base == authMiddlewareName || chainReachesAuth(chains, base, seen) {
			return true
		}
	}
	return false
}

// desiredRouteLabelsLocked returns, per compose service, the Traefik
// labels the Hub's override sets that decide exposure: every router's
// tls.options and the public router / strip middleware, with values as the
// running container will carry them (PORTCULLIS_DOMAIN expanded, "$$" ->
// "$"). Caller must hold mu.
func (h *Hub) desiredRouteLabelsLocked(t *templates.Template) (map[string]map[string]string, error) {
	rl, err := h.routeLabelsLocked(t)
	if err != nil {
		return nil, err
	}
	labels, err := hubLabels(rl)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	for svc, l := range labels {
		if !t.IsDefault() {
			l = templates.RenameLabels(l, t.Names, t.ID)
		}
		m := make(map[string]string, len(l))
		for k, v := range l {
			m[k] = expandComposeValue(v, h.cfg.Domain, t.InstanceEnv)
		}
		out[svc] = m
	}
	return out, nil
}

// composeVarRe matches what compose interpolation turns into something
// else in a Hub-generated value: "$$" (a literal "$") and ${VAR...}.
var composeVarRe = regexp.MustCompile(`\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(?::?[-?])[^${}]*)?\}`)

// expandComposeValue does what compose does to a Hub-generated label value:
// ${PORTCULLIS_DOMAIN...} becomes the domain, the instance variables
// (${PORTCULLIS_HOST_*...}, …) their values, "$$" becomes "$".
func expandComposeValue(v, domain string, instanceEnv map[string]string) string {
	return composeVarRe.ReplaceAllStringFunc(v, func(m string) string {
		if m == "$$" {
			return "$"
		}
		name := composeVarRe.FindStringSubmatch(m)[1]
		if name == "PORTCULLIS_DOMAIN" {
			return domain
		}
		if val, ok := instanceEnv[name]; ok {
			return val
		}
		return m
	})
}

// exposureLabel reports whether a label key decides an app's exposure:
// a router's tls.options, anything of its public router / middleware, of
// its extra-domain sign-in routers or of any portcullis-mcp-* router and,
// for apps whose sign-in the Hub sets (mw), every router's middlewares.
func exposureLabel(id, k string, mw bool) bool {
	// Folded like Traefik's decoder, so an odd-cased key counts too.
	k = templates.FoldKey(k)
	return strings.HasPrefix(k, "traefik.http.routers."+PublicRouterName(id)+".") ||
		strings.HasPrefix(k, "traefik.http.routers."+templates.MCPNamePrefix) ||
		strings.HasPrefix(k, "traefik.http.routers."+SignInRouterName(id, "")) ||
		(mw && strings.HasPrefix(k, "traefik.http.routers.") && strings.HasSuffix(k, ".middlewares")) ||
		strings.HasPrefix(k, "traefik.http.middlewares."+PublicStripMiddleware(id)+".") ||
		(strings.HasPrefix(k, "traefik.http.routers.") && strings.HasSuffix(k, ".tls.options"))
}

// companionRenderedLocked: companion c of t is switched on and gets its
// alias and router (no revoke_all owed, app_token / identity_headers only, the alias one DNS
// label, the router's host known, the policy below LoA 3 — any doubt
// renders nothing, fail closed). Caller holds mu.
func (h *Hub) companionRenderedLocked(t *templates.Template, c *templates.Companion) bool {
	if sw := h.st.AIInstances[t.ID].Companions[c.Name]; !t.HasAIMCP() || !sw.Enabled || sw.RevokePending || sw.Pruned ||
		(sw.IdentityMode != "" && sw.IdentityMode != c.Identity.Mode) || c.Identity.Mode == templates.IdentityAppOAuth || !templates.AliasFits(t.ID, c.Name) {
		return false
	}
	if host := NormalizeHost(t.Hosts[c.Router]); host == "" || !templates.ValidHostname(host) {
		return false
	}
	return policy.LoA(h.effectivePolicyLocked(t)) <= 2
}

// mcpRoutersLocked renders one router per rendered companion (contract
// §5): portcullis-mcp-<id>--<c>, exact Path matchers on its router's
// host, the host's tier, a priority above every router of the instance,
// its public and sign-in routers, service mcp-gate@docker, middlewares
// rate-limit + security-headers; on the first traefik.enable service.
// Caller holds mu.
func (h *Hub) mcpRoutersLocked(t *templates.Template, rl *routeLabels) error {
	var on []*templates.Companion
	for i := range t.Manifest.AI.MCP {
		if c := &t.Manifest.AI.MCP[i]; h.companionRenderedLocked(t, c) {
			on = append(on, c)
		}
	}
	if len(on) == 0 {
		return nil
	}
	svc, err := templates.FirstEnabledService(t.ReadCompose())
	if err != nil {
		return err
	}
	if svc == "" {
		return fmt.Errorf("no service with traefik.enable=true for the MCP routers")
	}
	prio := strconv.Itoa(rl.routes.MaxPriorityBound() + 3)
	rl.mcpService, rl.mcpLabels = svc, map[string]string{}
	for _, c := range on {
		host := NormalizeHost(t.Hosts[c.Router])
		pp := c.EffectivePublicPath()
		k := "traefik.http.routers." + templates.MCPAlias(t.ID, c.Name) + "."
		rl.mcpLabels[k+"rule"] = "Host(`" + host + "`) && (Path(`" + pp + "`) || Path(`/.well-known/oauth-protected-resource" + pp + "`))"
		rl.mcpLabels[k+"entrypoints"] = "websecure"
		rl.mcpLabels[k+"tls.options"] = rl.tier
		rl.mcpLabels[k+"priority"] = prio
		rl.mcpLabels[k+"service"] = "mcp-gate@docker"
		rl.mcpLabels[k+"middlewares"] = "rate-limit@file,security-headers@file"
	}
	return nil
}

// companionService is what the override sets on a companion's service.
type companionService struct {
	scale      *int     // kind companion: 1 on, 0 off
	aliases    []string // portcullis-mcp-<id>--<c> on portcullis-proxy
	addDefault bool     // the service declares no networks: keep default
}

// companionServicesLocked: per compose service backing a companion, its
// scale (kind companion) and the aliases of its rendered companions.
// Caller holds mu.
func (h *Hub) companionServicesLocked(t *templates.Template) map[string]*companionService {
	if !t.HasAIMCP() {
		return nil
	}
	nets := templates.ServiceNetworks(t.ReadCompose())
	out := map[string]*companionService{}
	get := func(svc string) *companionService {
		if out[svc] == nil {
			out[svc] = &companionService{}
		}
		return out[svc]
	}
	for i := range t.Manifest.AI.MCP {
		c := &t.Manifest.AI.MCP[i]
		on := h.companionRenderedLocked(t, c)
		if c.Kind == templates.CompanionKind {
			n := 0
			if on {
				n = 1
			}
			get(c.Service).scale = &n
		}
		if on && !nets[c.Service].NetworkMode {
			cs := get(c.Service)
			cs.aliases = append(cs.aliases, templates.MCPAlias(t.ID, c.Name))
			cs.addDefault = len(nets[c.Service].Networks) == 0
		}
	}
	for _, cs := range out {
		sort.Strings(cs.aliases)
	}
	return out
}

// desiredMCPAliasesLocked: per compose service, the portcullis-mcp-
// aliases the override gives it (exposure drift, §5). Caller holds mu.
func (h *Hub) desiredMCPAliasesLocked(t *templates.Template) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for svc, cs := range h.companionServicesLocked(t) {
		for _, a := range cs.aliases {
			if out[svc] == nil {
				out[svc] = map[string]bool{}
			}
			out[svc][a] = true
		}
	}
	return out
}
