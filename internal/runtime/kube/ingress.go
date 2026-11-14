package kube

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/portcullis/hub/internal/templates"
)

// FileMiddlewares are the core middlewares app routers may name on
// Kubernetes (contract §5 "Names apps may use"): …@docker → …@file.
var FileMiddlewares = []string{
	"client-headers", "client-cert-pem", "rate-limit", "rate-limit-auth", "security-headers", "strip-client-forwarded",
	"portcullis-auth", "portcullis-auth-ext", "portcullis-groups", "portcullis-groups-vpn",
	"portcullis-public-guard", "portcullis-public-guard-vpn", "vpn-required-path",
}

// FileServices are the core services app routers may name: …@docker →
// a TraefikService reference to …@file.
var FileServices = []string{"group-gate", "forward-auth-ext", "mcp-gate"}

// MaxAppPriority is the highest router priority an app route may carry
// (core's admission params maxAppPriority; core's own routes rank above).
const MaxAppPriority = 1000

// hostLabel / routeMatch: the route shape core's edge policy admits —
// Host(`…`) [|| Host(`…`)] with an optional && Path/PathPrefix [|| …],
// hosts of lowercase labels, no empty label, no trailing dot.
const hostLabel = "[a-z0-9]([a-z0-9-]*[a-z0-9])?"

var routeMatch = regexp.MustCompile("^\\(?Host\\(`" + hostLabel + "(\\." + hostLabel + ")+`\\)( \\|\\| Host\\(`" + hostLabel + "(\\." + hostLabel + ")+`\\))*\\)?" +
	"( && \\(?(PathPrefix|Path)\\(`[^`()]*`\\)( \\|\\| (PathPrefix|Path)\\(`[^`()]*`\\))*\\)?)?$")

// TLSOptions are the router TLS tiers (the only @file names tls.options
// may hold).
var TLSOptions = []string{"authaware@file", "public@file", "protected@file", "protected-any@file"}

// traefik.io CRD version the chart pins (K14).
const traefikAPI = "traefik.io/v1alpha1"

type router struct {
	name                                  string
	rule, entrypoints, middlewares, svc   string
	priority, tlsOptions, tlsCertResolver string
	tls                                   bool
}

// IngressObjects converts an instance's rendered Traefik labels (per
// compose service, as the Hub renders them for Docker) into IngressRoutes
// and Middlewares in its namespace. Core names map @docker → @file (the
// K15 list); the instance's own middlewares and services stay in its
// namespace; anything else refuses the instance.
//
// The objects live in the edge namespace (the only one Traefik watches:
// it never reads the apps namespace's Secrets), labelled with the
// instance and portcullis.io/owner: hub; Service refs name the apps
// namespace.
func IngressObjects(instance, namespace, appsNamespace string, labels map[string]map[string]string) ([]*unstructured.Unstructured, error) {
	routers := map[string]*router{}
	ports := map[string]int64{}     // own service → port
	svcOwner := map[string]string{} // own service → compose service
	mws := map[string]map[string]string{}
	for _, svc := range slices.Sorted(mapKeys(labels)) {
		for k, v := range labels[svc] {
			fk := templates.FoldKey(k)
			rest, ok := strings.CutPrefix(fk, "traefik.")
			if !ok || rest == "enable" || rest == "docker.network" {
				continue
			}
			parts := strings.SplitN(rest, ".", 4)
			if len(parts) < 4 || parts[0] != "http" {
				if strings.HasPrefix(rest, "tcp.") || strings.HasPrefix(rest, "udp.") {
					return nil, refused("%s: %s routers are not on Kubernetes", svc, strings.SplitN(rest, ".", 2)[0])
				}
				continue
			}
			kind, name, field := parts[1], parts[2], parts[3]
			switch kind {
			case "routers":
				r := routers[name]
				if r == nil {
					r = &router{name: name}
					routers[name] = r
				}
				switch field {
				case "rule":
					r.rule = v
				case "entrypoints":
					r.entrypoints = v
				case "middlewares":
					r.middlewares = v
				case "service":
					r.svc = v
				case "priority":
					r.priority = v
				case "tls":
					r.tls = v == "true"
				case "tls.options":
					r.tlsOptions, r.tls = v, true
				case "tls.certresolver":
					r.tlsCertResolver, r.tls = v, true
				default:
					return nil, refused("router %s: %s is not on Kubernetes", name, field)
				}
			case "services":
				if field != "loadbalancer.server.port" {
					return nil, refused("service %s: %s is not on Kubernetes", name, field)
				}
				p, err := strconv.ParseInt(v, 10, 32)
				if err != nil || p < 1 || p > 65535 {
					return nil, refused("service %s: bad port %q", name, v)
				}
				ports[name], svcOwner[name] = p, svc
			case "middlewares":
				if mws[name] == nil {
					mws[name] = map[string]string{}
				}
				// A header name keeps its raw case and characters (the
				// Hub strips X_Forwarded_* spellings on purpose).
				if raw := strings.SplitN(k, ".", 5); len(raw) == 5 && strings.HasPrefix(field, "headers.") {
					if sub, _, ok := strings.Cut(strings.TrimPrefix(field, "headers."), "."); ok {
						field = "headers." + sub + "." + raw[4][strings.Index(strings.ToLower(raw[4]), sub)+len(sub)+1:]
					}
				}
				mws[name][field] = v
			}
		}
	}
	var out []*unstructured.Unstructured
	for _, name := range slices.Sorted(mapKeys(mws)) {
		spec, err := middlewareSpec(instance, name, mws[name], mws)
		if err != nil {
			return nil, err
		}
		out = append(out, crd("Middleware", mwName(instance, name), namespace, instance, spec))
	}
	for _, name := range slices.Sorted(mapKeys(routers)) {
		r := routers[name]
		if r.rule == "" {
			return nil, refused("router %s has no rule", name)
		}
		if !routeMatch.MatchString(r.rule) {
			return nil, refused("router %s: rule %s isn't Host(…) with an optional && Path/PathPrefix over lowercase hostnames (not on Kubernetes)", name, r.rule)
		}
		route := map[string]any{"match": r.rule, "kind": "Rule"}
		if r.priority != "" {
			p, err := strconv.ParseInt(r.priority, 10, 64)
			if err != nil {
				return nil, refused("router %s: bad priority %q", name, r.priority)
			}
			if p > MaxAppPriority {
				return nil, refused("router %s: priority %d is above %d (not on Kubernetes)", name, p, MaxAppPriority)
			}
			route["priority"] = p
		}
		var refs []any
		for _, m := range splitList(r.middlewares) {
			ref, err := middlewareRef(instance, namespace, m, mws)
			if err != nil {
				return nil, fmt.Errorf("router %s: %w", name, err)
			}
			refs = append(refs, ref)
		}
		if len(refs) > 0 {
			route["middlewares"] = refs
		}
		svc, err := serviceRef(instance, appsNamespace, name, r.svc, ports, svcOwner)
		if err != nil {
			return nil, err
		}
		route["services"] = []any{svc}
		spec := map[string]any{"routes": []any{route}}
		eps := splitList(r.entrypoints)
		if len(eps) == 0 {
			eps = []string{"websecure"}
		}
		spec["entryPoints"] = toAny(eps)
		if r.tls {
			tls := map[string]any{}
			if r.tlsOptions != "" {
				if !slices.Contains(TLSOptions, r.tlsOptions) {
					return nil, refused("router %s: tls.options %s is not one of the tiers", name, r.tlsOptions)
				}
				tls["options"] = map[string]any{"name": strings.TrimSuffix(r.tlsOptions, "@file") + "@file"}
			}
			if r.tlsCertResolver != "" {
				tls["certResolver"] = r.tlsCertResolver
			}
			spec["tls"] = tls
		}
		out = append(out, crd("IngressRoute", joinName(instance, "r-"+name, ""), namespace, instance, spec))
	}
	return out, nil
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func crd(kind, name, ns, instance string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": traefikAPI, "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]any{LabelInstance: instance, LabelOwner: OwnerHub}},
		"spec":     spec,
	}}
}

// mwName is an own middleware's object name.
func mwName(instance, name string) string { return joinName(instance, "m-"+name, "") }

// middlewareRef maps a router's middleware name: an own one (defined in
// the instance's labels, bare or @docker) → its Middleware; a K15 core
// name @docker (or bare) / an allowed @file name → <name>@file; anything
// else refused.
func middlewareRef(instance, ns, m string, own map[string]map[string]string) (map[string]any, error) {
	name, provider, hasProvider := strings.Cut(m, "@")
	switch {
	case (!hasProvider || provider == "docker") && own[strings.ToLower(name)] != nil:
		return map[string]any{"name": mwName(instance, strings.ToLower(name)), "namespace": ns}, nil
	case (!hasProvider || provider == "docker" || provider == "file") && slices.Contains(FileMiddlewares, name):
		return map[string]any{"name": name + "@file"}, nil
	}
	return nil, refused("middleware %s is not on Kubernetes (not the instance's own, not a core name apps may use)", m)
}

// serviceRef maps a router's service.
func serviceRef(instance, appsNamespace, router, svc string, ports map[string]int64, owner map[string]string) (map[string]any, error) {
	name, provider, hasProvider := strings.Cut(svc, "@")
	if svc == "" {
		// Traefik's default: the router's container's only service.
		if len(ports) == 1 {
			for n := range ports {
				name = n
			}
		} else {
			return nil, refused("router %s names no service", router)
		}
	}
	switch {
	case (!hasProvider || provider == "docker") && ports[strings.ToLower(name)] != 0:
		n := strings.ToLower(name)
		return map[string]any{"name": ObjectName(instance, owner[n]), "namespace": appsNamespace, "port": ports[n], "kind": "Service"}, nil
	case hasProvider && (provider == "docker" || provider == "file") && slices.Contains(FileServices, name):
		return map[string]any{"name": name + "@file", "kind": "TraefikService"}, nil
	}
	return nil, refused("router %s: service %s is not on Kubernetes", router, svc)
}

// middlewareSpec builds a Middleware's spec from its label fields (the
// types the Hub and the templates render; anything else refused): no
// forwardAuth, no X-Portcullis-* header.
func middlewareSpec(instance, name string, f map[string]string, own map[string]map[string]string) (map[string]any, error) {
	spec := map[string]any{}
	set := func(typ, key string, v any) {
		m, _ := spec[typ].(map[string]any)
		if m == nil {
			m = map[string]any{}
			spec[typ] = m
		}
		m[key] = v
	}
	for _, field := range slices.Sorted(mapKeys(f)) {
		v := f[field]
		typ, rest, _ := strings.Cut(field, ".")
		switch typ {
		case "forwardauth":
			return nil, refused("middleware %s is a forwardAuth (not allowed for apps)", name)
		case "headers":
			sub, header, _ := strings.Cut(rest, ".")
			key := map[string]string{"customrequestheaders": "customRequestHeaders", "customresponseheaders": "customResponseHeaders"}[sub]
			if key == "" || header == "" {
				return nil, refused("middleware %s: headers.%s is not on Kubernetes", name, sub)
			}
			if h := strings.ToLower(strings.ReplaceAll(header, "_", "-")); strings.HasPrefix(h, "x-portcullis-") {
				return nil, refused("middleware %s sets %s (an X-Portcullis-* header)", name, header)
			}
			m, _ := spec["headers"].(map[string]any)
			if m == nil {
				m = map[string]any{}
				spec["headers"] = m
			}
			h, _ := m[key].(map[string]any)
			if h == nil {
				h = map[string]any{}
				m[key] = h
			}
			h[header] = v
		case "ipallowlist":
			switch rest {
			case "sourcerange":
				set("ipAllowList", "sourceRange", toAny(splitList(v)))
			case "rejectstatuscode":
				n, err := strconv.ParseInt(v, 10, 32)
				if err != nil {
					return nil, refused("middleware %s: bad rejectstatuscode %q", name, v)
				}
				set("ipAllowList", "rejectStatusCode", n)
			default:
				return nil, refused("middleware %s: ipallowlist.%s is not on Kubernetes", name, rest)
			}
		case "chain":
			if rest != "middlewares" {
				return nil, refused("middleware %s: chain.%s is not on Kubernetes", name, rest)
			}
			var refs []any
			for _, m := range splitList(v) {
				ref, err := middlewareRef(instance, "", m, own)
				if err != nil {
					return nil, fmt.Errorf("chain %s: %w", name, err)
				}
				delete(ref, "namespace")
				refs = append(refs, ref)
			}
			set("chain", "middlewares", refs)
		case "addprefix":
			if rest != "prefix" {
				return nil, refused("middleware %s: addprefix.%s is not on Kubernetes", name, rest)
			}
			set("addPrefix", "prefix", v)
		case "stripprefix":
			if rest != "prefixes" {
				return nil, refused("middleware %s: stripprefix.%s is not on Kubernetes", name, rest)
			}
			set("stripPrefix", "prefixes", toAny(splitList(v)))
		case "redirectregex":
			switch rest {
			case "regex", "replacement":
				set("redirectRegex", rest, v)
			case "permanent":
				set("redirectRegex", "permanent", v == "true")
			default:
				return nil, refused("middleware %s: redirectregex.%s is not on Kubernetes", name, rest)
			}
		default:
			return nil, refused("middleware %s: type %s is not on Kubernetes", name, typ)
		}
	}
	if len(spec) != 1 {
		return nil, refused("middleware %s must have exactly one type", name)
	}
	return spec, nil
}

// LabelReach marks a VPN-only instance's routes (reach: vpn).
const LabelReach = "portcullis.io/reach"

// markVPNOnly labels the IngressRoutes of a VPN-only instance.
func markVPNOnly(objs []*unstructured.Unstructured) {
	for _, o := range objs {
		if o.GetKind() == "IngressRoute" {
			l := o.GetLabels()
			l[LabelReach] = "vpn"
			o.SetLabels(l)
		}
	}
}
