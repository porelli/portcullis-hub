package doctor

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// The exposure checks (contract §14.7): only lan_only ports are judged,
// template ports and custom-override ports alike. The Hub can't see host
// firewalls or NAT and never probes reachability from outside: the
// bind address is what is judged.

// Finding kinds and the one-click fix of this file.
const (
	KindLANOnlyExposed = "lan_only_exposed"
	KindHostNetwork    = "host_network"

	// FixRebindPort binds a LAN-only port to an address the admin types
	// (Task 12).
	FixRebindPort = "rebind_port"
)

// hostNetworkText is the contract's explain text for host_network.
const hostNetworkText = "Docker publishes around host firewalls such as ufw; restrict the port in your router or host firewall"

func init() {
	Register(lanOnlyExposedCheck{})
	Register(hostNetworkCheck{})
}

// loopback always counts as local.
var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

// IsLocal: a (unmapped first) is loopback or inside one of nets.
func IsLocal(a netip.Addr, nets []netip.Prefix) bool {
	a = a.Unmap()
	for _, n := range append(loopback[:len(loopback):len(loopback)], nets...) {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// ParseBind reads a bind address as compose takes it: "" = all
// interfaces, brackets around IPv6 allowed; unmapped. ok false: not an
// address (judged as all interfaces).
func ParseBind(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

// sortedPorts are in's ports in a stable order.
func sortedPorts(in *Inputs) []PortIn {
	ps := append([]PortIn(nil), in.Ports...)
	sort.Slice(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		if a.Custom != b.Custom {
			return !a.Custom
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Protocol < b.Protocol
	})
	return ps
}

// portName is p as the admin reads it: "SMB (SAMBA_SMB)".
func portName(p PortIn) string {
	if p.Label == "" || p.Label == p.Key {
		return p.Key
	}
	return p.Label + " (" + p.Key + ")"
}

// portSpec is "445/tcp" (or a range).
func portSpec(p PortIn) string {
	s := strconv.Itoa(p.Port)
	if p.PortEnd > p.Port {
		s += "-" + strconv.Itoa(p.PortEnd)
	}
	return s + "/" + p.Protocol
}

// portSubjects identify p: template ports by key, custom-override ports
// by service, container port and host port.
func portSubjects(p PortIn) []string {
	if p.Custom {
		return []string{p.Instance, "custom", p.Service, strconv.Itoa(p.Container), strconv.Itoa(p.Port), p.Protocol}
	}
	return []string{p.Instance, p.Key, p.Protocol}
}

type lanOnlyExposedCheck struct{}

func (lanOnlyExposedCheck) Kind() string { return KindLANOnlyExposed }

func (lanOnlyExposedCheck) Run(in *Inputs) []Finding {
	domain := map[netip.Addr]bool{}
	for _, a := range in.DomainAddrs {
		domain[a.Unmap()] = true
	}
	var out []Finding
	for _, p := range sortedPorts(in) {
		if !p.LanOnly || p.HostNetwork {
			continue
		}
		a, ok := ParseBind(p.Bind)
		all := !ok || a.IsUnspecified()
		f := Finding{
			Kind:      KindLANOnlyExposed,
			FP:        Fingerprint(KindLANOnlyExposed, portSubjects(p)...),
			Instances: []string{p.Instance},
		}
		why := "all"
		switch {
		case all:
			f.Severity = Warning
			f.Title = fmt.Sprintf("%s: LAN-only port %s listens on all interfaces (%s).", p.Instance, portName(p), portSpec(p))
			f.Why = "The template marks this port LAN-only. Bound to all interfaces, it is reachable wherever the host is: from the internet too when the host has a public address or the router forwards the port."
		case domain[a]:
			why = "domain"
			f.Severity = Problem
			f.Title = fmt.Sprintf("%s: LAN-only port %s is bound to %s, an address of %s.", p.Instance, portName(p), a, in.Domain)
			f.Why = fmt.Sprintf("The template marks this port LAN-only, but %s's A / AAAA records point at %s: the port is published where the internet reaches the Hub.", in.Domain, a)
		case !IsLocal(a, in.LocalNetworks):
			why = "outside"
			f.Severity = Problem
			f.Title = fmt.Sprintf("%s: LAN-only port %s is bound to %s, outside the local networks.", p.Instance, portName(p), a)
			f.Why = fmt.Sprintf("The template marks this port LAN-only, but %s isn't in the local networks (Hub Settings → Local networks): it is reachable from outside the LAN.", a)
		default:
			continue
		}
		// A failed lookup changes only the text: a mute holds.
		f.Inputs = Digest([]any{p, why})
		if in.DomainErr && in.Domain != "" {
			f.Why += fmt.Sprintf(" (couldn't resolve %s: the main domain's addresses weren't checked.)", in.Domain)
		}
		if p.Custom {
			f.Class = FixExplain
			f.Fix = "Bind the port to the host's LAN address in the custom override."
			f.Steps = []string{
				fmt.Sprintf("Open %s's Expert tab and edit the custom override's ports entry for container port %d of service %s.", p.Instance, p.Container, p.Service),
				fmt.Sprintf("Write the host's LAN address before the host port, e.g. \"192.168.1.10:%d:%d\".", p.Port, p.Container),
			}
		} else {
			f.Class, f.FixKind = FixOneClick, FixRebindPort
			f.Fix = fmt.Sprintf("Bind %s to the host's LAN address (%s_BIND); %s restarts.", p.Key, p.Key, p.Instance)
		}
		out = append(out, f)
	}
	return out
}

type hostNetworkCheck struct{}

func (hostNetworkCheck) Kind() string { return KindHostNetwork }

func (hostNetworkCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, p := range sortedPorts(in) {
		if !p.LanOnly || !p.HostNetwork {
			continue
		}
		out = append(out, Finding{
			Kind:      KindHostNetwork,
			FP:        Fingerprint(KindHostNetwork, portSubjects(p)...),
			Severity:  Warning,
			Title:     fmt.Sprintf("%s: LAN-only port %s uses host networking (%s).", p.Instance, portName(p), portSpec(p)),
			Why:       "Service " + p.Service + " runs on the host's network: the Hub can't publish the port to the LAN only. " + hostNetworkText + ".",
			Instances: []string{p.Instance},
			Class:     FixExplain,
			Steps:     []string{hostNetworkText + "."},
			Inputs:    Digest([]any{p}),
		})
	}
	return out
}
