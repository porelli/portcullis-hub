package doctor

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

// VPN kinds (contract §14.5, spec §12): judged on Inputs.VPN (nil = the
// Hub had no VPN inputs: none fire). All explain-only; every why ends
// with VPNUDPNote.
const (
	KindVPNDown              = "vpn_down"
	KindVPNProviderStale     = "vpn_provider_stale"
	KindVPNProviderInvalid   = "vpn_provider_invalid"
	KindVPNRangeOverlap      = "vpn_range_overlap"
	KindVPNViaDead           = "vpn_via_dead"
	KindVPNDNSFailed         = "vpn_dns_failed"
	KindVPNDNSManual         = "vpn_dns_manual"
	KindVPNGatewayPrivileged = "vpn_gateway_privileged"
	KindVPNStaticMapping     = "vpn_static_mapping"
	KindVPNSingleProvider    = "vpn_single_provider"
	KindVPNPublicLinks       = "vpn_public_links"
	KindVPNNoAdminDevice     = "vpn_no_admin_device"
	KindVPNDeviceStale       = "vpn_device_stale"
	KindVPNExpiring          = "vpn_expiring"
	KindVPNReachFailedClosed = "vpn_reach_failed_closed"
	vpnNoAdminDeviceWindow   = 30 * 24 * time.Hour
	vpnDeviceStaleWindow     = 90 * 24 * time.Hour
	vpnExpiringWindow        = 14 * 24 * time.Hour
	vpnModeApps              = "apps"
	vpnSourceStatic          = "static"
	vpnBuiltin               = "builtin"
)

// VPNUDPNote ends every VPN finding's why.
const VPNUDPNote = "Portcullis can't test UDP reachability from outside."

// VPNKinds are the VPN kinds.
var VPNKinds = []string{KindVPNDown, KindVPNProviderStale, KindVPNProviderInvalid, KindVPNRangeOverlap, KindVPNViaDead, KindVPNDNSFailed,
	KindVPNDNSManual, KindVPNGatewayPrivileged, KindVPNStaticMapping, KindVPNSingleProvider, KindVPNPublicLinks, KindVPNNoAdminDevice,
	KindVPNDeviceStale, KindVPNExpiring, KindVPNReachFailedClosed}

// VPNIn is what the VPN kinds judge.
type VPNIn struct {
	Mode    string
	WGUp    bool
	WGError string
	// Builtin: the built-in provider is on.
	Builtin bool
	// VPNOnly are the enabled VPN-only instances.
	VPNOnly       []string
	Providers     []VPNProviderIn
	Instances     []VPNInstanceIn
	LocalNetworks []netip.Prefix
	DockerNets    []netip.Prefix
	Devices       []VPNDeviceIn
	// AdminSeen: the last time an administrator's device was seen on the
	// built-in or a hook provider (zero: never).
	AdminSeen time.Time
	// FailedClosed: instances stopped because a narrowing VPN change
	// couldn't be applied.
	FailedClosed []string
}

// VPNProviderIn is one wired provider.
type VPNProviderIn struct {
	ID, Label, Source string
	Stale             bool
	LastError         string
	GatewayUp         bool
	GatewayPrivileged bool
	// PrivilegedServices: the gateway's (or its namespace's) services
	// with NET_ADMIN, privileged or host devices.
	PrivilegedServices []string
	Ranges             []netip.Prefix
	Duplicates         int
	Outside            int
	Unresolved         int
	DNSManual          bool
	DNSAcked           bool
	DNSError           string
}

// VPNInstanceIn is one instance's reach.
type VPNInstanceIn struct {
	ID          string
	Via         []string
	PublicLinks bool
}

// VPNDeviceIn is one built-in device.
type VPNDeviceIn struct {
	ID, User      string
	Name          string
	Created       time.Time
	LastHandshake *time.Time
	Expires       *time.Time
}

func init() {
	for _, k := range VPNKinds {
		Register(vpnCheck{kind: k})
	}
}

type vpnCheck struct{ kind string }

func (c vpnCheck) Kind() string { return c.kind }

// vpnFinding is the common shape: explain-only, the UDP note.
func vpnFinding(kind string, sev Severity, title, why string, steps []string, inputs string, fp ...string) Finding {
	return Finding{FP: Fingerprint(kind, fp...), Kind: kind, Severity: sev, Title: title, Why: strings.TrimSpace(why + " " + VPNUDPNote),
		Class: FixExplain, Steps: steps, Inputs: Digest([]string{string(sev), inputs})}
}

func (c vpnCheck) Run(in *Inputs) []Finding {
	v := in.VPN
	if v == nil {
		return nil
	}
	var out []Finding
	admin := v.Mode != "" && v.Mode != vpnModeApps
	switch c.kind {
	case KindVPNDown:
		if (len(v.VPNOnly) > 0 || admin || len(v.Providers) > 0) && !v.WGUp {
			why := "VPN-only apps, the " + v.Mode + " mode or wired VPN providers need the wg service, and it isn't up"
			if v.WGError != "" {
				why += " (" + v.WGError + ")"
			}
			out = append(out, vpnFinding(c.kind, Problem, "The VPN service is down: every VPN request is refused.", why+".",
				[]string{"Run `./portcullis up` on the server.", "Check `./portcullis logs wg`."}, v.WGError))
		}
	case KindVPNProviderStale:
		for _, p := range v.Providers {
			if p.Source == vpnSourceStatic || !p.Stale && p.GatewayUp {
				continue
			}
			why := p.Label + "'s device list is out of date or its gateway is down, so its devices are refused."
			if !p.GatewayUp {
				why = p.Label + "'s gateway container isn't running, so its devices are refused."
			}
			if p.LastError != "" {
				why += " Last error: " + p.LastError
			}
			out = append(out, withInstance(vpnFinding(c.kind, Problem, p.ID+"'s VPN device list is stale.", why,
				[]string{"Start " + p.ID + " if it is stopped, and check its identity hook (the VPN tab shows the last error)."}, p.LastError+fmt.Sprint(p.GatewayUp), p.ID), p.ID))
		}
	case KindVPNProviderInvalid:
		for _, p := range v.Providers {
			if p.Duplicates > 0 {
				out = append(out, withInstance(vpnFinding(c.kind, Problem, fmt.Sprintf("%s reports %d devices sharing an address.", p.ID, p.Duplicates),
					"Every device with a shared address is left out of the map until the app fixes it.",
					[]string{"Check the devices of " + p.ID + " in the app (its VPN tab lists the ones left out)."}, fmt.Sprint(p.Duplicates), p.ID, "dup"), p.ID))
			}
			if p.Outside+p.Unresolved > 0 {
				out = append(out, withInstance(vpnFinding(c.kind, Info, fmt.Sprintf("%s reports devices Portcullis leaves out.", p.ID),
					fmt.Sprintf("%d outside its ranges, %d whose owner isn't a Portcullis person allowed to use the VPN.", p.Outside, p.Unresolved),
					[]string{"Its VPN tab lists them and why."}, fmt.Sprint(p.Outside, p.Unresolved), p.ID, "left-out"), p.ID))
			}
		}
	case KindVPNRangeOverlap:
		for _, p := range v.Providers {
			for _, r := range p.Ranges {
				if d := firstOverlapping(r, v.DockerNets); d.IsValid() {
					out = append(out, withInstance(vpnFinding(c.kind, Problem, fmt.Sprintf("%s's range %s overlaps a container network (%s).", p.ID, r, d),
						"A provider range overlapping a container network can't be wired: its addresses would be the containers' own.",
						[]string{"Change " + p.ID + "'s client range (its settings), then wire it again."}, r.String()+d.String(), p.ID, r.String(), "docker"), p.ID))
				}
				if l := firstOverlapping(r, v.LocalNetworks); l.IsValid() {
					out = append(out, withInstance(vpnFinding(c.kind, Warning, fmt.Sprintf("%s's range %s overlaps your Local networks (%s).", p.ID, r, l),
						"Its devices also reach LAN-only ports, as the Local networks allow; that never counts for VPN-only apps.",
						[]string{"Narrow Local networks (Settings) if the VPN shouldn't reach LAN-only ports."}, r.String()+l.String(), p.ID, r.String(), "local"), p.ID))
				}
			}
		}
	case KindVPNViaDead:
		live := map[string]bool{}
		if v.Builtin && v.WGUp {
			live[vpnBuiltin] = true
		}
		for _, p := range v.Providers {
			if !p.Stale && p.GatewayUp && v.WGUp {
				live[p.ID] = true
			}
		}
		for _, i := range v.Instances {
			if len(i.Via) == 0 || slices.Contains(i.Via, "*") {
				continue
			}
			if !slices.ContainsFunc(i.Via, func(id string) bool { return live[id] }) {
				out = append(out, withInstance(vpnFinding(c.kind, Problem, i.ID+" is unreachable: none of the VPNs it accepts works.",
					"Its Through names only "+strings.Join(i.Via, ", ")+", none of them wired and fresh.",
					[]string{"Wire one of them again, or widen " + i.ID + "'s Through (its Access section)."}, strings.Join(i.Via, ","), i.ID), i.ID))
			}
		}
	case KindVPNDNSFailed:
		for _, p := range v.Providers {
			if p.DNSError != "" {
				out = append(out, withInstance(vpnFinding(c.kind, Problem, p.ID+"'s DNS hook failed.",
					"Portcullis names then resolve publicly on its devices and VPN-only apps answer /vpn-required. "+p.DNSError,
					[]string{"Check the dns hook of " + p.ID + " (its VPN tab)."}, p.DNSError, p.ID), p.ID))
			}
		}
	case KindVPNDNSManual:
		for _, p := range v.Providers {
			if p.DNSManual && !p.DNSAcked {
				out = append(out, withInstance(vpnFinding(c.kind, Info, p.ID+"'s DNS records are set by hand.",
					"Configure the records its VPN tab lists in the app, then acknowledge them there.", []string{"Open " + p.ID + "'s VPN tab."}, "", p.ID), p.ID))
			}
		}
	case KindVPNGatewayPrivileged:
		for _, p := range v.Providers {
			if p.GatewayPrivileged {
				svcs := strings.Join(p.PrivilegedServices, ", ")
				out = append(out, withInstance(vpnFinding(c.kind, Info, p.ID+"'s gateway has NET_ADMIN, privileged mode or host devices ("+svcs+").",
					"A gateway with those on the VPN network could pretend to be another provider's gateway; Portcullis trusts the template with the host.",
					[]string{"Prefer a userspace mode of the app's VPN client if it has one."}, svcs, p.ID), p.ID))
			}
		}
	case KindVPNStaticMapping:
		for _, p := range v.Providers {
			if p.Source == vpnSourceStatic {
				out = append(out, withInstance(vpnFinding(c.kind, Info, p.ID+" maps devices statically.",
					"Static mapping: devices are assigned by an admin, and Portcullis can't prove a device exists (the app owns peers and keys).",
					[]string{"Keep its static assignments up to date (its VPN tab)."}, "", p.ID), p.ID))
			}
		}
	case KindVPNSingleProvider:
		n := len(v.Providers)
		if v.Builtin {
			n++
		}
		if admin && n == 1 {
			out = append(out, vpnFinding(c.kind, Warning, "Only one VPN provider serves the "+v.Mode+" mode.",
				"If it fails, nobody reaches what is VPN-only. The built-in VPN is a second path that needs nothing but the wg service.",
				[]string{"Turn on the built-in VPN: `./portcullis vpn init` (or wire a second provider).", "`./portcullis vpn add-device` on the host always mints a built-in device for an admin."}, v.Mode))
		}
	case KindVPNPublicLinks:
		for _, i := range v.Instances {
			if i.PublicLinks {
				out = append(out, withInstance(vpnFinding(c.kind, Warning, i.ID+"'s public links stay on the internet in server mode.",
					"Its share links answer anyone on the internet, outside the VPN.", []string{"Turn the opt-in off in its Access section if they don't need to."}, "", i.ID), i.ID))
			}
		}
	case KindVPNNoAdminDevice:
		if admin && (v.AdminSeen.IsZero() || in.Now.Sub(v.AdminSeen) > vpnNoAdminDeviceWindow) {
			out = append(out, vpnFinding(c.kind, Problem, "No administrator's VPN device was seen in 30 days.",
				"In the "+v.Mode+" mode the Hub is VPN-only: without an administrator's working device, nobody can manage Portcullis from the browser.",
				[]string{"Connect an administrator's device, or run `./portcullis vpn add-device <you> <name>` on the host.", "Break-glass: `./portcullis vpn mode apps` on the host."}, v.Mode+v.AdminSeen.String()))
		}
	case KindVPNDeviceStale:
		for _, d := range v.Devices {
			last := d.Created
			if d.LastHandshake != nil {
				last = *d.LastHandshake
			}
			if !last.IsZero() && in.Now.Sub(last) > vpnDeviceStaleWindow {
				f := vpnFinding(c.kind, Info, d.User+"'s VPN device "+d.Name+" hasn't connected in 90 days.",
					"An unused device's key still works until it is removed or expires.",
					[]string{"Remove it (People → " + d.User + " → VPN devices) if it isn't used any more."}, last.String(), d.ID)
				f.Persons = []string{d.User}
				out = append(out, f)
			}
		}
	case KindVPNExpiring:
		for _, d := range v.Devices {
			if d.Expires != nil && d.Expires.After(in.Now) && d.Expires.Sub(in.Now) <= vpnExpiringWindow {
				f := vpnFinding(c.kind, Info, d.User+"'s VPN device "+d.Name+" expires on "+d.Expires.Format("2006-01-02")+".",
					"After that it can't connect until it is renewed (a new key, made on the VPN page).",
					[]string{d.User + " renews it at people.<domain>/vpn/."}, d.Expires.String(), d.ID)
				f.Persons = []string{d.User}
				out = append(out, f)
			}
		}
	case KindVPNReachFailedClosed:
		for _, id := range v.FailedClosed {
			out = append(out, withInstance(vpnFinding(c.kind, Problem, id+" was stopped: its VPN access couldn't be narrowed.",
				"A change that takes VPN access away couldn't be written into its configuration, so Portcullis stopped it rather than leave the wider access in place. It starts again once the change is written.",
				[]string{"Check the Hub's log and data volume (free space, permissions); the Hub retries on its own."}, "", id), id))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].FP < out[j].FP })
	return out
}

func withInstance(f Finding, id string) Finding {
	f.Instances = []string{id}
	return f
}

// firstOverlapping is the first prefix of ps overlapping r (invalid: none).
func firstOverlapping(r netip.Prefix, ps []netip.Prefix) netip.Prefix {
	for _, p := range ps {
		if p.Overlaps(r) {
			return p
		}
	}
	return netip.Prefix{}
}
