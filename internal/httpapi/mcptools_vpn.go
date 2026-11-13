package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

// The VPN admin tools (contract §15.10): get_vpn and list_vpn_devices
// (R), remove_vpn_device, set_vpn_provider, assign_vpn_address and
// set_instance_reach (D, per-call confirmation where they widen access).
// No tool creates a device configuration: no key ever lands in a
// transcript, and no output carries a public key either.

type (
	vpnDevicesArgs struct {
		User string `json:"user,omitempty"`
	}
	vpnDeviceIDArgs struct {
		ID string `json:"id"`
	}
	vpnProviderToolArgs struct {
		ID      string `json:"id"`
		Wired   bool   `json:"wired"`
		Refresh string `json:"refresh,omitempty"`
	}
	vpnAssignArgs struct {
		ID string `json:"id"`
		IP string `json:"ip"`
		// User and Name assign; Remove (with neither) unassigns (the
		// contract's two shapes, anything else is refused).
		User   string `json:"user,omitempty"`
		Name   string `json:"name,omitempty"`
		Remove bool   `json:"remove,omitempty"`
	}
	vpnReachArgs struct {
		ID          string   `json:"id"`
		Mode        string   `json:"mode"`
		Via         []string `json:"via,omitempty"`
		PublicLinks bool     `json:"public_links,omitempty"`
	}
)

func (s *Server) registerVPNTools() {
	for _, t := range []Tool{
		admin("get_vpn", "The VPN overview: the mode and public enrolment (set on the host), whether the wg service is up, the built-in provider, every VPN-capable instance (wired or not, its ranges, devices, freshness, last error and the devices it left out) and Settings → VPN. No keys.",
			ClassRead, "GET /api/vpn", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
				return s.Hub.VPNOverview(ctx), nil
			}),
		admin("list_vpn_devices", "Every person's VPN devices on every provider (or one person's): name, provider, address, last seen, expiry, online. No keys.",
			ClassRead, "GET /api/vpn/devices", "", func(ctx context.Context, _ directory.Actor, in vpnDevicesArgs) (any, error) {
				return s.Hub.AllVPNDevices(ctx, in.User), nil
			}),
		{Name: "remove_vpn_device", Description: "Remove a built-in VPN device (needs your confirmation in the browser): it can't connect any more and its address is kept unused for 7 days. Marketplace devices are managed in their app.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "DELETE /api/vpn/devices/{id}", Audit: "vpn.device_removed", In: vpnDeviceIDArgs{},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				return []string{"Removes VPN device " + q(idOf(args)) + ": it can't connect any more."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, _ := decode[vpnDeviceIDArgs](args)
				if err := s.removeVPNDevice(ctx, toolActor(ctx, c), in.ID); err != nil {
					return nil, err
				}
				return map[string]string{"status": "removed", "id": in.ID}, nil
			}},
		{Name: "set_vpn_provider", Description: "Use an instance with a VPN (its vpn: block) for Portcullis access, or stop using it. Wiring makes its devices a way into VPN-only apps and needs your confirmation in the browser; unwiring only narrows.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "PUT /api/instances/{id}/vpn-provider", Audit: "vpn.provider_wired", In: vpnProviderToolArgs{},
			ClassFor: func(_ context.Context, args json.RawMessage) ToolClass {
				if a, err := decode[vpnProviderToolArgs](args); err == nil && !a.Wired {
					return ClassWrite
				}
				return ClassDestructive
			},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				return []string{"Makes " + idOf(args) + "'s VPN devices a way into every VPN-only app that accepts all providers (each device still bound to its owner, behind sign-in)."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, _ := decode[vpnProviderToolArgs](args)
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.setVPNProvider(ctx, toolActor(ctx, c), in.ID, vpnProviderArgs{Wired: in.Wired, Refresh: in.Refresh})
			}},
		{Name: "assign_vpn_address", Description: "Assign an address of a static VPN provider (a plain WireGuard app) to a person and device name, or remove the assignment (remove: true, no user or name). Assigning needs your confirmation in the browser.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "PUT /api/instances/{id}/vpn-static/{ip}", AlsoTwins: []string{"DELETE /api/instances/{id}/vpn-static/{ip}"}, Audit: "vpn.static_assigned", In: vpnAssignArgs{},
			ClassFor: func(_ context.Context, args json.RawMessage) ToolClass {
				if a, err := decode[vpnAssignArgs](args); err == nil && a.Remove && a.User == "" && a.Name == "" {
					return ClassWrite
				}
				return ClassDestructive
			},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[vpnAssignArgs](args)
				return []string{"Traffic from " + q(a.IP) + " on " + a.ID + "'s VPN counts as " + q(a.User) + "'s device " + q(a.Name) + " for VPN-only apps."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, _ := decode[vpnAssignArgs](args)
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				if in.Remove == (in.User != "" || in.Name != "") || !in.Remove && (in.User == "" || in.Name == "") {
					return nil, &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New("give user and name, or remove: true")}
				}
				if in.Remove {
					if err := s.unassignVPN(ctx, toolActor(ctx, c), in.ID, in.IP); err != nil {
						return nil, err
					}
					return map[string]string{"status": "unassigned", "ip": in.IP}, nil
				}
				if err := s.assignVPN(ctx, toolActor(ctx, c), in.ID, in.IP, in.User, in.Name); err != nil {
					return nil, err
				}
				return map[string]string{"status": "assigned", "ip": in.IP}, nil
			}},
		{Name: "set_instance_reach", Description: "Set where an instance is reachable from: internet, or vpn (only through Portcullis VPNs, via all providers [\"*\"] or the ones named), and whether its public links stay on the internet in server mode. Widening needs your confirmation in the browser.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "PUT /api/instances/{id}/reach", Audit: "instance.reach", In: vpnReachArgs{},
			ClassFor: func(_ context.Context, args json.RawMessage) ToolClass {
				// W only when the change keeps or narrows the instance's
				// access as it is now (the Hub's access key, the same
				// predicate as the re-render's); anything else, an unknown
				// instance included, is D.
				if a, err := decode[vpnReachArgs](args); err == nil && s.Hub.ReachChangeNarrows(a.ID, state.Reach{Mode: a.Mode, Via: a.Via, PublicLinks: a.PublicLinks}) {
					return ClassWrite
				}
				return ClassDestructive
			},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[vpnReachArgs](args)
				line := a.ID + " becomes reachable from " + q(a.Mode)
				if len(a.Via) > 0 {
					line += " through " + strings.Join(quoteAll(a.Via), ", ")
				}
				if a.PublicLinks {
					line += "; its public links stay on the internet in server mode"
				}
				return []string{line + "."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, _ := decode[vpnReachArgs](args)
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				r := state.Reach{Mode: in.Mode, Via: in.Via, PublicLinks: in.PublicLinks}
				// Classed W without a confirmation: SetInstanceReach still
				// refuses (409) anything but a keep or narrow, decided
				// under its lock on the value it stores.
				if err := s.setInstanceReach(ctx, toolActor(ctx, c), in.ID, r); err != nil {
					return nil, err
				}
				return map[string]any{"instance": in.ID, "mode": in.Mode, "via": in.Via, "public_links": in.PublicLinks}, nil
			}},
	} {
		s.registerTool(t)
	}
}
