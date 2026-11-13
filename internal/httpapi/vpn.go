package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

// The VPN admin API (contract §11; Hub listener only, administrators):
// the overview, Settings → VPN, wiring a provider, an instance's reach,
// static assignments, the DNS acknowledgement and every person's
// devices. Audited by the Hub (vpn.*, instance.reach); never key
// material.

func (s *Server) registerVPN(mux routeMux) {
	mux.HandleFunc("GET /api/vpn", s.handleVPN)
	mux.HandleFunc("PUT /api/vpn/settings", s.handleVPNSettings)
	mux.HandleFunc("PUT /api/instances/{id}/vpn-provider", s.handleVPNProvider)
	mux.HandleFunc("PUT /api/instances/{id}/reach", s.handleInstanceReach)
	mux.HandleFunc("PUT /api/instances/{id}/vpn-static/{ip}", s.handleVPNStatic)
	mux.HandleFunc("DELETE /api/instances/{id}/vpn-static/{ip}", s.handleVPNUnstatic)
	mux.HandleFunc("POST /api/instances/{id}/vpn-dns/ack", s.handleVPNDNSAck)
	mux.HandleFunc("GET /api/vpn/devices", s.handleVPNAllDevices)
	mux.HandleFunc("DELETE /api/vpn/devices/{id}", s.handleVPNRemoveDevice)
}

// vpnBody decodes a VPN body strictly (≤ 8 KiB).
func vpnBody(w http.ResponseWriter, r *http.Request, v any, usage string) bool {
	return readMySignInBody(w, r, v, usage)
}

// vpnErr answers a VPN refusal with the Hub's status and text.
func vpnErr(w http.ResponseWriter, err error) {
	writeErr(w, err, http.StatusInternalServerError)
}

func (s *Server) handleVPN(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, s.Hub.VPNOverview(r.Context()))
}

func (s *Server) handleVPNSettings(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var u hub.VPNSettingsUpdate
	if !vpnBody(w, r, &u, `{"users_group", "devices_per_person", "expiry"} (any of them)`) {
		return
	}
	if err := s.Hub.SetVPNSettings(r.Context(), requestActor(r), u); err != nil {
		vpnErr(w, err)
		return
	}
	writeJSON(w, s.Hub.VPNOverview(r.Context()).Settings)
}

// vpnProviderArgs is PUT /api/instances/{id}/vpn-provider's body.
type vpnProviderArgs struct {
	Wired   bool   `json:"wired"`
	Refresh string `json:"refresh,omitempty"`
}

func (s *Server) setVPNProvider(ctx context.Context, a directory.Actor, id string, in vpnProviderArgs) (any, error) {
	s.rec("SetVPNProvider", id, in.Wired, in.Refresh)
	var refresh time.Duration
	if in.Refresh != "" {
		d, err := time.ParseDuration(in.Refresh)
		if err != nil {
			return nil, badArg("refresh: a duration between 15s and 10m")
		}
		refresh = d
	}
	if err := s.Hub.SetVPNProvider(ctx, a, id, in.Wired, refresh); err != nil {
		return nil, err
	}
	return map[string]any{"instance": id, "wired": in.Wired}, nil
}

func (s *Server) handleVPNProvider(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var in vpnProviderArgs
	if !vpnBody(w, r, &in, `{"wired": true|false, "refresh": "60s"}`) {
		return
	}
	out, err := s.setVPNProvider(r.Context(), requestActor(r), r.PathValue("id"), in)
	if err != nil {
		vpnErr(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleInstanceReach(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var in state.Reach
	if !vpnBody(w, r, &in, `{"mode": "internet"|"vpn", "via": ["*"], "public_links": false}`) {
		return
	}
	if err := s.setInstanceReach(r.Context(), requestActor(r), r.PathValue("id"), in); err != nil {
		vpnErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setInstanceReach / assignVPN / unassignVPN are the routes' and tools'
// shared work.
func (s *Server) setInstanceReach(ctx context.Context, a directory.Actor, id string, in state.Reach) error {
	s.rec("SetInstanceReach", id, in.Mode, in.Via, in.PublicLinks)
	return s.Hub.SetInstanceReach(ctx, a, id, in)
}

func (s *Server) assignVPN(ctx context.Context, a directory.Actor, id, ip, user, name string) error {
	s.rec("AssignVPNAddress", id, ip, user, name)
	return s.Hub.AssignVPNAddress(ctx, a, id, ip, user, name)
}

func (s *Server) unassignVPN(ctx context.Context, a directory.Actor, id, ip string) error {
	s.rec("UnassignVPNAddress", id, ip)
	return s.Hub.UnassignVPNAddress(ctx, a, id, ip)
}

func (s *Server) handleVPNStatic(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var in struct {
		User string `json:"user"`
		Name string `json:"name"`
	}
	if !vpnBody(w, r, &in, `{"user", "name"}`) {
		return
	}
	if err := s.assignVPN(r.Context(), requestActor(r), r.PathValue("id"), r.PathValue("ip"), in.User, in.Name); err != nil {
		vpnErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleVPNUnstatic(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	if err := s.unassignVPN(r.Context(), requestActor(r), r.PathValue("id"), r.PathValue("ip")); err != nil {
		vpnErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleVPNDNSAck(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	if err := s.Hub.AckVPNDNS(r.Context(), requestActor(r), r.PathValue("id")); err != nil {
		vpnErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleVPNAllDevices(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, s.Hub.AllVPNDevices(r.Context(), r.URL.Query().Get("user")))
}

// removeVPNDevice removes a built-in device (route and
// remove_vpn_device): 409 "managed in <label>" for a marketplace one, 404
// for an unknown id.
func (s *Server) removeVPNDevice(ctx context.Context, a directory.Actor, id string) error {
	s.rec("RemoveVPNDevice", id)
	if s.Hub.VPNDeviceOwner(id) == "" {
		for _, d := range s.Hub.AllVPNDevices(ctx, "") {
			if d.ID == id && !d.Managed {
				return &hub.StatusError{Status: http.StatusConflict, Err: errors.New("managed in " + d.ProviderLabel)}
			}
		}
		return &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("no such device")}
	}
	return s.Hub.RemoveVPNDevice(ctx, a, id)
}

func (s *Server) handleVPNRemoveDevice(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	if err := s.removeVPNDevice(r.Context(), requestActor(r), r.PathValue("id")); err != nil {
		vpnErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
