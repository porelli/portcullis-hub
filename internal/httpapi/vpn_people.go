package httpapi

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
)

// The people listener's VPN page (contract §5.1): GET /vpn/, its own
// assets under /vpn/assets/ (vpnAssets: the page's files and its own
// copies of the fresh-auth scripts, reachable while /static/ is VPN-only
// in server mode), and the caller's devices under /vpn/api/. People →
// person's VPN devices (§9.7) are /api/people/{user}/vpn-devices.

// vpnAssets are the only files /vpn/assets/ serves.
var vpnAssets = map[string]bool{"vpn.js": true, "qrcode.js": true, "freshauth.js": true, "freshauth-callback.js": true, "directory.css": true, "favicon.svg": true}

// vpnAssetPath is the embedded path of a /vpn/assets/ file.
func vpnAssetPath(f string) string {
	if f == "qrcode.js" {
		return "vendor/qrcode.js"
	}
	return f
}

func (s *Server) registerVPNPeople(mux routeMux) {
	mux.HandleFunc("GET /vpn/{$}", s.handleVPNPage)
	mux.HandleFunc("GET /vpn/assets/{file}", s.handleVPNAsset)
	mux.HandleFunc("GET /vpn/api/devices", s.handleMyVPNDevices)
	mux.HandleFunc("POST /vpn/api/devices", s.handleAddVPNDevice)
	mux.HandleFunc("PUT /vpn/api/devices/{id}", s.handleRenameVPNDevice)
	mux.HandleFunc("DELETE /vpn/api/devices/{id}", s.handleRemoveMyVPNDevice)
	mux.HandleFunc("POST /vpn/api/devices/{id}/renew", s.handleRenewVPNDevice)
	mux.HandleFunc("GET /api/people/{user}/vpn-devices", s.handlePersonVPNDevices)
	mux.HandleFunc("DELETE /api/people/{user}/vpn-devices/{id}", s.handleRemovePersonVPNDevice)
}

// vpnCSP: the page loads only its own scripts, fetches only its own
// origin and Keycloak's (fresh auth opens a popup), never framed.
const vpnCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

func (s *Server) handleVPNPage(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFS(s.Web, "vpn.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	domain := ""
	if s.Hub != nil {
		domain = s.Hub.Domain()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", vpnCSP)
	if err := t.Execute(w, map[string]any{"Domain": domain, "HubURL": s.HubURL, "PeopleURL": s.PeopleURL}); err != nil {
		log.Printf("render vpn page: %v", err)
	}
}

func (s *Server) handleVPNAsset(w http.ResponseWriter, r *http.Request) {
	f := strings.ToLower(r.PathValue("file"))
	if !vpnAssets[f] {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(s.Web, vpnAssetPath(f))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(f, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(f, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(f, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

// vpnDevicesPage is GET /vpn/api/devices: the caller's devices and what
// the page needs to start a fresh sign-in.
type vpnDevicesPage struct {
	Devices   []hub.VPNDeviceView      `json:"devices"`
	FreshAuth *freshauth.AuthorizeInfo `json:"fresh_auth"`
}

func (s *Server) handleMyVPNDevices(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	noStore(w)
	writeJSON(w, vpnDevicesPage{Devices: s.Hub.VPNDevices(r.Context(), user), FreshAuth: s.Hub.FreshAuthInfoFor(hub.ListenerPeopleVPN)})
}

// vpnAddBody is the add / renew body: only the public key and the
// fresh-auth proof (never a private key).
type vpnAddBody struct {
	Name         string `json:"name"`
	PublicKey    string `json:"public_key"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

func (s *Server) handleAddVPNDevice(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	var b vpnAddBody
	if !readMySignInBody(w, r, &b, `{"name": "...", "public_key": "...", "code": "...", "code_verifier": "...", "nonce": "..."}`) {
		return
	}
	cfg, err := s.Hub.AddVPNDevice(r.Context(), user, b.Name, b.PublicKey, freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce})
	if err != nil {
		mySignInErr(w, "adding a VPN device of "+user, err)
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cfg)
}

func (s *Server) handleRenameVPNDevice(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	var b struct {
		Name string `json:"name"`
	}
	if !readMySignInBody(w, r, &b, `{"name": "..."}`) {
		return
	}
	if err := s.Hub.RenameVPNDevice(r.Context(), selfActor(r, user), user, r.PathValue("id"), b.Name); err != nil {
		mySignInErr(w, "renaming a VPN device of "+user, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveMyVPNDevice(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if s.Hub.VPNDeviceOwner(id) != user {
		http.Error(w, "no such device", http.StatusNotFound)
		return
	}
	if err := s.Hub.RemoveVPNDevice(r.Context(), selfActor(r, user), id); err != nil {
		mySignInErr(w, "removing a VPN device of "+user, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRenewVPNDevice(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	var b vpnAddBody
	if !readMySignInBody(w, r, &b, `{"public_key": "...", "code": "...", "code_verifier": "...", "nonce": "..."}`) {
		return
	}
	if b.Name != "" {
		http.Error(w, "a renewal keeps the device's name", http.StatusBadRequest)
		return
	}
	cfg, err := s.Hub.RenewVPNDevice(r.Context(), user, r.PathValue("id"), b.PublicKey, freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce})
	if err != nil {
		mySignInErr(w, "renewing a VPN device of "+user, err)
		return
	}
	noStore(w)
	writeJSON(w, cfg)
}

func (s *Server) handlePersonVPNDevices(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	if _, ok := mySignInUser(w, r); !ok {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	u := r.PathValue("user")
	v, err := s.Hub.PersonVPNDevices(r.Context(), c, u)
	if err != nil {
		mySignInErr(w, "VPN devices of "+u, err)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

func (s *Server) handleRemovePersonVPNDevice(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	if _, ok := mySignInUser(w, r); !ok {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	u := r.PathValue("user")
	if err := s.Hub.RemovePersonVPNDevice(r.Context(), c, u, r.PathValue("id")); err != nil {
		mySignInErr(w, "removing a VPN device of "+u, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
