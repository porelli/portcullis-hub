package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// The host control socket (contract §16): HTTP on a Unix socket in the
// Hub's tmpfs (mode 0600), never on a TCP listener (the /host/ routes are
// 404 on all three). Its only clients are `hub vpn …` inside the Hub
// container (`./portcullis vpn …` on the host). The audit actor is host.

// HostSocketPath is the control socket.
const HostSocketPath = "/tmp/hub-host.sock"

// hostBodyMax bounds a control request body.
const hostBodyMax = 8 << 10

// HostHandler is the control socket's routes.
func HostHandler(h *hub.Hub) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /host/vpn/devices", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			User      string `json:"user"`
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, hostBodyMax))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&b); err != nil || dec.Decode(&struct{}{}) != io.EOF {
			http.Error(w, `body must be {"user", "name", "public_key"}`, http.StatusBadRequest)
			return
		}
		cfg, err := h.HostAddVPNDevice(r.Context(), b.User, b.Name, b.PublicKey)
		if err != nil {
			hostErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("GET /host/vpn/devices", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, h.HostVPNDevices(r.Context(), r.URL.Query().Get("user")))
	})
	mux.HandleFunc("DELETE /host/vpn/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := h.RemoveVPNDevice(r.Context(), directory.Human(hub.HostActor), r.PathValue("id")); err != nil {
			hostErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /host/vpn/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, h.VPNHostInfo(r.Context()))
	})
	return mux
}

func hostErr(w http.ResponseWriter, err error) {
	var se *hub.StatusError
	if errors.As(err, &se) {
		http.Error(w, se.Error(), se.Status)
		return
	}
	log.Printf("host socket: %v", err)
	http.Error(w, "the Hub couldn't do it: see its log", http.StatusInternalServerError)
}

// ListenHost opens the control socket at path, mode 0600 (a stale socket
// file is replaced; anything else there refuses).
func ListenHost(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, errors.New(path + " exists and isn't a socket")
		}
		os.Remove(path)
	}
	old := syscall.Umask(0o177)
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
