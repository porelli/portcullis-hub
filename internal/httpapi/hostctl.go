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
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// The host control socket (contract §16): HTTP on a Unix socket in the
// Hub's tmpfs (mode 0600), never on a TCP listener (the /host/ routes are
// 404 on all three). Its only clients are `hub vpn …` and `hub mail …`
// inside the Hub container (`./portcullis vpn …` / `mail disable` on the
// host). The audit actor is host.

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
	// Mail (contract §19.10): `./portcullis mail disable` drains every
	// mail domain and waits for every one to be off.
	mux.HandleFunc("POST /host/mail/drain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"domains": h.HostMailDrain(r.Context())})
	})
	mux.HandleFunc("GET /host/mail/domains", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, h.HostMailDomains())
	})
	// The mail provider (contract §19.10): its view with the warning,
	// and the install-and-wire of `./portcullis mail enable` (the host
	// operator's typed confirmation stands in for the fresh sign-in).
	mux.HandleFunc("GET /host/mail/provider", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, h.HostMailProviderView(r.Context()))
	})
	mux.HandleFunc("GET /host/mail/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, h.HostMailStatus(r.Context()))
	})
	mux.HandleFunc("POST /host/mail/tls", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			SPKI     []string  `json:"spki_sha256"`
			NotAfter time.Time `json:"not_after"`
		}
		if !hostBody(w, r, &b, `{"spki_sha256": ["<64 hex>", …], "not_after": "<rfc3339>"}`) {
			return
		}
		serving, err := h.HostMailTLS(r.Context(), b.SPKI, b.NotAfter)
		if err != nil {
			hostErr(w, err)
			return
		}
		writeJSON(w, map[string]string{"serving_spki_sha256": serving})
	})
	mux.HandleFunc("POST /host/mail/test", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			To string `json:"to"`
		}
		if !hostBody(w, r, &b, `{"to": "<address>"}`) {
			return
		}
		q, err := h.HostMailTest(r.Context(), b.To)
		if err != nil {
			hostErr(w, err)
			return
		}
		writeJSON(w, map[string]string{"queue_id": q})
	})
	mux.HandleFunc("POST /host/mail/backup", func(w http.ResponseWriter, r *http.Request) {
		archive, err := h.HostMailBackup()
		if err != nil {
			hostErr(w, err)
			return
		}
		writeJSON(w, map[string]string{"archive": archive})
	})
	mux.HandleFunc("POST /host/mail/restore", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Archive string `json:"archive"`
		}
		if !hostBody(w, r, &b, `{"archive": "<instance>/<file>.tar"}`) {
			return
		}
		op, err := h.HostMailRestore(b.Archive)
		if err != nil {
			hostErr(w, err)
			return
		}
		writeJSONStatus(w, http.StatusAccepted, acceptedBody(op))
	})
	mux.HandleFunc("POST /host/mail/action", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Name   string `json:"name"`
			Domain string `json:"domain"`
		}
		if !hostBody(w, r, &b, `{"name": "dkim-rotate|dmarc-promote|mtasts-enforce", "domain": "<domain>"}`) {
			return
		}
		if err := h.MailAction(r.Context(), b.Name, b.Domain, directory.Human(hub.HostActor)); err != nil {
			hostErr(w, err)
			return
		}
		writeJSONStatus(w, http.StatusAccepted, map[string]bool{"accepted": true})
	})
	mux.HandleFunc("GET /host/mail/op", func(w http.ResponseWriter, r *http.Request) {
		rec := h.HostMailOp(r.URL.Query().Get("instance"), r.URL.Query().Get("op_id"))
		if rec == nil {
			http.Error(w, "no operation recorded", http.StatusNotFound)
			return
		}
		writeJSON(w, rec)
	})
	mux.HandleFunc("GET /host/mail/dns/main", func(w http.ResponseWriter, r *http.Request) {
		recs, err := h.HostMailDNSMain(r.Context())
		if err != nil {
			hostErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"records": recs, "rules": h.HostMailDNSRules()})
	})
	mux.HandleFunc("POST /host/mail/unwire", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Drain *bool `json:"drain"`
		}
		if !hostBody(w, r, &b, `{"drain": <bool>}`) {
			return
		}
		drain := b.Drain == nil || *b.Drain
		op, err := h.HostMailUnwire(drain)
		if err != nil {
			hostErr(w, err)
			return
		}
		writeJSONStatus(w, http.StatusAccepted, acceptedBody(op))
	})
	mux.HandleFunc("POST /host/mail/install", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Template string `json:"template"`
			Source   string `json:"source"`
			Confirm  string `json:"confirm"`
		}
		if !hostBody(w, r, &b, `{"template", "source", "confirm"}`) {
			return
		}
		op, err := h.HostMailInstall(r.Context(), b.Template, b.Source, b.Confirm)
		if err != nil {
			hostErr(w, err)
			return
		}
		writeJSONStatus(w, http.StatusAccepted, mailWireAccepted{acceptedBody(op), hub.MailWarning})
	})
	return mux
}

// hostBody decodes a strict control body (≤ 8 KiB, unknown fields and
// trailing data 400 with usage).
func hostBody(w http.ResponseWriter, r *http.Request, v any, usage string) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, hostBodyMax))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "body must be "+usage, http.StatusBadRequest)
		return false
	}
	return true
}

func hostErr(w http.ResponseWriter, err error) {
	var se *hub.StatusError
	if errors.As(err, &se) {
		http.Error(w, se.Error(), se.Status)
		return
	}
	if errors.As(err, new(hub.ErrBusy)) {
		http.Error(w, err.Error(), http.StatusConflict)
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
