package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/servers"
)

// TLSConfig is the control listener's TLS: TLS 1.3, a client certificate
// required (RequireAnyClientCert: the standard library would check
// validity before the clock tolerance, pre-flight P5) and verified in
// VerifyPeerCertificate against the pinned pki_node CA — or, while
// enrolling, against the CA in the Hub's chain whose sha256(DER) is the
// join code's ca_sha256. The server certificate is the node-worker one
// once stored, else the enrolling self-signed one.
func (a *Agent) TLSConfig() *tls.Config {
	base := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			_, err := a.verifyPeer(raw)
			return err
		},
	}
	base.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.tlsCert != nil && a.tlsKey != nil {
			return &tls.Certificate{Certificate: [][]byte{a.tlsCert.Raw}, PrivateKey: a.tlsKey, Leaf: a.tlsCert}, nil
		}
		if a.enrolCert != nil {
			return &tls.Certificate{Certificate: [][]byte{a.enrolCert.Raw}, PrivateKey: a.enrolKey, Leaf: a.enrolCert}, nil
		}
		return nil, errors.New("no server certificate")
	}
	return base
}

// verifyPeer verifies a client chain for the current state and returns
// the caller's CN. While enrolling only hub.control is accepted, and the
// CA learned from the chain is kept for the rest of the enrolment.
func (a *Agent) verifyPeer(raw [][]byte) (string, error) {
	a.mu.Lock()
	ca, state, pin := a.ca, a.state, a.pins.CASHA256
	a.mu.Unlock()
	learned := false
	if ca == nil {
		if state != StateEnrolling {
			return "", errors.New("no pinned CA")
		}
		c, err := caFromChain(raw, pin)
		if err != nil {
			return "", err
		}
		ca, learned = c, true
	}
	cn, err := verifyControl(raw, ca, a.cfg.Now())
	if err != nil {
		return "", err
	}
	if state == StateEnrolling && cn != CNControl {
		return "", errors.New("only hub.control may enrol a worker")
	}
	if learned {
		a.mu.Lock()
		if a.ca == nil {
			a.ca = ca
		}
		a.mu.Unlock()
	}
	return cn, nil
}

// writeJSON / writeError answer with a body (errors: {"error"}, ≤ 200).
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

// clipMsg shortens an engine or validation message for the error shape.
func clipMsg(s string) string {
	if len(s) > 180 {
		return s[:180] + "…"
	}
	return s
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	w.Write(agentapi.ErrorBody(msg))
}

// Handler is the control API. Every request is authorised again here
// from its TLS state (the CN of a chain verifyPeer accepts): link.control
// reaches GET /v1/metrics only; while enrolling only /v1/info, the enrol
// routes and the enrolment's identity calls answer; once ready, hub.control
// reaches the identity routes and Config.Routes.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(r agentapi.Route, cns []string, states []string, h http.HandlerFunc) {
		mux.HandleFunc(r.Pattern(), a.guard(cns, states, h))
	}
	ctl, both := []string{CNControl}, []string{CNControl, CNLink}
	enrolling, ready, any := []string{StateEnrolling}, []string{StateReady}, []string{StateEnrolling, StateReady}
	route(agentapi.Routes["Info"][0], ctl, any, a.handleInfo)
	route(agentapi.ExtraRoutes["Metrics"], both, ready, a.handleMetrics)
	route(agentapi.ExtraRoutes["EnrolNonce"], ctl, enrolling, a.handleNonce)
	route(agentapi.ExtraRoutes["Enrol"], ctl, enrolling, a.handleEnrol)
	route(agentapi.ExtraRoutes["IdentityCert"], ctl, any, a.handleCert)
	route(agentapi.ExtraRoutes["Network"], ctl, enrolling, a.handleNetwork)
	route(agentapi.ExtraRoutes["IdentityWG"], ctl, enrolling, a.handleWG)
	route(agentapi.ExtraRoutes["IdentityCSR"], ctl, ready, a.handleCSR)
	rest := a.guard(ctl, ready, func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.Routes == nil || !strings.HasPrefix(r.URL.Path, agentapi.Prefix+"/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		a.cfg.Routes.ServeHTTP(w, r)
	})
	mux.HandleFunc("/", rest)
	return mux
}

func (a *Agent) guard(cns, states []string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeError(w, http.StatusForbidden, "a client certificate is required")
			return
		}
		raw := make([][]byte, len(r.TLS.PeerCertificates))
		for i, c := range r.TLS.PeerCertificates {
			raw[i] = c.Raw
		}
		cn, err := a.verifyPeer(raw)
		if err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		if !contains(cns, cn) {
			writeError(w, http.StatusForbidden, cn+" may not call this route")
			return
		}
		if st := a.State(); !contains(states, st) {
			if st == StateEnrolling {
				writeError(w, http.StatusForbidden, "the agent is enrolling: only /v1/info and the enrolment answer")
			} else {
				writeError(w, http.StatusConflict, "not while the agent is "+st)
			}
			return
		}
		h(w, r)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ServeData accepts data connections on ln (the netstack's :7000) and
// hands every one whose source is link's address (10.214.0.1) to handle;
// any other source is closed at once.
func ServeData(ln net.Listener, handle func(net.Conn)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		if !fromLink(c.RemoteAddr()) || handle == nil {
			c.Close()
			continue
		}
		go handle(c)
	}
}

func fromLink(addr net.Addr) bool {
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	return ok && ip.Unmap() == servers.LinkAddr
}

// NewHTTPServer is the control server's http.Server (header and idle
// timeouts; bodies are capped per route).
func NewHTTPServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
}
