package host

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
	na "github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/pkinode"
)

// The nodeagent API (contract §20.4): https://<mesh ip>:7443/v1, TLS 1.3
// with the node-cluster certificate, a client certificate required and
// verified against the pki_node CA. Only the fixed operations of Routes
// answer (any other method or path 404); each names the clients that may
// call it (anyone else 403).

var oidCN = asn1.ObjectIdentifier{2, 5, 4, 3}

// ClockTolerance: a client certificate valid at now ± 5 min is accepted.
const ClockTolerance = 5 * time.Minute

// Route is one fixed operation.
type Route struct {
	Method  string
	Path    string
	Clients []string
}

// Routes is the whole API.
var Routes = []Route{
	{http.MethodGet, "/v1/health", []string{na.CNHub, na.CNNodeadm}},
	{http.MethodGet, "/v1/checks", []string{na.CNHub}},
	{http.MethodPut, "/v1/mesh/peers", []string{na.CNHub}},
	{http.MethodGet, "/v1/mesh/rtt", []string{na.CNHub}},
	{http.MethodGet, "/v1/probes", []string{na.CNHub, na.CNFrontdoor}},
	{http.MethodPut, "/v1/probes/targets", []string{na.CNNodeadm}},
	{http.MethodPost, "/v1/etcd/remove-member", []string{na.CNNodeadm}},
	{http.MethodPost, "/v1/k3s/uninstall", []string{na.CNHub}},
	{http.MethodPost, "/v1/k3s/token-rotate", []string{na.CNNodeadm}},
}

// TLSConfig serves the node-cluster certificate and requires a client
// certificate verified against the pki_node CA (the handler authorises
// its CN per route).
func (a *Agent) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			_, err := a.verifyClient(raw)
			return err
		},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.cert == nil {
				return nil, errors.New("no node-cluster certificate")
			}
			return a.cert, nil
		},
	}
}

func (a *Agent) verifyClient(raw [][]byte) (string, error) {
	a.mu.Lock()
	ca := a.ca
	a.mu.Unlock()
	leaf, err := pkinode.Verify(raw, ca, a.cfg.Now(), ClockTolerance, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return "", err
	}
	// Exactly one CN attribute (Go keeps the last of several).
	n := 0
	for _, at := range leaf.Subject.Names {
		if at.Type.Equal(oidCN) {
			n++
		}
	}
	if n != 1 {
		return "", errors.New("the client certificate must name exactly one CN")
	}
	return leaf.Subject.CommonName, nil
}

type apiErr struct {
	Error string `json:"error"`
	Kind  string `json:"kind,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func writeErr(w http.ResponseWriter, err error) {
	code, msg, kind := http.StatusInternalServerError, err.Error(), ""
	var he *httpError
	if errors.As(err, &he) {
		code, kind = he.code, he.kind
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	writeJSON(w, code, apiErr{msg, kind})
}

// Handler is the API.
func (a *Agent) Handler(ctx context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := slices.IndexFunc(Routes, func(rt Route) bool { return rt.Method == r.Method && rt.Path == r.URL.Path })
		if i < 0 || r.URL.RawQuery != "" {
			writeJSON(w, http.StatusNotFound, apiErr{Error: "not found"})
			return
		}
		rt := Routes[i]
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeJSON(w, http.StatusForbidden, apiErr{Error: "a client certificate is required"})
			return
		}
		raw := make([][]byte, len(r.TLS.PeerCertificates))
		for i, c := range r.TLS.PeerCertificates {
			raw[i] = c.Raw
		}
		cn, err := a.verifyClient(raw)
		if err != nil {
			writeJSON(w, http.StatusForbidden, apiErr{Error: err.Error()})
			return
		}
		if !slices.Contains(rt.Clients, cn) {
			writeJSON(w, http.StatusForbidden, apiErr{Error: "this client may not call " + rt.Method + " " + rt.Path})
			return
		}
		var body []byte
		if r.Method != http.MethodGet {
			body, err = io.ReadAll(io.LimitReader(r.Body, na.MaxBody+1))
			if err != nil {
				writeErr(w, errBadRequest)
				return
			}
			if len(body) > na.MaxBody {
				writeJSON(w, http.StatusRequestEntityTooLarge, apiErr{Error: "the body is over 1 MiB"})
				return
			}
		}
		a.serve(ctx, w, r, rt.Path, body)
	})
}

func decode(b []byte, v any) error {
	if err := jsonstrict.Decode(b, v); err != nil {
		return errStatus(http.StatusBadRequest, "malformed request: %v", err)
	}
	return nil
}

func (a *Agent) serve(ctx context.Context, w http.ResponseWriter, r *http.Request, path string, body []byte) {
	switch path {
	case "/v1/health":
		writeJSON(w, http.StatusOK, a.Health(r.Context()))
	case "/v1/checks":
		writeJSON(w, http.StatusOK, a.HostChecks(r.Context()))
	case "/v1/mesh/peers":
		var p na.MeshPlan
		if err := decode(body, &p); err != nil {
			writeErr(w, err)
			return
		}
		if err := a.ApplyMesh(r.Context(), p); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "/v1/mesh/rtt":
		writeJSON(w, http.StatusOK, a.CachedRTT(r.Context()))
	case "/v1/probes":
		writeJSON(w, http.StatusOK, a.probe.Rounds())
	case "/v1/probes/targets":
		var t na.ProbeTargets
		if err := decode(body, &t); err != nil {
			writeErr(w, err)
			return
		}
		if err := a.probe.SetTargets(t); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "/v1/etcd/remove-member":
		var q na.EtcdRemove
		if err := decode(body, &q); err != nil {
			writeErr(w, err)
			return
		}
		if err := a.RemoveMember(r.Context(), q); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "/v1/k3s/token-rotate":
		var q na.TokenRotate
		if err := jsonstrict.Decode(body, &q); err != nil {
			// The decoder's message never echoes a value, but the body is
			// a token: say nothing about it.
			writeErr(w, errBadRequest)
			return
		}
		// The step runs on its own context (a closed request doesn't stop
		// it halfway); the answer waits for it or the request's end.
		done := make(chan error, 1)
		go func() {
			sctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), tokenStepTimeout)
			defer cancel()
			done <- a.TokenStep(sctx, q)
		}()
		select {
		case err := <-done:
			if err != nil {
				writeErr(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	case "/v1/k3s/uninstall":
		var q struct{}
		if err := decode(body, &q); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() {
			time.Sleep(500 * time.Millisecond) // the answer leaves first
			a.Uninstall(context.WithoutCancel(ctx))
		}()
	}
}

// Health is GET /v1/health.
func (a *Agent) Health(ctx context.Context) na.Health {
	st := a.state()
	return na.Health{ID: st.ID, Version: a.cfg.Version, MeshIP: st.MeshIP, MeshPub: a.meshPub(),
		K3s: a.k3sState(ctx), Time: a.cfg.Now().UTC().Format(time.RFC3339)}
}
