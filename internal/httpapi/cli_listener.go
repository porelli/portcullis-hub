package httpapi

// The CLI listener (contract §18.3–18.4): HUB_CLI_ADDR (:8891), reached
// only through core's people-cli router. It serves /api/cli/v1/* and
// nothing else, accepts only HUB_CLI_PROXY_SECRET, never reads an
// identity header, and decodes every body strictly with its cap.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/hub"
)

// CLIOptions configure the CLI listener.
type CLIOptions struct {
	// Secret is HUB_CLI_PROXY_SECRET (≥ 32 characters).
	Secret string
	// Issuer and AuthorizeURL are the realm's public issuer and authorize
	// endpoint (the config answer).
	Issuer, AuthorizeURL string
	// MinCLI is the oldest CLI version served ("" = any).
	MinCLI string
}

// CheckCLISecret refuses a short or missing secret (the Hub refuses to
// start: plan C7), never quoting it.
func CheckCLISecret(s string) error {
	if len(s) < 32 {
		return errors.New("HUB_CLI_PROXY_SECRET must be set (at least 32 characters): run ./portcullis init")
	}
	return nil
}

// CLIHandler is the CLI listener's handler.
func (s *Server) CLIHandler() (http.Handler, error) {
	if err := CheckCLISecret(s.CLI.Secret); err != nil {
		return nil, err
	}
	if s.CLI.Secret == s.Secret || s.CLI.Secret == s.MCPSecret {
		return nil, errors.New("HUB_CLI_PROXY_SECRET must differ from the Hub's other listener secrets")
	}
	if s.Hub == nil {
		return nil, errors.New("the CLI listener needs the Hub")
	}
	return cliProxySecret(s.CLI.Secret, s.cliVersion(s.cliMux().ServeMux)), nil
}

// cliMux is the CLI listener's routes, recorded. "/" makes every other
// path (or method) 404.
func (s *Server) cliMux() *recordingMux {
	mux := &recordingMux{ServeMux: http.NewServeMux()}
	mux.HandleFunc("GET /api/cli/v1/config", s.handleCLIConfig)
	mux.HandleFunc("POST /api/cli/v1/ssh/certificates", s.handleCLICertificates)
	mux.HandleFunc("POST /api/cli/v1/ssh/revocations", s.handleCLIRevocations)
	mux.HandleFunc("GET /api/cli/v1/ssh/ca", s.handleCLICA)
	mux.HandleFunc("GET /api/cli/v1/ssh/revoked-keys", s.handleCLIRevokedKeys)
	s.registerCLIHosts(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { cliError(w, http.StatusNotFound, "not found") })
	return mux
}

// registerCLIHosts adds the host routes (cli_hosts.go; plan Task 8).
var registerCLIHostsHook func(s *Server, mux *recordingMux)

func (s *Server) registerCLIHosts(mux *recordingMux) {
	if registerCLIHostsHook != nil {
		registerCLIHostsHook(s, mux)
	}
}

// cliProxySecret: exactly one X-Portcullis-Proxy-Secret equal to secret
// (constant time), else 401; the header is removed afterwards.
func cliProxySecret(secret string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(secret))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vals := r.Header.Values(ProxySecretHeader)
		got := sha256.Sum256([]byte(strings.Join(vals, ",")))
		if len(vals) != 1 || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			cliError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		r.Header.Del(ProxySecretHeader)
		next.ServeHTTP(w, r)
	})
}

// cliVersion answers 426 to a CLI without `<version>; api=1` or older
// than MinCLI (contract §18.3).
func (s *Server) cliVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, api, ok := cliapi.ParseCLIHeader(r.Header.Get(cliapi.HeaderCLI))
		min := s.CLI.MinCLI
		if !ok || api != cliapi.APIVersion || (min != "" && semver.IsValid("v"+strings.TrimPrefix(v, "v")) && semver.Compare("v"+strings.TrimPrefix(v, "v"), "v"+strings.TrimPrefix(min, "v")) < 0) {
			cliError(w, http.StatusUpgradeRequired, "update the Portcullis CLI to "+cliMin(min))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func cliMin(m string) string {
	if m == "" {
		return "the server's version"
	}
	return m
}

// cliAddr is the client address Traefik set (X-Real-Ip), or "unknown".
func cliAddr(r *http.Request) string {
	vals := r.Header.Values("X-Real-Ip")
	if len(vals) != 1 {
		return "unknown"
	}
	a, err := netip.ParseAddr(strings.TrimSpace(vals[0]))
	if err != nil {
		return "unknown"
	}
	return a.Unmap().String()
}

func cliHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func cliJSON(w http.ResponseWriter, code int, v any) {
	cliHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func cliError(w http.ResponseWriter, code int, text string) {
	cliJSON(w, code, cliapi.ErrorAnswer{Error: text})
}

// cliHubError answers a Hub error with its fixed text.
func cliHubError(w http.ResponseWriter, err error) {
	code, text := hub.SSHErrorStatus(err)
	cliError(w, code, text)
}

// cliDecode reads the body strictly (cap max): 413 or 400.
func cliDecode(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	if err := cliapi.DecodeStrict(r.Body, max, v); err != nil {
		if errors.Is(err, cliapi.ErrTooLarge) {
			cliError(w, http.StatusRequestEntityTooLarge, "request too large")
		} else {
			cliError(w, http.StatusBadRequest, "malformed request")
		}
		return false
	}
	return true
}

func (s *Server) handleCLIConfig(w http.ResponseWriter, r *http.Request) {
	ports := cliapi.RedirectPorts
	cliJSON(w, http.StatusOK, cliapi.Config{API: cliapi.APIVersion, Domain: s.Hub.Domain(), Issuer: s.CLI.Issuer, AuthorizeURL: s.CLI.AuthorizeURL,
		ClientID: cliapi.ClientID, RedirectPorts: ports[:], Device: false, MinCLI: s.CLI.MinCLI})
}

func (s *Server) handleCLICertificates(w http.ResponseWriter, r *http.Request) {
	var req cliapi.CertRequest
	if !cliDecode(w, r, cliapi.MaxCertRequest, &req) {
		return
	}
	ans, err := s.Hub.SignSSH(r.Context(), req, cliAddr(r))
	if err != nil {
		cliHubError(w, err)
		return
	}
	cliJSON(w, http.StatusOK, ans)
}

func (s *Server) handleCLIRevocations(w http.ResponseWriter, r *http.Request) {
	var req cliapi.RevocationRequest
	if !cliDecode(w, r, cliapi.MaxCertRequest, &req) {
		return
	}
	n, err := s.Hub.RevokeOwnSSH(r.Context(), req, cliAddr(r))
	if err != nil {
		cliHubError(w, err)
		return
	}
	cliJSON(w, http.StatusOK, cliapi.RevocationAnswer{Revoked: n})
}

func (s *Server) handleCLICA(w http.ResponseWriter, r *http.Request) {
	u, h := s.Hub.SSHCAKeys()
	cliJSON(w, http.StatusOK, cliapi.CAAnswer{UserCAs: u, HostCAs: h})
}

func (s *Server) handleCLIRevokedKeys(w http.ResponseWriter, r *http.Request) {
	cliHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	var b strings.Builder
	for _, k := range s.Hub.RevokedKeys() {
		b.WriteString(k + "\n")
	}
	_, _ = w.Write([]byte(b.String()))
}
