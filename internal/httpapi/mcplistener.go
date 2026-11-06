package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/hub"
)

// The Hub's third listener (contract §15.7): HUB_MCP_ADDR (:8890), for
// mcp-gate only. Every request but GET /healthz carries
// X-Portcullis-MCP-Secret (HUB_MCP_GATE_SECRET, compared in constant
// time, else 401; removed before any handler runs). With it the only
// routes are /mcp/admin, /mcp/people (the Portcullis MCP, Tasks 14/15),
// POST /internal/credentials, POST /internal/confirmations and POST
// /internal/confirmations/consume; anything else is 404. No CSRF guard
// (no browser reaches it), no proxy secret (Traefik never targets it).
//
// This file is the only one that names the gate's AI identity headers
// (mcpAIHeaderFiles, TestNoAIHeaderReads, G41): on /mcp/* they become
// the request's mcpIdentity; the Hub and people listeners never read
// them and never serve these routes.

// MCPSecretHeader carries HUB_MCP_GATE_SECRET from the gate.
const MCPSecretHeader = "X-Portcullis-MCP-Secret"

// The gate's identity headers on /mcp/* (§15.7): X-Forwarded-User (the
// token's preferred_username), the AI client (azp) and the resource URL.
const (
	mcpClientHeader   = "X-Portcullis-AI-Client"
	mcpResourceHeader = "X-Portcullis-AI-Resource"
)

// LoadMCPSecret reads HUB_MCP_GATE_SECRET_FILE once, at start (contract
// §15.7). A missing file is ("", false, nil): no listener, AI support
// off. Unreadable, or not at least MinSecretLen printable ASCII
// characters once trimmed (the gate's own rule), is an error: the Hub
// refuses to start. Errors never quote the file's content.
func LoadMCPSecret(path string) (secret string, ok bool, err error) {
	if path == "" {
		return "", false, nil
	}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", false, nil
	case err != nil:
		cause := errors.Unwrap(err)
		if cause == nil {
			cause = err
		}
		return "", false, fmt.Errorf("HUB_MCP_GATE_SECRET_FILE %s: %v", path, cause)
	}
	defer clear(b)
	s := strings.TrimSpace(string(b))
	if err := CheckMCPSecret(s); err != nil {
		return "", false, fmt.Errorf("HUB_MCP_GATE_SECRET_FILE %s: %v", path, err)
	}
	return s, true, nil
}

// CheckMCPSecret: at least MinSecretLen printable ASCII characters (no
// space; what the gate accepts).
func CheckMCPSecret(s string) error {
	if len(s) < MinSecretLen {
		return fmt.Errorf("the MCP gate secret is too short (%d chars, need at least %d)", len(s), MinSecretLen)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return errors.New("the MCP gate secret must be printable ASCII without spaces")
		}
	}
	return nil
}

// MCPSecret answers 401 to every request without exactly one
// X-Portcullis-MCP-Secret equal to secret, except GET/HEAD /healthz. Both
// sides are hashed before the constant-time compare (the length doesn't
// leak). The header is removed before next runs.
func MCPSecret(secret string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(secret))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isHealthz(r) {
			r.Header.Del(MCPSecretHeader)
			next.ServeHTTP(w, r)
			return
		}
		vals := r.Header.Values(MCPSecretHeader)
		ok := 0
		if len(vals) == 1 {
			got := sha256.Sum256([]byte(vals[0]))
			ok = subtle.ConstantTimeCompare(got[:], want[:])
		}
		r.Header.Del(MCPSecretHeader)
		if ok != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MCPHandler is the MCP listener's chain: MCPSecret → routes. Its secret
// is s.MCPSecret (HUB_MCP_GATE_SECRET; checked here too).
func (s *Server) MCPHandler() (http.Handler, error) {
	if err := CheckMCPSecret(s.MCPSecret); err != nil {
		return nil, err
	}
	if s.Hub == nil {
		return nil, errors.New("the MCP listener needs the Hub")
	}
	return MCPSecret(s.MCPSecret, s.mcpMux().ServeMux), nil
}

// mcpMux is the MCP listener's routes, recorded (TestMCPListenerSecret
// compares them with the contract's table). The catch-all "/" makes any
// other path — or another method on a listed path — 404.
func (s *Server) mcpMux() *recordingMux {
	mux := &recordingMux{ServeMux: http.NewServeMux()}
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("/", http.NotFound)
	domain := hub.NormalizeHost(s.Hub.Domain())
	// The Portcullis MCP (§15.10), Streamable HTTP: Task 14 (admin) and
	// Task 15 (people) replace these stubs. The identity check is final.
	mux.HandleFunc("/mcp/admin", s.mcpRoute(aigate.AdminURL(domain), notYet("the Portcullis admin MCP (Task 14)")))
	mux.HandleFunc("/mcp/people", s.mcpRoute(aigate.PeopleURL(domain), notYet("the Portcullis people MCP (Task 15)")))
	s.registerInternal(mux)
	return mux
}

// notYet is a 501 stub of a route a later task implements.
func notYet(what string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSONStatus(w, http.StatusNotImplemented, map[string]string{"error": what + " is not implemented yet"})
	}
}

// mcpRoute guards a /mcp/* route (§15.7): the gate's resource header must
// be exactly resource (else 403), and the person and AI client become the
// request's mcpIdentity (missing: 403). The gate's identity headers are
// removed before next runs, so nothing downstream can read them.
func (s *Server) mcpRoute(resource string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := r.Header.Values(mcpResourceHeader)
		clients := r.Header.Values(mcpClientHeader)
		users := r.Header.Values("X-Forwarded-User")
		r.Header.Del(mcpResourceHeader)
		r.Header.Del(mcpClientHeader)
		if len(res) != 1 || res[0] != resource {
			http.Error(w, "forbidden: not this resource", http.StatusForbidden)
			return
		}
		if len(users) != 1 || len(clients) != 1 {
			http.Error(w, "forbidden: no AI identity", http.StatusForbidden)
			return
		}
		a, err := mcpIdentity(users[0], clients[0])
		if err != nil {
			http.Error(w, "forbidden: no AI identity", http.StatusForbidden)
			return
		}
		next(w, withMCPIdentity(r, a))
	}
}
