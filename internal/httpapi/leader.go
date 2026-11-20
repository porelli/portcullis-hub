package httpapi

import (
	"net/http"
)

// Leader is the Hub's write fence (internal/leader.Fence): Check is nil
// while this Hub may write, else why it stands by.
type Leader interface{ Check() error }

// leading reports whether s's fence lets it write (no fence: Docker and
// Podman, always).
func (s *Server) leading() bool { return s.Leader == nil || s.Leader.Check() == nil }

// leaderGate is LeaderGate with s's fence.
func (s *Server) leaderGate(next http.Handler) http.Handler { return LeaderGate(s.Leader, next) }

// LeaderGate answers every request but GET and HEAD with 503 {"error":
// <the fence's reason>} while l stands by (contract §20.5); reads pass.
// A nil l always leads (Docker, Podman): next unchanged.
func LeaderGate(l Leader, next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if err := l.Check(); err != nil {
				w.Header().Set("Cache-Control", "no-store")
				writeJSONError(w, http.StatusServiceUnavailable, err.Error())
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
