package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/portcullis/hub/internal/directory"
)

// "Via AI" attribution (contract §9.5, §15.7, §15.10; ruling G41).
//
// A request's actor is the person in X-Forwarded-User, with no AI
// attribution — on the Hub and people listeners always: their handlers
// never read the gate's AI identity headers (TestNoAIHeaderReads,
// TestForgedAIHeadersIgnored), so a browser can't forge "via AI". Only the
// MCP listener (HUB_MCP_ADDR, Task 13) builds an identity with
// mcpIdentity — from the headers the gate sent, after the MCP secret
// check — and attaches it with withMCPIdentity; requestActor, actor and
// Server.caller then use it, so the same handlers and directory methods
// audit the person, via ai and the AI client.

type mcpIdentityKey struct{}

// mcpIdentity is the actor of a request the gate forwarded to the MCP
// listener: user = the token's preferred_username (lowercased here too),
// client = its azp. Either missing is refused (403).
func mcpIdentity(user, client string) (directory.Actor, error) {
	a := directory.Actor{
		User:   strings.ToLower(strings.TrimSpace(user)),
		Via:    directory.ViaAI,
		Client: strings.TrimSpace(client),
	}
	if err := a.Check(); err != nil {
		return directory.Actor{}, err
	}
	return a, nil
}

// withMCPIdentity returns r carrying a (built by mcpIdentity). Only the
// MCP listener calls it.
func withMCPIdentity(r *http.Request, a directory.Actor) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), mcpIdentityKey{}, a))
}

// requestActor is who r's changes are attributed to: the MCP listener's
// identity when r carries one, else the person in X-Forwarded-User (no AI
// attribution, whatever else r says).
func requestActor(r *http.Request) directory.Actor {
	if a, ok := r.Context().Value(mcpIdentityKey{}).(directory.Actor); ok {
		return a
	}
	return directory.Human(r.Header.Get("X-Forwarded-User"))
}
