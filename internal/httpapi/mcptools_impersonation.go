package httpapi

import (
	"context"
	"strings"

	"github.com/portcullis/hub/internal/directory"
)

// The Portcullis MCP's impersonation tools (contract §15.10, §15.11,
// D46): an AI may list impersonations (R), stop one (W) and switch the
// feature off (W). No tool starts one (it needs the administrator's
// fresh YubiKey touch and a typed reason) or switches it on (Hub
// Settings only); the impersonating browser's routes have none either.

type stopImpersonationArgs struct {
	User string `json:"user" jsonschema:"the LLDAP username of the person someone is signed in as"`
}

// registerImpersonationTools registers the three admin tools.
func (s *Server) registerImpersonationTools() {
	for _, t := range []Tool{
		admin("impersonations", "Signing in as someone else: whether it is switched on, the longest length, the running impersonations and the last 20 ended (who, as whom, the reason, when and how it ended).",
			ClassRead, "GET /api/impersonations", "", func(_ context.Context, _ directory.Actor, _ noArgs) (any, error) {
				return s.impersonations(), nil
			}),
		admin("stop_impersonation", "Stop the running impersonation of a person (an administrator signed in as them): their session as that person ends at once.",
			ClassWrite, "POST /api/directory/users/{username}/impersonation/stop", "impersonation.end", func(ctx context.Context, a directory.Actor, in stopImpersonationArgs) (any, error) {
				if err := s.stopImpersonation(ctx, a, in.User); err != nil {
					return nil, err
				}
				return map[string]string{"status": "stopped", "user": strings.ToLower(strings.TrimSpace(in.User))}, nil
			}),
		admin("turn_off_impersonation", "Switch signing in as someone else off for the whole server: every running impersonation ends and no administrator can start one. Switching it back on is done in Hub Settings only.",
			ClassWrite, "PUT /api/signin/impersonation", "signin.impersonation", func(ctx context.Context, a directory.Actor, _ noArgs) (any, error) {
				return s.setImpersonationAllowed(ctx, a, false)
			}),
	} {
		s.registerTool(t)
	}
}
