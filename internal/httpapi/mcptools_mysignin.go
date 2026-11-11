package httpapi

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/portcullis/hub/internal/directory"
)

// The Sign-in page's people tools (contract §15.10, plan D33): the
// caller's own view (my_sign_in, R, with the last 20 history entries),
// two handoffs (my_browser_certificate, my_password: R, the Sign-in
// page's link — never a file, a password or a certificate) and
// revoke_my_certificate (W). The YubiKey renewal (it needs the
// certificate the browser presents) and the history route have no twin
// (mcp_parity_test.go, signInNoToolRoutes).

// mySignInHistoryN is how many history entries my_sign_in carries.
const mySignInHistoryN = 20

// signInPage is the Sign-in page (https://people.<d>/signin).
func (s *Server) signInPage() string { return s.peopleHome() + "signin" }

type revokeMyCertArgs struct {
	Serial string `json:"serial" jsonschema:"the serial of one of your own browser certificates (from my_sign_in), e.g. 1a:2b:3c"`
}

// signInHandoff is the answer of a handoff tool.
func (s *Server) signInHandoff(what string) map[string]string {
	return map[string]string{"link": s.signInPage(),
		"note": "create it on the Sign-in page, " + s.signInPage() + ": " + what + "; it never goes through the AI"}
}

// registerMySignInTools registers the Sign-in page's people tools.
func (s *Server) registerMySignInTools() {
	for _, t := range []Tool{
		{Name: "my_sign_in", Description: "Your sign-in methods: which of the six are set up, off or unknown, your passkeys, your YubiKey and browser certificates (with status), the apps you sign in to and whether your methods meet each, the limits, and your last 20 sign-in history entries. Only your data.",
			Class: ClassRead, Scope: ScopePeople, Twin: "GET /api/me/signin", In: noArgs{},
			Run: func(ctx context.Context, c *directory.Caller, _ json.RawMessage) (any, error) {
				u := strings.ToLower(c.User)
				v, err := s.Hub.MySignInView(ctx, u)
				if err != nil {
					return nil, err
				}
				page, err := s.Hub.SignInHistory(ctx, u, "", mySignInHistoryN)
				if err != nil {
					return nil, err
				}
				return map[string]any{"sign_in": v, "history": page}, nil
			}},
		{Name: "my_browser_certificate", Description: "Where to create a browser certificate: the Sign-in page, after a fresh sign-in. The certificate file and its password are shown only there, never to the AI.",
			Class: ClassRead, Scope: ScopePeople, Twin: "POST /api/me/signin/browser-certificates", In: noArgs{},
			Run: func(context.Context, *directory.Caller, json.RawMessage) (any, error) {
				return s.signInHandoff("the certificate file and its password are shown once there"), nil
			}},
		{Name: "my_password", Description: "Where to set your password: the Sign-in page, after a fresh sign-in. You type it there; it is never passed through the AI.",
			Class: ClassRead, Scope: ScopePeople, Twin: "PUT /api/me/signin/password", In: noArgs{},
			Run: func(context.Context, *directory.Caller, json.RawMessage) (any, error) {
				return s.signInHandoff("you type the password there"), nil
			}},
		{Name: "revoke_my_certificate", Description: "Revoke one of your own browser certificates (it stops working within a minute). Only your own browser certificates; YubiKey certificates are renewed or revoked elsewhere.",
			Class: ClassWrite, Scope: ScopePeople, Twin: "DELETE /api/me/signin/certificates/{serial}", Audit: "cert.revoke", In: revokeMyCertArgs{},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[revokeMyCertArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				if err := s.Hub.RevokeOwnBrowserCertificateAs(ctx, toolActor(ctx, c), in.Serial); err != nil {
					return nil, err
				}
				return map[string]string{"status": "revoked", "serial": in.Serial}, nil
			}},
	} {
		s.registerTool(t)
	}
}
