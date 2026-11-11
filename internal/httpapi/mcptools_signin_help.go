package httpapi

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/portcullis/hub/internal/directory"
)

// The Portcullis MCP's twins of the person's Sign-in routes (contract
// §15.10, plan D33):
//   - admin: person_sign_in (R), revoke_person_certificate (D) and
//     issue_yubikey_certificate (R, a handoff to the person's page on
//     people.<d>, whose Sign-in tab issues it: never a certificate);
//   - people: person_sign_in (R), revoke_person_certificate (D) and
//     remove_passkeys (D), each needing sign_in_help (admins always):
//     the directory's CheckHelp decides the target before any
//     confirmation (Precheck), and the Hub or directory method decides
//     again when it runs.
//
// The history route (GET /api/directory/users/{u}/signin/history) has
// no twin: person_sign_in carries the last 20 entries.

type (
	revokePersonCertArgs struct {
		Username string `json:"username" jsonschema:"the person's LLDAP username"`
		Serial   string `json:"serial" jsonschema:"the serial of one of their certificates (from person_sign_in), e.g. 1a:2b:3c"`
	}
)

// personSignInPage is the person's page on people.<d> (its Sign-in tab).
func (s *Server) personSignInPage(user string) string {
	return s.peopleHome() + "#people/" + url.PathEscape(user)
}

// personSignIn is person_sign_in's answer: the view plus the last 20
// history entries.
func (s *Server) personSignIn(ctx context.Context, c *directory.Caller, user string) (any, error) {
	s.rec("PersonSignInView", user)
	v, err := s.Hub.PersonSignInView(ctx, c, user)
	if err != nil {
		return nil, err
	}
	page, err := s.Hub.PersonSignInHistory(ctx, c, user, "", mySignInHistoryN)
	if err != nil {
		return nil, err
	}
	return map[string]any{"sign_in": v, "history": page}, nil
}

// helpPrecheck refuses at once a target the caller may not help (no
// confirmation for a call that can't run).
func (s *Server) helpPrecheck(ctx context.Context, c *directory.Caller, args json.RawMessage) error {
	if s.Directory == nil {
		return errNoUserManagement
	}
	return s.Directory.CheckHelp(ctx, c, usernameOf(args))
}

func revokeConsequences(_ context.Context, args json.RawMessage) []string {
	return []string{"Revokes certificate " + q(argField(args, "serial")) + " of " + argField(args, "username") + ": it stops working within a minute, and can't be undone."}
}

// registerSignInHelpTools registers the admin and people twins.
func (s *Server) registerSignInHelpTools() {
	personView := func(scope string) Tool {
		t := dirTool(s, "person_sign_in", "A person's sign-in methods as their Sign-in page shows them (methods, passkeys, YubiKey and browser certificates with status, apps and what they need), what you may do for them (can), and their last 20 sign-in history entries. Administrators, and holders of sign_in_help for the people they may help.",
			ClassRead, "GET /api/directory/users/{username}/signin", "", func(ctx context.Context, c *directory.Caller, in personArgs) (any, error) {
				return s.personSignIn(ctx, c, in.Username)
			})
		if scope == ScopePeople {
			t.Scope, t.Perm = ScopePeople, directory.PermSignInHelp
		}
		return t
	}
	revoke := func(scope string) Tool {
		t := dirD(dirTool(s, "revoke_person_certificate", "Revoke one of a person's certificates (YubiKey or browser); it stops working within a minute. Administrators' certificates and the server's own accounts are managed from the server. Needs your confirmation in the browser.",
			ClassWrite, "DELETE /api/directory/users/{username}/certificates/{serial}", "cert.revoke", func(ctx context.Context, c *directory.Caller, in revokePersonCertArgs) (any, error) {
				if err := s.revokePersonCert(ctx, c, in.Username, in.Serial); err != nil {
					return nil, err
				}
				return map[string]string{"status": "revoked", "user": strings.ToLower(in.Username), "serial": in.Serial}, nil
			}), usernameOf, revokeConsequences)
		// The route's own target check (review m3): 403, the protected
		// names' and administrators' 409s, 404 — before any confirmation.
		t.Precheck = func(ctx context.Context, c *directory.Caller, args json.RawMessage) error {
			return s.Hub.CheckCertTarget(ctx, c, usernameOf(args))
		}
		if scope == ScopePeople {
			t.Scope, t.Perm = ScopePeople, directory.PermSignInHelp
		}
		return t
	}
	removePasskeys := dirD(dirTool(s, "remove_passkeys", "Remove all of a person's passkeys and sign them out everywhere (needs sign_in_help; ordinary people only). Needs your confirmation in the browser. A new setup link is sent from the People page.",
		ClassWrite, "POST /api/directory/users/{username}/remove-passkeys", "user.remove_passkeys", func(ctx context.Context, c *directory.Caller, in personArgs) (any, error) {
			// The typed check (the name) was the confirmation page's;
			// never an invite here.
			res, err := s.removePasskeys(ctx, c, in.Username, in.Username, false)
			if err != nil {
				return nil, err
			}
			out := s.safeResult(in.Username, "removed", res)
			out["page"] = s.personSignInPage(strings.ToLower(in.Username))
			return out, nil
		}), usernameOf, func(_ context.Context, args json.RawMessage) []string {
		return []string{"Removes every passkey of " + argField(args, "username") + " and signs them out everywhere."}
	})
	removePasskeys.Precheck = s.helpPrecheck
	removePasskeys.Scope, removePasskeys.Perm = ScopePeople, directory.PermSignInHelp

	for _, t := range []Tool{
		personView(ScopeAdmin), revoke(ScopeAdmin),
		dirTool(s, "issue_yubikey_certificate", "Where to issue a person's YubiKey certificate: their page on the People site, whose Sign-in tab takes a CSR made on the YubiKey after your fresh sign-in. The certificate is never made or passed through the AI.",
			ClassRead, "POST /api/directory/users/{username}/certificates", "", func(_ context.Context, _ *directory.Caller, in personArgs) (any, error) {
				link := s.personSignInPage(strings.ToLower(in.Username))
				return map[string]string{"link": link,
					"note": "open " + link + " and use the Sign-in tab: it asks you to sign in again, then takes the CSR made on the YubiKey; it never goes through the AI"}, nil
			}),
		personView(ScopePeople), revoke(ScopePeople), removePasskeys,
	} {
		s.registerTool(t)
	}
}
