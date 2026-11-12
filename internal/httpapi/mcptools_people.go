package httpapi

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/lldap"
)

// The Portcullis MCP's people tools (plan 4 Task 19; contract §5.1,
// §15.9, §15.10; G1, G38, G39): /mcp/people (https://people.<d>/mcp), for
// anyone signed in. Each Run calls the same Hub or directory method its
// people-listener twin calls, as the caller (callerFrom: the token's
// person, via ai, the AI client):
//   - caller-only tools (my_apps, my_profile, directory,
//     my_ai_connections, disconnect_ai, my_file_share_password) take no
//     person: they act on the caller's own data only;
//   - the delegate tools (update_person with edit_details, invite_person
//     with invite, delete_person with remove) are the only ones that name
//     another person; they carry a Perm, so callTool hides them from
//     tools/list without it and refuses them (403, audited refused) when
//     called anyway, and the directory's delegate guardrails decide the
//     rest (ordinary users only, never an administrator or a holder).
//
// G38: the gate's aggregate ("all my apps", §15.9) lists the people
// tools through this server's tools/list and drops the names in its
// delegateTools (mcp-gate/internal/aggregate) — a name convention, so
// peopleDelegateTools is that list (TestPeopleDelegateToolsOffAggregate,
// TestCoreAggregateDelegatesComplete). The delegate tools are only on
// people.<d>/mcp.
//
// G39: every directory-derived result drops Invite, Password and
// ServerInvite (safeOverview: a server invite is the fixed text; the
// people view, PeopleOverview, has none of them). G1: no tool returns or
// creates a file-share password (my_file_share_password is the People
// page's link, whose card fresh-auths); there is no certificates project,
// so no my_certificates.

// peopleDelegateTools are the people tools that act on another person:
// the gate keeps exactly these names out of the aggregate (G38).
var peopleDelegateTools = []string{"invite_person", "update_person", "delete_person",
	// Help to reset (sign_in_help, D32/D33): they act on another person.
	"person_sign_in", "revoke_person_certificate", "remove_passkeys"}

// peopleHome is the People page (https://people.<d>/).
func (s *Server) peopleHome() string { return s.mcpScope(ScopePeople).home }

// peopleInviteForm is the People page's invite form, pre-filled (the
// deep link #invite?… of people.html): the delegate creates the person
// there, where the one-time link is shown to them.
func (s *Server) peopleInviteForm(a invitePersonArgs) string {
	q := url.Values{}
	q.Set("username", a.Username)
	q.Set("email", a.Email)
	q.Set("display_name", a.DisplayName)
	return s.peopleHome() + "#invite?" + q.Encode()
}

// peopleTool is a people-scope tool: dirTool's Run (T decoded, the
// caller re-resolved with the consumed confirmation) on ScopePeople.
func peopleTool[T any](s *Server, name, desc string, class ToolClass, twin, audit, perm string,
	run func(ctx context.Context, c *directory.Caller, in T) (any, error)) Tool {
	t := dirTool(s, name, desc, class, twin, audit, run)
	t.Scope, t.Perm = ScopePeople, perm
	return t
}

// Argument types of the people tools.
type (
	disconnectArgs struct {
		Client string `json:"client" jsonschema:"the AI client id to disconnect (from my_ai_connections), e.g. portcullis-ai-claude"`
	}
	invitePersonArgs struct {
		Username    string `json:"username" jsonschema:"the new person's LLDAP username (lowercase letters, digits, . _ -)"`
		Email       string `json:"email" jsonschema:"their email address (contact only, never an identity)"`
		DisplayName string `json:"display_name" jsonschema:"their display name"`
	}
)

// myProfile is GET /api/directory/me (handleMe: user, admin, perms) and
// the caller's own entry of the people view.
func (s *Server) myProfile(ctx context.Context, c *directory.Caller) (any, error) {
	out := map[string]any{"user": c.User, "admin": c.Admin, "perms": perms(c), "person": nil}
	ov, err := s.Directory.PeopleOverview(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, u := range ov.Users {
		if strings.EqualFold(u.Username, c.User) {
			out["person"] = u
			out["fields"] = ov.Fields
		}
	}
	return out, nil
}

// peopleDirectory is GET /api/directory on the people listener: the
// admin view (OverviewFor) for admins, else the people view — stripped
// (G39).
func (s *Server) peopleDirectory(ctx context.Context, c *directory.Caller) (any, error) {
	if err := s.Directory.LLDAP.Available(); err != nil {
		ov, err := s.Directory.Overview(ctx, c.User)
		if err != nil {
			return nil, err
		}
		return directory.PeopleViewOf(ov), nil
	}
	if c.Admin {
		ov, err := s.Directory.OverviewFor(ctx, c)
		return safeOverview(ov), err
	}
	return s.Directory.PeopleOverview(ctx, c)
}

// peopleInviteState is what the directory knows about user's invite, as
// the caller may see it (invite_person's Run; never the client's
// accept): whether they exist in the caller's view, who created them
// (created_by), and the caller's own newest invite of them in the audit
// log (an invite-mode user.create or a user.invite, result ok) with
// core's 72 h expiry — never another person's actions, never a link.
func (s *Server) peopleInviteState(ctx context.Context, c *directory.Caller, user string) (map[string]any, error) {
	out := map[string]any{"username": user, "exists": false, "last_invite": nil, "pending": false,
		"note": "the one-time invite link is shown only on the People page, never to the AI; core keeps invites in memory, so a restarted enroll drops them"}
	ov, err := s.Directory.PeopleOverview(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, u := range ov.Users {
		if strings.EqualFold(u.Username, user) {
			out["exists"] = true
			if u.CreatedBy != "" {
				out["created_by"] = u.CreatedBy
			}
		}
	}
	if e := s.lastInvite(user, c.User); e != nil {
		out["last_invite"] = map[string]any{"time": e.Time, "via": e.Via, "action": e.Action}
		out["expires_at"] = e.Time.Add(inviteTTL)
		out["pending"] = time.Now().Before(e.Time.Add(inviteTTL))
	}
	return out, nil
}

// registerPeopleTools registers the people tools.
func (s *Server) registerPeopleTools() {
	for _, t := range []Tool{
		// ── The caller's own ──
		{Name: "my_apps", Description: "Your apps: for each app you can use, your own per-person values (and why), the values you entered yourself, your file-sharing credential cards (status only) and its AI connectors. Only your data.",
			Class: ClassRead, Scope: ScopePeople, Twin: "GET /api/me/apps", In: noArgs{},
			Run: func(ctx context.Context, c *directory.Caller, _ json.RawMessage) (any, error) {
				return s.Hub.MyApps(ctx, strings.ToLower(c.User))
			}},
		peopleTool(s, "my_profile", "Your own account: username, email, display name, groups and how each is held, your custom field values, whether you are an administrator and which delegated permissions you hold.",
			ClassRead, "GET /api/directory/me", "", "", func(ctx context.Context, c *directory.Caller, _ noArgs) (any, error) {
				return s.myProfile(ctx, c)
			}),
		peopleTool(s, "directory", "Users & Groups as the People page shows it to you: people (groups, how each is held, the fields you may see), groups (rules, exceptions, expiries), the fields, delegated permissions and the org chart. Invite links and passwords are never shown.",
			ClassRead, "GET /api/directory", "", "", func(ctx context.Context, c *directory.Caller, _ noArgs) (any, error) {
				return s.peopleDirectory(ctx, c)
			}),
		{Name: "my_ai_connections", Description: "Your AI connections (each AI client you gave access, when, last used, when it ends) and your own last 50 AI requests through Portcullis. Only your data.",
			Class: ClassRead, Scope: ScopePeople, Twin: "GET /api/me/ai", In: noArgs{},
			Run: func(ctx context.Context, c *directory.Caller, _ json.RawMessage) (any, error) {
				return s.Hub.MyAI(ctx, strings.ToLower(c.User))
			}},
		{Name: "disconnect_ai", Description: "Disconnect one of your own AI connections (revokes your consent and its sessions for that AI client; it must ask you again). Only your own connections.",
			Class: ClassWrite, Scope: ScopePeople, Twin: "DELETE /api/me/ai/connections/{client}", Audit: "ai.connection.revoke", In: disconnectArgs{},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[disconnectArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				u := strings.ToLower(c.User)
				if err := s.Hub.DisconnectAI(ctx, u, in.Client, toolActor(ctx, c)); err != nil {
					return nil, err
				}
				return map[string]string{"status": "disconnected", "client": in.Client}, nil
			}},
		// G1: the link only — the card there fresh-auths, then shows the
		// password once; never one here, never created here.
		{Name: "my_file_share_password", Description: "Where to create or regenerate your file-share password: the My apps page, after a fresh sign-in. The password is shown only there, never to the AI.",
			Class: ClassRead, Scope: ScopePeople, Twin: "POST /api/me/apps/{instance}/credentials/{key}", In: noArgs{},
			Run: func(context.Context, *directory.Caller, json.RawMessage) (any, error) {
				return map[string]string{"link": s.peopleHome() + "#myapps",
					"note": "open it and use the app's file-sharing card: it asks you to sign in again, then shows the password once; it is never passed through the AI"}, nil
			}},
		// ── Delegates (G38: only on people.<d>/mcp) ──
		peopleTool(s, "update_person", "Change a person's email or display name (needs the edit_details permission; ordinary people only).",
			ClassWrite, "PUT /api/directory/users/{username}", "user.update", directory.PermEditDetails,
			func(ctx context.Context, c *directory.Caller, in updatePersonArgs) (any, error) {
				if err := s.updateUser(ctx, c, in.Username, in.Email, in.DisplayName); err != nil {
					return nil, err
				}
				return map[string]string{"status": "saved"}, nil
			}),
		// invite_person is U (T18's invite ruling): the invite link is a
		// secret, so the delegate creates the person on the People page's
		// invite form, where it is shown; Run reports what the directory
		// knows, never the client's accept.
		{Name: "invite_person", Description: "Invite a new person (needs the invite permission): the People page's invite form opens pre-filled; you create them there, where their one-time invite link is shown to you. Afterwards this reports whether they exist and your latest invite of them.",
			Class: ClassSecret, Scope: ScopePeople, Twin: "POST /api/directory/users", Perm: directory.PermInvite, Audit: "user.create", In: invitePersonArgs{},
			SecretForm: func(args json.RawMessage) string {
				a, _ := decode[invitePersonArgs](args)
				return s.peopleInviteForm(a)
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				if s.Directory == nil {
					return nil, errNoUserManagement
				}
				a, _ := decode[invitePersonArgs](args)
				if !lldap.ValidUsername(a.Username) {
					return nil, badArg("invalid username")
				}
				return s.peopleInviteState(ctx, c, a.Username)
			}},
		dirD(peopleTool(s, "delete_person", "Delete a person from LLDAP and Keycloak for good (needs the remove permission; ordinary people only). Needs your confirmation in the browser.",
			ClassWrite, "DELETE /api/directory/users/{username}", "user.delete", directory.PermRemove,
			func(ctx context.Context, c *directory.Caller, in personArgs) (any, error) {
				res, err := s.deleteUser(ctx, c, in.Username, in.Username)
				if err != nil {
					return nil, err
				}
				return s.safeResult(in.Username, "deleted", res), nil
			}), usernameOf, s.personConsequences("Deletes %s from LLDAP and Keycloak; this can't be undone.")),
	} {
		if t.Name == "delete_person" {
			// A target the directory refuses a delegate (an administrator,
			// a protected account, a permission holder, themselves) is
			// refused at once: no confirmation for a call that can't run.
			t.Precheck = func(ctx context.Context, c *directory.Caller, args json.RawMessage) error {
				if s.Directory == nil {
					return errNoUserManagement
				}
				return s.Directory.CheckDelegate(ctx, c, directory.PermRemove, usernameOf(args))
			}
		}
		s.registerTool(t)
	}
}
