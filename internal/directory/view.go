package directory

import (
	"context"
	"strings"
	"time"
)

// CanImport: admins and holders of any delegated permission may review
// and apply a CSV import (each row is still checked on its own).
func (c *Caller) CanImport() bool {
	return c != nil && (c.Admin || c.Perms[PermEditDetails] || c.Perms[PermInvite] || c.Perms[PermRemove])
}

// The non-admin view of GET /api/directory. Default deny: these types
// list exactly what a signed-in non-admin may see (contract §9.6:
// everyone's fields and the org chart), copied field by field from the
// Overview, so a field added to Overview, UserView, GroupView or Field
// never reaches them without being added here
// (TestPeopleListenerReadForEveryone pins the key sets).

// PeopleOverview is the non-admin Overview.
type PeopleOverview struct {
	Available        bool              `json:"available"`
	Reason           string            `json:"reason,omitempty"`
	Me               string            `json:"me"`
	ServiceUser      string            `json:"service_user"`
	Admin            bool              `json:"admin"`
	Perms            []string          `json:"perms"`
	InvitesAvailable bool              `json:"invites_available"`
	Users            []PeopleUser      `json:"users"`
	Groups           []PeopleGroup     `json:"groups"`
	Fields           []PeopleField     `json:"fields"`
	FieldsError      string            `json:"fields_error,omitempty"`
	Permissions      map[string]string `json:"permissions"`
	Cycles           [][]string        `json:"cycles"`
}

// PeopleUser is a user without Keycloak state or recovery commands.
type PeopleUser struct {
	Username    string              `json:"username"`
	Email       string              `json:"email"`
	DisplayName string              `json:"display_name"`
	Created     string              `json:"created"`
	Groups      []string            `json:"groups"`
	Memberships []Membership        `json:"memberships"`
	CreatedBy   string              `json:"created_by,omitempty"`
	Protected   string              `json:"protected,omitempty"`
	Self        bool                `json:"self,omitempty"`
	Admin       bool                `json:"admin,omitempty"`
	Attrs       map[string][]string `json:"attrs"`
}

// PeopleGroup is a group as non-admins see it.
type PeopleGroup struct {
	Name        string               `json:"name"`
	Created     string               `json:"created"`
	Members     []string             `json:"members"`
	Builtin     bool                 `json:"builtin,omitempty"`
	Admin       bool                 `json:"admin,omitempty"`
	UsedBy      []string             `json:"used_by"`
	RuleAllowed bool                 `json:"rule_allowed"`
	Rule        *RuleView            `json:"rule"`
	Exceptions  []ExceptionView      `json:"exceptions"`
	Expiry      map[string]time.Time `json:"expiry"`
	AddsBlocked string               `json:"adds_blocked,omitempty"`
}

// PeopleField is a field definition.
type PeopleField struct {
	Name          string    `json:"name"`
	Label         string    `json:"label"`
	Kind          FieldKind `json:"kind"`
	Values        []string  `json:"values"`
	Multi         bool      `json:"multi"`
	ShareWithApps bool      `json:"share_with_apps"`
	AdminOnly     bool      `json:"admin_only"`
}

// PeopleOverview is GET /api/directory for a non-admin c (admins use
// OverviewFor). An unavailable LLDAP gives a generic Reason.
func (s *Service) PeopleOverview(ctx context.Context, c *Caller) (*PeopleOverview, error) {
	if c == nil || strings.TrimSpace(c.User) == "" {
		return nil, errNoActor()
	}
	nonAdmin := *c
	nonAdmin.Admin = false // this view never carries admin data
	ov, err := s.overview(ctx, c.User, &nonAdmin)
	if err != nil {
		return nil, err
	}
	out := PeopleViewOf(ov)
	if c.Admin {
		out.Admin, out.Perms = true, append([]string{}, delegatedPerms...)
	}
	return out, nil
}

// PeopleViewOf copies what non-admins may see out of ov.
func PeopleViewOf(ov *Overview) *PeopleOverview {
	out := &PeopleOverview{Available: ov.Available, Me: ov.Me, ServiceUser: ov.ServiceUser, Admin: ov.Admin,
		Perms: append([]string{}, ov.Perms...), InvitesAvailable: ov.InvitesAvailable,
		Users: make([]PeopleUser, 0, len(ov.Users)), Groups: make([]PeopleGroup, 0, len(ov.Groups)),
		Fields: make([]PeopleField, 0, len(ov.Fields)), Permissions: map[string]string{}, Cycles: [][]string{}}
	if ov.Reason != "" {
		out.Reason = GenericUnavailable
	}
	if ov.FieldsError != "" {
		out.FieldsError = "custom fields are temporarily unavailable"
	}
	for _, u := range ov.Users {
		attrs := u.Attrs
		if attrs == nil {
			attrs = map[string][]string{}
		}
		out.Users = append(out.Users, PeopleUser{Username: u.Username, Email: u.Email, DisplayName: u.DisplayName, Created: u.Created,
			Groups: u.Groups, Memberships: u.Memberships, CreatedBy: u.CreatedBy, Protected: u.Protected, Self: u.Self, Admin: u.Admin, Attrs: attrs})
	}
	for _, g := range ov.Groups {
		out.Groups = append(out.Groups, PeopleGroup{Name: g.Name, Created: g.Created, Members: g.Members, Builtin: g.Builtin, Admin: g.Admin,
			UsedBy: g.UsedBy, RuleAllowed: g.RuleAllowed, Rule: g.Rule, Exceptions: g.Exceptions, Expiry: g.Expiry, AddsBlocked: g.AddsBlocked})
	}
	for _, f := range ov.Fields {
		out.Fields = append(out.Fields, PeopleField{Name: f.Name, Label: f.Label, Kind: f.Kind, Values: f.Values, Multi: f.Multi,
			ShareWithApps: f.ShareWithApps, AdminOnly: f.AdminOnly})
	}
	for p, g := range ov.Permissions {
		out.Permissions[p] = g
	}
	out.Cycles = append(out.Cycles, ov.Cycles...)
	return out
}

// GenericUnavailable is the reason non-admins get when the directory
// can't be reached (the detail is logged and shown to admins).
const GenericUnavailable = "directory temporarily unavailable"
