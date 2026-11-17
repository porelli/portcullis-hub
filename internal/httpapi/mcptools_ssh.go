package httpapi

// The SSH access tools (contract §15.10, spec §9.12). Admin: the reads,
// revoke_ssh_certificates and set_ssh_grant (D, per-call confirmation;
// non-privileged, non-widening grants only — the Hub refuses the rest for
// Via AI). People: my_ssh_access and revoke_my_ssh_certificates. Never a
// signing of user or host certificates, an enrolment code, a privileged
// grant, a source address, a setting or a CA rotation.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

type (
	sshPreviewArgs struct {
		Host     string `json:"host" jsonschema:"the managed host id (from list_ssh_hosts)"`
		RootOnly bool   `json:"root_only,omitempty" jsonschema:"only rows with root or sudo"`
	}
	sshCertsArgs struct {
		User string `json:"user,omitempty" jsonschema:"only this person's certificates"`
	}
	sshRevokeArgs struct {
		User         string   `json:"user" jsonschema:"the person whose SSH certificates to revoke"`
		Fingerprints []string `json:"fingerprints,omitempty" jsonschema:"SHA256 key fingerprints (from list_ssh_certificates); empty = all of the person's unexpired ones"`
	}
	sshGrantArgs struct {
		ID             string   `json:"id,omitempty" jsonschema:"the grant to change; empty = a new grant"`
		Group          string   `json:"group" jsonschema:"the LLDAP group the grant is for"`
		HostGroup      string   `json:"host_group" jsonschema:"the host group"`
		Accounts       []string `json:"accounts" jsonschema:"{username} and/or shared account names"`
		TTLHours       int      `json:"ttl_hours,omitempty" jsonschema:"certificate lifetime 1-12 h (0 = the default)"`
		PortForwarding bool     `json:"port_forwarding,omitempty"`
	}
)

func (s *Server) registerSSHTools() {
	for _, t := range []Tool{
		admin("list_ssh_access", "SSH access: the host groups (members, template, delegable) and the grants (group → host group, accounts, sudo, lifetime, forwarding, privileged and why). No keys.",
			ClassRead, "GET /api/ssh/grants", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
				return map[string]any{"host_groups": s.Hub.SSHHostGroups(), "grants": s.Hub.SSHGrants(false)}, nil
			}),
		admin("ssh_access_preview", "Who can reach a host, as which account, with or without sudo, and through which grant (the Access tab).",
			ClassRead, "GET /api/ssh/hosts/{id}/access", "", func(ctx context.Context, _ directory.Actor, in sshPreviewArgs) (any, error) {
				rows, err := s.Hub.SSHAccess("host", in.Host, in.RootOnly)
				if err != nil {
					return nil, err
				}
				return map[string]any{"rows": rows}, nil
			}),
		admin("list_ssh_certificates", "Issued SSH certificates (person, host group, principals, key fingerprint, serial, until) and the revoked keys by fingerprint.",
			ClassRead, "GET /api/ssh/certificates", "", func(ctx context.Context, _ directory.Actor, in sshCertsArgs) (any, error) {
				return s.Hub.SSHCertificates(in.User), nil
			}),
		admin("list_ssh_hosts", "Managed and unmanaged SSH hosts: state, last sync, bundle serial, host certificate expiry and drift findings.",
			ClassRead, "GET /api/ssh/hosts", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
				return map[string]any{"hosts": s.Hub.SSHHosts()}, nil
			}),
		{Name: "revoke_ssh_certificates", Description: "Revoke a person's SSH certificates (needs your confirmation in the browser): their keys go on the revoked list, managed hosts refuse them within seconds.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "POST /api/ssh/certificates/revoke", Audit: "ssh.certificate.revoke", In: sshRevokeArgs{},
			Typed:        argReader("user"),
			Consequences: sshRevokeConsequences,
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[sshRevokeArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				n, err := s.revokeSSH(ctx, toolActor(ctx, c), in.User, in.Fingerprints)
				if err != nil {
					return nil, err
				}
				return map[string]any{"revoked": n}, nil
			}},
		{Name: "set_ssh_grant", Description: "Create or narrow a non-privileged SSH grant (needs your confirmation in the browser): no sudo, no root, no agent forwarding, not the all host group, and never widening an existing grant — those are made on the Hub page.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "POST /api/ssh/grants", Audit: "ssh.grant.create", In: sshGrantArgs{},
			Typed:        argReader("group"),
			Consequences: sshGrantConsequences,
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[sshGrantArgs](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				if confirmationID(ctx) != "" && s.Directory != nil {
					// The caller with the consumed confirmation (dirTool's rule).
					if c, err = s.Directory.CallerAs(ctx, toolActor(ctx, c)); err != nil {
						return nil, err
					}
				}
				g := state.SSHGrant{ID: in.ID, Group: in.Group, HostGroup: in.HostGroup, Accounts: in.Accounts, Sudo: state.SudoNone, TTLHours: in.TTLHours, PortForwarding: in.PortForwarding}
				return s.saveSSHGrant(ctx, c, g, "", nil)
			}},
		{Name: "my_ssh_access", Description: "Your SSH access: your host groups, accounts, sudo, hosts and your unexpired certificates (fingerprints only), and the two commands to start.",
			Class: ClassRead, Scope: ScopePeople, Twin: "GET /api/me/ssh", In: noArgs{},
			Run: func(ctx context.Context, c *directory.Caller, _ json.RawMessage) (any, error) {
				return s.Hub.PersonSSHAccess(strings.ToLower(c.User)), nil
			}},
		{Name: "revoke_my_ssh_certificates", Description: "Revoke all your own SSH certificates (\"I lost a device\"): managed hosts refuse them within seconds. Sign in again with portcullis login for new ones.",
			Class: ClassWrite, Scope: ScopePeople, Twin: "POST /api/me/ssh/revoke-all", Audit: "ssh.certificate.revoke", In: noArgs{},
			Run: func(ctx context.Context, c *directory.Caller, _ json.RawMessage) (any, error) {
				n, err := s.Hub.RevokeAllSSH(toolActor(ctx, c), strings.ToLower(c.User), "I lost a device")
				if err != nil {
					return nil, err
				}
				return map[string]any{"revoked": n}, nil
			}},
	} {
		s.registerTool(t)
	}
}

// sshRevokeConsequences lists every effective argument of
// revoke_ssh_certificates (TestSSHToolConsequencesShowEveryField).
func sshRevokeConsequences(_ context.Context, args json.RawMessage) []string {
	in, _ := decode[sshRevokeArgs](args)
	out := []string{"Person: " + q(in.User) + "."}
	if len(in.Fingerprints) == 0 {
		out = append(out, "Revokes every unexpired SSH certificate of "+q(in.User)+": they stop working on managed hosts within seconds.")
	} else {
		out = append(out, fmt.Sprintf("Revokes %d SSH certificate key(s) of %s: %s. They stop working on managed hosts within seconds.", len(in.Fingerprints), q(in.User), strings.Join(quoteAll(in.Fingerprints), ", ")))
	}
	return out
}

// sshGrantConsequences lists every effective argument of set_ssh_grant
// (TestSSHToolConsequencesShowEveryField).
func sshGrantConsequences(_ context.Context, args json.RawMessage) []string {
	in, _ := decode[sshGrantArgs](args)
	var out []string
	if in.ID != "" {
		out = append(out, "Replaces grant "+q(in.ID)+" with this one.")
	} else {
		out = append(out, "Creates a new grant.")
	}
	out = append(out, "Lets the members of "+q(in.Group)+" log into host group "+q(in.HostGroup)+" as "+strings.Join(quoteAll(in.Accounts), ", ")+", without sudo.")
	if in.PortForwarding {
		out = append(out, "Allows port forwarding.")
	} else {
		out = append(out, "No port forwarding.")
	}
	if in.TTLHours > 0 {
		out = append(out, fmt.Sprintf("Certificates last %d h.", in.TTLHours))
	} else {
		out = append(out, "Certificates last the default lifetime.")
	}
	return out
}
