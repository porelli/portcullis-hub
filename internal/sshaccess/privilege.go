package sshaccess

import (
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/state"
)

// PrivilegedTTLHours is a privileged grant's default TTL.
const PrivilegedTTLHours = 4

// Privileged reports whether g is privileged (spec §9.4) and why, in
// words: sudo, the account root, agent forwarding, a shared account with
// sudo, or the host group all / a portcullis-* group.
func Privileged(g state.SSHGrant) (bool, string) {
	var why []string
	if g.Sudo == state.SudoFull {
		why = append(why, "sudo")
		for _, a := range g.Accounts {
			if a != cliapi.UsernamePlaceholder {
				why = append(why, "a shared account with sudo")
				break
			}
		}
	}
	for _, a := range g.Accounts {
		if a == "root" {
			why = append(why, "the root account")
			break
		}
	}
	for _, a := range g.Accounts {
		if slices.Contains(CloudDefaultAccounts, a) {
			why = append(why, "the account "+a+" (a cloud image's default user, usually with sudo)")
			break
		}
	}
	if g.AgentForwarding {
		why = append(why, "agent forwarding")
	}
	if g.HostGroup == cliapi.BuiltinAllHostGroup || cliapi.ReservedHostGroupID(g.HostGroup) {
		why = append(why, "every managed host")
	}
	if len(why) == 0 {
		return false, ""
	}
	return true, strings.Join(why, ", ")
}

// CloudDefaultAccounts are the default users of common cloud and board
// images, which usually have passwordless sudo (FR-H4): a grant of one is
// privileged whatever its sudo setting (the typed group name and a fresh
// sign-in; never by a delegate or through the AI). The host's ceiling
// also refuses any account with sudo when allow_sudo is off.
var CloudDefaultAccounts = []string{"ubuntu", "ec2-user", "admin", "centos", "debian", "rocky", "almalinux", "fedora",
	"azureuser", "opc", "cloud-user", "pi", "alpine", "arch"}

// GrantTTLHours is the grant's effective TTL: its own, else 4 h for a
// privileged grant, else the setting; never above the setting's maximum.
func GrantTTLHours(g state.SSHGrant, s state.SSHSettings) int {
	max := s.TTLHours()
	h := g.TTLHours
	if h == 0 {
		if p, _ := Privileged(g); p {
			h = PrivilegedTTLHours
		} else {
			h = max
		}
	}
	if h > max {
		h = max
	}
	return h
}

// WideningReasons lists how an edit (before → after) widens a grant,
// whether or not either side is privileged (security review ruling):
// accounts added, a longer effective TTL, forwarding newly allowed, sudo
// or privilege added, another host group or group. A widening edit needs
// the same guard as creating a privileged grant (an administrator, a
// fresh sign-in, the audit). A new grant (before nil) is judged by
// Privileged instead: nil here.
func WideningReasons(before *state.SSHGrant, after state.SSHGrant, s state.SSHSettings) []string {
	if before == nil {
		return nil
	}
	var why []string
	for _, a := range after.Accounts {
		if !slices.Contains(before.Accounts, a) {
			why = append(why, "adds the account "+a)
		}
	}
	if GrantTTLHours(after, s) > GrantTTLHours(*before, s) {
		why = append(why, "longer certificates")
	}
	if after.PortForwarding && !before.PortForwarding {
		why = append(why, "allows port forwarding")
	}
	if after.AgentForwarding && !before.AgentForwarding {
		why = append(why, "allows agent forwarding")
	}
	if after.Sudo == state.SudoFull && before.Sudo != state.SudoFull {
		why = append(why, "adds sudo")
	}
	pb, _ := Privileged(*before)
	pa, _ := Privileged(after)
	if pa && !pb {
		why = append(why, "becomes privileged")
	}
	if after.HostGroup != before.HostGroup {
		why = append(why, "another host group")
	}
	if after.Group != before.Group || after.GroupID != before.GroupID {
		why = append(why, "another group")
	}
	return why
}

// Widens is WideningReasons != nil.
func Widens(before *state.SSHGrant, after state.SSHGrant, s state.SSHSettings) bool {
	return len(WideningReasons(before, after, s)) > 0
}
