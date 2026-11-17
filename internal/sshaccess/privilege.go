package sshaccess

import (
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

// Widens reports whether after grants more than before (the check for a
// delegate's edit and an admin's typed confirmation): any privileged
// condition after that before lacks.
func Widens(before *state.SSHGrant, after state.SSHGrant) bool {
	pa, _ := Privileged(after)
	if !pa {
		return false
	}
	if before == nil {
		return true
	}
	pb, wb := Privileged(*before)
	_, wa := Privileged(after)
	return !pb || wa != wb || before.HostGroup != after.HostGroup || before.Group != after.Group
}
