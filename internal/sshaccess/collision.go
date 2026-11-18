package sshaccess

import (
	"slices"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/state"
)

// SystemAccounts are account names below uid 1000 on common distributions
// (Debian, Ubuntu, Fedora / RHEL / Rocky, Alpine, macOS's daemons start
// with "_"), plus the default break-glass account and the cloud images'
// default users. A person whose username is one of them gets no personal
// principal (contract §18.12 "Collisions").
var SystemAccounts = []string{
	"_apt", "adm", "admin", "apache", "avahi", "backup", "bin", "breakglass", "centos", "chrony", "colord", "daemon",
	"dbus", "debian", "dnsmasq", "ec2-user", "fedora", "ftp", "games", "gdm", "gnats", "halt", "irc", "list", "lp",
	"mail", "man", "messagebus", "mysql", "news", "nfsnobody", "nginx", "nobody", "nscd", "ntp", "operator",
	"polkitd", "postfix", "postgres", "proxy", "pulse", "redis", "rocky", "root", "rpc", "rpcuser", "rtkit", "shutdown",
	"sshd", "sssd", "sync", "sys", "syslog", "tcpdump", "tss", "ubuntu", "unbound", "uucp", "uuidd", "www-data",
}

// systemPrefixes are name prefixes of system accounts.
var systemPrefixes = []string{"_", "systemd-", "portcullis"}

// Collision is a person's personal grant skipped because their username
// equals an account that isn't theirs (the doctor's ssh_username_collision).
type Collision struct {
	User   string `json:"user"`
	Grant  string `json:"grant"`
	Reason string `json:"reason"`
}

// reservedFor returns why username can't be a personal account, or "".
// shared is every shared account named by any grant; protected the hosts'
// break-glass and protected accounts.
func reservedFor(user string, shared, protected map[string]bool) string {
	switch {
	case user == "root":
		return "the username is root"
	case shared[user]:
		return "the username is a shared account of a grant"
	case protected[user]:
		return "the username is a host's protected or break-glass account"
	case slices.Contains(SystemAccounts, user):
		return "the username is a system account name"
	case user == "admin" || user == "portcullis-hub" || strings.HasPrefix(user, "portcullis-"):
		return "the username is reserved"
	}
	for _, p := range systemPrefixes {
		if strings.HasPrefix(user, p) {
			return "the username looks like a system account"
		}
	}
	return ""
}

// sharedAccounts is every shared account named by any grant.
func sharedAccounts(st state.SSHState) map[string]bool {
	out := map[string]bool{}
	for _, g := range st.Grants {
		for _, a := range g.Accounts {
			if a != cliapi.UsernamePlaceholder {
				out[a] = true
			}
		}
	}
	return out
}

// protectedAccounts is every host's break-glass and protected accounts as
// their ceilings reported them.
func protectedAccounts(st state.SSHState) map[string]bool {
	out := map[string]bool{}
	for _, h := range st.Hosts {
		if h.Ceiling == nil {
			continue
		}
		if h.Ceiling.BreakglassAccount != "" {
			out[h.Ceiling.BreakglassAccount] = true
		}
		for _, a := range h.Ceiling.ProtectedAccounts {
			out[a] = true
		}
	}
	return out
}

// CheckSharedAgainstUsers refuses a grant whose shared account equals a
// current directory username (a shared account and a person must never
// be the same local account).
func CheckSharedAgainstUsers(g state.SSHGrant, users map[string]bool) error {
	for _, a := range g.Accounts {
		if a != cliapi.UsernamePlaceholder && users[a] {
			return statusError("grant " + g.ID + ": the shared account " + a + " is a person's username: pick another account name")
		}
	}
	return nil
}

type statusError string

func (e statusError) Error() string { return string(e) }

func sortCollisions(cs []Collision) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].User != cs[j].User {
			return cs[i].User < cs[j].User
		}
		return cs[i].Grant < cs[j].Grant
	})
}
