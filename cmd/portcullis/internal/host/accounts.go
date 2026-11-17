package host

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"slices"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

// PortcullisComment is a Portcullis-created account's comment
// ("portcullis <username>": /etc/passwd fields can't hold a ':', so
// useradd refuses the spec's "portcullis:<username>").
func PortcullisComment(name string) string { return "portcullis " + name }

// nologin is a locked account's shell.
const nologin = "/usr/sbin/nologin"

// shellFor is /bin/bash when present, else /bin/sh.
func shellFor(sys System) string {
	if exists(sys, "/bin/bash") {
		return "/bin/bash"
	}
	return "/bin/sh"
}

// accountsCtx is the host's accounts as an apply sees them.
type accountsCtx struct {
	users   map[string]Passwd
	members map[string]bool // members of portcullis-users
	created int             // Portcullis-created accounts present
}

func loadAccounts(sys System) (*accountsCtx, error) {
	u, err := Users(sys)
	if err != nil {
		return nil, err
	}
	g, err := GroupMembers(sys)
	if err != nil {
		return nil, err
	}
	a := &accountsCtx{users: u, members: map[string]bool{}}
	for _, m := range g[UsersGroup] {
		a.members[m] = true
	}
	for name := range u {
		if a.ours(name) {
			a.created++
		}
	}
	return a, nil
}

// ours: an account Portcullis created (the comment and the group).
func (a *accountsCtx) ours(name string) bool {
	u, ok := a.users[name]
	return ok && u.Comment == PortcullisComment(name) && a.members[name]
}

// ensureGroup creates portcullis-users once.
func ensureGroup(ctx context.Context, sys System) error {
	g, err := GroupMembers(sys)
	if err != nil {
		return err
	}
	if _, ok := g[UsersGroup]; ok {
		return nil
	}
	if out, err := sys.Run(ctx, "groupadd", UsersGroup); err != nil {
		return fmt.Errorf("groupadd %s: %s", UsersGroup, firstLine(out))
	}
	return nil
}

// createPerson is useradd -u <uid> -U -G portcullis-users -m -s <shell>
// -c portcullis:<name> <name> (contract §18.14).
func createPerson(ctx context.Context, sys System, name string, uid int) error {
	out, err := sys.Run(ctx, "useradd", "-u", strconv.Itoa(uid), "-U", "-G", UsersGroup, "-m", "-s", shellFor(sys), "-c", PortcullisComment(name), name)
	if err != nil {
		return fmt.Errorf("useradd %s: %s", name, firstLine(out))
	}
	return nil
}

// lock ends an account's access: locked, expired, no shell, sessions
// ended (loginctl, then pkill).
func lock(ctx context.Context, sys System, name string) error {
	if out, err := sys.Run(ctx, "usermod", "-L", "-e", "1", "-s", nologin, name); err != nil {
		return fmt.Errorf("usermod -L %s: %s", name, firstLine(out))
	}
	if _, err := sys.Run(ctx, "loginctl", "terminate-user", name); err != nil {
		_, _ = sys.Run(ctx, "pkill", "-KILL", "-u", name)
	}
	return nil
}

// unlock gives a locked Portcullis account back its shell.
func unlock(ctx context.Context, sys System, name string) error {
	if out, err := sys.Run(ctx, "usermod", "-U", "-e", "", "-s", shellFor(sys), name); err != nil {
		return fmt.Errorf("usermod -U %s: %s", name, firstLine(out))
	}
	return nil
}

// removeAccount moves the home to /home/.portcullis-removed/<name>-<date>
// and deletes the account (its files stay).
func removeAccount(ctx context.Context, sys System, a *accountsCtx, name string, now time.Time) error {
	u := a.users[name]
	if err := lock(ctx, sys, name); err != nil {
		return err
	}
	if u.Home != "" && exists(sys, u.Home) {
		if err := sys.MkdirAll(RemovedHomes, 0o700); err != nil {
			return err
		}
		if err := sys.Rename(u.Home, path.Join(RemovedHomes, name+"-"+now.UTC().Format("20060102"))); err != nil {
			return fmt.Errorf("moving %s's home: %v", name, err)
		}
	}
	if out, err := sys.Run(ctx, "userdel", name); err != nil {
		return fmt.Errorf("userdel %s: %s", name, firstLine(out))
	}
	return nil
}

// authorizedKeysCount counts key lines of an account's authorized_keys.
func authorizedKeysCount(sys System, u Passwd) int {
	n := 0
	for _, f := range []string{u.Home + "/.ssh/authorized_keys", u.Home + "/.ssh/authorized_keys2"} {
		raw, err := sys.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range bytes.Split(raw, []byte("\n")) {
			if l = bytes.TrimSpace(l); len(l) > 0 && l[0] != '#' {
				if _, _, _, _, err := ssh.ParseAuthorizedKey(l); err == nil {
					n++
				}
			}
		}
	}
	return n
}

// validBundleAccount: the principals are of the account's own kind and
// name (u:<name>@… for a person, s:<name>@… for a shared account): a
// bundle can never make one account accept another's certificates.
func validBundleAccount(a cliapi.Account) bool {
	want := cliapi.PrincipalShared
	if a.Kind == cliapi.AccountPerson {
		want = cliapi.PrincipalPersonal
	} else if a.Kind != cliapi.AccountShared {
		return false
	}
	for _, p := range a.Principals {
		kind, acct, _, ok := cliapi.ParsePrincipal(p)
		if !ok || kind != want || acct != a.Name {
			return false
		}
	}
	return len(a.Principals) == len(slices.Compact(slices.Clone(a.Principals)))
}
