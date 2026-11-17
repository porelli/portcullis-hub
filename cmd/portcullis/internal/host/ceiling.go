package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

// LoadCeiling reads /etc/portcullis/host.json (strict). Missing is an
// error: a host is never managed without its operator's ceiling.
func LoadCeiling(sys System) (*cliapi.Ceiling, error) {
	raw, err := sys.ReadFile(CeilingFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", CeilingFile, err)
	}
	var c cliapi.Ceiling
	if err := cliapi.UnmarshalStrict(raw, &c); err != nil {
		return nil, fmt.Errorf("%s is invalid: %v", CeilingFile, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %v", CeilingFile, err)
	}
	return &c, nil
}

// CeilingBytes is the file's content.
func CeilingBytes(c cliapi.Ceiling) []byte {
	b, _ := json.MarshalIndent(c, "", "  ")
	return append(b, '\n')
}

// Protected reports whether account name is out of Portcullis's reach on
// this host: root, below uid 1000, listed, or the break-glass account.
func Protected(c cliapi.Ceiling, name string, users map[string]Passwd) bool {
	if name == "root" || name == c.BreakglassAccount || slices.Contains(c.ProtectedAccounts, name) {
		return true
	}
	if u, ok := users[name]; ok && u.UID < cliapi.ProtectedBelowUID {
		return true
	}
	return false
}

// CheckBreakglass: the break-glass account exists and has at least one
// key in its authorized_keys (a working way in that isn't Portcullis), or
// the operator said there is console access (account "").
func CheckBreakglass(sys System, account string, noBreakglass bool) error {
	if noBreakglass {
		return nil
	}
	if account == "" {
		return errors.New("a break-glass account is required: --breakglass-account <name> (an account with its own authorized_keys, e.g. an offline FIDO key), or --no-breakglass-i-have-console-access")
	}
	users, err := Users(sys)
	if err != nil {
		return err
	}
	u, ok := users[account]
	if !ok {
		return fmt.Errorf("the break-glass account %s doesn't exist: create it with an authorized_keys entry first (or pass --no-breakglass-i-have-console-access)", account)
	}
	for _, f := range []string{u.Home + "/.ssh/authorized_keys", u.Home + "/.ssh/authorized_keys2"} {
		raw, err := sys.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range bytes.Split(raw, []byte("\n")) {
			l = bytes.TrimSpace(l)
			if len(l) == 0 || l[0] == '#' {
				continue
			}
			if _, _, _, _, err := ssh.ParseAuthorizedKey(l); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("the break-glass account %s has no key in %s/.ssh/authorized_keys: add one first (or pass --no-breakglass-i-have-console-access)", account, u.Home)
}

// readMaybe reads path ("" with no error when missing).
func readMaybe(sys System, path string) ([]byte, error) {
	b, err := sys.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func trimLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
