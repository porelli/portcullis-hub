package host

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The OpenSSH floor (contract §18.14).
const minMajor, minMinor = 8, 2

// IncludeLine is what the main config must include.
const IncludeLine = "Include /etc/ssh/sshd_config.d/*.conf"

var versionRE = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)

// SSHDVersion is the installed OpenSSH's version string and numbers.
func SSHDVersion(ctx context.Context, sys System) (string, int, int, error) {
	for _, cmd := range [][]string{{sshdPath(sys), "-V"}, {"ssh", "-V"}} {
		out, _ := sys.Run(ctx, cmd[0], cmd[1:]...)
		if m := versionRE.FindSubmatch(out); m != nil {
			maj, _ := strconv.Atoi(string(m[1]))
			min, _ := strconv.Atoi(string(m[2]))
			return string(m[0]), maj, min, nil
		}
	}
	return "", 0, 0, errors.New("OpenSSH isn't installed (no sshd found)")
}

func sshdPath(sys System) string {
	if p := sys.LookPath("sshd"); p != "" {
		return p
	}
	return "/usr/sbin/sshd"
}

// CheckFloor refuses OpenSSH below 8.2, with the lines to set up by hand.
func CheckFloor(ctx context.Context, sys System) (string, error) {
	v, maj, min, err := SSHDVersion(ctx, sys)
	if err != nil {
		return "", err
	}
	if maj < minMajor || maj == minMajor && min < minMinor {
		return v, fmt.Errorf("%s is older than OpenSSH 8.2: set this host up by hand — %s", v, manualLines())
	}
	return v, nil
}

func manualLines() string {
	return "in " + MainConfig + " add: TrustedUserCAKeys " + UserCAFile + "; AuthorizedPrincipalsFile " + PrincipalsDir + "/%u; RevokedKeys " + RevokedKeysFile
}

// CheckInclude refuses a main config without the drop-in directory's
// Include (the tools never edit the main config).
func CheckInclude(sys System) error {
	raw, err := sys.ReadFile(MainConfig)
	if err != nil {
		return fmt.Errorf("reading %s: %w", MainConfig, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && strings.EqualFold(f[0], "Include") {
			for _, inc := range f[1:] {
				if inc == DropInDir+"/*.conf" || inc == "sshd_config.d/*.conf" {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%s doesn't include %s/*.conf: add this line at its top, then run this again: %s", MainConfig, DropInDir, IncludeLine)
}

// SSHDTest is sshd -t.
func SSHDTest(ctx context.Context, sys System) error {
	if out, err := sys.Run(ctx, sshdPath(sys), "-t"); err != nil {
		return fmt.Errorf("sshd -t refused the configuration: %s", firstLine(out))
	}
	return nil
}

// Effective is sshd -T -C user=<u>,host=localhost,addr=127.0.0.1 (plan
// C14), keyword → value (lowercase keywords).
func Effective(ctx context.Context, sys System, user string) (map[string]string, error) {
	out, err := sys.Run(ctx, sshdPath(sys), "-T", "-C", "user="+user+",host=localhost,addr=127.0.0.1")
	if err != nil {
		return nil, fmt.Errorf("sshd -T for %s failed: %s", user, firstLine(out))
	}
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if ok {
			if _, dup := m[strings.ToLower(k)]; !dup {
				m[strings.ToLower(k)] = strings.TrimSpace(v)
			}
		}
	}
	return m, nil
}

// EffectiveKeywords are the six keywords a report carries.
var EffectiveKeywords = []string{"trustedusercakeys", "authorizedprincipalsfile", "revokedkeys", "pubkeyauthentication", "authorizedkeysfile", "hostcertificate", "passwordauthentication", "kbdinteractiveauthentication"}

// Mismatch is one effective value that isn't Portcullis's.
type Mismatch struct{ User, Keyword, Want, Got string }

func (m Mismatch) String() string {
	return fmt.Sprintf("%s: %s is %q, not %q", m.User, m.Keyword, m.Got, m.Want)
}

// EffectiveCheck checks that sshd uses the Portcullis values (contract
// §18.14 "Apply"): the global ones for both users; the Match values for
// portcullisUser ("" = none to check) and not for other ("" = root).
func EffectiveCheck(ctx context.Context, sys System, portcullisUser, other string, hostCert bool) ([]Mismatch, map[string]map[string]string, error) {
	if other == "" {
		other = "root"
	}
	eff := map[string]map[string]string{}
	var bad []Mismatch
	want := map[string]string{"trustedusercakeys": UserCAFile, "authorizedprincipalsfile": PrincipalsDir + "/%u", "revokedkeys": RevokedKeysFile, "pubkeyauthentication": "yes"}
	users := []string{other}
	if portcullisUser != "" {
		users = append([]string{portcullisUser}, other)
	}
	// root too, always (security review 2): its certificates must go
	// through the principals file like everyone's, so root never accepts a
	// certificate naming "root" — Vault would sign that for a tampered role.
	if !slices.Contains(users, "root") {
		users = append(users, "root")
	}
	for _, u := range users {
		m, err := Effective(ctx, sys, u)
		if err != nil {
			return nil, nil, err
		}
		keep := map[string]string{}
		for _, k := range EffectiveKeywords {
			keep[k] = m[k]
		}
		eff[u] = keep
		for k, v := range want {
			if m[k] != v {
				bad = append(bad, Mismatch{u, k, v, m[k]})
			}
		}
		if hostCert && !strings.Contains(" "+m["hostcertificate"]+" ", " "+HostCertFile+" ") && !strings.Contains(m["hostcertificate"], HostCertFile) {
			bad = append(bad, Mismatch{u, "hostcertificate", HostCertFile, m["hostcertificate"]})
		}
	}
	if portcullisUser != "" {
		m := eff[portcullisUser]
		for k, v := range map[string]string{"authorizedkeysfile": "none", "passwordauthentication": "no", "kbdinteractiveauthentication": "no"} {
			if m[k] != v {
				bad = append(bad, Mismatch{portcullisUser, k, v, m[k]})
			}
		}
	}
	if eff[other]["authorizedkeysfile"] == "none" {
		bad = append(bad, Mismatch{other, "authorizedkeysfile", "not none (the Portcullis Match must not apply to " + other + ")", "none"})
	}
	return bad, eff, nil
}

// mismatchError is EffectiveCheck's refusal text.
func mismatchError(bad []Mismatch) error {
	var parts []string
	for _, b := range bad {
		parts = append(parts, b.String())
	}
	return fmt.Errorf("sshd isn't using the Portcullis settings (something in %s or an earlier drop-in sets them first): %s", MainConfig, strings.Join(parts, "; "))
}

// Reload reloads sshd (plan C28): systemctl reload ssh / sshd, launchctl
// on macOS, else SIGHUP to /run/sshd.pid; none works → refuse.
func Reload(ctx context.Context, sys System, serviceNone bool) error {
	if !serviceNone {
		if sys.GOOS() == "darwin" {
			if _, err := sys.Run(ctx, "launchctl", "kickstart", "-k", "system/com.openssh.sshd"); err == nil {
				return nil
			}
		} else if sys.LookPath("systemctl") != "" {
			unit := "sshd"
			if out, err := sys.Run(ctx, "systemctl", "cat", "ssh.service"); err == nil && len(out) > 0 {
				unit = "ssh"
			}
			if _, err := sys.Run(ctx, "systemctl", "reload", unit); err == nil {
				return nil
			}
		}
	}
	for _, p := range []string{"/run/sshd.pid", "/var/run/sshd.pid"} {
		raw, err := sys.ReadFile(p)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || pid < 1 {
			continue
		}
		// Only ever an sshd (the pid file could be stale): /proc's comm.
		if comm, err := sys.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm"); err != nil || !strings.HasPrefix(strings.TrimSpace(string(comm)), "sshd") {
			continue
		}
		if err := signalHUP(sys, pid); err == nil {
			return nil
		}
	}
	return errors.New("couldn't reload sshd (no systemctl / launchctl, no /run/sshd.pid): reload it by hand")
}

// signalHUP is a var for tests.
var signalHUP = func(sys System, pid int) error {
	if _, ok := sys.(OS); !ok {
		return errors.New("not the real system")
	}
	return hup(pid)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// filepathBase is filepath.Base (kept for the account checks).
func filepathBase(p string) string { return filepath.Base(p) }
