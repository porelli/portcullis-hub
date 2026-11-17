package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

// State is what the last apply did (/etc/portcullis/state.json, 0600).
type State struct {
	HostID string            `json:"host_id"`
	Domain string            `json:"domain"`
	Serial int64             `json:"serial"`
	Files  map[string]string `json:"files"`
	Locked []string          `json:"locked"`
	// Removed are accounts removed and not yet confirmed to the Hub.
	Removed  []string  `json:"removed"`
	Applied  time.Time `json:"applied"`
	Reported time.Time `json:"reported"`
	// ServiceNone: sshd is reloaded by its pid file only.
	ServiceNone bool `json:"service_none,omitempty"`
}

// LoadState reads the state (missing = nil).
func LoadState(sys System) (*State, error) {
	raw, err := readMaybe(sys, StateFile)
	if err != nil || raw == nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s is corrupt", StateFile)
	}
	return &s, nil
}

// SaveState writes it.
func SaveState(sys System, s *State) error {
	raw, _ := json.MarshalIndent(s, "", "  ")
	return sys.WriteFileAtomic(StateFile, raw, 0o600)
}

// ApplyOptions are an apply's environment.
type ApplyOptions struct {
	Domain      string
	ServiceNone bool
	Now         time.Time
}

func hashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func finding(kind, sev, subject, detail string) cliapi.Finding {
	return cliapi.Finding{Kind: kind, Severity: sev, Subject: clipStr(subject), Detail: clipStr(detail)}
}

func clipStr(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// ValidateBundle checks a bundle's content (the schema and size are the
// decoder's): its host, every key and principal; anything else refuses
// the whole bundle (nothing applied).
func ValidateBundle(b *cliapi.Bundle, hostID string, hostKey ssh.PublicKey) error {
	switch {
	case b.Version != cliapi.BundleVersion:
		return errors.New("bundle version isn't 1")
	case b.HostID != hostID:
		return errors.New("bundle for another host")
	case len(b.UserCAs) == 0 || len(b.UserCAs) > 4:
		return errors.New("bundle without a user CA")
	case len(b.Accounts) > 100000 || len(b.RevokedKeys) > 100000:
		return errors.New("bundle too large")
	}
	for _, k := range b.UserCAs {
		if _, _, err := cliapi.ParseAuthorizedKey(k); err != nil {
			return errors.New("bundle holds a user CA that isn't a public key")
		}
	}
	// Revoked keys: an invalid line is dropped and reported by Apply
	// (FR-H1), never a reason to refuse the bundle — that would freeze the
	// host (no later revocation, lock or removal would arrive).
	seen := map[string]bool{}
	for _, a := range b.Accounts {
		if seen[a.Name] || !validBundleAccount(a) || len(a.Name) == 0 || len(a.Name) > 64 || strings.ContainsAny(a.Name, "/:\n\x00 ") {
			return fmt.Errorf("bundle account %q is invalid", clipStr(a.Name))
		}
		seen[a.Name] = true
	}
	for _, n := range append(slices.Clone(b.Locked), b.Remove...) {
		if !cliapi.ValidUsername(n) && !cliapi.ValidAccount(n) {
			return errors.New("bundle names an invalid account to lock or remove")
		}
	}
	if b.HostCertificate != "" {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(b.HostCertificate))
		c, ok := k.(*ssh.Certificate)
		if err != nil || !ok || c.CertType != ssh.HostCert || hostKey == nil || !bytes.Equal(c.Key.Marshal(), hostKey.Marshal()) {
			return errors.New("bundle's host certificate isn't for this host's key")
		}
	}
	return nil
}

// Apply makes the host match bundle b within ceiling c (contract §18.14):
// accounts with useradd / usermod / userdel, then every file through one
// transaction validated by visudo -cf, sshd -t and the effective check,
// sshd reloaded only when a file changed. Bundle entries over the ceiling
// are skipped and reported; a validation failure puts every file back.
func Apply(ctx context.Context, sys System, b *cliapi.Bundle, c cliapi.Ceiling, prev *State, o ApplyOptions) (*State, []cliapi.Finding, error) {
	var findings []cliapi.Finding
	if err := ensureGroup(ctx, sys); err != nil {
		return nil, nil, err
	}
	acc, err := loadAccounts(sys)
	if err != nil {
		return nil, nil, err
	}
	// Drift: a managed file that isn't what the last apply wrote.
	if prev != nil {
		for p, h := range prev.Files {
			cur, _ := readMaybe(sys, p)
			if cur != nil && hashHex(cur) != h {
				findings = append(findings, finding(cliapi.FindingDrift, cliapi.SeverityWarning, p, "fixed"))
			}
		}
	}
	principals := map[string][]string{}
	var sudo []string
	wantNames := map[string]bool{}
	for _, a := range b.Accounts {
		wantNames[a.Name] = true
		if !cliapi.ValidAccount(a.Name) {
			findings = append(findings, finding(cliapi.FindingAccountInvalid, cliapi.SeverityWarning, a.Name, "can't be a local account name on this host"))
			continue
		}
		if a.Name == "root" {
			if !c.AllowRootLogin {
				findings = append(findings, finding(cliapi.FindingCeiling, cliapi.SeverityWarning, a.Name, "root logins aren't allowed by this host's ceiling"))
				continue
			}
		} else if Protected(c, a.Name, acc.users) {
			findings = append(findings, finding(cliapi.FindingCeiling, cliapi.SeverityWarning, a.Name, "a protected account on this host"))
			continue
		}
		if len(a.Principals) == 0 {
			continue
		}
		switch a.Kind {
		case cliapi.AccountPerson:
			u, existsU := acc.users[a.Name]
			switch {
			case existsU && !acc.ours(a.Name):
				findings = append(findings, finding(cliapi.FindingAccountConflict, cliapi.SeverityWarning, a.Name, "a local account Portcullis didn't create: never adopted"))
				continue
			case !existsU:
				if a.UID < c.UIDRange[0] || a.UID > c.UIDRange[1] {
					findings = append(findings, finding(cliapi.FindingCeiling, cliapi.SeverityWarning, a.Name, fmt.Sprintf("uid %d is outside this host's range", a.UID)))
					continue
				}
				if c.MaxAccounts > 0 && acc.created >= c.MaxAccounts {
					findings = append(findings, finding(cliapi.FindingCeiling, cliapi.SeverityWarning, a.Name, fmt.Sprintf("this host allows at most %d Portcullis accounts", c.MaxAccounts)))
					continue
				}
				if uidTaken(acc.users, a.UID) {
					findings = append(findings, finding(cliapi.FindingAccountConflict, cliapi.SeverityWarning, a.Name, fmt.Sprintf("uid %d belongs to another account", a.UID)))
					continue
				}
				if err := createPerson(ctx, sys, a.Name, a.UID); err != nil {
					findings = append(findings, finding(cliapi.FindingAccountMissing, cliapi.SeverityWarning, a.Name, err.Error()))
					continue
				}
				acc.created++
			default:
				if u.Shell == nologin || prev != nil && slices.Contains(prev.Locked, a.Name) {
					if err := unlock(ctx, sys, a.Name); err != nil {
						findings = append(findings, finding(cliapi.FindingAccountMissing, cliapi.SeverityWarning, a.Name, err.Error()))
						continue
					}
				}
			}
		case cliapi.AccountShared:
			u, existsU := acc.users[a.Name]
			if !existsU {
				if !b.Options.CreateSharedAccounts {
					findings = append(findings, finding(cliapi.FindingAccountMissing, cliapi.SeverityWarning, a.Name, "the shared account doesn't exist: create it, or let Portcullis create shared accounts"))
				} else if out, err := sys.Run(ctx, "useradd", "-m", "-s", shellFor(sys), a.Name); err != nil {
					findings = append(findings, finding(cliapi.FindingAccountMissing, cliapi.SeverityWarning, a.Name, "useradd: "+firstLine(out)))
					continue
				}
			} else if n := authorizedKeysCount(sys, u); n > 0 {
				findings = append(findings, finding(cliapi.FindingAuthorizedKeysShared, cliapi.SeverityInfo, a.Name, fmt.Sprintf("%d authorized_keys entries", n)))
			}
		}
		// FR-H4: an account that can reach root by other means is sudo,
		// whatever the bundle says; with sudo off by the ceiling it gets no
		// principals (a cloud image's default user, an admin's own login).
		if !c.AllowSudo {
			if via := acc.sudoVia(ctx, sys, a.Name); via != "" {
				findings = append(findings, finding(cliapi.FindingCeiling, cliapi.SeverityWarning, a.Name, "has sudo on this host ("+via+") and this host's ceiling doesn't allow sudo"))
				continue
			}
		}
		principals[a.Name] = a.Principals
		if a.Sudo {
			if !c.AllowSudo {
				findings = append(findings, finding(cliapi.FindingCeiling, cliapi.SeverityWarning, a.Name, "sudo isn't allowed by this host's ceiling"))
			} else {
				sudo = append(sudo, a.Name)
			}
		}
	}
	// Losing access: lock (never delete); remove only when asked.
	locked := map[string]bool{}
	for _, n := range b.Locked {
		if wantNames[n] || !acc.ours(n) || Protected(c, n, acc.users) {
			continue
		}
		locked[n] = true
		if prev == nil || !slices.Contains(prev.Locked, n) || acc.users[n].Shell != nologin {
			if err := lock(ctx, sys, n); err != nil {
				findings = append(findings, finding(cliapi.FindingAccountMissing, cliapi.SeverityWarning, n, err.Error()))
			}
		}
	}
	var removed []string
	for _, n := range b.Remove {
		if !acc.ours(n) || Protected(c, n, acc.users) {
			continue
		}
		if err := removeAccount(ctx, sys, acc, n, o.Now); err != nil {
			findings = append(findings, finding(cliapi.FindingAccountMissing, cliapi.SeverityWarning, n, err.Error()))
			continue
		}
		removed = append(removed, n)
		delete(locked, n)
	}
	// The files, in one transaction.
	tx := NewTransaction(sys)
	for _, d := range []string{PortcullisDir, PrincipalsDir, DropInDir, ConfDir} {
		if err := sys.MkdirAll(d, 0o755); err != nil {
			return nil, findings, err
		}
	}
	if old, _ := readMaybe(sys, RevokedKeysFile); old == nil {
		if err := tx.Stage(RevokedKeysFile, []byte{}, 0o644); err != nil {
			return nil, findings, err
		}
	}
	var cas, revoked []string
	for _, k := range b.UserCAs {
		_, n, _ := cliapi.ParseAuthorizedKey(k)
		cas = append(cas, n)
	}
	dropped := 0
	for _, k := range b.RevokedKeys {
		_, n, err := cliapi.ParseAuthorizedKey(k)
		if err != nil {
			dropped++
			continue
		}
		revoked = append(revoked, n)
	}
	if dropped > 0 {
		findings = append(findings, finding(cliapi.FindingDrift, cliapi.SeverityWarning, RevokedKeysFile, fmt.Sprintf("%d revoked key line(s) from the Hub weren't public keys: dropped", dropped)))
	}
	sort.Strings(revoked)
	stage := func(p string, body []byte, mode uint32) error { return tx.Stage(p, body, fsMode(mode)) }
	steps := []func() error{
		func() error { return stage(UserCAFile, []byte(strings.Join(cas, "\n")+"\n"), 0o644) },
		func() error { return stage(RevokedKeysFile, linesBody(revoked), 0o644) },
	}
	if err := runAll(steps); err != nil {
		tx.Rollback()
		return nil, findings, err
	}
	have, _ := sys.Glob(PrincipalsDir + "/*")
	for _, p := range have {
		if _, ok := principals[filepathBase(p)]; !ok {
			if err := tx.StageRemove(p); err != nil {
				tx.Rollback()
				return nil, findings, err
			}
		}
	}
	for _, n := range sortedKeys(principals) {
		if err := tx.Stage(PrincipalsFile(n), principalsBody(principals[n]), 0o644); err != nil {
			tx.Rollback()
			return nil, findings, err
		}
	}
	hostCert := b.HostCertificate != ""
	if hostCert {
		if err := tx.Stage(HostCertFile, []byte(strings.TrimSpace(b.HostCertificate)+"\n"), 0o644); err != nil {
			tx.Rollback()
			return nil, findings, err
		}
	}
	if err := tx.Stage(DropInFile, DropIn(SyncOrigin(o.Domain, b.HostID), hostCert), 0o644); err != nil {
		tx.Rollback()
		return nil, findings, err
	}
	sudoBody := SudoersBody(sudo)
	if sudoBody != nil {
		if err := CheckSudoers(ctx, sys, sudoBody); err != nil {
			// The old sudoers file stays; the rest still applies.
			findings = append(findings, finding(cliapi.FindingDrift, cliapi.SeverityProblem, SudoersFile, err.Error()))
		} else if err := tx.Stage(SudoersFile, sudoBody, 0o440); err != nil {
			tx.Rollback()
			return nil, findings, err
		}
	} else if err := tx.StageRemove(SudoersFile); err != nil {
		tx.Rollback()
		return nil, findings, err
	}
	// A Portcullis account for the effective check (any of ours).
	check := ""
	for _, n := range sortedKeys(principals) {
		if acc.members[n] || slices.ContainsFunc(b.Accounts, func(a cliapi.Account) bool { return a.Name == n && a.Kind == cliapi.AccountPerson }) {
			check = n
			break
		}
	}
	err = tx.Commit(func() error {
		if err := SSHDTest(ctx, sys); err != nil {
			return err
		}
		bad, _, err := EffectiveCheck(ctx, sys, check, c.BreakglassAccount, hostCert)
		if err != nil {
			return err
		}
		if len(bad) > 0 {
			return mismatchError(bad)
		}
		if tx.Changed() {
			return Reload(ctx, sys, o.ServiceNone)
		}
		return nil
	})
	if err != nil {
		findings = append(findings, finding(cliapi.FindingDrift, cliapi.SeverityProblem, "sshd", err.Error()))
		return nil, findings, err
	}
	st := &State{HostID: b.HostID, Domain: o.Domain, Serial: b.Serial, Files: map[string]string{}, Locked: sortedKeys(locked), Removed: removed, Applied: o.Now.UTC(), ServiceNone: o.ServiceNone}
	if prev != nil {
		st.Reported = prev.Reported
		st.Removed = append(slices.Clone(prev.Removed), removed...)
	}
	for _, p := range managedFiles(sys, principals, hostCert, sudoBody != nil) {
		if b, err := sys.ReadFile(p); err == nil {
			st.Files[p] = hashHex(b)
		}
	}
	if err := SaveState(sys, st); err != nil {
		return st, findings, err
	}
	return st, findings, nil
}

func managedFiles(sys System, principals map[string][]string, hostCert, sudo bool) []string {
	out := []string{UserCAFile, RevokedKeysFile, DropInFile}
	for n := range principals {
		out = append(out, PrincipalsFile(n))
	}
	if hostCert {
		out = append(out, HostCertFile)
	}
	if sudo {
		out = append(out, SudoersFile)
	}
	sort.Strings(out)
	return out
}

func uidTaken(users map[string]Passwd, uid int) bool {
	for _, u := range users {
		if u.UID == uid {
			return true
		}
	}
	return false
}

func linesBody(l []string) []byte {
	if len(l) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(l, "\n") + "\n")
}

func runAll(steps []func() error) error {
	for _, s := range steps {
		if err := s(); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
