package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/cliapi"
)

// TrustOptions are `portcullis host trust`'s flags.
type TrustOptions struct {
	Domain    string
	HostGroup string
	// CAKey is --ca-key; CAFingerprint is --ca-fingerprint (with Fetch).
	CAKey, CAFingerprint string
	// Persons are --person (the person's own account: u: principals),
	// Accounts --account (shared accounts: s: principals).
	Persons, Accounts []string
	RevokedKeys       bool
	Breakglass        string
	NoBreakglass      bool
	ServiceNone       bool
	// Fetch GETs a public CLI path on https://people.<domain> (nil = no
	// network: --ca-key without --revoked-keys never connects).
	Fetch func(ctx context.Context, path string) ([]byte, error)
	// Self is this binary's path (the revoked-keys timer runs it).
	Self string
}

// Trust sets up an unmanaged host (contract §18.8): the CA key, one
// principals file per account, the empty revoked-keys file before the
// drop-in, sshd -t and the effective check, a reload — every file put
// back on any failure. No connection unless --ca-fingerprint or
// --revoked-keys.
func Trust(ctx context.Context, sys System, o TrustOptions) (err error) {
	if sys.GOOS() == "windows" {
		return errors.New("Windows hosts: follow the manual steps in the docs")
	}
	if !cliapi.ValidDomain(o.Domain) || !cliapi.ValidHostGroupID(o.HostGroup) || cliapi.ReservedHostGroupID(o.HostGroup) {
		return errors.New("--domain and --host-group must be a domain and a host group id")
	}
	if len(o.Persons)+len(o.Accounts) == 0 {
		return errors.New("name at least one account: --person <username> (their own account) or --account <name> (a shared one)")
	}
	for _, a := range append(slices.Clone(o.Persons), o.Accounts...) {
		if !cliapi.ValidAccount(a) || a == "root" && slices.Contains(o.Persons, a) {
			return fmt.Errorf("%q isn't an account name", a)
		}
	}
	if _, err := CheckFloor(ctx, sys); err != nil {
		return err
	}
	if err := CheckInclude(sys); err != nil {
		return err
	}
	if err := CheckBreakglass(sys, o.Breakglass, o.NoBreakglass); err != nil {
		return err
	}
	if o.RevokedKeys {
		// Before anything is written: the root timer runs this binary.
		if _, err := CheckRootExecutable(sys, o.Self); err != nil {
			return err
		}
	}
	ca, err := trustCAKey(ctx, o)
	if err != nil {
		return err
	}
	users, err := Users(sys)
	if err != nil {
		return err
	}
	for _, a := range append(slices.Clone(o.Persons), o.Accounts...) {
		if a == o.Breakglass {
			return fmt.Errorf("%s is the break-glass account: Portcullis must never manage it", a)
		}
		if _, ok := users[a]; !ok {
			notef("note: the account %s doesn't exist on this host yet: create it, then certificates for it work", a)
		}
	}
	tx := NewTransaction(sys)
	defer func() {
		if err != nil {
			if rerr := tx.Rollback(); rerr != nil {
				err = fmt.Errorf("%v (and putting the files back failed: %v)", err, rerr)
			}
		}
	}()
	for _, d := range []string{PortcullisDir, PrincipalsDir, DropInDir} {
		if err := sys.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// The revoked-keys file exists before sshd is told about it: an
	// unreadable RevokedKeys refuses every key, break-glass included.
	if old, _ := readMaybe(sys, RevokedKeysFile); old == nil {
		if err := tx.Stage(RevokedKeysFile, []byte{}, 0o644); err != nil {
			return err
		}
	}
	if err := tx.Stage(UserCAFile, []byte(ca+"\n"), 0o644); err != nil {
		return err
	}
	for _, a := range o.Persons {
		if err := tx.Stage(PrincipalsFile(a), principalsBody([]string{cliapi.Principal(cliapi.PrincipalPersonal, a, o.HostGroup)}), 0o644); err != nil {
			return err
		}
	}
	for _, a := range o.Accounts {
		if err := tx.Stage(PrincipalsFile(a), principalsBody([]string{cliapi.Principal(cliapi.PrincipalShared, a, o.HostGroup)}), 0o644); err != nil {
			return err
		}
	}
	hostCert := exists(sys, HostCertFile)
	if err := tx.Stage(DropInFile, DropIn(TrustOrigin(o.Domain, o.HostGroup), hostCert), 0o644); err != nil {
		return err
	}
	ceil := cliapi.DefaultCeiling()
	ceil.BreakglassAccount = o.Breakglass
	ceil.ProtectedAccounts = nil
	if o.Breakglass != "" {
		ceil.ProtectedAccounts = []string{o.Breakglass}
	}
	if err := sys.MkdirAll(ConfDir, 0o755); err != nil {
		return err
	}
	if err := tx.Stage(CeilingFile, CeilingBytes(ceil), 0o644); err != nil {
		return err
	}
	if o.RevokedKeys {
		if err := stageRevokedTimer(tx, sys, o); err != nil {
			return err
		}
	}
	if err := tx.Commit(func() error {
		if err := SSHDTest(ctx, sys); err != nil {
			return err
		}
		bad, _, err := EffectiveCheck(ctx, sys, "", o.Breakglass, hostCert)
		if err != nil {
			return err
		}
		if len(bad) > 0 {
			return mismatchError(bad)
		}
		return Reload(ctx, sys, o.ServiceNone)
	}); err != nil {
		return err
	}
	if o.RevokedKeys && !o.ServiceNone {
		if err := enableRevokedTimer(ctx, sys); err != nil {
			return fmt.Errorf("the files are in place, but the revoked-keys timer didn't start: %v", err)
		}
		if err := FetchRevokedKeys(ctx, sys, o.Fetch); err != nil {
			notef("note: the first revoked-keys fetch failed (%v); the timer tries again every 5 minutes", err)
		}
	}
	return nil
}

// trustCAKey: --ca-key as given, or the key fetched from ssh/ca that
// matches --ca-fingerprint; there is no unpinned fetch.
func trustCAKey(ctx context.Context, o TrustOptions) (string, error) {
	if o.CAKey != "" {
		_, norm, err := cliapi.ParseAuthorizedKey(o.CAKey)
		if err != nil {
			return "", errors.New("--ca-key must be the user CA's public key line (ssh-ed25519 AAAA…)")
		}
		if o.CAFingerprint != "" {
			k, _, _ := cliapi.ParseAuthorizedKey(norm)
			if cliapi.Fingerprint(k) != o.CAFingerprint {
				return "", errors.New("--ca-key doesn't match --ca-fingerprint")
			}
		}
		return norm, nil
	}
	if o.CAFingerprint == "" || !strings.HasPrefix(o.CAFingerprint, "SHA256:") {
		return "", errors.New("give --ca-key, or --ca-fingerprint SHA256:… to fetch the key (an unpinned fetch is never done)")
	}
	if o.Fetch == nil {
		return "", errors.New("can't fetch the CA key")
	}
	raw, err := o.Fetch(ctx, "/api/cli/v1/ssh/ca")
	if err != nil {
		return "", fmt.Errorf("fetching the CA key: %v", err)
	}
	var ans cliapi.CAAnswer
	if err := cliapi.UnmarshalStrict(raw, &ans); err != nil {
		return "", errors.New("the CA answer is malformed")
	}
	for _, l := range ans.UserCAs {
		if k, norm, err := cliapi.ParseAuthorizedKey(l); err == nil && cliapi.Fingerprint(k) == o.CAFingerprint {
			return norm, nil
		}
	}
	return "", errors.New("the server's user CA doesn't match --ca-fingerprint: refusing")
}

// The revoked-keys timer (an unmanaged host's 5-minute pull).
const (
	revokedService = "/etc/systemd/system/portcullis-revoked-keys.service"
	revokedTimer   = "/etc/systemd/system/portcullis-revoked-keys.timer"
	revokedPlist   = "/Library/LaunchDaemons/eu.portcullis.revoked-keys.plist"
	revokedDomain  = "/etc/portcullis/revoked-keys-domain"
)

func stageRevokedTimer(tx *Transaction, sys System, o TrustOptions) error {
	self, err := CheckRootExecutable(sys, o.Self)
	if err != nil {
		return err
	}
	if err := tx.Stage(revokedDomain, []byte(o.Domain+"\n"), 0o644); err != nil {
		return err
	}
	if sys.GOOS() == "darwin" {
		return tx.Stage(revokedPlist, []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>eu.portcullis.revoked-keys</string>
<key>ProgramArguments</key><array><string>`+xmlEscape(self)+`</string><string>host</string><string>revoked-keys</string></array>
<key>StartInterval</key><integer>300</integer>
<key>RunAtLoad</key><true/>
</dict></plist>
`), 0o644)
	}
	if err := sys.MkdirAll("/etc/systemd/system", 0o755); err != nil {
		return err
	}
	if err := tx.Stage(revokedService, []byte(`# Written by portcullis host trust. Do not edit.
[Unit]
Description=Portcullis: fetch the revoked SSH keys
After=network-online.target

[Service]
Type=oneshot
ExecStart=`+systemdQuote(self)+` host revoked-keys
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/etc/ssh/portcullis
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
`), 0o644); err != nil {
		return err
	}
	return tx.Stage(revokedTimer, []byte(`# Written by portcullis host trust. Do not edit.
[Unit]
Description=Portcullis: fetch the revoked SSH keys every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
`), 0o644)
}

func enableRevokedTimer(ctx context.Context, sys System) error {
	if sys.GOOS() == "darwin" {
		_, err := sys.Run(ctx, "launchctl", "bootstrap", "system", revokedPlist)
		return err
	}
	if _, err := sys.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err := sys.Run(ctx, "systemctl", "enable", "--now", "portcullis-revoked-keys.timer")
	return err
}

// FetchRevokedKeys fetches the public list and writes it; any failure
// keeps the last file (a stale list is bounded by the certificates' TTL).
func FetchRevokedKeys(ctx context.Context, sys System, fetch func(context.Context, string) ([]byte, error)) error {
	if fetch == nil {
		return errors.New("no network")
	}
	raw, err := fetch(ctx, "/api/cli/v1/ssh/revoked-keys")
	if err != nil {
		return err
	}
	if len(raw) > cliapi.MaxBundle {
		return errors.New("the list is too large")
	}
	var lines []string
	for _, l := range trimLines(string(raw)) {
		_, norm, err := cliapi.ParseAuthorizedKey(l)
		if err != nil {
			return errors.New("the list holds something that isn't a public key: the last file stays")
		}
		lines = append(lines, norm)
	}
	body := strings.Join(lines, "\n")
	if body != "" {
		body += "\n"
	}
	return sys.WriteFileAtomic(RevokedKeysFile, []byte(body), 0o644)
}

// SaveRevokedCAFile records --ca-file for the timer's fetches.
func SaveRevokedCAFile(sys System, caFile string) error {
	raw, err := sys.ReadFile(revokedDomain)
	if err != nil {
		return err
	}
	lines := trimLines(string(raw))
	if len(lines) == 0 {
		return errors.New("no domain")
	}
	return sys.WriteFileAtomic(revokedDomain, []byte(lines[0]+"\n"+caFile+"\n"), 0o644)
}

// RevokedDomain is the timer's domain (and optional CA file).
func RevokedDomain(sys System) (string, string, error) {
	raw, err := sys.ReadFile(revokedDomain)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w (run portcullis host trust --revoked-keys first)", revokedDomain, err)
	}
	lines := trimLines(string(raw))
	if len(lines) == 0 || !cliapi.ValidDomain(lines[0]) {
		return "", "", errors.New(revokedDomain + " is invalid")
	}
	ca := ""
	if len(lines) > 1 {
		ca = lines[1]
	}
	return lines[0], ca, nil
}

// notef prints a note on stderr (a var for tests).
var notef = func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
