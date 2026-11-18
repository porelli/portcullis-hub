// Package sshconf writes the person's SSH files (contract §18.15, spec
// §6): ~/.ssh/portcullis/<domain>/ (0700) with id.pub, one
// <host group>-cert.pub per certificate, known_hosts and config — and
// the private key id (0600) only with --write-files. Everything the
// Hub answered is checked (cliapi's grammars) before it's written.
package sshconf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

// Dir is ~/.ssh/portcullis/<domain> under home.
func Dir(home, domain string) string { return filepath.Join(home, ".ssh", "portcullis", domain) }

// Write writes domain's files under home for ans; pub is the key's
// authorized_keys line; privPEM (nil = none) the private key to write.
func Write(home, domain string, ans *cliapi.CertAnswer, pub string, privPEM []byte) error {
	if !cliapi.ValidDomain(domain) {
		return errors.New("not a valid domain")
	}
	var groups []cliapi.ClientGroup
	certs := map[string]string{}
	for _, c := range ans.Certificates {
		if !cliapi.ValidHostGroupID(c.HostGroup) {
			return fmt.Errorf("the server answered an invalid host group id")
		}
		if _, err := ParseCert(c.Certificate); err != nil {
			return fmt.Errorf("the %s certificate: %w", c.HostGroup, err)
		}
		groups = append(groups, cliapi.ClientGroup{HostGroup: c.HostGroup, Hosts: c.Hosts})
		certs[c.HostGroup] = strings.TrimSpace(c.Certificate) + "\n"
	}
	cfg, err := cliapi.ClientConfig(domain, groups, privPEM != nil)
	if err != nil {
		return fmt.Errorf("the server's answer can't be written as SSH config: %w", err)
	}
	kh, err := cliapi.KnownHosts(domain, groups, ans.HostCAs, ans.RevokedHostKeys)
	if err != nil {
		return fmt.Errorf("the server's answer can't be written as known_hosts: %w", err)
	}
	dir := Dir("", domain)
	dir = filepath.Join(home, dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	// Certificates of host groups no longer granted go.
	old, _ := filepath.Glob(filepath.Join(dir, "*-cert.pub"))
	for _, p := range old {
		hg := strings.TrimSuffix(filepath.Base(p), "-cert.pub")
		if _, ok := certs[hg]; !ok {
			os.Remove(p)
		}
	}
	files := map[string][]byte{"id.pub": []byte(strings.TrimSpace(pub) + "\n"), "config": []byte(cfg), "known_hosts": []byte(kh)}
	for hg, c := range certs {
		files[hg+"-cert.pub"] = []byte(c)
	}
	for name, b := range files {
		if err := writeAtomic(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	if privPEM != nil {
		if err := writeAtomic(filepath.Join(dir, "id"), privPEM, 0o600); err != nil {
			return err
		}
	} else {
		os.Remove(filepath.Join(dir, "id"))
	}
	return nil
}

// ParseCert parses one certificate line.
func ParseCert(line string) (*ssh.Certificate, error) {
	k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("not a certificate line")
	}
	c, ok := k.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a certificate")
	}
	return c, nil
}

// Remove deletes domain's directory (logout).
func Remove(home, domain string) error {
	if !cliapi.ValidDomain(domain) {
		return errors.New("not a valid domain")
	}
	return os.RemoveAll(filepath.Join(home, Dir("", domain)))
}

func writeAtomic(p string, b []byte, mode os.FileMode) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Installed reports whether ~/.ssh/config already includes the line.
func Installed(home string) bool {
	raw, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(l) == cliapi.IncludeLine {
			return true
		}
	}
	return false
}

// Install adds the include line at the top of ~/.ssh/config after
// confirm says yes (never silently); a second run changes nothing.
func Install(home string, confirm func() bool) (bool, error) {
	if Installed(home) {
		return false, nil
	}
	if !confirm() {
		return false, nil
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return false, err
	}
	p := filepath.Join(sshDir, "config")
	raw, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(p); err == nil {
		mode = st.Mode().Perm()
	}
	out := cliapi.IncludeLine + "\n"
	if len(raw) > 0 {
		out += "\n" + string(raw)
	}
	return true, writeAtomic(p, []byte(out), mode)
}
