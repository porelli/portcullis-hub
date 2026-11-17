package host

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// The host files (contract §18.14).
const (
	PortcullisDir   = "/etc/ssh/portcullis"
	UserCAFile      = "/etc/ssh/portcullis/user_ca.pub"
	PrincipalsDir   = "/etc/ssh/portcullis/principals"
	RevokedKeysFile = "/etc/ssh/portcullis/revoked_keys"
	DropInFile      = "/etc/ssh/sshd_config.d/50-portcullis.conf"
	DropInDir       = "/etc/ssh/sshd_config.d"
	MainConfig      = "/etc/ssh/sshd_config"
	SudoersFile     = "/etc/sudoers.d/portcullis"
	CeilingFile     = "/etc/portcullis/host.json"
	StateFile       = "/etc/portcullis/state.json"
	HostKeyFile     = "/etc/ssh/ssh_host_ed25519_key.pub"
	HostCertFile    = "/etc/ssh/ssh_host_ed25519_key-cert.pub"
	ConfDir         = "/etc/portcullis"
	UsersGroup      = "portcullis-users"
	RemovedHomes    = "/home/.portcullis-removed"
)

// staged is one file of a Transaction: what it was before.
type staged struct {
	path    string
	had     bool
	before  []byte
	mode    fs.FileMode
	changed bool
	remove  bool
}

// Transaction writes files atomically one by one and puts every one back,
// byte for byte, if the commit's validation fails (plan C26, §18.14
// "Apply").
type Transaction struct {
	sys   System
	files []*staged
	done  bool
}

// NewTransaction starts a transaction.
func NewTransaction(sys System) *Transaction { return &Transaction{sys: sys} }

func (t *Transaction) remember(path string) (*staged, error) {
	for _, s := range t.files {
		if s.path == path {
			return s, nil
		}
	}
	s := &staged{path: path}
	b, err := t.sys.ReadFile(path)
	switch {
	case err == nil:
		s.had, s.before = true, b
		if st, err := t.sys.Stat(path); err == nil {
			s.mode = st.Mode().Perm()
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	t.files = append(t.files, s)
	return s, nil
}

// Stage writes b to path (mode) now, remembering what was there.
func (t *Transaction) Stage(path string, b []byte, mode fs.FileMode) error {
	s, err := t.remember(path)
	if err != nil {
		return err
	}
	if s.had && bytes.Equal(s.before, b) && s.mode == mode {
		return nil
	}
	if err := t.sys.WriteFileAtomic(path, b, mode); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	s.changed = true
	return nil
}

// StageRemove removes path now, remembering it.
func (t *Transaction) StageRemove(path string) error {
	s, err := t.remember(path)
	if err != nil {
		return err
	}
	if !s.had {
		return nil
	}
	if err := t.sys.Remove(path); err != nil {
		return err
	}
	s.changed, s.remove = true, true
	return nil
}

// Changed reports whether any staged file differs from before.
func (t *Transaction) Changed() bool {
	for _, s := range t.files {
		if s.changed {
			return true
		}
	}
	return false
}

// ChangedPaths are the changed files, sorted.
func (t *Transaction) ChangedPaths() []string {
	var out []string
	for _, s := range t.files {
		if s.changed {
			out = append(out, s.path)
		}
	}
	sort.Strings(out)
	return out
}

// Commit runs validate; on its error every file is put back.
func (t *Transaction) Commit(validate func() error) error {
	if validate != nil {
		if err := validate(); err != nil {
			if rerr := t.Rollback(); rerr != nil {
				return fmt.Errorf("%v; and putting the files back failed: %v", err, rerr)
			}
			return err
		}
	}
	t.done = true
	return nil
}

// Rollback restores every staged file (newest first).
func (t *Transaction) Rollback() error {
	if t.done {
		return nil
	}
	var errs []string
	for i := len(t.files) - 1; i >= 0; i-- {
		s := t.files[i]
		if !s.changed {
			continue
		}
		var err error
		if s.had {
			mode := s.mode
			if mode == 0 {
				mode = 0o644
			}
			err = t.sys.WriteFileAtomic(s.path, s.before, mode)
		} else {
			err = t.sys.Remove(s.path)
		}
		if err != nil {
			errs = append(errs, s.path+": "+err.Error())
		}
	}
	t.done = true
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// PrincipalsFile is an account's principals file.
func PrincipalsFile(account string) string { return PrincipalsDir + "/" + account }

// principalsBody is one principal per line.
func principalsBody(ps []string) []byte {
	if len(ps) == 0 {
		return nil
	}
	return []byte(strings.Join(ps, "\n") + "\n")
}
