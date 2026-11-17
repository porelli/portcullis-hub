// Package host is `portcullis host …` (contract §18.11, §18.14): the
// managed host's agent and the unmanaged host's static trust. It works
// through System (commands, a root-prefixed file system, account
// lookups) so it is tested without root (plan C26); the real thing runs
// as root and uses the system's own useradd, usermod, userdel, visudo
// and sshd -t / -T — it never edits /etc/passwd or the main sshd_config.
package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// System is everything the host code touches.
type System interface {
	// Run runs a command and answers its combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	ReadFile(path string) ([]byte, error)
	// WriteFileAtomic writes path (owned by root) through a temporary
	// file and a rename.
	WriteFileAtomic(path string, b []byte, mode fs.FileMode) error
	Remove(path string) error
	MkdirAll(path string, mode fs.FileMode) error
	Stat(path string) (fs.FileInfo, error)
	Glob(pattern string) ([]string, error)
	Rename(from, to string) error
	// LookPath finds a command ("" when absent).
	LookPath(name string) string
	GOOS() string
}

// OS is the real system; Root prefixes every path (tests: a directory).
type OS struct{ Root string }

func (s OS) p(path string) string { return filepath.Join(s.Root, path) }

// Run runs name with args (no shell); stdin is closed.
func (s OS) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.Bytes(), err
}

func (s OS) ReadFile(path string) ([]byte, error) { return os.ReadFile(s.p(path)) }

func (s OS) WriteFileAtomic(path string, b []byte, mode fs.FileMode) error {
	p := s.p(path)
	tmp := p + ".portcullis-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, p)
}

func (s OS) Remove(path string) error {
	err := os.Remove(s.p(path))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (s OS) MkdirAll(path string, mode fs.FileMode) error {
	if err := os.MkdirAll(s.p(path), mode); err != nil {
		return err
	}
	return os.Chmod(s.p(path), mode)
}

func (s OS) Stat(path string) (fs.FileInfo, error) { return os.Stat(s.p(path)) }

func (s OS) Glob(pattern string) ([]string, error) {
	m, err := filepath.Glob(s.p(pattern))
	for i := range m {
		m[i] = strings.TrimPrefix(m[i], s.Root)
	}
	return m, err
}

func (s OS) Rename(from, to string) error { return os.Rename(s.p(from), s.p(to)) }

func (s OS) LookPath(name string) string {
	for _, d := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"} {
		p := filepath.Join(d, name)
		if st, err := os.Stat(s.p(p)); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func (s OS) GOOS() string { return goos }

// exists reports a path's presence.
func exists(sys System, p string) bool {
	_, err := sys.Stat(p)
	return err == nil
}

// Passwd is one /etc/passwd line (read only: accounts are changed with
// useradd / usermod / userdel).
type Passwd struct {
	Name, Comment, Home, Shell string
	UID, GID                   int
}

// Users reads /etc/passwd.
func Users(sys System) (map[string]Passwd, error) {
	raw, err := sys.ReadFile("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("reading /etc/passwd: %w", err)
	}
	out := map[string]Passwd{}
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out[f[0]] = Passwd{Name: f[0], UID: uid, GID: gid, Comment: f[4], Home: f[5], Shell: f[6]}
	}
	return out, nil
}

// GroupMembers reads /etc/group: group → its listed members.
func GroupMembers(sys System) (map[string][]string, error) {
	raw, err := sys.ReadFile("/etc/group")
	if err != nil {
		return nil, fmt.Errorf("reading /etc/group: %w", err)
	}
	out := map[string][]string{}
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 4 || strings.HasPrefix(l, "#") {
			continue
		}
		var m []string
		for _, x := range strings.Split(f[3], ",") {
			if x = strings.TrimSpace(x); x != "" {
				m = append(m, x)
			}
		}
		out[f[0]] = m
	}
	return out, nil
}
