// Package host is portcullis-nodeagent, the fixed-function root host
// service on every cluster node (contract §20.3, §20.4, §20.11): the join,
// the mesh pcmesh (kernel WireGuard through wgctrl), the RTT echo, the host
// checks, the public ingress probes, the k3s token steps, the etcd member
// removal and the k3s uninstall. It is its own binary
// (cmd/portcullis-nodeagent): the Hub never imports it.
//
// Secrets: the node-cluster key and the pcmesh private key are generated
// here and never leave the node; they and the k3s tokens never reach a log
// line, an error, an answer, argv or the environment.
package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Cmd is one fixed program run: a name, its arguments (never a secret),
// extra environment (never a secret) and stdin.
type Cmd struct {
	Name  string
	Args  []string
	Env   []string
	Stdin []byte
	// Out receives the output when set (else it is returned, ≤ 64 KiB).
	Out io.Writer
}

// Runner runs programs without a shell.
type Runner interface {
	Run(ctx context.Context, c Cmd) ([]byte, error)
}

// ExecRunner is the real Runner: os/exec, a fixed PATH.
type ExecRunner struct{}

const fixedPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func (ExecRunner) Run(ctx context.Context, c Cmd) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = append([]string{fixedPath, "LC_ALL=C"}, c.Env...)
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	var buf limitedBuffer
	buf.max = 64 << 10
	if c.Out != nil {
		cmd.Stdout, cmd.Stderr = c.Out, c.Out
	} else {
		cmd.Stdout, cmd.Stderr = &buf, &buf
	}
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return buf.Bytes(), fmt.Errorf("%s exited %d", filepath.Base(c.Name), ee.ExitCode())
		}
		return buf.Bytes(), fmt.Errorf("%s: %v", filepath.Base(c.Name), errors.Unwrap(err))
	}
	return buf.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// fsys is the host's file system under a root (tests: a temp dir).
type fsys struct{ root string }

func (f fsys) p(path string) string {
	if f.root == "" {
		return path
	}
	return filepath.Join(f.root, path)
}

func (f fsys) read(path string) ([]byte, error) { return os.ReadFile(f.p(path)) }

func (f fsys) readTrim(path string) string {
	b, err := f.read(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (f fsys) exists(path string) bool {
	_, err := os.Stat(f.p(path))
	return err == nil
}

// write writes data atomically (a temp file in the same directory, then a
// rename) with mode, creating the parent directories with dirMode.
func (f fsys) write(path string, data []byte, mode, dirMode os.FileMode) error {
	full := f.p(path)
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), unwrapPath(err))
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(full)+".tmp*")
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, unwrapPath(err))
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(name)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", path, unwrapPath(err))
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", path, unwrapPath(err))
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", path, unwrapPath(err))
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", path, unwrapPath(err))
	}
	if err := os.Rename(name, full); err != nil {
		return fmt.Errorf("writing %s: %w", path, unwrapPath(err))
	}
	ok = true
	return nil
}

// writeInPlace writes an existing file in place (a sysctl under /proc).
func (f fsys) writeInPlace(path string, data []byte) error {
	fh, err := os.OpenFile(f.p(path), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, unwrapPath(err))
	}
	_, err = fh.Write(data)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, unwrapPath(err))
	}
	return nil
}

func (f fsys) remove(path string) error {
	err := os.Remove(f.p(path))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", path, unwrapPath(err))
	}
	return nil
}

func (f fsys) removeAll(path string) error {
	if err := os.RemoveAll(f.p(path)); err != nil {
		return fmt.Errorf("removing %s: %w", path, unwrapPath(err))
	}
	return nil
}

// unwrapPath drops the *PathError's path (the root prefix in tests; the
// caller names the host path).
func unwrapPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
