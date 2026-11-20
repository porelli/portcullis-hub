package fsutil

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sync/atomic"
	"time"
)

// The write gate (contract §20.5): every file write of the Hub goes
// through this package, and each writer asks the gate first. On
// Kubernetes the gate is the Lease fence's Check (internal/leader): a Hub
// that isn't the active writer writes nothing. Unset (Docker, Podman,
// tests, the helper subcommands) the gate is open: every writer behaves
// exactly as the os function it wraps.
var writeGate atomic.Pointer[func() error]

// SetWriteGate installs g as the gate every writer asks first (nil: the
// gate is open again).
func SetWriteGate(g func() error) {
	if g == nil {
		writeGate.Store(nil)
		return
	}
	writeGate.Store(&g)
}

// gateLost, when set, closes the moment the gate stands by for good (the
// fence's Lost): WriteContext cancels on it.
var gateLost atomic.Pointer[<-chan struct{}]

// SetWriteGateLost installs the channel that closes when the gate closes
// for good (nil: none).
func SetWriteGateLost(ch <-chan struct{}) {
	if ch == nil {
		gateLost.Store(nil)
		return
	}
	gateLost.Store(&ch)
}

// WriteContext is a context for a long writer outside this package (an
// exec'd git): cancelled when parent ends or the moment the gate stands
// by for good — already cancelled when the gate is closed now. The
// caller calls cancel when done.
func WriteContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	if CheckWrite() != nil {
		cancel()
		return ctx, cancel
	}
	if p := gateLost.Load(); p != nil {
		lost := *p
		go func() {
			select {
			case <-lost:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	return ctx, cancel
}

// CheckRequest is the gate for an outbound request to another service
// (Keycloak, LLDAP, domains, enroll, the mail provider, a worker agent):
// GET, HEAD and OPTIONS read; any other method asks the gate.
func CheckRequest(method string) error {
	if readMethod(method) {
		return nil
	}
	return CheckWrite()
}

// readMethod: GET, HEAD and OPTIONS change nothing.
func readMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// GateTransport wraps rt so that every request but GET, HEAD and OPTIONS
// asks the gate first and runs on WriteContext: the moment the Hub stands
// by, a write still in flight is cancelled (the connection closed) and
// the caller gets the gate's error. The response body holds the context
// until it is closed. (What the server already applied stays applied:
// contract §20.5.)
func GateTransport(rt http.RoundTripper) http.RoundTripper { return GateTransportExcept(rt, nil) }

// GateTransportExcept is GateTransport with reads also passing (a POST
// that only signs in, say).
func GateTransportExcept(rt http.RoundTripper, reads func(*http.Request) bool) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return gatedRT{next: rt, reads: reads}
}

type gatedRT struct {
	next  http.RoundTripper
	reads func(*http.Request) bool
}

func (g gatedRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if readMethod(r.Method) || g.reads != nil && g.reads(r) {
		return g.next.RoundTrip(r)
	}
	if err := CheckWrite(); err != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	ctx, cancel := WriteContext(r.Context())
	resp, err := g.next.RoundTrip(r.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, standByOr(ctx, err)
	}
	resp.Body = &fencedBody{rc: resp.Body, ctx: ctx, cancel: cancel}
	return resp, nil
}

// standByOr is the gate's error when ctx was cancelled by a stand-by,
// else err.
func standByOr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		if gerr := CheckWrite(); gerr != nil {
			return gerr
		}
	}
	return err
}

// fencedBody is a gated write's response body: closing it ends its
// WriteContext; a read cut by a stand-by answers the gate's error.
type fencedBody struct {
	rc     io.ReadCloser
	ctx    context.Context
	cancel context.CancelFunc
}

func (b *fencedBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if err != nil && err != io.EOF {
		err = standByOr(b.ctx, err)
	}
	return n, err
}

func (b *fencedBody) Close() error {
	err := b.rc.Close()
	b.cancel()
	return err
}

// Do is c.Do(req) through GateTransport (c's own transport underneath):
// each outbound client's one call for requests to another service.
func Do(c *http.Client, req *http.Request) (*http.Response, error) {
	if c == nil {
		c = http.DefaultClient
	}
	gc := *c
	gc.Transport = GateTransport(c.Transport)
	resp, err := gc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			if gerr := CheckWrite(); gerr != nil && errors.Is(ue.Err, gerr) {
				return nil, gerr
			}
		}
	}
	return resp, err
}

// CheckWrite is the gate's answer: nil when a write may happen now, else
// the reason (the fence's ErrStandingBy). Writers that aren't files (a
// git checkout, a cluster apply) ask it too.
func CheckWrite() error {
	if g := writeGate.Load(); g != nil {
		return (*g)()
	}
	return nil
}

// writeFlags are the open flags that make an open a write.
const writeFlags = os.O_WRONLY | os.O_RDWR | os.O_CREATE | os.O_APPEND | os.O_TRUNC

// WriteFile is os.WriteFile behind the gate (in place, not atomic: for
// files whose inode must stay, or scratch files).
func WriteFile(name string, data []byte, perm os.FileMode) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.WriteFile(name, data, perm)
}

// AppendFile appends data to name (created with perm when missing) in one
// write, behind the gate.
func AppendFile(name string, data []byte, perm os.FileMode) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// OpenFile is os.OpenFile; an open with a write flag asks the gate first,
// and every write through the returned File asks it again.
func OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	if flag&writeFlags != 0 {
		if err := CheckWrite(); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &File{f: f}, nil
}

// Create is os.Create behind the gate.
func Create(name string) (*File, error) {
	return OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

// CreateTemp is os.CreateTemp behind the gate.
func CreateTemp(dir, pattern string) (*File, error) {
	if err := CheckWrite(); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return &File{f: f}, nil
}

// MkdirTemp is os.MkdirTemp behind the gate.
func MkdirTemp(dir, pattern string) (string, error) {
	if err := CheckWrite(); err != nil {
		return "", err
	}
	return os.MkdirTemp(dir, pattern)
}

// Mkdir is os.Mkdir behind the gate.
func Mkdir(name string, perm os.FileMode) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.Mkdir(name, perm)
}

// MkdirAll is os.MkdirAll behind the gate.
func MkdirAll(name string, perm os.FileMode) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.MkdirAll(name, perm)
}

// Remove is os.Remove behind the gate.
func Remove(name string) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.Remove(name)
}

// RemoveAll is os.RemoveAll with the gate asked before every unlink and
// rmdir: a large tree stops at the entry where the Hub stands by. The
// walk runs inside an os.Root opened on name's parent, each directory
// through its own root (checked to be the directory that was stat'ed):
// a directory swapped for a symlink mid-walk is never followed. A missing
// name is nil.
func RemoveAll(name string) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	if name == "" {
		return nil
	}
	base := filepath.Base(name)
	if base == "." || base == ".." || base == string(filepath.Separator) {
		return &fs.PathError{Op: "RemoveAll", Path: name, Err: errors.New("invalid argument")}
	}
	parent, err := os.OpenRoot(filepath.Dir(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	return removeIn(parent, base)
}

// removeIn removes name inside r and, for a directory, everything below
// it, asking the gate before each removal. The gate's error stops it at
// once; other errors are collected (the first returned) and the walk goes
// on.
func removeIn(r *os.Root, name string) error {
	fi, err := r.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var first error
	if fi.IsDir() {
		first = removeChildren(r, name, fi)
		if gerr := CheckWrite(); gerr != nil {
			return gerr
		}
	}
	if err := CheckWrite(); err != nil {
		return err
	}
	if err := r.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) && first == nil {
		first = err
	}
	return first
}

// removeChildren empties directory name of r (fi: its Lstat) through a
// root of its own, refused when what opened isn't that directory.
func removeChildren(r *os.Root, name string, fi fs.FileInfo) error {
	sub, err := r.OpenRoot(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer sub.Close()
	if st, err := sub.Stat("."); err != nil {
		return err
	} else if !os.SameFile(fi, st) {
		return &fs.PathError{Op: "RemoveAll", Path: name, Err: errors.New("changed during the removal")}
	}
	entries, err := fs.ReadDir(sub.FS(), ".")
	var first error
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		first = err
	}
	for _, e := range entries {
		if err := removeIn(sub, e.Name()); err != nil {
			if gerr := CheckWrite(); gerr != nil {
				return gerr
			}
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// Rename is os.Rename behind the gate.
func Rename(oldpath, newpath string) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.Rename(oldpath, newpath)
}

// Symlink is os.Symlink behind the gate.
func Symlink(oldname, newname string) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.Symlink(oldname, newname)
}

// Chmod is os.Chmod behind the gate.
func Chmod(name string, mode os.FileMode) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.Chmod(name, mode)
}

// Chown is os.Chown behind the gate.
func Chown(name string, uid, gid int) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.Chown(name, uid, gid)
}

// Lchown is os.Lchown behind the gate.
func Lchown(name string, uid, gid int) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.Lchown(name, uid, gid)
}

// Chtimes is os.Chtimes behind the gate.
func Chtimes(name string, atime, mtime time.Time) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.Chtimes(name, atime, mtime)
}

// File is an open file whose every write, change of mode, owner or size
// asks the gate first: a write that started while the Hub led stops at
// the next call once it stands by. Reads pass through.
type File struct{ f *os.File }

func (f *File) Write(p []byte) (int, error) {
	if err := CheckWrite(); err != nil {
		return 0, err
	}
	return f.f.Write(p)
}

func (f *File) WriteString(s string) (int, error) {
	if err := CheckWrite(); err != nil {
		return 0, err
	}
	return f.f.WriteString(s)
}

func (f *File) WriteAt(p []byte, off int64) (int, error) {
	if err := CheckWrite(); err != nil {
		return 0, err
	}
	return f.f.WriteAt(p, off)
}

func (f *File) Chmod(mode os.FileMode) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return f.f.Chmod(mode)
}

func (f *File) Chown(uid, gid int) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return f.f.Chown(uid, gid)
}

func (f *File) Truncate(size int64) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return f.f.Truncate(size)
}

// Sync flushes what was already written (it adds nothing new: not gated).
func (f *File) Sync() error                                  { return f.f.Sync() }
func (f *File) Read(p []byte) (int, error)                   { return f.f.Read(p) }
func (f *File) ReadAt(p []byte, off int64) (int, error)      { return f.f.ReadAt(p, off) }
func (f *File) Seek(offset int64, whence int) (int64, error) { return f.f.Seek(offset, whence) }
func (f *File) Stat() (fs.FileInfo, error)                   { return f.f.Stat() }
func (f *File) Name() string                                 { return f.f.Name() }
func (f *File) Close() error                                 { return f.f.Close() }

// Root is os.Root with every write behind the gate (the same
// containment: nothing escapes the directory).
type Root struct{ r *os.Root }

// OpenRoot is os.OpenRoot (opening reads nothing new: not gated).
func OpenRoot(name string) (*Root, error) {
	r, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &Root{r: r}, nil
}

func (r *Root) Close() error                           { return r.r.Close() }
func (r *Root) Name() string                           { return r.r.Name() }
func (r *Root) FS() fs.FS                              { return r.r.FS() }
func (r *Root) Open(name string) (*os.File, error)     { return r.r.Open(name) }
func (r *Root) Stat(name string) (fs.FileInfo, error)  { return r.r.Stat(name) }
func (r *Root) Lstat(name string) (fs.FileInfo, error) { return r.r.Lstat(name) }
func (r *Root) ReadFile(name string) ([]byte, error)   { return r.r.ReadFile(name) }
func (r *Root) Readlink(name string) (string, error)   { return r.r.Readlink(name) }

// OpenFile is os.Root.OpenFile; an open with a write flag asks the gate
// first, and every write through the returned File asks it again.
func (r *Root) OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	if flag&writeFlags != 0 {
		if err := CheckWrite(); err != nil {
			return nil, err
		}
	}
	f, err := r.r.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &File{f: f}, nil
}

// Create is os.Root.Create behind the gate.
func (r *Root) Create(name string) (*File, error) {
	return r.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

// WriteFile is os.Root.WriteFile behind the gate.
func (r *Root) WriteFile(name string, data []byte, perm os.FileMode) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return r.r.WriteFile(name, data, perm)
}

// Mkdir is os.Root.Mkdir behind the gate.
func (r *Root) Mkdir(name string, perm os.FileMode) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return r.r.Mkdir(name, perm)
}

// MkdirAll is os.Root.MkdirAll behind the gate.
func (r *Root) MkdirAll(name string, perm os.FileMode) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return r.r.MkdirAll(name, perm)
}

// Remove is os.Root.Remove behind the gate.
func (r *Root) Remove(name string) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return r.r.Remove(name)
}

// RemoveAll is os.Root.RemoveAll with the gate asked before every
// unlink and rmdir (RemoveAll's walk, inside the root).
func (r *Root) RemoveAll(name string) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	name = path.Clean(filepath.ToSlash(name))
	if name == "." || name == ".." {
		return &fs.PathError{Op: "RemoveAll", Path: name, Err: errors.New("invalid argument")}
	}
	return removeIn(r.r, name)
}

// Rename is os.Root.Rename behind the gate.
func (r *Root) Rename(oldname, newname string) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return r.r.Rename(oldname, newname)
}

// Symlink is os.Root.Symlink behind the gate.
func (r *Root) Symlink(oldname, newname string) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return r.r.Symlink(oldname, newname)
}

// Chmod is os.Root.Chmod behind the gate.
func (r *Root) Chmod(name string, mode os.FileMode) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return r.r.Chmod(name, mode)
}

// Chown is os.Root.Chown behind the gate.
func (r *Root) Chown(name string, uid, gid int) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	return r.r.Chown(name, uid, gid)
}
