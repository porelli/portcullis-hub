package host

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSys is an in-memory host: files, modes, a command log and
// command handlers; sshd's answers are computed from the files.
type fakeSys struct {
	mu      sync.Mutex
	files   map[string][]byte
	modes   map[string]fs.FileMode
	dirs    map[string]bool
	writes  []string
	runs    []string
	handler map[string]func(args []string) ([]byte, error)
	version string
	goos    string
	sshdT   error
	reloads int
	// owners: path → uid / mode for Owner (default root, 0755).
	owners map[string]ownerOf
	links  map[string]string
}

type ownerOf struct {
	uid  int
	mode fs.FileMode
}

func (f *fakeSys) EvalSymlinks(p string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.links[p]; ok {
		return t, nil
	}
	return p, nil
}

func (f *fakeSys) Owner(p string) (int, fs.FileMode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.owners[p]; ok {
		return o.uid, o.mode, nil
	}
	return 0, 0o755, nil
}

func newFakeSys(t *testing.T) *fakeSys {
	t.Helper()
	notef = func(string, ...any) {}
	signalHUP = func(sys System, pid int) error {
		if fs, ok := sys.(*fakeSys); ok && pid > 1 {
			fs.mu.Lock()
			fs.reloads++
			fs.mu.Unlock()
			return nil
		}
		return errors.New("no")
	}
	f := &fakeSys{files: map[string][]byte{}, modes: map[string]fs.FileMode{}, dirs: map[string]bool{}, handler: map[string]func([]string) ([]byte, error){},
		owners: map[string]ownerOf{}, links: map[string]string{},
		version: "OpenSSH_9.6p1 Ubuntu", goos: "linux"}
	f.files[MainConfig] = []byte("Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\nSubsystem sftp /usr/lib/openssh/sftp-server\n")
	f.files["/etc/passwd"] = []byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbreakglass:x:1001:1001::/home/breakglass:/bin/bash\nops:x:1002:1002::/home/ops:/bin/bash\n")
	f.files["/etc/group"] = []byte("root:x:0:\nbreakglass:x:1001:\nops:x:1002:\n")
	f.files["/home/breakglass/.ssh/authorized_keys"] = []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXf2yZXNFwHqiadxQBruvDLwOZYX4l4+MUIDqyknOMZ safe key\n")
	f.files["/bin/bash"] = []byte("#!")
	f.files["/usr/sbin/sshd"] = []byte("bin")
	f.files["/usr/bin/systemctl"] = []byte("bin")
	f.files["/run/sshd.pid"] = []byte("4242\n")
	return f
}

func (f *fakeSys) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.runs = append(f.runs, strings.TrimSpace(path.Base(name)+" "+strings.Join(args, " ")))
	h := f.handler[path.Base(name)]
	f.mu.Unlock()
	if h != nil {
		return h(args)
	}
	switch path.Base(name) {
	case "sshd":
		switch {
		case len(args) > 0 && args[0] == "-V":
			return []byte(f.version), nil
		case len(args) > 0 && args[0] == "-t":
			if f.sshdT != nil {
				return []byte("line 3: bad option"), f.sshdT
			}
			return nil, nil
		case len(args) > 1 && args[0] == "-T":
			return f.effective(args[2]), nil
		}
	case "ssh":
		return []byte(f.version), nil
	case "systemctl":
		if len(args) > 0 && args[0] == "reload" {
			f.mu.Lock()
			f.reloads++
			f.mu.Unlock()
		}
		if len(args) > 0 && args[0] == "cat" {
			return []byte("[Unit]"), nil
		}
		return nil, nil
	case "useradd":
		return nil, f.useradd(args)
	case "usermod":
		return nil, f.usermod(args)
	case "userdel":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.files["/etc/passwd"] = []byte(dropLine(string(f.files["/etc/passwd"]), args[len(args)-1]))
		return nil, nil
	case "groupadd":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.files["/etc/group"] = append(f.files["/etc/group"], []byte(args[len(args)-1]+":x:999:\n")...)
		return nil, nil
	case "visudo", "loginctl", "pkill", "launchctl":
		return nil, nil
	}
	return nil, fmt.Errorf("fake: %s not handled", name)
}

// effective is sshd -T: the first value of each keyword in the main
// config, then the drop-ins in order; the drop-in's Match Group
// portcullis-users block for users in that group.
func (f *fakeSys) effective(spec string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	user := strings.TrimPrefix(strings.SplitN(spec, ",", 2)[0], "user=")
	members := map[string]bool{}
	for _, l := range strings.Split(string(f.files["/etc/group"]), "\n") {
		p := strings.Split(l, ":")
		if len(p) >= 4 && p[0] == UsersGroup {
			for _, m := range strings.Split(p[3], ",") {
				members[m] = true
			}
		}
	}
	vals := map[string]string{}
	set := func(k, v string) {
		k = strings.ToLower(k)
		if _, ok := vals[k]; !ok {
			vals[k] = v
		}
	}
	var lines []string
	for _, l := range strings.Split(string(f.files[MainConfig]), "\n") {
		if strings.HasPrefix(strings.ToLower(l), "include ") {
			var names []string
			for p := range f.files {
				if strings.HasPrefix(p, DropInDir+"/") && strings.HasSuffix(p, ".conf") {
					names = append(names, p)
				}
			}
			sort.Strings(names)
			for _, n := range names {
				lines = append(lines, strings.Split(string(f.files[n]), "\n")...)
				lines = append(lines, "Match all")
			}
			continue
		}
		lines = append(lines, l)
	}
	in := true
	for _, l := range lines {
		fl := strings.Fields(l)
		if len(fl) < 2 || strings.HasPrefix(fl[0], "#") {
			continue
		}
		if strings.EqualFold(fl[0], "Match") {
			in = fl[1] == "all" || (fl[1] == "Group" && members[user])
			continue
		}
		if in {
			set(fl[0], strings.Join(fl[1:], " "))
		}
	}
	for k, v := range map[string]string{"authorizedkeysfile": ".ssh/authorized_keys", "passwordauthentication": "yes", "kbdinteractiveauthentication": "no",
		"pubkeyauthentication": "yes", "trustedusercakeys": "none", "authorizedprincipalsfile": "none", "revokedkeys": "none"} {
		set(k, v)
	}
	var b strings.Builder
	for k, v := range vals {
		b.WriteString(k + " " + v + "\n")
	}
	return []byte(b.String())
}

func (f *fakeSys) ReadFile(p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (f *fakeSys) WriteFileAtomic(p string, b []byte, mode fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[p] = append([]byte(nil), b...)
	f.modes[p] = mode
	f.writes = append(f.writes, p)
	return nil
}

func (f *fakeSys) Remove(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.files, p)
	f.writes = append(f.writes, "rm "+p)
	return nil
}

func (f *fakeSys) MkdirAll(p string, mode fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirs[p] = true
	f.modes[p] = mode | fs.ModeDir
	return nil
}

type fakeInfo struct {
	name string
	mode fs.FileMode
	size int64
}

func (i fakeInfo) Name() string       { return i.name }
func (i fakeInfo) Size() int64        { return i.size }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInfo) Sys() any           { return nil }

func (f *fakeSys) Stat(p string) (fs.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.files[p]; ok {
		m := f.modes[p]
		if m == 0 {
			m = 0o644
		}
		return fakeInfo{path.Base(p), m, int64(len(b))}, nil
	}
	if f.dirs[p] {
		return fakeInfo{path.Base(p), f.modes[p], 0}, nil
	}
	return nil, fs.ErrNotExist
}

func (f *fakeSys) Glob(pattern string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for p := range f.files {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeSys) Rename(from, to string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.files[from]; ok {
		f.files[to] = b
		delete(f.files, from)
		return nil
	}
	if f.dirs[from] {
		f.dirs[to] = true
		delete(f.dirs, from)
		return nil
	}
	return errors.New("no such file")
}

func (f *fakeSys) LookPath(name string) string {
	for _, d := range []string{"/usr/sbin/", "/usr/bin/", "/bin/"} {
		if _, ok := f.files[d+name]; ok {
			return d + name
		}
	}
	return ""
}

func (f *fakeSys) GOOS() string { return f.goos }

func (f *fakeSys) ran(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.runs {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

func (f *fakeSys) snapshot() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for k, v := range f.files {
		out[k] = string(v)
	}
	return out
}

func dropLine(passwd, name string) string {
	var out []string
	for _, l := range strings.Split(passwd, "\n") {
		if l != "" && !strings.HasPrefix(l, name+":") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n") + "\n"
}

// useradd: [-u uid] [-U] [-G group] [-m] [-s shell] [-c comment] name.
func (f *fakeSys) useradd(args []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	uid, shell, comment, group := "3000", "/bin/sh", "", ""
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "-u":
			uid = args[i+1]
		case "-s":
			shell = args[i+1]
		case "-c":
			comment = args[i+1]
		case "-G":
			group = args[i+1]
		}
	}
	name := args[len(args)-1]
	if strings.Contains(comment, ":") {
		return errors.New("useradd: invalid comment")
	}
	if strings.Contains(string(f.files["/etc/passwd"]), "\n"+name+":") || strings.HasPrefix(string(f.files["/etc/passwd"]), name+":") {
		return errors.New("useradd: user exists")
	}
	f.files["/etc/passwd"] = append(f.files["/etc/passwd"], []byte(name+":x:"+uid+":"+uid+":"+comment+":/home/"+name+":"+shell+"\n")...)
	f.dirs["/home/"+name] = true
	if group != "" {
		var out []string
		for _, l := range strings.Split(string(f.files["/etc/group"]), "\n") {
			if strings.HasPrefix(l, group+":") {
				if strings.HasSuffix(l, ":") {
					l += name
				} else {
					l += "," + name
				}
			}
			if l != "" {
				out = append(out, l)
			}
		}
		f.files["/etc/group"] = []byte(strings.Join(out, "\n") + "\n")
	}
	return nil
}

// usermod: -s shell sets the shell (the lock and unlock).
func (f *fakeSys) usermod(args []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := args[len(args)-1]
	shell := ""
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-s" {
			shell = args[i+1]
		}
	}
	var out []string
	for _, l := range strings.Split(string(f.files["/etc/passwd"]), "\n") {
		if strings.HasPrefix(l, name+":") && shell != "" {
			p := strings.Split(l, ":")
			p[6] = shell
			l = strings.Join(p, ":")
		}
		if l != "" {
			out = append(out, l)
		}
	}
	f.files["/etc/passwd"] = []byte(strings.Join(out, "\n") + "\n")
	return nil
}
