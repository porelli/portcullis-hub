package fsutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The packages of the Hub binary that may write files without this
// package's gate, each with the reason. Nothing else may.
var writeAllowlist = map[string]string{
	"github.com/portcullis/hub/internal/folderfix": "runs only as `hub folderfix …` in a helper container, its own process: main dispatches it before the gate exists (cmd/hub/main.go)",
	"github.com/portcullis/hub/internal/volcopy":   "runs only as the `hub volcopy|seed|rev …` helper subcommands, their own process: main dispatches them before the gate exists (cmd/hub/helper.go)",
}

// bannedFuncs are the package-level functions that write to the file
// system, by package. Each has an fsutil twin behind the gate.
var bannedFuncs = map[string]map[string]bool{
	"os": set("WriteFile", "Create", "CreateTemp", "MkdirTemp", "OpenFile", "OpenRoot", "NewFile",
		"Rename", "Remove", "RemoveAll", "Mkdir", "MkdirAll", "Symlink", "Link", "Chmod", "Chown", "Lchown",
		"Truncate", "Chtimes", "CopyFS"),
	"io/ioutil": set("WriteFile", "TempFile", "TempDir"),
	"syscall": set("Open", "Openat", "Creat", "Mkdir", "Mkdirat", "Rename", "Renameat", "Unlink", "Unlinkat",
		"Rmdir", "Symlink", "Link", "Chmod", "Fchmod", "Fchmodat", "Chown", "Fchown", "Fchownat", "Lchown",
		"Truncate", "Ftruncate", "Write", "Pwrite", "Utimes", "UtimesNano"),
	"golang.org/x/sys/unix": set("Open", "Openat", "Openat2", "Creat", "Mkdir", "Mkdirat", "Rename", "Renameat",
		"Renameat2", "Unlink", "Unlinkat", "Rmdir", "Symlink", "Symlinkat", "Link", "Linkat", "Chmod", "Fchmod",
		"Fchmodat", "Chown", "Fchown", "Fchownat", "Lchown", "Truncate", "Ftruncate", "Write", "Pwrite",
		"Utimes", "UtimesNano", "UtimesNanoAt"),
}

// bannedMethods are the writing methods of *os.File and *os.Root. A
// write-capable *os.File only comes from a banned opener, so writes
// through io.Writer interfaces are covered by banning those; these
// catch a mode, owner or size change through a read-only handle.
var bannedMethods = map[string]map[string]bool{
	"File": set("Write", "WriteString", "WriteAt", "ReadFrom", "Chmod", "Chown", "Truncate"),
	"Root": set("OpenFile", "Create", "WriteFile", "Mkdir", "MkdirAll", "Remove", "RemoveAll", "Rename",
		"Symlink", "Link", "Chmod", "Chown", "Lchown", "Chtimes", "OpenRoot"),
}

// External writers: a process the Hub runs, a unix socket it serves or
// dials (the container engine, the host control socket). Each site is
// listed with why its writes are fenced; a new one fails the test until
// it is gated and listed. Keyed "<file>:<function>".
var externalWriters = map[string]string{
	"internal/compose/compose.go:CLI.run":               "docker/podman compose: Docker and Podman only, where the Hub always leads (no Lease)",
	"internal/compose/compose.go:CLI.Config":            "docker/podman compose config: reads the project (Docker and Podman only)",
	"internal/compose/compose.go:CLI.Version":           "docker/podman compose version: reads (Docker and Podman only)",
	"internal/hub/sources.go:runGit":                    "git: every command but rev-parse asks the gate and runs on fsutil.WriteContext (killed with its process group at stand-by)",
	"internal/httpapi/hostctl.go:ListenHost":            "the host control socket: created at start (before any request); its handler is behind LeaderGate",
	"internal/docker/client.go:New":                     "the engine socket: every request goes through fsutil.GateTransport (Docker and Podman only)",
	"internal/hub/mail_mtasts.go:Hub.fetchMTASTSPolicy": "an HTTPS GET of the MTA-STS policy through Traefik (the network is http.Transport's, tcp): a read",
	"cmd/hub/ssh.go:sshMain":                            "`hub ssh status`, its own process: a client of the host control socket, whose handler is behind LeaderGate",
	"cmd/hub/vpn.go:vpnMain":                            "`hub vpn …`, its own process: a client of the host control socket (LeaderGate)",
	"cmd/hub/vpn.go:mailMain":                           "`hub mail …`, its own process: a client of the host control socket (LeaderGate)",
	"cmd/hub/servers.go:serversMain":                    "`hub servers …`, its own process: a client of the host control socket (LeaderGate)",
}

// externalFuncs are the os/exec and net functions that start a writer
// outside the Hub process or serve/dial a unix socket. net's are flagged
// only for a unix network (a constant "unix…" or a non-constant one).
var externalFuncs = map[string]map[string]bool{
	"os/exec":               set("Command", "CommandContext"),
	"os":                    set("StartProcess"),
	"syscall":               set("ForkExec", "Exec", "StartProcess"),
	"golang.org/x/sys/unix": set("Exec"),
	"net":                   set("Listen", "ListenPacket", "Dial", "DialTimeout", "ListenUnix", "ListenUnixgram", "DialUnix"),
}

// netAlwaysUnix are the net functions that are unix sockets whatever
// their arguments.
var netAlwaysUnix = set("ListenUnix", "ListenUnixgram", "DialUnix")

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

type listedPackage struct {
	ImportPath string
	Dir        string
	Export     string
	GoFiles    []string
	CgoFiles   []string
	Standard   bool
}

// TestNoFileWritesOutsideFsutil: every package linked into the Hub binary
// (go list -deps ./cmd/hub, the module's own) is type-checked, and no
// call or reference may reach a file-system writer of os, io/ioutil,
// syscall or x/sys/unix, nor a writing method of *os.File or *os.Root —
// only this package, behind the gate. Writes to os.Stdout and os.Stderr
// are allowed (they aren't the data).
func TestNoFileWritesOutsideFsutil(t *testing.T) {
	if testing.Short() {
		t.Skip("type-checks the Hub binary's packages")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "list", "-deps", "-export", "-json=ImportPath,Dir,Export,GoFiles,CgoFiles,Standard", "./cmd/hub")
	cmd.Dir = root
	// The Hub runs on Linux: its files (fs_linux.go, …), wherever the
	// test runs.
	cmd.Env = append(os.Environ(), "GOOS=linux", "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	exports := map[string]string{}
	var ours []listedPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		exports[p.ImportPath] = p.Export
		if !p.Standard && strings.HasPrefix(p.ImportPath, "github.com/portcullis/hub/") {
			ours = append(ours, p)
		}
	}
	seen := map[string]bool{}
	for _, p := range ours {
		seen[p.ImportPath] = true
	}
	for _, must := range []string{"github.com/portcullis/hub/cmd/hub", "github.com/portcullis/hub/internal/hub",
		"github.com/portcullis/hub/internal/state", "github.com/portcullis/hub/internal/directory"} {
		if !seen[must] {
			t.Fatalf("%s isn't among the Hub binary's packages: the scan is broken", must)
		}
	}
	for p := range writeAllowlist {
		if !seen[p] {
			t.Errorf("allowlisted %s isn't in the Hub binary any more: drop it from writeAllowlist", p)
		}
	}

	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		e := exports[path]
		if e == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(e)
	})
	var found []string
	used := map[string]bool{}
	for _, p := range ours {
		if p.ImportPath == "github.com/portcullis/hub/internal/fsutil" || writeAllowlist[p.ImportPath] != "" {
			continue
		}
		if len(p.CgoFiles) > 0 {
			t.Errorf("%s has cgo files: the scan doesn't cover them", p.ImportPath)
		}
		var files []*ast.File
		for _, name := range p.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
		conf := types.Config{Importer: imp}
		if _, err := conf.Check(p.ImportPath, fset, files, info); err != nil {
			t.Fatalf("type-checking %s: %v", p.ImportPath, err)
		}
		for _, f := range files {
			found = append(found, scanWrites(fset, root, f, info)...)
			found = append(found, scanExternal(fset, root, f, info, used)...)
		}
	}
	for site := range externalWriters {
		if !used[site] {
			t.Errorf("listed external writer %s isn't there any more: drop it from externalWriters", site)
		}
	}
	sort.Strings(found)
	for _, f := range found {
		t.Error(f)
	}
	if len(found) > 0 {
		t.Logf("%d file writes outside fsutil: use the fsutil wrapper (behind the write gate, contract §20.5)", len(found))
	}
}

// scanWrites returns the banned references in f.
func scanWrites(fset *token.FileSet, root string, f *ast.File, info *types.Info) []string {
	var out []string
	calls := map[*ast.SelectorExpr]*ast.CallExpr{}
	ast.Inspect(f, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if sel, ok := ast.Unparen(c.Fun).(*ast.SelectorExpr); ok {
				calls[sel] = c
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		fn, ok := info.Uses[sel.Sel].(*types.Func)
		if !ok || fn.Pkg() == nil {
			return true
		}
		where := func(what string) {
			pos := fset.Position(sel.Pos())
			rel, _ := filepath.Rel(root, pos.Filename)
			out = append(out, fmt.Sprintf("%s:%d: %s", rel, pos.Line, what))
		}
		sig := fn.Type().(*types.Signature)
		pkg := fn.Pkg().Path()
		if sig.Recv() == nil {
			if !bannedFuncs[pkg][fn.Name()] {
				return true
			}
			if pkg == "os" && fn.Name() == "OpenFile" && readOnlyFlag(info, calls[sel], 1) {
				return true
			}
			where(pkg + "." + fn.Name())
			return true
		}
		if pkg != "os" {
			return true
		}
		recv := sig.Recv().Type()
		if p, ok := recv.(*types.Pointer); ok {
			recv = p.Elem()
		}
		named, ok := recv.(*types.Named)
		if !ok || !bannedMethods[named.Obj().Name()][fn.Name()] {
			return true
		}
		if named.Obj().Name() == "File" && isStdStream(info, sel.X) {
			return true
		}
		where(fmt.Sprintf("(*os.%s).%s", named.Obj().Name(), fn.Name()))
		return true
	})
	return out
}

// readOnlyFlag: call's argument i is a constant open flag without a
// write bit (O_RDONLY with O_NOFOLLOW, O_NONBLOCK, …).
func readOnlyFlag(info *types.Info, call *ast.CallExpr, i int) bool {
	if call == nil || len(call.Args) <= i {
		return false
	}
	tv, ok := info.Types[call.Args[i]]
	if !ok || tv.Value == nil {
		return false
	}
	v, ok := constant.Int64Val(constant.ToInt(tv.Value))
	return ok && int(v)&writeFlags == 0
}

// isStdStream: x is os.Stdout or os.Stderr.
func isStdStream(info *types.Info, x ast.Expr) bool {
	sel, ok := ast.Unparen(x).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	v, ok := info.Uses[sel.Sel].(*types.Var)
	return ok && v.Pkg() != nil && v.Pkg().Path() == "os" && (v.Name() == "Stdout" || v.Name() == "Stderr")
}

// scanExternal returns the os/exec and unix-socket references in f that
// aren't listed in externalWriters (marking the listed ones used).
func scanExternal(fset *token.FileSet, root string, f *ast.File, info *types.Info, used map[string]bool) []string {
	var out []string
	pos := fset.Position(f.Pos())
	rel, _ := filepath.Rel(root, pos.Filename)
	for _, decl := range f.Decls {
		fn := "<package>"
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				t := fd.Recv.List[0].Type
				if st, ok := t.(*ast.StarExpr); ok {
					t = st.X
				}
				if ix, ok := t.(*ast.IndexExpr); ok {
					t = ix.X
				}
				if id, ok := t.(*ast.Ident); ok {
					fn = id.Name + "." + fn
				}
			}
		}
		// Calls by selector, to judge net's network argument.
		calls := map[*ast.SelectorExpr]*ast.CallExpr{}
		ast.Inspect(decl, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := ast.Unparen(c.Fun).(*ast.SelectorExpr); ok {
					calls[sel] = c
				}
			}
			return true
		})
		ast.Inspect(decl, func(n ast.Node) bool {
			var what string
			var at token.Pos
			switch n := n.(type) {
			case *ast.CompositeLit:
				// An exec.Cmd built by hand (&exec.Cmd{Path: …}).
				tv, ok := info.Types[n]
				if !ok {
					return true
				}
				named, ok := tv.Type.(*types.Named)
				if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "os/exec" || named.Obj().Name() != "Cmd" {
					return true
				}
				what, at = "exec.Cmd literal", n.Pos()
			case *ast.SelectorExpr:
				// Every use: a call, or the function as a value (f :=
				// exec.Command), as the file scan does.
				obj, ok := info.Uses[n.Sel].(*types.Func)
				if !ok || obj.Pkg() == nil {
					return true
				}
				pkg, name := obj.Pkg().Path(), obj.Name()
				sig := obj.Type().(*types.Signature)
				call := calls[n]
				switch {
				case sig.Recv() == nil && externalFuncs[pkg][name]:
					if pkg == "net" && !netAlwaysUnix[name] && call != nil && !unixNetwork(info, call) {
						return true
					}
					what = pkg + "." + name
				case pkg == "net" && sig.Recv() != nil && (name == "Dial" || name == "DialContext" || name == "Listen" || name == "ListenPacket"):
					// (*net.Dialer).Dial*, (*net.ListenConfig).Listen*.
					if call != nil && !unixNetwork(info, call) {
						return true
					}
					what = "net." + recvName(sig) + "." + name
				default:
					return true
				}
				if call == nil {
					what += " (as a value)"
				}
				at = n.Pos()
			default:
				return true
			}
			site := rel + ":" + fn
			if externalWriters[site] != "" {
				used[site] = true
				return true
			}
			p := fset.Position(at)
			out = append(out, fmt.Sprintf("%s:%d: %s in %s (an external writer: gate it and list it in externalWriters)", rel, p.Line, what, fn))
			return true
		})
	}
	return out
}

func recvName(sig *types.Signature) string {
	t := sig.Recv().Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return "?"
}

// unixNetwork: call's network argument (the first string argument) is a
// constant "unix…", or not a constant at all.
func unixNetwork(info *types.Info, call *ast.CallExpr) bool {
	for _, a := range call.Args {
		tv, ok := info.Types[a]
		if !ok {
			continue
		}
		if b, ok := tv.Type.Underlying().(*types.Basic); !ok || b.Kind() != types.String && b.Kind() != types.UntypedString {
			continue
		}
		if tv.Value == nil {
			return true
		}
		return strings.HasPrefix(constant.StringVal(tv.Value), "unix")
	}
	return false
}
