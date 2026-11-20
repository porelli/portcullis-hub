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
