package hub

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// pinnedRefRe finds a pinned image reference (name:tag@sha256:<64 hex>)
// anywhere in a string literal.
var pinnedRefRe = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}`)

// imageQualified: the first path component is a registry host (has a "."
// or ":", or is localhost), as core's tests/lint_images.sh decides. Rootless
// Podman resolves a short name only through registries.conf aliases.
func imageQualified(ref string) bool {
	host, _, ok := strings.Cut(ref, "/")
	if !ok {
		return false
	}
	return strings.ContainsAny(host, ".:") || host == "localhost"
}

func TestImageQualified(t *testing.T) {
	for ref, want := range map[string]bool{
		"docker.io/library/alpine:3@sha256:" + strings.Repeat("0", 64): true,
		"ghcr.io/porelli/portcullis-hub:edge":                          true,
		"localhost/x:1":                                                true,
		"alpine:3.24.3@sha256:" + strings.Repeat("0", 64):              false,
		"restic/restic:0.19.1":                                         false,
	} {
		if got := imageQualified(ref); got != want {
			t.Errorf("imageQualified(%q) = %v, want %v", ref, got, want)
		}
	}
}

// TestBuiltinImagesQualified: every image the Hub runs on its own
// (HelperImage, and any pinned ref in a non-test Go file of the module) is
// fully qualified (docker.io/library/…), so a rootless Podman engine never
// resolves a short name.
func TestBuiltinImagesQualified(t *testing.T) {
	if !imageQualified(HelperImage) {
		t.Errorf("HelperImage %q is not fully qualified (docker.io/library/…)", HelperImage)
	}
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	found := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, ref := range pinnedRefRe.FindAllString(s, -1) {
				found++
				if !imageQualified(ref) {
					t.Errorf("%s: image %q is not fully qualified (docker.io/library/…, docker.io/<org>/…)", fset.Position(lit.Pos()), ref)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no pinned image reference found in the module: the scan is broken")
	}
}
