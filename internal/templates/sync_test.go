package templates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A symlink that points outside the template refuses the copy (every
// template): the published tree stays as it was.
func TestSyncFilesRefusesOutboundSymlinks(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("top secret"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, link := range map[string]func(src string) (string, string){
		"absolute":     func(string) (string, string) { return secret, "leak" },
		"relative":     func(string) (string, string) { return "../../etc/passwd", "conf/leak" },
		"dangling out": func(string) (string, string) { return "/nonexistent/x", "leak" },
		"via a chain":  func(string) (string, string) { return "hop", "leak" },
	} {
		t.Run(name, func(t *testing.T) {
			src := t.TempDir()
			root := filepath.Join(t.TempDir(), "templates")
			tpl := &Template{ID: "app", Path: src}
			os.MkdirAll(filepath.Join(src, "conf"), 0755)
			os.WriteFile(filepath.Join(src, "compose.yml"), []byte("v1"), 0644)
			if err := SyncFiles(tpl, root); err != nil {
				t.Fatal(err)
			}
			target, at := link(src)
			if name == "via a chain" {
				os.Symlink(secret, filepath.Join(src, "hop"))
				os.Remove(filepath.Join(src, "hop"))
				os.Symlink(secret, filepath.Join(src, "hop"))
			}
			if err := os.Symlink(target, filepath.Join(src, at)); err != nil {
				t.Fatal(err)
			}
			os.WriteFile(filepath.Join(src, "compose.yml"), []byte("v2"), 0644)
			err := SyncFiles(tpl, root)
			if err == nil || !strings.Contains(err.Error(), "points outside the template") {
				t.Fatalf("err = %v", err)
			}
			if b, _ := os.ReadFile(filepath.Join(root, "app", "compose.yml")); string(b) != "v1" {
				t.Errorf("published tree changed: %q", b)
			}
		})
	}
}

func TestSyncFiles(t *testing.T) {
	src := t.TempDir()
	root := filepath.Join(t.TempDir(), "templates")
	tpl := &Template{ID: "app", Path: src}

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(src, "compose.yml"), []byte("services: {}\n"), 0644))
	must(os.MkdirAll(filepath.Join(src, "conf", "nested"), 0755))
	must(os.WriteFile(filepath.Join(src, "conf", "nested", "setup.sh"), []byte("#!/bin/sh\n"), 0755))
	must(os.MkdirAll(filepath.Join(src, ".git"), 0755))
	must(os.WriteFile(filepath.Join(src, ".git", "config"), []byte("x"), 0644))
	// A link inside the template is skipped (never copied or followed).
	must(os.Symlink(filepath.Join("conf", "nested", "setup.sh"), filepath.Join(src, "leak")))

	must(SyncFiles(tpl, root))
	dest := filepath.Join(root, "app")
	if b, err := os.ReadFile(filepath.Join(dest, "conf", "nested", "setup.sh")); err != nil || string(b) != "#!/bin/sh\n" {
		t.Fatalf("nested file not synced: %q %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(dest, "conf", "nested", "setup.sh")); fi.Mode().Perm() != 0755 {
		t.Errorf("mode not preserved: %v", fi.Mode())
	}
	if _, err := os.Lstat(filepath.Join(dest, "leak")); !os.IsNotExist(err) {
		t.Error("symlink must not be copied/followed")
	}
	if _, err := os.Stat(filepath.Join(dest, ".git")); !os.IsNotExist(err) {
		t.Error(".git must be skipped")
	}

	// Second sync replaces content and drops deleted files; no stage/.old
	// directories are left behind.
	must(os.Remove(filepath.Join(src, "conf", "nested", "setup.sh")))
	must(os.WriteFile(filepath.Join(src, "compose.yml"), []byte("v2"), 0644))
	must(SyncFiles(tpl, root))
	if b, _ := os.ReadFile(filepath.Join(dest, "compose.yml")); string(b) != "v2" {
		t.Errorf("content not refreshed: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dest, "conf", "nested", "setup.sh")); !os.IsNotExist(err) {
		t.Error("deleted file still present")
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 || entries[0].Name() != "app" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("leftovers in root: %v", names)
	}

	if err := SyncFiles(&Template{ID: "../evil", Path: src}, root); err == nil {
		t.Error("invalid id accepted")
	}
}

func TestSyncFilesIfChanged(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src", "app")
	os.MkdirAll(filepath.Join(src, "conf"), 0755)
	os.WriteFile(filepath.Join(src, "conf", "a.ini"), []byte("a\n"), 0644)
	out := filepath.Join(root, "out")
	dest := filepath.Join(out, "app")
	tpl := &Template{ID: "app-b", TemplateID: "app", Path: src}

	sum, err := SyncFilesIfChanged(tpl, out, "")
	if err != nil || sum == "" {
		t.Fatalf("first sync: %q %v", sum, err)
	}
	stat := func() os.FileInfo {
		fi, err := os.Lstat(dest)
		if err != nil {
			t.Fatal(err)
		}
		return fi
	}
	same := func(want bool, what string) {
		t.Helper()
		before := stat()
		got, err := SyncFilesIfChanged(tpl, out, sum)
		if err != nil || got != sum {
			t.Fatalf("%s: %q %v", what, got, err)
		}
		if os.SameFile(before, stat()) != want {
			t.Errorf("%s: swapped = %v, want %v", what, !want, want)
		}
		if b, err := os.ReadFile(filepath.Join(dest, "conf", "a.ini")); err != nil || string(b) != "a\n" {
			t.Errorf("%s: content %q %v", what, b, err)
		}
		if fi, err := os.Lstat(dest); err != nil || !fi.IsDir() {
			t.Errorf("%s: dest is not a real directory", what)
		}
	}
	same(true, "unchanged")

	// The recorded hash comes from the caller, never from dest.
	before := stat()
	if _, err := SyncFilesIfChanged(tpl, out, "stale"); err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, stat()) {
		t.Error("an identical dest was trusted without a matching recorded hash")
	}
	// A planted symlink forces a re-sync (and is gone afterwards).
	os.Symlink("/etc/passwd", filepath.Join(dest, "conf", "evil"))
	same(false, "symlink in dest")
	if _, err := os.Lstat(filepath.Join(dest, "conf", "evil")); err == nil {
		t.Error("planted symlink survived")
	}
	// An edited file with an unchanged source.
	os.WriteFile(filepath.Join(dest, "conf", "a.ini"), []byte("evil\n"), 0644)
	same(false, "edited file")
	// A .git entry.
	os.MkdirAll(filepath.Join(dest, ".git"), 0755)
	same(false, ".git in dest")
	// dest replaced by a symlink to a directory holding the same files.
	elsewhere := filepath.Join(root, "elsewhere")
	os.MkdirAll(filepath.Join(elsewhere, "conf"), 0755)
	os.WriteFile(filepath.Join(elsewhere, "conf", "a.ini"), []byte("a\n"), 0644)
	os.RemoveAll(dest)
	os.Symlink(elsewhere, dest)
	same(false, "dest is a symlink")
	if _, err := os.Stat(filepath.Join(elsewhere, "conf", "a.ini")); err != nil {
		t.Errorf("the symlink's target was touched: %v", err)
	}
	// A changed source re-syncs and returns the new hash.
	os.WriteFile(filepath.Join(src, "conf", "a.ini"), []byte("b\n"), 0644)
	got, err := SyncFilesIfChanged(tpl, out, sum)
	if err != nil || got == sum {
		t.Fatalf("changed source: %q %v", got, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "conf", "a.ini")); string(b) != "b\n" {
		t.Errorf("content = %q", b)
	}
}
