package templates

import (
	"os"
	"path/filepath"
	"testing"
)

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
	secret := filepath.Join(t.TempDir(), "secret")
	must(os.WriteFile(secret, []byte("top secret"), 0600))
	must(os.Symlink(secret, filepath.Join(src, "leak")))

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
