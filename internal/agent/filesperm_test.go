package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestBundleFilesReadableByTheApp (seen live: busybox httpd as 65534
// couldn't enter its template bind): the files tree is the primary's
// templates/ shape — every directory 0755, files with their bundle modes —
// files/ itself 0711 (traversable, not listable), and the project's own
// directory (the env) stays 0700.
func TestBundleFilesReadableByTheApp(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app")
	err := filepath.WalkDir(f.api.filesDir("app"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if st, _ := os.Stat(p); st.Mode().Perm() != 0o755 {
				t.Errorf("%s: %o, want 755", p, st.Mode().Perm())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(f.api.filesDir("app"), "templates", "app", "app.conf")); err != nil || st.Mode().Perm()&0o004 == 0 {
		t.Errorf("the template file isn't world-readable: %v %v", st, err)
	}
	if st, _ := os.Stat(filepath.Dir(f.api.filesDir("app"))); st.Mode().Perm() != 0o711 {
		t.Errorf("files/: %o, want 711", st.Mode().Perm())
	}
	if st, _ := os.Stat(f.api.projectDir("app")); st.Mode().Perm() != 0o700 {
		t.Errorf("the project dir: %o, want 700", st.Mode().Perm())
	}
}
