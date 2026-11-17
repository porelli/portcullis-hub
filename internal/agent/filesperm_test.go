package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// TestNoSecretInFilesTree: the world-readable files tree holds template
// files and the CA bundle only. The instance env, the appfiles' data and
// secrets files stay where only the agent reads them (the project dir
// 0700; appfiles/ with their own modes) — never under files/<id>.
func TestNoSecretInFilesTree(t *testing.T) {
	f := newAPI(t)
	const envSecret, fileSecret = "topsecret-env-7c1d", "topsecret-appfile-9e2a"
	b := bundleTar(t, "app", map[string]string{"data": "portcullis-app_data"}, []bundleFile{
		{name: BundleCompose, data: testCompose},
		{name: BundleEnv, data: "A=1\nAPP_SECRET=" + envSecret + "\n", mode: 0o600},
		{name: "templates/app/app.conf", data: "x=1\n"},
		{name: "appfiles/people/people.json", data: `{"alice":1}`, mode: 0o640},
		{name: "appfiles/people/people.secrets.json", data: `{"token":"` + fileSecret + `"}`, mode: 0o600},
		{name: certsBundle, data: "-----BEGIN CERTIFICATE-----\n"},
	})
	if c := f.code(t, "PUT", "/v1/projects/app/bundle", b); c != 204 {
		t.Fatalf("bundle: %d", c)
	}
	err := filepath.WalkDir(f.api.filesDir("app"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(f.api.filesDir("app"), p)
		if rel != filepath.FromSlash(certsBundle) && !strings.HasPrefix(rel, "templates"+string(filepath.Separator)) {
			t.Errorf("files/app holds %s", rel)
		}
		data, _ := os.ReadFile(p)
		if strings.Contains(string(data), envSecret) || strings.Contains(string(data), fileSecret) {
			t.Errorf("a secret is in the files tree: %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{
		f.api.projectDir("app"):                                                  0o700,
		filepath.Join(f.api.projectDir("app"), BundleEnv):                        0o600,
		filepath.Join(f.api.appfilesDir("app"), "people", "people.secrets.json"): 0o600,
	} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %o", p, st, err, want)
		}
	}
	if st, _ := os.Stat(f.api.appfilesDir("app")); st.Mode().Perm()&0o007 != 0 {
		t.Errorf("appfiles/app is open to others: %o", st.Mode().Perm())
	}
	// A bundle can't put anything else in the files tree (the allowlist).
	if err := filesTreeOnly(t.TempDir()); err != nil {
		t.Errorf("an empty tree: %v", err)
	}
	bad := t.TempDir()
	os.MkdirAll(filepath.Join(bad, "certs"), 0o755)
	os.WriteFile(filepath.Join(bad, "certs", "server.key"), []byte("k"), 0o600)
	if err := filesTreeOnly(bad); err == nil {
		t.Error("certs/server.key was let into the files tree")
	}
}
