package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The spec: a corrupt directory.yaml refuses to start; a missing one is
// an empty directory.
func TestOpenDirectoryStore(t *testing.T) {
	dir := t.TempDir()
	if st, err := openDirectoryStore(dir); err != nil || st.Path != filepath.Join(dir, "directory.yaml") {
		t.Fatalf("missing file: %v %v", st, err)
	}
	for name, body := range map[string]string{
		"corrupt":         "version: 1\nfields: [\n",
		"unknown version": "version: 99\n",
		"unknown key":     "version: 1\nbogus: true\n",
		"bad rule":        "version: 1\ngroups:\n  g:\n    rule: 'city ='\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, "directory.yaml"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := openDirectoryStore(dir); err == nil || !strings.Contains(err.Error(), "directory.yaml") {
			t.Errorf("%s: err = %v, want a refusal naming directory.yaml", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "directory.yaml"), []byte("version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openDirectoryStore(dir); err != nil {
		t.Errorf("valid file: %v", err)
	}
}
