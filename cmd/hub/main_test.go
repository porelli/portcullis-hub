package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
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

// TestFolderfixDispatch runs the test binary as `hub folderfix …` with no
// Hub environment: the fixer answers, not the Hub's start-up checks.
func TestFolderfixDispatch(t *testing.T) {
	if args := os.Getenv("HUB_TEST_MAIN_ARGS"); args != "" {
		os.Args = append([]string{"hub"}, strings.Split(args, "\x1f")...)
		main()
		return
	}
	run := func(args ...string) (int, string, string) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFolderfixDispatch$")
		cmd.Env = []string{"HUB_TEST_MAIN_ARGS=" + strings.Join(args, "\x1f"), "PATH=" + os.Getenv("PATH")}
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			t.Fatal(err)
		}
		return cmd.ProcessState.ExitCode(), out.String(), errb.String()
	}
	code, _, errOut := run("folderfix", "bogus")
	if code != 1 || strings.Contains(errOut, "HUB_PROXY_SECRET") || !strings.Contains(errOut, "folderfix:") {
		t.Fatalf("bad mode: exit %d stderr %q", code, errOut)
	}
	code, out, errOut := run("folderfix", "scan", "--root="+t.TempDir())
	line := strings.SplitN(out, "\n", 2)[0]
	var r struct{ Mode string }
	if code != 0 || json.Unmarshal([]byte(line), &r) != nil || r.Mode != "scan" {
		t.Fatalf("scan: exit %d out %q stderr %q", code, out, errOut)
	}
}
