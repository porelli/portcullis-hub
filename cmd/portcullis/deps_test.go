package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestCLIImportGraph pins plan ruling C27: the CLI imports no Hub package
// but internal/cliapi, on every OS it ships for.
func TestCLIImportGraph(t *testing.T) {
	const mod = "github.com/portcullis/hub/"
	for _, goos := range []string{"linux", "darwin", "windows"} {
		cmd := exec.Command("go", "list", "-deps", "./...")
		cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go list (%s): %v\n%s", goos, err, out)
		}
		for _, p := range strings.Fields(string(out)) {
			if !strings.HasPrefix(p, mod) {
				continue
			}
			rest := strings.TrimPrefix(p, mod)
			if rest == "internal/cliapi" || rest == "cmd/portcullis" || strings.HasPrefix(rest, "cmd/portcullis/") {
				continue
			}
			t.Errorf("%s: cmd/portcullis depends on %s", goos, p)
		}
	}
}
