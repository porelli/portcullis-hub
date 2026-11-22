package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	na "github.com/portcullis/hub/internal/nodeagent"
)

// TestAgentUpgrade (Task 30 fix round 1): nodeadm names the sums; the
// node downloads its architecture's binary from nodeadm's public path,
// installs it only when its sha256 is the named one, answers "upgraded"
// and restarts its unit; the same binary again is "current" (no
// download); a wrong sum installs nothing; the first node (adopted)
// refuses; only nodeadm.control may ask.
func TestAgentUpgrade(t *testing.T) {
	r := newRig(t, "agent")
	newBin := []byte("#!/bin/sh\necho new nodeagent\n")
	sum := sha256.Sum256(newBin)
	good := hex.EncodeToString(sum[:])
	var gets []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		gets = append(gets, q.URL.Path)
		if q.URL.Path != "/node/nodeagent-"+runtime.GOARCH {
			http.NotFound(w, q)
			return
		}
		w.Write(newBin)
	}))
	t.Cleanup(srv.Close)
	setEndpoint(t, r, srv.URL+"/node")
	r.a.cfg.HTTP = srv.Client()
	writeFile(t, r.root, AgentBinary, "old nodeagent\n", 0o755)
	s := r.server()
	other := strings.Repeat("0", 64)
	body := func(s string) string {
		if runtime.GOARCH == "arm64" {
			return `{"amd64":"` + other + `","arm64":"` + s + `"}`
		}
		return `{"amd64":"` + s + `","arm64":"` + other + `"}`
	}
	bin := filepath.Join(r.root, AgentBinary)
	// A sum the download doesn't have: nothing installed, no restart.
	if code, out := do(t, r.client(r.ca, na.CNNodeadm), "POST", s.URL+"/v1/agent/upgrade", body(strings.Repeat("e", 64))); code != 502 {
		t.Fatalf("a wrong sum: %d %s", code, out)
	}
	if b, _ := os.ReadFile(bin); string(b) != "old nodeagent\n" {
		t.Fatalf("a wrong sum replaced the binary: %q", b)
	}
	// Only nodeadm.control.
	if code, _ := do(t, r.client(r.ca, na.CNHub), "POST", s.URL+"/v1/agent/upgrade", body(good)); code != 403 {
		t.Fatalf("the Hub may upgrade: %d", code)
	}
	code, out := do(t, r.client(r.ca, na.CNNodeadm), "POST", s.URL+"/v1/agent/upgrade", body(good))
	if code != 200 || !strings.Contains(out, `"state":"upgraded"`) {
		t.Fatalf("upgrade: %d %s", code, out)
	}
	if b, _ := os.ReadFile(bin); string(b) != string(newBin) {
		t.Fatalf("the binary %q", b)
	}
	if fi, _ := os.Stat(bin); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode())
	}
	deadline := time.Now().Add(3 * time.Second)
	for !r.ran("systemctl restart --no-block " + UnitName) {
		if time.Now().After(deadline) {
			t.Fatal("the unit wasn't restarted")
		}
		time.Sleep(20 * time.Millisecond)
	}
	n := len(gets)
	if code, out := do(t, r.client(r.ca, na.CNNodeadm), "POST", s.URL+"/v1/agent/upgrade", body(good)); code != 200 || !strings.Contains(out, `"state":"current"`) || len(gets) != n {
		t.Fatalf("the same binary again: %d %s (downloads %d → %d)", code, out, n, len(gets))
	}
	if code, _ := do(t, r.client(r.ca, na.CNNodeadm), "POST", s.URL+"/v1/agent/upgrade", `{"amd64":"x","arm64":"y"}`); code != 400 {
		t.Fatalf("malformed sums: %d", code)
	}
	// The first node is the CLI's.
	r.a.mu.Lock()
	r.a.st.Adopted = true
	r.a.mu.Unlock()
	if code, _ := do(t, r.client(r.ca, na.CNNodeadm), "POST", s.URL+"/v1/agent/upgrade", body(strings.Repeat("d", 64))); code != 409 {
		t.Fatalf("an adopted node: %d", code)
	}
	_ = context.Background()
}

// ran: the fake runner saw this command line.
func (r *rig) ran(line string) bool {
	r.run.mu.Lock()
	defer r.run.mu.Unlock()
	for _, c := range r.run.cmds {
		if strings.Join(append([]string{c.Name}, c.Args...), " ") == line {
			return true
		}
	}
	return false
}
