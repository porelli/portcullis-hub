package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/servers"
)

func code(t *testing.T) servers.JoinCode {
	k := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	sec := make([]byte, 32)
	rand.Read(sec)
	return servers.JoinCode{V: 1, Endpoint: "example.org:51821", LinkPub: k, ServerID: "nas", TunnelIP: netip.MustParseAddr("10.214.0.10"),
		BootstrapKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), CASHA256: strings.Repeat("ab", 32),
		Secret: base64.RawURLEncoding.EncodeToString(sec)}
}

// TestJoinReadsStdinOnly: the code is read from stdin only (an argument
// is refused with exit 2), never printed, and stored 0600 in a 0700 dir.
func TestJoinReadsStdinOnly(t *testing.T) {
	data := t.TempDir()
	env := func(k string) string {
		if k == "AGENT_DATA" {
			return data
		}
		return ""
	}
	c := code(t)
	var out, errb bytes.Buffer
	if rc := Main([]string{"join", c.Encode()}, strings.NewReader(""), &out, &errb, env); rc != 2 || !strings.Contains(errb.String(), "the join code is a secret") {
		t.Fatalf("argument: rc %d %q", rc, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), c.Secret) {
		t.Error("the code was echoed")
	}
	if _, err := os.Stat(filepath.Join(data, "identity")); err == nil {
		t.Error("an argument wrote an identity")
	}
	out.Reset()
	errb.Reset()
	if rc := Main([]string{"join"}, strings.NewReader("garbage"), &out, &errb, env); rc != 1 {
		t.Errorf("bad code: rc %d", rc)
	}
	if rc := Main([]string{"join"}, strings.NewReader(strings.Repeat("x", MaxJoinInput+1)), &out, &errb, env); rc != 2 {
		t.Errorf("oversized: rc %d", rc)
	}
	out.Reset()
	errb.Reset()
	if rc := Main([]string{"join"}, strings.NewReader(c.Encode()+"\n"), &out, &errb, env); rc != 0 {
		t.Fatalf("stdin: rc %d %s", rc, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), c.Secret) || strings.Contains(out.String(), c.BootstrapKey) {
		t.Error("the code was echoed")
	}
	fi, err := os.Stat(filepath.Join(data, "identity", "join.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("join.json: %v %v", err, fi)
	}
	if di, _ := os.Stat(filepath.Join(data, "identity")); di.Mode().Perm() != 0o700 {
		t.Errorf("identity dir %v", di.Mode().Perm())
	}
	out.Reset()
	Main([]string{"status"}, nil, &out, &errb, env)
	if !strings.Contains(out.String(), `"state":"enrolling"`) || strings.Contains(out.String(), c.Secret) {
		t.Errorf("status %s", out.String())
	}
	if rc := Main([]string{"healthcheck"}, nil, &out, &errb, env); rc != 1 {
		t.Error("healthy without run")
	}
	if rc := Main([]string{"leave"}, nil, &out, &errb, env); rc != 0 {
		t.Error("leave")
	}
	if _, err := os.Stat(filepath.Join(data, "identity")); err == nil {
		t.Error("leave kept the identity")
	}
	if rc := Main([]string{"run"}, nil, &out, &errb, func(string) string { return "relative" }); rc != 2 {
		t.Error("relative AGENT_DATA accepted")
	}
	if rc := Main([]string{"run"}, nil, &out, &errb, env); rc != 1 {
		t.Error("run without AGENT_RUNTIME")
	}
}

func TestParseRoots(t *testing.T) {
	if r, err := parseRoots(""); err != nil || len(r) != 3 {
		t.Errorf("default: %v %v", r, err)
	}
	for _, bad := range []string{"/", "srv", "/srv/../etc", "/srv:$HOME"} {
		if _, err := parseRoots(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
