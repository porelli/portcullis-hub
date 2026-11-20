package publish_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/publish"
	"github.com/portcullis/hub/internal/vpn"
)

// TestFileSinkMatchesOldWriters: each document the package writers
// wrote before (policy.Write, policy.WriteUserAttributes,
// aigate.WriteFile, aigate.WriteCredFile, vpn.WriteGroup), written once
// by them and once by the FileSink from the new encoders, in two
// directories: the same bytes, mode and group; and the bytes and modes
// equal testdata/golden, written by those writers before this package
// existed (c4bbe7cd, the same inputs). (The three files the
// Hub wrote itself, portal-apps, signin-keycloak and impersonation,
// were json.MarshalIndent + 0644: internal/hub TestPublishDockerFiles.)
// goldenModes are the golden files' modes as the old writers left them.
var goldenModes = map[string]os.FileMode{"group-gate-policy.json": 0644, "user-attributes.json": 0644, "mcp-gate.json": 0640, "mcp-credentials.json": 0640, "vpn.json": 0640}

func TestFileSinkMatchesOldWriters(t *testing.T) {
	oldDir, newDir := t.TempDir(), t.TempDir()
	gid := os.Getgid()
	sink := publish.FileSink{Dirs: map[publish.Doc]string{}, GID: map[publish.Doc]int{publish.VPN: gid}}
	for _, d := range publish.All {
		sink.Dirs[d] = newDir
	}
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	pub := func(d publish.Doc, b []byte, err error) {
		t.Helper()
		must(err)
		_, err = sink.Publish(ctx, d, b)
		must(err)
	}

	doc := policy.Build(policy.BuildInput{MainDomain: "example.org", Default: "x", ExtraDomains: []string{"b.example", "a.example"}})
	must(policy.Write(filepath.Join(oldDir, "group-gate-policy.json"), doc))
	b, err := policy.Encode(doc)
	pub(publish.GroupGatePolicy, b, err)

	attrs := policy.BuildUserAttributes(nil, map[string]map[string][]string{"alice": {"dept": {"ops"}}}, nil)
	must(policy.WriteUserAttributes(filepath.Join(oldDir, "user-attributes.json"), attrs))
	b, err = policy.EncodeUserAttributes(attrs)
	pub(publish.UserAttributes, b, err)

	gb, err := os.ReadFile("../aigate/testdata/mcp-gate.json")
	must(err)
	gf, err := aigate.DecodeFile(gb)
	must(err)
	must(aigate.WriteFile(filepath.Join(oldDir, "mcp-gate.json"), gf))
	b, err = aigate.EncodeChecked(gf)
	pub(publish.MCPGate, b, err)

	cb, err := os.ReadFile("../aigate/testdata/mcp-credentials.json")
	must(err)
	cf, err := aigate.DecodeCredFile(cb)
	must(err)
	must(aigate.WriteCredFile(filepath.Join(oldDir, "mcp-credentials.json"), cf))
	b, err = aigate.EncodeCredChecked(cf)
	pub(publish.MCPCredentials, b, err)

	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	vu := now.Add(time.Hour)
	vd := vpn.Doc{Version: vpn.DocVersion, ValidUntil: &vu}
	must(vpn.WriteGroup(filepath.Join(oldDir, "vpn.json"), vd, gid, now))
	b, err = vpn.EncodeChecked(vd, now)
	pub(publish.VPN, b, err)

	for _, n := range []string{"group-gate-policy.json", "user-attributes.json", "mcp-gate.json", "mcp-credentials.json", "vpn.json"} {
		ob, err1 := os.ReadFile(filepath.Join(oldDir, n))
		nb, err2 := os.ReadFile(filepath.Join(newDir, n))
		if err1 != nil || err2 != nil || !bytes.Equal(ob, nb) {
			t.Errorf("%s: bytes differ (%v %v)", n, err1, err2)
		}
		gb, err := os.ReadFile(filepath.Join("testdata", "golden", n))
		if err != nil || !bytes.Equal(gb, nb) {
			t.Errorf("%s: differs from the golden (%v)", n, err)
		}
		oi, _ := os.Stat(filepath.Join(oldDir, n))
		ni, _ := os.Stat(filepath.Join(newDir, n))
		if oi.Mode() != ni.Mode() || ni.Mode().Perm() != goldenModes[n] {
			t.Errorf("%s: mode %v, old %v, golden %o", n, ni.Mode(), oi.Mode(), goldenModes[n])
		}
		os1, ok1 := oi.Sys().(*syscall.Stat_t)
		ns1, ok2 := ni.Sys().(*syscall.Stat_t)
		if ok1 && ok2 && os1.Gid != ns1.Gid {
			t.Errorf("%s: gid %d, old %d", n, ns1.Gid, os1.Gid)
		}
	}
}
