package host

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// firstNode is init's host before the adoption: pcmesh's key and a k3s
// server, no nodeagent state.
func firstNode(t *testing.T) *rig {
	t.Helper()
	root := t.TempDir()
	r := &rig{t: t, root: root, ca: newCA(t), wg: &fakeWG{}, log: &logBuf{}}
	r.run = &fakeRun{wg: r.wg}
	k, _ := wgtypes.GeneratePrivateKey()
	r.priv, r.pub = k.String(), k.PublicKey().String()
	writeFile(t, root, MeshKeyFile, r.priv+"\n", 0o600)
	r.a = New(Config{Root: root, Version: "0.0.0-test", Run: r.run, WG: r.wg, Log: slog.New(slog.NewTextHandler(r.log, nil)), Exit: func() {}})
	installK3s(t, r, "server", "rawinittoken0123")
	return r
}

func adoptBody(t *testing.T, id, certPEM string, ca []byte) *bytes.Reader {
	b, _ := json.Marshal(AdoptRequest{ID: id, MeshIP: "10.215.0.1", Site: "main", Class: "home", Certificate: certPEM, CA: string(ca)})
	return bytes.NewReader(b)
}

func signCSR(t *testing.T, ca *testCA, csrPEM []byte, cn string) string {
	blk, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.sign(t, cn, csr.PublicKey)}))
}

// TestAdoptFirstNode (plan Task 30 carry): init's node gets a nodeagent
// without a join: a key made on the node (never printed), the CLI's
// certificate for it, the state marked adopted, the unit started; the
// agent loads and never renews through nodeadm. Every refusal writes
// nothing.
func TestAdoptFirstNode(t *testing.T) {
	ctx := context.Background()
	r := firstNode(t)
	csr, err := r.a.AdoptCSR(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(csr), "-----BEGIN CERTIFICATE REQUEST-----") || strings.Contains(string(csr), "PRIVATE KEY") {
		t.Fatalf("csr output %q", csr)
	}
	if fi, err := os.Stat(filepath.Join(r.root, adoptPEMFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the adoption key: %v %v", fi, err)
	}
	cert := signCSR(t, r.ca, csr, "node-1."+clusterDomain)
	other := newCA(t)
	ok, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, body := range map[string]*bytes.Reader{
		"another name":     adoptBody(t, "node-1", signCSR(t, r.ca, csr, "node-2."+clusterDomain), r.ca.pem),
		"another key":      adoptBody(t, "node-1", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.ca.sign(t, "node-1."+clusterDomain, &ok.PublicKey)})), r.ca.pem),
		"another CA":       adoptBody(t, "node-1", cert, other.pem),
		"a leaf as the CA": adoptBody(t, "node-1", cert, []byte(cert)),
		"another id":       adoptBody(t, "node-2", cert, r.ca.pem),
		"an unknown field": bytes.NewReader([]byte(`{"id":"node-1","token":"x"}`)),
	} {
		if err := r.a.Adopt(ctx, body); err == nil {
			t.Errorf("%s: adopted", name)
		}
		if _, err := os.Stat(filepath.Join(r.root, stateFile)); err == nil {
			t.Fatalf("%s: a refusal wrote the state", name)
		}
	}
	if err := r.a.Adopt(ctx, adoptBody(t, "node-1", cert, r.ca.pem)); err != nil {
		t.Fatal(err)
	}
	if r.run.count("systemctl", "restart", UnitName) != 1 || r.run.count("systemctl", "enable", UnitName) != 1 {
		t.Errorf("unit not started: %v", r.run.cmds)
	}
	if b, _ := os.ReadFile(filepath.Join(r.root, unitFile)); string(b) != UnitText() {
		t.Error("no unit file")
	}
	if _, err := os.Stat(filepath.Join(r.root, adoptPEMFile)); err == nil {
		t.Error("the adoption key file stayed")
	}
	if err := r.a.Load(); err != nil {
		t.Fatal(err)
	}
	if st := r.a.State(); !st.Adopted || st.ID != "node-1" || st.Role != "server" || st.MeshIP != "10.215.0.1" || st.Site != "main" {
		t.Fatalf("state %+v", st)
	}
	for _, f := range []string{stateFile, nodePEMFile, caFile} {
		if fi, err := os.Stat(filepath.Join(r.root, f)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, fi, err)
		}
	}
	// No nodeadm renewal: RunRenewal returns at once (nodeadm has no record).
	done := make(chan struct{})
	go func() { r.a.RunRenewal(ctx); close(done) }()
	<-done
	// A renewal by the CLI: a new key, the same CA and id.
	csr2, err := r.a.AdoptCSR(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.a.Adopt(ctx, adoptBody(t, "node-1", signCSR(t, other, csr2, "node-1."+clusterDomain), other.pem)); err == nil {
		t.Error("a re-adoption swapped the CA")
	}
	if err := r.a.Adopt(ctx, adoptBody(t, "node-1", signCSR(t, r.ca, csr2, "node-1."+clusterDomain), r.ca.pem)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.a.AdoptCSR(ctx, "node-2"); err == nil {
		t.Error("an adopted node changed its id")
	}
}

// TestAdoptOnlyTheFirstNode: a joined node (its state not adopted) and a
// host without a k3s server (an agent, or nothing) are never adopted.
func TestAdoptOnlyTheFirstNode(t *testing.T) {
	ctx := context.Background()
	joined := newRig(t, "server")
	installK3s(t, joined, "server", "rawinittoken0123")
	if _, err := joined.a.AdoptCSR(ctx, "n2"); err == nil || !strings.Contains(err.Error(), "joined the cluster") {
		t.Errorf("a joined node: %v", err)
	}
	agent := newRig(t, "agent")
	installK3s(t, agent, "agent", "rawinittoken0123")
	if _, err := agent.a.AdoptCSR(ctx, "n2"); err == nil || !strings.Contains(err.Error(), "no k3s server here") {
		t.Errorf("an agent: %v", err)
	}
	r := firstNode(t)
	os.Remove(filepath.Join(r.root, MeshKeyFile))
	if _, err := r.a.AdoptCSR(ctx, "node-1"); err == nil {
		t.Error("adopted without the pcmesh key")
	}
	if _, err := firstNode(t).a.AdoptCSR(ctx, "Node_1"); err == nil {
		t.Error("an invalid id")
	}
}
