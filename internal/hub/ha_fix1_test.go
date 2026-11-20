package hub

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/leader"
	"github.com/portcullis/hub/internal/nodeadm"
)

// failingNodeadm answers no snapshot.
type failingNodeadm struct {
	*fakeNodeadm
	err error
}

func (f failingNodeadm) Cluster(context.Context) (nodeadm.Snapshot, error) {
	return nodeadm.Snapshot{}, f.err
}

// TestHADegradesWithoutSnapshot (Q2): nodeadm failing (or not
// configured) still answers the page: experimental, the command, the
// backup destination judged, every snapshot item red with the reason
// (`ha enable` stays refused), the error among the warnings, the front
// door still read.
func TestHADegradesWithoutSnapshot(t *testing.T) {
	cf := haFixture(t, haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", ""), true, true))
	cf.h.SetNodeadm(failingNodeadm{cf.na, &nodeadm.APIError{Status: 503, Kind: "not_leader", Text: "not the leader"}})
	cf.h.cfg.HA, cf.h.cfg.BackupDestination = true, true
	cf.h.SetFrontdoorStatus(func(context.Context) ([]byte, error) {
		return []byte(`{"v":1,"state":"leading","names":{"example.org":{"addresses":["198.51.100.7"],"worst_case_s":90}},"sites":{"main":{"healthy":true}}}`), nil
	})
	v, err := cf.h.HA(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Experimental || v.Command != HACommand || !v.Enabled || v.Guarantee != GuaranteeDegraded || len(v.Nodes) != 0 || len(v.DNS) != 1 || v.Frontdoor.State != "leading" {
		t.Errorf("view %+v", v)
	}
	if got := strings.Join(haIDs(v), ","); got != "nodes,servers,storage,ingress,backup_destination,n_minus_1,watchdog" {
		t.Errorf("items %s", got)
	}
	for _, it := range v.Checklist {
		switch {
		case it.ID == "backup_destination":
			if !it.OK {
				t.Errorf("backup %+v", it)
			}
		case it.OK || !strings.HasPrefix(it.Text, "nodeadm's snapshot isn't readable: nodeadm: "):
			t.Errorf("%+v", it)
		}
	}
	if len(v.Warnings) != 1 || !strings.HasPrefix(v.Warnings[0], "nodeadm's snapshot isn't readable: ") {
		t.Errorf("warnings %q", v.Warnings)
	}
	// nodeadm not configured at all: the same degraded page.
	cf.h.SetNodeadm(nil)
	cf.h.cfg.NodeadmURL = ""
	if v, err = cf.h.HA(context.Background()); err != nil || !strings.Contains(haItem(t, v, "nodes").Text, "nodeadm isn't configured") {
		t.Errorf("unconfigured: %v %+v", err, v)
	}
}

// TestHAReadPanicIsAnError (Q3): a panic in the shared read is the
// call's error, never the Hub's end; the next read works.
func TestHAReadPanicIsAnError(t *testing.T) {
	cf := haFixture(t, haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", ""), true, true))
	cf.h.cfg.HA = true
	cf.h.SetFrontdoorStatus(func(context.Context) ([]byte, error) { panic("boom") })
	if _, err := cf.h.HA(context.Background()); err == nil || err.Error() != "the HA read failed: boom" {
		t.Fatalf("panic: %v", err)
	}
	cf.h.SetFrontdoorStatus(func(context.Context) ([]byte, error) { return nil, errors.New("gone") })
	if v, err := cf.h.HA(context.Background()); err != nil || v.Frontdoor.Error == "" {
		t.Errorf("after the panic: %v %+v", err, v)
	}
}

// TestHAWorstCaseUnreported (Q5): no worst_case_s is "unknown", never
// a short "~1 min".
func TestHAWorstCaseUnreported(t *testing.T) {
	_, dns, err := haDNS([]byte(`{"v":1,"state":"leading","names":{"example.org":{"addresses":[]}},"sites":{"main":{"healthy":false}}}`), "Porkbun")
	if err != nil || len(dns) != 1 {
		t.Fatal(err)
	}
	if dns[0].WorstCaseText != "worst case unknown (the front door didn't report it)" ||
		dns[0].PerSite[0].WorstCaseText != "if site main fails: worst case unknown (the front door didn't report it)" {
		t.Errorf("%+v", dns[0])
	}
	if WorstCaseText(-5, "X") != worstUnknown {
		t.Error("a negative worst case shown")
	}
}

// TestHAProviderSources (S1): HUB_DNS_PROVIDER first, else core.env's
// DNS_PROVIDER (Docker's HUB_ENV_VARS key), each only as an id
// (^[a-z0-9-]{1,32}$); anything else, or nothing, is an unknown provider:
// the generic text and no note.
func TestHAProviderSources(t *testing.T) {
	cf := haFixture(t, haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", ""), true, true))
	cf.h.cfg.HA = true
	cf.h.SetFrontdoorStatus(func(context.Context) ([]byte, error) {
		return []byte(`{"v":1,"state":"leading","names":{"example.org":{"addresses":["198.51.100.7"],"worst_case_s":630}},"sites":{"main":{"healthy":true}}}`), nil
	})
	for _, c := range []struct{ env, core, note, on string }{
		{"", "", "", "your DNS provider"},
		{"", "porkbun", PorkbunCredentialsNote, "Porkbun"},
		{"cloudflare", "porkbun", "", "Cloudflare"},
		{"porkbun", "cloudflare", PorkbunCredentialsNote, "Porkbun"},
		{"", "Porkbun", "", "your DNS provider"},
		{"", "<b>x</b>", "", "your DNS provider"},
		{"bad id", "", "", "your DNS provider"},
	} {
		writeFile(t, filepath.Join(cf.project, ".env"), "PORTCULLIS_DOMAIN=example.org\nDNS_PROVIDER="+c.core+"\n")
		cf.h.cfg.DNSProvider = c.env
		v, err := cf.h.HA(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v.CredentialsNote != c.note || v.DNS[0].WorstCaseText != "worst case ~10 min for clients that hit the dead address first, on "+c.on {
			t.Errorf("%+v: %q %q", c, v.CredentialsNote, v.DNS[0].WorstCaseText)
		}
	}
}

// TestControlCertKeptWhenRenewalCantBeSaved (Q6): a renewal whose files
// can't be written (the fence closed) keeps the still-valid certificate:
// a read never fails for it.
func TestControlCertKeptWhenRenewalCantBeSaved(t *testing.T) {
	sf := newServersFixture(t)
	if _, _, err := sf.h.controlCert(context.Background()); err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(4343), Subject: pkix.Name{CommonName: ControlCN}, NotBefore: time.Now().Add(-29 * 24 * time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, sf.ca.cert, &k.PublicKey, sf.ca.key)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	dir := filepath.Join(sf.data, "nodes")
	os.WriteFile(filepath.Join(dir, "control.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "control.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	fsutil.SetWriteGate(func() error { return leader.ErrStandingBy })
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
	c, _, err := sf.h.controlCert(context.Background())
	if err != nil || c.Leaf.SerialNumber.Cmp(big.NewInt(4343)) != 0 {
		t.Fatalf("kept: %v", err)
	}
	fsutil.SetWriteGate(nil)
	if c, _, err = sf.h.controlCert(context.Background()); err != nil || c.Leaf.SerialNumber.Cmp(big.NewInt(4343)) == 0 {
		t.Errorf("renewed once writable: %v", err)
	}
}
