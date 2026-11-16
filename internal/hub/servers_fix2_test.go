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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/linkdoc"
	"github.com/portcullis/hub/internal/state"
)

// revokeAsync starts RevokeServer and waits until the revocation began
// (state revoked): for seams running inside an op RevokeServer waits for.
func (sf *serversFixture) revokeAsync(t *testing.T, id string) <-chan error {
	done := make(chan error, 1)
	go func() { done <- sf.h.RevokeServer(context.Background(), admin, id) }()
	for i := 0; i < 2000; i++ {
		if s, _ := sf.server(id); s.State == ServerRevoked {
			return done
		}
		time.Sleep(time.Millisecond)
	}
	t.Error("the revocation didn't start")
	return done
}

func (sf *serversFixture) assertRevokedEverywhere(t *testing.T, what, id string) {
	t.Helper()
	sf.place("grafana", id)
	if _, err := sf.h.rtFor("grafana"); err == nil || !strings.Contains(err.Error(), "is revoked") {
		t.Errorf("%s: rtFor %v", what, err)
	}
	if _, ok := sf.h.runtimes()[id]; ok {
		t.Errorf("%s: in runtimes()", what)
	}
	sf.h.srvMu.Lock()
	watching := sf.h.polls[id] != nil && sf.h.polls[id].stop != nil
	sf.h.srvMu.Unlock()
	if watching {
		t.Errorf("%s: an event stream runs", what)
	}
}

// TestRevokeRacesRegistry (review B-M1): a revocation landing between a
// state check and the registry write of pollServer, renewServer,
// rebuildBackends or the enrolment commit wins: the revoked server is
// never handed out again, no event stream runs, no server.enrolled.
func TestRevokeRacesRegistry(t *testing.T) {
	for _, path := range []string{"poll", "renew", "rebuild"} {
		t.Run(path, func(t *testing.T) {
			sf := newServersFixture(t)
			sf.enrol(t, "nas")
			sf.link.handshake("nas", time.Now())
			if path == "renew" {
				sf.h.mu.Lock()
				s := sf.h.st.Servers["nas"]
				s.CertNotAfter = time.Now().Add(9 * 24 * time.Hour)
				sf.h.st.Servers["nas"] = s
				sf.h.mu.Unlock()
			}
			fired := false
			sf.h.srvT.beforeSetServer = func(id string) {
				if fired {
					return
				}
				// renew: let the poll's own set pass, race the renewal's.
				if path == "renew" && !slices.Contains(sf.agent.Calls(), "csr") {
					return
				}
				fired = true
				if err := sf.h.RevokeServer(context.Background(), admin, id); err != nil {
					t.Error(err)
				}
			}
			switch path {
			case "poll", "renew":
				sf.h.pollServer(context.Background(), "nas")
			case "rebuild":
				sf.h.rebuildBackends(context.Background())
			}
			if !fired {
				t.Fatal("the seam never ran")
			}
			sf.assertRevokedEverywhere(t, path, "nas")
		})
	}
	t.Run("enrolment commit", func(t *testing.T) {
		sf := newServersFixture(t)
		var done <-chan error
		sf.h.srvT.beforeSetServer = func(id string) {
			if done == nil {
				done = sf.revokeAsync(t, id)
			}
		}
		code, _, err := sf.h.AddServer(context.Background(), admin, "nas", "")
		if err != nil {
			t.Fatal(err)
		}
		sf.agent.takeCode(t, code)
		sf.link.handshake("nas", time.Now().Add(time.Second))
		r := waitServerOp(t, sf.h, serverOpKey("nas"))
		if done == nil {
			t.Fatal("the seam never ran")
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if r.OK {
			t.Error("the enrolment succeeded after its revocation")
		}
		if slices.Contains(sf.actions(), "server.enrolled:ok") {
			t.Errorf("server.enrolled after the revocation: %v", sf.actions())
		}
		sf.assertRevokedEverywhere(t, "enrolment", "nas")
	})
}

// TestRevokeStep1BeforeWaiting (review B-L1): the peer leaves link.json
// at the revocation's start, before RevokeServer waits for the running
// enrolment to end.
func TestRevokeStep1BeforeWaiting(t *testing.T) {
	sf := newServersFixture(t)
	block, entered := make(chan struct{}), make(chan struct{})
	sf.agent.onCert = func() {
		close(entered)
		<-block
	}
	code, _, err := sf.h.AddServer(context.Background(), admin, "nas", "")
	if err != nil {
		t.Fatal(err)
	}
	sf.agent.takeCode(t, code)
	sf.link.handshake("nas", time.Now().Add(time.Second))
	<-entered
	done := sf.revokeAsync(t, "nas")
	if d := sf.linkDoc(t); len(d.Peers) != 0 {
		t.Errorf("while RevokeServer waits: peers %+v", d.Peers)
	}
	close(block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitServerOp(t, sf.h, serverOpKey("nas"))
}

// TestRemoveRefusesPlacementDuringLeave (review B-L2): an instance placed
// while the leave runs makes the removal 409; placement is refused while
// the server is being removed.
func TestRemoveRefusesPlacementDuringLeave(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	placeErr := make(chan error, 1)
	sf.agent.mu.Lock()
	sf.agent.onLeave = func() {
		sf.h.mu.RLock()
		placeErr <- sf.h.placeableLocked("nas")
		sf.h.mu.RUnlock()
		sf.place("other", "nas") // as if a placement slipped in
	}
	sf.agent.mu.Unlock()
	err := sf.h.RemoveServer(context.Background(), admin, "nas")
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "still has 1 instance") {
		t.Errorf("remove: %v", err)
	}
	if pe := <-placeErr; pe == nil || !strings.Contains(pe.Error(), "being removed") {
		t.Errorf("placement during the removal: %v", pe)
	}
	if s, _ := sf.server("nas"); s.State == ServerRevoked {
		t.Error("revoked although the removal was refused")
	}
	sf.h.mu.RLock()
	err = sf.h.placeableLocked("nas")
	sf.h.mu.RUnlock()
	if err != nil {
		t.Errorf("placeable again: %v", err)
	}
}

// TestServersOffWithoutRelayImage (review B-L3): link_doc exists but no
// usable relay image → Servers is off.
func TestServersOffWithoutRelayImage(t *testing.T) {
	for _, img := range []string{"", "ghcr.io/porelli/portcullis-relay:latest"} {
		sf := newServersFixture(t)
		sf.h.cfg.RelayImage = img
		_, _, err := sf.h.AddServer(context.Background(), admin, "nas", "")
		if errStatus(err) != 503 || !strings.Contains(err.Error(), "HUB_RELAY_IMAGE") {
			t.Errorf("%q: %v", img, err)
		}
	}
}

// TestToolRedactionIncludesRelayToken (review B-L4).
func TestToolRedactionIncludesRelayToken(t *testing.T) {
	sf := newServersFixture(t)
	if err := sf.h.newRelayToken("other"); err != nil {
		t.Fatal(err)
	}
	tok := readEnvRaw(sf.h.relayEnvPath("other"))[RelayTokenVar]
	key1 := sf.h.ToolRedactionKey()
	vals, err := sf.h.ToolRedactionSet()
	if err != nil || !slices.Contains(vals, tok) {
		t.Errorf("the relay token isn't redacted: %v", err)
	}
	sf.h.newRelayToken("other")
	if sf.h.ToolRedactionKey() == key1 {
		t.Error("the redaction key didn't change with the token")
	}
	// Even with no other file of the instance.
	os.Remove(sf.h.envPath("other"))
	sf.h.newRelayToken("zzz")
	vals, _ = sf.h.ToolRedactionSet()
	if !slices.Contains(vals, readEnvRaw(sf.h.relayEnvPath("zzz"))[RelayTokenVar]) {
		t.Error("a relay env alone isn't read")
	}
}

// TestControlCertRenewalHygiene (review B-L5): a renewed control
// certificate's predecessor is owed (the tick revokes it); a leaf not
// signed by the pki_node CA is refused.
func TestControlCertRenewalHygiene(t *testing.T) {
	sf := newServersFixture(t)
	c1, _, err := sf.h.controlCert(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Make it due: rewrite it with a life nearly over.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: ControlCN}, NotBefore: time.Now().Add(-29 * 24 * time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, sf.ca.cert, &k.PublicKey, sf.ca.key)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	dir := filepath.Join(sf.data, "nodes")
	os.WriteFile(filepath.Join(dir, "control.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "control.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	c2, _, err := sf.h.controlCert(context.Background())
	if err != nil || c2.Leaf.SerialNumber.Cmp(big.NewInt(4242)) == 0 || c2.Leaf.SerialNumber.Cmp(c1.Leaf.SerialNumber) == 0 {
		t.Fatalf("renewal: %v", err)
	}
	if owed := sf.owed(); !slices.Contains(owed, ":"+VaultSerial(big.NewInt(4242))) {
		t.Errorf("owed %v", owed)
	}
	sf.h.drainOwed(context.Background(), "")
	if !slices.Contains(sf.ca.revokedList(), VaultSerial(big.NewInt(4242))) {
		t.Errorf("revoked %v", sf.ca.revokedList())
	}
	// A leaf from another CA (the answer's CA is the pinned one).
	sf2 := newServersFixture(t)
	sf2.h.SetNodeSigner(foreignLeafSigner{sf2.ca, newTestNodeCA(t)})
	if _, _, err := sf2.h.controlCert(context.Background()); err == nil || !strings.Contains(err.Error(), "isn't a pki_node client certificate") {
		t.Errorf("a foreign leaf: %v", err)
	}
}

// foreignLeafSigner signs with other but answers ca as the CA.
type foreignLeafSigner struct{ ca, other *testNodeCA }

func (f foreignLeafSigner) SignNode(ctx context.Context, role, cn, csr string) (*NodeCert, error) {
	nc, err := f.other.SignNode(ctx, role, cn, csr)
	if err == nil {
		nc.CA = f.ca.pem
	}
	return nc, err
}
func (f foreignLeafSigner) RevokeNode(ctx context.Context, s string) error { return nil }

// TestOfflineWhenLinkStatusUnreadable (review B-L7): no readable link
// status → offline at the next poll, the reason shown.
func TestOfflineWhenLinkStatusUnreadable(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	os.Remove(sf.link.path)
	sf.h.pollServer(context.Background(), "nas")
	if s, _ := sf.server("nas"); s.State != ServerOffline {
		t.Fatalf("state %s", s.State)
	}
	for _, v := range sf.h.Servers(context.Background()) {
		if v.ID == "nas" && !strings.Contains(v.Error, "unreadable") {
			t.Errorf("view %+v", v)
		}
	}
}

// TestRevokeRotatesWithoutTemplate (review B-M3): with the template gone,
// the instance's recorded clients (else every client tagged with its id)
// are deleted and its relay token replaced; a failure is a doctor
// problem, retried every tick.
func TestRevokeRotatesWithoutTemplate(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	sf.h.mu.Lock()
	sf.h.st.Instances["gone"] = state.Instance{ID: "gone", Template: "no-such-template", Server: "nas", KeycloakClients: []string{"gone", "gone-mcp"}}
	sf.h.noteServersLocked()
	sf.h.mu.Unlock()
	sf.h.newRelayToken("gone")
	old := sf.h.relayTokenSHA("gone")
	sf.idp.mu.Lock()
	sf.idp.deleteErr = errors.New("keycloak down")
	sf.idp.mu.Unlock()
	sf.h.RevokeServer(context.Background(), admin, "nas")
	if s, _ := sf.server("nas"); s.Revoke == nil || s.Revoke.Rotated {
		t.Fatalf("rotated with Keycloak failing: %+v", s.Revoke)
	}
	if in := sf.h.serversDoctorIn(); in == nil || !strings.Contains(in.NotRotated["nas"], "keycloak down") {
		t.Errorf("doctor input %+v", in)
	}
	sf.idp.mu.Lock()
	sf.idp.deleteErr = nil
	sf.idp.mu.Unlock()
	sf.h.serversTick(context.Background())
	s, _ := sf.server("nas")
	sf.idp.mu.Lock()
	deleted := strings.Join(sf.idp.deleted, ",")
	sf.idp.mu.Unlock()
	if !s.Revoke.Rotated || deleted != "gone:gone,gone-mcp:gone" || sf.h.relayTokenSHA("gone") == old {
		t.Errorf("rotation %+v deleted %s", s.Revoke, deleted)
	}
	if in := sf.h.serversDoctorIn(); in != nil && in.NotRotated["nas"] != "" {
		t.Error("the doctor problem stays")
	}
}

// TestClientsRecordedAtCreate (review B-M3): the instance's client ids
// are on its state entry from its create on.
func TestClientsRecordedAtCreate(t *testing.T) {
	f := newFixture(t)
	if err := f.h.CreateInstance("other", "other", nil); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	got := f.h.st.Instances["other"].KeycloakClients
	v := f.h.findLocked("other")
	f.h.mu.RUnlock()
	if len(got) != 1 || v == nil || got[0] != v.Manifest.Clients[0].ClientID {
		t.Errorf("recorded %v", got)
	}
	_ = linkdoc.FileName
}
