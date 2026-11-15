package hub

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEnrollNodesWire: POST /internal/nodes/sign|revoke with the invite
// bearer and the contract's bodies; an error answer is 502 with enroll's
// message, never the secret.
func TestEnrollNodesWire(t *testing.T) {
	secret := strings.Repeat("s", 40)
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		got = append(got, r.URL.Path+":"+body["role"]+body["common_name"]+body["serial"])
		switch r.URL.Path {
		case "/internal/nodes/sign":
			if body["role"] == "node-link" {
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"role refused"}`))
				return
			}
			w.WriteHeader(201)
			w.Write([]byte(`{"certificate":"C","serial":"0a:1b","not_after":"2026-12-15T00:00:00Z","ca":"CA"}`))
		case "/internal/nodes/revoke":
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	sf := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(sf, []byte(secret+"\n"), 0o600)
	e, err := NewEnrollNodes(srv.URL+"/internal/invites", sf)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := e.SignNode(context.Background(), RoleNodeWorker, "nas.node.portcullis.internal", "CSR")
	if err != nil || nc.Serial != "0a:1b" || nc.Certificate != "C" || nc.CA != "CA" || nc.NotAfter.IsZero() {
		t.Fatalf("%+v %v", nc, err)
	}
	if err := e.RevokeNode(context.Background(), "0a:1b"); err != nil {
		t.Fatal(err)
	}
	_, err = e.SignNode(context.Background(), "node-link", "link.control", "CSR")
	if errStatus(err) != 502 || !strings.Contains(err.Error(), "role refused") || strings.Contains(err.Error(), secret) {
		t.Errorf("refusal: %v", err)
	}
	if strings.Join(got, ",") != "/internal/nodes/sign:node-workernas.node.portcullis.internal,/internal/nodes/revoke:0a:1b,/internal/nodes/sign:node-linklink.control" {
		t.Errorf("calls %v", got)
	}
	os.WriteFile(sf, []byte("short"), 0o600)
	if err := e.RevokeNode(context.Background(), "x"); err == nil {
		t.Error("a short secret was used")
	}
}

// TestControlCertIssuedOnceAndRenewed: the control certificate is signed
// once (key 0600), reused while more than ⅓ of its life is left, and
// renewDue is the ⅓ rule.
func TestControlCertIssuedOnceAndRenewed(t *testing.T) {
	sf := newServersFixture(t)
	c1, ca, err := sf.h.controlCert(context.Background())
	if err != nil || ca == nil || !ca.Equal(sf.ca.cert) || c1.Leaf.Subject.CommonName != ControlCN || len(c1.Certificate) != 2 {
		t.Fatalf("%v", err)
	}
	if _, _, err := sf.h.controlCert(context.Background()); err != nil || len(sf.ca.signs) != 1 {
		t.Errorf("signed again: %v %v", sf.ca.signs, err)
	}
	if fi, err := os.Stat(filepath.Join(sf.data, "nodes", "control.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key %v %v", fi, err)
	}
	now := time.Now()
	c := &x509.Certificate{NotBefore: now.Add(-20 * 24 * time.Hour), NotAfter: now.Add(10*24*time.Hour + time.Hour)}
	if renewDue(c, now) {
		t.Error("due with more than a third left")
	}
	c.NotAfter = now.Add(9 * 24 * time.Hour)
	if !renewDue(c, now) {
		t.Error("not due with less than a third left")
	}
}
