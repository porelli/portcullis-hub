package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/vpn"
)

// serversCA signs node certificates for the Servers route tests.
type serversCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  string
}

func newServersCA(t *testing.T) *serversCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Node CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &serversCA{key: k, cert: c, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (c *serversCA) SignNode(_ context.Context, role, cn, csrPEM string) (*hub.NodeCert, error) {
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil {
		return nil, errors.New("no CSR")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return &hub.NodeCert{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Serial: tpl.SerialNumber.Text(16),
		CA: c.pem, NotAfter: tpl.NotAfter}, nil
}

func (c *serversCA) RevokeNode(context.Context, string) error { return nil }

// serversEnv is an instEnv with Servers on (link up, link_doc, a relay
// image, a node signer) and a fresh-auth verifier on the Hub listener.
type serversEnv struct {
	*instEnv
	fa   *fakeFreshAuth
	root string
}

func newServersEnv(t *testing.T) *serversEnv {
	t.Helper()
	dir := t.TempDir()
	_, linkPub, _ := servers.NewWGKeyPair()
	status := filepath.Join(dir, "status.json")
	b, _ := json.Marshal(vpn.Status{Version: vpn.StatusVersion, Written: time.Now().UTC(), Mode: "apps", Edge: vpn.RoleStatus{OK: true},
		Link: &vpn.LinkState{OK: true, PublicKey: linkPub, Port: 51821, Peers: []vpn.LinkPeer{}}})
	os.WriteFile(status, b, 0o600)
	linkDoc := filepath.Join(dir, "link-doc")
	os.MkdirAll(linkDoc, 0o750)
	root := t.TempDir()
	e := newInstEnvOpts(t, root, instEnvOpts{cfg: func(c *hub.Config) {
		c.LinkDocDir, c.LinkDocGID, c.VPNStatusFile = linkDoc, os.Getgid(), status
		c.RelayImage = "ghcr.io/porelli/portcullis-relay:edge"
		if c.Domain == "" {
			c.Domain = "example.org"
		}
	}})
	e.s.Hub.SetNodeSigner(newServersCA(t))
	fa := &fakeFreshAuth{}
	e.s.Hub.SetFreshAuth(hub.ListenerHub, fa)
	e.s.Hub.SetFreshAuthReadyForTest(true)
	// An enrolment waits for its join until the code expires: stopped
	// before the env's cleanup waits for the Hub's background work.
	t.Cleanup(func() { e.s.Hub.StopServerEnrol("nas", directory.Human("root"), "") })
	return &serversEnv{instEnv: e, fa: fa, root: root}
}

const proofJSON = `"code":"c","code_verifier":"v","nonce":"n"`

// serverRoutes are every Servers route (Hub listener only).
var serverRoutes = []struct{ method, path, body string }{
	{"GET", "/api/servers", ""},
	{"POST", "/api/servers", `{"id":"nas","name":"NAS",` + proofJSON + `}`},
	{"GET", "/api/servers/nas", ""},
	{"DELETE", "/api/servers/nas", `{"confirm":"nas",` + proofJSON + `}`},
	{"GET", "/api/servers/nas/op", ""},
	{"POST", "/api/servers/nas/op/stop", `{}`},
	{"PUT", "/api/servers/nas/settings", `{"name":"x"}`},
	{"PUT", "/api/servers/primary/settings", `{"backup_schedule":{"mode":"daily","hour":3}}`},
	{"POST", "/api/servers/nas/revoke", `{"confirm":"nas",` + proofJSON + `}`},
	{"POST", "/api/instances/grafana/move", `{"server":"nas"}`},
	{"POST", "/api/instances/grafana/move/undo", `{"confirm":"grafana",` + proofJSON + `}`},
	{"DELETE", "/api/instances/grafana/move-leftover", `{"confirm":"grafana",` + proofJSON + `}`},
	{"POST", "/api/instances/grafana/quarantine/lift", `{` + proofJSON + `}`},
}

// TestServersRoutesAdminOnly: delegates, non-admins and anonymous
// callers get 403 and reach nothing; the people listener has none of
// them; a cross-origin write is refused by the CSRF guard.
func TestServersRoutesAdminOnly(t *testing.T) {
	e := newServersEnv(t)
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/invite", `{"group":"helpers"}`, 200)
	for _, user := range []string{"dana", "nobody", ""} {
		for _, r := range serverRoutes {
			if code, b := e.do(t, user, r.method, r.path, r.body); code != 403 {
				t.Errorf("%q %s %s = %d %s, want 403", user, r.method, r.path, code, b)
			}
		}
	}
	for _, r := range serverRoutes {
		if resp, _ := doAs(t, e.ppl, "root", r.method, r.path, r.body); resp.StatusCode != 404 && resp.StatusCode != 405 {
			t.Errorf("people %s %s = %d, want 404", r.method, r.path, resp.StatusCode)
		}
	}
	if a := e.auditActions(t, "server."); len(a) != 0 {
		t.Fatalf("refused requests reached the Hub: %v", a)
	}
	if e.fa.calls.Load() != 0 {
		t.Errorf("a refused caller's proof was checked")
	}
	req, _ := http.NewRequest("POST", e.hub.URL+"/api/servers", strings.NewReader(serverRoutes[1].body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("cross-origin add = %d, want 403 (CSRF)", resp.StatusCode)
	}
}

// TestAddServerNoStore: a stale or missing fresh sign-in is 403 (audited,
// nothing added); a fresh one answers 201 with the code once, no-store;
// the list and the detail never carry it.
func TestAddServerNoStore(t *testing.T) {
	e := newServersEnv(t)
	e.fa.err = &freshauth.Error{Reason: "too old"}
	resp, b := doAs(t, e.hub, "root", "POST", "/api/servers", `{"id":"nas","name":"NAS",`+proofJSON+`}`)
	if resp.StatusCode != 403 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("stale proof = %d %s", resp.StatusCode, b)
	}
	if code, _ := e.do(t, "root", "GET", "/api/servers/nas", ""); code != 404 {
		t.Errorf("added without a fresh sign-in: %d", code)
	}
	if a := e.auditActions(t, "server.add"); len(a) != 1 || !strings.HasPrefix(a[0], "server.add:refused:root") {
		t.Errorf("audit %v", a)
	}
	e.fa.err = nil
	resp, b = doAs(t, e.hub, "root", "POST", "/api/servers", `{"id":"nas","name":"NAS",`+proofJSON+`}`)
	if resp.StatusCode != 201 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("add = %d %q %s", resp.StatusCode, resp.Header.Get("Cache-Control"), b)
	}
	var got addedServer
	json.Unmarshal([]byte(b), &got)
	if got.Code == "" || got.Op != "server_enrol" || got.OpID == "" || got.Poll != "/api/servers/nas/op?op_id="+got.OpID || got.ExpiresAt.IsZero() {
		t.Fatalf("answer %+v", got)
	}
	for _, p := range []string{"/api/servers", "/api/servers/nas", "/api/servers/nas/op"} {
		resp, body := doAs(t, e.hub, "root", "GET", p, "")
		if resp.Header.Get("Cache-Control") != "no-store" || strings.Contains(body, got.Code) {
			t.Errorf("%s = %d %q: carries the code or is cacheable", p, resp.StatusCode, resp.Header.Get("Cache-Control"))
		}
	}
	for _, a := range readAudit(t, e.audit) {
		if strings.Contains(a.Detail, got.Code) {
			t.Errorf("audit carries the code: %+v", a)
		}
	}
}

// TestRevokeNeedsFreshAuthAndTypedID: revoke and remove need the typed
// server id and a fresh sign-in; neither reaches the Hub otherwise.
func TestRevokeNeedsFreshAuthAndTypedID(t *testing.T) {
	e := newServersEnv(t)
	mustDo(t, e.hub, "root", "POST", "/api/servers", `{"id":"nas","name":"NAS",`+proofJSON+`}`, 201)
	for _, r := range []struct{ method, path string }{{"POST", "/api/servers/nas/revoke"}, {"DELETE", "/api/servers/nas"}} {
		if code, b := e.do(t, "root", r.method, r.path, `{"confirm":"nasx",`+proofJSON+`}`); code != 400 || !strings.Contains(b, "type the server id") {
			t.Errorf("%s %s mistyped = %d %s", r.method, r.path, code, b)
		}
		if code, b := e.do(t, "root", r.method, r.path, `{"confirm":"nas"}`); code != 403 {
			e.fa.err = nil
			t.Errorf("%s %s without a proof = %d %s", r.method, r.path, code, b)
		}
		e.fa.err = &freshauth.Error{Reason: "too old"}
		if code, b := e.do(t, "root", r.method, r.path, `{"confirm":"nas",`+proofJSON+`}`); code != 403 {
			t.Errorf("%s %s stale = %d %s", r.method, r.path, code, b)
		}
		e.fa.err = nil
	}
	if s, err := e.s.Hub.ServerDetailOf(context.Background(), "nas"); err != nil || s.State == hub.ServerRevoked {
		t.Fatalf("revoked without a fresh sign-in: %+v %v", s, err)
	}
	if code, b := e.do(t, "root", "POST", "/api/servers/nas/revoke", `{"confirm":"nas",`+proofJSON+`}`); code != 200 {
		t.Fatalf("revoke = %d %s", code, b)
	}
	if a := e.auditActions(t, "server.revoked"); len(a) == 0 || !strings.Contains(strings.Join(a, " "), "server.revoked:ok:root:nas") {
		t.Errorf("audit %v", a)
	}
}

// TestServerViewHasNoSecrets: the list, the detail and the op record
// carry no join-code secret, bootstrap key, WireGuard key, serial or
// SPKI.
func TestServerViewHasNoSecrets(t *testing.T) {
	e := newServersEnv(t)
	mustDo(t, e.hub, "root", "POST", "/api/servers", `{"id":"nas","name":"NAS",`+proofJSON+`}`, 201)
	st, err := state.Load(filepath.Join(e.root, "data", "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	stored := st.Servers["nas"]
	secrets := []string{stored.WGPublicKey, stored.Enrol.SecretSHA256, stored.Enrol.BootstrapPub}
	for _, p := range []string{"/api/servers", "/api/servers/nas", "/api/servers/primary"} {
		code, body := e.do(t, "root", "GET", p, "")
		if code != 200 {
			t.Fatalf("%s = %d %s", p, code, body)
		}
		for _, s := range secrets {
			if s != "" && strings.Contains(body, s) {
				t.Errorf("%s carries %q", p, s)
			}
		}
		for _, k := range []string{"serial", "spki", "secret", "wg_public_key", "enrol", "bootstrap"} {
			if strings.Contains(body, `"`+k+`":`) || strings.Contains(body, `_`+k+`":`) {
				t.Errorf("%s has a %s field: %s", p, k, body)
			}
		}
	}
}

// TestMCPNoJoinCodeTool: no tool adds, revokes or removes a server, and
// the server tools' twins are the read and settings routes.
func TestMCPNoJoinCodeTool(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	for _, tl := range e.s.tools(ScopeAdmin) {
		for _, r := range append([]string{tl.Twin}, tl.AlsoTwins...) {
			if r == "POST /api/servers" || r == "POST /api/servers/{id}/revoke" || r == "DELETE /api/servers/{id}" {
				t.Errorf("tool %s mirrors %s", tl.Name, r)
			}
		}
	}
	for _, r := range []string{"POST /api/servers", "POST /api/servers/{id}/revoke", "DELETE /api/servers/{id}"} {
		if serverNoToolRoutes[r] == "" {
			t.Errorf("%s has no no-tool reason", r)
		}
	}
	names := map[string]ToolClass{}
	for _, tl := range e.s.tools(ScopeAdmin) {
		names[tl.Name] = tl.Class
	}
	for n, c := range map[string]ToolClass{"list_servers": ClassRead, "get_server": ClassRead, "move_instance": ClassDestructive, "set_backup_schedule": ClassWrite} {
		if got, ok := names[n]; !ok || got != c {
			t.Errorf("tool %s: %v %v, want %v", n, got, ok, c)
		}
	}
}

// TestServerSettingsRoutes: name, Local networks (a list or null for the
// defaults) and the schedule; the primary takes the schedule only.
func TestServerSettingsRoutes(t *testing.T) {
	e := newServersEnv(t)
	mustDo(t, e.hub, "root", "POST", "/api/servers", `{"id":"nas","name":"NAS",`+proofJSON+`}`, 201)
	for _, c := range []struct {
		path, body string
		code       int
		want       string
	}{
		{"/api/servers/nas/settings", `{"name":"Attic NAS","local_networks":["192.168.1.0/24"],"backup_schedule":{"mode":"weekly","hour":4,"weekday":6}}`, 200, `"name":"Attic NAS"`},
		{"/api/servers/nas/settings", `{"local_networks":null}`, 200, `"local_networks_default":true`},
		{"/api/servers/nas/settings", `{"local_networks":["0.0.0.0/0"]}`, 400, "local networks"},
		{"/api/servers/nas/settings", `{"backup_schedule":{"mode":"hourly","hour":1}}`, 400, "mode"},
		{"/api/servers/nas/settings", `{"backup_schedule":{"mode":"daily","hour":24}}`, 400, "hour"},
		{"/api/servers/nas/settings", `{"backup_schedule":{"mode":"daily","hour":1,"weekday":3}}`, 400, "weekly schedule only"},
		{"/api/servers/nas/settings", `{"x":1}`, 400, "body must be"},
		{"/api/servers/primary/settings", `{"backup_schedule":{"mode":"daily","hour":2}}`, 200, `"mode":"daily"`},
		{"/api/servers/primary/settings", `{"name":"x"}`, 400, "backup schedule only"},
		{"/api/servers/ghost/settings", `{"name":"x"}`, 404, "no server"},
	} {
		code, b := e.do(t, "root", "PUT", c.path, c.body)
		if code != c.code || !strings.Contains(b, c.want) {
			t.Errorf("PUT %s %s = %d %q, want %d %q", c.path, c.body, code, b, c.code, c.want)
		}
	}
	if a := e.auditActions(t, "server.settings"); len(a) < 3 {
		t.Errorf("audit %v", a)
	}
}

// TestMoveRoutesNeedFresh: undo, leftover removal and the quarantine
// lift need a fresh sign-in (403 and audited without one, the Hub's
// action never runs); a move to an unknown server and forgetting an
// instance that isn't orphaned are refused synchronously.
func TestMoveRoutesNeedFresh(t *testing.T) {
	e := newServersEnv(t)
	for _, r := range []struct{ method, path, body, action string }{
		{"POST", "/api/instances/grafana/move/undo", `{"confirm":"grafana"}`, "instance.move_undo"},
		{"DELETE", "/api/instances/grafana/move-leftover", `{"confirm":"grafana"}`, "instance.move_leftover_removed"},
		{"POST", "/api/instances/grafana/quarantine/lift", `{}`, "server.quarantine_lift"},
	} {
		resp, b := doAs(t, e.hub, "root", r.method, r.path, r.body)
		if resp.StatusCode != 403 || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s = %d %s", r.method, r.path, resp.StatusCode, b)
		}
		a := readAudit(t, e.audit)
		found := false
		for _, x := range a {
			if x.Action == r.action && x.Result != "ok" && strings.Contains(x.Detail, "fresh sign-in refused") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no refused audit entry", r.action)
		}
	}
	if code, b := e.do(t, "root", "POST", "/api/instances/grafana/move", `{"server":"ghost"}`); code < 400 || code >= 500 {
		t.Errorf("move to an unknown server = %d %s", code, b)
	}
	if code, b := e.do(t, "root", "POST", "/api/instances/grafana/move", `{}`); code != 400 {
		t.Errorf("move without a server = %d %s", code, b)
	}
	if code, b := e.do(t, "root", "DELETE", "/api/instances/grafana?forget=1", `{"confirm":"grafana"}`); code != 409 {
		t.Errorf("forget a live instance = %d %s", code, b)
	}
}
