package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

func hostSigned(t *testing.T, srv *httptest.Server, key ssh.Signer, method, path string, body []byte) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	ts := time.Now().UTC().Format(time.RFC3339)
	nb := make([]byte, 16)
	rand.Read(nb)
	nonce := base64.RawURLEncoding.EncodeToString(nb)
	sig, err := sshsig.Sign(bytes.NewReader(cliapi.HostRequestMessage("web-9", method, req.URL.Path, req.URL.RawQuery, ts, nonce, body)), key, sshsig.HashSHA512, cliapi.NSHostRequest)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(ProxySecretHeader, testCLISecret)
	req.Header.Set(cliapi.HeaderCLI, cliapi.CLIHeaderValue("1.2.3"))
	req.Header.Set(cliapi.HeaderHostID, "web-9")
	req.Header.Set(cliapi.HeaderHostTime, ts)
	req.Header.Set(cliapi.HeaderHostNonce, nonce)
	req.Header.Set(cliapi.HeaderHostSignature, cliapi.EncodeSignatureHeader(sshsig.Armor(sig)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestReportStrict256KiB(t *testing.T) {
	srv, h := newCLIServer(t)
	enableSSH(t, h)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewSignerFromKey(priv)
	if err := h.PinHostForTest("web-9", cliapi.NormalAuthorizedKey(key.PublicKey())); err != nil {
		t.Fatal(err)
	}
	good := `{"version":1,"host_id":"web-9","serial":1,"time":"2026-11-15T09:00:00Z","sshd_version":"OpenSSH_9.6p1","applied":true,"error":"",` +
		`"files":{"../../etc/shadow":"x"},"effective":{},"accounts":{"present":[],"missing":[],"locked":[],"removed":[]},"findings":[],"authorized_keys_shared":0,` +
		`"logins":{"portcullis":0,"breakglass":0,"breakglass_last":{"time":"","from":""}}}`
	if r, b := hostSigned(t, srv, key, "POST", "/api/cli/v1/hosts/report", []byte(good)); r.StatusCode != 204 {
		t.Fatalf("good report: %d %s", r.StatusCode, b)
	}
	rep, err := h.LastHostReport("web-9")
	if err != nil || rep.Report.Files["../../etc/shadow"] != "x" {
		t.Errorf("a path in a field is stored as an opaque string: %+v %v", rep, err)
	}
	unknown := strings.Replace(good, `"version":1`, `"version":1,"x":1`, 1)
	if r, _ := hostSigned(t, srv, key, "POST", "/api/cli/v1/hosts/report", []byte(unknown)); r.StatusCode != 400 {
		t.Errorf("unknown field: %d", r.StatusCode)
	}
	other := strings.Replace(good, `"host_id":"web-9"`, `"host_id":"web-1"`, 1)
	if r, _ := hostSigned(t, srv, key, "POST", "/api/cli/v1/hosts/report", []byte(other)); r.StatusCode != 400 {
		t.Errorf("another host's report: %d", r.StatusCode)
	}
	big := strings.Replace(good, `"error":""`, `"error":"`+strings.Repeat("a", 257<<10)+`"`, 1)
	if r, _ := hostSigned(t, srv, key, "POST", "/api/cli/v1/hosts/report", []byte(big)); r.StatusCode != 413 {
		t.Errorf("257 KiB: %d", r.StatusCode)
	}
	// Unsigned: refused.
	r, _ := cliDo(t, srv, "POST", "/api/cli/v1/hosts/report", good, nil)
	if r.StatusCode != 403 {
		t.Errorf("unsigned: %d", r.StatusCode)
	}
	// The bundle route: 204 / bad since.
	if r, _ := hostSigned(t, srv, key, "GET", "/api/cli/v1/hosts/bundle?since=x", nil); r.StatusCode != 400 {
		t.Errorf("since=x: %d", r.StatusCode)
	}
}
