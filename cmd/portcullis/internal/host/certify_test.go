package host

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/portcullis/hub/cmd/portcullis/internal/api"
	"github.com/portcullis/hub/cmd/portcullis/internal/login"
	"github.com/portcullis/hub/cmd/portcullis/internal/loopback"
	"github.com/portcullis/hub/internal/cliapi"
)

func TestCertifyNeedsAdminMethod(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/cli/v1/config", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(cliapi.Config{API: 1, Domain: "example.org", Issuer: "https://auth.example.org/realms/portcullis",
			AuthorizeURL: "https://auth.example.org/realms/portcullis/protocol/openid-connect/auth", ClientID: "portcullis-cli", RedirectPorts: []int{38917, 38918, 38919}})
	})
	var gotMethod string
	mux.HandleFunc("POST /api/cli/v1/ssh/host-certificates", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"error":"signing a host key needs a security key or a YubiKey certificate sign-in: use --method security_key"}`))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	old := loopback.Ports
	var ps []int
	for i := 0; i < 3; i++ {
		ln, _ := net.Listen("tcp4", "127.0.0.1:0")
		ps = append(ps, ln.Addr().(*net.TCPAddr).Port)
		ln.Close()
	}
	loopback.Ports = ps
	defer func() { loopback.Ports = old }()
	key, _ := caKey(t)
	kf := filepath.Join(t.TempDir(), "ssh_host_ed25519_key.pub")
	os.WriteFile(kf, []byte(key+"\n"), 0o644)
	o := CertifyOptions{HostGroup: "web", KeyFile: kf, Names: []string{"web-9.lab.example.org"}, Login: login.Options{Domain: "example.org", Version: "1.0.0",
		PeopleURL: srv.URL, HTTP: srv.Client(), Stderr: io.Discard, AllowAuthorizeHost: "auth.example.org", OpenBrowser: func(u string) error {
			p, _ := url.Parse(u)
			gotMethod = p.Query().Get("pc_method")
			go func() {
				time.Sleep(20 * time.Millisecond)
				resp, err := http.Get(p.Query().Get("redirect_uri") + "?state=" + url.QueryEscape(p.Query().Get("state")) + "&code=c")
				if err == nil {
					resp.Body.Close()
				}
			}()
			return nil
		}}}
	err := Certify(context.Background(), o)
	if api.ExitCode(err) != api.ExitRefused {
		t.Errorf("err %v (%d)", err, api.ExitCode(err))
	}
	if gotMethod != "security_key" {
		t.Errorf("pc_method %q", gotMethod)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(kf), "ssh_host_ed25519_key-cert.pub")); err == nil {
		t.Error("a certificate file was written")
	}
}
