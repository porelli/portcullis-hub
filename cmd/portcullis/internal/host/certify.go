package host

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/cmd/portcullis/internal/api"
	"github.com/portcullis/hub/cmd/portcullis/internal/login"
	"github.com/portcullis/hub/internal/cliapi"
)

// CertifyOptions are `portcullis host certify`'s flags.
type CertifyOptions struct {
	Login     login.Options // Domain, Method, CAFile, Version, …
	HostGroup string
	KeyFile   string
	Names     []string
}

// Certify signs an unmanaged host's key (plan C31): an administrator's
// fresh security_key / yubikey_cert sign-in in the browser; the
// certificate is written next to the key (<key>-cert.pub).
func Certify(ctx context.Context, o CertifyOptions) error {
	if !cliapi.ValidHostGroupID(o.HostGroup) || len(o.Names) == 0 {
		return api.Errorf(api.ExitUsage, "--host-group and at least one --name are required")
	}
	for _, n := range o.Names {
		if !cliapi.ValidHostName(n) {
			return api.Errorf(api.ExitUsage, "%q isn't a host name or address", api.Printable(n))
		}
	}
	raw, err := os.ReadFile(o.KeyFile)
	if err != nil {
		return api.Errorf(api.ExitUsage, "--key: %v", err)
	}
	pub, norm, err := cliapi.ParseAuthorizedKey(strings.TrimSpace(string(raw)))
	if err != nil || pub.Type() != ssh.KeyAlgoED25519 {
		return api.Errorf(api.ExitUsage, "--key must be the host's ed25519 public key (ssh_host_ed25519_key.pub)")
	}
	lo := o.Login
	if lo.Method == "" {
		lo.Method = "security_key"
	}
	c, err := lo.Client(lo.CAFile)
	if err != nil {
		return err
	}
	cfg, err := login.Discover(ctx, &lo, c)
	if err != nil {
		return err
	}
	si, err := login.DoSignIn(ctx, &lo, cfg)
	if err != nil {
		return err
	}
	var ans cliapi.HostCertAnswer
	req := cliapi.HostCertRequest{Code: si.Code, CodeVerifier: si.Verifier, Nonce: si.Nonce, RedirectURI: si.RedirectURI, HostGroup: o.HostGroup, PublicKey: norm, Names: o.Names}
	if _, err := c.Do(ctx, http.MethodPost, "/api/cli/v1/ssh/host-certificates", req, &ans, nil); err != nil {
		return err
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ans.Certificate))
	cert, ok := k.(*ssh.Certificate)
	if err != nil || !ok || cert.CertType != ssh.HostCert || string(cert.Key.Marshal()) != string(pub.Marshal()) {
		return errors.New("the server answered a certificate that isn't a host certificate for this key")
	}
	out := strings.TrimSuffix(o.KeyFile, ".pub") + "-cert.pub"
	if err := os.WriteFile(out, []byte(strings.TrimSpace(ans.Certificate)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("Wrote %s (valid until %s). Add HostCertificate %s to sshd_config and reload sshd.\n", out, ans.ValidBefore.Local().Format("2006-01-02"), out)
	return nil
}
