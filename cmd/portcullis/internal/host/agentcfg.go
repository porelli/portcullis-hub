package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

// AgentFile is the managed host's agent config (0600): its Portcullis,
// its id, the extra CA file and the service mode. No secret.
const AgentFile = "/etc/portcullis/agent.json"

// HostPrivateKeyFile is the host's ed25519 key (it signs the host's
// requests; never copied, logged or sent).
const HostPrivateKeyFile = "/etc/ssh/ssh_host_ed25519_key"

// AgentConfig is AgentFile.
type AgentConfig struct {
	Domain      string `json:"domain"`
	HostID      string `json:"host_id"`
	CAFile      string `json:"ca_file,omitempty"`
	ServiceNone bool   `json:"service_none,omitempty"`
	// PeopleURL overrides https://people.<domain>: the container
	// tests' fake Hub. Only a -tags sshtest CLI honours it; a release
	// binary refuses an agent.json that sets it.
	PeopleURL string `json:"people_url,omitempty"`
}

// LoadAgentConfig reads it.
func LoadAgentConfig(sys System) (*AgentConfig, error) {
	raw, err := sys.ReadFile(AgentFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (enroll this host first: portcullis host enroll)", AgentFile, err)
	}
	var c AgentConfig
	if err := cliapi.UnmarshalStrict(raw, &c); err != nil || !cliapi.ValidDomain(c.Domain) || !cliapi.ValidHostID(c.HostID) {
		return nil, fmt.Errorf("%s is invalid", AgentFile)
	}
	return &c, nil
}

func agentConfigBytes(c AgentConfig) []byte {
	b, _ := json.MarshalIndent(c, "", "  ")
	return append(b, '\n')
}

// HostSigner reads the host's ed25519 private key.
func HostSigner(sys System) (ssh.Signer, error) {
	raw, err := sys.ReadFile(HostPrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("the host's ed25519 key %s can't be read (run as root): %v", HostPrivateKeyFile, errors.Unwrap(err))
	}
	s, err := ssh.ParsePrivateKey(raw)
	if err != nil || s.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("%s isn't an ed25519 private key", HostPrivateKeyFile)
	}
	return s, nil
}

// HostPublicKey reads the host's ed25519 public key.
func HostPublicKey(sys System) (ssh.PublicKey, error) {
	raw, err := sys.ReadFile(HostKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", HostKeyFile, err)
	}
	k, _, err := cliapi.ParseAuthorizedKey(string(bytes.TrimSpace(raw)))
	if err != nil || k.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("%s isn't an ed25519 public key", HostKeyFile)
	}
	return k, nil
}

// signRequest adds the signed host-request headers (plan C6).
func signRequest(signer ssh.Signer, hostID string, now func() time.Time) func(*http.Request, []byte) error {
	return func(r *http.Request, body []byte) error {
		nb := make([]byte, 16)
		if _, err := rand.Read(nb); err != nil {
			return err
		}
		nonce := base64.RawURLEncoding.EncodeToString(nb)
		tm := now().UTC().Format(time.RFC3339)
		msg := cliapi.HostRequestMessage(hostID, r.Method, r.URL.Path, r.URL.RawQuery, tm, nonce, body)
		sig, err := sshsig.Sign(bytes.NewReader(msg), signer, sshsig.HashSHA512, cliapi.NSHostRequest)
		if err != nil {
			return err
		}
		r.Header.Set(cliapi.HeaderHostID, hostID)
		r.Header.Set(cliapi.HeaderHostTime, tm)
		r.Header.Set(cliapi.HeaderHostNonce, nonce)
		r.Header.Set(cliapi.HeaderHostSignature, cliapi.EncodeSignatureHeader(sshsig.Armor(sig)))
		return nil
	}
}

// Client is how the host talks to its Portcullis.
type Client interface {
	Do(ctx context.Context, method, path string, body any, out any, extra func(*http.Request, []byte) error) (int, error)
}
