package cliapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHSIG namespaces (contract §18.6, §18.11).
const (
	NSKeyProof    = "portcullis-ssh-certificate@v1"
	NSHostRequest = "portcullis-host-request@v1"
	NSHostEnrol   = "portcullis-host-enrol@v1"
)

// Host request headers (plan C6).
const (
	HeaderHostID        = "Portcullis-Host-Id"
	HeaderHostTime      = "Portcullis-Host-Time"
	HeaderHostNonce     = "Portcullis-Host-Nonce"
	HeaderHostSignature = "Portcullis-Host-Signature"
)

// SKKeysAccepted is spike S1's outcome: Vault 2.2.1 signs the two FIDO key
// types (docs/superpowers/spikes/2026-11-15-cli-ssh-results.md).
var SKKeysAccepted = true

// AcceptedKeyType reports whether a public key type may be certified.
// RSA, DSA, ECDSA P-384/521 and everything else are refused.
func AcceptedKeyType(t string, sk bool) bool {
	switch t {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256:
		return true
	case ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		return sk
	}
	return false
}

// ParseAuthorizedKey parses one authorized_keys line (no options) and
// returns the key and its normalised form "<type> <base64>" (no comment).
// Errors never quote the input.
func ParseAuthorizedKey(s string) (ssh.PublicKey, string, error) {
	if len(s) > 8192 || strings.ContainsAny(s, "\r\n") {
		return nil, "", errors.New("not a single public key line")
	}
	k, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil || len(opts) > 0 || len(rest) > 0 {
		return nil, "", errors.New("not a public key")
	}
	if _, isCert := k.(*ssh.Certificate); isCert {
		return nil, "", errors.New("a certificate is not a public key")
	}
	return k, NormalAuthorizedKey(k), nil
}

// NormalAuthorizedKey is "<type> <base64>" for a key.
func NormalAuthorizedKey(k ssh.PublicKey) string {
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

// Fingerprint is ssh.FingerprintSHA256 ("SHA256:…").
func Fingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// SHA256Hex is the hex SHA-256 of b.
func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func canonical(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only strings: can't fail
	}
	return b
}

// KeyProofMessage is the canonical JSON the CLI signs to prove it holds the
// key (contract §18.6). authorizedKey is the normalised "<type> <base64>".
func KeyProofMessage(domain, nonce, code, authorizedKey string) []byte {
	return canonical(struct {
		Domain     string `json:"domain"`
		Nonce      string `json:"nonce"`
		CodeSHA256 string `json:"code_sha256"`
		PublicKey  string `json:"public_key"`
	}{domain, nonce, SHA256Hex([]byte(code)), authorizedKey})
}

// HostRequestMessage is the canonical JSON a managed host signs for every
// request (plan C6). body is the raw request body (empty for a GET).
func HostRequestMessage(hostID, method, path, query, tm, nonce string, body []byte) []byte {
	return canonical(struct {
		HostID     string `json:"host_id"`
		Method     string `json:"method"`
		Path       string `json:"path"`
		Query      string `json:"query"`
		Time       string `json:"time"`
		Nonce      string `json:"nonce"`
		BodySHA256 string `json:"body_sha256"`
	}{hostID, method, path, query, tm, nonce, SHA256Hex(body)})
}

// EnrolMessage is the canonical JSON the host key signs over the
// enrolment challenge (plan C4).
func EnrolMessage(domain, hostID, challenge string) []byte {
	return canonical(struct {
		Domain    string `json:"domain"`
		HostID    string `json:"host_id"`
		Challenge string `json:"challenge"`
	}{domain, hostID, challenge})
}

// EncodeSignatureHeader turns SSHSIG armour into a one-line header value
// (newlines as the two characters `\n`); DecodeSignatureHeader reverses it.
func EncodeSignatureHeader(armor []byte) string {
	return strings.ReplaceAll(strings.TrimRight(string(armor), "\n"), "\n", `\n`)
}

// DecodeSignatureHeader is the inverse of EncodeSignatureHeader.
func DecodeSignatureHeader(h string) []byte {
	return []byte(strings.ReplaceAll(h, `\n`, "\n") + "\n")
}

// EnrolCodePrefix starts every enrolment code.
const EnrolCodePrefix = "pcenrol1."

// EnrolCode is the one-time host enrolment code (plan C5).
type EnrolCode struct {
	Domain     string    `json:"d"`
	HostID     string    `json:"h"`
	HostGroups []string  `json:"g"`
	UserCAFP   string    `json:"ufp"`
	HostCAFP   string    `json:"hfp"`
	Secret     string    `json:"s"`
	Expires    time.Time `json:"exp"`
}

// String encodes the code. The result is a secret.
func (c EnrolCode) String() string {
	return EnrolCodePrefix + base64.RawURLEncoding.EncodeToString(canonical(c))
}

// ParseEnrolCode decodes and validates a code. Errors never quote it.
func ParseEnrolCode(s string) (*EnrolCode, error) {
	s = strings.TrimSpace(s)
	if len(s) > 4096 || !strings.HasPrefix(s, EnrolCodePrefix) {
		return nil, errors.New("not a Portcullis enrolment code")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s[len(EnrolCodePrefix):])
	if err != nil {
		return nil, errors.New("enrolment code: bad encoding")
	}
	var c EnrolCode
	if err := UnmarshalStrict(raw, &c); err != nil {
		return nil, errors.New("enrolment code: bad content")
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("enrolment code: %w", err)
	}
	return &c, nil
}

func (c EnrolCode) validate() error {
	switch {
	case c.Domain == "" || strings.ContainsAny(c.Domain, "/:@ "):
		return errors.New("bad domain")
	case !ValidHostID(c.HostID):
		return errors.New("bad host id")
	case len(c.HostGroups) == 0 || len(c.HostGroups) > 64:
		return errors.New("bad host groups")
	case !strings.HasPrefix(c.UserCAFP, "SHA256:") || !strings.HasPrefix(c.HostCAFP, "SHA256:"):
		return errors.New("bad CA fingerprint")
	case c.Expires.IsZero():
		return errors.New("no expiry")
	}
	for _, g := range c.HostGroups {
		if !ValidHostGroupID(g) {
			return errors.New("bad host groups")
		}
	}
	sec, err := base64.RawURLEncoding.Strict().DecodeString(c.Secret)
	if err != nil || len(sec) != 32 {
		return errors.New("bad secret")
	}
	return nil
}
