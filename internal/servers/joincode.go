package servers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/vpn"
)

// JoinCodePrefix starts every join code of this version (contract §17;
// pre-flight P27: SSH part 2 bumps it to pcj2, with no reader of pcj1
// then).
const JoinCodePrefix = "pcj1."

// JoinCodeVersion is the payload's v.
const JoinCodeVersion = 1

// MaxJoinCode bounds a join code's length before anything decodes it.
const MaxJoinCode = 2048

// JoinCode is a join code's payload (contract §17): the link endpoint
// (<host>:<port>) and public key, the server id, its tunnel address, the
// bootstrap WireGuard private key, the pki_node CA's sha256 (hex, of the
// certificate DER; pre-flight P5) and the 256-bit enrolment secret
// (base64url, no padding). The Hub stays authoritative for the network
// parameters (PUT /v1/network), so the code carries none (P6).
//
// BootstrapKey and Secret are secrets: String and GoString redact them,
// so a code never prints by accident; Encode is the only way out.
type JoinCode struct {
	V            int        `json:"v"`
	Endpoint     string     `json:"endpoint"`
	LinkPub      string     `json:"link_pub"`
	ServerID     string     `json:"server_id"`
	TunnelIP     netip.Addr `json:"tunnel_ip"`
	BootstrapKey string     `json:"bootstrap_key"`
	CASHA256     string     `json:"ca_sha256"`
	Secret       string     `json:"secret"`
}

// String redacts the secrets.
func (c JoinCode) String() string {
	return fmt.Sprintf("join code {v:%d endpoint:%s server_id:%s tunnel_ip:%s bootstrap_key:<redacted> secret:<redacted>}", c.V, c.Endpoint, c.ServerID, c.TunnelIP)
}

// GoString redacts the secrets (%#v).
func (c JoinCode) GoString() string { return c.String() }

// Encode is "pcj1." + base64url (no padding) of the JSON payload.
func (c JoinCode) Encode() string {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err) // plain strings and an Addr: never fails
	}
	return JoinCodePrefix + base64.RawURLEncoding.EncodeToString(b)
}

// SecretBytes is the decoded secret (the code must be valid).
func (c JoinCode) SecretBytes() []byte {
	b, _ := base64.RawURLEncoding.Strict().DecodeString(c.Secret)
	return b
}

var (
	hexSHA256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostnameRe  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidSHA256Hex: 64 lower-case hex digits.
func ValidSHA256Hex(s string) bool { return hexSHA256Re.MatchString(s) }

// ValidEndpoint: <hostname or IP>:<port 1–65535>, IPv6 in brackets.
func ValidEndpoint(ep string) bool {
	host, port, err := net.SplitHostPort(ep)
	if err != nil || host == "" || len(host) > 253 {
		return false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return false
		}
	} else if !hostnameRe.MatchString(host) {
		return false
	}
	if strings.Trim(port, "0123456789") != "" || len(port) > 5 {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// DecodeJoinCode is strict: surrounding whitespace is dropped, then the
// pcj1. prefix, unpadded base64url, one JSON object with exactly the
// payload's keys (no unknown, duplicate, missing or null key), v 1 and
// every field valid. Errors never carry the code's content.
func DecodeJoinCode(s string) (JoinCode, error) {
	s = strings.TrimSpace(s)
	if len(s) > MaxJoinCode {
		return JoinCode{}, errors.New("join code: too long")
	}
	payload, ok := strings.CutPrefix(s, JoinCodePrefix)
	if !ok {
		return JoinCode{}, fmt.Errorf("join code: not a %s code (paste it as the Hub showed it)", strings.TrimSuffix(JoinCodePrefix, "."))
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil {
		return JoinCode{}, errors.New("join code: not base64url (copy it again)")
	}
	var c JoinCode
	if err := jsonstrict.Decode(b, &c); err != nil {
		return JoinCode{}, fmt.Errorf("join code: %v", err)
	}
	return c.validate()
}

func (c JoinCode) validate() (JoinCode, error) {
	switch {
	case c.V != JoinCodeVersion:
		return JoinCode{}, fmt.Errorf("join code: version %d (only %d is understood)", c.V, JoinCodeVersion)
	case !ValidEndpoint(c.Endpoint):
		return JoinCode{}, errors.New("join code: endpoint must be <host>:<port>")
	case !vpn.ValidPublicKey(c.LinkPub):
		return JoinCode{}, errors.New("join code: link_pub is not a WireGuard key")
	case ValidID(c.ServerID) != nil:
		return JoinCode{}, fmt.Errorf("join code: server_id: %v", ValidID(c.ServerID))
	case !TunnelIPOK(c.TunnelIP):
		return JoinCode{}, fmt.Errorf("join code: tunnel_ip must be a worker address of %s (.%d–.%d)", LinkSubnet, FirstHost, LastHost)
	case !vpn.ValidPublicKey(c.BootstrapKey):
		return JoinCode{}, errors.New("join code: bootstrap_key is not a WireGuard key")
	case !ValidSHA256Hex(c.CASHA256):
		return JoinCode{}, errors.New("join code: ca_sha256 must be 64 lower-case hex digits")
	}
	if sec, err := base64.RawURLEncoding.Strict().DecodeString(c.Secret); err != nil || len(sec) != SecretLen {
		return JoinCode{}, fmt.Errorf("join code: secret must be %d bytes, base64url without padding", SecretLen)
	}
	return c, nil
}
