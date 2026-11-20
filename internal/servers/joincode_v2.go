package servers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
)

// Join code v2 (contract §20.3): a cluster node's code. nodeadm builds it
// (POST /v1/codes) and the Hub only shows it, once; the Hub decodes it to
// check that nodeadm answered the code it asked for. It carries no k3s
// token.

// JoinCodeV2Prefix starts every v2 code.
const JoinCodeV2Prefix = "pcj2."

// MaxJoinCodeV2 is a v2 code's longest form (4 KiB, inclusive).
const MaxJoinCodeV2 = 4096

// MeshPrefix is the node mesh pcmesh (contract §20.11).
var MeshPrefix = netip.MustParsePrefix("10.215.0.0/24")

// AgentSHA256 are the nodeagent binaries' sha256 (64 lower-case hex each).
type AgentSHA256 struct {
	AMD64 string `json:"amd64"`
	ARM64 string `json:"arm64"`
}

// JoinCodeV2 is a v2 code's payload, its keys in the code's order.
//
// Secret is a secret: String, GoString and MarshalJSON redact it, so a
// code never prints, logs or serialises by accident; EncodeV2 is the only
// way out.
type JoinCodeV2 struct {
	V            int
	Kind         string
	Endpoint     string
	Servers      []string
	ServerID     string
	Role         string
	Class        string
	Site         string
	CASHA256     string
	ScriptSHA256 string
	AgentSHA256  AgentSHA256
	MeshIP       string
	Secret       string
}

// joinCodeV2Wire is the code's JSON (the order of contract §20.3).
type joinCodeV2Wire struct {
	V            int         `json:"v"`
	Kind         string      `json:"kind"`
	Endpoint     string      `json:"endpoint"`
	Servers      []string    `json:"servers"`
	ServerID     string      `json:"server_id"`
	Role         string      `json:"role"`
	Class        string      `json:"class"`
	Site         string      `json:"site"`
	CASHA256     string      `json:"ca_sha256"`
	ScriptSHA256 string      `json:"script_sha256"`
	AgentSHA256  AgentSHA256 `json:"agent_sha256"`
	MeshIP       string      `json:"mesh_ip"`
	Secret       string      `json:"secret"`
}

// String redacts the secret.
func (c JoinCodeV2) String() string {
	return fmt.Sprintf("join code v2 {server_id:%s role:%s class:%s site:%s mesh_ip:%s endpoint:%s secret:<redacted>}",
		c.ServerID, c.Role, c.Class, c.Site, c.MeshIP, c.Endpoint)
}

// GoString redacts the secret (%#v).
func (c JoinCodeV2) GoString() string { return c.String() }

// MarshalJSON writes the payload with the secret redacted (a code in a
// JSON log or answer by accident shows no secret).
func (c JoinCodeV2) MarshalJSON() ([]byte, error) {
	w := joinCodeV2Wire(c)
	w.Secret = "<redacted>"
	return json.Marshal(w)
}

// EncodeV2 is "pcj2." + base64url (no padding) of the JSON payload
// (nodeadm's form: no HTML escaping, no trailing newline).
func (c JoinCodeV2) EncodeV2() string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(joinCodeV2Wire(c)); err != nil {
		panic(err) // plain strings: never fails
	}
	return JoinCodeV2Prefix + base64.RawURLEncoding.EncodeToString(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

// EncodeV2 is c.EncodeV2 (the package-level form).
func EncodeV2(c JoinCodeV2) string { return c.EncodeV2() }

// The exact errors of contract §20.3.
var (
	errNotPCJ2   = errors.New("join code: not a pcj2 code")
	errV2TooLong = errors.New("join code: too long")
)

var joinCodeV2Keys = []string{"v", "kind", "endpoint", "servers", "server_id", "role", "class", "site", "ca_sha256", "script_sha256", "agent_sha256", "mesh_ip", "secret"}

var siteRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// ValidSite: a site name (the server id's grammar).
func ValidSite(s string) bool { return siteRe.MatchString(s) }

// ValidClass: small, home or cloud.
func ValidClass(s string) bool { return s == "small" || s == "home" || s == "cloud" }

// MeshAddrOK: a host address of 10.215.0.0/24 in its canonical form (not
// the network or broadcast address).
func MeshAddrOK(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || !MeshPrefix.Contains(a) || a.String() != s {
		return false
	}
	last := a.As4()[3]
	return last != 0 && last != 255
}

// DecodeJoinCodeV2 is strict (contract §20.3): surrounding whitespace is
// dropped, then at most 4 KiB, the pcj2. prefix, unpadded base64url, one
// JSON object with exactly the payload's keys (no unknown, duplicate or
// null key), v 2, kind cluster and every field valid. Errors are the
// contract's exact texts and never carry the code's content.
func DecodeJoinCodeV2(s string) (JoinCodeV2, error) {
	s = strings.TrimSpace(s)
	if len(s) > MaxJoinCodeV2 {
		return JoinCodeV2{}, errV2TooLong
	}
	payload, ok := strings.CutPrefix(s, JoinCodeV2Prefix)
	if !ok {
		return JoinCodeV2{}, errNotPCJ2
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil {
		return JoinCodeV2{}, errNotPCJ2
	}
	fields, err := v2Object(b)
	if err != nil {
		return JoinCodeV2{}, errNotPCJ2
	}
	known := map[string]bool{}
	for _, k := range joinCodeV2Keys {
		known[k] = true
	}
	for k := range fields {
		if !known[k] {
			return JoinCodeV2{}, errNotPCJ2
		}
	}
	for _, k := range joinCodeV2Keys {
		if _, ok := fields[k]; !ok {
			return JoinCodeV2{}, fmt.Errorf("join code: field %s missing", k)
		}
	}
	var c JoinCodeV2
	var agents json.RawMessage
	str := func(k string, dst *string) bool { return v2String(fields[k], dst) }
	if !v2Int(fields["v"], &c.V) || !str("kind", &c.Kind) || !str("endpoint", &c.Endpoint) || !v2Strings(fields["servers"], &c.Servers) ||
		!str("server_id", &c.ServerID) || !str("role", &c.Role) || !str("class", &c.Class) || !str("site", &c.Site) ||
		!str("ca_sha256", &c.CASHA256) || !str("script_sha256", &c.ScriptSHA256) || !str("mesh_ip", &c.MeshIP) || !str("secret", &c.Secret) {
		return JoinCodeV2{}, errNotPCJ2
	}
	agents = fields["agent_sha256"]
	if c.V != 2 || c.Kind != "cluster" {
		return JoinCodeV2{}, errNotPCJ2
	}
	am, err := v2Object(agents)
	if err != nil {
		return JoinCodeV2{}, errNotPCJ2
	}
	for k, raw := range am {
		var v string
		if !v2String(raw, &v) {
			return JoinCodeV2{}, errNotPCJ2
		}
		switch k {
		case "amd64":
			c.AgentSHA256.AMD64 = v
		case "arm64":
			c.AgentSHA256.ARM64 = v
		default:
			return JoinCodeV2{}, errors.New("join code: agent_sha256 must be 64 hex for amd64 and arm64")
		}
	}
	switch {
	case c.Role != "server" && c.Role != "agent":
		return JoinCodeV2{}, errors.New("join code: role must be server or agent")
	case !MeshAddrOK(c.MeshIP):
		return JoinCodeV2{}, errors.New("join code: mesh_ip outside 10.215.0.0/24")
	case !ValidSHA256Hex(c.CASHA256):
		return JoinCodeV2{}, errors.New("join code: ca_sha256 must be 64 hex")
	case len(am) != 2 || !ValidSHA256Hex(c.AgentSHA256.AMD64) || !ValidSHA256Hex(c.AgentSHA256.ARM64):
		return JoinCodeV2{}, errors.New("join code: agent_sha256 must be 64 hex for amd64 and arm64")
	case !ValidSHA256Hex(c.ScriptSHA256):
		return JoinCodeV2{}, errors.New("join code: script_sha256 must be 64 hex")
	}
	if sec, err := base64.RawURLEncoding.Strict().DecodeString(c.Secret); err != nil || len(sec) != SecretLen {
		return JoinCodeV2{}, errors.New("join code: secret must be 32 bytes")
	}
	// Any other fault is "not a pcj2 code" (§20.3).
	if ValidID(c.ServerID) != nil || !ValidClass(c.Class) || !ValidSite(c.Site) || !strings.HasPrefix(c.Endpoint, "https://") || len(c.Servers) == 0 {
		return JoinCodeV2{}, errNotPCJ2
	}
	for _, sv := range c.Servers {
		if !MeshAddrOK(sv) {
			return JoinCodeV2{}, errNotPCJ2
		}
	}
	return c, nil
}

// SecretBytes is the decoded secret (the code must be valid).
func (c JoinCodeV2) SecretBytes() []byte {
	b, _ := base64.RawURLEncoding.Strict().DecodeString(c.Secret)
	return b
}

// v2Object splits one JSON object (no trailing data) into its keys,
// refusing duplicates and null values.
func v2Object(b []byte) (map[string]json.RawMessage, error) {
	if !json.Valid(b) {
		return nil, errNotPCJ2
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errNotPCJ2
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errNotPCJ2
		}
		k, _ := tok.(string)
		if _, dup := out[k]; dup {
			return nil, errNotPCJ2
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, errNotPCJ2
		}
		out[k] = v
	}
	return out, nil
}

func v2String(raw json.RawMessage, dst *string) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '"' && json.Unmarshal(t, dst) == nil
}

func v2Int(raw json.RawMessage, dst *int) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] != '"' && json.Unmarshal(t, dst) == nil
}

func v2Strings(raw json.RawMessage, dst *[]string) bool {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '[' {
		return false
	}
	var items []json.RawMessage
	if json.Unmarshal(t, &items) != nil {
		return false
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		var s string
		if !v2String(it, &s) {
			return false
		}
		out = append(out, s)
	}
	*dst = out
	return true
}

// JoinCodeSecret is a whole join code as it travels from nodeadm to the
// one answer that shows it (review M1): String, GoString, MarshalJSON and
// LogValue redact it, so a code printed, logged or serialised by
// accident shows nothing; Reveal is called only by the writers of that
// answer (the 201 of POST /api/servers and of the host socket's twin).
type JoinCodeSecret string

// Reveal is the code itself.
func (c JoinCodeSecret) Reveal() string { return string(c) }

// String redacts the code.
func (c JoinCodeSecret) String() string { return "<join code>" }

// GoString redacts the code.
func (c JoinCodeSecret) GoString() string { return c.String() }

// MarshalJSON redacts the code.
func (c JoinCodeSecret) MarshalJSON() ([]byte, error) { return []byte(`"<redacted>"`), nil }

// LogValue redacts the code (log/slog).
func (c JoinCodeSecret) LogValue() slog.Value { return slog.StringValue("<join code>") }

// LogValue redacts the secret (log/slog).
func (c JoinCodeV2) LogValue() slog.Value { return slog.StringValue(c.String()) }
