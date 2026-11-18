package cliapi

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type vectors struct {
	Principals []struct {
		In, Kind, Account string
		HostGroup         string `json:"host_group"`
		OK                bool
	} `json:"principals"`
	HostPatterns []struct {
		In            string
		Pattern, Name bool
	} `json:"host_patterns"`
	HostGroupIDs []struct {
		In           string
		OK, Reserved bool
	} `json:"host_group_ids"`
	Usernames []struct {
		In string
		OK bool
	} `json:"usernames"`
	KeyIDs []struct {
		In, User, Req string
		HostGroup     string `json:"host_group"`
		OK            bool
	} `json:"key_ids"`
	Extensions []struct {
		PortForwarding  bool   `json:"port_forwarding"`
		AgentForwarding bool   `json:"agent_forwarding"`
		Value           string `json:"value"`
	} `json:"extensions"`
	RoleTTLs []struct {
		In, Out int
		OK      bool
	} `json:"role_ttls"`
	KeyProofMessages []struct {
		Domain, Nonce, Code, Message string
		PublicKey                    string `json:"public_key"`
	} `json:"key_proof_messages"`
	EnrolMessages []struct {
		Domain, Challenge, Message string
		HostID                     string `json:"host_id"`
	} `json:"enrol_messages"`
	HostRequestMessages []struct {
		HostID                                          string `json:"host_id"`
		Method, Path, Query, Time, Nonce, Body, Message string
	} `json:"host_request_messages"`
	Roles []struct {
		Name      string
		HostGroup string `json:"host_group"`
		Spec      RoleSpec
		Body      string
		Vault     map[string]any
	} `json:"roles"`
	KeyTypes []struct {
		Type         string
		Accepted, SK bool
	} `json:"key_types"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPrincipalGrammar(t *testing.T) {
	ok := []string{"u:alice@web", "u:a@portcullis-servers", "s:_x@all"}
	bad := []string{"alice@web", "u:Alice@web", "u:alice@Web", "u:1x@web", "u:@web", "u:alice@", "u:" + strings.Repeat("a", 33) + "@web", "x:alice@web"}
	for _, s := range ok {
		if _, _, _, k := ParsePrincipal(s); !k {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range bad {
		if _, _, _, k := ParsePrincipal(s); k {
			t.Errorf("%q accepted", s)
		}
	}
	k, a, g, _ := ParsePrincipal(Principal(PrincipalShared, "deploy", "web"))
	if k != "s" || a != "deploy" || g != "web" {
		t.Errorf("split = %q %q %q", k, a, g)
	}
	// The namespaces never overlap: the same account and host group make
	// two different principals.
	if Principal(PrincipalPersonal, "deploy", "web") == Principal(PrincipalShared, "deploy", "web") {
		t.Error("personal and shared principals collide")
	}
}

func TestHostPatternGrammar(t *testing.T) {
	for _, c := range loadVectors(t).HostPatterns {
		if ValidHostPattern(c.In) != c.Pattern || ValidHostName(c.In) != c.Name {
			t.Errorf("%q: pattern %v name %v", c.In, ValidHostPattern(c.In), ValidHostName(c.In))
		}
	}
}

func TestClientConfigRefusesInjection(t *testing.T) {
	for _, bad := range []ClientGroup{
		{HostGroup: "web", Hosts: []string{"web-1.example.com\nProxyCommand nc evil 22"}},
		{HostGroup: "web", Hosts: []string{"a b"}},
		{HostGroup: "web", Hosts: []string{"a,b"}},
		{HostGroup: "web\nHost *", Hosts: []string{"a"}},
	} {
		if out, err := ClientConfig("example.com", []ClientGroup{bad}, false); err == nil || out != "" {
			t.Errorf("%q rendered: %q", bad, out)
		}
		if out, err := KnownHosts("example.com", []ClientGroup{bad}, nil, nil); err == nil || out != "" {
			t.Errorf("known_hosts %q rendered: %q", bad, out)
		}
	}
	if _, err := ClientConfig("example.com\nHost *", nil, false); err == nil {
		t.Error("a bad domain rendered")
	}
	if _, err := KnownHosts("example.com", nil, []string{"ssh-ed25519 AAAA\n@cert-authority * x"}, nil); err == nil {
		t.Error("a bad host CA rendered")
	}
}

// FuzzClientConfig: whatever the names, the output is either refused or
// exactly the fixed lines with the names on the Match lines only.
func FuzzClientConfig(f *testing.F) {
	for _, s := range []string{"web-1.example.com", "*.lab.example.com", "a\nb", "a b", "192.0.2.1", "a,b", "!x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		out, err := ClientConfig("example.com", []ClientGroup{{HostGroup: "web", Hosts: []string{name}}}, false)
		if err != nil {
			return
		}
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if len(lines) != 6 || lines[1] != "Match host "+name || strings.ContainsAny(name, " \t\r\n,\"'") {
			t.Fatalf("name %q rendered as %q", name, out)
		}
		kh, err := KnownHosts("example.com", []ClientGroup{{HostGroup: "web", Hosts: []string{name}}}, nil, nil)
		if err != nil || kh != "" {
			t.Fatalf("known_hosts %q %v", kh, err)
		}
	})
}

func TestKeyIDRoundTrip(t *testing.T) {
	id := KeyID("alice", "web", "0123456789abcdef")
	if id != "pc:alice:web:0123456789abcdef" {
		t.Fatalf("KeyID = %q", id)
	}
	u, g, r, ok := ParseKeyID(id)
	if !ok || u != "alice" || g != "web" || r != "0123456789abcdef" {
		t.Fatalf("ParseKeyID = %q %q %q %v", u, g, r, ok)
	}
	for _, s := range []string{"pc:alice:web:0123456789abcde", "pc:alice:web:0123456789ABCDEF"} {
		if _, _, _, ok := ParseKeyID(s); ok {
			t.Errorf("%q accepted", s)
		}
	}
	if !ValidBreakglassKeyID("pc-breakglass:outage 2026-11-15") || ValidBreakglassKeyID("pc-breakglass:") {
		t.Error("break-glass key id grammar")
	}
}

func TestKeyProofMessageCanonical(t *testing.T) {
	v := loadVectors(t)
	if len(v.KeyProofMessages) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.KeyProofMessages {
		got := string(KeyProofMessage(c.Domain, c.Nonce, c.Code, c.PublicKey))
		if got != c.Message {
			t.Errorf("message\n got %s\nwant %s", got, c.Message)
		}
	}
	if !strings.HasPrefix(string(KeyProofMessage("d", "n", "c", "k")), `{"domain":"d","nonce":"n","code_sha256":"`) {
		t.Error("field order")
	}
}

func TestDecodeStrictRefusesUnknownAndTrailing(t *testing.T) {
	var r CertRequest
	if err := DecodeStrict(strings.NewReader(`{"code":"x","extra":1}`), MaxCertRequest, &r); err == nil {
		t.Error("unknown field accepted")
	}
	if err := DecodeStrict(strings.NewReader(`{"code":"x"} {"code":"y"}`), MaxCertRequest, &r); err == nil {
		t.Error("trailing value accepted")
	}
	if err := DecodeStrict(strings.NewReader(`{"code":"x"} x`), MaxCertRequest, &r); err == nil {
		t.Error("trailing garbage accepted")
	}
	if err := DecodeStrict(strings.NewReader(``), MaxCertRequest, &r); err == nil {
		t.Error("empty accepted")
	}
	if err := DecodeStrict(strings.NewReader(`{"code":"secret-code","host_groups":7}`), MaxCertRequest, &r); err == nil || strings.Contains(err.Error(), "secret-code") {
		t.Errorf("type error = %v (must not quote input)", err)
	}
	if err := DecodeStrict(strings.NewReader("{\"code\":\"x\"}\n"), MaxCertRequest, &r); err != nil || r.Code != "x" {
		t.Errorf("good body: %v", err)
	}
}

func TestDecodeStrictSize(t *testing.T) {
	var r CertRequest
	big := `{"code":"` + strings.Repeat("a", MaxCertRequest) + `"}`
	err := DecodeStrict(strings.NewReader(big), MaxCertRequest, &r)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	exact := `{"code":"` + strings.Repeat("a", MaxCertRequest-11) + `"}`
	if len(exact) != MaxCertRequest {
		t.Fatalf("len %d", len(exact))
	}
	if err := DecodeStrict(strings.NewReader(exact), MaxCertRequest, &r); err != nil {
		t.Errorf("exactly the cap refused: %v", err)
	}
}

func testCode() EnrolCode {
	s := make([]byte, 32)
	rand.Read(s)
	return EnrolCode{Domain: "example.com", HostID: "web-1", HostGroups: []string{"web", "all"},
		UserCAFP: "SHA256:abc", HostCAFP: "SHA256:def", Secret: base64.RawURLEncoding.EncodeToString(s),
		Expires: time.Date(2026, 11, 15, 9, 15, 0, 0, time.UTC)}
}

func TestEnrolCodeRoundTrip(t *testing.T) {
	c := testCode()
	s := c.String()
	if !strings.HasPrefix(s, "pcenrol1.") || strings.ContainsAny(s, "=+/") {
		t.Fatalf("code %q", s)
	}
	got, err := ParseEnrolCode(s + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if got.HostID != c.HostID || got.Secret != c.Secret || !got.Expires.Equal(c.Expires) || len(got.HostGroups) != 2 {
		t.Errorf("round trip %+v", got)
	}
}

func TestEnrolCodeRefusesBadPrefixAndPadding(t *testing.T) {
	c := testCode()
	s := c.String()
	body := s[len(EnrolCodePrefix):]
	raw, _ := json.Marshal(c)
	for name, in := range map[string]string{
		"prefix":   "pcenrol2." + body,
		"none":     body,
		"padding":  EnrolCodePrefix + base64.URLEncoding.EncodeToString(raw),
		"std b64":  EnrolCodePrefix + strings.NewReplacer("-", "+", "_", "/").Replace(body) + "+/",
		"garbage":  EnrolCodePrefix + "!!!",
		"unknown":  EnrolCodePrefix + base64.RawURLEncoding.EncodeToString([]byte(`{"d":"x","zz":1}`)),
		"short s":  EnrolCodePrefix + base64.RawURLEncoding.EncodeToString(mustJSON(func() EnrolCode { c := testCode(); c.Secret = "AAAA"; return c }())),
		"bad host": EnrolCodePrefix + base64.RawURLEncoding.EncodeToString(mustJSON(func() EnrolCode { c := testCode(); c.HostID = "Web 1"; return c }())),
	} {
		_, err := ParseEnrolCode(in)
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		if strings.Contains(err.Error(), c.Secret) {
			t.Errorf("%s: error quotes the secret", name)
		}
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestAcceptedKeyTypes(t *testing.T) {
	if !SKKeysAccepted {
		t.Fatal("spike S1 passed: SKKeysAccepted must be true")
	}
	for _, c := range loadVectors(t).KeyTypes {
		if got := AcceptedKeyType(c.Type, true); got != c.Accepted {
			t.Errorf("%s with sk: %v", c.Type, got)
		}
		want := c.Accepted && !c.SK
		if got := AcceptedKeyType(c.Type, false); got != want {
			t.Errorf("%s without sk: %v", c.Type, got)
		}
	}
	// Real keys: the types x/crypto reports.
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	edk, _ := ssh.NewPublicKey(ed)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384k, _ := ssh.NewPublicKey(&p384.PublicKey)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsak, _ := ssh.NewPublicKey(&rk.PublicKey)
	if !AcceptedKeyType(edk.Type(), SKKeysAccepted) || AcceptedKeyType(p384k.Type(), true) || AcceptedKeyType(rsak.Type(), true) {
		t.Error("real key types")
	}
}

func TestParseAuthorizedKey(t *testing.T) {
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(ed)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " a comment"
	got, norm, err := ParseAuthorizedKey(line)
	if err != nil || norm != NormalAuthorizedKey(k) || got.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("parse: %v %q", err, norm)
	}
	for _, bad := range []string{"", "ssh-ed25519", line + "\n" + line, `command="x" ` + line, "ssh-ed25519 AAAA!"} {
		if _, _, err := ParseAuthorizedKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSignatureHeaderRoundTrip(t *testing.T) {
	armor := []byte("-----BEGIN SSH SIGNATURE-----\nAAAA\nBBBB\n-----END SSH SIGNATURE-----\n")
	h := EncodeSignatureHeader(armor)
	if strings.Contains(h, "\n") {
		t.Fatal("newline in header")
	}
	if string(DecodeSignatureHeader(h)) != string(armor) {
		t.Errorf("round trip %q", DecodeSignatureHeader(h))
	}
}

func TestCLIHeader(t *testing.T) {
	v, a, ok := ParseCLIHeader(CLIHeaderValue("1.2.3"))
	if !ok || v != "1.2.3" || a != 1 {
		t.Fatalf("%q %d %v", v, a, ok)
	}
	for _, bad := range []string{"", "1.2.3", "1.2.3; api=x", "; api=1", "1.2.3; v=1"} {
		if _, _, ok := ParseCLIHeader(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if got := RedirectURIs(); len(got) != 3 || got[0] != "http://127.0.0.1:38917/callback" || got[2] != "http://127.0.0.1:38919/callback" {
		t.Errorf("redirect URIs %v", got)
	}
}

func TestCeilingDefaultsAndValidate(t *testing.T) {
	c := DefaultCeiling()
	if !c.AllowSudo || c.AllowRootLogin || c.UIDRange != [2]int{20000, 59999} || c.BreakglassAccount != "breakglass" || c.MaxAccounts != 500 {
		t.Errorf("defaults %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Error(err)
	}
	c.UIDRange = [2]int{500, 600}
	if c.Validate() == nil {
		t.Error("uid range below 1000 accepted")
	}
}

func TestVectorsFile(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Principals {
		k, a, g, ok := ParsePrincipal(c.In)
		build := Principal
		if IsApprovedPrincipal(c.In) {
			build = ApprovedPrincipal
		}
		if ok != c.OK || (ok && (k != c.Kind || a != c.Account || g != c.HostGroup || build(k, a, g) != c.In)) {
			t.Errorf("principal %q: %q %q %q %v", c.In, k, a, g, ok)
		}
	}
	for _, c := range v.HostGroupIDs {
		if ValidHostGroupID(c.In) != c.OK || (c.OK && ReservedHostGroupID(c.In) != c.Reserved) {
			t.Errorf("host group %q", c.In)
		}
	}
	for _, c := range v.Usernames {
		if ValidUsername(c.In) != c.OK {
			t.Errorf("username %q", c.In)
		}
	}
	for _, c := range v.KeyIDs {
		u, g, r, ok := ParseKeyID(c.In)
		if ok != c.OK || (ok && (u != c.User || g != c.HostGroup || r != c.Req || KeyID(u, g, r) != c.In)) {
			t.Errorf("key id %q", c.In)
		}
	}
	for _, c := range v.Extensions {
		got := CanonicalExtensions(c.PortForwarding, c.AgentForwarding)
		if got != c.Value || !ValidExtensionSet(got) {
			t.Errorf("extensions %v/%v = %q", c.PortForwarding, c.AgentForwarding, got)
		}
	}
	if ValidExtensionSet("permit-port-forwarding,permit-pty") || ValidExtensionSet("permit-pty,permit-X11-forwarding") {
		t.Error("non-canonical extension set accepted")
	}
	for _, c := range v.RoleTTLs {
		out, ok := RoundRoleTTL(c.In)
		if out != c.Out || ok != c.OK {
			t.Errorf("role ttl %d = %d %v", c.In, out, ok)
		}
	}
	for _, c := range v.EnrolMessages {
		if got := string(EnrolMessage(c.Domain, c.HostID, c.Challenge)); got != c.Message {
			t.Errorf("enrol message %s", got)
		}
	}
	for _, c := range v.HostRequestMessages {
		if got := string(HostRequestMessage(c.HostID, c.Method, c.Path, c.Query, c.Time, c.Nonce, []byte(c.Body))); got != c.Message {
			t.Errorf("host request message %s", got)
		}
	}
	if len(v.Roles) == 0 {
		t.Fatal("no role vectors")
	}
	for _, c := range v.Roles {
		b, _ := json.Marshal(c.Spec)
		if string(b) != c.Body {
			t.Errorf("role %s body\n got %s\nwant %s", c.Name, b, c.Body)
		}
		if c.Vault["allowed_users"] != strings.Join(c.Spec.Principals, ",") || c.Vault["allowed_extensions"] != c.Spec.Extensions {
			t.Errorf("role %s vault map disagrees with the spec", c.Name)
		}
		for k, val := range c.Vault {
			switch val.(type) {
			case string, map[string]any:
			default:
				t.Errorf("role %s: vault field %s is %T, C15 wants strings", c.Name, k, val)
			}
		}
		for _, f := range []string{"ttl", "max_ttl"} {
			ttl, _ := c.Vault[f].(string)
			n, err := strconv.Atoi(ttl)
			if err != nil || n < MinRoleTTLSeconds || n > MaxRoleTTLSeconds || n%3600 != 0 {
				t.Errorf("role %s: %s %q is not a whole hour of at most 12 h", c.Name, f, ttl)
			}
		}
	}
}

func TestKnownHostsScoped(t *testing.T) {
	ca := genKey(t)
	bad := genKey(t)
	got, err := KnownHosts("example.com", []ClientGroup{{HostGroup: "web", Hosts: []string{"web-1.example.com", "*.lab.example.com"}}, {HostGroup: "db"}},
		[]string{ca + " a comment"}, []string{bad})
	if err != nil {
		t.Fatal(err)
	}
	want := "@cert-authority web-1.example.com,*.lab.example.com " + ca + "\n@revoked * " + bad + "\n"
	if got != want {
		t.Errorf("got %q", got)
	}
}

func genKey(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return NormalAuthorizedKey(k)
}
