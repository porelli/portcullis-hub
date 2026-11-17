package servers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func key(b byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune(b)), 32)))
}

func sampleCode() JoinCode {
	return JoinCode{V: 1, Endpoint: "example.org:51821", LinkPub: key(1), ServerID: "nas", TunnelIP: netip.MustParseAddr("10.214.0.10"),
		BootstrapKey: key(2), CASHA256: strings.Repeat("ab", 32), Secret: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
}

func encodeRaw(t *testing.T, m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return JoinCodePrefix + base64.RawURLEncoding.EncodeToString(b)
}

func TestJoinCodeRoundTripAndStrict(t *testing.T) {
	c := sampleCode()
	s := c.Encode()
	if !strings.HasPrefix(s, "pcj1.") || strings.ContainsAny(s, "=+/") {
		t.Fatalf("encoding %q", s)
	}
	got, err := DecodeJoinCode(s)
	if err != nil || got != c {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if got, err := DecodeJoinCode("  " + s + "\n"); err != nil || got != c {
		t.Errorf("surrounding whitespace: %v", err)
	}
	// The secret and the bootstrap key never print.
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(f, c); strings.Contains(out, c.Secret) || strings.Contains(out, c.BootstrapKey) {
			t.Errorf("%s prints a secret: %s", f, out)
		}
	}

	base := func() map[string]any {
		var m map[string]any
		b, _ := json.Marshal(c)
		json.Unmarshal(b, &m)
		return m
	}
	if len(base()) != 8 {
		t.Fatalf("join code keys: %v", base())
	}
	payload := strings.TrimPrefix(s, "pcj1.")
	cases := map[string]string{
		"pcj2 prefix":       "pcj2." + payload,
		"no prefix":         payload,
		"upper prefix":      "PCJ1." + payload,
		"bad base64":        "pcj1." + payload + "!",
		"padded base64":     "pcj1." + base64.URLEncoding.EncodeToString([]byte(`{"v":1}`)),
		"std alphabet":      "pcj1." + strings.NewReplacer("-", "+", "_", "/").Replace(payload) + "+/",
		"empty":             "",
		"too long":          "pcj1." + strings.Repeat("A", MaxJoinCode),
		"not json":          "pcj1." + base64.RawURLEncoding.EncodeToString([]byte("hello")),
		"trailing json":     "pcj1." + base64.RawURLEncoding.EncodeToString([]byte(`{"v":1} {}`)),
		"duplicate key raw": "pcj1." + base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(mustJSON(c), `"v":1`, `"v":1,"v":1`, 1))),
	}
	mut := map[string]func(m map[string]any){
		"extra key":           func(m map[string]any) { m["proxy_subnet"] = "172.31.254.0/26" },
		"missing secret":      func(m map[string]any) { delete(m, "secret") },
		"missing ca":          func(m map[string]any) { delete(m, "ca_sha256") },
		"v 2":                 func(m map[string]any) { m["v"] = 2 },
		"v 0":                 func(m map[string]any) { m["v"] = 0 },
		"null secret":         func(m map[string]any) { m["secret"] = nil },
		"short secret":        func(m map[string]any) { m["secret"] = base64.RawURLEncoding.EncodeToString(make([]byte, 31)) },
		"padded secret":       func(m map[string]any) { m["secret"] = base64.URLEncoding.EncodeToString(make([]byte, 32)) },
		"bad server id":       func(m map[string]any) { m["server_id"] = "Nas" },
		"primary id":          func(m map[string]any) { m["server_id"] = "primary" },
		"tunnel ip link":      func(m map[string]any) { m["tunnel_ip"] = "10.214.0.1" },
		"tunnel ip outside":   func(m map[string]any) { m["tunnel_ip"] = "10.215.0.10" },
		"bad link key":        func(m map[string]any) { m["link_pub"] = "abc" },
		"bad bootstrap key":   func(m map[string]any) { m["bootstrap_key"] = key(2)[:40] },
		"upper ca hash":       func(m map[string]any) { m["ca_sha256"] = strings.Repeat("AB", 32) },
		"short ca hash":       func(m map[string]any) { m["ca_sha256"] = "ab" },
		"endpoint no port":    func(m map[string]any) { m["endpoint"] = "example.org" },
		"endpoint port 0":     func(m map[string]any) { m["endpoint"] = "example.org:0" },
		"endpoint port big":   func(m map[string]any) { m["endpoint"] = "example.org:65536" },
		"endpoint bad host":   func(m map[string]any) { m["endpoint"] = "exa mple.org:51821" },
		"endpoint url":        func(m map[string]any) { m["endpoint"] = "udp://example.org:51821" },
		"endpoint empty host": func(m map[string]any) { m["endpoint"] = ":51821" },
		"case-folded key":     func(m map[string]any) { m["Secret"] = m["secret"]; delete(m, "secret") },
	}
	for name, f := range mut {
		m := base()
		f(m)
		cases[name] = encodeRaw(t, m)
	}
	for name, code := range cases {
		_, err := DecodeJoinCode(code)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), c.Secret) || strings.Contains(err.Error(), c.BootstrapKey) {
			t.Errorf("%s: the error carries a secret: %v", name, err)
		}
	}
	for _, ep := range []string{"192.0.2.1:51821", "[2001:db8::1]:51821", "vpn.example.org:1"} {
		m := base()
		m["endpoint"] = ep
		if _, err := DecodeJoinCode(encodeRaw(t, m)); err != nil {
			t.Errorf("endpoint %s: %v", ep, err)
		}
	}
	if _, err := (JoinCode{}).validate(); err == nil {
		t.Error("zero code valid")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
