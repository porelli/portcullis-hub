package mailprovider

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestDNSRuleVectors: every case of the shared vectors (a case's
// context overrides the file's).
func TestDNSRuleVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/mail_dns_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v dnsVectors
	if err := strictDecode(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, k := range v.Cases {
		c := v.Context
		if len(k.Context) > 0 {
			if err := json.Unmarshal(k.Context, &c); err != nil {
				t.Fatal(err)
			}
		}
		rs := make([]Record, 0, len(k.Records))
		for _, r := range k.Records {
			rs = append(rs, Record{Name: r.Name, Type: r.Type, TTL: r.TTL, Value: r.Value})
		}
		err := ValidateSet(RuleContext{Domain: c.Domain, MailHostname: c.MailHostname, RelayInclude: c.RelayInclude, DMARCFloor: c.DMARCFloor, Wildcard: c.Wildcard, Draining: c.Draining}, rs)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != k.WantError {
			t.Errorf("%s:\n got %q\nwant %q", k.Name, got, k.WantError)
		}
	}
}

// TestNoTLSAFromProvider: any TLSA, anywhere under the domain, refuses
// the set (TLSA is core's).
func TestNoTLSAFromProvider(t *testing.T) {
	c := RuleContext{Domain: "example.com", MailHostname: "mail.example.com", DMARCFloor: "none"}
	for _, n := range []string{"_25._tcp.mail.example.com", "_25._tcp.example.com", "example.com"} {
		err := ValidateSet(c, []Record{{Name: n, Type: "TLSA", TTL: 3600, Value: "3 1 1 " + strings.Repeat("ab", 32)}})
		if err == nil || !strings.HasSuffix(err.Error(), "TLSA records are not allowed") {
			t.Errorf("%s: %v", n, err)
		}
	}
}

// TestDMARCPolicyAndFloor: the published p= and the stricter of two.
func TestDMARCPolicyAndFloor(t *testing.T) {
	rs := []Record{{Name: "_dmarc.example.com.", Type: "TXT", Value: "v=DMARC1; adkim=s; P=Quarantine; rua=mailto:x@example.com"}}
	if p := DMARCPolicy("example.com", rs); p != "quarantine" {
		t.Fatalf("%q", p)
	}
	if DMARCPolicy("example.org", rs) != "" {
		t.Fatal("another domain's policy")
	}
	for _, c := range [][3]string{{"none", "reject", "reject"}, {"reject", "none", "reject"}, {"quarantine", "", "quarantine"}, {"", "", "none"}} {
		if got := StricterDMARC(c[0], c[1]); got != c[2] {
			t.Errorf("%v: %s", c, got)
		}
	}
}
