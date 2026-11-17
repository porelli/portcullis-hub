package mailprovider

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// strictDecode decodes b into v: unknown keys and trailing data refused.
func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return &json.SyntaxError{}
	}
	return nil
}

// TestMailStateV2VectorDecodesStrict: testdata/mailstate_v2.json is the
// contract's MailState v2 block byte for byte (web/docs is the synced
// contract) and has exactly the document's keys: two domains (floors
// reject and none) and a relay.
func TestMailStateV2VectorDecodesStrict(t *testing.T) {
	raw, err := os.ReadFile("testdata/mailstate_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../web/docs/integration-contracts.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(doc)
	i := strings.Index(s, "**MailState v2**")
	if i < 0 {
		t.Fatal("no MailState v2 in the contract")
	}
	a := strings.Index(s[i:], "```json\n") + i + len("```json\n")
	b := strings.Index(s[a:], "```") + a
	if s[a:b] != string(raw) {
		t.Fatal("testdata/mailstate_v2.json differs from the contract's vector")
	}
	var m map[string]json.RawMessage
	if err := strictDecode(raw, &m); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	})
	want := []string{"accounts", "aliases", "client_ip", "confirm_mass_removal", "dkim_rotate", "domains", "former_retention",
		"generation", "limits", "lists", "local_networks", "mail_hostname", "postmaster", "primary_domain", "relay", "spam",
		"submission_lan_only", "tls", "version"}
	if !slices.Equal(keys, want) {
		t.Fatalf("keys %v, want %v", keys, want)
	}
	var d struct {
		Version int `json:"version"`
		Domains []struct {
			DMARCFloor string `json:"dmarc_floor"`
		} `json:"domains"`
		Relay *struct {
			Host string `json:"host"`
		} `json:"relay"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if d.Version != 2 || len(d.Domains) != 2 || d.Domains[0].DMARCFloor != "reject" || d.Domains[1].DMARCFloor != "none" || d.Relay == nil || d.Relay.Host == "" {
		t.Fatalf("decoded %+v", d)
	}
}

// dnsVectors is testdata/mail_dns_vectors.json, shared byte for byte with
// core's domains/internal/dnsplan/testdata/mail_dns_vectors.json. A
// case's context overrides keys of the file's context. want_error is ""
// (the set is valid) or the first refusal: "mail set: <name> <type>:
// <why>", the first record (in list order) that fails. Each record is
// judged in this order: not under the domain; a type the set never
// holds; a name outside the table (or a type the name doesn't take); its
// value.
type dnsVectors struct {
	Context dnsContext `json:"context"`
	Cases   []struct {
		Name    string          `json:"name"`
		Context json.RawMessage `json:"context"`
		Records []struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			TTL   int    `json:"ttl"`
			Value string `json:"value"`
		} `json:"records"`
		WantError string `json:"want_error"`
	} `json:"cases"`
}

type dnsContext struct {
	Domain       string `json:"domain"`
	MailHostname string `json:"mail_hostname"`
	RelayInclude string `json:"relay_include"`
	DMARCFloor   string `json:"dmarc_floor"`
	Wildcard     bool   `json:"wildcard"`
}

// TestDNSVectorsShape: strict shape, unique names, one ok case per row of
// the §19.7 table, one refusal per forbidden shape, every refusal names
// one of its case's records.
func TestDNSVectorsShape(t *testing.T) {
	raw, err := os.ReadFile("testdata/mail_dns_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v dnsVectors
	if err := strictDecode(raw, &v); err != nil {
		t.Fatal(err)
	}
	c := v.Context
	if c.Domain == "" || c.MailHostname == "" || c.RelayInclude == "" || c.DMARCFloor != "reject" {
		t.Fatalf("context %+v", c)
	}
	wantRe := regexp.MustCompile(`^mail set: (\S+) ([A-Z]+): \S.*$`)
	names := map[string]bool{}
	for _, k := range v.Cases {
		if names[k.Name] {
			t.Errorf("case %q twice", k.Name)
		}
		names[k.Name] = true
		if len(k.Context) > 0 {
			var o dnsContext
			if err := strictDecode(k.Context, &o); err != nil {
				t.Errorf("%s: context: %v", k.Name, err)
			}
		}
		if len(k.Records) == 0 {
			t.Errorf("%s: no records", k.Name)
		}
		for _, r := range k.Records {
			if r.Name == "" || r.Type == "" || r.TTL <= 0 || r.Value == "" {
				t.Errorf("%s: record %+v", k.Name, r)
			}
		}
		if k.WantError == "" {
			if !strings.HasSuffix(k.Name, " ok") {
				t.Errorf("%s: a valid case's name ends in ok", k.Name)
			}
			continue
		}
		if !strings.HasSuffix(k.Name, " refused") {
			t.Errorf("%s: a refused case's name ends in refused", k.Name)
		}
		m := wantRe.FindStringSubmatch(k.WantError)
		if m == nil {
			t.Errorf("%s: %q isn't mail set: <name> <type>: <why>", k.Name, k.WantError)
			continue
		}
		found := false
		for _, r := range k.Records {
			found = found || (r.Name == m[1] && r.Type == m[2])
		}
		if !found {
			t.Errorf("%s: %q names none of its records", k.Name, k.WantError)
		}
	}
	for _, n := range []string{
		// ok, one per row of the table
		"mx ok", "spf with the relay include ok", "dkim ok", "dmarc at the floor ok", "mta-sts id ok", "tls-rpt ok",
		"srv submissions, submission and imaps ok", "srv 0 0 0 . ok", "cnames without a wildcard ok",
		// one refusal per forbidden shape
		"A record refused", "AAAA record refused", "CAA record refused", "NS record refused", "DS record refused", "TLSA record refused",
		"mx to a foreign host refused", "spf with a refused", "spf with ip4 refused", "spf include without a relay refused",
		"dkim selector with a dot refused", "dmarc p=none under floor reject refused", "dmarc rua off-domain refused",
		"dmarc ruf refused", "mta-sts id of 33 characters refused", "srv on a wrong port refused", "_imap._tcp not 0 0 0 . refused",
		"cname with wildcard=true refused", "a name outside the table refused", "a name under another domain refused",
	} {
		if !names[n] {
			t.Errorf("case %q missing", n)
		}
	}
}
