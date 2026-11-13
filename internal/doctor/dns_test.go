package doctor

import (
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/domains"
)

// DNS hardening Task 12 (contract §14.5): the ten DNS kinds.

const (
	testD    = "team-b.example.org"
	ourURI   = "https://acme-v02.api.letsencrypt.org/acme/acct/123"
	otherURI = "https://acme-v02.api.letsencrypt.org/acme/acct/999"
)

func okPlan() domains.Plan {
	return domains.Plan{Name: testD, CanWrite: true,
		Items: []domains.PlanItem{
			{Set: "address", Name: testD, Type: "A", Want: []string{"203.0.113.10"}, Live: []string{"203.0.113.10"}, Status: "ok", Severity: "ok", Fix: "none"},
			{Set: "caa", Name: testD, Type: "CAA", Want: []string{`0 issue "letsencrypt.org; accounturi=` + ourURI + `; validationmethods=dns-01"`},
				Live: []string{`0 issue "letsencrypt.org; accounturi=` + ourURI + `; validationmethods=dns-01"`}, Status: "ok", Severity: "ok", Fix: "none"},
		},
		CAA:    domains.PlanCAA{Issuer: "letsencrypt.org", AccountURI: ourURI, WouldIssue: true},
		DNSSEC: domains.PlanDNSSEC{State: "secure", Zone: "example.org"}}
}

func dnsRun(plans []domains.Plan, main *domains.Plan) []Finding {
	return Run(&Inputs{DNS: plans, DNSMain: main}, nil).Findings
}

func onlyKind(t *testing.T, fs []Finding, kind string) Finding {
	t.Helper()
	var got []Finding
	for _, f := range fs {
		if f.Kind == kind {
			got = append(got, f)
		}
	}
	if len(got) != 1 {
		t.Fatalf("%s: %d findings, want 1 (all: %+v)", kind, len(got), fs)
	}
	return got[0]
}

func TestDNSKinds(t *testing.T) {
	cases := []struct {
		kind  string
		edit  func(p *domains.Plan)
		sev   Severity
		class FixClass
		fix   string
		sets  []string
	}{
		{KindDNSRecordsWrong, func(p *domains.Plan) {
			p.Items[0].Status, p.Items[0].Severity, p.Items[0].Fix, p.Items[0].Live = "wrong", "problem", "auto", []string{"198.51.100.1"}
		}, Problem, FixOneClick, FixDNSApply, []string{"address"}},
		{KindDNSCAAMissing, func(p *domains.Plan) {
			p.Items[1].Status, p.Items[1].Severity, p.Items[1].Fix, p.Items[1].Live = "missing", "warning", "auto", []string{}
		}, Warning, FixOneClick, FixDNSApply, []string{"caa"}},
		{KindDNSCAAWrongAccount, func(p *domains.Plan) {
			p.CAA.WouldIssue = false
			p.Items[1].Status, p.Items[1].Severity, p.Items[1].Fix = "wrong", "problem", "auto"
			p.Items[1].Live = []string{`0 issue "letsencrypt.org; accounturi=` + otherURI + `; validationmethods=dns-01"`}
		}, Problem, FixOneClick, FixDNSApply, []string{"caa"}},
		{KindDNSCAAOtherIssuers, func(p *domains.Plan) {
			p.Items = append(p.Items, domains.PlanItem{Set: "caa", Name: testD, Type: "CAA", Want: []string{}, Live: []string{}, Status: "foreign", Severity: "info", Fix: "none",
				Steps: []string{"other CAs may also issue for " + testD + ": digicert.com"}})
		}, Info, FixExplain, "", nil},
		{KindDNSSECBogus, func(p *domains.Plan) {
			p.DNSSEC.State, p.DNSSEC.Steps = "ds_mismatch", []string{"Validating resolvers can't reach " + testD + "."}
		}, Problem, FixExplain, "", nil},
		{KindDNSSECDSMissing, func(p *domains.Plan) {
			p.DNSSEC.State = "ds_missing"
			p.DNSSEC.DS = []domains.DS{{KeyTag: 2371, Algorithm: 13, DigestType: 2, Digest: "1F98"}}
			p.DNSSEC.Steps = []string{"Add this DS at your registrar: key tag 2371, algorithm 13, digest type 2, digest 1F98"}
		}, Warning, FixExplain, "", nil},
		{KindDNSSECUnsigned, func(p *domains.Plan) { p.DNSSEC.State, p.DNSSEC.ProviderCanSign = "unsigned", true }, Info, FixOneClick, FixDNSSECSign, nil},
		{KindDNSDangling, func(p *domains.Plan) {
			p.Items = append(p.Items, domains.PlanItem{Set: "address", Name: "app." + testD, Type: "CNAME", Want: []string{}, Live: []string{"old.example.net."},
				Status: "foreign", Severity: "warning", Fix: "manual", Steps: []string{"remove the dangling CNAME"}})
		}, Warning, FixExplain, "", nil},
		{KindDNSShadowed, func(p *domains.Plan) {
			p.Items = append(p.Items, domains.PlanItem{Set: "address", Name: "app." + testD, Type: "A", Want: []string{}, Live: []string{"198.51.100.7"},
				Status: "foreign", Severity: "info", Fix: "manual", Steps: []string{"app." + testD + " doesn't reach Portcullis"}})
		}, Info, FixExplain, "", nil},
		{KindDNSNoMailRecommended, func(p *domains.Plan) {
			p.Items = append(p.Items, domains.PlanItem{Set: "nomail", Name: testD, Type: "MX", Want: []string{"0 ."}, Live: []string{}, Status: "missing", Severity: "info", Fix: "auto"})
		}, Info, FixOneClick, FixDNSApply, []string{"nomail"}},
	}
	if fs := dnsRun([]domains.Plan{okPlan()}, nil); len(fs) != 0 {
		t.Fatalf("a clean plan: %+v", fs)
	}
	for _, c := range cases {
		p := okPlan()
		c.edit(&p)
		fs := dnsRun([]domains.Plan{p}, nil)
		f := onlyKind(t, fs, c.kind)
		if len(fs) != 1 {
			t.Errorf("%s: other findings too: %+v", c.kind, fs)
		}
		if f.Severity != c.sev || f.Class != c.class || f.FixKind != c.fix {
			t.Errorf("%s: severity %s class %s fix %q, want %s %s %q", c.kind, f.Severity, f.Class, f.FixKind, c.sev, c.class, c.fix)
		}
		if !slices.Equal(DNSFixSets(c.kind), c.sets) {
			t.Errorf("%s: sets %v, want %v", c.kind, DNSFixSets(c.kind), c.sets)
		}
		if !slices.Equal(f.Domains, []string{testD}) || f.Title == "" || f.Why == "" {
			t.Errorf("%s: domains %v title %q", c.kind, f.Domains, f.Title)
		}
		if c.class == FixExplain && len(f.Steps) == 0 && c.kind != KindDNSCAAOtherIssuers {
			t.Errorf("%s: explain-only without steps", c.kind)
		}
		wantFP := Fingerprint(c.kind, testD)
		if c.kind == KindDNSDangling || c.kind == KindDNSShadowed {
			wantFP = Fingerprint(c.kind, testD, "app."+testD)
		}
		if f.FP != wantFP {
			t.Errorf("%s: fp %s, want %s", c.kind, f.FP, wantFP)
		}
	}
	// unsigned where the provider can't sign: explain-only with its steps.
	p := okPlan()
	p.DNSSEC.State, p.DNSSEC.Steps = "unsigned", []string{"digitalocean can't sign: move the zone to sign it"}
	if f := onlyKind(t, dnsRun([]domains.Plan{p}, nil), KindDNSSECUnsigned); f.Class != FixExplain || f.FixKind != "" || len(f.Steps) != 1 {
		t.Errorf("unsigned, can't sign: %+v", f)
	}
}

// TestDNSUnknownCANotCAAMissing (controller carry): an unknown CA's one
// item (set caa, status unknown, severity info, fix none, "CAA skipped:
// unknown CA") is never dns_caa_missing — no finding at all.
func TestDNSUnknownCANotCAAMissing(t *testing.T) {
	p := okPlan()
	p.CAA = domains.PlanCAA{}
	p.Items[1] = domains.PlanItem{Set: "caa", Name: testD, Type: "CAA", Want: []string{}, Live: []string{}, Status: "unknown", Severity: "info", Fix: "none",
		Steps: []string{"CAA skipped: unknown CA (set DNS_CAA_ISSUER to its CAA issuer domain)"}}
	if fs := dnsRun([]domains.Plan{p}, nil); len(fs) != 0 {
		t.Fatalf("unknown CA: %+v", fs)
	}
}

// TestDNSMainExplainOnly: the main domain's findings are explain-only,
// ending with the server command, never a one-click fix.
func TestDNSMainExplainOnly(t *testing.T) {
	p := okPlan()
	p.Name, p.CanWrite = "example.org", false
	for i := range p.Items {
		p.Items[i].Name = "example.org"
	}
	p.Items[0].Status, p.Items[0].Fix = "missing", "manual"
	p.Items[1].Status, p.Items[1].Fix = "missing", "manual"
	p.DNSSEC.State, p.DNSSEC.ProviderCanSign = "unsigned", true
	p.Items = append(p.Items, domains.PlanItem{Set: "nomail", Name: "example.org", Type: "MX", Want: []string{"0 ."}, Live: []string{}, Status: "missing", Severity: "info", Fix: "manual"})
	fs := dnsRun([]domains.Plan{}, &p)
	if len(fs) != 4 {
		t.Fatalf("main findings %+v", fs)
	}
	for _, f := range fs {
		last := DNSMainStep
		if f.Kind == KindDNSSECUnsigned {
			last = DNSMainDNSSECStep // docs M9: signing needs --dnssec
		}
		if f.Class != FixExplain || f.FixKind != "" || len(f.Steps) == 0 || f.Steps[len(f.Steps)-1] != last || !slices.Equal(f.Domains, []string{"example.org"}) {
			t.Errorf("main %s: %+v", f.Kind, f)
		}
	}
	if !strings.Contains(DNSMainStep, "./portcullis dns setup") {
		t.Fatal(DNSMainStep)
	}
	if !strings.Contains(DNSMainDNSSECStep, "./portcullis dns setup --dnssec") || !strings.Contains(DNSMainDNSSECStep, "Cloudflare only") {
		t.Fatal(DNSMainDNSSECStep)
	}
}

// TestDNSAddressBlockedByCNAME (final review I2): a CNAME at <d> or *.<d>
// (an address item foreign / problem / manual) is dns_records_wrong,
// explain-only with the plan's steps (the service refuses address next to
// a CNAME), also when other address items could be fixed.
func TestDNSAddressBlockedByCNAME(t *testing.T) {
	cname := domains.PlanItem{Set: "address", Name: "*." + testD, Type: "CNAME", Want: []string{}, Live: []string{"elsewhere.example.net."},
		Status: "foreign", Severity: "problem", Fix: "manual", Steps: []string{"remove the CNAME at *." + testD + " first"}}
	p := okPlan()
	p.Items = append(p.Items, cname)
	f := onlyKind(t, dnsRun([]domains.Plan{p}, nil), KindDNSRecordsWrong)
	if f.Severity != Problem || f.Class != FixExplain || f.FixKind != "" || !slices.Equal(f.Steps, cname.Steps) || f.FP != Fingerprint(KindDNSRecordsWrong, testD) {
		t.Fatalf("cname: %+v", f)
	}
	q := okPlan()
	q.Items[0].Status, q.Items[0].Severity, q.Items[0].Fix, q.Items[0].Steps = "wrong", "problem", "auto", []string{"set A"}
	q.Items = append(q.Items, cname)
	g := onlyKind(t, dnsRun([]domains.Plan{q}, nil), KindDNSRecordsWrong)
	if g.Class != FixExplain || g.FixKind != "" || !slices.Equal(g.Steps, []string{"set A", cname.Steps[0]}) {
		t.Fatalf("wrong + cname: %+v", g)
	}
}

// TestDNSUnavailableOnUnknown (final review I1): a plan whose lookups
// failed (an unknown item above info, or DNSSEC state unknown) — of an
// added domain or the main one — sets dns_unavailable; the unknown-CA item
// (caa / unknown / info) doesn't.
func TestDNSUnavailableOnUnknown(t *testing.T) {
	unknownItem := func(p *domains.Plan) {
		p.Items[0].Status, p.Items[0].Severity, p.Items[0].Live = "unknown", "warning", nil
	}
	unknownSEC := func(p *domains.Plan) { p.DNSSEC.State = "unknown" }
	unknownCA := func(p *domains.Plan) {
		p.CAA = domains.PlanCAA{}
		p.Items[1] = domains.PlanItem{Set: "caa", Name: testD, Type: "CAA", Status: "unknown", Severity: "info", Fix: "none"}
	}
	for _, c := range []struct {
		name string
		edit func(*domains.Plan)
		want bool
	}{{"item", unknownItem, true}, {"dnssec", unknownSEC, true}, {"unknown CA", unknownCA, false}, {"clean", func(*domains.Plan) {}, false}} {
		p := okPlan()
		c.edit(&p)
		if r := Run(&Inputs{DNS: []domains.Plan{okPlan(), p}}, nil); r.DNSUnavailable != c.want {
			t.Errorf("%s (added): dns_unavailable %v", c.name, r.DNSUnavailable)
		}
		ok := okPlan()
		if r := Run(&Inputs{DNS: []domains.Plan{ok}, DNSMain: &p}, nil); r.DNSUnavailable != c.want {
			t.Errorf("%s (main): dns_unavailable %v", c.name, r.DNSUnavailable)
		}
	}
}

// TestDNSFingerprintStable: reordered items give the same findings; a
// changed live value changes the inputs digest (the mute lifts) but not
// the fingerprint.
func TestDNSFingerprintStable(t *testing.T) {
	p := okPlan()
	p.Items[0].Status, p.Items[0].Live = "wrong", []string{"198.51.100.1"}
	p.Items = append(p.Items, domains.PlanItem{Set: "address", Name: "*." + testD, Type: "A", Want: []string{"203.0.113.10"}, Live: []string{"198.51.100.2", "198.51.100.3"}, Status: "wrong"})
	a := onlyKind(t, dnsRun([]domains.Plan{p}, nil), KindDNSRecordsWrong)
	q := p
	q.Items = []domains.PlanItem{p.Items[2], p.Items[1], p.Items[0]}
	q.Items[0].Live = []string{"198.51.100.3", "198.51.100.2"}
	b := onlyKind(t, dnsRun([]domains.Plan{q}, nil), KindDNSRecordsWrong)
	if a.FP != b.FP || a.Token != b.Token {
		t.Fatalf("reordered: %s/%s vs %s/%s", a.FP, a.Token, b.FP, b.Token)
	}
	r := p
	r.Items = slices.Clone(p.Items)
	r.Items[0].Live = []string{"198.51.100.9"}
	c := onlyKind(t, dnsRun([]domains.Plan{r}, nil), KindDNSRecordsWrong)
	if c.FP != a.FP || c.Token == a.Token {
		t.Fatalf("changed live value: fp %s/%s token %s/%s", a.FP, c.FP, a.Token, c.Token)
	}
}

// TestDNSUnavailableNoFindings (F19): without DNS inputs there are no DNS
// findings and the report says so; with them (even none) it doesn't.
func TestDNSUnavailableNoFindings(t *testing.T) {
	main := okPlan()
	main.DNSSEC.State = "bogus"
	r := Run(&Inputs{DNS: nil, DNSMain: &main}, nil)
	if len(r.Findings) != 0 || !r.DNSUnavailable {
		t.Fatalf("unavailable: %+v", r)
	}
	if r := Run(&Inputs{DNS: []domains.Plan{}}, nil); r.DNSUnavailable {
		t.Fatal("available with no domains reads as unavailable")
	}
}

func TestDNSKindsRegistered(t *testing.T) {
	ks := Kinds()
	for _, k := range DNSKinds {
		if !slices.Contains(ks, k) {
			t.Errorf("kind %s isn't registered", k)
		}
	}
	if len(DNSKinds) != 10 {
		t.Fatalf("%d DNS kinds, want 10", len(DNSKinds))
	}
}
