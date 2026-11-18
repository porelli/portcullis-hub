package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
	"github.com/portcullis/hub/internal/state"
)

const teamB = "team-b.example.net"

// goodSet is a valid set for domain d (MAIL_HOSTNAME mail.example.org)
// with DMARC policy p.
func goodSet(d, p string) mailprovider.DNSSet {
	return mailprovider.DNSSet{Domain: d, DKIM: "auto", Records: []mailprovider.Record{
		{Name: d, Type: "MX", TTL: 3600, Value: "10 mail.example.org."},
		{Name: d, Type: "TXT", TTL: 3600, Value: "v=spf1 mx -all"},
		{Name: "_dmarc." + d, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=" + p + "; rua=mailto:dmarc-reports@" + d},
	}}
}

func (w *wireFix) setDNS(d string, set mailprovider.DNSSet) {
	w.mc.Lock(func(s *mailprovidertest.Server) { s.DNSSets[d] = set })
}

func (w *wireFix) writeSet(t *testing.T, d string) error {
	t.Helper()
	return w.h.writeMailSet(context.Background(), w.mc.Client(), w.dom, d)
}

func storedDMARC(w *wireFix, d string) string {
	w.dom.mu.Lock()
	defer w.dom.mu.Unlock()
	for _, r := range w.dom.mailSets[d] {
		if strings.HasPrefix(r.Name, "_dmarc.") {
			return r.Value
		}
	}
	return ""
}

// TestRefusedSetKeepsLastGood: a set outside the table isn't written;
// the last good one stays and the doctor's problem names the domain.
func TestRefusedSetKeepsLastGood(t *testing.T) {
	w := wiredFix(t)
	w.h.mu.Lock()
	w.h.st.Mail.Domains[teamB] = state.MailDomain{Enabled: true}
	w.h.mu.Unlock()
	w.sync(t)
	w.setDNS(teamB, goodSet(teamB, "reject"))
	if err := w.writeSet(t, teamB); err != nil {
		t.Fatal(err)
	}
	bad := goodSet(teamB, "reject")
	bad.Records = append(bad.Records, mailprovider.Record{Name: teamB, Type: "A", TTL: 300, Value: "203.0.113.66"})
	w.setDNS(teamB, bad)
	err := w.writeSet(t, teamB)
	if !errors.Is(err, errMailSetRefused) || !strings.Contains(err.Error(), "A records are not allowed") {
		t.Fatalf("%v", err)
	}
	w.dom.mu.Lock()
	n := len(w.dom.mailSets[teamB])
	w.dom.mu.Unlock()
	if n != 3 {
		t.Fatalf("the stored set changed: %d records", n)
	}
	if p := w.h.MailDNSProblems(); len(p) != 1 || p[0].Domain != teamB || !strings.Contains(p[0].Reason, "A records") {
		t.Fatalf("problems %+v", p)
	}
	w.setDNS(teamB, goodSet(teamB, "reject"))
	if err := w.writeSet(t, teamB); err != nil || len(w.h.MailDNSProblems()) != 0 {
		t.Fatalf("%v %+v", err, w.h.MailDNSProblems())
	}
}

// TestFloorFromPublished: the published p= raises dmarc_floor over a
// lower dmarc_start; a set below it is refused.
func TestFloorFromPublished(t *testing.T) {
	w := wiredFix(t)
	w.h.mu.Lock()
	w.h.st.Mail.Domains[teamB] = state.MailDomain{Enabled: true, HadMailRecords: true} // dmarc_start none
	w.h.mu.Unlock()
	w.setDNS(teamB, goodSet(teamB, "quarantine"))
	w.sync(t)
	if err := w.writeSet(t, teamB); err != nil {
		t.Fatal(err)
	}
	w.h.mu.RLock()
	floor := mailDMARCFloor(w.h.st.Mail, teamB, "none")
	w.h.mu.RUnlock()
	if floor != "quarantine" {
		t.Fatalf("floor %s", floor)
	}
	w.sync(t)
	var got string
	for _, d := range w.mc.Last().Domains {
		if d.Name == teamB {
			got = d.DMARCStart + "/" + d.DMARCFloor
		}
	}
	if got != "none/quarantine" {
		t.Fatalf("document %s", got)
	}
	w.setDNS(teamB, goodSet(teamB, "none"))
	if err := w.writeSet(t, teamB); err == nil || !strings.Contains(err.Error(), "p=none is below the floor quarantine") {
		t.Fatalf("%v", err)
	}
	if v := storedDMARC(w, teamB); !strings.Contains(v, "p=quarantine") {
		t.Fatalf("stored %q", v)
	}
}

// TestSwitchNeverLowersDMARC (moved from Task 9): after a switch the new
// provider's set below the published policy is dropped.
func TestSwitchNeverLowersDMARC(t *testing.T) {
	w := switchFix(t)
	w.h.mu.Lock()
	w.h.st.Mail.Domains[teamB] = state.MailDomain{Enabled: true}
	w.h.mu.Unlock()
	w.sync(t)
	w.setDNS(teamB, goodSet(teamB, "reject"))
	if err := w.writeSet(t, teamB); err != nil {
		t.Fatal(err)
	}
	doSwitch(t, w)
	w.setDNS(teamB, goodSet(teamB, "none"))
	if err := w.writeSet(t, teamB); err == nil || !strings.Contains(err.Error(), "below the floor reject") {
		t.Fatalf("%v", err)
	}
	if v := storedDMARC(w, teamB); !strings.Contains(v, "p=reject") {
		t.Fatalf("stored %q", v)
	}
}

// TestMainDNSRouteValidated: GET /host/mail/dns/main answers the
// validated main set; a refused one is 409 with the reason; nothing
// wired is 409 "no mail provider is wired".
func TestMainDNSRouteValidated(t *testing.T) {
	w := wiredFix(t)
	w.setDNS("example.org", goodSet("example.org", "reject"))
	recs, err := w.h.HostMailDNSMain(context.Background())
	if err != nil || len(recs) != 3 {
		t.Fatalf("%v %+v", err, recs)
	}
	bad := goodSet("example.org", "reject")
	bad.Records[0].Value = "10 mx.evil.example.net."
	w.setDNS("example.org", bad)
	if recs, err := w.h.HostMailDNSMain(context.Background()); statusOf(err) != 409 || !strings.Contains(err.Error(), "the target must be mail.example.org.") {
		t.Fatalf("%v %+v", err, recs)
	}
	w.h.mu.Lock()
	w.h.st.Mail.Provider = nil
	w.h.mu.Unlock()
	if _, err := w.h.HostMailDNSMain(context.Background()); statusOf(err) != 409 || err.Error() != "no mail provider is wired" {
		t.Fatalf("%v", err)
	}
}

// TestMainDNSRetiringDKIMIncluded: the main set carries a switch's
// retiring DKIM until its 7 days are over.
func TestMainDNSRetiringDKIMIncluded(t *testing.T) {
	w := wiredFix(t)
	w.setDNS("example.org", goodSet("example.org", "reject"))
	w.h.mu.Lock()
	w.h.st.Mail.RetiringDKIM = map[string]state.RetiringDKIM{"example.org": {
		Records: []state.MailRecord{{Name: "old._domainkey.example.org", Type: "TXT", TTL: 3600, Value: "v=DKIM1; p=OLD"}},
		Until:   w.now.Add(MailDKIMRetention)}}
	w.h.mu.Unlock()
	recs, err := w.h.HostMailDNSMain(context.Background())
	if err != nil || len(recs) != 4 || recs[3].Name != "old._domainkey.example.org" {
		t.Fatalf("%v %+v", err, recs)
	}
	w.advance(MailDKIMRetention + 1)
	recs, _ = w.h.HostMailDNSMain(context.Background())
	if len(recs) != 3 {
		t.Fatalf("expired retiring DKIM kept: %+v", recs)
	}
}

// policyServer serves body at /.well-known/mta-sts.txt over TLS and
// counts requests (with the Host it saw).
func policyServer(t *testing.T, w *wireFix, body string) *atomic.Int32 {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/.well-known/mta-sts.txt" || r.Host != "mta-sts.example.org" || r.TLS == nil || r.TLS.ServerName != "mta-sts.example.org" {
			http.NotFound(rw, r)
			return
		}
		rw.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	w.h.cfg.MailPolicyAddr = strings.TrimPrefix(srv.URL, "https://")
	w.h.mu.Lock()
	w.h.st.Mail.MTASTSPublished = map[string]bool{"example.org": true}
	w.h.mu.Unlock()
	return &hits
}

// TestMTASTSPolicyWrongMX: a policy naming another mx (or two, or no
// version) is refused and recorded; the right one passes and clears it.
func TestMTASTSPolicyWrongMX(t *testing.T) {
	w := wiredFix(t)
	ctx := context.Background()
	policyServer(t, w, "version: STSv1\r\nmode: testing\r\nmx: mx.evil.example.net\r\nmax_age: 86400\r\n")
	if err := w.h.checkMTASTSPolicy(ctx, "example.org"); err == nil || !strings.Contains(err.Error(), "exactly one mx: mail.example.org") {
		t.Fatalf("%v", err)
	}
	if p := w.h.MailDNSProblems(); len(p) != 1 || p[0].Domain != "example.org" {
		t.Fatalf("%+v", p)
	}
	for _, body := range []string{"version: STSv1\nmx: mail.example.org\nmx: mail2.example.org\n", "mode: testing\nmx: mail.example.org\n"} {
		policyServer(t, w, body)
		if err := w.h.checkMTASTSPolicy(ctx, "example.org"); err == nil {
			t.Errorf("%q accepted", body)
		}
	}
	policyServer(t, w, "version: STSv1\nmode: enforce\nmx: mail.example.org\nmax_age: 604800\n")
	if err := w.h.checkMTASTSPolicy(ctx, "example.org"); err != nil || len(w.h.MailDNSProblems()) != 0 {
		t.Fatalf("%v %+v", err, w.h.MailDNSProblems())
	}
}

// TestMTASTSPolicySkippedWhenOff: no fetch while the Hub published no
// _mta-sts record for the domain or the well-known router isn't public
// (VPN server mode); the provider's word never switches it off (M13).
func TestMTASTSPolicySkippedWhenOff(t *testing.T) {
	w := wiredFix(t)
	hits := policyServer(t, w, "version: STSv1\nmx: mx.evil.example.net\n")
	// The provider reports off, but the Hub published the record: judged.
	w.mc.Lock(func(s *mailprovidertest.Server) {
		s.StatusV.MTASTS = []mailprovider.StatusMTASTS{{Domain: "example.org", Mode: "off"}}
	})
	if err := w.h.checkMTASTSPolicy(context.Background(), "example.org"); err == nil || hits.Load() != 1 {
		t.Fatalf("provider off: %v, %d fetches", err, hits.Load())
	}
	w.h.mu.Lock()
	w.h.st.Mail.MTASTSPublished = nil
	w.h.mu.Unlock()
	if err := w.h.checkMTASTSPolicy(context.Background(), "example.org"); err != nil || hits.Load() != 1 {
		t.Fatalf("unpublished: %v, %d fetches", err, hits.Load())
	}
	w.h.mu.Lock()
	w.h.st.Mail.MTASTSPublished = map[string]bool{"example.org": true}
	w.h.mu.Unlock()
	writeFile(t, filepath.Join(w.project, ".env"), "CORE_VAR=core-value\nPORTCULLIS_MAIL=on\nPORTCULLIS_MAIL_HOSTNAME=mail.example.org\n"+VarVPNMode+"="+VPNModeServer+"\n")
	if err := w.h.checkMTASTSPolicy(context.Background(), "example.org"); err != nil || hits.Load() != 1 {
		t.Fatalf("server mode: %v, %d fetches", err, hits.Load())
	}
}

// TestPublishedSetRecordsMTASTS (M13): publishing a set records whether
// it carries _mta-sts.<d>.
func TestPublishedSetRecordsMTASTS(t *testing.T) {
	w := wiredFix(t)
	w.h.mailSetPublished("Example.org", []mailprovider.Record{{Name: "_mta-sts.example.org", Type: "TXT", Value: "v=STSv1; id=1"}})
	w.h.mu.RLock()
	on := w.h.st.Mail.MTASTSPublished["example.org"]
	w.h.mu.RUnlock()
	w.h.mailSetPublished("example.org", nil)
	w.h.mu.RLock()
	off := w.h.st.Mail.MTASTSPublished["example.org"]
	w.h.mu.RUnlock()
	if !on || off {
		t.Fatalf("on %v off %v", on, off)
	}
}

// TestMailSetBodyCarriesRules: the PUT carries the rules' inputs the
// domains service judges with (mail_hostname, relay_include,
// dmarc_floor, wildcard, draining).
func TestMailSetBodyCarriesRules(t *testing.T) {
	w := wiredFix(t)
	w.h.mu.Lock()
	w.h.st.Mail.Domains[teamB] = state.MailDomain{Enabled: true}
	w.h.st.Mail.Relay = &state.MailRelay{Host: "smtp.relay.example.net", Port: 465, SPFInclude: "_spf.relay.example.net"}
	w.h.mu.Unlock()
	w.sync(t)
	w.setDNS(teamB, goodSet(teamB, "reject"))
	if err := w.writeSet(t, teamB); err != nil {
		t.Fatal(err)
	}
	w.dom.mu.Lock()
	b := w.dom.mailBodies[len(w.dom.mailBodies)-1]
	w.dom.mu.Unlock()
	if b.MailHostname != "mail.example.org" || b.RelayInclude != "_spf.relay.example.net" || b.DMARCFloor != "reject" || b.Draining || len(b.Records) != 3 {
		t.Fatalf("%+v", b)
	}
}

// dnsFlipAPI changes the main domain's rule context during its DNS
// read (a relay include set mid-read), the first flips times.
type dnsFlipAPI struct {
	MailAPI
	h     *Hub
	flips int
	n     int
}

func (a *dnsFlipAPI) DNS(ctx context.Context, d string, wc bool) (mailprovider.DNSSet, error) {
	if a.n < a.flips {
		a.n++
		a.h.mu.Lock()
		a.h.st.Mail.Relay = nil
		if a.n%2 == 1 {
			a.h.st.Mail.Relay = &state.MailRelay{SPFInclude: fmt.Sprintf("spf%d.relay.example.net", a.n)}
		}
		a.h.mu.Unlock()
	}
	return a.MailAPI.DNS(ctx, d, wc)
}

// TestMainDNSRulesOneSnapshot (final cross review L10): the main set and
// its rules are one consistent pair: a rule change during the read reads
// both again; one that never settles is a 409, never a mismatched pair.
func TestMainDNSRulesOneSnapshot(t *testing.T) {
	w := wiredFix(t)
	w.setDNS("example.org", goodSet("example.org", "reject"))
	// A relay include set during the first read, gone during the second:
	// the third read's pair is consistent (and valid: no relay).
	api := &dnsFlipAPI{MailAPI: w.mc.Client(), h: w.h, flips: 2}
	w.h.SetMailAPI(api)
	recs, rules, err := w.h.HostMailDNSMainWithRules(context.Background())
	if err != nil || len(recs) != 3 || rules.RelayInclude != "" || rules != w.h.HostMailDNSRules() {
		t.Fatalf("%v %d %+v", err, len(recs), rules)
	}
	api.flips, api.n = 10, 0
	if _, _, err := w.h.HostMailDNSMainWithRules(context.Background()); statusOf(err) != 409 {
		t.Fatalf("never settling: %v", err)
	}
}
