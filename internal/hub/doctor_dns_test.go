package hub

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/domains"
)

// DNS hardening Task 12: the doctor's DNS inputs and the dns_apply /
// dnssec_sign fixes (contract §14.5–14.6).

const dnsD = "team-b.example.net"

func dnsDoctorFixture(t *testing.T) (*fixture, *fakeDomainsAPI, *fakeAudit) {
	t.Helper()
	f, api, audit := newDomainsFixture(t)
	f.h.SetPeople(newFakePeople("erin"))
	readyDomain(t, f, api, dnsD)
	api.plans[dnsD] = domains.Plan{Name: dnsD, CanWrite: true,
		Items: []domains.PlanItem{{Set: "caa", Name: dnsD, Type: "CAA", Want: []string{`0 issue "letsencrypt.org; validationmethods=dns-01"`},
			Live: []string{`0 issue "digicert.com"`}, Status: "missing", Severity: "warning", Fix: "auto"}},
		CAA:    domains.PlanCAA{Issuer: "letsencrypt.org"},
		DNSSEC: domains.PlanDNSSEC{State: "unsigned", Zone: "example.net", ProviderCanSign: true}}
	api.main = domains.Plan{Name: "example.org", DNSSEC: domains.PlanDNSSEC{State: "secure"}}
	return f, api, audit
}

func waitDomainOp(t *testing.T, f *fixture, name string) *OpRecord {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r := f.h.LastOp(OpKeyDomain(name)); r != nil && !r.Running {
			return r
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no ended op record for %s", name)
	return nil
}

// TestDNSDoctorInputs: the doctor reads the cached plans (never a
// refresh); with the service down its report has no DNS findings and
// says dns_unavailable.
func TestDNSDoctorInputs(t *testing.T) {
	f, api, _ := dnsDoctorFixture(t)
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, x := range r.Findings {
		if slices.Contains(x.Domains, dnsD) {
			kinds = append(kinds, x.Kind)
		}
	}
	slices.Sort(kinds)
	if strings.Join(kinds, ",") != "dns_caa_missing,dnssec_unsigned" || r.DNSUnavailable || api.refreshes != 0 {
		t.Fatalf("kinds %v, unavailable %v, refreshes %d", kinds, r.DNSUnavailable, api.refreshes)
	}
	api.setDown(true)
	r, err = f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range r.Findings {
		if len(x.Domains) > 0 {
			t.Errorf("DNS finding while unavailable: %+v", x)
		}
	}
	if !r.DNSUnavailable {
		t.Fatal("dns_unavailable not set")
	}
}

// TestDNSApplyPreviewHash: the preview refreshes the plan and lists one
// line per differing item; the apply runs under _domain.<name> and calls
// ApplyDomainDNS with the finding's set (audited domain.dns_apply and
// doctor.fix).
func TestDNSApplyPreviewHash(t *testing.T) {
	f, api, audit := dnsDoctorFixture(t)
	ctx := context.Background()
	fp := doctor.Fingerprint(doctor.KindDNSCAAMissing, dnsD)
	p, err := f.h.PreviewFix(ctx, fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `caa ` + dnsD + ` CAA: 0 issue "digicert.com" → 0 issue "letsencrypt.org; validationmethods=dns-01"`
	if !slices.Equal(p.Lines, []string{want}) || p.Kind != doctor.FixDNSApply || p.TouchesData || len(p.Hash) != 64 || api.refreshes != 1 {
		t.Fatalf("plan %+v (refreshes %d)", p, api.refreshes)
	}
	if _, err := f.h.PreviewFix(ctx, fp, map[string]string{"sets": "address"}); statusOf(err) != 400 {
		t.Fatalf("another set: %v", err)
	}
	op, err := f.h.ApplyFix(ctx, fp, nil, p.Hash, directory.Human("alice"))
	if err != nil || op.Instance != "_domain."+dnsD || op.Op != OpDNSApply {
		t.Fatalf("apply = %+v, %v", op, err)
	}
	rec := waitDomainOp(t, f, dnsD)
	if !rec.OK || rec.Result["sets"] != "caa" {
		t.Fatalf("record %+v", rec)
	}
	if strings.Join(api.applied, ";") != dnsD+" caa" {
		t.Fatalf("applied %v", api.applied)
	}
	var actions []string
	for _, e := range audit.entries {
		actions = append(actions, e.Action+":"+e.Result)
	}
	if !slices.Contains(actions, "domain.dns_apply:ok") || !slices.Contains(actions, "doctor.fix:ok") {
		t.Fatalf("audit %v", actions)
	}
}

// TestDNSApplyHashMismatch409: a live value that changed since the
// preview is 409 "the DNS records changed since the preview", nothing
// applied.
func TestDNSApplyHashMismatch409(t *testing.T) {
	f, api, _ := dnsDoctorFixture(t)
	ctx := context.Background()
	fp := doctor.Fingerprint(doctor.KindDNSCAAMissing, dnsD)
	p, err := f.h.PreviewFix(ctx, fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	pl := api.plans[dnsD]
	pl.Items[0].Live = []string{`0 issue "sectigo.com"`}
	api.plans[dnsD] = pl
	api.mu.Unlock()
	_, err = f.h.ApplyFix(ctx, fp, nil, p.Hash, directory.Human("alice"))
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "the DNS records changed since the preview: preview it again") {
		t.Fatalf("apply = %v", err)
	}
	if len(api.applied) != 0 {
		t.Fatalf("applied %v", api.applied)
	}
}

// TestDNSSECSignPreviewLine: exactly one line naming the zone; the apply
// calls EnableDomainDNSSEC (audited domain.dnssec_enable); through the
// AI without a confirmation it is refused before anything runs.
func TestDNSSECSignPreviewLine(t *testing.T) {
	f, api, _ := dnsDoctorFixture(t)
	ctx := context.Background()
	fp := doctor.Fingerprint(doctor.KindDNSSECUnsigned, dnsD)
	p, err := f.h.PreviewFix(ctx, fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Lines, []string{"turns on signing for the whole zone example.net"}) || p.TouchesData || p.Kind != doctor.FixDNSSECSign {
		t.Fatalf("plan %+v", p)
	}
	if need, err := f.h.FixNeedsConfirmation(ctx, nil, fp, nil, p.Hash); !need || err != nil {
		t.Fatalf("needs confirmation = %v, %v", need, err)
	}
	ai := directory.Actor{User: "alice", Via: directory.ViaAI, Client: "portcullis-ai-claude"}
	if _, err := f.h.ApplyFix(ctx, fp, nil, p.Hash, ai); statusOf(err) != 409 || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("AI without confirmation: %v", err)
	}
	if _, err := f.h.ApplyFix(ctx, fp, nil, p.Hash, directory.Human("alice")); err != nil {
		t.Fatal(err)
	}
	if rec := waitDomainOp(t, f, dnsD); !rec.OK || rec.Op != OpDNSSECSign || rec.Result["zone"] != "example.net" {
		t.Fatalf("record %+v", rec)
	}
	if !slices.Equal(api.signed, []string{dnsD}) {
		t.Fatalf("signed %v", api.signed)
	}
	// dns_apply is W (no confirmation).
	ap, err := f.h.PreviewFix(ctx, doctor.Fingerprint(doctor.KindDNSCAAMissing, dnsD), nil)
	if err != nil {
		t.Fatal(err)
	}
	if need, err := f.h.FixNeedsConfirmation(ctx, nil, doctor.Fingerprint(doctor.KindDNSCAAMissing, dnsD), nil, ap.Hash); need || err != nil {
		t.Fatalf("dns_apply needs confirmation = %v, %v", need, err)
	}
}

// TestDNSFixersTouchNoData (F9): both declare TouchesData false; only
// dnssec_sign always confirms.
func TestDNSFixersTouchNoData(t *testing.T) {
	for _, k := range []string{doctor.FixDNSApply, doctor.FixDNSSECSign} {
		fx := fixerFor(k)
		if fx == nil || fx.TouchesData() {
			t.Errorf("fixer %s: %v", k, fx)
		}
	}
	if fixerAlwaysConfirms(fixerFor(doctor.FixDNSApply)) || !fixerAlwaysConfirms(fixerFor(doctor.FixDNSSECSign)) {
		t.Error("AlwaysConfirm wrong")
	}
	if !validOpKey(OpKeyDomain("Team-B.example.net")) || validOpKey("_domain.") || validOpKey("_domain.bad_name") {
		t.Error("validOpKey for _domain.")
	}
}

// TestDNSNamesNeverReachOpPaths (security review): a plan the service
// answers under another name ("../x", "a/b", a name not added) is
// dropped; a finding naming such a domain has no fix; validOpKey refuses
// path separators and dot-dot, and startAsync / recordOp refuse any key
// it refuses (no file outside the ops directory).
func TestDNSNamesNeverReachOpPaths(t *testing.T) {
	f, api, _ := dnsDoctorFixture(t)
	ctx := context.Background()
	for _, bad := range []string{"../x", "a/b", "other.example.net"} {
		api.mu.Lock()
		p := api.plans[dnsD]
		p.Name = bad
		api.plans[dnsD] = p
		api.mu.Unlock()
		r, err := f.h.Doctor(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range r.Findings {
			if len(x.Domains) > 0 && x.Domains[0] != "example.org" {
				t.Errorf("plan named %q: finding %+v", bad, x)
			}
		}
		fd := doctor.Finding{Kind: doctor.KindDNSCAAMissing, Domains: []string{bad}, Class: doctor.FixOneClick, FixKind: doctor.FixDNSApply}
		if _, err := (dnsApplyFixer{}).Apply(f.h, fd, nil, "x", directory.Human("alice")); statusOf(err) != 409 {
			t.Errorf("apply for %q: %v", bad, err)
		}
		if _, err := (dnssecSignFixer{}).Preview(ctx, f.h, fd, nil); statusOf(err) != 409 {
			t.Errorf("sign preview for %q: %v", bad, err)
		}
	}
	for _, k := range []string{"_domain.../x", "_domain.a/b", "../x", "a/b", "_folder.../x", "_domain.", "_domain..."} {
		if validOpKey(k) {
			t.Errorf("validOpKey(%q) = true", k)
		}
		if _, err := f.h.startAsync(k, OpDNSApply, directory.Human("alice"), nil, func(_ context.Context, ready func()) (map[string]string, []string, error) {
			ready()
			return nil, nil, nil
		}); err == nil {
			t.Errorf("startAsync(%q) accepted", k)
		}
		f.h.recordOp(k, OpRecord{Op: OpDNSApply})
		if f.h.LastOp(k) != nil {
			t.Errorf("recordOp(%q) recorded", k)
		}
	}
	if _, err := os.Stat(filepath.Join(f.h.opsDir(), "..", "x.json")); err == nil {
		t.Error("a record was written outside the ops directory")
	}
}
