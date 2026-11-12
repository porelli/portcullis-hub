package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/hub"
)

// DNS hardening Task 12 (F2, contract §14.6): the DNS fixes' op record
// under _domain.<name>, its route and tool, and doctor_apply_fix's class.

const dnsTestD = "team-b.example.net"

// TestDomainOpAcceptedPoll: a DNS fix's 202 body names the domain and
// polls GET /api/domains/<n>/op, which answers the record.
func TestDomainOpAcceptedPoll(t *testing.T) {
	e := newDomainsEnv(t)
	e.s.Hub.SetPeople(e.s.Directory)
	e.enrolled(t)
	fp := doctor.Fingerprint(doctor.KindDNSCAAMissing, dnsTestD)
	code, b := e.do(t, e.hub, "root", "POST", "/api/doctor/findings/"+fp+"/preview", `{}`)
	if code != 200 {
		t.Fatalf("preview = %d %s", code, b)
	}
	var p hub.FixPlan
	json.Unmarshal([]byte(b), &p)
	code, b = e.do(t, e.hub, "root", "POST", "/api/doctor/findings/"+fp+"/apply", `{"plan_hash":"`+p.Hash+`"}`)
	if code != 202 {
		t.Fatalf("apply = %d %s", code, b)
	}
	var acc map[string]string
	json.Unmarshal([]byte(b), &acc)
	if acc["poll"] != "/api/domains/"+dnsTestD+"/op" || acc["domain"] != dnsTestD || acc["op"] != hub.OpDNSApply {
		t.Fatalf("accepted %v", acc)
	}
	waitIdle(t, e.s.Hub, hub.OpKeyDomain(dnsTestD))
	code, b = e.do(t, e.hub, "root", "GET", acc["poll"], "")
	if code != 200 || !strings.Contains(b, `"op_id":"`+acc["op_id"]+`"`) || !strings.Contains(b, `"ok":true`) {
		t.Fatalf("op = %d %s", code, b)
	}
	if code, _ := e.do(t, e.hub, "root", "GET", "/api/domains/other.example.net/op", ""); code != 404 {
		t.Fatalf("no record = %d", code)
	}
	for _, u := range []string{"bob", "dana"} {
		if code, _ := e.do(t, e.hub, u, "GET", acc["poll"], ""); code != 403 {
			t.Errorf("%s: op = %d, want 403", u, code)
		}
	}
	if code, _ := e.do(t, e.ppl, "root", "GET", acc["poll"], ""); code != 404 && code != 405 {
		t.Errorf("people listener: %d", code)
	}
	// GET /api/instances/ops never lists _domain.* records.
	code, b = e.do(t, e.hub, "root", "GET", "/api/instances/ops", "")
	if code != 200 || strings.Contains(b, "_domain.") {
		t.Fatalf("instance ops = %d %s", code, b)
	}
}

// TestInstanceOpsExcludeDomain: OpSummaries (GET /api/instances/ops,
// list_ops) skip _domain.* keys after a DNS fix ran.
func TestInstanceOpsExcludeDomain(t *testing.T) {
	e := newDomainsEnv(t)
	e.s.Hub.SetPeople(e.s.Directory)
	e.enrolled(t)
	fp := doctor.Fingerprint(doctor.KindDNSSECUnsigned, dnsTestD)
	p, err := e.s.Hub.PreviewFix(context.Background(), fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Hub.ApplyFix(context.Background(), fp, nil, p.Hash, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, e.s.Hub, hub.OpKeyDomain(dnsTestD))
	if e.s.Hub.LastOp(hub.OpKeyDomain(dnsTestD)) == nil {
		t.Fatal("no domain op record")
	}
	for k := range e.s.Hub.OpSummaries() {
		if strings.HasPrefix(k, "_") {
			t.Errorf("OpSummaries lists %s", k)
		}
	}
}

// TestDoctorApplyFixDNSClass (security ruling): doctor_apply_fix is D
// (a confirmation) for dnssec_sign, W for dns_apply.
func TestDoctorApplyFixDNSClass(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	fake := withDomains(t, e)
	fake.mu.Lock()
	fake.list[dnsTestD] = map[string]any{"name": dnsTestD, "provider": "cloudflare", "records_ok": true, "cert_not_after": nil, "last_error": "", "state": "ready"}
	fake.mu.Unlock()
	if _, err := e.s.Hub.RefreshDomains(context.Background()); err != nil {
		t.Fatal(err)
	}
	for kind, wantD := range map[string]bool{doctor.KindDNSSECUnsigned: true, doctor.KindDNSCAAMissing: false} {
		fp := doctor.Fingerprint(kind, dnsTestD)
		txt, isErr, _ := e.tool(t, "doctor_preview_fix", map[string]any{"fp": fp})
		var p hub.FixPlan
		if isErr || json.Unmarshal([]byte(txt), &p) != nil || p.Hash == "" || p.TouchesData {
			t.Fatalf("%s preview = %s", kind, txt)
		}
		txt, isErr, conf := e.tool(t, "doctor_apply_fix", map[string]any{"fp": fp, "plan_hash": p.Hash})
		if isErr || (conf != "") != wantD {
			t.Errorf("%s: apply = %s (err %v), confirmation %q, want D %v", kind, txt, isErr, conf, wantD)
		}
		waitIdle(t, e.s.Hub, hub.OpKeyDomain(dnsTestD))
	}
	// domain_op answers the record (R).
	if txt, isErr, _ := e.tool(t, "domain_op", map[string]any{"name": dnsTestD}); isErr || !strings.Contains(txt, `"ok": true`) && !strings.Contains(txt, `"ok":true`) {
		t.Fatalf("domain_op = %s", txt)
	}
}
