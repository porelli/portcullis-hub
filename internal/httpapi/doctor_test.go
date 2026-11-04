package httpapi

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/hub"
)

// doctorRoutes are every doctor route; fp is a well-formed fingerprint.
func doctorRoutes(fp string) []route {
	return []route{
		{"GET", "/api/doctor", ""},
		{"POST", "/api/doctor/scan", ""},
		{"GET", "/api/doctor/op", ""},
		{"POST", "/api/doctor/findings/" + fp + "/preview", `{"params":{}}`},
		{"POST", "/api/doctor/findings/" + fp + "/apply", `{"plan_hash":"x","params":{}}`},
		{"POST", "/api/doctor/findings/" + fp + "/mute", `{"reason":"known"}`},
		{"DELETE", "/api/doctor/findings/" + fp + "/mute", ""},
	}
}

// report fetches GET /api/doctor as root.
func report(t *testing.T, e *instEnv) doctor.Report {
	t.Helper()
	var r doctor.Report
	if err := json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/doctor", "", 200)), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func findingOf(r doctor.Report, kind string) *doctor.Finding {
	for i := range r.Findings {
		if r.Findings[i].Kind == kind {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestDoctorRoutesAdminOnly(t *testing.T) {
	e := newFolderEnv(t, true)
	lan := findingOf(report(t, e), "lan_only_exposed")
	if lan == nil {
		t.Fatal("no lan_only_exposed finding")
	}
	// Both fix routes included (T12 M4): a delegate is 403 on each.
	checkAdminOnly(t, e, doctorRoutes(lan.FP))
	for _, p := range []string{"doctor.", "settings.change"} {
		if a := e.auditActions(t, p); len(a) != 0 {
			t.Fatalf("refused requests reached the Hub: %v", a)
		}
	}
}

func TestDoctorAnswerShape(t *testing.T) {
	e := newFolderEnv(t, true)
	r, b := doAs(t, e.hub, "root", "GET", "/api/doctor", "")
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("doctor = %d %s", r.StatusCode, b)
	}
	for _, k := range []string{`"findings":`, `"counts":`, `"muted":`, `"scans":`, `"fix_class":"one_click"`, `"fix_kind":"rebind_port"`} {
		if !strings.Contains(b, k) {
			t.Errorf("answer lacks %s: %s", k, b)
		}
	}
	rep := report(t, e)
	fpRe := regexp.MustCompile(`^[0-9a-f]{16}$`)
	for _, f := range rep.Findings {
		if !fpRe.MatchString(f.FP) || f.Severity == "" || f.Kind == "" || f.Title == "" {
			t.Errorf("finding = %+v", f)
		}
	}
	und, lan := findingOf(rep, "undeclared_template"), findingOf(rep, "lan_only_exposed")
	if und == nil || und.Severity != doctor.Info || lan == nil || lan.Severity != doctor.Warning || lan.Class != doctor.FixOneClick {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	infos := rep.Counts[doctor.Info]

	// Mute: refusals first.
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+und.FP+"/mute", `{"reason":""}`, 400)
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/0123456789abcdef/mute", `{"reason":"x"}`, 404)
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/not-an-fp/mute", `{"reason":"x"}`, 404)
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+und.FP+"/mute", `{"reason":"known","why":1}`, 400)
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+und.FP+"/mute", `{"reason":"we know"}`, 204)
	rep = report(t, e)
	m := findingOf(rep, "undeclared_template")
	if m == nil || m.Muted == nil || m.Muted.Reason != "we know" || m.Muted.Actor != "root" || rep.Muted != 1 || rep.Counts[doctor.Info] != infos-1 {
		t.Fatalf("muted report = %+v", rep)
	}
	mustDo(t, e.hub, "root", "DELETE", "/api/doctor/findings/"+und.FP+"/mute", "", 204)
	mustDo(t, e.hub, "root", "DELETE", "/api/doctor/findings/"+und.FP+"/mute", "", 404)
	if rep = report(t, e); rep.Muted != 0 || findingOf(rep, "undeclared_template").Muted != nil {
		t.Errorf("unmuted report = %+v", rep)
	}
	got := strings.Join(e.auditActions(t, "doctor."), " ")
	for _, w := range []string{"doctor.mute:ok:root:" + und.FP, "doctor.unmute:ok:root:" + und.FP, "doctor.mute:refused:root:"} {
		if !strings.Contains(got, w) {
			t.Errorf("audit lacks %s: %s", w, got)
		}
	}
}

func TestDoctorFixRoutes(t *testing.T) {
	e := newFolderEnv(t, true)
	rep := report(t, e)
	und, lan := findingOf(rep, "undeclared_template"), findingOf(rep, "lan_only_exposed")
	// No fix: 409 {error}; an unknown fp 404; an unknown param or fix 400.
	if b := mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+und.FP+"/preview", `{"params":{}}`, 409); !strings.Contains(b, `"error":`) {
		t.Errorf("no fix = %s", b)
	}
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/0123456789abcdef/preview", `{"params":{}}`, 404)
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+lan.FP+"/preview", `{"params":{"color":"red"}}`, 400)
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+lan.FP+"/preview", `{"params":{"fix":"undo_folder"}}`, 400)
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+lan.FP+"/preview", `{"params":{"address":1}}`, 400)
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+lan.FP+"/preview", `{"params":{},"extra":1}`, 400)
	// A main-domain address (the stubbed DNS answer) is refused.
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+lan.FP+"/preview", `{"params":{"address":"203.0.113.7"}}`, 400)
	b := mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+lan.FP+"/preview", `{"params":{"fix":"rebind_port","address":"192.168.1.10"}}`, 200)
	var plan hub.FixPlan
	if json.Unmarshal([]byte(b), &plan); plan.Hash == "" || plan.Kind != "rebind_port" || plan.FP != lan.FP {
		t.Fatalf("preview = %s", b)
	}
	mustDo(t, e.hub, "root", "POST", "/api/doctor/findings/"+lan.FP+"/apply", `{"plan_hash":"`+strings.Repeat("0", 64)+`","params":{"address":"192.168.1.10"}}`, 409)
	r, b := doAs(t, e.hub, "root", "POST", "/api/doctor/findings/"+lan.FP+"/apply", `{"plan_hash":"`+plan.Hash+`","params":{"address":"192.168.1.10"}}`)
	var acc map[string]string
	json.Unmarshal([]byte(b), &acc)
	// A rebind is the instance's own op record.
	if r.StatusCode != 202 || acc["op"] != hub.OpRebind || acc["instance"] != "photos" || acc["poll"] != "/api/instances/photos/op" || acc["op_id"] == "" {
		t.Fatalf("apply = %d %s", r.StatusCode, b)
	}
	waitOp(t, e, acc["poll"], acc["op_id"])
	if a := strings.Join(e.auditActions(t, "doctor.fix"), " "); !strings.Contains(a, "doctor.fix:ok:root:"+lan.FP) {
		t.Errorf("audit = %s", a)
	}
}

func TestDoctorScanAnswers202(t *testing.T) {
	e := newFolderEnv(t, true)
	mustDo(t, e.hub, "root", "GET", "/api/doctor/op", "", 404)
	r, b := doAs(t, e.hub, "root", "POST", "/api/doctor/scan", "")
	var acc map[string]string
	json.Unmarshal([]byte(b), &acc)
	if r.StatusCode != 202 || acc["op"] != hub.OpDoctorScan || acc["instance"] != "_doctor" || acc["poll"] != "/api/doctor/op" || acc["op_id"] == "" {
		t.Fatalf("scan = %d %s", r.StatusCode, b)
	}
	rec := waitOp(t, e, "/api/doctor/op", acc["op_id"])
	if rec.Op != hub.OpDoctorScan {
		t.Errorf("op = %+v", rec)
	}
	if rep := report(t, e); len(rep.Scans) == 0 {
		t.Errorf("no scans after a scan: %+v", rep)
	}
}
