package doctor

import (
	"strings"
	"testing"
	"time"
)

var usageNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func i64p(v int64) *int64 { return &v }

// memPoints are n points, 15 s apart up to now, at mem bytes each.
func memPoints(n int, mem int64) []UsagePointIn {
	var ps []UsagePointIn
	for i := range n {
		ps = append(ps, UsagePointIn{At: usageNow.Add(-time.Duration(n-1-i) * 15 * time.Second), Mem: i64p(mem), Pids: i64p(mem)})
	}
	return ps
}

func usageRun(u *UsageIn, kind string) []Finding {
	return usageCheck{kind: kind}.Run(&Inputs{Usage: u})
}

func appCont(points []UsagePointIn) ContainerUsageIn {
	return ContainerUsageIn{Instance: "paperless", Service: "web", Number: 1, MemLimit: 100, PidsLimit: 100, Points: points}
}

func TestMemoryNearLimitTenMinutes(t *testing.T) {
	u := &UsageIn{Now: usageNow, Verified: true, Containers: []ContainerUsageIn{appCont(memPoints(40, 95))}}
	fs := usageRun(u, KindMemoryNearLimit)
	if len(fs) != 1 || fs[0].Severity != Warning || fs[0].Link == nil || fs[0].Link.Tab != TabUsage || fs[0].Link.Instance != "paperless" {
		t.Fatalf("40 at 95%% = %+v", fs)
	}
	ps := memPoints(40, 95)
	ps[20].Mem = i64p(85)
	for name, c := range map[string]ContainerUsageIn{
		"one at 85%": appCont(ps),
		"29 points":  appCont(memPoints(29, 95)),
		"no limit":   {Instance: "a", Service: "web", Number: 1, Points: memPoints(40, 95)},
	} {
		if fs := usageRun(&UsageIn{Now: usageNow, Containers: []ContainerUsageIn{c}}, KindMemoryNearLimit); len(fs) != 0 {
			t.Errorf("%s: %+v", name, fs)
		}
	}
	nilPs := memPoints(40, 95)
	nilPs[3].Mem = nil
	if fs := usageRun(&UsageIn{Now: usageNow, Containers: []ContainerUsageIn{appCont(nilPs)}}, KindMemoryNearLimit); len(fs) != 0 {
		t.Errorf("a nil in the window: %+v", fs)
	}
	// Points older than 10 minutes don't count.
	old := memPoints(80, 95)
	for i := range old {
		old[i].At = old[i].At.Add(-15 * time.Minute)
	}
	if fs := usageRun(&UsageIn{Now: usageNow, Containers: []ContainerUsageIn{appCont(old)}}, KindMemoryNearLimit); len(fs) != 0 {
		t.Errorf("old points: %+v", fs)
	}
}

func TestOOMKilled(t *testing.T) {
	c := appCont(nil)
	c.OOMKilled = true
	if fs := usageRun(&UsageIn{Now: usageNow, Containers: []ContainerUsageIn{c}}, KindOOMKilled); len(fs) != 1 || fs[0].Severity != Warning {
		t.Errorf("oom = %+v", fs)
	}
	c = appCont(nil)
	c.Restarts, c.RestartsHourAgo, c.OOMSeenHour = 7, 3, true
	if fs := usageRun(&UsageIn{Now: usageNow, Containers: []ContainerUsageIn{c}}, KindOOMKilled); len(fs) != 1 {
		t.Errorf("restarts with oom = %+v", fs)
	}
	c.OOMSeenHour = false
	if fs := usageRun(&UsageIn{Now: usageNow, Containers: []ContainerUsageIn{c}}, KindOOMKilled); len(fs) != 0 {
		t.Errorf("restarts without oom = %+v", fs)
	}
}

func TestPidsNearLimit(t *testing.T) {
	c := appCont(memPoints(40, 92))
	if fs := usageRun(&UsageIn{Now: usageNow, Containers: []ContainerUsageIn{c}}, KindPidsNearLimit); len(fs) != 1 || fs[0].Severity != Warning {
		t.Errorf("pids = %+v", fs)
	}
	c.PidsLimit = 0
	if fs := usageRun(&UsageIn{Now: usageNow, Containers: []ContainerUsageIn{c}}, KindPidsNearLimit); len(fs) != 0 {
		t.Errorf("no pids limit = %+v", fs)
	}
}

func TestUsageNotMeasured(t *testing.T) {
	fs := usageRun(&UsageIn{Now: usageNow, Verified: true, LastSuccess: usageNow.Add(-6 * time.Minute)}, KindUsageNotMeasured)
	if len(fs) != 1 || fs[0].Severity != Info || !strings.Contains(fs[0].Why, "no successful sample for 5 minutes") {
		t.Errorf("stale = %+v", fs)
	}
	if fs := usageRun(&UsageIn{Now: usageNow, Verified: true, LastSuccess: usageNow.Add(-time.Minute)}, KindUsageNotMeasured); len(fs) != 0 {
		t.Errorf("fresh = %+v", fs)
	}
	if fs := usageRun(&UsageIn{Now: usageNow, Verified: false, LastSuccess: usageNow.Add(-time.Hour)}, KindUsageNotMeasured); len(fs) != 0 {
		t.Errorf("unverified = %+v", fs)
	}
	why := "the cluster has no metrics API (metrics-server)"
	fs = usageRun(&UsageIn{Now: usageNow, Verified: true, LastSuccess: usageNow, NotMeasured: why}, KindUsageNotMeasured)
	if len(fs) != 1 || !strings.Contains(fs[0].Why, why) {
		t.Errorf("not measured = %+v", fs)
	}
}

func TestUsageFindingTokenStableAcrossSamples(t *testing.T) {
	run := func(mem int64) Finding {
		r := Run(&Inputs{Usage: &UsageIn{Now: usageNow, Verified: true, LastSuccess: usageNow, Containers: []ContainerUsageIn{appCont(memPoints(40, mem))}}}, nil)
		for _, f := range r.Findings {
			if f.Kind == KindMemoryNearLimit {
				return f
			}
		}
		t.Fatalf("no finding at %d", mem)
		return Finding{}
	}
	a, b := run(95), run(99)
	if a.Token != b.Token || a.FP != b.FP {
		t.Errorf("token %s vs %s", a.Token, b.Token)
	}
}

func TestUsageCoreServiceFinding(t *testing.T) {
	c := ContainerUsageIn{Service: "traefik", Number: 1, MemLimit: 100, Points: memPoints(40, 96)}
	fs := usageRun(&UsageIn{Now: usageNow, Containers: []ContainerUsageIn{c}}, KindMemoryNearLimit)
	if len(fs) != 1 || fs[0].Severity != Warning || !strings.Contains(fs[0].Title, "traefik") || fs[0].Link != nil ||
		!strings.Contains(fs[0].Fix, "docs/operations/hardening.md") {
		t.Errorf("core = %+v", fs)
	}
	if fs[0].FP != Fingerprint(KindMemoryNearLimit, "core", "traefik", "1") {
		t.Errorf("fp = %s", fs[0].FP)
	}
}

func TestUsageNilInputsNoFindings(t *testing.T) {
	r := Run(&Inputs{}, nil)
	for _, f := range r.Findings {
		for _, k := range UsageKinds {
			if f.Kind == k {
				t.Errorf("%s fired without inputs", k)
			}
		}
	}
	kinds := strings.Join(Kinds(), ",")
	for _, k := range UsageKinds {
		if !strings.Contains(kinds, k) {
			t.Errorf("%s isn't registered", k)
		}
	}
}
