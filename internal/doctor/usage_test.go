package doctor

import (
	"slices"
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

const gib = 1 << 30

func diskRun(fs ...FilesystemIn) []Finding {
	return storageCheck{kind: KindDiskNearlyFull}.Run(&Inputs{Storage: &StorageIn{Filesystems: fs}})
}

func TestDiskNearlyFullBands(t *testing.T) {
	for _, c := range []struct {
		free, total uint64
		want        Severity
	}{
		{12 * gib, 100 * gib, ""}, {9 * gib, 100 * gib, Warning}, {gib * 5 / 2, 100 * gib, Problem},
		{4 * gib, 20 * gib, Warning}, {gib * 9 / 10, 20 * gib, Problem},
	} {
		fs := diskRun(FilesystemIn{Dev: 1, Path: "/srv", Free: c.free, Total: c.total, Owners: []string{"a"}})
		switch {
		case c.want == "" && len(fs) != 0:
			t.Errorf("%d/%d: %+v", c.free, c.total, fs)
		case c.want != "" && (len(fs) != 1 || fs[0].Severity != c.want):
			t.Errorf("%d/%d: %+v, want %s", c.free, c.total, fs, c.want)
		}
	}
}

func TestDiskNearlyFullDedupByDev(t *testing.T) {
	fs := diskRun(
		FilesystemIn{Dev: 5, Path: "/srv/data", Free: gib, Total: 100 * gib, Owners: []string{"paperless", "core"}},
		FilesystemIn{Dev: 5, Path: "/srv/media", Free: gib, Total: 100 * gib, Owners: []string{"folder:media"}},
		FilesystemIn{Dev: 5, Path: "/data", Free: gib, Total: 100 * gib, Owners: []string{"core"}},
	)
	if len(fs) != 1 {
		t.Fatalf("findings = %+v", fs)
	}
	f := fs[0]
	if !strings.Contains(f.Why, "paperless, core, shared folder media") || f.Fix != "free space or move the data" ||
		f.Link == nil || f.Link.Instance != "paperless" || f.Link.Tab != TabUsage || !slices.Equal(f.Paths, []string{"/srv/data"}) {
		t.Errorf("finding = %+v", f)
	}
}

func TestDiskNearlyFullNoNumbers(t *testing.T) {
	if fs := diskRun(FilesystemIn{Dev: 1, Path: "/srv", Total: 0}); len(fs) != 0 {
		t.Errorf("no numbers: %+v", fs)
	}
	if fs := (storageCheck{kind: KindDiskNearlyFull}).Run(&Inputs{}); len(fs) != 0 {
		t.Error("nil storage fired")
	}
}

func TestStorageMeasurePartial(t *testing.T) {
	fs := storageCheck{kind: KindStorageMeasurePartial}.Run(&Inputs{Storage: &StorageIn{Partial: []StoragePartialIn{{Target: "portcullis-a_data", Owner: "a", Reason: "time"}}}})
	if len(fs) != 1 || fs[0].Severity != Info || !strings.Contains(fs[0].Why, "the figure is a lower bound") ||
		fs[0].FP != Fingerprint(KindStorageMeasurePartial, "a", "portcullis-a_data") {
		t.Errorf("partial = %+v", fs)
	}
}

// L4: the why and the advice follow the reason: unreadable entries never
// say "the next run measures it again".
func TestStorageMeasurePartialByReason(t *testing.T) {
	for reason, want := range map[string]string{
		"failed": "couldn't be read", "hard_links": "hard-linked", "entries": "stopped at its cap (entries)",
		"time": "stopped at its cap (time)", "names": "was skipped (names)", "depth": "was skipped (depth)",
	} {
		fs := storageCheck{kind: KindStorageMeasurePartial}.Run(&Inputs{Storage: &StorageIn{Partial: []StoragePartialIn{{Target: "t", Owner: "a", Reason: reason}}}})
		if len(fs) != 1 || !strings.Contains(fs[0].Why, want) || !strings.Contains(fs[0].Why, "lower bound") {
			t.Errorf("%s: why %q", reason, fs[0].Why)
		}
		if reason == "failed" && strings.Contains(strings.Join(fs[0].Steps, " "), "next run") {
			t.Errorf("failed: steps %q", fs[0].Steps)
		}
	}
}

func TestDiskTokenStableInBand(t *testing.T) {
	tok := func(free uint64) string {
		r := Run(&Inputs{Storage: &StorageIn{Filesystems: []FilesystemIn{{Dev: 1, Path: "/srv", Free: free, Total: 100 * gib}}}}, nil)
		for _, f := range r.Findings {
			if f.Kind == KindDiskNearlyFull {
				return f.Token
			}
		}
		return ""
	}
	a, b, c := tok(9*gib), tok(gib*17/2), tok(gib*29/10)
	if a == "" || a != b || c == a {
		t.Errorf("tokens %q %q %q", a, b, c)
	}
}
