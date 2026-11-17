package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/state"
)

type recAudit struct {
	mu sync.Mutex
	es []directory.AuditEntry
}

func (a *recAudit) Append(e directory.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.es = append(a.es, e)
	return nil
}

func (a *recAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.es {
		out = append(out, e.Action+"|"+e.Actor+"|"+e.Detail+"|"+e.Result)
	}
	return out
}

// storageEnv: instances a and b; a runs web.1 with volumes data and
// cache, a bind /srv/data/shared (also b's), a bind into the shared
// folder media (/srv/media); core has portcullis_postgres_data.
type storageEnv struct {
	*usageEnv
	audit *recAudit
	mu    sync.Mutex
	runs  []fixerRun
	rep   func(r fixerRun) (*folderfix.Report, error)
}

func (e *storageEnv) fixerRuns() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, r := range e.runs {
		if r.Volume.Name != "" {
			out = append(out, "volume:"+r.Volume.Name)
		} else {
			out = append(out, "bind:"+r.Source)
		}
	}
	return out
}

func vol(name, project string) runtime.Volume {
	return runtime.Volume{Name: name, Labels: map[string]string{LabelComposeProject: project}}
}

func newStorageEnv(t *testing.T) *storageEnv {
	t.Helper()
	ue := newUsageEnv(t, "a", "b")
	e := &storageEnv{usageEnv: ue, audit: &recAudit{}}
	h := ue.h
	h.SetAudit(e.audit)
	h.bindRoots = []string{"/srv"}
	h.mu.Lock()
	if h.st.Folders == nil {
		h.st.Folders = map[string]state.Folder{}
	}
	h.st.Folders["media"] = state.Folder{Name: "Media", Path: "/srv/media"}
	h.mu.Unlock()
	ue.rt.Volumes = map[string]runtime.Volume{
		"portcullis-a_data": vol("portcullis-a_data", "portcullis-a"), "portcullis-a_cache": vol("portcullis-a_cache", "portcullis-a"),
		"portcullis_postgres_data": vol("portcullis_postgres_data", "portcullis"), "other": vol("other", "elsewhere"),
	}
	ue.rt.InfoVal.ForbiddenRoots = []string{"/var/lib/docker"}
	a1, b1 := uunit("a1", "portcullis-a", "web", 1, "running"), uunit("b1", "portcullis-b", "web", 1, "running")
	a1.Image, b1.Image = "img-a", "img-shared"
	ue.setUnits(a1, b1)
	ue.rt.Infos = map[string]runtime.UnitInfo{
		"a1": {ID: "a1", Mounts: []runtime.UnitMount{{Type: "bind", Source: "/srv/data/shared", Destination: "/s"}, {Type: "bind", Source: "/srv/media/a", Destination: "/m"},
			{Type: "bind", Source: "/opt/templates/x", Destination: "/t"}}},
		"b1": {ID: "b1", Mounts: []runtime.UnitMount{{Type: "bind", Source: "/srv/data/shared", Destination: "/s"}}},
	}
	ue.stats("a1", 1, 1)
	ue.stats("b1", 1, 1)
	ue.rt.LayerSizes = map[string]int64{"a1": 4096}
	ue.rt.ImageSizes = map[string]int64{"img-a": 1 << 20}
	ue.sweep()
	h.usage.fixer = func(_ context.Context, r fixerRun) (*folderfix.Report, error) {
		e.mu.Lock()
		e.runs = append(e.runs, r)
		f := e.rep
		e.mu.Unlock()
		if f != nil {
			return f(r)
		}
		return &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 1000, ApparentBytes: 900, Dev: 7, FreeBytes: 50, TotalBytes: 100}, nil
	}
	return e
}

func (e *storageEnv) measure(t *testing.T, instance string) (map[string]string, []string, error) {
	t.Helper()
	return e.h.measureStorage(context.Background(), instance)
}

func TestStorageTargets(t *testing.T) {
	e := newStorageEnv(t)
	disk, sizes, err := e.h.storageTargets(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, d := range disk {
		keys = append(keys, d.Key+"="+strings.Join(d.Owners, ","))
	}
	want := []string{"volume:portcullis-a_cache=a", "volume:portcullis-a_data=a", "bind:/srv/data/shared=a,b", "volume:portcullis_postgres_data=core"}
	if !slices.Equal(keys, want) {
		t.Errorf("targets = %q\nwant %q", keys, want)
	}
	var sk []string
	for _, s := range sizes {
		sk = append(sk, s.Key)
	}
	if !slices.Equal(sk, []string{"layer:a/web.1", "layer:b/web.1", "image:img-a", "image:img-shared"}) {
		t.Errorf("sizes = %q", sk)
	}
	// One instance: its targets only, no core.
	disk, _, _ = e.h.storageTargets(context.Background(), "b", nil)
	if len(disk) != 1 || disk[0].Key != "bind:/srv/data/shared" {
		t.Errorf("b's targets = %+v", disk)
	}
	// A bind under the engine's root is listed, never measured.
	disk, _, _ = e.h.storageTargets(context.Background(), "b", []string{"/srv/data"})
	if len(disk) != 1 || disk[0].Refused != "refused: under the engine's data root" {
		t.Errorf("refused = %+v", disk)
	}
}

func TestStorageSequentialAndDiskMu(t *testing.T) {
	e := newStorageEnv(t)
	var running, overlap atomic.Int32
	e.rep = func(fixerRun) (*folderfix.Report, error) {
		if running.Add(1) > 1 {
			overlap.Add(1)
		}
		time.Sleep(5 * time.Millisecond)
		running.Add(-1)
		return &folderfix.Report{Version: 1, Mode: "usage"}, nil
	}
	// A doctor scan holds diskMu: the run waits.
	e.h.usage.diskMu.Lock()
	done := make(chan struct{})
	go func() { e.measure(t, ""); close(done) }()
	time.Sleep(50 * time.Millisecond)
	if n := len(e.fixerRuns()); n != 0 {
		t.Errorf("%d runs while the doctor held the disk", n)
	}
	e.h.usage.diskMu.Unlock()
	<-done
	if overlap.Load() != 0 || len(e.fixerRuns()) != 4 {
		t.Errorf("overlap %d, runs %q", overlap.Load(), e.fixerRuns())
	}
}

func TestStorageCapsAndBudget(t *testing.T) {
	e := newStorageEnv(t)
	e.rep = func(r fixerRun) (*folderfix.Report, error) {
		if r.Opts.MaxEntries != 2_000_000 || r.Opts.MaxTime != 2*time.Minute {
			t.Errorf("caps = %+v", r.Opts)
		}
		return &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 5, Partial: true, PartialReason: "time"}, nil
	}
	if _, _, err := e.measure(t, ""); err != nil {
		t.Fatal(err)
	}
	g := e.h.usageStorageGroup("a")
	var data *StorageItem
	for i := range g.Items {
		if g.Items[i].Target == "portcullis-a_data" {
			data = &g.Items[i]
		}
	}
	if data == nil || !data.Partial || data.PartialReason != "time" || !g.Partial {
		t.Fatalf("partial = %+v", data)
	}
	old := *data.MeasuredAt
	// The budget spent after the first target: the rest keep their old
	// figure and date.
	e.clock.Add(time.Minute)
	n := 0
	e.rep = func(fixerRun) (*folderfix.Report, error) {
		n++
		e.clock.Add(2 * time.Hour)
		return &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 7}, nil
	}
	_, warns, _ := e.measure(t, "")
	if n != 1 || len(warns) == 0 || !strings.Contains(warns[0], "not measured: the run's time budget (1h0m0s) is spent") {
		t.Errorf("runs %d, warnings %q", n, warns)
	}
	for _, it := range e.h.usageStorageGroup("a").Items {
		if it.Target == "portcullis-a_data" && (!it.MeasuredAt.Equal(old) || *it.AllocBytes != 5) {
			t.Errorf("a_data lost its old figure: %+v", it)
		}
	}
}

func TestStorageLayerAndImageSizes(t *testing.T) {
	e := newStorageEnv(t)
	if _, _, err := e.measure(t, ""); err != nil {
		t.Fatal(err)
	}
	items := map[string]StorageItem{}
	for _, it := range e.h.usageStorageGroup("a").Items {
		items[it.Kind+":"+it.Target] = it
	}
	if l := items["layer:web.1"]; l.AllocBytes == nil || *l.AllocBytes != 4096 || !l.InTotal {
		t.Errorf("layer = %+v", l)
	}
	if i := items["image:img-a"]; i.AllocBytes == nil || i.InTotal {
		t.Errorf("image = %+v", i)
	}
	if hf := items["hub_files:Hub-managed files"]; hf.AllocBytes != nil {
		t.Errorf("hub files = %+v", hf)
	}
	bl := e.h.usageStorageGroup("b")
	for _, it := range bl.Items {
		if it.Kind == "layer" && (it.AllocBytes != nil || !strings.HasPrefix(it.Error, "not measured")) {
			t.Errorf("b's layer = %+v", it)
		}
	}
}

// Review Focus 4: a host path two apps use is measured once and in no
// total; the disk's owners name both.
func TestStorageSharedTargetMeasuredOnce(t *testing.T) {
	e := newStorageEnv(t)
	if _, _, err := e.measure(t, ""); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range e.fixerRuns() {
		if r == "bind:/srv/data/shared" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("shared bind measured %d times", n)
	}
	for _, id := range []string{"a", "b"} {
		found := false
		for _, it := range e.h.usageStorageGroup(id).Items {
			if it.Target == "/srv/data/shared" {
				found = true
				if it.InTotal || len(it.Shared) != 1 {
					t.Errorf("%s: shared item = %+v", id, it)
				}
			}
		}
		if !found {
			t.Errorf("%s doesn't list the shared path", id)
		}
	}
	v := e.h.UsageStorage()
	var d *DiskView
	for i := range v.Disks {
		if v.Disks[i].Dev == 7 {
			d = &v.Disks[i]
		}
	}
	if d == nil || !slices.Contains(d.Owners, "a") || !slices.Contains(d.Owners, "b") || !slices.Contains(d.Owners, "core") {
		t.Errorf("disk = %+v", d)
	}
	// b's total holds nothing of the shared path.
	if g := e.h.usageStorageGroup("b"); g.TotalAlloc != nil && *g.TotalAlloc >= 1000 {
		t.Errorf("b's total %d counts the shared path", *g.TotalAlloc)
	}
}

// Review Focus 5: an instance deleted mid-run vanishes from the cache;
// the other targets are measured.
func TestStorageInstanceDeletedMidRun(t *testing.T) {
	e := newStorageEnv(t)
	gone := false
	e.rep = func(r fixerRun) (*folderfix.Report, error) {
		if r.Volume.Name == "portcullis-a_cache" {
			gone = true
			e.h.usage.instances = func() []usageInst { return []usageInst{{ID: "b", Template: "tmpl", Name: "App b"}} }
		}
		return &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 10}, nil
	}
	res, _, err := e.measure(t, "")
	if err != nil || !gone || res["measured"] == "0" {
		t.Fatalf("res %v, %v", res, err)
	}
	sf := e.h.storageSnapshot()
	for k, en := range sf.Entries {
		if slices.Contains(en.Owners, "a") {
			t.Errorf("%s still names the deleted instance", k)
		}
	}
	if _, ok := sf.Entries["volume:portcullis_postgres_data"]; !ok {
		t.Error("the core volume wasn't measured")
	}
	b, _ := os.ReadFile(e.h.storagePath())
	if strings.Contains(string(b), "portcullis-a_") {
		t.Error("the file keeps the deleted instance")
	}
}

// Review Focus 5: a failed cache write keeps the previous file and says so.
func TestStorageCacheWriteFailureKeepsPrevious(t *testing.T) {
	e := newStorageEnv(t)
	if _, _, err := e.measure(t, ""); err != nil {
		t.Fatal(err)
	}
	prev, err := os.ReadFile(e.h.storagePath())
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(e.h.storagePath()); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	dir := filepath.Dir(e.h.storagePath())
	os.Chmod(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	e.rep = func(fixerRun) (*folderfix.Report, error) {
		return &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 99999}, nil
	}
	_, warns, err := e.measure(t, "")
	if err != nil || !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "the storage cache couldn't be written") }) {
		t.Errorf("warnings %q, %v", warns, err)
	}
	now, _ := os.ReadFile(e.h.storagePath())
	if string(now) != string(prev) {
		t.Error("the previous file changed")
	}
}

func TestStorageCacheCorruptDropped(t *testing.T) {
	for name, body := range map[string][]byte{
		"5 MiB":     []byte(`{"version":1,"entries":{},"x":"` + strings.Repeat("a", 5<<20) + `"}`),
		"garbage":   []byte("not json"),
		"version 2": []byte(`{"version":2,"last_run":"2026-11-15T00:00:00Z","entries":{}}`),
	} {
		e := newStorageEnv(t)
		os.MkdirAll(filepath.Dir(e.h.storagePath()), 0o700)
		os.WriteFile(e.h.storagePath(), body, 0o600)
		if v := e.h.UsageStorage(); v.MeasuredAt != nil {
			t.Errorf("%s: measured_at = %v", name, v.MeasuredAt)
		}
	}
	e := newStorageEnv(t)
	os.MkdirAll(filepath.Dir(e.h.storagePath()), 0o700)
	os.WriteFile(e.h.storagePath(), []byte(`{"version":1,"last_run":"2026-11-15T00:00:00Z","entries":{}}`), 0o600)
	if v := e.h.UsageStorage(); v.MeasuredAt == nil {
		t.Error("a good file was dropped")
	}
}

func waitUsageOp(t *testing.T, h *Hub) *OpRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r := h.LastOp(opKeyUsage); r != nil && !r.Running {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the measurement didn't end")
	return nil
}

func TestStorageOp409WhileRunning(t *testing.T) {
	e := newStorageEnv(t)
	release := make(chan struct{})
	e.rep = func(fixerRun) (*folderfix.Report, error) {
		<-release
		return &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 1}, nil
	}
	alice := directory.Actor{User: "alice"}
	op, err := e.h.StartUsageMeasure(alice, "")
	if err != nil || op.Op != OpUsageMeasure || op.Instance != opKeyUsage {
		t.Fatalf("start = %+v, %v", op, err)
	}
	if r := e.h.LastOp(opKeyUsage); r == nil || !r.Running {
		t.Errorf("record = %+v", r)
	}
	if _, err := e.h.StartUsageMeasure(alice, ""); errStatus(err) != 409 || !strings.Contains(err.Error(), "already running") {
		t.Errorf("second = %v", err)
	}
	if _, err := e.h.StartUsageMeasure(alice, "nope"); errStatus(err) != 404 {
		t.Errorf("unknown = %v", err)
	}
	if _, err := e.h.StartUsageMeasure(directory.Actor{}, ""); errStatus(err) != 401 {
		t.Errorf("no user = %v", err)
	}
	close(release)
	r := waitUsageOp(t, e.h)
	if !r.OK || r.Result["targets"] != "8" || r.Result["measured"] == "" || r.Actor != "alice" {
		t.Errorf("final = %+v", r)
	}
	if a := e.audit.actions(); len(a) == 0 || a[0] != "usage.measure|alice|scope=all|ok" {
		t.Errorf("audit = %q", a)
	}
}

func TestStorageStopBetweenTargets(t *testing.T) {
	e := newStorageEnv(t)
	inFirst := make(chan struct{})
	release := make(chan struct{})
	var first sync.Once
	e.rep = func(fixerRun) (*folderfix.Report, error) {
		first.Do(func() { close(inFirst); <-release })
		return &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 3}, nil
	}
	alice := directory.Actor{User: "alice"}
	op, err := e.h.StartUsageMeasure(alice, "a")
	if err != nil {
		t.Fatal(err)
	}
	<-inFirst
	if _, err := e.h.StopUsageMeasure(alice, op.OpID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	close(release)
	r := waitUsageOp(t, e.h)
	if r.OK || r.StoppedBy != "alice" || r.Result["measured"] != "1" {
		t.Errorf("record = %+v", r)
	}
	if runs := e.fixerRuns(); len(runs) != 1 {
		t.Errorf("runs after the stop: %q", runs)
	}
	if !slices.ContainsFunc(e.audit.actions(), func(a string) bool { return strings.HasPrefix(a, "usage.measure.stop|alice|") }) {
		t.Errorf("audit = %q", e.audit.actions())
	}
	if _, err := e.h.StopUsageMeasure(alice, ""); errStatus(err) != 409 {
		t.Errorf("stop of nothing = %v", err)
	}
}

func TestStorageScheduleFirstRun(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	old, recent := now.Add(-25*time.Hour), now.Add(-2*time.Hour)
	if d := usageStorageFirstDelay(now, &old, 24*time.Hour); d != 10*time.Minute {
		t.Errorf("25 h old: %s", d)
	}
	if d := usageStorageFirstDelay(now, nil, 24*time.Hour); d != 10*time.Minute {
		t.Errorf("never: %s", d)
	}
	if d := usageStorageFirstDelay(now, &recent, 24*time.Hour); d != 22*time.Hour {
		t.Errorf("2 h old: %s", d)
	}
}

func TestStorageFoldersFromScans(t *testing.T) {
	e := newStorageEnv(t)
	h := e.h
	h.mu.Lock()
	h.st.Folders["tm"] = state.Folder{Name: "Time Machine", Path: "/srv/tm"}
	h.st.Folders["old"] = state.Folder{Name: "Old", Path: "/srv/old"}
	h.mu.Unlock()
	at := time.Date(2026, 11, 15, 3, 0, 0, 0, time.UTC)
	h.scanCacheMu.Lock()
	h.scanData = &scanFile{Version: scanCacheVersion, Scans: map[string]scanEntry{
		"/srv/media": {Target: "/srv/media", Folder: "media", At: at, Report: &folderfix.Report{AllocBytes: 123, Entries: 5, Dev: 9, TotalBytes: 1000, FreeBytes: 10}},
		"/srv/tm":    {Target: "/srv/tm", Folder: "tm", At: at, Report: &folderfix.Report{Entries: 3}, Children: true},
		"/srv/old":   {Target: "/srv/old", Folder: "old", At: at, Report: &folderfix.Report{Entries: 7}},
	}}
	h.scanCacheMu.Unlock()
	v := h.UsageStorage()
	by := map[string]FolderStorage{}
	for _, f := range v.Folders {
		by[f.ID] = f
	}
	if f := by["media"]; f.AllocBytes == nil || *f.AllocBytes != 123 || !slices.Equal(f.UsedBy, []string{"a"}) || f.MeasuredAt == nil {
		t.Errorf("media = %+v", f)
	}
	if f := by["tm"]; f.AllocBytes != nil || f.Note != "not measured (checked at the top level only)" {
		t.Errorf("tm = %+v", f)
	}
	if f := by["old"]; f.AllocBytes != nil || f.Note != "not measured yet" {
		t.Errorf("old = %+v", f)
	}
	// a lists the folder, not in its total.
	for _, it := range h.usageStorageGroup("a").Items {
		if it.Kind == "folder" && (it.Target != "media" || it.InTotal || *it.AllocBytes != 123) {
			t.Errorf("folder item = %+v", it)
		}
	}
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), `"folders"`) {
		t.Error("no folders")
	}
}

var _ = errors.New

// A Stop before the first target ends the run stopped, never failed.
func TestStorageStopBeforeTargets(t *testing.T) {
	e := newStorageEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, _, err := e.h.measureStorage(ctx, "")
	if !errors.Is(err, ErrStopped) || res["measured"] != "0" || res["skipped"] != "8" {
		t.Errorf("res %v, err %v", res, err)
	}
	if n := len(e.fixerRuns()); n != 0 {
		t.Errorf("%d runs after a Stop", n)
	}
}
