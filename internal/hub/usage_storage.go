package hub

// The storage measurer (contract §11.11): daily and on demand (op _usage),
// one target after the other — each named volume and hand-typed bind of
// every instance, then core's volumes, through the fixer's read-only usage
// mode; then the writable layers and images. Results go to the storage
// cache; the views read only that cache and the doctor's scans.
//
// Rules: a fixer run holds diskMu (shared with the doctor's scans, U12),
// never across the run; a running target finishes on Stop, the rest keep
// their previous figures; never Hub.mu across an engine call.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/state"
)

// OpUsageMeasure is a storage measurement (op record key opKeyUsage).
const (
	OpUsageMeasure = "usage_measure"
	opKeyUsage     = "_usage"
)

// The measurer's pinned values (contract §11.11).
const (
	storageMaxEntries = 2_000_000
	storageMaxTime    = 2 * time.Minute
	storageRunBudget  = time.Hour
	storageFirstDelay = 10 * time.Minute
	storageEvery      = 24 * time.Hour
	storageBusyRetry  = time.Hour // a scheduled run that couldn't start (L11)
)

const usageCoreOwner = "core"

// storageTarget is one thing a run measures.
type storageTarget struct {
	Key, Kind, Target string // Kind volume | bind | layer | image
	Owners            []string
	Volume            runtime.VolumeMount // a volume
	Source            string              // a bind's host path
	Unit              string              // a layer's container id
	Refused           string              // listed, not measured (why)
	Labelled          bool                // a volume that had labels when listed (M3)
}

// storageTargets lists instance's targets (all: "") in run order: apps
// by id (volumes, then binds), then core's volumes; then the layers and
// images. A bind or volume several instances use is one target with
// every owner.
//
// rootsKnown false (the engine's info failed): every bind is refused,
// since none can be checked against the engine's data root (L1).
func (h *Hub) storageTargets(ctx context.Context, instance string, roots []string, rootsKnown bool) (disk, sizes []storageTarget, err error) {
	insts := h.usageInstances()
	ids := slices.Sorted(maps.Keys(insts))
	if instance != "" {
		ids = []string{instance}
	}
	// The sampler's cached mounts and images (never the engine here).
	type cont struct {
		id, group, service string
		number             int
		image              string
		mounts             []runtime.UnitMount
	}
	var conts []cont
	s := h.usage
	s.mu.RLock()
	for _, c := range s.conts {
		if c.Kind == usageApp {
			conts = append(conts, cont{c.ID, c.Group, c.Service, c.Number, c.Image, slices.Clone(c.Mounts)})
		}
	}
	s.mu.RUnlock()
	sort.Slice(conts, func(i, j int) bool {
		if conts[i].group != conts[j].group {
			return conts[i].group < conts[j].group
		}
		if conts[i].service != conts[j].service {
			return conts[i].service < conts[j].service
		}
		return conts[i].number < conts[j].number
	})
	byKey := map[string]*storageTarget{}
	var order []string
	add := func(t storageTarget, owner string) {
		if x := byKey[t.Key]; x != nil {
			if !slices.Contains(x.Owners, owner) {
				x.Owners = append(x.Owners, owner)
				sort.Strings(x.Owners)
			}
			return
		}
		t.Owners = []string{owner}
		byKey[t.Key] = &t
		order = append(order, t.Key)
	}
	// Binds are found on every instance (a path shared with another
	// instance is listed on both), measured when the run covers one.
	bindOwners := map[string][]string{}
	h.mu.RLock()
	for _, c := range conts {
		for _, m := range c.mounts {
			if m.Type != "bind" || !h.underBindRoots(m.Source) || h.inFolderLocked(m.Source) {
				continue
			}
			if !slices.Contains(bindOwners[m.Source], c.group) {
				bindOwners[m.Source] = append(bindOwners[m.Source], c.group)
			}
		}
	}
	h.mu.RUnlock()
	for _, id := range ids {
		vols, err := h.rt.ListVolumes(ctx, runtime.Filter{Instance: id})
		if err != nil {
			return nil, nil, err
		}
		names := make([]string, 0, len(vols))
		labelled := map[string]bool{}
		for _, v := range vols {
			names = append(names, v.Name)
			labelled[v.Name] = len(v.Labels) > 0
		}
		sort.Strings(names)
		for _, n := range names {
			add(storageTarget{Key: "volume:" + n, Kind: "volume", Target: n, Volume: runtime.VolumeMount{Name: n, Instance: id}, Labelled: labelled[n]}, id)
		}
		var binds []string
		for src, owners := range bindOwners {
			if slices.Contains(owners, id) {
				binds = append(binds, src)
			}
		}
		sort.Strings(binds)
		for _, src := range binds {
			t := storageTarget{Key: "bind:" + src, Kind: "bind", Target: src, Source: src}
			if !rootsKnown {
				t.Refused = "refused: the engine's data root is unknown"
			}
			for _, r := range roots {
				if pathUnder(src, r) {
					t.Refused = "refused: under the engine's data root"
				}
			}
			for _, o := range bindOwners[src] {
				add(t, o)
			}
		}
	}
	if instance == "" {
		if h.rt.Kind() == runtime.KindKubernetes {
			// Core lives in another namespace: nothing of it is measured.
		} else {
			vols, err := h.rt.ListVolumes(ctx, runtime.Filter{})
			if err != nil {
				return nil, nil, err
			}
			var names []string
			for _, v := range vols {
				if v.Labels[LabelComposeProject] == usageCoreProject {
					names = append(names, v.Name)
				}
			}
			sort.Strings(names)
			for _, n := range names {
				add(storageTarget{Key: "volume:" + n, Kind: "volume", Target: n, Volume: runtime.VolumeMount{Name: n}, Labelled: true}, usageCoreOwner)
			}
		}
	}
	for _, k := range order {
		disk = append(disk, *byKey[k])
	}
	// Writable layers, then images (instances share images: listed, not
	// in any total).
	images := map[string][]string{}
	for _, c := range conts {
		if instance != "" && c.group != instance {
			continue
		}
		if _, ok := insts[c.group]; !ok {
			continue
		}
		key := c.group + "/" + usageKey(c.service, c.number)
		sizes = append(sizes, storageTarget{Key: "layer:" + key, Kind: "layer", Target: usageKey(c.service, c.number), Owners: []string{c.group}, Unit: c.id})
		if c.image != "" && !slices.Contains(images[c.image], c.group) {
			images[c.image] = append(images[c.image], c.group)
		}
	}
	for _, ref := range slices.Sorted(maps.Keys(images)) {
		owners := images[ref]
		sort.Strings(owners)
		sizes = append(sizes, storageTarget{Key: "image:" + ref, Kind: "image", Target: ref, Owners: owners})
	}
	return disk, sizes, nil
}

// storageVolumeLive: t's volume still exists, and so does its instance
// (an instance's volume). An inspect error but "not found" counts as live:
// the helper run reports the real failure.
func (h *Hub) storageVolumeLive(ctx context.Context, t storageTarget) bool {
	if id := t.Volume.Instance; id != "" {
		if _, ok := h.usageInstances()[id]; !ok {
			return false
		}
	}
	_, err := h.rt.InspectVolume(ctx, t.Volume.Name)
	return err == nil || !docker.IsNotFound(err)
}

// storageVolumeRecreated: the volume was deleted between the check and the
// helper's create, so the engine made it anew, without labels (M3). The
// new, empty volume is removed (never forced), and the target is gone.
func (h *Hub) storageVolumeRecreated(ctx context.Context, t storageTarget) bool {
	if !t.Labelled || h.rt.Kind() == runtime.KindKubernetes {
		return false
	}
	v, err := h.rt.InspectVolume(ctx, t.Volume.Name)
	if err != nil || len(v.Labels) > 0 {
		return false
	}
	if err := h.rt.RemoveVolume(ctx, t.Volume.Name); err != nil {
		log.Printf("usage: removing the volume %s the helper recreated: %s", clipRunes(t.Volume.Name, 120), usageErrText(err))
	} else {
		log.Printf("usage: removed the volume %s the helper recreated", clipRunes(t.Volume.Name, 120))
	}
	return true
}

// LabelComposeProject is compose's project label on volumes.
const LabelComposeProject = "com.docker.compose.project"

// usageFixerRun runs one usage measurement (the test seam: usage.fixer).
func (h *Hub) usageFixerRun(ctx context.Context, r fixerRun) (*folderfix.Report, error) {
	if f := h.usage.fixer; f != nil {
		return f(ctx, r)
	}
	return h.runUsageFixer(ctx, r)
}

// usageErrText is a failed target's fixed text (never a raw error).
func usageErrText(err error) string {
	var nm *runtime.NotMeasuredError
	switch {
	case errors.As(err, &nm):
		return "not measured: " + nm.Why
	case err != nil && strings.Contains(err.Error(), "timed out"):
		return "timed out"
	case errStatus(err) == http.StatusServiceUnavailable:
		return "not measured: the engine refused the helper"
	case errStatus(err) == http.StatusConflict:
		return "refused by the fixer"
	}
	return "measurement failed"
}

func i64p(v uint64) *int64 {
	n := int64(min(v, 1<<62))
	return &n
}

// measureStorage is one run: instance's targets ("" = all). Stop
// (ctx) ends it between targets; the budget of an hour too. The result
// counts and the warnings go to the op record.
func (h *Hub) measureStorage(ctx context.Context, instance string) (map[string]string, []string, error) {
	s := h.usage
	start := s.now()
	p := progressFrom(ctx)
	// The listing finishes on a Stop too (a Stop then skips every target):
	// a Stop is never a failure of the run.
	listCtx := context.WithoutCancel(ctx)
	var roots []string
	rootsKnown := false
	if info, err := h.rt.Info(listCtx); err == nil {
		roots, rootsKnown = info.ForbiddenRoots, true
	} else if usageRefused(err) {
		return nil, nil, statusErr(http.StatusServiceUnavailable, "%s", usageRefusal(err))
	}
	disk, sizes, err := h.storageTargets(listCtx, instance, roots, rootsKnown)
	if err != nil {
		return nil, nil, statusErr(http.StatusServiceUnavailable, "storage targets: %s", usageErrText(err))
	}
	total := len(disk) + len(sizes)
	measured, failed, skipped, gone := 0, 0, 0, 0
	budgetSpent, stopped := false, false
	got := map[string]storageEntry{}
	owned := map[string]bool{}
	for _, t := range append(slices.Clone(disk), sizes...) {
		owned[t.Key] = true
	}
	n := 0
	next := func(t storageTarget) bool {
		n++
		if ctx.Err() != nil {
			stopped = true
			skipped++
			return false
		}
		if s.now().Sub(start) > storageRunBudget {
			budgetSpent = true
			skipped++
			return false
		}
		if p != nil {
			p.Detail("measure", fmt.Sprintf("%d/%d: %s", n, total, clipRunes(t.Target, 120)))
		}
		return true
	}
	// A running target finishes on Stop: its own deadline only.
	runCtx := context.WithoutCancel(ctx)
	for _, t := range disk {
		if !next(t) {
			continue
		}
		e := storageEntry{Kind: t.Kind, Target: t.Target, Owners: t.Owners, MeasuredAt: s.now()}
		if t.Refused != "" {
			e.Error = t.Refused
			got[t.Key] = e
			failed++
			continue
		}
		// M3: a volume (or its instance) deleted since the listing is gone,
		// never mounted: the engine would recreate it empty.
		if t.Kind == "volume" && !h.storageVolumeLive(runCtx, t) {
			log.Printf("usage: %s %s is gone: skipped", t.Kind, clipRunes(t.Target, 120))
			delete(owned, t.Key)
			gone++
			continue
		}
		r := fixerRun{Mode: "usage", Volume: t.Volume, Source: t.Source, Opts: folderfix.Options{MaxEntries: storageMaxEntries, MaxTime: storageMaxTime}}
		began := time.Now()
		s.diskMu.Lock()
		rep, err := h.usageFixerRun(runCtx, r)
		s.diskMu.Unlock()
		if t.Kind == "volume" && h.storageVolumeRecreated(runCtx, t) {
			delete(owned, t.Key)
			gone++
			continue
		}
		e.DurationMS = time.Since(began).Milliseconds()
		if err != nil || rep == nil {
			e.Error = usageErrText(err)
			log.Printf("usage: measuring %s %s: %s", t.Kind, clipRunes(t.Target, 120), e.Error)
			failed++
		} else {
			e.AllocBytes, e.ApparentBytes = i64p(rep.AllocBytes), i64p(rep.ApparentBytes)
			e.Partial, e.PartialReason = rep.Partial, rep.PartialReason
			e.Dev, e.Free, e.Total = rep.Dev, rep.FreeBytes, rep.TotalBytes
			measured++
		}
		got[t.Key] = e
	}
	for _, t := range sizes {
		if !next(t) {
			continue
		}
		e := storageEntry{Kind: t.Kind, Target: t.Target, Owners: t.Owners, MeasuredAt: s.now()}
		began := time.Now()
		var size int64
		var err error
		if t.Kind == "layer" {
			size, err = h.rt.LayerSize(runCtx, t.Unit)
		} else {
			size, err = h.rt.ImageSize(runCtx, t.Target)
		}
		e.DurationMS = time.Since(began).Milliseconds()
		if err != nil {
			e.Error = usageErrText(err)
			failed++
		} else {
			e.AllocBytes = &size
			measured++
		}
		got[t.Key] = e
	}
	var warns []string
	if failed > 0 {
		warns = append(warns, fmt.Sprintf("%d of %d targets couldn't be measured (Usage → Storage shows why)", failed, total))
	}
	if budgetSpent {
		warns = append(warns, fmt.Sprintf("not measured: the run's time budget (%s) is spent: %d targets keep their previous figures", storageRunBudget, skipped))
	}
	// The cache: measured entries replace theirs; entries whose owners
	// are all gone (a deleted instance) are dropped, and so are targets
	// the run's listing (always complete, even on Stop) no longer has
	// (M1): all of them on a full run; on an instance's run, that
	// instance's ownership.
	insts := h.usageInstances()
	now := s.now()
	s.storeMu.Lock()
	sf := h.storageLoadLocked()
	next2 := &storageFile{Version: storageCacheVersion, LastRun: sf.LastRun, Entries: map[string]storageEntry{}}
	for k, e := range sf.Entries {
		if owned[k] {
			next2.Entries[k] = e
			continue
		}
		if instance == "" {
			continue
		}
		e.Owners = slices.DeleteFunc(slices.Clone(e.Owners), func(o string) bool { return o == instance })
		if len(e.Owners) > 0 {
			next2.Entries[k] = e
		}
	}
	for k, e := range got {
		if prev, ok := next2.Entries[k]; ok && instance != "" {
			// An instance's run lists only that instance's users of a
			// shared image: the other owners stay.
			for _, o := range prev.Owners {
				if o != instance && !slices.Contains(e.Owners, o) {
					e.Owners = append(slices.Clone(e.Owners), o)
				}
			}
			sort.Strings(e.Owners)
		}
		next2.Entries[k] = e
	}
	for k, e := range next2.Entries {
		var live []string
		for _, o := range e.Owners {
			if _, ok := insts[o]; ok || o == usageCoreOwner {
				live = append(live, o)
			}
		}
		if len(live) == 0 {
			delete(next2.Entries, k)
			continue
		}
		e.Owners = live
		next2.Entries[k] = e
	}
	if instance == "" && !stopped && !budgetSpent {
		next2.LastRun = &now
	}
	if err := h.storageSaveLocked(next2); err != nil {
		log.Printf("usage: writing the storage cache: %v", err)
		warns = append(warns, "the storage cache couldn't be written: the previous one is kept on disk")
	}
	s.store = next2
	s.storeMu.Unlock()
	res := map[string]string{"targets": strconv.Itoa(total), "measured": strconv.Itoa(measured), "failed": strconv.Itoa(failed), "skipped": strconv.Itoa(skipped), "gone": strconv.Itoa(gone)}
	if stopped {
		return res, warns, ErrStopped
	}
	return res, warns, nil
}

// StartUsageMeasure measures storage now (all, or instance) in the
// background: 202 with the op; 401 no user, 404 unknown instance, 409 a
// run is going, 503 no engine. Audited usage.measure (target storage,
// detail scope=all|<instance>).
func (h *Hub) StartUsageMeasure(actor directory.Actor, instance string) (*AsyncOp, error) {
	scope := "all"
	if instance != "" {
		scope = instance
	}
	op, err := h.startUsageMeasure(actor, instance)
	h.auditOp(actor, "usage.measure", "storage", "scope="+scope, err)
	return op, err
}

func (h *Hub) startUsageMeasure(actor directory.Actor, instance string) (*AsyncOp, error) {
	if actor.User == "" {
		return nil, statusErr(http.StatusUnauthorized, "a storage measurement needs a signed-in admin")
	}
	if instance != "" {
		if _, ok := h.usageInstances()[instance]; !ok {
			return nil, statusErr(http.StatusNotFound, "app instance not found: %s", instance)
		}
	}
	if h.noEngine() {
		return nil, statusErr(http.StatusServiceUnavailable, "measuring storage needs the container engine")
	}
	return h.startAsync(opKeyUsage, OpUsageMeasure, actor, []Step{{Key: "measure", Label: "Measure storage"}},
		func(ctx context.Context, ready func()) (map[string]string, []string, error) {
			if !h.usage.measureMu.TryLock() {
				return nil, nil, statusErr(http.StatusConflict, "a storage measurement is already running")
			}
			defer h.usage.measureMu.Unlock()
			ready()
			p := progressFrom(ctx)
			if p != nil {
				p.Start("measure")
			}
			res, warns, err := h.measureStorage(ctx, instance)
			if p != nil && err == nil {
				p.Done("measure")
			}
			return res, warns, err
		})
}

// StopUsageMeasure stops the running measurement (expectedOpID: that one
// only, "" any) between targets: 404 none recorded, 409 not running or
// another op. Audited usage.measure.stop.
func (h *Hub) StopUsageMeasure(actor directory.Actor, expectedOpID string) (*OpRecord, error) {
	rec := h.LastOp(opKeyUsage)
	var err error
	switch {
	case rec == nil:
		err = statusErr(http.StatusNotFound, "no storage measurement was recorded")
	case expectedOpID != "" && rec.OpID != expectedOpID:
		err = ErrOpChanged
	default:
		err = h.cancelOpExpect(opKeyUsage, actor, expectedOpID)
	}
	h.auditOp(actor, "usage.measure.stop", "storage", "", err)
	if err != nil {
		return rec, err
	}
	return h.LastOp(opKeyUsage), nil
}

// usageStorageFirstDelay is the scheduled run's first wait: 10 min after
// the start when the last full run is older than every (or none), else
// until last + every.
func usageStorageFirstDelay(now time.Time, last *time.Time, every time.Duration) time.Duration {
	if last == nil || now.Sub(*last) >= every {
		return storageFirstDelay
	}
	return max(last.Add(every).Sub(now), storageFirstDelay)
}

// usageStorageNext is the wait after a scheduled run: the interval, or
// storageBusyRetry when it couldn't run (another run going, no engine) —
// never a whole day without a full run (L11).
func usageStorageNext(ran bool, every time.Duration) time.Duration {
	if ran {
		return every
	}
	return min(storageBusyRetry, every)
}

// RunUsageStorage measures everything every interval until ctx ends
// (main: daily), as the Hub (not audited, like the doctor's daily scans).
func (h *Hub) RunUsageStorage(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = storageEvery
	}
	sf := h.storageSnapshot()
	t := time.NewTimer(usageStorageFirstDelay(h.usage.now(), sf.LastRun, every))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ran := false
		if !h.noEngine() {
			busy := false
			_, finished, err := h.startOp(opKeyUsage, OpUsageMeasure, directory.Actor{User: "hub", Via: "schedule"}, []Step{{Key: "measure", Label: "Measure storage"}},
				func(octx context.Context, ready func()) (map[string]string, []string, error) {
					if !h.usage.measureMu.TryLock() {
						busy = true
						return nil, nil, statusErr(http.StatusConflict, "a storage measurement is already running")
					}
					defer h.usage.measureMu.Unlock()
					ready()
					return h.measureStorage(octx, "")
				})
			if err != nil {
				log.Printf("usage: the scheduled storage measurement is skipped: %v", err)
			} else {
				select {
				case <-finished:
					ran = !busy
				case <-ctx.Done():
					return
				}
			}
		}
		t.Reset(usageStorageNext(ran, every))
	}
}

// StorageView is GET /api/usage/storage (contract §11.11).
type StorageView struct {
	MeasuredAt     *time.Time      `json:"measured_at"`
	RunningOp      *AsyncOp        `json:"running_op"`
	MetricsScraped bool            `json:"metrics_scraped"`
	Disks          []DiskView      `json:"disks"`
	Apps           []StorageGroup  `json:"apps"`
	Folders        []FolderStorage `json:"folders"`
	Core           []StorageItem   `json:"core"`
}

// FolderStorage is one shared folder, from the doctor's scan.
type FolderStorage struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	AllocBytes *int64     `json:"alloc_bytes"`
	Partial    bool       `json:"partial"`
	UsedBy     []string   `json:"used_by"`
	MeasuredAt *time.Time `json:"measured_at"`
	Note       string     `json:"note,omitempty"`
}

// DiskView is one filesystem.
type DiskView struct {
	Dev         uint64   `json:"dev"`
	FreeBytes   uint64   `json:"free_bytes"`
	TotalBytes  uint64   `json:"total_bytes"`
	UsedPercent float64  `json:"used_percent"`
	Owners      []string `json:"owners"`
	// path: a path on it (the doctor's fingerprint).
	path string
}

const (
	noteNotYet  = "not measured yet"
	noteTopOnly = "not measured (checked at the top level only)"
)

// storageModel is the storage view with the disks' paths (the doctor).
func (h *Hub) storageModel() StorageView {
	v := StorageView{Disks: []DiskView{}, Apps: []StorageGroup{}, Folders: []FolderStorage{}, Core: []StorageItem{}, MetricsScraped: h.MetricsScrapedRecently()}
	sf := h.storageSnapshot()
	v.MeasuredAt = sf.LastRun
	if r := h.LastOp(opKeyUsage); r != nil && r.Running {
		v.RunningOp = &AsyncOp{OpID: r.OpID, Op: r.Op, Instance: opKeyUsage}
	}
	insts := h.usageInstances()
	// The sampler's mounts: which instance binds into which folder.
	folderUsers := map[string][]string{}
	h.mu.RLock()
	folders := maps.Clone(h.st.Folders)
	h.mu.RUnlock()
	s := h.usage
	s.mu.RLock()
	for _, c := range s.conts {
		if c.Kind != usageApp {
			continue
		}
		for _, m := range c.Mounts {
			if m.Type != "bind" {
				continue
			}
			for id, f := range folders {
				if pathUnder(m.Source, f.Path) && !slices.Contains(folderUsers[id], c.Group) {
					folderUsers[id] = append(folderUsers[id], c.Group)
				}
			}
		}
	}
	s.mu.RUnlock()
	scans := h.scanEntries()
	folderScan := map[string]scanEntry{}
	for _, e := range scans {
		if e.Folder != "" {
			folderScan[e.Folder] = e
		}
	}
	// disks: dev → owner → bytes. Free and total are the newest reading
	// of the dev (M2): the live statfs of the data directory beats any
	// cached run's, a newer folder scan beats an older cache entry.
	type disk struct {
		free, total uint64
		at          time.Time
		owners      map[string]int64
		path        string
	}
	disks := map[uint64]*disk{}
	addDisk := func(dev, free, total uint64, at time.Time, owner string, alloc *int64, path string) {
		if total == 0 {
			return
		}
		d := disks[dev]
		if d == nil {
			d = &disk{free: free, total: total, at: at, owners: map[string]int64{}, path: path}
			disks[dev] = d
		} else if !at.Before(d.at) {
			d.free, d.total, d.at = free, total, at
		}
		var n int64
		if alloc != nil {
			n = *alloc
		}
		d.owners[owner] += n
	}
	itemOf := func(e storageEntry, owner string) StorageItem {
		t := e.MeasuredAt
		it := StorageItem{Target: e.Target, Kind: e.Kind, Owner: owner, AllocBytes: e.AllocBytes, ApparentBytes: e.ApparentBytes,
			Partial: e.Partial, PartialReason: e.PartialReason, MeasuredAt: &t, DurationMS: e.DurationMS, Error: e.Error, Dev: e.Dev}
		if e.Kind == "bind" {
			it.Path = e.Target
		}
		for _, o := range e.Owners {
			if o != owner {
				it.Shared = append(it.Shared, o)
			}
		}
		it.InTotal = e.Kind != "image" && len(it.Shared) == 0
		return it
	}
	keys := slices.Sorted(maps.Keys(sf.Entries))
	for _, id := range slices.Sorted(maps.Keys(insts)) {
		g := StorageGroup{Instance: id, Name: insts[id].Name, Items: []StorageItem{}}
		for _, k := range keys {
			e := sf.Entries[k]
			if slices.Contains(e.Owners, id) {
				g.Items = append(g.Items, itemOf(e, id))
			}
		}
		for _, fid := range slices.Sorted(maps.Keys(folderUsers)) {
			if !slices.Contains(folderUsers[fid], id) {
				continue
			}
			fs := h.folderStorage(fid, folders[fid], folderScan, folderUsers[fid])
			g.Items = append(g.Items, StorageItem{Target: fid, Kind: "folder", Owner: id, AllocBytes: fs.AllocBytes, Partial: fs.Partial,
				MeasuredAt: fs.MeasuredAt, InTotal: false, Shared: without(folderUsers[fid], id)})
		}
		g.Items = append(g.Items, StorageItem{Target: "Hub-managed files", Kind: "hub_files", Owner: id})
		var sum int64
		some := false
		for _, it := range g.Items {
			if !it.InTotal {
				continue
			}
			if it.AllocBytes == nil || it.Partial {
				g.Partial = true
			}
			if it.AllocBytes != nil {
				sum += *it.AllocBytes
				some = true
			}
		}
		if some {
			g.TotalAlloc = &sum
		}
		if len(g.Items) > 1 {
			v.Apps = append(v.Apps, g)
		}
	}
	for _, k := range keys {
		e := sf.Entries[k]
		for _, o := range e.Owners {
			addDisk(e.Dev, e.Free, e.Total, e.MeasuredAt, o, e.AllocBytes, e.Target)
		}
		if slices.Contains(e.Owners, usageCoreOwner) {
			v.Core = append(v.Core, itemOf(e, usageCoreOwner))
		}
	}
	for _, fid := range slices.Sorted(maps.Keys(folders)) {
		fs := h.folderStorage(fid, folders[fid], folderScan, folderUsers[fid])
		v.Folders = append(v.Folders, fs)
		if e, ok := folderScan[fid]; ok && e.Report != nil {
			addDisk(e.Report.Dev, e.Report.FreeBytes, e.Report.TotalBytes, e.At, fid, fs.AllocBytes, folders[fid].Path)
		}
	}
	// The Hub's data directory, once the measurer has run (before that
	// nothing of the storage view is judged).
	if sf.LastRun != nil || len(sf.Entries) > 0 {
		if dev, free, total, err := statDir(h.cfg.DataDir); err == nil {
			addDisk(dev, free, total, s.now(), usageCoreOwner, nil, h.cfg.DataDir)
		}
	}
	for _, dev := range slices.Sorted(maps.Keys(disks)) {
		d := disks[dev]
		owners := slices.Collect(maps.Keys(d.owners))
		sort.Slice(owners, func(i, j int) bool {
			if d.owners[owners[i]] != d.owners[owners[j]] {
				return d.owners[owners[i]] > d.owners[owners[j]]
			}
			return owners[i] < owners[j]
		})
		used := 0.0
		if d.total > 0 {
			used = 100 * float64(d.total-min(d.free, d.total)) / float64(d.total)
		}
		v.Disks = append(v.Disks, DiskView{Dev: dev, FreeBytes: d.free, TotalBytes: d.total, UsedPercent: used, Owners: owners, path: d.path})
	}
	return v
}

func without(xs []string, x string) []string {
	var out []string
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

// folderStorage is a shared folder's figure from its doctor scan.
func (h *Hub) folderStorage(id string, f state.Folder, scans map[string]scanEntry, users []string) FolderStorage {
	fs := FolderStorage{ID: id, Name: f.Name, UsedBy: slices.Clone(users)}
	if fs.UsedBy == nil {
		fs.UsedBy = []string{}
	}
	sort.Strings(fs.UsedBy)
	e, ok := scans[id]
	switch {
	case !ok || e.Report == nil:
		fs.Note = noteNotYet
	case e.Children:
		fs.Note = noteTopOnly
	case e.Report.AllocBytes == 0 && e.Report.Entries > 0:
		// A scan cached before alloc_bytes existed.
		fs.Note = noteNotYet
	default:
		fs.AllocBytes = i64p(e.Report.AllocBytes)
		fs.Partial = e.Report.Partial
	}
	if ok {
		t := e.At
		fs.MeasuredAt = &t
	}
	return fs
}

// UsageStorage is the storage view (the cache and the doctor's scans).
func (h *Hub) UsageStorage() StorageView { return h.storageModel() }

// usageStorageGroup is an instance's storage (nil: nothing listed).
func (h *Hub) usageStorageGroup(id string) *StorageGroup {
	for _, g := range h.storageModel().Apps {
		if g.Instance == id {
			return &g
		}
	}
	return nil
}

// statDir is the filesystem of dir: its dev, free and total bytes.
func statDir(dir string) (dev, free, total uint64, err error) {
	var st unix.Stat_t
	if err = unix.Stat(dir, &st); err != nil {
		return
	}
	var fs unix.Statfs_t
	if err = unix.Statfs(dir, &fs); err != nil {
		return
	}
	return uint64(st.Dev), uint64(fs.Bavail) * uint64(fs.Bsize), uint64(fs.Blocks) * uint64(fs.Bsize), nil
}
