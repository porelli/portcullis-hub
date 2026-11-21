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

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/fixerspec"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/usage"
)

// OpUsageMeasure is a storage measurement (op record key opKeyUsage).
const (
	OpUsageMeasure = "usage_measure"
	opKeyUsage     = "_usage"
)

// The measurer's pinned values (contract §11.11).
const (
	storageMaxEntries = fixerspec.UsageMaxEntries
	storageMaxTime    = fixerspec.UsageMaxTime
	storageRunBudget  = time.Hour
	storageFirstDelay = 10 * time.Minute
	storageEvery      = 24 * time.Hour
	storageBusyRetry  = time.Hour // a scheduled run that couldn't start (L11)
)

const usageCoreOwner = "core"

// storageTarget is one thing a run measures, on Server ("" = the
// primary; a worker's targets are measured on that worker, through its
// agent, never by the primary's engine).
type storageTarget struct {
	Key, Kind, Target string // Kind volume | bind | layer | image
	Owners            []string
	Volume            runtime.VolumeMount // a volume
	Source            string              // a bind's host path
	Unit              string              // a layer's container id
	Refused           string              // listed, not measured (why)
	Labelled          bool                // a volume that had labels when listed (M3)
	Server            string
}

// storageKey is a target's cache key: kind:target on the primary,
// "<server>/kind:target" on a worker (the same path or name on two
// servers is two targets).
func storageKey(server, key string) string {
	if server == "" {
		return key
	}
	return server + "/" + key
}

// storageServer is one server's bind scope for a run: its bind roots and
// its engine's data roots (rootsKnown false: binds refused, L1), its
// folders' paths (a bind into one is the folder's, never a target).
type storageServer struct {
	rt               runtime.Instances
	bindRoots, roots []string
	rootsKnown       bool
	folderPaths      []string
	err              error
}

// storageServerOf is server's scope for a run. The primary's comes from
// the caller (its engine's info) and the Hub's bind roots; a worker's
// from its agent's /v1/info (bind roots, DockerRootDir).
func (h *Hub) storageServerOf(ctx context.Context, server string, roots []string, rootsKnown bool) *storageServer {
	ss := &storageServer{}
	h.mu.RLock()
	for _, f := range h.st.Folders {
		if f.Server == server {
			ss.folderPaths = append(ss.folderPaths, f.Path)
		}
	}
	h.mu.RUnlock()
	if server == "" {
		ss.rt, ss.bindRoots, ss.roots, ss.rootsKnown = h.rt, slices.Clone(h.bindRoots), roots, rootsKnown
		return ss
	}
	rt, err := h.rtForServer(server)
	if err != nil {
		ss.err = err
		return ss
	}
	ss.rt = unwrapRT(rt)
	ictx, cancel := context.WithTimeout(ctx, usage.StatsTimeout)
	defer cancel()
	if ai, ok := ss.rt.(interface {
		AgentInfo(context.Context) (agentapi.Info, error)
	}); ok {
		if i, err := ai.AgentInfo(ictx); err == nil {
			ss.bindRoots = slices.Clone(i.BindRoots)
			if i.DockerRootDir != "" {
				ss.roots = []string{i.DockerRootDir}
			}
			ss.rootsKnown = i.DockerRootDir != ""
		}
		return ss
	}
	if i, err := ss.rt.Info(ictx); err == nil {
		ss.roots, ss.rootsKnown = i.ForbiddenRoots, true
	}
	return ss
}

// storageTargets lists instance's targets (all: "") in run order: apps
// by id (volumes, then binds), then core's volumes; then the layers and
// images. A bind or volume several instances use is one target with
// every owner (on one server). An app on a worker is listed on that
// worker's engine (its agent); a worker that isn't ready lists nothing.
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
		id, server, group, service string
		number                     int
		image                      string
		mounts                     []runtime.Mount
	}
	var conts []cont
	s := h.usage
	s.mu.RLock()
	for _, c := range s.conts {
		if c.Kind == usageApp && c.Server == insts[c.Group].Server {
			conts = append(conts, cont{c.ID, c.Server, c.Group, c.Service, c.Number, c.Image, slices.Clone(c.Mounts)})
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
	scopes := map[string]*storageServer{}
	scope := func(server string) *storageServer {
		if ss := scopes[server]; ss != nil {
			return ss
		}
		ss := h.storageServerOf(ctx, server, roots, rootsKnown)
		scopes[server] = ss
		return ss
	}
	byKey := map[string]*storageTarget{}
	var order []string
	add := func(t storageTarget, owner string) {
		t.Key = storageKey(t.Server, t.Key)
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
	// instance on the same server is listed on both), measured when the
	// run covers one.
	type bindKey struct{ server, src string }
	bindOwners := map[bindKey][]string{}
	for _, c := range conts {
		ss := scope(c.server)
		for _, m := range c.mounts {
			if m.Type != "bind" || !slices.ContainsFunc(ss.bindRoots, func(r string) bool { return pathUnder(m.Source, r) }) ||
				slices.ContainsFunc(ss.folderPaths, func(f string) bool { return pathUnder(m.Source, f) }) {
				continue
			}
			k := bindKey{c.server, m.Source}
			if !slices.Contains(bindOwners[k], c.group) {
				bindOwners[k] = append(bindOwners[k], c.group)
			}
		}
	}
	for _, id := range ids {
		server := insts[id].Server
		ss := scope(server)
		if ss.err != nil {
			log.Printf("usage: %s's targets on server %s: %s", id, server, usageErrText(ss.err))
			continue
		}
		lctx, lcancel := storageCallCtx(ctx, server, storageWorkerCall)
		vols, err := ss.rt.ListVolumes(lctx, runtime.Filter{Instance: id})
		lcancel()
		if err != nil {
			if server != "" {
				// A worker that fails its listing: none of its instances
				// is listed again this run (each would wait its deadline);
				// their targets wait for the next run, the primary's run.
				log.Printf("usage: %s's volumes on server %s: %s (its other instances skipped this run)", id, server, usageErrText(err))
				ss.err = err
				continue
			}
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
			add(storageTarget{Key: "volume:" + n, Kind: "volume", Target: n, Volume: runtime.VolumeMount{Name: n, Instance: id}, Labelled: labelled[n], Server: server}, id)
		}
		var binds []string
		for k, owners := range bindOwners {
			if k.server == server && slices.Contains(owners, id) {
				binds = append(binds, k.src)
			}
		}
		sort.Strings(binds)
		for _, src := range binds {
			t := storageTarget{Key: "bind:" + src, Kind: "bind", Target: src, Source: src, Server: server}
			if !ss.rootsKnown {
				t.Refused = "refused: the engine's data root is unknown"
			}
			for _, r := range ss.roots {
				if pathUnder(src, r) {
					t.Refused = "refused: under the engine's data root"
				}
			}
			for _, o := range bindOwners[bindKey{server, src}] {
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
	// The primary's targets first: a worker never pushes them out of the
	// run's budget.
	sort.SliceStable(disk, func(i, j int) bool { return disk[i].Server == "" && disk[j].Server != "" })
	// Writable layers, then images (instances share images: listed, not
	// in any total).
	type imageKey struct{ server, ref string }
	images := map[imageKey][]string{}
	for _, c := range conts {
		if instance != "" && c.group != instance {
			continue
		}
		if _, ok := insts[c.group]; !ok {
			continue
		}
		key := c.group + "/" + usageKey(c.service, c.number)
		sizes = append(sizes, storageTarget{Key: storageKey(c.server, "layer:"+key), Kind: "layer", Target: usageKey(c.service, c.number), Owners: []string{c.group}, Unit: c.id, Server: c.server})
		k := imageKey{c.server, c.image}
		if c.image != "" && !slices.Contains(images[k], c.group) {
			images[k] = append(images[k], c.group)
		}
	}
	ikeys := slices.Collect(maps.Keys(images))
	sort.Slice(ikeys, func(i, j int) bool {
		if ikeys[i].server != ikeys[j].server {
			return ikeys[i].server < ikeys[j].server
		}
		return ikeys[i].ref < ikeys[j].ref
	})
	for _, k := range ikeys {
		owners := images[k]
		sort.Strings(owners)
		sizes = append(sizes, storageTarget{Key: storageKey(k.server, "image:"+k.ref), Kind: "image", Target: k.ref, Owners: owners, Server: k.server})
	}
	sort.SliceStable(sizes, func(i, j int) bool { return sizes[i].Server == "" && sizes[j].Server != "" })
	return disk, sizes, nil
}

// storageVolumeLive: t's volume still exists, and so does its instance
// (an instance's volume). An inspect error but "not found" counts as live:
// the helper run reports the real failure.
func (h *Hub) storageVolumeLive(ctx context.Context, t storageTarget) bool {
	if id := t.Volume.Instance; id != "" {
		if in, ok := h.usageInstances()[id]; !ok || in.Server != t.Server {
			return false
		}
	}
	rt, err := h.storageRT(t.Server)
	if err != nil {
		return false
	}
	cctx, cancel := storageCallCtx(ctx, t.Server, storageWorkerCall)
	defer cancel()
	_, err = rt.InspectVolume(cctx, t.Volume.Name)
	return err == nil || !docker.IsNotFound(err)
}

// The Hub-side deadlines of a worker's storage calls (the agent client's
// own default is hours): an inspect, remove, list or size like the
// primary's engine calls; a fixer run its walk's cap and a margin.
var (
	storageWorkerCall  = 10 * time.Second
	storageWorkerFixer = fixerspec.UsageMaxTime + time.Minute
)

// storageCallCtx bounds a call to a worker (the primary's engine client
// bounds its own).
func storageCallCtx(ctx context.Context, server string, d time.Duration) (context.Context, context.CancelFunc) {
	if server == "" {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

// storageRT is the engine a target is measured on: the primary's, or the
// worker's agent backend while it is ready.
func (h *Hub) storageRT(server string) (runtime.Instances, error) {
	if server == "" {
		return h.rt, nil
	}
	rt, err := h.rtForServer(server)
	if err != nil {
		return nil, err
	}
	return unwrapRT(rt), nil
}

// storageVolumeRecreated: the volume was deleted between the check and the
// helper's create, so the engine made it anew, without labels (M3). The
// new, empty volume is removed (never forced), and the target is gone.
func (h *Hub) storageVolumeRecreated(ctx context.Context, t storageTarget) bool {
	rt, err := h.storageRT(t.Server)
	if err != nil || !t.Labelled || rt.Kind() == runtime.KindKubernetes {
		return false
	}
	cctx, cancel := storageCallCtx(ctx, t.Server, storageWorkerCall)
	defer cancel()
	v, err := rt.InspectVolume(cctx, t.Volume.Name)
	if err != nil || len(v.Labels) > 0 {
		return false
	}
	if err := rt.RemoveVolume(cctx, t.Volume.Name); err != nil {
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
		e := storageEntry{Kind: t.Kind, Target: t.Target, Owners: t.Owners, MeasuredAt: s.now(), Server: t.Server}
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
		r := fixerRun{Mode: "usage", Volume: t.Volume, Source: t.Source, Server: t.Server, Opts: folderfix.Options{MaxEntries: storageMaxEntries, MaxTime: storageMaxTime}}
		began := time.Now()
		// diskMu guards the primary's disks (never two walks at once,
		// U12); a worker's run walks the worker's disks and is never
		// held under it (nor without its own deadline).
		var rep *folderfix.Report
		if t.Server == "" {
			s.diskMu.Lock()
			rep, err = h.usageFixerRun(runCtx, r)
			s.diskMu.Unlock()
		} else {
			fctx, fcancel := context.WithTimeout(runCtx, storageWorkerFixer)
			rep, err = h.usageFixerRun(fctx, r)
			fcancel()
		}
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
			e.Partial, e.PartialReason = rep.Partial, clipRunes(rep.PartialReason, 200)
			e.Dev, e.Free, e.Total = rep.Dev, rep.FreeBytes, rep.TotalBytes
			measured++
		}
		got[t.Key] = e
	}
	for _, t := range sizes {
		if !next(t) {
			continue
		}
		e := storageEntry{Kind: t.Kind, Target: t.Target, Owners: t.Owners, MeasuredAt: s.now(), Server: t.Server}
		began := time.Now()
		var size int64
		rt, err := h.storageRT(t.Server)
		switch {
		case err != nil:
		case t.Kind == "layer":
			cctx, cancel := storageCallCtx(runCtx, t.Server, storageWorkerCall)
			size, err = rt.LayerSize(cctx, t.Unit)
			cancel()
		default:
			cctx, cancel := storageCallCtx(runCtx, t.Server, storageWorkerCall)
			size, err = rt.ImageSize(cctx, t.Target)
			cancel()
		}
		if err == nil && size < 0 {
			err = errors.New("a negative size")
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

// serverIDOf is a server's id in the views: "" (the primary's internal
// form) is servers.PrimaryID.
func serverIDOf(s string) string {
	if s == "" {
		return servers.PrimaryID
	}
	return s
}

// FolderStorage is one shared folder, from the doctor's scan.
type FolderStorage struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Server: the server the folder is defined on ("primary", a worker).
	Server     string     `json:"server"`
	AllocBytes *int64     `json:"alloc_bytes"`
	Partial    bool       `json:"partial"`
	UsedBy     []string   `json:"used_by"`
	MeasuredAt *time.Time `json:"measured_at"`
	Note       string     `json:"note,omitempty"`
}

// DiskView is one filesystem.
type DiskView struct {
	// Server: the server it is on ("primary"; workers: Task 10).
	Server string `json:"server"`
	Dev    uint64 `json:"dev"`
	// Device is dev as "<major>:<minor>" (lsblk's form); Role what it
	// holds (docker_data | folder_root | agent_data | other) and Path a
	// host path on it ("": unknown), contract §11.11 "Disk roles".
	Device      string   `json:"device"`
	Role        string   `json:"role"`
	Path        string   `json:"path,omitempty"`
	FreeBytes   uint64   `json:"free_bytes"`
	TotalBytes  uint64   `json:"total_bytes"`
	UsedPercent float64  `json:"used_percent"`
	Owners      []string `json:"owners"`
	// fsPath: a path on it (the doctor's fingerprint).
	fsPath string
}

// The disk roles (contract §11.11 "Disk roles"), in precedence order.
const (
	DiskDockerData = "docker_data"
	DiskFolderRoot = "folder_root"
	DiskAgentData  = "agent_data"
	DiskOther      = "other"
)

// linuxDevice is dev as "<major>:<minor>" in Linux's encoding (the dev
// numbers come from Linux hosts' reports and statfs).
func linuxDevice(dev uint64) string {
	major := (dev>>8)&0xfff | (dev>>32)&0xfffff000
	minor := dev&0xff | (dev>>12)&0xffffff00
	return strconv.FormatUint(major, 10) + ":" + strconv.FormatUint(minor, 10)
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
	// mounters: "<owner>\x00<kind>:<target>" → the owner's containers
	// that mount it ("<service>.<number>"), for the items' services.
	mounters := map[string][]string{}
	s := h.usage
	s.mu.RLock()
	// roots: each server's engine data root ("" the primary), the
	// docker_data disk's path.
	roots := map[string]string{"": s.dataRoot}
	for id, w := range s.workers {
		roots[id] = w.dataRoot
	}
	for _, c := range s.conts {
		if c.Kind != usageApp && c.Kind != usageCore {
			continue
		}
		// An app's containers on its own server only (a leftover on
		// another server is not its storage's user).
		if (c.Kind == usageApp && c.Server != insts[c.Group].Server) || (c.Kind == usageCore && c.Server != "") {
			continue
		}
		owner := c.Group
		if c.Kind == usageCore {
			owner = usageCoreOwner
		}
		for _, m := range c.Mounts {
			var k string
			switch {
			case m.Type == "volume" && m.Name != "":
				k = owner + "\x00volume:" + m.Name
			case m.Type == "bind" && m.Source != "":
				k = owner + "\x00bind:" + m.Source
			default:
				continue
			}
			if svc := usageKey(c.Service, c.Number); !slices.Contains(mounters[k], svc) {
				mounters[k] = append(mounters[k], svc)
			}
		}
		if c.Kind != usageApp {
			continue
		}
		for _, m := range c.Mounts {
			if m.Type != "bind" {
				continue
			}
			for id, f := range folders {
				if f.Server == c.Server && pathUnder(m.Source, f.Path) && !slices.Contains(folderUsers[id], c.Group) {
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
	// volume / dataDir: a measured volume (the engine's data root) or the
	// Hub's data directory is on it; folders / binds: the shared-folder
	// and bind paths on it.
	type disk struct {
		free, total    uint64
		at             time.Time
		owners         map[string]int64
		path           string
		volume         bool
		dataDir        bool
		folders, binds []string
	}
	// diskKey: a filesystem is one server's (the same dev on two servers
	// is two disks).
	type diskKey struct {
		server string
		dev    uint64
	}
	disks := map[diskKey]*disk{}
	addDisk := func(server string, dev, free, total uint64, at time.Time, owner string, alloc *int64, path, kind string) {
		if total == 0 {
			return
		}
		defer func() {
			d := disks[diskKey{server, dev}]
			switch kind {
			case "volume":
				d.volume = true
			case "datadir":
				d.dataDir = true
			case "folder":
				if !slices.Contains(d.folders, path) {
					d.folders = append(d.folders, path)
				}
			case "bind":
				if !slices.Contains(d.binds, path) {
					d.binds = append(d.binds, path)
				}
			}
		}()
		d := disks[diskKey{server, dev}]
		if d == nil {
			d = &disk{free: free, total: total, at: at, owners: map[string]int64{}, path: path}
			disks[diskKey{server, dev}] = d
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
			Partial: e.Partial, PartialReason: e.PartialReason, MeasuredAt: &t, DurationMS: e.DurationMS, Error: e.Error}
		if e.Kind == "volume" || e.Kind == "bind" {
			// A report's dev: only a measured volume or bind has one.
			if e.Error == "" && e.AllocBytes != nil && e.Total > 0 {
				dev := e.Dev
				it.Dev = &dev
			}
			if ss := mounters[owner+"\x00"+e.Kind+":"+e.Target]; len(ss) > 0 {
				it.Services = slices.Sorted(slices.Values(ss))
			}
		}
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
		g := StorageGroup{Instance: id, Name: insts[id].Name, Server: serverIDOf(insts[id].Server), Items: []StorageItem{}}
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
			it := StorageItem{Target: fid, Kind: "folder", Owner: id, AllocBytes: fs.AllocBytes, Partial: fs.Partial,
				MeasuredAt: fs.MeasuredAt, InTotal: false, Shared: without(folderUsers[fid], id)}
			// The doctor's scan report names the folder's filesystem.
			if sc, ok := folderScan[fid]; ok && sc.Report != nil && sc.Report.TotalBytes > 0 {
				dev := sc.Report.Dev
				it.Dev = &dev
			}
			g.Items = append(g.Items, it)
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
			addDisk(e.Server, e.Dev, e.Free, e.Total, e.MeasuredAt, o, e.AllocBytes, e.Target, e.Kind)
		}
		if slices.Contains(e.Owners, usageCoreOwner) {
			v.Core = append(v.Core, itemOf(e, usageCoreOwner))
		}
	}
	for _, fid := range slices.Sorted(maps.Keys(folders)) {
		fs := h.folderStorage(fid, folders[fid], folderScan, folderUsers[fid])
		v.Folders = append(v.Folders, fs)
		if e, ok := folderScan[fid]; ok && e.Report != nil {
			addDisk(folders[fid].Server, e.Report.Dev, e.Report.FreeBytes, e.Report.TotalBytes, e.At, fid, fs.AllocBytes, folders[fid].Path, "folder")
		}
	}
	// The Hub's data directory, once the measurer has run (before that
	// nothing of the storage view is judged).
	if sf.LastRun != nil || len(sf.Entries) > 0 {
		if dev, free, total, err := statDir(h.cfg.DataDir); err == nil {
			addDisk("", dev, free, total, s.now(), usageCoreOwner, nil, h.cfg.DataDir, "datadir")
		}
	}
	dkeys := slices.Collect(maps.Keys(disks))
	sort.Slice(dkeys, func(i, j int) bool {
		if dkeys[i].server != dkeys[j].server {
			return dkeys[i].server < dkeys[j].server
		}
		return dkeys[i].dev < dkeys[j].dev
	})
	for _, dk := range dkeys {
		d, dev := disks[dk], dk.dev
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
		role, path := DiskOther, ""
		switch {
		case d.volume:
			role, path = DiskDockerData, roots[dk.server]
		case len(d.folders) > 0:
			role, path = DiskFolderRoot, slices.Min(d.folders)
		case d.dataDir:
			role = DiskAgentData
		case len(d.binds) > 0:
			path = slices.Min(d.binds)
		}
		v.Disks = append(v.Disks, DiskView{Server: usageServerID(dk.server), Dev: dev, Device: linuxDevice(dev), Role: role, Path: path,
			FreeBytes: d.free, TotalBytes: d.total, UsedPercent: used, Owners: owners, fsPath: d.path})
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
	fs := FolderStorage{ID: id, Name: f.Name, Server: serverIDOf(f.Server), UsedBy: slices.Clone(users)}
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
