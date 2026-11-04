package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The doctor's disk checks (contract §14.5, Task 11): fixer scans of every
// shared folder and of the hand-typed host paths apps share, run on demand
// (StartDoctorScan), after every folder apply (storeScan) and daily
// (RunDoctorScans), plus the runtime gid check of the running containers.
// Results are cached in <data>/doctor/scans.json (0600, size-bounded; a
// corrupt cache is dropped and means a rescan) and judged by the doctor's
// disk checks on every GET /api/doctor. Every scan is read-only (the
// folder bound read-only, DAC_READ_SEARCH only, --max-entries /
// --max-time), one target after the other, outside mu; a folder's scan
// holds its folderLock (a busy folder is skipped and keeps its previous
// result), so a folder is never scanned twice at once.

// OpDoctorScan is an on-demand disk check (op record key opKeyDoctor).
const OpDoctorScan = "doctor_scan"

const (
	// maxScanCacheBytes / maxScanCacheEntries bound the cache file: over
	// the size, reports lose their sample paths, then the oldest entries
	// go; a larger file on disk is corrupt.
	maxScanCacheBytes   = 8 << 20
	maxScanCacheEntries = 512
	// maxScanPrincipals: identities judged per target.
	maxScanPrincipals = 32
	// doctorScanBudget bounds one run: each scan stops at scanMaxTime (the
	// walk's R50 chain check costs O(depth) per entry, so a deep tree
	// reaches the time cap before the entry cap), and targets left when
	// the budget is spent keep their previous result.
	doctorScanBudget = 3 * time.Hour
	// The runtime gid check: containers per run, process statuses per
	// container, and each exec's timeout.
	maxRuntimeContainers = 256
	maxStatusPIDs        = 64
	gidExecTimeout       = 10 * time.Second
	// defaultScanStartDelay: the first scheduled run after a start (when
	// the cache is older than the interval), so the Hub settles first.
	defaultScanStartDelay = 5 * time.Minute
	scanCacheVersion      = 1
)

// ScanTarget is one disk scan: a shared folder (Folder) or a hand-typed
// host path (Folder ""); Principals are the identities judged there
// (folderfix names them "<instance>" or "<instance>.<n>"), Target the
// folder's last apply (nil = no expected state: never applied, or a
// hand-typed path).
type ScanTarget struct {
	Path, Folder string
	Principals   []folderfix.Principal
	Target       *folderfix.Target
}

// scanEntry is one cached scan (Report nil ⇔ Err set).
type scanEntry struct {
	Target     string                `json:"target"`
	Folder     string                `json:"folder,omitempty"`
	At         time.Time             `json:"at"`
	Report     *folderfix.Report     `json:"report,omitempty"`
	Principals []folderfix.Principal `json:"principals,omitempty"`
	Err        string                `json:"error,omitempty"`
	// Dev / Ino: a folder entry's root as state.yaml had it when scanned
	// (M6: a folder re-created at the same path is another directory).
	Dev uint64 `json:"dev,omitempty"`
	Ino uint64 `json:"ino,omitempty"`
}

// runtimeEntry is one running container's gids (the runtime gid check).
type runtimeEntry struct {
	Instance  string `json:"instance"`
	Service   string `json:"service"`
	Container string `json:"container"`
	GIDs      []int  `json:"gids"`
	// Err: the container couldn't be read (an Info finding, I4).
	Err string `json:"error,omitempty"`
	// Read / Total: processes read and listed (H11 M4).
	Read  int `json:"pids_read,omitempty"`
	Total int `json:"pids_total,omitempty"`
	// At: when they were read (H11 M6).
	At time.Time `json:"at,omitempty"`
}

// scanFile is <data>/doctor/scans.json.
type scanFile struct {
	Version int                  `json:"version"`
	LastRun time.Time            `json:"last_run"` // the last full run that finished (zero: never: a rescan is due)
	Scans   map[string]scanEntry `json:"scans"`    // by target path
	Runtime []runtimeEntry       `json:"runtime"`
}

func (h *Hub) scanCachePath() string { return filepath.Join(h.cfg.DataDir, "doctor", "scans.json") }

// ── targets ─────────────────────────────────────────────

// scanTargetsLocked lists the disk scans (contract §14.5): every shared
// folder, and every distinct hand-typed host path (settings and
// custom-override mounts of enabled instances, under the bind roots, not
// inside a shared folder) used by two or more uses or by a writer, nested
// paths collapsed to the outermost. Sorted by path. Caller holds mu.
func (h *Hub) scanTargetsLocked() []ScanTarget {
	uses := h.pathUsagesLocked()
	var out []ScanTarget
	for _, id := range slices.Sorted(maps.Keys(h.st.Folders)) {
		f := h.st.Folders[id]
		t := ScanTarget{Path: f.Path, Folder: id}
		if a := f.LastApply; a != nil {
			t.Target = &folderfix.Target{GID: f.GID, Files: a.Files}
			if a.OwnerUID != nil {
				uid := *a.OwnerUID
				t.Target.OwnerUID = &uid
			}
		}
		var fu []PathUsage
		for _, u := range uses {
			if u.Folder == id {
				fu = append(fu, u)
			}
		}
		t.Principals = scanPrincipals(fu)
		out = append(out, t)
	}
	var hand []PathUsage
	for _, u := range uses {
		if (u.Source != PathSourceSetting && u.Source != PathSourceCustomOverride) || u.HostPath == "" {
			continue
		}
		p := path.Clean(u.HostPath)
		if !h.underBindRoots(p) || h.inFolderLocked(p) {
			continue
		}
		u.HostPath = p
		hand = append(hand, u)
	}
	sort.SliceStable(hand, func(i, j int) bool { return hand[i].HostPath < hand[j].HostPath })
	// An ancestor sorts before its descendants: the first path of a
	// cluster is its outermost.
	var roots []string
	cl := map[string][]PathUsage{}
	for _, u := range hand {
		root := ""
		for _, r := range roots {
			if pathUnder(u.HostPath, r) {
				root = r
				break
			}
		}
		if root == "" {
			root = u.HostPath
			roots = append(roots, root)
		}
		cl[root] = append(cl[root], u)
	}
	for _, r := range roots {
		us := cl[r]
		writer := slices.ContainsFunc(us, func(u PathUsage) bool { return u.Writes })
		if len(us) < 2 && !writer {
			continue
		}
		var own []PathUsage
		for _, u := range us {
			if u.HostPath == r {
				own = append(own, u)
			}
		}
		out = append(out, ScanTarget{Path: r, Principals: scanPrincipals(own)})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// underBindRoots: p is at or under one of the bind roots.
func (h *Hub) underBindRoots(p string) bool {
	return slices.ContainsFunc(h.bindRoots, func(r string) bool { return pathUnder(p, r) })
}

// inFolderLocked: p is at or under a shared folder (its scan covers it).
func (h *Hub) inFolderLocked(p string) bool {
	for _, f := range h.st.Folders {
		if pathUnder(p, f.Path) {
			return true
		}
	}
	return false
}

// scanPrincipals is the uses' identities (declared owners only): uid,
// primary gid then the gids the Hub adds, write when any of them writes;
// one per distinct identity, named by instance ("<instance>.<n>" from the
// second of an instance on).
func scanPrincipals(uses []PathUsage) []folderfix.Principal {
	us := slices.Clone(uses)
	sort.SliceStable(us, func(i, j int) bool {
		if us[i].Instance != us[j].Instance {
			return us[i].Instance < us[j].Instance
		}
		return us[i].Key < us[j].Key
	})
	var out []folderfix.Principal
	idx := map[string]int{}
	perInst := map[string]int{}
	for _, u := range us {
		if !u.OwnerKnown || u.UID < 0 || u.GID < 0 {
			continue
		}
		gids := []int{u.GID}
		for _, g := range u.GIDs {
			if !slices.Contains(gids, g) {
				gids = append(gids, g)
			}
		}
		k := fmt.Sprint(u.Instance, u.UID, gids)
		if i, ok := idx[k]; ok {
			out[i].Write = out[i].Write || u.Writes
			continue
		}
		if len(out) == maxScanPrincipals {
			break
		}
		perInst[u.Instance]++
		name := u.Instance
		if n := perInst[u.Instance]; n > 1 {
			name += "." + strconv.Itoa(n)
		}
		idx[k] = len(out)
		out = append(out, folderfix.Principal{UID: u.UID, GIDs: gids, Write: u.Writes, Name: name})
	}
	return out
}

// ── running scans ───────────────────────────────────────

// StartDoctorScan runs every disk scan and the runtime gid check in the
// background (op key "_doctor", op doctor_scan; 202). 401 without an
// actor, 503 without Users & Groups or the Engine API, 409 while a scan
// runs (scheduled or on demand).
//
// Audited doctor.scan (target "disks"): a refusal (401, 503, 409) as
// "refused", a finished scan with its counts — always after scanMu is
// released (I1).
func (h *Hub) StartDoctorScan(actor string) (*AsyncOp, error) {
	op, err := h.startDoctorScan(actor)
	if err != nil {
		h.auditScan(actor, "", err)
	}
	return op, err
}

// auditScan writes the doctor.scan entry (after every lock): err set = the
// scan was refused before it started (401, 503 and 409 alike: nothing
// ran), recorded "refused" with its reason.
func (h *Hub) auditScan(actor, detail string, err error) {
	h.mu.RLock()
	a := h.audit
	h.mu.RUnlock()
	if a == nil {
		return
	}
	e := directory.AuditEntry{Actor: actor, Action: "doctor.scan", Target: "disks", Detail: detail, Result: "ok"}
	if err != nil {
		e.Result, e.Error = "refused", err.Error()
	}
	if aerr := a.Append(e); aerr != nil {
		log.Printf("audit: %v", aerr)
	}
}

func (h *Hub) startDoctorScan(actor string) (*AsyncOp, error) {
	if actor == "" {
		return nil, statusErr(http.StatusUnauthorized, "a disk check needs a signed-in admin")
	}
	h.mu.RLock()
	noPeople := h.people == nil
	h.mu.RUnlock()
	if noPeople {
		return nil, statusErr(http.StatusServiceUnavailable, "users & groups is not available")
	}
	if h.engine == nil {
		return nil, statusErr(http.StatusServiceUnavailable, "the disk check needs the Docker Engine API")
	}
	return h.startAsync(opKeyDoctor, OpDoctorScan, func(ready func()) (map[string]string, []string, error) {
		if !h.scanMu.TryLock() {
			return nil, nil, statusErr(http.StatusConflict, "a disk check is already running")
		}
		ready()
		res, warns := func() (map[string]string, []string) {
			defer h.scanMu.Unlock()
			return h.runDoctorScan(h.doctorContext())
		}()
		h.auditScan(actor, fmt.Sprintf("targets=%s scanned=%s failed=%s skipped=%s containers=%s",
			res["targets"], res["scanned"], res["failed"], res["skipped"], res["containers"]), nil)
		return res, warns, nil
	})
}

// RunDoctorScans runs the disk check every interval until ctx ends (main:
// daily). The first run waits scanStartDelay, or until the last full run
// is an interval old; a run while another holds scanMu is skipped. A
// running scan stops with ctx (the fixer is killed); so do on-demand
// scans, which use ctx too.
func (h *Hub) RunDoctorScans(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 24 * time.Hour
	}
	h.scanCacheMu.Lock()
	h.scanCtx = ctx
	h.scanCacheMu.Unlock()
	delay := h.scanStartDelay
	if delay <= 0 {
		delay = defaultScanStartDelay
	}
	if last := h.lastFullScan(); !last.IsZero() {
		if d := time.Until(last.Add(every)); d > delay {
			delay = d
		}
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		switch {
		case h.engine == nil:
		case !h.scanMu.TryLock():
			log.Printf("doctor: a disk check is already running: the scheduled one is skipped")
		default:
			res, warns := h.runDoctorScan(ctx)
			h.scanMu.Unlock()
			log.Printf("doctor: scheduled disk check: %d scanned, %d failed, %d skipped, %s containers%s",
				countOf(res["scanned"]), countOf(res["failed"]), countOf(res["skipped"]), res["containers"], warnSuffix(warns))
		}
		t.Reset(every)
	}
}

func countOf(s string) int { n, _ := strconv.Atoi(s); return n }

func warnSuffix(ws []string) string {
	if len(ws) == 0 {
		return ""
	}
	return " (" + strings.Join(ws, "; ") + ")"
}

// doctorContext is the scheduler's context (the Hub's lifetime), or
// Background before RunDoctorScans started.
func (h *Hub) doctorContext() context.Context {
	h.scanCacheMu.Lock()
	defer h.scanCacheMu.Unlock()
	if h.scanCtx != nil {
		return h.scanCtx
	}
	return context.Background()
}

// runDoctorScan scans every target, one after the other (the caller holds
// scanMu), then reads the running containers' gids, and caches it all.
// A failed target is cached as failed (scan_failed) and the others go on;
// a busy folder, or a target past the run's budget, keeps its previous
// result.
func (h *Hub) runDoctorScan(ctx context.Context) (map[string]string, []string) {
	start := time.Now().UTC()
	h.mu.RLock()
	targets := h.scanTargetsLocked()
	var enabled []string
	for i := range h.instances {
		if h.st.IsEnabled(h.instances[i].ID) {
			enabled = append(enabled, h.instances[i].ID)
		}
	}
	h.mu.RUnlock()
	sort.Strings(enabled)
	var warns []string
	scanned, failed, skipped := 0, 0, 0
	keep := map[string]bool{}
	for _, t := range targets {
		keep[t.Path] = true
		if ctx.Err() != nil {
			skipped++
			continue
		}
		if time.Since(start) > doctorScanBudget {
			skipped++
			warns = append(warns, fmt.Sprintf("%s: not checked, the run's time budget (%s) is spent; its previous check is kept", t.Path, doctorScanBudget))
			continue
		}
		e, why := h.scanOne(ctx, t)
		if why != "" {
			skipped++
			warns = append(warns, why)
			continue
		}
		if e.Err != "" {
			failed++
		} else {
			scanned++
		}
		h.putScan(e)
	}
	if ctx.Err() != nil {
		warns = append(warns, "stopped: the Hub is shutting down")
	}
	rt := h.collectRuntime(ctx, enabled)
	h.finishScanRun(start, keep, rt, ctx.Err() == nil)
	return map[string]string{"targets": strconv.Itoa(len(targets)), "scanned": strconv.Itoa(scanned),
		"failed": strconv.Itoa(failed), "skipped": strconv.Itoa(skipped), "containers": strconv.Itoa(len(rt))}, warns
}

// scanOne scans t (never under mu). why != "": not scanned, the previous
// result kept (a busy or meanwhile changed folder).
func (h *Hub) scanOne(ctx context.Context, t ScanTarget) (e scanEntry, why string) {
	e = scanEntry{Target: t.Path, Folder: t.Folder, Principals: t.Principals}
	fail := func(err error) (scanEntry, string) {
		e.At, e.Report, e.Err = time.Now().UTC(), nil, clipRunes(err.Error(), 400)
		return e, ""
	}
	opts := folderfix.Options{Principals: t.Principals, MaxEntries: scanMaxEntries, MaxTime: scanMaxTime}
	if t.Target != nil {
		opts.Target = *t.Target
	}
	if t.Folder != "" {
		h.mu.RLock()
		f, ok := h.st.Folders[t.Folder]
		h.mu.RUnlock()
		name := t.Folder
		if ok {
			name = f.Name
		}
		unlock, err := h.folderLock(t.Folder)
		if err != nil {
			return e, fmt.Sprintf("shared folder %s is busy (an operation holds it): its previous check is kept", name)
		}
		defer unlock()
		h.mu.RLock()
		f, ok = h.st.Folders[t.Folder]
		h.mu.RUnlock()
		if !ok || f.Path != t.Path {
			return e, fmt.Sprintf("shared folder %s changed while the check ran: checked next time", name)
		}
		opts.ExpectDev, opts.ExpectIno, opts.ExpectMountRoot = f.Dev, f.Ino, f.MountRoot
		e.Dev, e.Ino = f.Dev, f.Ino
		rep, err := h.runFixer(ctx, fixerRun{Mode: "scan", Folder: t.Folder, Source: f.Path, Opts: opts})
		if err != nil {
			return fail(err)
		}
		if rep.Dev != f.Dev || rep.Ino != f.Ino {
			why := identityText
			if rep.Ino != f.Ino {
				why = swappedText
			}
			return fail(fmt.Errorf("%s: device/inode %d/%d, now %d/%d: %s", f.Path, f.Dev, f.Ino, rep.Dev, rep.Ino, why))
		}
		e.At, e.Report = time.Now().UTC(), rep
		return e, ""
	}
	// A hand-typed path (ruling 36, S10): the folder path rules and a
	// probe (no symlink component) before it is bound into the helper,
	// then its mount root checked against the path below its bind root.
	p := t.Path
	if c, err := cleanFolderPath(p); err != nil || c != p {
		if err == nil {
			err = fmt.Errorf("%s is not a clean path", p)
		}
		return fail(err)
	}
	if err := h.folderPathRule(p); err != nil {
		return fail(err)
	}
	if err := h.dockerRootRule(ctx, p); err != nil {
		return fail(err)
	}
	pr, err := h.probePath(ctx, p, false, "")
	if err != nil {
		return fail(err)
	}
	if !pr.Exists {
		return fail(fmt.Errorf("%s doesn't exist", p))
	}
	opts.ExpectDev, opts.ExpectIno = pr.Dev, pr.Ino
	rep, err := h.runFixer(ctx, fixerRun{Mode: "scan", Source: p, Opts: opts})
	if err != nil {
		return fail(err)
	}
	if rep.Dev != pr.Dev || rep.Ino != pr.Ino {
		return fail(fmt.Errorf("%s changed while it was checked: checked next time", p))
	}
	if _, rel := h.bindRootOf(p); rel == "" || (rep.MountRoot != "/"+rel && !strings.HasSuffix(rep.MountRoot, "/"+rel)) {
		return fail(fmt.Errorf("the mount root %q of %s doesn't end with %q: the path resolved elsewhere, so its check was discarded", clipRunes(rep.MountRoot, 200), p, "/"+rel))
	}
	e.At, e.Report = time.Now().UTC(), rep
	return e, ""
}

// storeScan keeps an apply's verify scan as the folder's doctor scan
// (P13): its races and skipped entries become skipped_entries findings,
// its conformance clears a drift finding, and its principals (the uses
// as the apply leaves them, I3) keep a blocked app reported. Called
// outside mu.
func (h *Hub) storeScan(folder string, rep *folderfix.Report, principals []folderfix.Principal) {
	if rep == nil {
		return
	}
	h.mu.RLock()
	f, ok := h.st.Folders[folder]
	h.mu.RUnlock()
	if !ok {
		return
	}
	cp := *rep
	h.putScan(scanEntry{Target: f.Path, Folder: folder, At: time.Now().UTC(), Report: &cp,
		Principals: slices.Clone(principals), Dev: f.Dev, Ino: f.Ino})
}

// plannedPrincipals are folder id's uses' principals as the apply c
// leaves them (I3: the verify scan judges them), from a planned copy —
// T8's renderView {settings, folders} with c's edits applied to clones
// (applyEdits) and the folder's write confirmations — under the read
// lock (deferred: a panic releases it). h.st is never changed (T8 C1).
func (h *Hub) plannedPrincipals(id string, c *assignCalc) []folderfix.Principal {
	h.mu.RLock()
	defer h.mu.RUnlock()
	planned := renderView{settings: maps.Clone(h.st.Settings), folders: maps.Clone(h.st.Folders)}
	if planned.settings == nil {
		planned.settings = map[string]state.InstanceSettings{}
	}
	if planned.folders == nil {
		planned.folders = map[string]state.Folder{}
	}
	for _, inst := range c.changedInstances() {
		if next := applyEdits(h.st.Settings[inst], c.edits, inst); next.IsZero() {
			delete(planned.settings, inst)
		} else {
			planned.settings[inst] = next
		}
	}
	if f, ok := planned.folders[id]; ok {
		f.WriteConfirmed = maps.Clone(c.wc)
		planned.folders[id] = f
	}
	var fu []PathUsage
	for _, u := range h.pathUsagesIn(planned) {
		if u.Folder == id {
			fu = append(fu, u)
		}
	}
	return scanPrincipals(fu)
}

// ── the runtime gid check ───────────────────────────────

// collectRuntime reads the gids every running container of the enabled
// instances holds (containerGIDs). A container that can't be read is
// left out (logged): no finding, never a guess.
func (h *Hub) collectRuntime(ctx context.Context, ids []string) []runtimeEntry {
	out := []runtimeEntry{}
	if h.engine == nil {
		return out
	}
	for _, id := range ids {
		if ctx.Err() != nil || len(out) >= maxRuntimeContainers {
			break
		}
		cs, err := h.engine.ListContainers(ctx, docker.ProjectFilter(projectName(id)))
		if err != nil {
			log.Printf("doctor: %s: listing containers: %v", id, err)
			continue
		}
		sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
		for _, c := range cs {
			if c.State != "running" || c.Project() != projectName(id) || len(out) >= maxRuntimeContainers {
				continue
			}
			e := runtimeEntry{Instance: id, Service: c.Service(), Container: c.Name(), At: time.Now().UTC()}
			ci, err := h.engine.InspectContainer(ctx, c.ID)
			switch {
			case err != nil:
				e.Err = clipRunes("inspecting the container failed: "+err.Error(), 300)
			case ci.PidMode == "host":
				// I2: its /proc is the host's: other apps' processes
				// would be blamed on it.
				e.Err = "it runs with pid: host, so its /proc lists the host's processes, not its own"
			case strings.HasPrefix(ci.PidMode, "container:"):
				// H11 M5: another container's processes would be blamed
				// on it.
				e.Err = "it shares another container's pid namespace (pid: service/container), so its /proc lists that container's processes"
			default:
				if e.GIDs, e.Read, e.Total, err = h.containerGIDs(ctx, c.ID); err != nil {
					e.Err = clipRunes(err.Error(), 300)
				}
			}
			if e.Err != "" {
				log.Printf("doctor: %s: container %s: group check skipped: %s", id, c.Name(), e.Err)
			}
			out = append(out, e)
		}
	}
	return out
}

// containerGIDs is every gid the container's processes hold: the Gid: and
// Groups: lines of /proc/<pid>/status. No inspect field gives them (the
// configured user and group_add miss an image's /etc/group, an entrypoint
// that switches to PGID, setgroups at run time), and the Engine API's
// top answers host pids. So two argv execs (never a shell), as the
// container's own user, read-only, output capped and parsed for numbers
// only: `ls /proc` (the pids, at most maxStatusPIDs; failing — no ls —
// pid 1 only) and one `cat` of their status files (a process that exited
// meanwhile is just missing).
//
// M8: Docker can't kill a timed-out exec. Its id is kept (gidExecs), and
// while one still runs (ExecRunning) the container is skipped with an
// error, so hung processes never pile up run after run.
func (h *Hub) containerGIDs(ctx context.Context, id string) (gids []int, read, total int, err error) {
	h.scanCacheMu.Lock()
	pending := slices.Clone(h.gidExecs[id])
	h.scanCacheMu.Unlock()
	for _, x := range pending {
		if running, err := h.engine.ExecRunning(ctx, x); err == nil && running {
			return nil, 0, 0, errors.New("a previous group check (timed out) is still running in it")
		}
	}
	h.scanCacheMu.Lock()
	delete(h.gidExecs, id)
	h.scanCacheMu.Unlock()
	exec := func(cmd []string) (*docker.ExecResult, error) {
		res, err := h.engine.Exec(ctx, id, cmd, gidExecTimeout)
		if err == nil && res.TimedOut && res.ExecID != "" {
			h.scanCacheMu.Lock()
			if h.gidExecs == nil {
				h.gidExecs = map[string][]string{}
			}
			h.gidExecs[id] = append(h.gidExecs[id], res.ExecID)
			h.scanCacheMu.Unlock()
		}
		return res, err
	}
	pids, total := []int{1}, 1
	if res, err := exec([]string{"ls", "/proc"}); err == nil && res.ExitCode == 0 && !res.TimedOut {
		pids, total = pidList(res.Output)
	}
	args := []string{"cat"}
	for _, p := range pids {
		args = append(args, "/proc/"+strconv.Itoa(p)+"/status")
	}
	res, err := exec(args)
	if err != nil {
		return nil, 0, 0, err
	}
	if res.TimedOut {
		return nil, 0, 0, errors.New("timed out")
	}
	gids, ok := statusGIDs(res.Output)
	if !ok {
		return nil, 0, 0, fmt.Errorf("no process status readable (exit %d)", res.ExitCode)
	}
	return gids, len(pids), total, nil
}

// pidList is the numeric names of ls /proc: 1 first, then ascending, at
// most maxStatusPIDs; total is how many were listed (1 included).
func pidList(out []byte) ([]int, int) {
	seen := map[int]bool{1: true}
	var ps []int
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || len(l) > 10 || l[0] == '0' || strings.Trim(l, "0123456789") != "" {
			continue
		}
		if n, err := strconv.Atoi(l); err == nil && !seen[n] {
			seen[n] = true
			ps = append(ps, n)
		}
	}
	sort.Ints(ps)
	return append([]int{1}, ps[:min(len(ps), maxStatusPIDs-1)]...), len(ps) + 1
}

// statusGIDs collects the ids of every Gid: / Groups: line (ok: one was
// seen), sorted.
func statusGIDs(out []byte) ([]int, bool) {
	set := map[int]bool{}
	ok := false
	for _, l := range bytes.Split(out, []byte("\n")) {
		s := string(l)
		var rest string
		switch {
		case strings.HasPrefix(s, "Gid:"):
			rest = s[len("Gid:"):]
		case strings.HasPrefix(s, "Groups:"):
			rest = s[len("Groups:"):]
		default:
			continue
		}
		ok = true
		for _, f := range strings.Fields(rest) {
			if n, err := strconv.ParseUint(f, 10, 32); err == nil {
				set[int(n)] = true
			}
		}
	}
	return slices.Sorted(func(yield func(int) bool) {
		for g := range set {
			if !yield(g) {
				return
			}
		}
	}), ok
}

// ── the cache ───────────────────────────────────────────

// scanFileLocked is the cache, loaded on first use. A file that can't be
// read, doesn't parse, has another version or an entry that doesn't hold
// together is dropped (logged): an empty cache with no last run, so the
// next scheduled run is due. Caller holds scanCacheMu.
func (h *Hub) scanFileLocked() *scanFile {
	if h.scanData != nil {
		return h.scanData
	}
	sf := &scanFile{Version: scanCacheVersion, Scans: map[string]scanEntry{}, Runtime: []runtimeEntry{}}
	b, err := readLimited(h.scanCachePath(), maxScanCacheBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		log.Printf("doctor: the scan cache is unreadable (%v): rescanning", err)
	default:
		var x scanFile
		if err := json.Unmarshal(b, &x); err != nil {
			log.Printf("doctor: the scan cache is corrupt (%v): rescanning", err)
		} else if why := x.problem(); why != "" {
			log.Printf("doctor: the scan cache is corrupt (%s): rescanning", why)
		} else {
			sf = &x
		}
	}
	h.scanData = sf
	return sf
}

// problem: why x isn't a cache this Hub wrote ("" = fine).
func (x *scanFile) problem() string {
	if x.Version != scanCacheVersion {
		return fmt.Sprintf("version %d", x.Version)
	}
	if len(x.Scans) > maxScanCacheEntries || len(x.Runtime) > maxRuntimeContainers {
		return "too many entries"
	}
	if x.Scans == nil {
		x.Scans = map[string]scanEntry{}
	}
	if x.Runtime == nil {
		x.Runtime = []runtimeEntry{}
	}
	for k, e := range x.Scans {
		if e.Target != k || !path.IsAbs(k) || path.Clean(k) != k || (e.Report == nil) == (e.Err == "") || e.At.IsZero() ||
			(e.Folder != "" && (e.Dev == 0 || e.Ino == 0)) {
			return fmt.Sprintf("entry %q", clipRunes(k, 80))
		}
	}
	for _, r := range x.Runtime {
		if !templates.ValidID(r.Instance) {
			return fmt.Sprintf("runtime instance %q", clipRunes(r.Instance, 80))
		}
	}
	return ""
}

// readLimited reads p, refusing a file over max bytes.
func readLimited(p string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return b, nil
}

// putScan caches e (replacing the target's previous entry) and saves.
func (h *Hub) putScan(e scanEntry) {
	h.scanCacheMu.Lock()
	defer h.scanCacheMu.Unlock()
	sf := h.scanFileLocked()
	sf.Scans[e.Target] = e
	h.saveScanFileLocked(sf)
}

// finishScanRun ends a run: entries of targets that are gone (not in keep
// and older than the run) dropped, the runtime gids replaced, LastRun set
// when the run finished (not cut short), saved.
func (h *Hub) finishScanRun(start time.Time, keep map[string]bool, rt []runtimeEntry, complete bool) {
	h.scanCacheMu.Lock()
	defer h.scanCacheMu.Unlock()
	sf := h.scanFileLocked()
	for k, e := range sf.Scans {
		if !keep[k] && e.At.Before(start) {
			delete(sf.Scans, k)
		}
	}
	if complete {
		sf.Runtime, sf.LastRun = rt, time.Now().UTC()
	}
	h.saveScanFileLocked(sf)
}

// saveScanFileLocked writes the cache (0600, dir 0700, atomic), bounded:
// the oldest entries beyond maxScanCacheEntries go; over
// maxScanCacheBytes the reports lose their sample paths, then the oldest
// entries go. A failed write is logged (the cache is a cache).
func (h *Hub) saveScanFileLocked(sf *scanFile) {
	byAge := func() []string {
		ks := slices.Collect(maps.Keys(sf.Scans))
		sort.Slice(ks, func(i, j int) bool { return sf.Scans[ks[i]].At.Before(sf.Scans[ks[j]].At) })
		return ks
	}
	if n := len(sf.Scans) - maxScanCacheEntries; n > 0 {
		for _, k := range byAge()[:n] {
			delete(sf.Scans, k)
		}
	}
	data, err := json.Marshal(sf)
	if err == nil && len(data) > maxScanCacheBytes {
		for k, e := range sf.Scans {
			if e.Report != nil {
				e.Report = withoutSamples(e.Report)
				sf.Scans[k] = e
			}
		}
		data, err = json.Marshal(sf)
		for _, k := range byAge() {
			if err != nil || len(data) <= maxScanCacheBytes {
				break
			}
			delete(sf.Scans, k)
			data, err = json.Marshal(sf)
		}
	}
	if err != nil {
		log.Printf("doctor: encoding the scan cache: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(h.scanCachePath()), 0o700); err != nil {
		log.Printf("doctor: saving the scan cache: %v", err)
		return
	}
	if err := fsutil.WriteFileAtomic(h.scanCachePath(), data, 0o600); err != nil {
		log.Printf("doctor: saving the scan cache: %v", err)
	}
}

// withoutSamples is a deep copy of r without sample paths.
func withoutSamples(r *folderfix.Report) *folderfix.Report {
	b, err := json.Marshal(r)
	if err != nil {
		return r
	}
	var c folderfix.Report
	if json.Unmarshal(b, &c) != nil {
		return r
	}
	c.DropSamples()
	return &c
}

// scanCache is the cached scans as the doctor reads them, by target path.
func (h *Hub) scanCache() map[string]doctor.ScanIn {
	out := map[string]doctor.ScanIn{}
	for k, e := range h.scanEntries() {
		out[k] = scanIn(e)
	}
	return out
}

func scanIn(e scanEntry) doctor.ScanIn {
	return doctor.ScanIn{At: e.At, Report: e.Report, Target: e.Target, Folder: e.Folder,
		Principals: slices.Clone(e.Principals), Err: e.Err}
}

// scanEntries is a copy of the cached entries.
func (h *Hub) scanEntries() map[string]scanEntry {
	h.scanCacheMu.Lock()
	defer h.scanCacheMu.Unlock()
	return maps.Clone(h.scanFileLocked().Scans)
}

// scanRuntime is the last run's container gids.
func (h *Hub) scanRuntime() []doctor.RuntimeIn {
	h.scanCacheMu.Lock()
	defer h.scanCacheMu.Unlock()
	var out []doctor.RuntimeIn
	for _, r := range h.scanFileLocked().Runtime {
		out = append(out, doctor.RuntimeIn{Instance: r.Instance, Service: r.Service, Container: r.Container, GIDs: slices.Clone(r.GIDs), Err: r.Err,
			PIDsRead: r.Read, PIDsTotal: r.Total, At: r.At})
	}
	return out
}

// lastFullScan is when the last complete run finished (zero: never, or
// the cache was dropped).
func (h *Hub) lastFullScan() time.Time {
	h.scanCacheMu.Lock()
	defer h.scanCacheMu.Unlock()
	return h.scanFileLocked().LastRun
}

// doctorScansLocked is the cached scans of the current targets (a scan of
// a target that is no longer one, or of a folder whose path or root
// dev/ino changed — M6 —, is not judged) and the runtime gids of enabled
// instances. scans / rt come from scanEntries / scanRuntime, read before
// mu. Caller holds mu.
func (h *Hub) doctorScansLocked(scans map[string]scanEntry, rt []doctor.RuntimeIn) (map[string]doctor.ScanIn, []doctor.RuntimeIn) {
	out := map[string]doctor.ScanIn{}
	for _, t := range h.scanTargetsLocked() {
		if e, ok := scans[t.Path]; ok && h.entryCurrentLocked(e, t.Folder) {
			out[t.Path] = scanIn(e)
		}
	}
	var r []doctor.RuntimeIn
	for _, x := range rt {
		// H11 M6: an instance started since the read runs new processes:
		// its old gids aren't judged against today's assignments.
		if s, ok := h.startedAt[x.Instance]; ok && !x.At.IsZero() && s.After(x.At) {
			continue
		}
		if h.st.IsEnabled(x.Instance) {
			r = append(r, x)
		}
	}
	return out, r
}

// entryCurrentLocked: e is a scan of folder (a hand-typed path: "") as
// it is now — for a folder, the same root dev/ino. Caller holds mu.
func (h *Hub) entryCurrentLocked(e scanEntry, folder string) bool {
	if e.Folder != folder {
		return false
	}
	if folder == "" {
		return true
	}
	f, ok := h.st.Folders[folder]
	return ok && f.Path == e.Target && f.Dev == e.Dev && f.Ino == e.Ino
}

// fillLastCheck adds the folder's cached scan (never under mu: the cache
// is read first, then judged under the read lock).
func (h *Hub) fillLastCheck(v *FolderView) {
	e, ok := h.scanEntries()[v.Path]
	if !ok {
		return
	}
	h.mu.RLock()
	cur := h.entryCurrentLocked(e, v.ID)
	h.mu.RUnlock()
	if !cur {
		return
	}
	s := &doctor.ScanSummary{Target: e.Target, At: e.At}
	if e.Report != nil {
		s.Partial, s.Entries = e.Report.Partial, e.Report.Entries
	}
	v.LastCheck = s
}
