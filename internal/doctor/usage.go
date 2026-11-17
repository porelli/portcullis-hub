package doctor

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Usage (contract §14.5, §11.11): kinds that judge the usage sampler's
// snapshot (Inputs.Usage) and the storage cache (Inputs.Storage). They
// never run anything, and no finding is ever raised from a missing
// figure: a nil value in the window is no finding (usage_not_measured
// speaks for missing data). All explain-only.
const (
	KindDiskNearlyFull        = "disk_nearly_full"
	KindMemoryNearLimit       = "memory_near_limit"
	KindOOMKilled             = "oom_killed"
	KindPidsNearLimit         = "pids_near_limit"
	KindUsageNotMeasured      = "usage_not_measured"
	KindStorageMeasurePartial = "storage_measure_partial"
	// TabUsage is the instance page's Usage tab (a finding's link).
	TabUsage = "usage"
)

// UsageKinds are the live-usage kinds.
var UsageKinds = []string{KindMemoryNearLimit, KindOOMKilled, KindPidsNearLimit, KindUsageNotMeasured}

// The thresholds (contract §14.5).
const (
	usageNearPercent  = 90
	usageWindow       = 10 * time.Minute
	usageMinPoints    = 30
	usageStaleAfter   = 5 * time.Minute
	usageOOMRestarts  = 3
	usageHardeningDoc = "docs/operations/hardening.md"
)

// UsageIn is the usage sampler as the doctor sees it: the runtime,
// whether the engine is verified, the last successful sweep (Since: the
// sampler's first attempt, when none succeeded yet), a runtime-wide
// "not measured" reason, and each app and core container.
type UsageIn struct {
	Runtime     string
	Verified    bool
	Now         time.Time
	LastSuccess time.Time
	Since       time.Time
	NotMeasured string
	Containers  []ContainerUsageIn
}

// ContainerUsageIn is one container (Instance "" = core): its limits
// (0 = none), OOM state, restart count now and an hour ago, whether an
// OOM kill was seen in the hour, and its points of the last 10 minutes.
type ContainerUsageIn struct {
	Instance, Service   string
	Number              int
	MemLimit, PidsLimit int64
	OOMKilled           bool
	Restarts            int
	RestartsHourAgo     int
	OOMSeenHour         bool
	Points              []UsagePointIn
}

// UsagePointIn is one sample's memory and pids (nil: not measured).
type UsagePointIn struct {
	At        time.Time
	Mem, Pids *int64
}

// StorageIn is the storage cache as the doctor sees it: every filesystem
// with data and every target that hit a cap in the last run.
type StorageIn struct {
	Filesystems []FilesystemIn
	Partial     []StoragePartialIn
}

// FilesystemIn is one filesystem (by dev): a path on it, its free and
// total bytes, and its owners (instance ids, "core", folder ids), largest
// first.
type FilesystemIn struct {
	Dev         uint64
	Path        string
	Free, Total uint64
	Owners      []string
}

// StoragePartialIn is one capped target.
type StoragePartialIn struct{ Target, Owner, Reason string }

func init() {
	for _, k := range UsageKinds {
		Register(usageCheck{kind: k})
	}
}

type usageCheck struct{ kind string }

func (c usageCheck) Kind() string { return c.kind }

func (c usageCheck) Run(in *Inputs) []Finding {
	if in.Usage == nil {
		return nil
	}
	switch c.kind {
	case KindMemoryNearLimit:
		return nearLimit(in.Usage, KindMemoryNearLimit)
	case KindPidsNearLimit:
		return nearLimit(in.Usage, KindPidsNearLimit)
	case KindOOMKilled:
		return oomKilled(in.Usage)
	case KindUsageNotMeasured:
		return usageNotMeasured(in.Usage)
	}
	return nil
}

// usageSubject names a container: "<instance>'s <service>.<n>" or core's
// "<service>".
func usageSubject(c ContainerUsageIn) string {
	if c.Instance == "" {
		return "core's " + c.Service
	}
	return fmt.Sprintf("%s's %s.%d", c.Instance, c.Service, c.Number)
}

// usageFinding fills what every container finding shares: the
// fingerprint, the band digest, the link (apps) or the core text.
func usageFinding(kind string, c ContainerUsageIn, f Finding) Finding {
	inst := c.Instance
	if inst == "" {
		inst = "core"
	}
	f.FP = Fingerprint(kind, inst, c.Service, strconv.Itoa(c.Number))
	f.Kind, f.Class = kind, FixExplain
	if c.Instance == "" {
		f.Inputs = Digest([]string{"warning", c.Service})
		f.Fix = "Core's limits are its compose values: see " + usageHardeningDoc + " (Container hardening) before raising one."
		f.Steps = append(f.Steps, "Core service limits are set in core's docker-compose.yml; "+usageHardeningDoc+" lists them.")
		return f
	}
	f.Inputs = Digest("warning")
	f.Instances = []string{c.Instance}
	f.Link = &Link{Instance: c.Instance, Tab: TabUsage}
	return f
}

// window are the points of the last 10 minutes.
func window(u *UsageIn, c ContainerUsageIn) []UsagePointIn {
	var out []UsagePointIn
	for _, p := range c.Points {
		if !p.At.Before(u.Now.Add(-usageWindow)) {
			out = append(out, p)
		}
	}
	return out
}

func nearLimit(u *UsageIn, kind string) []Finding {
	var out []Finding
	for _, c := range u.Containers {
		limit := c.MemLimit
		if kind == KindPidsNearLimit {
			limit = c.PidsLimit
		}
		if limit <= 0 {
			continue
		}
		ps := window(u, c)
		if len(ps) < usageMinPoints {
			continue
		}
		near := true
		for _, p := range ps {
			v := p.Mem
			if kind == KindPidsNearLimit {
				v = p.Pids
			}
			if v == nil || *v*100 < limit*usageNearPercent {
				near = false
				break
			}
		}
		if !near {
			continue
		}
		f := Finding{Severity: Warning}
		if kind == KindMemoryNearLimit {
			f.Title = fmt.Sprintf("%s has used 90%% of its memory limit or more for 10 minutes.", usageSubject(c))
			f.Why = "A container at its memory limit is killed by the kernel (OOM) the next time it needs more: the app restarts or fails."
			f.Steps = []string{
				"Raise the limit: the instance's setting if its template has one, else the Expert override (mem_limit).",
				"Or look at the app's Logs: a leak or a cache that grows without bound fills any limit.",
			}
		} else {
			f.Title = fmt.Sprintf("%s has used 90%% of its process limit or more for 10 minutes.", usageSubject(c))
			f.Why = "At its pids limit a container can't start another process or thread: the app hangs or fails."
			f.Steps = []string{
				"Raise the limit: the instance's setting if its template has one, else the Expert override (pids_limit).",
				"Or look at the app's Logs for processes that never end.",
			}
		}
		out = append(out, usageFinding(kind, c, f))
	}
	return out
}

func oomKilled(u *UsageIn) []Finding {
	var out []Finding
	for _, c := range u.Containers {
		restarted := c.OOMSeenHour && c.Restarts-c.RestartsHourAgo >= usageOOMRestarts
		if !c.OOMKilled && !restarted {
			continue
		}
		f := Finding{Severity: Warning,
			Title: fmt.Sprintf("%s was killed for running out of memory.", usageSubject(c)),
			Why:   "The kernel stopped it at its memory limit (OOM). It restarts, losing what it was doing, and it will happen again while the limit is too low.",
			Steps: []string{
				"Raise the limit: the instance's setting if its template has one, else the Expert override (mem_limit).",
				"Or look at the app's Logs for what used the memory.",
			},
		}
		if restarted && !c.OOMKilled {
			f.Title = fmt.Sprintf("%s restarted %d times in the last hour after running out of memory.", usageSubject(c), c.Restarts-c.RestartsHourAgo)
		}
		out = append(out, usageFinding(KindOOMKilled, c, f))
	}
	return out
}

func usageNotMeasured(u *UsageIn) []Finding {
	why := u.NotMeasured
	if why == "" {
		if !u.Verified {
			return nil // the engine's own kinds say why
		}
		last := u.LastSuccess
		if last.IsZero() {
			last = u.Since
		}
		if last.IsZero() || u.Now.Sub(last) < usageStaleAfter {
			return nil
		}
		why = "the usage sampler has had no successful sample for 5 minutes"
	}
	return []Finding{{
		FP: Fingerprint(KindUsageNotMeasured), Kind: KindUsageNotMeasured, Severity: Info,
		Title:  "CPU and memory usage are not measured.",
		Why:    "Not measured: " + why + ". The Usage page shows no figures, and the memory and process checks can't judge.",
		Class:  FixExplain,
		Steps:  []string{"Check the engine's state in Settings (GET /api/runtime) and the Hub's log for \"usage:\" lines."},
		Inputs: Digest(why),
	}}
}

// StorageKinds are the storage kinds (Inputs.Storage).
var StorageKinds = []string{KindDiskNearlyFull, KindStorageMeasurePartial}

// The disk bands (contract §14.5).
const (
	diskWarnPercent  = 10
	diskWarnBytes    = 5 << 30
	diskProblemPerc  = 3
	diskProblemBytes = 1 << 30
)

func init() {
	for _, k := range StorageKinds {
		Register(storageCheck{kind: k})
	}
}

type storageCheck struct{ kind string }

func (c storageCheck) Kind() string { return c.kind }

func (c storageCheck) Run(in *Inputs) []Finding {
	if in.Storage == nil {
		return nil
	}
	if c.kind == KindDiskNearlyFull {
		return diskNearlyFull(in.Storage)
	}
	return storageMeasurePartial(in.Storage)
}

// diskBand is a filesystem's band: "problem", "warning" or "".
func diskBand(free, total uint64) string {
	if total == 0 {
		return ""
	}
	switch {
	case free*100 < total*diskProblemPerc || free < diskProblemBytes:
		return "problem"
	case free*100 < total*diskWarnPercent || free < diskWarnBytes:
		return "warning"
	}
	return ""
}

// fmtGiB is bytes in GiB, one decimal.
func fmtGiB(n uint64) string { return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30)) }

func diskNearlyFull(s *StorageIn) []Finding {
	// One finding per filesystem: the same dev from several sources is
	// merged (owners kept in order, largest first as given).
	type fsAgg struct {
		f      FilesystemIn
		owners []string
	}
	var order []uint64
	byDev := map[uint64]*fsAgg{}
	for _, f := range s.Filesystems {
		a := byDev[f.Dev]
		if a == nil {
			a = &fsAgg{f: f}
			byDev[f.Dev] = a
			order = append(order, f.Dev)
		}
		for _, o := range f.Owners {
			if !contains(a.owners, o) {
				a.owners = append(a.owners, o)
			}
		}
	}
	var out []Finding
	for _, dev := range order {
		a := byDev[dev]
		band := diskBand(a.f.Free, a.f.Total)
		if band == "" {
			continue
		}
		sev := Warning
		if band == "problem" {
			sev = Problem
		}
		pct := float64(a.f.Free) * 100 / float64(a.f.Total)
		var insts, folders, names []string
		var link *Link
		for _, o := range a.owners {
			switch {
			case o == "core":
				names = append(names, "core")
			case strings.HasPrefix(o, "folder:"):
				id := strings.TrimPrefix(o, "folder:")
				folders = append(folders, id)
				names = append(names, "shared folder "+id)
			default:
				insts = append(insts, o)
				names = append(names, o)
				if link == nil {
					link = &Link{Instance: o, Tab: TabUsage}
				}
			}
		}
		why := fmt.Sprintf("%s free of %s (%.1f %%). When it fills, apps can't write: databases stop, uploads and backups fail.", fmtGiB(a.f.Free), fmtGiB(a.f.Total), pct)
		if len(names) > 0 {
			why += " Data there, largest first: " + strings.Join(names, ", ") + "."
		}
		out = append(out, Finding{
			FP: Fingerprint(KindDiskNearlyFull, strconv.FormatUint(dev, 10), a.f.Path), Kind: KindDiskNearlyFull, Severity: sev,
			Title:     fmt.Sprintf("The disk with %s is nearly full.", a.f.Path),
			Why:       why,
			Fix:       "free space or move the data",
			Class:     FixExplain,
			Instances: insts, Folders: folders, Paths: []string{a.f.Path},
			Steps: []string{
				"Free space or move the data: Usage → Storage shows what is on this disk, largest first.",
				"Old backups (Settings, an instance's Backups) and unused images are often the quickest to remove.",
			},
			Link:   link,
			Inputs: Digest(band),
		})
	}
	return out
}

func storageMeasurePartial(s *StorageIn) []Finding {
	var out []Finding
	for _, p := range s.Partial {
		f := Finding{
			FP: Fingerprint(KindStorageMeasurePartial, p.Owner, p.Target), Kind: KindStorageMeasurePartial, Severity: Info,
			Title:  fmt.Sprintf("The storage of %s's %s was measured only in part.", p.Owner, p.Target),
			Why:    "The measurement stopped at its cap (" + p.Reason + "): the figure is a lower bound.",
			Class:  FixExplain,
			Steps:  []string{"Nothing to do: the next run measures it again. A very large tree is always capped; the Usage page shows it as \"≥\"."},
			Inputs: Digest(p.Reason),
		}
		if p.Owner != "core" {
			f.Instances = []string{p.Owner}
			f.Link = &Link{Instance: p.Owner, Tab: TabUsage}
		}
		out = append(out, f)
	}
	return out
}
