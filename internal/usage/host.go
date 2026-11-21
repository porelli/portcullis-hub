package usage

// Host figures (contract §6 "Host figures", §11.11): the host's CPU,
// memory and disk IO from the Hub's own procfs. /proc/stat, /proc/meminfo
// and /proc/diskstats aren't namespaced, so a container reads the host's
// figures from them; nothing else is read (no /proc/net/dev: the Hub's is
// its own network namespace's).

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/prometheus/procfs"
	"github.com/prometheus/procfs/blockdevice"
)

// userHZ is the kernel's USER_HZ: procfs gives /proc/stat in seconds
// (ticks / 100), HostCounters keeps the ticks.
const userHZ = 100

// sectorBytes: /proc/diskstats counts 512-byte sectors whatever the
// device's own sector size.
const sectorBytes = 512

// HostCounters are one read of the host's counters.
type HostCounters struct {
	At                  time.Time
	CPUTotal, CPUIdle   uint64 // USER_HZ ticks; idle includes iowait
	MemTotal            int64  // bytes; <= 0: not read
	MemAvailable        int64  // bytes; < 0: not read
	DiskRead, DiskWrite uint64 // bytes, whole disks only
}

// HostSample is the host's derived figures (nil: not measured).
type HostSample struct {
	CPUUsedCores *float64
	MemUsedBytes *int64
	BlkReadBps   *float64
	BlkWriteBps  *float64
}

func ticks(sec float64) uint64 { return uint64(math.Round(sec * userHZ)) }

// ReadHost reads the counters from fs (/proc/stat, /proc/meminfo) and bfs
// (/proc/diskstats). Any file that can't be read or parsed is an error:
// no partial counters.
func ReadHost(fs procfs.FS, bfs blockdevice.FS) (HostCounters, error) {
	c := HostCounters{At: time.Now().UTC(), MemTotal: 0, MemAvailable: -1}
	st, err := fs.Stat()
	if err != nil {
		return HostCounters{}, fmt.Errorf("reading the host's cpu ticks: %w", err)
	}
	t := st.CPUTotal
	// guest and guest_nice are already counted in user and nice.
	c.CPUTotal = ticks(t.User) + ticks(t.Nice) + ticks(t.System) + ticks(t.Idle) + ticks(t.Iowait) +
		ticks(t.IRQ) + ticks(t.SoftIRQ) + ticks(t.Steal)
	c.CPUIdle = ticks(t.Idle) + ticks(t.Iowait)
	if c.CPUTotal == 0 {
		return HostCounters{}, fmt.Errorf("reading the host's cpu ticks: no cpu line")
	}
	mi, err := fs.Meminfo()
	if err != nil {
		return HostCounters{}, fmt.Errorf("reading the host's memory: %w", err)
	}
	if mi.MemTotalBytes != nil && *mi.MemTotalBytes <= math.MaxInt64 {
		c.MemTotal = int64(*mi.MemTotalBytes)
	}
	if mi.MemAvailableBytes != nil && *mi.MemAvailableBytes <= math.MaxInt64 {
		c.MemAvailable = int64(*mi.MemAvailableBytes)
	}
	ds, err := bfs.ProcDiskstats()
	if err != nil {
		return HostCounters{}, fmt.Errorf("reading the host's disk counters: %w", err)
	}
	names := make(map[string]bool, len(ds))
	for _, d := range ds {
		names[d.DeviceName] = true
	}
	for _, d := range ds {
		if wholeDisk(d.DeviceName, names) {
			c.DiskRead += d.ReadSectors * sectorBytes
			c.DiskWrite += d.WriteSectors * sectorBytes
		}
	}
	return c, nil
}

// virtualDisks are block devices on top of others (or in memory): their
// IO is counted on the disks below, or isn't disk IO.
var virtualDisks = []string{"loop", "ram", "zram", "dm-", "md", "sr", "fd", "zd", "nbd"}

// wholeDisk reports whether name (of the devices in all) is a whole disk:
// not a virtual device and not a partition. The kernel names a disk's
// partitions <disk><n>, or <disk>p<n> when the disk's name ends in a
// digit (nvme0n1p1, mmcblk0p1).
func wholeDisk(name string, all map[string]bool) bool {
	for _, p := range virtualDisks {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	for i := len(name) - 1; i > 0 && isDigit(name[i]); i-- {
		disk := name[:i]
		if strings.HasSuffix(disk, "p") && len(disk) > 1 && isDigit(disk[len(disk)-2]) && all[disk[:len(disk)-1]] {
			return false
		}
		if !isDigit(disk[len(disk)-1]) && all[disk] {
			return false
		}
	}
	return true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// DeriveHost is cur's figures with rates against prev, on a host of cpus
// CPUs (the engine's NCPU). Rates are nil on the first read, when that
// counter went down, and when the reads are less than MinInterval apart
// (or out of order); the memory figure needs only cur.
func DeriveHost(prev *HostCounters, cur HostCounters, cpus int) HostSample {
	var s HostSample
	if cur.MemTotal > 0 && cur.MemAvailable >= 0 && cur.MemAvailable <= cur.MemTotal {
		v := cur.MemTotal - cur.MemAvailable
		s.MemUsedBytes = &v
	}
	if prev == nil {
		return s
	}
	dt := cur.At.Sub(prev.At)
	if dt < MinInterval {
		return s
	}
	if cpus > 0 && cur.CPUTotal > prev.CPUTotal && cur.CPUIdle >= prev.CPUIdle {
		dTotal, dIdle := cur.CPUTotal-prev.CPUTotal, cur.CPUIdle-prev.CPUIdle
		if dIdle <= dTotal {
			v := float64(dTotal-dIdle) / float64(dTotal) * float64(cpus)
			s.CPUUsedCores = &v
		}
	}
	s.BlkReadBps = rate(&prev.DiskRead, &cur.DiskRead, dt)
	s.BlkWriteBps = rate(&prev.DiskWrite, &cur.DiskWrite, dt)
	return s
}

// HostPoint is the host's figures at one sweep.
type HostPoint struct {
	T time.Time
	S HostSample
}

// HostRing keeps the host's last n points (not safe for concurrent use:
// the sampler guards it).
type HostRing struct {
	buf  []HostPoint
	next int
	full bool
}

// NewHostRing is an empty ring of n points (n < 1: RingSize).
func NewHostRing(n int) *HostRing {
	if n < 1 {
		n = RingSize
	}
	return &HostRing{buf: make([]HostPoint, n)}
}

// Cap is the ring's size.
func (r *HostRing) Cap() int { return len(r.buf) }

// Add appends p, dropping the oldest when full.
func (r *HostRing) Add(p HostPoint) {
	r.buf[r.next] = p
	r.next++
	if r.next == len(r.buf) {
		r.next, r.full = 0, true
	}
}

// Len is the number of points held.
func (r *HostRing) Len() int {
	if r.full {
		return len(r.buf)
	}
	return r.next
}

// Points are the points, oldest first (a copy).
func (r *HostRing) Points() []HostPoint {
	if !r.full {
		return append([]HostPoint(nil), r.buf[:r.next]...)
	}
	out := make([]HostPoint, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	return append(out, r.buf[:r.next]...)
}

// Last is the newest point (false when empty).
func (r *HostRing) Last() (HostPoint, bool) {
	if r.Len() == 0 {
		return HostPoint{}, false
	}
	i := r.next - 1
	if i < 0 {
		i = len(r.buf) - 1
	}
	return r.buf[i], true
}
