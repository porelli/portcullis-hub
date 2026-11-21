package usage

import (
	"testing"
	"time"

	"github.com/prometheus/procfs"
	"github.com/prometheus/procfs/blockdevice"
)

func TestReadHostFixture(t *testing.T) {
	fs, err := procfs.NewFS("testdata/proc")
	if err != nil {
		t.Fatal(err)
	}
	bfs, err := blockdevice.NewFS("testdata/proc", "testdata/sys")
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	c, err := ReadHost(fs, bfs)
	if err != nil {
		t.Fatal(err)
	}
	// cpu: user+nice+system+idle+iowait+irq+softirq+steal (guest is in
	// user already); idle = idle+iowait.
	if c.CPUTotal != 6485 || c.CPUIdle != 5100 {
		t.Errorf("cpu = %d total, %d idle", c.CPUTotal, c.CPUIdle)
	}
	if c.MemTotal != 16384000*1024 || c.MemAvailable != 8192000*1024 {
		t.Errorf("mem = %d total, %d available", c.MemTotal, c.MemAvailable)
	}
	// Whole disks only: sda, nvme0n1, nvme0n10 (a disk: nvme0n1's
	// partitions are nvme0n1pN), mmcblk0. Never a partition, loop, dm,
	// md, sr or zram device.
	if c.DiskRead != 3017*512 || c.DiskWrite != 2003*512 {
		t.Errorf("disk = %d read, %d write", c.DiskRead, c.DiskWrite)
	}
	if c.At.Before(before) || c.At.After(time.Now()) {
		t.Errorf("at = %v", c.At)
	}
}

func TestReadHostMissing(t *testing.T) {
	fs, err := procfs.NewFS("testdata/sys")
	if err != nil {
		t.Fatal(err)
	}
	bfs, err := blockdevice.NewFS("testdata/sys", "testdata/sys")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHost(fs, bfs); err == nil {
		t.Error("no procfs files read without an error")
	}
}

func TestWholeDisk(t *testing.T) {
	names := []string{"sda", "sda1", "sdaa", "sdaa3", "vda", "vda1", "xvda", "xvda1", "nvme0n1", "nvme0n1p2", "nvme0n12",
		"mmcblk0", "mmcblk0p1", "loop3", "dm-1", "md127", "sr0", "zram0", "ram0", "fd0", "zd0", "nbd0"}
	whole := map[string]bool{"sda": true, "sdaa": true, "vda": true, "xvda": true, "nvme0n1": true, "nvme0n12": true, "mmcblk0": true}
	all := map[string]bool{}
	for _, n := range names {
		all[n] = true
	}
	for _, n := range names {
		if got := wholeDisk(n, all); got != whole[n] {
			t.Errorf("wholeDisk(%q) = %v", n, got)
		}
	}
}

func TestDeriveHost(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	prev := HostCounters{At: t0, CPUTotal: 10000, CPUIdle: 6000, MemTotal: 8 << 30, MemAvailable: 6 << 30, DiskRead: 1 << 20, DiskWrite: 2 << 20}
	cur := HostCounters{At: t0.Add(15 * time.Second), CPUTotal: 13000, CPUIdle: 7500, MemTotal: 8 << 30, MemAvailable: 5 << 30,
		DiskRead: 1<<20 + 15*4096, DiskWrite: 2<<20 + 15*1000}
	s := DeriveHost(&prev, cur, 2)
	if s.CPUUsedCores == nil || *s.CPUUsedCores != 1.0 {
		t.Errorf("cpu = %v", s.CPUUsedCores)
	}
	if s.MemUsedBytes == nil || *s.MemUsedBytes != 3<<30 {
		t.Errorf("mem = %v", s.MemUsedBytes)
	}
	if s.BlkReadBps == nil || *s.BlkReadBps != 4096 || s.BlkWriteBps == nil || *s.BlkWriteBps != 1000 {
		t.Errorf("blk = %v %v", s.BlkReadBps, s.BlkWriteBps)
	}

	noRates := func(name string, s HostSample) {
		t.Helper()
		if s.CPUUsedCores != nil || s.BlkReadBps != nil || s.BlkWriteBps != nil {
			t.Errorf("%s: rates = %v %v %v", name, s.CPUUsedCores, s.BlkReadBps, s.BlkWriteBps)
		}
		if s.MemUsedBytes == nil || *s.MemUsedBytes != 3<<30 {
			t.Errorf("%s: mem = %v", name, s.MemUsedBytes)
		}
	}
	noRates("first", DeriveHost(nil, cur, 2))
	down := prev
	down.CPUTotal, down.CPUIdle, down.DiskRead, down.DiskWrite = 20000, 9000, 1<<30, 1<<30
	noRates("down", DeriveHost(&down, cur, 2))
	near := prev
	near.At = cur.At.Add(-MinInterval + time.Millisecond)
	noRates("near", DeriveHost(&near, cur, 2))
	late := prev
	late.At = cur.At.Add(time.Second)
	noRates("out of order", DeriveHost(&late, cur, 2))

	// Each counter on its own: a disk counter going down (a disk gone)
	// leaves the CPU figure.
	disk := prev
	disk.DiskRead = 1 << 30
	if s := DeriveHost(&disk, cur, 2); s.CPUUsedCores == nil || s.BlkReadBps != nil || s.BlkWriteBps == nil {
		t.Errorf("disk down = %+v", s)
	}
	// No engine CPU count: no CPU figure.
	if s := DeriveHost(&prev, cur, 0); s.CPUUsedCores != nil || s.BlkReadBps == nil {
		t.Errorf("no cpus = %+v", s)
	}
	// Idle grew more than total, or no tick at all: no CPU figure.
	odd := cur
	odd.CPUIdle = prev.CPUIdle + 4000
	if s := DeriveHost(&prev, odd, 2); s.CPUUsedCores != nil {
		t.Errorf("idle > total = %v", *s.CPUUsedCores)
	}
	still := cur
	still.CPUTotal, still.CPUIdle = prev.CPUTotal, prev.CPUIdle
	if s := DeriveHost(&prev, still, 2); s.CPUUsedCores != nil {
		t.Errorf("no ticks = %v", *s.CPUUsedCores)
	}
	// Memory not read (or nonsense): nil, never 0 or negative.
	for _, m := range [][2]int64{{0, 0}, {8 << 30, -1}, {1 << 30, 2 << 30}} {
		c := cur
		c.MemTotal, c.MemAvailable = m[0], m[1]
		if s := DeriveHost(&prev, c, 2); s.MemUsedBytes != nil {
			t.Errorf("mem %v = %v", m, *s.MemUsedBytes)
		}
	}
}

func TestHostRing(t *testing.T) {
	r := NewHostRing(3)
	if _, ok := r.Last(); ok || r.Len() != 0 {
		t.Fatal("empty ring has a point")
	}
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	for i := range 5 {
		r.Add(HostPoint{T: t0.Add(time.Duration(i) * Interval)})
	}
	ps := r.Points()
	if len(ps) != 3 || !ps[0].T.Equal(t0.Add(2*Interval)) || !ps[2].T.Equal(t0.Add(4*Interval)) {
		t.Errorf("points = %v", ps)
	}
	if last, ok := r.Last(); !ok || !last.T.Equal(t0.Add(4*Interval)) {
		t.Errorf("last = %v", last)
	}
	if NewHostRing(0).Cap() != RingSize {
		t.Error("default size")
	}
}
