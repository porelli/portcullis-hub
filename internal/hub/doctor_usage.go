package hub

import (
	"maps"
	"slices"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/servers"
)

// usageDoctorIn is the usage kinds' input, from the sampler's snapshot
// (never the engine): each container's last 10 minutes and its restart
// count an hour ago. nil before the sampler's first sweep (no engine).
func (h *Hub) usageDoctorIn() *doctor.UsageIn {
	snap := h.usageSnapshot()
	if snap.Since.IsZero() {
		return nil
	}
	in := &doctor.UsageIn{Runtime: snap.Runtime, Verified: snap.Verified, Now: snap.Now, LastSuccess: snap.LastSuccess,
		Since: snap.Since, NotMeasured: snap.NotMeasured}
	window, hour := snap.Now.Add(-10*time.Minute), snap.Now.Add(-time.Hour)
	for _, c := range snap.Containers {
		if !c.Running {
			continue
		}
		ci := doctor.ContainerUsageIn{Instance: c.Instance, Service: c.Service, Number: c.Number,
			MemLimit: c.Limits.MemBytes, PidsLimit: c.Limits.Pids, OOMKilled: c.Limits.OOMKilled,
			Restarts: c.Limits.Restarts, RestartsHourAgo: c.Limits.Restarts}
		oldest := true
		for _, p := range c.Points {
			if p.T.Before(hour) {
				continue
			}
			if oldest {
				ci.RestartsHourAgo, oldest = p.Restarts, false
			}
			if p.OOMKilled {
				ci.OOMSeenHour = true
			}
			if !p.T.Before(window) {
				ci.Points = append(ci.Points, doctor.UsagePointIn{At: p.T, Mem: p.S.MemBytes, Pids: p.S.Pids})
			}
		}
		in.Containers = append(in.Containers, ci)
	}
	return in
}

// storageDoctorIn is the storage kinds' input: every filesystem with data
// (the storage cache's reports, the doctor's scans and the Hub's data
// directory, deduplicated by dev, owners largest first; folders named
// "folder:<id>") and every target that hit a cap in the last run. Never
// the engine.
func (h *Hub) storageDoctorIn() *doctor.StorageIn {
	v := h.storageModel()
	h.mu.RLock()
	folders := make(map[string]bool, len(h.st.Folders))
	for id := range h.st.Folders {
		folders[id] = true
	}
	h.mu.RUnlock()
	insts := h.usageInstances()
	in := &doctor.StorageIn{}
	for _, d := range v.Disks {
		// The primary's filesystems (a worker's dev and paths are its own).
		if d.Server != servers.PrimaryID {
			continue
		}
		f := doctor.FilesystemIn{Dev: d.Dev, Path: d.path, Free: d.FreeBytes, Total: d.TotalBytes}
		for _, o := range d.Owners {
			_, isInst := insts[o]
			if folders[o] && !isInst {
				o = "folder:" + o
			}
			f.Owners = append(f.Owners, o)
		}
		in.Filesystems = append(in.Filesystems, f)
	}
	sf := h.storageSnapshot()
	for _, k := range slices.Sorted(maps.Keys(sf.Entries)) {
		e := sf.Entries[k]
		if !e.Partial {
			continue
		}
		for _, o := range e.Owners {
			in.Partial = append(in.Partial, doctor.StoragePartialIn{Target: e.Target, Owner: o, Reason: e.PartialReason})
		}
	}
	return in
}
