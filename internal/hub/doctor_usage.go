package hub

import (
	"time"

	"github.com/portcullis/hub/internal/doctor"
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
