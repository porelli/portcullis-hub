package hub

import (
	"sort"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/kube"
)

// usageHelperLabel: a Hub helper container (Docker/Podman or Kubernetes).
func usageHelperUnit(u runtime.Unit) bool {
	if _, ok := u.Labels[docker.LabelHelper]; ok {
		return true
	}
	_, ok := u.Labels[kube.LabelHelper]
	return ok
}

// usageUnit is one listed unit in scope.
type usageUnit struct {
	runtime.Unit
	Group, Kind string
	Number      int
}

// usageScope groups the listed units (contract §11.11 "Scope"): app
// instances, core, unknown portcullis-<id> projects and running Hub
// helpers are in scope; everything else is only counted.
func usageScope(units []runtime.Unit, insts map[string]usageInst) (in []usageUnit, notShown int) {
	for _, u := range units {
		uu := usageUnit{Unit: u}
		uu.Number, _ = strconv.Atoi(u.Labels[docker.LabelNumber])
		switch {
		case usageHelperUnit(u):
			if u.State != "running" {
				continue
			}
			uu.Group, uu.Kind = usageCoreProject, usageHelper
		case u.Project == usageCoreProject:
			uu.Group, uu.Kind = usageCoreProject, usageCore
		case strings.HasPrefix(u.Project, runtime.ProjectPrefix):
			id := strings.TrimPrefix(u.Project, runtime.ProjectPrefix)
			if _, ok := insts[id]; ok {
				uu.Group, uu.Kind = id, usageApp
			} else {
				uu.Group, uu.Kind = u.Project, usageUnknown
			}
		default:
			notShown++
			continue
		}
		in = append(in, uu)
	}
	rank := map[string]int{usageApp: 0, usageCore: 1, usageUnknown: 2, usageHelper: 3}
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if rank[a.Kind] != rank[b.Kind] {
			return rank[a.Kind] < rank[b.Kind]
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.Number != b.Number {
			return a.Number < b.Number
		}
		return a.ID < b.ID
	})
	return in, notShown
}
